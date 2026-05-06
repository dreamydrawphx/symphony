defmodule SymphonyElixir.BlockedAudit do
  @moduledoc """
  Tracks repeated unchanged blocked-audit signatures and pauses noisy continuations.
  """

  require Logger

  alias SymphonyElixir.{Config, SlackNotifier}
  alias SymphonyElixir.Linear.Issue

  @review_gate_pattern ~r/(^needs-.*review$|^needs-security-review$|^human review$)/

  @type decision :: :not_blocked | :ready | :paused
  @type result :: %{
          decision: decision(),
          same_blocked_audit_count: non_neg_integer(),
          blocked_signature: map() | nil,
          signature_hash: String.t() | nil
        }

  @spec evaluate_issue(Issue.t()) :: {:ok, result()} | {:error, term()}
  def evaluate_issue(%Issue{} = issue) do
    if blocked_audit_issue?(issue) do
      persist_blocked_audit(issue)
    else
      clear_issue(issue)
      {:ok, empty_result(:not_blocked)}
    end
  end

  @spec dispatch_paused?(Issue.t()) :: boolean()
  def dispatch_paused?(%Issue{id: issue_id} = issue) when is_binary(issue_id) do
    store = read_store()

    case Map.get(store, issue_id) do
      %{"paused" => true, "signature_hash" => stored_hash} when is_binary(stored_hash) ->
        current_hash = signature_hash(blocked_signature(issue))

        if current_hash == stored_hash do
          true
        else
          clear_issue(issue)
          false
        end

      _ ->
        false
    end
  end

  def dispatch_paused?(_issue), do: false

  @spec blocked_signature(Issue.t()) :: map()
  def blocked_signature(%Issue{} = issue) do
    %{
      "issue_id" => issue.id,
      "issue_identifier" => issue.identifier,
      "current_status" => issue.state,
      "blocking_issue_ids" => blocking_issue_ids(issue),
      "blocking_issues" => blocking_issues(issue),
      "blocking_labels" => sorted_strings(issue.labels),
      "required_review_gates" => required_review_gates(issue),
      "open_pull_requests" => open_pull_requests(issue),
      "dependency_gates" => dependency_gates(issue)
    }
  end

  defp persist_blocked_audit(issue) do
    signature = blocked_signature(issue)
    signature_hash = signature_hash(signature)
    now = DateTime.utc_now() |> DateTime.to_iso8601()

    store = read_store()
    existing = Map.get(store, issue.id, %{})
    same_signature? = Map.get(existing, "signature_hash") == signature_hash
    count = if same_signature?, do: Map.get(existing, "same_blocked_audit_count", 0) + 1, else: 1
    notified_thresholds = if same_signature?, do: Map.get(existing, "notified_thresholds", []), else: []
    commented_thresholds = if same_signature?, do: Map.get(existing, "commented_thresholds", []), else: []
    paused = count >= thresholds().pause

    entry = %{
      "issue_id" => issue.id,
      "issue_identifier" => issue.identifier,
      "signature_hash" => signature_hash,
      "blocked_signature" => signature,
      "same_blocked_audit_count" => count,
      "paused" => paused,
      "notified_thresholds" => notified_thresholds,
      "commented_thresholds" => commented_thresholds,
      "last_audited_at" => now,
      "updated_at" => now
    }

    store = Map.put(store, issue.id, entry)

    with :ok <- write_store(store) do
      entry = maybe_handle_threshold(issue, entry)
      {:ok, result_from_entry(entry)}
    end
  end

  defp maybe_handle_threshold(issue, entry) do
    thresholds = thresholds()

    entry
    |> maybe_notify_threshold(issue, thresholds.pause, :pause)
    |> maybe_notify_threshold(issue, thresholds.anomaly, :anomaly)
  end

  defp maybe_notify_threshold(entry, issue, threshold, level)
       when is_integer(threshold) and threshold > 0 do
    count = Map.get(entry, "same_blocked_audit_count", 0)
    notified_thresholds = Map.get(entry, "notified_thresholds", [])
    commented_thresholds = Map.get(entry, "commented_thresholds", [])
    threshold_key = to_string(threshold)

    if count >= threshold and threshold_key not in notified_thresholds do
      entry =
        if threshold_key in commented_thresholds do
          entry
        else
          post_manager_summary(issue, entry, threshold, level)

          entry
          |> Map.put("commented_thresholds", Enum.uniq([threshold_key | commented_thresholds]))
          |> tap(&persist_entry(issue.id, &1))
        end

      slack_result = send_slack_alert(issue, entry, threshold, level)

      if slack_result == :ok do
        updated_entry = Map.put(entry, "notified_thresholds", Enum.uniq([threshold_key | notified_thresholds]))
        persist_entry(issue.id, updated_entry)
        updated_entry
      else
        entry
      end
    else
      entry
    end
  end

  defp post_manager_summary(issue, entry, threshold, level) do
    body = manager_summary(issue, entry, threshold, level)

    case SymphonyElixir.Tracker.create_comment(issue.id, body) do
      :ok ->
        :ok

      {:error, reason} ->
        Logger.warning("Failed to post blocked-audit manager summary issue_id=#{issue.id} threshold=#{threshold}: #{inspect(reason)}")
    end
  end

  defp send_slack_alert(issue, entry, threshold, level) do
    settings = Config.settings!()
    slack = settings.slack

    text = slack_alert_text(issue, entry, threshold, level, slack.manager_mention)

    case SlackNotifier.post_blocked_audit_alert(slack.blocked_audit_channel, text, slack.bot_token) do
      :ok ->
        :ok

      {:error, reason} ->
        Logger.warning("Failed to send blocked-audit Slack alert issue_id=#{issue.id} threshold=#{threshold}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp manager_summary(issue, entry, threshold, level) do
    signature = Map.get(entry, "blocked_signature", %{})
    count = Map.get(entry, "same_blocked_audit_count", 0)

    """
    ## Symphony Blocked-Audit Backoff

    Symphony observed #{count} unchanged blocked audits for #{issue.identifier || issue.id}.

    - Threshold: #{threshold}
    - Action: #{threshold_action(level)}
    - Blocked signature hash: `#{Map.get(entry, "signature_hash")}`
    - Current status: #{Map.get(signature, "current_status")}
    - Blockers: #{format_blocker_chain(signature)}
    - Required review gates: #{format_list(Map.get(signature, "required_review_gates", []))}
    - Open PRs: #{format_pull_requests(Map.get(signature, "open_pull_requests", []))}

    Continuations remain paused until the blocker signature changes or a manager explicitly overrides the pause.
    """
  end

  defp slack_alert_text(issue, entry, threshold, level, manager_mention) do
    signature = Map.get(entry, "blocked_signature", %{})
    count = Map.get(entry, "same_blocked_audit_count", 0)
    mention = normalize_manager_mention(manager_mention)

    """
    #{mention} *Symphony blocked-audit #{alert_title(level)}*
    Issue: #{issue.identifier || issue.id} — #{issue.title}
    URL: #{issue.url || "n/a"}
    Same blocked audits: #{count}
    Threshold: #{threshold}
    Status: #{Map.get(signature, "current_status")}
    Signature: `#{Map.get(entry, "signature_hash")}`
    Blocker chain: #{format_blocker_chain(signature)}
    Review gates: #{format_list(Map.get(signature, "required_review_gates", []))}
    Open PRs: #{format_pull_requests(Map.get(signature, "open_pull_requests", []))}
    Action: #{threshold_action(level)}
    """
  end

  defp threshold_action(:anomaly), do: "force manager review / workflow anomaly flag; keep continuations paused"
  defp threshold_action(:pause), do: "pause further continuations for this unchanged blocker signature"

  defp alert_title(:anomaly), do: "anomaly escalation"
  defp alert_title(:pause), do: "pause"

  defp normalize_manager_mention(mention) when is_binary(mention) do
    trimmed = String.trim(mention)

    cond do
      trimmed == "" -> "AJ Marz"
      String.starts_with?(trimmed, "<@") -> trimmed
      true -> "@#{String.trim_leading(trimmed, "@")}"
    end
  end

  defp persist_entry(issue_id, entry) do
    store = read_store()
    write_store(Map.put(store, issue_id, entry))
  end

  defp clear_issue(%Issue{id: issue_id}) when is_binary(issue_id) do
    store = read_store()

    if Map.has_key?(store, issue_id) do
      write_store(Map.delete(store, issue_id))
    else
      :ok
    end
  end

  defp blocked_audit_issue?(%Issue{} = issue) do
    issue.blocked_by != [] or
      blocking_labels(issue.labels) != [] or
      required_review_gates(issue) != [] or
      open_pull_requests(issue) != []
  end

  defp blocking_issue_ids(%Issue{blocked_by: blockers}) do
    blockers
    |> Enum.map(fn blocker -> Map.get(blocker, :identifier) || Map.get(blocker, "identifier") || Map.get(blocker, :id) || Map.get(blocker, "id") end)
    |> Enum.reject(&is_nil/1)
    |> sorted_strings()
  end

  defp blocking_issues(%Issue{blocked_by: blockers}) do
    blockers
    |> Enum.map(fn blocker ->
      %{
        "id" => Map.get(blocker, :id) || Map.get(blocker, "id"),
        "identifier" => Map.get(blocker, :identifier) || Map.get(blocker, "identifier"),
        "state" => Map.get(blocker, :state) || Map.get(blocker, "state"),
        "labels" => sorted_strings(Map.get(blocker, :labels) || Map.get(blocker, "labels") || [])
      }
    end)
    |> Enum.sort_by(&{to_string(&1["identifier"]), to_string(&1["id"])})
  end

  defp blocking_labels(labels) when is_list(labels) do
    labels
    |> Enum.filter(fn label ->
      normalized = normalize_label(label)
      normalized == "blocked" or String.starts_with?(normalized, "blocked:")
    end)
    |> sorted_strings()
  end

  defp blocking_labels(_labels), do: []

  defp required_review_gates(%Issue{labels: labels, blocked_by: blockers}) do
    own_gates = review_gate_labels(labels)

    blocker_gates =
      blockers
      |> Enum.flat_map(fn blocker -> Map.get(blocker, :labels) || Map.get(blocker, "labels") || [] end)
      |> review_gate_labels()

    sorted_strings(own_gates ++ blocker_gates)
  end

  defp review_gate_labels(labels) when is_list(labels) do
    labels
    |> Enum.map(&normalize_label/1)
    |> Enum.filter(&Regex.match?(@review_gate_pattern, &1))
  end

  defp review_gate_labels(_labels), do: []

  defp open_pull_requests(%Issue{pull_requests: pull_requests}) when is_list(pull_requests) do
    pull_requests
    |> Enum.map(fn pr ->
      %{
        "id" => Map.get(pr, :id) || Map.get(pr, "id"),
        "url" => Map.get(pr, :url) || Map.get(pr, "url"),
        "review_state" => Map.get(pr, :review_state) || Map.get(pr, "review_state") || "unknown"
      }
    end)
    |> Enum.sort_by(&to_string(&1["url"]))
  end

  defp open_pull_requests(_issue), do: []

  defp dependency_gates(%Issue{} = issue) do
    %{
      "branch_name" => issue.branch_name
    }
  end

  defp signature_hash(signature) do
    :crypto.hash(:sha256, Jason.encode!(signature))
    |> Base.encode16(case: :lower)
  end

  defp result_from_entry(entry) do
    %{
      decision: if(Map.get(entry, "paused") == true, do: :paused, else: :ready),
      same_blocked_audit_count: Map.get(entry, "same_blocked_audit_count", 0),
      blocked_signature: Map.get(entry, "blocked_signature"),
      signature_hash: Map.get(entry, "signature_hash")
    }
  end

  defp empty_result(decision) do
    %{decision: decision, same_blocked_audit_count: 0, blocked_signature: nil, signature_hash: nil}
  end

  defp thresholds do
    config = Config.settings!().blocked_audit
    %{pause: config.pause_threshold, anomaly: config.anomaly_threshold}
  end

  defp state_file do
    Config.settings!().blocked_audit.state_file
  end

  defp read_store do
    path = state_file()

    case File.read(path) do
      {:ok, content} ->
        case Jason.decode(content) do
          {:ok, store} when is_map(store) -> store
          _ -> %{}
        end

      {:error, :enoent} ->
        %{}

      {:error, reason} ->
        Logger.warning("Failed to read blocked-audit store path=#{path}: #{inspect(reason)}")
        %{}
    end
  end

  defp write_store(store) when is_map(store) do
    path = state_file()

    with :ok <- File.mkdir_p(Path.dirname(path)),
         :ok <- File.write(path, Jason.encode!(store, pretty: true) <> "\n") do
      :ok
    else
      {:error, reason} ->
        Logger.warning("Failed to write blocked-audit store path=#{path}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp format_blocker_chain(%{"blocking_issues" => blockers}) when is_list(blockers) and blockers != [] do
    Enum.map_join(blockers, " -> ", fn blocker ->
      identifier = blocker["identifier"] || blocker["id"] || "unknown"
      state = blocker["state"] || "unknown"
      labels = format_list(blocker["labels"] || [])
      "#{identifier} (#{state}; labels #{labels})"
    end)
  end

  defp format_blocker_chain(_signature), do: "none recorded"

  defp format_pull_requests(prs) when is_list(prs) and prs != [] do
    Enum.map_join(prs, ", ", fn pr ->
      "#{pr["url"] || pr["id"] || "unknown"} (review: #{pr["review_state"] || "unknown"})"
    end)
  end

  defp format_pull_requests(_prs), do: "none recorded"

  defp format_list(values) when is_list(values) and values != [], do: Enum.join(values, ", ")
  defp format_list(_values), do: "none"

  defp sorted_strings(values) when is_list(values) do
    values
    |> Enum.map(&to_string/1)
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.uniq()
    |> Enum.sort()
  end

  defp sorted_strings(_values), do: []

  defp normalize_label(label) when is_binary(label) do
    label
    |> String.trim()
    |> String.downcase()
  end

  defp normalize_label(label), do: label |> to_string() |> normalize_label()
end
