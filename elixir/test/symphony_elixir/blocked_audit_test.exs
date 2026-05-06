defmodule SymphonyElixir.BlockedAuditTest do
  use SymphonyElixir.TestSupport

  alias SymphonyElixir.BlockedAudit
  alias SymphonyElixir.SlackNotifier

  test "unchanged blocked signatures pause at threshold and dedupe alerts" do
    state_file = Path.join(System.tmp_dir!(), "blocked-audit-#{System.unique_integer([:positive])}.json")
    Application.put_env(:symphony_elixir, :memory_tracker_recipient, self())

    write_workflow_file!(Workflow.workflow_file_path(),
      tracker_kind: "memory",
      blocked_audit_pause_threshold: 2,
      blocked_audit_anomaly_threshold: 3,
      blocked_audit_state_file: state_file
    )

    issue = blocked_issue()

    assert {:ok, %{decision: :ready, same_blocked_audit_count: 1}} = BlockedAudit.evaluate_issue(issue)
    assert {:ok, %{decision: :paused, same_blocked_audit_count: 2}} = BlockedAudit.evaluate_issue(issue)

    assert_receive {:memory_tracker_comment, "issue-1", pause_comment}, 1_000
    assert pause_comment =~ "Symphony Blocked-Audit Backoff"
    assert pause_comment =~ "Threshold: 2"
    assert pause_comment =~ "pause further continuations"

    assert {:ok, %{decision: :paused, same_blocked_audit_count: 3}} = BlockedAudit.evaluate_issue(issue)

    assert_receive {:memory_tracker_comment, "issue-1", anomaly_comment}, 1_000
    assert anomaly_comment =~ "Threshold: 3"
    assert anomaly_comment =~ "force manager review"

    assert {:ok, %{decision: :paused, same_blocked_audit_count: 4}} = BlockedAudit.evaluate_issue(issue)
    refute_receive {:memory_tracker_comment, "issue-1", _body}, 100

    store = state_file |> File.read!() |> Jason.decode!()
    entry = store["issue-1"]
    assert entry["paused"] == true
    assert entry["notified_thresholds"] == ["3", "2"]
    assert entry["blocked_signature"]["blocking_issue_ids"] == ["DRE-475"]
    assert [%{"review_state" => "CHANGES_REQUESTED"}] = entry["blocked_signature"]["open_pull_requests"]
  end

  test "dispatch pause clears when the blocked signature changes" do
    state_file = Path.join(System.tmp_dir!(), "blocked-audit-change-#{System.unique_integer([:positive])}.json")

    write_workflow_file!(Workflow.workflow_file_path(),
      tracker_kind: "memory",
      blocked_audit_pause_threshold: 1,
      blocked_audit_anomaly_threshold: 2,
      blocked_audit_state_file: state_file
    )

    issue = blocked_issue()

    assert {:ok, %{decision: :paused}} = BlockedAudit.evaluate_issue(issue)
    assert BlockedAudit.dispatch_paused?(issue)

    changed_issue = %{issue | blocked_by: [%{id: "blocker-2", identifier: "DRE-476", state: "Done", labels: []}]}
    refute BlockedAudit.dispatch_paused?(changed_issue)

    store = state_file |> File.read!() |> Jason.decode!()
    refute Map.has_key?(store, "issue-1")
  end

  test "non-blocked issues clear persisted audit metadata" do
    state_file = Path.join(System.tmp_dir!(), "blocked-audit-clear-#{System.unique_integer([:positive])}.json")

    write_workflow_file!(Workflow.workflow_file_path(),
      tracker_kind: "memory",
      blocked_audit_pause_threshold: 1,
      blocked_audit_state_file: state_file
    )

    issue = blocked_issue()
    assert {:ok, %{decision: :paused}} = BlockedAudit.evaluate_issue(issue)

    unblocked_issue = %{issue | labels: [], blocked_by: [], pull_requests: []}
    assert {:ok, %{decision: :not_blocked}} = BlockedAudit.evaluate_issue(unblocked_issue)

    store = state_file |> File.read!() |> Jason.decode!()
    refute Map.has_key?(store, "issue-1")
  end

  test "dispatch pause and signature helpers handle fallback shapes" do
    state_file = Path.join(System.tmp_dir!(), "blocked-audit-fallback-#{System.unique_integer([:positive])}.json")

    write_workflow_file!(Workflow.workflow_file_path(),
      tracker_kind: "memory",
      blocked_audit_pause_threshold: 1,
      blocked_audit_state_file: state_file
    )

    refute BlockedAudit.dispatch_paused?(:not_an_issue)

    label_blocked_issue = %Issue{
      id: "issue-label",
      identifier: "DRE-Label",
      title: "Label blocked",
      state: "In Progress",
      labels: ["blocked:external", 123],
      blocked_by: [],
      pull_requests: []
    }

    assert {:ok, %{decision: :paused}} = BlockedAudit.evaluate_issue(label_blocked_issue)

    refute match?(
             {:ok, %{decision: :paused}},
             BlockedAudit.evaluate_issue(%{label_blocked_issue | id: "issue-nil-labels", labels: nil})
           )

    fallback_signature =
      BlockedAudit.blocked_signature(%Issue{
        id: "issue-fallback",
        identifier: "DRE-Fallback",
        title: "Fallbacks",
        state: "In Progress",
        labels: nil,
        blocked_by: [%{id: "blocker-without-labels", identifier: nil, state: nil, labels: nil}],
        pull_requests: nil
      })

    assert fallback_signature["blocking_issue_ids"] == ["blocker-without-labels"]
    assert fallback_signature["blocking_labels"] == []
    assert fallback_signature["required_review_gates"] == []
    assert fallback_signature["open_pull_requests"] == []
  end

  test "invalid persisted audit JSON is treated as an empty store" do
    state_file = Path.join(System.tmp_dir!(), "blocked-audit-invalid-#{System.unique_integer([:positive])}.json")
    File.write!(state_file, "not json")

    write_workflow_file!(Workflow.workflow_file_path(),
      tracker_kind: "memory",
      blocked_audit_pause_threshold: 1,
      blocked_audit_state_file: state_file
    )

    assert {:ok, %{decision: :paused}} = BlockedAudit.evaluate_issue(blocked_issue())
  end

  test "read/write failures and tracker comment failures are surfaced without crashing threshold handling" do
    state_dir = Path.join(System.tmp_dir!(), "blocked-audit-dir-#{System.unique_integer([:positive])}")
    File.mkdir_p!(state_dir)

    write_workflow_file!(Workflow.workflow_file_path(),
      tracker_kind: "memory",
      blocked_audit_state_file: state_dir
    )

    assert {:error, :eisdir} = BlockedAudit.evaluate_issue(blocked_issue())

    state_file = Path.join(System.tmp_dir!(), "blocked-audit-comment-error-#{System.unique_integer([:positive])}.json")
    Application.put_env(:symphony_elixir, :linear_client_module, __MODULE__.FailingLinearClient)

    Application.put_env(:symphony_elixir, :slack_request_fun, fn _url, _opts ->
      {:ok, %{status: 200, body: %{"ok" => true}}}
    end)

    on_exit(fn ->
      Application.delete_env(:symphony_elixir, :linear_client_module)
      Application.delete_env(:symphony_elixir, :slack_request_fun)
    end)

    write_workflow_file!(Workflow.workflow_file_path(),
      tracker_kind: "linear",
      tracker_api_token: "token",
      blocked_audit_pause_threshold: 1,
      blocked_audit_state_file: state_file,
      slack_bot_token: "token",
      slack_manager_mention: ""
    )

    assert {:ok, %{decision: :paused}} = BlockedAudit.evaluate_issue(blocked_issue())
  end

  test "slack notifier maps Slack API responses" do
    on_exit(fn -> Application.delete_env(:symphony_elixir, :slack_request_fun) end)

    Application.put_env(:symphony_elixir, :slack_request_fun, fn _url, _opts ->
      {:ok, %{status: 200, body: %{"ok" => true}}}
    end)

    assert :ok = SlackNotifier.post_blocked_audit_alert("C0ADCCYAY2V", "hello", "token")

    Application.put_env(:symphony_elixir, :slack_request_fun, fn _url, _opts ->
      {:ok, %{status: 200, body: %{"ok" => false, "error" => "channel_not_found"}}}
    end)

    assert {:error, {:slack_api_error, "channel_not_found"}} =
             SlackNotifier.post_blocked_audit_alert("C0ADCCYAY2V", "hello", "token")

    Application.put_env(:symphony_elixir, :slack_request_fun, fn _url, _opts ->
      {:ok, %{status: 500, body: "oops"}}
    end)

    assert {:error, {:slack_status, 500, "oops"}} =
             SlackNotifier.post_blocked_audit_alert("C0ADCCYAY2V", "hello", "token")

    Application.put_env(:symphony_elixir, :slack_request_fun, fn _url, _opts ->
      {:error, :closed}
    end)

    assert {:error, {:slack_request_failed, :closed}} =
             SlackNotifier.post_blocked_audit_alert("C0ADCCYAY2V", "hello", "token")
  end

  defp blocked_issue do
    %Issue{
      id: "issue-1",
      identifier: "DRE-465",
      title: "Continuation audit",
      state: "In Progress",
      url: "https://linear.example/DRE-465",
      labels: ["blocked", "needs-security-review"],
      blocked_by: [%{id: "blocker-1", identifier: "DRE-475", state: "Human Review", labels: ["needs-security-review"]}],
      pull_requests: [
        %{
          id: "pr-16",
          url: "https://github.com/dreamydrawphx/westside/pull/16",
          review_state: "CHANGES_REQUESTED"
        }
      ],
      updated_at: ~U[2026-05-05 23:58:00Z]
    }
  end

  defmodule FailingLinearClient do
    @moduledoc false

    def graphql(_query, _variables), do: {:error, :comment_failed}
  end
end
