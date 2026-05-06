defmodule SymphonyElixir.SlackNotifier do
  @moduledoc """
  Sends operator alerts to Slack.
  """

  require Logger

  @slack_post_message_url "https://slack.com/api/chat.postMessage"

  @spec post_blocked_audit_alert(String.t(), String.t(), String.t()) :: :ok | {:error, term()}
  def post_blocked_audit_alert(channel, text, token)
      when is_binary(channel) and is_binary(text) and is_binary(token) do
    payload = %{channel: channel, text: text, mrkdwn: true}
    request_fun = Application.get_env(:symphony_elixir, :slack_request_fun, &Req.post/2)

    case request_fun.(
           @slack_post_message_url,
           headers: [{"Authorization", "Bearer #{token}"}, {"Content-Type", "application/json"}],
           json: payload,
           connect_options: [timeout: 30_000]
         ) do
      {:ok, %{status: 200, body: %{"ok" => true}}} ->
        :ok

      {:ok, %{status: 200, body: %{"ok" => false, "error" => error}}} ->
        {:error, {:slack_api_error, error}}

      {:ok, %{status: status, body: body}} ->
        {:error, {:slack_status, status, body}}

      {:error, reason} ->
        {:error, {:slack_request_failed, reason}}
    end
  end

  def post_blocked_audit_alert(_channel, _text, token) when token in [nil, ""] do
    Logger.warning("Skipping blocked-audit Slack alert because slack.bot_token/SLACK_BOT_TOKEN is not configured")
    {:error, :missing_slack_bot_token}
  end
end
