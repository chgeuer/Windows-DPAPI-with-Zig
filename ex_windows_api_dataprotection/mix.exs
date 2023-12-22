defmodule Windows.API.DataProtection.MixProject do
  use Mix.Project

  def project do
    [
      app: :ex_windows_api_dataprotection_rustler,
      version: "0.1.0",
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: []
    ]
  end

  defp deps do
    [
       {:rustler, "~> 0.30.0", runtime: false}
    ]
  end
end
