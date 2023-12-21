defmodule RustPlayground.MixProject do
  use Mix.Project

  def project do
    [
      app: :rust_playground,
      version: "0.1.0",
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
       {:rustler, "~> 0.30.0", runtime: false}
    ]
  end
end
