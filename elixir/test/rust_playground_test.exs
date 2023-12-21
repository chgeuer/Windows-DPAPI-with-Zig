defmodule RustPlaygroundTest do
  use ExUnit.Case
  doctest RustPlayground

  test "greets the world" do
    assert RustPlayground.hello() == :world
  end
end
