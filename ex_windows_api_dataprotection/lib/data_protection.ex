defmodule Windows.API.DataProtection do
  @moduledoc """
  Documentation for `Windows.API.DataProtection`.
  """

  @doc """
  Hello world.

  ## Examples

      iex> Windows.API.DataProtection.hello()
      :world

  """
  def hello do
    :world
  end

  @doc """  
  Wraps a binary for the given user.
  """
  def wrap(binary) when is_binary(binary) do
    Windows.API.DataProtection.Native.nif_wrap(binary)
  end

  @doc """  
  Unwraps a binary for the given user.
  
  ## Examples

      iex> "some confidential input value"
      ...> |> Windows.API.DataProtection.wrap()
      ...> |> Windows.API.DataProtection.unwrap()
      "some confidential input value"

  """
  def unwrap(binary) when is_binary(binary) do
    Windows.API.DataProtection.Native.nif_unwrap(binary)
  end
end