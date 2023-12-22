defmodule Windows.API.DataProtection.Native do
  use Rustler, otp_app: :ex_windows_api_dataprotection_rustler, crate: "ex_windows_api_dataprotection_rustler"

  def nif_wrap(_cleartext_bytes), do: :erlang.nif_error(:nif_not_loaded)

  def nif_unwrap(_ciphertext_bytes), do: :erlang.nif_error(:nif_not_loaded)
end
