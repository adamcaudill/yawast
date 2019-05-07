require File.dirname(__FILE__) + '/../lib/yawast'
require File.dirname(__FILE__) + '/base'

class TestAppFWRails < Minitest::Test
  include TestBase

  def test_check_cve_2019_5418
    override_stdout

    port = rand(60000) + 1024 # pick a random port number
    server = start_web_server File.dirname(__FILE__) + '/data/etc_passwd.txt', '', port
    uri = Yawast::Commands::Utils.extract_uri(["http://localhost:#{port}"])

    error = nil
    begin
      Yawast::Scanner::Plugins::Applications::Framework::Rails.check_cve_2019_5418 [uri.to_s]
    rescue => e
      error = e.message
    end

    assert !stdout_value.include?('[W]'), "Unexpected finding: #{stdout_value}"
    assert error == nil, "Unexpected error: #{error}"

    restore_stdout

    server.exit
  end
end