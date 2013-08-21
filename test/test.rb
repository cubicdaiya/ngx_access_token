require "minitest/autorun"
require "net/empty_port"
require "net/http"

class TestNginxAccessToken < MiniTest::Test
    def setup
      @dir = File.dirname(File.expand_path(__FILE__))
      nginx_bin     = ENV['NGINX_BIN']
      nginx_options = " -p #{@dir}/ngx_base/ -c #{@dir}/ngx_base/etc/nginx.conf"
      `sudo #{nginx_bin} #{nginx_options}`
      Net::EmptyPort.wait(8000, 10)
    end

    def get(path)
      url = URI.parse('http://localhost:8000')
      res = Net::HTTP.start(url.host, url.port) {|http|
        http.get(path)
      }
      yield res
    end

    def test_acl_ok
      # This test is available until 2018/08/04 for expires
      get('/index.html?AccessKey=bokko&Expires=1533240048&Signature=CUz9G4lke6JbS+Z9ovfJEJECcFQ=') { |res|
        assert_equal(res.code, "200")
      }
    end

    def test_acl_ng
      get('/index.html?AccessKey=bokko&Expires=1375558147&Signature=YYMK4Xu8wdrTf2QrZa5PaZ0GqsA=') { |res|
        assert_equal(res.code, "403")
      }
    end

    def test_invalid_access_key
      get('/index.html?AccessKey=bokkko&Expires=1533240048&Signature=Y24uOnb+AWSlmvppucOWE3AbhDc=') { |res|
        assert_equal(res.code, "403")
      }
    end

    def teardown
      `sudo pkill nginx`
    end
end
