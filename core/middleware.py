class PrintHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        print(request.headers)
        print('thisis it')
        return self.get_response(request)
