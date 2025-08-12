class WebApp:
    def build_profile_html(self, name: str, bio: str) -> str:
        # SOURCE: `name`, `bio` are user-controlled
        # PROPAGATOR: tainted values formatted into HTML
        return f"<div class='card'><h2>{name}</h2><p>{bio}</p></div>"

    def render_profile(self, name: str, bio: str) -> str:
        html = self.build_profile_html(name, bio)  # PROPAGATOR
        return html  # SINK: response body sent to client

def profile_response(name: str, bio: str) -> str:
    # SOURCE: `name`, `bio` come from user input
    app = WebApp()
    return app.render_profile(name, bio)  # SINK: unescaped HTML
