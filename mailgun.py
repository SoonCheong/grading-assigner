import requests

def send_email(subject, content):
    return requests.post(
        "https://api.mailgun.net/v3/sandbox324fab6d78cc49c6babc319197f9975e.mailgun.org/messages",
        auth=("api", "key-7fe98dedb4579c6689173ffee8767ab9"),
        data={"from": "Sooner AI <postmaster@sandbox324fab6d78cc49c6babc319197f9975e.mailgun.org>",
              "to": "Soon Yau Cheong <soonyau@gmail.com>",
              "subject": subject,
              "text": content})

if __name__ == "__main__":
    send_email("hello","ni hao ma")
