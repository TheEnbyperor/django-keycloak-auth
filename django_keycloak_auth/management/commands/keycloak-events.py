import pika
import json
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Processes RabbitMQ events from Keycloak"

    def handle(self, *args, **options):
        parameters = pika.URLParameters(settings.RABBITMQ_RPC_URL)
        connection = pika.BlockingConnection(parameters=parameters)
        channel = connection.channel()

        queue_result = channel.queue_declare('', exclusive=True)
        callback_queue = queue_result.method.queue

        channel.basic_qos(prefetch_count=1)
        channel.basic_consume(callback_queue, self.on_response, auto_ack=True)

        channel.queue_bind(
            exchange='keycloak',
            queue=callback_queue,
            routing_key="KK.EVENT.CLIENT.master.SUCCESS.account.#"
        )

        print("RPC handler now running")
        try:
            channel.start_consuming()
        except (KeyboardInterrupt, SystemExit):
            print("Exiting...")
            return

    def on_response(self, _ch, _method, _props, body):
        self.handle_keycloak_event(body)

    @staticmethod
    def handle_keycloak_event(event_json: str):
        user_model = get_user_model()
        email_field_name = user_model.get_email_field_name()

        data = json.loads(event_json)

        if data.get("type") == "UPDATE_PROFILE":
            user_id = data.get("userId")
            user = user_model.objects.filter(username=user_id).first()
            if not user:
                return

            new_email = data["details"].get("updated_email")
            new_first_name = data["details"].get("updated_first_name")
            new_last_name = data["details"].get("updated_last_name")

            if new_email:
                setattr(user, email_field_name, new_email)
            if new_first_name:
                user.first_name = new_first_name
            if new_last_name:
                user.last_name = new_last_name

            user.save()
