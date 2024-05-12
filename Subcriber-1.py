import time
from cyclonedds.domain import DomainParticipant
from cyclonedds.topic import Topic
from cyclonedds.sub import Subscriber, DataReader
from SpeedModule import _SpeedData

def receive_speed():
    # Initialize DomainParticipant
    participant = DomainParticipant()

    # Create a Topic
    topic = Topic(participant, "SpeedTopic", _SpeedData.SpeedData)

    # Create a Subscriber and DataReader
    subscriber = Subscriber(participant)
    reader = DataReader(subscriber, topic)

    try:
        while True:
            # Take the data
            data_seq = reader.take()
            
            # Print received data
            for data in data_seq:
                print(f"Received Speed: {data.speed:.2f} km/h")
                
            # Sleep for a short time before the next read
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("Subscription stopped.")
    finally:
        # Clean up DDS entities
        participant.delete_contained_entities()

if __name__ == "__main__":
    receive_speed()
