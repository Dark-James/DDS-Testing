import time
import random
from cyclonedds.domain import DomainParticipant
from cyclonedds.topic import Topic
from cyclonedds.pub import Publisher, DataWriter
from SpeedModule import _SpeedData

def publish_speed():
    # Initialize DomainParticipant
    participant = DomainParticipant()

    # Create a Topic
    topic = Topic(participant, "SpeedTopic", _SpeedData.SpeedData)

    # Create a Publisher and DataWriter
    publisher = Publisher(participant)
    writer = DataWriter(publisher, topic)

    try:
        while True:
            # Generate a random speed value
            speed_value = random.uniform(0, 120)
            
            # Create a SpeedData instance with the random speed value
            speed_data = _SpeedData.SpeedData(speed_value)
            
            # Write the data
            writer.write(speed_data)
            
            # Print the published value
            print(f"Published Speed: {speed_data.speed:.2f} km/h")

            # Sleep for 1 second
            time.sleep(1)
    except KeyboardInterrupt:
        print("Publishing stopped.")
    finally:
        # Clean up DDS entities
        participant.delete_contained_entities()

if __name__ == "__main__":
    publish_speed()
