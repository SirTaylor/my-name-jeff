"""Python API Practice"""
import requests

API_KEY = '48b516a69e2838ae96634614d49c50b1'

# Example: OpenWeatherMap API endpoint for current weather
API_URL = 'http://api.openweathermap.org/data/2.5/weather'


def get_weather(city):
    ''' Request the weather of a search city '''
        # Specify parameters for the API call
    params = {
        'q': city,
        'units': 'imperial',  # You can adjust the units based on your preference
        'appid': API_KEY
    }

    try:
        # Make the API call
        response = requests.get(API_URL, params=params, timeout=15)
        data = response.json()

        # Extract relevant information from the API response
        weather_data = {
            'city': data['name'],
            'description': data['weather'][0]['description'],
            'temperature': data['main']['temp'],
            'humidity': data['main']['humidity']
        }

        return weather_data

    except requests.exceptions.RequestException as e:
        # Handle API request errors
        print(f"Error making API request: {e}")
        return None
