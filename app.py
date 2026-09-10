"""NOSY application entry point. Run with: streamlit run app.py"""
from backend.pipeline import start_pipeline
from frontend.dashboard import render

render(start_pipeline())
