import asyncio
import signal
import sys
from collectors.data_collector import DataCollector
from analyzers.analyzer import AnalyzerEngine
from alerts.alert_handler import AlertHandler

async def main():
    print("Starting Simple IDS...")
    
    # Initialize components
    collector = DataCollector()
    analyzer = AnalyzerEngine(collector)
    alert_handler = AlertHandler()
    
    # Setup signal handlers for graceful shutdown
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(shutdown(collector, analyzer)))
        
    # Start collection and analysis tasks
    collection_task = asyncio.create_task(collector.collect_all_data())
    analysis_task = asyncio.create_task(analyzer.start_analysis())
    
    # Wait for tasks to complete (they shouldn't unless cancelled)
    try:
        await asyncio.gather(collection_task, analysis_task)
    except asyncio.CancelledError:
        print("Tasks cancelled, shutting down...")
    
async def shutdown(collector, analyzer):
    print("\nShutdown initiated...")
    await collector.cleanup()
    await analyzer.cleanup()
    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    for task in tasks:
        task.cancel()
    sys.exit(0)

if __name__ == "__main__":
    asyncio.run(main())

