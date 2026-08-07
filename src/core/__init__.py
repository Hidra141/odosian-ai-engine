"""Core engine layer.

Internal engine of the ODOSIAN AI Engine. Owns the engine, the pipeline, the
workflows and the operation dispatcher.

Analyze, enhance and generate are workflows rather than separate modules. They
share a single pipeline; the requested operation determines only which prompt
and which execution mode are used.
"""
