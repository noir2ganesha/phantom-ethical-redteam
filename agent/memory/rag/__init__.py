"""RAG memory subsystem — attack memory, strategy memory, and search fusion.

Requires PostgreSQL with pgvector for full functionality.
Degrades gracefully when database is unavailable.

Optional modules (gtfobins_db, lolbas_db, hacktricks_loader, knowledge_loader)
are not imported by default — they require additional data files.
"""
