from typing import Optional, Dict, Any, List
from contextlib import contextmanager
from neo4j import GraphDatabase, Driver
from app.core.config import settings
from app.core.logging import logger

class Neo4jConnection:
    _instance: Optional["Neo4jConnection"] = None
    _driver: Optional[Driver] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Neo4jConnection, cls).__new__(cls)
        return cls._instance

    def connect(self) -> Optional[Driver]:
        if self._driver is None:
            try:
                logger.info(f"Connecting to Neo4j database at {settings.NEO4J_URI}...")
                self._driver = GraphDatabase.driver(
                    settings.NEO4J_URI,
                    auth=(settings.NEO4J_USERNAME, settings.NEO4J_PASSWORD)
                )
                logger.info("Successfully initialized Neo4j driver.")
            except Exception as e:
                logger.error(f"Failed to connect to Neo4j database: {str(e)}")
                self._driver = None
        return self._driver

    def verify_connectivity(self) -> bool:
        driver = self.connect()
        if not driver:
            return False
        try:
            driver.verify_connectivity()
            logger.info("Neo4j connectivity verified.")
            return True
        except Exception as e:
            logger.warning(f"Neo4j connectivity check failed: {str(e)}")
            return False

    def query(self, cypher_query: str, parameters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        driver = self.connect()
        if not driver:
            raise RuntimeError("Neo4j driver is not connected.")
        
        with driver.session(database=settings.NEO4J_DATABASE) as session:
            result = session.run(cypher_query, parameters or {})
            return [record.data() for record in result]

    @contextmanager
    def transaction(self):
        """
        Provides an ACID transactional context manager on the active Neo4j database.
        Commits automatically on successful block exit; rolls back completely on any exception.
        """
        driver = self.connect()
        if not driver:
            raise RuntimeError("Neo4j driver is not connected.")
        with driver.session(database=settings.NEO4J_DATABASE) as session:
            with session.begin_transaction() as tx:
                yield tx
                tx.commit()

    def close(self):
        if self._driver:
            self._driver.close()
            self._driver = None
            logger.info("Closed Neo4j connection driver.")

neo4j_conn = Neo4jConnection()
