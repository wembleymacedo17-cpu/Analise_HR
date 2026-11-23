from contextlib import contextmanager
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session


class TransacaoService:
    """
    Gestor centralizado de transações ACID para o SQLAlchemy.
    Garante commit automático em sucesso, rollback em erro e suporte a SAVEPOINT.
    """

    @staticmethod
    @contextmanager
    def gerenciar(db_session: Session, nested: bool = False):
        if nested or db_session.in_transaction():
            transacao = db_session.begin_nested()
        else:
            transacao = db_session.begin()

        try:
            yield db_session
            if transacao.is_active:
                db_session.commit()
        except SQLAlchemyError as e:
            if transacao.is_active:
                db_session.rollback()
            print(f"❌ [TRANSAÇÃO - SQL ERROR] Rollback executado: {e}")
            raise
        except Exception as e:
            if transacao.is_active:
                db_session.rollback()
            print(f"❌ [TRANSAÇÃO - ERRO] Rollback executado: {e}")
            raise