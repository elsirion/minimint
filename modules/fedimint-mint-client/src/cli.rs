use std::iter::once;
use std::time::Duration;
use std::{ffi, iter};

use anyhow::bail;
use clap::Parser;
use fedimint_client::module::ClientModule;
use futures::future::join_all;
use futures::StreamExt;
use serde::Serialize;
use tracing::{error, info};

use crate::{MintClientModule, OOBNotes, ReissueExternalNotesState, SelectNotesWithAtleastAmount};

#[derive(Parser, Serialize)]
enum Opts {
    /// Reissue out of band notes
    Reissue {
        notes: OOBNotes,
    },
    StressTest,
}

pub(crate) async fn handle_cli_command(
    mint: &MintClientModule,
    args: &[ffi::OsString],
) -> anyhow::Result<serde_json::Value> {
    let opts = Opts::parse_from(iter::once(&ffi::OsString::from("mint")).chain(args.iter()));

    match opts {
        Opts::Reissue { notes } => {
            let amount = notes.total_amount();

            let operation_id = mint.reissue_external_notes(notes, ()).await?;

            let mut updates = mint
                .subscribe_reissue_external_notes(operation_id)
                .await
                .unwrap()
                .into_stream();

            while let Some(update) = updates.next().await {
                if let ReissueExternalNotesState::Failed(e) = update {
                    bail!("Reissue failed: {e}");
                }
            }

            Ok(serde_json::to_value(amount).expect("JSON serialization failed"))
        }
        Opts::StressTest => {
            let total_amount = mint
                .get_balance(&mut mint.client_ctx.module_db().begin_transaction_nc().await)
                .await;
            let (_operation_id, notes) = mint
                .spend_notes_with_selector(
                    &SelectNotesWithAtleastAmount,
                    total_amount,
                    Duration::from_secs(3600),
                    false,
                    (),
                )
                .await?;

            let mut update_streams = vec![];
            for (amount, &note) in notes.notes().iter_items() {
                let operation_id = mint
                    .reissue_external_notes(
                        OOBNotes::new(notes.federation_id_prefix(), once((amount, note)).collect()),
                        (),
                    )
                    .await?;

                let updates = mint.subscribe_reissue_external_notes(operation_id).await?;
                update_streams.push(Box::pin(async move {
                    let mut stream = updates.into_stream();
                    while let Some(update) = stream.next().await {
                        info!(?operation_id, ?update, "Reissue update");
                        if let ReissueExternalNotesState::Failed(e) = update {
                            error!("Reissue failed: {e}");
                        }
                    }
                }));
            }

            join_all(update_streams).await;

            Ok(serde_json::Value::Null)
        }
    }
}
