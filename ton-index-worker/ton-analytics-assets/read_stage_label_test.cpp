// Offline standalone test: compile this file with a C++20 compiler and run it.
// No NodeDB, TON headers, shared scanner or production binary is involved.
#define TON_ASSETS_STAGE_LABEL_ONLY
#include "main.cpp"

#include <cassert>

int main() {
  using assets_analytics::ReadStage;
  using assets_analytics::read_stage_label;
  assert(read_stage_label(ReadStage::SecondaryCatchUp) == "secondary_catch_up");
  assert(read_stage_label(ReadStage::McZeroHandle) == "mc0_handle_lookup");
  assert(read_stage_label(ReadStage::FetchMc, 90051907) == "fetch_mc_seqno_90051907");
  assert(read_stage_label(ReadStage::FetchMc, 90051908) == "fetch_mc_seqno_90051908");
  assert(read_stage_label(ReadStage::FetchMc, 0) == "fetch_mc_seqno_0");
}
