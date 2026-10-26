#!/usr/bin/env python3
"""Contract-authored event/action scenarios, not snapshots of implementation output."""
import json
from pathlib import Path

MIB = 1024 * 1024
CONSTANTS = {
    "UPLOAD_COMMIT_SLOTS_SMALL": 2,
    "UPLOAD_COMMIT_SLOTS_LARGE": 1,
    "UPLOAD_COMMIT_SLOTS_SMALL_BELOW": 16 * MIB,
    "UPLOAD_PUT_LANES": 1,
    "UPLOAD_FILE_CONCURRENCY_DEFAULT": 4,
    "UPLOAD_FILE_CONCURRENCY_MAX": 8,
    "UPLOAD_TAIL_FILES_MAX": 4,
    "UPLOAD_API_REQUESTS_PER_SECOND_MAX": 60,
    "UPLOAD_API_BURST": 20,
}


def a(kind, **kw):
    return {"kind": kind, **kw}


ACCEPT = a("accept")
RELEASE = a("release_lane")
COMPLETE = a("complete")
IDLE = a("idle")
PRODUCER = a("give_up", reason=a("producer"))
USE_API = a("give_up", reason=a("use_api"))


def grant(i, digest=None):
    return a("grant", index=i, digest=digest)


def wait(t, kind):
    return a("wait", until_ms=t, wait_kind=kind)


def event(kind, i=None, **kw):
    return a(kind, **({"index": i} if i is not None else {}), **kw)


def step(e, *actions, now=0, retained=None, done=None):
    s = {"now_ms": now, "event": e, "expect": list(actions) or [IDLE], "done": (any(x.get("kind") == "give_up" for x in actions) if done is None else done)}
    if retained is not None:
        s["retained"] = retained
    return s


def start(n=1, digest=None, length=28):
    return [step(event("tick"), ACCEPT, retained=0),
            step(event("chunk_produced", 0, len=length, digest=digest), grant(0, digest),
                 *([ACCEPT] if n > 1 else []), retained=1)]


def putting(n=1, digest=None):
    return start(n, digest) + [step(event("grant_ok", 0), a("put", index=0), retained=1)]


def committing(n=1, digest=None):
    return putting(n, digest) + [step(event("put_done", 0), a("commit", index=0),
                                     *([RELEASE] if n == 1 else []), retained=1)]


def refused(i=0, status=429, after=5000, outstanding=True):
    return event("grant_refused", i, status=status,
                 outcome=a("backoff", after_ms=after), commits_outstanding=outstanding)


def commit_fail(i=0, status=503, kind="backoff", **kw):
    return event("commit_failed", i, status=status, outcome=a(kind, **({"status":status} if kind=="terminal" else {}), **kw))


def scenarios():
    rows = []
    def add(name, steps, n=1, size=4*MIB, version="v1", lengths=None, policy=None, source="§6; §3.3"):
        row = {"name": name, "source": "task 2173 pipelining design " + source,
               "chunk_size_bytes": size, "chunk_lens": lengths if lengths is not None else [28]*n,
               "version": version, "steps": steps}
        if policy:
            row["policy"] = policy
        rows.append(row)

    add("serial_chunk_flows_in_order", committing() + [step(event("commit_done", 0), COMPLETE, retained=0, done=True)])
    add("zero_byte_file_is_one_chunk_through_the_pipeline", committing() + [step(event("commit_done", 0), COMPLETE, retained=0, done=True)], source="I-P18; §6")
    add("commit_overlaps_next_grant", committing(2) + [step(event("chunk_produced", 1, len=28, digest=None), grant(1), retained=2)], n=2)
    add("grant_waits_for_free_lane", putting(2) + [step(event("chunk_produced", 1, len=28, digest=None), retained=2), step(event("put_done", 0), a("commit", index=0), grant(1), retained=2)], n=2, source="I-P2; §3.3 rule 1")
    two = committing(3) + [step(event("chunk_produced", 1, len=28, digest=None), grant(1), ACCEPT, retained=2), step(event("grant_ok", 1), a("put", index=1)), step(event("put_done", 1), a("commit", index=1))]
    add("second_commit_slot_under_16mib", two, n=3)
    one = committing(3) + [step(event("chunk_produced", 1, len=28, digest=None), grant(1), retained=2), step(event("grant_ok", 1), a("put", index=1)), step(event("put_done", 1), retained=2), step(event("commit_done", 0), a("commit", index=1), ACCEPT, retained=1)]
    add("one_commit_slot_from_16mib", one, n=3, size=16*MIB)
    add("a_short_tail_chunk_keeps_the_files_slot_count", one, n=3, size=32*MIB, source="§3.4; I-P6")
    bounded = two + [step(event("chunk_produced", 2, len=28, digest=None), grant(2), retained=3), step(event("grant_ok", 2), a("put", index=2)), step(event("put_done", 2), retained=3), step(event("tick"), retained=3)]
    add("retained_never_exceeds_one_plus_slots", bounded, n=4, source="I-P6; §3.4")
    add("accept_is_emitted_only_when_the_retention_rule_admits", bounded, n=4, source="I-P20; §3.3 rule 12")
    add("grant_skipped_marks_stored_without_put_or_commit", start() + [step(event("grant_skipped", 0), RELEASE, COMPLETE, retained=0, done=True)], source="I-P4; §6")
    staged_two = committing(2) + [step(event("chunk_produced", 1, len=28, digest=None), grant(1)), step(event("grant_ok", 1), a("put", index=1))]
    regrant = staged_two + [step(commit_fail(kind="regrant", status=409)), step(event("put_done", 1), a("commit", index=1), grant(0))]
    add("commit_409_regrants_at_front_and_is_not_an_ack", regrant, n=2)
    hold = staged_two + [step(commit_fail(status=409, kind="held", after_ms=5000), wait(5000, {"hold":0})), step(event("put_done", 1), a("commit", index=1), RELEASE)]
    add("held_commit_does_not_block_later_commits", hold, n=2)
    add("hold_wait_is_not_a_gate", hold, n=2, source="I-P8; §6")
    add("complete_waits_for_held_chunk", hold + [step(event("commit_done", 1), retained=1), step(event("tick"), a("commit", index=0), now=5000), step(event("commit_done", 0), COMPLETE, now=5001, retained=0, done=True)], n=2, source="I-P1; §6")
    add("a_held_commit_keeps_the_only_large_slot", hold[:-1] + [step(event("put_done", 1)), step(event("tick"), a("commit", index=0), now=5000), step(event("commit_done", 0), a("commit", index=1), RELEASE, now=5001)], n=2, size=32*MIB)
    first = start() + [step(refused(), a("await_ack", index=0)), step(event("ack"), grant(0), now=1000)]
    add("first_grant_429_awaits_ack_then_asks_again", first, source="I-P7; §3.3 rule 5")
    add("second_grant_429_is_a_counted_stated_wait_and_closes_the_gate", first + [step(refused(after=300000), wait(121000, "gate"), now=1000), step(event("tick"), grant(0), now=121000)])
    add("grant_429_without_commit_outstanding_waits_stated_time_clamped_120s", start() + [step(refused(after=300000, outstanding=False), wait(120000,"gate")), step(event("tick"), now=119999), step(event("tick"), grant(0), now=120000)])
    add("ack_wait_budget_exhausted_falls_to_the_normal_path", start() + [step(refused(), a("await_ack",index=0)), step(event("tick"), wait(155000,"gate"), now=150000), step(event("tick"), grant(0), now=155000)])
    add("a_tick_does_not_end_an_ack_wait_but_an_ack_does", start() + [step(refused(),a("await_ack",index=0)), step(event("tick"), now=1000), step(event("ack"), grant(0), now=1001)], source="§3.3 rule 5; F4")
    add("a_503_grant_waits_and_does_not_await_an_ack", start() + [step(refused(status=503),wait(5000,"gate")),step(event("tick"),grant(0),now=5000)])
    add("commit_429_closes_the_gate_not_the_commit_path", staged_two + [step(commit_fail(status=429,after_ms=5000),wait(5000,"gate")),step(event("put_done",1),a("commit",index=1),RELEASE),step(event("tick"),a("commit",index=0),now=5000)],n=2)
    add("commit_503_waits_only_its_chunk", staged_two + [step(commit_fail(after_ms=5000),wait(5000,{"chunk":0})),step(event("put_done",1),a("commit",index=1),RELEASE)],n=2)
    add("a_stated_gate_holds_only_new_grants", committing(2) + [step(commit_fail(status=429,after_ms=5000),wait(5000,"gate")),step(event("chunk_produced",1,len=28,digest=None)),step(event("tick"),a("commit",index=0),grant(1),now=5000)],n=2)
    add("v2_put_412_goes_straight_to_commit", putting(digest=[7]*16)+[step(event("put_already_there",0),a("commit",index=0),RELEASE)],version="v2")
    # A v1 412 follows the existing policy: first seed-0 equal-jitter backoff is 791 ms.
    add("v1_put_412_is_a_failed_put",putting()+[step(event("put_already_there",0),wait(791,{"chunk":0})),step(event("tick"),grant(0),now=791)])
    add("storage_403_expiry_gets_a_new_grant",putting()+[step(event("put_failed",0,status=403),wait(791,{"chunk":0})),step(event("tick"),grant(0),now=791)])
    add("a_network_put_error_gets_a_new_grant",putting()+[step(event("put_failed",0,status=0),wait(791,{"chunk":0}))])
    add("v2_bad_digest_is_a_counted_failure",putting(digest=[7]*16)+[step(event("put_failed",0,status=400),wait(791,{"chunk":0}))],version="v2")
    add("give_up_from_commit_cancels_put_in_flight",staged_two+[step(commit_fail(kind="api_for_this_file",status=409),a("cancel",index=1),USE_API)],n=2,source="I-P5; §3.3 rule 10")
    for status in (401,403):
        add(f"terminal_{status}_is_not_use_api",staged_two+[step(commit_fail(kind="terminal",status=status,error="refused"),a("cancel",index=1),a("give_up",reason=a("terminal",status=status,error="refused")))],n=2)
    add("session_gone_is_its_own_give_up",putting()+[step(event("session_gone"),a("cancel",index=0),a("give_up",reason=a("session_gone")))])
    add("producer_error_is_not_an_api_give_up",putting()+[step(event("producer_failed"),a("cancel",index=0),PRODUCER)])
    add("interrupt_cancels_the_inflight_put",putting()+[step(event("interrupt"),a("cancel",index=0),done=True),step(event("put_done",0),done=True)])
    add("interrupt_commits_every_staged_chunk_once",one[:-1]+[step(event("interrupt")),step(event("commit_done",0),a("commit",index=1)),step(event("commit_done",1),done=True),step(event("tick"),done=True)],n=3,size=32*MIB)
    add("interrupt_does_not_poll_an_already_held_commit",committing()+[step(commit_fail(status=409,kind="held",after_ms=5000),wait(5000,{"hold":0})),step(event("interrupt"),done=True),step(event("tick"),now=5000,done=True)])
    add("interrupt_before_start_admits_nothing",[step(event("interrupt"),done=True),step(event("tick"),done=True)])
    digest = committing(digest=[7]*16)+[step(commit_fail(kind="regrant",status=409),grant(0,[7]*16)),step(event("grant_ok",0),a("put",index=0)),step(event("put_done",0),a("commit",index=0),RELEASE)]
    add("digest_travels_with_regrant",digest,version="v2",source="I-P3; §3.5")
    add("release_lane_after_the_last_put_and_not_before",committing(),source="I-P19; §3.3 rule 11")
    add("release_lane_after_a_skipped_last_grant",start()+[step(event("grant_skipped",0),RELEASE,COMPLETE,done=True)],source="I-P19; §3.3 rule 11")
    add("release_lane_again_after_a_tail_regrant",digest,version="v2",source="I-P19; §3.3 rule 11")
    add("a_second_chunk_produced_for_an_index_is_a_producer_give_up",putting()+[step(event("chunk_produced",0,len=28,digest=None),a("cancel",index=0),PRODUCER)])
    add("a_changed_digest_on_a_regrant_is_a_producer_give_up",digest[:5]+[step(event("chunk_produced",0,len=28,digest=[8]*16),PRODUCER)],version="v2",source="I-P3; F9")
    add("a_chunk_shorter_than_the_plan_is_a_producer_give_up_before_any_grant",[step(event("tick"),ACCEPT),step(event("chunk_produced",0,len=27,digest=None),PRODUCER)],source="§6; F7")
    add("an_out_of_range_chunk_is_a_producer_give_up",[step(event("tick"),ACCEPT),step(event("chunk_produced",99,len=28,digest=None),PRODUCER)])
    add("an_out_of_order_chunk_is_a_producer_give_up",[step(event("tick"),ACCEPT),step(event("chunk_produced",1,len=28,digest=None),PRODUCER)],n=2)
    add("produce_requires_an_accept_permit",[step(event("chunk_produced",0,len=28,digest=None),PRODUCER)])
    add("a_v2_chunk_without_a_digest_is_a_producer_give_up",[step(event("tick"),ACCEPT),step(event("chunk_produced",0,len=28,digest=None),PRODUCER)],version="v2")
    add("a_tick_does_not_duplicate_accept",[step(event("tick"),ACCEPT),step(event("tick")),step(event("tick"))])
    add("a_completed_plan_is_inert",committing()+[step(event("commit_done",0),COMPLETE,done=True),step(event("tick"),done=True),step(event("interrupt"),done=True)])
    add("a_give_up_is_emitted_once",start()+[step(event("grant_refused",0,status=409,outcome=a("api_for_this_file"),commits_outstanding=False),USE_API,done=True),step(event("tick"),done=True)])
    add("an_empty_chunk_plan_is_refused",[step(event("tick"),PRODUCER,done=True)],lengths=[])
    add("a_plan_with_a_zero_ciphertext_length_is_refused",[step(event("tick"),PRODUCER,done=True)],lengths=[0])
    add("grant_401_is_terminal",start()+[step(event("grant_refused",0,status=401,outcome=a("terminal",status=401,error=None),commits_outstanding=False),a("give_up",reason=a("terminal",status=401,error=None)),done=True)])
    add("ack_wait_ignores_chunk_not_stored",staged_two[:-1]+[step(refused(1),a("await_ack",index=1)),step(commit_fail(status=409,kind="regrant")),step(event("tick"),now=1000)],n=2)
    # Independent chunks have independent failure/hold allowances, using deterministic stated waits.
    independent=staged_two+[step(event("put_done",1),a("commit",index=1),RELEASE)]
    for i in range(7):
        independent += [step(commit_fail(0,after_ms=1000),wait((i+1)*1000,{"chunk":0}),now=i*1000),step(event("tick"),a("commit",index=0),now=(i+1)*1000)]
    independent += [step(event("commit_done",0),now=7000),step(commit_fail(1,after_ms=1000),wait(8000,{"chunk":1}),now=7000),step(event("tick"),a("commit",index=1),now=8000),step(event("commit_done",1),COMPLETE,done=True,now=8001)]
    add("seven_failures_of_one_chunk_do_not_spend_another_chunks_budget",independent,n=2)
    add("the_eighth_failure_ends_the_chunk",independent[:-4]+[step(commit_fail(0,after_ms=1000),USE_API,done=True,now=7000)],n=2)
    add("a_hold_does_not_spend_the_failure_allowance",committing()+[step(commit_fail(status=409,kind="held",after_ms=5000),wait(5000,{"hold":0})),step(event("tick"),a("commit",index=0),now=5000),step(commit_fail(after_ms=1000),wait(6000,{"chunk":0}),now=5000),step(event("tick"),a("commit",index=0),now=6000),step(event("commit_done",0),COMPLETE,done=True,now=6001)],policy={"attempts":2})
    add("a_hold_keeps_the_next_grant_open",committing(2)+[step(commit_fail(status=409,kind="held",after_ms=5000),wait(5000,{"hold":0})),step(event("chunk_produced",1,len=28,digest=None),grant(1))],n=2)
    add("a_503_commit_keeps_the_next_grant_open",committing(2)+[step(commit_fail(after_ms=5000),wait(5000,{"chunk":0})),step(event("chunk_produced",1,len=28,digest=None),grant(1))],n=2)
    priority=putting(3)+[step(event("chunk_produced",1,len=28,digest=None),ACCEPT),step(event("put_done",0),a("commit",index=0),grant(1)),step(event("chunk_produced",2,len=28,digest=None)),step(event("grant_ok",1),a("put",index=1)),step(commit_fail(status=409,kind="regrant")),step(event("put_done",1),a("commit",index=1),grant(0))]
    add("regrant_goes_before_a_queued_unsent_chunk",priority,n=3)
    add("two_commit_waits_do_not_hold_each_other_with_the_gate",staged_two+[step(event("put_done",1),a("commit",index=1),RELEASE),step(commit_fail(status=429,after_ms=5000),wait(5000,"gate")),step(commit_fail(1,status=429,after_ms=10000),wait(10000,"gate")),step(event("tick"),a("commit",index=0),now=5000)],n=2)
    from jitter_port import Sim
    sim=Sim(0)
    capped=putting()
    now=0
    for i in range(3):
        now+=sim.failure()
        capped += [step(event("put_failed",0,status=403),wait(now,{"chunk":0}),now=capped[-1]["now_ms"]),step(event("tick"),grant(0),now=now),step(event("grant_ok",0),a("put",index=0),now=now)]
    capped+=[step(event("put_failed",0,status=403),USE_API,now=now)]
    add("four_grants_are_the_bound_even_before_eight_failures",capped)
    add("the_counted_wait_budget_is_bounded",committing()+[step(commit_fail(after_ms=120000),wait(120000,{"chunk":0})),step(event("tick"),a("commit",index=0),now=120000),step(commit_fail(after_ms=120000),USE_API,now=120000)])
    add("a_second_interrupt_does_not_resend_a_commit",committing()+[step(event("interrupt")),step(event("interrupt")),step(event("commit_done",0),done=True)])
    assert len(rows) >= 45
    assert len({r['name'] for r in rows}) == len(rows)
    return rows


def vectors():
    rows = scenarios()
    return {"source":"task 2173 pipelining design sections 3.3, 3.4, 4, 5, 6, 8", "constants":CONSTANTS, "scenario_count":len(rows), "scenarios":rows}


if __name__ == "__main__":
    (Path(__file__).resolve().parents[1]/"direct_upload_pipeline.json").write_text(json.dumps(vectors(),indent=2)+"\n")
