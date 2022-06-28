Return-Path: <kasan-dev+bncBC7OBJGL2MHBB55B5OKQMGQEZICEOPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id BBFE155BFF9
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 11:59:24 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id z11-20020a05600c0a0b00b003a043991610sf4526096wmp.8
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 02:59:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656410359; cv=pass;
        d=google.com; s=arc-20160816;
        b=LT01LLlK+2CdwxSaDYTFj5ibsD8z1Dg39taj3b83aFpe76IzqgtXgFtbMMwlGp+Zdr
         rZ9cojSCjB/6lDqkbz1GLHkaD0KtE21eXXjYnhKNRx4N3VUvIQnV+g2SLiZNEI+h3qh3
         eudNE8Q3RmqxIWDxMfdc1Iaseytsysqa6iPJa5kuLVqJ70D8gSm1dpNg7+v7HYNtNIwm
         zJZIU4QCh4vM28mjbTyUKnroC0+cQP/qetXTNEcEg2pokjTTzRzHZBJ4pAPsn17SY5fK
         YcbHntPnnQVwW9YzuxLkgj0xxoL03L8yHW6tLpfe1WzechRi4zmM+bbs3jMjpjuJy7p4
         ZTcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=0kWMxjO0ExeuXzvnnnXmJ85AH4ekj1E1RNHmo9tQe+w=;
        b=DeIVx27ZxdBgndoXveNjuxrl44YkwyxYppgATPLLgD6o8hWET0yr1Krsjs8PSMMXby
         M5qiOWnRy7Rnxn8Mi0f7HK0k1S6wYfcV9QfA64ahPDrxflfuRw2ghFWaHjZtSGOaa3L4
         x+MaoRYsyBcQ0ZPs/t5jHotQ+2xxTF989cao9iYWcLO6o7E/3IMI2CCJCSrTfyoAKyE4
         k07q8GgCgpjPOKePLXqtgcvblkcbgA3VpTXZx707fCYzfJ0JQpvs5wx2jpEqkmOUBWT+
         ZSsijhQRfFADk6MVcGv6EuRIquJT4ceTmRwS277QfE9f/RHKKaPfSIg0rJCkxspUDOJY
         rizw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=A0dgUThU;
       spf=pass (google.com: domain of 39dc6ygukcz4cjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=39dC6YgUKCZ4CJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0kWMxjO0ExeuXzvnnnXmJ85AH4ekj1E1RNHmo9tQe+w=;
        b=mrx3lSfBzrOFMxq9wLV1Em8j2fkMj9DUCCGuSs3Hvt4lsv5L7/m54Bcvpry6l/U7TP
         jTa501tOEvi4alcgWfLp6z/opmTMk7wkzULpmfOG8CsulEY5h0GqR9gNBCSwWAoJG9xl
         9qocwqPsdeym9RNbxWGUMc7/pKqjskdKa+8VX1OIHTL+egVus4gZCFBA0X/6Ptc2+RDm
         wMO+SFmFoDfWW2smWe3/kIHDCgwLxTyKMQ5m21OoXBuJW7uqutb37d+W6l5bDNcyEqGh
         2+3C41Ly8HTXHGmI9DN+XeLOL96VRPwqtz88MLVXhDJjYrb4qPICKsDyJSAlZRbtglZq
         11Wg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0kWMxjO0ExeuXzvnnnXmJ85AH4ekj1E1RNHmo9tQe+w=;
        b=QbSJCSsxzVyy9yf7H9Oau3uWslcxxymI22Mc+ORUWfYMdSzJuBiybYnpJCCJsC1vkk
         FyRlRAUY1cx7C71N26yydowH25vEzJV3+3aMGJ0umNc+h1z0QwRZkrxWwsnW7ZInVJuf
         J0sPJKV4/ej6bJAO4V0Y6savf6Sau+1PY/WnYJ8ECjll2u/GvYrLlcviEd2Lf6omuRIN
         ZtTvcp2lr41GlsnYs5DKlSSRsfutoqbWcXz1WaKZdgnGFXpACdSHksPrF6uTe6Znq1xZ
         sUdqbbvXxVceh8qkedjpkp94VoIVY5U5BZJqWG5HV3J7Zn0ENBUfbznqG+ohHujToT8I
         STSg==
X-Gm-Message-State: AJIora/6eKJSIXM+VrErlWX9CTmtOfcpwYF82UPGBXQliBdQvfCgaaA4
	Ar31u8367P86VOVbqygy9qc=
X-Google-Smtp-Source: AGRyM1vc5jNYikr5eAs0LNtGXF0/Tn4a4XVZaLc/QojEXJG9jAbx+o6uZWslEjaZ7hsMbWDSriXF2Q==
X-Received: by 2002:a05:6000:11d1:b0:21b:8e53:bf02 with SMTP id i17-20020a05600011d100b0021b8e53bf02mr17460311wrx.131.1656410359410;
        Tue, 28 Jun 2022 02:59:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6dab:0:b0:212:d9db:a98 with SMTP id u11-20020a5d6dab000000b00212d9db0a98ls31074000wrs.3.gmail;
 Tue, 28 Jun 2022 02:59:18 -0700 (PDT)
X-Received: by 2002:adf:fd07:0:b0:21a:3917:cf7a with SMTP id e7-20020adffd07000000b0021a3917cf7amr17010267wrr.239.1656410358196;
        Tue, 28 Jun 2022 02:59:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656410358; cv=none;
        d=google.com; s=arc-20160816;
        b=G5FysJwS3GDZr7gAAOAgIPfHMT7ZJCJqbkt9K6SOOnHBW0gcci2l4DN8xHClYa5kLC
         QuRfyHK8WUb/oSm3YMe4FlhepyB1xgtYzY4pwCjy5SktbowF4VGiV4TPRx5tXrSV0hq8
         TCltJ4ObOFwMB1Buqii3YDKBWu45L6OqFJyWTJV0BwxtWyEgUYdobq+HKZkRw1yPSXgL
         hwmHQo7hUb628TZB+GKNA07Hn3oF5Z7f4cAo9S7Z/wIGVfclXGMNawdU+wRdCO7hgrBj
         7Xg8gmJ80NTs20kdEciNcfAxsw3CPxM7RY3ya8jvFRnO6KwZL9IrKmUlkaBwuA44NGFB
         uN6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=/0VhMmtwvDisaf1/VFeOhEr7O2fqwRDhX2jxpYNVTBM=;
        b=GZhBDxL7/NKnTL2hs/5kQTGfum7H2j1JjNBTpN1FaahLXk/uL9UiAqewSZ3Yms58dZ
         ShYNF9oj4PYCo5Xn6NsSu1lx04ZWBFImiyWX1PKEyshxkq3vNmkvM6vQw0TuawljqMVy
         YylA3yr38wi4rOxpz0GDIE8gAS5QnnnFM2n7DSYu5rEN/0ywZVhQ723GZH0txlVRs6tk
         917u2/XadjOaBPCdIjjk94PutXUm4J7kEOoSaGHUjjSp+xuAxrLlRBvIDFoHUom5dSlP
         J0o9IKVIdGXld7bQwttKNuH17ciTA8o3FmQ7IOUvwvWnFBCT6hY8l7kSM76Wc+G/PO96
         DvyQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=A0dgUThU;
       spf=pass (google.com: domain of 39dc6ygukcz4cjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=39dC6YgUKCZ4CJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id m7-20020adffa07000000b0021a07a20517si436452wrr.7.2022.06.28.02.59.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jun 2022 02:59:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of 39dc6ygukcz4cjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id 7-20020a170906310700b007263068d531so3422130ejx.15
        for <kasan-dev@googlegroups.com>; Tue, 28 Jun 2022 02:59:18 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:3496:744e:315a:b41b])
 (user=elver job=sendgmr) by 2002:a17:906:e4c:b0:726:94a0:2701 with SMTP id
 q12-20020a1709060e4c00b0072694a02701mr12840911eji.360.1656410357809; Tue, 28
 Jun 2022 02:59:17 -0700 (PDT)
Date: Tue, 28 Jun 2022 11:58:27 +0200
In-Reply-To: <20220628095833.2579903-1-elver@google.com>
Message-Id: <20220628095833.2579903-8-elver@google.com>
Mime-Version: 1.0
References: <20220628095833.2579903-1-elver@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v2 07/13] perf/hw_breakpoint: Remove useless code related to
 flexible breakpoints
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Frederic Weisbecker <frederic@kernel.org>, Ingo Molnar <mingo@kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=A0dgUThU;       spf=pass
 (google.com: domain of 39dc6ygukcz4cjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=39dC6YgUKCZ4CJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

Flexible breakpoints have never been implemented, with
bp_cpuinfo::flexible always being 0. Unfortunately, they still occupy 4
bytes in each bp_cpuinfo and bp_busy_slots, as well as computing the max
flexible count in fetch_bp_busy_slots().

This again causes suboptimal code generation, when we always know that
`!!slots.flexible` will be 0.

Just get rid of the flexible "placeholder" and remove all real code
related to it. Make a note in the comment related to the constraints
algorithm but don't remove them from the algorithm, so that if in future
flexible breakpoints need supporting, it should be trivial to revive
them (along with reverting this change).

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Also remove struct bp_busy_slots, and simplify functions.
---
 kernel/events/hw_breakpoint.c | 57 +++++++++++------------------------
 1 file changed, 17 insertions(+), 40 deletions(-)

diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
index a124786e3ade..63e39dc836bd 100644
--- a/kernel/events/hw_breakpoint.c
+++ b/kernel/events/hw_breakpoint.c
@@ -45,8 +45,6 @@ struct bp_cpuinfo {
 #else
 	unsigned int	*tsk_pinned;
 #endif
-	/* Number of non-pinned cpu/task breakpoints in a cpu */
-	unsigned int	flexible; /* XXX: placeholder, see fetch_this_slot() */
 };
 
 static DEFINE_PER_CPU(struct bp_cpuinfo, bp_cpuinfo[TYPE_MAX]);
@@ -67,12 +65,6 @@ static const struct rhashtable_params task_bps_ht_params = {
 
 static bool constraints_initialized __ro_after_init;
 
-/* Gather the number of total pinned and un-pinned bp in a cpuset */
-struct bp_busy_slots {
-	unsigned int pinned;
-	unsigned int flexible;
-};
-
 /* Serialize accesses to the above constraints */
 static DEFINE_MUTEX(nr_bp_mutex);
 
@@ -190,14 +182,14 @@ static const struct cpumask *cpumask_of_bp(struct perf_event *bp)
 }
 
 /*
- * Report the number of pinned/un-pinned breakpoints we have in
- * a given cpu (cpu > -1) or in all of them (cpu = -1).
+ * Returns the max pinned breakpoint slots in a given
+ * CPU (cpu > -1) or across all of them (cpu = -1).
  */
-static void
-fetch_bp_busy_slots(struct bp_busy_slots *slots, struct perf_event *bp,
-		    enum bp_type_idx type)
+static int
+max_bp_pinned_slots(struct perf_event *bp, enum bp_type_idx type)
 {
 	const struct cpumask *cpumask = cpumask_of_bp(bp);
+	int pinned_slots = 0;
 	int cpu;
 
 	for_each_cpu(cpu, cpumask) {
@@ -210,24 +202,10 @@ fetch_bp_busy_slots(struct bp_busy_slots *slots, struct perf_event *bp,
 		else
 			nr += task_bp_pinned(cpu, bp, type);
 
-		if (nr > slots->pinned)
-			slots->pinned = nr;
-
-		nr = info->flexible;
-		if (nr > slots->flexible)
-			slots->flexible = nr;
+		pinned_slots = max(nr, pinned_slots);
 	}
-}
 
-/*
- * For now, continue to consider flexible as pinned, until we can
- * ensure no flexible event can ever be scheduled before a pinned event
- * in a same cpu.
- */
-static void
-fetch_this_slot(struct bp_busy_slots *slots, int weight)
-{
-	slots->pinned += weight;
+	return pinned_slots;
 }
 
 /*
@@ -298,7 +276,12 @@ __weak void arch_unregister_hw_breakpoint(struct perf_event *bp)
 }
 
 /*
- * Constraints to check before allowing this new breakpoint counter:
+ * Constraints to check before allowing this new breakpoint counter.
+ *
+ * Note: Flexible breakpoints are currently unimplemented, but outlined in the
+ * below algorithm for completeness.  The implementation treats flexible as
+ * pinned due to no guarantee that we currently always schedule flexible events
+ * before a pinned event in a same CPU.
  *
  *  == Non-pinned counter == (Considered as pinned for now)
  *
@@ -340,8 +323,8 @@ __weak void arch_unregister_hw_breakpoint(struct perf_event *bp)
  */
 static int __reserve_bp_slot(struct perf_event *bp, u64 bp_type)
 {
-	struct bp_busy_slots slots = {0};
 	enum bp_type_idx type;
+	int max_pinned_slots;
 	int weight;
 	int ret;
 
@@ -357,15 +340,9 @@ static int __reserve_bp_slot(struct perf_event *bp, u64 bp_type)
 	type = find_slot_idx(bp_type);
 	weight = hw_breakpoint_weight(bp);
 
-	fetch_bp_busy_slots(&slots, bp, type);
-	/*
-	 * Simulate the addition of this breakpoint to the constraints
-	 * and see the result.
-	 */
-	fetch_this_slot(&slots, weight);
-
-	/* Flexible counters need to keep at least one slot */
-	if (slots.pinned + (!!slots.flexible) > hw_breakpoint_slots_cached(type))
+	/* Check if this new breakpoint can be satisfied across all CPUs. */
+	max_pinned_slots = max_bp_pinned_slots(bp, type) + weight;
+	if (max_pinned_slots > hw_breakpoint_slots_cached(type))
 		return -ENOSPC;
 
 	ret = arch_reserve_bp_slot(bp);
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220628095833.2579903-8-elver%40google.com.
