Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFPLWKMAMGQEZR7EPZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 249135A4C3D
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Aug 2022 14:48:22 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id v67-20020a1cac46000000b003a615c4893dsf5026132wme.3
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Aug 2022 05:48:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661777301; cv=pass;
        d=google.com; s=arc-20160816;
        b=iy2PnwFLRVw2sPAWYvgKlA2Xk/088QeWFpNqHJhGeG1J5nKgklgYvGNL2c0jgyUbrq
         sKDA8z4BFPxd+CBiTPwV3b15Gfez7cBUlwfW3Rm0pPKy6MCG8oaQOmT+MamwZGum+OJ0
         GZrPEbb92RW0MjDwEENtT7t3Uk1vdWFgXIcCELuoJ2MrSXGSTo2NPV4ZFkWa4vOaiMl+
         wLa/rlMxS0aMJCoM6w25OquDzvpEFyYZ/9EYNRUqkcQ+nLtRXJLT3hngNM+HwzVGqfcS
         kwASCnA+ALMGMN9R89TPf0s6RoQ6+TIfvzmcLrUW8QjSWesznaBl8ytg3/XaeyK3Ue7N
         hirQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Szc4cbnuNlZo6/mh5k3rhb/BtHPUG+CXjAQ8Z453w34=;
        b=yIp1mS+zw8BiqP4Pnv8rXU0GTj1rTYmW9oUuJr23wEFhe8nRQeChCeq1ZWfetjMV8g
         KPfUFsqj4wxcM+PqTnaSdVUKn2QK/xlPWq0lVq11x5DZWLHwrPNXkkOE0JBl5qUc5V6x
         hfjBvSGnO19g1BEQy7gZH6Ma1xV7IWPhKg5yPeWqlfN9EPHv9c3iLTfdPJc1ljpQ0qRZ
         2YJGL4rAv+fHrOvWod5/KiIkX3LFLzafSkKei7Iktez7kc2nMRJzpUtITE5HoAHwOWbe
         M/eycXX9CCiiQ3BMYWsuwrtqk8SRMvBavdbUySvZr7BJXSmAClApbv5l2gRRlIyigAW8
         ZGGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="W7W/4jDz";
       spf=pass (google.com: domain of 3llumywukcvex4exaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3lLUMYwUKCVEx4ExAz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=Szc4cbnuNlZo6/mh5k3rhb/BtHPUG+CXjAQ8Z453w34=;
        b=NcY5JVWy+RCQYrDor4L19TZgjy5EwPcXlmnR/ZsLMgKHbTiZhAw2jceXyBtGhtUISf
         ucgjIP29fuNkyE9mzjCPodOtigtqjIxul8UhqmL49MEoz3GdVYpn2zK+OeazO+bkPn3Q
         0i1ALPZ6eK+9h480y0S5eENoIUE29RW+5V/VumS4oo++kTT0MJjeLI8kLTBSFqTJdp5M
         CvgASx2U1JyKKIKEmd7eyXBAbN6KWWZXU/ip7s4g8wx/dbm+Jt/klKfy1ESRuNAfd1RF
         p0eivY3wVliJFdShicaJnQSBU0iAyMdLa7pa2cDLjAAoD6J0U7qGzKIgWvSYhJ9XhExd
         FqOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=Szc4cbnuNlZo6/mh5k3rhb/BtHPUG+CXjAQ8Z453w34=;
        b=kvRhwUJ8tNUncxiYAzlsHWGLLZAnNgVuOf3MmBQOLN/YbqJkWpumKYcC9NBiLyPb/l
         gyGxFBp2hgzr7YLw5IPNW58HZLbFwwBRzttRSr8xHn1STqxLzgwDSn8hP1vcSOuZKKOB
         AAwdq7itms35Cv1DxmTWVQdLXMkw6pkxr+SxbeS/SrW62slfEFm7vsiRQ2p9NYErNVUx
         P9ydNX4WJx505XUF/Ny3qiR6F2OcvRnKvfl2HIVFsbeWbgEu2fp7Op7oo2ViVIpvgOwY
         meBmmiu3ZVcnniN0r+HHPOTpqTYGJ3ZBO/PYZyhKl3X1VQTVEDo98DiGr9NNd7P7IQru
         2KvA==
X-Gm-Message-State: ACgBeo390cDE7A2+LXmRcu4VonHVLZj8JlgNKueYV18dCmbFnm1wHTAD
	arIWTJsS33thh5MzOhhOc9s=
X-Google-Smtp-Source: AA6agR5S3sRFcmZldBHxtDf20Sop0hRcnBUg6vWWvqYxlRxPsLccnuCRPxmIjtqo0NxU/GcV+TTzbQ==
X-Received: by 2002:a5d:5644:0:b0:225:3ae9:e4c3 with SMTP id j4-20020a5d5644000000b002253ae9e4c3mr6107118wrw.148.1661777301741;
        Mon, 29 Aug 2022 05:48:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:251:b0:221:24a2:5cf with SMTP id
 m17-20020a056000025100b0022124a205cfls1692616wrz.0.-pod-prod-gmail; Mon, 29
 Aug 2022 05:48:20 -0700 (PDT)
X-Received: by 2002:adf:f592:0:b0:225:2f5e:6a99 with SMTP id f18-20020adff592000000b002252f5e6a99mr6621268wro.593.1661777300543;
        Mon, 29 Aug 2022 05:48:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661777300; cv=none;
        d=google.com; s=arc-20160816;
        b=qveOs98rfTrXdbXhYZ2kkLHHmmHKJthQqrB0dyLDHhfS6+sOZsuqMryPUkVNZvhtx/
         RuyQB0C+f2s1QxWATTo1j4c2ul+8FcRo9ZqT/DEfBstxRHCzqFPPU7WuJuSaGrw4DwrS
         v/nsi8yNQW3ciXDe/+DBN3nC/wYPXf4lh5oe0iDg+17Rz71+9/Pc+KfOMDDRualRQg16
         mTcW41PkQL1Gd1cy77aoyzdVl/cATOT4E6xTUW6UuGIgUnCpS3NPpjawLQA+1u5CONid
         5v7TOSZwe+u6LxKQgBD5urSJAJb9Bh/+YyJdR9kQcQVF7QJLBKQwfXtZMIi6vsieBWxW
         kcKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=mMk84n4RwXUmdOHQie4vTMaJ1dE0ku+oL7Yd7vDc1Ps=;
        b=SOc6nrj8hTRnWEo5wwMFYssafAwNRZtnI02VlUrRox8hsZ4iLI7DMHt+yNL6xc3kgb
         6PNQKy6Vlyddrt92zNnWQwW0XRxuX9Ud20OrNCB0HZqIHIC6u0Z+axgoYnz4rvxxPdkG
         sf1RRMz7sSewQNqj1JIXHNoQ877RCW8WjvgMxYQr5YBLRhDd3YGYH5WYL8s7m4Mr+iT8
         DirTUwDFB8hZO3ZWzx6fplgh6SRaesv40B13ulXZ+ccwF7JMtX+Oz2OQPKBXffQiWDBl
         9/dZk0KGLqvYr4b/0B2EU4+gPiFBGRIYFIRy3aFWCvzUchzw21kV/z5yQz4AApdSs3Zz
         GZnA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="W7W/4jDz";
       spf=pass (google.com: domain of 3llumywukcvex4exaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3lLUMYwUKCVEx4ExAz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id b15-20020a05600003cf00b0021f15aa1a8esi219405wrg.8.2022.08.29.05.48.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Aug 2022 05:48:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3llumywukcvex4exaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id gb33-20020a170907962100b00741496e2da1so1256473ejc.1
        for <kasan-dev@googlegroups.com>; Mon, 29 Aug 2022 05:48:20 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:196d:4fc7:fa9c:62e3])
 (user=elver job=sendgmr) by 2002:a05:6402:5024:b0:440:e4ad:f7b6 with SMTP id
 p36-20020a056402502400b00440e4adf7b6mr16547207eda.358.1661777300281; Mon, 29
 Aug 2022 05:48:20 -0700 (PDT)
Date: Mon, 29 Aug 2022 14:47:13 +0200
In-Reply-To: <20220829124719.675715-1-elver@google.com>
Mime-Version: 1.0
References: <20220829124719.675715-1-elver@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220829124719.675715-9-elver@google.com>
Subject: [PATCH v4 08/14] perf/hw_breakpoint: Remove useless code related to
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
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Ian Rogers <irogers@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="W7W/4jDz";       spf=pass
 (google.com: domain of 3llumywukcvex4exaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3lLUMYwUKCVEx4ExAz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--elver.bounces.google.com;
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
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Acked-by: Ian Rogers <irogers@google.com>
---
v2:
* Also remove struct bp_busy_slots, and simplify functions.
---
 kernel/events/hw_breakpoint.c | 57 +++++++++++------------------------
 1 file changed, 17 insertions(+), 40 deletions(-)

diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
index 9c9bf17666a5..8b40fca1a063 100644
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
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220829124719.675715-9-elver%40google.com.
