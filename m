Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIPLWKMAMGQET23LGMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id B948E5A4C46
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Aug 2022 14:48:38 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id k13-20020a2ea28d000000b00261d461fad4sf1891958lja.23
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Aug 2022 05:48:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661777313; cv=pass;
        d=google.com; s=arc-20160816;
        b=Om8brEwdJEBQvRDHYH0UDTOz/hPbra5BbhJNYda0vKwhnzQlKCwL0BG0RFlqlUGGdz
         lnF90R2LiDCaEP8ZX6058UyOkG+IOSSNhhdFpa1XLxh2qKfCwteg429UyZWI9+fC/j1u
         uZnVRR3JVU3IUT14gx2Ru13vu50VZ6TuhzLS1OHhCpd4jc6vYAu0oUq4ub/i/DTY5qZK
         kk3iWUnNUiOLmnFqRpbhcwX47zyxIqgUIiwKuB6aFEeKMqZxxfjXlWpWfbmJ+nx14C2o
         wvpZpCh7LQsYsdLekwgtpPwgwccZF3jZvw/aecp86xUzypw7XKJwYBSxcxj3ZuFfMbdz
         uA9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Fqkyt3H6Gr47hUiRlkAqPcoc2YuYccrA59ntggiEicQ=;
        b=XIpGQpoD3ugR+k1U+kVA6sbT3iIhe7/42i7hzVWOt2VhFqVy+9wULN38pni+ufBvyR
         ZrJ4qoCzPGLUmGRAjercMWDdfFMLPbUh04qUu/7iR2TpW+B3FMaxKwnrntfWtAQWEeWf
         0M9o3Mu75lz3AMOBKWQgZWbSSIW1h2XBFm1SiI/mhCPNNKFuK5S+hvw2jvH6sMm3duft
         E2yBq0dI43ArY/9DObH1bNkq459ykQivL3kRe3dxUULl8fZfHqCidE6WF+JQOzoXQc80
         Viy3kks/6iAjiCis8rcRxTxuKBtPZA8/JlHtFzKJs0WOpJu7Oy7V/6LoqjlRny01gwNy
         q6wQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="q/g+BEJN";
       spf=pass (google.com: domain of 3n7umywukcvw8fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3n7UMYwUKCVw8FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=Fqkyt3H6Gr47hUiRlkAqPcoc2YuYccrA59ntggiEicQ=;
        b=UMf96gmKIiD1RF0ZoC9F7Wiox1CFNeJPAi1rLIwixkefFZRX84otimwR4Ob69bs5LM
         GMlaYdAjEbKR+zxrRTARJ977CJexhstKyvi3J/IeJ85TIrvYbCtElo+r7+q/Avo51hgJ
         6cuJoDDjBfKWD/sAf185SF8w00nuzjDfUaTCQgXr9W8x+NAbHOL0G8xFsG7l5EqNqxXd
         zUDHOR1GOwBi+CVtmjJCTMTB/1sihCh/y834ShdLFP5Vr4B3VTiSj4+udTxeOJcL6zIQ
         qK/sAIl+17F3XNnbIm4NnyiJ9UqsM2ETlWGi1pbyVfiBdOAd1fHd3KRM64Coycs2hCYL
         Z5pg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=Fqkyt3H6Gr47hUiRlkAqPcoc2YuYccrA59ntggiEicQ=;
        b=SVeTGi3EQMTQ+0rHV7hQSGGj+bTcSuOcqqXWi6B7Qok0ll+6NqfmxcTZbmZKCqp7HY
         hsHGycR0LmQcVuR7Vhav4bA+8f3r628DhKar4inKZeZS0c2gNmH1d4QHz3WxI/Pwzk9T
         yKvJoyAYsr7u8umX00Mi1zajfiujLOR+QvvDQRdcD7L8H2HS9vCGXn8tOoqCEgrAr1Rq
         4pDaRTErQVqZficOkFNAcl9CotchTlwLfDQ7yAyO9MMKYBy8YRb+qilvayMF1BCpHbRX
         Y0E+AAv+UevuFwDecRYX1NVkZm021kTOk4rrtgCWg1+cjzF4VhlL1UtnVV9chi2H1Uz0
         45rA==
X-Gm-Message-State: ACgBeo0rqvJ38jy9aTzda32/AgMy1ZvS4CqXh91vUdAKCoSIPB2BnYna
	ZQfHjACLDSq1/AM1I5d+v/E=
X-Google-Smtp-Source: AA6agR4MK4um1GBQcaNeIFV2AhBbvmsfHhP8VL/BypSedk+wJ/6iI/+MtFcmQeHeKGSLXOxAkO1Tdg==
X-Received: by 2002:a2e:a99b:0:b0:261:b1a1:4ee9 with SMTP id x27-20020a2ea99b000000b00261b1a14ee9mr5887415ljq.366.1661777313275;
        Mon, 29 Aug 2022 05:48:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:91cb:0:b0:263:7e6f:73e0 with SMTP id u11-20020a2e91cb000000b002637e6f73e0ls600909ljg.6.-pod-prod-gmail;
 Mon, 29 Aug 2022 05:48:31 -0700 (PDT)
X-Received: by 2002:a2e:9283:0:b0:253:e175:dd84 with SMTP id d3-20020a2e9283000000b00253e175dd84mr5259300ljh.221.1661777311800;
        Mon, 29 Aug 2022 05:48:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661777311; cv=none;
        d=google.com; s=arc-20160816;
        b=zUKKVVNHzO6E0gUIaAlA2ECLftTzBI3Q52s2qC27vCxFTdm3Xs7yz3tDQ0lNa8+eDF
         5rBFlXjhM8LgS+Ih9NMKAek2ZnudMV0D87YVS6aTEE+L1Je8kBFoV/9/7i1nB20txS4+
         Zussm/Fii9lc2Q8ELqL5fV6Mn7sSfX0qiZ7Pq5Z4lHNHRoTGIBqyIVLBtCDlCJ22rqDX
         6unbskrpAJ2/Pe9sr29xRXBbI47KGHTHdJc8eOZ817nzqUrtT0Qe9da4BpfXtb6vVh9F
         CTbAJaiBbg9TumquTB7HlIaSHodBha90nTU8ukS9TtGKJRHzkYB1v5CajTF7rEM3n8kQ
         uk1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=ALPSUyHQQrXCFAhvO3GrH4UhqRd+C7lu7ougUmdRQTc=;
        b=mmCQKqIWPhAcKEjI778K5K5QejDWe9VUsHlYyvZ595zjDY/dt9HJVkwUK1vijqrHpN
         ldrvkcrmBjl0OdmHmzPWRybCzTVKD79CgN3EnumZYM+bzQ+l7iXINbz8dgIHTcnrvQMq
         9zA7gHAT2DQi/KV2uf61WMYLDWqt8BhH54KdicHWVcZ0rtLo5mQKnpe0/2EUT1fV4Tnm
         qb+VGeINK1YHn6afSyyyvMTgjQ11GshAPOWIj9Xvlxw0clxJtlXfT/acgipFWSBzeRv5
         P9kxTxSpOoYl/M7n9bPegUeMuSeLZH4HkjXl4AUd3edOvbCph9K3Fzpn4wyZQn1dSX38
         nbAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="q/g+BEJN";
       spf=pass (google.com: domain of 3n7umywukcvw8fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3n7UMYwUKCVw8FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id p15-20020a2ea4cf000000b002652a5a5536si3823ljm.2.2022.08.29.05.48.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Aug 2022 05:48:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3n7umywukcvw8fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id w17-20020a056402269100b0043da2189b71so5311319edd.6
        for <kasan-dev@googlegroups.com>; Mon, 29 Aug 2022 05:48:31 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:196d:4fc7:fa9c:62e3])
 (user=elver job=sendgmr) by 2002:a05:6402:e94:b0:443:e3fe:7c87 with SMTP id
 h20-20020a0564020e9400b00443e3fe7c87mr16853908eda.144.1661777311215; Mon, 29
 Aug 2022 05:48:31 -0700 (PDT)
Date: Mon, 29 Aug 2022 14:47:17 +0200
In-Reply-To: <20220829124719.675715-1-elver@google.com>
Mime-Version: 1.0
References: <20220829124719.675715-1-elver@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220829124719.675715-13-elver@google.com>
Subject: [PATCH v4 12/14] perf/hw_breakpoint: Introduce bp_slots_histogram
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
 header.i=@google.com header.s=20210112 header.b="q/g+BEJN";       spf=pass
 (google.com: domain of 3n7umywukcvw8fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3n7UMYwUKCVw8FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
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

Factor out the existing `atomic_t count[N]` into its own struct called
'bp_slots_histogram', to generalize and make its intent clearer in
preparation of reusing elsewhere. The basic idea of bucketing "total
uses of N slots" resembles a histogram, so calling it such seems most
intuitive.

No functional change.

Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Acked-by: Ian Rogers <irogers@google.com>
---
v3:
* Also warn in bp_slots_histogram_add() if count goes below 0.

v2:
* New patch.
---
 kernel/events/hw_breakpoint.c | 96 +++++++++++++++++++++++------------
 1 file changed, 63 insertions(+), 33 deletions(-)

diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
index 229c6f4fae75..03ebecf048c0 100644
--- a/kernel/events/hw_breakpoint.c
+++ b/kernel/events/hw_breakpoint.c
@@ -36,19 +36,27 @@
 #include <linux/slab.h>
 
 /*
- * Constraints data
+ * Datastructure to track the total uses of N slots across tasks or CPUs;
+ * bp_slots_histogram::count[N] is the number of assigned N+1 breakpoint slots.
  */
-struct bp_cpuinfo {
-	/* Number of pinned cpu breakpoints in a cpu */
-	unsigned int	cpu_pinned;
-	/* tsk_pinned[n] is the number of tasks having n+1 breakpoints */
+struct bp_slots_histogram {
 #ifdef hw_breakpoint_slots
-	atomic_t	tsk_pinned[hw_breakpoint_slots(0)];
+	atomic_t count[hw_breakpoint_slots(0)];
 #else
-	atomic_t	*tsk_pinned;
+	atomic_t *count;
 #endif
 };
 
+/*
+ * Per-CPU constraints data.
+ */
+struct bp_cpuinfo {
+	/* Number of pinned CPU breakpoints in a CPU. */
+	unsigned int			cpu_pinned;
+	/* Histogram of pinned task breakpoints in a CPU. */
+	struct bp_slots_histogram	tsk_pinned;
+};
+
 static DEFINE_PER_CPU(struct bp_cpuinfo, bp_cpuinfo[TYPE_MAX]);
 
 static struct bp_cpuinfo *get_bp_info(int cpu, enum bp_type_idx type)
@@ -159,6 +167,18 @@ static inline int hw_breakpoint_slots_cached(int type)
 	return __nr_bp_slots[type];
 }
 
+static __init bool
+bp_slots_histogram_alloc(struct bp_slots_histogram *hist, enum bp_type_idx type)
+{
+	hist->count = kcalloc(hw_breakpoint_slots_cached(type), sizeof(*hist->count), GFP_KERNEL);
+	return hist->count;
+}
+
+static __init void bp_slots_histogram_free(struct bp_slots_histogram *hist)
+{
+	kfree(hist->count);
+}
+
 static __init int init_breakpoint_slots(void)
 {
 	int i, cpu, err_cpu;
@@ -170,8 +190,7 @@ static __init int init_breakpoint_slots(void)
 		for (i = 0; i < TYPE_MAX; i++) {
 			struct bp_cpuinfo *info = get_bp_info(cpu, i);
 
-			info->tsk_pinned = kcalloc(__nr_bp_slots[i], sizeof(atomic_t), GFP_KERNEL);
-			if (!info->tsk_pinned)
+			if (!bp_slots_histogram_alloc(&info->tsk_pinned, i))
 				goto err;
 		}
 	}
@@ -180,7 +199,7 @@ static __init int init_breakpoint_slots(void)
 err:
 	for_each_possible_cpu(err_cpu) {
 		for (i = 0; i < TYPE_MAX; i++)
-			kfree(get_bp_info(err_cpu, i)->tsk_pinned);
+			bp_slots_histogram_free(&get_bp_info(err_cpu, i)->tsk_pinned);
 		if (err_cpu == cpu)
 			break;
 	}
@@ -189,6 +208,34 @@ static __init int init_breakpoint_slots(void)
 }
 #endif
 
+static inline void
+bp_slots_histogram_add(struct bp_slots_histogram *hist, int old, int val)
+{
+	const int old_idx = old - 1;
+	const int new_idx = old_idx + val;
+
+	if (old_idx >= 0)
+		WARN_ON(atomic_dec_return_relaxed(&hist->count[old_idx]) < 0);
+	if (new_idx >= 0)
+		WARN_ON(atomic_inc_return_relaxed(&hist->count[new_idx]) < 0);
+}
+
+static int
+bp_slots_histogram_max(struct bp_slots_histogram *hist, enum bp_type_idx type)
+{
+	for (int i = hw_breakpoint_slots_cached(type) - 1; i >= 0; i--) {
+		const int count = atomic_read(&hist->count[i]);
+
+		/* Catch unexpected writers; we want a stable snapshot. */
+		ASSERT_EXCLUSIVE_WRITER(hist->count[i]);
+		if (count > 0)
+			return i + 1;
+		WARN(count < 0, "inconsistent breakpoint slots histogram");
+	}
+
+	return 0;
+}
+
 #ifndef hw_breakpoint_weight
 static inline int hw_breakpoint_weight(struct perf_event *bp)
 {
@@ -205,13 +252,11 @@ static inline enum bp_type_idx find_slot_idx(u64 bp_type)
 }
 
 /*
- * Report the maximum number of pinned breakpoints a task
- * have in this cpu
+ * Return the maximum number of pinned breakpoints a task has in this CPU.
  */
 static unsigned int max_task_bp_pinned(int cpu, enum bp_type_idx type)
 {
-	atomic_t *tsk_pinned = get_bp_info(cpu, type)->tsk_pinned;
-	int i;
+	struct bp_slots_histogram *tsk_pinned = &get_bp_info(cpu, type)->tsk_pinned;
 
 	/*
 	 * At this point we want to have acquired the bp_cpuinfo_sem as a
@@ -219,14 +264,7 @@ static unsigned int max_task_bp_pinned(int cpu, enum bp_type_idx type)
 	 * toggle_bp_task_slot() to tsk_pinned, and we get a stable snapshot.
 	 */
 	lockdep_assert_held_write(&bp_cpuinfo_sem);
-
-	for (i = hw_breakpoint_slots_cached(type) - 1; i >= 0; i--) {
-		ASSERT_EXCLUSIVE_WRITER(tsk_pinned[i]); /* Catch unexpected writers. */
-		if (atomic_read(&tsk_pinned[i]) > 0)
-			return i + 1;
-	}
-
-	return 0;
+	return bp_slots_histogram_max(tsk_pinned, type);
 }
 
 /*
@@ -300,8 +338,7 @@ max_bp_pinned_slots(struct perf_event *bp, enum bp_type_idx type)
 static void toggle_bp_task_slot(struct perf_event *bp, int cpu,
 				enum bp_type_idx type, int weight)
 {
-	atomic_t *tsk_pinned = get_bp_info(cpu, type)->tsk_pinned;
-	int old_idx, new_idx;
+	struct bp_slots_histogram *tsk_pinned = &get_bp_info(cpu, type)->tsk_pinned;
 
 	/*
 	 * If bp->hw.target, tsk_pinned is only modified, but not used
@@ -311,14 +348,7 @@ static void toggle_bp_task_slot(struct perf_event *bp, int cpu,
 	 * bp_cpuinfo_sem as a writer to stabilize tsk_pinned's value.
 	 */
 	lockdep_assert_held_read(&bp_cpuinfo_sem);
-
-	old_idx = task_bp_pinned(cpu, bp, type) - 1;
-	new_idx = old_idx + weight;
-
-	if (old_idx >= 0)
-		atomic_dec(&tsk_pinned[old_idx]);
-	if (new_idx >= 0)
-		atomic_inc(&tsk_pinned[new_idx]);
+	bp_slots_histogram_add(tsk_pinned, task_bp_pinned(cpu, bp, type), weight);
 }
 
 /*
@@ -768,7 +798,7 @@ bool hw_breakpoint_is_used(void)
 				return true;
 
 			for (int slot = 0; slot < hw_breakpoint_slots_cached(type); ++slot) {
-				if (atomic_read(&info->tsk_pinned[slot]))
+				if (atomic_read(&info->tsk_pinned.count[slot]))
 					return true;
 			}
 		}
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220829124719.675715-13-elver%40google.com.
