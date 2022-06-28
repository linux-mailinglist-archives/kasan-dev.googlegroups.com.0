Return-Path: <kasan-dev+bncBC7OBJGL2MHBBANC5OKQMGQE3ZG5AJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id D53F155BFFD
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 11:59:30 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id j17-20020a056e02219100b002d955e89a54sf7155514ila.11
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 02:59:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656410369; cv=pass;
        d=google.com; s=arc-20160816;
        b=jWRnPFKUcMaQMuMv8rfIzU0chJH+/s+/R+82hJhkmM2h8qk5f7on/S5mbR8VQxePd8
         NPYFk+Agoo5BPrAvyxenub3amkgVqWyPuR/3WCgej+2O/A7kAR1nQHY7VtOlMoNyBHN7
         8lapiz6Ii/khfeGUh+1FTeU1NxRo52TIlysUGmcEdaEyb0QYJP0FbKpEGqlgm0M/uxbl
         jDMrYll5geTSbMdvn4rWEBE2CEXcewbLMsreP9yB+jYKl29F3V1i4bBpregIBo6rkUTe
         MKZwxpDpYQ5CmqDSKfsRM8KuUqIHMjfJ+3lVJypQ4IcBCVZD15khem2geAFYWgRl6pal
         ah/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=v2HtxV2YlwBilEHdrusXw63vMR1ex2Q/v3IQF6HtXjg=;
        b=KHBncrYS1laDFZ6fqNVUrYePkbbS85F1VyL9gmG5Ox3nDT4L+ftU5IJZBITpFYE2jX
         nzXHMfjONDfL/A0zzQICNq/ODI4COG9QtZOTM3LczQa7uDuldQxwDn+XEmMxaXa+ZN6C
         JbvEajzKL2WkkdmTpLPGeODIiqqewOen/Wh3gkrZdXH1xXaxvoKjpluj5qEy+e+WBrRk
         wOVN8ZYyjYkC1B6JGzRNrhaps4BMfNBHNGGVYpFAYwsk3mW1Dq22fZITF9FHhNOtECBe
         ZIkS7bKiD7Bvb8vASlxH8nRH+P1o1Ws2AdOgGHhRCMrL7O+xeRmeKcq78jpI6TvkstNM
         FFdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=F4htJF5l;
       spf=pass (google.com: domain of 3ang6ygukcaknuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3ANG6YgUKCakNUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=v2HtxV2YlwBilEHdrusXw63vMR1ex2Q/v3IQF6HtXjg=;
        b=QfUgsDdPM4+pKG8Uku7alYQARPrCn8zoUopLE+RBw6qAzYSLdVuNLYjQKbY7pwBaw8
         Bggoq56HheseoNGFUz3kQAeHD8DycmoWwqqEAzK1qR4GrcXOcKa289MFOPZlUhy/ELEg
         oKyGsvdnEswPHXHyjeot3NTevNszpdjhjSplsv/swEeHjWVjiKIKT4t2qtElPXnspU2o
         ZF1pjUB2WCa75hDWZFtNXQdICofx6R4H6X6cVbD+rXWoJB/7Tq3TieSQIUHWcpQEZLz4
         K+NlaZebtZwFgGsVzaDgNW8MQ05lqYEsuK0UIT0PxH7XADnASzCUW6Uvr23Yvu4npeCb
         4hPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=v2HtxV2YlwBilEHdrusXw63vMR1ex2Q/v3IQF6HtXjg=;
        b=5tYs4E94T+BEv9n/hfiqQ5IZr6LLo6I3SuEALSB4QnY11IjMY18YE/W6tkAHZ0Iryc
         DAQPObRSBB7fdCPxzNgMDOv7Lh27uUcQKCXClDjtbAhB3jMmPKaaWFjdqQACjnDr1D87
         qKzcNF0MEirFhnQvouv9E4k8fDPg2LDDPQvPzzcrzCwhHb7yBjCEk9fNpmwE11ktDui1
         Uf5ZfedhPmWPXbMVrepEIxVBDX6kIuA1IXX9AG0P3qO1bD5zcqjIjxr/oxnWKaq6erhj
         xRbEzvzsTS81RlHPM3nJpDeXImpEPmqqyRwjd0f7ojA8FXQTqq8K0Qi7efU7IcevpJRl
         N7xQ==
X-Gm-Message-State: AJIora9gQW3GgEVmipWeMSaXPCP5FOK3jS1OxBusRQIR1kZYjDr/IfFq
	//51RH00CfDTQEWSEHdwcaE=
X-Google-Smtp-Source: AGRyM1sBxGa6AdcUGxL8/9GIdmJ0yy/7ulWc3EEoAx8JDD7cH4y+qAjMAwTTQxl9LDCUSmXNcFcIkg==
X-Received: by 2002:a92:cd52:0:b0:2d9:f27:366b with SMTP id v18-20020a92cd52000000b002d90f27366bmr9799615ilq.41.1656410369669;
        Tue, 28 Jun 2022 02:59:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1d84:b0:2da:a084:8a7f with SMTP id
 h4-20020a056e021d8400b002daa0848a7fls573467ila.9.gmail; Tue, 28 Jun 2022
 02:59:29 -0700 (PDT)
X-Received: by 2002:a05:6e02:168c:b0:2da:971e:700c with SMTP id f12-20020a056e02168c00b002da971e700cmr5213828ila.311.1656410369144;
        Tue, 28 Jun 2022 02:59:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656410369; cv=none;
        d=google.com; s=arc-20160816;
        b=XuQ1qcFme1jI+eGA9+KcpMJRTGeY3ImoOfz+n2CC1bldEX71mqmvWdmdNgx5RCUThZ
         GOvmwb98MYaLXdxeWiB5e0WL3pNhJAL11Li0EnB+HX7rJ3kCRGlKHG7LLQb4I+yWChoS
         rwJk39qU5MmEoxZjV42a5k0hNSkfshnXW55XmvB4xpd0FAHxWM5I7M9ImnOSFOvRb1vl
         oGDBuAu16NzQ1QXh1cT61lEDGWgmxx4aulZwLWxcQZYEZIjGPWvYRYm5vTPOptaju0mu
         1jlTYuB3PR8r3wRkb5DH2qOfyputdr3bogDdyw9DnYa4Hd3rx79NMLFkbllE+3qiTfwE
         yZ+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=1QsQANeqdFobJvV2MAaRL6zWG6aX2Y9RNZ6A4p9R7aA=;
        b=TynVgfbuNBThAFbDlvHFLhjst4hDAAWVBpAmu/c2cl8uufd6SPV3MzCG8cgzOV4qjt
         cX7hznxg/3j33WJR7BP16ffTcXk25kyTihTUbOFWgD/Od39pVC3ijS0+Jo+ptsp++pE9
         jCSam4QTnbKy3dqjelaTsrhkw47FI26jMpIbt5zJil/KaQFqOquAC2FgF+KImbIOcwnZ
         M9WaMTBQG48fLs5vJqGJQ+wEC4ackZcqA/TAi78fAGl8ivzpSzHoRFofbS8uE0YGilx2
         S6DoNupYYm9I3hRkpbkDb4DOf4BC9cFLO4UGA0vT8ecXQWJS+rXla9jTGrl1VVybGSoV
         XcLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=F4htJF5l;
       spf=pass (google.com: domain of 3ang6ygukcaknuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3ANG6YgUKCakNUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id o47-20020a02742f000000b0033ca5e75ddfsi151891jac.6.2022.06.28.02.59.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jun 2022 02:59:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ang6ygukcaknuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id u131-20020a254789000000b0066c8beed1e2so7283904yba.16
        for <kasan-dev@googlegroups.com>; Tue, 28 Jun 2022 02:59:29 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:3496:744e:315a:b41b])
 (user=elver job=sendgmr) by 2002:a25:9388:0:b0:66d:1fd9:6f73 with SMTP id
 a8-20020a259388000000b0066d1fd96f73mr3984902ybm.147.1656410368789; Tue, 28
 Jun 2022 02:59:28 -0700 (PDT)
Date: Tue, 28 Jun 2022 11:58:31 +0200
In-Reply-To: <20220628095833.2579903-1-elver@google.com>
Message-Id: <20220628095833.2579903-12-elver@google.com>
Mime-Version: 1.0
References: <20220628095833.2579903-1-elver@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v2 11/13] perf/hw_breakpoint: Introduce bp_slots_histogram
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
 header.i=@google.com header.s=20210112 header.b=F4htJF5l;       spf=pass
 (google.com: domain of 3ang6ygukcaknuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3ANG6YgUKCakNUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
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
---
v2:
* New patch.
---
 kernel/events/hw_breakpoint.c | 94 +++++++++++++++++++++++------------
 1 file changed, 62 insertions(+), 32 deletions(-)

diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
index 128ba3429223..18886f115abc 100644
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
+		atomic_dec(&hist->count[old_idx]);
+	if (new_idx >= 0)
+		atomic_inc(&hist->count[new_idx]);
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
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220628095833.2579903-12-elver%40google.com.
