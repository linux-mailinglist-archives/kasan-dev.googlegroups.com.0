Return-Path: <kasan-dev+bncBC7OBJGL2MHBBF7LWKMAMGQEH7UOBCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1139.google.com (mail-yw1-x1139.google.com [IPv6:2607:f8b0:4864:20::1139])
	by mail.lfdr.de (Postfix) with ESMTPS id E87595A4C3F
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Aug 2022 14:48:24 +0200 (CEST)
Received: by mail-yw1-x1139.google.com with SMTP id 00721157ae682-340a4dcb403sf106836357b3.22
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Aug 2022 05:48:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661777303; cv=pass;
        d=google.com; s=arc-20160816;
        b=LO6mRWR1OBQI/Swz76QtBfAKJe7rkbV1o2oHPXq66YjNajuj/zTEjyeGdO6D0EB0qY
         b/iCQjpnoI31Ek5nYiu/F8O59Y6E1lj+QC7c/Fh2yt6YK6k4iG7yJyy0aemiW3m7+Wiq
         aBbh4aTsSVYDXuNBX8PDMjKyRmqqcr2CBg+lQvm8inuRm//G2EOERf9A3idODZAkGqeR
         a7He4ufg42FgOuncKW8V8t/kRKEQeDfVQ/oyJxWTEflbNkuhLMfWQZfIo/9rMzORVgL7
         lYinoDToieB8a0/hfcni/q2nuSO5FjAum+zQXICZvyIon2At/G0WbWE/8/hmYeFvAy1t
         m3CA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=0wHEdCpPfSAMGRWKLP0yGYxe1CNJxcGQJrmNZZl5ITk=;
        b=MWmQk521+4TpGwpUbhRNrWDZfgCefpD3SbjzCEeG3nFiMD1BFlmlSs74AfLKYJRsVb
         iX4EjD7GdI2MFgvFZAG+DqNrBPG9SZFsELfQf4mLaB61CrWxdxlOh6GROpOQoPjEC7rX
         qnptgJ4Y5dR5+FfLRFlhdSSOi9Kvap8k6YjrbiNdRp/tNultXmGE4aENiacNzhcjO5M1
         4xmbH+tzH3V6kW0Ii4e/qVgtNc6T3CK8SGx5fo3FWWV6ekAPIJhylZ1mvwaJ3UvNSq4M
         j8fZ6jQMG/Cz41UHvBUZJBh1fO/g2xroKMq39saetqr7FlIh2VhTPeZZCtWwFu+OPly0
         5SSQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=CbUwP42f;
       spf=pass (google.com: domain of 3lrumywukcvmz6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3lrUMYwUKCVMz6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=0wHEdCpPfSAMGRWKLP0yGYxe1CNJxcGQJrmNZZl5ITk=;
        b=I2Fs/t8KK/ANRIUowOCDEIaBr3wgrOD2y7BLews2fnj8oYg+e1ekHqbdie+NmzcG7K
         6pMvV15iiT9+LOGiI8j8YEIHcX634NRZehxXmyT0qk8hKc/13cHnfaefrCsUj4aC80K9
         Y5aAtby26WcwjRwZOXh4tWswRLu8qg8GYCTCign33Z8Gzr+u/t6yHN7CnidSmFNzKzkB
         kH93ID2QyC/DPGkJc3LqPkD8b32eVTd6MjJNKbLMSQLPTwzb7Yn4Jc8Qy2U+jjicljLc
         2cVDY5U+TRy0ho1UXiXEbTE5VwkufmgN4wr+zNwBwnsbYQIla8gMhlwmwaD3Zmm/yQ6i
         ISlw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=0wHEdCpPfSAMGRWKLP0yGYxe1CNJxcGQJrmNZZl5ITk=;
        b=uEhZmJ9nFFmXv3y+6pPvquBc0IZMvibyUfus3PLQgvSxCiCBo7xjhls9kohsMkUhC4
         ToEzildXRsbFFnqLuv6S7N/DkHXBHcXUExeo2iu0ajHM/yk0lb97U97vfa0r+Era+Gj5
         DvT6PFd89Zc/tUc1dO+tRNOiiENuPqBaqbDyc/yDYp//AR8oPLmhRIfPTMRzdQgxWKRw
         n8XPqkjTB148EEWKSJVOwsrbVFGc9zMWv46oDLv0gDi/6GAyvlkvuH2qpSEH7HoE4a82
         NO26E4/5WWjjSxmYUi4dDS4mHZzKcenvkYKnsJQP6b0ypsA2EiB+lwMKkZOeRSRmzmyJ
         ew6A==
X-Gm-Message-State: ACgBeo10hf5V1aNNFIthbBqIdu9efNMWeSAqSv8e/4hHQeTny9lG7m5C
	UP8WZZTDNahwrQHcRkf/XWQ=
X-Google-Smtp-Source: AA6agR4wx58BoEBhI/iCx5914NHGAT9uJlVwuTL7Y8UB4ysVhEOuSFlquE8chAAOUEMyva5WL+JKyA==
X-Received: by 2002:a25:b986:0:b0:671:a73:1ea6 with SMTP id r6-20020a25b986000000b006710a731ea6mr7908404ybg.405.1661777303654;
        Mon, 29 Aug 2022 05:48:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:690c:b1c:b0:32f:d9b9:1357 with SMTP id
 cj28-20020a05690c0b1c00b0032fd9b91357ls2461539ywb.1.-pod-prod-gmail; Mon, 29
 Aug 2022 05:48:23 -0700 (PDT)
X-Received: by 2002:a81:a18d:0:b0:341:2437:f7c7 with SMTP id y135-20020a81a18d000000b003412437f7c7mr3433569ywg.69.1661777303077;
        Mon, 29 Aug 2022 05:48:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661777303; cv=none;
        d=google.com; s=arc-20160816;
        b=scuH7DbBbL5kk+WHHfGltEV3+fj1DtZhX1xSEaq93nJR6jUIHTt4vnjbSf3MtDKAo+
         4ZmuTaYMNQYI8SgyeNvC2alAGgvuFcF4U0TnOAktYLfwenrS07w/yyNptpLjwsHtZA/G
         6qy/P1rKFxYqp0hXD1SuYQulUSgno3zi4VjD7f7bUPnN1vwNbohLJz+tZP0AKuf6F+x8
         Su8X/IR1WtZJpGtwEELNsUEdgXYuqDzkD/BWyFALkO/F51l+M16j4crBjFpb7ossnWtW
         hst1KGIED46xLPznuOKyvP6kdDbDc4xMg2CNMPXR6SFA6uiEiBRON3ry92DIXIDmDHCI
         bhCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=17GhIUVsdBD381xCSlsSf/bvMmuZOpgOvCsizfGJYww=;
        b=RjinXLrS2EUY07eRfj/+NTnFanCJaVlZ+znYm4r3vRr9B4cbjOKCNP13M2SPy3Gujw
         8kJfwO0tNfoolvEspCvQawshWyaIKx9mpGX882KyJU4YvtdeAT9yZ60adfQ/207cohv9
         GlQD4vHLXWktJbTD5LxOnbzPV35XvNsBcfsNfiUK0QLqlZtdJH7UYvCLilXdaF6Q7ixX
         Dd7pF3pqG7DtHZPkHb7Aobb//cG2X3Tj29bBoA3+KFsavGpDBNLuDLnH4Be1IgKhVwUL
         0fCOTbNzkmT0omS6GfR8NRrPT2rFT72IQDLaHzRMEzA+VdrSedVXEgmWtFLeiXbQaTj+
         b8qQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=CbUwP42f;
       spf=pass (google.com: domain of 3lrumywukcvmz6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3lrUMYwUKCVMz6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id n133-20020a25728b000000b0069015ac7716si436267ybc.0.2022.08.29.05.48.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Aug 2022 05:48:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3lrumywukcvmz6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-340862314d9so112369957b3.3
        for <kasan-dev@googlegroups.com>; Mon, 29 Aug 2022 05:48:23 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:196d:4fc7:fa9c:62e3])
 (user=elver job=sendgmr) by 2002:a0d:f402:0:b0:33c:eda4:8557 with SMTP id
 d2-20020a0df402000000b0033ceda48557mr9486024ywf.183.1661777302876; Mon, 29
 Aug 2022 05:48:22 -0700 (PDT)
Date: Mon, 29 Aug 2022 14:47:14 +0200
In-Reply-To: <20220829124719.675715-1-elver@google.com>
Mime-Version: 1.0
References: <20220829124719.675715-1-elver@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220829124719.675715-10-elver@google.com>
Subject: [PATCH v4 09/14] powerpc/hw_breakpoint: Avoid relying on caller synchronization
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
 header.i=@google.com header.s=20210112 header.b=CbUwP42f;       spf=pass
 (google.com: domain of 3lrumywukcvmz6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3lrUMYwUKCVMz6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
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

Internal data structures (cpu_bps, task_bps) of powerpc's hw_breakpoint
implementation have relied on nr_bp_mutex serializing access to them.

Before overhauling synchronization of kernel/events/hw_breakpoint.c,
introduce 2 spinlocks to synchronize cpu_bps and task_bps respectively,
thus avoiding reliance on callers synchronizing powerpc's hw_breakpoint.

Reported-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Dmitry Vyukov <dvyukov@google.com>
Acked-by: Ian Rogers <irogers@google.com>
---
v2:
* New patch.
---
 arch/powerpc/kernel/hw_breakpoint.c | 53 ++++++++++++++++++++++-------
 1 file changed, 40 insertions(+), 13 deletions(-)

diff --git a/arch/powerpc/kernel/hw_breakpoint.c b/arch/powerpc/kernel/hw_breakpoint.c
index 2669f80b3a49..8db1a15d7acb 100644
--- a/arch/powerpc/kernel/hw_breakpoint.c
+++ b/arch/powerpc/kernel/hw_breakpoint.c
@@ -15,6 +15,7 @@
 #include <linux/kernel.h>
 #include <linux/sched.h>
 #include <linux/smp.h>
+#include <linux/spinlock.h>
 #include <linux/debugfs.h>
 #include <linux/init.h>
 
@@ -129,7 +130,14 @@ struct breakpoint {
 	bool ptrace_bp;
 };
 
+/*
+ * While kernel/events/hw_breakpoint.c does its own synchronization, we cannot
+ * rely on it safely synchronizing internals here; however, we can rely on it
+ * not requesting more breakpoints than available.
+ */
+static DEFINE_SPINLOCK(cpu_bps_lock);
 static DEFINE_PER_CPU(struct breakpoint *, cpu_bps[HBP_NUM_MAX]);
+static DEFINE_SPINLOCK(task_bps_lock);
 static LIST_HEAD(task_bps);
 
 static struct breakpoint *alloc_breakpoint(struct perf_event *bp)
@@ -174,7 +182,9 @@ static int task_bps_add(struct perf_event *bp)
 	if (IS_ERR(tmp))
 		return PTR_ERR(tmp);
 
+	spin_lock(&task_bps_lock);
 	list_add(&tmp->list, &task_bps);
+	spin_unlock(&task_bps_lock);
 	return 0;
 }
 
@@ -182,6 +192,7 @@ static void task_bps_remove(struct perf_event *bp)
 {
 	struct list_head *pos, *q;
 
+	spin_lock(&task_bps_lock);
 	list_for_each_safe(pos, q, &task_bps) {
 		struct breakpoint *tmp = list_entry(pos, struct breakpoint, list);
 
@@ -191,6 +202,7 @@ static void task_bps_remove(struct perf_event *bp)
 			break;
 		}
 	}
+	spin_unlock(&task_bps_lock);
 }
 
 /*
@@ -200,12 +212,17 @@ static void task_bps_remove(struct perf_event *bp)
 static bool all_task_bps_check(struct perf_event *bp)
 {
 	struct breakpoint *tmp;
+	bool ret = false;
 
+	spin_lock(&task_bps_lock);
 	list_for_each_entry(tmp, &task_bps, list) {
-		if (!can_co_exist(tmp, bp))
-			return true;
+		if (!can_co_exist(tmp, bp)) {
+			ret = true;
+			break;
+		}
 	}
-	return false;
+	spin_unlock(&task_bps_lock);
+	return ret;
 }
 
 /*
@@ -215,13 +232,18 @@ static bool all_task_bps_check(struct perf_event *bp)
 static bool same_task_bps_check(struct perf_event *bp)
 {
 	struct breakpoint *tmp;
+	bool ret = false;
 
+	spin_lock(&task_bps_lock);
 	list_for_each_entry(tmp, &task_bps, list) {
 		if (tmp->bp->hw.target == bp->hw.target &&
-		    !can_co_exist(tmp, bp))
-			return true;
+		    !can_co_exist(tmp, bp)) {
+			ret = true;
+			break;
+		}
 	}
-	return false;
+	spin_unlock(&task_bps_lock);
+	return ret;
 }
 
 static int cpu_bps_add(struct perf_event *bp)
@@ -234,6 +256,7 @@ static int cpu_bps_add(struct perf_event *bp)
 	if (IS_ERR(tmp))
 		return PTR_ERR(tmp);
 
+	spin_lock(&cpu_bps_lock);
 	cpu_bp = per_cpu_ptr(cpu_bps, bp->cpu);
 	for (i = 0; i < nr_wp_slots(); i++) {
 		if (!cpu_bp[i]) {
@@ -241,6 +264,7 @@ static int cpu_bps_add(struct perf_event *bp)
 			break;
 		}
 	}
+	spin_unlock(&cpu_bps_lock);
 	return 0;
 }
 
@@ -249,6 +273,7 @@ static void cpu_bps_remove(struct perf_event *bp)
 	struct breakpoint **cpu_bp;
 	int i = 0;
 
+	spin_lock(&cpu_bps_lock);
 	cpu_bp = per_cpu_ptr(cpu_bps, bp->cpu);
 	for (i = 0; i < nr_wp_slots(); i++) {
 		if (!cpu_bp[i])
@@ -260,19 +285,25 @@ static void cpu_bps_remove(struct perf_event *bp)
 			break;
 		}
 	}
+	spin_unlock(&cpu_bps_lock);
 }
 
 static bool cpu_bps_check(int cpu, struct perf_event *bp)
 {
 	struct breakpoint **cpu_bp;
+	bool ret = false;
 	int i;
 
+	spin_lock(&cpu_bps_lock);
 	cpu_bp = per_cpu_ptr(cpu_bps, cpu);
 	for (i = 0; i < nr_wp_slots(); i++) {
-		if (cpu_bp[i] && !can_co_exist(cpu_bp[i], bp))
-			return true;
+		if (cpu_bp[i] && !can_co_exist(cpu_bp[i], bp)) {
+			ret = true;
+			break;
+		}
 	}
-	return false;
+	spin_unlock(&cpu_bps_lock);
+	return ret;
 }
 
 static bool all_cpu_bps_check(struct perf_event *bp)
@@ -286,10 +317,6 @@ static bool all_cpu_bps_check(struct perf_event *bp)
 	return false;
 }
 
-/*
- * We don't use any locks to serialize accesses to cpu_bps or task_bps
- * because are already inside nr_bp_mutex.
- */
 int arch_reserve_bp_slot(struct perf_event *bp)
 {
 	int ret;
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220829124719.675715-10-elver%40google.com.
