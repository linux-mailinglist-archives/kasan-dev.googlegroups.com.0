Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5UDRSLAMGQEUNN3UBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 971F0565946
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jul 2022 17:06:30 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id c20-20020a05640227d400b004369cf00c6bsf7444456ede.22
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 08:06:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656947190; cv=pass;
        d=google.com; s=arc-20160816;
        b=Bnprga8Cpf24XJK4VSmqZx7TgOGX7mHVHQivMJZZvIKIT+vDgjgU2mCfKV9J6+4UTr
         46QhU0swzJQ+atkBGYpmRQcn5HqbCs0ElYuZyvKtrK5ribz/IMcID1K7JwEQbdpQNLGm
         mu6Ib+7ChTkkD1+w3OEN14PYvbO4v0doSXZQTaVFLm4WAVGEiZEk3Rwe+KOEModbzLFQ
         s51ZfWrNeAQTrrrWqRWVYyPg+eOsTW9mfMlt7cbiqWXWfgivTxyEG16BKl6aXpAdt93l
         SlFBvclFiOHdP0XurB8Ibyilcx/TSjFRZoO2HPeyvkbQ+7AflzaDHoxvLFuoJyiVST3O
         EW8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=gF/auNJodn2RpYEteQ6nMbaQqyqt2WMFKbEH8/HvKiI=;
        b=hTUE9siRWunOKH5tUkMYyUHQkM8Jw40N20GMwc0TjcMin0Nn0rSe4FjJo+dhvInnqJ
         lNY9Vu9vj2y61sNw980asmYeAC6WM0JUpC42KMjkWwuDNy3vx4okTs2Tg3XIvJKivyYo
         hrB2BYlV+8DLN+/9ZF6J7ZTsGvKnU5oViSb9bBMNX/9UvMimYPohO+5eBb1sv3DZ/Nw9
         WKGfpK0BaUk7sx2Y32/UbAVL4qijzuipMQAv9QFDHa44q5wz563ct2GZ0jot4SPKlio9
         7oKGaf6jkxGOTF3LI/JOaSj7E3n2XmwYNqTg5cWWmojT5bKKYNGPZ59ydKJDL6RSgyEs
         dT8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=KryRGHzB;
       spf=pass (google.com: domain of 39ahdygukcsebisbodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=39AHDYgUKCSEBISBODLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gF/auNJodn2RpYEteQ6nMbaQqyqt2WMFKbEH8/HvKiI=;
        b=HQWAYFfOZFRG5UjsueGrNCdfygBF5srQaIPbi9vI0mJHm+yVeX2lKUpCMH9C1OeUm1
         rZyrGDwhmXjc25NqQ7vXLQNkgiTRAaOwg8BCHBWEumeJjna32SIQU2kDkql1gyRmxLnd
         95M6+aen/EY39rk+1crvjdNmm2LXILKNXL0oCFp0X1nOgx9vkU12tQaVCfYHf5HEAB6M
         onyCcHpj4WPh12Yo9GVRWni9yNb/pwYJ3RR5iRXKkW8criIrG205q+PXfJVTD9BMzWtd
         r2mLwbpfheEXp0nQ68+lEqgT8qm7BP6Svmki6NcLLQgJ/1c3kpyHUVi8oLu9qiiOhRMq
         CbVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gF/auNJodn2RpYEteQ6nMbaQqyqt2WMFKbEH8/HvKiI=;
        b=sclImMZSydNGbIO9GbSY6xMBx02r1+ocdGHpaDEX6cOL0ca9FgEhgZOBoZ/ZqLOrDv
         +wmQquSNpYHsv6Oebw8hVfLH05jf3N0DwA4P9TFpMisKRi2dtGmpQgUJLZwXCqJJ6Tpj
         0RHPnTPrSsCtLseZVF69oHdywCeA8reypRgtq1TSToenF408fseKf6/KOmAd74NdZ22X
         lYlUwj0puFqA1+Y/i6Db7M9rDSQVmHVhPf7uEHjJ0Paxoz1vxd8JbtwziMdU4BI1mmUb
         wFiY91fVhhVeexM4Xro1tHxJdVOs7qpctgS1ho2BOHmx4RgGVh5uYcourtlgMtmJqMFb
         X4Lg==
X-Gm-Message-State: AJIora9269wfhl2BALBun2IyDemy0K1Aybqy8CH9+BSJbi5N5egvcGd5
	utaT+9dqcwKOSsyA93h6/30=
X-Google-Smtp-Source: AGRyM1vYis9a+t5d4dJhOPZYjWS9qlBUwmTNnrqa6E873JUGvZArYD6Hz348mfDt6Wzi8QIAdZuPzg==
X-Received: by 2002:a05:6402:1e95:b0:437:ce7f:e17a with SMTP id f21-20020a0564021e9500b00437ce7fe17amr38887859edf.169.1656947190195;
        Mon, 04 Jul 2022 08:06:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:2ad6:b0:6fe:976a:7a5 with SMTP id
 m22-20020a1709062ad600b006fe976a07a5ls7512355eje.7.gmail; Mon, 04 Jul 2022
 08:06:29 -0700 (PDT)
X-Received: by 2002:a17:907:8a14:b0:726:b4df:7863 with SMTP id sc20-20020a1709078a1400b00726b4df7863mr29345063ejc.552.1656947188917;
        Mon, 04 Jul 2022 08:06:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656947188; cv=none;
        d=google.com; s=arc-20160816;
        b=bFdfjmlOSh/z5n8eOtn7JP7L/JFYiryWm7S5qgr2A+xJj+xnqEDbyH6meIznkGFSdT
         K7C7t67eIhL+i3/M4UV27geIx4rUKR5lbojQuJfgiy2bY9QwG1wUhTksLjou9LnaPse7
         SrMOcG7kYlgSbZ3cBykbTVX4ktdafo5/zlpBtNB/t768T6NAzVyWouDaa2H3bd51lmtw
         Gesag9DklqS2wYMLdFssPhp+HcMHlUs3CXZTpwCfLoMz8GSpgQoludk0g2LyIqh+DyLf
         p7o+12rH2UpJPGQDwmHXzkVLKziD/LR0fhoLzokTKA1L0Z6C0uOq1r3/R42Mt9oFigLf
         HDUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=pxbTqlp1PMd6Kn/Ogba6QdxHSgu8OctnaZIv/qt2Oi0=;
        b=YEhhiNs05oWaFjkUD6msPl4n9TKEsK0Pfl+B0BX+BEPNF6Pe8jHFactlQCdJlXonoA
         jndBZQNOHU1/e1rU7K60Fhww+zNlLS2VVhT51iFvwMJBsoABlzYKkZPohm7RkjLmmpyA
         hrFOS/GsGBFhI11aE5f4D0uyidAjuMHmFi5t7xf9Il7dEuXUhqIxSjx8jnCvCxwEv32y
         JRdFXSDgFj/qPdkFZzNKCkSNYDt/XYlOMGCkPRWM966sSOUjVaG0495qZlVofVthDLn+
         SQA7GNBg0qiUpYWt0kwtSW//17MYEdVpQnCRPRVSZDoO6HTX4atCryGxmjwAt61PmSJj
         eN1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=KryRGHzB;
       spf=pass (google.com: domain of 39ahdygukcsebisbodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=39AHDYgUKCSEBISBODLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id a22-20020a170906245600b0072695cb14f9si934965ejb.0.2022.07.04.08.06.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Jul 2022 08:06:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of 39ahdygukcsebisbodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id qk8-20020a1709077f8800b00722fcbfdcf7so2116155ejc.2
        for <kasan-dev@googlegroups.com>; Mon, 04 Jul 2022 08:06:28 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:6edf:e1bc:9a92:4ad0])
 (user=elver job=sendgmr) by 2002:a05:6402:34cd:b0:43a:6e91:c5ff with SMTP id
 w13-20020a05640234cd00b0043a6e91c5ffmr3092109edc.88.1656947188668; Mon, 04
 Jul 2022 08:06:28 -0700 (PDT)
Date: Mon,  4 Jul 2022 17:05:12 +0200
In-Reply-To: <20220704150514.48816-1-elver@google.com>
Message-Id: <20220704150514.48816-13-elver@google.com>
Mime-Version: 1.0
References: <20220704150514.48816-1-elver@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v3 12/14] perf/hw_breakpoint: Introduce bp_slots_histogram
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
 header.i=@google.com header.s=20210112 header.b=KryRGHzB;       spf=pass
 (google.com: domain of 39ahdygukcsebisbodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=39AHDYgUKCSEBISBODLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--elver.bounces.google.com;
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
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220704150514.48816-13-elver%40google.com.
