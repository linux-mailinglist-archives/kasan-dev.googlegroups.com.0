Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4NB5OKQMGQE5ZVJW4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 48AEB55BFF7
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 11:59:14 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id w12-20020adf8bcc000000b0021d20a5b24fsf267811wra.22
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 02:59:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656410354; cv=pass;
        d=google.com; s=arc-20160816;
        b=Nn/nzXhUXFpRJE2VMr0scCNyxEELIW1YMo8gPOfRCfU74xLaxlmuCov89YRYhgV/dq
         gDCMgLt52UPwDtz02GXvuL6AMwwAKrCJXOrC7W4BgfUOgYcxms+7JUSnSv+WBE2Yx6V+
         m0PpCmyG1dLd4RyTjRyC6r2FcqTqatcW3cISYr2n336F3LcMxA44uYuIK7j9M3pprChP
         +dHe+clfTD4U1y7/2OeLjHMW0HP49rlgW1YmTuN56yu5REFckYuXRIVxzLs6ubqBAex/
         mBd6iRxCOX5i6quuiKsVyItgA8GeS6N2KbLHN7JSYZiWvdHh+woHQcl9ds3Zw+R+lsm/
         /JQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=J3SOuFYvYR/CFSq2NSieEDcNwbBqXdGi95kK7VC69x8=;
        b=Hpl3vdkDUXmXCFwhWWgygX89Xuk09+EsrVLe1sDXAA3X7yPeWa1wbIBKjRUH1V74fP
         yQ+E3gNmuy+HJdWh26WuSxEYL930BAbGLN24FzxR9fwbeTfbOOWFz5nCrveVkENZ7vpc
         1WEXOQJiF5E4wJ6pHrvJYtfWJYFPEk03cpWxwXP3SmVD0VyaDlBhDUJCIJUDrvX5aXyJ
         nVDJjX5nQHEK49/LktdGXJrLz66W24GQqKd4yTUIvEnjMcTHE7cn663QgF1xd6OHnI7K
         J6mSotodH+pij3nx0u/2U7IGbWj6J07NI3gxgThvNZ2M6XBrzdqQiZnAQZrj/VVMrhaD
         x/aA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=oiApGXN2;
       spf=pass (google.com: domain of 38nc6ygukczk7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=38NC6YgUKCZk7EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=J3SOuFYvYR/CFSq2NSieEDcNwbBqXdGi95kK7VC69x8=;
        b=lj0f2L8QJm+imzPSBfabMZ2oJynGMyGB07EPTeO+RdN9bPhiEfLqkcv4t1S/MeDUO5
         5l8gj8GV93Kg+H2/ncKgjO53HTQd6iKccSEym495oJmVM7kf4bHjpcoO99tU6a/EXG5a
         Gmtd3pqDMhvFEf8r8zbgBmYo1xA2cPkQWko/jVUaBeDmfTB82x4DTWFJVwpZI89I38K1
         XXnCYYs/FEH0E1B/KeZ1HClzo3L24FPz2h3e652CAIwGHxhWmJYs/vR7MPLPKWbk/AvJ
         ZaWkimsP+76lYkqOea3avh9kPTtJrm57OTh6H/DCQUpJ742Oq3ov35MpPxLr5daFh2D9
         rMfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=J3SOuFYvYR/CFSq2NSieEDcNwbBqXdGi95kK7VC69x8=;
        b=zW86PmaUK/n8TUbwdllZmXIe1Y+OOyk3rltZaP2cyG08bAxCtlFYRVYyudXwEuqpNF
         5Yl/pNVf3OylUhYV+x6D3PonFzSkJE2/K1Kl5IRc2WG7b1jyzIGNsidjuJGZZQ2eMKmp
         ARpRTHH3Bhg30jtUZLR6DSSJwx982wQsHp/UiBzdw2oXJgPFuJIZ0xX2OnyVs9rlX4Qx
         uYBlevKfqSHogszouXkYEcDuV9HasbIcGVOzcLbgZ6wI1Vo295P7n5iRKSg6tzx6FCiX
         7fA5sQoKw83fEbDnwc03fv+o8dsuGBZ1eAlM75mISZ6obuwpQzv38x/wHfsuLorgk4WZ
         K3zw==
X-Gm-Message-State: AJIora/usP3EWKpGbcjFKAzGZDjeZD5V+M8XuAGPg/tVLfHYMzeltBZc
	MMix7e2BgbKbk1GAAa64P+0=
X-Google-Smtp-Source: AGRyM1sW6tOkFDrquXa+5ZTq8yh4YJyfmayUfVOvV2HQxB6otOJpwVtfJq0QvlT7iXpkYVlMKtqMFw==
X-Received: by 2002:a7b:c5c6:0:b0:397:8a39:37b with SMTP id n6-20020a7bc5c6000000b003978a39037bmr19889705wmk.182.1656410353955;
        Tue, 28 Jun 2022 02:59:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1887:b0:218:5c3b:1a23 with SMTP id
 a7-20020a056000188700b002185c3b1a23ls10061138wri.0.gmail; Tue, 28 Jun 2022
 02:59:12 -0700 (PDT)
X-Received: by 2002:a05:6000:80e:b0:21b:9fb8:1b65 with SMTP id bt14-20020a056000080e00b0021b9fb81b65mr17119106wrb.592.1656410352726;
        Tue, 28 Jun 2022 02:59:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656410352; cv=none;
        d=google.com; s=arc-20160816;
        b=g44ngJugl7vTJEzgwDQvGqPiJM2bLeF+tjHICT/TTWWoC566dPRQCvcQJSYpkiKIIF
         w/ugf65uMaXuGxVuGFR7AJ3OLniLkyifhSLNY1EgI38z92If5NtBKNjlxmprXTxEHb4l
         R427adqOBmvKYCebh4HPyFKKxnHMCnRalDmai7XKJFRu9z+SMT/2VrxI6Ru5QlZVuA4Y
         gg/HIWvVcSwbleluqw+zUpwzAwXDSR10QGNEzX/kJ6JNawaLPetO6BIaQVoRFKNqjPgK
         grvarFcyeuakWGEeABAvxC7dnngGleVcaQoUCDUkPFcdvFXhcE17p4q2Ew6kdC7+ZBXc
         dUZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=rbZIw4RHxWyjZ7uKCIj1/02nzDfS7BCWoBx2cEn1z+M=;
        b=UMZvtajRAvtLr1r58KNKuPfxclxh6/Fbc6hcZS8D6vasgtGIedxmiVtIivyyNw5dEL
         KvYIhRYgkTYfggmZisgrw9rP9chZ0oJkx30ur7+ImIhyriLMZQ0s20cPytWZWlqeaOi3
         OxWdPXyuP8KkzbxWkxU31zSisxLehGR7IyorR67AOozjz7S6YzUfUbAGo3TzSV3KXT3Y
         vh1tXypXVfMDoSptElv37wcaPhC8fwS4rP+7Zw/W9Tv2NcE5eIo2P+90FOevviBH5Fz6
         1Xmi2Spe0ZP07fhW4rZ9mJLVLkufbE+D7F3iBILvSPE39W4FE8JV1J/O5u8VIAP14l3U
         fRmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=oiApGXN2;
       spf=pass (google.com: domain of 38nc6ygukczk7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=38NC6YgUKCZk7EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id i17-20020a7bc951000000b0039c903985c6si723867wml.2.2022.06.28.02.59.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jun 2022 02:59:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of 38nc6ygukczk7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id w22-20020a05640234d600b00435ba41dbaaso9209496edc.12
        for <kasan-dev@googlegroups.com>; Tue, 28 Jun 2022 02:59:12 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:3496:744e:315a:b41b])
 (user=elver job=sendgmr) by 2002:a05:6402:268a:b0:435:c137:6452 with SMTP id
 w10-20020a056402268a00b00435c1376452mr22004368edd.419.1656410352317; Tue, 28
 Jun 2022 02:59:12 -0700 (PDT)
Date: Tue, 28 Jun 2022 11:58:25 +0200
In-Reply-To: <20220628095833.2579903-1-elver@google.com>
Message-Id: <20220628095833.2579903-6-elver@google.com>
Mime-Version: 1.0
References: <20220628095833.2579903-1-elver@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v2 05/13] perf/hw_breakpoint: Optimize constant number of
 breakpoint slots
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
 header.i=@google.com header.s=20210112 header.b=oiApGXN2;       spf=pass
 (google.com: domain of 38nc6ygukczk7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=38NC6YgUKCZk7EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
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

Optimize internal hw_breakpoint state if the architecture's number of
breakpoint slots is constant. This avoids several kmalloc() calls and
potentially unnecessary failures if the allocations fail, as well as
subtly improves code generation and cache locality.

The protocol is that if an architecture defines hw_breakpoint_slots via
the preprocessor, it must be constant and the same for all types.

Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Dmitry Vyukov <dvyukov@google.com>
---
 arch/sh/include/asm/hw_breakpoint.h  |  5 +-
 arch/x86/include/asm/hw_breakpoint.h |  5 +-
 kernel/events/hw_breakpoint.c        | 92 ++++++++++++++++++----------
 3 files changed, 62 insertions(+), 40 deletions(-)

diff --git a/arch/sh/include/asm/hw_breakpoint.h b/arch/sh/include/asm/hw_breakpoint.h
index 199d17b765f2..361a0f57bdeb 100644
--- a/arch/sh/include/asm/hw_breakpoint.h
+++ b/arch/sh/include/asm/hw_breakpoint.h
@@ -48,10 +48,7 @@ struct pmu;
 /* Maximum number of UBC channels */
 #define HBP_NUM		2
 
-static inline int hw_breakpoint_slots(int type)
-{
-	return HBP_NUM;
-}
+#define hw_breakpoint_slots(type) (HBP_NUM)
 
 /* arch/sh/kernel/hw_breakpoint.c */
 extern int arch_check_bp_in_kernelspace(struct arch_hw_breakpoint *hw);
diff --git a/arch/x86/include/asm/hw_breakpoint.h b/arch/x86/include/asm/hw_breakpoint.h
index a1f0e90d0818..0bc931cd0698 100644
--- a/arch/x86/include/asm/hw_breakpoint.h
+++ b/arch/x86/include/asm/hw_breakpoint.h
@@ -44,10 +44,7 @@ struct arch_hw_breakpoint {
 /* Total number of available HW breakpoint registers */
 #define HBP_NUM 4
 
-static inline int hw_breakpoint_slots(int type)
-{
-	return HBP_NUM;
-}
+#define hw_breakpoint_slots(type) (HBP_NUM)
 
 struct perf_event_attr;
 struct perf_event;
diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
index 270be965f829..a089302ddf59 100644
--- a/kernel/events/hw_breakpoint.c
+++ b/kernel/events/hw_breakpoint.c
@@ -40,13 +40,16 @@ struct bp_cpuinfo {
 	/* Number of pinned cpu breakpoints in a cpu */
 	unsigned int	cpu_pinned;
 	/* tsk_pinned[n] is the number of tasks having n+1 breakpoints */
+#ifdef hw_breakpoint_slots
+	unsigned int	tsk_pinned[hw_breakpoint_slots(0)];
+#else
 	unsigned int	*tsk_pinned;
+#endif
 	/* Number of non-pinned cpu/task breakpoints in a cpu */
 	unsigned int	flexible; /* XXX: placeholder, see fetch_this_slot() */
 };
 
 static DEFINE_PER_CPU(struct bp_cpuinfo, bp_cpuinfo[TYPE_MAX]);
-static int nr_slots[TYPE_MAX] __ro_after_init;
 
 static struct bp_cpuinfo *get_bp_info(int cpu, enum bp_type_idx type)
 {
@@ -73,6 +76,54 @@ struct bp_busy_slots {
 /* Serialize accesses to the above constraints */
 static DEFINE_MUTEX(nr_bp_mutex);
 
+#ifdef hw_breakpoint_slots
+/*
+ * Number of breakpoint slots is constant, and the same for all types.
+ */
+static_assert(hw_breakpoint_slots(TYPE_INST) == hw_breakpoint_slots(TYPE_DATA));
+static inline int hw_breakpoint_slots_cached(int type)	{ return hw_breakpoint_slots(type); }
+static inline int init_breakpoint_slots(void)		{ return 0; }
+#else
+/*
+ * Dynamic number of breakpoint slots.
+ */
+static int __nr_bp_slots[TYPE_MAX] __ro_after_init;
+
+static inline int hw_breakpoint_slots_cached(int type)
+{
+	return __nr_bp_slots[type];
+}
+
+static __init int init_breakpoint_slots(void)
+{
+	int i, cpu, err_cpu;
+
+	for (i = 0; i < TYPE_MAX; i++)
+		__nr_bp_slots[i] = hw_breakpoint_slots(i);
+
+	for_each_possible_cpu(cpu) {
+		for (i = 0; i < TYPE_MAX; i++) {
+			struct bp_cpuinfo *info = get_bp_info(cpu, i);
+
+			info->tsk_pinned = kcalloc(__nr_bp_slots[i], sizeof(int), GFP_KERNEL);
+			if (!info->tsk_pinned)
+				goto err;
+		}
+	}
+
+	return 0;
+err:
+	for_each_possible_cpu(err_cpu) {
+		for (i = 0; i < TYPE_MAX; i++)
+			kfree(get_bp_info(err_cpu, i)->tsk_pinned);
+		if (err_cpu == cpu)
+			break;
+	}
+
+	return -ENOMEM;
+}
+#endif
+
 __weak int hw_breakpoint_weight(struct perf_event *bp)
 {
 	return 1;
@@ -95,7 +146,7 @@ static unsigned int max_task_bp_pinned(int cpu, enum bp_type_idx type)
 	unsigned int *tsk_pinned = get_bp_info(cpu, type)->tsk_pinned;
 	int i;
 
-	for (i = nr_slots[type] - 1; i >= 0; i--) {
+	for (i = hw_breakpoint_slots_cached(type) - 1; i >= 0; i--) {
 		if (tsk_pinned[i] > 0)
 			return i + 1;
 	}
@@ -312,7 +363,7 @@ static int __reserve_bp_slot(struct perf_event *bp, u64 bp_type)
 	fetch_this_slot(&slots, weight);
 
 	/* Flexible counters need to keep at least one slot */
-	if (slots.pinned + (!!slots.flexible) > nr_slots[type])
+	if (slots.pinned + (!!slots.flexible) > hw_breakpoint_slots_cached(type))
 		return -ENOSPC;
 
 	ret = arch_reserve_bp_slot(bp);
@@ -687,42 +738,19 @@ static struct pmu perf_breakpoint = {
 
 int __init init_hw_breakpoint(void)
 {
-	int cpu, err_cpu;
-	int i, ret;
-
-	for (i = 0; i < TYPE_MAX; i++)
-		nr_slots[i] = hw_breakpoint_slots(i);
-
-	for_each_possible_cpu(cpu) {
-		for (i = 0; i < TYPE_MAX; i++) {
-			struct bp_cpuinfo *info = get_bp_info(cpu, i);
-
-			info->tsk_pinned = kcalloc(nr_slots[i], sizeof(int),
-							GFP_KERNEL);
-			if (!info->tsk_pinned) {
-				ret = -ENOMEM;
-				goto err;
-			}
-		}
-	}
+	int ret;
 
 	ret = rhltable_init(&task_bps_ht, &task_bps_ht_params);
 	if (ret)
-		goto err;
+		return ret;
+
+	ret = init_breakpoint_slots();
+	if (ret)
+		return ret;
 
 	constraints_initialized = true;
 
 	perf_pmu_register(&perf_breakpoint, "breakpoint", PERF_TYPE_BREAKPOINT);
 
 	return register_die_notifier(&hw_breakpoint_exceptions_nb);
-
-err:
-	for_each_possible_cpu(err_cpu) {
-		for (i = 0; i < TYPE_MAX; i++)
-			kfree(get_bp_info(err_cpu, i)->tsk_pinned);
-		if (err_cpu == cpu)
-			break;
-	}
-
-	return ret;
 }
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220628095833.2579903-6-elver%40google.com.
