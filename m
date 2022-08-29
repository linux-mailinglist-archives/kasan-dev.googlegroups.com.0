Return-Path: <kasan-dev+bncBC7OBJGL2MHBBI7LWKMAMGQEALIEYOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id BCC775A4C44
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Aug 2022 14:48:35 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id w2-20020adfbac2000000b00225688186e5sf1111779wrg.8
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Aug 2022 05:48:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661777315; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y8rhzbLYCBk+CBxLKZ48CV9qR5p7lbv3gxZprVKEfm0YnwPguBTvuR4siXVHgsuHhQ
         Pr+iozjIg45+mkUcUHelXALGbw/o7veQEF9miIWl08dEM0O5+e/wAikWV6eLBjFuoJ4q
         VUN+4UGrQlawe5zg7V690TO0ztMS5B3lJDN4PDOc67YNfpR99QsyV2UJbCFGVbxdGLe6
         w8J37fqXsyJUbUCqxq0er0KoEvQOGPDi8/ESx7Tk4ngX+L3IN6jqYCV6KcQLX/GWH4wJ
         rrSVxAWeIxjx4T/fqLxEi93dNTr7dxR09ofeQuhCcTF+umtnzORr1t5hZCWi9BvMS5QL
         3qtg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=3LP4udDfV6MsU0p0uKTQ4vuTqDq0L0cFQ+zobIuKYPQ=;
        b=mqr3c2Vt69GxC8O+Fpjsva8TIINDcIcIEnS6YIOadjWS8T6uwWoemNiOhOAkfMf1be
         YQ8HsdX/38HAm6+DWqeOB3ArDxqkxrkmZJwKN+5ymXn9XD+O0EB/qafpVcl47MmI1Cg+
         FiDR920sa5NdjTZpEl/UDWKSXaWX78R+DP7PtsJDPNcS2p3D2ssipYa5tuyu0pkpe7nX
         fjWr2p5+cPrgT9vLIbkC2vzYk10BNRaXu8CPpQPc9L2RFg/cwaLiHkq2634kZoQTfmzo
         huO9+TNpauEOu76x0Ga+D9Fc1JhxNuVVM8jWugTv55rxA4ThN9169BxOznj+hlQt3h95
         hjkA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rToQIqGv;
       spf=pass (google.com: domain of 3orumywukcv8bisbodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3orUMYwUKCV8BISBODLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=3LP4udDfV6MsU0p0uKTQ4vuTqDq0L0cFQ+zobIuKYPQ=;
        b=b+LG5bBJ9yKNlz3aOtSjVrh4ydCyayPxkWLc7IeM8YbKHBjbEuEavacyzCGd3FvRX5
         zOgd8dKjoim5JhjVMsP5+5jy16IGcUPBIIhMsSO4gqw4OsUFYgMlNpiMNVVSkWBKrZHO
         txWsbGLyGfhJGoQRRCqBzRfJCRYy4tarufpTSVrvDXNnKqw3+upJvcUiPwRbpPh+geyN
         SNKpJyB1cJasqF7v2so3Va2N2kbsrkR4iOUEwIu2Uehldp6gIlnjBpqCZTF3+xsZbk1E
         o2vapYBWDjMQs7hAFN3BNKUwlrEQGE7cjyfwhoCi3syZQUsvw0bjPkUpHMn8+n3AqG4n
         aXww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=3LP4udDfV6MsU0p0uKTQ4vuTqDq0L0cFQ+zobIuKYPQ=;
        b=IXjgO7puw/LBOHmJsGwWXGqjeueqSM+4d48/+nnXYcOA673GU9/GGVNWINBsqYBsp0
         Hj9/ApcK9gB8wvWCruwZw2RzKk6gFuLEzE2Op4TeHzp34Kv2CCDDQaw4J+jVgYqIL0cZ
         ypfA0rDIfBSXKhgmKSNDOA0DAATTZRgItzorZAKrHqlQJfn9FU7CeTbqXHH4wEos6k1l
         S9QG1jalpwT237Qk62jx/Kw7fluVa76AdpoEqtpm8PZWuAd8/KYjqXYtMPaS20kXpqX9
         vW2swhjSr1dst7NH0+ops7RgW6Ei8jm2fa8UG/O2QdpXVjL+Pr/GTWItxgcysLvxIKxn
         68wg==
X-Gm-Message-State: ACgBeo02UcxsF/Gc7HHUcSCYVYjtiqNbVab0etT/EXH0aOdGliGpgluq
	gUbJsim9olT4k4Xh7IO8lEQ=
X-Google-Smtp-Source: AA6agR6hUyqZini+NqTsnTJ8hzbD3sDbNeKBYUNO7yRWB961m2Oynu5WQTLMnGoEdoDk7EMFcvBd2g==
X-Received: by 2002:adf:da50:0:b0:223:a1f5:fa68 with SMTP id r16-20020adfda50000000b00223a1f5fa68mr6079285wrl.528.1661777315526;
        Mon, 29 Aug 2022 05:48:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:251:b0:221:24a2:5cf with SMTP id
 m17-20020a056000025100b0022124a205cfls1693366wrz.0.-pod-prod-gmail; Mon, 29
 Aug 2022 05:48:34 -0700 (PDT)
X-Received: by 2002:a5d:484d:0:b0:226:d977:5a33 with SMTP id n13-20020a5d484d000000b00226d9775a33mr3412136wrs.398.1661777314400;
        Mon, 29 Aug 2022 05:48:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661777314; cv=none;
        d=google.com; s=arc-20160816;
        b=ZAL5xLh6nijeTwuYsloVFaUlKTKurnJ1WU6ScALMPsblUeqasQggoVbrRbjBD1A/s1
         fsg5m27xsOZfCe2p7wbsyn017CIxglwN6vWOYbrv6HmZVTZG5gvFgoCRfd351SaCROmE
         O7kEzGzwX1t0yrGi1E1Tc53+9OCMIyqZy+rCmzhWPRXLlkasUjDYOf2lSWKuoLjAap8u
         EHFU+t6hUezID+h0ggES/ZleA+mWdlpypoWfcUgqtWnh1GLgwaXHsOoiLDzHxg+rJEKM
         kYapLdFWGzFZYPKWO7qmI/oeA9GLGBe1Ck/7KV3WXU3/v1HYgnQiaszTk5MCFNeUbtWE
         56Yg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=tHogyOz5U0y7+H4DYPxiXG1ukMrOYP0VQiSgNpC/zOM=;
        b=fBXMAAwtUAnUV6AfWNT52Cis1253hXf3gPtvHYIQLdH4qAiV5q/cpBjfn9KK2Zktk9
         /Zff6poU3ZgHt35YxXSBTeHs/aIfSjaWkdbqPK+r3wnLsaLb0gp4N88LrFArSqMkrFN3
         u7yesDmC2IkIYlSLpVOQq+ULY38jF1b3PFeTcPqeokWI2J+7U3P9rbb/eLnyMhzkXNPr
         nFbgamM0GOPPSPXrX/gxMMaJmk60UVEEgYRUOyq9zoPkpUdLnD8gGxPyDXx6LJkXUQF2
         dt/BssR/xIPYunjvGESIhRN+iiEbbU55TKHE0wC55b12vAO0a06Uqc4NKmYyGT3AOdOV
         GKQA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rToQIqGv;
       spf=pass (google.com: domain of 3orumywukcv8bisbodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3orUMYwUKCV8BISBODLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id bi19-20020a05600c3d9300b003a6787eaf57si1109879wmb.2.2022.08.29.05.48.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Aug 2022 05:48:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3orumywukcv8bisbodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id w2-20020adfbac2000000b00225688186e5so1111760wrg.8
        for <kasan-dev@googlegroups.com>; Mon, 29 Aug 2022 05:48:34 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:196d:4fc7:fa9c:62e3])
 (user=elver job=sendgmr) by 2002:a5d:5048:0:b0:226:df3b:72f4 with SMTP id
 h8-20020a5d5048000000b00226df3b72f4mr1036162wrt.205.1661777314053; Mon, 29
 Aug 2022 05:48:34 -0700 (PDT)
Date: Mon, 29 Aug 2022 14:47:18 +0200
In-Reply-To: <20220829124719.675715-1-elver@google.com>
Mime-Version: 1.0
References: <20220829124719.675715-1-elver@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220829124719.675715-14-elver@google.com>
Subject: [PATCH v4 13/14] perf/hw_breakpoint: Optimize max_bp_pinned_slots()
 for CPU-independent task targets
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
 header.i=@google.com header.s=20210112 header.b=rToQIqGv;       spf=pass
 (google.com: domain of 3orumywukcv8bisbodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3orUMYwUKCV8BISBODLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--elver.bounces.google.com;
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

Running the perf benchmark with (note: more aggressive parameters vs.
preceding changes, but same 256 CPUs host):

 | $> perf bench -r 100 breakpoint thread -b 4 -p 128 -t 512
 | # Running 'breakpoint/thread' benchmark:
 | # Created/joined 100 threads with 4 breakpoints and 128 parallelism
 |      Total time: 1.989 [sec]
 |
 |       38.854160 usecs/op
 |     4973.332500 usecs/op/cpu

    20.43%  [kernel]       [k] queued_spin_lock_slowpath
    18.75%  [kernel]       [k] osq_lock
    16.98%  [kernel]       [k] rhashtable_jhash2
     8.34%  [kernel]       [k] task_bp_pinned
     4.23%  [kernel]       [k] smp_cfm_core_cond
     3.65%  [kernel]       [k] bcmp
     2.83%  [kernel]       [k] toggle_bp_slot
     1.87%  [kernel]       [k] find_next_bit
     1.49%  [kernel]       [k] __reserve_bp_slot

We can see that a majority of the time is now spent hashing task
pointers to index into task_bps_ht in task_bp_pinned().

Obtaining the max_bp_pinned_slots() for CPU-independent task targets
currently is O(#cpus), and calls task_bp_pinned() for each CPU, even if
the result of task_bp_pinned() is CPU-independent.

The loop in max_bp_pinned_slots() wants to compute the maximum slots
across all CPUs. If task_bp_pinned() is CPU-independent, we can do so by
obtaining the max slots across all CPUs and adding task_bp_pinned().

To do so in O(1), use a bp_slots_histogram for CPU-pinned slots.

After this optimization:

 | $> perf bench -r 100 breakpoint thread -b 4 -p 128 -t 512
 | # Running 'breakpoint/thread' benchmark:
 | # Created/joined 100 threads with 4 breakpoints and 128 parallelism
 |      Total time: 1.930 [sec]
 |
 |       37.697832 usecs/op
 |     4825.322500 usecs/op/cpu

    19.13%  [kernel]       [k] queued_spin_lock_slowpath
    18.21%  [kernel]       [k] rhashtable_jhash2
    15.46%  [kernel]       [k] osq_lock
     6.27%  [kernel]       [k] toggle_bp_slot
     5.91%  [kernel]       [k] task_bp_pinned
     5.05%  [kernel]       [k] smp_cfm_core_cond
     1.78%  [kernel]       [k] update_sg_lb_stats
     1.36%  [kernel]       [k] llist_reverse_order
     1.34%  [kernel]       [k] find_next_bit
     1.19%  [kernel]       [k] bcmp

Suggesting that time spent in task_bp_pinned() has been reduced.
However, we're still hashing too much, which will be addressed in the
subsequent change.

Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Acked-by: Ian Rogers <irogers@google.com>
---
v3:
* Update hw_breakpoint_is_used() to include global cpu_pinned.

v2:
* New patch.
---
 kernel/events/hw_breakpoint.c | 57 ++++++++++++++++++++++++++++++++---
 1 file changed, 53 insertions(+), 4 deletions(-)

diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
index 03ebecf048c0..a489f31fe147 100644
--- a/kernel/events/hw_breakpoint.c
+++ b/kernel/events/hw_breakpoint.c
@@ -64,6 +64,9 @@ static struct bp_cpuinfo *get_bp_info(int cpu, enum bp_type_idx type)
 	return per_cpu_ptr(bp_cpuinfo + type, cpu);
 }
 
+/* Number of pinned CPU breakpoints globally. */
+static struct bp_slots_histogram cpu_pinned[TYPE_MAX];
+
 /* Keep track of the breakpoints attached to tasks */
 static struct rhltable task_bps_ht;
 static const struct rhashtable_params task_bps_ht_params = {
@@ -194,6 +197,10 @@ static __init int init_breakpoint_slots(void)
 				goto err;
 		}
 	}
+	for (i = 0; i < TYPE_MAX; i++) {
+		if (!bp_slots_histogram_alloc(&cpu_pinned[i], i))
+			goto err;
+	}
 
 	return 0;
 err:
@@ -203,6 +210,8 @@ static __init int init_breakpoint_slots(void)
 		if (err_cpu == cpu)
 			break;
 	}
+	for (i = 0; i < TYPE_MAX; i++)
+		bp_slots_histogram_free(&cpu_pinned[i]);
 
 	return -ENOMEM;
 }
@@ -270,6 +279,9 @@ static unsigned int max_task_bp_pinned(int cpu, enum bp_type_idx type)
 /*
  * Count the number of breakpoints of the same type and same task.
  * The given event must be not on the list.
+ *
+ * If @cpu is -1, but the result of task_bp_pinned() is not CPU-independent,
+ * returns a negative value.
  */
 static int task_bp_pinned(int cpu, struct perf_event *bp, enum bp_type_idx type)
 {
@@ -288,9 +300,18 @@ static int task_bp_pinned(int cpu, struct perf_event *bp, enum bp_type_idx type)
 		goto out;
 
 	rhl_for_each_entry_rcu(iter, pos, head, hw.bp_list) {
-		if (find_slot_idx(iter->attr.bp_type) == type &&
-		    (iter->cpu < 0 || cpu == iter->cpu))
-			count += hw_breakpoint_weight(iter);
+		if (find_slot_idx(iter->attr.bp_type) != type)
+			continue;
+
+		if (iter->cpu >= 0) {
+			if (cpu == -1) {
+				count = -1;
+				goto out;
+			} else if (cpu != iter->cpu)
+				continue;
+		}
+
+		count += hw_breakpoint_weight(iter);
 	}
 
 out:
@@ -316,6 +337,19 @@ max_bp_pinned_slots(struct perf_event *bp, enum bp_type_idx type)
 	int pinned_slots = 0;
 	int cpu;
 
+	if (bp->hw.target && bp->cpu < 0) {
+		int max_pinned = task_bp_pinned(-1, bp, type);
+
+		if (max_pinned >= 0) {
+			/*
+			 * Fast path: task_bp_pinned() is CPU-independent and
+			 * returns the same value for any CPU.
+			 */
+			max_pinned += bp_slots_histogram_max(&cpu_pinned[type], type);
+			return max_pinned;
+		}
+	}
+
 	for_each_cpu(cpu, cpumask) {
 		struct bp_cpuinfo *info = get_bp_info(cpu, type);
 		int nr;
@@ -366,8 +400,11 @@ toggle_bp_slot(struct perf_event *bp, bool enable, enum bp_type_idx type,
 
 	/* Pinned counter cpu profiling */
 	if (!bp->hw.target) {
+		struct bp_cpuinfo *info = get_bp_info(bp->cpu, type);
+
 		lockdep_assert_held_write(&bp_cpuinfo_sem);
-		get_bp_info(bp->cpu, type)->cpu_pinned += weight;
+		bp_slots_histogram_add(&cpu_pinned[type], info->cpu_pinned, weight);
+		info->cpu_pinned += weight;
 		return 0;
 	}
 
@@ -804,6 +841,18 @@ bool hw_breakpoint_is_used(void)
 		}
 	}
 
+	for (int type = 0; type < TYPE_MAX; ++type) {
+		for (int slot = 0; slot < hw_breakpoint_slots_cached(type); ++slot) {
+			/*
+			 * Warn, because if there are CPU pinned counters,
+			 * should never get here; bp_cpuinfo::cpu_pinned should
+			 * be consistent with the global cpu_pinned histogram.
+			 */
+			if (WARN_ON(atomic_read(&cpu_pinned[type].count[slot])))
+				return true;
+		}
+	}
+
 	return false;
 }
 
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220829124719.675715-14-elver%40google.com.
