Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6NB5OKQMGQEURLML4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63e.google.com (mail-ej1-x63e.google.com [IPv6:2a00:1450:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4224D55BFFA
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 11:59:25 +0200 (CEST)
Received: by mail-ej1-x63e.google.com with SMTP id kv9-20020a17090778c900b007262b461ecdsf3383085ejc.6
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 02:59:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656410361; cv=pass;
        d=google.com; s=arc-20160816;
        b=PadTPaMq9+F4mZKFpfFc4Js3/ym6Lz6hgPPbjn9OPEL/iCVB4OjNFbBxjz2aOiReNJ
         zH842dQavPM6wNt7WlTy5LKpyp9BxmD5e3DzG6WWzG0Rj1/+sACSs90QAJ7TxN7E6mMm
         eGzjg5zviS69S+VGoa0YMOVmOT6FvPzFqP9CB9G7YACprd9kzg4g+liYmF8vNE6qbIVN
         8n0gu3RkPY1q2AWpL5ZYYZh5dk3zvVpE28MdriYqrmp/VxmUIIJ7cjw0IB8KAo0lxd6x
         G/eYBsg62EQllYU5VDgFzI1z807PIhQVH5k7GkOGwffv33wSksvQwPacklzNnYxpr4fK
         44Ow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=7jyNMTrghRvXC4z9YHxDBdxoTSOwGoHuxLNPk/epsoU=;
        b=z79t+gJ4Znhxi0D5ldu0MpTdCZ1Z8NZ+mnrAXD14CqiG1u5zsWHL7/mmc/bFzQNytw
         F6VegL5s+junNHkjhXmPrjmYYsxKJTqsfqLIuGvBVKVnjuSofE/6mT3vScUv/e9EuIGe
         PnAWuZdiIXJ9X5pV3VehPSavwd324S/aXP5JbUU85FWeZtT26n+RYkN3NMcDsZxP/zr9
         l2G7S2CwrwIam+tGTP/rj886yTLbw+fdcr1OE/1lzhBvMVcCEzQyWe1QDwOrVHirnWA/
         hszAJLhQGa+bc5Tpa179OkLH0tCFraR8qGaq5JS1/UiTrNcNCrfuUv/vNnygVIW3PvEn
         8J+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bptAGp9M;
       spf=pass (google.com: domain of 3-nc6ygukcaefmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3-NC6YgUKCaEFMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7jyNMTrghRvXC4z9YHxDBdxoTSOwGoHuxLNPk/epsoU=;
        b=D4B3mfIxL50ChhdJYdNqWB4P+R/2U27L7Gb5YL5PEL4PujINgkGAZQhR4xxdtIshNN
         R2OccKmRMFgTogFdcOc5dmiCyRen4TNE0FQWJ3xdiU/6m+14YlJvers3IlI8lhL8KeWe
         9ojIZ61vPdcXjfEr/hwLg964ZxH3rjpQMvxj7d+QqBhkGCmbVeoIsMsLeaB2oQrPnVes
         /QaTePN/YDxC5VJbu1Um/gXPX4kNYkPXyQoUNE18i6eIfl2i/V3N/RTJY7TUJQHg1fKj
         7H/lW8msP4xyJjceDxjpbNg3H0mqL5INzBZbm5TBgG5Q2rbkMuCzhI+4W31rL8G/Dbep
         gqlQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7jyNMTrghRvXC4z9YHxDBdxoTSOwGoHuxLNPk/epsoU=;
        b=Ag+jU0KVm3gZxx16EPGoZpBFkO3O8RW8V0qx/+eON2hnvmBljkJ8jolkh0AcnsqwBv
         CVjuR8smDSPi3Xhpx7HosX1pV7fBp1xtz7BD92Hdh034/ITn2Saly/vv+qJxfHRdOZWa
         7l1vsaCpgGT/ehbM5SBNI5waQy0bASUk2FfdhGFYMyJi61tf5OhaVeRdvhYg1pyQTb6S
         I7U6ZKjPK9Ku9fKcBLswjTtTc8CmtpidfaOdRYEvoA6sxI+zDP9R/JhLui8IsfHJy5KR
         bZ/1jIAjrU6tzMD2MJ79OOTZiYkxqFte2Ll+5fYSLily43n04gxWn0vlJxb6QCqbWXoL
         i+JA==
X-Gm-Message-State: AJIora/nDRsqMDcJg6K1AUKWGN2yIdtRGBFGhKehM5zPOj9rpBOYiYr/
	TGmFjaGopdgGVBxWu0Zmozw=
X-Google-Smtp-Source: AGRyM1vwf/fzHcgqFHEPy+mHOuHYz3wdbh1OvuhQg8L+TOlP8flBC52zIjMju1ceMEIgIYq3+NBQJg==
X-Received: by 2002:aa7:cc03:0:b0:435:5574:bf30 with SMTP id q3-20020aa7cc03000000b004355574bf30mr22208626edt.15.1656410361674;
        Tue, 28 Jun 2022 02:59:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:26c9:b0:435:95a1:8b64 with SMTP id
 x9-20020a05640226c900b0043595a18b64ls4724173edd.2.gmail; Tue, 28 Jun 2022
 02:59:20 -0700 (PDT)
X-Received: by 2002:a05:6402:94e:b0:437:8d58:4ece with SMTP id h14-20020a056402094e00b004378d584ecemr13384397edz.396.1656410360475;
        Tue, 28 Jun 2022 02:59:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656410360; cv=none;
        d=google.com; s=arc-20160816;
        b=HgGXjJZKu3wm85Kb2w5LZXzGy5cap+ah4daZdMxdDf2TPqrzU6jinHy7nlA8OYADZd
         QnvlIMwFpoVwBtR6ZW5AgFilb+OmaDLtiuuMr3+KwomI4eVocVUqoCdKFQsdwhwFOiNV
         aQFypM30fpJagFeFRD8lO8YpnzccBreEc/72Rf9VMgcJ/ppsg9IgvM6vgiEjEoF+2Sn3
         FCKDgbdd97Cit32/tAkj5lmXMuUEykQ9FqawYZWsyfilxIfEGSNagyD3epP7yAz+55oi
         LYqz034RljaG1EWwJnVZrZ4lP2OUoZVCcPGtGT5ptq8ao7Lis+g0B0E7cw8vfEscgc2D
         CECQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=N0CsnkS2p9dPRyWs60cbt81/FpP/ql53P9DK+2utdXk=;
        b=XRe438ssz8jcoPtRZ/5XHYSfN+Vg5RnRQVh+SQOAXXwXZK0W4/BtezGnhN/rcNLWYJ
         k4G57Ip8DjBFGBszR56yHE6PiCsRm73Y9faZiP8TpGKBs4E1oxDA50V0+Kvmh2e9EcJR
         aDvxwDnI+i3j2UJ1CnXaRimdCYeWzEqKKkXf31rA4plW8Kb7UjMB/HAlA+GrUOuPj1Xh
         q0Jofd3PevZpOXZd/mf0kglIPchej1r/IUnBAET2XrNAWA7hRcpZ++b9Ssi6wKCk4c5O
         G0JkqqS07LkZWOBYytLNsWuo0ENIwK/D0KJlHWfiRU0lQuPfCfb64v0Zry7HArU/Jylz
         kxPA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bptAGp9M;
       spf=pass (google.com: domain of 3-nc6ygukcaefmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3-NC6YgUKCaEFMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id q31-20020a056402249f00b0043780485814si306652eda.2.2022.06.28.02.59.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jun 2022 02:59:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3-nc6ygukcaefmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id ne36-20020a1709077ba400b00722d5f547d8so3377091ejc.19
        for <kasan-dev@googlegroups.com>; Tue, 28 Jun 2022 02:59:20 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:3496:744e:315a:b41b])
 (user=elver job=sendgmr) by 2002:aa7:cccb:0:b0:437:77d3:4d5c with SMTP id
 y11-20020aa7cccb000000b0043777d34d5cmr17916256edt.230.1656410360304; Tue, 28
 Jun 2022 02:59:20 -0700 (PDT)
Date: Tue, 28 Jun 2022 11:58:28 +0200
In-Reply-To: <20220628095833.2579903-1-elver@google.com>
Message-Id: <20220628095833.2579903-9-elver@google.com>
Mime-Version: 1.0
References: <20220628095833.2579903-1-elver@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v2 08/13] powerpc/hw_breakpoint: Avoid relying on caller synchronization
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
 header.i=@google.com header.s=20210112 header.b=bptAGp9M;       spf=pass
 (google.com: domain of 3-nc6ygukcaefmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3-NC6YgUKCaEFMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
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
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220628095833.2579903-9-elver%40google.com.
