Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3UDRSLAMGQEYVOHTNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 81B44565943
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jul 2022 17:06:22 +0200 (CEST)
Received: by mail-ed1-x53d.google.com with SMTP id q18-20020a056402519200b004358ce90d97sf7260386edd.4
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 08:06:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656947182; cv=pass;
        d=google.com; s=arc-20160816;
        b=uUEtALzCLrtNXfFSgpuoFtjag/yM2Y6nrKKn4tvcs4TTBWzc8GBI+dZpxQtXYBRclU
         Xiqh/ByoDJ3ddenfQqTcVr6GVcHieNUNtWTl21wrTy+JN5LAtK2+poBWJGRzlIDxTjy/
         P0KeHTSCKw1/kbjbJNpx7ECGD95hoJ1AM7ZJu4mzmkHTcU4SmbcJqMowdJQ2wfuUmBF+
         0i503axjD2l3gdozPp91OGNLtrGVhpes2qz9l04svCun9KOZm2euFDZ7VgFWowvKLmAG
         w3f08JRGmwnlTnsH/Yb16J1Y6sHkK4a+UC+u/NxYOML1Tw+eZJZWwUzJqvOjmpnk/3o3
         P1yA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=A+36yqBuNhXf+j1hr/4BmHYemJ3aa7YCA/fcAOtLvM8=;
        b=sBlNiSkE2b43ROWDqq/hndFQsvbCw9wIa2Szguj39ICvtFG1OUDU4z30KRJOdY7K37
         hmbxJo+wTRDhZwzKfqYGlg1tUegOT7pJ6z5ASkrVi5s1duZ7JMW7uFjIMe+tLpm78vgp
         7xMgxoMj0NsDY7eyLJITSy/nhSjDDLbC0OZMoF+tdBzTq4q2A9abVJAaGdrPXa8pfjw+
         B36XMxesHWGEtPmPk63fobb31rAGLkOZt4NBreuN44vpBYyIrfpyUbiy21dWS9N2mQqU
         sdffFjiVVbbcxJ3ABo0YrXsjVDu8H1aaI3Z7UeOwX/gFhPgy5f1dTIAlVP+P/UOwdHnM
         KFew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VH8XGPdq;
       spf=pass (google.com: domain of 37ahdygukcrk3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=37AHDYgUKCRk3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=A+36yqBuNhXf+j1hr/4BmHYemJ3aa7YCA/fcAOtLvM8=;
        b=qm7TW4ujGvEinEC2pTnU1sTVB8wupdOHJsPmZfXZjNI9iF7wTgStDEeWLCveyleFaF
         Rigp6kfMHseHwXqnEXfi4uipm4FCPielhPseh14WdNEg4OsFDvI0ePpYpqLefDXHC3La
         nK7eOEeaU3PBhfUxXPBfhqLTP9dE+rHstwRsx42oZ4A9VMxm0eZeqIbjGRa4G/NvCurZ
         kqWmLxhR21jrPbvmHnzK/34Lk2tj7Osq3CbK3K+sDWYMhzyWWv2JS7Cqfhl9s1mqwNJh
         G7dFfdJdNMCDF5F2QIEkLNyjGkGb4TB3FzOs6bDB2//23xftM/Wo3VeZh2YvlNtZ8aU7
         uwNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=A+36yqBuNhXf+j1hr/4BmHYemJ3aa7YCA/fcAOtLvM8=;
        b=GI6QYbQarDHiphCkxCceVbjhBxFuJ1EYoxizGuTVoN3eIBROIWoG/rTCXE61ed7aq1
         zUUUOyAKJEc60rKOe3+teCVFoLzluCNmNpCI5+KxI0iYJPRDEMfwM4pu2RkEC0vUWLPr
         LGkEOvzP5KFcfHVFKXjHzgATdtG63X+UFWWBLJuJelja16InI+E2YRHGv6FnBB+j1jzH
         2abHhMmAUNCJ9i2x2eBmQonAHvwr26tjZLSIr3PT6ohOZYBq/bHVR406Hg3T9KpbiXxt
         SMfIEknMUWOgccXgSmyn87jGp7bp2pmVx3fjg7U12I+4J+2jU7sAOk5psYCiIqQaHJMP
         eo5g==
X-Gm-Message-State: AJIora9GZs1rlsGjBnDe/y15fP6YzsggB4E+wibiKxTdNICvAFUQJhVk
	u016L0VOTZ5w/Z4vEIqa76k=
X-Google-Smtp-Source: AGRyM1uQ7IIdnHHKlvQkt9eF6xpBr8UACNil9XUAWXWb4ecymVQ2Wp3LF2xqaw1NB2URe+8w3lqDEQ==
X-Received: by 2002:a05:6402:528f:b0:42a:c778:469e with SMTP id en15-20020a056402528f00b0042ac778469emr39108869edb.404.1656947182284;
        Mon, 04 Jul 2022 08:06:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:6d05:b0:726:a6bb:94ac with SMTP id
 sa5-20020a1709076d0500b00726a6bb94acls6333156ejc.10.gmail; Mon, 04 Jul 2022
 08:06:21 -0700 (PDT)
X-Received: by 2002:a17:907:1b1c:b0:6fe:f1a9:ef5a with SMTP id mp28-20020a1709071b1c00b006fef1a9ef5amr29964901ejc.233.1656947181044;
        Mon, 04 Jul 2022 08:06:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656947181; cv=none;
        d=google.com; s=arc-20160816;
        b=KO1sBlc+J0GL40iDPEncCtfjswFOpccpZgGXt1SZCyQrlAbyGqqg7VvcmOg5cXB/6v
         C0JvC0i9uE33jHeYkq7tQgk/ILe6KAMyAZLnhKXjp2i9+62rTmh+n4hPRqvpecXIQXwQ
         EgitMxIJHa9Og4FPU3+kau6wcN9S1NUk2G4QqN2XWfH2Jv6G6enuVk1BzwK6PTy0TA61
         fCpv/AUNQWMKT3GOLRg14t4zitJbKET0P+KcYNBVCa5i1SIlr4VMa2OosfmdkFcWGzf0
         EKAoHvgpvI9ZKOIuZ4YoWzLcWm+p72lAzVYtrrnd5i7+ku6VQO+zyy2ahzm5q72urNc0
         gRqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=JfXu58z7UaUBjps4RoWkmcCG0rF85BXMjQyAUe0XzyE=;
        b=ct1/QatZBp2PnfurQtseKlljBxTgSk39S19LTOFQ87nt2oct/3xLW21Dxk22CZmEA3
         UozG+aZ80v+HbFG64/eqv71sAm1RWevz6yOOoV22dqpGbwmXFS11reRe0BOdbb21yYCI
         0bMLxxoK5mQ6+rLFyG4wzbcC9V8fWj2GmIXrh9sJpiNi5j2kvusbLEXhF6S5aJYs7UBL
         xWZUM/0CvZcR1X6aWruAhbxdHjs33mbglCgjhfVwCohB2Yaskt+50QBXGRofbcbbV92Z
         gfg3BEx5wZvFNtJHiG+9X0WzbqxCAfht5CoxnbwyW4xvEg9piTwCLgx5qpAw27t04yaZ
         sY3g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VH8XGPdq;
       spf=pass (google.com: domain of 37ahdygukcrk3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=37AHDYgUKCRk3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id i24-20020a0564020f1800b004319ce84356si1199860eda.4.2022.07.04.08.06.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Jul 2022 08:06:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of 37ahdygukcrk3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id v16-20020a056402349000b00435a1c942a9so7412941edc.15
        for <kasan-dev@googlegroups.com>; Mon, 04 Jul 2022 08:06:21 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:6edf:e1bc:9a92:4ad0])
 (user=elver job=sendgmr) by 2002:a05:6402:4446:b0:43a:3f52:4172 with SMTP id
 o6-20020a056402444600b0043a3f524172mr9836137edb.417.1656947180619; Mon, 04
 Jul 2022 08:06:20 -0700 (PDT)
Date: Mon,  4 Jul 2022 17:05:09 +0200
In-Reply-To: <20220704150514.48816-1-elver@google.com>
Message-Id: <20220704150514.48816-10-elver@google.com>
Mime-Version: 1.0
References: <20220704150514.48816-1-elver@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v3 09/14] powerpc/hw_breakpoint: Avoid relying on caller synchronization
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
 header.i=@google.com header.s=20210112 header.b=VH8XGPdq;       spf=pass
 (google.com: domain of 37ahdygukcrk3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=37AHDYgUKCRk3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220704150514.48816-10-elver%40google.com.
