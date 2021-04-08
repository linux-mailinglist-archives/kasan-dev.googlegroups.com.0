Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRNZXOBQMGQEBTCM4BA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 926F53580BB
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Apr 2021 12:36:54 +0200 (CEST)
Received: by mail-qk1-x73b.google.com with SMTP id u5sf985685qkj.10
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Apr 2021 03:36:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617878213; cv=pass;
        d=google.com; s=arc-20160816;
        b=Gc9Z4ZidgosrghT71dYwCzZDLuEgTHc1VDwmxN6GwkNcHV0ITFQTGo0Jc6SwHK1jJm
         03747uV2I33TN4eHVZJdEl+GHdRGtZjQghhhKjZVYR5zJebJgWVid/qASuCPrk1zREvL
         2HoutP/PMeo6N7T6JYxFo53H5TxocAeLC78e2W908KpgyDzu/er3FwYfe7OUjU6MwH5y
         NTr5YCxIDAlCu+RISKKb25br86RFgrKWqtG5c8xIHASQf3QFVsxM3/LdY+iCP5t7XIdq
         Ci3bUpqxk4nOUEsBmp9Wa7xBE5eAehli22/YA1JzCiYPGFisE1q9NpEucP1jq6KtLSFA
         D3FA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=4gvUfxsWVVH4nGQgNEVVEpOLQ260I4w7FV/NeVQdJ/8=;
        b=edA1JUKCFw9IP/GfIx+2EJBZFxTCJTREaNJJTiL/IUrmtx8hfqBP5fIrINTCkVcy9D
         Or70yZucS3aQnBC3/XLDr7obQ+5owCrfKn2Skcqqjtkc5M7Vh3R7s/tTNZk0/xF2p0m/
         rhzYD+lIlXxmSA2i1OHyJ+IFZ/MFoo1LmSn14TM78ec3jwX3YW2Yua+8Ro8TmTjl7toY
         W4qZ6lnegBm8x+/550EUmh1vQlutNDAXaZQOdmyixjV5RylUQ4E/zJfRUIW2RZZ4O9Ba
         lT7PT8CnDelZRvwWG3qg1S+gH9RV1DI5G7/NC1c6A3rW3Q7/NvA4SsSytzlRV2r6HZPY
         tZQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aOyQ4Pw3;
       spf=pass (google.com: domain of 3xnxuyaukcumjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3xNxuYAUKCUMjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4gvUfxsWVVH4nGQgNEVVEpOLQ260I4w7FV/NeVQdJ/8=;
        b=WaYmpgDCLCTSpQysrw9hw63TZFpnu7cvOoM6bGBy0skS/CuksZd9Rahtcm23fGTKpL
         Hzu52eyWrSSqoJRUo8rNmj0dgtYz9ic49tlvW9sAW4eUQRsx7NdYwy5I6hSC/1vsDOKJ
         P9KBwQvOmzhabbSHWHLvNaGj2577qBKfHqzGXfFtpPgwlgJ+FX6bisk0z9Lhilr1uC45
         +GlT9vY48SXdwBTL+Jz9RIfUTuH6xyeysdDA3SqZ4j9zQSGFms8g07Qs1Q3oSlZQQTSl
         mpHtMRUlF1hZtUc2PDtNMQCt5AKM6s4bkBfPQYEXblFJrTGUWAuJBrBZxcL9xddrTC43
         KqNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4gvUfxsWVVH4nGQgNEVVEpOLQ260I4w7FV/NeVQdJ/8=;
        b=o8PJx4Rjuh6w59MrXqhpKQyyfmFA6fEnJgKk7RPKyEDt2JyK1u733Cx0Ds+jWueLTq
         Zf3QA7q3HRpM0FqJnDjkaHKOUehKlSGAmJke5E1Jgolxs8ZnFt09HnlBiTL2Pe1NanrW
         LadasQYPxI8n0EBBNk97xzXynfb8WdnhnhSZhZ4yfX/VuX7Y5D4/VqXAp0YjkBtO2cIa
         X8xaIO+ooKF++akxmZmUxGlB6M7wB0YoMHXTVcAEzuO7EhxyhP3ceAPRU8ElUMOXpYau
         lrHlFXMa5ufqOutjqY0wP+igKyIhAiqVH56XBs8EJPBa/oHO9RMlPNW/OqqQB930B6vf
         caQg==
X-Gm-Message-State: AOAM533xt6wdm+8vsI6lKXkd67Sb4NBWWGpp2Brca5CDK/27acvMawrj
	7dC+qPj3S6cnlizLleDSQXA=
X-Google-Smtp-Source: ABdhPJyP03otlQU7K43ytkNrcM7URUdZhfA66gn4H5TNq+JuvBzf31mB+HKCKWAU2GTrzUxME9Uelw==
X-Received: by 2002:ac8:124b:: with SMTP id g11mr6466912qtj.239.1617878213635;
        Thu, 08 Apr 2021 03:36:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:c83:: with SMTP id r3ls1494158qvr.5.gmail; Thu, 08
 Apr 2021 03:36:53 -0700 (PDT)
X-Received: by 2002:a05:6214:8c4:: with SMTP id da4mr8100747qvb.57.1617878213156;
        Thu, 08 Apr 2021 03:36:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617878213; cv=none;
        d=google.com; s=arc-20160816;
        b=YifpoaaeQvr/5RJyHrFcZIUxN3ixU55s/BgKp2fIZyxtgfsFE4fgKgVAPU9o0NZxXj
         IRSA6zjoCFPLmltgyu1eSQ95BNsw5QoTeLI1Aww7lPLDenAgive41r3IIVACP1wbish/
         xTI+e8fs9d8OG/HeNoIDdpmTUxIQ2Rt6y51hg/r6eaGGWG3m+KJERnTacDiD2bGii+hX
         8YD8ibIXtxiJDKsHQrXXHqO6jiUZPaIyUBSY9be/rf/NlKFY4rwPb050dRDPjSEmOUum
         FoYeNjv0ARHCPMNjUi+lY3hJHw5lcKYNotrTriPP2gqt4/WKAMzNwdbhtsw92kqLM/fF
         imcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=G3Xq6UoPycIyFKKsJYoXqIgvhMnp8KWQM7260h+GZ6k=;
        b=i5euQJ/btA7rpfEx6JtJpkIvQeNoOQez6yHx8wkypZEaTv7VeH51/Sl70lxKb8z/41
         ksdrhslKDRT+sWOCiYu+IKcer/Ex5GPzGIMyS8kD7RzybgQq6WjIp4ITUumwE+cOn0id
         IQFubivRjqvP8WF0KZq6hdPDWO8tBabQaaJO7de7b9xIoovNfEomLeDTpKZbQIiOUpA1
         5F8Yu3HKLQuzL0mnDuce0uILMjaUpEWIMYyJsFhxrytEKgGsNlQ+OZaHXiLBzwXz6Mps
         LGHlgrUiIG8BECueDxA//E6Y7gYHJdGq7QvBCA6qoSitgZ5kcStboUbdmPnpkhOjOELz
         tPxQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aOyQ4Pw3;
       spf=pass (google.com: domain of 3xnxuyaukcumjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3xNxuYAUKCUMjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id t7si1378096qkp.7.2021.04.08.03.36.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 08 Apr 2021 03:36:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3xnxuyaukcumjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id c7so988661qka.6
        for <kasan-dev@googlegroups.com>; Thu, 08 Apr 2021 03:36:53 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:9038:bbd3:4a12:abda])
 (user=elver job=sendgmr) by 2002:ad4:5e8b:: with SMTP id jl11mr7930340qvb.50.1617878212820;
 Thu, 08 Apr 2021 03:36:52 -0700 (PDT)
Date: Thu,  8 Apr 2021 12:35:58 +0200
In-Reply-To: <20210408103605.1676875-1-elver@google.com>
Message-Id: <20210408103605.1676875-4-elver@google.com>
Mime-Version: 1.0
References: <20210408103605.1676875-1-elver@google.com>
X-Mailer: git-send-email 2.31.0.208.g409f899ff0-goog
Subject: [PATCH v4 03/10] perf: Support only inheriting events if cloned with CLONE_THREAD
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, peterz@infradead.org, alexander.shishkin@linux.intel.com, 
	acme@kernel.org, mingo@redhat.com, jolsa@redhat.com, mark.rutland@arm.com, 
	namhyung@kernel.org, tglx@linutronix.de
Cc: glider@google.com, viro@zeniv.linux.org.uk, arnd@arndb.de, 
	christian@brauner.io, dvyukov@google.com, jannh@google.com, axboe@kernel.dk, 
	mascasa@google.com, pcc@google.com, irogers@google.com, oleg@redhat.com, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-kernel@vger.kernel.org, x86@kernel.org, 
	linux-kselftest@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=aOyQ4Pw3;       spf=pass
 (google.com: domain of 3xnxuyaukcumjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3xNxuYAUKCUMjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
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

Adds bit perf_event_attr::inherit_thread, to restricting inheriting
events only if the child was cloned with CLONE_THREAD.

This option supports the case where an event is supposed to be
process-wide only (including subthreads), but should not propagate
beyond the current process's shared environment.

Link: https://lore.kernel.org/lkml/YBvj6eJR%2FDY2TsEB@hirez.programming.kicks-ass.net/
Suggested-by: Peter Zijlstra <peterz@infradead.org>
Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Add patch to series.
---
 include/linux/perf_event.h      |  5 +++--
 include/uapi/linux/perf_event.h |  3 ++-
 kernel/events/core.c            | 21 ++++++++++++++-------
 kernel/fork.c                   |  2 +-
 4 files changed, 20 insertions(+), 11 deletions(-)

diff --git a/include/linux/perf_event.h b/include/linux/perf_event.h
index 3d478abf411c..1660039199b2 100644
--- a/include/linux/perf_event.h
+++ b/include/linux/perf_event.h
@@ -958,7 +958,7 @@ extern void __perf_event_task_sched_in(struct task_struct *prev,
 				       struct task_struct *task);
 extern void __perf_event_task_sched_out(struct task_struct *prev,
 					struct task_struct *next);
-extern int perf_event_init_task(struct task_struct *child);
+extern int perf_event_init_task(struct task_struct *child, u64 clone_flags);
 extern void perf_event_exit_task(struct task_struct *child);
 extern void perf_event_free_task(struct task_struct *task);
 extern void perf_event_delayed_put(struct task_struct *task);
@@ -1449,7 +1449,8 @@ perf_event_task_sched_in(struct task_struct *prev,
 static inline void
 perf_event_task_sched_out(struct task_struct *prev,
 			  struct task_struct *next)			{ }
-static inline int perf_event_init_task(struct task_struct *child)	{ return 0; }
+static inline int perf_event_init_task(struct task_struct *child,
+				       u64 clone_flags)			{ return 0; }
 static inline void perf_event_exit_task(struct task_struct *child)	{ }
 static inline void perf_event_free_task(struct task_struct *task)	{ }
 static inline void perf_event_delayed_put(struct task_struct *task)	{ }
diff --git a/include/uapi/linux/perf_event.h b/include/uapi/linux/perf_event.h
index ad15e40d7f5d..813efb65fea8 100644
--- a/include/uapi/linux/perf_event.h
+++ b/include/uapi/linux/perf_event.h
@@ -389,7 +389,8 @@ struct perf_event_attr {
 				cgroup         :  1, /* include cgroup events */
 				text_poke      :  1, /* include text poke events */
 				build_id       :  1, /* use build id in mmap2 events */
-				__reserved_1   : 29;
+				inherit_thread :  1, /* children only inherit if cloned with CLONE_THREAD */
+				__reserved_1   : 28;
 
 	union {
 		__u32		wakeup_events;	  /* wakeup every n events */
diff --git a/kernel/events/core.c b/kernel/events/core.c
index a9a0a46909af..de2917b3c59e 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -11649,6 +11649,9 @@ static int perf_copy_attr(struct perf_event_attr __user *uattr,
 	    (attr->sample_type & PERF_SAMPLE_WEIGHT_STRUCT))
 		return -EINVAL;
 
+	if (!attr->inherit && attr->inherit_thread)
+		return -EINVAL;
+
 out:
 	return ret;
 
@@ -12869,12 +12872,13 @@ static int
 inherit_task_group(struct perf_event *event, struct task_struct *parent,
 		   struct perf_event_context *parent_ctx,
 		   struct task_struct *child, int ctxn,
-		   int *inherited_all)
+		   u64 clone_flags, int *inherited_all)
 {
 	int ret;
 	struct perf_event_context *child_ctx;
 
-	if (!event->attr.inherit) {
+	if (!event->attr.inherit ||
+	    (event->attr.inherit_thread && !(clone_flags & CLONE_THREAD))) {
 		*inherited_all = 0;
 		return 0;
 	}
@@ -12906,7 +12910,8 @@ inherit_task_group(struct perf_event *event, struct task_struct *parent,
 /*
  * Initialize the perf_event context in task_struct
  */
-static int perf_event_init_context(struct task_struct *child, int ctxn)
+static int perf_event_init_context(struct task_struct *child, int ctxn,
+				   u64 clone_flags)
 {
 	struct perf_event_context *child_ctx, *parent_ctx;
 	struct perf_event_context *cloned_ctx;
@@ -12946,7 +12951,8 @@ static int perf_event_init_context(struct task_struct *child, int ctxn)
 	 */
 	perf_event_groups_for_each(event, &parent_ctx->pinned_groups) {
 		ret = inherit_task_group(event, parent, parent_ctx,
-					 child, ctxn, &inherited_all);
+					 child, ctxn, clone_flags,
+					 &inherited_all);
 		if (ret)
 			goto out_unlock;
 	}
@@ -12962,7 +12968,8 @@ static int perf_event_init_context(struct task_struct *child, int ctxn)
 
 	perf_event_groups_for_each(event, &parent_ctx->flexible_groups) {
 		ret = inherit_task_group(event, parent, parent_ctx,
-					 child, ctxn, &inherited_all);
+					 child, ctxn, clone_flags,
+					 &inherited_all);
 		if (ret)
 			goto out_unlock;
 	}
@@ -13004,7 +13011,7 @@ static int perf_event_init_context(struct task_struct *child, int ctxn)
 /*
  * Initialize the perf_event context in task_struct
  */
-int perf_event_init_task(struct task_struct *child)
+int perf_event_init_task(struct task_struct *child, u64 clone_flags)
 {
 	int ctxn, ret;
 
@@ -13013,7 +13020,7 @@ int perf_event_init_task(struct task_struct *child)
 	INIT_LIST_HEAD(&child->perf_event_list);
 
 	for_each_task_context_nr(ctxn) {
-		ret = perf_event_init_context(child, ctxn);
+		ret = perf_event_init_context(child, ctxn, clone_flags);
 		if (ret) {
 			perf_event_free_task(child);
 			return ret;
diff --git a/kernel/fork.c b/kernel/fork.c
index 426cd0c51f9e..f592c9a0272a 100644
--- a/kernel/fork.c
+++ b/kernel/fork.c
@@ -2084,7 +2084,7 @@ static __latent_entropy struct task_struct *copy_process(
 	if (retval)
 		goto bad_fork_cleanup_policy;
 
-	retval = perf_event_init_task(p);
+	retval = perf_event_init_task(p, clone_flags);
 	if (retval)
 		goto bad_fork_cleanup_policy;
 	retval = audit_alloc(p);
-- 
2.31.0.208.g409f899ff0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210408103605.1676875-4-elver%40google.com.
