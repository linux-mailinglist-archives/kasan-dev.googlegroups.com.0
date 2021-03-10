Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5GEUKBAMGQEZCUE2BI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B931333A40
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Mar 2021 11:41:57 +0100 (CET)
Received: by mail-io1-xd40.google.com with SMTP id w8sf12480324iox.13
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Mar 2021 02:41:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615372916; cv=pass;
        d=google.com; s=arc-20160816;
        b=KU8jN0DDASY9a4vKwIQGwxWrBbm3Y7dHpPGWfmGzJnTMTf8QkXCO+EbEkWv+PtIVUi
         bBaD2tegqxJl3aqeL8vKsXUBOSDyLyW3CnPvWIB6jn9LEVppQXzgl9QdD7ml1AOC9vqj
         Aa7Oe9ZsVIfAB7klQyvf2NgBULv9lx9eHta5LIWkGoacPwD9XHou4e4BuchSTrrYdF0p
         3QDMbU/lw8v59UsZ+szXhwpQ1Z1CEnFyWA46J9hvalMjI3R9mf7ioEznHnQ8TVIkotk3
         1V95lp5tdJ1hRsQqA3laMnk94hW0+mSAQrTjlg9S0d1iVyYNgwu/4cc4vfNoU+9ArQS2
         D2og==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=lrQ/fIMQnr2ABXTaOKh25OXLzjE0YgAyD08Sg6E79YU=;
        b=XBWpatTitVNOsTeGIavw2K7xMV27nN/1hoBNqEtrknlc361pshiDT995unMWo7W8x3
         pofZHnPX1lca8P0l24EuO85eKJ87HE5nVM8/pqEW2hbHbtsMyP5oLdoLxKsyMD8oBGkJ
         +wsJhG/FaEI6r4XTWz67aSulkqTO6a5g6r8WVze259/Em1QK5GxtfkgnYjjxxk+gnyVa
         4Kr8xRxfS2uTHoGpFjWW48zoKAkZVp5n1wuVlvoyAMqlFPLOP6RH7HK3wodZE1pcVk+B
         8Yndo4oNRKI5aFah3cynOgrp4Uf0qBG6I03UNucg5htd6bjeLhM7hEBhQ+BQlrYmH6qi
         zpEw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="N/u3p5qk";
       spf=pass (google.com: domain of 3c6jiyaukceiipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3c6JIYAUKCeIIPZIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lrQ/fIMQnr2ABXTaOKh25OXLzjE0YgAyD08Sg6E79YU=;
        b=Ul+uDiNusEVMYrRIwvkFZOUYDLlhqWTHHrvj2CuZGDmj+Pee9acZ8GeBfkSTkEOPNe
         EFahh3qE+s75OdN/d7NasEMioaIpw8ZTz0iyHyRpMWy0QT1DmKOGVAqEbEc3b0VKS3kB
         vxN1petCPeYdkl4gJSn89H+aMNQcZvkCYtWUcRxjUj2BjZxKjTfKJSjyCQk6Jlz5ait9
         fZoSEigV+o9AtdjDgTzDU+9RqbFHKTvmTmw8G9gNkkTfh7j+oXg7tXHkgx5XxV6Qv2a+
         eq0Em5tUGtJcaCTZvuD/il94rWoCHP1r+vhibaEJjPPkpUXcM2a55vOFMmHMZldK37mN
         DdRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lrQ/fIMQnr2ABXTaOKh25OXLzjE0YgAyD08Sg6E79YU=;
        b=O/8lbaLb0gziZBHPv9abbnNOURp/BW7Tqm/kh1bH2MIrNAqeWvd06bCqPrNblbbsNs
         /E00gI/cfdorWHuw9NsaSaFDAPnHZnDrcLoH/+q9hqlGb2J1G7A0jVETRgQ15yO+b+SQ
         LMZVpbrJ6MXKbDfvJvhSfdBU+B0AFXYBOONd2r5rjXuu9vFnO6vUwbcrckMPS1tcdu3I
         TSAXs6MnhhS0DDp1XSldmI/jzC6zXEwkeXvWQ/hGGNr/w3cQvKKJRpYzE453kYH7m91r
         rfV2zYOwZbGHh7zQgaIiyXLaC41AruLWKEXrNMshNwABx5umfMp8hSs7v5YspeHa62TT
         o+NQ==
X-Gm-Message-State: AOAM533ILW1fj5qESsTXqecuO9o6bAJpn9lQ4U9XSOW2I6DY+baGj3ep
	mxVKDX3dCPuD/r+0y7UOEvc=
X-Google-Smtp-Source: ABdhPJyzFIRrDi3YUZLNwq2a0nsJzozLjHVqb/TTV8qwF5rWCsl1tKDx1/u4upbZLIVzDOh3Tn6uCA==
X-Received: by 2002:a02:ec6:: with SMTP id 189mr2245678jae.91.1615372916395;
        Wed, 10 Mar 2021 02:41:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:191b:: with SMTP id p27ls211629jal.4.gmail; Wed, 10
 Mar 2021 02:41:55 -0800 (PST)
X-Received: by 2002:a02:ce8d:: with SMTP id y13mr2272691jaq.29.1615372915898;
        Wed, 10 Mar 2021 02:41:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615372915; cv=none;
        d=google.com; s=arc-20160816;
        b=WefBudB7Zw12M+9C6n4bi4C4nD+/sI7rnVoBKCS80s9XDDtTQ+FDivQP8aYuR5ym5+
         0uPRYTTu2MH+fLU2sXOFnPF55zxo+pB2aG30r/G3kDYscnL+JUdRsyfKSiXdjRRSG2Vj
         zpb9dYGUrgN+LNmGTfjM3D0tQ9U7BieCflIqmApvVsl3OsZjZz3bbC3LXUA72laqf5MC
         qSgs7zCw5T6g/FG0ij6lyKv+O88q0nJLkrcEPfopplGElql6zQu9Guwm3Fx83WrTcirF
         2v0Q3ELVfCgYtTxdYlZIhtzdsHfgLmSW6GhnZzU5Mz+ToFdo2lDR9FtCBlq5ZJciHDUB
         NgyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=LX0emKbgsHYtGpYyL1x1FnLQ5ewlS0gEm+vlZ3nascQ=;
        b=KvmI4gCBhOeuJxRxRM6D4fvW9qJq6yij7uC0si2QXJxincRgvP9YmdDzM7/eBjqJ15
         Kp6pfLNqbOn+lEy0RN+HSTB5T6Zxr2vPAAOY8/GpnajH3OEo2fphoqquiHJtSDiTMO7m
         zCuqKEBAoLe8PgmBqaGczcI/ZVfZCTYAvcXj3+R84rN8HYSAhCN9Eblxuqwfqo899sq6
         axaTxoOq1lg2ELsBb3b+SniMiXBLOgdPvpbJpbDva4A2z7odK8JwIGvEZ9L5OZUD+TzI
         V5fI0L2eIqQ6PEt0G7X6BfLhUTL6z9NDYHzfGBLHdv45x/+NTLNa6NJpVBJivCD3x5bj
         JNfA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="N/u3p5qk";
       spf=pass (google.com: domain of 3c6jiyaukceiipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3c6JIYAUKCeIIPZIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id r19si988127iov.3.2021.03.10.02.41.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 10 Mar 2021 02:41:55 -0800 (PST)
Received-SPF: pass (google.com: domain of 3c6jiyaukceiipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id o14so12357304qvn.18
        for <kasan-dev@googlegroups.com>; Wed, 10 Mar 2021 02:41:55 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:e995:ac0b:b57c:49a4])
 (user=elver job=sendgmr) by 2002:ad4:4d82:: with SMTP id cv2mr2356657qvb.6.1615372915311;
 Wed, 10 Mar 2021 02:41:55 -0800 (PST)
Date: Wed, 10 Mar 2021 11:41:33 +0100
In-Reply-To: <20210310104139.679618-1-elver@google.com>
Message-Id: <20210310104139.679618-3-elver@google.com>
Mime-Version: 1.0
References: <20210310104139.679618-1-elver@google.com>
X-Mailer: git-send-email 2.30.1.766.gb4fecdf3b7-goog
Subject: [PATCH RFC v2 2/8] perf/core: Support only inheriting events if
 cloned with CLONE_THREAD
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, peterz@infradead.org, alexander.shishkin@linux.intel.com, 
	acme@kernel.org, mingo@redhat.com, jolsa@redhat.com, mark.rutland@arm.com, 
	namhyung@kernel.org, tglx@linutronix.de
Cc: glider@google.com, viro@zeniv.linux.org.uk, arnd@arndb.de, 
	christian@brauner.io, dvyukov@google.com, jannh@google.com, axboe@kernel.dk, 
	mascasa@google.com, pcc@google.com, irogers@google.com, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-kernel@vger.kernel.org, x86@kernel.org, 
	linux-kselftest@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="N/u3p5qk";       spf=pass
 (google.com: domain of 3c6jiyaukceiipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3c6JIYAUKCeIIPZIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--elver.bounces.google.com;
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
index fab42cfbd350..982ad61c653a 100644
--- a/include/linux/perf_event.h
+++ b/include/linux/perf_event.h
@@ -955,7 +955,7 @@ extern void __perf_event_task_sched_in(struct task_struct *prev,
 				       struct task_struct *task);
 extern void __perf_event_task_sched_out(struct task_struct *prev,
 					struct task_struct *next);
-extern int perf_event_init_task(struct task_struct *child);
+extern int perf_event_init_task(struct task_struct *child, u64 clone_flags);
 extern void perf_event_exit_task(struct task_struct *child);
 extern void perf_event_free_task(struct task_struct *task);
 extern void perf_event_delayed_put(struct task_struct *task);
@@ -1446,7 +1446,8 @@ perf_event_task_sched_in(struct task_struct *prev,
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
index bff498766065..a8382e6c907c 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -11597,6 +11597,9 @@ static int perf_copy_attr(struct perf_event_attr __user *uattr,
 	    (attr->sample_type & PERF_SAMPLE_WEIGHT_STRUCT))
 		return -EINVAL;
 
+	if (!attr->inherit && attr->inherit_thread)
+		return -EINVAL;
+
 out:
 	return ret;
 
@@ -12820,12 +12823,13 @@ static int
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
@@ -12857,7 +12861,8 @@ inherit_task_group(struct perf_event *event, struct task_struct *parent,
 /*
  * Initialize the perf_event context in task_struct
  */
-static int perf_event_init_context(struct task_struct *child, int ctxn)
+static int perf_event_init_context(struct task_struct *child, int ctxn,
+				   u64 clone_flags)
 {
 	struct perf_event_context *child_ctx, *parent_ctx;
 	struct perf_event_context *cloned_ctx;
@@ -12897,7 +12902,8 @@ static int perf_event_init_context(struct task_struct *child, int ctxn)
 	 */
 	perf_event_groups_for_each(event, &parent_ctx->pinned_groups) {
 		ret = inherit_task_group(event, parent, parent_ctx,
-					 child, ctxn, &inherited_all);
+					 child, ctxn, clone_flags,
+					 &inherited_all);
 		if (ret)
 			goto out_unlock;
 	}
@@ -12913,7 +12919,8 @@ static int perf_event_init_context(struct task_struct *child, int ctxn)
 
 	perf_event_groups_for_each(event, &parent_ctx->flexible_groups) {
 		ret = inherit_task_group(event, parent, parent_ctx,
-					 child, ctxn, &inherited_all);
+					 child, ctxn, clone_flags,
+					 &inherited_all);
 		if (ret)
 			goto out_unlock;
 	}
@@ -12955,7 +12962,7 @@ static int perf_event_init_context(struct task_struct *child, int ctxn)
 /*
  * Initialize the perf_event context in task_struct
  */
-int perf_event_init_task(struct task_struct *child)
+int perf_event_init_task(struct task_struct *child, u64 clone_flags)
 {
 	int ctxn, ret;
 
@@ -12964,7 +12971,7 @@ int perf_event_init_task(struct task_struct *child)
 	INIT_LIST_HEAD(&child->perf_event_list);
 
 	for_each_task_context_nr(ctxn) {
-		ret = perf_event_init_context(child, ctxn);
+		ret = perf_event_init_context(child, ctxn, clone_flags);
 		if (ret) {
 			perf_event_free_task(child);
 			return ret;
diff --git a/kernel/fork.c b/kernel/fork.c
index d3171e8e88e5..d090366d1206 100644
--- a/kernel/fork.c
+++ b/kernel/fork.c
@@ -2070,7 +2070,7 @@ static __latent_entropy struct task_struct *copy_process(
 	if (retval)
 		goto bad_fork_cleanup_policy;
 
-	retval = perf_event_init_task(p);
+	retval = perf_event_init_task(p, clone_flags);
 	if (retval)
 		goto bad_fork_cleanup_policy;
 	retval = audit_alloc(p);
-- 
2.30.1.766.gb4fecdf3b7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210310104139.679618-3-elver%40google.com.
