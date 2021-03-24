Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKGD5SBAMGQEY7PB6VI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 07B4B34770F
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 12:25:30 +0100 (CET)
Received: by mail-pj1-x103f.google.com with SMTP id r18sf1429566pjz.1
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 04:25:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616585128; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZWF7KDFzcwxQPZxfzIvNNeSe2FaBmDZShLCVdRK3AJqZgv23BqJ05pOzAZBp/ybMol
         IRKy/Ng38WyOTGAeMoffIK/prwfd0T+hBrl1WUHSv6AzpuE4TYwx7QP/CKTImXDNp496
         waQhuRs2sKJquFeL9y2jeH9qN6PoJnlgzrKoYGUIecWWNAt1+8j+YXWtFU5kcEiW/Arw
         p5Z6ioeGZZdooD8+qm+ubXgMjwItB+LENaT4A+Fnvmf8rvN7SodadoRHTeJ3c+0GJau5
         eJKebHjR4+Pp4GYG65/btdtr9jcCfipCGBzaUEz9kxe1cvth4smTurAcECTVPhR/Aode
         /ZiQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=zrQ5x9tRRn8/9ogpWWIh+bvGkY9LggEiuDm1lyW6ccE=;
        b=ffe1pskbF+AMQy2vv58tt+7BE1ZT1BHGwaXO9rV73Sl0a54zuIzP49nlHxQvo1P1Do
         eHp6j2bC/6EwNWgxL6TCjUqqCjGMzC9iXqVr8mFchWRzUF93dVBi1Rg8XL1YdCrTPud3
         C8PuaTYWVJTcXjQRMOPQoj9XEN9eK2nprr29fp2e4MtCe7Pm56ATNcuLjICEe9MxpGkt
         i0+p92b4hUv7enZ+5hLshUvr473d6DhBvxvwOtG6iB1/hakH2T96qOEwcjmwf2bU3419
         kV2B/076Ko2v1c//Ugo9PaddJyyBHsJW33XNlQvv+LFWiWLiSYXd6CORXkZ/kmeoRIvu
         hzTg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sgl7z3sC;
       spf=pass (google.com: domain of 3pyfbyaukcwacjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3pyFbYAUKCWACJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zrQ5x9tRRn8/9ogpWWIh+bvGkY9LggEiuDm1lyW6ccE=;
        b=kCRXEyxiD0Vu2BrI0n2cCBmgCXwU48H9PViyAShwiKr1Z+YJgM+o8N6aXyzr5atWPi
         RXW8XlRObLCPZAFHABtHN2DLGimZ2M9FnwuLQ8Rr1Nv9Vy/5NyymLLEieAvgVloC5fCO
         KWxwwtemxckAhoGL2YbdTKUW2z70dQh4C8eGvZybrET9pqo5U8XPwxXORUtz7OQ9Uoau
         aW7h0CfTWoGUpwC7zbBzDMXMfB9WZX6TjqRIBVlsGFJCBa8XGGsL1Q9YONaadqv/pBKK
         7BvQ+9L8+KrCQkpw4Rn2eOQ+2xlilmSMAlaTpQSTXXI4GPLBAj+jCXBjPHVyzAoVbMTO
         fFOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zrQ5x9tRRn8/9ogpWWIh+bvGkY9LggEiuDm1lyW6ccE=;
        b=oxVkHgG6qq5tkR/S102NVHIny0sQRUjqT815ARaA8aDa1P2QBTm0z/Sxw7CKbyooqZ
         YJGV2+WXcCoftX7pnhXeXZ2QYOCv46Aypm0pwOo4XCBMJNNicIefP6E5AJHh8gpB7s0t
         ssJ6jIJ8Oj/hB8pnqLq/mCGqTLwbPuOPDrqWnuBqMh5uh5PbyCjjPGI+prJPDQCiymhA
         5bRMmDlzNu4BBwwnPSLr+YgAC2eAoufudjaWmrlYEDxcIHANL4Uh9gSmKoKYfUR/Da5R
         hITcEXOGjiAulvJO47RTPkPXP5vA8W3wxqdPf4f4Cd8CyEjFu4GNCPqDsjojMHYRO2iQ
         U+6g==
X-Gm-Message-State: AOAM5325RZ0eWrrRpgAZIbROVRgj10Ob9ITlbSfu8BqYBZFg2eit5BKr
	XWM3DfMhZC0z+S1Tc+pd9SY=
X-Google-Smtp-Source: ABdhPJxGfdamLDm5QOYzPFN9MNGUgD9KRTDTXEKDqwBXMjqCipHu2ifa4NE6WBHLBg2bD0XObUjxGA==
X-Received: by 2002:a17:90a:a603:: with SMTP id c3mr2935674pjq.107.1616585128839;
        Wed, 24 Mar 2021 04:25:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:ec9:: with SMTP id gz9ls1074476pjb.2.gmail; Wed, 24
 Mar 2021 04:25:28 -0700 (PDT)
X-Received: by 2002:a17:902:e98c:b029:e5:defc:ccf8 with SMTP id f12-20020a170902e98cb02900e5defcccf8mr3057053plb.20.1616585128085;
        Wed, 24 Mar 2021 04:25:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616585128; cv=none;
        d=google.com; s=arc-20160816;
        b=ele0LWROOhB3sKA6IDa1Hdde9KoORz7EY4ZFPifjcghSmY9NwkaVbF0FfGnjxEeQEC
         6I7gLrBJo1YE9nIGsdSZ0Vyfvne/NCItetcZJwdrcBk1xrbwCvrxhKb3bzZNrB+GKByT
         LUfl+oG8BN1hXT030qTYVLU7uKuisL+n9uz/0CHuk41N4EYln6WzDd56EApKE1doYYCE
         OLFsEemWdXCNPGRrIIh+I9KUMHHtH9fPYA6eAZi9PsLQgggcjY/q7J2lgRbBtr2g21kG
         qKGFAQJDQzz0uUNHOBHYI49kwd9Za8kobecLR785HxFQRK+9rGgjeik/qnVM/ZiDdk5p
         kQZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=ra+FSk7yg/IrYqjIco0O1nyWKLubPz+XwZQjmYUKsC0=;
        b=sxM0UAQ6yOyysyTDMdSPNYXBTwPVNW7bkCdN50Wz5uV7gBdWaYRsYe7VM3W4oPv3hm
         tX1E10u7A9aDaYUKtlOS679W0Z5R3PDTXDQ28in10Yok6wmP6R3Rqh2h3kpgUxztOpz2
         4eaq+0yTcwcjfX+D+AJF6UYz9SQ/vJWJvhio0MuH5/MUtdEZyL11aMIopMwhzEh7fiYd
         tve9p9FKGFUTQ+WLna/TrzyqGF9j/U7jHMFmrKSQjUWTF7nnrcYRkVgR1af+bx+GfVAg
         gjNXvpa/TCPIKSCzaNn3hGxgyJQfoeCezegvPMDdNAGPyZA43Y/TmmBkC+uBopKFcILe
         wA9A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sgl7z3sC;
       spf=pass (google.com: domain of 3pyfbyaukcwacjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3pyFbYAUKCWACJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id h92si88432pjd.2.2021.03.24.04.25.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Mar 2021 04:25:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3pyfbyaukcwacjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id v3so963653qtw.8
        for <kasan-dev@googlegroups.com>; Wed, 24 Mar 2021 04:25:28 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:6489:b3f0:4af:af0])
 (user=elver job=sendgmr) by 2002:a0c:80ca:: with SMTP id 68mr2559743qvb.12.1616585127125;
 Wed, 24 Mar 2021 04:25:27 -0700 (PDT)
Date: Wed, 24 Mar 2021 12:24:55 +0100
In-Reply-To: <20210324112503.623833-1-elver@google.com>
Message-Id: <20210324112503.623833-4-elver@google.com>
Mime-Version: 1.0
References: <20210324112503.623833-1-elver@google.com>
X-Mailer: git-send-email 2.31.0.291.g576ba9dcdaf-goog
Subject: [PATCH v3 03/11] perf: Support only inheriting events if cloned with CLONE_THREAD
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
 header.i=@google.com header.s=20161025 header.b=sgl7z3sC;       spf=pass
 (google.com: domain of 3pyfbyaukcwacjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3pyFbYAUKCWACJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
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
index 37d106837962..224cbcf6125a 100644
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
index 54cc905e5fe0..aeccd7f46ce3 100644
--- a/kernel/fork.c
+++ b/kernel/fork.c
@@ -2078,7 +2078,7 @@ static __latent_entropy struct task_struct *copy_process(
 	if (retval)
 		goto bad_fork_cleanup_policy;
 
-	retval = perf_event_init_task(p);
+	retval = perf_event_init_task(p, clone_flags);
 	if (retval)
 		goto bad_fork_cleanup_policy;
 	retval = audit_alloc(p);
-- 
2.31.0.291.g576ba9dcdaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210324112503.623833-4-elver%40google.com.
