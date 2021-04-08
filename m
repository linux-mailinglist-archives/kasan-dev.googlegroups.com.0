Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSFZXOBQMGQE5QZ5WEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 830A43580BC
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Apr 2021 12:36:57 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id r79sf658746lff.20
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Apr 2021 03:36:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617878217; cv=pass;
        d=google.com; s=arc-20160816;
        b=D97w7sAkF5M3xGzKDZFKgS3W2jywlGFGts0Jff2b2OsR1gtp/ocH5KDcSIWbFCI3Aw
         MJoWyjmNTI2DPxTiS7TIsbWETIhB0dBKgoHR3t5veFK9GgzbjrW9xyuCFBUGC2tOIH/R
         0u6VyA7jADBXmfN4TjABw/+zejBtFQkKkJXCNQLpVtTJ5O5tg5qyF2pO+JDK80mjvSJk
         onwZL3CB8VGB0H+VChmWLs/NKjQTw5HCjPyfoCUAKBxt7zqWlV6Szkaf4h1Lu2gLWdFv
         3XDc1Rrb806Occ4QMwzMIhnRDin54piRa2CLtF4FCbXteiIc6LnPyU5ZMzW0ZrenM4BC
         gsmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=/w0jK/4T1fLKS5+Bj0vVFZQu1hxpPucuSv1MjoX37u4=;
        b=ItBdeHAkumhZtL4xUgMQApeQoJJkVUZpnWe8obaTr8NtbxhKHPn11siaOOIjNPaSWn
         9SXIt2G0lgg0hQ6zeaBzeCY0brEUCAPWfnhRE1YFACvOgFDyXZqW3pE9akZriT3vjOqE
         3EsGol6cQxikTOKaNvcFgMZQcHlySeLlFJMrBN3vw6h2qwusJUJdYfoI4p/iVBpnJ2Fg
         XBSDMElgq8ORvvncxfZY1r7Hpsi7F9GGuK7UleCKpEP97Hr9VnGilDD6crJQ6bRPFgWA
         34xEBT/4WH29jR9FfZsdgIUsSDdWTOu8rEB0ujedjN3zaE512P8XHCfZOe3hwbFpI6zW
         Pc9A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ed4EtZeH;
       spf=pass (google.com: domain of 3x9xuyaukcuymt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3x9xuYAUKCUYmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/w0jK/4T1fLKS5+Bj0vVFZQu1hxpPucuSv1MjoX37u4=;
        b=XBJfbgcigShniWK5jGlJjR7ng7E1ZOo6Ca7FI6681+l0tUE15RkZ/VdTGyBO/ib0cj
         y5bqxDDSHP17dGDkSo3NslP9o76CBxEx6QY8MZWBGYgTfc038VXJ13HNKAQkz+oIslnX
         NI7glYhizcnV7oCyREiVcyIMYTkQkvL50b61NwIdR1H0k1rbPEw+rP1DJaUGxk1VzZWI
         VZbrPnVIYAGo60zR21MBJiKlfXcg/IGh9c82AzXexAp7bjFje05/V8U/PGvkh78InpJI
         8JKR25BCFyRlyaGcqzCHlJMmglJnELC6agEC54rSFPUs9PMSqQcKhQBEp0HulYk5ygTY
         wBZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/w0jK/4T1fLKS5+Bj0vVFZQu1hxpPucuSv1MjoX37u4=;
        b=PuMb8S791trhKEfUhtAx1hJ0rLKzhcAlDaetBPH+8bCLGgQPsR+1rTySIaYmQj+rWz
         vVJb+EAsRkRO3I9Gxb/bQeOsusMiUwETnDriXDoZw2FSNqEJQdWK421wDVmHnPMrhsfF
         OwH0tROaq6LtEXzIn4ifZBaQISOqu9rWkuTdgeMv6/bqN4SGrgjP2d48ZZFcU5Q05QzF
         DkjUp0b3Oz+GubMP74QAP+ZfgNOGD1yPF5o1RdSwyqt+VzH8cjZtacljFD68/XCYAqkR
         s+KKz9BLBGirmmajYAiU4Fe1VN4tKQdijG1zD4dIxtgqX9JQdqInsoHhB5uMBAt9UJyc
         LD6w==
X-Gm-Message-State: AOAM530PJ5l3vf9BB56w3B+MsKpXedyszZylD54JaJorImLGeBiRLyiJ
	pst7/rt/o4O+BXG7LQjRDRM=
X-Google-Smtp-Source: ABdhPJxMUDNaDYofQmz9HZUwC3D2CH6j65MbFOUNivuJjgm7Gi7sG9ccLdeqIBOnrC/7D9lPWGzdMw==
X-Received: by 2002:ac2:593c:: with SMTP id v28mr5754685lfi.581.1617878217062;
        Thu, 08 Apr 2021 03:36:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9191:: with SMTP id f17ls1095844ljg.11.gmail; Thu, 08
 Apr 2021 03:36:55 -0700 (PDT)
X-Received: by 2002:a05:651c:603:: with SMTP id k3mr1784347lje.191.1617878215875;
        Thu, 08 Apr 2021 03:36:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617878215; cv=none;
        d=google.com; s=arc-20160816;
        b=HACqJI3bRRvZE6qYXKuW7at/9BsJbFrUfbdlaVEALUUnaNVciaJB+B0QembAjQ1N2t
         hy8HiH8OLxTIce02igt+U/3fjtc/aW1sAErAeR9J9oR11Bue8jbJLQpxmskKq4zOZ4n4
         h7sJO58WxVjbM8hdko/coIfzvD67Fb48BNZIQqBqsKt6UWZYHeRJTvnEkgH+5pjEJyge
         ZStYZCvM3aQlS525eaha0DzV4qLUQTs+bofQi0AWvYLkgOVVWby7n4KicNmV7zfQrcVm
         gZAEYQGwI2VTTKozk3twUgnOlPM0XJ2Gj0k7G4Qmt8FeWMiLfmoW8fQrZyLRXaj4hQSr
         GirQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=WFLySSLyk1OHGUPgGWpvFgqBO4Z7Oek9XA/23wsFKPA=;
        b=FB7LQjazN3ipaF0kaopNOpO1fDw7csT5e6emVQHcymEysQqk2Is9S7BqGZAvUKPtZr
         htqM3aRR2YK2zpVM0lgMzz64TCgVHquGBpnA3hu/jcAEvlyDfcFfkNzOv08HtlMSkoCN
         kArgsWREWTONTxhh7l2YKumpC9blmYXDy7QXw9GlZ1EU2tf1GRT9FeuPvSWRJwbNhAY3
         s1/B9NyUhZRiRG9O/Ox00UW8dXG4Uj/x7teNumgPQCJZixvgBHauU7IvTPfTs6Ys9Gp8
         oN/Z90HSBbpyiS0hp2uIG16tjg1G4ZY04CadvFTukHdjF7fgyBO3p3MojCbwgvDKHeBl
         Tu4A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ed4EtZeH;
       spf=pass (google.com: domain of 3x9xuyaukcuymt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3x9xuYAUKCUYmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id 63si1923854lfd.1.2021.04.08.03.36.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 08 Apr 2021 03:36:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3x9xuyaukcuymt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id j4so787844wru.20
        for <kasan-dev@googlegroups.com>; Thu, 08 Apr 2021 03:36:55 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:9038:bbd3:4a12:abda])
 (user=elver job=sendgmr) by 2002:a1c:9a02:: with SMTP id c2mr7815998wme.131.1617878215147;
 Thu, 08 Apr 2021 03:36:55 -0700 (PDT)
Date: Thu,  8 Apr 2021 12:35:59 +0200
In-Reply-To: <20210408103605.1676875-1-elver@google.com>
Message-Id: <20210408103605.1676875-5-elver@google.com>
Mime-Version: 1.0
References: <20210408103605.1676875-1-elver@google.com>
X-Mailer: git-send-email 2.31.0.208.g409f899ff0-goog
Subject: [PATCH v4 04/10] perf: Add support for event removal on exec
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
 header.i=@google.com header.s=20161025 header.b=ed4EtZeH;       spf=pass
 (google.com: domain of 3x9xuyaukcuymt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3x9xuYAUKCUYmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
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

Adds bit perf_event_attr::remove_on_exec, to support removing an event
from a task on exec.

This option supports the case where an event is supposed to be
process-wide only, and should not propagate beyond exec, to limit
monitoring to the original process image only.

Suggested-by: Peter Zijlstra <peterz@infradead.org>
Signed-off-by: Marco Elver <elver@google.com>
---
v3:
* Rework based on Peter's "perf: Rework perf_event_exit_event()" added
  to the beginning of the series. Intermediate attempts between v2 and
  this v3 can be found here:
	  https://lkml.kernel.org/r/YFm6aakSRlF2nWtu@elver.google.com

v2:
* Add patch to series.
---
 include/uapi/linux/perf_event.h |  3 +-
 kernel/events/core.c            | 70 +++++++++++++++++++++++++++++----
 2 files changed, 64 insertions(+), 9 deletions(-)

diff --git a/include/uapi/linux/perf_event.h b/include/uapi/linux/perf_event.h
index 813efb65fea8..8c5b9f5ad63f 100644
--- a/include/uapi/linux/perf_event.h
+++ b/include/uapi/linux/perf_event.h
@@ -390,7 +390,8 @@ struct perf_event_attr {
 				text_poke      :  1, /* include text poke events */
 				build_id       :  1, /* use build id in mmap2 events */
 				inherit_thread :  1, /* children only inherit if cloned with CLONE_THREAD */
-				__reserved_1   : 28;
+				remove_on_exec :  1, /* event is removed from task on exec */
+				__reserved_1   : 27;
 
 	union {
 		__u32		wakeup_events;	  /* wakeup every n events */
diff --git a/kernel/events/core.c b/kernel/events/core.c
index de2917b3c59e..19c045ff2b9c 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -4247,6 +4247,57 @@ static void perf_event_enable_on_exec(int ctxn)
 		put_ctx(clone_ctx);
 }
 
+static void perf_remove_from_owner(struct perf_event *event);
+static void perf_event_exit_event(struct perf_event *event,
+				  struct perf_event_context *ctx);
+
+/*
+ * Removes all events from the current task that have been marked
+ * remove-on-exec, and feeds their values back to parent events.
+ */
+static void perf_event_remove_on_exec(int ctxn)
+{
+	struct perf_event_context *ctx, *clone_ctx = NULL;
+	struct perf_event *event, *next;
+	LIST_HEAD(free_list);
+	unsigned long flags;
+	bool modified = false;
+
+	ctx = perf_pin_task_context(current, ctxn);
+	if (!ctx)
+		return;
+
+	mutex_lock(&ctx->mutex);
+
+	if (WARN_ON_ONCE(ctx->task != current))
+		goto unlock;
+
+	list_for_each_entry_safe(event, next, &ctx->event_list, event_entry) {
+		if (!event->attr.remove_on_exec)
+			continue;
+
+		if (!is_kernel_event(event))
+			perf_remove_from_owner(event);
+
+		modified = true;
+
+		perf_event_exit_event(event, ctx);
+	}
+
+	raw_spin_lock_irqsave(&ctx->lock, flags);
+	if (modified)
+		clone_ctx = unclone_ctx(ctx);
+	--ctx->pin_count;
+	raw_spin_unlock_irqrestore(&ctx->lock, flags);
+
+unlock:
+	mutex_unlock(&ctx->mutex);
+
+	put_ctx(ctx);
+	if (clone_ctx)
+		put_ctx(clone_ctx);
+}
+
 struct perf_read_data {
 	struct perf_event *event;
 	bool group;
@@ -7559,18 +7610,18 @@ void perf_event_exec(void)
 	struct perf_event_context *ctx;
 	int ctxn;
 
-	rcu_read_lock();
 	for_each_task_context_nr(ctxn) {
-		ctx = current->perf_event_ctxp[ctxn];
-		if (!ctx)
-			continue;
-
 		perf_event_enable_on_exec(ctxn);
+		perf_event_remove_on_exec(ctxn);
 
-		perf_iterate_ctx(ctx, perf_event_addr_filters_exec, NULL,
-				   true);
+		rcu_read_lock();
+		ctx = rcu_dereference(current->perf_event_ctxp[ctxn]);
+		if (ctx) {
+			perf_iterate_ctx(ctx, perf_event_addr_filters_exec,
+					 NULL, true);
+		}
+		rcu_read_unlock();
 	}
-	rcu_read_unlock();
 }
 
 struct remote_output {
@@ -11652,6 +11703,9 @@ static int perf_copy_attr(struct perf_event_attr __user *uattr,
 	if (!attr->inherit && attr->inherit_thread)
 		return -EINVAL;
 
+	if (attr->remove_on_exec && attr->enable_on_exec)
+		return -EINVAL;
+
 out:
 	return ret;
 
-- 
2.31.0.208.g409f899ff0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210408103605.1676875-5-elver%40google.com.
