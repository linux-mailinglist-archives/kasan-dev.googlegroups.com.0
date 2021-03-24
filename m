Return-Path: <kasan-dev+bncBC7OBJGL2MHBBK6D5SBAMGQESTVBTQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5803E347710
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 12:25:32 +0100 (CET)
Received: by mail-pg1-x53f.google.com with SMTP id k21sf1330056pgg.17
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 04:25:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616585131; cv=pass;
        d=google.com; s=arc-20160816;
        b=qs/ByYAuCXjB0bzZ4NWrJbp1OXFTUW9Jyptgre+w3HbrLdGnfd9uAwUR5WgkEd2Ipj
         eW533U7a4bYapH9OXSML//Dsupv+Y7tX/3aGBpL3ZDP7DkJYWvGRjZaFFsA1tLtx7dag
         gT4cdAFSqxsjADeIgpV4zYa3iRsCShJG5rM5XwU0XTN6EHeWCODfwfaSd1k3Cvh5L0nj
         wG2gJB1hPp8oze7vHwqWxEx/l03w6nCPHvTWp1fAKSUFQvE3eD3Cv53qUix+AF5EwIkL
         k7ZsczyoT5v2VHbH/sMoO3GWaOilLHs9q0ZAJYgliyce6xYDnONEnyAsp+dVC4QyR6jz
         Q/Sg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=OFcNFa0t+YM7gNNDlSSBgV8ymcWJBP0I3qWpc8iwNHQ=;
        b=fhyLZrxbF2rb2QDGg6gf/0JykeoRmLdee2pPPlKVYfhTaj0hRR7SQZc+YM43Cgl4wx
         joD1thtSKdgw2cWur/VCfiii2p9q0OWfz8Z/9CQ1SEiX/035CInK3yQhq9RNK2xYgia+
         cimLQmNiFcv2N1S1mbCn0iqvtMh0ol+rTJmqVOVmLxxBo3TXWbcpXe6BdePAgONzXQrY
         S0PrSZiG95fDBcwuYP3u34MjbRAOYGCPS6qRNf08XRrbGerZ1hgwLk5+5V/zi3S3dhX7
         IJTqeLr3dRfl9+PI9gNL88TuOfNR9b5vij2wIjRvYrxUPUistS8b1eosNOpnnZD6J4F1
         5EMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="HP/OpHnG";
       spf=pass (google.com: domain of 3qsfbyaukcwielvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3qSFbYAUKCWIELVERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OFcNFa0t+YM7gNNDlSSBgV8ymcWJBP0I3qWpc8iwNHQ=;
        b=FojY7WzTfm+651LmywkH/TWbOd0FofT4jklM7qRi0zmD8LdPTYOOCh7gaJUGBSE4ca
         uLmqMpOIJm85EARWSdWhrCIQvXkFT4AsSJgXZN7n4UcEJIVPr/yQrKrMjgV5u/G5xY2/
         thksA1r8c1XfWJ02UJq/TxfbSa3l823Ux5QgweKTwmWst6i/lR1eDax7oY0dFwCO7jtr
         C6eIhpsXIz2LmNN6qu8TtEjKU4/zfXAT8F89pDCUuGBsibez6XDIwFcPGNCZqek83jBZ
         qeZC3KhG4mSXMr8j0xAIRajcM+Bhvc/umDKmkVgv3A3wSQr4twUObBi+v+d6QGVzLOLT
         9Www==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OFcNFa0t+YM7gNNDlSSBgV8ymcWJBP0I3qWpc8iwNHQ=;
        b=YiuFHBLhKmlKyX/4xtQrCxCKYbnxC2LcwlfIyMLH1rvVmpfJygUYdk6TaHbFJZgUmV
         tVkaQErJMp9WCxCWohAv8eRLWaHmoEVp+EIawaV20ndOMIXMLjnWfX+yx5xgpjsnLeUr
         ILdn2mbc6BiNzbx3YVxemyUWPL1MQQNjKrVe52VXtoeDgUhdZoTfYzgCQ4h5Q/eBSGvX
         gvk4tV9IGSGsZbEY+Qjkw1vQ9dfNsrzysTLr+AMsrclHHUSJ5aklsAskfcuEmf+9PH6n
         w+xvo6ARpSwKPxDE6Dg2wdLVYdvI0PTcAeI4rQLEehX9+BjjzNzVP1qK2ddF7NUjQvYL
         J56Q==
X-Gm-Message-State: AOAM533QSWY8xK3+DnppuVdMrOlJf25IAJ2Uu1jDx1ZSYCVSwiNDxNOc
	8wqwqkVvsByaKX0Hlpes6ik=
X-Google-Smtp-Source: ABdhPJyaxgvOPdIaFXEcVnNI6glEx78a1SD1fXdER8sZ0p0q3ZobyAZsPJ2lbujewEV2257YAT3IjA==
X-Received: by 2002:a17:90a:7186:: with SMTP id i6mr3107609pjk.191.1616585131091;
        Wed, 24 Mar 2021 04:25:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:1382:: with SMTP id i2ls1075773pja.1.canary-gmail;
 Wed, 24 Mar 2021 04:25:30 -0700 (PDT)
X-Received: by 2002:a17:902:eb4a:b029:e5:e7d0:5aa with SMTP id i10-20020a170902eb4ab02900e5e7d005aamr3134397pli.3.1616585130463;
        Wed, 24 Mar 2021 04:25:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616585130; cv=none;
        d=google.com; s=arc-20160816;
        b=emP+rhKBmDXCH/9F4d/oe2KeLxzboCo8cHWnLS4yLx/ICjw1o31YEXPCAon6k9zAlK
         X2/FTwqEgeDos72YrihJnQvMSgg1fFcTblzjG7NQ50eskYzfR1zoJps5unUBwvpa8STI
         b+R4Fxd2py9Fu97Gt3CAjIeZpxQ33QqUd8+zDmFyMTTC9lkB2vDalV61dFA49Zda9O1K
         lUbshIxctrF47IzdBXIVGgtx+S3aRASLUmUPhL7W9uyHGacotnN4pMyqv22QwPMZ/HiH
         AvkL6boM+r14vZDsuvoiJp72XWjYLo5x+3luH8D/E2ZRUaE9rHujIuPzqRLfxCA0iQLv
         /vtQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=LX/BpTku7Mw/ygEVGiq+Ue/R3uDPIzOnmcdooJRuOrg=;
        b=t/6zpL4+fBuFiVF0Rx/jEjn/dDhINfUGVjiwgxmW1IEoQ4xSvqCnv5dxR06ZBCT7Ll
         ZfEqlXyA2gdGawCX8udn5rXPI7+xdJhr2PehvItR3ABEq/jMnwlPN5ORoaUvn765+52v
         QKWBJmxUPLWHR8HKfSBbri/gV4MiLhgKQv9kyRUJlWzqqLxKmOV3OoQKKYtWAVL0iHOY
         /dhEBh8pDM0AOlwNXSEbhdBD4YKqYK44oKY/KKAvkh8n4+yaDyOF3AjBBQWWr8ZhXyQW
         S6THrTQCIO2m4NWwTg7Py6wWI8b803t6x1eUlbK/dAc7YoVUAF3L74+U/GQVS3yFhZqO
         QPvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="HP/OpHnG";
       spf=pass (google.com: domain of 3qsfbyaukcwielvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3qSFbYAUKCWIELVERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id y11si117130pju.3.2021.03.24.04.25.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Mar 2021 04:25:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3qsfbyaukcwielvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id p10so958239qtq.12
        for <kasan-dev@googlegroups.com>; Wed, 24 Mar 2021 04:25:30 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:6489:b3f0:4af:af0])
 (user=elver job=sendgmr) by 2002:a0c:a5a5:: with SMTP id z34mr2625271qvz.4.1616585129586;
 Wed, 24 Mar 2021 04:25:29 -0700 (PDT)
Date: Wed, 24 Mar 2021 12:24:56 +0100
In-Reply-To: <20210324112503.623833-1-elver@google.com>
Message-Id: <20210324112503.623833-5-elver@google.com>
Mime-Version: 1.0
References: <20210324112503.623833-1-elver@google.com>
X-Mailer: git-send-email 2.31.0.291.g576ba9dcdaf-goog
Subject: [PATCH v3 04/11] perf: Add support for event removal on exec
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
 header.i=@google.com header.s=20161025 header.b="HP/OpHnG";       spf=pass
 (google.com: domain of 3qsfbyaukcwielvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3qSFbYAUKCWIELVERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--elver.bounces.google.com;
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
index 224cbcf6125a..b6434697c516 100644
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
2.31.0.291.g576ba9dcdaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210324112503.623833-5-elver%40google.com.
