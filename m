Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4WEUKBAMGQEFGF7UWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x640.google.com (mail-ej1-x640.google.com [IPv6:2a00:1450:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 976EA333A3F
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Mar 2021 11:41:54 +0100 (CET)
Received: by mail-ej1-x640.google.com with SMTP id k16sf7031621ejg.9
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Mar 2021 02:41:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615372914; cv=pass;
        d=google.com; s=arc-20160816;
        b=cNQAujX8/8Og2dAVHXSdgjsir40LhVTFYdDgOKhdfUi5pU/ICRWmFJfrP7iymUYPZt
         7wfyjoTVTvKkxhQ/U8+ywpo7Ub9BSekisbUE11MENlBYnAUUKQDgrZd3iC+dDh/MjzfM
         W0XZT8g99uPLpNM1ExaxlQ7e/1ZKCMF8TAATRvw/hXXgqKNtm04Dm4AloI5XOKb8+lRv
         belRhCMT9oPPvK5hcHdvLGguacp1Evu/xQ4UfE4DmAI3F/SCIIjOGxZ6YTtVQJdr6adr
         ywv6eL9arcclhFFDctH9hkUxwAbIzL7vkFUQ3QnQ2p6ugWseKM9PambFXe+epJ+avMeo
         Fmrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=QUge894rLMCh0k/S9iDVvwNgbaCF910Zhp93jK095ac=;
        b=TppZFRFuM6x+3peNg6n1w27vlB4Zt+uPJ518K/EE273N3H0otJMMbAjduSs/P/Vx7l
         xyiyjwxV/GC+16l+u6bzlDBNjhDpJWlz+u+1LJwzx3ffSZ8BAlyREvpUdnbPksu09Fyn
         ynBIBKoh38rr/tXCtXl9nLpOp7vLJnS9Q0UZ9gtiJmWNqksxPeP1jSyAbR6SOm56XE7v
         HJHPkg9RsRqZkWNX1opQ0ur+5rzHJ9ZfQDgpO6Ntx9WC3FdMZdR+5ocX54Nb6O692SfG
         UwZN882Yws0HOsnUq9QbR+2Sl8GvFSmlbC/11Zknw43mMFT4A2qjwDN663DQkhTcTx/Z
         QuiQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="U/F3Fdi9";
       spf=pass (google.com: domain of 3cajiyaukceagnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3caJIYAUKCeAGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QUge894rLMCh0k/S9iDVvwNgbaCF910Zhp93jK095ac=;
        b=ZKDNv2aQLa4I2MkzRXtKSPv0NLAX8NpO7xKC8xZCwlr/ZYItSVXOQqhiT300cB+zxe
         6eS8YAH27mFi92BdZBSGA9eDIMybGkSqeIOxwWf4XKDaMfNqas9dBzsEBJWOMcitvNYz
         nfsysKb4D4LOwWAMBlzaFlDwXXuwb0CQKZyGP4DwhSq5RlsQVj23onlFtpHq5GUGB19T
         RWxT+i8lEUJ0OxAbKF89FsuA8oEWtQ9Gr41b/UM9ei/3d6EwQ6mP6U7z/J7JjDr6YYiJ
         lx8PS2cTOKwD/1a7pHNf8xGlpRyQqwIWPY5RGPYLw9m/OR4g5gAKrLECqXKrZyTEk+h9
         aS7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QUge894rLMCh0k/S9iDVvwNgbaCF910Zhp93jK095ac=;
        b=NxGq7HDYxp0K9SjsvpsmaZAv+JGldxXbkv3RF7xfp+AuLWxdBIjuKnO2haYB3XkWfv
         tqtXccPtHuHTsEei+ecHOk33y6/aJLrPtYJmH2q5PdYQvXrI1nDa/Ojw1IgsGjl3GJzP
         +FlSA/v7pTiErdnrj5IhRTgLM7onDG0AnTr5k+b82QsNmtPgWV8JjxXhrQjHgctZAxrb
         Kt1es5pLQxSkVTYIBBVUdL4a/o/Jk6HAYOWg7LOrOyOA/idXVeJKlDq0e3gE96JBAVsV
         TX8ebFVUfipbhTfNrGvWJN4P++wUdPiKCAmhyRRLoIrS1B36it/rEyl+sV6jIVb9/ugr
         i5CQ==
X-Gm-Message-State: AOAM533J/XYXP5zQiN/d0qpQ5ZlR/QF1DJlGb47mzCElrQrjpZMwUixN
	Mq7EJWMQ0iv0w89Ucwvveh4=
X-Google-Smtp-Source: ABdhPJzJ5X5fxU7PJvpqDxfRpUcB2qUclrZzMq4ZoOoZAiLn6lRtW3NKDjNRbDxtv1JS1hI1zbTwdw==
X-Received: by 2002:a17:906:d554:: with SMTP id cr20mr2957373ejc.61.1615372914319;
        Wed, 10 Mar 2021 02:41:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:1e48:: with SMTP id i8ls878900ejj.5.gmail; Wed, 10
 Mar 2021 02:41:53 -0800 (PST)
X-Received: by 2002:a17:906:b316:: with SMTP id n22mr2784603ejz.249.1615372913370;
        Wed, 10 Mar 2021 02:41:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615372913; cv=none;
        d=google.com; s=arc-20160816;
        b=0oZxoc9wwhrOkupFDK5Q/8LwGi86FpuKcIOSdf6UNX2d6+fHSqn1QqdV6RQbV4Nk0L
         acNOlvj9rA7ElhBK2yK9YrF+p1pOvHAG6YXTyuI0KWiftzuoQZvnP2gRxgDV2y1udE6h
         oUfAYpKzGe4XG4wc5t4QFERfJxDWsJHux4T9yWfanymDDUtdzKJxBrVyoDE7MscyM6Ho
         qWcXEhYh4QXF6M0sEH7yenqcHEOqDFLTaBS6S1stxDWi14ls73SI+GxAvxryzV9XpgDo
         fofAcqlOu6mC/xM6NXJLFcrfKew8kck3VWT+wJXvFzDjfDfmchtLAi0Sb52iFRa7Nn7K
         X1pQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=JNI5Tf6KKGhkGniIZ5cU47CifTg2LZA5JMDRp5Vdgq4=;
        b=wzrWLaeN+hsT2jwZGrLYN4RVRr3ducubAY7+Vyquh59+cBehAUTk5/KlF6ODRy4Fnf
         5bZVY2sAHdiauiY7JAoza8Q5xCYk/773zZCKkIxVownvkffDmLGFG23991UWGFTdtWy4
         vobhdH+lyIhX9iMk4Q4opbPlHoHmeWNXiqeRf3FJ1sEEcBSgq6wwiAGC0Tx8NJWxbyto
         v0WVoNAeMA969wCHMXVICypCahqV/+a3hGuq131Iuaq0W2GVxz9sDrCJ7o1JdFJYj7qT
         TGy2PzFC4hS9T4J3rmMYWvRZz2KMarIEJagSHfS/i40Xokv9AXHVLXpRx3s49531tvVQ
         QEpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="U/F3Fdi9";
       spf=pass (google.com: domain of 3cajiyaukceagnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3caJIYAUKCeAGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id jz19si719133ejb.0.2021.03.10.02.41.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 10 Mar 2021 02:41:53 -0800 (PST)
Received-SPF: pass (google.com: domain of 3cajiyaukceagnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id g2so7789774wrx.20
        for <kasan-dev@googlegroups.com>; Wed, 10 Mar 2021 02:41:53 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:e995:ac0b:b57c:49a4])
 (user=elver job=sendgmr) by 2002:a05:600c:608:: with SMTP id
 o8mr2806133wmm.42.1615372913037; Wed, 10 Mar 2021 02:41:53 -0800 (PST)
Date: Wed, 10 Mar 2021 11:41:32 +0100
In-Reply-To: <20210310104139.679618-1-elver@google.com>
Message-Id: <20210310104139.679618-2-elver@google.com>
Mime-Version: 1.0
References: <20210310104139.679618-1-elver@google.com>
X-Mailer: git-send-email 2.30.1.766.gb4fecdf3b7-goog
Subject: [PATCH RFC v2 1/8] perf/core: Apply PERF_EVENT_IOC_MODIFY_ATTRIBUTES
 to children
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
 header.i=@google.com header.s=20161025 header.b="U/F3Fdi9";       spf=pass
 (google.com: domain of 3cajiyaukceagnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3caJIYAUKCeAGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
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

As with other ioctls (such as PERF_EVENT_IOC_{ENABLE,DISABLE}), fix up
handling of PERF_EVENT_IOC_MODIFY_ATTRIBUTES to also apply to children.

Link: https://lkml.kernel.org/r/YBqVaY8aTMYtoUnX@hirez.programming.kicks-ass.net
Suggested-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/events/core.c | 22 +++++++++++++++++++++-
 1 file changed, 21 insertions(+), 1 deletion(-)

diff --git a/kernel/events/core.c b/kernel/events/core.c
index 0aeca5f3c0ac..bff498766065 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -3179,16 +3179,36 @@ static int perf_event_modify_breakpoint(struct perf_event *bp,
 static int perf_event_modify_attr(struct perf_event *event,
 				  struct perf_event_attr *attr)
 {
+	int (*func)(struct perf_event *, struct perf_event_attr *);
+	struct perf_event *child;
+	int err;
+
 	if (event->attr.type != attr->type)
 		return -EINVAL;
 
 	switch (event->attr.type) {
 	case PERF_TYPE_BREAKPOINT:
-		return perf_event_modify_breakpoint(event, attr);
+		func = perf_event_modify_breakpoint;
+		break;
 	default:
 		/* Place holder for future additions. */
 		return -EOPNOTSUPP;
 	}
+
+	WARN_ON_ONCE(event->ctx->parent_ctx);
+
+	mutex_lock(&event->child_mutex);
+	err = func(event, attr);
+	if (err)
+		goto out;
+	list_for_each_entry(child, &event->child_list, child_list) {
+		err = func(child, attr);
+		if (err)
+			goto out;
+	}
+out:
+	mutex_unlock(&event->child_mutex);
+	return err;
 }
 
 static void ctx_sched_out(struct perf_event_context *ctx,
-- 
2.30.1.766.gb4fecdf3b7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210310104139.679618-2-elver%40google.com.
