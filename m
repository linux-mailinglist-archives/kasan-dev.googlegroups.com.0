Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCFF2SAQMGQEWIERLWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 252F7322C6A
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 15:34:51 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id g6sf1540195lfu.13
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 06:34:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614090890; cv=pass;
        d=google.com; s=arc-20160816;
        b=0jQukc0/3zpA92R1Qze/3hjfFWU5GCnQ2OO+opWOBY005msEUk4TewYVaHJTt/dEbR
         Jg5c35aLUgBMyvbvctiTd+bICvEEUQwkp63sM4Ekn0MpvtMYEpZ+lBxyeWkBkiPwNSiu
         OugSZOK+6UsVQcu13phqCadF7tkQ0225JcKfhNqI2dkrBV+GHZbxmjs+P1QyTtlNvaPr
         +Z+96F+btZjDRg9F60G+jCN8xU8yiIZMOxPqLsvimBiirkq2Hqzhf2WN9WYj+qcnymAs
         of8lDMfDtZvWx4yJeSahpVkWixNVnBiRHUPZkAL2T5jCBuH7KRZsiivgIgmVedjlKT/7
         pFbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=hGrAKQPI/pmt5wYwGAHU7ME6APjCk/O8WSLrjs8X+P0=;
        b=T2IMN5bqQtkm8xsuofXg4nXJD8T0id+jn2mdBPQbTQ4kKMstKDO8BpkF5UZSQ6qdHQ
         jY6YOVbLgbQPk5jtZc64pVIT1/7dyMOpZVCoOWF8rGDv605Vc5gfsNT7hh9bL/g3oqqv
         nt4COxj3ZKTxb1wQWUtb7qWhV/iCkhyVifqxEAmQt+b1ror56jtaypLsGSAo+mr5vb+E
         6hc1GL2NOkcxdf962Wg+JWgkXDpLrFnxIYHRPjrBoJB4w1cdMKNGqVeGSBjJXd+MZE6s
         r/2hDVQaG7hto/PnK1b7vubr7QP0La0yhvnTH75MCQiwQdNgfX3e4Xg7uW7rLJ5+2j8t
         nYFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=a431b0ZL;
       spf=pass (google.com: domain of 3hxi1yaukcygqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3hxI1YAUKCYgqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=hGrAKQPI/pmt5wYwGAHU7ME6APjCk/O8WSLrjs8X+P0=;
        b=Q0cmkcxu3fHkBqTHnYgv2zEMfWmh7aqwkUtT9lU2HaToy3a4icZf6OE9hRASDCz21E
         zsAEJ3y5SZuxY6/bNrOvsl8S3+yJL4yYdB+DUkb36hwAU0qauXYp7Wzlmd8jIOhqf2fc
         BdkKPee1Nw8kZpQ12QT/xNJIAK0u+c1vrOKW//dnYkl54jfXtbmC/s6sN4eMVLX6f6lq
         d8psxfd6J6Q/CKhTB1NCZq1MOrjeoyfyz7FHtFYkkbxElN3fZh1DNmFJynYlRxuJzTO6
         R+1P4ejOU2lxKCIRYi5GwNZlsXZNFoqh5QfDf200FR2TP/3631rQQYnu74+Dys/xfkwK
         NusA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hGrAKQPI/pmt5wYwGAHU7ME6APjCk/O8WSLrjs8X+P0=;
        b=SFAD+deb3LL7J+pApnXvbEjKqeom56UPqwy9gEubfetG3ffElMNwKN3eBaUkNpUeMs
         QLsa6nwr0cjhQM1GAvSJWRDUFCkdQukD3dqJ+x4KZMseyXPAiiQrhNgdeg+B9Y37BEpL
         ywp7salh7rAD/NhGRpCTb/IP5IklUYzIdnf4pWFkgNoPx6g4/QNzjmQoypwjgLixxHa+
         fqsgGnA1Nxij65wOdbwZHGBfkQPfxlmqgYCOf0jkWJ0eHxQ+76G7xRssu1mQ/zeuB9x0
         /hVElAbiCd6JG/0DXx0NJjSOg4SviXrdhsg7GM0JSYlFB8SYVtYqE2WicDbo5u88X/c7
         y1jg==
X-Gm-Message-State: AOAM5326GSFXYKGAacfRHyt1SLZSVGowFIuu1KeXHfs+Ih4Y7aNsftV5
	+eAD4FWV4xvaNWfjAsaaYJ4=
X-Google-Smtp-Source: ABdhPJzbtXISYVMNwz19ybDL0G7ePc7DgUuJb7Z4CqaOqLjk691HhncosEtGUVavi3aAyVAwTj1N4g==
X-Received: by 2002:a05:651c:38f:: with SMTP id e15mr17101438ljp.420.1614090889108;
        Tue, 23 Feb 2021 06:34:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:480d:: with SMTP id v13ls230897lfa.0.gmail; Tue, 23 Feb
 2021 06:34:48 -0800 (PST)
X-Received: by 2002:a05:6512:21cf:: with SMTP id d15mr15351846lft.561.1614090888023;
        Tue, 23 Feb 2021 06:34:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614090888; cv=none;
        d=google.com; s=arc-20160816;
        b=xm+59c1z3KzwqBoux+WC9HMSJtC+R4Frxj6YNTUZVngUp6xlpLyRPDTL6XhFOL0Ous
         OFg52ITujToNLYEcwoJWrBgP+dGZ+0gUzX1iPJ+bGXF9KfxczNn0RBN4lLlB21aWj7gP
         ygLPDfTerkgmBFpkqwY1lA9sUH/IGSHfEHN+NTstl6WettyHKuV/wx/V/i84FJygPDwU
         gdJs30E7ppvVjNUGQGawDWwx1iJJEk79jOZSFF/5jPiVAxn88MKt+B+OGbW9hy+1dyqw
         uMrsCJXRNN/1Foa2LHo5TGzWUJ9gFrkJsTJmR0I53WH0e6yfUeNvPEdxQoDxADCHewKg
         ZoNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=Z91iRBzRx2L82S3eGkndbig8apk87DxttK33upPKVz8=;
        b=ehDZOV4YGXOgbOoS02YbHkJlMn70rHNdQY+fX3Jm58EaYc+ncrPUQhjm9RHt+LHfxJ
         lJMsc9np0bjkGO+1Iqui7VAVP6dp8mS12+A1xCcvkUjfGw4UjrQiMd4OqWetG70KpuMo
         hn4pCJhYWEENwRQSoBjzhJGs8X0BDilY4gaCdVP1CmPLc3vDWECSgGJ+FmVibS7m1cSI
         iCrAN4IRCpNi0rQGk6KwBbfIpbjKiO40NK/AT64HiTYXbnETERMIrhScYtmgLupt0uXa
         AyZPzbcVRMnQxsj+SDpfxNTLfwtxTmc3pR67uw+MsJPJiaoo9zNfx2RjVoQK2konugTX
         XiyQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=a431b0ZL;
       spf=pass (google.com: domain of 3hxi1yaukcygqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3hxI1YAUKCYgqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id z15si892290lfr.7.2021.02.23.06.34.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Feb 2021 06:34:47 -0800 (PST)
Received-SPF: pass (google.com: domain of 3hxi1yaukcygqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id z67so1276628wme.3
        for <kasan-dev@googlegroups.com>; Tue, 23 Feb 2021 06:34:47 -0800 (PST)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:855b:f924:6e71:3d5d])
 (user=elver job=sendgmr) by 2002:a1c:a90e:: with SMTP id s14mr25359822wme.36.1614090887099;
 Tue, 23 Feb 2021 06:34:47 -0800 (PST)
Date: Tue, 23 Feb 2021 15:34:23 +0100
In-Reply-To: <20210223143426.2412737-1-elver@google.com>
Message-Id: <20210223143426.2412737-2-elver@google.com>
Mime-Version: 1.0
References: <20210223143426.2412737-1-elver@google.com>
X-Mailer: git-send-email 2.30.0.617.g56c4b15f3c-goog
Subject: [PATCH RFC 1/4] perf/core: Apply PERF_EVENT_IOC_MODIFY_ATTRIBUTES to children
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, peterz@infradead.org, alexander.shishkin@linux.intel.com, 
	acme@kernel.org, mingo@redhat.com, jolsa@redhat.com, mark.rutland@arm.com, 
	namhyung@kernel.org, tglx@linutronix.de
Cc: glider@google.com, viro@zeniv.linux.org.uk, arnd@arndb.de, 
	christian@brauner.io, dvyukov@google.com, jannh@google.com, axboe@kernel.dk, 
	mascasa@google.com, pcc@google.com, irogers@google.com, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-m68k@lists.linux-m68k.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=a431b0ZL;       spf=pass
 (google.com: domain of 3hxi1yaukcygqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3hxI1YAUKCYgqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
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
Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/events/core.c | 22 +++++++++++++++++++++-
 1 file changed, 21 insertions(+), 1 deletion(-)

diff --git a/kernel/events/core.c b/kernel/events/core.c
index 129dee540a8b..37a8297be164 100644
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
2.30.0.617.g56c4b15f3c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210223143426.2412737-2-elver%40google.com.
