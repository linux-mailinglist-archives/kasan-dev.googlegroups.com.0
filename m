Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJWD5SBAMGQECRVNMIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0A08D34770E
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 12:25:27 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id b24sf1054798ljf.11
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 04:25:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616585126; cv=pass;
        d=google.com; s=arc-20160816;
        b=K7y9LvMNMpAQI9oHAvdfJ/WynrxALVzyUJUztjvzzHVzo0x44adIfTB54+flHSjIPQ
         oax2dMEgPJqBGmuNvhOYZRYMqS7fUHZ12bGqhAWbIutZt+mj1lOK5U8Zr1S1STJW7pI7
         ogjd8EsfviYmE31d/t/oigEvTyL9mGF65kww1Tow4rQfigZecy+JfOcPVzQCUwTlk4ps
         gJ7KyzaZz+4HfDJobhSLpb6uy5FxqZ+lS03TngYsFmVPVWk6i39wThhL/AY0Mff5AQzw
         C5FSFOTXkOe0q6BxDh7eChBAHGLUBFnUQnna65lHNNnmgV8giOnY3VAwVDqqrt7/uJs9
         zkyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=02HTLg7irlx2FqJjgTfEgeW3pTHvpiEOveU0D3oK4sI=;
        b=mMgjqEfVSLLN8zgH9ZBEnofSFa3oDG05YZtJyZFAyWdBzaXZm5hNqdSUYswcGfdzM0
         NPAWpabspZ8K4dmLk3YKXYFLB2L+BN5MyLIrIzfZBeiAO3k++cLjN0L3AMPsBNNI7jBb
         r0/6C+JJ1BwOAWzOGRqyTprUFWgMOtkfQdLzfbw5ShSD/UNsKppKASpJTzeH0k9mHRNp
         nqU2S25hsRFq7DAtreRqNr5v7+Cz+zRvz/9IHPUyg8MOEFbgRmGkeiqkD6we3EJI4iBT
         cVXR3sZi9tfTBh4Xgnje3HqWy851DPQo7t4SpwyFjf8j2ETFdU3CvuKKov8tX4h3T9wn
         tVaQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nYXjrHCe;
       spf=pass (google.com: domain of 3pcfbyaukcv09gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3pCFbYAUKCV09GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=02HTLg7irlx2FqJjgTfEgeW3pTHvpiEOveU0D3oK4sI=;
        b=A4UuQoRS8As0YP3H4zr1MPnoKpoHKLhFSZcSD/hjT26Z8SNodI2gdNH5OdpRg/l6t0
         ldvyPg4QmV5kqQBwjiX9jjvwoi0OIFelc35a/ywQQFNXRZ2PZ2xbpyAh0vuxaw3SwoNl
         dusgyIdE0mv+uGP0sLqSobZIEmfinbZKLHYRjYGwpTw+wC6s8NYq+PfuUpOLML4CjVrw
         wAE4ulpPBuGHXjDRs1tXtPEclMXP1+hYoSTTETndI+QESn1hkBYNJT+7GwY28lDAIDEd
         eNooGnfPni9ijvV/kdr25R4hWo6gYne7OYSe7ioMF0FReY7JUU54FlkYhNIP/20m9PDT
         AaXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=02HTLg7irlx2FqJjgTfEgeW3pTHvpiEOveU0D3oK4sI=;
        b=MfGRVoD4tKJ9Vea1SyfgL0gOhaayZheawJjAf3ui2mS9MPM4P6GpWDKKipQ167T2uy
         fg8rnR1Uu80HI4rAu5ph7Va2f5xkE/57OxeaytK7mGc43mhjj9ftZ47MHmINLbEKxBlt
         wWSHnYLEj16ZnXQu88lpiHG5O0AjORnUxViC3cfns7GwS2Iy6pP4XYEdOMhr8XqA7eO9
         nbzo0ioUZGKH6XVpHvKuEuuVxjrnRUcCqv5htAscn1Lco+x7KTwOonAiwsFZ9+0YHYU/
         S9/+ENs3aQg/MJ7w2EYcPBTF4/s5Ji1ucVSAgsR4/CX1gtlTCDPtylgZr4rHH3CdhbsL
         l0ww==
X-Gm-Message-State: AOAM530YdGvXFmPTplXEgsuLOprNrnNqLIPG7k4hBOf3msr5tm8h4ymO
	XANXOK0JmWcigUFjaLeAIas=
X-Google-Smtp-Source: ABdhPJw55WnCCR05HaX3Un5wti5zxjd7zfXxwFx9Il0G611t27NNsyuk1j7umjG4PNe3TRJ2ojWEgA==
X-Received: by 2002:a05:6512:3702:: with SMTP id z2mr1728429lfr.505.1616585126600;
        Wed, 24 Mar 2021 04:25:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:e86:: with SMTP id 128ls1327476lfo.0.gmail; Wed, 24 Mar
 2021 04:25:25 -0700 (PDT)
X-Received: by 2002:a05:6512:243:: with SMTP id b3mr1727036lfo.529.1616585125445;
        Wed, 24 Mar 2021 04:25:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616585125; cv=none;
        d=google.com; s=arc-20160816;
        b=HrhEL5Re/dzsiM3/TUlApEv0zh1DoBBjg6UsqrbxM1kYPRE0+hXIbctbzPUPnbpx1f
         R2YbSFFJlAJdmeQCd+s2dN3k0vOZXEw0O0trJpY26jXetLNWoWchm9FTcFKA6Ux+O3OG
         8fq8HlxEhWYY0DyY0X5aucNdeETChpMusFiiz3a9JEmt0rxSqV+anXJWtWN9YFv5poKi
         ug0r+nPzWzjJmDy91krCdLvAoj7rL5DfyOD0sFJg1UxH7ojafly7/QpTAWuU5qh5WOgL
         w9sSj/FUQj89wgnYIbXPfkBw0hZrfJtxZUKibEE07KkL55bg1NKcFOoqzLrIEsWsJN2U
         h9xw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=3/AI1hI3URzVJhSImUodjFuCeBbn3a274zCrbDQNsz8=;
        b=ZlJQkN/uDUsSW0hqdbQTvYEiJZSbnmyJQHJLR5SjK6wDZioe9EAGl5Gya1e+qP/H8z
         5LoOZS0hayhrCj+cieq4eMZdoI0zb3BB1qQPC2zyD8TzhGOUcBEQq4hBzLmYcSAl8TlK
         Y4aZ/p2L/n4leEhNV86LzBVqaNnZO8ulm491N8cT71gXn88K2DPgbvZjpwzKbbkhcgNH
         1xHxs4QzVcJv/bZ6xpbi4/v7zTlHNWVlO7v6XVDeUQ3bw7EqjNGJ+hl7vc9z2048Klgc
         OL95uTyYZht6o30vE7ngK/7PT3CYLq7MWPPoGkilRJU60Ehfg52moS/XxXtYNswFC5aa
         cDUA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nYXjrHCe;
       spf=pass (google.com: domain of 3pcfbyaukcv09gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3pCFbYAUKCV09GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id v26si102137lfo.2.2021.03.24.04.25.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Mar 2021 04:25:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3pcfbyaukcv09gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id i5so945494wrp.8
        for <kasan-dev@googlegroups.com>; Wed, 24 Mar 2021 04:25:25 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:6489:b3f0:4af:af0])
 (user=elver job=sendgmr) by 2002:a5d:4903:: with SMTP id x3mr2936933wrq.143.1616585124744;
 Wed, 24 Mar 2021 04:25:24 -0700 (PDT)
Date: Wed, 24 Mar 2021 12:24:54 +0100
In-Reply-To: <20210324112503.623833-1-elver@google.com>
Message-Id: <20210324112503.623833-3-elver@google.com>
Mime-Version: 1.0
References: <20210324112503.623833-1-elver@google.com>
X-Mailer: git-send-email 2.31.0.291.g576ba9dcdaf-goog
Subject: [PATCH v3 02/11] perf: Apply PERF_EVENT_IOC_MODIFY_ATTRIBUTES to children
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
 header.i=@google.com header.s=20161025 header.b=nYXjrHCe;       spf=pass
 (google.com: domain of 3pcfbyaukcv09gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3pCFbYAUKCV09GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
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
index 57de8d436efd..37d106837962 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -3199,16 +3199,36 @@ static int perf_event_modify_breakpoint(struct perf_event *bp,
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
2.31.0.291.g576ba9dcdaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210324112503.623833-3-elver%40google.com.
