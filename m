Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2HG76MQMGQEFVFFAFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 71EDE5F765D
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Oct 2022 11:37:45 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id o20-20020a05600c059400b003c35afaf286sf231556wmd.9
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Oct 2022 02:37:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665135465; cv=pass;
        d=google.com; s=arc-20160816;
        b=JVaHxZoXdJGujMboK0tDo+jPQq8UgrS3Alvg0sbtc+vlaGnzSF1gvwPzPYPhdsWA7k
         YHuOlXeMpiMwkfhw1v2U+bjaV5CwTXGzYwWGZrOHQGV4VkPOL5VE9tHwLkX6IpKFe3KY
         AXi/XyKL3Mgh0iimij6sPZWPVU54nMNv9f+ITCaduUhAtclOfa+0j19ox1CXH7aJceEo
         FxxZVw4Nhw/FH8s05L1ll0czkjryiyDxsU+QCzHgMzc0ytlRoaw9eSOYFi0worYXdASj
         e9JjavJGgpqLbMxYKK0f40fpoUU5Cc6t1WvjKskCxlbbSi4eKokkKAtTB1zB9ydgFY+P
         /zXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=8afV6lw09kEsdC87/RbmKPdxVkBNZ9aGcsIqe6gA3Pg=;
        b=WAsUiXlnaT9dHPn5BHIiUsRSpQD44WjYhWvyQU8HipmQ0r4pcenOqKRzOj9V5wfDAH
         Ena/CeRKaRMO/9gD3SV3NfcbVhIS6YbwEf21cZU4ZkUI5pOVSNZ4+eHas5GXeCO2ssKF
         F82zo0tYlbdMCV62GeoeoofOokXIni2Etv20vVtHXs8+iMV0RMfyjaYOA4zahp8u43HD
         e/HAHCwT+d+oPi3cbP5pYR/CK3h7/xYO3+xrVLKh3MP5UuMnUL9yBYZfwlwHVRwxDXcP
         HaYENqA+FuAwCWkXu0LYlnXTwnjLKKP8xm/fvPlpGwxoUbQhAN9CE3r1vRoRmGg8s95a
         YOrg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lsFbyXl3;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=8afV6lw09kEsdC87/RbmKPdxVkBNZ9aGcsIqe6gA3Pg=;
        b=HuCqzPIKOD10LseGmKkWYa47ew3mMHL6jz5kQ4kjMUguXl9+rRpCyrS7Pk5VwIDbS4
         pSijTAOlWYQSiE2IDKrshOMs9azwyRPXdIPk+uqImJog7rOWTFyfzto7FsYMa+smDMw9
         s/J6PKyBGqvJMop7oKy/0PrYoW8/pA47g3ZLO9WqYekjgOiTHgSHC8LZlAbLOfOfKCZK
         Bsu/on0Cm8mKHt3JK9HN97chdINVJ5KVzYRGQSu4u9wsglOhAF4e/DnnAKkFg144O0h5
         1LtCYExCMZfIJosli2dqTmdtHe2CxiLu6q/6Wfq6Tl/0h7R3la9fu3Ljb7hKepKlXwxo
         E+Rg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8afV6lw09kEsdC87/RbmKPdxVkBNZ9aGcsIqe6gA3Pg=;
        b=qYD4KhdPJBn/IfZKeG5+/ikhct6DiUikL+JuBS/9d8zX4QrpZ+OrOU4dmhmVnHLnr0
         4iFBL4ezdrk2HJwL4k1xYP/EGJnmMCl9L8/uZ79PRC/4DxYZOc5IQVyONk6gcGT3Z8gg
         xMyNTwsNhkMg5b59g4X5It34jFIQl1ztziYmJLCecG3OrwQm0uWvBB5By21sasOtdQv6
         F4JvoV4LmXZFzvulIo3kKL137IQ0RT+nDKZ7NFlgKrZ5VwuJ6sMELVz2RIQceYMbAMZ/
         /fNdnCYCN2do0z94/FTvMbmEOvgbEATmmb+5q0TlHHejO95KCxsXAudpWM7WNUilpNK4
         +Kyg==
X-Gm-Message-State: ACrzQf3f19tmwPYPWyWyOj/AkuN8Pe+spqQWJCIosZu9QHJHfvJlJ2Cg
	52l8xxBjXH0VGOtRPqaauIQ=
X-Google-Smtp-Source: AMsMyM7cfQbS2JUBJPLf9Ilon7uvH0RQQs5wpQcnTGraM/Xzc8X9dbbKBSvI1tooCBMN0KMlFISs/A==
X-Received: by 2002:a05:600c:4ba9:b0:3be:a765:cc2f with SMTP id e41-20020a05600c4ba900b003bea765cc2fmr8743313wmp.26.1665135464481;
        Fri, 07 Oct 2022 02:37:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:6011:b0:3a8:3c9f:7e90 with SMTP id
 az17-20020a05600c601100b003a83c9f7e90ls3668747wmb.1.-pod-canary-gmail; Fri,
 07 Oct 2022 02:37:43 -0700 (PDT)
X-Received: by 2002:a05:600c:3543:b0:3b4:ba45:9945 with SMTP id i3-20020a05600c354300b003b4ba459945mr9621213wmq.58.1665135463114;
        Fri, 07 Oct 2022 02:37:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665135463; cv=none;
        d=google.com; s=arc-20160816;
        b=XCIaHzEZALWNI5oJDZQfAWAwIrl/IcUN99tsvg02ebN4jVJB/+nXwGCcJrnfjmqKQd
         zMzRk3FHPZKvOU62m0pnBeSD3luWKUUfJcXUpJWt+z1pjPBXG1graIrbcskHph+RYFuy
         Dg2/+PSsnCaduEBeY9MXt2nje+NkdpN70EwEx6ydWSIhUO1PohLBpjpr6pcwXC3VXRYx
         gsF7wZPjkhrZBAyUvoB5xGmmBncFFWVx0hWvFWpZh8W03/6nS3nKRGyuIVKftfqeXuGb
         zTvPM3+WdKSFtwa16+eUzzKMLFv2q9DO5Qa56+OkqURGaXNBXQAf3nAgvzszH7QB2ga/
         USMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=LH9uOMgE/N45WO2wenwuwG6vNOy7NLHsypVs9cw/6bM=;
        b=FzYm7WQfUVUkfXbCky1GRJqHMke/bNqcW0VKDWsyscNceA4woBa5RbseCYVCh232bo
         HrxwTdeO1AcqeyZ/p2mAUjwoulFesvdQzOiBcl2GhKTLDhci4fOCkcXtBRh/oekf4uXx
         TIhlBS7lTXTtPK04ZBoDZO1JeO2ywXbz7l4Kc5SuOQTqDeq9mU9qCsNwEluyj5UWxd5u
         ukXFlOOC3mvRp166ChKqE9M0J5U3vupAzA3huSM84p4KVkJt9H7CL1XGDWC++HwPoJNk
         kn5ZS95FG+bF8cA2/ZKAJAQNOPwXwwPWr0uDhWd7Rmz5uEOpHwU/fBVJyHBIpj/qBA+B
         4Esg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lsFbyXl3;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x52e.google.com (mail-ed1-x52e.google.com. [2a00:1450:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id m3-20020a5d64a3000000b0022e54ade3fcsi69149wrp.1.2022.10.07.02.37.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 07 Oct 2022 02:37:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::52e as permitted sender) client-ip=2a00:1450:4864:20::52e;
Received: by mail-ed1-x52e.google.com with SMTP id s2so6270077edd.2
        for <kasan-dev@googlegroups.com>; Fri, 07 Oct 2022 02:37:43 -0700 (PDT)
X-Received: by 2002:a05:6402:42c7:b0:45a:2d91:741f with SMTP id i7-20020a05640242c700b0045a2d91741fmr1000007edc.39.1665135462718;
        Fri, 07 Oct 2022 02:37:42 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:4e4:454c:b135:33f2])
        by smtp.gmail.com with ESMTPSA id o29-20020a509b1d000000b00459c5c2138csm1123758edi.32.2022.10.07.02.37.40
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 07 Oct 2022 02:37:41 -0700 (PDT)
Date: Fri, 7 Oct 2022 11:37:34 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Ingo Molnar <mingo@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>, Namhyung Kim <namhyung@kernel.org>,
	linux-perf-users@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH] perf: Fix missing SIGTRAPs
Message-ID: <Yz/zXpF1yLshrJm/@elver.google.com>
References: <20220927121322.1236730-1-elver@google.com>
 <Yz7ZLaT4jW3Y9EYS@hirez.programming.kicks-ass.net>
 <Yz7fWw8duIOezSW1@elver.google.com>
 <Yz78MMMJ74tBw0gu@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Yz78MMMJ74tBw0gu@hirez.programming.kicks-ass.net>
User-Agent: Mutt/2.2.7 (2022-08-07)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=lsFbyXl3;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::52e as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Thu, Oct 06, 2022 at 06:02PM +0200, Peter Zijlstra wrote:

> This can happen if we get two consecutive event_sched_out() and both
> instances will have pending_sigtrap set. This can happen when the event
> that has sigtrap set also triggers in kernel space.
> 
> You then get task_work list corruption and *boom*.
> 
> I'm thinking the below might be the simplest solution; we can only send
> a single signal after all.

That worked. In addition I had to disable the ctx->task != current check
if we're in task_work, because presumably the event might have already
been disabled/moved??

At least with all the below fixups, things seem to work (tests +
light fuzzing).

Thanks,
-- Marco

------ >8 ------

diff --git a/kernel/events/core.c b/kernel/events/core.c
index 9319af6013f1..29ed6e58906b 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -2285,9 +2285,10 @@ event_sched_out(struct perf_event *event,
 			 */
 			local_dec(&event->ctx->nr_pending);
 		} else {
-			WARN_ON_ONCE(event->pending_work);
-			event->pending_work = 1;
-			task_work_add(current, &event->pending_task, TWA_RESUME);
+			if (!event->pending_work) {
+				event->pending_work = 1;
+				task_work_add(current, &event->pending_task, TWA_RESUME);
+			}
 		}
 	}
 
@@ -6455,18 +6456,19 @@ void perf_event_wakeup(struct perf_event *event)
 	}
 }
 
-static void perf_sigtrap(struct perf_event *event)
+static void perf_sigtrap(struct perf_event *event, bool in_task_work)
 {
 	/*
 	 * We'd expect this to only occur if the irq_work is delayed and either
 	 * ctx->task or current has changed in the meantime. This can be the
 	 * case on architectures that do not implement arch_irq_work_raise().
 	 */
-	if (WARN_ON_ONCE(event->ctx->task != current))
+	if (WARN_ON_ONCE(!in_task_work && event->ctx->task != current))
 		return;
 
 	/*
-	 * perf_pending_irq() can race with the task exiting.
+	 * Both perf_pending_task() and perf_pending_irq() can race with the
+	 * task exiting.
 	 */
 	if (current->flags & PF_EXITING)
 		return;
@@ -6496,7 +6498,7 @@ static void __perf_pending_irq(struct perf_event *event)
 		if (event->pending_sigtrap) {
 			event->pending_sigtrap = 0;
 			local_dec(&event->ctx->nr_pending);
-			perf_sigtrap(event);
+			perf_sigtrap(event, false);
 		}
 		if (event->pending_disable) {
 			event->pending_disable = 0;
@@ -6563,16 +6565,18 @@ static void perf_pending_task(struct callback_head *head)
 	 * If we 'fail' here, that's OK, it means recursion is already disabled
 	 * and we won't recurse 'further'.
 	 */
+	preempt_disable_notrace();
 	rctx = perf_swevent_get_recursion_context();
 
 	if (event->pending_work) {
 		event->pending_work = 0;
 		local_dec(&event->ctx->nr_pending);
-		perf_sigtrap(event);
+		perf_sigtrap(event, true);
 	}
 
 	if (rctx >= 0)
 		perf_swevent_put_recursion_context(rctx);
+	preempt_enable_notrace();
 }
 
 #ifdef CONFIG_GUEST_PERF_EVENTS

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yz/zXpF1yLshrJm/%40elver.google.com.
