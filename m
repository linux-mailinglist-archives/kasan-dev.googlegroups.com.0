Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQHPQSNAMGQEBWZC62A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 344865F8450
	for <lists+kasan-dev@lfdr.de>; Sat,  8 Oct 2022 10:41:37 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id r81-20020a1c4454000000b003c41e9ae97dsf1200827wma.6
        for <lists+kasan-dev@lfdr.de>; Sat, 08 Oct 2022 01:41:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665218496; cv=pass;
        d=google.com; s=arc-20160816;
        b=DTt4K8b299OLxcax1xwq/PfyDQP9/+szWH7nCmTu/gi48DLbQowFtO3DlfhBHrtESb
         NXVapC2TCwZ6xJoSPZgE8fZZCBlwO8D0gKctMNqYqPIoDxxfKMULiLgxOn8CWLy3uBSx
         0IXRRYPsGHcShYLxM91v+I+Zmd1JSuOCmIf7s9+K423wf9ntvb4deeioW+aFbA7vc43Z
         JwVFF4J9HgsZVYOGQnplucWTyL0nVq/selBR0E8J6GTAggDMnmuVxMFH0zrlX+WcZ/R0
         glIQNlSa7bdXn64e0ZJ1U+ym5n/YH402Pg3G8BF4ckDZU3xxNvsUMpXXkcQXSsWYc2hv
         WCVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=tjKwciEbJtljOgNWMvXxXmYitmlIPioij0s9uI4H0yA=;
        b=Suz5wb6cnSvsyQKzO5MyLWq8KicZbZDvvTlFobuvEsipj+Q2cbtweLU5HwlJjsspR/
         ZTfEIcC2I7NB/Blba2puXDaQ1XEoz97EwhNWpuUDVyM6aWOOIL5zlM8wEQlLYB999a+v
         0OH2QG0wQimF3n1M+OaTAqMiuNMsFpAJy/JoSLrAnzbACX0hR0n0mCxyIGpRzIEEb7z9
         YJtutQgTj3jbrXDk+BaWqIeAHVsYnxGRgXPaQx9lbYDVSQ1zC/NWdGh+0842CP8J0vtp
         RCjNop33cr3+4jNffo1TtNFzQ/eNRSx/iKe8msr4I5sG+5n3M7HwbY9tgJgZq8J83Iau
         WXoQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=nmR1Fi0P;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::531 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=tjKwciEbJtljOgNWMvXxXmYitmlIPioij0s9uI4H0yA=;
        b=oXiKjuWBxv6kKzf6tdUoAvQeZYwcGic0hrAjfFqUEgiUg93GjHHFseIQlUv46OfFFH
         hj5tgvDFO9D0FYM5zsF7sjK2/3XZgwV+XQyhpWcylyTjGOVWQJ8kbctw8A8opvC1Y6si
         yOcONx4UpHgKcOTIJ2J90WhK/Y5vXaBdSYYxLdObaiKZU+pq3wQJytEJTOQuNfOkuAi2
         6rCIuZ3jHzmHQ+8aNVWTZfMSTezRcVwJlE2fNy0uvcrHQ54jrwVybhhH2pjtIJZQ7qnY
         MvITGQkx5x1W8qTcMyWGqKzfxjtGvEkxw7hiWN9g8mq85u7FW6li94PQopNlH/t8RAR9
         AtzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tjKwciEbJtljOgNWMvXxXmYitmlIPioij0s9uI4H0yA=;
        b=LTAMFrqxG6lb6nbSiD1DND6nZEqP1Polqrblp0N7LebCkMU3JgzjxQtMNjuTW52Tsi
         BPFnXcimVzbSq3BpywfqyNrbxy0q0I8Os8ZW/Y1yJ8DgLwaM33xcMTboChfQ3vryvKmj
         48pln2OyaUMnO9JnL+0Oip9/MHQEjpkfc6gvFkKSPYgDZ/8T2c7W2ARBf8bgWr+uXwal
         /yadXsKNEoEDld0WjcJjrV/NgEMK5zdTzWDArSWiFWeb2/XVYdB4YtW98qz/skPQdEmN
         L8+Fm/nMwlLhAxfo1/h11qrqNtjab+29+mzaGMbzmfCJzogAZMyaYhT3LMct/57FjGJ1
         oa5w==
X-Gm-Message-State: ACrzQf07aLSFcqZ+Q8e+UdkGpdF3es6dJJvRjvnzNHOiDhGs3dHCcWNM
	msc7xS5vWDOEIOqI7jDJA6E=
X-Google-Smtp-Source: AMsMyM43bE8Yb94r1lE/zfV6U9VMAjdLoLI8yvxoQkkw+ALMkjtO3nseuIl5lde/Fqa5HX9cHVJ6TQ==
X-Received: by 2002:a05:600c:2b88:b0:3b4:8680:165b with SMTP id j8-20020a05600c2b8800b003b48680165bmr13617237wmc.113.1665218496589;
        Sat, 08 Oct 2022 01:41:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:23c:b0:22c:d34e:768c with SMTP id
 l28-20020a056000023c00b0022cd34e768cls3180996wrz.0.-pod-prod-gmail; Sat, 08
 Oct 2022 01:41:35 -0700 (PDT)
X-Received: by 2002:adf:dbc5:0:b0:22c:c605:3b81 with SMTP id e5-20020adfdbc5000000b0022cc6053b81mr5541107wrj.218.1665218495118;
        Sat, 08 Oct 2022 01:41:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665218495; cv=none;
        d=google.com; s=arc-20160816;
        b=pMEd8gMZU/3670IFk3mia4DDWcW7Qbi7YcEBZ6QbLMoqIRwWwYqhxMLcw3W9erTYGH
         my1oCEhwBzZj/tRFv2IGNHSrkako4w9TTYxcIngi57NrFINRwqx/7jYkaY1wYbWzbDjR
         avnlpauuSEaJioyJeYSTWWG3E6p7n1CAcUyW/aGKb9dOw3isbR1lkvStLrT5z7DbfX0r
         1HIjHmYXXrZuVNMUgHRTSpu1XYF1XHHXpWdsSXa94OpCMSEUHnsjh1rjqyKK2TIKipVy
         QZxHkpvL6Smoxqh2pJHL09FTg3cgzvPjSEnt+hQGlG2AzxcffTw3vw1ECy7dtJLbOu+z
         eSug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=WxdcSrBOGO9MYgndz6qzjn61BZYNh2xTD3igd7MSm5c=;
        b=QgzIWfiRXO/NpPRIT+UqVw4pCVe+CPul5z3sXyXz70nMyjSQ5FQ0RCPaAsA93Hslh3
         F2QJDDetOFxoItUCLedcYZg1usIXAgh1gPPe6n74/vFRi8qUNiSKj8ZyR6TtyidUbvIi
         GR0fBEXdjwnpTTlvIoCGxqFPCDwYK7B8mtSdALTnVLhB//a+P0tjBf4EGDI7rAeL78/P
         yctxk0hiATM9K89JudqbrgurbuHVjG4cggHqSGqrMfZ5DLP0dN14bUc7YF4t/KLIq6z5
         bpitce+LsRRJjScecg8BtMTdynUIwcjN1AHuoUnZyK4slp/DHUfGzPPkRwFuCZB3EuTl
         KQTg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=nmR1Fi0P;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::531 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x531.google.com (mail-ed1-x531.google.com. [2a00:1450:4864:20::531])
        by gmr-mx.google.com with ESMTPS id bk6-20020a0560001d8600b0022f74ffaae6si28564wrb.8.2022.10.08.01.41.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 08 Oct 2022 01:41:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::531 as permitted sender) client-ip=2a00:1450:4864:20::531;
Received: by mail-ed1-x531.google.com with SMTP id y100so9818340ede.6
        for <kasan-dev@googlegroups.com>; Sat, 08 Oct 2022 01:41:35 -0700 (PDT)
X-Received: by 2002:a05:6402:1842:b0:458:e6f2:bd3d with SMTP id v2-20020a056402184200b00458e6f2bd3dmr7973061edy.169.1665218494605;
        Sat, 08 Oct 2022 01:41:34 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:6029:e851:8078:4621])
        by smtp.gmail.com with ESMTPSA id d6-20020a50f686000000b00459e3a3f3ddsm3081688edn.79.2022.10.08.01.41.33
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 08 Oct 2022 01:41:33 -0700 (PDT)
Date: Sat, 8 Oct 2022 10:41:28 +0200
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
Message-ID: <Y0E3uG7jOywn7vy3@elver.google.com>
References: <20220927121322.1236730-1-elver@google.com>
 <Yz7ZLaT4jW3Y9EYS@hirez.programming.kicks-ass.net>
 <Yz7fWw8duIOezSW1@elver.google.com>
 <Yz78MMMJ74tBw0gu@hirez.programming.kicks-ass.net>
 <Yz/zXpF1yLshrJm/@elver.google.com>
 <Y0Ak/D05KhJeKaed@hirez.programming.kicks-ass.net>
 <Y0AwaxcJNOWhMKXP@elver.google.com>
 <Y0BQYxewPB/6KWLz@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Y0BQYxewPB/6KWLz@elver.google.com>
User-Agent: Mutt/2.2.7 (2022-08-07)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=nmR1Fi0P;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::531 as
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

On Fri, Oct 07, 2022 at 06:14PM +0200, Marco Elver wrote:
> On Fri, Oct 07, 2022 at 03:58PM +0200, Marco Elver wrote:
> > On Fri, Oct 07, 2022 at 03:09PM +0200, Peter Zijlstra wrote:
> > > On Fri, Oct 07, 2022 at 11:37:34AM +0200, Marco Elver wrote:
> > > 
> > > > That worked. In addition I had to disable the ctx->task != current check
> > > > if we're in task_work, because presumably the event might have already
> > > > been disabled/moved??
> > > 
> > > Uhmmm... uhhh... damn. (wall-time was significantly longer)
> > > 
> > > Does this help?
> > 
> > No unfortunately - still see:
> > 
> > [   82.300827] ------------[ cut here ]------------
> > [   82.301680] WARNING: CPU: 0 PID: 976 at kernel/events/core.c:6466 perf_sigtrap+0x60/0x70
> 
> Whenever the warning fires, I see that event->state is OFF.

The below patch to the sigtrap_threads test can repro the issue (when
run lots of them concurrently again). It also illustrates the original
problem we're trying to solve, where the event never gets rearmed again
and the test times out (doesn't happen with the almost-working fix).

Thanks,
-- Marco

------ >8 ------

From 98d225bda6d94dd793a1d0c77ae4b301c364166e Mon Sep 17 00:00:00 2001
From: Marco Elver <elver@google.com>
Date: Sat, 8 Oct 2022 10:26:58 +0200
Subject: [PATCH] selftests/perf_events: Add a SIGTRAP stress test with
 disables

Add a SIGTRAP stress test that exercises repeatedly enabling/disabling
an event while it concurrently keeps firing.

Signed-off-by: Marco Elver <elver@google.com>
---
 .../selftests/perf_events/sigtrap_threads.c   | 35 +++++++++++++++++--
 1 file changed, 32 insertions(+), 3 deletions(-)

diff --git a/tools/testing/selftests/perf_events/sigtrap_threads.c b/tools/testing/selftests/perf_events/sigtrap_threads.c
index 6d849dc2bee0..d1d8483ac628 100644
--- a/tools/testing/selftests/perf_events/sigtrap_threads.c
+++ b/tools/testing/selftests/perf_events/sigtrap_threads.c
@@ -62,6 +62,8 @@ static struct perf_event_attr make_event_attr(bool enabled, volatile void *addr,
 		.remove_on_exec = 1, /* Required by sigtrap. */
 		.sigtrap	= 1, /* Request synchronous SIGTRAP on event. */
 		.sig_data	= TEST_SIG_DATA(addr, id),
+		.exclude_kernel = 1, /* To allow */
+		.exclude_hv     = 1, /* running as !root */
 	};
 	return attr;
 }
@@ -93,9 +95,13 @@ static void *test_thread(void *arg)
 
 	__atomic_fetch_add(&ctx.tids_want_signal, tid, __ATOMIC_RELAXED);
 	iter = ctx.iterate_on; /* read */
-	for (i = 0; i < iter - 1; i++) {
-		__atomic_fetch_add(&ctx.tids_want_signal, tid, __ATOMIC_RELAXED);
-		ctx.iterate_on = iter; /* idempotent write */
+	if (iter >= 0) {
+		for (i = 0; i < iter - 1; i++) {
+			__atomic_fetch_add(&ctx.tids_want_signal, tid, __ATOMIC_RELAXED);
+			ctx.iterate_on = iter; /* idempotent write */
+		}
+	} else {
+		while (ctx.iterate_on);
 	}
 
 	return NULL;
@@ -208,4 +214,27 @@ TEST_F(sigtrap_threads, signal_stress)
 	EXPECT_EQ(ctx.first_siginfo.si_perf_data, TEST_SIG_DATA(&ctx.iterate_on, 0));
 }
 
+TEST_F(sigtrap_threads, signal_stress_with_disable)
+{
+	const int target_count = NUM_THREADS * 3000;
+	int i;
+
+	ctx.iterate_on = -1;
+
+	EXPECT_EQ(ioctl(self->fd, PERF_EVENT_IOC_ENABLE, 0), 0);
+	pthread_barrier_wait(&self->barrier);
+	while (__atomic_load_n(&ctx.signal_count, __ATOMIC_RELAXED) < target_count) {
+		EXPECT_EQ(ioctl(self->fd, PERF_EVENT_IOC_DISABLE, 0), 0);
+		EXPECT_EQ(ioctl(self->fd, PERF_EVENT_IOC_ENABLE, 0), 0);
+	}
+	ctx.iterate_on = 0;
+	for (i = 0; i < NUM_THREADS; i++)
+		ASSERT_EQ(pthread_join(self->threads[i], NULL), 0);
+	EXPECT_EQ(ioctl(self->fd, PERF_EVENT_IOC_DISABLE, 0), 0);
+
+	EXPECT_EQ(ctx.first_siginfo.si_addr, &ctx.iterate_on);
+	EXPECT_EQ(ctx.first_siginfo.si_perf_type, PERF_TYPE_BREAKPOINT);
+	EXPECT_EQ(ctx.first_siginfo.si_perf_data, TEST_SIG_DATA(&ctx.iterate_on, 0));
+}
+
 TEST_HARNESS_MAIN
-- 
2.38.0.rc1.362.ged0d419d3c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y0E3uG7jOywn7vy3%40elver.google.com.
