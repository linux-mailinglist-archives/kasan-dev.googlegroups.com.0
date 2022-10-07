Return-Path: <kasan-dev+bncBDBK55H2UQKRBAOKQCNAMGQENYWVCFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 36C975F789D
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Oct 2022 15:09:22 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id y9-20020a056402270900b00451dfbbc9b2sf3821706edd.12
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Oct 2022 06:09:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665148162; cv=pass;
        d=google.com; s=arc-20160816;
        b=QM9TimNr5IpA1P7tqqgu6ayUsVrV/Wt72k4KLyqwmJ06eCPiC4Wfq4c0xW2QOIlju1
         tqbWnPjLy4QHH2UqrS9LALe0QVTAskY+yMVucKoV66bvBpkhND4TpWxKwpUgce1jklTH
         39+Paf6TK23qXt4WqgApUs9J86lMUVoaiOy8jUGvURGI8ZiEJVQPu7hDMLM3lMzWPUf+
         yNwFJkneMrukTQDMoGm3yoK9ZNmbH3t+uooeOSX3/+NKmNodwWVvU5OXd7AdRvS+XpWc
         RJaLZgdE9UmtEbE2vh4VQ3CVV2pD/R3odd0AmVk5T5sim9o5aK2+2zvGUWpcMPsODYit
         zgaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=WHwxCdyYsqZavmsmF/9tqO50pht3doUWe7XdWrXWbjo=;
        b=ECPCW9Y+QNkBJ2NrzRDJQeuQMFiwIiJolOOVRHDaRCCd0yAcdi7lj+I+xwOjCSpfZD
         OMtBdUVhVKykKbOLgXGG3WnZPVKB+HQlrv55L2OxSvSGEamIl7zMM6lDa2xFh2c6Z77x
         pHPm4WMFOb1dIPbvWL2mnIVrj1suMhq+p5Gls4ZHqBRawIzCXBpuWl88eFQ4/vrrkoV2
         WlCSboky1D+n/TyCCKz830wyvK5krEMSSrYvU2gIEirJEDnJu5fi5FcPtX4KW85BDTkU
         NJmiQZeziiKPd6iaHMWAyWH3rmzfUhBBAKrxCb+I9uS3rYy3BhtgF1XgcJnV1BABYeav
         xudA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=nEqRyilq;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=WHwxCdyYsqZavmsmF/9tqO50pht3doUWe7XdWrXWbjo=;
        b=B+KXScxd7aNFmSPN0dbnVOZ/Z3B9XxCEi8c2BLULatPOUyAoydxCt79xtr+ElzvD7I
         J9O8zOPdKb7BfuqfHmwDL6SWLSBCTqzqTUhuEgV1U40/JYCMxJwwgYrZf8QSZsjh8UOL
         DxsW0x5vjLIhf9hwNcaJ6Jks4Hq2BeDwStyQEbFqyRz+eYsnpa3UMWwHgh6AIKFgsvTq
         2c8gvDkVKSZkagB3UCyHO+33GcnNhxCbz2nVBvySOrxEQBEyW3wiMt2N1ru/mDO/+qSI
         /NupepXj0bvU9Xcmd2Bc2rI9n8MLbERWH+9ZLxO1E120og+T9lEkEw8WTwrFVSL0g533
         IryQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WHwxCdyYsqZavmsmF/9tqO50pht3doUWe7XdWrXWbjo=;
        b=B8kXdj1ffnBw/WpuN5cJN7RfJlgtA6tARrsZMf1sqq6LkEu4kpSMaXaj3RPeEuxU8o
         mvRMjHIiZCcP+T/uT9Yu+n/+54QPvsriXD0lhWoWLy2irAIbwgWGmu77eHyRnL4Rn7eX
         ozva/2rUzVptXKInWgMY7uiUCIifwo7jl0V6cRkCEIibUUd6WS9vl4hD7clRmvb5CFnW
         l6mEIQzc5AUJ1J8zeareF8Efa+0iHhGYGv/gsb9CCC68CykaT94MHkNGqrzvatF7k1nn
         MYpZCSmAnVaSlAbVDaGDCMg0uzl8zNAiW4viVWF9FhO+n8zgDQqetMQgbYib4QOoli0+
         2D+A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3oByMl0mEERAM6QQCx6aNsunh+xwJmmuZwuuW8lHZZUXydDQ8/
	nGfNQQNaM9G56f5hxBdGYMs=
X-Google-Smtp-Source: AMsMyM6O6+qiWtp/mQheanoXy+x7TOzRrziMLRvC3R8D31/waFGLHePJvrSl+RQo4FuA56GYEiS9Zg==
X-Received: by 2002:a17:907:270b:b0:77b:17b3:f446 with SMTP id w11-20020a170907270b00b0077b17b3f446mr4000193ejk.415.1665148161639;
        Fri, 07 Oct 2022 06:09:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:5255:b0:457:99eb:cba9 with SMTP id
 t21-20020a056402525500b0045799ebcba9ls1844111edd.0.-pod-prod-gmail; Fri, 07
 Oct 2022 06:09:20 -0700 (PDT)
X-Received: by 2002:a50:ec8f:0:b0:459:b0e0:e030 with SMTP id e15-20020a50ec8f000000b00459b0e0e030mr4514263edr.303.1665148160362;
        Fri, 07 Oct 2022 06:09:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665148160; cv=none;
        d=google.com; s=arc-20160816;
        b=eFM/aFzQ0rJBGoaKTHiLNyCwQ6cA3n7yzaCA/7LECmrL+fyJDU3fBWm8zX93JdvnZt
         AcivrQ5IJD4asabU2uOrtFPJzVn1sc+MpEYklN4NDBPzw4mz0EnsPE4Td2LY6M8TkMwP
         rWFtj9DmqTXKFVNNQ9fFcUs/a2kYnJeoUFs/aRyjja9fBgGU7Wi1TesM6sFiyX1M//iJ
         K83AlWTwVs5TOOHJAMzCv1Du6BAoCidYENciNzsPMnHV+2HYW3Vt4KsHo2qanictVpID
         dQhxmRcwctg8MU6RBjtRlZpeWyzBYSk5RqBB3bWka9/3YP8kR86YMJw5A98EfYV4cZQ8
         39Uw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=0BeKBcF7ouX2G91odn0fVr+GuMOLBqXSocw/B9YMzNQ=;
        b=bFLOEY7S566mGF2ChcpI5OW3oJY+y62W39+iQtohKNQY7pwaNGTMdSiJkHyarTemTi
         Ql6uP9BIuPbA51hY35rpRMr2lHKqefCI0dETyVoq7ZB0Fr+KP1K9k5ojdseVYrXAsSVT
         QrZLzhpEWL4aim0WvuzOqivKrpvDoUDgtelX+8isa4TfrW7hfSFYjfFFBZr8BDWQkx1t
         0on3NCjXEp4+HeXEDRhQWlYpVkiJtMqXEgLg6v459zq2LXV425BAat8Ed2M2VlrXrHQI
         YXq9+mh2JLYv151TU2hCJai6UuWIwdux4+fjViS+Z7At8SqObQcoMxE8rbVs2DkIB+z5
         V83w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=nEqRyilq;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id hz20-20020a1709072cf400b00780aaa56c40si63071ejc.2.2022.10.07.06.09.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 07 Oct 2022 06:09:20 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1ogn6L-001THF-Il; Fri, 07 Oct 2022 13:09:17 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 0D51A300155;
	Fri,  7 Oct 2022 15:09:17 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id E2DB92BDA8BD6; Fri,  7 Oct 2022 15:09:16 +0200 (CEST)
Date: Fri, 7 Oct 2022 15:09:16 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Ingo Molnar <mingo@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>, Namhyung Kim <namhyung@kernel.org>,
	linux-perf-users@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH] perf: Fix missing SIGTRAPs
Message-ID: <Y0Ak/D05KhJeKaed@hirez.programming.kicks-ass.net>
References: <20220927121322.1236730-1-elver@google.com>
 <Yz7ZLaT4jW3Y9EYS@hirez.programming.kicks-ass.net>
 <Yz7fWw8duIOezSW1@elver.google.com>
 <Yz78MMMJ74tBw0gu@hirez.programming.kicks-ass.net>
 <Yz/zXpF1yLshrJm/@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Yz/zXpF1yLshrJm/@elver.google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=nEqRyilq;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as
 permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Fri, Oct 07, 2022 at 11:37:34AM +0200, Marco Elver wrote:

> That worked. In addition I had to disable the ctx->task != current check
> if we're in task_work, because presumably the event might have already
> been disabled/moved??

Uhmmm... uhhh... damn. (wall-time was significantly longer)

Does this help?

--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -6490,8 +6490,8 @@ static void __perf_pending_irq(struct pe
 	if (cpu == smp_processor_id()) {
 		if (event->pending_sigtrap) {
 			event->pending_sigtrap = 0;
-			local_dec(&event->ctx->nr_pending);
 			perf_sigtrap(event);
+			local_dec(&event->ctx->nr_pending);
 		}
 		if (event->pending_disable) {
 			event->pending_disable = 0;
@@ -6563,8 +6563,8 @@ static void perf_pending_task(struct cal
 
 	if (event->pending_work) {
 		event->pending_work = 0;
-		local_dec(&event->ctx->nr_pending);
 		perf_sigtrap(event);
+		local_dec(&event->ctx->nr_pending);
 	}
 
 	if (rctx >= 0)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y0Ak/D05KhJeKaed%40hirez.programming.kicks-ass.net.
