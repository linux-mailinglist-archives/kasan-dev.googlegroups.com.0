Return-Path: <kasan-dev+bncBDBK55H2UQKRBOHY7OMQMGQEG5FXQOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 89DE65F6B22
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 18:03:06 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id z17-20020a19f711000000b004a24ea72fa4sf778995lfe.9
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Oct 2022 09:03:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665072185; cv=pass;
        d=google.com; s=arc-20160816;
        b=N+jXewG7vUk0xr0k6wzDC7C7UYtjYtlo4xus/yC+Q22Ec+AGeEb0zvHs0vpZv/2L5D
         QBqtPAZB9nb4mh1gCUKZw5Ht/68eFSnjTEdaNj4pvtyEOONkOytSDFrFuStwkSy0nxHi
         ciHbPzf63Mx9zQ6JcjGR4fwigAHCixAYPzlBbqe2sRdkUh0wjJsm1jSNntSgQjVhPmYk
         76vhuzAoi4Ftsv+7an2Blr1iKzsFLA83apTQLxUJ5y85Ggtw2yy0pCVy1BnuLk2PhKaY
         d0FdvNSLfuNkFAb+wWbWoacKDe7NG3w4ivbcFOLfZwmjkNOH3zj0O8MndGRCcwFDcuXw
         2hCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ryJEg/Sjbt+f+RtEwRGzp13+fSqisX9L44FZRW3WB+k=;
        b=A0eS4XNwgD3UPi6H2+cZ2df4gTtc/8JT4Wt/UfPAvZDidOKV9ou1nZ/qgRZYasgyOm
         8L+7LO+Pgu5aosTmB02BIl443NwBYAFJW24uv1H8aoEhjPP29B1M3EP6Ai+BXpVtANQ+
         Wm/vIioTxo1XvOIIqwz66kTbui0H4xvaXgY/tmhRWK3bgD24qZeKgKGTKxT2ytB7gXua
         euj2RxBD1+aJaWoaEdmtfFas5ZNGkfYiFLbjoi+PgXIRjLMEYrwWjRNq4Lvqa/9MIMoU
         xxy1mrzAOSHZkdDi/c8bk+OWZGPIQt5SNXSaPjuJSDrKGjHSvgLv2oi+LTY9ifoPIfQM
         eQWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=EOo9MOrs;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ryJEg/Sjbt+f+RtEwRGzp13+fSqisX9L44FZRW3WB+k=;
        b=d4jZCdxu6enPimmsMtdS5i1zJyLHRAJzVEJPGc90YglSmWu9SMK7P/TncomPogDScU
         x1e8LJF240RGey9SZsvmjnJoIZR/ri9Mrt8dZlDxk9eq1Fom3dCqRNfgPALPwBAzj3ff
         F1er5F63swN7MVJO48h4IJzZtW9ClmeZpVnNIWodvno60R6BhLC4ytiYC107R722sguJ
         1fdw8trT39eWvxVZHZFYa+RzbLk+TujYBwsf/4ftfSHu3JVlTosGbDiz7sj4WbSm0gwh
         mLubI5sKDonqtLdWbbzPyRSpWgb+AZYCOBxKUiTXskJnczbL3A5nmoBwoEid2XjPv2rD
         mYmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ryJEg/Sjbt+f+RtEwRGzp13+fSqisX9L44FZRW3WB+k=;
        b=PYtT25AgUGj9DzZtZWOPyZT7LS21aslLWr2cM/Msaho179b7LBqrXWoc1WHWXwunVE
         l7UtalHYu1gobBMGWfhZV298PgGRaJ+Rt8+bh3/WuwaiCnRwaAkHYHANEFx26GCqveYd
         ulyok7LMRE0Dix+fX9Ol27PlsRH6gcVwT9hT0Fk7jW1YcM+RkMmSMSCGw2Mo2azqWJKU
         8+1axoMapHfz7cOWKE87gwBEE946gZtBxSxqH/0oPiu5a6qW/Ey6olghkxBH5trc6Zwu
         o8N1JL1SvX/+1gNdAPsnPQjFUgFRBMId21ukP5llooZgHnXNtJAA9Xva7viiytfcgj8m
         7yAA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2WJpnHsewqlmFBbmqFfxI/yay+mTVww+EapzArLNQCSx/QNDUB
	hqOUsYNq9z4b/jaeJRNz2Qk=
X-Google-Smtp-Source: AMsMyM6AOzvJcWL38X/1hpFmq97NbOVILgjghPuMeRDN4AxLOqliA6M4Nfj7cXr0suAuAwZT144oBA==
X-Received: by 2002:a2e:8315:0:b0:26d:cbfe:477a with SMTP id a21-20020a2e8315000000b0026dcbfe477amr135923ljh.480.1665072185030;
        Thu, 06 Oct 2022 09:03:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3a5:b0:49a:b814:856d with SMTP id
 v5-20020a05651203a500b0049ab814856dls1678796lfp.1.-pod-prod-gmail; Thu, 06
 Oct 2022 09:03:02 -0700 (PDT)
X-Received: by 2002:ac2:4e90:0:b0:4a2:2a79:392d with SMTP id o16-20020ac24e90000000b004a22a79392dmr249816lfr.578.1665072182143;
        Thu, 06 Oct 2022 09:03:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665072182; cv=none;
        d=google.com; s=arc-20160816;
        b=beg6zKhzJHvTaBCWjECivlgMw0fmc2koJrsq95RNSSbnsMJ+zr4ej1Oh8mfLn8QmY1
         +ZbW/Ao6ZliGyHFNYOJiwxc0/3BiWK1S463NiebCv1/SLNAza+AYVgvuZ9A/UO+OSexl
         hX7zg3g3mW3klo4QRRYYSNIJtp++dRC7gF/T2xnpRFxu1ZSCYJZo3oOS6wSbpQ+jEBer
         0F7txzip2geCOGtOXgxEyMLPxjz6tJmLD5cJf0bfeQ2oVDhq43fSlk/yHQ8FF46rYBlP
         jUwpetiPcyzH6k8P6ZHu2adhW2Wtfiv5LpgP4YJhojyhMAhD+rZI2bH6ZPMjFKLUbXyP
         OwaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=zm6xeXW0jCLbsA/duPDusxJlDbKzTuDSlIfxsNlzugc=;
        b=u09vFCOnR1TUnxYmL9bPI9pPdUQ4vqUCV0LyPQuRQiiM3b5UC1O47YksozFrHdpgeh
         I4M+2tfU2QSxsd4BapjYO6AQLdsTYvZv6JOzRnhN++ti7f5iEPcFGJEx512qhPhAj6to
         H5CFES4bP0u1ojk1O8baGNf/Xatfuay3dhTawBXhhzq+xqMBSCOJssLe6/99M+zOvj5E
         u2ShPgIfJjeL5lWr1eLivNGQF6JhMDVtI9BjiPEVjml3rKiaM2wrLjaeKTG+FQRh1Y3f
         DvzopMseuZqvTsBOGOaEPckpeLKs1OOiyqlM9V/HSSLycfDmcXn3Pwa16UXHFNuKAHJb
         mYdQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=EOo9MOrs;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id bi42-20020a0565120eaa00b0048b38f379d7si655170lfb.0.2022.10.06.09.03.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 06 Oct 2022 09:03:01 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1ogTKs-001GSf-9e; Thu, 06 Oct 2022 16:02:58 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 47397300137;
	Thu,  6 Oct 2022 18:02:57 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 0995220ACE696; Thu,  6 Oct 2022 18:02:57 +0200 (CEST)
Date: Thu, 6 Oct 2022 18:02:56 +0200
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
Message-ID: <Yz78MMMJ74tBw0gu@hirez.programming.kicks-ass.net>
References: <20220927121322.1236730-1-elver@google.com>
 <Yz7ZLaT4jW3Y9EYS@hirez.programming.kicks-ass.net>
 <Yz7fWw8duIOezSW1@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Yz7fWw8duIOezSW1@elver.google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=EOo9MOrs;
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

On Thu, Oct 06, 2022 at 03:59:55PM +0200, Marco Elver wrote:

> That one I could fix up with:
> 
>  | diff --git a/kernel/events/core.c b/kernel/events/core.c
>  | index 9319af6013f1..2f1d51b50be7 100644
>  | --- a/kernel/events/core.c
>  | +++ b/kernel/events/core.c
>  | @@ -6563,6 +6563,7 @@ static void perf_pending_task(struct callback_head *head)
>  |  	 * If we 'fail' here, that's OK, it means recursion is already disabled
>  |  	 * and we won't recurse 'further'.
>  |  	 */
>  | +	preempt_disable_notrace();
>  |  	rctx = perf_swevent_get_recursion_context();
>  |  
>  |  	if (event->pending_work) {
>  | @@ -6573,6 +6574,7 @@ static void perf_pending_task(struct callback_head *head)
>  |  
>  |  	if (rctx >= 0)
>  |  		perf_swevent_put_recursion_context(rctx);
>  | +	preempt_enable_notrace();
>  |  }
>  |  
>  |  #ifdef CONFIG_GUEST_PERF_EVENTS

Right, thanks! It appears I only have lockdep enabled but not the
preempt warning :/

> But following that, I get:
> 

>  | WARNING: CPU: 3 PID: 13018 at kernel/events/core.c:2288 event_sched_out+0x3f2/0x410 kernel/events/core.c:2288

I'm taking this is (my line numbers are slightly different):

	WARN_ON_ONCE(event->pending_work);



> So something isn't quite right yet. Unfortunately I don't have a good
> reproducer. :-/

This can happen if we get two consecutive event_sched_out() and both
instances will have pending_sigtrap set. This can happen when the event
that has sigtrap set also triggers in kernel space.

You then get task_work list corruption and *boom*.

I'm thinking the below might be the simplest solution; we can only send
a single signal after all.


--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -2293,9 +2293,10 @@ event_sched_out(struct perf_event *event
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
 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yz78MMMJ74tBw0gu%40hirez.programming.kicks-ass.net.
