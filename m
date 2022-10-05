Return-Path: <kasan-dev+bncBDBK55H2UQKRBGX66SMQMGQEWVH3BRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 503115F50BF
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Oct 2022 10:23:55 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id l1-20020a7bc341000000b003bfe1273d6csf92896wmj.4
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Oct 2022 01:23:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664958235; cv=pass;
        d=google.com; s=arc-20160816;
        b=rLRBi1r7b3nnYtOM8qMvI3798lW+F4wWVwcawWnjSOZjbAatIgzzsNnnILWREto0BE
         funhFMBEVbH/xFXhkgD/KGQ9ttQAVLtpkXrPorDW/ljoM8EMmBzdHGYVw0F/etOyGFvC
         yZDR+nBsIcfmOBW635k3aD9M2DMww6em7qejm2kE524qFb3WiRC4HifQiAKvDWMLmaCv
         gfcQyP0IkDDLnfvgHWMQIZV7QENDSj7okF+AHyykwowDjVy1IicYcz+EncVOtBHDfDxl
         ElrmndmoB+Ihey3/kAMcxt7X1NL3Rz1aD8upoR04D7H50Y0AR9p2tnxVypnrper4ak53
         Nc0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=0BmWwdSjzwngya8GFND/+UC8gRlhQyZMM/h25nULE6c=;
        b=e9VLfgBSyXePS7yVf3XfQowGyrrou5hanqjCUlVfZWWR3HSO7SH4xnbsaK7T2loX8k
         9ws0STuHLjT5btXHyMpfI2u6SXlTUXLRboDKAPuG0J4fpaOkGPQZ+wvRH/3hSt160qc+
         ABSZlaOq1P6FjGQ1csobTfCMH4KjmjPfWYW0U91pbPuaNrUwR/803yBoaoNMbW0WyQc/
         7U1rpzTO8/J+/V64X9ErrKeQI4jPt0X+At0k9b4lYidDyaXiMhavJzNrOj9o1Vqzwrsi
         +QpMdcVs4fvh7+R2WdUjhGS2Kjm31tkx5gZivYzGO2cw6pSS9EEwJnM/UD+7LxOUeO0N
         YofA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=kJMPjhN6;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=0BmWwdSjzwngya8GFND/+UC8gRlhQyZMM/h25nULE6c=;
        b=ZSxcB06HkCpXyA9ym7YKaRNkFOnnmsbT78aD7CWSxvGwVPeRC5tTIvRNUIvOUMusjx
         Rne6Fz6LgxdE8zskUA6q7sScjDT27Y6HVseWmljKmFr0QaIEvV6W19HiCCnpwzxBElSF
         Dk5MDWIe/tvcZkDTLydRM+OsL4cV8L0541Yuij/2UgyA4ZT+K+4tuKMusZ2lU0ORAXTn
         xqax4B0z2wymJHQOn+PymbGCysYio7c8giCY0EsFR6i13nQ6cdqGyDrUWbFM66RkUC4K
         rfKXKGKiGxUPGSb0c4L74UDA0nK+z0clYA9f50bzeaAmFWfV/kJMWJhTkCsKthPmgSZW
         1LmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=0BmWwdSjzwngya8GFND/+UC8gRlhQyZMM/h25nULE6c=;
        b=EMXe3tmcwqBIL6Pxr6teAwTOCyzKj4r1Ba2VtTJn7MGtgunHt8XUj4VwjCX94m7un7
         MG5ErgKLwgdOXv9o94cjsugxAtVk1GGSGZF49cGBUjadQ84J6roQfqZj+XfnQ4f2Cy6L
         vXYHapy1QBqCRuCfgQzB+YtsO3iacz4eqhQeIuEAl0zDpf4ykyJbGJz911EOFmur74lt
         8lyZvQGIsvhM6Ozt/GG/bPCPoHoyhhmmcHESpBTAVIjCeYkmebciqw3bu42bOEyhtYFP
         VKo0ELzP5ESgYRqpu66R++lAzhu/eCe1N/awXP9JYxZ6vFbMCULEnbcn3X9IdFMIpl5c
         V0cA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3+OYhIUhbqRBGl8jK8iN3bNPnZpiOU/U1smDZXMrHucW8FwEiZ
	fyDM8lu+iET8lUBF5iDpDC4=
X-Google-Smtp-Source: AMsMyM7rGGrb3lB3EQ2BuBykhTIOTBRaGOXoac8pBwK61nzUwmQMISuVaJYJSq0pgt93AUsIAUtsuA==
X-Received: by 2002:adf:dd47:0:b0:22e:2bf0:3fea with SMTP id u7-20020adfdd47000000b0022e2bf03feamr12785849wrm.197.1664958235027;
        Wed, 05 Oct 2022 01:23:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b20:b0:3b4:fe03:c8a2 with SMTP id
 m32-20020a05600c3b2000b003b4fe03c8a2ls606682wms.0.-pod-canary-gmail; Wed, 05
 Oct 2022 01:23:53 -0700 (PDT)
X-Received: by 2002:a05:600c:5128:b0:3b5:d6:eb8f with SMTP id o40-20020a05600c512800b003b500d6eb8fmr2540769wms.65.1664958233727;
        Wed, 05 Oct 2022 01:23:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664958233; cv=none;
        d=google.com; s=arc-20160816;
        b=ntk9PajZ2sDtCtAQBpb1XrFbVgV5HhMP9DfsO7VysA6Nn0djMj8Snld8Pf8KKGvDuh
         quCtXMQRFmBbtctZxgCoin/9tCW/rpo4rkwVOVqhGtmd8vOELVxkbUkMrk/jUeIsEaHi
         PSWuzWBGdCrhm9mW8gSU4H6OiX6fsNhcPS0X0icz/XJT0g8Y0Te/VnnaUbdWmayQWTKR
         SR9UkdDysXmQ+eb3tS5n0Gs+a1IEbBf94b0h42u491QRtwogJfBdXs4U+pVlNiOUGrFW
         h3LFYLLcvLxxXN9NYWlURuWqhAn0Dk+RsvQ8sSqqRwnkpsYZmhQI2A0T/nGhUmFg4opJ
         uklg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=EnWe5Z/LqqGP1/UejfDNmVCgj3ooQI9F6kvj8QuOzms=;
        b=b2Tmh/Gfr1UOBJ5ES4zDc1KLgdaUWj5ooCxBjAjwN6RfZsH1dhGZY1NajaT3Pgv5HG
         jZS2P2JdiMQJFVfYZiXuFHaRJk9yKhx6fGNTpPEOAEgMrN+vnlATpl3KNL75cMuIFFf9
         ycc27GohMt2qpNdX8YdSXTmUNZBf2AaVSf18/gv4HfwPO9ZH3XbVrP0Jew0envBjBPP9
         Tn/NRuP8Jl+W4DBBi1EEQorPoxYr0aj0QRkfoKwF/sxkL9TigeZjfeHSlLyj+ZsZyKa6
         JkGhMZWpFZwpAQkoaJnTdIfL/WjzQTaI/iv0/Bj0bdNEVU0JwQ3Fb+0tDrhEzBcDQkC3
         EVEg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=kJMPjhN6;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id 125-20020a1c1983000000b003a66dd18895si208600wmz.4.2022.10.05.01.23.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 Oct 2022 01:23:53 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1ofzh4-000Ded-KV; Wed, 05 Oct 2022 08:23:54 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 3CF75300137;
	Wed,  5 Oct 2022 10:23:50 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id EB6552018BB82; Wed,  5 Oct 2022 10:23:49 +0200 (CEST)
Date: Wed, 5 Oct 2022 10:23:49 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Ingo Molnar <mingo@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>, Namhyung Kim <namhyung@kernel.org>,
	linux-perf-users@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH] perf: Fix missing SIGTRAPs due to pending_disable abuse
Message-ID: <Yz0/FfW4kwSK/p9c@hirez.programming.kicks-ass.net>
References: <20220927121322.1236730-1-elver@google.com>
 <YzM/BUsBnX18NoOG@hirez.programming.kicks-ass.net>
 <YzNu5bgASbuVi0S3@elver.google.com>
 <YzQcqe9p9C5ZbjZ1@elver.google.com>
 <YzRgcnMXWuUZ4rlt@elver.google.com>
 <Yzxou9HB/1XjMXWI@hirez.programming.kicks-ass.net>
 <CANpmjNPwiL279B5id5dPF821aXYdTUqsfDNAtB4q7jXX+41Qgg@mail.gmail.com>
 <Yz00IjTZjlsKlNvy@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Yz00IjTZjlsKlNvy@hirez.programming.kicks-ass.net>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=kJMPjhN6;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Wed, Oct 05, 2022 at 09:37:06AM +0200, Peter Zijlstra wrote:
> On Tue, Oct 04, 2022 at 07:33:55PM +0200, Marco Elver wrote:
> > It looks reasonable, but obviously needs to pass tests. :-)
> 
> Ikr :-)
> 
> > Also, see comment below (I think you're still turning signals
> > asynchronous, which we shouldn't do).
> 
> Indeed so; I tried fixing that this morning, but so far that doesn't
> seem to want to actually cure things :/ I'll need to stomp on this
> harder.
> 
> Current hackery below. The main difference is that instead of trying to
> restart the irq_work on sched_in, sched_out will now queue a task-work.
> 
> The event scheduling is done from 'regular' IRQ context and as such
> there should be a return-to-userspace for the relevant task in the
> immediate future (either directly or after scheduling).
> 
> Alas, something still isn't right...

Oh, lol, *groan*... this fixes it:

Now to find a sane way to inhibit this while a sig thing is pending :/

diff --git a/kernel/events/core.c b/kernel/events/core.c
index b981b879bcd8..92b6a2f6de1a 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -3426,7 +3434,7 @@ static void perf_event_context_sched_out(struct task_struct *task, int ctxn,
 		 */
 		raw_spin_lock(&ctx->lock);
 		raw_spin_lock_nested(&next_ctx->lock, SINGLE_DEPTH_NESTING);
-		if (context_equiv(ctx, next_ctx)) {
+		if (0 && context_equiv(ctx, next_ctx)) {
 
 			WRITE_ONCE(ctx->task, next);
 			WRITE_ONCE(next_ctx->task, task);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yz0/FfW4kwSK/p9c%40hirez.programming.kicks-ass.net.
