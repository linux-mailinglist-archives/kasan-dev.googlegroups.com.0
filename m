Return-Path: <kasan-dev+bncBDBK55H2UQKRBMGX6GMQMGQEPWIBRNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D53C5F484A
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Oct 2022 19:21:53 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id v125-20020a1cac83000000b003bd44dc5242sf594286wme.7
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Oct 2022 10:21:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664904112; cv=pass;
        d=google.com; s=arc-20160816;
        b=WAtDjex/HKqhfcFfg+1omWStrTqUs/mvjhXX0JoylmXnhehTrTbAawUIKncVJtB8M9
         s5rBUtRmoZ+809jSDA1kF3YlXJ+RqehblscsqWKtgH6lmAHEYaoNXgFuy50rCKdHSaZQ
         Ko2fCtl0u/X19rXi7TFQ3lzG6iRAsy+wAHqZn9Q9wjwGnda5g1l5UNrFG6cf+Mj+5xt4
         RjRURIRqmhaS2BVtWc2b+fM3y2V7+M+ifVuIcg2s9SkgUzqddHehEwnkNW5Nt2R63dx8
         o+MoemwmoTm56KrV51lGBHP03Q0CyV25viFUfgq1LoHKq6X1q0gFlJfpoTa4H2D4/RR3
         s1Aw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=SH6P6LDas7XfPjD90gNx2rq3IwkyebT4JKmuC/vp1q4=;
        b=WcZiUyPCrpKmWvnr0yMUC7H3E4kf2muttXP/mMJ7vrtRE9hDKBfuka35Xn8K8aRKkw
         zttRz+nKIcK/2xer0QBWOBO2F/IoX4msB5/qMJYPDpRMI+uxPzY8OVEMplMzSe96OEFR
         sdLJbPPnA4Q4QT/zW4HqQcF1Lg97YhsMSUMUPUwNONaUwIwjeblcGZZmy2vvRg0gcGBn
         UB4xu8/icJIUihiRMD7o7z0umaim8J7O+ZAvXNu1eEaF2lY7kC3iLtulRV8OZL1Ibdva
         7ov3S4pcLRjK3x9diS85hL+MdOkcBd1k0WKwmah0SX7CvdhH+xUD49VHs6sCgRb7r9Bw
         n7jA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=JRMyjcoK;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=SH6P6LDas7XfPjD90gNx2rq3IwkyebT4JKmuC/vp1q4=;
        b=PLo/KQZQJPI1x3cF0U2Oo14FwHfdMMHS68k3wffJfg2hbWHV1sh1g1D04n8rs/5ex1
         5YAttT4qUnYqEMnLRSNkk4jC6gaNTi21sSnicGJsqzp4T7Db9DH72fXewX7B8liE7wPV
         kVvcR3RJD0SBYe+mqP/AHWPX/i7aQApOgylrSog28M64jrm5RKY6JK4S5aMSEEFkTfBT
         2otlQTLCg8IARo+D2mBkzPsfQAjZu4RjTC54XSXZMKmk3zoRf/YtLDEGfXFE9ClyleYx
         AnVW0Y/x/crRLbb6OikhnpGNhO3VjKsQ6X0m3vo+5C47F01mqnEW+1mVUIWinrtl9nXZ
         H19A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=SH6P6LDas7XfPjD90gNx2rq3IwkyebT4JKmuC/vp1q4=;
        b=0G5nrN5JSLnVYPzE2bALdmOTbOJzGt7e8MOMyjiz09JmR9ZolDVC/c8YzuIQ2bQdeb
         i0hsBjYJ1s48KF3sD0GJ5Pu9nor1NfDbmrDJc0MQ/FP5RLEY78kDAXNiDQ71SRID9/0w
         nKPx7REKwfc3jev0DVGMC8cgmilVu7efeZ4Oxlb3YcNfBCi134HGLe/o+vzEZ8BAivNl
         5Q1vVxnBSAjWzB+8grg1bgobkzEpk7oeZfY1FQzgIsBIy/gZo+QLqzhQG4+FiW+1ys23
         AQkfVhIqUNb2VniZT9qlo6fDjy5vH+Tsd+uLYszhLIPB3g3HuauZ8q3UltbRpnNgiHTx
         XG9Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0/UBwB9Y9NotN861avLTCpzM1gZFphBbjeEaG5uhae/joW7I0A
	aSsaRObEldBtmadOT1TS7VA=
X-Google-Smtp-Source: AMsMyM6jMVYbrNHU7KlThMuHOcZhpEhR38Z3KOVHJRy+kPB9gH7h8QBsUU8xdBYcbJ50c6KWAxlL0Q==
X-Received: by 2002:a1c:4b03:0:b0:3b4:74d3:b4c5 with SMTP id y3-20020a1c4b03000000b003b474d3b4c5mr576808wma.96.1664904112473;
        Tue, 04 Oct 2022 10:21:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:388:b0:225:6559:3374 with SMTP id
 u8-20020a056000038800b0022565593374ls5611357wrf.2.-pod-prod-gmail; Tue, 04
 Oct 2022 10:21:51 -0700 (PDT)
X-Received: by 2002:a5d:4106:0:b0:22d:494:ca05 with SMTP id l6-20020a5d4106000000b0022d0494ca05mr13254038wrp.714.1664904111155;
        Tue, 04 Oct 2022 10:21:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664904111; cv=none;
        d=google.com; s=arc-20160816;
        b=nyZVr/DQ+5KFpc75uDMo3NI+m1cNkeF/h3iMQYGoHUdXzY7X7zI9E+Ei2W4wGMmXN/
         j2LFguiLm/tmckjbr9dPVASfQwTmvgE/1yDN8I0A3SGsIbyoSQusTFpuD+v8ZqGnJxAz
         5ysL82N4fxPuRCiorSnaAsHaAMPHjgfo4iGjaEzWlWF8UDE6gnRzwTWiFamNrR7P7xLy
         CPcn+BnmnWrj/HgvpqBjza5n+K53w+QzZ1VpG5RU8eY1yiCfweuNmsvLVdKb+hFngXH4
         96WPk8pd3u12bUcgQWE7qK9LY7vuCSrB/YKZV+nXXOgiZqDM0SsMGWoBcnfEMmtLeGMw
         zL9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=bh6vzn8U2ZsRPHfJfbA7bhjBG4wiyjRnctJShcuE7JE=;
        b=yZLiqmKPATbGmeaSzQx5ptXkvcnSX5vksPC0Lxa1B14/GgNjpDg3I/W67DXqUtqv4P
         EbGt5jYQVqbjk45sDRatufy19C1O4RE6qTH7G6h06z+f9ZMhkyX24pPciE5Ahi8juBSc
         vFijyGvAE2dmi7DHMfZeHV0pzzt/p6e3wbP6GPZDNQxOwt9BHnDUoDOXEVdvBq/Yu7jM
         PvoStzPtjUyaMg6eTrwFgbkIgssv4M9oWPdlCTeJycATOfM7FV3LWXqzKGx448Aldpj3
         UcbeeNdiYji5qQ3N8/Kseh2+0P0um7euaKVspcr8dHeNjuFLtLUXl86lhZNp1YsUVo2a
         KSow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=JRMyjcoK;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id l6-20020a05600c1d0600b003a54f1563c9si520449wms.0.2022.10.04.10.21.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 04 Oct 2022 10:21:51 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oflc3-000lRQ-4T; Tue, 04 Oct 2022 17:21:47 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 9E23C3002EC;
	Tue,  4 Oct 2022 19:21:45 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 8264920C3AB5A; Tue,  4 Oct 2022 19:21:45 +0200 (CEST)
Date: Tue, 4 Oct 2022 19:21:45 +0200
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
Message-ID: <YzxrqUFBNy/kR6PZ@hirez.programming.kicks-ass.net>
References: <20220927121322.1236730-1-elver@google.com>
 <YzM/BUsBnX18NoOG@hirez.programming.kicks-ass.net>
 <YzNu5bgASbuVi0S3@elver.google.com>
 <YzQcqe9p9C5ZbjZ1@elver.google.com>
 <YzRgcnMXWuUZ4rlt@elver.google.com>
 <Yzxou9HB/1XjMXWI@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Yzxou9HB/1XjMXWI@hirez.programming.kicks-ass.net>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=JRMyjcoK;
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

On Tue, Oct 04, 2022 at 07:09:15PM +0200, Peter Zijlstra wrote:
> On Wed, Sep 28, 2022 at 04:55:46PM +0200, Marco Elver wrote:
> > On Wed, Sep 28, 2022 at 12:06PM +0200, Marco Elver wrote:
> > 
> > > My second idea about introducing something like irq_work_raw_sync().
> > > Maybe it's not that crazy if it is actually safe. I expect this case
> > > where we need the irq_work_raw_sync() to be very very rare.
> > 
> > The previous irq_work_raw_sync() forgot about irq_work_queue_on(). Alas,
> > I might still be missing something obvious, because "it's never that
> > easy". ;-)
> > 
> > And for completeness, the full perf patch of what it would look like
> > together with irq_work_raw_sync() (consider it v1.5). It's already
> > survived some shorter stress tests and fuzzing.
> 
> So.... I don't like it. But I cooked up the below, which _almost_ works :-/
> 
> For some raisin it sometimes fails with 14999 out of 15000 events
> delivered and I've not yet figured out where it goes sideways. I'm
> currently thinking it's that sigtrap clear on OFF.

Oh Urgh, this is ofcourse the case where an IPI races with a migration
and we loose the race with return to use. Effectively giving the signal
skid vs the hardware event.

Bah.. I really hate having one CPU wait for another... Let me see if I
can find another way to close that hole.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YzxrqUFBNy/kR6PZ%40hirez.programming.kicks-ass.net.
