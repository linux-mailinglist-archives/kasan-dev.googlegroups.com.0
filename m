Return-Path: <kasan-dev+bncBCV5TUXXRUIBBF7N5SBAMGQEN4KXQJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0ACF53478EA
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 13:54:48 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id a65sf390781wmh.1
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 05:54:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616590487; cv=pass;
        d=google.com; s=arc-20160816;
        b=B/1LkuNWOnR30I62hnOnxTx4RYbaKPp8ygds1M1YPHWUnx1Hmm3mr90VYjo0j90dHM
         olSKKdTszG9r/fyAnb4AzLBh9vpOGJwZXFJ27jbAq30i4fF6ud6ZxgD0RFmTtTTpizt6
         bSFrZFkL+ClmoG4879N43G9yEb8EPo9ohSqOTYssyQ9kvA/wJf/R387859XZJrJR7map
         gvniToI/txFFEqyF5fGxRExWDXJPO2/MQ2Z/mL9tB6ktgLJeVIwcfYTlICA/M5qvGuYg
         pZCi6Z/NAQkwxNr7n8I+6Rl6NbMMA+sLvJ9uvoWBSxK80mlcYP2+ddL10WtBDLcZFQkS
         UTCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=UwzkY1IRIgxNOEJh1MrxntLzP8F30pEeBe5ZMzsJ6Hw=;
        b=izyDatcSvbrpW14mgFH6G8lNuebF3t/jtejc/hyGEo1Xxq2FM+s6eJkw6qQuG5rWX5
         vwy8AuaFJtPTYyu3S++XzveUDfm+c5/4AzdYIX60aiCAUUWKJ4Po10hdzxq06GskEc6A
         TQab/lFNWgzFaLmXWTZmo1XjOXlaSOxHNQQAD1lR29Bz+m5jON2+OBIHYLFn4P58G3nv
         FU8HZecYh8ElVwcmhy/UVvQczWAmUo5zsGx80x5cL5bhRRWradcH4wrWTeNE4zUp0pDV
         IUDc64rKrN36Fnutf4jRSk88kNUF2fDkmbH6RZu1JbKMS9iIg3/CvOkIDN9kcihGN4Fr
         GRkw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=tf1rnOdW;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UwzkY1IRIgxNOEJh1MrxntLzP8F30pEeBe5ZMzsJ6Hw=;
        b=rww3LdfvDqormHqh36rSqUll8pl69FXnHJPGxylGki5qLobMWNBFGmv9StHO2vxZAw
         uFJzq1oONLIZqHzMqa8F2ic6kzbLXH5ANudVYdptm/DV77+9YU4TFk8DpgumS4CxcWze
         V0dRKR0s5tuP/QhCpaNsfImXL+wzm/dh3dhz0D32S2IDpQTRsXLdeyzBoPLQXqF7TsA3
         lYwvTc1Pbz0Z2twseVPafXHWqaGWbfKWc14NrOEbCHZNT1h1UxAK0oxQ5wQtmOEVDugv
         ngaz+vHeZu+P5m9WwwQ90iqCWVdith3rPHCoQvuvgsxyj7lm0q3tkWcnE3BoCIZ827oj
         awXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=UwzkY1IRIgxNOEJh1MrxntLzP8F30pEeBe5ZMzsJ6Hw=;
        b=B6d2/P80nRXY3CEw1qfAPmeKQjKEB5htHV6WBAzVK4U0gnQY0GPd2X7qn7TSMA6ubw
         yyrkUGGnvb5ivPDG3Pfj7Fc1aDxXfOZqyAuzISp2+Zefum0mi/p1vuLr6zRUqVsV9jVy
         ztVY92xG1+InLXhsY3nOKdiB0adMXGvf3QeoNp2GWIIc4Nlvr9u262pUUqPwuad3MKf4
         SChjaE1N7dUvSLCQf12NoW0uFoE5twxDcXENAAio/pbEjzAYzF86TH8iBiiXOqiI9Z1n
         uh9w+qxH8A+mk/ydPF2BqKxdg/GfZ1i9SGy0x6xxEQuhEbhJ4vsRbUI2ZlffisiuCtek
         8O9A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533B7werdGarmdsaZfWIh8NEGqgvcK0n04XlLtGBEa81KfiawYHz
	ltwzAviu+VzS58/lM+7JVOU=
X-Google-Smtp-Source: ABdhPJyMJTrQqo/Cl3HHbdi3fz2CRYp+elCREykAdL1TsfsVumjSzRsoGsShCi11Fi9jJiTF0cxfSg==
X-Received: by 2002:a5d:6b50:: with SMTP id x16mr3262756wrw.379.1616590487804;
        Wed, 24 Mar 2021 05:54:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6a89:: with SMTP id s9ls2539705wru.2.gmail; Wed, 24 Mar
 2021 05:54:47 -0700 (PDT)
X-Received: by 2002:adf:f711:: with SMTP id r17mr3349506wrp.358.1616590486990;
        Wed, 24 Mar 2021 05:54:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616590486; cv=none;
        d=google.com; s=arc-20160816;
        b=qm1jgLFkJ8IJkxaapyYNn5VMldnwmFBaiHBGMrSkrt7z20iFUGgM+8OcvIt6sY1MHv
         RH04JUYsxjZF1a508cVVV6CST3Qhq/FMeAftMCzMUTgVKvnYp4Cryui7MUgm43TqvzHt
         uYfv50fA28F0OKvG2C45L0CYXKWotVGo3tRW74ToeQYZYbdkEk28q93C5aBxQCNOtTlg
         TFyvI1Wag8py2VCRATc4sKlozLwCJ/ARBl+HMr5ARjIlebUohRKZbCr4GtfbOgHt9wgI
         X3yZ3JvWRLSaGT4V2mwDbAsCt9Pm0cKft+Ebax2UF6h4FlI3dnU2RbAYutZORO30ftMT
         qZ4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=tHp+k1OitbRlspde73UjQtr/BpbC8h6lYxWD13OBqjk=;
        b=AXGanh3vqdRYkwrKrAQrFFfE1LsqLlRKHki6ZxDTnwPO/z0MuY47EahkgS/i7tXTCC
         dGyb4biD0/mEV6hH/vSUvcryjGR5JXwd9aSirlsncJ1hQEFY4IaaXAz14Llg5PYlOZSO
         s6UnfVJ/q9MfQPkFedhbs4pMdZ5PblIbhv1bH4tLZjvx0IUVJ9H03gh4yIiazvVRdR0k
         Z2yTsvN5HFfEI7KxRSAsv3U59YEYCg48qMgTq8cXQVjANEl2MR1i7gmpv82IyOb7EvSt
         gOzq108EK78gEpFBHOv85Ksho2mlkbOImo7qgkyhRECIvV8h5Avdg8uY4712sifVNO8x
         UtdQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=tf1rnOdW;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id q145si322822wme.1.2021.03.24.05.54.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Mar 2021 05:54:46 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94 #2 (Red Hat Linux))
	id 1lP31B-00BM08-Uc; Wed, 24 Mar 2021 12:53:58 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 92E65300F7A;
	Wed, 24 Mar 2021 13:53:48 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 7823A20693983; Wed, 24 Mar 2021 13:53:48 +0100 (CET)
Date: Wed, 24 Mar 2021 13:53:48 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: alexander.shishkin@linux.intel.com, acme@kernel.org, mingo@redhat.com,
	jolsa@redhat.com, mark.rutland@arm.com, namhyung@kernel.org,
	tglx@linutronix.de, glider@google.com, viro@zeniv.linux.org.uk,
	arnd@arndb.de, christian@brauner.io, dvyukov@google.com,
	jannh@google.com, axboe@kernel.dk, mascasa@google.com,
	pcc@google.com, irogers@google.com, kasan-dev@googlegroups.com,
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	linux-kernel@vger.kernel.org, x86@kernel.org,
	linux-kselftest@vger.kernel.org
Subject: Re: [PATCH v3 07/11] perf: Add breakpoint information to siginfo on
 SIGTRAP
Message-ID: <YFs2XHqepwtlLinx@hirez.programming.kicks-ass.net>
References: <20210324112503.623833-1-elver@google.com>
 <20210324112503.623833-8-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210324112503.623833-8-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=tf1rnOdW;
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

On Wed, Mar 24, 2021 at 12:24:59PM +0100, Marco Elver wrote:
> Encode information from breakpoint attributes into siginfo_t, which
> helps disambiguate which breakpoint fired.
> 
> Note, providing the event fd may be unreliable, since the event may have
> been modified (via PERF_EVENT_IOC_MODIFY_ATTRIBUTES) between the event
> triggering and the signal being delivered to user space.
> 
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> v2:
> * Add comment about si_perf==0.
> ---
>  kernel/events/core.c | 16 ++++++++++++++++
>  1 file changed, 16 insertions(+)
> 
> diff --git a/kernel/events/core.c b/kernel/events/core.c
> index 1e4c949bf75f..0316d39e8c8f 100644
> --- a/kernel/events/core.c
> +++ b/kernel/events/core.c
> @@ -6399,6 +6399,22 @@ static void perf_sigtrap(struct perf_event *event)
>  	info.si_signo = SIGTRAP;
>  	info.si_code = TRAP_PERF;
>  	info.si_errno = event->attr.type;
> +
> +	switch (event->attr.type) {
> +	case PERF_TYPE_BREAKPOINT:
> +		info.si_addr = (void *)(unsigned long)event->attr.bp_addr;
> +		info.si_perf = (event->attr.bp_len << 16) | (u64)event->attr.bp_type;

Ahh, here's the si_perf user. I wasn't really clear to me what was
supposed to be in that field at patch #5 where it was introduced.

Would it perhaps make sense to put the user address of struct
perf_event_attr in there instead? (Obviously we'd have to carry it from
the syscall to here, but it might be more useful than a random encoding
of some bits therefrom).

Then we can also clearly document that's in that field, and it might be
more useful for possible other uses.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YFs2XHqepwtlLinx%40hirez.programming.kicks-ass.net.
