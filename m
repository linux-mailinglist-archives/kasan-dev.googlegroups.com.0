Return-Path: <kasan-dev+bncBCV5TUXXRUIBBV6V3L3AKGQEGZATRSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id D13611EC2E7
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jun 2020 21:39:04 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id o4sf5684282ilc.15
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jun 2020 12:39:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591126743; cv=pass;
        d=google.com; s=arc-20160816;
        b=PLHxsFHbKDMYQxYOWMaYrk/z+r1gqTVSE6PsvUWwiFVKwRnkqML1iSWMr+hgadmijt
         GAEQhaaNnNz4WDSxtda44H9U1TUrvw3KAzwmOLXYMSlwx0kker9hcoDVI5vt5ypxcwKc
         hx4nRekCY4tqrUZxbB/shvy0zqUWDih3qhy+tXIWdSemxJa6/IrPgYyd0Tg+4OcwBz+q
         oGtMrVtC1xwlXqvFewbLjJrr6vH5rs2PpHp9U/mmEKKco/BB4RYZ0oDvplG43hRN1UmH
         kYTcSKDIQ2fQu7EOTmFpSzy+OZEAc7jfYWJlHRL/6wNEzyhIkIXpRvBNrouuJvAoZmKM
         sczQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=n8NxJoSh78t8yrpbGRqwt3Nw/1/2BxWwbbhQ2CNiGlk=;
        b=uSscbMABptsTSauU3P3neKm2r7ll7lSfhcxR6vPK5D9CcSZIiX1SudTDEzYasxamte
         J9hk7dz69Wk8pY1YFMUErbIipw+1aJOIzxJfAi2GveihdBQiKkw6WGPFBfmHHZG1narC
         B9tDDoAJHnsGasJcQnfgfKDjLrGqaE/ip7kFMXAuYs2H8nlNAjuKgArHr/oUXUWmIvLF
         bLVzt3Ni58GHlKfPVkd9eysyTKNcNMk6lQOR7Av5Zug/uB57+gCxV+8wm3+zDiY7FSL5
         H1/v2L++B4ca01zUNxrK1SPyYtWZ9n5tC4dz2UNrVjAEC2OVTLulNRLOttSJlTCdl5KO
         GfZw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=Y97cQnPw;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=n8NxJoSh78t8yrpbGRqwt3Nw/1/2BxWwbbhQ2CNiGlk=;
        b=abgSsWhhF1+dpwG4u5QqzZDLPqDB6Vrzhy26XCWWnUXJroa5ICSTHRlE6NIDcXIWvP
         /oqZyu6hD5vIyvdVU9hPs5aryzbFq9KS8qOZjtkwoVsNBWLyRlhwAUFDTz6xDxyKY614
         jcTz0nRKASG5DOs0CM9ACxJBrsKiFcX+7s4X7ra7IeW8xG1GFXzuKHIpriRVQjUQbv7N
         RBL74Rt+X6K76U93JvEESoo1WQwAAzJatj8o6PePZUzbZC+whMOE1k+LKzNrE9B0jDkf
         V7U6fQaudGbgfR77OoHdrotBJ0IAl/QEmfs2COXBGD8sPPBr4/+SfAdH2bsJkMq64qWQ
         GfXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=n8NxJoSh78t8yrpbGRqwt3Nw/1/2BxWwbbhQ2CNiGlk=;
        b=TdT3fM3Us5wo6KgbMspvwc4DCFF4/MVm5s8BlelyfOwjSOT+YJcnKEpQaCdRWlFZG/
         Qzkw95vCYxriibrtDjzGoCpdiBUWclhU0oP8yoYg9yiz2AkpGY8pje9zZpGl8ypBEga0
         Lx2yoadrF5TRMsMb4MzF96Ig3dBl2osyQ2ubMQNtQnAt2OKPmyRyTBTMUqJ9ByHOuUAL
         Vl1axhY0x4eeyHy301GvGPC9TXQKjd85p/ERFCINS4XVV7+Kqprvp8XUBRnkeBelWHHz
         yahhHB65yqLtzk5y9zZzkNyg+qf4yOTrv2zWqxbQMaMa6+2jW7nZEqSODRnYzP05DyuJ
         D8Ww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532/vvDbX19pG+k7EsWTnl78qTy6TczWEmO3vfpsC5Du2Ej5tC/j
	dUhhZIoXPvSlfR5r25NIFQw=
X-Google-Smtp-Source: ABdhPJwBRvIhmlfjJIVF85n6egAGetNvEnPdx4YHm/xB6/teIaA2NbyiocNkily5TUXhHI2VdSweFg==
X-Received: by 2002:a92:6c0f:: with SMTP id h15mr869831ilc.210.1591126743792;
        Tue, 02 Jun 2020 12:39:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:3b07:: with SMTP id c7ls794894jaa.9.gmail; Tue, 02 Jun
 2020 12:39:03 -0700 (PDT)
X-Received: by 2002:a05:6638:cb2:: with SMTP id x18mr27602889jad.6.1591126743460;
        Tue, 02 Jun 2020 12:39:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591126743; cv=none;
        d=google.com; s=arc-20160816;
        b=yxtdocqfcVlodm6DZdiRJxewxKoI5Yw2oXHvTDJ9l46DWlfOh8f1MU0gYPHz7m+Cws
         7OCdlC+A1DhiNjGRSuH2QEoC+H8rAX+u7FmRogBKm1it6M5cdLhSPtbkMKoYezPW7tq/
         1K63RzrfJiGoqaX86Nvy51fgxnDxaTKeG4Sq/XswN9uMi4JNqGwn+3sDFnV2fD9Tdc9U
         tpHyu7YlNYGHpeok6KkrptqbcOqtCwW22plzzHRCbcLBKhgy/xx/XZVoZG7w2h+7eC/8
         F+x1Mi9rIVaJAhtJR1a73I8qivdYK3VgqOVPd6aPi/1sf7AfLENGoXPXbUfJq/EhC8IC
         H4rA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=07uMamPsL7K8+1SyUHisvSOhlqTxoE0W90sdhD4QMmw=;
        b=dOpiSHalD0ff2s75ZYRhrCRmQ+15zTEByEplQSis0jrodjE+qbBFrWcF337+Qd+nlY
         JNTJHTfPxOa0z/sTteOHop3/QGPzABZ7O9Q8Z4sc0BddzG4SkOHhuIXfBigk3EYuEe6L
         FrI/LtfNUO3m5oh14uUHGfhblxpPA2rOFDpP/QpUPykhRii6iPCUaH3vP0+M2ZnYyFHL
         e0pVkEBNOTaBnLeQQbCXlPhP4OM0PXLs8ZKkBMqGMGK8NTrJ8LpCtaP88PhSIqlmBNSX
         3EhN9sP/zU/QEOz7MuIGIYqJf/3hM74nDZrhaAffLeVSdGBJgOC73YuGO/lCScJIP0eE
         JcWQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=Y97cQnPw;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id v16si315945ilj.1.2020.06.02.12.39.03
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Jun 2020 12:39:03 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jgCkQ-0003KJ-JB; Tue, 02 Jun 2020 19:38:54 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 1B30A30081A;
	Tue,  2 Jun 2020 21:38:53 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 0EB462020B7BF; Tue,  2 Jun 2020 21:38:53 +0200 (CEST)
Date: Tue, 2 Jun 2020 21:38:53 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Nick Desaulniers <ndesaulniers@google.com>,
	Will Deacon <will@kernel.org>, Borislav Petkov <bp@alien8.de>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@kernel.org>,
	clang-built-linux <clang-built-linux@googlegroups.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH -tip 1/2] Kconfig: Bump required compiler version of
 KASAN and UBSAN
Message-ID: <20200602193853.GF2604@hirez.programming.kicks-ass.net>
References: <20200602184409.22142-1-elver@google.com>
 <CAKwvOd=5_pgx2+yQt=V_6h7YKiCnVp_L4nsRhz=EzawU1Kf1zg@mail.gmail.com>
 <20200602191936.GE2604@hirez.programming.kicks-ass.net>
 <CANpmjNP3kAZt3kXuABVqJLAJAW0u9-=kzr-QKDLmO6V_S7qXvQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNP3kAZt3kXuABVqJLAJAW0u9-=kzr-QKDLmO6V_S7qXvQ@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=Y97cQnPw;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Tue, Jun 02, 2020 at 09:25:47PM +0200, Marco Elver wrote:
> On Tue, 2 Jun 2020 at 21:19, Peter Zijlstra <peterz@infradead.org> wrote:

> > Currently x86 only, but I know other arch maintainers are planning to
> > have a hard look at their code based on our findings.
> 
> I've already spotted a bunch of 'noinstr' outside arch/x86 e.g. in
> kernel/{locking,rcu}, and a bunch of these functions use atomic_*, all
> of which are __always_inline. The noinstr uses outside arch/x86 would
> break builds on all architecture with GCC <= 7 when using sanitizers.
> At least that's what led me to conclude we need this for all
> architectures.

True; but !x86 could, probably, get away with not fully respecting
noinstr at this time. But that'd make a mess of things again, so my
preference is as you did, unilaterally raise the min version for *SAN.

That said; noinstr's __no_sanitize combined with atomic_t might be
'interesting', because the regular atomic things have explicit
annotations in them. That should give validation warnings for the right
.config, I'll have to go try -- so far I've made sure to never enable
the *SAN stuff.


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200602193853.GF2604%40hirez.programming.kicks-ass.net.
