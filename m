Return-Path: <kasan-dev+bncBCV5TUXXRUIBBOGQRX3QKGQEJ3X3S3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 3690F1F775A
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Jun 2020 13:34:18 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id o140sf10149184yba.16
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Jun 2020 04:34:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591961657; cv=pass;
        d=google.com; s=arc-20160816;
        b=NtrmSLKvC/riSRjOv4luWct78KI8uhsqx4rhfvtYpBrsqNcG5qmUB584Mq+nRWYlbr
         McKWJjeAafhdtK+4Y5OxNM5m/eTyGd3SwcKotHv58NytQXLtCNFue6sEtdx1G1WuGQIr
         u9/ALAfxJJM7xPHEPZMhIyhaLLnc3qhUKwEPE2mmhM+AEdt2V9h8fHELOsyYv/pHh742
         5EO4JJIo5Dki7ovT/Am4u+SE4ofLL6SV639H4D3U5OWbh1Bh104124W9QGb/rDQ9CcyW
         ymhNkGzvhIXazjnBVqUTcsbRyc+HbfVFzxcV+b5XtTx0wdYomBhXweAh3ETpmwFEfTsF
         8vfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=IvKhIgTZkuEAcI+1Smz7q4A2g0/Jtxh9lz5c/N09NoA=;
        b=FfCJbkkAj6y9unGGIjvBda9+N8p7YJEP38HA5Pvy4ptXWhyNzL/OHgjbMXxCeSAyyN
         G43B7C5L+ewQA4VoMpc0L3YSthBPTEwI3k3GwETDvBBoAAEppiM+TjPPmWPJY7a7aAvn
         jYBCVUpUt9G70qHWp+mGzHbL9roeYEDTgxq+a0KA7HDVFXqDw/AJx/BSx5ltKGFFUx0a
         f0lD9CV4JERcxqgB9DkxgOwzZUymD7rWnL41zNSI129hp9WFvLsHUeCFMo4167iJC6Df
         s7C0dqU+iiqMwDpzHkchLjcl66Ma1BqW+SiuuQKIb9mqtejSdy9FbEaDMdGcNRYG00TG
         t/oQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=oCw3KNDX;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=IvKhIgTZkuEAcI+1Smz7q4A2g0/Jtxh9lz5c/N09NoA=;
        b=LoreDXroNWFGTaQruJiLqQ6oDlPp+uIv+PfpiF07b5sFAecQMpZ+cRBb504tux3Ysn
         GJmSCmR2aqS+v0u65o/z5pKCq/zQOQcq0DJnXU78X5lqZfMtaXCYPu272JSesos384pW
         xpiYkqftSNau6cUH96ReYGotyRl6oOfm3Yv5UcKyGBZY+em85IylPEgj+COKUMPM0Ue6
         5Mcnccd42BqoOB3BRSkbj6Y2HINX/V6F+T94jxjtuMOKOqfYuDJ/bOnqy+cLdnUDWCxW
         DNBIjXqPm/gjs/HUchTqJExU5MWsFHzSOqRdLW9Zxsouyo4g9cdGy2s2HUwPDp3KjgpI
         HyIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=IvKhIgTZkuEAcI+1Smz7q4A2g0/Jtxh9lz5c/N09NoA=;
        b=paO92o58fSIhrkHup+8OzvPGsJWtffCgRhQXNfOM8EaS77GcMEzLmkYGKt8b8lmm4W
         r4FvGoAGPASz9cj51zJdrv52fnRJh7eEqDX65SyfIpI14QkP2HiwzZIHQyzB3TXqURGI
         6Cq1x5SK+ze3xNnDMdwnXe598jUQT6cKuv5NSHrHomgYLlCERQWf4o3MVPlON6XkqkyN
         QdaOsCQ3QJttX62/nQ9yUMcCAkcBikJroPNfl7qxV18MJN6xPqbFsbfV8PKKn83jKDzV
         3Y6RxDZuQJaHQKSEwbfZSpUcFlVDs9xug2B2WTp2+7lAcYsYRaDKZ16qCz+2YaR03Krl
         Q1vA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531wohsv+ILTxw5bQtwIpyxgAh+UAYDF2y1YMLPhyfz8wDT2GAwq
	2KtCoNaRlA5pvVDjxD/YSlY=
X-Google-Smtp-Source: ABdhPJyBNklsIBkfkqufXrDa9/lvxtupO1rxDivb44kBRQtn6CRBIJvlSTbqw4N3lV+OHQ+7rGNOeA==
X-Received: by 2002:a25:2d44:: with SMTP id s4mr21551129ybe.256.1591961657070;
        Fri, 12 Jun 2020 04:34:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:c785:: with SMTP id w127ls2197327ybe.7.gmail; Fri, 12
 Jun 2020 04:34:16 -0700 (PDT)
X-Received: by 2002:a25:941:: with SMTP id u1mr23051509ybm.274.1591961656766;
        Fri, 12 Jun 2020 04:34:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591961656; cv=none;
        d=google.com; s=arc-20160816;
        b=VNxizLygP+7KOHI+GjXatUVpSrl8FjE00YdXyKjDYGspnpVjD21W5kx/C0aFbfdpVP
         e6b+reuGWAsCryyuuxIplKE3drKSoPIqZ95w9lMkugWdi2f2P1EqbBINlrZky5JtD2jN
         2ftf6hdLQMLcJT/Y434rYVOoJxcQ1nHcZupJz53L5sKKQD6mWcS4WtpYlsGxhsSCAK5X
         FvGXtLmD2/wP6vjwyay2KE4AeB+kZBkjg/+aSiXtEzTtVZg2NjgMaZXQ1/avkq/xLNt6
         DxLfdLdcQw0pvunW+9NbY69Cgyd8PoKHjySnv6+FbDZnQdR+Hnk3nhLtPK3/mu8jb8gQ
         q70A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=KeIr7tqTdmTxWp0qLbXPXOvRu/jpVQnRhJVoQ2kBrSM=;
        b=CI875OQCmJhn1UzyuHJS9K82buLZST2ZBlIdCMg6LOddO97n21bwl+RqnwTGZSTkzf
         uS48U9lbzOjG6qeNv/owiVJFXLx+o42ufTVz3VGjPZyKDhkgDhlaf6WJnrbiCw3v2KmK
         apKk0tKy/iLyDhU5BDOue725/uzGIdTDLz8XVQD//4Fuilo8eBLPvqRNdv50DjAJj5cv
         Z4z2ODmVMDeDgWtkJG6qgPvA3hbM3nP/i4CCu18IAXaAnlYjRQiEnBrKQvuCf018TlME
         8CW9j03b5DzXblZxp9Pf5w1F5D7qlWLIFAo1aH+0dqpemX34sZVJ1VlY9HOSPFIwEtRG
         FWyg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=oCw3KNDX;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id n63si424668ybb.1.2020.06.12.04.34.12
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Jun 2020 04:34:12 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jjhwi-0002Ob-Nd; Fri, 12 Jun 2020 11:34:05 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id C57B83003E7;
	Fri, 12 Jun 2020 13:34:01 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id AB98B29DB6157; Fri, 12 Jun 2020 13:34:01 +0200 (CEST)
Date: Fri, 12 Jun 2020 13:34:01 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Mark Rutland <mark.rutland@arm.com>, Borislav Petkov <bp@alien8.de>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@kernel.org>,
	clang-built-linux <clang-built-linux@googlegroups.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	the arch/x86 maintainers <x86@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Josh Poimboeuf <jpoimboe@redhat.com>
Subject: Re: [PATCH -tip v3 1/2] kcov: Make runtime functions
 noinstr-compatible
Message-ID: <20200612113401.GC2554@hirez.programming.kicks-ass.net>
References: <20200605082839.226418-1-elver@google.com>
 <CACT4Y+ZqdZD0YsPHf8UFJT94yq5KGgbDOXSiJYS0+pjgYDsx+A@mail.gmail.com>
 <20200605120352.GJ3976@hirez.programming.kicks-ass.net>
 <CAAeHK+zErjaB64bTRqjH3qHyo9QstDSHWiMxqvmNYwfPDWSuXQ@mail.gmail.com>
 <CACT4Y+Zwm47qs8yco0nNoD_hFzHccoGyPznLHkBjAeg9REZ3gA@mail.gmail.com>
 <CANpmjNPNa2f=kAF6c199oYVJ0iSyirQRGxeOBLxa9PmakSXRbA@mail.gmail.com>
 <CACT4Y+Z+FFHFGSgEJGkd+zCBgUOck_odOf9_=5YQLNJQVMGNdw@mail.gmail.com>
 <20200608110108.GB2497@hirez.programming.kicks-ass.net>
 <20200611215538.GE4496@worktop.programming.kicks-ass.net>
 <20200611215812.GF4496@worktop.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200611215812.GF4496@worktop.programming.kicks-ass.net>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=oCw3KNDX;
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

On Thu, Jun 11, 2020 at 11:58:12PM +0200, Peter Zijlstra wrote:
> On Thu, Jun 11, 2020 at 11:55:38PM +0200, Peter Zijlstra wrote:
> > I'll have to dig around a little more to see if I can't get rid of the
> > relocation entirely. Also, I need to steal better arch_nop_insn() from
> > the kernel :-)

Oh, I just realized that recordmcount does exactly this same thing, so I
checked what that does to the relocation, and it turns out, it does the
same thing I did. They change the relocation type to R_*_NONE too.

So I suppose that's all right then.

I suppose I ought to go look at the recordmcount to objtool patches to
see if there's anything to share there.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200612113401.GC2554%40hirez.programming.kicks-ass.net.
