Return-Path: <kasan-dev+bncBCV5TUXXRUIBBSESQXZQKGQEE5QVTUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id E338517AE73
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Mar 2020 19:47:37 +0100 (CET)
Received: by mail-qt1-x838.google.com with SMTP id r7sf4511478qtu.0
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2020 10:47:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583434056; cv=pass;
        d=google.com; s=arc-20160816;
        b=XdxYx3i9TLD0OFoU3Kf5d10jVzqmhr0z22vHemBdJbCAplUJMvqDjqgE7E986wBHyf
         rJFn71CpZXWTwFIr8t416omijFwKSmPGMi1nCNegzLZ0xOeKFasuOV7Rz5kvbaE6g52T
         kJDENCuBE4EVQqq+88HVDk8VB7cdamsOHAN9Nr6c5Rjh66chnXl8hWrzm5gceuRMbOYm
         yhEAvmkAtY+55T/XJKKzIjyh/ub7kas2Bq2LZtxktw0LbTglypOGtb/U6wCBuFT/y8dL
         Xv1EwrlyY1QbLxZmeufA3RTd7A19ayqthsb6+1rIy+GT8XgaMxm4IeU7U3AUg1HVBbYD
         E6DA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=3kqKa8oBf00Dj+lGF3YBMcptKXQjdD8msMbSE5dg/EM=;
        b=A7pLYUPgMrI0ew4HhPJGFpm66g+PPPpFZXmjvvQlYiIl4Uua26S6/b0zBH0HGdX7LH
         6ElJaHo+kM9urJDEKNixfTNxHIAXfyOta582aKD+KZlOKHOajk2RWIjjthf/y1u01pVf
         NQkwNEgSR8Lx+heREDS0cT7UR/39LXaz1pRVuErd97iQWmIXTH44FhW7DCp8kVd6dVGR
         GN5gQTCG87WUKSqkqhlLjAJQ2alqrG5cPi5jNDoUrCdxVysHd1I92kWIvBSELidUirg3
         rtjMhFYKwMLCiVGGH/u6qSIdN8QtQVMQGwWdy3fs27TvM2TUImHAUE2nLXZ2/Hjp/xtl
         Vsqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=TdreGGGQ;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3kqKa8oBf00Dj+lGF3YBMcptKXQjdD8msMbSE5dg/EM=;
        b=Crea9A8NAepNDs1AyI9ZQCVFAUdSgJvMpEe3XD7XCIHbSP6m/P4dpbant5DXri7S7m
         bQWy9B/fqxg0w5iXR1OZSALy5hbNhbnPRA9sRWu4qxMlCl1qqR3mQxcVUh8qk9c8C+Gu
         xhRQgPhVMzdmsxks9BgbW7urIZtTSP31+bFbORza2giM30UwigFfhWW+7vypcPqK6PyA
         eoMsGO4tP1Zn/t0eQLeDb4nsJb4eJ1BFJK71+SpaqfxcffkMS0m0RT7RuiyxZ1RXTP68
         vToiosJlw7GFQ6/8gv9wUjxqPxjEhq9RVke9LBEGD3mLfIFd+YfhFvAQJqyLHPgTijdj
         l1sw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3kqKa8oBf00Dj+lGF3YBMcptKXQjdD8msMbSE5dg/EM=;
        b=IGm5qDaKcstg1vy6YIQIZ2aQPY9bto6x3fFAZ430c4Deni/Ry6T3bjhw5mEGLulgKl
         CTEhpnyTquN108ZDMYlA6e34UdQCz+HfBEy3tGPRcfixYHnJCq67YjTaqKvoQC3pLdeH
         e4tevqJXRp9BKhgrV+6GcxCeWXgFcarbHfsMfhtMTWqbWNBc07ESvwnarJUTJS3R+tP9
         /SJk1UMxEdFYI66yURoS/Q5Z0Qhu2z6qW8TLDiZ2gGsYBtd7z3tlPRe0Vcg0rGDNJP3J
         GA7LOomJgqN2Ltm9iR0wr1rqn7FDafN/p1gKCBP8xnE0s5aUzlTSbGcbi0Kd7gY0l+a5
         wnIQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ2xMFtLTJ70WcYyFgSF6/zN+u4xKG71oYZM77NjhfkrRO1L6hgb
	EH3i+9896YlMwxFKsKMFt0Y=
X-Google-Smtp-Source: ADFU+vvir4Rh4wTdyi21xKdXtlDBh/VNnk+WIEp5+Kr2tCMzz4tlwufewpd5NKK6UfWYMX1plH7z8g==
X-Received: by 2002:ad4:4684:: with SMTP id bq4mr110736qvb.35.1583434056662;
        Thu, 05 Mar 2020 10:47:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:eb41:: with SMTP id b62ls750760qkg.6.gmail; Thu, 05 Mar
 2020 10:47:36 -0800 (PST)
X-Received: by 2002:a05:620a:21cb:: with SMTP id h11mr9566970qka.310.1583434056243;
        Thu, 05 Mar 2020 10:47:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583434056; cv=none;
        d=google.com; s=arc-20160816;
        b=JfOBcAEmoSMJmCOd0RN9OwuNCpa2RjIykXNcIARuknvc7Vm6CGK710wkfjMxGHeOW2
         CsvZFxTljnEPgaF7pJ+BdYtJtH/Dgb/EM0V308ggkumtPLHUVOvg9FweNoM58wSkTQXr
         14CFhL+KX6Qi7uS77t6AcIg6Tj7z8i4QPkYn6w2MlcreUK3gcAZQMv8OZub0mQV8LV/e
         v5p3I2AnMn0JcdDACjWE0hQVwYnHW9HBLFG0vAa/fK+Bfg7tBx8vJbZeWve5Bf808/sn
         Hflqc/2+ZMuHRyCyV4LULADIQEtlIKxL/lphRMlJ81QWhrHMVME/i0grzLV5/G85NnhS
         c/1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=jMj2lMaLBUB/iZwc1nFwpSrI9qT37+HdmAbX8z4HkCg=;
        b=h4h6fMcPO3wQv0wO3ZoENbz73dvUORxiQaUQUZ5EHsLqP0orGIgeSrAogIGu/jX8k0
         3yIyCgzWFRImnjAr3eLMlnn40ck4uC8yTErwS0AYknGMkjM155OHDne6YwL2CHnFXfaX
         UsJOtS3fdA55TjmxvBYwlKtysi9b4Q7+AOPU3JqIgDnAM/sjdAfNG/zZ8FqXc82p44nW
         lysg1mNJbgK0CSTrbLdctTtAA9/J3olidwk0HG5oRhrNUlwWKB0iK/Y5WzLNhDcSprVf
         MKfcFm/Df8ByC9igNr427q5t0xA1Trc6I05mfH3wg2GkISbu0eUY3Ksvre7BgcQiX4xa
         mnqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=TdreGGGQ;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id c6si436940qko.3.2020.03.05.10.47.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 05 Mar 2020 10:47:36 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=worktop.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1j9vWw-00044T-JZ; Thu, 05 Mar 2020 18:47:34 +0000
Received: by worktop.programming.kicks-ass.net (Postfix, from userid 1000)
	id 21322980EDA; Thu,  5 Mar 2020 19:47:27 +0100 (CET)
Date: Thu, 5 Mar 2020 19:47:27 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: kbuild test robot <lkp@intel.com>, kbuild-all@lists.01.org,
	Thomas Gleixner <tglx@linutronix.de>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [peterz-queue:core/rcu 31/33]
 arch/x86/kernel/alternative.c:961:26: error: inlining failed in call to
 always_inline 'try_get_desc': function attribute mismatch
Message-ID: <20200305184727.GA3348@worktop.programming.kicks-ass.net>
References: <202002292221.D4YLxcV6%lkp@intel.com>
 <20200305134341.GY2596@hirez.programming.kicks-ass.net>
 <CACT4Y+apHDVM7u8f660vc3orkHtCXY+ZGgn_Ueu_eXDxDw3Dgw@mail.gmail.com>
 <CACT4Y+ZuGLqNaB+C+VJREtOrnTZVyHLckdAHRMSHF3JMDTg_TA@mail.gmail.com>
 <CACT4Y+ayJrm6ZrkQwybGZniP-xwtxjkmMpYVdCoU4mKzDUWydQ@mail.gmail.com>
 <20200305155539.GA12561@hirez.programming.kicks-ass.net>
 <CACT4Y+ZBE=FDMjXxOkmtn0rd8oRWvNaBGnRgXKKSjuohuqd3=A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+ZBE=FDMjXxOkmtn0rd8oRWvNaBGnRgXKKSjuohuqd3=A@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=TdreGGGQ;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Thu, Mar 05, 2020 at 05:29:27PM +0100, Dmitry Vyukov wrote:
> On Thu, Mar 5, 2020 at 4:55 PM Peter Zijlstra <peterz@infradead.org> wrote:
> >
> > On Thu, Mar 05, 2020 at 04:23:11PM +0100, Dmitry Vyukov wrote:
> > > Compilers just don't allow this: asking to inline sanitized function
> > > into a non-sanitized function. But I don't know the ptrace/alternative
> > > code good enough to suggest the right alternative (don't call
> > > user_mode, copy user_mode, or something else).
> >
> > Does it work if we inline into a .c file and build it with:
> >
> >   KASAN_SANITIZE := n
> >   UBSAN_SANITIZE := n
> >   KCOV_INSTRUMENT := n
> >
> > Which would be effectively the very same, just more cumbersome.
> 
> I think it should work, because then user_mode will also not be instrumented.

Right, but then I have to ask how this is different vs inlining things
into a __no_sanitize function.

Anyway, I'll go move code around so we can do this..

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200305184727.GA3348%40worktop.programming.kicks-ass.net.
