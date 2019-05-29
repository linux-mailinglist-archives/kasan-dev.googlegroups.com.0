Return-Path: <kasan-dev+bncBCMIZB7QWENRBGGLXHTQKGQESBLQ7SI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id CE0E42DB3A
	for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 12:57:29 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id z10sf1445917pgf.15
        for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 03:57:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559127448; cv=pass;
        d=google.com; s=arc-20160816;
        b=KbHWt+j+iJwbFAZhhy3qqTnp5JNvBGpYBMpgtLAVmw37zIqs3KbWGX4s4tkqP0Pmy1
         7VaJyiLPZNjBIlsBZL10sNHehKFbUUlMxrFx0GeruswPnSpW2eA4oU/Tkjr610hCSfAv
         CkAlnS/dF+W5sU0qycudk73+ANeUwndRlyoBKadC8JE4OKZ8Nz+ruGvUy0VMK5dzhLvn
         N8bviw30MDEr2Gm8OoQhVp/eZkwzwIsk0MC/wxge0Gu+EEW1y4n8JYuDDuc4RLmmTMMS
         UwUkvb+PT1OMXAaYu7BE10aP92taQY3suJatgNp+maV5EmOodeQ8Z3/0T/KvLZmUKlbs
         4u7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Q1EoInYWP+kBVAVKIJh9wZjwVeMF8vUEzuhNKLhK+X0=;
        b=u9v7yGOM65MaeTkcBYKJ9K689SgyFKKq16jIZZ3h9ey8GpTX3yiw6ctfOqziDl7nGZ
         e4g+WKX9BIA6pnC3vTOCRauZekHycaMWkil8WzOszug79r02OkofZzQEbV/ch7J1KjqN
         MCAEELFH07ROt7a+hK/BRNOew6a06AExkNjARRNzGSv/ON7joq+02ehr9PiIGEiJxPOD
         wmfzeoKmnzaakjiECcoO6WLnjkC7H13ohVj5ybY64MJp0bFgP4VSAb3FTzj8WPAfxbW7
         RN9PlydBdBjaebFfi64Kcstzw44NkqU9FuRfU2aQXik5U+pI2S2XE72nJnZlyEzCGHeM
         L3Ew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rtsUS66O;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::144 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q1EoInYWP+kBVAVKIJh9wZjwVeMF8vUEzuhNKLhK+X0=;
        b=JSlePUzSJ9kVKlqIRCddFYHyONLhBrx1/jiO/DpbJq5DK0eW/44oc+amgI0GoigcNG
         mAeAFKSvuo24VTKXl2Dud5qqZHcZBQlOkbczvkMy+ZF/yoV1fy4LgJP6hB6wxVk4LI3i
         KIPuIORUJcqiCcI2ZTElvhaTPAYj29lGD4BUO33QNa+i8x5CrbAhqOpXBk0LOBU47KZC
         AKLzXYw45yhHJ0068B2O/9T2UcxAvW3Qs0RNkH60hgRxjbz36Md+aa1/29lr7VAb2Bkh
         fuTAnEE6ZQqYJ9oFkSbQ3ak7CWm1o7K8P/1LHngPl8roeDNUUv5Dt6Z7KYcKPqWHWg4H
         ZeCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q1EoInYWP+kBVAVKIJh9wZjwVeMF8vUEzuhNKLhK+X0=;
        b=hNGOOEK/G4TQsoGwxh/1lsyU2iBI8ORf+b4WoXbcuBrcMZ8+mnwgq/YWADrJKTNHh1
         gxlkJFadRSKgIhl+BMvPAfSkx83TNQP/SZVHu96y9OGVBURlgLoZPBCWtv1duGFNZmgu
         SUtLIPZ/WlMZiW2bOu0LmqN2+u1eKl3fTk2WC/uXrDXtfqrw5VHUFVioQqoTpNT/9+tq
         6ht2sBNQePhlEC84X3EFZZD16XE49bC2QcOyIljN51E6dFZzz3qPKkajnW3EFtuls/5v
         Wpc1FQMHlA70RhzzNMfd2zeNFx8nXr1y1HYq2FDzEBCSyBZsWbCgqJpA9ErVISCfRbvw
         MCTg==
X-Gm-Message-State: APjAAAUTsBeOSDh/nMv6o8Zoh9mj1jIru+6WRxq6YYYlsM/Wv2zJ9Lxs
	7ChZFB8hB7q9DLLFpjGHi20=
X-Google-Smtp-Source: APXvYqykOVAPeuxkgAdkE3BSVKgpc6xDbRsMDMSvisxtNNW+dgczgz2Opifd9iQPvfiECj5MIbBj9g==
X-Received: by 2002:a17:902:7581:: with SMTP id j1mr56578251pll.23.1559127448591;
        Wed, 29 May 2019 03:57:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:24f:: with SMTP id 76ls444517pgc.10.gmail; Wed, 29 May
 2019 03:57:28 -0700 (PDT)
X-Received: by 2002:a62:304:: with SMTP id 4mr131347509pfd.186.1559127448366;
        Wed, 29 May 2019 03:57:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559127448; cv=none;
        d=google.com; s=arc-20160816;
        b=JvNwsKKXNytJp8RkHvbLNbjNPWvZxRw716xXoMrE5pRWw2yWavnyU8DHcoNz0JjjSZ
         DT82nOFNT15PZ0djove/7fEoRip+Kagai9nzimnbPXFor37+u7aIcylxjubW/iMer0a8
         yLAN8RUQyHGKjLEzSDUV/uOkvZszgZLZxQsMNxRNHwBoxPPamdF1Xn4amr/hqwhe12AB
         sGVvzGMa9GCBPgNVW7DK8loLZ1icFZGTIMVl8b9Vnj/C5MbBXBOnxDGTTE1hdUp4gr3m
         WQwgR3uj7oYA+ZfqmxBJS/vrI18yShNEBbgsy39oQDpZHqW+xbxUUinAV5FJNT+t8PDF
         dm0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=j0vRsAP/7oCPDaNFunzfNnWkHNHD3PczMiRqJpFCS8w=;
        b=DrdXWDlmJ9VC92mqZtRtx6T/QZtnx4BzsYckiXGPoqV/5YEH3ALZB5b2cHffSoPd6h
         3t2pvkLbO7QwvTPxndjAhe6d+vITRWrv18vV5wotIQSbR18ocXubM5KaCE+2XBGDQfR6
         RBoz5pSJ3Ls4rpoathsdpn9ldqd/Lg9Fq6ZBFruBFwj/rZX/uPc60Mmfr4A42qGaJU82
         huq/R8dP/oyA3I7WGmv6jW36EkttfIIw3jh5kGKLl1eZ6oZFjaRgtx63Ik1D/7FNXZXF
         8hrLIE8p+VXU0WPz8LagCiwVsQlmlP58Uxjku6U9gWZoFwyJa/hRKgy3teynFIQRMoWq
         FlsA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rtsUS66O;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::144 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-it1-x144.google.com (mail-it1-x144.google.com. [2607:f8b0:4864:20::144])
        by gmr-mx.google.com with ESMTPS id q6si114117pjb.1.2019.05.29.03.57.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 29 May 2019 03:57:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::144 as permitted sender) client-ip=2607:f8b0:4864:20::144;
Received: by mail-it1-x144.google.com with SMTP id h20so2955117itk.4
        for <kasan-dev@googlegroups.com>; Wed, 29 May 2019 03:57:28 -0700 (PDT)
X-Received: by 2002:a24:c204:: with SMTP id i4mr6670043itg.83.1559127447315;
 Wed, 29 May 2019 03:57:27 -0700 (PDT)
MIME-Version: 1.0
References: <20190528163258.260144-1-elver@google.com> <20190528163258.260144-3-elver@google.com>
 <20190528165036.GC28492@lakrids.cambridge.arm.com> <CACT4Y+bV0CczjRWgHQq3kvioLaaKgN+hnYEKCe5wkbdngrm+8g@mail.gmail.com>
 <CANpmjNNtjS3fUoQ_9FQqANYS2wuJZeFRNLZUq-ku=v62GEGTig@mail.gmail.com>
 <20190529100116.GM2623@hirez.programming.kicks-ass.net> <CANpmjNMvwAny54udYCHfBw1+aphrQmiiTJxqDq7q=h+6fvpO4w@mail.gmail.com>
 <20190529103010.GP2623@hirez.programming.kicks-ass.net>
In-Reply-To: <20190529103010.GP2623@hirez.programming.kicks-ass.net>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 29 May 2019 12:57:15 +0200
Message-ID: <CACT4Y+aVB3jK_M0-2D_QTq=nncVXTsNp77kjSwBwjqn-3hAJmA@mail.gmail.com>
Subject: Re: [PATCH 3/3] asm-generic, x86: Add bitops instrumentation for KASAN
To: Peter Zijlstra <peterz@infradead.org>
Cc: Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Jonathan Corbet <corbet@lwn.net>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	"H. Peter Anvin" <hpa@zytor.com>, "the arch/x86 maintainers" <x86@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, linux-arch <linux-arch@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=rtsUS66O;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::144
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Wed, May 29, 2019 at 12:30 PM Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Wed, May 29, 2019 at 12:16:31PM +0200, Marco Elver wrote:
> > On Wed, 29 May 2019 at 12:01, Peter Zijlstra <peterz@infradead.org> wrote:
> > >
> > > On Wed, May 29, 2019 at 11:20:17AM +0200, Marco Elver wrote:
> > > > For the default, we decided to err on the conservative side for now,
> > > > since it seems that e.g. x86 operates only on the byte the bit is on.
> > >
> > > This is not correct, see for instance set_bit():
> > >
> > > static __always_inline void
> > > set_bit(long nr, volatile unsigned long *addr)
> > > {
> > >         if (IS_IMMEDIATE(nr)) {
> > >                 asm volatile(LOCK_PREFIX "orb %1,%0"
> > >                         : CONST_MASK_ADDR(nr, addr)
> > >                         : "iq" ((u8)CONST_MASK(nr))
> > >                         : "memory");
> > >         } else {
> > >                 asm volatile(LOCK_PREFIX __ASM_SIZE(bts) " %1,%0"
> > >                         : : RLONG_ADDR(addr), "Ir" (nr) : "memory");
> > >         }
> > > }
> > >
> > > That results in:
> > >
> > >         LOCK BTSQ nr, (addr)
> > >
> > > when @nr is not an immediate.
> >
> > Thanks for the clarification. Given that arm64 already instruments
> > bitops access to whole words, and x86 may also do so for some bitops,
> > it seems fine to instrument word-sized accesses by default. Is that
> > reasonable?
>
> Eminently -- the API is defined such; for bonus points KASAN should also
> do alignment checks on atomic ops. Future hardware will #AC on unaligned
> [*] LOCK prefix instructions.
>
> (*) not entirely accurate, it will only trap when crossing a line.
>     https://lkml.kernel.org/r/1556134382-58814-1-git-send-email-fenghua.yu@intel.com

Interesting. Does an address passed to bitops also should be aligned,
or alignment is supposed to be handled by bitops themselves?

This probably should be done as a separate config as not related to
KASAN per se. But obviously via the same
{atomicops,bitops}-instrumented.h hooks which will make it
significantly easier.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaVB3jK_M0-2D_QTq%3DnncVXTsNp77kjSwBwjqn-3hAJmA%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
