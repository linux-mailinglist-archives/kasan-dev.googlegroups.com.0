Return-Path: <kasan-dev+bncBDV37XP3XYDRBIF6376QKGQEBDFRMZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id A29B22BADB5
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 16:22:09 +0100 (CET)
Received: by mail-pg1-x53d.google.com with SMTP id e3sf7044784pgu.1
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 07:22:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605885728; cv=pass;
        d=google.com; s=arc-20160816;
        b=zd8MHGnLhrFhruNmoLL/42HO5BiAIO6HSO/nnk/F4QY88S0Z8v3sHVRQ+ObJMw7uNG
         s7y56/xmxBWYry7rZU0XPH+zqvyu+KUtclVpFICsaois5BasELNMroM03Xa6T0CUTRQO
         ERXcUxNToCPvULHw5Kbba/hor1hrKEHy1AeHGfwWEyguF7AzcMJnFjWzrTv4jhDvuXXI
         aKf/lys5fss18BKPsTpiPWxSqaelujgi/9WiEbrsQz/dQ1ioRlCMPwwVJ8qK87E5NxUg
         shR6+sGv4Y8AHUXOfpVxXU6Bu2hpu894ZxLeglEXCVPV3rLCdTN2Eaeuk7T6R40T7fPB
         Kovg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=5G5randgxsWiSiR9sKDc3cMqthNUWdkmrwEH6kGe0/k=;
        b=vnVNwsJm7K14ikuB5LRGjPMsrCSpLKWlD5K0kdfgrW3RM+cmH5vjOrqtJqdhuNWZEv
         C0prxPlfGyw7uKnQ22OqZpze8w8LntvTRYbyD5RBRYboSNBxpweaxIfCpnuLmIi0IEVO
         Xt2M0XpIeAeWFPM1p8ob8e99oJ5kP/7ConJ3+EJP5ye7zUjTxSqR77lVXyYELfX5/Ax9
         mXiLjCRYMqBf/285137rFYwYa81Rfgqac9SDeHRCyTrzPgJdMqX9YXrPGFsss/4WCAVL
         DR2Q7Vpl4X4N58mfD5w0g2qetnYSDheFd189G6YvwcwXFNmGP/vOJwzsnUNB2BrdGECw
         wjrA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=5G5randgxsWiSiR9sKDc3cMqthNUWdkmrwEH6kGe0/k=;
        b=DKCrbpHk9sZLjI+IvVdACNtiOzBw3ujD7WHfNowTRaR3I0G8So0Bk+phSGoMjHugNA
         ispaqb/CaH+q1N/wT3KgIXPpuLyrHUkQYqE2WzExXUvHI/CoqHgXXKid6ZVKRx8x8aTY
         eAxs/QwHG01kkx1/H4xKwq44dEws074gcYJGxEJ9MLlRykjQi+hGiQknuBw2J4gMOcGX
         U5LTsL3U2jd4L3yQR66WagFFw7Ph6mWhJyrZioTYY9CI0y9k05iYuzWLtL461ww9zXAI
         DJDgDoV5vMaa08SlpIL8VS8eobeLTilXxei9gBuUDBKgft5viXrcvErkfwFq3zF4Rvwz
         +qag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=5G5randgxsWiSiR9sKDc3cMqthNUWdkmrwEH6kGe0/k=;
        b=InhAxl3IlhGuMr3IVeAITyI2S5/hGxgDcZQlqdNbrrpQW8wk7goGnka3AndjhBaQX+
         XvscwTWaOIivH8a7NmYJxu7KkROoxqJhE5bzjYCh+v2EBkZMcHQqZgCfWBpuMh9O1ire
         Dm565NW7zE5rCB4PA8eg0EeKAWbNqeegBZOmCDf7fyiFNxulP2+5DCUCeTBQFAkLGiqm
         gs3LHjo1psYuC3iC7ECK7CediBwLHNkBefV+Ks1uffhsLtwq3thcRZhfMRpKYUMyFu/s
         cOHUk0T9pnpiyZk57YX9jnMDCAdLk86N8q9Vk4rN7Hhz0Ipxf05+SoBCYQYAo5t/Jrdy
         NOaw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530ywcIyIXRrayJBuJORjuiRSfvmhsmjNk89tyG3TRV2SD4DltmK
	xAeQWIazkV85YMyXgg7dmTk=
X-Google-Smtp-Source: ABdhPJy4V1zLeq0TgLRI9WrHAxyfw8jIOyDutUayPNQyNftScIl9C0dz4hB34Sb3nQSSez/JV3Fhcw==
X-Received: by 2002:a62:1d4b:0:b029:18a:df98:515f with SMTP id d72-20020a621d4b0000b029018adf98515fmr15090224pfd.30.1605885728204;
        Fri, 20 Nov 2020 07:22:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7745:: with SMTP id s66ls2576562pfc.0.gmail; Fri, 20 Nov
 2020 07:22:07 -0800 (PST)
X-Received: by 2002:a62:e40b:0:b029:18b:2d21:45cd with SMTP id r11-20020a62e40b0000b029018b2d2145cdmr14250407pfh.36.1605885727632;
        Fri, 20 Nov 2020 07:22:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605885727; cv=none;
        d=google.com; s=arc-20160816;
        b=tBkqXLzK/kYUJkMjMCOtw6eGrSZkv5TXKCwdC5InlTg36AvBsh9S9r+QZcQAm8qdK6
         h2AV9cCdfTkJdF1eOBMqMYcu3nLEISlbaojqr9QoriIA/zfWXxNMjEoeHhjtuy28Y/fN
         KW3x/gyhmKR6L0MlfeFCT5KlijiBw7H8kZS0CbNWp7CMEq66UFX4GnQddv34DpkeoHwI
         5kbqtngNcg2TZMjQHr/2DfE/cZXiYUASN/BtTlo2uopgn1X6neP2wTyNjBxb6nwGEmpS
         XSAiUectIf5qXbwCnWJQw5KKWHnJRja2ac2oA0RjF8h1bNXcLwOPuIABJJ/xvEcwEzVq
         zkbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=aCwdjyN5gAVYtfqY72qL/6aQo8bMVDUYRuEp9vgIvkE=;
        b=SEOhgfjtGHgoEgoUhy4rMA6xzSwLt+zW80Z5fyBGABQtVlNUWzp9kuBI7X5Krk4hoj
         8rQfLQPOsBkJPPl9ErESXOUL47IR1GoVLDQ4p8ep+mQDdihWbwHtuevkHrcFAjTfrzi/
         nlZyqDbbTJZo/tkhiY+v993fvEa7yH5HcjNqMKtesQH5E8ikr7jkBSh8CejgtumsnBoZ
         khvnoY6gEJ0W1iwhSQR+4kRQhSkfCVPvooDlcLJM6wGSuoPVM5fPwt+sLNbEEA+P3Qrb
         wbuEGjjVAYZzNMRCeg8vVvweJ6pY/4ij4DpVXR2nr7o7hXBl3pRGjGIFFiYGcPZ58UwT
         T+Tg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id d2si316552pfr.4.2020.11.20.07.22.07
        for <kasan-dev@googlegroups.com>;
        Fri, 20 Nov 2020 07:22:07 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id C1C0311D4;
	Fri, 20 Nov 2020 07:22:06 -0800 (PST)
Received: from C02TD0UTHF1T.local (unknown [10.57.27.176])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 2DEEF3F70D;
	Fri, 20 Nov 2020 07:22:02 -0800 (PST)
Date: Fri, 20 Nov 2020 15:22:00 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Marco Elver <elver@google.com>, Steven Rostedt <rostedt@goodmis.org>,
	Anders Roxell <anders.roxell@linaro.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Linux-MM <linux-mm@kvack.org>,
	kasan-dev <kasan-dev@googlegroups.com>, rcu@vger.kernel.org,
	Peter Zijlstra <peterz@infradead.org>, Tejun Heo <tj@kernel.org>,
	Lai Jiangshan <jiangshanlai@gmail.com>,
	linux-arm-kernel@lists.infradead.org
Subject: Re: linux-next: stall warnings and deadlock on Arm64 (was: [PATCH]
 kfence: Avoid stalling...)
Message-ID: <20201120152200.GD2328@C02TD0UTHF1T.local>
References: <20201118225621.GA1770130@elver.google.com>
 <20201118233841.GS1437@paulmck-ThinkPad-P72>
 <20201119125357.GA2084963@elver.google.com>
 <20201119151409.GU1437@paulmck-ThinkPad-P72>
 <20201119170259.GA2134472@elver.google.com>
 <20201119184854.GY1437@paulmck-ThinkPad-P72>
 <20201119193819.GA2601289@elver.google.com>
 <20201119213512.GB1437@paulmck-ThinkPad-P72>
 <20201120141928.GB3120165@elver.google.com>
 <20201120143928.GH1437@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201120143928.GH1437@paulmck-ThinkPad-P72>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Fri, Nov 20, 2020 at 06:39:28AM -0800, Paul E. McKenney wrote:
> On Fri, Nov 20, 2020 at 03:19:28PM +0100, Marco Elver wrote:
> > I found that disabling ftrace for some of kernel/rcu (see below) solved
> > the stalls (and any mention of deadlocks as a side-effect I assume),
> > resulting in successful boot.
> > 
> > Does that provide any additional clues? I tried to narrow it down to 1-2
> > files, but that doesn't seem to work.
> 
> There were similar issues during the x86/entry work.  Are the ARM guys
> doing arm64/entry work now?

I'm currently looking at it. I had been trying to shift things to C for
a while, and right now I'm trying to fix the lockdep state tracking,
which is requiring untangling lockdep/rcu/tracing.

The main issue I see remaining atm is that we don't save/restore the
lockdep state over exceptions taken from kernel to kernel. That could
result in lockdep thinking IRQs are disabled when they're actually
enabled (because code in the nested context might do a save/restore
while IRQs are disabled, then return to a context where IRQs are
enabled), but AFAICT shouldn't result in the inverse in most cases since
the non-NMI handlers all call lockdep_hardirqs_disabled().

I'm at a loss to explaim the rcu vs ftrace bits, so if you have any
pointers to the issuies ween with the x86 rework that'd be quite handy.

Thanks,
Mark.

> 
> 							Thanx, Paul
> 
> > Thanks,
> > -- Marco
> > 
> > ------ >8 ------
> > 
> > diff --git a/kernel/rcu/Makefile b/kernel/rcu/Makefile
> > index 0cfb009a99b9..678b4b094f94 100644
> > --- a/kernel/rcu/Makefile
> > +++ b/kernel/rcu/Makefile
> > @@ -3,6 +3,13 @@
> >  # and is generally not a function of system call inputs.
> >  KCOV_INSTRUMENT := n
> >  
> > +ifdef CONFIG_FUNCTION_TRACER
> > +CFLAGS_REMOVE_update.o = $(CC_FLAGS_FTRACE)
> > +CFLAGS_REMOVE_sync.o = $(CC_FLAGS_FTRACE)
> > +CFLAGS_REMOVE_srcutree.o = $(CC_FLAGS_FTRACE)
> > +CFLAGS_REMOVE_tree.o = $(CC_FLAGS_FTRACE)
> > +endif
> > +
> >  ifeq ($(CONFIG_KCSAN),y)
> >  KBUILD_CFLAGS += -g -fno-omit-frame-pointer
> >  endif

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201120152200.GD2328%40C02TD0UTHF1T.local.
