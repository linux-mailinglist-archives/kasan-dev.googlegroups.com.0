Return-Path: <kasan-dev+bncBCV5TUXXRUIBBDOCQXZQKGQELJ6WVSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 15AAD17AFB1
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Mar 2020 21:29:03 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id 12sf3909126pgv.1
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2020 12:29:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583440141; cv=pass;
        d=google.com; s=arc-20160816;
        b=yk7HZFcTehisBi6LY+QMAkT/h3VxpZlStzrswMMH01LVaNlAFNO5DDGhYaxN7NYmEN
         z1aYRqz4tC+BglQ7r8sbXQR75aYWe19tfu5aKadNoq+0PQx2EiNookxNPTrt14hpT+Zw
         AMY9PDXkij393uimtSzfTeoCsY7Im8p1l7DnG55hTBpTV4BBfZUROKzIRxPxbO4T4FVr
         6TKv20N85IxM7/5vnJH+Ps9J/Sbg85W7G5xOtUwBbqHY+GYhFHBA2pk28htlMknVVvo1
         fhIjSnBIOryCCTWYC/P6uyIdn4967OcxcNkYvFBzZd1SXS8yAyGvwKeqNEjU5Nl7b435
         9cYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=C1N3pWZiFn1srHFD2gOODt38zby4wcnCsX3ifyy1TAE=;
        b=HB87z3hxKvUSLemqB3gOQaiOrlhLoQZd8JvMuI63NG8gyykUjsX85S6vzngX3XUQ/O
         cKmBEJjJGjQYKJnl8ecT/W+sJpxjdySUJKYjJUVKqKJ/Xd72UhRB0lECk7KIRN/K1GuT
         ybLP+1lgRaWgEcK/6Ix04kHZWZ3I+wixgFSPOih9uf/rVpioHE8sLJfL6FOFlqN3cSs0
         OKaROK3Tf0ToZGe3be4qMK5LSETxsLvyI3XObcV7uN+TWKmoX4wZq83CrkQTivhNbOOv
         +523+7vhjXt9sSrq1ek4W982WFLUpIlCO4O48y5L3+F7k7/3mpbMRmZMme9E238eNIEc
         gaiQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=wRGrckIs;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=C1N3pWZiFn1srHFD2gOODt38zby4wcnCsX3ifyy1TAE=;
        b=phzSYoPhvHxWd7QqjzeAunHMJC5501GpoBSUIKveyMCslmv32A5p1jKOfx68z6hN2Z
         fPzYjcwuWksg2eCEFmI2tGHg9z/aUiCepkTMP3ERglTEjcQKQiaAmDJRIaaD7cFv7TFK
         34S5cB8DvvlSKMt8kG92MS7M2T83OmdDRs3+loro3COeiej2VY4/qY07IDSAf+8Mc6+/
         HFX24ayd6dSv2d/0tOrLxHd/CN3oYUHEEGa+LSWD3Rg4cDlZKDJstI9HWtxwK9f+rBiD
         zX8euIFt3teQepdX+G91Pr1MnlF9YBeepaE1Cr3XRSmYWQunqoPl91L0vP77ytGL8NT0
         D0Ew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=C1N3pWZiFn1srHFD2gOODt38zby4wcnCsX3ifyy1TAE=;
        b=YCDgWeRBNAA7n7+AkdC2CfXu8GupfBi8qWI0Bh/Hc33Ykv0y1ju+Pu6sLzoRbeSrgg
         LSRtWwBkNLt8HD6hWW5PFLjSpailcNv+fz9yU7ADFCCAde1gTg3hMiLmnWt+BEDDhU8/
         wnqCnrJpBXLrD/qz0u/t5Ais8WWuvprUZM3REJ7Ls/FR3132jVl10r1aie6P2BGCflOn
         I6jdj8iAwK1RqX7B+L9X9Dq1vRz7CEAXz7rk2UsslgV0fOaIea3HBbesYvquWHHQoXZn
         3BI43a793VGSamamWxxlzGuGTd+A9dqvxtl4P8mxEZGtiCtabm8bq7HoUvMxEtq7jaqc
         +UZQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ0A8yjk02C8btXmRFN73Lc5ax6op1DiRd9qcIfUb4EExsODVjDT
	p0vG1p1RzbyABS/cPIpKUxY=
X-Google-Smtp-Source: ADFU+vtJY9lzpSseqgdYi9UmnCUs01sShHp7f7n6tx856h6nGDyJzbwQ/pXpEcCyjzwPFe3c+7Q/sw==
X-Received: by 2002:a17:90a:a385:: with SMTP id x5mr444385pjp.102.1583440141463;
        Thu, 05 Mar 2020 12:29:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:b114:: with SMTP id z20ls54272pjq.0.canary-gmail;
 Thu, 05 Mar 2020 12:29:01 -0800 (PST)
X-Received: by 2002:a17:902:ab98:: with SMTP id f24mr598482plr.338.1583440140975;
        Thu, 05 Mar 2020 12:29:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583440140; cv=none;
        d=google.com; s=arc-20160816;
        b=W60d7sAXvT9wW12OaZWBm1M4g+a5sBRQ1K6Be5WbvCKY7ELDe+XFEdEVHMruWSva9/
         04+L8b/zzR1HPa9QuT6oHbD8Pgry8UGA8QIKQEdGIWdgmGdlf/qUPTlNz4EHFZiISe67
         wcvitCiZPb8I3X1rUpbymuTSD3FjcobkdO1D9rZDasPCQyueeIAtn1K9KRoOqryNZ+4b
         YF1m2e6CmkDwsosn4lww//pICea971Vp9PO4T3VP572T/Evs/tN8BQps5uKyrfQ19R4P
         EB6ydxbpp4oHiDEcCcodmZZwkskiIVjfg1o5+280VyowIKB6MH5v8/ZhVaCVXtWlI05y
         fdCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=t8yy3Lde8//31SwTJu29OqkzL4aSFID25kBMZTqfasU=;
        b=iDLZV9aSdCvjRY95FcKpQgYThCsun5+Y9ck0TaAxtkYg8YzuWp2VTFLuOas0dO7YR+
         P57rmk4o0J9BT47nDijB/wuAXd45P7QPIm8pGADZ6ZDYhUtmqTNdPnOXsANOEEbNEqDC
         45xfgvdknMLyAeDQ8WlBGUL+YVGwCXLgmNv6rQQeQ5HV/qrCD46sYoowGhGuomuNIJV5
         CEjNI4T14RI+Iu/vXerKn075nawamepL58whmuEPOXPaJTGB7H6SlwryE7CfN96VOP3y
         np+b3MfMajwIJtobDt4VlaaQcoYNSH6f3Mtms8o2LIXsXPS7LSCdeeqsqsFyeP8RqtPD
         LcJg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=wRGrckIs;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id w34si266775pga.5.2020.03.05.12.29.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 05 Mar 2020 12:29:00 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=worktop.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1j9x71-0006Ho-Px; Thu, 05 Mar 2020 20:28:56 +0000
Received: by worktop.programming.kicks-ass.net (Postfix, from userid 1000)
	id 224D0980DC4; Thu,  5 Mar 2020 21:28:54 +0100 (CET)
Date: Thu, 5 Mar 2020 21:28:54 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: kbuild test robot <lkp@intel.com>, kbuild-all@lists.01.org,
	Thomas Gleixner <tglx@linutronix.de>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [peterz-queue:core/rcu 31/33]
 arch/x86/kernel/alternative.c:961:26: error: inlining failed in call to
 always_inline 'try_get_desc': function attribute mismatch
Message-ID: <20200305202854.GD3348@worktop.programming.kicks-ass.net>
References: <202002292221.D4YLxcV6%lkp@intel.com>
 <20200305134341.GY2596@hirez.programming.kicks-ass.net>
 <CACT4Y+apHDVM7u8f660vc3orkHtCXY+ZGgn_Ueu_eXDxDw3Dgw@mail.gmail.com>
 <CACT4Y+ZuGLqNaB+C+VJREtOrnTZVyHLckdAHRMSHF3JMDTg_TA@mail.gmail.com>
 <CACT4Y+ayJrm6ZrkQwybGZniP-xwtxjkmMpYVdCoU4mKzDUWydQ@mail.gmail.com>
 <20200305155539.GA12561@hirez.programming.kicks-ass.net>
 <CACT4Y+ZBE=FDMjXxOkmtn0rd8oRWvNaBGnRgXKKSjuohuqd3=A@mail.gmail.com>
 <20200305184727.GA3348@worktop.programming.kicks-ass.net>
 <CACT4Y+axD4ZjEPdekgVkkUGu6V0MMR9Q1RNcVA9v6dOSi8FHzg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+axD4ZjEPdekgVkkUGu6V0MMR9Q1RNcVA9v6dOSi8FHzg@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=wRGrckIs;
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

On Thu, Mar 05, 2020 at 09:13:26PM +0100, Dmitry Vyukov wrote:

> > Right, but then I have to ask how this is different vs inlining things
> > into a __no_sanitize function.
> 
> We ask compiler to do slightly different things in these cases. In the
> original case we asked to sanitize user_mode. If we have a separate
> file, we ask to not sanitize user_mode. A more explicit analog of this
> would be to introduce user_mode2 with no_sanitize attribute and call
> it from the poke_int3_handler.
> Strictly saying what you are going to do is sort of ODR violation,
> because now we have user_mode that is sanitized and another user_mode
> which is not sanitized (different behavior). It should work for
> force_inline functions because we won't actually have the user_mode
> symbol materizalied. But generally one needs to be careful with such
> tricks, say if the function would be inline and compiled to a real
> symbol, an instrumented or non-instrumented version will be chosen
> randomly and we may end up with silent unexpected results.

Right, so I'd completely understand the compiler yelling at me if the
functions were indeed instantiated, but exactly because of the
force-inline I was expecting it to actually work.

A well, can't have it all it seems.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200305202854.GD3348%40worktop.programming.kicks-ass.net.
