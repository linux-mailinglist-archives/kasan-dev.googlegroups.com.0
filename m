Return-Path: <kasan-dev+bncBCV5TUXXRUIBBNVJ6X2QKGQE7VVS34Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 448251D32BC
	for <lists+kasan-dev@lfdr.de>; Thu, 14 May 2020 16:24:56 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id a12sf2756081pfc.22
        for <lists+kasan-dev@lfdr.de>; Thu, 14 May 2020 07:24:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589466294; cv=pass;
        d=google.com; s=arc-20160816;
        b=MUpgxppqRDX9IsQd7xumY7uaOor/zQaXwR6u+ya6ymCDpZlwE/Aa67bZEzc8Wae/QD
         n/Apvf8nzpLwfeDv/smgfSzzKaXhTwEE1MCGDkip1nkUqXuz1X95/FD0l6RNO8Uazdtw
         a9I9FOb36igJSG7m9Tuhth1n+YH0txzdSxrvkh4M3PsIkrdVamAjyetBZkEJRk3ETLJX
         oj3JFgIM2NnYiJP9E1EadZH/zfwk5e+63m6nU/MgL/T8unJSLgvGBiCDu7pubA0ncNPs
         LLidj0eUUmvFg2KqtHV73Vt576NROahpegRl4X63tscvBAaAkc+7W+ov2il8eQ8VBuy1
         vGIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Y55FHCA0kIva82vxS+j8YNS0R5R652QQFB1L/RPC+DQ=;
        b=uNAm9RNuaoCUEF+M073A2yVPoJBFzVV+NIGAXIikXdMeB37n5bYBwgNQgm4JP2hbbA
         Cu+rHhNxJzJrol6Zwj5diUcgxuVbv0LKPvAgBGBVy/Zbtq8M4AepYjmHFwLkuXL3dx0B
         Oawzi09id2e9hazv8E6992nd1CRkS1ue2fdqnnNf/gM9hGPW+b3CJpoBbnr7ul7RBMVe
         bR3QYrLrkmkBwvKJm4ozQYWuIPqhHRe5ec/AOghHB7pbIjGsVRhfBsRGwArE83EI6X/1
         E4FQYA5X6+qlz6EjtCeJgrpWXov/D7ERI4/IdDGDSbJanbLV3rvPefflVbkNvRLrsE2K
         hjCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=JyAQXOUW;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Y55FHCA0kIva82vxS+j8YNS0R5R652QQFB1L/RPC+DQ=;
        b=F2V/zfw4YTAv163ZlSR5gJFzjg6q9zHX3ZhzTRL2MEda0tHE047s6175Q1J8ta8pay
         T3blvlqEcb9lv3XPKr4JIQz2SzIEhlRqajfgOAOEO+Y7XIOmDwZQ3+4IiN+5tNPHx1fA
         e41AFXUuMXwTrLpU6/fMacvTY9MgHK481m5U07NH67ctMV/2JHIN4B6sRTx6LRNc6xVQ
         iNPMfA8oKmdRvY7jSGtb4TSWnSL4S1yq1zCJVRq9riK1bFaFdDvaoRxjh/kCkDEVaP5H
         UbMSH4v8AF9ahqPhgSO0mjL/YLBTMHgWAEUOkCIEZqIE8jV4LI1g4we++WCyly6k5NDB
         3oZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Y55FHCA0kIva82vxS+j8YNS0R5R652QQFB1L/RPC+DQ=;
        b=mjOP7glSNYX+b7CwVdpWYluXJ8vAYEQlOMlocdPwyPkRfB8fvOsDFbRr/qZlPePXF6
         UWDtqEKvVNeXHwfM7oMb9tjvskpw4/ph6tltrI24dhEHdbPSCfp+HhvZ5Wpf61QoC9XP
         3kPVoinfwIJmC2D1fL4Js5Q2BUikYBWi/lzDkhI/tDph3+yDcf2U7HLIUrQ3MXRvBv78
         SQOHoPHZ+h/TeGcGO9vHRuo/Gip6coLIewtpU+peoueG3lRoSrJcQC7WoFcZdqkBBQIF
         fE0jSektA3WQxgW1CSI8e/3r4aA08PT7tC+nNq1bH2rldq+J2ddqHaa4co70pKcOieIa
         x77w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532atcPMX/94mjTu6NhqqHeGH92EitterzhZO1ew1exsnTGTjPzS
	dj7lTjytQgBdccKdPvM/hlI=
X-Google-Smtp-Source: ABdhPJwF/i5GFKyX8HE/G5f2Yf6d5jIo8sejEC3FwEmY9E4HbsKUVYqvNW27Ul278tXnqnaU50b7+A==
X-Received: by 2002:a17:90a:358c:: with SMTP id r12mr10352042pjb.161.1589466294599;
        Thu, 14 May 2020 07:24:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:e116:: with SMTP id z22ls853873pgh.9.gmail; Thu, 14 May
 2020 07:24:54 -0700 (PDT)
X-Received: by 2002:a62:81c6:: with SMTP id t189mr4701632pfd.174.1589466294238;
        Thu, 14 May 2020 07:24:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589466294; cv=none;
        d=google.com; s=arc-20160816;
        b=rDnHdQjLkx0AkaiowJWqAcQxFbW+b+PK1AG+hE0Ur2eTKq810HCE1hC/5YAjIY5fxK
         ehUZ4tuJYiwAvWpucqcoqC8uxiMoXTuWkad7mn+X5quz0xRFaDRu9DidG5aYBcbcMJYG
         0aojoXOpf7dY4Bmi9qUfUHmpdAwpC+UocfBNUrGfexLOFPJp7Q0PdY3s9Conx8xVtsuT
         ByEXxx86y0vtb0IETu52L+Zm6yQlGxgT4++gCA0kO+Jo5Q0Tkqsc2lTKcLpAzxHUrckW
         hPQTVim2rJ38LowtHJ7lbnSzvZyyhoHd9AVVtzzbEHsaVnSz3LM/BzK9vNAsuA3nWaw6
         TkaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Jfq3RHqQr0LXNTIpWKRuiuSUC1EarhLNtIVJLxWCknU=;
        b=iD06WgNb4ISKIOL/m4poCXCC9LWs7ajbQ2O+QOYSDhksAkC+G/8eVH+BUpCmzild+l
         Mq6tpsPqcinsyF/r5+V8MQlzNOucdPHMXVWTtyAR8PuCUVDFABXZnjERTEoSn9gPDD33
         TwrdEDRVNdXdNx9h16U0rVuW5dMLB5cAZhvi5NklYJ9/eiVj/Oxqkof+4to4fQce/GYS
         Y3Qpbbx+x4YG0Cmbq+POP4NsIxbVh7kcUFZlglOqO26vfDRSQ4fi4XP+F3PN/L7/B69o
         xCk0JDM4DhKQs8j31n/8HKjM5zLAOTh2CZErNNiwfX1HFpU0S7iVl5wIvalVXAqfQUmp
         jGzw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=JyAQXOUW;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id g6si277620pjl.1.2020.05.14.07.24.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 May 2020 07:24:54 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jZEn6-00012p-Cl; Thu, 14 May 2020 14:24:52 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id C276F302753;
	Thu, 14 May 2020 16:24:50 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id A952B2B852D47; Thu, 14 May 2020 16:24:50 +0200 (CEST)
Date: Thu, 14 May 2020 16:24:50 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Will Deacon <will@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Ingo Molnar <mingo@kernel.org>, Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH v5 00/18] Rework READ_ONCE() to improve codegen
Message-ID: <20200514142450.GC2978@hirez.programming.kicks-ass.net>
References: <20200513124021.GB20278@willie-the-truck>
 <CANpmjNM5XW+ufJ6Mw2Tn7aShRCZaUPGcH=u=4Sk5kqLKyf3v5A@mail.gmail.com>
 <20200513165008.GA24836@willie-the-truck>
 <CANpmjNN=n59ue06s0MfmRFvKX=WB2NgLgbP6kG_MYCGy2R6PHg@mail.gmail.com>
 <20200513174747.GB24836@willie-the-truck>
 <CANpmjNNOpJk0tprXKB_deiNAv_UmmORf1-2uajLhnLWQQ1hvoA@mail.gmail.com>
 <20200513212520.GC28594@willie-the-truck>
 <CANpmjNOAi2K6knC9OFUGjpMo-rvtLDzKMb==J=vTRkmaWctFaQ@mail.gmail.com>
 <20200514110537.GC4280@willie-the-truck>
 <CANpmjNMTsY_8241bS7=XAfqvZHFLrVEkv_uM4aDUWE_kh3Rvbw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMTsY_8241bS7=XAfqvZHFLrVEkv_uM4aDUWE_kh3Rvbw@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=JyAQXOUW;
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

On Thu, May 14, 2020 at 03:35:58PM +0200, Marco Elver wrote:

> Let me try to spell out the requirements I see so far (this is for
> KCSAN only though -- other sanitizers might be similar):
> 
>   1. __no_kcsan functions should not call anything, not even
> kcsan_{enable,disable}_current(), when using __{READ,WRITE}_ONCE.
> [Requires leaving data_race() off of these.]
> 
>   2. __always_inline functions inlined into __no_sanitize function is
> not instrumented. [Has always been satisfied by GCC and Clang.]
> 
>   3. __always_inline functions inlined into instrumented function is
> instrumented. [Has always been satisfied by GCC and Clang.]
> 
>   4. __no_kcsan functions should never be spuriously inlined into
> instrumented functions, causing the accesses of the __no_kcsan
> function to be instrumented. [Satisfied by Clang >= 7. All GCC
> versions are broken.]
> 
>   5. we should not break atomic_{read,set} for KCSAN. [Because of #1,
> we'd need to add data_race() around the arch-calls in
> atomic_{read,set}; or rely on Clang 11's -tsan-distinguish-volatile
> support (GCC 11 might get this as well).]
> 
>   6. never emit __tsan_func_{entry,exit}. [Clang supports disabling
> this, GCC doesn't.]
> 
>   7. kernel is supported by compiler. [Clang >= 9 seems to build -tip
> for me, anything below complains about lack of asm goto. GCC trivial.]
> 
> So, because of #4 & #6 & #7 we're down to Clang >= 9. Because of #5
> we'll have to make a choice between Clang >= 9 or Clang >= 11
> (released in ~June). In an ideal world we might even fix GCC in
> future.
> 
> That's not even considering the problems around UBSan and KASAN. But
> maybe one step at a time?

Exact same requirements, KASAN even has the data_race() problem through
READ_ONCE_NOCHECK(), UBSAN doesn't and might be simpler because of it.

> Any preferences?

I suppose DTRT, if we then write the Makefile rule like:

KCSAN_SANITIZE := KCSAN_FUNCTION_ATTRIBUTES

and set that to either 'y'/'n' depending on the compiler at hand
supporting enough magic to make it all work.

I suppose all the sanitize stuff is most important for developers and
we tend to have the latest compiler versions anyway, right?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200514142450.GC2978%40hirez.programming.kicks-ass.net.
