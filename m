Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSNLWT3AKGQEAC2XEOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B6AF1E22C8
	for <lists+kasan-dev@lfdr.de>; Tue, 26 May 2020 15:12:43 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id x10sf20275759ybx.8
        for <lists+kasan-dev@lfdr.de>; Tue, 26 May 2020 06:12:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590498762; cv=pass;
        d=google.com; s=arc-20160816;
        b=uURUjmgCUuTCQaQ2v98+EBzCzqoORi/Rm4ILRmB6repUm1Xa/TVDbz536V2wdMzjtl
         bilRQeJhFsdHA67+757BE5iXN7BYAhrlUxEirI9O4tMMyfgRTOgvYEdzuFFrVD6GT0dN
         W8VRFg42hOiQltKpmTbuyMjXO9wPtESwMtMUkEDKH+af5hq6XDFZGTHcIZQx8BJqGUcP
         cQah1DJk6Js7JHncntPCA4ofdyqyYup4/jAudabERgTig3jGjlvSgh2GmfgUIxdA4rQU
         U5l5VWf0nQ1Qp4rfvgafa/mfV83RM4jp87mmGhu1cGCT8KWrIiQ8BS9M3LCfqUys05LY
         2/Bg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1HhiYR9QwfN2xycnBMSzGyYXMQUo+I5NF9W+NH207as=;
        b=OCDv4aMa9YCFGSQa+jZ4xOWQw7aPi21dEetCRrcHCiAMRZ1jOxpR3Uljj8G19JMWe4
         s46Ib0HHroM4rAjsiHjk0zgJorKzzptV6TbsC+UBcPkfwNkzrkQbg80okRSjm3WRck5O
         rS/v1I7aZb4//Glg/r/Pcn+mITY1hyQ0lpP7IBa32OXsc8YGsE0YmyWsOo8mvVgIwPHs
         YgCD1LSRH3wPM61Sjb9tDjiqPGj1is1BBwa1WjM4y2byqNvFl9h6LbIhG9ltlo4QaRaI
         jP5D17lMFll4/WNjdyG/6VaKBIyG2Zyj2/Qf6JENj91XX47Y2T2GD6i/TVL/JlxrD2KN
         34UQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YUmih8bK;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1HhiYR9QwfN2xycnBMSzGyYXMQUo+I5NF9W+NH207as=;
        b=PGHQx6VhC2xKCUHVl7lniS/NXH9tZRenW4/Cuf6GIJr6uhOTBaQ2FXpv5rgNS0xajO
         FaDL5nrNdHFftdNSzMit6RtnXouEk09KcCVAD7ABA0LwyW4KqshdzOtXxirj4K5dwiRI
         enXBWLZtJWxafx6XedfanqSY8B2ciS0v1Y3yCxTA9k4gxsnegPmIIRHCFHnvqjt2UDoZ
         OkhsV/UX37w17cczH8lxMCjxGGFedseYbnqAEvmrhcZpO3jMxSzgQYMrtDX2d/vNu6Gb
         NE3BvNQ0JQ5Qb150eRRPZZewQ0Vt/nVuWbc7UV9tYLQW9n3ZnF3LOsTI7g7i6ta3+Naw
         z6aA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1HhiYR9QwfN2xycnBMSzGyYXMQUo+I5NF9W+NH207as=;
        b=IcrlV5wIdraRC7xhRXBrwMOIxn6U9FDmpr1KZsWSfB18CCoiUin33beA3Kbxx70KFo
         LR3mK/N/0T0zv5RGMKRKNTK5YvbbHiSCSuK0fenaYtNoDIooQhXQJfHOH5vYu/Ulqyb0
         xogxzgheSKCgrV6we7anKNx14v/mcr4hpaUdfaUryNW1+yPDsqeVOy36REaQRldT2bXJ
         iZhEPnTY5v5HJ93sPVJxPp9ayYQULthspsHYDP4bhmcYXDhG3uJ0gMwaNIT3mQ59c0L/
         bCoVosL+NMffjQaLYrh4JuhAN9hmfOAlgYwj3j37cYViGjyjseGXjCp1Vl6eGfpX0TIS
         XYCw==
X-Gm-Message-State: AOAM5323aHGPwNr2wliymtHQ5/gkudFVY5dG75poSCyJkhbKeel9JLSx
	cu54LQO6ag1A8Zks2v7JHLg=
X-Google-Smtp-Source: ABdhPJzl7g4bZkDBOZU8MuHFDQR1Uby9aLOtdhhFpNhRHLcii8cgcSYGtE19Cak7IgZE5ViuZ2uUrQ==
X-Received: by 2002:a25:257:: with SMTP id 84mr1463675ybc.397.1590498761136;
        Tue, 26 May 2020 06:12:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:be4d:: with SMTP id d13ls4114292ybm.2.gmail; Tue, 26 May
 2020 06:12:39 -0700 (PDT)
X-Received: by 2002:a25:b7d3:: with SMTP id u19mr1494675ybj.434.1590498759295;
        Tue, 26 May 2020 06:12:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590498759; cv=none;
        d=google.com; s=arc-20160816;
        b=jr++BeM1E4tHGNIpJEATcrVLE7o1igHC6P/EWq+eCt7kkwgJ9etVFjS7QEobp8qJK+
         L0PRK0L937CD7m06SNNfNfREN8TA7X1zquC34QibyEI2NmezQOL+mrE/e7M3K83XkQ6L
         pyv+kHbRKKlWiVf2YL+L5qGiaG/auNjS4F5x30CYHNYus0TDVeHepHvb8kdZsTGv8yM7
         apP7scvYGbBquzCLeYMzosxrMvmyyI+TE3mhE0xMNQDF8gKUo+1VWYHk5bG4mBZxv+La
         aAglbr+kwbpe/Gh7+TsZzCFT1xyWjmdXGBIs0DLbcgo6JXnaAVJeYXiKPiEFkGK1LwpB
         YnRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=n2vqEAYjxMamt8eKicI31y8Z10SrX1vFFP0/1fJj8mo=;
        b=0Ixelgeh9d3yO2UIjy0vlOsDV4sXm6OOQHvd9yh9G0d8pCRr4NngA0Ly3RWR8NJnrJ
         aGIGgUs1G0CyXslbYgZiEVB9UV4IG5W2CfCEplryIFRGwV7nTNHQNIrsgVvUWojftkRC
         AV4OS9KYslHJD0tvaT6vsWUd4IXSl/IJOhWj3lCG2b5N2e0K3GL7m/I59ijpHyfvBgIV
         J7Bh+nECFj7aZNqhdOgQa/ZdnFLNcLwjhaR6xWHyVj9NQcbyNWdeUBMNKXLBg8+JMI4i
         su3X9qmnE7xjK/0sDuw8pNSLnUVhXcojH0h29LMQt1o/9T95s3Og9SEPJhHO/rqBjghN
         YZWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YUmih8bK;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x341.google.com (mail-ot1-x341.google.com. [2607:f8b0:4864:20::341])
        by gmr-mx.google.com with ESMTPS id u126si1188644ybg.0.2020.05.26.06.12.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 May 2020 06:12:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) client-ip=2607:f8b0:4864:20::341;
Received: by mail-ot1-x341.google.com with SMTP id v17so16246724ote.0
        for <kasan-dev@googlegroups.com>; Tue, 26 May 2020 06:12:39 -0700 (PDT)
X-Received: by 2002:a9d:518a:: with SMTP id y10mr840760otg.17.1590498758658;
 Tue, 26 May 2020 06:12:38 -0700 (PDT)
MIME-Version: 1.0
References: <20200521142047.169334-1-elver@google.com> <20200521142047.169334-10-elver@google.com>
 <CAKwvOdnR7BXw_jYS5PFTuUamcwprEnZ358qhOxSu6wSSSJhxOA@mail.gmail.com>
 <CAK8P3a0RJtbVi1JMsfik=jkHCNFv+DJn_FeDg-YLW+ueQW3tNg@mail.gmail.com>
 <20200526120245.GB27166@willie-the-truck> <CAK8P3a29BNwvdN1YNzoN966BF4z1QiSxdRXTP+BzhM9H07LoYQ@mail.gmail.com>
In-Reply-To: <CAK8P3a29BNwvdN1YNzoN966BF4z1QiSxdRXTP+BzhM9H07LoYQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 26 May 2020 15:12:26 +0200
Message-ID: <CANpmjNOUdr2UG3F45=JaDa0zLwJ5ukPc1MMKujQtmYSmQnjcXg@mail.gmail.com>
Subject: Re: [PATCH -tip v3 09/11] data_race: Avoid nested statement expression
To: Arnd Bergmann <arnd@arndb.de>
Cc: Will Deacon <will@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, Borislav Petkov <bp@alien8.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YUmih8bK;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, 26 May 2020 at 14:19, Arnd Bergmann <arnd@arndb.de> wrote:
>
> On Tue, May 26, 2020 at 2:02 PM Will Deacon <will@kernel.org> wrote:
> > On Tue, May 26, 2020 at 12:42:16PM +0200, Arnd Bergmann wrote:
> > >
> > > I find this patch only solves half the problem: it's much faster than
> > > without the
> > > patch, but still much slower than the current mainline version. As far as I'm
> > > concerned, I think the build speed regression compared to mainline is not yet
> > > acceptable, and we should try harder.
> > >
> > > I have not looked too deeply at it yet, but this is what I found from looking
> > > at a file in a randconfig build:
> > >
> > > Configuration: see https://pastebin.com/raw/R9erCwNj
> >
> > So this .config actually has KCSAN enabled. Do you still see the slowdown
> > with that disabled?
>
> Yes, enabling or disabling KCSAN seems to make no difference to
> compile speed in this config and source file, I still get the 12 seconds
> preprocessing time and 9MB file size with KCSAN disabled, possibly
> a few percent smaller/faster. I actually thought that CONFIG_FTRACE
> had a bigger impact, but disabling that also just reduces the time
> by a few percent rather than getting it down to the expected milliseconds.
>
> > Although not ideal, having a longer compiler time when
> > the compiler is being asked to perform instrumentation doesn't seem like a
> > show-stopper to me.
>
> I agree in general, but building an allyesconfig kernel is still an important
> use case that should not take twice as long after a small kernel change
> regardless of whether a new feature is used or not. (I have not actually
> compared the overall build speed for allmodconfig, as this takes a really
> long time at the moment)

Note that an 'allyesconfig' selects KASAN and not KCSAN by default.
But I think that's not relevant, since KCSAN-specific code was removed
from ONCEs. In general though, it is entirely expected that we have a
bit longer compile times when we have the instrumentation passes
enabled.

But as you pointed out, that's irrelevant, and the significant
overhead is from parsing and pre-processing. FWIW, we can probably
optimize Clang itself a bit:
https://github.com/ClangBuiltLinux/linux/issues/1032#issuecomment-633712667

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOUdr2UG3F45%3DJaDa0zLwJ5ukPc1MMKujQtmYSmQnjcXg%40mail.gmail.com.
