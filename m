Return-Path: <kasan-dev+bncBCMIZB7QWENRB77NXH6AKGQEYAKT32Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe38.google.com (mail-vs1-xe38.google.com [IPv6:2607:f8b0:4864:20::e38])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B76029344E
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Oct 2020 07:34:56 +0200 (CEST)
Received: by mail-vs1-xe38.google.com with SMTP id z9sf175768vsl.3
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Oct 2020 22:34:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603172095; cv=pass;
        d=google.com; s=arc-20160816;
        b=Yyz0RU/0yEkLRMD86mk6wVBIBkG5ReMODTyVa+ry2pygyGgsRg8RsCf5/VqAoNX2O6
         Tg4gD5e8igqAbKQRuHnNU9hokHeKuJUdepgWNUkmHzoQWSQiQbadTY3/oL1DYbuGivbR
         oMB4o6bE0FAOQBXTygKA48ysH6C2xbTezXJ3H4kurNQoTKG61z52zEdi4thU5QUPkMQG
         U83Ok3Z3aygkt8Dm9FciXZQHjSYddPWnRKGMJUTnk1avvUblN1ScsAm8iwa8gC6loyf2
         FWecViRdESD2LIO5wbio/qW5k5aMqi0sNdKe16E7eBxKz0x7M6mpIUKIwUiOf6MeVSuY
         0Yrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=tMSqACrjG5+mDh3F6z7PNwYNRAToxl6qcOxLnbURNt8=;
        b=nhrNAFYUPcf8q7vCA7vdKHUqRJ8swv2MIcDayxRGcgcvb76N7CMO7r7M/tDTMAlP4D
         NLqKOkJlQGXc5jP8zgGGWEB/QgEZJkKA2f17aBJuV9StipKpF7LSQtVsr9F+xZlSkCxr
         HD3qP1a7qKfvyO0OJBqRG099Vk6lBQ5DiWSBF8nmPN5IKi1M44wNy5sA9IidqQpW4lcd
         rIIKn9B3zLGLjT+Tt2k3OfSDmMLSsIemPXMA1dUU1UNPFT/iGwOZl1zYl0aiGocejRVC
         KOtIxwO5+E1aj5yjI8Ik+Jo1TZCLzY0qqprM/uai2NUIjsXbxfxPUzR/epGySyss4Vqd
         DT9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lSWQdfR8;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tMSqACrjG5+mDh3F6z7PNwYNRAToxl6qcOxLnbURNt8=;
        b=fzr2XYrhZ0Fk096qqV1QonzXKeve2MpgnxmurRe5jsIv5AufcjRP2fizMLiqM0OXSH
         1Sm7noDzC57yTX2l1tlE7PJUSUyo6JN0DdW7PlbVhwG3Drpq4D8m6whI/12/FjZLnsTe
         YUQWOUIH73eThqvHLyvsbYJYBnu6seBWVgMDDckLo72bLiANV2yljVJ5ChUvg8MWHANQ
         My2FjYIzHmHtiYAS/5V5kX+z9T286+YyGsT6AlsXtdm6Q1kkY6Zl2KdW+uLsHlOvt5Vv
         CHIYtahSM+pI1Cl3iLRNo2nh4MuLYCTMTfXSthUQupsbVUqoKjW733IuROTkzXXz1Ilo
         CMfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tMSqACrjG5+mDh3F6z7PNwYNRAToxl6qcOxLnbURNt8=;
        b=cwS/vwIT/bjNtk7Ogx6xER/C8C984RvUcyTNjr5jGRM0ZhIMtXepdSITX9uQdN2s64
         Yt19dkDlkBQJOyK+kI1CoE4h/PBwC8iWr/oeiP5KyedvgByQf9Y+PG3xXnONyzAi+60u
         KiMBDx2JAwfR9aa9KpHorv1JBeBhYylqIgGseJgaUPL0cs/rpWai0Gf37uZrYcKPLEL5
         8uJEFYdmxY8rwtafqbT+Yfv1RzzbrhMqzRWay3jDOoMKjf60/cMwm0i4lT3tQEziTtu9
         qrKobPB/CpR8k2Z3hjtvvbID1KC+BgrVVV+QsBQpsmdrJxx3PRfjDbKA0iZ7kJIWdBUW
         v/gg==
X-Gm-Message-State: AOAM530mCVAZQ8WmM18KQEXUGPi2g+r3NOWqQFP7cCSiF+XvPG4AKiSH
	u1KFk+c/BfVtU+inH0pLrpc=
X-Google-Smtp-Source: ABdhPJwPhR8EkXyLAXbmrWO2fZtDii3i2kj9QoSb7H22HZUI7nJRjVTBXdhJNI2Iv1YH8riuBLipcQ==
X-Received: by 2002:a05:6102:3013:: with SMTP id s19mr583285vsa.2.1603172095420;
        Mon, 19 Oct 2020 22:34:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:24d7:: with SMTP id k23ls38204uan.5.gmail; Mon, 19 Oct
 2020 22:34:54 -0700 (PDT)
X-Received: by 2002:a9f:24e8:: with SMTP id 95mr459477uar.12.1603172094877;
        Mon, 19 Oct 2020 22:34:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603172094; cv=none;
        d=google.com; s=arc-20160816;
        b=GBewGYAsve2ZEaOKf/K0TDCXLA9vItUzXdCQQ+MMdlxhp/qcfI1NPclctGGCyby8l6
         bsSVldZWXinZk6cPZriRUV1EtHq55qXxrTgrtV0sklRYEjfU+KOtq7K/zllN9o9S55wB
         8TNSwyybmR188NhgJsV4CjEb+G+7HEe87oXQ3HEcNj4+4pMSZcuhNtGBqValFt2r1WCT
         pXSWNCsKPKS+SqzFUyLdPy3lFYnVaq8CaUugUjYYuKx7mlCU/TumNXnUxnT4rcP2dkGG
         toWRG6AKhVR3mf+9Acr61KN9CX9xjVBmgUOWxUdGmo/VPIyCk2QjMFmddzZyL5qeyayD
         VBvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=s42cP9f/U3GYa0s71Z6i/ug0NaSJrPca2FKEkcjzEig=;
        b=Ilw97CX0/uuV7ttYf1iBbO2W9Hw5KAzJgsXRENLWZYMIWI7XnnQT2kcEZT8KLh6jRl
         CXTIpG2E/CV5wAEnsVhaLdrMba8opCi7YStxCfIkXl6j2L/PsB/vbo8vtlSakIULxEx8
         MRCMdUVsO86Msrs07D3+i5qUXurrg2o/s2Ww305Iuk3wI2Endo1s3gHiKGJBJDOocnCM
         zpo1L/jm8Uf3uMPhPJAjCyh2DKBZbausreuXVKXZk8UjkXioPdkp/0AxJKURQPHjTpNx
         1EI+/xK6YotnK9A32nf/B8ceC/Funx9S3iGriBblUt5DDvD5y0bkyXoYiLzGSciDD4S6
         ZKwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lSWQdfR8;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id e21si49147vsj.2.2020.10.19.22.34.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Oct 2020 22:34:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id x20so602731qkn.1
        for <kasan-dev@googlegroups.com>; Mon, 19 Oct 2020 22:34:54 -0700 (PDT)
X-Received: by 2002:a05:620a:1657:: with SMTP id c23mr1269155qko.231.1603172094152;
 Mon, 19 Oct 2020 22:34:54 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1602708025.git.andreyknvl@google.com> <CANpmjNOV90-eZyX9wjsahBkzCFMtm=Y0KtLn_VLDXVO_ehsR1g@mail.gmail.com>
 <CAAeHK+zOaGJbG0HbVRHrYv8yNmPV0Anf5hvDGcHoZVZ2bF+LBg@mail.gmail.com>
 <CANpmjNPvx4oozqSf9ZXN8FhZia03Y0Ar0twrogkfoxTekHx39A@mail.gmail.com>
 <CAAeHK+yuUJFbQBCPyp7S+hVMzBM0m=tgrWLMCskELF6SXHXimw@mail.gmail.com> <CAN=P9pjxptTQyvZQg7Z9XA50kFfRBc=E3iaK-KR14Fqay7Xo-Q@mail.gmail.com>
In-Reply-To: <CAN=P9pjxptTQyvZQg7Z9XA50kFfRBc=E3iaK-KR14Fqay7Xo-Q@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 20 Oct 2020 07:34:42 +0200
Message-ID: <CACT4Y+aw+TwUXkuVsQcSOGTDrMFoWnM-58TvCFfvVSnp6ZP5Sw@mail.gmail.com>
Subject: Re: [PATCH RFC 0/8] kasan: hardware tag-based mode for production use
 on arm64
To: Kostya Serebryany <kcc@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>, Serban Constantinescu <serbanc@google.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Alexander Potapenko <glider@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=lSWQdfR8;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744
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

On Tue, Oct 20, 2020 at 12:51 AM Kostya Serebryany <kcc@google.com> wrote:
>
> Hi,
> I would like to hear opinions from others in CC on these choices:
> * Production use of In-kernel MTE should be based on stripped-down
> KASAN, or implemented independently?

Andrey, what are the fundamental consequences of basing MTE on KASAN?
I would assume that there are none as we can change KASAN code and
special case some code paths as necessary.

> * Should we aim at a single boot-time flag (with several values) or
> for several independent flags (OFF/SYNC/ASYNC, Stack traces on/off)

We won't be able to answer this question for several years until we
have actual hardware/users...
It's definitely safer to aim at multiple options. I would reuse the fs
opt parsing code as we seem to have lots of potential things to
configure so that we can do:
kasan_options=quarantine=off,fault=panic,trap=async

I am also always confused by the term "debug" when configuring the
kernel. In some cases it's for debugging of the subsystem (for
developers of KASAN), in some cases it adds additional checks to catch
misuses of the subsystem. in some - it just adds more debugging output
on console. And in this case it's actually neither of these. But I am
not sure what's a better name ("full"?). Even if we split options into
multiple, we still can have some kind of presents that just flip all
other options into reasonable values.



> Andrey, please give us some idea of the CPU and RAM overheads other
> than those coming from MTE
> * stack trace collection and storage
> * adding redzones to every allocation - not strictly needed for MTE,
> but convenient to store the stack trace IDs.
>
> Andrey: with production MTE we should not be using quarantine, which
> means storing the stack trace IDs
> in the deallocated memory doesn't provide good report quality.
> We may need to consider another approach, e.g. the one used in HWASAN
> (separate ring buffer, per thread or per core)
>
> --kcc
>
>
> On Fri, Oct 16, 2020 at 8:52 AM Andrey Konovalov <andreyknvl@google.com> wrote:
> >
> > On Fri, Oct 16, 2020 at 3:31 PM Marco Elver <elver@google.com> wrote:
> > >
> > > On Fri, 16 Oct 2020 at 15:17, 'Andrey Konovalov' via kasan-dev
> > > <kasan-dev@googlegroups.com> wrote:
> > > [...]
> > > > > > The intention with this kind of a high level switch is to hide the
> > > > > > implementation details. Arguably, we could add multiple switches that allow
> > > > > > to separately control each KASAN or MTE feature, but I'm not sure there's
> > > > > > much value in that.
> > > > > >
> > > > > > Does this make sense? Any preference regarding the name of the parameter
> > > > > > and its values?
> > > > >
> > > > > KASAN itself used to be a debugging tool only. So introducing an "on"
> > > > > mode which no longer follows this convention may be confusing.
> > > >
> > > > Yeah, perhaps "on" is not the best name here.
> > > >
> > > > > Instead, maybe the following might be less confusing:
> > > > >
> > > > > "full" - current "debug", normal KASAN, all debugging help available.
> > > > > "opt" - current "on", optimized mode for production.
> > > >
> > > > How about "prod" here?
> > >
> > > SGTM.
> > >
> > > [...]
> > > >
> > > > > > Should we somehow control whether to panic the kernel on a tag fault?
> > > > > > Another boot time parameter perhaps?
> > > > >
> > > > > It already respects panic_on_warn, correct?
> > > >
> > > > Yes, but Android is unlikely to enable panic_on_warn as they have
> > > > warnings happening all over. AFAIR Pixel 3/4 kernels actually have a
> > > > custom patch that enables kernel panic for KASAN crashes specifically
> > > > (even though they don't obviously use KASAN in production), and I
> > > > think it's better to provide a similar facility upstream. Maybe call
> > > > it panic_on_kasan or something?
> > >
> > > Best would be if kasan= can take another option, e.g.
> > > "kasan=prod,panic". I think you can change the strcmp() to a
> > > str_has_prefix() for the checks for full/prod/on/off, and then check
> > > if what comes after it is ",panic".
> > >
> > > Thanks,
> > > -- Marco
> >
> > CC Kostya and Serban.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Baw%2BTwUXkuVsQcSOGTDrMFoWnM-58TvCFfvVSnp6ZP5Sw%40mail.gmail.com.
