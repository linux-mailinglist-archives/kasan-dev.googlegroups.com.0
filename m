Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJNE6P4QKGQEAQ7BUWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 14F532496F6
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Aug 2020 09:17:59 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id s3sf7779807plq.22
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Aug 2020 00:17:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597821477; cv=pass;
        d=google.com; s=arc-20160816;
        b=rMo1MaWKaekBvqAyZjHHDoXWDFZJkMtMb2MItmlH4IcPdEc8WWEf+g33xubDDK+Y+5
         OEk97w9OfIUvdru8FvjnL32Eu4MmJgfxMOqUpJ8HuFJvWsPqD75Gh/gUsS9TlVsGCEVm
         Ruajei1UClMlvNU3IPJ5XMFeMcmvvF92NO+hujKMYMZ+qEOYpsc9OwzkF08orfsp1EzT
         t0eBpP7cPixRLCyr+gNBXi8Zg8vv336WMGpUGfet6NHAMC5AF2fLE84OPuIS/2DoT9iZ
         ghh8Eom0QOyLAOjb9mZN6pMqW4H3afsrE7xv77QMPS9PEZY8VGqErKQEP4nq/slFCFFF
         ZE2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=r4dHdwwDBVTiIPNBMhS9yB3K4+DC696+/ptPVazFxLo=;
        b=tNa6vbXUIM5xWqppbU0kiox1F/nRMl3p/GWm4k79Fjy2K+WQWeNZmIqJkQ2W4MRwoX
         S6nyn8tKwv9fQvXUt5f/PNwehZAPTcaF+D28+jJ3jP1AKpGyPsXwm9GArl0MmnDCAGSh
         c3EDZqYSsywHSz8/KBklLfxLjVsS8HNF7k8sxhTX+qYLbnfpoGjDXVb2rBIPQNyUG2bA
         xpPhV1AVvwpGT2FPQtDZ4nET+RrwIPtwAudMZ0+eQg6ukYkUVsiYUiQA0b8C+Cn2sbnb
         LdlcXf94/qK+j1gKzgtupLSk2jJDTBvPFVSsFDjis8rPqMwuRlAaxStHkXPe1L+fjQop
         6IeQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=de1Fn2AF;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r4dHdwwDBVTiIPNBMhS9yB3K4+DC696+/ptPVazFxLo=;
        b=kjYIV9UGxJNPPE4sM7ek/hsArOxBiwdGrFUq29aZmxEbPtUnx6Dx3Ah2AaN2ir67C7
         T1aVvW2mSaocUeSs/u1K8IU0pO4cn2cZB32klQC+kl2ZcvfaxG7022SKUYSi3WEwI9zf
         tdu+VvxEHr8BAGNQyhagIscPxMuxFZyZbifby3fs2Dh7rwj69zby5Xf8EL0f8Xn6wrp4
         5irdPT2/rLsyOTyWe96vVqBpNL7iEDI6+buSE3Q4Ap1MKlYqXwv8zDWfPo7FwJM9qZHU
         bS/UIYuh6NLrsNWVtBN7EzxcceXpeBuV5Vt/t8H3l7V/Ifpkvyht70kmZyECDZ2EWDVt
         6CNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r4dHdwwDBVTiIPNBMhS9yB3K4+DC696+/ptPVazFxLo=;
        b=bEtDQbuB23fF0fC7vsg6tKTfWNZt35nrQ+HdORn7RkiO10xuvx7m2kHFnfNgxyw3fm
         iWKFrpufHKJcFxyQ/9zmG8087pIS66uclobiLD9iFUwjgX9X6aSh93taQihrrZYH/qDe
         uzoB/ncf8o4/12VgG1ySkpedHSo1Qq+2n6ykH+Fa83bqslLPzPe0Zub71gAxx2uoZekY
         kZk0WlPweJb7MINDBL3ks6BY8AqsTj3SmlzTpYEd5egTMUMbSxmExfAugTmt8sXtaRvd
         kI/ScljrNw3m/eaxA2iKXR0iyvmRYSJV1AvszHkd7OxnzJMbn22wYidq/7ec+MazVNNR
         wUvQ==
X-Gm-Message-State: AOAM533hWSPFDzKzc5ASCtlk4QOEtT9dBH8B2p59eMd/ZAdMYnSa0Jqs
	Vt+OYotbTFlfgTHUiZa93gQ=
X-Google-Smtp-Source: ABdhPJwIh/LcAtAunzV4AXYDvhZRmDrLVTLilj0Xn2cK6SFOGhf0FanqEMaKFcW+GjPU7aPEN7+H0w==
X-Received: by 2002:a63:b70c:: with SMTP id t12mr15632439pgf.178.1597821477571;
        Wed, 19 Aug 2020 00:17:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:525b:: with SMTP id s27ls6432342pgl.11.gmail; Wed, 19
 Aug 2020 00:17:57 -0700 (PDT)
X-Received: by 2002:a62:1803:: with SMTP id 3mr18995577pfy.198.1597821477062;
        Wed, 19 Aug 2020 00:17:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597821477; cv=none;
        d=google.com; s=arc-20160816;
        b=Z5uRD9MHW04VwnPnfORolC8DVMCY9CKJyAe/q16Z3EUJAtbz5p3W+09GCOWDuXdF8+
         1pbNNiaG37+Ot6t1X7/8WP/OKWBzx7zRYQgLmpKfWVGfdci9W4WU5r6mlNhA1MGZ1cTN
         Q7ZpJ6O3Y9p504doQ5KidIMoBOgBZxKf7xyetJ+fSmo8lnxBt6UKwAEojescu9BKxVNP
         DtFZJDYOByh52+7BwYte8+s0FmxPI6Ip9+SIfi0orM7qmW6oUGmBnzb3rjwA1fVnhskM
         uqxTG/ORQLJz3pVUb5VK7kFiNeRDmz7B++LPQ+O8K0CAZNsVy8jI9piD90PR39T2PWO+
         jXCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=411CfGuuJOCR4DffLLDxtlWEILtmDE8ph6hY4tDWTjc=;
        b=xuyhEeJC7QhH8QuY7egGOyjY/aona06QSTYBzUUvcr1zdciG6AHx4vk9FeYLlGsGB0
         hNpyciK2KmYl8boxD8bUQu+RK6JdArpn4qCk5QLIDUbH6OeVVKm2iDpDKa6mG5rnMEFY
         l69tzc/ON+UlbGOH8T315c4Tl1cAy3knP6whqR6I/NqZzEA5LKTTbr8eU9wHiCW1w+NQ
         iNTlnb2WZ8XEP98Inr0LSQPwvJUMwW4/YgLMZgcY1iEIqPJWnGJEM2GTU4fOBCyO0Ivn
         3hEErH+KqnCDujAyjMVN20SWHW2y0bAdZnTWMbEoefaaVa3Wlj+AITYu902PPQF3rqPX
         u73Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=de1Fn2AF;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x243.google.com (mail-oi1-x243.google.com. [2607:f8b0:4864:20::243])
        by gmr-mx.google.com with ESMTPS id jx18si115753pjb.1.2020.08.19.00.17.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Aug 2020 00:17:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) client-ip=2607:f8b0:4864:20::243;
Received: by mail-oi1-x243.google.com with SMTP id u63so20206868oie.5
        for <kasan-dev@googlegroups.com>; Wed, 19 Aug 2020 00:17:57 -0700 (PDT)
X-Received: by 2002:aca:d4d5:: with SMTP id l204mr2477803oig.70.1597821476108;
 Wed, 19 Aug 2020 00:17:56 -0700 (PDT)
MIME-Version: 1.0
References: <CAJSYYSUZFTWakvGWVuw+UYdMNs40zCSQt=mszp4H=on4YaZsnA@mail.gmail.com>
 <CACT4Y+bLNzbhkJi10v4pqffaRjTsPTwNe+RmB1cjgqSdbHbGaA@mail.gmail.com>
In-Reply-To: <CACT4Y+bLNzbhkJi10v4pqffaRjTsPTwNe+RmB1cjgqSdbHbGaA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 19 Aug 2020 09:17:44 +0200
Message-ID: <CANpmjNPEVm9A6+ByZmzae6i=jJOjiH+g6LCrgGdB-JEdB+8c_g@mail.gmail.com>
Subject: Re: Hi ! I have a question regarding the CONFIG_KASAN option.
To: Dmitry Vyukov <dvyukov@google.com>
Cc: V4bel <yhajug0012@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=de1Fn2AF;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as
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

On Wed, 19 Aug 2020 at 08:59, 'Dmitry Vyukov' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
> On Tue, Aug 18, 2020 at 9:03 PM V4bel <yhajug0012@gmail.com> wrote:
> >
> > After downloading the 5.8 version of the Linux kernel source from
> > here, I checked the .config file after doing `make defconfig` and
> > found that there was no KASAN_CONFIG option.
> >
> > These were the only options associated with KASAN :
> > ---
> > 4524 CONFIG_HAVE_ARCH_KASAN=y
> > 4525 CONFIG_HAVE_ARCH_KASAN_VMALLOC=y
> > 4526 CONFIG_CC_HAS_KASAN_GENERIC=y
> > 4527 CONFIG_KASAN_STACK=1
> > 4528 # end of Memory Debugging
> > ---

You seem to be missing CONFIG_CC_HAS_WORKING_NOSANITIZE_ADDRESS, which
means your compiler is too old. Please upgrade to at least GCC 8.3 or
later.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPEVm9A6%2BByZmzae6i%3DjJOjiH%2Bg6LCrgGdB-JEdB%2B8c_g%40mail.gmail.com.
