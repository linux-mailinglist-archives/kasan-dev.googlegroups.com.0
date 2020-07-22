Return-Path: <kasan-dev+bncBC7OBJGL2MHBBY62374AKGQEBNA6YVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 4CF38229259
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Jul 2020 09:40:20 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id p22sf1422290ybg.21
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Jul 2020 00:40:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595403619; cv=pass;
        d=google.com; s=arc-20160816;
        b=DjFX7Wrk+ou0AI+eIwXjrlFJrs2lGDgwnOnb33CHgv5lnWQCmiSIcG7dmjbMfaFGyw
         VxGmNruBVxGBoQiIhFc13ViCdULozgzIm78rLxR+y7bd0pKiTQ5WuHNVLdva4LpGowfB
         8nOnNv0WchzsULhAKcDozVBywub8ZMVfRIoi8mArrxH0vPzjOr7eMlRQ0NY+MgM8xK9V
         g57MlhGGb8YfjKPrAdrE6wKnaFdiQG+VKNhVmhU4DwNB7v3W4mEp6Tluxnq43MeuJWBK
         lv71yC+mUjTvw7DhfcWGqVKLB1ec2EHabooJVqBy6HkAsV/Gr62KZl2APIZ6fHV4kUiD
         z1uA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=JogPGREyapAb2xUNiYCK92PnbhlW9L71G+VvfHaeTLQ=;
        b=fdOTS9GKBQex+tnpHAI9zh9mhTkfHdj6yB3vii+rm/aXm8B+mrz8cENwC32KEWqomt
         erwYiYzuMJg9oBBbUMXpSmtuUcs2YhjmaSDGoY9i24S2yqPbTD48nrDN9aRQZnH411Xi
         J84qrFpe20EQPEV7vU+RwMIkU+EOjmtKpMdjzZYlsI+PHKmyUD1y1oha9k2N5B+JQ4Tj
         3kViUeYWGLfBV2lk6nsiV78s8JDWwUHeTVxDr+/pOCzvhuIPjDqFdUKDiuq9383bORT3
         xO/+f/Np2YPjg8IFMUvGfgqWJNy65doypAVqEnfkxfcvPCbs7pjgZyNQsV3rDPjQrVYh
         P2cg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="A5/BRShw";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JogPGREyapAb2xUNiYCK92PnbhlW9L71G+VvfHaeTLQ=;
        b=XFNR821/9SxBV2IILSkdGK9aCp3X45iOIYjbzQrxiMAnPldD8oq+dheQEuSWZMkYg8
         6FOVLM7EdfiHZpv/n0V7sgLuQ8acB1FEqqMuexBY0yHtvBqghYUhbyy+0pMXF5YVuNpA
         k6dvm9oU8Tp6R4JEkyBOtmmp4Cb/A8a7A5biMAyAZo6NXlmadPEPz44tZDq6U1rKenhD
         ADilpmqEKNImiBrV1E0OCTuAykSyh+XB5HD52tj03HbLX91mNOOPJySMonpG+fEO8meG
         DEZiJY0OFXkl2aZjwnQeEZ9fhKJ+kKoy9PQvLENz24yQ1ebxRdxkLLKcsJuzNSypa1f7
         NeOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JogPGREyapAb2xUNiYCK92PnbhlW9L71G+VvfHaeTLQ=;
        b=bhC3LeASjzqNz3nCPSH4E6cdCNbYQxPZtGnMtWsM1c338/HC9DxvQ/atd1K837VYeb
         PhTVdJlpjnIm9Iaazghjo/YQ85a55cJR+YJxawGuGOoXElAhReljKwf7OHTPDDJtFRIt
         kBonvadaThZX7D7uHr8BPWYoRHLaydZCzMHr8q6Wc47z6Axjalasjwtq8pUOKT+RNu25
         yuiWC4JJJeeQD02henWL4ezsU7E458yoSXZKdGq2EQkVmwPbHHglt6ig8jPIwV/oHXo4
         m2w3srYWwZlvJgJuxPm+6SlfDyzMyEVeFzUIhsHRLw6zSkngRlkUfSj9WAWXgigDOR5l
         60BQ==
X-Gm-Message-State: AOAM532I9JiR+IOhO6huOoMCLRvJO6iraDCuuJXSXXGSiYv9+TKyMI0D
	BVfCKyvNBa9jn4Awc/dSS7Y=
X-Google-Smtp-Source: ABdhPJxcfJMgYCmENAEbeQPpERiVN0xfsYcpM4oc8s/WOURwxpSZ9J0b1uiqFyQZWvtYrnoMea7Cxg==
X-Received: by 2002:a25:c711:: with SMTP id w17mr51185355ybe.109.1595403619313;
        Wed, 22 Jul 2020 00:40:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:aa48:: with SMTP id s66ls428749ybi.3.gmail; Wed, 22 Jul
 2020 00:40:18 -0700 (PDT)
X-Received: by 2002:a25:31d4:: with SMTP id x203mr48355445ybx.396.1595403618798;
        Wed, 22 Jul 2020 00:40:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595403618; cv=none;
        d=google.com; s=arc-20160816;
        b=y4rcK0+SPlOcBbr7BYtu4c8mhmcl9nezfCu5n9LH1hEX3ok+ZCvInkLMMQ/tts9KNm
         lj07hZxZuKcYy7HDRSe6KLyo+aMmceGlY1WaApBguKUJRKFvxiG78HBTZ+lbqzLUuCxg
         092IWVOaU4VT8xXfVPne8NoRk7M4jYVLAIaBwRSJLBdl0U0yPgyqagwxuW06lccuI1YS
         qoE2rRi4JQuFw24UtON3Ibg5sSM554w8sMq3NhLsn959pB4rwYdpQUfG//LDsVKkAH9h
         WYwhT4tNkdMSYOyvHCdY88alnK+5ul/DqJSNKrkx7sCjjCbQju/Ni2y0AwHcARVq4zi5
         bomQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=F/8qLitSrAd9/TNuQJAYnYdsR+JtleEYUya6tVsA5jU=;
        b=LXuMGASvbGfKViFEhikBPNeAoquTld+ZLYc+hDrvMDO5PXFOcy+KoTlFh4dCIibNlN
         eXexNn0LtRGLuCbXJXrhhG9Jadw52gHSwLKtmRvgQQcV6HttXC1us7MIBam7nDO6w+QG
         ddxNCbY3O0rmv882HKlaAsjm1dTTrOBwv6Pcl37PB0ewrxr1i5ocIAXfQIejzPEiGUb0
         JmT6YQ0WLsKrD/2J6MPEiyFA2vHDxIQCZNJxIpepQN0liVwOM3X7LSuNl/x1+4E1rye8
         B2e5ICg2F6JTTjEIr1KF6DC77a7V5tVZqUH3QAsf1LlmfuRtsR76rXcgoZa1DYTCkJFO
         Fp9Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="A5/BRShw";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id l10si822383ybt.5.2020.07.22.00.40.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 22 Jul 2020 00:40:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id 5so1080477oty.11
        for <kasan-dev@googlegroups.com>; Wed, 22 Jul 2020 00:40:18 -0700 (PDT)
X-Received: by 2002:a9d:6190:: with SMTP id g16mr29172935otk.233.1595403618123;
 Wed, 22 Jul 2020 00:40:18 -0700 (PDT)
MIME-Version: 1.0
References: <202007211404.0DD27D0C@keescook> <CACT4Y+bpDUa6bzP1P6apPDOFM5h+PkMfoauBnxe7uByJovZRdA@mail.gmail.com>
In-Reply-To: <CACT4Y+bpDUa6bzP1P6apPDOFM5h+PkMfoauBnxe7uByJovZRdA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 22 Jul 2020 09:40:06 +0200
Message-ID: <CANpmjNO0HAqT6L+rnn7wu528yNzwb-c2Xj81KN9RpZ2+X=QmNQ@mail.gmail.com>
Subject: Re: alloc/free tracking without "heavy" instrumentation?
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Kees Cook <keescook@chromium.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="A5/BRShw";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as
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

On Wed, 22 Jul 2020 at 07:47, 'Dmitry Vyukov' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> On Tue, Jul 21, 2020 at 11:11 PM Kees Cook <keescook@chromium.org> wrote:
> >
> > Hi,
> >
> > Is there a way to enable KASAN's slab alloc/free tracking (or something
> > similar) without turning on all the "slow" instrumentation?
> >
> > Specifically, I have a corruption that is due to a race, but using KASAN
> > to see it doesn't work because the race stops happening. However, I have
> > another much cheaper and specific way to determine when the corruption
> > happens and I'd like to see what thread called kfree() on an address. I
> > didn't find any other existing tools that would track that kind of thing
> > besides KASAN...
>
> Hi Kees,
>
> Such mode does not exist, but if you are interested in a one-off thing
> that it should not be hard to do.
> You can disable the heavy instrumentation by finding the Makefile that
> adds -fsanitize=kernel-address flag and removing the flag.
> Then you can eliminate most of the remaining overhead by commenting
> out bodies of kasan_poison_shadow, kasan_unpoison_shadow,
> memory_is_poisoned*, check_memory_region* function in mm/kasan/*.c.
> That will remain is mostly what you need: heap object metainfo and
> quarantine. Call print_address_description when you need the info.

In addition, as an experiment, I'd be curious if KCSAN could point out
the race. There is a patch in -next to check racy UAF by instrumenting
kfree: https://lore.kernel.org/linux-mm/20200623072653.114563-1-elver@google.com/

Once booted before you run the reproducer, you could make KCSAN more
aggressive if it's a very elusive race:
- decrease: /sys/module/kcsan/parameters/skip_watch
- increase: /sys/module/kcsan/parameters/udelay_*

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO0HAqT6L%2Brnn7wu528yNzwb-c2Xj81KN9RpZ2%2BX%3DQmNQ%40mail.gmail.com.
