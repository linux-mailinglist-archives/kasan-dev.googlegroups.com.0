Return-Path: <kasan-dev+bncBCMIZB7QWENRBNMYWH2AKGQE4EZ4DBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id AF9D31A0A67
	for <lists+kasan-dev@lfdr.de>; Tue,  7 Apr 2020 11:47:34 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id x189sf2013996pfd.6
        for <lists+kasan-dev@lfdr.de>; Tue, 07 Apr 2020 02:47:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586252853; cv=pass;
        d=google.com; s=arc-20160816;
        b=bJ4P3bhlnqAkQ6PZtIxHY2Ecx2cOm1lhDRMhohcCkPmKieRJF8j4Pf4hRK/rR6S+MM
         iX77OSkrlhaEBTuYqcdYEPtaBClsT5jabwlwP9/pydIuJz6PCMGG4ZFQNvpEYXgPGqUe
         u/VkAOHwwwNH/TR2yia/WLItbYgRuqmbC65T1sOE6CPnPC/US7ixePBU9P2n8ov+Jmy1
         evFMBNBE7YlI8RfdQtzajLJjZNQsGC7kM0sA09Fyx9M4a7vYO5HiVjFUcZqhqg2FL9RA
         jZTriPbYEMNhrw04fsuBzNb36e+PfCTbb0EglLHNCYuTEA3LvbYp9Mb1o2uq5Y7gPIM4
         f13w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=c6C/nG9Zwsq1tkIgT/3hLAQhpBWWZxwlATAt3rXMo8M=;
        b=hucst0Wyfz7ONsXRbeS5t/2HfNCx7HRF6mOn9bNlB5n2luoiHYtupQtpz4HHuV1MSR
         vEi9G4RpoiETQevliTA4mPHgZYu82GlAjrA0uLI1pTkJ4HxM7niR0RHwSmhQhbwQrnRu
         l6Er7NQhtsyYEYnMpHjLQMOvJCIFK97lCi6DPNq+7U2+waRGbP1yKVGYc2vXaR4ouoWO
         HVFRHVrrLaNKuAceHVathiRzcpBgfWuJXtBbfOMEYw20ve/Ur5vpt/yr0qVnHISDMzAY
         eL/wnkkL/yKvkkadM+8xf9BMy70OSv3+VGEUGEKMCitDv3KqX9F36JRBnZ3B4yXYkuJt
         2gnw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ciw7o9v1;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=c6C/nG9Zwsq1tkIgT/3hLAQhpBWWZxwlATAt3rXMo8M=;
        b=LcNM8qPA0DUEnOB3/u9q6pQRk2dtT6Z5mfa/NZGf3/RKMA/nIf6MHoJsG4gZwnPpN+
         3Z9HFNwEe6ZX3rngDC+k+gmVEBlZN9FTY3W6gBKNTxeasxiN+8LOGB4Rh/KooKMHzQpd
         qqppOG56Zek2wBIJfW9O39v72XNo8epB1FS9e4h6oiKVm5WngAxZIQZ5/yN7fDKvp16c
         oyPqs+SWarLngXpd5keDEdvmjKNVhWCWioKqblXVUt3/nkC2g4wht+/oq2W0DpzsaFiV
         jOcDkdmMay4F2UF1AkUcj9LfKSxue1GLN+P7Kpz6QBy7ya6bA8DsOuasOerpkkPigX7u
         R+Gw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=c6C/nG9Zwsq1tkIgT/3hLAQhpBWWZxwlATAt3rXMo8M=;
        b=iJe2KPu2xN+2WDQ28iHf4knzw2EboZFUnGeWzeajHetkcazQ/5nTtlP/5Kad99g7MO
         7ofVFYpNMCtsWj/0bPrZfRNkedUFtF/ooa0V4HH+DB0qXBlOXykr9/3SL5+0K9Yef5xM
         v3AN4ZvGw+GOoOTgqVINBQ2ZSMwOXEifOz15PyRYcOySkJi+lE4tG1lRQ4dNvGEGFl5F
         R9IVL7yXJgZjBNEBQsih+fTiQRmGrocukCMX2MAx6p6cDnoAYY6vWvKCWwZY+iCD3yRU
         ti8Fpqb8/CxINS2J90mfbs2VgGscJEGrzEWhVxSGBH2+zIkCGH532ZIHt/HYtlfHfhPC
         8TUQ==
X-Gm-Message-State: AGi0PubT9fhW4fAeahRxPz1+zCchCX+DWTzkhjauvnObf3IuOcia78P8
	AgtHrGOnGskkhHfbI8Sj904=
X-Google-Smtp-Source: APiQypJrKE5nCLqYD6v5UE0bVD2mZ6p1c5YYgCHH8Nff9VQMXDwOhjCfRZaDDE468bRl/BYUJkbmcg==
X-Received: by 2002:a62:7c82:: with SMTP id x124mr1844198pfc.280.1586252853344;
        Tue, 07 Apr 2020 02:47:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:982:: with SMTP id 2ls2172419pjo.1.gmail; Tue, 07
 Apr 2020 02:47:32 -0700 (PDT)
X-Received: by 2002:a17:90a:1b42:: with SMTP id q60mr1806291pjq.84.1586252852509;
        Tue, 07 Apr 2020 02:47:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586252852; cv=none;
        d=google.com; s=arc-20160816;
        b=SJL75EopQOvaCmRakh/1Bxq234sdjfO/RQSESVHUtkbr0upMgnPQzTASDMIHyi0GQf
         rfj9dtdzZWSvGRPhNMJfX8Y3oPISxQpip+FJVln+pk6daJHQnk90MSVft40J5P6pGR/A
         n48A13dmEBThRvtwyDhQ68qDLhO5nd6/rpqm14DgOn/ePc38eoUn7xiWgwQbNrR2QmHS
         wJ9/727vi3WeGffUtjqwuiEr6hTzO67asjvVFE58/+gYGqGFJzNvrl6dP23zn1QFRYaG
         UYJTf6O3CVgsC4M1l4dEr3LFTbe98e7Lq+Q7O5FlXM4R5IvXzcYNiB8lys/vxa9YReFp
         MmVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GSqWDHGUS+esGVjkJZ+Ya1Ky6uDzAiUK5oOJLdH+PYU=;
        b=VBnXNVVjMcFPdBge+re5cogqQ5P9BCscCqCrZnGScYhT5+JxUiyuU3faD/8HL8ayC9
         TxuGF4RXDMgrj1Yo7yFLI2KtPJQghYZwAHKKgWf9nNXH1T4qiDJLY6zXvzqQ4CGmE9Ds
         jPNCG+bR07ENnYAIIwZSLG1p66OarbvrJkMb8aVhEYFBfYjaER6YdM85rV6ZNyA7ZYFx
         GhqtehXs3w1KsRbm+hCkTLUus+jTLHu6z6eHBiMkeAsPFugSRE6+zzRytJ9wU0qSTlhx
         Xls/lXTKrTKnaSWfadM52bh6+HjxHTnGuzEDDz1bLIByecJBJ0yByMdBuUviyAwi6un9
         dpBw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ciw7o9v1;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id y5si107548plr.4.2020.04.07.02.47.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 07 Apr 2020 02:47:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id o18so942542qko.12
        for <kasan-dev@googlegroups.com>; Tue, 07 Apr 2020 02:47:32 -0700 (PDT)
X-Received: by 2002:a05:620a:110e:: with SMTP id o14mr1233586qkk.256.1586252851227;
 Tue, 07 Apr 2020 02:47:31 -0700 (PDT)
MIME-Version: 1.0
References: <78d7f888-7960-433f-9807-d703e57002bf@googlegroups.com>
 <CACT4Y+ZvX1Cs1SJppVfLXyV9F4hra=JdBaQCqBTeFX3++f48kQ@mail.gmail.com>
 <CACT4Y+abK5o34h_rks7HMivmVigTG3CM9X93MOt9d7B6dxY_9w@mail.gmail.com> <CABDgRhumwQxxpQDmGq6=zf9Xi4DY4tM=_kOdbf=SFvfPYMNYrQ@mail.gmail.com>
In-Reply-To: <CABDgRhumwQxxpQDmGq6=zf9Xi4DY4tM=_kOdbf=SFvfPYMNYrQ@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 7 Apr 2020 11:47:19 +0200
Message-ID: <CACT4Y+aqy0MgJntoKPcjoxnyH3w4n0UW5yxFJX-prm-Zgqn+0g@mail.gmail.com>
Subject: Re: [libfuzzer] Linker fails on finding Symbols on (Samsung) Android
 Kernel Build
To: Johannes Wagner <ickyphuz@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ciw7o9v1;       spf=pass
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

On Tue, Apr 7, 2020 at 11:09 AM Johannes Wagner <ickyphuz@gmail.com> wrote:
>
> Thanks for your reply Dmitry,
>
> i'll try the old compiler toolchain first.
>
> Are there any pointers for the KASAN backporting part
> or Stackinstrumentation-disable besides  maybe mailing list archives?
>
> Thanks a lot!

+kasan-dev, please keep the mailing list in CC

For backports 'git log --oneline mm/kasan' is usually useful.
Re stack instrumentation is the compiler flag that
CONFIG_KASAN_STACK=1 enables/disables.

> On Tue, Apr 7, 2020, 10:16 Dmitry Vyukov <dvyukov@google.com> wrote:
>>
>> On Tue, Apr 7, 2020 at 10:14 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>> >
>> > On Mon, Apr 6, 2020 at 10:48 PM jrw <ickyphuz@gmail.com> wrote:
>> > >
>> > > HI,
>> > >
>> > > i try to build a Samsung Kernel with KASAN enabled but have problems getting it compiled.
>> > > how would you proceed from there to make it a successfull build?
>> > > I tried several cross compilers but i always end up with the same errors.
>> > >
>> > > -------------------cut-------------------------------------
>> > > /home/kerneldev/kernel/net/core/rtnetlink.c:2557: undefined reference to `__asan_alloca_poison'
>> > > /home/kerneldev/kernel/net/core/rtnetlink.c:2558: undefined reference to `__asan_alloca_poison'
>> > > /home/kerneldev/kernel/net/core/rtnetlink.c:2745: undefined reference to `__asan_allocas_unpoison'
>> > > /home/kerneldev/kernel/net/core/rtnetlink.c:2745: undefined reference to `__asan_allocas_unpoison'
>> > > /home/kerneldev/kernel/net/core/rtnetlink.c:2746: undefined reference to `__asan_allocas_unpoison'
>> > > net/netfilter/nfnetlink.o: In function `nfnetlink_rcv_msg':
>> > > /home/kerneldev/kernel/net/netfilter/nfnetlink.c:190: undefined reference to `__asan_alloca_poison'
>> > > /home/kerneldev/kernel/net/netfilter/nfnetlink.c:224: undefined reference to `__asan_allocas_unpoison'
>> > > /home/kerneldev/kernel/net/netfilter/nfnetlink.c:224: undefined reference to `__asan_allocas_unpoison'
>> > > /home/kerneldev/kernel/net/netfilter/nfnetlink.c:225: undefined reference to `__asan_allocas_unpoison'
>> > > net/netfilter/nfnetlink.o: In function `nfnetlink_rcv_batch':
>> > > /home/kerneldev/kernel/net/netfilter/nfnetlink.c:407: undefined reference to `__asan_allocas_unpoison'
>> > > /home/kerneldev/kernel/net/netfilter/nfnetlink.c:384: undefined reference to `__asan_alloca_poison'
>> > > /home/kerneldev/kernel/net/netfilter/nfnetlink.c:454: undefined reference to `__asan_allocas_unpoison'
>> > > net/bluetooth/smp.o: In function `aes_cmac':
>> > > /home/kerneldev/kernel/net/bluetooth/smp.c:175: undefined reference to `__asan_alloca_poison'
>> > > /home/kerneldev/kernel/net/bluetooth/smp.c:214: undefined reference to `__asan_allocas_unpoison'
>> > > /home/kerneldev/kernel/net/bluetooth/smp.c:214: undefined reference to `__asan_allocas_unpoison'
>> > > net/wireless/nl80211.o: In function `nl80211_send_wiphy':
>> > > /home/kerneldev/kernel/net/wireless/nl80211.c:1914: undefined reference to `__asan_set_shadow_00'
>> > > -------------------cut-------------------------------------
>> > >
>> > > the only thing i could find was a stackoverflow post [1] but this guy also had no solution to the problem.
>> > >
>> > >
>> > > [1] https://stackoverflow.com/questions/58717275/compiling-aosp-kernel-with-kasan
>> > >
>> > >
>> > > Thanks for any help!
>> >
>> > +kasan-dev  BCC:libfuzzer
>>
>>
>> It looks like you have an old kernel and a new compiler.
>> You either need to backport KASAN patches for stack support, or take
>> an older compiler maybe, or maybe disabling KASAN stack
>> instrumentation will help.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Baqy0MgJntoKPcjoxnyH3w4n0UW5yxFJX-prm-Zgqn%2B0g%40mail.gmail.com.
