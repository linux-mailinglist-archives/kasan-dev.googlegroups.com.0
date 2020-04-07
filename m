Return-Path: <kasan-dev+bncBCMIZB7QWENRBQHNWD2AKGQE2A7UAIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id 905BA1A092B
	for <lists+kasan-dev@lfdr.de>; Tue,  7 Apr 2020 10:16:01 +0200 (CEST)
Received: by mail-qk1-x73c.google.com with SMTP id h186sf2374065qkc.22
        for <lists+kasan-dev@lfdr.de>; Tue, 07 Apr 2020 01:16:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586247360; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ko4l8P2fM286aIsy3TCrdkaHoHCvgk1L0/txuuw9OpQISKU4PxahbbGfxAKcuxdgkx
         FjhuCj5KkU54H/oMM1cjIsgFpERhKTMRCilOqbOOaQdwGcCJhmEKDSFZFvCGdgbSOFtG
         Lc94TXe6ZjRy6xQziXzv2j6wLu672FrKvtVH6mibuIyitAhsl4Nt3rJNT+g/R3ljbRQA
         Obig7pFNY1drH4SUnVbbpIIerX1+fMwD/rCkB1eKjnihyp3AD5mrZAzQX2jonHKd5nB1
         yG8ZJZl7mIH7MCSfs6xwXrnMTln2dlJQRmiO3D2dHSqd3i1ABTBi4tAQwDa/BH3Uwfi0
         ke4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:to:subject:message-id:date
         :from:in-reply-to:references:mime-version:dkim-signature;
        bh=lqS9xlSDFdwP9d1/ry8Axopj0QaapHgy+1cBgDXxuVY=;
        b=Pe+k9mBFAknQebicteJTq3l9fNObwUvyeB7tyhPj1yQf6c27gOar1RCKbYR8wdm7yG
         LUX9oC8ciR96F+skXGeOo5lkWGciRGRn9gBMd3p/24eqtslQznWs5TREIBe8QEoQzxLN
         DVbbwrhLgFAkNEvwLwcPQp4qXCmnhbqH3QIeP1a14CN6kwWStW53Tiy/4qb20Yvo05l5
         WUprSW+jBQEI876HZ7lkj6mGRe6C+EiEHp2eFudhde+18TMe4agZm77RlOwFW911Rz88
         0bqpdMahrN6iuufROiVVHeYTfZAf/UH0LEXhS9xtaSX839dxkp/I8Hs/Rj4Xf7cn2jHu
         OtMw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YkFKvczg;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lqS9xlSDFdwP9d1/ry8Axopj0QaapHgy+1cBgDXxuVY=;
        b=USdjZPmC5eNncHOAKrAQmV+YCc1OFRPFrnQPnPiHUMvlKJMnqfaqxgBxg3+JAiSaR5
         0I/sJ6XrhEP//9MLuZGhZHG1aa6/6u1bmx9Bh/Fe7tCJgn9S/j/XzjYHDDlWoAVtDDb3
         xxyxvSRJTx769IK3ExCQmZLnG/k9OJZ/Wla/3TPtkJ9gxaSknCBxoipybE+E4pLEuzrS
         Z0PcJXiYlmj00F5bJjmtwx4WuLa/Wzv5dHArFBzHjlHeJjtvc88j3D9El7gxH29z/0/7
         q1zrQCrOX5yawC2MN8Jf7WNKNBN9uayGa4uAhio9JiM1JTT0q+BChvSYlmKhys9X1xdc
         PvzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lqS9xlSDFdwP9d1/ry8Axopj0QaapHgy+1cBgDXxuVY=;
        b=MmWeb6AA+g6iNgMyxJVezHKoh2lzrXVGR1KW8shfVi63hBSh8VtfqEHTVNQ2KYX2To
         YKqULnULZCgKEdoE4QflIqFu9wz0w/ogVwYables2GPhYcq8EiUCdkDvnWQG7RQ7j6dj
         ZeAUIhVi0f4hNh6EYZwI8o5U3GsuWx1AQFNuNOMTB8bVZFC+cDckQ48leNjT/DKwKw/2
         PRl0UKGRP6S1uDLeq987OARQpzXcWnggGyO5m4renH2DZNLhPr3atJPU3wk/EdhyGmEs
         XqzSM4mEHzJuD/ub3oyHWUYpu1to14IVUOqwWh28TJ3QzLEIDNj8eAha83CAAXnsjN2K
         6FvA==
X-Gm-Message-State: AGi0PuZd7KAO6nQEP0qemBe87D/+VgIHgVUf9vCzJ9MKToADVgplEJ/r
	jfbjq5uNLGjDpPioGr1vOxc=
X-Google-Smtp-Source: APiQypIpXkBCndP+FaNsrjNrlKnJKq8J9ZIDdt2g1ucj8/zuu+1S4n7T8YyLiQBZqlndtuW2Zo5rcw==
X-Received: by 2002:ac8:fcf:: with SMTP id f15mr1081128qtk.233.1586247360426;
        Tue, 07 Apr 2020 01:16:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:b21d:: with SMTP id x29ls866801qvd.0.gmail; Tue, 07 Apr
 2020 01:16:00 -0700 (PDT)
X-Received: by 2002:a05:6214:941:: with SMTP id dn1mr986324qvb.57.1586247360123;
        Tue, 07 Apr 2020 01:16:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586247360; cv=none;
        d=google.com; s=arc-20160816;
        b=ntBgOtuRU4q/BpglQ9TUULeFq9qnMYxOUgWlxZ1GBTUeLHn7cMVeJEK48PNHoPFc7L
         Lr1twi/NGblsY+ltZBHP6jgUzmShT90gII3dywHEhk0dn+ty/L++jQLh+JYIj1R8+g5T
         r9FCHsP53/60v+vxDRNekzMU01u7gIeM0nj3I874GacCtfCKTXVdNYZcpRh4oyfjDio5
         afghlLrwkjw8W1A2YJrUh9pZKCdjifekduvEE7slSTKON1RGag/5tJ1cN1blF/KfLffH
         EcSXnnFznQpFff8GlGsvduVAkFwq1KW90XZv9GUc4WU5L4ST8wNUJ5EITKmaDv5UiAZc
         tWQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:in-reply-to:references:mime-version
         :dkim-signature;
        bh=zI3nKLNdWJFcXn83kwzvzHijQutvoz1UHNI24r9U0gQ=;
        b=iWRfDjURIQVM2TA2VuvuWEJGDFD6+pIOW8sIyn0aihGfJhglFyUhFI/JdQtoDLTSQu
         ElmTHGpITyz7T+jY5Tc6IwjVem1hJko1CNEVsggGYccsZudRl6tXt51nyq1gZ3OHzLXx
         aTXs1qnup+TUQ4i/8FlG+7TvSAXjuQGjYdp2avqBxB9Je0TDQ+CG9nXdN5c8IsiZU5de
         sBNuOSuLZNSfE8zQIQCXBXgsfHwWWuyYTFDITzvpR9YkfcRrYhyaVvAAKEVhZI9L7K/6
         RfV+pRF9ySdQxz8rvZN+r6F9z0u6+RrfOS+4ijSc2+mylgZTIeNHe7RlbetY/8kbxoFz
         QJUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YkFKvczg;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf42.google.com (mail-qv1-xf42.google.com. [2607:f8b0:4864:20::f42])
        by gmr-mx.google.com with ESMTPS id z126si216949qkd.2.2020.04.07.01.16.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 07 Apr 2020 01:16:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) client-ip=2607:f8b0:4864:20::f42;
Received: by mail-qv1-xf42.google.com with SMTP id p19so1439355qve.0
        for <kasan-dev@googlegroups.com>; Tue, 07 Apr 2020 01:16:00 -0700 (PDT)
X-Received: by 2002:ad4:49d1:: with SMTP id j17mr1049883qvy.80.1586247359577;
 Tue, 07 Apr 2020 01:15:59 -0700 (PDT)
MIME-Version: 1.0
References: <78d7f888-7960-433f-9807-d703e57002bf@googlegroups.com> <CACT4Y+ZvX1Cs1SJppVfLXyV9F4hra=JdBaQCqBTeFX3++f48kQ@mail.gmail.com>
In-Reply-To: <CACT4Y+ZvX1Cs1SJppVfLXyV9F4hra=JdBaQCqBTeFX3++f48kQ@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 7 Apr 2020 10:15:48 +0200
Message-ID: <CACT4Y+abK5o34h_rks7HMivmVigTG3CM9X93MOt9d7B6dxY_9w@mail.gmail.com>
Subject: Re: [libfuzzer] Linker fails on finding Symbols on (Samsung) Android
 Kernel Build
To: jrw <ickyphuz@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YkFKvczg;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42
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

On Tue, Apr 7, 2020 at 10:14 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Mon, Apr 6, 2020 at 10:48 PM jrw <ickyphuz@gmail.com> wrote:
> >
> > HI,
> >
> > i try to build a Samsung Kernel with KASAN enabled but have problems getting it compiled.
> > how would you proceed from there to make it a successfull build?
> > I tried several cross compilers but i always end up with the same errors.
> >
> > -------------------cut-------------------------------------
> > /home/kerneldev/kernel/net/core/rtnetlink.c:2557: undefined reference to `__asan_alloca_poison'
> > /home/kerneldev/kernel/net/core/rtnetlink.c:2558: undefined reference to `__asan_alloca_poison'
> > /home/kerneldev/kernel/net/core/rtnetlink.c:2745: undefined reference to `__asan_allocas_unpoison'
> > /home/kerneldev/kernel/net/core/rtnetlink.c:2745: undefined reference to `__asan_allocas_unpoison'
> > /home/kerneldev/kernel/net/core/rtnetlink.c:2746: undefined reference to `__asan_allocas_unpoison'
> > net/netfilter/nfnetlink.o: In function `nfnetlink_rcv_msg':
> > /home/kerneldev/kernel/net/netfilter/nfnetlink.c:190: undefined reference to `__asan_alloca_poison'
> > /home/kerneldev/kernel/net/netfilter/nfnetlink.c:224: undefined reference to `__asan_allocas_unpoison'
> > /home/kerneldev/kernel/net/netfilter/nfnetlink.c:224: undefined reference to `__asan_allocas_unpoison'
> > /home/kerneldev/kernel/net/netfilter/nfnetlink.c:225: undefined reference to `__asan_allocas_unpoison'
> > net/netfilter/nfnetlink.o: In function `nfnetlink_rcv_batch':
> > /home/kerneldev/kernel/net/netfilter/nfnetlink.c:407: undefined reference to `__asan_allocas_unpoison'
> > /home/kerneldev/kernel/net/netfilter/nfnetlink.c:384: undefined reference to `__asan_alloca_poison'
> > /home/kerneldev/kernel/net/netfilter/nfnetlink.c:454: undefined reference to `__asan_allocas_unpoison'
> > net/bluetooth/smp.o: In function `aes_cmac':
> > /home/kerneldev/kernel/net/bluetooth/smp.c:175: undefined reference to `__asan_alloca_poison'
> > /home/kerneldev/kernel/net/bluetooth/smp.c:214: undefined reference to `__asan_allocas_unpoison'
> > /home/kerneldev/kernel/net/bluetooth/smp.c:214: undefined reference to `__asan_allocas_unpoison'
> > net/wireless/nl80211.o: In function `nl80211_send_wiphy':
> > /home/kerneldev/kernel/net/wireless/nl80211.c:1914: undefined reference to `__asan_set_shadow_00'
> > -------------------cut-------------------------------------
> >
> > the only thing i could find was a stackoverflow post [1] but this guy also had no solution to the problem.
> >
> >
> > [1] https://stackoverflow.com/questions/58717275/compiling-aosp-kernel-with-kasan
> >
> >
> > Thanks for any help!
>
> +kasan-dev  BCC:libfuzzer


It looks like you have an old kernel and a new compiler.
You either need to backport KASAN patches for stack support, or take
an older compiler maybe, or maybe disabling KASAN stack
instrumentation will help.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BabK5o34h_rks7HMivmVigTG3CM9X93MOt9d7B6dxY_9w%40mail.gmail.com.
