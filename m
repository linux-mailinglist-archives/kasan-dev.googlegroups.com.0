Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6MCZTCAMGQEUK4AECA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1EF42B1C123
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Aug 2025 09:17:15 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-3e3e69b2951sf8194095ab.0
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Aug 2025 00:17:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754464633; cv=pass;
        d=google.com; s=arc-20240605;
        b=iuBvj7X2EM9OecwQNY96nr5NzjW3iLlhR4p7+xq2wxFT7O3dqyRcUdQavoDmtqTIAm
         hq+uBchmtaUqbQpNiQOJ1nC7ohsW752cM75d3OsF4UOzTpiv7KPEnwSHThY6GB/4MQE0
         mpgDShRLlGvhqZtYmF4G8Ikcif44pICFbUlJTbEFg0wpdGjCNEgyLm5vnWACRr9Y/oDc
         fHc4NIiPuPPu/cS6D1aQakdJ9ib2yVk2dG4QEVw2NjoULtqiJCgh4Ik/2x2yonZrwv+/
         u5YKBys/zc4UPP/StqYM5es8KkHLunqvSqvO/27FctfMd8m9mWl/eW977BlveLOq7eFo
         U3wQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=HNxsWpXypU0C2DZt3jKTWoLkY4vcoRUsKjmOPsmDpvA=;
        fh=CTRkW5LhOdxpzYfXERq7LTr1ef7qTAqv85AI84e1KJA=;
        b=Ow20UaGtQ/S7fLnN0o0Q0iRrIPJEjJ2eoguuchkqUahmqBZAKPf2WhD1f/lOL0/0z1
         F6429AO4q4QhXl2NI/R5Mhhqziu/MglyfEMwvkGi+W9qg+YwYuw8rcO+oCE40V7I95wI
         Ye1Lo1MuccYu1Nqcy2xCTTx0PUJ/6jnMvk77IXR/agCl9Ih1GYo25DddG8osBkMAA5Ji
         Vex8dgewurmWQrNdwetrH0tdComnMC/zaMChGexjvdiJs2sQzmV3q5yX1HzVkmsJtcxK
         BRwlCpXJ+L4c6/D1Z0sNbiD623nrN0Fa8Ok2eiAQ1kxP1O7J8vNU25JU/Gv+9pyNfB1T
         GABQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=f6Tp4Pyb;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754464633; x=1755069433; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HNxsWpXypU0C2DZt3jKTWoLkY4vcoRUsKjmOPsmDpvA=;
        b=rVUL4j+e6S4renfh41m405vRu4yYMRuHMYixY1yGXi8FyFKl75rbkyx9zElqKwL54e
         jtsRM4neDnRfpfMWOYXJPjjUoH4+fEeHBvjZPQ25OGb+a/S48eNDYAvrZ4cZqIG0Vo5S
         E0yWr1fpXoG4Hg+K3YcAk5M5wrSaBstOiZbv+koYTjjSwz4+nGgyzqUgpb22rb5ezrLw
         3i7lTwttgP6fGPang6DzVmNJCRD7nULaQNKNXpsEL0KoVgWuPMKDssvSTHpeypr05+/a
         57STk9WxWolcDqg3SypBjqTPNLsdMCKpTK5LrMhY3XrupZeMWkY702kzAIeAgsQSHvjN
         IQgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754464633; x=1755069433;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HNxsWpXypU0C2DZt3jKTWoLkY4vcoRUsKjmOPsmDpvA=;
        b=Zb/+XUOAEo5IRnU/i8mn2++0YIt3Vzjydx/bf4IM9uJOrBBdS04O+odY7u7GQbhIx9
         0wwkYcBKStN6pltgaFPLPFYguvnpAk9UCEL+VsEBR5LATA49z8FcOuOxrobLm+bdWxkW
         ZEZqxGtqJPwVfILFmSb5zyRPvqmMq1D6ifI98SncLMz8EuxnNs5G4AsT20/XEIZZd+PK
         v99jE+4HsDpb4Rvvikx/bjQWbg8vMcUfvdoA7bYk/9Jnay+snep5p2aCX76D2SglC+Mh
         aS1ZUt7GjB26AW5vPzprCq9VMQnlvgJtZBRyif5cMLwkp1w5Q6h/mxYJbZXmkZ4L1pmX
         LK1Q==
X-Forwarded-Encrypted: i=2; AJvYcCVP3luemhaPWVNVQNR/q6hWvMMc8LKN23JtMDcXXiX9alox7d7w0m2HNB77PoQA2IYWn/a90g==@lfdr.de
X-Gm-Message-State: AOJu0Yy+PzgQM1dRHfkYHjLsS4JSDwoQ8huoWmWQuvCSfVbixDQpiY7c
	QPM8Q6IqwP7L2Ec3lGQX4h3hlN8iAotCCKR2Fm+AkW84G7g5h06TBGGl
X-Google-Smtp-Source: AGHT+IERX7KXw1YTRxsgm1P9JgO5N31qetnAVieFlYGJ3608/ilKEF+lSDJvF1TU74wWpSm71W0Z/g==
X-Received: by 2002:a05:6e02:16cb:b0:3e2:77d9:f8fc with SMTP id e9e14a558f8ab-3e51ada0261mr30994335ab.10.1754464633402;
        Wed, 06 Aug 2025 00:17:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf7viSmCmYYM0t9aDmBGJ9IMPIja01rkZQj8hffIumjzQ==
Received: by 2002:a05:6e02:460e:b0:3dd:a103:6762 with SMTP id
 e9e14a558f8ab-3e519eafa43ls2978015ab.2.-pod-prod-00-us; Wed, 06 Aug 2025
 00:17:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWaijF1kRzZ8t6tFLsq2kWvTMhHQ6z8oqcSQwpL2s0GGj7WVij7hmS0mwvEjMqUy5Ebohr7XRuwvz4=@googlegroups.com
X-Received: by 2002:a05:6e02:1567:b0:3e3:fff9:eb1f with SMTP id e9e14a558f8ab-3e51ac64d78mr32579805ab.2.1754464632381;
        Wed, 06 Aug 2025 00:17:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754464632; cv=none;
        d=google.com; s=arc-20240605;
        b=J7X0/AbQb74zZGi3GrIPGjD+LRAEwvdd5fmd1I7TZLnUNwCWloO2QvfGTO0CfFsKwj
         ZltFua02bB7bYjMripqw9eeJeqTNplpbMF5IIWOeKRCPbWwbeCFMB1X2Ygc9T3V++pwY
         Hd2JpVKtMxc1dK/i6JIvmeWO1y74dpv1DH1xSmvkY9QMHUkr4/SCW4tOI8PSY+18wmez
         kkQDE1olHecJzYqBCWLc7bcVtK/Ps92/p7H+6PvJsbkRz76hJYwGQvMO1mhzdjN48YCy
         FCqbUcUPJfjXxQtD613DkGAOv9T1pGdg0nwpIghtqEGF3RA7NDtUXyuRKeio665VmrJ5
         k1kg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wXLDPCGDjNvdOeR7jZ736CzN/nAMcYgqmwaHMi4ddf4=;
        fh=LqLpXjMGTVgNW2EZOdQDOvo8OyX95MMaB4ACznubLYI=;
        b=Sj/xAhaT09N9ZVaSCzjnBeFEcP1uvue+VVo2D6CklwSJT12PudvbfTruIuylMR7G1P
         qMnTS55Ahft/1dMnwmOd6/2zireopb8fdBr19Ktgz8gtFJtNy0+l061elRiSOZYpOEZT
         6p4aoYvnnF6hDyD8iPvH1E0c5A5ZPGvwSv483tJff4VwC94pNCTrlmUb6kFEa75PDCf7
         9MSYH8+1ZIjZT9/9gEsdzlFogpOF3OgXFLnyD+IDx/k0nPSPe0aT8Oyll9ApPS3RDZWI
         qE5Xqo4MPrs4PaAkkP8s7TYVJbtlMDnSv7AWriA6KE5hdWsmkaR77heCwZ7DPrZ6oHeA
         JZew==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=f6Tp4Pyb;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62d.google.com (mail-pl1-x62d.google.com. [2607:f8b0:4864:20::62d])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3e402a13343si3670435ab.2.2025.08.06.00.17.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Aug 2025 00:17:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62d as permitted sender) client-ip=2607:f8b0:4864:20::62d;
Received: by mail-pl1-x62d.google.com with SMTP id d9443c01a7336-2403c13cac3so4965985ad.0
        for <kasan-dev@googlegroups.com>; Wed, 06 Aug 2025 00:17:12 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVUbKPa1f2ujSNU8oDYYhxEE8+Flqv7JKe8cs44Wu+tkO3mQxEi7Rx/YcmF9511xDDSZwLVEzDqEJA=@googlegroups.com
X-Gm-Gg: ASbGncvjLJl23bHIh82rnrPlum1YqoQMrZakfkcdlsTZZPy1mqQJr7iyr0sBg8bls7k
	pUj4y18LviRoESDxm4OdEtaK1qITwrTu6MGztIZjHKnfM4m5AkDGwxskC9nnJTzVgzPt2vkUWtO
	kcTQ5QtDubJpnB3sGrVLuiytRlS7NqYJd00lD5H6d//poLQU8ZcmWwGWBm0S6RY/D7F8CL44ywR
	DISBclhcGXoAUZIClfPuRXbpSIKtujeCgfZfIE=
X-Received: by 2002:a17:902:f691:b0:23f:75d1:3691 with SMTP id
 d9443c01a7336-2429f959eacmr24836285ad.15.1754464631438; Wed, 06 Aug 2025
 00:17:11 -0700 (PDT)
MIME-Version: 1.0
References: <20250805062333.121553-1-bhe@redhat.com>
In-Reply-To: <20250805062333.121553-1-bhe@redhat.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 6 Aug 2025 09:16:34 +0200
X-Gm-Features: Ac12FXwlK-cs-vH-SavIGCKnyqqqvtGaUUbmDgA0yfosyX6KUMYZkchuphMeuWE
Message-ID: <CANpmjNP-29cuk+MY0w9rvLNizO02yY_ZxP+T0cmCZBi+b5tDTQ@mail.gmail.com>
Subject: Re: [PATCH 0/4] mm/kasan: make kasan=on|off work for all three modes
To: Baoquan He <bhe@redhat.com>
Cc: linux-mm@kvack.org, ryabinin.a.a@gmail.com, glider@google.com, 
	andreyknvl@gmail.com, dvyukov@google.com, vincenzo.frascino@arm.com, 
	akpm@linux-foundation.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, kexec@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=f6Tp4Pyb;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62d as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Tue, 5 Aug 2025 at 08:23, 'Baoquan He' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> Currently only hw_tags mode of kasan can be enabled or disabled with
> kernel parameter kasan=on|off for built kernel. For kasan generic and
> sw_tags mode, there's no way to disable them once kernel is built.
> This is not convenient sometime, e.g in system kdump is configured.
> When the 1st kernel has KASAN enabled and crash triggered to switch to
> kdump kernel, the generic or sw_tags mode will cost much extra memory
> for kasan shadow while in fact it's meaningless to have kasan in kdump
> kernel.

Are you using KASAN generic or SW-tags is production?
If in a test environment, is the overhead of the kdump kernel really
unacceptable?

> So this patchset moves the kasan=on|off out of hw_tags scope and into
> common code to make it visible in generic and sw_tags mode too. Then we
> can add kasan=off in kdump kernel to reduce the unneeded meomry cost for
> kasan.
>
> Test:
> =====
> I only took test on x86_64 for generic mode, and on arm64 for
> generic, sw_tags and hw_tags mode. All of them works well.

Does it also work for CONFIG_KASAN_INLINE?

> However when I tested sw_tags on a HPE apollo arm64 machine, it always
> breaks kernel with a KASAN bug. Even w/o this patchset applied, the bug
> can always be seen too.
>
> "BUG: KASAN: invalid-access in pcpu_alloc_noprof+0x42c/0x9a8"
>
> I haven't got root cause of the bug, will report the bug later in
> another thread.
> ====
>
> Baoquan He (4):
>   mm/kasan: add conditional checks in functions to return directly if
>     kasan is disabled
>   mm/kasan: move kasan= code to common place
>   mm/kasan: don't initialize kasan if it's disabled
>   mm/kasan: make kasan=on|off take effect for all three modes
>
>  arch/arm/mm/kasan_init.c               |  6 +++++
>  arch/arm64/mm/kasan_init.c             |  7 ++++++
>  arch/loongarch/mm/kasan_init.c         |  5 ++++
>  arch/powerpc/mm/kasan/init_32.c        |  8 +++++-
>  arch/powerpc/mm/kasan/init_book3e_64.c |  6 +++++
>  arch/powerpc/mm/kasan/init_book3s_64.c |  6 +++++
>  arch/riscv/mm/kasan_init.c             |  6 +++++
>  arch/um/kernel/mem.c                   |  6 +++++
>  arch/x86/mm/kasan_init_64.c            |  6 +++++
>  arch/xtensa/mm/kasan_init.c            |  6 +++++
>  include/linux/kasan-enabled.h          | 11 ++------
>  mm/kasan/common.c                      | 27 ++++++++++++++++++++
>  mm/kasan/generic.c                     | 20 +++++++++++++--
>  mm/kasan/hw_tags.c                     | 35 ++------------------------
>  mm/kasan/init.c                        |  6 +++++
>  mm/kasan/quarantine.c                  |  3 +++
>  mm/kasan/shadow.c                      | 23 ++++++++++++++++-
>  mm/kasan/sw_tags.c                     |  9 +++++++
>  18 files changed, 150 insertions(+), 46 deletions(-)
>
> --
> 2.41.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250805062333.121553-1-bhe%40redhat.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP-29cuk%2BMY0w9rvLNizO02yY_ZxP%2BT0cmCZBi%2Bb5tDTQ%40mail.gmail.com.
