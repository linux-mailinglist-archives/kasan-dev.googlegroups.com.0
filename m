Return-Path: <kasan-dev+bncBC7OBJGL2MHBBG6P46EQMGQECX6R7TI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 11FA64048B8
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Sep 2021 12:53:17 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id b5-20020a92db05000000b0022c6493d0e5sf1641413iln.2
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Sep 2021 03:53:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631184795; cv=pass;
        d=google.com; s=arc-20160816;
        b=0YI4Jp2RzKm7YMB8iuctcNCdZTE0d14cJioDWmLHS9FGUPOQMvqiSvprUj/Ez825z2
         p0Nhl+cgmY+xYG3PviD4GlxG0CKqDZFJWaBNag7kTo+Xkz7WGJsPPHwRiYTvfzg0d5iD
         gFujdUzZ99U27L7AFHrO/dIH82fHdcQassC4VE6wFGPkm0F5XQRxreh2L6A411zciEvR
         xQW8cnQNCH412IVauWRj4mkFackwwype1OvDqVULiJuq+iqSSbX8jxbnFQ+3l6OLrB+U
         q7MmIvwfMnMLpZGTe3CvVUfwfQAX7svz2S+UmKVra8MBPGfFOxLcMfMgn+XwKpeZSv0q
         w6Jw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vLE5b/C71VycAzrEkhWuA1Y1rP+IY3c50bCpFAmuoxs=;
        b=CeCY7C5C9K4yRb+9ofOC4TurSEEeyRw9N8R35CAEL1VI8SYdQ8C28acMsDVClukj5Y
         nGRhm2rEo70aug7i+vssljl4xNIEntiPPWi/Eco3dnYGb7QFuLNvA0kP3CU4VR2Bu7aL
         dMGnqcnib/vm+Pr0RGT/c/rC0qG2gyTxq3LkNWuDha02lHT+bwXd9jIfFtuH3ac/73KK
         817sEm/9JeA+wf7krDdhooWUE8FLElW+uP58FU+dzKVX1eLWIFaXXL20nExrEi9/tMXX
         vUUm5NNHs9U6zLp5oSHZ8G/m1DxJh8sQFKzaZtIKtkcOcgPw6+QQuDSC134YrJJkc8ws
         BpPw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=svEsGSMu;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=vLE5b/C71VycAzrEkhWuA1Y1rP+IY3c50bCpFAmuoxs=;
        b=nnPO1iNfgu8/QE4gT7qG/XnoKUh9pPhqUskKemIhklxdWY5sIVIMXfG+avBqmY17F8
         kXjBHkHWUewZvVkm2HmaQerX0ITI0GsRMzjN+fNFwJtG9OtTi4wAL1/YCWBiDfiQAAP1
         9yW06fj844zgxpAHo2MZsjU6Suh8+2q5FWzhNjjAcw+YVvLtycscE76v2t+P65q7QHL2
         0bhfKB16X1JS4xx+yRlUICks6kky+D5AY8YaBwOyHcIVi5t5v9oF+BDGrV+A1pa7Amxw
         vEw91Vy/3T4ll3+W/nnGPgfWeayJAHYDBSAwOEQSu2AKPvnIf8TpfalGvJgHv+fTBxWQ
         VadA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vLE5b/C71VycAzrEkhWuA1Y1rP+IY3c50bCpFAmuoxs=;
        b=bWp/0UYmeebH7oVK2h9lmA/3eFm4MAlX/xjXKBlJdDFwwsj8amFa5/TzubYmFki9vx
         b4JELahk2+RigZCOWJlyNnUn4ppEgNYyEp/BR30IOkgHMJkWFJ8igGd3wHmxZqGNs6bB
         flozXkc4cat4Rm1tfLv2QIRIKcvHRGOw9YlHzwbgLCDtdrQhAoq/LiN3M9IcgpGJ0qeb
         GXyckea9K+InFe1uMWZc67NlfMqyiWK/tf/X1u7sHGDxyGdpW2Xtu/20U/D6XRjGfPLi
         qrOhBAS47HsubeMLGhOSGMWkBTW+yFMNrtbWv0t4P7PRDMRdaI/xlTr2PX1FY7SdMa29
         c8Dw==
X-Gm-Message-State: AOAM532EWyG5AwP1T56QdpRxQCaqvfBQMDo4868d9J+MJH+PM9/YX8lp
	PaLiIckd6+U7xV5rrZY8XR0=
X-Google-Smtp-Source: ABdhPJz1DJoEl31eE7FJkUk/QU1m2cSCiv1agCh8En+ZmTWmTDaQw2ew9BMDw9MG5uywNY/b8vO6bA==
X-Received: by 2002:a05:6638:2051:: with SMTP id t17mr2208485jaj.143.1631184795576;
        Thu, 09 Sep 2021 03:53:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:6504:: with SMTP id z4ls141791ilb.6.gmail; Thu, 09 Sep
 2021 03:53:15 -0700 (PDT)
X-Received: by 2002:a92:6907:: with SMTP id e7mr1795023ilc.301.1631184795230;
        Thu, 09 Sep 2021 03:53:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631184795; cv=none;
        d=google.com; s=arc-20160816;
        b=0FVjGT6KNTEYDSLYVlFjceEaPdvNuPb7psRh1gbdTkWa5IvTnVd+erNP+SgNMF4agH
         /s9FOcJJSzTSwhYfqur/iqxNnQAbBD1ct+aXCQpmg6wxpK4Gz1TklUpTl4mIBKxkyrtf
         AztqcdKE7GDbtNEhCmbzGLs8M9hsolnfiNfkj0X6wp7+LFL2hrix4h9z0znwn2LZ8R1c
         p1WYxcL6VxfzWKwXaITSAll3sH/Dkfx8DEPuTQLjf89m/jsxgpdYU8Rd7Rxs/2UwQTEA
         mOtOY+ZOt4huRbFzt7tgvbuRS8y8eHnZsptTmJdL059DI3Od578erkUMxpAQwmef0xr3
         AMRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=fU5ufvRRjTtfwnNvK13MR5zMOLz3I8fk1OzlUMqINLQ=;
        b=Jw58I02/bSsgSS2q+yLbTuKudwHMB7/KLFDTM2qCX8RKM5xIUeCnzB714gDxuxNuZC
         nLuhbwrpvFoAyxpWVLR8V/mzPlY/Pfyxhal+OCjsfJC34JVjI6T9DixNC63DxXaJLFwr
         XSdIWi2JX/+ajA9ehgvo6veY5BXVvL4Mpy2SJ9bEdeOzgteBJ4q3g7eY0sybb2ezond2
         MzP4jX/p8TWxjFwr+lESnfmusXIeL4FPfxZxe+v7tpyyZbUFPEJaMDQ4ifcG27xpguWL
         At6b2j1XbHGy71WC+UdW11XDqyxHDW+DTvSkGXrlAn5nego0DBtHFPEjDZw8YXbBK8vH
         Uz1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=svEsGSMu;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x229.google.com (mail-oi1-x229.google.com. [2607:f8b0:4864:20::229])
        by gmr-mx.google.com with ESMTPS id y129si98273iof.3.2021.09.09.03.53.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Sep 2021 03:53:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) client-ip=2607:f8b0:4864:20::229;
Received: by mail-oi1-x229.google.com with SMTP id bd1so1950413oib.5
        for <kasan-dev@googlegroups.com>; Thu, 09 Sep 2021 03:53:15 -0700 (PDT)
X-Received: by 2002:a05:6808:21a5:: with SMTP id be37mr1443831oib.172.1631184794726;
 Thu, 09 Sep 2021 03:53:14 -0700 (PDT)
MIME-Version: 1.0
References: <20210906142615.GA1917503@roeck-us.net> <CAHk-=wgjTePY1v_D-jszz4NrpTso0CdvB9PcdroPS=TNU1oZMQ@mail.gmail.com>
 <YTbOs13waorzamZ6@Ryzen-9-3900X.localdomain> <CAK8P3a3_Tdc-XVPXrJ69j3S9048uzmVJGrNcvi0T6yr6OrHkPw@mail.gmail.com>
 <YTkjJPCdR1VGaaVm@archlinux-ax161> <75a10e8b-9f11-64c4-460b-9f3ac09965e2@roeck-us.net>
 <YTkyIAevt7XOd+8j@elver.google.com> <YTmidYBdchAv/vpS@infradead.org>
In-Reply-To: <YTmidYBdchAv/vpS@infradead.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Sep 2021 12:53:03 +0200
Message-ID: <CANpmjNNCVu8uyn=8=5_8rLeKM5t3h7-KzVg1aCJASxF8u_6tEQ@mail.gmail.com>
Subject: Re: [PATCH] Enable '-Werror' by default for all kernel builds
To: Christoph Hellwig <hch@infradead.org>
Cc: Guenter Roeck <linux@roeck-us.net>, Nathan Chancellor <nathan@kernel.org>, 
	Arnd Bergmann <arnd@kernel.org>, Linus Torvalds <torvalds@linux-foundation.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, llvm@lists.linux.dev, 
	Nick Desaulniers <ndesaulniers@google.com>, Paul Walmsley <paul.walmsley@sifive.com>, 
	Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, 
	linux-riscv@lists.infradead.org, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, kasan-dev@googlegroups.com, 
	=?UTF-8?Q?Christian_K=C3=B6nig?= <christian.koenig@amd.com>, 
	"Pan, Xinhui" <Xinhui.Pan@amd.com>, amd-gfx@lists.freedesktop.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=svEsGSMu;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as
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

On Thu, 9 Sept 2021 at 07:59, Christoph Hellwig <hch@infradead.org> wrote:
> On Wed, Sep 08, 2021 at 11:58:56PM +0200, Marco Elver wrote:
> > It'd be good to avoid. It has helped uncover build issues with KASAN in
> > the past. Or at least make it dependent on the problematic architecture=
.
> > For example if arm is a problem, something like this:
>
> I'm also seeing quite a few stack size warnings with KASAN on x86_64
> without COMPILT_TEST using gcc 10.2.1 from Debian.  In fact there are a
> few warnings without KASAN, but with KASAN there are a lot more.
> I'll try to find some time to dig into them.

Right, this reminded me that we actually at least double the real
stack size for KASAN builds, because it inherently requires more stack
space. I think we need Wframe-larger-than to match that, otherwise
we'll just keep having this problem:

https://lkml.kernel.org/r/20210909104925.809674-1-elver@google.com

> While we're at it, with -Werror something like this is really futile:
>
> drivers/gpu/drm/amd/amdgpu/amdgpu_object.c: In function =E2=80=98amdgpu_b=
o_support_uswc=E2=80=99:
> drivers/gpu/drm/amd/amdgpu/amdgpu_object.c:493:2: warning: #warning
> Please enable CONFIG_MTRR and CONFIG_X86_PAT for better performance thank=
s to write-combining [-Wcpp
>   493 | #warning Please enable CONFIG_MTRR and CONFIG_X86_PAT for better =
performance \
>       |  ^~~~~~~

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNNCVu8uyn%3D8%3D5_8rLeKM5t3h7-KzVg1aCJASxF8u_6tEQ%40mail.gm=
ail.com.
