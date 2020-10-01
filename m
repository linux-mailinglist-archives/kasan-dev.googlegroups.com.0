Return-Path: <kasan-dev+bncBDX4HWEMTEBRBH5A3H5QKGQEMABVAHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id BB86B2809BA
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Oct 2020 23:54:40 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id e2sf122994ooq.23
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 14:54:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601589279; cv=pass;
        d=google.com; s=arc-20160816;
        b=VIbdco4grZ+zLHgsbLEERXodtyDslxB4CDofsAvQnBkgY8Ze1t8QBpWd59/YpRUUpK
         44KqfJWqBzA7FZTvUEAijt2hEuw4lTk1CRCEPL32e+3TLQIaNe+c1IvUUNoCfEGUv3pe
         bT8lghS5UryfLzW90kKcGvVSzag9Esm+YAqzn1tz0eEEN/HYBVvWObTApG4zTzHaL+yi
         WqHRmASbv4qBY8jBoLRjJA0CYKicHJxEGKbGosDXGqQ7RdjmyQ/ue9HLCD1qKhk38+rV
         5pr39TZxReCl5K9B4p30MXUhfGFb0lmVZXl6n2V3aChYM9o2GSH2x6wQnyhc3tyhyeU/
         IEFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=3RBFB3JA1l3RTtBiRBzx6/l1m+2fc3lYssi+5HHPGzo=;
        b=u62McYuQlQisGEajRh/9Ai3aBsagnrT+l+xFPNLxH0L0mlXIUDferR7QPC/MDDy6+T
         hh9ejo5F4acWxVTb3ZcmIRK+xFZVbrh+UM7v2DyCuXe0l7r0jlSzidgVo7GOQu+2yVvB
         LJiCPVnf78RpxVTI9ZLKD7ioLzhk8Le092c0TUqi+m+7W7PvAATQT5WwT1EP8Pk6Ik7e
         Dm2jJw7CbxOuG6I/AZCmbCZmzh01h5QRRN4UFV56ygS3hulzN6/HaPvqGydjqZuJV5FE
         9ED1XGVuWmHzrbCKo0GF3sRLix/14vTgloRFKIuvJFdK0JBjU6CKVyqNmZ4MPsJTmJNY
         hIsA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nqXbUTBc;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3RBFB3JA1l3RTtBiRBzx6/l1m+2fc3lYssi+5HHPGzo=;
        b=iYwVtdRCz2CDU7fHqf4tDYb3dztF/GIzQNd2pEZ2IjH9vLGNwMFlSJ7LTgr9+uOK45
         NCRmX2j+JY8SgQA9B/KsBPVZsAoJ8EhD/v9QiYWl6oG8T41NIgHwRGiXD8SJ/izZS4oM
         WIBjsRx0HwGHoBSGUuJLVJSMDjzWikG/kcQYWf36xdzPv82qOpu0Xdr7nv6DpLfUoWT1
         rgTRcUjErp/sRfaevXXSI5YVCHImCuBVZqrclzJO+VVoo5tgW7W+lrZ+R1nLOHmqkaNg
         j8QJxrSKv9o5W96tT3WXiCpKsmzQb6QTdFZ9PswBHxKRQheRX07RdnkQ6u4V/Nhg941v
         cxCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3RBFB3JA1l3RTtBiRBzx6/l1m+2fc3lYssi+5HHPGzo=;
        b=RwfzZcWCLiB/XfEYzGTsxrigdJ6Jnk9f2Bj/Lu+18sK+xrlg7rzQPH72lIaKQWcd0J
         Pze70T4zn310WjGwUYHA6IogJ/6wta9iRSKcgQIowMgnaddMLXg49Ozx/LpyZTW8XTx7
         ilv3s+8eLQryuRPOrs3/bu4HgeSM1VPKErGVXDRGAItYbAWA8AO1sTZCKv+a+bYKJvJU
         fJZbn8Q+zRLY7ENVV040f+iKwlIpf8YtkpxcaZcjO0D3F8lBMhFAqkReAXZcfruCM29Y
         C8ATQoB2HYSg8LHODcwxwo8iXDT3W4v4oTt3ugRJD9C4wmhpKdaQWynXaOCeCbieFM6j
         z9Jw==
X-Gm-Message-State: AOAM53205CilZaBBId/Nmllcn+M65s+wjzRv0le6yhtpnoWW2WKX28Ly
	VsFU+6cQJfsJ04k//8tEYcw=
X-Google-Smtp-Source: ABdhPJyt4T/Ac9TGwzFBfy1MMi7Q7CqJJLf9A1S7rfDHx2sjKJEf5R2kybfsRoQuDq+SAY+YshfFrw==
X-Received: by 2002:a9d:2a83:: with SMTP id e3mr6134470otb.237.1601589279483;
        Thu, 01 Oct 2020 14:54:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:3741:: with SMTP id e62ls1582450oia.7.gmail; Thu, 01 Oct
 2020 14:54:39 -0700 (PDT)
X-Received: by 2002:a05:6808:69a:: with SMTP id k26mr1321019oig.127.1601589279127;
        Thu, 01 Oct 2020 14:54:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601589279; cv=none;
        d=google.com; s=arc-20160816;
        b=tOvW8SUNO+OC2rVEgisl8ZSWwXF8r0FG7felRAfbmrZmHYgCDi1LuQCj9yhqA+zztn
         IDAmONNTpXlq+DYkT+UPmy9K31iuC1Vs3VmRwaVwLEoW3Ddrev63hHqHrhXnA699XOug
         Kp9uJ/EKRYWW87geCf2UylA7xDdOAEfh86IW3TXYsryNrgZKX8Wzdcqh0aDAfHpLuxUO
         /PeHTJydC2T7wxJg9xQiqzeHhhA6zNSpb4x0/Ftf7mUCg1XOcMtpo702BmaqOoW/+DQ+
         DzLUVtB/Xxf8+CcabJXW71nJLRZTf3Jz9NZRoqBiguOxUIG0j7xSvJSJ1xVl9hfujjR+
         we/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3q47gBSVfL/j+OZHN/FfdXXTWivJeUwTp3edwFJcf2k=;
        b=a89yV8HFAjFN8UTCy/dBXcfqxotHXDv8EYZCIJJwBQzyjIfzcyfHsZVp9UVKksoqnb
         mRN71A5y6llbuaGMriG7LU/H/uW3WaBoXslSFT8D08tHTo+rAM7TEt1TKFUCTbvVgSWa
         181Pu6kceWcNx0p5ufdkRcBY9DLRFoBXb/br0UOoCG+qz3htE97Hc82Q7pqOYd4A8Iox
         D6WMGMSzmopPpSEmVHp29YzHFMJLN8TR7+loCIF/keZRLURrTIE8StejhkHM13+3VeAK
         gUhyBecEpy1ycmtdakk7ul8yhSEMAAGfGuyVo1Enn/iwfGnwsx6FPtsLz1Pa80a0iy+X
         so7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nqXbUTBc;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x541.google.com (mail-pg1-x541.google.com. [2607:f8b0:4864:20::541])
        by gmr-mx.google.com with ESMTPS id u27si484141otg.5.2020.10.01.14.54.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 14:54:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541 as permitted sender) client-ip=2607:f8b0:4864:20::541;
Received: by mail-pg1-x541.google.com with SMTP id 197so61241pge.8
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 14:54:39 -0700 (PDT)
X-Received: by 2002:a62:ee10:0:b029:142:2501:3972 with SMTP id
 e16-20020a62ee100000b029014225013972mr4653258pfi.55.1601589278265; Thu, 01
 Oct 2020 14:54:38 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com> <728981bdedbca9dc1e4cca853699b6a6e8f244e0.1600987622.git.andreyknvl@google.com>
 <20201001173945.GI4162920@elver.google.com>
In-Reply-To: <20201001173945.GI4162920@elver.google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 1 Oct 2020 23:54:27 +0200
Message-ID: <CAAeHK+zYRYd=67fqrKn7hyAjMj++Z70pjyxS4gQ2KChZa1A5ag@mail.gmail.com>
Subject: Re: [PATCH v3 11/39] kasan: don't duplicate config dependencies
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=nqXbUTBc;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Thu, Oct 1, 2020 at 7:39 PM <elver@google.com> wrote:
>
> On Fri, Sep 25, 2020 at 12:50AM +0200, Andrey Konovalov wrote:
> > Both KASAN_GENERIC and KASAN_SW_TAGS have common dependencies, move
> > those to KASAN.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
>
> Reviewed-by: Marco Elver <elver@google.com>
>
> But see comment below:
>
> > ---
> > Change-Id: I77e475802e8f1750b9154fe4a6e6da4456054fcd
> > ---
> >  lib/Kconfig.kasan | 11 +++--------
> >  1 file changed, 3 insertions(+), 8 deletions(-)
> >
> > diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> > index e1d55331b618..b4cf6c519d71 100644
> > --- a/lib/Kconfig.kasan
> > +++ b/lib/Kconfig.kasan
> > @@ -24,6 +24,9 @@ menuconfig KASAN
> >                  (HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS)
> >       depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
> >       depends on CC_HAS_WORKING_NOSANITIZE_ADDRESS
> > +     select SLUB_DEBUG if SLUB
> > +     select CONSTRUCTORS
> > +     select STACKDEPOT
>
> In the later patch your move 'select SLUB_DEBUG' back to where they were
> here it seems. The end result is the same, so I leave it to you if you
> want to change it.

Will fix in v4, thank you!

>
> >       help
> >         Enables KASAN (KernelAddressSANitizer) - runtime memory debugger,
> >         designed to find out-of-bounds accesses and use-after-free bugs.
> > @@ -46,10 +49,6 @@ choice
> >  config KASAN_GENERIC
> >       bool "Generic mode"
> >       depends on HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC
> > -     depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
> > -     select SLUB_DEBUG if SLUB
> > -     select CONSTRUCTORS
> > -     select STACKDEPOT
> >       help
> >         Enables generic KASAN mode.
> >
> > @@ -70,10 +69,6 @@ config KASAN_GENERIC
> >  config KASAN_SW_TAGS
> >       bool "Software tag-based mode"
> >       depends on HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS
> > -     depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
> > -     select SLUB_DEBUG if SLUB
> > -     select CONSTRUCTORS
> > -     select STACKDEPOT
> >       help
> >         Enables software tag-based KASAN mode.
> >
> > --
> > 2.28.0.681.g6f77f65b4e-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzYRYd%3D67fqrKn7hyAjMj%2B%2BZ70pjyxS4gQ2KChZa1A5ag%40mail.gmail.com.
