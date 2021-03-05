Return-Path: <kasan-dev+bncBDX4HWEMTEBRBG5DRGBAMGQE2QHAUKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id D538932EF34
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Mar 2021 16:43:24 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id e16sf2005814ile.19
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Mar 2021 07:43:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614959003; cv=pass;
        d=google.com; s=arc-20160816;
        b=Fw/dg5tkIxdKwr8XM6dLKyGSzJjCP45D+a3AqO52IzQVBHBF8YwU0CXiH2vreWpJnq
         6lEKJ4L4PWLV35Wu7OD0bWTVP9B7v7RsG218HzRWlwv+eNCG9IjGivQPrEq6yk8p8sdK
         VigxdsBuo5PKe74CqF9VUX+frXfPURqODr/OExuDje1DhS4myB7tUMdc92LVB1HChBZC
         iuKBW7D/lhDO1IG1u5PwPuNWaPRYPpEj7+6WLSB7E969sceWjC/n/dCHemLR8A6pOTWt
         W2BYKoMlJimsSYBU8c6ZfvCNiJpHq/lS+nnHGKddAXN2TCHOgJ4urAxxaBey4LQoYqBz
         c6fw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ePMCS/gg0OEkYckQeW7vnUBqYtj2isNlwLyTghbyKX8=;
        b=KYusEeBMGIM2or99cM2735qVpty91gIHzmy0ONIbrmRLMJ4bAsFybe171LNNS53Dyb
         MPnaqScyE8hIlJVhT1p8K7w4e8uw+TZJYyLvqAW4pfOSBc/3MPWTLaDnDd8feu+quHol
         OiFDm3kezZWqe4AFzaXcXxzmCUd6+esCi6iHkeQPxemtAxrNJ2HJNXWiH2IatsN5B92L
         1wKW9uz3hOlgoz20YhxJQ+RswPBgYdMiYiw+XJf902vVz0j6IE5RfQkZTmY9WdYqk3vH
         Nou3T+oO7KgIbxg4VKADlgSMqNNDQw2np++FZhIUV2Ga7qurynEREyA6rOmAwnCablwH
         pKOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lwmLF3IO;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ePMCS/gg0OEkYckQeW7vnUBqYtj2isNlwLyTghbyKX8=;
        b=U889U4IRErVlw/9xsxd9nHT6Yp0lm7CT8lo5KUM5t3n2LWb45VxWENL1dp6hxngNfU
         o3Zr90kekN7cGOKq78ehxqqlZ2ekU+g1P2nNeH1BWwqlKLN5lC1//IwbqOYmZV/rApJ6
         1fHf2jC09xONLmrjYEdlwrXUhz6ZK7bW2xUHYq8eqwHxSuwsd8zAGRN+FKjh6ITIovma
         fv4cicEgMasOosKSiUcODs8qpV+vHU5WWHahzxn3SGjJVwXp6I+mt4vRxxR/YW6hGcEt
         waGU7fBsSEOzrCHlnCq3ci6MkgJKeL/i9OL19yYDcJNluATMQ/+cJqDgfQa8WZNbozIw
         nqog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ePMCS/gg0OEkYckQeW7vnUBqYtj2isNlwLyTghbyKX8=;
        b=gTTgz9u/aDw7VHOaoUJDCz15oCw540xzvuPaWlseEVN272A92VTg+EA73phnZ07BHS
         VecXSsQXwl10lD2wRJFMuoYztagS5eLNQBTCr8wWRlKfAHniarJlS+ePY1tJWeWSZ5it
         vNA/VZAU38sBFtaZBMtaoEMAVSvi335ygR2y+R25NlOnx0s7V8CRXZMwznTBAj74YRVE
         knQ9Ec7fOaY8moo/fZGdxmpJG7xJF9qctbiMMAgxTkgaQjHXPvgz0d+c5sv5gr0OgWq7
         TM2vLnTsWEtx4mPwFEbq6w2af/kArisFJtZV8Eg6gfrEtaLih9boueupBv8fuK4LGHjH
         5CjQ==
X-Gm-Message-State: AOAM531ei3vIk2mJmCu7UjYazUUZbTSqtg+m5LKHhIOJVStbU5JcmleX
	z9j87NdNv9sjEqu2qVZyX1A=
X-Google-Smtp-Source: ABdhPJywGEZomSWlRcHRbY7tFLOm22/ns5T/ZbOrLjSb/bI5aV2Tdegs6g9EAHAKP3H+7UeARWrPzQ==
X-Received: by 2002:a02:cc1b:: with SMTP id n27mr10420142jap.106.1614959003655;
        Fri, 05 Mar 2021 07:43:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d24b:: with SMTP id v11ls2560001ilg.7.gmail; Fri, 05 Mar
 2021 07:43:23 -0800 (PST)
X-Received: by 2002:a05:6e02:1bec:: with SMTP id y12mr9076382ilv.214.1614959003297;
        Fri, 05 Mar 2021 07:43:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614959003; cv=none;
        d=google.com; s=arc-20160816;
        b=fDRdwoAFHrgiJkTS1bOemtXl3Tx7NOetEGfoxDC43uGA9+hZ5f6KlN6+WFrgQW5ewI
         JcQ0PWlHeOvSuE5s6zDOIomxT3bSv7X1jhasuOE1V+zoXPll/+gfplL5Bw44RwZNI6dI
         jnjDAvmu+PkhYvIWmtKISjJBp9HlWhRogsKxf0fu5OOGY20B1OASKCurjDB6xCLIM4dE
         dSdhmROW2Fh0m+U08lgKcxZPQkyz6vd6GURcAuoMX02126cjETUpEiXKoinupC5xa3P+
         3lZ025G774EnaCZk1ntpWzZ3qGTVddwIm2wRWDgxLmfQPM+oBE3FUY/iGT5yOkwll3SW
         iGuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qTbQ4CYrvEtOKN3sK9Cdx0Ymm+PDCdjrJdMZxf0RYq0=;
        b=HgiMKNU/MGK+3xGkpkZKMdZ0bNgFlPC1kEu26wP7RHIFEg+pELK0yKiULgknhi2Rx4
         g2uaoOCH152Bdx24BleqkL+kNdSH+ovQ0N7BVuvKn2csCfR/mBDzX1EMfWdONa3SUicN
         wTTZpkWanfgqj0ZL6wsQHlvOwVLDd+Z5exk85wAZyHN4C8N8r/eVzRowX5bx4+8fSmru
         JzF54R6KUiyD3Jj/RNV4ArSJ8vPyN3W+9rhnQULYyhFfF9o1hH5S6bMUTcyznU+ajT+q
         LdswI72wXNrKLxKeWiSZ6tjQk/bmykOqipV1C4ZZ6i5puXl6ODPMACV9uz1Zoi3xiUkS
         GubQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lwmLF3IO;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1034.google.com (mail-pj1-x1034.google.com. [2607:f8b0:4864:20::1034])
        by gmr-mx.google.com with ESMTPS id y6si160916ill.1.2021.03.05.07.43.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Mar 2021 07:43:23 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1034 as permitted sender) client-ip=2607:f8b0:4864:20::1034;
Received: by mail-pj1-x1034.google.com with SMTP id jx13so2089309pjb.1
        for <kasan-dev@googlegroups.com>; Fri, 05 Mar 2021 07:43:23 -0800 (PST)
X-Received: by 2002:a17:902:7898:b029:e4:182f:e31d with SMTP id
 q24-20020a1709027898b02900e4182fe31dmr9028328pll.13.1614959002581; Fri, 05
 Mar 2021 07:43:22 -0800 (PST)
MIME-Version: 1.0
References: <1aa83e48627978de8068d5e3314185f3a0d7a849.1614302398.git.andreyknvl@google.com>
 <20210303152355.fa7c3bcb02862ceefea5ca45@linux-foundation.org>
In-Reply-To: <20210303152355.fa7c3bcb02862ceefea5ca45@linux-foundation.org>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 5 Mar 2021 16:43:11 +0100
Message-ID: <CAAeHK+yVG0-36TUpH8EkQ7r1DHNGTHuOfLfKBKO3aDtCV0RnRQ@mail.gmail.com>
Subject: Re: [PATCH] kasan, mm: fix crash with HW_TAGS and DEBUG_PAGEALLOC
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Christoph Hellwig <hch@infradead.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	stable <stable@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=lwmLF3IO;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1034
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

On Thu, Mar 4, 2021 at 12:23 AM Andrew Morton <akpm@linux-foundation.org> wrote:
>
> On Fri, 26 Feb 2021 02:25:37 +0100 Andrey Konovalov <andreyknvl@google.com> wrote:
>
> > Currently, kasan_free_nondeferred_pages()->kasan_free_pages() is called
> > after debug_pagealloc_unmap_pages(). This causes a crash when
> > debug_pagealloc is enabled, as HW_TAGS KASAN can't set tags on an
> > unmapped page.
> >
> > This patch puts kasan_free_nondeferred_pages() before
> > debug_pagealloc_unmap_pages().
> >
> > Besides fixing the crash, this also makes the annotation order consistent
> > with debug_pagealloc_map_pages() preceding kasan_alloc_pages().
> >
>
> This bug exists in 5.12, does it not?
>
> If so, is cc:stable appropriate and if so, do we have a suitable Fixes:
> commit?

Sure:

Fixes: 94ab5b61ee16  ("kasan, arm64: enable CONFIG_KASAN_HW_TAGS")
Cc: <stable@vger.kernel.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2ByVG0-36TUpH8EkQ7r1DHNGTHuOfLfKBKO3aDtCV0RnRQ%40mail.gmail.com.
