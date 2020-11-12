Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPN4WX6QKGQE26TUO2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id E0B0D2B0990
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 17:09:34 +0100 (CET)
Received: by mail-pf1-x43c.google.com with SMTP id b139sf4299073pfb.2
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 08:09:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605197373; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZKoqlAYRUDdN0NEjivYFis2ke2qCaQC+pKlUnFq/dJiCzHvI6bfD90WrTwoj7rf/YN
         iawUctm9FuHXOuC8ZFR0SAspmkIjSvc5H/QrgF1stC5l46A+aDPoqswQ7LMGcEbZVRpd
         UMGxUStva3k3aIVItwMwvNGvhClCFD0xPQpQvxArkLx28kSskJxB6wjH8EocS2VWr0LA
         7k26EH6SmCNXJcidYv2XUJnp/lflTHa5OeJ5GKF5TiWN/cYCb3vxTcLnpnZofmWxuYZT
         MYCUz343W0pvqYK+GZqcsSiIGj4kDCV6SK7Kh32DodIWnwsMxzJbkhtnInz9IpKroMGc
         cp8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=l/JL/BlOu56juZ8N4QacgGyoQrfZMbFOch/1/S8wcjI=;
        b=WjEkta45Oi/X+PC6lS2/JHYzIw+XBrt/+v1ZtTGfsSsV2XdNDvcPCUBYuMArQsDht7
         7+h+VFX6ejpbMCzcP/Cskn2QzCitms4zU50UAbr6bGiazgLMUBdcWp8z3Gyz/sIhZ2gx
         bWpEqeYrZT2ZzLKUBs1X2i8+LpEEGe+NSObc+iBliRnErK+rYuI+OQrfvCaVM+k/Ydzu
         6j2rjpYRrlmxIiyQY933wBuS/NPlf0VNbQz+syTrFliYhM38wgSGlB8XC8qrh7ho9qrs
         qjEZ6tKmDK841XmeMqW9B7iP4VgdZw3veK/oF22O1sd4hm1L1wHia1uDOgpmfpNMqkMw
         meVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Y0UBlSyA;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=l/JL/BlOu56juZ8N4QacgGyoQrfZMbFOch/1/S8wcjI=;
        b=O6W6XaE9M0jt16x1T1l5N7CeOLHOwrO9MxzCJfuSVKs38fwQXdCGwcDzCNOmob9pH+
         ++fSk7DuXsOWXDlY0qvvor0AjpjOKLmgxCE+ND1Rf0zFli0aWReiqsBM6U8mWLrX/3Tf
         EKNk0+X1H91HKGZzvmoc+3oKRERVqvKh0R2TIpXV4aW7klGdcNdCoBiA2DmJdNKRTsAD
         ZlySO7Vh8dM5RN79/hNYHZJSePhBA4gmuHrEm/vKFIY7axplP7RY3w0H8YDMcylSAb8p
         owz2gdHYwXP8ivRwPmaXMhM4qUwHgD99bCaBdCVxVnoxrsy3/EAtcpwJbiwyUom+Sw/r
         xu+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=l/JL/BlOu56juZ8N4QacgGyoQrfZMbFOch/1/S8wcjI=;
        b=SN6BqaJJIYZKk8gQ24/IYPta/Tv/6dAJOzOczOpiQeZJ+k81aDQvcyly0RV0ivo2Qa
         HlmBR5kcYMHWw7c9yLTZNEDGJxCZbZpzWzvy5pjGCgI7v6/3pFF/hP+S+xFrmIvTeVHC
         SSlQJDwOueAsq+7COEiKAKVnspEgt3TOpWwIgu/AzQeOA2qDPTnJQoOtR8OA7AxEbX0p
         drsmrVJb5R+yMSeXOBvqJUaTmUcyRwvjdFQYnI+/EfZ0UMDhXWtJTmlPQqv2zqRfjs8F
         7YsPCtB+XeXkVZkah+QvdnI8Fm/GWrDcCTLLSozneFHOI5y/11+ExFxrNSxU1YV+AKJO
         7kxw==
X-Gm-Message-State: AOAM530jppeB74+sXyw3u1jAhbYwFd+WInGkZksADIaoDGOHop0nWkZo
	sKBhzYfkyx3UE2lUGj7jF/M=
X-Google-Smtp-Source: ABdhPJzsOD+GL36ndIz9HYloZeiF/si16IZzf9ux9vT2eOVF+x8ADZEDfqTZNhGtwvFNEFAQDWi7cA==
X-Received: by 2002:aa7:934a:0:b029:18a:aaea:ff4 with SMTP id 10-20020aa7934a0000b029018aaaea0ff4mr195696pfn.56.1605197373617;
        Thu, 12 Nov 2020 08:09:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:aa08:: with SMTP id k8ls1928002pjq.0.gmail; Thu, 12
 Nov 2020 08:09:33 -0800 (PST)
X-Received: by 2002:a17:902:c10c:b029:d8:c028:5ceb with SMTP id 12-20020a170902c10cb02900d8c0285cebmr124101pli.36.1605197373013;
        Thu, 12 Nov 2020 08:09:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605197373; cv=none;
        d=google.com; s=arc-20160816;
        b=zofspa2xIYr/3qHK6nm+hoPodsyLTXrYWPIvzLz2fF+cqUiMqzasXNhL66tVmTA+5r
         7Igq05D8BdNbLxcnqB3dMloBIGIlM3fUQI/zrtWsYp4zZXdGQGJ/1DKhGtaG3Aw6a/qR
         4EIJiGekZah/jk+xS3eM4eTT8PyJIR0kz7EDiWGc3n1WiE4CW/RZngfGgc702PsdorRR
         VdjEVXLgUZY728avgfBZnYrgDDGWNopTvHwz+zRuUaL9WIoPI+ZNOc2vN9SJ7b5iLdHb
         lTJEAyVoFXSHU1r1ntBnz5tkQ/vWxFaA2Y1vXyYSx0j/ulpCC/e8uP2OM6LGscxz9HF9
         pD0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4E3aNnRy7r7yE8tRTHVuCw1bn/xlTevCdbx03WDIkcU=;
        b=C1m6Fwc7kqgd2NRrAbC419QzYZyBYBw75gIDtvw9NSaiKZ9tXye7DpEPaDs0C1Tbaz
         8a4pJ+N3uBYm+sBRArPlnYqEPHDWamsstVj1zZiz4QTHjHfzbFJV9SjzVqejQbk1Sjle
         WVPuygs5qO+kJf+JWzI3nqyOV0kd/cVnlYQ2pcyAb7wosV9h/3Zw/5vlv+SF/zRyLHTP
         i1zf2m8ky2hE00U+5tKXwrpJ3P5cVTPZ1J6EwjGAmYzebdMI4OsWtdwQs4JkstnGDvd3
         QROWzKX7yQl5s8UN7Y1EUIsWUJaVIU4geEVWSN9yKkJTVApDJ3aatjm9hpwh8QLiCPLA
         LkPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Y0UBlSyA;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id 38si349287pgq.3.2020.11.12.08.09.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Nov 2020 08:09:33 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id k3so6040831otp.12
        for <kasan-dev@googlegroups.com>; Thu, 12 Nov 2020 08:09:32 -0800 (PST)
X-Received: by 2002:a9d:65d5:: with SMTP id z21mr20378820oth.251.1605197370706;
 Thu, 12 Nov 2020 08:09:30 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <bd6825832c0cb376fc68ad61ffec6d829401ed0e.1605046192.git.andreyknvl@google.com>
 <CAG_fn=XpB5ZQagAm6bqR1z+6hWdmk_shH0x8ShAx0qpmjMsp5Q@mail.gmail.com>
In-Reply-To: <CAG_fn=XpB5ZQagAm6bqR1z+6hWdmk_shH0x8ShAx0qpmjMsp5Q@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Nov 2020 17:09:18 +0100
Message-ID: <CANpmjNMaDkKBtWF8y22rhc6bFNN0CrXgfGNKXBLPvz3c2wd7rA@mail.gmail.com>
Subject: Re: [PATCH v9 44/44] kselftest/arm64: Check GCR_EL1 after context switch
To: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Y0UBlSyA;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as
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

On Thu, 12 Nov 2020 at 16:59, Alexander Potapenko <glider@google.com> wrote:
>
> On Tue, Nov 10, 2020 at 11:12 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> >
> > From: Vincenzo Frascino <vincenzo.frascino@arm.com>
> >
> > This test is specific to MTE and verifies that the GCR_EL1 register
> > is context switched correctly.
> >
> > It spawn 1024 processes and each process spawns 5 threads. Each thread
>
> Nit: "spawns"
>
>
> > +       srand(time(NULL) ^ (pid << 16) ^ (tid << 16));
> > +
> > +       prctl_tag_mask = rand() % 0xffff;
>
> Nit: if you want values between 0 and 0xffff you probably want to use
> bitwise AND.

Another question would be, is the max here meant to be 0xffff or
0xffff-1. Because, as-is now, it's 0xffff-1. Only one of them has a
trivial conversion to bitwise AND ( x % 2^n == x & (2^n - 1) ).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMaDkKBtWF8y22rhc6bFNN0CrXgfGNKXBLPvz3c2wd7rA%40mail.gmail.com.
