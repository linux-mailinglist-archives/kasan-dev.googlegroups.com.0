Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKUQW2IAMGQEY2AMDKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x940.google.com (mail-ua1-x940.google.com [IPv6:2607:f8b0:4864:20::940])
	by mail.lfdr.de (Postfix) with ESMTPS id DA4E84B9476
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Feb 2022 00:26:35 +0100 (CET)
Received: by mail-ua1-x940.google.com with SMTP id h19-20020ab03093000000b0033c6844fdf2sf1481611ual.16
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Feb 2022 15:26:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645053994; cv=pass;
        d=google.com; s=arc-20160816;
        b=zFEAk30sn7KkULDLa3UhT/WRRDrj21IAxtgXc5UGF0rl4hMB2HuH3UdmEt5z/6FNhD
         eGPfApCsd40W3ZBiHQHSzwEpJUh28HX2H9mSFPbGAZobfGpkcUXhVhJbCGmn/gtMGGmU
         EGa0Wi59uRZUN1VG6NkSUBdZ4fMCr34q96ajrSaOsAmOh+l0j7Isu/uuHwk2sT3WVELh
         NrrFhLTloF+g6HNBxMu77nzRssXCv2lg0ji7jShWbKZcX95o5+iAJKF5wY5HwfdDQuhC
         sHQrCQgM0tSJr8PX/0grIfZvgtCtW+8MRF7XpX0EgLZprRR/RGROD2WpAlbVYZ7J+3YS
         /x/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ZBRkEf2Tg47NKgS/G6Ze9v5QbouSBsLzmfObo3v0F9I=;
        b=wBGHUrPh2ab9QrHS+qQcg58cM1jYACDLvpgP03ndju8TOGUSLi9F/BK9ISKeJJrjVd
         UjXTaOLBdQy+5Z4uacYPzzggvtn47Vz90IirHMulH3M9fanPsVlTfHp4kV8cJPQarbT8
         +7iPxVT4+8CaaKA8sNG00Zpd0hRBXx/qNs4bXlzPmcVlLDCgs/KAcFgqrk3oN1Rd+G3N
         P3fDixaZnPip+82nTftlTf/xzrYmXJGb2gSuv69x1D0Nzw17UYBfgTCsneC3QzN6mPXO
         gnG7O7cZ11YuvsCXVuIcFe1pTV5gFv9zfrGnEyhgTcwFqKiLjpfRAiE4hu99pm6ncCa4
         MTyQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=du1dfzkC;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZBRkEf2Tg47NKgS/G6Ze9v5QbouSBsLzmfObo3v0F9I=;
        b=Rms4hkpgnsuQ1kf0oBFZw8RBgmmPGBlUjQ2rnE+RLqYKq60ll54eD28+Q17/HVg8bQ
         id8Xewdqgxnw3lDtuWiurL/B3KBYLdwiArWm6xvqWRH0+USHPWS0UD5qzzBxTDScQ44h
         LEJg2pBNm3pVXco73trcT0HE+t+puYRfffSTPDUs9R7IXOkDz2XJzHFd7GFUQNCCz+RE
         f5qt/LQrseFS7+Od9V3Y/KgmRWXQS7nJvXNU37gIUu2QIoxJAizh7djHzC4DvS5fxZtK
         yCrCsvlSj9xby5ds1XahP/6zMvw5kcjCcLLw9VcTzL0+rkJMylNZ6sFzB1ywGF6s3kX+
         90gQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZBRkEf2Tg47NKgS/G6Ze9v5QbouSBsLzmfObo3v0F9I=;
        b=JSvURxT20u1hSDjSsnLsbtvqTLhtKeFHlpT0Hf2OGIFVN7juwk8dfgH+cRm8/Qo3B1
         d8jWNQpy54dOqQa6+1e+S4MR1BCTDnxu68Zuspous/z8zXrfauAsWuD/MwCn/78S1/to
         rWKlAL+mj2oPGYm73WgZhGsd0ieOWScyJ0QFqu88KJ4iS02YcM9K4Dc5tIRO2ncdDhFx
         Jbs2ETYIv3Y5FMcP7e5Gx8cMPOtdhV1xgupSl7DL8Y/G16lBq2YB1m5WQeOh7p9vMlDQ
         KiKkTuWvj/r6MjmBVTWpybvZAIfvCyy+H7Y0ZX2bvKbopXookWjVslcxcAbQVgSRLsKB
         2EXw==
X-Gm-Message-State: AOAM533lPSyFjHAeCJ5AKjId7i4hFkyuoYJYu60lLv0WrClQPPpOYKII
	Qw4622MPom3ykewruUm5CoM=
X-Google-Smtp-Source: ABdhPJxX/+8Pygqbw6595JX8NRXT6/+QKUpITIcDZvzhMtz+nMoJqdAfpTyJoNKCofYjjJimbFIbxg==
X-Received: by 2002:ab0:2306:0:b0:341:162f:4615 with SMTP id a6-20020ab02306000000b00341162f4615mr71023uao.140.1645053994804;
        Wed, 16 Feb 2022 15:26:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f2c9:0:b0:31a:835d:71b0 with SMTP id a9-20020a67f2c9000000b0031a835d71b0ls211693vsn.3.gmail;
 Wed, 16 Feb 2022 15:26:34 -0800 (PST)
X-Received: by 2002:a67:cb91:0:b0:31b:8112:bda2 with SMTP id h17-20020a67cb91000000b0031b8112bda2mr24775vsl.70.1645053994277;
        Wed, 16 Feb 2022 15:26:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645053994; cv=none;
        d=google.com; s=arc-20160816;
        b=ZFUTxc7/gZMo4/t9S8Mu8sDmtZ7KrSIYkv7w/JRNWa4l3NhkmTqtU/wdK9KrCiXy2+
         096DmjS0EB0QXKsPx5czuZJ7xor3lTQhJM3rAMsOavY9b2+cgoajkq2uYvToUen/7iJr
         pzSy8QXH2DDla0ZA8j900lIkUghv+HMcyQO8NzdlRg1OM9jzwlEGVXlNyvRVDVKaWlZn
         R6Yfz6rE5xccM4hFLiP8/X0kNKDRlGagQO/MwEmh+4Z30hn5OcAIl1qpYixdfrnUFrQC
         Cp1kWNvl50PC9SEq4pHne39GpsAdHkiGdDP/Ms8ziAw68mACywVB+82U0sqJVXs5ejZR
         bMUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yl++UbQHvu031O88qjaOvVPH96zPax6XyUywms3AfE8=;
        b=Ueq4XeQSt0MB4gtsEd5gY5/L0w3aSELCyqkRKmkxtwjaJlbWLW2uG6/Nl40PbU5NXL
         NfIwUxDIcs3xnzbq1pHy6oUAh23fsRJ0yJbXn4GIjt/emkVWMWCzm2boDJxQj+glXzTO
         Ear8s7854e4A46Zkshz2YUHT8W7ge5U2mMEMNdxtHn2p68BuqW+xREeds2LkoCl6yVvq
         5+FMLMjSH16NKiikLizVlokPuzUO+ILDghv1O3hq8ZNvnF9RQbzaRiMPqbtSzTiB/A+U
         mLy08VcQ1y7T/JIaopDfU73+MAWZAQvLbqI8t4Ear9uYqAHXOf4qnNP4Mm9PTLBWEGWt
         T97Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=du1dfzkC;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2f.google.com (mail-yb1-xb2f.google.com. [2607:f8b0:4864:20::b2f])
        by gmr-mx.google.com with ESMTPS id y139si578553vsy.1.2022.02.16.15.26.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Feb 2022 15:26:34 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) client-ip=2607:f8b0:4864:20::b2f;
Received: by mail-yb1-xb2f.google.com with SMTP id j12so9409816ybh.8
        for <kasan-dev@googlegroups.com>; Wed, 16 Feb 2022 15:26:34 -0800 (PST)
X-Received: by 2002:a25:28a:0:b0:620:e848:af9b with SMTP id
 132-20020a25028a000000b00620e848af9bmr218531ybc.374.1645053993763; Wed, 16
 Feb 2022 15:26:33 -0800 (PST)
MIME-Version: 1.0
References: <5b120f7cadcc0e0d8d5f41fd0cff35981b3f7f3a.1645038022.git.andreyknvl@google.com>
 <CANpmjNP0QCMhSL+ePf5G8UwbmdjM-qpimAQbuQD+pYK8Gx+2Gw@mail.gmail.com> <CA+fCnZd0aXZcZaSs7ijUZ+WaD6+s0vPcnp1vLOn2=1dSJQMa8A@mail.gmail.com>
In-Reply-To: <CA+fCnZd0aXZcZaSs7ijUZ+WaD6+s0vPcnp1vLOn2=1dSJQMa8A@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 17 Feb 2022 00:26:22 +0100
Message-ID: <CANpmjNOgae3xePOekX5jDD29rLi-3Us9N7LskXaRpU8BOirnyw@mail.gmail.com>
Subject: Re: [PATCH mm] kasan: print virtual mapping info in reports
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=du1dfzkC;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2f as
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

On Wed, 16 Feb 2022 at 21:42, Andrey Konovalov <andreyknvl@gmail.com> wrote:
>
> On Wed, Feb 16, 2022 at 8:31 PM Marco Elver <elver@google.com> wrote:
> >
> > On Wed, 16 Feb 2022 at 20:01, <andrey.konovalov@linux.dev> wrote:
> > >
> > > From: Andrey Konovalov <andreyknvl@google.com>
> > >
> > > Print virtual mapping range and its creator in reports affecting virtual
> > > mappings.
> > >
> > > Also get physical page pointer for such mappings, so page information
> > > gets printed as well.
> > >
> > > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > >
> > > ---
> > >
> > > Note: no need to merge this patch into any of the KASAN vmalloc patches
> > > that are already in mm, better to keep it separate.
> > > ---
> > >  mm/kasan/report.c | 12 +++++++++++-
> > >  1 file changed, 11 insertions(+), 1 deletion(-)
> > >
> > > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > > index 137c2c0b09db..8002fb3c417d 100644
> > > --- a/mm/kasan/report.c
> > > +++ b/mm/kasan/report.c
> > > @@ -260,8 +260,18 @@ static void print_address_description(void *addr, u8 tag)
> > >                 pr_err(" %pS\n", addr);
> > >         }
> > >
> > > +       if (is_vmalloc_addr(addr)) {
> > > +               struct vm_struct *va = find_vm_area(addr);
> > > +
> > > +               pr_err("The buggy address belongs to the virtual mapping at\n"
> > > +                      " [%px, %px) created by:\n"
> > > +                      " %pS\n", va->addr, va->addr + va->size, va->caller);
> >
> > Can you show an example of what this looks like?
>
> [   20.883723] The buggy address belongs to the virtual mapping at
> [   20.883723]  [ffff8000081c9000, ffff8000081cb000) created by:
> [   20.883723]  vmalloc_oob+0xd8/0x4dc
>
> > It's not showing a stack trace,
>
> No, only a single frame.
>
> > so why not continue the line and just say "... created by: %pS\n"
>
> Putting it on a separate line makes the line lengths looks more balanced.
>
> Also, printing a frame on a separate line is consistent with the rest
> of KASAN reporting code.

That's reasonable, thanks.

Reviewed-by: Marco Elver <elver@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOgae3xePOekX5jDD29rLi-3Us9N7LskXaRpU8BOirnyw%40mail.gmail.com.
