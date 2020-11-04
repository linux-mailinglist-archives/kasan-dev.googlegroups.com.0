Return-Path: <kasan-dev+bncBDX4HWEMTEBRB2EDRT6QKGQEVRWAKSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B08F2A6DF5
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Nov 2020 20:32:58 +0100 (CET)
Received: by mail-pf1-x437.google.com with SMTP id 64sf15604084pfg.9
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 11:32:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604518377; cv=pass;
        d=google.com; s=arc-20160816;
        b=A2OMyH2Qk4b8xjcvMDFuR7PKYGOJFz+KruTf29rXQAGs3sLsFeR6XrIZ3DwMYL5EjF
         e2kXY98VZl7ID3yALnNxaKctMwwtITfJQi8hXPyU50LCvv+H0mjmrG0/mi/mSBld9xjJ
         UVsrRmTxZw+670jTfcJm7AHHQDOH2s+YW290TRL24oHxUA1y90iBJgiRLZ8irp2su3ke
         1yod2qV/G/siIaOdSZA0580BR0hnmDNkqtLPtObUYp/Sx/LlANuwqPZJnyKnBjGlnDNT
         iJr3PmBE8u5hJzGg7Spb7Zf6x0szA8TckimcFY4ZC7Jsg5RJCaOKdzXCNRP0BrUuYMIR
         KmXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=17Yhov+zbW1mr+ZwfKV6z6byM7X3caiMYa6moLoFuPI=;
        b=ZmlvbOOM1N2xM+zZC6egWlXVQgazZ/A9OZ3douDNBsaBuLkz8cG6G7lA1lJEaX2U/a
         y1B/6BWMvfthWsVP4TXwQqQD4mGkOFV1hQNpzCB/eETbCBhKfe40AgrWTCkIOq4cpWpW
         yJRiR8+PAjHynFAeDY4sUB7Gz+pqNLa9DCd2kcj2C2i8CsMh16pICAiXrFqS9s28lwiG
         68YX0LH+UWD1VheLD0CwaiYzH9eMPFxVRQcNdXI3eXtKYaQVrSzb0HczF9DNLHfSzUQ+
         sjYlWZP2r974yDfL9ifXtYrM04rv4JDsBKJGanPsH1TADZIM8Xe4PZvt6V4PiG9s2Tbs
         kK0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=N5iD+1F5;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=17Yhov+zbW1mr+ZwfKV6z6byM7X3caiMYa6moLoFuPI=;
        b=G5JgUG/fjujFKlAU/jlsXENIZFbsx6ELjXdHnVVSJgWBNIWnBuQ/bV5YjNVVzKjAtP
         i1CwKD5AAWa0r22PyABfbV19Z1TMsbOLLocLaR+WzWBjTJKxN4yBUSPXCKVHmfxHuehi
         LqJuR7X96WaI87K2IzG/TG7irGb9HD98BXVwB0j0KbMArrW2OlG5eoEkw+0YNxO78qUH
         7WDhjPa86rzd2B0dCehDh25v/UHWnen9JJMOhFXJ8CLL4gg5OMkxQsTgKJQVZMUYvH9k
         io5YqSXKDSwvUB/k7weAXxKxUsafXP8pJR3Qkhmm0XtW6cb4Vfjnvc0tKTBCVVr5B6/w
         pKBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=17Yhov+zbW1mr+ZwfKV6z6byM7X3caiMYa6moLoFuPI=;
        b=N+clCnjBLSSstXQrgtsTtBUreIAcW0rYGRnFpteqXiVYeVd56dl0hqDXl2NmKHcNar
         IC9l/HSZQ+aoY9M0j46CJiYyzsHQvQQ8g+NUER9cRSeetC/OjnlFUTI1MnvWODrnT0t5
         pDpaUQrbLq6QsfAWAzq5D9DYPg2UF5a1jFOboxjXZtbJ5/O3de98EWkUiw8XuXoWzDJg
         O7BHAPuh+ESqmJ1H0tuRM6NRqeOSHqvYJ6Qa6UnxZj+A0tZ3MItMC06EhyXbXOofdQ1v
         +QUZkPGl5HZlYbBjmzo6A9BBiXQOBVnhald/FGsmuk/Wk59PegFbpsoNGnaMtK+3YCB+
         W0uw==
X-Gm-Message-State: AOAM530nonJpER6w1k9QnylK8ZMNMD6s9+//9XuYXVg3+53XN9UH+GxB
	PtuUqA6xafKwEN98tQTNpPM=
X-Google-Smtp-Source: ABdhPJya1JjZOQSN6ikiRl0jSTtm5rCUkujVWu0GQatQvpVYAkFXbuztrl4LJXPudrJCsi96jrbkfw==
X-Received: by 2002:a17:902:a406:b029:d6:cdb0:9afe with SMTP id p6-20020a170902a406b02900d6cdb09afemr14529877plq.24.1604518376974;
        Wed, 04 Nov 2020 11:32:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7809:: with SMTP id p9ls1464680pll.7.gmail; Wed, 04
 Nov 2020 11:32:56 -0800 (PST)
X-Received: by 2002:a17:90a:f2c5:: with SMTP id gt5mr5864226pjb.66.1604518376378;
        Wed, 04 Nov 2020 11:32:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604518376; cv=none;
        d=google.com; s=arc-20160816;
        b=BatVdrMeeV3aYkpKp66/Y2BaBavV6449M22mdKmg/MG6ovbI2iapwNrHGMHtAee3or
         utc0hvQHelt/nnCpmh/zpgpdrQGvcGt2lUMAZHqn3ihWc9a5gh5bZdXE6BBFXVyW3YcF
         bBWZok4tSJl1NGAtr5ocY7RJ5q6w4M3zq9vIBanfw4gX0pXVVskU14EQeGpOmeibLWKJ
         jg1DRfbc7/1K39iFChveBI9vNZLhKSq9sxIUuYPxS5F0iFKxqkdcdHU0f0My+zD5SS5o
         Exz2QnI81z54Jlfc1G5muKe5C6fnhExlQGUdRteYafMVIrmu9fOetEIs5DZUFXyPeRoo
         3V+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Gp5b6Mr5Qne4OLUNKLGgmsC9HZETysD3ixRMlsHSDMc=;
        b=WlvakMhPlF1p/MuPwKvRevxLAUdpQFzBJyMFtv1eBscqR6lJzGa/7PlgoyShRzgqna
         WseT3K1Z4G1HWheRNixOmQEkNLlwgz+qtaOf3ngtAnq58I6oSeoBHn767lL+o7whkAaU
         dlP4hNvJxv0yuxQt4p+gx9R1bd2mD4JnbMtzZUO3rgrtAPZHM1c3O+mzQ4zA2//y3NCs
         97BNq1m1bgNLm99zKfgSK3IKC96S8XHElLRXrj74DnMIzzfI+vh291U4ctUL/kLjpxIQ
         gCiYlvWQOm8EfhG70SY6kSuVIZqJg/PfVSdg0yF1/y67rPrLDt6plPZwgb3OX8E1In52
         8qmA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=N5iD+1F5;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x643.google.com (mail-pl1-x643.google.com. [2607:f8b0:4864:20::643])
        by gmr-mx.google.com with ESMTPS id f2si204058pfj.5.2020.11.04.11.32.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 11:32:56 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::643 as permitted sender) client-ip=2607:f8b0:4864:20::643;
Received: by mail-pl1-x643.google.com with SMTP id x23so10778313plr.6
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 11:32:56 -0800 (PST)
X-Received: by 2002:a17:902:e993:b029:d6:41d8:9ca3 with SMTP id
 f19-20020a170902e993b02900d641d89ca3mr32168650plb.57.1604518375779; Wed, 04
 Nov 2020 11:32:55 -0800 (PST)
MIME-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com> <4dee872cf377e011290bbe2e90c7e7fd24e789dd.1604333009.git.andreyknvl@google.com>
 <your-ad-here.call-01604517065-ext-2603@work.hours> <CAAeHK+wuJ5HuGgyor903VcBJSx8sUewJqmhA_nsbVbw0h2UFXg@mail.gmail.com>
 <your-ad-here.call-01604518242-ext-7611@work.hours>
In-Reply-To: <your-ad-here.call-01604518242-ext-7611@work.hours>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 4 Nov 2020 20:32:44 +0100
Message-ID: <CAAeHK+wddqC7WeeiDsEUNB9pWMpZz7ZSpJvMPtHCfbBO=uXoMg@mail.gmail.com>
Subject: Re: [PATCH v7 16/41] kasan: rename KASAN_SHADOW_* to KASAN_GRANULE_*
To: Vasily Gorbik <gor@linux.ibm.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=N5iD+1F5;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::643
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

On Wed, Nov 4, 2020 at 8:30 PM Vasily Gorbik <gor@linux.ibm.com> wrote:
>
> On Wed, Nov 04, 2020 at 08:22:07PM +0100, Andrey Konovalov wrote:
> > On Wed, Nov 4, 2020 at 8:11 PM Vasily Gorbik <gor@linux.ibm.com> wrote:
> > >
> > > On Mon, Nov 02, 2020 at 05:03:56PM +0100, Andrey Konovalov wrote:
> > > > This is a preparatory commit for the upcoming addition of a new hardware
> > > > tag-based (MTE-based) KASAN mode.
> > > >
> > > > The new mode won't be using shadow memory, but will still use the concept
> > > > of memory granules. Each memory granule maps to a single metadata entry:
> > > > 8 bytes per one shadow byte for generic mode, 16 bytes per one shadow byte
> > > > for software tag-based mode, and 16 bytes per one allocation tag for
> > > > hardware tag-based mode.
> > > >
> > > > Rename KASAN_SHADOW_SCALE_SIZE to KASAN_GRANULE_SIZE, and KASAN_SHADOW_MASK
> > > > to KASAN_GRANULE_MASK.
> > > >
> > > > Also use MASK when used as a mask, otherwise use SIZE.
> > > >
> > > > No functional changes.
> > > >
> > > > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > > > Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> > > > Reviewed-by: Marco Elver <elver@google.com>
> > > > ---
> > > > Change-Id: Iac733e2248aa9d29f6fc425d8946ba07cca73ecf
> > > > ---
> > > >  Documentation/dev-tools/kasan.rst |  2 +-
> > > >  lib/test_kasan.c                  |  2 +-
> > > >  mm/kasan/common.c                 | 39 ++++++++++++++++---------------
> > > >  mm/kasan/generic.c                | 14 +++++------
> > > >  mm/kasan/generic_report.c         |  8 +++----
> > > >  mm/kasan/init.c                   |  8 +++----
> > > >  mm/kasan/kasan.h                  |  4 ++--
> > > >  mm/kasan/report.c                 | 10 ++++----
> > > >  mm/kasan/tags_report.c            |  2 +-
> > > >  9 files changed, 45 insertions(+), 44 deletions(-)
> > >
> > > hm, this one got escaped somehow
> > >
> > > lib/test_kasan_module.c:
> > > 18 #define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : KASAN_SHADOW_SCALE_SIZE)
> >
> > You mean it's not on the patch? It is, almost at the very top.
>
> lib/test_kasan_module.c != lib/test_kasan.c
>
> I fetched your branch. And I had to fix it up to build old good kasan
> test module CONFIG_TEST_KASAN_MODULE=m

Ah, right, it was just recently merged into mainline, that's why it's
missing. Thanks for noticing!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwddqC7WeeiDsEUNB9pWMpZz7ZSpJvMPtHCfbBO%3DuXoMg%40mail.gmail.com.
