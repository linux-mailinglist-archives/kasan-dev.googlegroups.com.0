Return-Path: <kasan-dev+bncBDX4HWEMTEBRBZWT6H6AKGQERNZYYVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id BF10F2A0EAD
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 20:30:49 +0100 (CET)
Received: by mail-io1-xd3b.google.com with SMTP id i19sf5067088ioa.19
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 12:30:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1604086246; cv=pass;
        d=google.com; s=arc-20160816;
        b=nEi3cU+I/4CQG0nXrC+HopEuFawIFM9I8TSFyL6YYn2eMdcj+x/t++9/5aMUtLa/s+
         brxA0nx42rcJUoJX4fO+w/JWWSUPKD7nvpBcY0KAOU+NxtpKT6Z7ljM03E/FvpAdbdY0
         UI9djkCfi6tBnQ4qFBCaC9p3LUlY8ndxfPVVrWaz1y7wQHR1Y0f9z0fI1dRSHT6LSQ0A
         yIKk/ZzqnKNRa/gXJHl1H/bUshcRwoLUJyrbm5PedFdYjvZXeF0aY34j6sgiKK8Zq8ok
         rVn7qXde/qoVgJxGEmUjx7nENzBtOibl/GqHAMMyDZd9Xwl37RDH9r4Pcb1oxJIidZrN
         H6rg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=A3fyLP6HZzQ5Ni4xg2JwU0LChNjh5hwv2R0x+GlMEm0=;
        b=YlGncW+DlvNqPrPRHjV8orBOaH5m5PVrNgVImQ4RPMWYcOxfiC+i3WOIdXj5Oldkw3
         zltcR7KoK+BmyDFX8705TN/Y/z1gs/JGAdf46r/UVe6UPGipAlm1YEFCe7LOvzBsEkTG
         jrAvAwxPesER1Tc4OfohRN9Sjb+AIvIMYOHYPtgvWcWkYtJFpH3sbMDAVh2TmEzlaPBe
         NtqPXNkivGDWkH50mIQ6XZXaA3KACHl15wyLbgzICehBCLhtnAqbjH2JyTsyBkEzWPyE
         E4x/Ds5TJ7H2VaZNV14Eh19Ek4G/JABMIcr4G/BuqU5lQq67yQoQ8gQNJBcCkDhZRGlI
         DjJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kbvQq2bu;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=A3fyLP6HZzQ5Ni4xg2JwU0LChNjh5hwv2R0x+GlMEm0=;
        b=C37Z7SIS8CWlkqUksCPRDgzfjbN37W3f3y/ga0KJmvmHmC7OxnVd/cP4JJSGTuG0wp
         XWZBya5FvITfxe35Zkehs6SH871xHjXWOWcsBM2YTQkEgBgiBnhhtgxvA/ZvVxK24+v8
         e4qbHEgVmVFx+m4DruDP4MuDPBCIYOk1eW6NBteFOgpvKl/q3tD9jUmExmsl3UnEG/5S
         ZSkNSj2JeX3wvr0D+V70Kcz573lVTVu0ryE6ZOtcKR4zPfoPMnUpGFU9IGmolbrT5qpB
         oWCw1Iqjaey+3aar5YMWCHRFl52prNpUnIVm7Km4QzfP3WJYb8S8Qn/olhfuhjJlSrv+
         1pFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=A3fyLP6HZzQ5Ni4xg2JwU0LChNjh5hwv2R0x+GlMEm0=;
        b=MP0Xb99ixt2bTHFyg6YTdNB/VP9EYBVPMC9+evwdbeK6VdQyDIb/ZyXEZHxDVCh6sQ
         2sBlEHdrB1uYywAMdu5B1U0Ycq7SR1iJpNdTemG+ySC5cTJhiUwVki70cEOoXAJZw4M+
         RtKq07n+exlE/5a2PQD0y+T7nKn4sk5FiaGe4Fe5EsD//uA87FlvHqgQaMFxC5ofR1u8
         E7mU51cAuJRclTzJtFL3sokycG5t6NdjeCfWmJbBE9Wl+tFZq+PB/Vqbw/mfkWGbyHhg
         I00hWhZr3asH7FdrY2ei9Qu8G1lJzqCaLt/addJgWZVNPFp0SXoO9zW8/BrysjGW2GTB
         AEMw==
X-Gm-Message-State: AOAM531/Rl5mPv9IcIM93/NWl0zaf2zqFcVH/taZK0EjFUjS2jzdSX+b
	X7zaPTC2yg0eSHUfcESt2WM=
X-Google-Smtp-Source: ABdhPJyjZPvLagl8TuvwUVI7yWw/8XBpsAdnEqvFqpvB0uFXMCOK4Ogdp4zu6iLraGarRDc3/EDwtw==
X-Received: by 2002:a92:cd0a:: with SMTP id z10mr2644643iln.74.1604086246450;
        Fri, 30 Oct 2020 12:30:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:1308:: with SMTP id r8ls915092jad.7.gmail; Fri, 30
 Oct 2020 12:30:46 -0700 (PDT)
X-Received: by 2002:a05:6638:2603:: with SMTP id m3mr3204885jat.43.1604086246077;
        Fri, 30 Oct 2020 12:30:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1604086246; cv=none;
        d=google.com; s=arc-20160816;
        b=rbf+5lxgn6QdjCUx/naTpy5f5NzFPiODnY9hS5BCmyMx4ruACC5bbTxRedd93Un2Yk
         tPZM5pklsWOleLLpkPc5TixLSL0aLPW1fCCgLTaaA1N+rC4FO4i48Evswjkbkze++YUA
         ZA9+uiPo3PRWS+D6V6Q0fB/eJyAiDKbMBOmfkGKK8sOCYK6GH07dRUSRQwspBcjG68ya
         s87mNkW36B/8hKt1TTSdXfqJx3JAPo0wBPH8qqyNRVoF+SaHMWPsWNq4/uUojxAtVR4Y
         S3Q9CXq4vMND0/nYEBLgOHi4E7MQuqb5GzypCnlnhi3D+mQpTtfQJXeO4CG8LTB0z8zZ
         6ybg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1Ew5qTvePmElYR26zs05QLzhONyFgn22aBK2jtdC+Ac=;
        b=F4dwi4l9ut1etx7Mr15JO0Wejhcwj6htg2EvO6+UChOhkFTPwISmB4YvqdHmDeU+qf
         rFkmjJwHEpwIiie0EAcaMuMacxlzj6bI1eFCZ7Yu7pL6JEzlgw/r32bd41k68d5bTi3W
         uWrYmwimAugbhgMshqsZwewkLJdD40K5laxXOS7OAVBV0fGY4O3pvKylFzbsFeaHipLl
         NCaW330wsrwE5ZxHwHENsChKoTvgheukUZXTnbIABDh9xN+RKPhledW71QMcPZgfvyxO
         Zrfpt+jrxdrgnde0boT/BRC6mDxHMg+sVdJSa+ChcxAT1HJ6ans4J/QkOKCrFLoU8kkL
         27LA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kbvQq2bu;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x644.google.com (mail-pl1-x644.google.com. [2607:f8b0:4864:20::644])
        by gmr-mx.google.com with ESMTPS id d25si426711ioz.2.2020.10.30.12.30.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 30 Oct 2020 12:30:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) client-ip=2607:f8b0:4864:20::644;
Received: by mail-pl1-x644.google.com with SMTP id w11so3446005pll.8
        for <kasan-dev@googlegroups.com>; Fri, 30 Oct 2020 12:30:46 -0700 (PDT)
X-Received: by 2002:a17:902:9681:b029:d5:cdbd:c38c with SMTP id
 n1-20020a1709029681b02900d5cdbdc38cmr9755114plp.85.1604086245375; Fri, 30 Oct
 2020 12:30:45 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <6a4a7626bf280871518656f4fa89cb064740baf7.1603372719.git.andreyknvl@google.com>
 <CANpmjNPxUwrwAjN_c5sfBx5uE+Qf70B=8dbFcYPF2z1hWfpATg@mail.gmail.com>
In-Reply-To: <CANpmjNPxUwrwAjN_c5sfBx5uE+Qf70B=8dbFcYPF2z1hWfpATg@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 30 Oct 2020 20:30:34 +0100
Message-ID: <CAAeHK+wF_BBSDukSPRTTc0N=OuFgKXquzthCxdR3Gq=p6jA9WQ@mail.gmail.com>
Subject: Re: [PATCH RFC v2 14/21] kasan: add and integrate kasan boot parameters
To: Marco Elver <elver@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Kostya Serebryany <kcc@google.com>, Peter Collingbourne <pcc@google.com>, 
	Serban Constantinescu <serbanc@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=kbvQq2bu;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644
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

On Fri, Oct 30, 2020 at 3:45 PM Marco Elver <elver@google.com> wrote:
>
> On Thu, 22 Oct 2020 at 15:19, Andrey Konovalov <andreyknvl@google.com> wrote:
> >
> > TODO: no meaningful description here yet, please see the cover letter
> >       for this RFC series.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Link: https://linux-review.googlesource.com/id/If7d37003875b2ed3e0935702c8015c223d6416a4
> > ---
> >  mm/kasan/common.c  |  92 +++++++++++++-----------
> >  mm/kasan/generic.c |   5 ++
> >  mm/kasan/hw_tags.c | 169 ++++++++++++++++++++++++++++++++++++++++++++-
> >  mm/kasan/kasan.h   |   9 +++
> >  mm/kasan/report.c  |  14 +++-
> >  mm/kasan/sw_tags.c |   5 ++
> >  6 files changed, 250 insertions(+), 44 deletions(-)
> >
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index 1a5e6c279a72..cc129ef62ab1 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -129,35 +129,37 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
> >         unsigned int redzone_size;
> >         int redzone_adjust;
> >
> > -       /* Add alloc meta. */
> > -       cache->kasan_info.alloc_meta_offset = *size;
> > -       *size += sizeof(struct kasan_alloc_meta);
> > -
> > -       /* Add free meta. */
> > -       if (IS_ENABLED(CONFIG_KASAN_GENERIC) &&
> > -           (cache->flags & SLAB_TYPESAFE_BY_RCU || cache->ctor ||
> > -            cache->object_size < sizeof(struct kasan_free_meta))) {
> > -               cache->kasan_info.free_meta_offset = *size;
> > -               *size += sizeof(struct kasan_free_meta);
> > -       }
> > -
> > -       redzone_size = optimal_redzone(cache->object_size);
> > -       redzone_adjust = redzone_size - (*size - cache->object_size);
> > -       if (redzone_adjust > 0)
> > -               *size += redzone_adjust;
> > -
> > -       *size = min_t(unsigned int, KMALLOC_MAX_SIZE,
> > -                       max(*size, cache->object_size + redzone_size));
> > +       if (static_branch_unlikely(&kasan_stack)) {
>
> I just looked at this file in your Github repo, and noticed that this
> could just be
>
> if (!static_branch_unlikely(&kasan_stack))
>     return;
>
> since the if-block ends at the function. That might hopefully make the
> diff a bit smaller.

Will do, thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwF_BBSDukSPRTTc0N%3DOuFgKXquzthCxdR3Gq%3Dp6jA9WQ%40mail.gmail.com.
