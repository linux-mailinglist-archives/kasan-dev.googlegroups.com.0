Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEWO6D6AKGQENENLXZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 7456D2A082D
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 15:45:40 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id v6sf4696874plo.3
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 07:45:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1604069139; cv=pass;
        d=google.com; s=arc-20160816;
        b=dQXsr+iN5CGRAidbZ8B2SqdyPtCm3ETJ+ZsSsVmkImQtHbQMIMQ/KwpnQkydmuS0U6
         G2EBgZAQEgj+x1wv9GsZRlSNlkWjvthDG0SZfTE2+ztqV9bsww37xCcKMEu6KOC8yijK
         jJrxUCUVDJ6oYpNxU8qHsk90V6unizH8xVbHeo6VEFiERCr9dB8rdtQ24EPgNnhE9fbr
         BelQygtby6v7K5b+eOGSB+F1AvrSbvcsL019FiotnAtqD77vNh3kvv7AUHITjFIt7drh
         eYVfa7dRu27RlemhNIC7TBMYdOkgmVqMBem+hhYQwCVgiQHpwhZigFVcIzcNY27J3d4b
         iDOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=hJ7YUzoEBz7zsNL4EXBjLIgUi25LngprTkGIPEbFzew=;
        b=Wvyn+mN98Uz5DDyYkG5fMFh53w5ULPBeBbRExUOJz1IM1lC6E2zC4CLn8o7hR/jahB
         bKgIht/kqJqxLsF+iRDP+sVClnN3AmFa9FRlBi4KfLKjjcja8KlBVzuYivBMKDw2sI7o
         tlzqGfk1mvKPuApk89o4Xh283fuK0AR466GvIxdleNtZwHWpZ/ZFXR8a5Xp3D8HKwi0q
         Qotor+WVY9Catu9Sr6W+TA6D0oCrn4Y25vQO3bZ1+rlTXf45m3lipRO0gVzda8mPgGhe
         /nhP3gEim0HjBzSHqXwAdI5tcHiF6pvtXpl4J6fpfySNoSSueNzWgK3pur6Nf0bBRR5i
         K5jw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZFm0kFcr;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hJ7YUzoEBz7zsNL4EXBjLIgUi25LngprTkGIPEbFzew=;
        b=W/DIF9Tf6u8AChGzOwu3wsU+s11x8ya+Q4nYu2NcmuENh9a7F/lg9sCg+NmUujPebt
         XCDRr2n5LXZAiCspz54mn2VS6cIVZ2m9937DRfqBNECeNBXupmy+tyvkyIzXDvyYGalo
         ZnSX+b+MRS/Nr9fZL8h3zgzIjEE0KpJ4T0kVZR5XFPTcVf/orat4ZKNfIP2svnPCIDkD
         H726vBrvh34UxA0t50QIsvFmu33g9rNZfp2qjlJHvzID+2gNYsah2UYmddZgU82KOdMz
         l0tHN63T2xxfJDATGIYqjxtv5e7NMRjrr7/4ueMmLhbEEgsrD/RKn9bXMWww4Y+mNpS6
         TFvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hJ7YUzoEBz7zsNL4EXBjLIgUi25LngprTkGIPEbFzew=;
        b=ZtZbhpYQID319VstkTjy7o5kYq3maVqALdW+/KpV0mD8dOYhPORcCqZAJ6qB7EbbeU
         GlgobFw5XKtfBa9pRKUvxlkVA186N9VC6RbBbYbbzhUwWPNF6GSuKUHWltvsM0v87T94
         CSHeUk2ck/cWiBdIWw3gKIRrZGMQQuw24NovMRVzZsczD0zRcPyj4FnoIqEUMcm8nm6j
         whXzu3PgQDZ31nNyo6tHLpIkvB3HWk9BnTMcnH1eddBjkTtfSep77bnYhyFeb7gNPpXP
         LM3eI+c0Qlz5wLhlBdcPhNlk70zVamPKMCwv+vKNh8SbqghuOLmy3fMWk4T+/gd7ZN6u
         g8yw==
X-Gm-Message-State: AOAM530IjvNNOlorUvKpgOeM4kNabD9GNouCvUmC4A81tF5Ww4zneYQZ
	yXJHBxav+SW4to4iZgHq48s=
X-Google-Smtp-Source: ABdhPJxH3eRMsfdWtB44aoNaI17xq0CSbr+k0QDcH+9gE4OSCMmtaN9jWTPe05drXlkxZGRDp1Ushg==
X-Received: by 2002:a17:90a:f0c7:: with SMTP id fa7mr3296721pjb.3.1604069138877;
        Fri, 30 Oct 2020 07:45:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:aa08:: with SMTP id k8ls2138160pjq.0.gmail; Fri, 30
 Oct 2020 07:45:38 -0700 (PDT)
X-Received: by 2002:a17:90b:4a07:: with SMTP id kk7mr3393544pjb.92.1604069138319;
        Fri, 30 Oct 2020 07:45:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1604069138; cv=none;
        d=google.com; s=arc-20160816;
        b=RSiJ77V3hdMiLBAAtZsK1KdFZKqeNCNJ/o3JNDen9Y+hXtitZhkd2ORZkfDLNvMt2U
         IJmxMrzu2epApXe1qlgflvOXK1x6mMoBXojL0Fv3uTfXEVeRCHXBSN5kaHxCs+oxCRO/
         2rooAutewm2nwxjpYMFqQxU5W/X1gPMa3XD4NtqouKzUju9g2vE59DKvZG9N1PQ7oBBN
         C58awtUXI8UPv8qmimYL+VNYyyLqj5qzIa73OHVHeXoZvduO0nF/OT/HZMn/ylAIIeL6
         /DvOVuTUby/MkIWylnQNVFTFuIZ5XTrt5sy1j2CODxs1NTVKhlx7nfriueYlnGDvCVr8
         jUVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/l7OXXa9UuvkPT+n4O4t3Y5d8yYC198Ym1kgNFK1uSc=;
        b=nkrIH6YTSPm/jP4K0WQ2yXbUA8lStFoQVPeeRQ+1UfC3x6KLi9oudXeb+ajkUG9XpK
         DBvhlN4FZk6vvmKDf2uMw+G9i8NSIDdAqVecCAhxI9P+EiKUJn6T9wqAZjCypMuaHsbw
         OohAnZGwIoClS11+E80LYMxgPLLDuZbRdGL9HONQ7E1I2bddUEiqGGDPukoLjBiX5QsP
         6a3yaIqY3b00KslymSIzpRe0YfJZPmr7XP3P2blF+NtxNV1hLYLBiBcxH1dChGNhj7Fg
         Zs6v4yeG1KnYw6DQB/+ovz1/U8D+awDwCRYXK/Z8vG8YGIYAE718faWeXK+5nbjKO46P
         LklQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZFm0kFcr;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x344.google.com (mail-ot1-x344.google.com. [2607:f8b0:4864:20::344])
        by gmr-mx.google.com with ESMTPS id k24si189427pjq.2.2020.10.30.07.45.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 30 Oct 2020 07:45:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) client-ip=2607:f8b0:4864:20::344;
Received: by mail-ot1-x344.google.com with SMTP id m22so5758881ots.4
        for <kasan-dev@googlegroups.com>; Fri, 30 Oct 2020 07:45:38 -0700 (PDT)
X-Received: by 2002:a9d:649:: with SMTP id 67mr1983160otn.233.1604069137790;
 Fri, 30 Oct 2020 07:45:37 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <6a4a7626bf280871518656f4fa89cb064740baf7.1603372719.git.andreyknvl@google.com>
In-Reply-To: <6a4a7626bf280871518656f4fa89cb064740baf7.1603372719.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 30 Oct 2020 15:45:26 +0100
Message-ID: <CANpmjNPxUwrwAjN_c5sfBx5uE+Qf70B=8dbFcYPF2z1hWfpATg@mail.gmail.com>
Subject: Re: [PATCH RFC v2 14/21] kasan: add and integrate kasan boot parameters
To: Andrey Konovalov <andreyknvl@google.com>
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
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ZFm0kFcr;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as
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

On Thu, 22 Oct 2020 at 15:19, Andrey Konovalov <andreyknvl@google.com> wrote:
>
> TODO: no meaningful description here yet, please see the cover letter
>       for this RFC series.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/If7d37003875b2ed3e0935702c8015c223d6416a4
> ---
>  mm/kasan/common.c  |  92 +++++++++++++-----------
>  mm/kasan/generic.c |   5 ++
>  mm/kasan/hw_tags.c | 169 ++++++++++++++++++++++++++++++++++++++++++++-
>  mm/kasan/kasan.h   |   9 +++
>  mm/kasan/report.c  |  14 +++-
>  mm/kasan/sw_tags.c |   5 ++
>  6 files changed, 250 insertions(+), 44 deletions(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 1a5e6c279a72..cc129ef62ab1 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -129,35 +129,37 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
>         unsigned int redzone_size;
>         int redzone_adjust;
>
> -       /* Add alloc meta. */
> -       cache->kasan_info.alloc_meta_offset = *size;
> -       *size += sizeof(struct kasan_alloc_meta);
> -
> -       /* Add free meta. */
> -       if (IS_ENABLED(CONFIG_KASAN_GENERIC) &&
> -           (cache->flags & SLAB_TYPESAFE_BY_RCU || cache->ctor ||
> -            cache->object_size < sizeof(struct kasan_free_meta))) {
> -               cache->kasan_info.free_meta_offset = *size;
> -               *size += sizeof(struct kasan_free_meta);
> -       }
> -
> -       redzone_size = optimal_redzone(cache->object_size);
> -       redzone_adjust = redzone_size - (*size - cache->object_size);
> -       if (redzone_adjust > 0)
> -               *size += redzone_adjust;
> -
> -       *size = min_t(unsigned int, KMALLOC_MAX_SIZE,
> -                       max(*size, cache->object_size + redzone_size));
> +       if (static_branch_unlikely(&kasan_stack)) {

I just looked at this file in your Github repo, and noticed that this
could just be

if (!static_branch_unlikely(&kasan_stack))
    return;

since the if-block ends at the function. That might hopefully make the
diff a bit smaller.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPxUwrwAjN_c5sfBx5uE%2BQf70B%3D8dbFcYPF2z1hWfpATg%40mail.gmail.com.
