Return-Path: <kasan-dev+bncBCMIZB7QWENRBCOI436AKGQEOD3QAZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id 210C329D133
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Oct 2020 18:02:03 +0100 (CET)
Received: by mail-qk1-x73e.google.com with SMTP id i2sf99588qkk.0
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Oct 2020 10:02:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603904522; cv=pass;
        d=google.com; s=arc-20160816;
        b=rrQpk577NTBJROcF/ev2GL8bPD8LCAFBbpUX6m0n3+Ftr3aSgJi8RkN7SBzeFokLKC
         zwzpmQ99IAxIqLXuo7mdYqjvc9YXpFIcMMwNaHDpgqYvXTG7x5H7CirFXj2ewlYYD4BS
         c0rZWIMZj3EbysLacVzWd6PuXVR1xbfAuCSCA+Mg7Wf0LFs+bc68pDQ5C8V+rPQhblHW
         blARNvFYnb2q+bUd93ohKFWrtPKfU5rxacBaC0jP5MXDkNWSi7MaL6uoQdcxjvGOwcAS
         RVV4Gb0M24ZKrAez/p8kf2Qj3tSnW/jhhHaLW81AknXR36AxboM5snN3QjGGacnzkj4m
         WS3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=0CmKQ3vz4gcrIpT4pGbZTi7turHJ92k9R2aBrdVhsYc=;
        b=aUKegw8G78L8dhf0BUXIkb+8OSDUwL820ncwrdWHYb9We9US6MuukKrAIo3axWaoWk
         eH/AZeXgqK+Zjd4TzpfdpReCjhUacLKD4SVdZ7Egv2ihN6jF3lfFFX9ZOYfFmHr55HDn
         rOIC5DC5J8x0hC2tLzleNKaco+7RlIqQKv1U8VNVevZNN/VwrqbLe8M+pPhsU5VB3eMW
         WNomVAlA3dDjVPOvfL8XOfI5FzmaXgu3YUvz8cACz3geNHVGKf+mAt9dKvZfdcCJoFeQ
         v9gM4xECkpLkGoN3XOExd3Bpj9rXurv70jvOaEZOtvmG7M/5RQInCGD9Ssqwwd6z6hjE
         i++Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IC28rilz;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0CmKQ3vz4gcrIpT4pGbZTi7turHJ92k9R2aBrdVhsYc=;
        b=lMlGfCdDodKuq038wNRuG09IIixEBse30gMWBJGxzHrxsi4qfxhk4bTUr7kWGok2B4
         PlR4HgCopRO09yrRFymq8OsxT9gsntjCtpyO3T+cUMar7V66MKMQv8rwMnhB1mue5ZHG
         BY6AKJRFOHCrRlgkdLW1QjzmO0qZ9ucMdlBnZtbwv7YF+Zb+SbKWsy5Umk5bRPmjarE6
         HpK0TOKcfVW8b7JWcHpPCVp8wSZ+LOH6G03qs67bwbzcxORbYp8sIgJySKFNm85UbFm2
         Hql7hKjlq/UvXlZdtZtrQ/NmBcOCpKWdoSUqLlLAQvId9eyY/BngeDkgf+kTjtFijkTg
         Jv/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0CmKQ3vz4gcrIpT4pGbZTi7turHJ92k9R2aBrdVhsYc=;
        b=mkTZ6etWpcPLbswemKsboDCZO5zibZ3FSfyvDopYEp3QM1bZVHyRK5DxnQ0RWF51WW
         zao9TvfsObRannKFnGYcvpTBo/DUsCykRsgewvBcMc6DkZ4j34Cw6VsSflCBnLRexb7Z
         kUhUoNiHExBnupgAxb4fLJ9cyCPJASokH6DIFE6/Wb5QpSr0jBA7bB0MS/5txBrfZwwS
         r4ln91rN5qQ6j05TPVPON0mQkzPf7juzw78Du10UgUEKpTIE0Cv+8h3sLW9mPjnnJMng
         OVBED87pLHWTVllXxUDtoEVlZx/cuYmTdeqWnIE58iCIqOhREj9i3+1YDVOcdKqRS6AB
         r45w==
X-Gm-Message-State: AOAM532f1EfT+K7QI+JyetPDH9FW3MpKku+TD5LXvd0aAhpWCOxHKsyt
	LW5goNpuQ6KlLog/66ewe2k=
X-Google-Smtp-Source: ABdhPJxq60yjHvLR3T0PqtyIeeW2WAK4NEFisjdgU4Yj0s+h97eO0H/dDF7nYSPAJRgvC74RJmEIfA==
X-Received: by 2002:ac8:4551:: with SMTP id z17mr8035434qtn.381.1603904522101;
        Wed, 28 Oct 2020 10:02:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:4085:: with SMTP id f5ls32215qko.7.gmail; Wed, 28
 Oct 2020 10:02:01 -0700 (PDT)
X-Received: by 2002:a37:a30b:: with SMTP id m11mr8291089qke.318.1603904521495;
        Wed, 28 Oct 2020 10:02:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603904521; cv=none;
        d=google.com; s=arc-20160816;
        b=lrAI8V5V1KLw7s2c01kL1gaZ9QgvMYJp7x+Sx2RKHl8uaw0oP1L+LDfF+3vQFlZ/kM
         /uWpn80zn9/yRzxxZogtxFKv6jMNGmrwW1OwxKUPEJ/cXoZrCBK1QftSQimyf+HZPyCd
         sUCRLUAexTa0J+8OPxoxeV3ebd6bjyNOUtB/oDAmnpDpJUMlUzE9k4gSRYXQNTP+9+LY
         SBancv5wMVt8DyOEHL6Oc9eBj1d1QCWRY0ijRtk9RPxJQ9OTEwpTC9rp5uJOhN5hwi+z
         TqVzSX9ljkYzNa7PfSErxF+LeiPhY/ERAHLiI1eQxPnVdHkt/IlX2ekwYCbEaj/iIyy8
         7QZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=k0QqM9Gt2pl6jLDvRzSessXwooNr3cWtYYZ1FieYU24=;
        b=oN/CSBf8jU4Q3rgOdOlHKZvXHv4jCMdr6q6jZ3prZScoFHSvblBl25SeI71PXSQXvj
         SmwzOSXbz3XrhRlOpJWlBT3BNN3joj6RyxWb8tx6E4SPNlS8O7ksy8pRIP2zpj8Zi1pa
         IXaQdE6CyTRjsdv7MTE2zV8WH1fqkFw+8njtl9qbi9EjE7bqmS3YG1aCygjV1sv/+Pzv
         xwKgzU8Y82DWbkWlPG8jpoJmYFXBNACBsnUltVr19lES5iBxlmf8UvJQP8fhyZe0VC2k
         kJmwrv3GAmao1WYa+IQgHploXoU6ol5t5nLu1U+sAKjWDUznfwUgaIJTu+pczGMH6O3S
         i3dQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IC28rilz;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x843.google.com (mail-qt1-x843.google.com. [2607:f8b0:4864:20::843])
        by gmr-mx.google.com with ESMTPS id p51si4574qtc.4.2020.10.28.10.02.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 28 Oct 2020 10:02:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) client-ip=2607:f8b0:4864:20::843;
Received: by mail-qt1-x843.google.com with SMTP id r8so12681qtp.13
        for <kasan-dev@googlegroups.com>; Wed, 28 Oct 2020 10:02:01 -0700 (PDT)
X-Received: by 2002:ac8:46d5:: with SMTP id h21mr2208954qto.290.1603904520912;
 Wed, 28 Oct 2020 10:02:00 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <f48f800933dacfc554d9094d864a01688abcbffd.1603372719.git.andreyknvl@google.com>
In-Reply-To: <f48f800933dacfc554d9094d864a01688abcbffd.1603372719.git.andreyknvl@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 28 Oct 2020 18:01:49 +0100
Message-ID: <CACT4Y+bx=3JCqR3GPrEUjbRFdOTQCCBofx0jd_g2Ldi+L7-iKg@mail.gmail.com>
Subject: Re: [PATCH RFC v2 19/21] kasan: don't round_up too much
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Kostya Serebryany <kcc@google.com>, Peter Collingbourne <pcc@google.com>, 
	Serban Constantinescu <serbanc@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=IC28rilz;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843
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

On Thu, Oct 22, 2020 at 3:20 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> For tag-based mode kasan_poison_memory() already rounds up the size. Do
> the same for software modes and remove round_up() from common code.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/Ib397128fac6eba874008662b4964d65352db4aa4

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
>  mm/kasan/common.c | 8 ++------
>  mm/kasan/shadow.c | 1 +
>  2 files changed, 3 insertions(+), 6 deletions(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 5622b0ec0907..983383ebe32a 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -215,9 +215,7 @@ void __kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
>
>  void __kasan_poison_object_data(struct kmem_cache *cache, void *object)
>  {
> -       kasan_poison_memory(object,
> -                       round_up(cache->object_size, KASAN_GRANULE_SIZE),
> -                       KASAN_KMALLOC_REDZONE);
> +       kasan_poison_memory(object, cache->object_size, KASAN_KMALLOC_REDZONE);
>  }
>
>  /*
> @@ -290,7 +288,6 @@ static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
>  {
>         u8 tag;
>         void *tagged_object;
> -       unsigned long rounded_up_size;
>
>         tag = get_tag(object);
>         tagged_object = object;
> @@ -311,8 +308,7 @@ static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
>                 return true;
>         }
>
> -       rounded_up_size = round_up(cache->object_size, KASAN_GRANULE_SIZE);
> -       kasan_poison_memory(object, rounded_up_size, KASAN_KMALLOC_FREE);
> +       kasan_poison_memory(object, cache->object_size, KASAN_KMALLOC_FREE);
>
>         if (static_branch_unlikely(&kasan_stack)) {
>                 if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine) ||
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index 616ac64c4a21..ab1d39c566b9 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -82,6 +82,7 @@ void kasan_poison_memory(const void *address, size_t size, u8 value)
>          * addresses to this function.
>          */
>         address = reset_tag(address);
> +       size = round_up(size, KASAN_GRANULE_SIZE);
>
>         shadow_start = kasan_mem_to_shadow(address);
>         shadow_end = kasan_mem_to_shadow(address + size);
> --
> 2.29.0.rc1.297.gfa9743e501-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bbx%3D3JCqR3GPrEUjbRFdOTQCCBofx0jd_g2Ldi%2BL7-iKg%40mail.gmail.com.
