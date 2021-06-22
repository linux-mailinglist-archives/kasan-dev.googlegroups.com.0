Return-Path: <kasan-dev+bncBDW2JDUY5AORBG6XY6DAMGQEOFN77TI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 84DEB3B063E
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Jun 2021 15:54:35 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id b3-20020a05600018a3b029011a84f85e1csf5638191wri.10
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Jun 2021 06:54:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624370075; cv=pass;
        d=google.com; s=arc-20160816;
        b=BlY815IbfOJz70tytEkWZT6a7o3yP+3UqUpLB7IHFl1Fb2f4p1aWi0h5Eh7cvPVecQ
         e50VtvCysipXGqfD/qp5x9vzLKwaeawyQZC9p5u1xuAgaauQrhUBEQEzGN1ZTKOjzEvo
         wlnkdqsNTrieB9+SvCt3V5rj+SbiRrfxQRcinYBjj05qLWOwELIOM2wp0WU/ggEaD+4t
         wymKeYQvYqtnzKtgMdHNBTdr0YdBvsXRXU29E7Rir/cjsm/E61f8i9KGXdFU710cIK61
         R5j0m55+3ve3Die9wqI64J5CIKlotHSQBbtVsKAX+2miuuGCCJ5Ik2GHwre1w5/Ezj2q
         HYXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=uWBWB6KqSfaDvdul7pMXvWpdZJI8SHhWGJx8IyG6pYk=;
        b=gymqmtdf7VUfNhf267KpGfoiQRSEhgEcPtONVk27GzITlsKpeXWARdQ+yaetM2O8Gp
         wqa09g8ynoMO38F0waehV0RbDmRvwPL0DAQUm+7f7CvBY0Qzt69kVuoOnWnokhulPy9b
         YYNcUEMi+xpsIFI2SD8zBksl+4prl8oLmeUEpXkNS+B4J//lXDASn5NjOJnWyKyP4cM1
         hZ8WHpXsk11EcnQEnX3jnDz2JHVxUsyGLhib+VyGFE3CuGWvINASNuH6/U5B6RU9OgUA
         xv+lRG8sUQ3/yVZA5oecoGJZ3d4DW/gxfKMGIYYxdwG2X7cpU+thkYTTXHPV0upAWE4O
         a1vQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=tA5vW637;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::632 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uWBWB6KqSfaDvdul7pMXvWpdZJI8SHhWGJx8IyG6pYk=;
        b=XPPz+uB0VIYUhv+24hsGZ7AJgaZmt027mTd7J3t/rFWyMRXQSIptwHKAPfb2mLa5/u
         1LQZMaCw8Gv9xid667zjr2N9s1/95oJ8f5DY4+k6K7N+CfLeofs06BE1L+pljb40ROU6
         t9Vt6RaRlAUZRCP9oSpVqVAof0kv9F9S/L+9LLlp+ABete1Dr3R/6aWVqVSo0ruXcvH6
         KjuZF9PN5KVk/E3hOSDJRwpcIPvP17w2Wcg3f00hmC43sbEmE6L9lIG6/E6aAtuBHMWf
         FOhXEjrdJoAgXjyd3FXrAdPNCcxdVmkyV55FIIrhLpj0H41Srb3ZUZU+kUfhbBRv8GbC
         /euw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uWBWB6KqSfaDvdul7pMXvWpdZJI8SHhWGJx8IyG6pYk=;
        b=TTfBBJCh8dfyeHGueOQGAU52cttk9ve0KM7ThSmMcnrD27RhbOWQPUchjY5xDr4KfV
         8LgSjBLSt/EzG4cd7T5ZxsauCciJqWnUSFcvpkg6AQxgBKGfFZl32x/LnLtcPKZ5Mbyz
         2pg0ikPA0L4ad6FmY8K1BO42ye3ad4nMG6utyYp1LODgtKcEriS1yXXApvzI116Vpdmy
         iLAgSk6nPQUsQPtnd0s+z03u8gyQzdVF7eTJlWFqHhRNjGjYRa6Z+o4UG+MZ1Csk9dOM
         WLUelcmrJFKvWZLf7fRZH37YSLwQ3d+829IZqoNs3xTl1yE8qzxR6f+Ob1POWEWbDTz4
         ABbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uWBWB6KqSfaDvdul7pMXvWpdZJI8SHhWGJx8IyG6pYk=;
        b=CcVzRlAxAlMWBelyvdasiAoZlj68F0HBb/nkDXytzS/EZItrX6NexGAK6LSliv73dr
         otT2BjTzI7/A3dog5/i8sy4lfmseQOZxuq2nF1RwxfP8LYfCoF728WGPwt0C591m3XJG
         NnaJS+2aR8NRP6H8j6RvamoteKp/Uvyiz2y7mpy2UbDWzgflc4ZNIJ57VWbd641zqU1Y
         +yulGx3vvnTmdCaolQRyZes+hUrupCESeK3BKMYPqZ2Iyl/+c0KQ9lwGOBK4BOsQGGjB
         C3Y6CUimUVeh8gcUEpsrHCwZ/+dL4Nt0nEFFPo+jFncoFef8kBaVhiEeyYZCGp1b3cOZ
         URsQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531gIVUs0XnHm40uanp76uTv9vO8a8+lKamLewFuofUqDFqQchCi
	OlXIDvqeo6l9FP3qhkkLXXc=
X-Google-Smtp-Source: ABdhPJxHr1N495XxW+YwJ0aev3dr28SUpz74M7841S50eRtK8FBxErbf4ZwCAkgq3BUEGmtWnugecA==
X-Received: by 2002:adf:8061:: with SMTP id 88mr4870907wrk.233.1624370075276;
        Tue, 22 Jun 2021 06:54:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d0e:: with SMTP id l14ls1230461wms.1.canary-gmail;
 Tue, 22 Jun 2021 06:54:34 -0700 (PDT)
X-Received: by 2002:a1c:f314:: with SMTP id q20mr4757281wmq.154.1624370074401;
        Tue, 22 Jun 2021 06:54:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624370074; cv=none;
        d=google.com; s=arc-20160816;
        b=Vq+DEpo+r3O1ryiVW7AxX65Z/TuxF+aOfHE9tysZ7LayBfNsvxpmmrh8QC2VBCe5ZG
         AjXeduk/L5WlN1c+pETd8rpaxkVVuqDXbAQ4TPEN1APkgVmQAEqyRKID4U2ojuH9+Vse
         gzNWTWcd1DDSVKdBq/4AKRNWmIw1IoIwDMARMfnRzPWr72Eo7ORx49L8T/LvCeRA9Wpf
         JcISbgUCE83EKlzll4kaudLBAH4p4pCBDfJCeXfHM05ne8jzugTT6GtVZIravfnbN7cx
         +i3aQnCxvhMot4Fz6Z0nlsNsFl8LI33iEWdap0pKAEgT0UQWU1PHZRDaExTQo/AUcGGF
         g4Og==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FByLAh6Nf6CrO0CmfvZoHDR68Ruso4bZUuWvxrdb7+g=;
        b=lXvzXB69vG4BuN+cAXGO1j/u+QuJTZAoJpaVsz998B3qT59cmTw49Z9vi09k2/kqOp
         4dJJK8qy25UkKSkecP2z8fEnHOHPbhROXtcovK2bRPs6Pd8B71PVoXCQ1WJmlKSpkWDJ
         hmz3f9xKeLw3/3s8EOvzOUHVp4hrvWSWNpW9mpUulhU6HGM4mA+v1uVfIn3bnHaoWFy1
         lvqj14acpQifTpQryf4SXOeCpzLKh6xR/8gawMCeH8+DTyhRf8mF6SO48JeleMqEQ9tx
         tZhXFt1Ip1dI6ubyhQ/NhIOMENfhr9RrP79Dm46d0bCFICyBEJ6rQrqwNT0QEYHg6NFk
         PMyQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=tA5vW637;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::632 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x632.google.com (mail-ej1-x632.google.com. [2a00:1450:4864:20::632])
        by gmr-mx.google.com with ESMTPS id c26si151363wmr.1.2021.06.22.06.54.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 22 Jun 2021 06:54:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::632 as permitted sender) client-ip=2a00:1450:4864:20::632;
Received: by mail-ej1-x632.google.com with SMTP id gn32so7262764ejc.2
        for <kasan-dev@googlegroups.com>; Tue, 22 Jun 2021 06:54:34 -0700 (PDT)
X-Received: by 2002:a17:906:2f91:: with SMTP id w17mr4164114eji.443.1624370074257;
 Tue, 22 Jun 2021 06:54:34 -0700 (PDT)
MIME-Version: 1.0
References: <20210620114756.31304-1-Kuan-Ying.Lee@mediatek.com> <20210620114756.31304-2-Kuan-Ying.Lee@mediatek.com>
In-Reply-To: <20210620114756.31304-2-Kuan-Ying.Lee@mediatek.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 22 Jun 2021 16:54:14 +0300
Message-ID: <CA+fCnZcFxNwVd7oCLn4an-c6sx=3tQbZAB7Zu4jSPVqr6xDrVg@mail.gmail.com>
Subject: Re: [PATCH v3 1/3] kasan: rename CONFIG_KASAN_SW_TAGS_IDENTIFY to CONFIG_KASAN_TAGS_IDENTIFY
To: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	linux-mediatek@lists.infradead.org, wsd_upstream@mediatek.com, 
	chinwen.chang@mediatek.com, nicholas.tang@mediatek.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=tA5vW637;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::632
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Sun, Jun 20, 2021 at 2:48 PM Kuan-Ying Lee
<Kuan-Ying.Lee@mediatek.com> wrote:
>
> This patch renames CONFIG_KASAN_SW_TAGS_IDENTIFY to
> CONFIG_KASAN_TAGS_IDENTIFY in order to be compatible
> with hardware tag-based mode.
>
> Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> Suggested-by: Marco Elver <elver@google.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> ---
>  lib/Kconfig.kasan         | 2 +-
>  mm/kasan/kasan.h          | 4 ++--
>  mm/kasan/report_sw_tags.c | 2 +-
>  mm/kasan/sw_tags.c        | 4 ++--
>  4 files changed, 6 insertions(+), 6 deletions(-)
>
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index cffc2ebbf185..6f5d48832139 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -155,7 +155,7 @@ config KASAN_STACK
>           CONFIG_COMPILE_TEST.  On gcc it is assumed to always be safe
>           to use and enabled by default.
>
> -config KASAN_SW_TAGS_IDENTIFY
> +config KASAN_TAGS_IDENTIFY
>         bool "Enable memory corruption identification"
>         depends on KASAN_SW_TAGS
>         help
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 8f450bc28045..b0fc9a1eb7e3 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -153,7 +153,7 @@ struct kasan_track {
>         depot_stack_handle_t stack;
>  };
>
> -#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> +#ifdef CONFIG_KASAN_TAGS_IDENTIFY
>  #define KASAN_NR_FREE_STACKS 5
>  #else
>  #define KASAN_NR_FREE_STACKS 1
> @@ -170,7 +170,7 @@ struct kasan_alloc_meta {
>  #else
>         struct kasan_track free_track[KASAN_NR_FREE_STACKS];
>  #endif
> -#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> +#ifdef CONFIG_KASAN_TAGS_IDENTIFY
>         u8 free_pointer_tag[KASAN_NR_FREE_STACKS];
>         u8 free_track_idx;
>  #endif
> diff --git a/mm/kasan/report_sw_tags.c b/mm/kasan/report_sw_tags.c
> index 3d20d3451d9e..821a14a19a92 100644
> --- a/mm/kasan/report_sw_tags.c
> +++ b/mm/kasan/report_sw_tags.c
> @@ -31,7 +31,7 @@
>
>  const char *kasan_get_bug_type(struct kasan_access_info *info)
>  {
> -#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> +#ifdef CONFIG_KASAN_TAGS_IDENTIFY
>         struct kasan_alloc_meta *alloc_meta;
>         struct kmem_cache *cache;
>         struct page *page;
> diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> index 9362938abbfa..dd05e6c801fa 100644
> --- a/mm/kasan/sw_tags.c
> +++ b/mm/kasan/sw_tags.c
> @@ -177,7 +177,7 @@ void kasan_set_free_info(struct kmem_cache *cache,
>         if (!alloc_meta)
>                 return;
>
> -#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> +#ifdef CONFIG_KASAN_TAGS_IDENTIFY
>         idx = alloc_meta->free_track_idx;
>         alloc_meta->free_pointer_tag[idx] = tag;
>         alloc_meta->free_track_idx = (idx + 1) % KASAN_NR_FREE_STACKS;
> @@ -196,7 +196,7 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
>         if (!alloc_meta)
>                 return NULL;
>
> -#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> +#ifdef CONFIG_KASAN_TAGS_IDENTIFY
>         for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
>                 if (alloc_meta->free_pointer_tag[i] == tag)
>                         break;
> --
> 2.18.0
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcFxNwVd7oCLn4an-c6sx%3D3tQbZAB7Zu4jSPVqr6xDrVg%40mail.gmail.com.
