Return-Path: <kasan-dev+bncBCMIZB7QWENRBDEG4X6AKGQEXBVZNVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 88AC729CF68
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Oct 2020 11:08:13 +0100 (CET)
Received: by mail-il1-x13b.google.com with SMTP id c9sf3091584ilu.20
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Oct 2020 03:08:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603879692; cv=pass;
        d=google.com; s=arc-20160816;
        b=FxmnzV4WxLGl3Nhhfd0APUMXsu5GXK/YUrleSxIjGrtj8C7y9lEhteVwLEs1MFotOR
         hWAs3P3BWtcftofAp1m4VQ5M2dYfPz9VhMYmMRX9aezj3V1Nti8mX4Op0x00378dP9pr
         naayAT7xZLwTPv6Kc1irIOoUpboAQsdIs6UOSrorU/tsx/RvUzaldS2sLQNJ9jDbVTCQ
         3BrmATT/J8EwHieQV3kQjQHfc9wiTj9VJ0uRshXs75heP1fPEVoJIZtUnzdTVU3Af3ks
         jEGZWGzFwn4igDb2MdaNXA2ZS3AKN3JrhI17i2gPCRIIKwkRyh8EMS4qg69+0IG/zk34
         uDwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=/26TA7o78cjZUgGrbtBh2diDkxvUe2ieJmUU4Q1lmIY=;
        b=YH85Tstl3TaILWZe4FLWRfwVFmE8JfcbqZ1W8VyztOwgd9oZLDzOmloUrZi7eu26/I
         1UkUoLmj6haYxot6rdbqa/3A+FN8A93+LjudsP9Djdsy2VGBVD8qEu8mUGROUSTB//zX
         9+XNRsjivBb+wiL7jF7pAqwzRRM9wl4127hy8sSnFdR7cxLtagz1Ty7w95sT2CLsCx4e
         Dl/9IfZY3JoCAvipQy4d8pkwgzvcQpBUmPOCE3NVkVCE0rfIp/ek+x14z7FTGDeISeQG
         XiJXqoDQ+LlptncU1k81nm+XAqHp6O2t7qAtfZEBgmt72W8P5AZylh4k3W4h+b/yF/gI
         uIaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Q9nge9gM;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/26TA7o78cjZUgGrbtBh2diDkxvUe2ieJmUU4Q1lmIY=;
        b=AHgyUqsEN1T3Kcg+xVwHpdULT3OlwiGlPEpig+VHU8JHeYqCUlkXwYCnhRfZ1YGfds
         eIeepqV6lHpRco8v7SZM2cGMG1EjVIWMS34oc4B0o1Ls4VOF2MOM619fOv1cHjmbe9TY
         7SnDP0j8leUvwo/XPaaydaF7fajO/uPKSCs9T/jHVrS2HNLoVveTiv4q6me8m3BtRnKi
         JuFfEgks0cPyL4gbU7l0YMLyDkA3pfyMsV8nMkgks9hVC5yEVLwz4Z8PeYLi3G1PWe5a
         vYVHTUEJ/IgMkbfcV5aypF6PJZWXhd4DzkysDmLjvWCpr7zI3KnZh5ZG0YPLbf7MQEnB
         txfQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/26TA7o78cjZUgGrbtBh2diDkxvUe2ieJmUU4Q1lmIY=;
        b=gpjsjBsv0gvGPxoIt4HO30SfAHCJeCiq28F54CqjV1YP48f3r6gBSKmn8GvjURkND1
         jqOWn9PhjFQ4DPfrtks2lSfgd1gpr2+vdv1lKBYWINDCXtOFeiFti2Sbx7vx15HbsThb
         y0L91nRTP0CShFWnnbTENpdqZw6BsUBllilxu25rd2G7Y2eCW1tytJTmPaBCN8GQ8V/G
         4ngWOtyscrdmvWeN17qEXiifC7/nzzMGqXyS41V0A5/YOHftl7luj1SQDnFGD4DFrnjz
         BTIBI3XEIm6/kSYipRCJ+n6OSqEer6mBG9d35cnrz1Kh+oj1g/cOXMc84fy1fmP08GHy
         WScA==
X-Gm-Message-State: AOAM533U6sxWPcBwaTN/lkBM6Vm546W8B4Cs3SzyV15cBdpRxubF+1aX
	2M33VF5SEkoCaSmvHE6F9b0=
X-Google-Smtp-Source: ABdhPJzs/TJdXLS0k7pt+NxDjVtk+J9YwyEcWcWR3E4InbZsk2b/7pDAnO44C1a+PqVLAQ6JGe7l8Q==
X-Received: by 2002:a92:9641:: with SMTP id g62mr5502156ilh.166.1603879692529;
        Wed, 28 Oct 2020 03:08:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5e:d516:: with SMTP id e22ls698848iom.5.gmail; Wed, 28 Oct
 2020 03:08:12 -0700 (PDT)
X-Received: by 2002:a5d:80cc:: with SMTP id h12mr5816285ior.66.1603879692164;
        Wed, 28 Oct 2020 03:08:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603879692; cv=none;
        d=google.com; s=arc-20160816;
        b=W/Tj3Aal5SyZSlIEWzNplhObrOt/62JSJF2eFgvdHnUE/Xok7g32aKi5B+WAz/ZRm+
         5I1nywAoyWIhGFe4WlTd4lJLklmCGH0gJAD4oPqFCNAsLmldpXhNXgjCgkEgSyy+YEtb
         8WBglNAJf6bpQ9QiBZUD7sYOMXkzsho9Z2qZAkEu/bYUCCjb8FPIaOq9P+JLDcackqbG
         HR1JyYNBXM1+IwBUGNesBUAYnYN0GDC05lePZ1HxhWM99LLTRA0Kt60E9u4Zpe2Om3va
         AhLtgkpSeveJV0AGZ//c+1iYKnp0dTD74fWz7jsgTvVPplS6R+k0eU5UkX/B8X7R0i1u
         ryWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yocub4/NVz4KlLozUgrX2nJOzM43s4whYSIptCsoCIk=;
        b=pBioCFuINC4ZiHtcmlInXLcsnfkdEwKe0NtLnPt2+93stjMTrw2CmBXrk1iP7lE2nF
         YKxR+8PEDIhSKW+Z5j3DUQEiig6PO5Cyab3FBaq9pyPDZo7c0qwVVsbFbExdyRXPKgOc
         l4jgQBCDbBOi5CnDZSriThsSK+h9V1aQcEBfBg0sx/twk5oadUsHbA6NJRXQWUF/hhNN
         3JQ18j+gfMRmZt8cY78UIrbnYX0n8BozM+7erJBU0xI/l7hfMRtWnnDeuSjTixCH6OXZ
         Hu0YPIZYl4BR3QpxTKEN0DGfTmBNx6YoR1vJsirjBYt3MxRHBRJt6wNRzbvSmHN0Hg7g
         ZIfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Q9nge9gM;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id j7si220322ilc.4.2020.10.28.03.08.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 28 Oct 2020 03:08:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id 140so3958748qko.2
        for <kasan-dev@googlegroups.com>; Wed, 28 Oct 2020 03:08:12 -0700 (PDT)
X-Received: by 2002:a37:a00c:: with SMTP id j12mr617658qke.231.1603879691392;
 Wed, 28 Oct 2020 03:08:11 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <155123c77b1a068089421022c4c5b1ccb75defd8.1603372719.git.andreyknvl@google.com>
In-Reply-To: <155123c77b1a068089421022c4c5b1ccb75defd8.1603372719.git.andreyknvl@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 28 Oct 2020 11:08:00 +0100
Message-ID: <CACT4Y+Z9iE2u1g9Yg=y2TPuRaYVq3TQoJ-81cYzODso_3aJcGg@mail.gmail.com>
Subject: Re: [PATCH RFC v2 06/21] kasan: mark kasan_init_tags as __init
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
 header.i=@google.com header.s=20161025 header.b=Q9nge9gM;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743
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

On Thu, Oct 22, 2020 at 3:19 PM 'Andrey Konovalov' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> Similarly to kasan_init() mark kasan_init_tags() as __init.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/I8792e22f1ca5a703c5e979969147968a99312558

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

init_tags itself is not __init, but that's added in a different patch.
I've commented on that patch.


> ---
>  include/linux/kasan.h | 2 +-
>  mm/kasan/hw_tags.c    | 2 +-
>  mm/kasan/sw_tags.c    | 2 +-
>  3 files changed, 3 insertions(+), 3 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 7be9fb9146ac..93d9834b7122 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -185,7 +185,7 @@ static inline void kasan_record_aux_stack(void *ptr) {}
>
>  #if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
>
> -void kasan_init_tags(void);
> +void __init kasan_init_tags(void);
>
>  void *kasan_reset_tag(const void *addr);
>
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 2a38885014e3..0128062320d5 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -15,7 +15,7 @@
>
>  #include "kasan.h"
>
> -void kasan_init_tags(void)
> +void __init kasan_init_tags(void)
>  {
>         init_tags(KASAN_TAG_MAX);
>  }
> diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> index c10863a45775..bf1422282bb5 100644
> --- a/mm/kasan/sw_tags.c
> +++ b/mm/kasan/sw_tags.c
> @@ -35,7 +35,7 @@
>
>  static DEFINE_PER_CPU(u32, prng_state);
>
> -void kasan_init_tags(void)
> +void __init kasan_init_tags(void)
>  {
>         int cpu;
>
> --
> 2.29.0.rc1.297.gfa9743e501-goog
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/155123c77b1a068089421022c4c5b1ccb75defd8.1603372719.git.andreyknvl%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZ9iE2u1g9Yg%3Dy2TPuRaYVq3TQoJ-81cYzODso_3aJcGg%40mail.gmail.com.
