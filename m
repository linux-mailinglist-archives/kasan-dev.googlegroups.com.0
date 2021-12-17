Return-Path: <kasan-dev+bncBDY7XDHKR4OBBZGZ56GQMGQEIRKWLOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3c.google.com (mail-vk1-xa3c.google.com [IPv6:2607:f8b0:4864:20::a3c])
	by mail.lfdr.de (Postfix) with ESMTPS id CB30F478265
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Dec 2021 02:50:29 +0100 (CET)
Received: by mail-vk1-xa3c.google.com with SMTP id q3-20020a056122116300b002faa0b9026fsf209166vko.18
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Dec 2021 17:50:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639705828; cv=pass;
        d=google.com; s=arc-20160816;
        b=VQZOchji/ue04fCXF0BacDFACJFkO18f2MSbGaFl1XVQS1uq2JbqbFvWW+ABiiNgim
         izDjfK/2flU8lzDXTEQTpJWRW94VjiFgwA+N7sMRqL3R7Zc/xWOMU2ghKjozRHKjNRl9
         JJf/oUjs9D0Z9MWr383zL5gQ/p9eyXkalkLqwbFiDs5w3vhRSVdOgcfqWP5wBjCvXifa
         5bpXRrk68/nojb//PNiUbxiZgjeLvS8dXdh4xPmX31Vf2HxA+6WmmNXUQJuzeGhTLPZa
         AVfZZAYjzX9wzB9UXJLMLoA7GnD+eBbdJtgi/4RO3wk1opHAHZ/tunrKWsdB2/m/tisp
         3pqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=pbfY9YdcuTaiVZqEWdNmBA1KUIsW2GHeh5ZJPTLfX7E=;
        b=JyoEwvkkqDkkCAC1qhuJOk1fIPLo3/E30Vh+/3zWt/EgGT5ipCkQcQyP3PmonPffbR
         JNuxwM4OCPgfAKTWcaCHQBhybTrj8gJxF3aQw6ATTivOUKOVMO8lYIhILJtlgGwP4ks8
         aV2RaZc+b5l3gt6w5LP1cOtCBXeIhJQtVRnG2EYJ3ZjaoI/Ko9RszTvP7D2tJUj7s6Tz
         ZiehlBx6VvwM1evPYCXVu9oRJDYQn8B3efCBCKyTdbq+ngwxkYnlJGGySa/iSn/l957S
         ZErrHarEJbiE14zeQfIQvNn0SWmdbQaJI1onQmSz0yFN+oyVPTNbOWkofemq6vUJn01N
         Z4mw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pbfY9YdcuTaiVZqEWdNmBA1KUIsW2GHeh5ZJPTLfX7E=;
        b=P65wwhllqogoaLKEtyotm+AGjnb8MUSoZJTmkyNVqfZijhdFVtGeSjv+e30900Ibew
         xY22Hyo9SXREzJtcndC/TXHLvJqqphPXQhEWcvKwx/1YgHdJ3Wv2VrNM3oS0aW5FD1Rh
         OoPdO327MX3KAdPRS2OUikqaWaTa/PfrmHfLYakMVKP7Po9qQFpICwi/qXjRJ+iUmN6T
         WtKIz0QZRBNM09fZnH+3FBsiLTbTfDxgy87M7qyBWuANnD/zo6GOKYTleQVq+093CHoJ
         pX+C7prUuhRKSxA+xj2G8Fa8ZCWX0TybaJJMj5EMqCR3iloxQnX4VZtqYEjDYzjgZ/TU
         nxpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pbfY9YdcuTaiVZqEWdNmBA1KUIsW2GHeh5ZJPTLfX7E=;
        b=SnKJDlsSZ28Ob65vz/ROjKhT/RKkeMLWzqMeu8AyJWzAU4nEFCEBfF7Ro2QqezFnG5
         dchdXoUTh9J5DlDRVi7ZUkYTtlrklXahpk9jvD95fgMeDAu1I0P3nWZy32vgehnTp0Sz
         amnzuzewoNY1qKdxvo7fWsQoFbVpby5Wo0t1LGdD9mU7njGOrMDb3HCcyPTrzy95DCAm
         XaphevUHpOc/s1CXD+9lnVGr5RWdU4mZUN1WTTuR9aXvXIys+L17NNewyhv+kcjvYcah
         hw1jHEihmUE2ksy3ZE7wMeTdVLo09y1YSkVggNdLB9t7vK8OBUKjevmOT46Y7VpKg7mW
         O/JA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53081QiCOmg2QpllEWAaCEmv0j3QeNuyib2RKcRFD9q4T1aixGnb
	Z6aGo3sdCUBXCaNfdAGumkM=
X-Google-Smtp-Source: ABdhPJxJON8MXHmDbqU/xmsPKkhI7YgnWCcBU4kkULfG1EDcopK+496lxwskCEyP0+uUAhoad2pTyg==
X-Received: by 2002:a05:6102:f0f:: with SMTP id v15mr249671vss.28.1639705828493;
        Thu, 16 Dec 2021 17:50:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:a64e:: with SMTP id r14ls1466740vsh.10.gmail; Thu, 16
 Dec 2021 17:50:28 -0800 (PST)
X-Received: by 2002:a67:1701:: with SMTP id 1mr251024vsx.75.1639705827974;
        Thu, 16 Dec 2021 17:50:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639705827; cv=none;
        d=google.com; s=arc-20160816;
        b=ViIS6Y0pV2o+K0SA3d0rlmkypqZiG3bReyvci9GY26kpFrmWar2qu0vGbXq/drw18m
         c/PY4KahAy6a9NbeEE39wD7rKcJ5Aa8ScbJ4g6JbC4u0sWO4XN3DzPEClqIl7xUgdYap
         v3xeNfK8odjIAliAW1NxUcewx+ZHAGTnr3zBjpGN8EJ6EXHpYkTdSYb0cw0gfjDXrx89
         XyGx2/CMDrMvKV82+udn9oY5xUoNf8s9AtCL4QXCFIokp3aEQU6qtVrzsItBQhJ+NVAi
         qKdSEuJ//BaA85DD1MJxCGDuGK2AI2O5oID0JL+BXHWKiPl9Uq0aRXGh0y7qGjDaRYEx
         wWRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=dGVRmVzVHKu+kUGotLGDdBeOxXbl+OEbRJ40lQC83Eo=;
        b=ioxP0+IAx6K9za4GD92u4xrVW/hBznBEe3huW6o/pDTGHsvMlPgI/zYIEVTKYQ/viC
         +gl9e/aHmsqevg7iI8k3J43AKMIwFvnW769G/K0d1vGLaJ6XMSgKDIC9+R5VU8zw9RYx
         lk8eUVtw0TCYZDZ1bCE7Fcx76Q2DoSiXakusGYbx1kl5R2ezU0FWky2IrCQTCqqoox/R
         2jvVnHwpwWJQXfgR2F7KBpzES8sFu2OSeiLEIKRd1VlIY4OnYIkt9HOBEgjXGu5nJlgY
         zzG39vBRNmbQLXqjdRWTcikEfvuNOeVpIqhK2r983g3Vn0QTL0Vm9JsPNIJv59GEvQG8
         tvIA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id e5si186605vkn.1.2021.12.16.17.50.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 16 Dec 2021 17:50:27 -0800 (PST)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 7e41e068975f4003b105575a15179857-20211217
X-UUID: 7e41e068975f4003b105575a15179857-20211217
Received: from mtkexhb01.mediatek.inc [(172.21.101.102)] by mailgw02.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 316835896; Fri, 17 Dec 2021 09:50:21 +0800
Received: from mtkexhb02.mediatek.inc (172.21.101.103) by
 mtkmbs10n1.mediatek.inc (172.21.101.34) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id
 15.2.792.15; Fri, 17 Dec 2021 09:50:20 +0800
Received: from mtkcas11.mediatek.inc (172.21.101.40) by mtkexhb02.mediatek.inc
 (172.21.101.103) with Microsoft SMTP Server (TLS) id 15.0.1497.2; Fri, 17 Dec
 2021 09:50:20 +0800
Received: from mtksdccf07 (172.21.84.99) by mtkcas11.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Fri, 17 Dec 2021 09:50:20 +0800
Message-ID: <bf06044e10b5eae36c9ac6ad0d56c77b35ca8585.camel@mediatek.com>
Subject: Re: [PATCH mm v3 28/38] kasan, page_alloc: allow skipping memory
 init for HW_TAGS
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: "andrey.konovalov@linux.dev" <andrey.konovalov@linux.dev>, Marco Elver
	<elver@google.com>, Alexander Potapenko <glider@google.com>, Andrew Morton
	<akpm@linux-foundation.org>
CC: Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
	<dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>, Vincenzo Frascino
	<vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, "Will
 Deacon" <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
	"linux-arm-kernel@lists.infradead.org"
	<linux-arm-kernel@lists.infradead.org>, Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>, Andrey Konovalov <andreyknvl@google.com>,
	<kuan-ying.lee@mediatek.com>
Date: Fri, 17 Dec 2021 09:50:19 +0800
In-Reply-To: <cd8667450f7a0daf6b4081276e11a5f7bed60128.1639432170.git.andreyknvl@google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
	 <cd8667450f7a0daf6b4081276e11a5f7bed60128.1639432170.git.andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.28.5-0ubuntu0.18.04.2
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

On Tue, 2021-12-14 at 05:54 +0800, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Add a new GFP flag __GFP_SKIP_ZERO that allows to skip memory
> initialization. The flag is only effective with HW_TAGS KASAN.
> 
> This flag will be used by vmalloc code for page_alloc allocations
> backing vmalloc() mappings in a following patch. The reason to skip
> memory initialization for these pages in page_alloc is because
> vmalloc
> code will be initializing them instead.
> 
> With the current implementation, when __GFP_SKIP_ZERO is provided,
> __GFP_ZEROTAGS is ignored. This doesn't matter, as these two flags
> are
> never provided at the same time. However, if this is changed in the
> future, this particular implementation detail can be changed as well.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> 
> ---
> 
> Changes v2->v3:
> - Update patch description.
> 
> Changes v1->v2:
> - Add this patch.
> ---
>  include/linux/gfp.h | 16 +++++++++++-----
>  mm/page_alloc.c     | 13 ++++++++++++-
>  2 files changed, 23 insertions(+), 6 deletions(-)
> 
> diff --git a/include/linux/gfp.h b/include/linux/gfp.h
> index 6781f84345d1..b8b1a7198186 100644
> --- a/include/linux/gfp.h
> +++ b/include/linux/gfp.h
> @@ -54,10 +54,11 @@ struct vm_area_struct;
>  #define ___GFP_THISNODE		0x200000u
>  #define ___GFP_ACCOUNT		0x400000u
>  #define ___GFP_ZEROTAGS		0x800000u
> -#define ___GFP_SKIP_KASAN_UNPOISON	0x1000000u
> -#define ___GFP_SKIP_KASAN_POISON	0x2000000u
> +#define ___GFP_SKIP_ZERO	0x1000000u
> +#define ___GFP_SKIP_KASAN_UNPOISON	0x2000000u
> +#define ___GFP_SKIP_KASAN_POISON	0x4000000u
>  #ifdef CONFIG_LOCKDEP
> -#define ___GFP_NOLOCKDEP	0x4000000u
> +#define ___GFP_NOLOCKDEP	0x8000000u
>  #else
>  #define ___GFP_NOLOCKDEP	0
>  #endif
> @@ -230,7 +231,11 @@ struct vm_area_struct;
>   * %__GFP_ZERO returns a zeroed page on success.
>   *
>   * %__GFP_ZEROTAGS zeroes memory tags at allocation time if the
> memory itself
> - * is being zeroed (either via __GFP_ZERO or via init_on_alloc).
> + * is being zeroed (either via __GFP_ZERO or via init_on_alloc,
> provided that
> + * __GFP_SKIP_ZERO is not set).
> + *
> + * %__GFP_SKIP_ZERO makes page_alloc skip zeroing memory.
> + * Only effective when HW_TAGS KASAN is enabled.
>   *
>   * %__GFP_SKIP_KASAN_UNPOISON makes KASAN skip unpoisoning on page
> allocation.
>   * Only effective in HW_TAGS mode.
> @@ -242,6 +247,7 @@ struct vm_area_struct;
>  #define __GFP_COMP	((__force gfp_t)___GFP_COMP)
>  #define __GFP_ZERO	((__force gfp_t)___GFP_ZERO)
>  #define __GFP_ZEROTAGS	((__force gfp_t)___GFP_ZEROTAGS)
> +#define __GFP_SKIP_ZERO ((__force gfp_t)___GFP_SKIP_ZERO)
>  #define __GFP_SKIP_KASAN_UNPOISON ((__force
> gfp_t)___GFP_SKIP_KASAN_UNPOISON)
>  #define __GFP_SKIP_KASAN_POISON   ((__force
> gfp_t)___GFP_SKIP_KASAN_POISON)
>  
> @@ -249,7 +255,7 @@ struct vm_area_struct;
>  #define __GFP_NOLOCKDEP ((__force gfp_t)___GFP_NOLOCKDEP)
>  
>  /* Room for N __GFP_FOO bits */
> -#define __GFP_BITS_SHIFT (26 + IS_ENABLED(CONFIG_LOCKDEP))
> +#define __GFP_BITS_SHIFT (27 + IS_ENABLED(CONFIG_LOCKDEP))
>  #define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) -
> 1))
>  
>  /**
> diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> index f1d5b80591c4..af7516a2d5ea 100644
> --- a/mm/page_alloc.c
> +++ b/mm/page_alloc.c
> @@ -2409,10 +2409,21 @@ static inline bool
> should_skip_kasan_unpoison(gfp_t flags, bool init_tags)
>  	return init_tags || (flags & __GFP_SKIP_KASAN_UNPOISON);
>  }
>  
> +static inline bool should_skip_init(gfp_t flags)
> +{
> +	/* Don't skip if a software KASAN mode is enabled. */
> +	if (!IS_ENABLED(CONFIG_KASAN_HW_TAGS))
> +		return false;
> +

Hi Andrey,

Should we use kasan_hw_tags_enabled() in should_skip_init() function
instead of checking the config?

I think we should handle the condition which is CONFIG_KASAN_HW_TAGS=y
and command line="kasan=off".


> +	/* For hardware tag-based KASAN, skip if requested. */
> +	return (flags & __GFP_SKIP_ZERO);
> +}
> +
>  inline void post_alloc_hook(struct page *page, unsigned int order,
>  				gfp_t gfp_flags)
>  {
> -	bool init = !want_init_on_free() &&
> want_init_on_alloc(gfp_flags);
> +	bool init = !want_init_on_free() &&
> want_init_on_alloc(gfp_flags) &&
> +			!should_skip_init(gfp_flags);
>  	bool init_tags = init && (gfp_flags & __GFP_ZEROTAGS);
>  
>  	set_page_private(page, 0);
> -- 
> 2.25.1
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bf06044e10b5eae36c9ac6ad0d56c77b35ca8585.camel%40mediatek.com.
