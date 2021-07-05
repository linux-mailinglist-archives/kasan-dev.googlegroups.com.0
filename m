Return-Path: <kasan-dev+bncBDW2JDUY5AORBGFURSDQMGQE3B5NKQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id CC8D23BBE5B
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Jul 2021 16:41:28 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id y10-20020a05651c154ab02901337d2c58f3sf7582250ljp.9
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Jul 2021 07:41:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625496088; cv=pass;
        d=google.com; s=arc-20160816;
        b=BtG2iVOvqMjaX6DdHXQfZaaXpd5YiZ7IMHYpFjB/CL2O+kQK+/zTj0DDzcS7jk8ZCU
         ckeANcYN8LVmfC9Lfl63tiwAd3cEO1jDFB3pSAhzc6d0rc+jEpFS5VD7iOf5jgBeVVxw
         nrQm9+/mzKLs3ZOfafAY53a8lft0nbkiLpTNWTw1pkdLIjn43FClhPnLj5AdTJBLB8SG
         r1NQNGW/imY4WTU86zj/0TcGKJeGhSITkiE5jUj77ryWCugpIQunuReYaAocKxevBC/h
         RwwUYg2YkWgR/zTpxwui0ZAUGAXhkSLm5zqXqMZMUm8gp73g/PksrBckRXionOMjmdbO
         JQJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=CjW2Do3XVLnCtJO6gVOe5Zl0GXhAQUGlX0Qm57ngzYU=;
        b=gsTyaM6w2rrjto/FTwzEjSbfKwvRucDfXn9Ro97KKJ5BBwFLFQvYZubZOVGfUF1WXt
         +ZNk8ZMLtkWzFo36PX7iJPI5bHpH01yAUlEOWOyx1uWB+FMex2A7LF5jl1/kZ4EohAIN
         wWnK0jsplLRySpRGK7tfGv5gVI52IUZG/het/cO8zECDs4wefLl1TUT1RSPgOOkYC7ip
         hrvuRXFhu+krvy890WeWvdfz7aHGoeX7oBz36cESNyfEd7Upti2MHongcAqfWMWXiCbB
         eumU8+JBRkes9+IENrbXW/5TJ4WTH39FTUk0fAW9JDfMCeUkM0yUM0yPDp7+S8tFooh5
         ufAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=oVi79Zcu;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::62b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CjW2Do3XVLnCtJO6gVOe5Zl0GXhAQUGlX0Qm57ngzYU=;
        b=sGvIiInM6FL/EWbal4zJdPdQt3iqMZwrk/0+VA94ohLXb00AXskOlLSSJNTUWIoidV
         o/bgouAJQVEEezXMP7SwgcRVx57CALh762z6lbfGnjTWFvs303qepjJSduJHMwMnPTf7
         /a8Roj5RDQ+at025TW5GG5fkE9cOYjqgD7M3UmXP//XcXfemqJWXwn95dyftZtBxuPZ1
         XNhHBlDH84hQsyrvv8LkWS6ZlDrv9elCQezmH76Wc05ZyNCPPKt1hY0aRgeyDqznOHu6
         1Hq8TeglNBJcTnGrOWR1S+BstFX5LpBkSgzw9slzk2eKKbJ1dG01Zw1SKiR2neG0RQes
         83IA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CjW2Do3XVLnCtJO6gVOe5Zl0GXhAQUGlX0Qm57ngzYU=;
        b=N/7PgKS/ocKjuNivAynGrkDkxuVaYLJlBgmqBiS48XuOEWjBSA51r7eSOA9TZotYk0
         zB4Y4IkWgGNXcAowGe7ZqS4X3X2f/dHWOM5lRxm0dC7ta4tlhV3h5gszPAzMVRPleHIE
         vom0gkrCEwVEnZVqxYnKOGsn0+um2CVADDv34bcuOy3fFeYFdmVSzfVecU/QxNbzz58A
         6Q53QO7omU2hPmvUz/qZQr79oJ4sRrpdQYPj1JYrxqCjTSenshxfbYjn7Ci2iVMBzHoz
         xwyLs1JDvh+5brpNB9PA1r9HDzgUApfWU1K8C/JY7x91NKGXqoRGvDZnSAoknxrrkBtS
         ePXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CjW2Do3XVLnCtJO6gVOe5Zl0GXhAQUGlX0Qm57ngzYU=;
        b=nnyUFLJVK2Aj3W8zRblkbMr4UUFSn0J/C5oKyrKYd2HYPMAeznMBATR/wJajoh1SIy
         3hfminjeYBZ/EyGDnrl8UFEGelrjWY6KOGJwyC3tYOWkMjsPcUrPIw/jV5Asyo8j/UCL
         zHXVefHkPwgCsUXUpDgmNrxa5vgDZBEm+bHLOAHDnOPuJjbwWZ+LsATxIr6fq5+kiLGw
         b22uBVkCWA2FfwoDBrHjZvoWS+vc1IErgFk4Jkk02FxN0aKyLKLfi8KlzDjzJAhftHy2
         tjzi9fVgWb0X+e1ucuA/cHDSfoY37v9F4n3geKcZ+gdEwl3yeb/VPYsMwzBCtr1ZUOGE
         qECA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531csMRF1dKx5SZIoxQaE1gHBB1T7DUIza3fZZWSv0CwkOyoMZeX
	6hvbzpXfk2FNs9RHfJaDwJA=
X-Google-Smtp-Source: ABdhPJwJZKivpLd02xuMy6wXU4zstAH4bhwNyRtHm37j77pfpB5onGWyFZDDfeNaudIy/yPmser3JA==
X-Received: by 2002:a05:6512:110b:: with SMTP id l11mr9017077lfg.91.1625496088435;
        Mon, 05 Jul 2021 07:41:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:211f:: with SMTP id a31ls655313ljq.4.gmail; Mon, 05
 Jul 2021 07:41:27 -0700 (PDT)
X-Received: by 2002:a2e:9611:: with SMTP id v17mr10072220ljh.212.1625496087389;
        Mon, 05 Jul 2021 07:41:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625496087; cv=none;
        d=google.com; s=arc-20160816;
        b=nv/VDz2kFXjwWzCfVW0IzmIUmsScrquEtegb9hZ5m9VYaXxomYdTiG4uqbfLdmln6w
         XlyysTTPujBtRVaZhoYLQcO7NTxXsLTW8W6LVzTn5OZFkYHjgVWogDRuKUenNnecaWh3
         Oik1VhMVZp2kT59VMN5cVEtuk18RSNLUnRzNHSG1h5NmmkO6f4accBpun9KTz+yGzhR2
         KwY6yq5WPtL03h7yHdnI79fP85m7K/fd6XKZERHgXAC+OaQbsbElQgGctqlf06zEKaqg
         gvSwdA7ZyRqKrTX0hAWbHyqwIXLANO4dfJVMJugZgNkrhngPos7Jq+WaY4FxrU97k6kg
         IRgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pAbvWLlq9ACgk831d9oOZ3Sk5AFBCQPn8le+JrfsWvM=;
        b=ByEB+YeOKD4SwqufK8yxmHI0rfedGCXyzntJVbbDyM3JVjFNsis4t3TKxT+O4lffDH
         K4VtONw8K/VmEAVkh0MMZZR2XCWieuEbPaedkfa30PY/UatIjHPcG+45ok0Orl+NOZFx
         mbJNj8h4jt5XQn2tFETp6S161Ke6jB/1h1gHdk/VzLi4meTNXDzIEdeWdxVYo9atnz52
         chEDzrvnaGIGBnk3GJaK3M+hLwV6zoiM6ksQDhXTEGz16Xme/u6KArFtHRGIij+NHDnv
         Bk4z3MElSwaNt6TKg8wlpjtc7W1gZJMfWshYepeNQvWoBlJNOUwW2RxSE3Ez/QWrTwM8
         oPsA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=oVi79Zcu;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::62b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x62b.google.com (mail-ej1-x62b.google.com. [2a00:1450:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id d6si354790lfk.4.2021.07.05.07.41.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Jul 2021 07:41:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::62b as permitted sender) client-ip=2a00:1450:4864:20::62b;
Received: by mail-ej1-x62b.google.com with SMTP id he13so10690544ejc.11
        for <kasan-dev@googlegroups.com>; Mon, 05 Jul 2021 07:41:27 -0700 (PDT)
X-Received: by 2002:a17:906:f14e:: with SMTP id gw14mr13913822ejb.439.1625496086980;
 Mon, 05 Jul 2021 07:41:26 -0700 (PDT)
MIME-Version: 1.0
References: <20210705072716.2125074-1-elver@google.com>
In-Reply-To: <20210705072716.2125074-1-elver@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 5 Jul 2021 16:41:16 +0200
Message-ID: <CA+fCnZc4XrsCbh1ZXwFShmaZ41_4Sj9LywZAq1fYju2V_t0HQw@mail.gmail.com>
Subject: Re: [PATCH] kasan: fix build by including kernel.h
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Peter Collingbourne <pcc@google.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=oVi79Zcu;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::62b
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

On Mon, Jul 5, 2021 at 9:27 AM Marco Elver <elver@google.com> wrote:
>
> The <linux/kasan.h> header relies on _RET_IP_ being defined, and had
> been receiving that definition via inclusion of bug.h which includes
> kernel.h. However, since f39650de687e that is no longer the case and get
> the following build error when building CONFIG_KASAN_HW_TAGS on arm64:
>
>   In file included from arch/arm64/mm/kasan_init.c:10:
>   ./include/linux/kasan.h: In function 'kasan_slab_free':
>   ./include/linux/kasan.h:230:39: error: '_RET_IP_' undeclared (first use in this function)
>     230 |   return __kasan_slab_free(s, object, _RET_IP_, init);
>
> Fix it by including kernel.h from kasan.h.
>
> Fixes: f39650de687e ("kernel.h: split out panic and oops helpers")
> Cc: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  include/linux/kasan.h | 1 +
>  1 file changed, 1 insertion(+)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 5310e217bd74..dd874a1ee862 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -3,6 +3,7 @@
>  #define _LINUX_KASAN_H
>
>  #include <linux/bug.h>
> +#include <linux/kernel.h>
>  #include <linux/static_key.h>
>  #include <linux/types.h>
>
> --
> 2.32.0.93.g670b81a890-goog
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZc4XrsCbh1ZXwFShmaZ41_4Sj9LywZAq1fYju2V_t0HQw%40mail.gmail.com.
