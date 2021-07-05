Return-Path: <kasan-dev+bncBDW2JDUY5AORBKWSRODQMGQEHTGFL7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id F27E13BBC00
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Jul 2021 13:12:42 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id w4-20020a05600018c4b0290134e4f784e8sf946457wrq.10
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Jul 2021 04:12:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625483562; cv=pass;
        d=google.com; s=arc-20160816;
        b=vFAyal4NmreebBz14j/TSEZrtICULlaFKVkIsJpvlSU/uNjNKl6OVZuhHmSBd59Tgp
         ch1lC+h4FOKBYisl8WNeCdBPt1gEI8BTBYAvq5zpzuQJxFNbcZKS1a91FmAY3T9C5g2H
         fnD54cF2v5zM98b6ZP9UfRNVlfljdZIND0AHC45wLDRMZQVczO0+pKKJIIcX3vQFxsSp
         caqsOpi5nVxk+id+SxtEPfKMeNkKiUnYCqLe3emmDBqfJ9AJauQjief/pcmm0A//NUhq
         KBQua1nAFnKrtEgNZMJPcADSRizc7VRKMAsE6BQRT4vQGhhiZJEiY2R6unRSyuVqQai3
         ZpdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=NDmM1ph8ofuUu9fad3+PXSd/Bl/XFL/9kW0UyX2FXIE=;
        b=Ka9ZqewWV6VvoSpWCHym9FYG4uBtd/JHrwwW7M4eE/xWTTigAl5q9eyToX0csqEy6D
         7Ik8vwttIWZCJB7KRmoGTM21XpZRBwmtrPbvi02Yf6UYaGXsyIhmUDXuoVjOZG6GsdFA
         0sds6o+pZMZOVxsKuVseGqAq4yPJfPz1BYjxFxDTJfsDCpwUEW+npnZUdkqsjGUoMT5o
         nKzHSZOE1+rIrsWcEPvH914KnD65IHaP4SVC0NM9JOYzIYeQDVbPhsB1QNidTK1kK8UY
         NmRqw3JS2gN4rttz7M4C3+fY7O7PxlV88tqCO2ikjoom58v9ZteYfBGMgAQQMXitzLD+
         i4vg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=jEnaley9;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::52f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NDmM1ph8ofuUu9fad3+PXSd/Bl/XFL/9kW0UyX2FXIE=;
        b=UMmsucbKh6/v9F7epubt5XHzERgEOxQNLTiMzuM0iPl9MXvd1gNx38h63wcBry7e7V
         k1y26uwlnhl+zpfQyQDQ2x90zbxJDdSywMttvsWAoj38FIkIoihQZ8AybrJkJfNXOw9V
         cKEwP7yGNIaBQjBdAlWKA/STlErOzplAfoXozJZTrapfJFVJTitvEzVLZQKqPoN26sFK
         TdPFL6w2NRIYw8VbDqQTL82IYGpl0L/8+OaOXsLe9s1NFEB6RcWOL/WdhuexSikywGcJ
         ePGWACkNNfL8yKtXSXuwJ6ujfE0bjC2VNMHEwpWEHT5MlqCRBtjIlEjKRyUA9Wozrdud
         enGw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NDmM1ph8ofuUu9fad3+PXSd/Bl/XFL/9kW0UyX2FXIE=;
        b=YYxpN4CTkzSsueNF3XHjWBqpvQ/sK3EgOTjp8xmZS7CUWiHYYJdjcLD26KE3gpH1y3
         5Eqq3PKrqqX74OGHpgIp/wMtybJIvnc+x7+39YglbtvpzGwKkT5D69j8cxGU3xtn6QAj
         1Vq6PDEDczu3aPcHYI6INvr0K4LSKxqIKOYPn8/GJg72g26GWAPCPUDcxURqUBL1IJL4
         VWn3lrEESfcIrtf9qTAdM5WfUSC8fR+YHJf4sTiYnqSOO0NRIZGwBvGAXHhj8XaOmArn
         yCuyjUQ8hUWYvVwN9RcaHXLlOZlgqV04cKsqFHbZDPZ7TjgndlahjrBJJsilFivavv8t
         1kKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NDmM1ph8ofuUu9fad3+PXSd/Bl/XFL/9kW0UyX2FXIE=;
        b=h9x+2fNnUOimJ2wfcKwKr3x01OKLpbUHCD+X1ecR8D7AWgxnE+8Hf/rRRkw8fajfU/
         aUzVOQVAr0YayR3bbr9ts12X10M5IvaukSlSL4Aw0M0imSnUBpgA0C48jSWmuaaHyGEy
         ov1XEnW6o4tYiJob37EOYAmij9voNHinqUlrSnKyJ+OJlk2eb+A+90DyyBpWIIWywG+S
         NXGZxs/K5bFoHPRQNx2VttXICUsvr5xzm9+Rpm49u//5nQLtFySMVfvA6RObv617fxo2
         /ugED1hbElfO7XVZLTvzqUlCw5GApKeGOEaVKoTnDxoiJO9x1Q2SPDXr9aP9QRTaKPcV
         BSNg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5322UivCvwCq8O7wO3V3/7Rabs4/tzl8D+97Pc5jZH/EKcnIPvfX
	ab+L6tLv/JP1VEzaqZk/kOc=
X-Google-Smtp-Source: ABdhPJwaEvFt6ndu2/Ipg/ipeSSYLu8zLlDNA4X7PQaYOCi1a3evMJjfW8FJLM+7re9Ivu/R7Svplw==
X-Received: by 2002:a05:6000:e:: with SMTP id h14mr15279617wrx.235.1625483562740;
        Mon, 05 Jul 2021 04:12:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:ecd0:: with SMTP id s16ls6131814wro.0.gmail; Mon, 05 Jul
 2021 04:12:42 -0700 (PDT)
X-Received: by 2002:a5d:5985:: with SMTP id n5mr8883754wri.63.1625483561927;
        Mon, 05 Jul 2021 04:12:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625483561; cv=none;
        d=google.com; s=arc-20160816;
        b=Yrj6tZqUg4O1wFBEqBVOCJcYa90uwpWoPY7q/Jl/Vtpc4oUMFv+PVgpupkXriiExEb
         X+IZpUIa0r1lO1sdKF+uDAYgMEHhMecufc382uuZ7duXNpgSZoyMXUBDLRSH2VAPO2nL
         MQyO0OzxRenJfKmKhRL+vwow5vhPMKrPmjs7TmOXIskE9xBhsJemeI1cUTsrfCh5PNws
         Ltjo/6Rdlg2TgDI5P71hBjFRxaEXSGDF7pYq4ZxMvaBis/ubHTN2ScRcm7ZivWVMpYjh
         tSuOnRZqW/N0EDy/xizFI+QuDxqj9K40rxMXxceR23bz4rdXT6cwU1bPoRH8xdyYeW/2
         3azA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CaX0flpcWSf1BxIX9YKTaXTNjn37cg6419yg5j4auho=;
        b=qyI71ff7mNlB1HXstjlSm9xiob2hpDttRMVfIzdaJGJ5XTxf1cMPLKQN3aNf8bcX3/
         Cq0s849mpdMK0KgHd4kDeLSWtAE9ZIl3VrNfM0R1xI07teIgXqOXBuiVTfsWwDplYfrg
         1xJE+zFJ1jUdU85Enus+yd700h7o5oLTJQOWTIa+QjGsHx6Uyw8LM9ZoF4Y3UJf5nYLd
         seWIjQk1sB93oDv2c1aWD//bmGugRnkrzAke+Tnc/2iBV099LvpmoakcmdrrxMk8ZmGN
         cy6WxYMM1FtGHYWVeToJoB54zZ4Nr5QV9MzXW+EhMr6NpWuVqqQppVnGP+/Ahfky2zH5
         mHDg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=jEnaley9;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::52f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x52f.google.com (mail-ed1-x52f.google.com. [2a00:1450:4864:20::52f])
        by gmr-mx.google.com with ESMTPS id j63si690608wmj.2.2021.07.05.04.12.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Jul 2021 04:12:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::52f as permitted sender) client-ip=2a00:1450:4864:20::52f;
Received: by mail-ed1-x52f.google.com with SMTP id m17so1655205edc.9
        for <kasan-dev@googlegroups.com>; Mon, 05 Jul 2021 04:12:41 -0700 (PDT)
X-Received: by 2002:a05:6402:5c9:: with SMTP id n9mr3075816edx.30.1625483561668;
 Mon, 05 Jul 2021 04:12:41 -0700 (PDT)
MIME-Version: 1.0
References: <20210705103229.8505-1-yee.lee@mediatek.com> <20210705103229.8505-3-yee.lee@mediatek.com>
In-Reply-To: <20210705103229.8505-3-yee.lee@mediatek.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 5 Jul 2021 13:12:30 +0200
Message-ID: <CA+fCnZdhrjo4RMBcj94MO7Huf_BVzaF5S_E97xS1vXGHoQdu5A@mail.gmail.com>
Subject: Re: [PATCH v6 2/2] kasan: Add memzero int for unaligned size at DEBUG
To: yee.lee@mediatek.com
Cc: LKML <linux-kernel@vger.kernel.org>, nicholas.Tang@mediatek.com, 
	Kuan-Ying Lee <Kuan-Ying.lee@mediatek.com>, chinwen.chang@mediatek.com, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Matthias Brugger <matthias.bgg@gmail.com>, "open list:KASAN" <kasan-dev@googlegroups.com>, 
	"open list:MEMORY MANAGEMENT" <linux-mm@kvack.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-arm-kernel@lists.infradead.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-mediatek@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=jEnaley9;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::52f
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

On Mon, Jul 5, 2021 at 12:33 PM <yee.lee@mediatek.com> wrote:
>
> From: Yee Lee <yee.lee@mediatek.com>
>
> Issue: when SLUB debug is on, hwtag kasan_unpoison() would overwrite
> the redzone of object with unaligned size.
>
> An additional memzero_explicit() path is added to replacing init by
> hwtag instruction for those unaligned size at SLUB debug mode.
>
> The penalty is acceptable since they are only enabled in debug mode,
> not production builds. A block of comment is added for explanation.
>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Suggested-by: Marco Elver <elver@google.com>
> Suggested-by: Andrey Konovalov <andreyknvl@gmail.com>
> Signed-off-by: Yee Lee <yee.lee@mediatek.com>
> ---
>  mm/kasan/kasan.h | 12 ++++++++++++
>  1 file changed, 12 insertions(+)
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 98e3059bfea4..d739cdd1621a 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -9,6 +9,7 @@
>  #ifdef CONFIG_KASAN_HW_TAGS
>
>  #include <linux/static_key.h>
> +#include "../slab.h"
>
>  DECLARE_STATIC_KEY_FALSE(kasan_flag_stacktrace);
>  extern bool kasan_flag_async __ro_after_init;
> @@ -387,6 +388,17 @@ static inline void kasan_unpoison(const void *addr, size_t size, bool init)
>
>         if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
>                 return;
> +       /*
> +        * Explicitly initialize the memory with the precise object size to
> +        * avoid overwriting the SLAB redzone. This disables initialization in
> +        * the arch code and may thus lead to performance penalty. The penalty
> +        * is accepted since SLAB redzones aren't enabled in production builds.
> +        */
> +       if (__slub_debug_enabled() &&

What happened to slub_debug_enabled_unlikely()? Was it renamed? Why? I
didn't receive patch #1 of v6 (nor of v5).

> +           init && ((unsigned long)size & KASAN_GRANULE_MASK)) {
> +               init = false;
> +               memzero_explicit((void *)addr, size);
> +       }
>         size = round_up(size, KASAN_GRANULE_SIZE);
>
>         hw_set_mem_tag_range((void *)addr, size, tag, init);
> --
> 2.18.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdhrjo4RMBcj94MO7Huf_BVzaF5S_E97xS1vXGHoQdu5A%40mail.gmail.com.
