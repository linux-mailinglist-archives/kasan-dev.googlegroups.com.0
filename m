Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQ6FRODQMGQEKBZRLTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 084D03BBB72
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Jul 2021 12:45:25 +0200 (CEST)
Received: by mail-io1-xd3e.google.com with SMTP id c5-20020a5ea9050000b02904ed4b46ce62sf13145360iod.16
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Jul 2021 03:45:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625481924; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ue87vi/uas5r7qQM6lcj+GGBc+tgXSnWbFI8OXTJWjd8alAdjiOK4jAH5NMRP/PFRb
         9rg9A0FVBWF3hTgq0BIGWjyyUvvWqgIcsPvS1NnB905YE9UQiNEiBPJ2JabUcO/QlS9I
         /Je7dCzFnTzhgpAuyFGhN8dfvlmEc7AH/0B7oaEeQ1U4a8iqnYNwEJ4w/0a9T5317l1G
         90ZG87yIUnevcWhOB+U7b0a3/JOlyxyVmCAC/a3ry/6QGDP5pGXrsSMY2Mz8mf1eDHv0
         YRERxVCubIoapdvB23hRXbaLw+lfixK5GRHOp2K1hUZkBcGwqd899lygITEqmsoUXOQh
         IhLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5UuLr1Q49PY3C5yJSW1Sm/YZeKMq1Dc4FjsW/Bn2bek=;
        b=SOvg+BVbPNDoC8KyhRSwiFqE7zmEBg8KsrA2QC1zT+wNZUaB1QDJYqxtNH5b3qGMAE
         4GPciq0hy9nxevUU/qapd4JhHq+pd8UKVwXxBzfICTebUpCjmYly6+SmlnZIwRLALOvZ
         AiRQe6bptuHVV3w3R3uRg+FEy/Jvc/SmYadd7jIIGxsatnvIZh7QGnzGU+DSbHTIhnOr
         JqsrsR+sv3Clv3X8igYtgrRKQ+puHfR7LLa16BHcSdTNjA+p4iDhHeF1zokL6IOKf2ZU
         mmgaG1lc/z2+dPo+UeG6+GgYBlF5LZPI+CKA++3juAM5uF10LezFwliOFbqtU1mXM/Ih
         5X/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rzSYkZK4;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5UuLr1Q49PY3C5yJSW1Sm/YZeKMq1Dc4FjsW/Bn2bek=;
        b=fb0QGxlq0LiY5G3QAkUg1F6+WdVAaJTrmi45dMnsxrhfXgAbO5aoJAF112xN8SS82m
         nk3OjX0YjkwQ72tuF0vmydAKcnBnUorQ/SgiuHXNUEZxiPfvq7AiWY/HrySY8MJOvyCm
         3x4RAVYlkjZRKSXNwq4ceB4FmBXUsSh2sYsJiM3c4zKKbjmdTzRfO61GoN9QgALdVug/
         Hvj9LMl4u57E9R4mLrs1qica18/5fd3j4OdhhtDQLE9ZjIMvEJEoo0tfuTDn/6bCPKsb
         SeYdJVQRR0sBd3SYjv2+Ayv/9l2z8YMm6Ge54HDM3lRkNG8PNoX075Zoe+RHkpkFMYNs
         DTvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5UuLr1Q49PY3C5yJSW1Sm/YZeKMq1Dc4FjsW/Bn2bek=;
        b=Lxj7pp8ivxv3IG9vhMAPDCMkIT4uTjjyHZ4XWU6Wjqi/DuEEfBj/1HZcZ5Kgzf+heO
         sBOJSsTd8j0YkRN0EBI40effXH2PU/VkR/ovhvdGCJAWmWYvi6cBf3zpQ/E9f2LbsBNj
         9rkx2iS1lhhF4A3Od7zmD8KiTcP0BRWc17hsKJjKZ9hWwY6PLZVA0kbVWk0wTqDLdp5e
         6WP3UTpk3nbT4fxL94HukKon56xb6s/GZpxa/zXKabcJ5LWUT0AHFnB8eqBMsn/cYHdX
         yemaJSNqzPuGm8wcRtKSxvwl0Gn6kmbG3w/ln9MzA0X8Gz6mmyv0thMKoms7rphw9trE
         jb3g==
X-Gm-Message-State: AOAM530qsUDfduRPUgrdkhovKCZxnsty+razV59cZFB2RisaWoH3j47q
	Z2PlUV6MFoDOIiNVJbcUnTg=
X-Google-Smtp-Source: ABdhPJwxfDwYPqYNgjLUhMgU+6azvc+EhaNnPAJFfQD3557g++iEBf6hTtFtHWuqykfwWxDbSW4qtw==
X-Received: by 2002:a05:6e02:13b0:: with SMTP id h16mr9933853ilo.271.1625481923835;
        Mon, 05 Jul 2021 03:45:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:39c7:: with SMTP id o7ls2595923jav.0.gmail; Mon, 05
 Jul 2021 03:45:23 -0700 (PDT)
X-Received: by 2002:a02:7f89:: with SMTP id r131mr10833871jac.68.1625481923191;
        Mon, 05 Jul 2021 03:45:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625481923; cv=none;
        d=google.com; s=arc-20160816;
        b=l3c6MsjW+MWO2M6SS8FI1ABFLHLSBwnx6rkVaxhKtUsiSJgQ6yqIxsR9mrAFPoB1lc
         n/kUcDBSXJH2Tmk9zZ4s1b7acRgIp9yxsVikbwlXk8zKtIwgvfMZjtOEe9Px6kpl0Kmi
         vx7fan+wZqbnodqAFDzomhYedLQjBgnAt3417DdidoqTV1M+ti/nULj+24W9YBonxn8Z
         AsRKwpSEHRT7Ine1FeVeQ34l3tVrlHzjPAB+ifp7WDMVkA0XPXDOSapRItKk8eiGi2Uk
         zNGoH+PH69DdEj0UjnEmlWuGVTb0yepZ6mHFmR6TiCU7Q63T1h4D/5IpeW0LikXLwqS+
         hNZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/dlGtZu9Ej/xN5Tsuqsmc/vVOMpJLibVcfVItFdDo7U=;
        b=zWIHYbZj8jNn7TGXHnnePCi5tedfojkVDeJqHMu/iGdNkJjIHaEceJGhI7Kym7Jdfs
         fcI8FFlMb4J7jFKxocXKwUYKegiwB1IAO+OWbCJrIDk/xDO5d0YxdqWcXozoZdPskrhU
         LSe6e8mlPt65L3QD7AwufgNduf3/xtWHUmIdkSCTo3/l8d24+LqSsBuVym17nsycK6j/
         C2doZavYFP6w0smC5NzOwz2E48Rf7PDVcXlLImsllfI/IOTv2OjzyIcrzXbY7JcXxWt2
         QJx6Nvd3LAc8h3zHPGF5WwY9ZnqTkLwKdr8Ef/jaQubpV75dp4+xKJ8D34g6DQWoiDGQ
         ExYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rzSYkZK4;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32e.google.com (mail-ot1-x32e.google.com. [2607:f8b0:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id i12si1035621iog.2.2021.07.05.03.45.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Jul 2021 03:45:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32e as permitted sender) client-ip=2607:f8b0:4864:20::32e;
Received: by mail-ot1-x32e.google.com with SMTP id h24-20020a9d64180000b029036edcf8f9a6so17905961otl.3
        for <kasan-dev@googlegroups.com>; Mon, 05 Jul 2021 03:45:23 -0700 (PDT)
X-Received: by 2002:a9d:d04:: with SMTP id 4mr10779395oti.251.1625481922714;
 Mon, 05 Jul 2021 03:45:22 -0700 (PDT)
MIME-Version: 1.0
References: <20210705103229.8505-1-yee.lee@mediatek.com> <20210705103229.8505-3-yee.lee@mediatek.com>
In-Reply-To: <20210705103229.8505-3-yee.lee@mediatek.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 5 Jul 2021 12:45:11 +0200
Message-ID: <CANpmjNMg7DwVJL10AesxTsiz_9UEuwZkAxdGrQdsmxOR4qiHXQ@mail.gmail.com>
Subject: Re: [PATCH v6 2/2] kasan: Add memzero int for unaligned size at DEBUG
To: yee.lee@mediatek.com
Cc: linux-kernel@vger.kernel.org, nicholas.tang@mediatek.com, 
	Kuan-Ying.Lee@mediatek.com, chinwen.chang@mediatek.com, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Matthias Brugger <matthias.bgg@gmail.com>, 
	"open list:KASAN" <kasan-dev@googlegroups.com>, 
	"open list:MEMORY MANAGEMENT" <linux-mm@kvack.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-arm-kernel@lists.infradead.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-mediatek@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=rzSYkZK4;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32e as
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

On Mon, 5 Jul 2021 at 12:33, <yee.lee@mediatek.com> wrote:
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

Reviewed-by: Marco Elver <elver@google.com>

Thank you!

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
> +           init && ((unsigned long)size & KASAN_GRANULE_MASK)) {
> +               init = false;
> +               memzero_explicit((void *)addr, size);
> +       }
>         size = round_up(size, KASAN_GRANULE_SIZE);
>
>         hw_set_mem_tag_range((void *)addr, size, tag, init);
> --
> 2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMg7DwVJL10AesxTsiz_9UEuwZkAxdGrQdsmxOR4qiHXQ%40mail.gmail.com.
