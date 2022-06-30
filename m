Return-Path: <kasan-dev+bncBC7OBJGL2MHBBO6X6WKQMGQEJV63XHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 61664561640
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Jun 2022 11:24:13 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id b24-20020a17090ae39800b001ecd48d4b29sf1184588pjz.4
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Jun 2022 02:24:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656581052; cv=pass;
        d=google.com; s=arc-20160816;
        b=A4KhFQUCHqWWX4J3Y1qH3i62HgLSNwzNdxPRxa6slBibxPFfS57eXrcD1yDEdpItRp
         gPNDPlRHvWGdHuZr5C/JoGY1jZSHdPr97S0QyaNfI1rm73wO7wnSAnj4IkQ8frz3hfAp
         zlzfJu3X54QcmodB7mbeOyuEHsX439hgrmci5pKn0Wy1IExprglGKosjBbdqas1svZ44
         zXSotI1MrkTYK4Oph0rJb9CqIBaJhtHi23NLWfsDIzFYIrGKvcuj9iYr6HmElBYbheMo
         +waMFFtRum7XZbdB82qgs8cj6xrBo0HzoNV1UbblE5qzhh0BlULywWosheRqoKuJq0O9
         vUJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5kaQO+ff2cSdx491nz7RMNmu8RkhLT/xhIrJse/ccFs=;
        b=K+CENg/mDRM+ohjtDbaAD11+4i9v00jDQ9YYjSeoBoKOLBgzaXt3epNxeoAf/JOLWG
         msVBNMzX+IT1Mu4v8Zg8LKIQ13tL06i3GlNfl+35BJg7y7KxnbqZoHdmw/SA7hZRhYAc
         0prQt3kxjkpfb1cGUFLe4y4WhHjCca5NH8ay2bc8KAwASBa9acTH7QQQCujn6VZSuo+4
         YxCKL30jFJ/aZslkSV8eMRqGx6qmFODATrw4Hj3rOKmowj+Rjw8cqmt3ZS5Rm9ZQ4FFI
         LTmHhs0ysLuqTR9pXB3zZlcl7Eo9yT8a+QRkr0kLVNVHy8elgyOZc3U5IgwatN7Cg2GH
         Zc2Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Okonep8o;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5kaQO+ff2cSdx491nz7RMNmu8RkhLT/xhIrJse/ccFs=;
        b=SoixUCFO6lcTgcxjJRAoX10lhMXLHEhgFg1e4xhuuGlgd1wdTVm0bu/Kk02sRTQoR9
         DEddub6JboIpRJdxjoCViwukKy/gby3UYb1VB6eVeLHaXQEogWLEU10vURv/fg9mSQ1U
         zawnyDLKkcx4MaAqlR7qO8yWjXD9qClXJuKVh7P3Todq1xKJjdKjrtqhINaZwEmX3WnC
         865eEM5j1RnXwwbveuwY3XhdSsoZJG8lxrN76UYk7enM/GAS+qiD9bkUOsE1ova7Ib9O
         yYkDraPp7XTg3v+z0Tr2kL5NemXf7Y8BBB+546asLhVqfhnV0w6o7bEU2z0MOb6MOwag
         au2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5kaQO+ff2cSdx491nz7RMNmu8RkhLT/xhIrJse/ccFs=;
        b=IpSq2keVbgnX5pesUBfXM0fljCiBgNr5NsXGn/UsQHY/kmrPx1+ViFGKTVvfiTUMqI
         ichwdLbkmjUC7im0mL1Z8YHTgYLD052Q3jYfM1eb4mrwwd66CSf2i4GD/ClSSMus0cNN
         uZb2M/q+jFeOEeKYQGoREazK0zy4qo08Y2QYs73OiQW+jMW4jYrIMnNqgUD1ErmiJJML
         Kg6vYEZ8Ni6gvhCSTXRe5aJeXXIIsMq1des6GYPAxmWJombOv9hVcJdkyrHiR7OVlEei
         ubvlr7rrkaoneBQ4E3yqD0P2Xwznw31Q4HzD8nBRLNIz1nh6EgMWC5pB/Y0RYZw/Cf96
         P4YA==
X-Gm-Message-State: AJIora/W3XvqltJv7/2afJ2nzxkVkjjDp8VkdY4GV8R6hV+GW7EXJC1f
	zGr0YgmSyCinHnPfZ9PYUWQ=
X-Google-Smtp-Source: AGRyM1uMW99rlg2ZgipCcnx2cFWFKk95FCG/CrE9C6+EsLEkfQqXLR6oZGxVE+2Z2A0mAQoDx5JgGA==
X-Received: by 2002:a05:6a00:16ca:b0:525:a5d5:d16f with SMTP id l10-20020a056a0016ca00b00525a5d5d16fmr14829899pfc.9.1656581051906;
        Thu, 30 Jun 2022 02:24:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:ace:b0:505:bb88:8eb0 with SMTP id
 c14-20020a056a000ace00b00505bb888eb0ls17551816pfl.10.gmail; Thu, 30 Jun 2022
 02:24:11 -0700 (PDT)
X-Received: by 2002:a05:6a00:2395:b0:525:8980:5dc7 with SMTP id f21-20020a056a00239500b0052589805dc7mr14965789pfc.8.1656581050967;
        Thu, 30 Jun 2022 02:24:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656581050; cv=none;
        d=google.com; s=arc-20160816;
        b=U3l7Jb4YPrjWuqxcGV1/tWC1MP4yeHnmeK4o91ih5w1rDVCVIDQdmdnp2s4UfDQQ3T
         vDs51lDRkaSnA6ORrjGU3dN6Z8Qxwj9bfWTaki1CTHiPzs7SK/97vl0OM5rHhTGMzRyq
         lUadrIpNa1Gwuc2k19Hl2vLt5kPzFXxwBMlBW6fZn9mwBXNUecAA4e8asL2zqctNccrB
         CrfqbZ08BgqQTpmSTeQEIGKUwtQcpTywoRH7BXwll7Al3dakqmufhJCs87rIrjpmMiG2
         Ivg5jbW8Vi1QgtJR7eecy/kH4uCT/M9N+Zlgqkjt1ZNcWr3drmu6rqbrsJjA8M0ea5ZG
         gYXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BiBmHGa2ClhXtCQ51AGcLtCso1fCDbCqVOHmA5sybi8=;
        b=gg4DxIs0i7BCMKrm+Jes93RSd1nRhnuPqMiold91uja8+bpOI/4RVq33kiaO/zLiHA
         zKDNjcYJyVqo5hkaA7f7kfszA6Ca+Ec4UGV/wijFY3vrbrqpObAzgJKTjpFm2DSR3qek
         0f4Tx48016TsCP+eLwoLggcYf0mTPJeEVBKBELa7zmVNVv2qAHijtkP4U8xtGPWjtHDi
         86+Tm7EEPhgaiIID/LWJUaspVofz/l/s6mZXn7iCxbVii46JdSszYI3LnaFh1NuzbRnm
         +BrEymCx8lHX4sif+l3WCGZW46/1I3ImPxUAgqBZ+tlDiPFqJyej8cntZFkC3Z1Z+3Eu
         YaGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Okonep8o;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb32.google.com (mail-yb1-xb32.google.com. [2607:f8b0:4864:20::b32])
        by gmr-mx.google.com with ESMTPS id g14-20020a056a00078e00b00522cc5c7b21si697660pfu.6.2022.06.30.02.24.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 30 Jun 2022 02:24:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) client-ip=2607:f8b0:4864:20::b32;
Received: by mail-yb1-xb32.google.com with SMTP id d5so32673766yba.5
        for <kasan-dev@googlegroups.com>; Thu, 30 Jun 2022 02:24:10 -0700 (PDT)
X-Received: by 2002:a25:3497:0:b0:66c:c013:4bea with SMTP id
 b145-20020a253497000000b0066cc0134beamr8274918yba.625.1656581050492; Thu, 30
 Jun 2022 02:24:10 -0700 (PDT)
MIME-Version: 1.0
References: <20220630084124.691207-1-linus.walleij@linaro.org> <20220630084124.691207-4-linus.walleij@linaro.org>
In-Reply-To: <20220630084124.691207-4-linus.walleij@linaro.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 30 Jun 2022 11:23:34 +0200
Message-ID: <CANpmjNMWfERo-jF772e9XM=8GxhdYODsHrmg5xQ56aw_1OD7tw@mail.gmail.com>
Subject: Re: [PATCH 3/5] mm: kfence: Pass a pointer to virt_to_page()
To: Linus Walleij <linus.walleij@linaro.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Okonep8o;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as
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

On Thu, 30 Jun 2022 at 10:43, Linus Walleij <linus.walleij@linaro.org> wrote:
>
> Functions that work on a pointer to virtual memory such as
> virt_to_pfn() and users of that function such as
> virt_to_page() are supposed to pass a pointer to virtual
> memory, ideally a (void *) or other pointer. However since
> many architectures implement virt_to_pfn() as a macro,
> this function becomes polymorphic and accepts both a
> (unsigned long) and a (void *).
>
> If we instead implement a proper virt_to_pfn(void *addr)
> function the following happens (occurred on arch/arm):
>
> mm/kfence/core.c:558:30: warning: passing argument 1
>   of 'virt_to_pfn' makes pointer from integer without a
>   cast [-Wint-conversion]
>
> In one case we can refer to __kfence_pool directly (and
> that is a proper (char *) pointer) and in the other call
> site we use an explicit cast.
>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Marco Elver <elver@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: kasan-dev@googlegroups.com
> Cc: linux-mm@kvack.org
> Signed-off-by: Linus Walleij <linus.walleij@linaro.org>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  mm/kfence/core.c | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 4e7cd4c8e687..153cde62ad72 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -543,7 +543,7 @@ static unsigned long kfence_init_pool(void)
>         if (!arch_kfence_init_pool())
>                 return addr;
>
> -       pages = virt_to_page(addr);
> +       pages = virt_to_page(__kfence_pool);
>
>         /*
>          * Set up object pages: they must have PG_slab set, to avoid freeing
> @@ -657,7 +657,7 @@ static bool kfence_init_pool_late(void)
>         /* Same as above. */
>         free_size = KFENCE_POOL_SIZE - (addr - (unsigned long)__kfence_pool);
>  #ifdef CONFIG_CONTIG_ALLOC
> -       free_contig_range(page_to_pfn(virt_to_page(addr)), free_size / PAGE_SIZE);
> +       free_contig_range(page_to_pfn(virt_to_page((void *)addr)), free_size / PAGE_SIZE);
>  #else
>         free_pages_exact((void *)addr, free_size);
>  #endif
> --
> 2.36.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMWfERo-jF772e9XM%3D8GxhdYODsHrmg5xQ56aw_1OD7tw%40mail.gmail.com.
