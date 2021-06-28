Return-Path: <kasan-dev+bncBC7OBJGL2MHBB75P5CDAMGQE33FX53A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 268B23B68A1
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Jun 2021 20:42:11 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id a5-20020a056e020e05b02901ef113bb0fcsf145991ilk.16
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Jun 2021 11:42:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624905730; cv=pass;
        d=google.com; s=arc-20160816;
        b=ekBTGaw2gH+IHfeFr7UvjEaAvGlofv41l5SBr6vw6RHRaB7J0bEeapWeeN+182DjfD
         5m7SabUNtUp0VBJpPuIrLZpfoURj9hEqV6aPzAb0zdwSh5snb+aA7xhGoHc5a3NLm2pv
         2jnUjcOluiBPnL0DGCJ+qx9Xmm1Ug0VxKUG3ZyDesfxum4ePM16RHEgqjMJiGbSupazh
         x5m3OiPKrpe9Xjo8z0BQmpwQCoGYyqcaCkvaJzIUZSX+QrtcNyv1MhaUJ6Ro8lfTbDUb
         E9w656490PTZoacL4mAJ1AZzTcF0a9jYmbGTRZiB7ZHuOmMn60PEW0XmrAvgGWtAIe/6
         IN3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=VCTvMr6EYlI4//Z7u5wSrG3I6nNLJd4V4Veepzhvzew=;
        b=GbWmj/5YAarsRrItmmLR6vV2FNwum5ONg/O33bGKvq+hdydV4/VCEHhf5F1SIjZvk3
         UDt9CgtC3pVdsZAoHz6QWE2OxbcqpUpmN77WxOSUti5V46e1zljYcickrCa9gBkRD5vz
         Ck8LcLSH5yUkyAB851a8aK+X0o+ETT5i6vmkytjqOa2ZhsCP8NynoKQRXkA/8XMKkZuK
         U0LZB7qS5Par7AGCfhHOyL2G11UJmOsTiKhinYBsmWL1VvZEmXg6hMryj4A24eIsf5dw
         //0ybtf5i1YsBOckB9VSJ+Cld4Qhy/vkPIxK4QneErSWjUProX4SN6uopJ2To5+6rkXi
         M4Xg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vfK499WW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VCTvMr6EYlI4//Z7u5wSrG3I6nNLJd4V4Veepzhvzew=;
        b=WpSwMz1z9RKJ6uy+V5MCjc2EBaLjLFIrXTPMffcm8/l5CBMzBMxZTyPXr+8Y/IHf16
         NFziqWHC4dpSoWBOUksj5v2AZF+WsfPyLVeDdMg6Dh7p0+owewpjbXvn7ztJKOjBuFJs
         0psItuW7+JqSSfw+617iSUKuQ38clYZPiNyPAVjgbDupdoYBn0MhVxRhQZuuGg+YSz/2
         CQ8Wgwp6lhY/PKpnom4t4l5mRlsbZeoheHczu8KzAKk1cgpH+PdYGvs2wnNNQ6ZMQbju
         PMSyHyiFI2u3Z1YLj6ULG9a9jSjJr3TeWm7GymQNIDyUWd4srO3WffYKhvHJERPtf3Ap
         O1Tw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VCTvMr6EYlI4//Z7u5wSrG3I6nNLJd4V4Veepzhvzew=;
        b=OF3j2hjwYR+gwD3/qvfzVG3CmZbRRnoIhujLbOKZykuyC9+WaGd/wSj9nWGgHhGUw5
         8e1j29iv2vfj8wHWQPGfsHl0evW9khXFHZMPGk3eTGpFoIsIDl6y78gzUKQLaBI2RsgX
         EBgoZbNm63bpwrEmDLC07CxuRWrY3/xGVadHGX5myGyMMb+IRmwX29tMjYDXQ9evPfeX
         rYzCNqP0ul2VKFfoJglXgab8paAzU5ElClQZcpy6FZ6O/WjZ1Avv1BCN1mGFCWfUzjN3
         awLkWjl0v7yGXaG4GmRpGJS4QqsmWWlbGnf1X+7EOoxboPCul1OKJlPYw2QL8zA7xdE3
         yzwA==
X-Gm-Message-State: AOAM532zkUC+Zmwgf5OoZn1d+c+HfvGcsPM9fkJfE7dRlb6a8B96eE0T
	cb+LRxUNzUpMfDWHfSTT1b4=
X-Google-Smtp-Source: ABdhPJwGaOHD7Lv2g+sin9LftYoRqS5bd824jiBCcz0Z5b1paJg+wnAwedzXSgskUKv2HE9oVr+lnA==
X-Received: by 2002:a5d:8154:: with SMTP id f20mr679334ioo.89.1624905727991;
        Mon, 28 Jun 2021 11:42:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:670d:: with SMTP id b13ls2078039ilc.0.gmail; Mon, 28 Jun
 2021 11:42:07 -0700 (PDT)
X-Received: by 2002:a05:6e02:10c3:: with SMTP id s3mr19005610ilj.37.1624905727577;
        Mon, 28 Jun 2021 11:42:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624905727; cv=none;
        d=google.com; s=arc-20160816;
        b=e6W3eQ2KlBbvARBecVubp5uP2OwsTV+LRt2HO2ffXeMGGU0P0iUUBkbTeJXdyV4wcv
         r3qNYpnQ2nTEzLsoRcu0WeVkU5irhbzLoRh4DXIuwcRsSZUq1W+AH21BcGBDPbGyoiGq
         blYj5JMbF3tf+twAJNsrNbI93Ex9hbP7xQ0W0No0XQwPU80WTgAmHTWPFcWI8flEhXN1
         nhRWkIGsjXA9MnZX+6FVbYxdTapKtDnm68InxnN9dVSEaAKoP0ls38HgwC/HivuGpj5q
         P1MDB8zjG4m7Q/x84WbJRX3hgHMs0P0h/NjK5q00H4a+7bAXAyM+1r0NZVvd97+ZF4aF
         TVKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hGZGjPN7zJUyktr/g4knlZGNk67FduIZ8wWgBMyrHK8=;
        b=q9h2Vzb9cioBj1kDEpJd2rGvdMucrTqGVf3T+ZJqxgD4XbSt9ENB7BUGvqYnMsK+Fh
         iq52rBP6xEZKpLwAtvi8Z4tut/XcqQ5GS/WGK2UyAAQwMzXfPIAzCkZgAKd2/8cX0wb9
         YtzvdJYe0ryDDy70LuW/LzixqJ0XTNIfaAzkXA+52rjzHnVwWd7DuSEUF5qZeC8GEwFI
         cKf67dh3p2AXyuT9WBmYqaBmrR4jLo6TwFBc0hNUhcyNcXglX44d3EgRf0p3Ty9mGHO6
         N1bmSiag7FDCh9vc0upesoCMWTJFKm1YNxjnjl83ytsUDIs3DKns3a9cUFtbF7M++Hut
         WL1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vfK499WW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22a.google.com (mail-oi1-x22a.google.com. [2607:f8b0:4864:20::22a])
        by gmr-mx.google.com with ESMTPS id i12si1069205iog.2.2021.06.28.11.42.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Jun 2021 11:42:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22a as permitted sender) client-ip=2607:f8b0:4864:20::22a;
Received: by mail-oi1-x22a.google.com with SMTP id t3so160512oic.5
        for <kasan-dev@googlegroups.com>; Mon, 28 Jun 2021 11:42:07 -0700 (PDT)
X-Received: by 2002:a05:6808:7c8:: with SMTP id f8mr6642152oij.121.1624905726971;
 Mon, 28 Jun 2021 11:42:06 -0700 (PDT)
MIME-Version: 1.0
References: <20210624112624.31215-1-yee.lee@mediatek.com> <20210624112624.31215-2-yee.lee@mediatek.com>
In-Reply-To: <20210624112624.31215-2-yee.lee@mediatek.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 28 Jun 2021 20:41:55 +0200
Message-ID: <CANpmjNPSh4NephPOm08H_etX_FbDAebowE4rW3VJK_Fgb9auHw@mail.gmail.com>
Subject: Re: [PATCH v2 1/1] kasan: Add memzero init for unaligned size under
 SLUB debug
To: yee.lee@mediatek.com
Cc: andreyknvl@gmail.com, wsd_upstream@mediatek.com, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Matthias Brugger <matthias.bgg@gmail.com>, "open list:KASAN" <kasan-dev@googlegroups.com>, 
	"open list:MEMORY MANAGEMENT" <linux-mm@kvack.org>, open list <linux-kernel@vger.kernel.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-arm-kernel@lists.infradead.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-mediatek@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vfK499WW;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22a as
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

On Thu, 24 Jun 2021 at 13:27, <yee.lee@mediatek.com> wrote:
>
> From: Yee Lee <yee.lee@mediatek.com>
>
> Issue: when SLUB debug is on, hwtag kasan_unpoison() would overwrite
> the redzone of object with unaligned size.
>
> An additional memzero_explicit() path is added to replacing init by
> hwtag instruction for those unaligned size at SLUB debug mode.
>
> Signed-off-by: Yee Lee <yee.lee@mediatek.com>
> ---
>  mm/kasan/kasan.h | 6 ++++++
>  1 file changed, 6 insertions(+)
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 8f450bc28045..d1054f35838f 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -387,6 +387,12 @@ static inline void kasan_unpoison(const void *addr, size_t size, bool init)
>
>         if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
>                 return;
> +#if IS_ENABLED(CONFIG_SLUB_DEBUG)

Avoid the #if. I think none of the stuff referenced here is only
available if CONFIG_SLUB_DEBUG. In that case, please just write:

if (IS_ENABLED(CONFIG_SLUB_DEBUG) && init && .........) {

The compiler will correctly optimize out the branch if the config
option is not enabled. But the benefit is we compile-test this code
with all configs.

> +       if (init && ((unsigned long)size & KASAN_GRANULE_MASK)) {
> +               init = false;
> +               memzero_explicit((void *)addr, size);
> +       }
> +#endif

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPSh4NephPOm08H_etX_FbDAebowE4rW3VJK_Fgb9auHw%40mail.gmail.com.
