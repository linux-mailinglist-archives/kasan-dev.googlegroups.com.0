Return-Path: <kasan-dev+bncBC7OBJGL2MHBBY6G3OFAMGQEE6KUEPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 7FCF041EAF6
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Oct 2021 12:31:01 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id f4-20020a056e0204c400b0022dbd3f8b18sf7161584ils.2
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Oct 2021 03:31:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633084260; cv=pass;
        d=google.com; s=arc-20160816;
        b=JHwgyNVL8M5RVN045i1fzhhvs4eBnHQ25r2b6hAyB8bOqA5frDWhr0SbgEWNqa4D+v
         iHCtqhihV0LMybrPcxPbX+EuPRRl81NIJlBCgnThnOjRvO+FFucFG+NbGMflPmemNoVT
         ECEfZ+95dsqRG8jjcg789ZsrvnG53AVFLTgOBU/jp8LznvajoqQCekmXzj9GeRo8XqfX
         59Rb+VvLfetnutj6IjEzOavSlFZCA2u9+8lOPNU0hfcm1b1MB+EE7WEwR5SfSXNY28H/
         WAIhZVAATSAS7aym3MSvhxmYT7+sNR0N+paTEYFFDa8tuAP4BQzqwL2zkI6CnIjuw3ay
         Vfdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=2PVI+CNUC87tn+kBBpPDTiCES/Fp8mWMHsJxjRYHc30=;
        b=JlSCi5LOCabIrucgpd5I/p5Kv2du2tNkgm3E+txj2pOGpRtJ6HC9Kjctsv5N+/IfmF
         ayvRm0wVtGkiyRVtLsv6O2hNxpE1D9YxpWRg+7KMw7HK27q5L9y2sbU1C5PPCx4HXVie
         YBbikSvST9zRNbAbhvEyDujUSNmCnug1URpTH+riUdXY394yEHZnhxhX0fqX6w01ygbU
         U5XeazmWEPebfCnbw7rPMLWFi1U+JKFDZ8nHg3BT2713h3ACYugNjDHjkAycM4q0MvrY
         gKv0Wvirg3TQACvwia6QrMhivksE/wmIFfd8KI9n3AsSKBTnc4an6eaW9YHn1lXbbSyw
         GN0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PypTI49B;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c30 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2PVI+CNUC87tn+kBBpPDTiCES/Fp8mWMHsJxjRYHc30=;
        b=bu7AmWKgRK/r4os4LSuo45/f4Tf0Z+dmpKyPmfbbaFxRWFQcH3gmbe6WQryDXNF+bx
         hOxTH/7jlW0+7rGeoFbwUMc3rVq4Z0fDn/OauHEfCsXBz3BNSr0v/j7v2sO2gcuKol9B
         qMV1owg5F/iP17YkskQE2xIYdFassnkSsYhfX+oISf5Hw1ypiRqhuvS356zVmKGrYtV0
         yduraXuJYm4HSVw1bY20Evte86W7cO9pR76fYX6qgM34FbZKLeTxD6xRJ5p3iUK9czJ5
         du+1mJ/iPpCtp6c8rH6xpJh9hO0tCiE61Q7CxUKmyZ39fiBUw4hS/9MS9TXbf8AKtu/n
         lCCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2PVI+CNUC87tn+kBBpPDTiCES/Fp8mWMHsJxjRYHc30=;
        b=fqiB8nDVsO5q49s3Y+Z8v56RNnMSzEjNLiXrJWjnMryGdpnlUhpijyPNuo+mOFryP0
         m2WhWmAoLD3w/getvmOOFH3FhcCwxL2OAt+lWaOMUrc6v/sjiQos4/eqasLhIfM1AaNB
         rdgeyJYBnMuuRR79LCIsHglg5f4oXS2a8giaWm3OJnE0kZXMH4F4RLWvcovSU3Ix+YOj
         fvZZAZoADWFis3t2rcfgXu7WtYj9+D4rFI6EEeNyDnbJSOFnPh1OeERJyIXOvz8h2XuQ
         0Hq2UZKs0Y5PFH3IAFcD3Cmu4b/umnnCRaGjsG6VdZpiJ+sw3cFiOhuv+J+BCa0a5yiA
         KrBA==
X-Gm-Message-State: AOAM53156jWeC6XSsTa6sAgAHV4zic3b0jXXhMP38A2g1xe2ktRf3XJw
	JoGW7dCS5fBRoZ29ulnlrJ8=
X-Google-Smtp-Source: ABdhPJy+5OD6o3GQyL0YiKyOT9nEn9Z6c4nUkGUvmTn6SQaFBnZS7RBfwNlQnTkaGgsaGS4DZi9p5w==
X-Received: by 2002:a05:6638:dca:: with SMTP id m10mr9327175jaj.52.1633084259993;
        Fri, 01 Oct 2021 03:30:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:2009:: with SMTP id y9ls1410179iod.2.gmail; Fri, 01
 Oct 2021 03:30:59 -0700 (PDT)
X-Received: by 2002:a6b:8d4a:: with SMTP id p71mr7691482iod.184.1633084259609;
        Fri, 01 Oct 2021 03:30:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633084259; cv=none;
        d=google.com; s=arc-20160816;
        b=Qq1C0T6JSYwCkvM4NVwqSxlrCOvbm+m2yNgrQ0RYsZa83F7mWQq0y5DvWziqmrpJzF
         6b59oc4jp5zYF8w2pz/Xau6X1yEWet9xTwxNpayCL1ka6vkQxw51OYreTvvTMGGyS2jA
         JJU29IisSwagu4N76nwm3phtAA8nKXajsRlW7SoAZ/5J8nFDV128lx7FyK1UBG+lq7bz
         oumqHfBjHcPJwpqH5SB5YKqq1yeQIV6bKNupHQ/5roQScVDaIfQEe8ZQ4B3+eQxMjbxB
         0DT7igchkIBr5QedJ7fpnHqupI+DREI/qqv98uLtdl27T1H17NJUZzi9lcdbbzawE3Np
         1gow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8UnM6fWprDP/p4IMmb85dmfiw4okGcebGCdS4L7uqiY=;
        b=O5JFXfNN62Psr+q814gFXmdkDVwvnUJcGCtqQtbRkdbHBnToi53noR7gPH4AdqK9gd
         gtMIexrTPMRxaPHuJTQZfPEXHJpYHcOKFwfRRg8BycrWH4sY9vbob+UN4SdLMazN8Rqk
         s1e2GMTLpBLmee7GS+2p3wH2spYXSWhoumZMbc3Cf9BYcTGxXIWbCUA76VTXCtk8jyRX
         w5UYZEbnj5jroiB2H7Gjd/No2jEG4nNoaYF4XdEiPIDPLkeLpVK3LfpvddtTO/Inwplk
         +mdS0Y7qXkYm5JcohR4vRUwdb6Od/Ijj8p6hx1Bns72YUzR089mALNrOa0uudDLnU5rW
         0tzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PypTI49B;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c30 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc30.google.com (mail-oo1-xc30.google.com. [2607:f8b0:4864:20::c30])
        by gmr-mx.google.com with ESMTPS id j8si468746ilq.0.2021.10.01.03.30.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Oct 2021 03:30:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c30 as permitted sender) client-ip=2607:f8b0:4864:20::c30;
Received: by mail-oo1-xc30.google.com with SMTP id y16-20020a4ade10000000b002b5dd6f4c8dso2726079oot.12
        for <kasan-dev@googlegroups.com>; Fri, 01 Oct 2021 03:30:59 -0700 (PDT)
X-Received: by 2002:a4a:a6c6:: with SMTP id i6mr8693696oom.73.1633084259052;
 Fri, 01 Oct 2021 03:30:59 -0700 (PDT)
MIME-Version: 1.0
References: <20211001024105.3217339-1-willy@infradead.org>
In-Reply-To: <20211001024105.3217339-1-willy@infradead.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 1 Oct 2021 12:30:47 +0200
Message-ID: <CANpmjNOoFdbGi3vsKtgQ3VVzJb126Gj90txA83C41HHhoy3DOQ@mail.gmail.com>
Subject: Re: [PATCH] kasan: Fix tag for large allocations when using CONFIG_SLAB
To: "Matthew Wilcox (Oracle)" <willy@infradead.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=PypTI49B;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c30 as
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

On Fri, 1 Oct 2021 at 04:42, Matthew Wilcox (Oracle)
<willy@infradead.org> wrote:
> If an object is allocated on a tail page of a multi-page slab, kasan
> will get the wrong tag because page->s_mem is NULL for tail pages.
> I'm not quite sure what the user-visible effect of this might be.
>
> Fixes: 7f94ffbc4c6a ("kasan: add hooks implementation for tag-based mode")
> Signed-off-by: Matthew Wilcox (Oracle) <willy@infradead.org>

Acked-by: Marco Elver <elver@google.com>

Indeed this looks wrong. I don't know how much this code is even
tested, because it depends on CONFIG_KASAN_SW_TAGS && CONFIG_SLAB, and
the cache having a constructor or SLAB_TYPESAFE_BY_RCU. HW_TAGS isn't
affected because it doesn't work with SLAB.

And to run SW_TAGS, one needs an arm64 CPU with TBI. And the instances
of KASAN_SW_TAGS I'm aware of use SLUB.

With eventual availability of Intel LAM, I expect KASAN_SW_TAGS to
become more widely used though, including its SLAB support.

> ---
>  mm/kasan/common.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 2baf121fb8c5..41779ad109cd 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -298,7 +298,7 @@ static inline u8 assign_tag(struct kmem_cache *cache,
>         /* For caches that either have a constructor or SLAB_TYPESAFE_BY_RCU: */
>  #ifdef CONFIG_SLAB
>         /* For SLAB assign tags based on the object index in the freelist. */
> -       return (u8)obj_to_index(cache, virt_to_page(object), (void *)object);
> +       return (u8)obj_to_index(cache, virt_to_head_page(object), (void *)object);
>  #else
>         /*
>          * For SLUB assign a random tag during slab creation, otherwise reuse
> --
> 2.32.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOoFdbGi3vsKtgQ3VVzJb126Gj90txA83C41HHhoy3DOQ%40mail.gmail.com.
