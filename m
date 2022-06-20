Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMXRYGKQMGQEVQFET7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 27DCA551ACC
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jun 2022 15:40:04 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id v18-20020a05683018d200b0060c0f70134fsf5849053ote.21
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jun 2022 06:40:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655732402; cv=pass;
        d=google.com; s=arc-20160816;
        b=t8o8ykksRroKVjsELYbJdWi6rtkO1MnRF7hMzPkXmZ/Ai0j7N+bvD1QoQE8tmfaRi7
         D8a4HgqL7zQSZAQwf0WqvMkryO7oDRE2+a0Ud41hJlOb1bsPq7c0HYtIHTAc/Nc5n81c
         JQZ0LGnkR6y7kM2Hb07FiI0iKPsfp8bVxkfoH7FZfInXCO59Fi914cOgBZ9/CwoR3ZQ/
         /2N/Ggi7U2N4E+sOAIpSQyQ1zi0deO4CbB6Xc7ZezchVjeD7emwXKQSt7A7c9wCRfERM
         nXA3MNyJysR7gtX4/Wp89EmMiWpS8FAt8fFOwc8fx5ja85zyjU8fB0koL9bPEeT3DKdN
         rg2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=NwmvPAeN7HOhDaDW3OtAXQbHe8WbMeILXD+qiMxw+3k=;
        b=PjpV5fwhsyTpwm5choPYRBGYquEVczVVD2qnCwUF/wn3RNtIncKULCRICGvvdvUl4k
         mqIAt95SJIinPuRkUJVmYzwfxunfps4Ab60/x/FhPPaWw0sgJI/ODSKDJ3gI+GBMwXDi
         My0BT60W+2j3uleXS8TZ1w/AZPsRk1MF8H5RoWYKqy1WkZ2PvTJSH4lieIwNhm9uNE63
         DSg0Ixg2NXScMTIAKr7tyMD/fPwhmYQCWs6mF6jR5mUTDXruLn6HVdfpBLhdCsfQWstd
         BgZEs4Oq6HpSjGtt4auYji7oa68MpJSLbghL+hAghMlQBREPO2RC0GrXNjSV7Vn0X9+B
         1BRw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=oe3RFUCF;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NwmvPAeN7HOhDaDW3OtAXQbHe8WbMeILXD+qiMxw+3k=;
        b=aNDqoG6tV6lf5wiWufeNEj3sjqicJc4i/h7LEo71Qz+fIUQz/09ak+eQ675eehRvOR
         jso/1V8lTiwaqgAQ+n+39wH31Q3+Nn/atiAmX56wWl4y9qcPtm1m2PnA5GtWwqyDNNZq
         jdyMwVj2qS92TcKEulMVgCY6sdArNhMsy7Uvac4slo5V6m6KfI19WAN/ES84tig2NDBs
         wc8IiPlUeHNbzfABH2k0XfhyvPV+p2sU7UVlhA+yxijDlLBtXny1btM8P+JaAhruM/7g
         9J+GuTnm+pHJ7dGdA2Nse53A2zmgaaLKIUhiGWBMh/6PjSKUoeG1spVraHbI/qXc1zEx
         EF9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NwmvPAeN7HOhDaDW3OtAXQbHe8WbMeILXD+qiMxw+3k=;
        b=mznCbMFZ2weMvT5qxmTrYPJlMJOEYA9Ofs4iIXB3ILJMPnPA18/aQ20DeeWN3o+jMU
         sh9c5Cqhu3cB+ZBqmpKtF22zlSP99xXM12GeyDRCklG6FwZNSKeXbGY0xo7mwx4avP9O
         F00doQd7gpB9jCslQhu/smYLtUBQEiAFDuw3N02q028uHHsMJeZdzgZv+I/dg5HaS1be
         ZKZtAXa+I9krthndbGy2H2XQWIu86Dxh2gQM1lvki7aXSLkZHazMPXrNdfUU1RxO/HxB
         v2hp6FwYcVIpQq1klBB/aHVbMZINwBlyvvI73ZKzzBhKGwoI8mb6BZ4WvfzLvOFOZH3p
         ALKw==
X-Gm-Message-State: AJIora9ZrqXWEqyKCuXQU9rRGpmiZESvgyxJTI1XvuhmK0MhNqTtkQfH
	Hs8SEE0bkj5xDe9xbkzzqSQ=
X-Google-Smtp-Source: AGRyM1uwxYBXPYJvb7zAWdnij28U9b+3MWLikC3uYGdxyUyvD1th+suRGSkoJW8c97uCUZamQWUfdg==
X-Received: by 2002:a05:6870:581d:b0:101:dc4f:51 with SMTP id r29-20020a056870581d00b00101dc4f0051mr3585750oap.247.1655732402688;
        Mon, 20 Jun 2022 06:40:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:d683:b0:e5:d244:bf9f with SMTP id
 z3-20020a056870d68300b000e5d244bf9fls4121398oap.5.gmail; Mon, 20 Jun 2022
 06:40:02 -0700 (PDT)
X-Received: by 2002:a05:6870:ea87:b0:101:71d1:600a with SMTP id s7-20020a056870ea8700b0010171d1600amr14668892oap.264.1655732402213;
        Mon, 20 Jun 2022 06:40:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655732402; cv=none;
        d=google.com; s=arc-20160816;
        b=j0wdAvmjOzJOHyNIKRyE9/Q9WqMi5ttT2s53D4zWLitsoZBG/Ui8foech7KuCPIE1l
         wzPRwYyqx5TWebZnnGmHdfbDx2PLf9qeV8kx1+hvIhZf2AE6Irydd1YPnZGwEdiQ12mB
         YPdg43W4dudx16068I2GcQnsCmhGtyKKjiZaWYix4rjlFToUBmpRJhAjwcPfa7Jah1VV
         fLTgZeTxHqNo4wKZ1ghpWki8qnO8OKqY2TaipVMQT/evvjJOXQN6s/GEA7VdLvMmmAfX
         3HbQ+Eb5T+MYoyrG8H1YTEMgSwvXvmLXVROWOrvP4snz1rFV9wXndtB2uDv6IMDtc241
         z3sA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WS4VFRwLCNQ3Gv6onv6Grnwt8jHHc1O3704ajv1HwX8=;
        b=C7iPmjg2Llxzu9odbyfQvqWUDflQ58N/j5aWMLTPX93MLySkd34Cw2N70s3bm7hX/C
         sm6cUkxoepqR7zAoIE6/5PdF4ItWadYxNf6zr0qHOHx3M3Pbm5Qpq232g38wCVSegvt9
         syjIrYXrMrc3TGd2Jpio9QmIFOvJLUVgv6BVlPh6B3Yz0SZmTT6/bzOeERKl/M6gN7s/
         0UNAHFO/UXW0lZPdHj4o8AHywQc/UqPfov0xqzgT8WkvXqaKvh7QYOEELtFf1CsgBccb
         rU+4xG2hT39ZgWelsBrX4PxQy67OWfzaUBF36dUDMKHaJwv4yhmFqUcM8box0eT0b4O8
         Rl4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=oe3RFUCF;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb32.google.com (mail-yb1-xb32.google.com. [2607:f8b0:4864:20::b32])
        by gmr-mx.google.com with ESMTPS id d1-20020a056830044100b0060bade020f3si567464otc.5.2022.06.20.06.40.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Jun 2022 06:40:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) client-ip=2607:f8b0:4864:20::b32;
Received: by mail-yb1-xb32.google.com with SMTP id r3so19025412ybr.6
        for <kasan-dev@googlegroups.com>; Mon, 20 Jun 2022 06:40:02 -0700 (PDT)
X-Received: by 2002:a25:94a:0:b0:668:df94:fdf4 with SMTP id
 u10-20020a25094a000000b00668df94fdf4mr10943765ybm.425.1655732401678; Mon, 20
 Jun 2022 06:40:01 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1655150842.git.andreyknvl@google.com> <91406e5f2a1c0a1fddfc4e7f17df22fda852591c.1655150842.git.andreyknvl@google.com>
In-Reply-To: <91406e5f2a1c0a1fddfc4e7f17df22fda852591c.1655150842.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 20 Jun 2022 15:39:25 +0200
Message-ID: <CANpmjNMB6gJjqXuXBOnDtnEncNoKHcZKxsUU_Mc_y8=KFg=W2g@mail.gmail.com>
Subject: Re: [PATCH 01/32] kasan: check KASAN_NO_FREE_META in __kasan_metadata_size
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=oe3RFUCF;       spf=pass
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

On Mon, 13 Jun 2022 at 22:15, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> __kasan_metadata_size() calculates the size of the redzone for objects
> in a slab cache.
>
> When accounting for presence of kasan_free_meta in the redzone, this
> function only compares free_meta_offset with 0. But free_meta_offset could
> also be equal to KASAN_NO_FREE_META, which indicates that kasan_free_meta
> is not present at all.
>
> Add a comparison with KASAN_NO_FREE_META into __kasan_metadata_size().
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>


> ---
>
> This is a minor fix that only affects slub_debug runs, so it is probably
> not worth backporting.
> ---
>  mm/kasan/common.c | 5 +++--
>  1 file changed, 3 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index c40c0e7b3b5f..968d2365d8c1 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -223,8 +223,9 @@ size_t __kasan_metadata_size(struct kmem_cache *cache)
>                 return 0;
>         return (cache->kasan_info.alloc_meta_offset ?
>                 sizeof(struct kasan_alloc_meta) : 0) +
> -               (cache->kasan_info.free_meta_offset ?
> -               sizeof(struct kasan_free_meta) : 0);
> +               ((cache->kasan_info.free_meta_offset &&
> +                 cache->kasan_info.free_meta_offset != KASAN_NO_FREE_META) ?
> +                sizeof(struct kasan_free_meta) : 0);
>  }
>
>  struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
> --
> 2.25.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/91406e5f2a1c0a1fddfc4e7f17df22fda852591c.1655150842.git.andreyknvl%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMB6gJjqXuXBOnDtnEncNoKHcZKxsUU_Mc_y8%3DKFg%3DW2g%40mail.gmail.com.
