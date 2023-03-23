Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNU36CQAMGQEXBYY7ZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C2046C61A0
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Mar 2023 09:28:40 +0100 (CET)
Received: by mail-oo1-xc40.google.com with SMTP id s62-20020a4a5141000000b00537d702c199sf6876253ooa.15
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Mar 2023 01:28:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1679560119; cv=pass;
        d=google.com; s=arc-20160816;
        b=wtcq4DEWVixS29WEGL2Ij35LkcQ8T4WF2LFM1KvmO290vqKvC5n0Xi14brEYxuqIz6
         z/LnbzLdDZkcBsOaRDrDC1xrFeRy+QI/9rO292IodHqVhWI9cegyZDaNmKYR6ICccGQO
         brGOFPbzaWgHrgyudYvfcvHX4XD6P+AELoBme5PdQAhVHMErtCr90B+AEmaf4Urn9Cn3
         obNPlD+nJt0ZPeIuPspvh/81apN+9/Nq19DbcGVK4X6Cva8iASBKBqn28+o7yYm75iPL
         dA98el5uVWwMoqWrAvB51xWwE4lQlOU9iMwMmu8RAP1HZ/AuXhLu82itDqRaes1pXrkd
         zNiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=q52HMgAkCkZt/ShKHrLvT2pERWWHLQrh/9MKkh/7haI=;
        b=N/ukJyJsWJNlF2gEivIDcYw6jlEoNrMn8Fr+YWlVIPfFHBJIIrZV5GH9ZXfFGdLmHb
         U6cWMKVn7m/tHUOrf7UIe20A7HB4yOtWyGaNTklJE8uUdzrg75BGe5z93X2l4bXYVr+1
         tnEFf8Id5U4OrQykxSGgeKvsm7YF0Avf00PZqCXRKn5UUu5WWC+nDKMZT0bdQX/FUTkE
         qnG/oNW6vQxVyOjYulJsAagz3B4A82qWnbVhYYwG7kuvHXRGw3WMTYeORhYxrVBLxKyW
         DxEwIW3SbwPNpPBboBrznJLMhNc2IleCes55Zfm5wA1Ldv1slPe2gPJXCHaxHwUE5ale
         PlEQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kGBFE0Oc;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1679560119;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=q52HMgAkCkZt/ShKHrLvT2pERWWHLQrh/9MKkh/7haI=;
        b=cV0+FWyWMuH+ktvyNdOfc8chELDXDIgoMATF8EWgWq6e4TL4BbNWpciDEZlbNgamnB
         +y7nv/1wn12PsbvszXd+H8gUXRIGizUm9wffBJZ+fuhHS4Uu4Cmr2GRCNXFoSyuoHHC5
         CbzRT6niankzi98CHl8Vc1CnOFQoYz7IUOMjCH1guOqy5wNJ4le2PsmIuo0Z6krpFtnf
         iiZ2+hoqpkHu5sSUoXLfcNKINkCgyT9dO5mWP4BvFMTGUI1jDmiMBlc5Jn7kKpuA37C1
         i77/qmpuf/1FLRp7WKwbyOLWXhzwuGfkjZtYahSp1bDdCqzMH++ln0dVqB9mEuM+d2I8
         Jgow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1679560119;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=q52HMgAkCkZt/ShKHrLvT2pERWWHLQrh/9MKkh/7haI=;
        b=xpMSuoG/AHjlJdBlepE0abUR/AQnGCwDhit5mm31UogpwJ/6rAD3eW8VRI6+ufFzww
         Ho5jUfMTtGTER012kBK2EugU2Ii1KXtl3caRu/1BSRPXWzt1gzL6zevjHG0b3dpn//5M
         RL8PYxZ7xs3EXw395W4wABK/7uOH9wIqsJLiLUSjLvXu3Ivs30ogEPAy3v3xYtvzxFMj
         Kmts8za306pfmaBvm2cDMABB6Yvn5ZETz3N2bDoI6ucmsZ4CspAWzQ30wPoOFKNDQ1uB
         uu3yV418yMydGn5mQ90VQYvXYEGDMkXYoXDbedfpF7MNLHBxQrxUi0Slh6W78XaIKzsG
         9aYQ==
X-Gm-Message-State: AO0yUKWYqZBBVP1iIkEzgcPf3lmxecDWB3JbRrodqBvNax8Irne0eoKX
	4Rth+gn9WONvnz52m4vRtcM=
X-Google-Smtp-Source: AK7set+WwEV02HQfdCypCR1ESR++Ot0Zd/G4vAZ/tE6RQ65XQVvKU86nrVNY93XswiwnPEhyLm7LeA==
X-Received: by 2002:a4a:c914:0:b0:53b:4e0a:6714 with SMTP id v20-20020a4ac914000000b0053b4e0a6714mr2187847ooq.0.1679560118796;
        Thu, 23 Mar 2023 01:28:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:e999:b0:177:b908:1eda with SMTP id
 r25-20020a056870e99900b00177b9081edals7324271oao.1.-pod-prod-gmail; Thu, 23
 Mar 2023 01:28:38 -0700 (PDT)
X-Received: by 2002:a05:6870:460c:b0:177:cb83:4c66 with SMTP id z12-20020a056870460c00b00177cb834c66mr1496079oao.8.1679560118263;
        Thu, 23 Mar 2023 01:28:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1679560118; cv=none;
        d=google.com; s=arc-20160816;
        b=oU/Sq0Zb1Zve8o2nnHLA0Hxxhj6OBEGDHO2bNTImK6tMRf0/V/MoZlpuqglESPayo3
         2eXPHl8CKsdaXgXMO9aOgmXp3GuYrM5UT2NtSflm+nqsUQWPPX9dzpMxp2ZylMhrhb+I
         GCHBfwSVt2GSBWQ54BSVtkjG9LpSRaVEsXAweHPD7sfnBzUws0rEvniiNsq054+oLQEz
         YSES4s2kAwEGFWXROO3nDDDh+WGexLTK5LLm3lBgpqCf3NWDwDhi1N5DFBJLwWM3S/vq
         jvhSGBi7tQYxm2C5TgXaMWAGccHN+Jqh01lcZpHPZNp9Kod4SGli/fpLm7JlL+1CHrEf
         MZ7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OOYn20tiv4eFu0Zo7pcx9dFPpDzH/yyBBrbi1uHVeEQ=;
        b=A02BxauLMHlWTfPomHgxlQ1LWD+6dKtWtYsiIxTOTgTnRmx+HeDP2wK20RHU2NDvX6
         16w9g8G+01qRNHYcGZyn9J5IOVxh9znqs82SGu4LHxk9pxywBI2Dy/t7l2M+w+20103o
         t6rpxy+AfQHGt27IPMXoBQOPfAYoIcbspYoB4WvHmJKxbZm6pEFu9B631b8nXzZkuEZj
         LnsY/O+M85nG97dHGB/wWKZFhMPBW+aG/saJKEGwutk1j2KirOuqBDsFPaCxaoFtecfW
         WqINxnC9c3IpA+W/VQBcLmzy+lm33KpxWYsZdpMyIEZfQDs0+9xqeRdbKy+tmBJ6jwlv
         E6pg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kGBFE0Oc;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb34.google.com (mail-yb1-xb34.google.com. [2607:f8b0:4864:20::b34])
        by gmr-mx.google.com with ESMTPS id lm9-20020a0568703d8900b0017b0d68e731si1194627oab.2.2023.03.23.01.28.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Mar 2023 01:28:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) client-ip=2607:f8b0:4864:20::b34;
Received: by mail-yb1-xb34.google.com with SMTP id j7so23864295ybg.4
        for <kasan-dev@googlegroups.com>; Thu, 23 Mar 2023 01:28:38 -0700 (PDT)
X-Received: by 2002:a25:6dc1:0:b0:b67:4774:7a3e with SMTP id
 i184-20020a256dc1000000b00b6747747a3emr2279910ybc.62.1679560117717; Thu, 23
 Mar 2023 01:28:37 -0700 (PDT)
MIME-Version: 1.0
References: <20230323025003.94447-1-songmuchun@bytedance.com>
In-Reply-To: <20230323025003.94447-1-songmuchun@bytedance.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 23 Mar 2023 09:28:01 +0100
Message-ID: <CANpmjNP+WU4AjmNLMz317ipDKr2BQ-zJrNkJeqqAFiPwcYOs4g@mail.gmail.com>
Subject: Re: [PATCH] mm: kfence: fix handling discontiguous page
To: Muchun Song <songmuchun@bytedance.com>
Cc: glider@google.com, dvyukov@google.com, akpm@linux-foundation.org, 
	jannh@google.com, sjpark@amazon.de, muchun.song@linux.dev, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=kGBFE0Oc;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b34 as
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

On Thu, 23 Mar 2023 at 03:50, 'Muchun Song' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> The struct pages could be discontiguous when the kfence pool is allocated
> via alloc_contig_pages() with CONFIG_SPARSEMEM and !CONFIG_SPARSEMEM_VMEMMAP.
> So, the iteration should use nth_page().
>
> Fixes: 0ce20dd84089 ("mm: add Kernel Electric-Fence infrastructure")
> Signed-off-by: Muchun Song <songmuchun@bytedance.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  mm/kfence/core.c | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index d66092dd187c..1065e0568d05 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -556,7 +556,7 @@ static unsigned long kfence_init_pool(void)
>          * enters __slab_free() slow-path.
>          */
>         for (i = 0; i < KFENCE_POOL_SIZE / PAGE_SIZE; i++) {
> -               struct slab *slab = page_slab(&pages[i]);
> +               struct slab *slab = page_slab(nth_page(pages, i));
>
>                 if (!i || (i % 2))
>                         continue;
> @@ -602,7 +602,7 @@ static unsigned long kfence_init_pool(void)
>
>  reset_slab:
>         for (i = 0; i < KFENCE_POOL_SIZE / PAGE_SIZE; i++) {
> -               struct slab *slab = page_slab(&pages[i]);
> +               struct slab *slab = page_slab(nth_page(pages, i));
>
>                 if (!i || (i % 2))
>                         continue;
> --
> 2.11.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230323025003.94447-1-songmuchun%40bytedance.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP%2BWU4AjmNLMz317ipDKr2BQ-zJrNkJeqqAFiPwcYOs4g%40mail.gmail.com.
