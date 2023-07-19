Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIMC36SQMGQEBYURNFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D6FB75937D
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jul 2023 12:55:30 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id 4fb4d7f45d1cf-51dd0857366sf30204a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jul 2023 03:55:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689764130; cv=pass;
        d=google.com; s=arc-20160816;
        b=ighx6tWoUg3JpuIcN6IE3FBuigYQ2baHXUvcJlbsaKzOng6lfk83Om7TtisuqlyQM3
         582RZUM4gqHlBopb5SAsRQQ5JKlPikyVuxc0kP801PyN623qMlms5c+t5rUR3t1Ss2gy
         EOiJuLINiR4gf4V5Oof4U/8tzMOHpzxzrabHuDZs284rySwaLNmVjhsv7agsGo/pKxmL
         VK/v0LLy7UpJANkL44XFip9IoljtfrBvYZmJMcHbB6jCmiOUxzsYGsvQZQrAq2JzFIPa
         LfXXKqfI3l20GFYyU59ypk7KkgzXPf2z1cms/B04iq8rT9RiO/VkTZoHle5ocHpjqPrC
         WPtA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=TgTgTMMIjS8lmd0Yk/uYS6nwIBUTvyuqkNDLDi8euHs=;
        fh=ekILNjgjBQugiynVRxVxmFC3qj1BBouL+1SU2EbljSU=;
        b=x8Vbq4+ya73NF+/MhirXvTVDwXpd2AUWFPGloZefAbuqE91e+AmU38q4nA9Da+WrHJ
         PDDaD1ImZzk8/ErtlUchpdVct54YVruEJaM7bcNIoYughzSbrjogBXVqlq+6Pv8zPQWf
         W70S/cQ6zEOrUElPe99yvtsuEpZdiY98dprkfPOHXAjPA2m7tma1sPisabdxE2B/7PcV
         LKOm/I6TZ5iOrwcFySvrAHnZQU2lzFba3I0nanDbKcMvO7DTVt9fRdGu9bhMTUNt25dU
         1HSqsyr52G/Jdr8/cua6TNFd11E/Ng+He1E4oGME/yCgAFDDS4JuVtTuQpW11RPy3lH8
         iG+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=ZiKC0YFs;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689764130; x=1692356130;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=TgTgTMMIjS8lmd0Yk/uYS6nwIBUTvyuqkNDLDi8euHs=;
        b=ecyizQjZ97+wKDkEK3mJZ3tuw0k5rb0loGyVRBB9rCdj6tH/GWkFWevnYvJ+wtdEw6
         gN+tUNkc3cHJbPGZUArQTLkIR9JWJML/p3H0lI2XFKKeIC7ksI37xY0MzSyLbBZrp4CN
         5gwrdZNsZQ9S++ko/4Oz9Rf7cTmrsFIr4ohDvQnz5d88gNA2soo10luQw/6w06PNitNC
         d5oRbl7a3LXZadHlsdxQOyc/DR1djmnxmiujbg00u21YLJYjnH/25h2Skyjz329TUYj8
         nMekgaQuRGaC8hpFmfCzgb0qYqT84v7KPmHJqSKM1+F9UsL7ygvrSEAwUsZRUJuzARjI
         iJcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689764130; x=1692356130;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TgTgTMMIjS8lmd0Yk/uYS6nwIBUTvyuqkNDLDi8euHs=;
        b=B36R3S6tPV5R+0CdE96LqU57Zm7+C+rZYVAH9MzDUV9v2WTcLxHSNYCn9eCVKyE60n
         OG8DNr+t1LeUtl6ffWrvx+xq6rylPty6YHnAN5Q/gNBWKo4rMQl4sQWHeiQutzFiBvRp
         xATVX+s+aYQXKCUX9p/uEP/RdWP9uDls7BOkSn4nLrurau2lM69YmGcaFm6V62v3wKY7
         84uJFiPFPf1d2xJ2ilMdfhU/boBvMzWlqNRDyDAFxmdvdYBu8c5hvCv/VH4tCaQLyo7x
         wTxybYS8dz080BIjtxxJbIIAHgkKsvJ5R67WRo7rGacp0b7Xv1Qp6+OIkQuchOGhF2uf
         5qdg==
X-Gm-Message-State: ABy/qLad4J57ekYTD/BIT4XQ8ttWXNT+XOFk60IHtN7nWoYWd3TaGL6G
	jWcU+dvrJxPtZKhzB1WZjNc=
X-Google-Smtp-Source: APBJJlHu/qsNdLe0FQV994a7Xl1qDyUlM0K7txm0NiCo3mPAo0PHWF2lSsI/4ZCkAxmGwLpmUEKNow==
X-Received: by 2002:a50:d752:0:b0:519:7d2:e256 with SMTP id i18-20020a50d752000000b0051907d2e256mr270599edj.0.1689764129266;
        Wed, 19 Jul 2023 03:55:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:da0a:0:b0:521:caf2:66 with SMTP id r10-20020aa7da0a000000b00521caf20066ls98610eds.0.-pod-prod-06-eu;
 Wed, 19 Jul 2023 03:55:27 -0700 (PDT)
X-Received: by 2002:a17:906:30cd:b0:992:462d:e2af with SMTP id b13-20020a17090630cd00b00992462de2afmr2044672ejb.75.1689764127329;
        Wed, 19 Jul 2023 03:55:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689764127; cv=none;
        d=google.com; s=arc-20160816;
        b=rohtR4+ayzrDXK2rV5rVsQkhlzIYI5IuDwDTzGVTPxTE5yrPFLgIsaYNrVYNTszFem
         Gz5M0jEsI9FjiBIocHbkiB4uCdVGe0XlW/FUGMFjZRdSKs0Mpx25QzEw9XAa5WMkRgyE
         1yKusLhsK0kfj1OGQbnZGzwhcykABs/Zr1kGXfmyskWLZrnFd0wuZZ9dyznYlCYolC2Q
         AnYk9bRRxOWzqI76UlB2j9z7oYOuDsJFbmyqvwjixBhpX6jfoSm4XqSu7XUV0O84XHHj
         XHF1L6HqgowvlcJYURClpF/gKOsZ+BvvWvXUDjr444GlnYC4jnv8WCYKj1VvuEl61N3I
         1N5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=crS3CSY6szxFlGqC0R3v++4ayIAdFFaeNUOCZ6hKf28=;
        fh=tzhR3Hdt90ZhegiVfzc2fgIdxIbsAlWcRG8QMZ3d8fs=;
        b=hnTtSfVXq/xP2GOzlWWvIAP6PtcbpUHVe52iC7ijRwnso2as5+/R25pWmOVIaL/OkY
         2skVneMWaUvGcTicf5TrAEBGROtxPcjaACQ000z/90mq75kI90ebnAqvidxH0ZsTLEup
         zl0ud7K/bbE+jxSEH2b2izXBUnX8htUPuCATNQp1gcdEs6jbspWPc84xpk3hBQqeFFVP
         PE/vDvuKUR2BKSKbiFoUEy/s7nhQlqOKoZiDQdJ5rTlkaLpuhRZwmVkkpEEjlrXTyzqB
         LnTw6ODy3qdCEvfuswR/xp3/y01bdsABOEMEkkPmEIuXYmw36CwmKx1LN/xobkcE8Isc
         h/cA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=ZiKC0YFs;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x129.google.com (mail-lf1-x129.google.com. [2a00:1450:4864:20::129])
        by gmr-mx.google.com with ESMTPS id fn5-20020a1709069d0500b0099980cf4f64si118249ejc.0.2023.07.19.03.55.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Jul 2023 03:55:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::129 as permitted sender) client-ip=2a00:1450:4864:20::129;
Received: by mail-lf1-x129.google.com with SMTP id 2adb3069b0e04-4fbbfaacfc1so11165477e87.1
        for <kasan-dev@googlegroups.com>; Wed, 19 Jul 2023 03:55:27 -0700 (PDT)
X-Received: by 2002:ac2:4e8e:0:b0:4f8:b349:6938 with SMTP id
 o14-20020ac24e8e000000b004f8b3496938mr10924928lfr.65.1689764126796; Wed, 19
 Jul 2023 03:55:26 -0700 (PDT)
MIME-Version: 1.0
References: <20230719082732.2189747-1-lienze@kylinos.cn> <20230719082732.2189747-4-lienze@kylinos.cn>
In-Reply-To: <20230719082732.2189747-4-lienze@kylinos.cn>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 19 Jul 2023 12:54:49 +0200
Message-ID: <CANpmjNOHL8EMP+E9w5wxMJ+PUbxYZh2DMaEocfHP1ATQn64+ng@mail.gmail.com>
Subject: Re: [PATCH 3/4] KFENCE: Deferring the assignment of the local
 variable addr
To: Enze Li <lienze@kylinos.cn>
Cc: chenhuacai@kernel.org, kernel@xen0n.name, loongarch@lists.linux.dev, 
	glider@google.com, akpm@linux-foundation.org, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, zhangqing@loongson.cn, yangtiezhu@loongson.cn, 
	dvyukov@google.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=ZiKC0YFs;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::129 as
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

On Wed, 19 Jul 2023 at 10:28, Enze Li <lienze@kylinos.cn> wrote:
>
> The LoongArch architecture is different from other architectures.
> It needs to update __kfence_pool during arch_kfence_init_pool.
>
> This patch modifies the assignment location of the local variable addr
> in the kfence_init_pool function to support the case of updating
> __kfence_pool in arch_kfence_init_pool.
>
> Signed-off-by: Enze Li <lienze@kylinos.cn>

I think it's fair to allow this use case.

However, please make sure that when your arch_kfence_init_pool()
fails, it is still possible to free the memblock allocated memory
properly.

Acked-by: Marco Elver <elver@google.com>

> ---
>  mm/kfence/core.c | 5 +++--
>  1 file changed, 3 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index dad3c0eb70a0..e124ffff489f 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -566,13 +566,14 @@ static void rcu_guarded_free(struct rcu_head *h)
>   */
>  static unsigned long kfence_init_pool(void)
>  {
> -       unsigned long addr = (unsigned long)__kfence_pool;
> +       unsigned long addr;
>         struct page *pages;
>         int i;
>
>         if (!arch_kfence_init_pool())
> -               return addr;
> +               return (unsigned long)__kfence_pool;
>
> +       addr = (unsigned long)__kfence_pool;
>         pages = virt_to_page(__kfence_pool);
>
>         /*
> --
> 2.34.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOHL8EMP%2BE9w5wxMJ%2BPUbxYZh2DMaEocfHP1ATQn64%2Bng%40mail.gmail.com.
