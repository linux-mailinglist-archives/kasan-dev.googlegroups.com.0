Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNOL4WDAMGQEOXT2MUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 165223B58E5
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Jun 2021 08:01:26 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id r2-20020a5b01820000b0290550ec4385cdsf14812643ybl.11
        for <lists+kasan-dev@lfdr.de>; Sun, 27 Jun 2021 23:01:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624860085; cv=pass;
        d=google.com; s=arc-20160816;
        b=kpaiH0dBrJ0LQWKDCispHMuznVSSEIb3LJgDLsWCCblCbPNig1uZ5ScHDaaZiRWEMa
         GSCinZvoUm+RYYlisRe4wcRkYqlyE413nJ/NUwfakKNbqeOfdO0LZFes18oGjT2Pwibh
         vuVWU7Ci8qa70KRNJyF1gJTsvJnebDYqxoD+kvA17KYru5obfc7H+q6IamvOborTM2h/
         S7W0oRDPChrv3AkGbxgcyKUSoFGo7folrm8W2YTGcWovPF6x8DL80XZ5ALMBLWSpAcFC
         MOmKnaUQHFkxftjNxAqFT3x9TidfC6Jnh3Pp3GbPl32SG9GJC8RsgI4gl/1kKnTmaEwm
         Ogiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5Muug0eEQyYV2BYl3g3BK1HgoHW8PTCJuYLeL//ytN8=;
        b=zlfDKPCQ/aBVLTYuZnZNQ/qVUskswCNMDNHbjwr5tN2XD+okqaC+vxQRKPAGIqANwP
         9zEbnEU3M0TL4zMi6O//u/HQerwGZJFnQV24+6IK28jWmj5zNNR0eGYqF4ixM92iEPRa
         4C6PkSSuMtRJDMCDQeRiXI30u+c6ytvG4g4BmahcNI0fpr9dadUCvxhj0Sal+cRLT7P9
         I7oi0O94w4lSz7khyojJP7zrw/LVCQF4nOdkklfpcKKDq5jBT6kj25Dt8U6VxQ7XzeEF
         bSRL41ULpf5EJOf3oQOubH2XpIzYwEmjilxxX20HCX5KB4lIX+H8fodqUOXFLCcnxiQ9
         5DlQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=J8O8csdu;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5Muug0eEQyYV2BYl3g3BK1HgoHW8PTCJuYLeL//ytN8=;
        b=pEoXfaR3AKiaalYO5/eTqxl6Jn+GJiogmoUTY+ACO9C0NzTV7J8OdyzeRhNptnKXaD
         0mZ6LAQFaiQXhXQerx/bueAmEdbRF6u3YgOHICBITtrBbCevqtFqXPet6zDp/7Rpr0XV
         3koZBsmNPfU4Ke+l6yut3LJSSH73bMUAluW3b/IqkRpMqO7q/bl27liud3B6YUtXWtw6
         BWcPpIlqMcjRYloTLJGEg80H6+IUNS54qMPWiYbs9J43HqkZsqortNnfI/EUR946Wt8O
         dXHHTTYkCUYu1zwl33qcRkzuU+4Ks2Cy/DaMPXxmi9xm5gEo4/SxCskJt1MUe1Jvdj1O
         OR8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5Muug0eEQyYV2BYl3g3BK1HgoHW8PTCJuYLeL//ytN8=;
        b=lIonHnbrwm8epVsWSpzHPFPN+L7OvLACA3S/zriYUYNROd74wrBAcJjnnBazmMYs2G
         +HmX31gb2ch/oMsn87FUCFjbnPMSwy/gqICEndteYywV8Jn5Ern40sfFDs1XiCgTtUdB
         L3+IxKbfSymMhcC97nXWmio8G5hdXUXCjXO/kFmbD/mEQzfI26hZZCGuInzTGE1Px3F+
         zXpXXSbQKaP453eds5MmhRnT4NrZmmVb5esKut01N74OUKFbef9tzkgebZ1OZhs2rO7m
         ETZ308xaGmdWeyYo94NbP6WMQO9rsPUZEmqDJdFL/KZLiyOsQrXSz14AnB+6aNP2nU0n
         vmwg==
X-Gm-Message-State: AOAM530xF/yoNacuWIQ0UZytEqbLeh7NRnUTWT5agc9kmb5rAgJXlQpQ
	MYNd4NgFhoP40sncDs6Nb6E=
X-Google-Smtp-Source: ABdhPJwFxW7u9Ccv0Z8F9x3kFMa+2wbZOrWH2POaFmWQBJJA2ijbcCixp8lDe0mk13FVgt6c3yl3Gg==
X-Received: by 2002:a25:25cd:: with SMTP id l196mr9063499ybl.226.1624860085166;
        Sun, 27 Jun 2021 23:01:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5b:305:: with SMTP id j5ls596433ybp.3.gmail; Sun, 27 Jun
 2021 23:01:24 -0700 (PDT)
X-Received: by 2002:a25:6e02:: with SMTP id j2mr30212115ybc.461.1624860084678;
        Sun, 27 Jun 2021 23:01:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624860084; cv=none;
        d=google.com; s=arc-20160816;
        b=mdYFu9G++TExeg+7zSmyETtabeJPpLSAyM3Pnu0oIodD/MMxbTZCN2yGi7/wp2JJpa
         xN/kHNqklzJoItpUqzH+pVIcwWqFf/PAwXgjY/NCnLhoaISLv/bnvEW3rGzv42hvTsQM
         cz2grlEgkdzEsLWpjbAqWVg4U3mbTO9MpNkQtQc3ILEMkpg1/c5t2syLaqEHnp6R88d3
         6BrwmImGG3esag3WRTdARDqo69wwhA/F4X6NMgpzdhUwMPHErx5QECXSvDyN4Zpkj84k
         yQh96Pby1VUtwOfQOVOQKYiIHBux39zO6lGIeY6h7/AfaoytXCcjixGDCRBNly2T7zwj
         l40Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3eoMbUJoUpBqjeLK9yBay7/GW88cz7V1P5CryiYnRUc=;
        b=hz+rJgMVqIIvrbBQVH1L+PwDzUUhYqO5JvZ0Y9rhcbTNByO/Zv4npCLrkPYPRp4j7I
         7E/KoDk8EnXmjxwOt2QJ5PPUdgCJ+sy0rxyI1iCB6Q7rTepiQBiSvEIzlec4+ENtYztX
         jQw0boYTvkaEAMUmIAgz3l9W49uLuBs1WgCI/WStHjQDlEpY9E9yLgmVFQR079P0v8y8
         5GjHoJ7OirBAM824qSbzCfDyN9AU52KTEb3i/8Ai130DRXwgrODtCT0aQnVYuJzesviL
         8hPYNYi37hxby5a7DvNvdTVYHy88XdKXSK/TGYSiLi6WclAXcbf0drQcblv0sQKi2a7U
         5mFA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=J8O8csdu;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x234.google.com (mail-oi1-x234.google.com. [2607:f8b0:4864:20::234])
        by gmr-mx.google.com with ESMTPS id c13si273057ybr.5.2021.06.27.23.01.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 27 Jun 2021 23:01:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) client-ip=2607:f8b0:4864:20::234;
Received: by mail-oi1-x234.google.com with SMTP id o6so6163869oic.9
        for <kasan-dev@googlegroups.com>; Sun, 27 Jun 2021 23:01:24 -0700 (PDT)
X-Received: by 2002:aca:ba06:: with SMTP id k6mr16233354oif.70.1624860084112;
 Sun, 27 Jun 2021 23:01:24 -0700 (PDT)
MIME-Version: 1.0
References: <20210626100931.22794-1-Kuan-Ying.Lee@mediatek.com> <20210626100931.22794-4-Kuan-Ying.Lee@mediatek.com>
In-Reply-To: <20210626100931.22794-4-Kuan-Ying.Lee@mediatek.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 28 Jun 2021 08:00:00 +0200
Message-ID: <CANpmjNMyHQuUF1KwGj7cMgWVL-TifC52uZu54GgtS9SziyuXdg@mail.gmail.com>
Subject: Re: [PATCH v4 3/3] kasan: add memory corruption identification
 support for hardware tag-based mode
To: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-arm-kernel@lists.infradead.org, linux-mediatek@lists.infradead.org, 
	wsd_upstream@mediatek.com, chinwen.chang@mediatek.com, 
	nicholas.tang@mediatek.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=J8O8csdu;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as
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

On Sat, 26 Jun 2021 at 12:09, Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com> wrote:
>
> Add memory corruption identification support for hardware tag-based
> mode. We store one old free pointer tag and free backtrace instead
> of five because hardware tag-based kasan only has 16 different tags.
>
> If we store as many stacks as SW tag-based kasan does(5 stacks),
> there is high probability to find the same tag in the stacks when
> out-of-bound issues happened and we will mistake out-of-bound
> issue for use-after-free.
>
> Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> Suggested-by: Marco Elver <elver@google.com>
> Reviewed-by: Alexander Potapenko <glider@google.com>
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>

Reviewed-by: Marco Elver <elver@google.com>


> ---
>  lib/Kconfig.kasan | 2 +-
>  mm/kasan/kasan.h  | 2 +-
>  2 files changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index fdb4a08dba83..1e2d10f86011 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -169,7 +169,7 @@ config KASAN_STACK
>
>  config KASAN_TAGS_IDENTIFY
>         bool "Enable memory corruption identification"
> -       depends on KASAN_SW_TAGS
> +       depends on KASAN_SW_TAGS || KASAN_HW_TAGS
>         help
>           This option enables best-effort identification of bug type
>           (use-after-free or out-of-bounds) at the cost of increased
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 952df2db7fdd..f58672f6029a 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -153,7 +153,7 @@ struct kasan_track {
>         depot_stack_handle_t stack;
>  };
>
> -#ifdef CONFIG_KASAN_TAGS_IDENTIFY
> +#if defined(CONFIG_KASAN_TAGS_IDENTIFY) && defined(CONFIG_KASAN_SW_TAGS)
>  #define KASAN_NR_FREE_STACKS 5
>  #else
>  #define KASAN_NR_FREE_STACKS 1
> --
> 2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMyHQuUF1KwGj7cMgWVL-TifC52uZu54GgtS9SziyuXdg%40mail.gmail.com.
