Return-Path: <kasan-dev+bncBCCMH5WKTMGRBDG3Y2DAMGQEITXQ5JY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id E1BB63B003E
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Jun 2021 11:29:49 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id bv6-20020a17090af186b029016fb0e27fe2sf1359285pjb.4
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Jun 2021 02:29:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624354188; cv=pass;
        d=google.com; s=arc-20160816;
        b=fy72GTfYDfHNxgB0NWEZqlEZByj/3t32Q79Z3IZMnkC3ckLj99NfE9OMBBTyYpmvWa
         YHO1Kund1bUGLqb1fY27fOglI/t8Fl3E7qHzsAvEvIY2UtlQKKpt1oojzB0nE2wOif8E
         Sbw4tY5iMhiMMJXDTxhuJBoN85W2Dn0oO9Wqtu0CI0wJr+WCg/eMDx+mi97jM/5K1Bw6
         icwJXNNm9tMA3r3pqjwKxVWGJbfk/Xj9fpRtFilTOwEU7j/R1s1JxsCmBXKCNUhw0RQl
         fIH+b6cSz8CQ5kG5UrNqxdQpYllO1nhcNkb9OkC1zRNdhpRk3NDTgisykKd4Oyp+yt/H
         l6lA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fPJUFNRD8eaYCJcx2af0+F6yntA/WHblabiXyfsCpn0=;
        b=gzkucEsMSW30NAEsduHPCSUhYsULU8Uq3+rXRBuxwSmyN6Ggl5nSC2tVqX0s/GVW3m
         0P+gH9D+rW0FIDqND+i8xPqgM4+QmI2FE/3q884GHt+qgQq90wYUlQo/fYhnkgQoo8IX
         DpAZp8TatsyGhFs8uMzCi60SZUOW2Thix9jDUJwQS8mGB7dg1ZSS9H4yFegbi0O8oy8W
         NefgCtsHPgx61W6GTfv2WXENpo9ImdA8gdfyX1D4v9+WpjqyzeF1Sg93V98xXZpvIcrw
         rL3UUmIXa0IwpWcDHseYXE4G5IZSOAjVR6KvGa3w+CIIRf5qUkrrx6KDkeZ06YDtaTFa
         wf6A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=I8nT0GIC;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::829 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=fPJUFNRD8eaYCJcx2af0+F6yntA/WHblabiXyfsCpn0=;
        b=LzCOrofNNY14zRbuBxKklBh/+QFX8fAB6LaLVl3OrSrSnPN6Z0NsEY9zyKZkAhEqpU
         0xlSX7ZMlWZd/5Ep8s0HZegPpcwxi7Fm9u4fF3cPCnwuQRonvSbWkNiGYwgWDDrcP7Ts
         lvTkAjLdKIs1VjBdk15XSlPwq9LCPwabFprSwyuiD2WGYkybsSWqADk2oUMapEFIflEi
         INi+IlNUAujydtocllabB+YWnevg/PBbR0kE9g/OMshNQs9KIm1VxOXKY3OAiQY11Hk7
         MRdf1nsw4eEWAx3RcTUy4bxkbqSepzmyIawTmB53eww1GaCbSpk6fjYYlcMAXjYGg1KB
         TOIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fPJUFNRD8eaYCJcx2af0+F6yntA/WHblabiXyfsCpn0=;
        b=RzKeLo4b+H/Aq6NgrhGzbkTM66vGCfcVCjE/aYogaGY4pT3dkrAh/Dl4ff38wSZb/G
         g8GVuNt1iBkFuYqmLC/mvqcbk9PVEGRkD2SrC2iupkeU5HSOc8lUsiq51eXK+IzbrI75
         /a/3w5574gXLc5ncz9ehdxyd6xQNun+5f9uarTZd2WfhvAilsvC1jhrDgOnxQO7e1yLz
         MdZaznrvloHuR+cGo8xFjSV8QQRwz7kQcHecpoYWDs2FY8OcbY9AzY3kAPiFHPy/OngT
         rsUrxpwEtevaTjlj4wOtczQCdiw5c0viAsY8stJdiKLWUbWQCUvO1/qchWFtO/qy45nl
         +ojQ==
X-Gm-Message-State: AOAM533Gubuyv9KOcqb4vX8Cqgai2ltrk8noVRYbMjfl/E4KGGt28lG5
	c9IoxAri5YZRKT4phtCukvE=
X-Google-Smtp-Source: ABdhPJw4V5erCAY6N4LUxzcsyyT+kdfmHNfx2oZeZziKICfO15uvtCtuvbGe4dBgCAQB8LLuPBaZZA==
X-Received: by 2002:aa7:9578:0:b029:2e9:dec0:bef4 with SMTP id x24-20020aa795780000b02902e9dec0bef4mr2772848pfq.29.1624354188659;
        Tue, 22 Jun 2021 02:29:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ef16:: with SMTP id k22ls852659pjz.3.gmail; Tue, 22
 Jun 2021 02:29:48 -0700 (PDT)
X-Received: by 2002:a17:90b:3b88:: with SMTP id pc8mr3171985pjb.124.1624354188122;
        Tue, 22 Jun 2021 02:29:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624354188; cv=none;
        d=google.com; s=arc-20160816;
        b=BMpDFVKQljL4enpKgdwKqGBbw2xItfonuqbfKRJcnOlOtKR+FZzPWIHCPQ/sCYgoPg
         ttrYZdCpOWyGal+92vCYW9VuY6K3E6Np8WJWwzFxUdaBLjZ939upGl1553hEwaCbWOn5
         OD7sFMv5dSKfLSAVkqkVN3C4CA5uG2q40HW7jJXiUfJVKgERzbqfu1L09t3owGNmN/j/
         OaqYpjaCgQrJkhrKKwCSi7aUfj2/kCq1+vaK0yTs2D3AZ4h481eky6yfdPsxE5mKO7uo
         T2ObqumqmZD5mMICP3pnWkygOT9lgXHt4SiiOItbts1zjg4zbKlCq2ZT7MVioMbg1rdw
         6KCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=58zdBT4iccY3hk8j5TcU5G4OItRSttrTmPDv2LwwaDM=;
        b=ygBNmk5yHmmeD4S+Ggy42IP0yQqbbhX6tIc21/qU7+mgdWz2ku7wjFA9N74YHgxjDH
         Mrw1wTTa9UZwvP9NO66aAnBC6wPoxVwOE+9YbJ2YikKgzyIpJOnil0wtnEX7siM/GpvY
         ruuLeTLx36FZNGVaVhHWNUoDp6YxJQCmr4iyolaB2P/9diQXAoNxm3SkO5hxm4Uftx/T
         AAH83fG0duqXp5d+OofGcDzARr+Cj1hz4dYGtmkuTr+2+85tFIuSIYlG9Vuef+LgL2fN
         Qggjf3G19trUllz7eEFo8SGpbH4M3GrBmFvePeHmTzUS8WwcF8YcsP4nm2ICyDuS0a0n
         XzCA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=I8nT0GIC;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::829 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x829.google.com (mail-qt1-x829.google.com. [2607:f8b0:4864:20::829])
        by gmr-mx.google.com with ESMTPS id a15si165375pgw.2.2021.06.22.02.29.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 22 Jun 2021 02:29:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::829 as permitted sender) client-ip=2607:f8b0:4864:20::829;
Received: by mail-qt1-x829.google.com with SMTP id z4so15560484qts.4
        for <kasan-dev@googlegroups.com>; Tue, 22 Jun 2021 02:29:48 -0700 (PDT)
X-Received: by 2002:ac8:5dcd:: with SMTP id e13mr2542822qtx.175.1624354187077;
 Tue, 22 Jun 2021 02:29:47 -0700 (PDT)
MIME-Version: 1.0
References: <20210620114756.31304-1-Kuan-Ying.Lee@mediatek.com> <20210620114756.31304-4-Kuan-Ying.Lee@mediatek.com>
In-Reply-To: <20210620114756.31304-4-Kuan-Ying.Lee@mediatek.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 22 Jun 2021 11:29:11 +0200
Message-ID: <CAG_fn=U0_VzgqBtuyB4JnSMRiHg=C85e-m_4X+=QY-o_u-k9Fw@mail.gmail.com>
Subject: Re: [PATCH v3 3/3] kasan: add memory corruption identification
 support for hardware tag-based mode
To: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	linux-mediatek@lists.infradead.org, wsd_upstream <wsd_upstream@mediatek.com>, 
	chinwen.chang@mediatek.com, nicholas.tang@mediatek.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=I8nT0GIC;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::829 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Sun, Jun 20, 2021 at 1:48 PM Kuan-Ying Lee
<Kuan-Ying.Lee@mediatek.com> wrote:
>
> Add memory corruption identification support for hardware tag-based
> mode. We store one old free pointer tag and free backtrace.
>
> Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> Suggested-by: Marco Elver <elver@google.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
Reviewed-by: Alexander Potapenko <glider@google.com>
> ---
>  lib/Kconfig.kasan | 2 +-
>  mm/kasan/kasan.h  | 2 +-
>  2 files changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 6f5d48832139..2cc25792bc2f 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -157,7 +157,7 @@ config KASAN_STACK
>
>  config KASAN_TAGS_IDENTIFY
>         bool "Enable memory corruption identification"
> -       depends on KASAN_SW_TAGS
> +       depends on KASAN_SW_TAGS || KASAN_HW_TAGS
>         help
>           This option enables best-effort identification of bug type
>           (use-after-free or out-of-bounds) at the cost of increased
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index b0fc9a1eb7e3..d6f982b8a84e 100644
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
>
> --
> You received this message because you are subscribed to the Google Groups=
 "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgi=
d/kasan-dev/20210620114756.31304-4-Kuan-Ying.Lee%40mediatek.com.



--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DU0_VzgqBtuyB4JnSMRiHg%3DC85e-m_4X%2B%3DQY-o_u-k9Fw%40mai=
l.gmail.com.
