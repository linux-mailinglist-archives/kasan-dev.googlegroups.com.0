Return-Path: <kasan-dev+bncBCCMH5WKTMGRBJH4V76QKGQELTGTZNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id EAE2C2AF46A
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 16:07:17 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id f8sf1527603ilj.18
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 07:07:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605107236; cv=pass;
        d=google.com; s=arc-20160816;
        b=wKQSlNDOaZDDQ4M049bTVBgfhdnDuLFr2Q+Puip5Qyn2B457dcXV3wqI8akbwR5DZM
         mVcvCA/NSPxPY3Rd6AxOPoWg3qxlKnyqhaFhujXmEGTkCKSuR60M8p4WwI3Vd5VxBqJO
         b12Mc/JDrYtqNfQFX4u2rq88j2fmuq0f6fJ1Ubef+4luVpQb4R/nx1udsN6zbxEYe1mF
         r65OkjQZseii/rILK+RCXJVPWJwwy5/vFjIs0yyyr83X+jqL29ZIfFDUeq+xweM+KCt2
         WSqL0zl9IfwObC/sko9yQ0XfwRQlsw80mbYsaUc2Gsgh1dFCeuCvFltv0YVkqK32GT5P
         Tw9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2xcJdiL9VoLj+3HBlAgqmRpQX7djbVMw7tjTZH8jBuQ=;
        b=Fd0g6WQbIHmajBd32Cr1ly0nMgtRmp2DtLWO8F2+OWMuVyrAlbKWPfsjcRTGahYSC1
         qpja5rrqWxcl34y1RR6Nw63ZvDxT9s/S5+KSaNEBK0UFRuJHnvkj+SnPa4i1XwY1S13K
         4WUFy1zlU14xRgY8h6ImgrvyfTJE+Epb83YLbz1B3iGcv2jAiPb3x3kFunlGokHUl4ZH
         mcihW5zfUrBCnTK9aBIHWPOHrwTvQJw50wxZF1ilEYlAmraGpHgL2oHff0nDYY7ExWtw
         VcmHUmHWKCasxTVyQT6i01kUo8GCq5F/k60a9uSPjY5ufsf3LkIOF5eX3wL92UO5pk/U
         Sv+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hqeRokbo;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=2xcJdiL9VoLj+3HBlAgqmRpQX7djbVMw7tjTZH8jBuQ=;
        b=f5TttVhULgIf+dR69+kpu2l6jidfsdmOzpfZNetWPn4v7JrDGS2aEA9eVTlRNr2XlT
         bdxVvZqHjiukjI0dorw06q320vX7isQVtBbMRif1HiQXoDq17wrzudvr+sP4ZRwjfMhg
         qXrzPXHMqnT2OIzHxK+vdSJCUtC2b3xGyAjHcMcdtnOQiU5JFa4jQKZqDCUCbXECt9p8
         oBBNzCRq65DK3reuCQVw6jQUeYLUpMrSnZ65MAGQpPCRj6Qr1Yszd5AwESeF7XPM2yQn
         9HMexM8w0P9xPF5Xv25+qVkpcnkoGXDGfi8BFwA75VftFicLvdQgX9Du0OFFBOX9jbv/
         z9lQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2xcJdiL9VoLj+3HBlAgqmRpQX7djbVMw7tjTZH8jBuQ=;
        b=c6RFiCrIQoQDnhoOezNGRWMab56SNSfyZejzQpWJEvT8TqlQcivgzjUYDdS8BTx/4M
         5zazUft4fYMjd+hJEhuaVsZvt+Hv480SYuoCZPLwFJugQFdKzAijNUrXH3Yd46Vt614H
         xRA6kqGB7WRPnqAolBsDguac5yHpoHX5MZTZ71w7VfhPdsNyCmztVBOJqqYl3b0S8Rht
         0YaJU8XU+dajjfnYuXjaSi/QlJlAGSBOYiMnvn45fc31tjabyEShKv59f0J47bvRbnTb
         wIQVamH1WbDMS0ofF/PGSjH933WpYyFSrDSgkbuQwO9wxNWrMjYgFJBA+58BH2uGy2k4
         5qug==
X-Gm-Message-State: AOAM531qzgSyIwBNcW2JCDgBcLCz+WMEfnVXqElKrOs3B4VgZiNTUYgG
	AzAT4m2ELEG0JemeLVI38us=
X-Google-Smtp-Source: ABdhPJwpS1HnDaQ9F8foco9W88dIu+1quUIF9BKYRmihwJMSpUlAIVyP6vps0PUgq7AGDrTxXFFtTQ==
X-Received: by 2002:a6b:c047:: with SMTP id q68mr14555742iof.189.1605107236441;
        Wed, 11 Nov 2020 07:07:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:10a:: with SMTP id t10ls19083ilm.10.gmail; Wed, 11
 Nov 2020 07:07:16 -0800 (PST)
X-Received: by 2002:a05:6e02:106c:: with SMTP id q12mr19792135ilj.81.1605107236065;
        Wed, 11 Nov 2020 07:07:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605107236; cv=none;
        d=google.com; s=arc-20160816;
        b=jdq9L0yLiVFBOHd6xeb1zUKwxWuk145NYOjFkrh5iBF7/9JADSOzcDenIy42Kpczn9
         og9gSvHl80Gkmvq3bXnNj5wMbcvJDUz7V12tTIDcM8+4uExpS5I58MEZICsfQH1nv7gB
         cj8wB6DzckBaYIefSPcXTt7FgZ6GALq6GA5tCnH0HL8rxGXJNvKdCAp5cSllZ+/2zMxp
         BYnJjLWaouHXGYasMD3SQnYFpDuYd3qs+vN/ODCCkkHV7gEOPtwXgW+F5r1dE/HGYnj6
         Cg2a4jln2JJlUjilFvCvMGCzyGll5o0HB3zdj0tafaWsY+d1FC9LqHKMaxhJ064l5jWr
         4gyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=O5pvpxuaPFHh8IqCLJNTeWU2Zvn2pUlMlw4POTGBASw=;
        b=0cMXmWYpNXA4KNMoQgfZjUtS5mCXjLSIvxZTGzPgsOSlmoYfqM5bN7F1cvquIRkx2i
         WY2K/+4SwWz5fm95fBn/fAzd27Pj8EmITb3rACDdotxuqm36/tESZRKZdTqZQCpa9W6s
         LuziWv+dWVjBVXglIwtYthV/JHWKJLQZzNNIJ5XewM/13mTB0xAcSlK/saztFiZHLxS+
         Ns9U/F6CB4CO7bXsUgy5sV7ByFEs6gpVHPySvL0eYk+NggJkjU/ZS/AA+7DPRej/71zk
         pso7OY3CdfMxmVf54RF/Zbst5+f48mx5swG5q5HKlm54S5j5navvowgsydTM7scTquM3
         NYxw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hqeRokbo;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id i18si128187ils.5.2020.11.11.07.07.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 07:07:16 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id n132so1942888qke.1
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 07:07:16 -0800 (PST)
X-Received: by 2002:a37:bf04:: with SMTP id p4mr26492170qkf.326.1605107235287;
 Wed, 11 Nov 2020 07:07:15 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <47785f5259ba9ed493d2ac94ec7c2492fa5c1f14.1605046192.git.andreyknvl@google.com>
In-Reply-To: <47785f5259ba9ed493d2ac94ec7c2492fa5c1f14.1605046192.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Nov 2020 16:07:03 +0100
Message-ID: <CAG_fn=Wn+SaB3c1Xqqr20yS--CB_HRhiPaLfHV1jhF_F0vD_vA@mail.gmail.com>
Subject: Re: [PATCH v9 20/44] kasan: rename print_shadow_for_address to print_memory_metadata
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=hqeRokbo;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::744 as
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

On Tue, Nov 10, 2020 at 11:11 PM Andrey Konovalov <andreyknvl@google.com> w=
rote:
>
> This is a preparatory commit for the upcoming addition of a new hardware
> tag-based (MTE-based) KASAN mode.
>
> Hardware tag-based KASAN won't be using shadow memory, but will reuse
> this function. Rename "shadow" to implementation-neutral "metadata".
>
> No functional changes.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
> ---
> Change-Id: I18397dddbed6bc6d365ddcaf063a83948e1150a5
> ---
>  mm/kasan/report.c | 6 +++---
>  1 file changed, 3 insertions(+), 3 deletions(-)
>
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 2990ca34abaf..5d5733831ad7 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -252,7 +252,7 @@ static int shadow_pointer_offset(const void *row, con=
st void *shadow)
>                 (shadow - row) / SHADOW_BYTES_PER_BLOCK + 1;
>  }
>
> -static void print_shadow_for_address(const void *addr)
> +static void print_memory_metadata(const void *addr)
>  {
>         int i;
>         const void *shadow =3D kasan_mem_to_shadow(addr);
> @@ -338,7 +338,7 @@ void kasan_report_invalid_free(void *object, unsigned=
 long ip)
>         pr_err("\n");
>         print_address_description(object, tag);
>         pr_err("\n");
> -       print_shadow_for_address(object);
> +       print_memory_metadata(object);
>         end_report(&flags);
>  }
>
> @@ -379,7 +379,7 @@ static void __kasan_report(unsigned long addr, size_t=
 size, bool is_write,
>         if (addr_has_metadata(untagged_addr)) {
>                 print_address_description(untagged_addr, get_tag(tagged_a=
ddr));
>                 pr_err("\n");
> -               print_shadow_for_address(info.first_bad_addr);
> +               print_memory_metadata(info.first_bad_addr);
>         } else {
>                 dump_stack();
>         }
> --
> 2.29.2.222.g5d2a92d10f8-goog
>


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
kasan-dev/CAG_fn%3DWn%2BSaB3c1Xqqr20yS--CB_HRhiPaLfHV1jhF_F0vD_vA%40mail.gm=
ail.com.
