Return-Path: <kasan-dev+bncBCMIZB7QWENRBW5O4D6AKGQEEYAGASQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 6723B29AC76
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 13:49:32 +0100 (CET)
Received: by mail-ot1-x337.google.com with SMTP id q8sf314816otk.6
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 05:49:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603802971; cv=pass;
        d=google.com; s=arc-20160816;
        b=qo+Fftb8rRgqDfWMPrVnnwofd4HEJB4fggkXOWhRYLJ+Cl1G/SZvRPVWZRHDViu4V7
         b2eBvKru+SICi4neiEKBNm/G9R0fsnFehiUhlddm777KuShVa+2YkrYVwhZUh9HjNSy+
         CKNIHyWobSo5eFxhbLAar0AQzkzNjz8wMEFr8gu7dMWaM2obBeIuKQIGBv4sIJR6Tz4R
         TGxJZ2bmUjMxxP4+v/sBgd1+nA/ZUSX2JFpt9MjyQ3I1hM+qdUUQp0SFIIjCgSayATqv
         sQoPoYIh2HlI3ylSdHVQfbmqEPn8VaezQLLd26kz58kYT01jgo0QcEpJOez0ZRPA9MtS
         Xa1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=0LJ96v1L0Wm2suQbr88d8iCEEtBgtiJTouPDpm6c4ls=;
        b=kQebDJkLR5nc2GRpwG4hkzWqLyyd9nQ1maYJ0yNrTbjxXOBbKnfrAGU+WZS9eus1RY
         DCw2MQGBOPSsHaoNO3QDcZeguXN8CUpbLRHr98cN5CofAW79qiaMNUFsYYGamOFVJlFF
         9V0mq3jbRy6bktjMp5XftFFQYT5iSS2cuWf3Vlk8xsPnd+NHeClv5tBjPw42NEkq1ck8
         pCmhdut3pNtT7Jti6IjN9k5aHrlWZ8vHIzndRPW2x8zBGOjvwRQMpDUCpne8XeDCoGpn
         5t4p7jt2Kvk/3BOMjF5z5kc5DJpy/uyfBlCTr6OzgBUaBE7KEt2E9sueocUvaMgzmbwI
         hp/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MHrMfR8g;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0LJ96v1L0Wm2suQbr88d8iCEEtBgtiJTouPDpm6c4ls=;
        b=b3K3Xg4kW1I3KuNyEuIaKos7S8wnV5wmq3Fv8zGhRH3lKKJbmRPYIeG/DVKHRh2n6t
         98aYh/vgXk6iOLXP2QeAcTft28sIp4lMqOosvBatLYa4II1IUueADptkWRoxn/22gqrr
         /dQl4SrnoAVc6dYiNxmA1BrJkkCB1aQf8zndSlQHOA0PgbWRTgVsBKqABDYuXk+r0wk3
         9gcOAsHfDTmB6TjMvpp6ICyEqQ1bXJU+Q/gOT4uG0jrME1ZljGK5HsVKzObOzj2t5FSF
         0LEjlWUV7Nj23ygyeez1XLVhrshGUao9Vyyc4fs2JNKkBNbp1IQjHGu1XHThC8wp37q8
         Vu2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0LJ96v1L0Wm2suQbr88d8iCEEtBgtiJTouPDpm6c4ls=;
        b=GTV4kov0rUVV5qOhvBkTyjtjSGasU7s7UhQXUpPNZXYsq5iTOs0ROtkiw3BwibKYAA
         NWzrE0sieihDdjEdkNClNUpVoE3wNk+H7KURm9wUz1Qm9OREuc2l906speR2ZPuXEmoC
         keAFrLiZGIH23Z0MGmAwsLNKLYUUp/FlVZAnIXeQOPgITU+nUvcYEeAc5SGQqo9RdlnF
         +LLVOJ0tWPU7hrA+ISJ0qi2+qK97eywz7AzuuKpnmsZ/XxXezpS182P1UfbLuc1Q4bAq
         p14WeBhCiNaopIf85jD5WKdIziQdXY/rbPg6rlFT03Vj1IqAbH2kCJYrsvNQlx43VVV1
         uBXQ==
X-Gm-Message-State: AOAM531gIPIUemA6yWYxZsK9AjaPEl6s00/3i5QHvH40YzquU55V9CHV
	UpKhUA/I8exveTIzWh1FenA=
X-Google-Smtp-Source: ABdhPJwnrpk1Mq2zpUM+zxCi/118pVrRzJlg8qUhEjEZGyxg6/OWcohegeqNFXPgnEVY4Og5sRF0Zg==
X-Received: by 2002:aca:b509:: with SMTP id e9mr1268881oif.51.1603802971382;
        Tue, 27 Oct 2020 05:49:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a54:4198:: with SMTP id 24ls376604oiy.10.gmail; Tue, 27 Oct
 2020 05:49:31 -0700 (PDT)
X-Received: by 2002:aca:4f55:: with SMTP id d82mr1339589oib.172.1603802971079;
        Tue, 27 Oct 2020 05:49:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603802971; cv=none;
        d=google.com; s=arc-20160816;
        b=AjIkHLwReJRzNhP1Y4/+kZVWGMsGaPjlHXLuoucvDVUN8WVqLIQVAcnEkMxGxg3JYZ
         l5Rg+0cvv6GoK8yoSfLXBoHzEsIym1+/x2Sryf2jtcw14v7jjc4mcHiujSloKfl/rMED
         7noZhCREhy9uMeLKMuOVW6oHnacupTD6MxPAh6C1rA8UZofOrOEsTK7GUxlQHbkN+Z+V
         BMB0YYwMW2mskzUhGkpYEUo8JlYyluovyRu3FMbcPvY4BH369EbgmUILJyD7t2/DabaB
         Lx5PBg2bYh2/46z4COgYRuy8uSzqYBji3hIsx08MACQHm2lZr6+gBdI45AF0juSYvj/I
         lgyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BUlB37L5+bTkXv9HMzvRMeckvAGtdpURfCakqFt5pOg=;
        b=A/+Roi9gdEMSvtm871tIHWC6m3DwD36gBWW/qAXrKrRSgj72lRveDQ9oFTdWUa81a7
         lO4MHW/dJqy82qhvtIQJ/EW3N+KeSd2d74y/CMWzNcME6bXRMSnOTtZiioHiez8Jc+12
         Vii5GmfCPMXcu7hWcjSBvCVBhmgT1u4Boq4dctB08DaDz3XO0r5b8RwhBHktNt1Pf5fI
         WdsS5K+K+w4ql4PdRnmqa+FH6/U4Np9ul7LKtUvLKy+hv/boRwd/OZyE+Glc5DkzvXG+
         xIMkxEeE/GWF4B9w+osLhBCzuOAIeOfN7AtgiU+/9siBFD5ypcbmvO8j1Ff9qLStUnYe
         Jm1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MHrMfR8g;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf42.google.com (mail-qv1-xf42.google.com. [2607:f8b0:4864:20::f42])
        by gmr-mx.google.com with ESMTPS id j78si125114oib.5.2020.10.27.05.49.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 27 Oct 2020 05:49:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) client-ip=2607:f8b0:4864:20::f42;
Received: by mail-qv1-xf42.google.com with SMTP id de3so553185qvb.5
        for <kasan-dev@googlegroups.com>; Tue, 27 Oct 2020 05:49:31 -0700 (PDT)
X-Received: by 2002:a0c:ba2a:: with SMTP id w42mr1901434qvf.23.1603802970306;
 Tue, 27 Oct 2020 05:49:30 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <1049f02fb4132390a6a314eb21dccfe5500e69d6.1603372719.git.andreyknvl@google.com>
In-Reply-To: <1049f02fb4132390a6a314eb21dccfe5500e69d6.1603372719.git.andreyknvl@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 27 Oct 2020 13:49:19 +0100
Message-ID: <CACT4Y+a8e3c54Bzf5r2zhoC-cPziaVR=r89ONxrp9gx9arhrnw@mail.gmail.com>
Subject: Re: [PATCH RFC v2 05/21] kasan: allow VMAP_STACK for HW_TAGS mode
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Kostya Serebryany <kcc@google.com>, Peter Collingbourne <pcc@google.com>, 
	Serban Constantinescu <serbanc@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=MHrMfR8g;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, Oct 22, 2020 at 3:19 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> Even though hardware tag-based mode currently doesn't support checking
> vmalloc allocations, it doesn't use shadow memory and works with
> VMAP_STACK as is.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/I3552cbc12321dec82cd7372676e9372a2eb452ac
> ---
>  arch/Kconfig | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/arch/Kconfig b/arch/Kconfig
> index af14a567b493..3caf7bcdcf93 100644
> --- a/arch/Kconfig
> +++ b/arch/Kconfig
> @@ -868,7 +868,7 @@ config VMAP_STACK
>         default y
>         bool "Use a virtually-mapped stack"
>         depends on HAVE_ARCH_VMAP_STACK
> -       depends on !KASAN || KASAN_VMALLOC
> +       depends on !(KASAN_GENERIC || KASAN_SW_TAGS) || KASAN_VMALLOC

I find it a bit simpler to interpret:

    depends on !KASAN || KASAN_HW_TAGS || KASAN_VMALLOC

due to simpler structure. But maybe it's just me.

>         help
>           Enable this if you want the use virtually-mapped kernel stacks
>           with guard pages.  This causes kernel stack overflows to be
> --
> 2.29.0.rc1.297.gfa9743e501-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Ba8e3c54Bzf5r2zhoC-cPziaVR%3Dr89ONxrp9gx9arhrnw%40mail.gmail.com.
