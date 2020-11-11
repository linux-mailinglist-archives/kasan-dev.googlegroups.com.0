Return-Path: <kasan-dev+bncBCCMH5WKTMGRBFH5V76QKGQEZJU6B6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 561A32AF471
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 16:09:10 +0100 (CET)
Received: by mail-pf1-x440.google.com with SMTP id q16sf1628485pfj.7
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 07:09:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605107349; cv=pass;
        d=google.com; s=arc-20160816;
        b=I1BluKh3BI1EaGlZZaeO2GwhKqyWMTFlXF5WE05HvAF8TttphXmXg6HlGr42fn3Css
         49auZ3YheHgQ0vMeMMa8Dbo2rTj7APAzd9/gSzV1mqg7CX6uPWvyBrHIQLrL4y8SAUAv
         J0CFzpEnvAKIeuA5XnrUW4dqucU64kf3RD2yaYzgATAh9d9Ko8fBkRmeaFIXMV0UjQPy
         F9lHjBwOQ4kwF2BrTWfREypjqNGNJ18nHvfLZ6MHUV0x49z7qwEmmqUg1yW/ehax+1u1
         OWLDD1Ie9BFm/F86dtL3NY4/mx5RF8Y43m7DhPIvYTVnxwedRd1vzWwpGK/eC0jG+2ks
         StLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Q/fHfjY6PIzc8A/j1zW4Rcbml3qgNEG2KsrUlG/Rx+M=;
        b=jE4g7g0rAv+aWguPdwdf0tE2rfowQ5gNyonIiGk289Eo+l8TRDGXADbfHhfdr9jyS3
         VeDIiw+9x5OjnXTP75HoZjlyKQLcGc+kcrlQsjcGXH+5QOqD8/0joOmI8BuVB1enL1K8
         lTrKuOJnJYwuv7coaBcOXiCobjLFx0ZWY7CdllaDDgVR2QPtkCiMSjSKur3a0WREY3sy
         zSbw5qWnfVBKAd8RLi9vRFRixBLyOOh+8qyRjkwPgI54K0iGmnaEMg4KDqT95tNFOrYS
         HhNFdfsfIQ1MxVdTeL7gjRjNtFV0QNhS7H9fI3I082gcGMpOQ1dF0T4DeT2bUgakPzO1
         4Eig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lW1TBKqi;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Q/fHfjY6PIzc8A/j1zW4Rcbml3qgNEG2KsrUlG/Rx+M=;
        b=lIPhoZmN+EG2VUiksrOhsTZqLIzifmlp9Wh+edRSJ9UkOujW607HZWttup/lK6y8N1
         cTnjIvxHJU/JabGEqkFykgM46SO5pbGuA6Um2cOTPfVP3CMpLthmm7gBTWX06TTNm3O1
         EyAO4DAE9fp576dMaCbiw9k8PFhAF5flFl+X2lip+RDJafAXC4n6+ufERXiVYAyK2PJD
         ontnRWO/yc+znv21kzKVK0oFmM48xYbEkX4sqTAFdTRlaP0iByF1r5xCeqhrJ5M4PbHe
         xmgZ8v34Y/cmqRj9gPLXP0wslSiOUpoOLsQPMhtgmSAlXQjP4Nq59pG4jca+H+hTnkEp
         zFJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Q/fHfjY6PIzc8A/j1zW4Rcbml3qgNEG2KsrUlG/Rx+M=;
        b=WPKtKT/ja3ztq+VoSrWTKHqmf05u5Lmr/A/inKpdFHSGP/PWLtN6ApJN9QTJR6P9rp
         UL7RXJSLXKlMEGyQWUk5Nd0caBXnlawD+C6dPKw6lwM7N654tDAfzwLcG/zjV6LWIrPC
         ZkCDuZcfNlznEYkpii7F2JK0ggMGDH9JY8B4IfPZPtDfkNJwh0I67DsPXEdQemSCK8nS
         nUqETxbQOrce6hWrMz+K8FZnytQrUx3I7aM/uMXveqhTWkSf/HlHr0HzslG/+26w8M0A
         219ehjcAr4ttmCfZYIFFfzGKlFkGx1sG7wzom2OTTAQLuHCVJxUnaKW6eJAnjPm1BZef
         4oKA==
X-Gm-Message-State: AOAM532vXHiw0nxHE1J/4LSXumYVS/BKrpUagXWAWOiG0XclwCtqjvXm
	ouSfPQ0+4fLBK9T/0ZIFAZk=
X-Google-Smtp-Source: ABdhPJzQB4c6smB6qb/myXhRNU7fzErYiA3QwN64d8OFVFwNUr1Q3VDhIDaoAhLiSwy7fbUOAZHBeg==
X-Received: by 2002:a17:90b:384b:: with SMTP id nl11mr4365443pjb.126.1605107349073;
        Wed, 11 Nov 2020 07:09:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:bd82:: with SMTP id z2ls4138375pjr.3.canary-gmail;
 Wed, 11 Nov 2020 07:09:08 -0800 (PST)
X-Received: by 2002:a17:90a:e643:: with SMTP id ep3mr4402067pjb.211.1605107348534;
        Wed, 11 Nov 2020 07:09:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605107348; cv=none;
        d=google.com; s=arc-20160816;
        b=Y/3GtDtweiv+Wo5DhsRvVvIQovHW2r37enT1uy9dj8pHEhTZFHkSH0GG7HfZ2s3VF7
         X/UPsR+VoeBWi2jHkBTd9HmmygFX+rKfCeYuIty0lUTNHUOlR03aDYnBKhddF3cvXPBf
         M2IhIvve3qQdd58TErJB0hNgQcqp68ImROCXgF9ALtMyWmmN+IwTdCT0Lm0Lvw1r6k1q
         p+rrECet87Z+a8mUFXOcbLyaP9oAcTz3t4/iKv9XwUIjFuXsboIgchoBF/OBLVllr/66
         eM88KZlsuYn4gRlXMVTwcNA9zyhsFdIVrB1pLOKYfntvJ0lphChIuFNCPCRWVyajj3xC
         Imug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=AP20IjKPEiFXMZmCcqvgPxuG9Q2kK77mjoFZj0OZZoQ=;
        b=mx59TaaQAIpLc/P/DygCLTHD8PkoQg1aOgHststB4gbwh9HX6S7CjcwsHqhKpfE7Kk
         nImyHS/Zxvpg1zyzH/8z7392miPoGCvHIk4aD0I+YQxuh4StQmvJbIgJi9CCZX04W5ez
         AhSZU8sLW8ycOTCiefuqUsiMJXGbfzEAHBNSYZEGR/61EdX7nb7kC4AMhkae/E8KFpa7
         d2VXtXuQN4iN5hkuu/JPN9qPjSRoqzNXMwAhn2DTvLtIhm/kGe55osEjaNDCZ9vL2w6N
         khQ7H2yMoofyLtvbsdX1fg1BqIdbskeK6dhvPZx57O6ANo28XjRxGrovOZD4C+0Zyf8o
         Jxhg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lW1TBKqi;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id h17si130758pjv.3.2020.11.11.07.09.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 07:09:08 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id r7so1940190qkf.3
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 07:09:08 -0800 (PST)
X-Received: by 2002:a37:4552:: with SMTP id s79mr19382613qka.6.1605107347099;
 Wed, 11 Nov 2020 07:09:07 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <49f7f2c12b0d5805f9a7b7092b986bbc2dd077a1.1605046192.git.andreyknvl@google.com>
In-Reply-To: <49f7f2c12b0d5805f9a7b7092b986bbc2dd077a1.1605046192.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Nov 2020 16:08:55 +0100
Message-ID: <CAG_fn=VXhK0d__FkNdhdquy9F4VmB64_6eJQOQBRecy2oL6huQ@mail.gmail.com>
Subject: Re: [PATCH v9 21/44] kasan: kasan_non_canonical_hook only for
 software modes
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
 header.i=@google.com header.s=20161025 header.b=lW1TBKqi;       spf=pass
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
> kasan_non_canonical_hook() is only applicable to KASAN modes that use
> shadow memory, and won't be needed for hardware tag-based KASAN.
>
> No functional changes for software modes.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Reviewed-by: Marco Elver <elver@google.com>
> ---
> Change-Id: Icc9f5ef100a2e86f3a4214a0c3131a68266181b2
> ---
>  mm/kasan/report.c | 3 ++-
>  1 file changed, 2 insertions(+), 1 deletion(-)
>
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 5d5733831ad7..594bad2a3a5e 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -403,7 +403,8 @@ bool kasan_report(unsigned long addr, size_t size, bo=
ol is_write,
>         return ret;
>  }
>
> -#ifdef CONFIG_KASAN_INLINE
> +#if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && =
\
> +       defined(CONFIG_KASAN_INLINE)
>  /*
>   * With CONFIG_KASAN_INLINE, accesses to bogus pointers (outside the hig=
h
>   * canonical half of the address space) cause out-of-bounds shadow memor=
y reads

Perhaps this comment also needs to be updated.

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
kasan-dev/CAG_fn%3DVXhK0d__FkNdhdquy9F4VmB64_6eJQOQBRecy2oL6huQ%40mail.gmai=
l.com.
