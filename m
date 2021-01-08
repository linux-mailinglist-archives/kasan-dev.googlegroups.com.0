Return-Path: <kasan-dev+bncBDX4HWEMTEBRBMWH4L7QKGQE5HQ4O4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 53BF82EF748
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Jan 2021 19:25:56 +0100 (CET)
Received: by mail-pj1-x103c.google.com with SMTP id m7sf7480499pjr.0
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Jan 2021 10:25:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610130355; cv=pass;
        d=google.com; s=arc-20160816;
        b=iQMZaheokb7QpOiEHh4swzfrWiTmhOCIlAGhkFigQQh4tK1BiMajGaGb/lT+qAormx
         NE10VfccuWeyff5WB5fUdFDq9PWwiK9/ZPSjE81cfZQGPsmhuwadbHILQPpQOUbqailN
         hdKsTYMjeiEJLvm6tKaXCpRGiGdn1V9bvWF4LC9xH0jS2+oYeYX+5JIuKKJF6YzhX9Fw
         BjNDOyGJObdytHMSiOpCOGoKpoBI2Movj3FJ1nbwGK8gPFrzCY9zmDcHGHiJl0DwAePT
         TXgio2H/7qR2OdwPosPea1HOiRbBcyEBmjU1GHOI3byY/dsFTLackAlJiNU/rdwgqFeA
         WcwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Eh2cgct3J5Uyw4cxt6G8sXH0ILGw0oHgB9sjsXzxcDU=;
        b=HZZMdP/h7FFRi8CfdFJR8mVVAz1uk50kaFGbWoMPP9+oN3YDEZf0FduiPCfuidrjyx
         PEdM+VTznKyFHwtizqH35PxMHf2xW+XGsJFyMzkzM1ryC92H+P6wMA0X9Ww/OwXCV/Rs
         PaN9/kekIqKaerY6qD08IP1oQrzgHHucUCfsMfq9HC+YN1WjNrbCQ9O/MwUcAP0y+6WG
         60Apsi5K1hhCZ6VC1eP8u6tzTfWwqtgSIFDZWGlO7ECDRoni2XlDmqWbdXRxMs3SfWEC
         /m9m1ZDXhkTQPt6H5hj7nov8p5ajMgQHH8dm48xTh0cYpkenYrSGj66/LJplnuaeX6Fo
         99Eg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GmQA0TK1;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Eh2cgct3J5Uyw4cxt6G8sXH0ILGw0oHgB9sjsXzxcDU=;
        b=MLSuuNool2yaWEd9ePXgvWS+vZ2nXoSMHUnPWCQvP8kDTgCYtsibZoVzKpKlBZWtC4
         P3Ls+I9Vm1yKAqhMSCcMg27wE+Z0jCM8R7OP564/vS9SFNRx7LqRyt2SeCeL/wP8JlHz
         4N1W+nBCbzBrcuYtYpKTRTkd6YsPDcyeA4UAT1aDDUgvPAXMtq4gU0291ev5mj35yYHY
         AFh2WP4pS4CPA4ngneYMAMb0VEmVDkILKf7iN5TaXJknzSXSNpuhOu4Ujpq9Ky2ZVwMk
         44pJQ+RGQzRm8sCf7OavTB1sT5zaUc5e70ivU3I8ob+Ogv4/WkoNcV0xKe6CgBrXFhPq
         rqsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Eh2cgct3J5Uyw4cxt6G8sXH0ILGw0oHgB9sjsXzxcDU=;
        b=NqUg4tIP5B7Pf51NezUnuWIvOrODBAB1cjA487p3QJS2F65tenvMcschCF4ParoI1j
         64coXRDA1zH7TPizZWES9LPet7qYNcZLEm1Pk5RyEFyTNeNe22Qur2Dlt8DoXWcYU5zZ
         qTJJktb3NZ6x4ucX1XXo0RSeS8OqciZHd1xWo+qAyxckO0xhmx2TIkTU1egUF2kEwIHP
         /MCEMfo5vpky/s7lU2Kk8LkrTeErOf/gglWRacpSs8oBEaNiCUGnRl5q3kjflhHUoyZI
         FV9NVZyMK4AsvaGfS3q9vkmglJQA3PRa4ClKQsDtt67A+JY1WClRHyHgqcDn2guR4J+M
         Fzog==
X-Gm-Message-State: AOAM533f1FCL0rer3rdh91Yde6K9wcfOwdyvWxQugxQKunutceajDDbm
	uOMGkmICbf25uyZE6hrjpbQ=
X-Google-Smtp-Source: ABdhPJzN91mvdgnYlTAw1bNzo0PEa7fOVDyqG0Z9xHRROkVZlPrsGdr/2Cvusk6Qi9T4KA7ymHywlw==
X-Received: by 2002:a17:90b:94b:: with SMTP id dw11mr419549pjb.12.1610130354830;
        Fri, 08 Jan 2021 10:25:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:5c85:: with SMTP id q127ls4251395pfb.11.gmail; Fri, 08
 Jan 2021 10:25:54 -0800 (PST)
X-Received: by 2002:a62:8fca:0:b029:1a9:39bc:ed37 with SMTP id n193-20020a628fca0000b02901a939bced37mr4900974pfd.61.1610130354232;
        Fri, 08 Jan 2021 10:25:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610130354; cv=none;
        d=google.com; s=arc-20160816;
        b=q8dlTgine+QTXk96wbTP8Ae+5K3u/knrbSTILm0p1P848cB3qWieNLEYOiBrao9CoK
         O8uLx7YpyD6BWuKbRp/DRV8gNPYJ2UhYSbhGQlbpLQcguSPdbn8EoqFPXphjsVx/4u9x
         mHbGErGeOnM9L4nBF5DhHuqewj/j5Yqb0SGCm/nVTBIot4hB0ZY5CCniu0mbwcni7333
         RXSDNEA7fpFG6koZpEjF1b84UWbeyIRdqwOUyIRFSJvZBQUYYMxOkLxpKSke3dAA10cU
         OvDEuinm9VvdCzaTedkQk3DAns2omM4UIsbwBItTf3pHO2ZjqzTSC1wCc2Wgj5dDv9SS
         tlPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0EAbk42/5hnLn57GbgtjDwqdHR3jfIYT2uMLmHPvJts=;
        b=KfKuNQ+dy+LQO0Vs9o8wD75j4s4QWdXLp7VD3staq4rFWEwANxDCn1PMi4X5gcvEVL
         WDJpdH4QaCgY9vEnAVaSFEEQU+od3tLt8m7zr2zVyfckbk1PgIgkm0dcWO/0pFdNhVvN
         lSEhKDOEDdFVYbrmJC82lVTNWar2s5jlnpUUhnB+/sO4rKoaO1J+6Jf2QvJ6ndFpmQHD
         TJBcPovHs+ZodgAiUc+/Efl88/VQoFv9hMqPlo5eOTvh5n7zJnu8654FC7IfCuSW0RSc
         2Rs4T5ENUSYKSnFz1IT/CN+o6qkm1TQQR6IIoX7YptTdEZznTbH2QxB/s3czv2mQc20g
         VPRQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GmQA0TK1;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x434.google.com (mail-pf1-x434.google.com. [2607:f8b0:4864:20::434])
        by gmr-mx.google.com with ESMTPS id mp23si1106655pjb.1.2021.01.08.10.25.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 08 Jan 2021 10:25:54 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::434 as permitted sender) client-ip=2607:f8b0:4864:20::434;
Received: by mail-pf1-x434.google.com with SMTP id a188so6748357pfa.11
        for <kasan-dev@googlegroups.com>; Fri, 08 Jan 2021 10:25:54 -0800 (PST)
X-Received: by 2002:a62:2585:0:b029:1ab:7fb7:b965 with SMTP id
 l127-20020a6225850000b02901ab7fb7b965mr4980449pfl.2.1610130353786; Fri, 08
 Jan 2021 10:25:53 -0800 (PST)
MIME-Version: 1.0
References: <20210103135621.83129-1-lecopzer@gmail.com>
In-Reply-To: <20210103135621.83129-1-lecopzer@gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 8 Jan 2021 19:25:42 +0100
Message-ID: <CAAeHK+z0+hWBFha8Upu7JN-_ruBopzUkNKgBoihUPt1w6k8auA@mail.gmail.com>
Subject: Re: [PATCH] kasan: fix unaligned address is unhandled in kasan_remove_zero_shadow
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Dan Williams <dan.j.williams@intel.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	linux-mediatek@lists.infradead.org, yj.chiang@mediatek.com, 
	Lecopzer Chen <lecopzer@gmail.com>, Lecopzer Chen <lecopzer.chen@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=GmQA0TK1;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::434
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Sun, Jan 3, 2021 at 2:56 PM Lecopzer Chen <lecopzer@gmail.com> wrote:
>
> During testing kasan_populate_early_shadow and kasan_remove_zero_shadow,
> if the shadow start and end address in kasan_remove_zero_shadow() is
> not aligned to PMD_SIZE, the remain unaligned PTE won't be removed.
>
> In the test case for kasan_remove_zero_shadow():
>     shadow_start: 0xffffffb802000000, shadow end: 0xffffffbfbe000000
>     3-level page table:
>       PUD_SIZE: 0x40000000 PMD_SIZE: 0x200000 PAGE_SIZE: 4K
> 0xffffffbf80000000 ~ 0xffffffbfbdf80000 will not be removed because
> in kasan_remove_pud_table(), kasan_pmd_table(*pud) is true but the
> next address is 0xffffffbfbdf80000 which is not aligned to PUD_SIZE.
>
> In the correct condition, this should fallback to the next level
> kasan_remove_pmd_table() but the condition flow always continue to skip
> the unaligned part.
>
> Fix by correcting the condition when next and addr are neither aligned.
>
> Fixes: 0207df4fa1a86 ("kernel/memremap, kasan: make ZONE_DEVICE with work with KASAN")
> Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
> ---
>  mm/kasan/init.c | 20 ++++++++++++--------
>  1 file changed, 12 insertions(+), 8 deletions(-)
>
> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> index 67051cfae41c..ae9158f7501f 100644
> --- a/mm/kasan/init.c
> +++ b/mm/kasan/init.c
> @@ -372,9 +372,10 @@ static void kasan_remove_pmd_table(pmd_t *pmd, unsigned long addr,
>
>                 if (kasan_pte_table(*pmd)) {
>                         if (IS_ALIGNED(addr, PMD_SIZE) &&
> -                           IS_ALIGNED(next, PMD_SIZE))
> +                           IS_ALIGNED(next, PMD_SIZE)) {
>                                 pmd_clear(pmd);
> -                       continue;
> +                               continue;
> +                       }
>                 }
>                 pte = pte_offset_kernel(pmd, addr);
>                 kasan_remove_pte_table(pte, addr, next);
> @@ -397,9 +398,10 @@ static void kasan_remove_pud_table(pud_t *pud, unsigned long addr,
>
>                 if (kasan_pmd_table(*pud)) {
>                         if (IS_ALIGNED(addr, PUD_SIZE) &&
> -                           IS_ALIGNED(next, PUD_SIZE))
> +                           IS_ALIGNED(next, PUD_SIZE)) {
>                                 pud_clear(pud);
> -                       continue;
> +                               continue;
> +                       }
>                 }
>                 pmd = pmd_offset(pud, addr);
>                 pmd_base = pmd_offset(pud, 0);
> @@ -423,9 +425,10 @@ static void kasan_remove_p4d_table(p4d_t *p4d, unsigned long addr,
>
>                 if (kasan_pud_table(*p4d)) {
>                         if (IS_ALIGNED(addr, P4D_SIZE) &&
> -                           IS_ALIGNED(next, P4D_SIZE))
> +                           IS_ALIGNED(next, P4D_SIZE)) {
>                                 p4d_clear(p4d);
> -                       continue;
> +                               continue;
> +                       }
>                 }
>                 pud = pud_offset(p4d, addr);
>                 kasan_remove_pud_table(pud, addr, next);
> @@ -456,9 +459,10 @@ void kasan_remove_zero_shadow(void *start, unsigned long size)
>
>                 if (kasan_p4d_table(*pgd)) {
>                         if (IS_ALIGNED(addr, PGDIR_SIZE) &&
> -                           IS_ALIGNED(next, PGDIR_SIZE))
> +                           IS_ALIGNED(next, PGDIR_SIZE)) {
>                                 pgd_clear(pgd);
> -                       continue;
> +                               continue;
> +                       }
>                 }
>
>                 p4d = p4d_offset(pgd, addr);
> --
> 2.25.1

Andrey, could you please take a look at this change?

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bz0%2BhWBFha8Upu7JN-_ruBopzUkNKgBoihUPt1w6k8auA%40mail.gmail.com.
