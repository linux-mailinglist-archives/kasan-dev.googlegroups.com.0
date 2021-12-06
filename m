Return-Path: <kasan-dev+bncBDW2JDUY5AORBUEKXKGQMGQE6UATHEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id B0AA346AAF0
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:49:05 +0100 (CET)
Received: by mail-oo1-xc3d.google.com with SMTP id q63-20020a4a3342000000b002c25d2d8772sf8725514ooq.11
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:49:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638827344; cv=pass;
        d=google.com; s=arc-20160816;
        b=UYZqz2Kuyd64kUOctitXNv0YMuLcDS++ZxXXOSJmaOsk5vjSZzn0zi3p1kRGxu4doB
         bERf8+XYDdpLXLxZiL1wO5fId2RIRjLbwhSJwpzhQDHg4PnJfBBXlUpp0abdVYOuD65m
         KzKReEOq22JYrAFId0YAknQ+BBjgrAgFbgEn4D43luYpTGHzGPx5eCdx3NwvzwOfbmUv
         8RtMIDY5N3xQlCG8MQ9y9uyeFGX6zwa9vNffMLYVtL50VHLhAJHcLgFsTGrEn7l6tIiq
         Nt9lWT0CAKjDT5EjLeUObXCLnzzHp+j7rkvk/0OPbXvkZribLe3icF8QxNI+Yg2qYWCx
         u56g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=+dpvXD+oHjtfe73Y8E8woHdwBBsMxP4w/fjZPl6h3qA=;
        b=c49AGtvs7nG/fcSHJJTTSUpbEdf1yVWZMN9PKJhuugSw1MAb1DqV6nzyhkJSAmGtui
         /VLzjSEYNlsVtjWvWCrnCpXWjIH05EZqxnl8p40gbs4iDf2plDayH9ZfKVIBiPcyCxqF
         Vx/FGJ7R8sA/P+p/SJBOGwVHWrmt8tckvJkCZ5rs1oQOZOuwyqBdbnG54EGlnqdsIlRU
         xYdYZXRuPTWZaxJBHDaJKiiB42jL/RuO46zKQfw6Vt0uby5xKjo0D1K2Urf1YmdOsqfJ
         ZmObr4uXN1uNCzwIQlJkd8jUJY8BLMc4FW4T4Qq8cYIkVrTepW/A+L3wlUmKy6BGoLHu
         8Cqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="O5oU/P9U";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::136 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+dpvXD+oHjtfe73Y8E8woHdwBBsMxP4w/fjZPl6h3qA=;
        b=UDBz+KHzC1j8oKBgT3qKNFQ9XZsg+nEk4j49sIrUMhXd5uUqDQzu7EaN4DMKENjE2v
         26mBLofdQ6b6EZZsEH/WlnDGFPv6PsoxD5tYV/slzVMbXYuhiA2o+LeAeCZOroNuQ6MX
         gVu0n98aS3mURrzjr1Ca4sys86Yl4qHSXYQGRadq54mpW+u7MT70guLJOoGUlacBvkWV
         yOp+31do0V5JDvT2Y6DcucALovjZTEWdILwSCTVTYvzgGP5oWFHTPb+t1i/UOqr/+GSs
         YoekPGsaF1JEV0rh5RP5sQ2T2V90l1xPLz0+yy8ULOLZnRNh5hot/A3Thvi5Ys6MOJTT
         wCvg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+dpvXD+oHjtfe73Y8E8woHdwBBsMxP4w/fjZPl6h3qA=;
        b=lM1t3yYhz2Z03OHFKLcy99M8SEkPlb4gDLnci9uWnSkzWwfZnUJpZd5cslxy7zx+dP
         pRJZl9ZCd/GJes8Jw5tIx1Ugmg/cVoum3DAXOO0oEvl0VTvOSfPFwiUsX6g+S2TdHN8H
         Vekb2jKDlGHkBacT9/a9B2PO1GKizeOQhBzjDAyydDD/hQIaB1fNX23phnCWDSNBi3rZ
         ysUHxShV3iX4lW404W4OiQBjqD5bmBXl9LhXcxc1BefnNyajwvxeUez4Wo6cdFI4YQAa
         kCrgHY9FGRe4nFcX+rSY/ybKStrh3zCxAgHLRyWym/yoPMLBSp92+RcXPyz6+LicvQRX
         RPdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+dpvXD+oHjtfe73Y8E8woHdwBBsMxP4w/fjZPl6h3qA=;
        b=JlvYhBUhaJ653fIGco4f6zoKQY8grF9lBb3Pw46vtWpZpgBkaswUHxbhXhhQKpNqC8
         aS9uV7RwkRZDwb9m1mvYP6aheChEIj+GLjJiILsgYwrmQSHR3W4VrZup5U310PShem6d
         3cjG7zPA++9fLMVyDKhsKZUdL2vaXRTDdBIjvuHj9sY7KYDWK62xJAgRI0UDhtXVXuI8
         4DVVb9GTyDDPb1bONH5pEpPytbpZWAx0ZElMl+O7aboqILEGTNJVpxTSogRGARNCfasf
         xnPM3Lu1i8xm7XkG+IF0+iRKiMIISHZ6P2obgZKTfbPRIVJ8MivSu6bG6IzWEGi+631e
         9OWA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5319epQceQJN/loPlT52I2XkzvdbHstC8ctCJdH1rxbGpqs+EUQd
	zCjkc+lSzvuYmG1Spdmz05A=
X-Google-Smtp-Source: ABdhPJxwUxjz3qqScCXyWXNUmgkXTaI0cpMk2nDhjburCQkRgTJ4ikoc5smtpbCHeeeuAwN2FNa+cA==
X-Received: by 2002:a05:6808:1a02:: with SMTP id bk2mr1404525oib.52.1638827344603;
        Mon, 06 Dec 2021 13:49:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:4110:: with SMTP id w16ls6085462ott.6.gmail; Mon,
 06 Dec 2021 13:49:04 -0800 (PST)
X-Received: by 2002:a9d:1c86:: with SMTP id l6mr31309903ota.241.1638827344252;
        Mon, 06 Dec 2021 13:49:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638827344; cv=none;
        d=google.com; s=arc-20160816;
        b=FkLEm0apK3HaXrob1d2vb2896MES/GFTiid2/tp/n11We0l89GyXnEJCktbZPUf45D
         E4SVvEpGeipPRx0d/T1G1F7ytj6JfNk5RXO5sugzQrN6qtL9ukjxKo5TC306pWPhrlBW
         arygK1Qxow/x5iVhFXWdbglRRRNDboqpYm+FKGu2E/HBdqRMibC/dWsKzzaRmGsMTZsq
         Puj/usAULQ2r8kY5uBJXzOcsQUUC3bZS/l+2oALP6doWiEKKTq8y3ki50KcNXtuErSUL
         foaFntzKg6WeFlX7i0/ksPqTWfKX8ROee/UrMd6/l80SSnyJbejjAg8I1Q9EvpIIVTjy
         i3Lg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NRJ2Vq4GGEkOM9Z1L10C4gsdtd/cSS7963Dg1Lu81Vk=;
        b=HMNsTOTdAb15FR6m3dCf1vvR6+lJZU7ISs7izb4lLJDe0jlyqR8FPJV/l7NO/dIlXQ
         8DfGmDmzb01iFGaQQJN+0EezSrJEnbXmwarns2qImaYdel1gMPQnDbWMnWEFfLE/kDy9
         Fdk0A1lxE3lC2/NflUXnPVt+GPJTkVVTI9UCaU4ccew1uJMAIi7oilwZu9hLFy+aPqHt
         D2WGhn7TlrCy/qp+Qw5UCzCtdYCeqxLIBFWE/J22TJx/Qkhlb9moMHeQeaEbAHXRSiru
         JVGCD/vDmEXPmdtPYOfnEXGPLkpr2aAJ0ocaeZ4OVwu1dSbvgHNfLUMhbqbv3w/zzd5r
         3/rg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="O5oU/P9U";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::136 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x136.google.com (mail-il1-x136.google.com. [2607:f8b0:4864:20::136])
        by gmr-mx.google.com with ESMTPS id s16si1097868oiw.4.2021.12.06.13.49.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 06 Dec 2021 13:49:04 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::136 as permitted sender) client-ip=2607:f8b0:4864:20::136;
Received: by mail-il1-x136.google.com with SMTP id j21so11724893ila.5
        for <kasan-dev@googlegroups.com>; Mon, 06 Dec 2021 13:49:04 -0800 (PST)
X-Received: by 2002:a05:6e02:1605:: with SMTP id t5mr39279632ilu.233.1638827343979;
 Mon, 06 Dec 2021 13:49:03 -0800 (PST)
MIME-Version: 1.0
References: <cover.1638825394.git.andreyknvl@google.com> <a1f0413493eb7db125c3f8086f5d8635b627fd2c.1638825394.git.andreyknvl@google.com>
In-Reply-To: <a1f0413493eb7db125c3f8086f5d8635b627fd2c.1638825394.git.andreyknvl@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 6 Dec 2021 22:48:52 +0100
Message-ID: <CA+fCnZezMmEtt1GKge_3JOudz+9SE_1fgVh1em+v10aNG6K5Gg@mail.gmail.com>
Subject: Re: [PATCH v2 24/34] kasan, vmalloc, arm64: mark vmalloc mappings as pgprot_tagged
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Peter Collingbourne <pcc@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Will Deacon <will@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, andrey.konovalov@linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="O5oU/P9U";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::136
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Dec 6, 2021 at 10:46 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> HW_TAGS KASAN relies on ARM Memory Tagging Extension (MTE). With MTE,
> a memory region must be mapped as MT_NORMAL_TAGGED to allow setting
> memory tags via MTE-specific instructions.
>
> This change adds proper protection bits to vmalloc() allocations.
> These allocations are always backed by page_alloc pages, so the tags
> will actually be getting set on the corresponding physical memory.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Co-developed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  arch/arm64/include/asm/vmalloc.h | 10 ++++++++++
>  include/linux/vmalloc.h          |  7 +++++++
>  mm/vmalloc.c                     |  2 ++
>  3 files changed, 19 insertions(+)
>
> diff --git a/arch/arm64/include/asm/vmalloc.h b/arch/arm64/include/asm/vmalloc.h
> index b9185503feae..3d35adf365bf 100644
> --- a/arch/arm64/include/asm/vmalloc.h
> +++ b/arch/arm64/include/asm/vmalloc.h
> @@ -25,4 +25,14 @@ static inline bool arch_vmap_pmd_supported(pgprot_t prot)
>
>  #endif
>
> +#define arch_vmalloc_pgprot_modify arch_vmalloc_pgprot_modify
> +static inline pgprot_t arch_vmalloc_pgprot_modify(pgprot_t prot)
> +{
> +       if (IS_ENABLED(CONFIG_KASAN_HW_TAGS) &&
> +                       (pgprot_val(prot) == pgprot_val(PAGE_KERNEL)))
> +               prot = pgprot_tagged(prot);
> +
> +       return prot;
> +}
> +
>  #endif /* _ASM_ARM64_VMALLOC_H */
> diff --git a/include/linux/vmalloc.h b/include/linux/vmalloc.h
> index b22369f540eb..965c4bf475f1 100644
> --- a/include/linux/vmalloc.h
> +++ b/include/linux/vmalloc.h
> @@ -108,6 +108,13 @@ static inline int arch_vmap_pte_supported_shift(unsigned long size)
>  }
>  #endif
>
> +#ifndef arch_vmalloc_pgprot_modify
> +static inline pgprot_t arch_vmalloc_pgprot_modify(pgprot_t prot)
> +{
> +       return prot;
> +}
> +#endif
> +
>  /*
>   *     Highlevel APIs for driver use
>   */
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index 7be18b292679..f37d0ed99bf9 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -3033,6 +3033,8 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
>                 return NULL;
>         }
>
> +       prot = arch_vmalloc_pgprot_modify(prot);
> +
>         if (vmap_allow_huge && !(vm_flags & VM_NO_HUGE_VMAP)) {
>                 unsigned long size_per_node;
>
> --
> 2.25.1
>

Hi Vincenzo,

This patch is based on an early version of the HW_TAGS series you had.
Could you PTAL and give your sign-off?

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZezMmEtt1GKge_3JOudz%2B9SE_1fgVh1em%2Bv10aNG6K5Gg%40mail.gmail.com.
