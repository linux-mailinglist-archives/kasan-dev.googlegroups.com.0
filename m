Return-Path: <kasan-dev+bncBDW2JDUY5AORBRH2RCKQMGQEIJXZVRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 55DF7545434
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 20:34:45 +0200 (CEST)
Received: by mail-ot1-x33e.google.com with SMTP id y21-20020a0568302a1500b0060bd96d084dsf7695292otu.15
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 11:34:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654799684; cv=pass;
        d=google.com; s=arc-20160816;
        b=aB8SNMaTlScSRlyQav8hHWSBqPqnDTuJJeWo9zm9SGRQHM1hlGGdDRBmm2McmB3sce
         nQHnX//sHpS/8TcR8KWOvrAS/4gTdDTfAFa+xRPe4393hhuwJiY1hHnwrsgRcUZX0y46
         pxhJNhE3HjqKpT9VhUVjGFeVdg06b9RY204ZKv2yShF4tgppaKVYLMG1WYdpXsU6ZfL5
         8kfMge1LQgTRY8NYddUy3J4jlpL0zEuNsO0FLoiSYrR4quFwvVihojWM1EAELch5yHwx
         qwK4wHvETxP8l0YMAruP9X4kv4f0ILA5/h3X7eV3fGMLxahTyIbS9VHnWZNsSEdLi0xO
         pLZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=m7C67HCXWWVG4dCiPjQTf2zS78Z9DguJnYv0UP2f5W4=;
        b=OaYalPKGQuc0x+mb29YRMYDP8C7EuWyJAYgFr+6TP9hQa0WMSFsTXB37ix8He8qOUM
         0QvRl64Uv0d3JdP/V1VD6vC+QYZlm18EU/CXW+HH21w889wppuplgdDG6yrpP7Af+cNe
         2R4M88QzlbZ0i8pxysUxmxYTQy2k7R4GNyQaw5RRAzphVZID+OMHrP9UpcCOc/jYqaHI
         P9SC/40XpkMvxa5WRvXIGkr7Bky74p82LNM02SI3Ez24WOqqXWllarliZNCg4bNMf9Br
         SZwNac8amq2lhECUupsB3887TahVoZCzl5oU9IqUU6n8ZLdexVHUQ2R6+uaK4gMv99AP
         aCrQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Y7L1oYc4;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d33 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m7C67HCXWWVG4dCiPjQTf2zS78Z9DguJnYv0UP2f5W4=;
        b=oxSrowZDl47/MtQsoQnNpeIX2KuVoCzJKLIrtvMzBFPSEgRISRR2DvP+TQ65fdcjQM
         F1ud3SaQjrEJrs1DWJ/7vyAXHg+akQiSc6FOGTR0DRIu0EbtTm6n3/WPRsNBxzVu8IA1
         j8nlFcqpZslmF6eM+Y041+Hkd/UPN4xmNfl6TnZXESwglRjaN2ce8dsd9JefrlSE6niy
         /AlxPmeWcsZcFU9KI6u/ZMRYnqCP53by6Gjf+HuXFykNveOQ5an3ivlb5OUmI0VWjJ2a
         g5KK5B2x5Didf4C00m9VGOiSfNyKdYWI9s1QtUwM2w4t0immoNXBwJOVCcg3L/1GnDfT
         hG8g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m7C67HCXWWVG4dCiPjQTf2zS78Z9DguJnYv0UP2f5W4=;
        b=Dd8n8hOVzp70aDd9bvOfWNKSceqkU8wNELhRO43PC+39iq5wa7JLf6Nr0yywon93pC
         rO4IFaT3y54LusCQakWgNdkOGAsDTnCmI2S7rYViGEww4K1JkkLCDTMMItx4T6Lx3oL1
         VBlGH/35GVbBUL4C9h7HeuJK9ixJ/DwYex/u+l+eSzQKCRTTmWrgOstvxcid4Nofn2X1
         PJ5CDNP7uYLUSLx+58uHN3z5w+eq/tulBvHyJUWJu8o1mzVLF0P14rWWXZItWyfX+uQo
         y5LpJmswYdPVqB2axRb2JyuCobQWDk1m/BtECTb8QXV2mYsifdVqCoEpBopoX5+acE6k
         bh6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m7C67HCXWWVG4dCiPjQTf2zS78Z9DguJnYv0UP2f5W4=;
        b=LFV6Sle2CztPS6mjPuyCSm6T2bw/9ZIFVGj2iRI5mNiOFw+eGMP7I6RooW5OdJD5+l
         cfdbO5GmbiKJtixju/CIJXogkaOKAoK58BuB7AXKJADsV4he8V631D0C2g/eQfOm6EN2
         MutHYzbM4vPxaSQ+mqlYTi5H61mK5ZM4itajq5lPDvSYu2FCnS7C9mhb2u22bTLMgl3i
         X2PuzjCN2rw2JQn1usnz7Rq8PnxvqxujicLf9fXvvmfbrmcvxEvvX+JelqxDwemyTukH
         6zf8XaCGX3DX88MWJiQlYS1Ngxmd2GA2N64WEAW6qhI6428xgfuh9PRDHvicQ2W1JFq4
         EIFg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532zqisQ8FtAURN3ZPINuO/FyMBhjsvM207nwmSILQTKDtYR0xuf
	0712UFC/L+MMGXyzRGVbzJo=
X-Google-Smtp-Source: ABdhPJxEwCc5EY7PiIBpHHGjWzmQ9VawlaISweGcujxvimW2BuN2hlsONLDzkgkxelNicIJIBcfvJA==
X-Received: by 2002:a05:6808:138c:b0:32e:714f:35e4 with SMTP id c12-20020a056808138c00b0032e714f35e4mr2501870oiw.229.1654799684104;
        Thu, 09 Jun 2022 11:34:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:d78a:b0:f3:426e:e97a with SMTP id
 bd10-20020a056870d78a00b000f3426ee97als7859999oab.2.gmail; Thu, 09 Jun 2022
 11:34:43 -0700 (PDT)
X-Received: by 2002:a05:6870:d154:b0:f3:24ec:3332 with SMTP id f20-20020a056870d15400b000f324ec3332mr2506263oac.172.1654799683753;
        Thu, 09 Jun 2022 11:34:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654799683; cv=none;
        d=google.com; s=arc-20160816;
        b=Y+ojbiAw5JqlcAm8vzNpFNY1h984WvodTuBKGlyUXuS+n6HVnyX4U6uVucj9gGO2xP
         1Lu2E1mv0MtOHWDhnSPdJaF13Y0F6o9rhDNwGjeFQ/N4d3kZRt3AaL9Dg5RGwCo4gQ7u
         hzXHZS5/49PpyR2pKPKCD8L3o4Y06JDJGmMf3zOvPvpHfGXQyHPyR8NddDr7+11H0X7d
         J4Axl32t9VilPpvrp14H7Nt1/DV0l7el178dC1fq72BmQ33TGh2MtVHCXYXaCtDbV9Lr
         WlxdpHwOv6J5Wo/aewpMKzmRt1C/1hyNt9HwI43udiSPE1/88lCNGEVXUSsLZA6Y5xLD
         NXUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=h+QoQcZlBQcgjaXTtPpLAq3kb9O2sEKS7YuulaGYrdM=;
        b=nq7CHVpXu198Mw55wsgKjC88oIRBl29w0EV+BCuf3q96dwI86Ok33gNZ2rcOp0nQ/S
         zrGjpXx2QPUwFJDUbP8ulqZF3x0FmMy/HllJ5erHTB360yQDA3LCLBQlcYb2AM4afE/u
         Mqydx7jdrO6WJKP6x9/2z4C0rUXyRvr0P8FufqQrWV6hUgWtp6u8yNFeiHgghDFMfQy0
         8GWiv6mVfecOpsEIym4XkHHcRA3S2mDNWbZUn4jD6QPnq+L6jB/J6NDNUQAuFiWG92ow
         2Ure7303YeIBwwNZcjsoOm4Ne7vwb527wDeMAI8kVbIN3zTAL+SyWbqYb6u8h0Tf0HHz
         Dl/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Y7L1oYc4;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d33 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd33.google.com (mail-io1-xd33.google.com. [2607:f8b0:4864:20::d33])
        by gmr-mx.google.com with ESMTPS id u125-20020aca6083000000b0032ec87f4accsi398892oib.4.2022.06.09.11.34.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jun 2022 11:34:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d33 as permitted sender) client-ip=2607:f8b0:4864:20::d33;
Received: by mail-io1-xd33.google.com with SMTP id e80so1560652iof.3
        for <kasan-dev@googlegroups.com>; Thu, 09 Jun 2022 11:34:43 -0700 (PDT)
X-Received: by 2002:a5d:9817:0:b0:65a:f20b:db2c with SMTP id
 a23-20020a5d9817000000b0065af20bdb2cmr20052140iol.118.1654799683559; Thu, 09
 Jun 2022 11:34:43 -0700 (PDT)
MIME-Version: 1.0
References: <20220607113150.55140-1-vincenzo.frascino@arm.com>
In-Reply-To: <20220607113150.55140-1-vincenzo.frascino@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 9 Jun 2022 20:34:32 +0200
Message-ID: <CA+fCnZcZcoOz+SVXdVOsrC_pR_PJUoCQnJe3B2u=D_K7=J79+Q@mail.gmail.com>
Subject: Re: [PATCH] mte: Initialize tag storage to KASAN_TAG_INVALID
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=Y7L1oYc4;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d33
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

On Tue, Jun 7, 2022 at 1:32 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> When the kernel is entered on aarch64, the MTE allocation tags are in an
> UNKNOWN state.
>
> With MTE enabled, the tags are initialized:
>  - When a page is allocated and the user maps it with PROT_MTE.
>  - On allocation, with in-kernel MTE enabled (KHWASAN).

Hi Vincenzo,

I think we should move away from the KHWASAN name - it was used during
the early prototyping days for SW_TAGS KASAN. What you mean here is
HW_TAGS KASAN.

Thanks!


>
> If the tag pool is zeroed by the hardware at reset, it makes it
> difficult to track potential places where the initialization of the
> tags was missed.
>
> This can be observed under QEMU for aarch64, which initializes the MTE
> allocation tags to zero.
>
> Initialize to tag storage to KASAN_TAG_INVALID to catch potential
> places where the initialization of the tags was missed.
>
> This is done introducing a new kernel command line parameter
> "mte.tags_init" that enables the debug option.
>
> Note: The proposed solution should be considered a debug option because
> it might have performance impact on large machines at boot.
>
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  arch/arm64/kernel/mte.c | 47 +++++++++++++++++++++++++++++++++++++++++
>  1 file changed, 47 insertions(+)
>
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index 57b30bcf9f21..259a826363f1 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -6,6 +6,7 @@
>  #include <linux/bitops.h>
>  #include <linux/cpu.h>
>  #include <linux/kernel.h>
> +#include <linux/memblock.h>
>  #include <linux/mm.h>
>  #include <linux/prctl.h>
>  #include <linux/sched.h>
> @@ -35,6 +36,8 @@ DEFINE_STATIC_KEY_FALSE(mte_async_or_asymm_mode);
>  EXPORT_SYMBOL_GPL(mte_async_or_asymm_mode);
>  #endif
>
> +static bool mte_tags_init __ro_after_init;
> +
>  static void mte_sync_page_tags(struct page *page, pte_t old_pte,
>                                bool check_swap, bool pte_is_tagged)
>  {
> @@ -107,6 +110,48 @@ int memcmp_pages(struct page *page1, struct page *page2)
>         return ret;
>  }
>
> +/* mte.tags_init=off/on */
> +static int __init early_mte_tags_init(char *arg)
> +{
> +       if (!arg)
> +               return -EINVAL;
> +
> +       if (!strcmp(arg, "off"))
> +               mte_tags_init = false;
> +       else if (!strcmp(arg, "on"))
> +               mte_tags_init = true;
> +       else
> +               return -EINVAL;
> +
> +       return 0;
> +}
> +early_param("mte.tags_init", early_mte_tags_init);
> +
> +static inline void __mte_tag_storage_init(void)
> +{
> +       static bool mte_tags_uninitialized = true;
> +       phys_addr_t pa_start, pa_end;
> +       u64 index;
> +
> +       if (mte_tags_init && !mte_tags_uninitialized)
> +               return;
> +
> +       for_each_mem_range(index, &pa_start, &pa_end) {
> +               void *va_start = (void *)__phys_to_virt(pa_start);
> +               void *va_end = (void *)__phys_to_virt(pa_end);
> +               size_t va_size = (u64)va_end - (u64)va_start;
> +
> +               if (va_start >= va_end)
> +                       break;
> +
> +               mte_set_mem_tag_range(va_start, va_size, KASAN_TAG_INVALID, false);
> +       }
> +
> +       /* Tags are now initialized to KASAN_TAG_INVALID */
> +       mte_tags_uninitialized = false;
> +       pr_info("MTE: Tag Storage Initialized\n");
> +}
> +
>  static inline void __mte_enable_kernel(const char *mode, unsigned long tcf)
>  {
>         /* Enable MTE Sync Mode for EL1. */
> @@ -114,6 +159,8 @@ static inline void __mte_enable_kernel(const char *mode, unsigned long tcf)
>                          SYS_FIELD_PREP(SCTLR_EL1, TCF, tcf));
>         isb();
>
> +       __mte_tag_storage_init();
> +
>         pr_info_once("MTE: enabled in %s mode at EL1\n", mode);
>  }
>
> --
> 2.36.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220607113150.55140-1-vincenzo.frascino%40arm.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcZcoOz%2BSVXdVOsrC_pR_PJUoCQnJe3B2u%3DD_K7%3DJ79%2BQ%40mail.gmail.com.
