Return-Path: <kasan-dev+bncBDW2JDUY5AORBTUE36GQMGQE5374RSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id CCE2F473721
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:59:43 +0100 (CET)
Received: by mail-qv1-xf40.google.com with SMTP id h14-20020a0562140dae00b003ae664126e9sf25378194qvh.3
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:59:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432782; cv=pass;
        d=google.com; s=arc-20160816;
        b=Qge5vJA1cttD1eK6rQqa53s4IHLK3AzTfSESY9+GndtD7YB9L/FiBMFWhPe7zsMlRn
         lnQYKRxduhMiOWCMK1Gh/FM1pTkxAxjTGvJPQe+Ro+8pq97x1jH/JIDQACTLRlbCVzcN
         9liACquHCSg3MWUmCtSXKGnWkX+pcYiOve1vkXE7NkOgaPgB31YEGRDCwj1gUmPm0r6F
         /NIA3fxKOB6xgJIaMAt1ztQ7QtxSjMraBwb1K0T2GH/cBRJ976jTLdXrHdU9S7qk3sBE
         4Wm3Nr3+ZpkkB1tTbj/3ijYYOA9pXsv79j5/lPBUTFtrPvjmsEdm7lYvyecWyHy9wZcW
         ep2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=ptJf2nGHdDSlTJMA4ZS/RPH43m1AP0R1MfzQX2VZROw=;
        b=oUijmeIz9uYTougHjWpvDVkLW+XwlcHN3T43pobwdG6Ra9/MEJivk6wk7Ams72nWG0
         B+pYd4bh4kGHmC5De3QN+rlsjbiSpNV41ATIxryGW+29hetYgX2r+mWdFK1690j0raeL
         5qaw/9iaDs5NI6ZdvoLzUjCyhiLKqtrY2BOIAC1j40y/Zluq/3SZ7iUoViVWP8VRErbi
         jwf7Vl3gJGVf+LmZYDlkVW1QFvco9geQX1txTSNxte1NMzFoHVPBQ88MyvYpz5b+l+w3
         RuCLT6C6sy9CkMjvbRr4PQiFFKzwU8An2I3EGcDjA6dQkHw1imexy7rwCH/GyWBAJ7eR
         hzLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=BXPU2MKM;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d32 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ptJf2nGHdDSlTJMA4ZS/RPH43m1AP0R1MfzQX2VZROw=;
        b=bGeIKFnI7vijFD2tlu1F+IFsaMA+HRPK66QN1NN+xdYuroZbaRhEhhoa5hneyKIFak
         S6wWMWvfb3bUHHISseC10H2Jk4UR9djlmWAteK9jdEJsQUcxXl5pmcuw6zTw9OPC5J7u
         kWqjHDlzHFmB+bam7GFjdv5g3O3yjmSG0IItktPR0g3Zzde+0eDRCqAmr1YrJOc+THK3
         FYd1wGtJChhgbDS+WuFeBR2DLPZJXjvKtH9DwFKMoOUy0H0vRqW7GiSvMX9si3ZtUdIP
         OcJiCMBFPBrgfg4KS/bzay+/evhj3sTH0xshzHf81WbcM1VG3Do3AjyMRHHVJM7vtSr4
         BC8w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ptJf2nGHdDSlTJMA4ZS/RPH43m1AP0R1MfzQX2VZROw=;
        b=Cb31DshVxOuIvu5F5J/ErPCY0B7sOK1qpJ/SWqolku4248bdcBy8BEchq5CONkRtX2
         GeF6fewtYh5Od320U2D09G7EIcX2gtsQY4ZMAQM77tQKyB77veT0G3nyArCIOlvOo8ik
         QcqgC2Q0PxBsyBs7Kjaek+dVUqoySrK1xNEYDyRRK+QZ664fxO7rpbvKG2m21yW4lwPU
         PUpLxDq1/b5K9QBn+KD+sEPFGmaKpp5jgmOwF7yBg4DPG7hkuXSIlWGK/VEyNNIkX5XE
         Y813UTiLeb6QV4S08kE+eCVo05tubMlJki9+ZV4yCV1Wsud37PkwN/7ahSNaQG4Zu4Q3
         GxBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ptJf2nGHdDSlTJMA4ZS/RPH43m1AP0R1MfzQX2VZROw=;
        b=fmEs//si4/DM1/Msbol6zTTRtNvNP7pdCgBSuIsZBWyA3pMwh34L2XU6Tr1EFX9B4l
         rV7coIYvs129itBRHtFl1u1OZbFKb7ijVkc1TzwWvvvVr/F656r4y4guPVu+8tLT81Xx
         eOC3MuB73gsnt7I7enZ+MJC8ekL9XAjPBEgXhLDka7+Xei3lDGEwAkwTG3S8obYXxfMx
         vAlIFrEKZDRMxO8VdI7895IrOLleivEP6NJquCHr3EMvhnmhc389v7bte6+osH9fmD2J
         GYtnWGl4/V61f9C1Ws5kJiCXit1bib6bJni6ildamwXjJ8bqgrbnxmcet0Qf6AvSfkHk
         tyMg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533QdYMbJPCNwTjqgrh2ialPUP1EjUOxaOmUme2Y07t6hVT2T4YC
	ArZ5Ar7w1D2fjUa/gfRjEO4=
X-Google-Smtp-Source: ABdhPJwDqpGl6y/OPuLs0rRg5OwNi2CokmQTsCz5AV29QoS2xlHNGayP7KfZ5H8XCodjJhpUO8VFFg==
X-Received: by 2002:a05:620a:4450:: with SMTP id w16mr882361qkp.26.1639432782587;
        Mon, 13 Dec 2021 13:59:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:8d85:: with SMTP id t5ls9895652qvb.11.gmail; Mon, 13 Dec
 2021 13:59:42 -0800 (PST)
X-Received: by 2002:a05:6214:188:: with SMTP id q8mr994434qvr.123.1639432782200;
        Mon, 13 Dec 2021 13:59:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432782; cv=none;
        d=google.com; s=arc-20160816;
        b=vjPVSwsX06J+2YTaeu5jzufF/1oBTT+nWa2hrQ9Ddd64ulu5t0P42uj+f29hZnqXBu
         Lxik3TacAdpDoxTX7nB++nlyKkPd076rKcgUlLZXhpSaa7LozpaLCfm5mpZPHFwNB2n9
         F2h9Oi/esQki0Vxb/LvjApjBBgq/XQraCFgN28EFnfGl6i0Hz7/YtJyfRBGjhnJQeRFp
         aNsdkidTn2By9UbOCGrCPbJhlzkfEG0aRtp/5EYxZXarEHXTWElxLybXI8xt92ExVRoQ
         Vjxvz/5e11k7R4j2N+Fu8DqFDUyongpKHaq19HLuaoe1BKfcWl1lxwtb6aEEx1F18uCQ
         HDcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MRKR0iLm5s05rmkpI4jYkAhFh/8IVKgubKuDuwtAGZo=;
        b=id9mERqvIzrhvpTMyKOt/ZAwrGAZhYohDz884yvci+se4yjqrD7AXunVimbxLPS6S2
         P0E3HVNFKTA8+PcNkt9v91y5FYkd1M9+Ab1hELoeDomhRP35/My/+eRiQ1Ec5NUJ4t+l
         drZWsJYEEw60dv84k1BJP/1RVXMcyTqVDlsNdyZ71btp066g3l64pysL2y4p5undS34k
         OpIpMJ2h2oUvPW15vaTw4yoWp6RYw4cBuSa4Hk23wFHOG1JSIE2kUAzD1FX0PRCTRgmW
         gTbWKsKnnRv6pU3WY3un37ovYf1ZNTjkuoZMi4POp1j9Sf9H2XKUUpyE3b4kaYqpKE4U
         f6JA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=BXPU2MKM;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d32 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd32.google.com (mail-io1-xd32.google.com. [2607:f8b0:4864:20::d32])
        by gmr-mx.google.com with ESMTPS id f23si1004924qkg.1.2021.12.13.13.59.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Dec 2021 13:59:42 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d32 as permitted sender) client-ip=2607:f8b0:4864:20::d32;
Received: by mail-io1-xd32.google.com with SMTP id p65so20699358iof.3
        for <kasan-dev@googlegroups.com>; Mon, 13 Dec 2021 13:59:42 -0800 (PST)
X-Received: by 2002:a05:6602:2c94:: with SMTP id i20mr967459iow.99.1639432781773;
 Mon, 13 Dec 2021 13:59:41 -0800 (PST)
MIME-Version: 1.0
References: <cover.1639432170.git.andreyknvl@google.com> <bc9f6cb3df24eb076a6d99f91f97820718f3e29e.1639432170.git.andreyknvl@google.com>
In-Reply-To: <bc9f6cb3df24eb076a6d99f91f97820718f3e29e.1639432170.git.andreyknvl@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 13 Dec 2021 22:59:30 +0100
Message-ID: <CA+fCnZcwODsqmzHBXYi7GZWV_4ADCu72S60B7fqQikCHYdTYPQ@mail.gmail.com>
Subject: Re: [PATCH mm v3 23/38] kasan, arm64: reset pointer tags of vmapped stacks
To: Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Will Deacon <will@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, andrey.konovalov@linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=BXPU2MKM;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d32
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

On Mon, Dec 13, 2021 at 10:54 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Once tag-based KASAN modes start tagging vmalloc() allocations,
> kernel stacks start getting tagged if CONFIG_VMAP_STACK is enabled.
>
> Reset the tag of kernel stack pointers after allocation in
> arch_alloc_vmap_stack().
>
> For SW_TAGS KASAN, when CONFIG_KASAN_STACK is enabled, the
> instrumentation can't handle the SP register being tagged.
>
> For HW_TAGS KASAN, there's no instrumentation-related issues. However,
> the impact of having a tagged SP register needs to be properly evaluated,
> so keep it non-tagged for now.
>
> Note, that the memory for the stack allocation still gets tagged to
> catch vmalloc-into-stack out-of-bounds accesses.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
> ---
>
> Changes v2->v3:
> - Add this patch.
> ---
>  arch/arm64/include/asm/vmap_stack.h | 5 ++++-
>  1 file changed, 4 insertions(+), 1 deletion(-)
>
> diff --git a/arch/arm64/include/asm/vmap_stack.h b/arch/arm64/include/asm/vmap_stack.h
> index 894e031b28d2..20873099c035 100644
> --- a/arch/arm64/include/asm/vmap_stack.h
> +++ b/arch/arm64/include/asm/vmap_stack.h
> @@ -17,10 +17,13 @@
>   */
>  static inline unsigned long *arch_alloc_vmap_stack(size_t stack_size, int node)
>  {
> +       void *p;
> +
>         BUILD_BUG_ON(!IS_ENABLED(CONFIG_VMAP_STACK));
>
> -       return __vmalloc_node(stack_size, THREAD_ALIGN, THREADINFO_GFP, node,
> +       p = __vmalloc_node(stack_size, THREAD_ALIGN, THREADINFO_GFP, node,
>                         __builtin_return_address(0));
> +       return kasan_reset_tag(p);
>  }
>
>  #endif /* __ASM_VMAP_STACK_H */
> --
> 2.25.1
>

Catalin, Vincenzo,

This is a new patch added in v3. Could you PTAL? Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcwODsqmzHBXYi7GZWV_4ADCu72S60B7fqQikCHYdTYPQ%40mail.gmail.com.
