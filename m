Return-Path: <kasan-dev+bncBDW2JDUY5AORB4GV5XCAMGQEKM64ARI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id DAFC1B22D5E
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 18:25:21 +0200 (CEST)
Received: by mail-ed1-x53d.google.com with SMTP id 4fb4d7f45d1cf-61812f3dcadsf2488086a12.2
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 09:25:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755015921; cv=pass;
        d=google.com; s=arc-20240605;
        b=cm/v9t3Dn34reGJzf1EJ+Qza+17+uHQLOjC0RgxbS0c53XFQylO5AOLOtTrWiSmiHN
         02XwFZdCj2bxPlXTqhhBwpTCRcIR8Pj342STNSelupGR7UCbWPHcrDiOSswbrOkNOubs
         qRfbRMmaInaNaBntqSrPUqqmbFuQmBd0kG+olwXLP/yo+h/0QGkDxBebWyj0W3ROCGz6
         bFa3TYEjgqWhOYJq3xDjiQSfcoq37FE05vDKtWxDj2hjwLqf6PPwtDJ2aRwfQ7VoZNMd
         L5ts6FqdjbttG8oeUeJa6/OaUTPUchtb447Kj0OIuNaIb5+fO/DWRIUZ5+6E0IAup2po
         AD9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=wZ5eGYgNKs4KdAAVbjfGbBRpWeyrrjzs4YrcfCotSbc=;
        fh=XU72s+K6qbkkUjVcBm8jsfZy7Y2lyajBKyRt70s/O3Y=;
        b=T0Hh3abAqDeympVm30tGavjxBCvnafgiDXv7RKN5xWYCRcJ6poUiVhmskcrUtJy5aF
         PPxWYOZf8zJninxP4xey6HtVCfdP0TKdn+QzV9ru30o1Fx2NOjEdgESRzivl5L4M5SFs
         HW5Nn+SIPL3Yoc21z+lnuDbClha+0d+ZMCcH2dmqVK65VCz5ofix5W21pJMfBKnbOSu9
         Ex5w+HXTbXQIl+KhmChaS2HwiRrI5PfO9HYuatZwRA7RHpJ2N3hrBA5qHzn7p+wn9ZiC
         /0zWWAkHI649rqixqsQFCt291u4wpcjsFUiQd0ZBVx0WqZTZHSJGN3z8vhXFRcSOruLY
         QGKA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="HXv2hZ/s";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755015921; x=1755620721; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=wZ5eGYgNKs4KdAAVbjfGbBRpWeyrrjzs4YrcfCotSbc=;
        b=myQ3FwhuPuj7HRHz992shokVLmtD49MQqPMbgSiU9mVQQ45ybRNlD8zJcp3fT8tu6S
         ZLScTQ5ak+4KLdDBxzeqR4IcG7WNmpDD+yPzhRKTPEx80hx0+1dXbFMErTgvrn3radUD
         BvrREr0V+pYUv0b8KOprvq/Y+j0PNcUjCG+8hMxGKuZ2tlhD4LDrs9ZVWbsapEegLhv+
         taGkdxZGCUjpshJ4DcyY439SWTZnU6bL6ytDBbCEY8F91y/lSvPkMqaC0lef0bedlFW0
         Sy0YAYUJcjJh2ZCfAJz/4PnUXi7D6rACIv9ikhlwjxI0+ViWCJefE7R7IwJXi/8qXMyk
         Wivg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1755015921; x=1755620721; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wZ5eGYgNKs4KdAAVbjfGbBRpWeyrrjzs4YrcfCotSbc=;
        b=FHxqtBpVVDJ4/v/l81m+rjoGLu7BAXBOQOX0UuLV/T7XNTUAvBRrGUrFsbxXppTfGT
         OfuKQhaw/w0cN/0NE3+7E932MdL08piwKPweTR8DCb3trtRCyHNfUTYd5VTygl2z5YNa
         VtRXszh3LxfkPE1WQUHEyli0DjnQ6eRzyFqFXdOfQkuqHHEjr8W/WaJlnt1IuuBQ+3Nb
         wYvc2ErccXG4MRF9zvmCEdbujBGPhoRDWPU513ffddxYdIBSW360CvWTHVJFTBhz2ypm
         3i3cLOVp20U8A9iLIZCOdd4hNCXkdtp7RIkA2U2pOU85Q8Q8CQi4EfJ6LSrx115xC11K
         IksA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755015921; x=1755620721;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=wZ5eGYgNKs4KdAAVbjfGbBRpWeyrrjzs4YrcfCotSbc=;
        b=p86tc0TmyqmxC2YnLaqRa6e5zfHthLPvQ2lWvl11gM3A4yjpS6yHAQCySpycXiqHQC
         y39XkplZTubMN8790WdS+sqLDd2yZtaufcSyzjmut4+Ww/I7i1cHTEpyVeETgpZQ2u+R
         6QLVimmYRjnQiATygXKhBUe/4tNcpz2gIMRQGHcuSXsXrkLi9CjtiUWsqN8i2/kvcIWC
         BaoFoR79zKHzN3K98hH/qZGeBqWPILRs5HkYGsrgjzL3+KqLa61xv0Pccj3F8tRmkwn3
         Orn95fwrLuoOoUTXdU9sBuMSBPlciEysNxOTtSY8uLZlzGcppdQI1mqUWT16wPWlKMP2
         8VmA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXUjKZVZmrBN0++LMm/9u7Ufpd0Njz2tDAYNsYBHLBm4LVOEKIewSeW1Hzh792qZLwh6Vhz9g==@lfdr.de
X-Gm-Message-State: AOJu0Yy0nSt60gDhbxXwAltCao8aGRLWvpUCmRdp+nUFRNeYANo9OMRi
	kobImr0At/BVL23li22LexOeMo/92L47yAU0rnGmg97LxCGH68VbKpKB
X-Google-Smtp-Source: AGHT+IFHWeP5wfxUd9jbDyHca9ilfbReLr/fHaQ282154S/MVwgVSwL9PXtT/H3ImHyQCMG8xbupSQ==
X-Received: by 2002:a50:d506:0:b0:618:1cc6:8e75 with SMTP id 4fb4d7f45d1cf-618672522f2mr282915a12.14.1755015920774;
        Tue, 12 Aug 2025 09:25:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZevEivJWdzIoMfOXiqDE1dPFj9v7+mO2ZxMwSCbKbX00w==
Received: by 2002:a05:6402:1d53:b0:60c:44d6:282c with SMTP id
 4fb4d7f45d1cf-617b1cde85bls4290478a12.1.-pod-prod-04-eu; Tue, 12 Aug 2025
 09:25:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUlMkwpqoZiAh8rqSppJYHuBi2AIucEehmSLzrBHXo/I3klHt5x6BTSOBvNyNAwYgqaXiYOhAn3LrI=@googlegroups.com
X-Received: by 2002:a17:907:6d21:b0:afc:a331:ba2e with SMTP id a640c23a62f3a-afca397a85emr34592566b.24.1755015917974;
        Tue, 12 Aug 2025 09:25:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755015917; cv=none;
        d=google.com; s=arc-20240605;
        b=ijTY31UHFA6mHesJjrNk+koGDIKW28mB58ahZFEkxBfH6M+sDaRQycKbQySiLBPZAX
         4Cc3y+fjebObAT5Ha/RqtjyzdMz/1Yrjn5WkYM0KguhCn2+eTKPaU1WBQ59vm6kr27Bd
         1Ii0vv+lGZa3q/QPTI61KGCuBfE/7t2lQLqKqbjO8B+nOL+8u14FBiBp6Besi98JXGcx
         RqMqd+tBpKG6AsLoYcP5dv8PyqWlzaEcMHNbKuvsOlU0Ve9SFa4q+G4BDg9K8qn+LjhM
         PkDDcYB21JgBAo+mGnsnJ6Hp32FHR902ShALVbtV+aPNk1RcxgjCLWJFHzdhcOD+oqLd
         mCRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=l54bXCSQ2N1WCwc3yA5CAnPI3s4L8oTQr7q8YqSeHxE=;
        fh=5kg6q9RoexwyqP8rTk3LykEy74j24wu/yd/cjKcQUh4=;
        b=EiDrsM+qZKEa++eJWYPmeFm0z27bpNYC1mYKSLiRjS7UVNBahKusouCvHbUFoHz/t7
         LQiKJvzmmvKEc2oFU5jELw8Xdr7BuWoDSjqTkZF6/8KoF1FSa+EjNCZVBD6WI4CIfOI2
         ueoHswGT6heyYtOecyPDdIVp079DnDS4ALkcgX9gwv7Tl+BcMTQAyStkSX4LIjNA1vzU
         PdBagumLnPgKmhB7KvtlFnqKOsOsHKe6JXNAwotk0CxuRmKtkxBhQGFG56/0c3xpNk/x
         sqHv2BeOAlseOe/MX5F6yOtbXihfwY7Uu66r/D705N0VgYFgXnyjAlIwM1gnqxkWiECp
         hVrg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="HXv2hZ/s";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x330.google.com (mail-wm1-x330.google.com. [2a00:1450:4864:20::330])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-af91a0f4b9esi73251866b.2.2025.08.12.09.25.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Aug 2025 09:25:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::330 as permitted sender) client-ip=2a00:1450:4864:20::330;
Received: by mail-wm1-x330.google.com with SMTP id 5b1f17b1804b1-458aee6e86aso37882705e9.3
        for <kasan-dev@googlegroups.com>; Tue, 12 Aug 2025 09:25:17 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWzsfW1V89Xe6XmEnmQLhVXYs6P3qgxlc/KAnN+v49MJwFdQ1DEbyJrDBKc1vtHxb/1nFlKTnc8dG4=@googlegroups.com
X-Gm-Gg: ASbGncuj1YymawNYjnz1t/v9IFExf9BW67/j5hsLah9DWTQSZJt7s5hoelBja/+Rmkm
	XQGQShGVgD4AoY98Ob4iQnL86819JrkTBUvv8MSSDytfD4lDaokfcgWgCB1zPppDqMIstAEHom1
	a7ie/e9wnD3aaPx3E9OSHH4630kzyymvIJ09eD5eWR9ICkT4kR/q5Hr333Xa4ixuwCy+QmhaZP0
	P862APbbg==
X-Received: by 2002:a05:600c:4692:b0:456:475b:7af6 with SMTP id
 5b1f17b1804b1-45a15b0bf05mr4355835e9.7.1755015917114; Tue, 12 Aug 2025
 09:25:17 -0700 (PDT)
MIME-Version: 1.0
References: <20250811173626.1878783-1-yeoreum.yun@arm.com> <20250811173626.1878783-2-yeoreum.yun@arm.com>
In-Reply-To: <20250811173626.1878783-2-yeoreum.yun@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 12 Aug 2025 18:25:03 +0200
X-Gm-Features: Ac12FXyXZGDJqhGX1iCy4SWWpZA7ZwLA8x1I9FgM3lq8ZOVHVmywuvVz0HAZZV0
Message-ID: <CA+fCnZe6F9dn8qGbNsgWXkQ_3e8oSQ80sd3X=aHFa-AUy_7kjg@mail.gmail.com>
Subject: Re: [PATCH 1/2] kasan/hw-tags: introduce store only mode
To: Yeoreum Yun <yeoreum.yun@arm.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, dvyukov@google.com, 
	vincenzo.frascino@arm.com, corbet@lwn.net, catalin.marinas@arm.com, 
	will@kernel.org, akpm@linux-foundation.org, scott@os.amperecomputing.com, 
	jhubbard@nvidia.com, pankaj.gupta@amd.com, leitao@debian.org, 
	kaleshsingh@google.com, maz@kernel.org, broonie@kernel.org, 
	oliver.upton@linux.dev, james.morse@arm.com, ardb@kernel.org, 
	hardevsinh.palaniya@siliconsignals.io, david@redhat.com, 
	yang@os.amperecomputing.com, kasan-dev@googlegroups.com, 
	workflows@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="HXv2hZ/s";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::330
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Mon, Aug 11, 2025 at 7:36=E2=80=AFPM Yeoreum Yun <yeoreum.yun@arm.com> w=
rote:
>
> Since Armv8.9, FEATURE_MTE_STORE_ONLY feature is introduced to restrict
> raise of tag check fault on store operation only.

To clarify: this feature is independent on the sync/async/asymm modes?
So any mode can be used together with FEATURE_MTE_STORE_ONLY?

> Introcude KASAN store only mode based on this feature.
>
> KASAN store only mode restricts KASAN checks operation for store only and
> omits the checks for fetch/read operation when accessing memory.
> So it might be used not only debugging enviroment but also normal
> enviroment to check memory safty.
>
> This features can be controlled with "kasan.stonly" arguments.
> When "kasan.stonly=3Don", KASAN checks store only mode otherwise
> KASAN checks all operations.

"stonly" looks cryptic, how about "kasan.store_only"?

Also, are there any existing/planned modes/extensions of the feature?
E.g. read only? Knowing this will allow to better plan the
command-line parameter format.

>
> Signed-off-by: Yeoreum Yun <yeoreum.yun@arm.com>
> ---
>  Documentation/dev-tools/kasan.rst  |  3 ++
>  arch/arm64/include/asm/memory.h    |  1 +
>  arch/arm64/include/asm/mte-kasan.h |  6 +++
>  arch/arm64/kernel/cpufeature.c     |  6 +++
>  arch/arm64/kernel/mte.c            | 14 ++++++
>  include/linux/kasan.h              |  2 +
>  mm/kasan/hw_tags.c                 | 76 +++++++++++++++++++++++++++++-
>  mm/kasan/kasan.h                   | 10 ++++
>  8 files changed, 116 insertions(+), 2 deletions(-)
>
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/=
kasan.rst
> index 0a1418ab72fd..7567a2ca0e39 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -163,6 +163,9 @@ disabling KASAN altogether or controlling its feature=
s:
>    This parameter is intended to allow sampling only large page_alloc
>    allocations, which is the biggest source of the performance overhead.
>
> +- ``kasan.stonly=3Doff`` or ``kasan.stonly=3Don`` controls whether KASAN=
 checks
> +  store operation only or all operation.

How about:

``kasan.store_only=3Doff`` or ``=3Don`` controls whether KASAN checks only
the store (write) accesses only or all accesses (default: ``off``).

And let's put this next to kasan.mode, as the new parameter is related.

> +
>  Error reports
>  ~~~~~~~~~~~~~
>
> diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/mem=
ory.h
> index 5213248e081b..9d8c72c9c91f 100644
> --- a/arch/arm64/include/asm/memory.h
> +++ b/arch/arm64/include/asm/memory.h
> @@ -308,6 +308,7 @@ static inline const void *__tag_set(const void *addr,=
 u8 tag)
>  #define arch_enable_tag_checks_sync()          mte_enable_kernel_sync()
>  #define arch_enable_tag_checks_async()         mte_enable_kernel_async()
>  #define arch_enable_tag_checks_asymm()         mte_enable_kernel_asymm()
> +#define arch_enable_tag_checks_stonly()        mte_enable_kernel_stonly(=
)
>  #define arch_suppress_tag_checks_start()       mte_enable_tco()
>  #define arch_suppress_tag_checks_stop()                mte_disable_tco()
>  #define arch_force_async_tag_fault()           mte_check_tfsr_exit()
> diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/=
mte-kasan.h
> index 2e98028c1965..d75908ed9d0f 100644
> --- a/arch/arm64/include/asm/mte-kasan.h
> +++ b/arch/arm64/include/asm/mte-kasan.h
> @@ -200,6 +200,7 @@ static inline void mte_set_mem_tag_range(void *addr, =
size_t size, u8 tag,
>  void mte_enable_kernel_sync(void);
>  void mte_enable_kernel_async(void);
>  void mte_enable_kernel_asymm(void);
> +int mte_enable_kernel_stonly(void);
>
>  #else /* CONFIG_ARM64_MTE */
>
> @@ -251,6 +252,11 @@ static inline void mte_enable_kernel_asymm(void)
>  {
>  }
>
> +static inline int mte_enable_kenrel_stonly(void)
> +{
> +       return -EINVAL;
> +}
> +
>  #endif /* CONFIG_ARM64_MTE */
>
>  #endif /* __ASSEMBLY__ */
> diff --git a/arch/arm64/kernel/cpufeature.c b/arch/arm64/kernel/cpufeatur=
e.c
> index 9ad065f15f1d..fdc510fe0187 100644
> --- a/arch/arm64/kernel/cpufeature.c
> +++ b/arch/arm64/kernel/cpufeature.c
> @@ -2404,6 +2404,11 @@ static void cpu_enable_mte(struct arm64_cpu_capabi=
lities const *cap)
>
>         kasan_init_hw_tags_cpu();
>  }
> +
> +static void cpu_enable_mte_stonly(struct arm64_cpu_capabilities const *c=
ap)
> +{
> +       kasan_late_init_hw_tags_cpu();
> +}
>  #endif /* CONFIG_ARM64_MTE */
>
>  static void user_feature_fixup(void)
> @@ -2922,6 +2927,7 @@ static const struct arm64_cpu_capabilities arm64_fe=
atures[] =3D {
>                 .capability =3D ARM64_MTE_STORE_ONLY,
>                 .type =3D ARM64_CPUCAP_SYSTEM_FEATURE,
>                 .matches =3D has_cpuid_feature,
> +               .cpu_enable =3D cpu_enable_mte_stonly,
>                 ARM64_CPUID_FIELDS(ID_AA64PFR2_EL1, MTESTOREONLY, IMP)
>         },
>  #endif /* CONFIG_ARM64_MTE */
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index e5e773844889..a1cb2a8a79a1 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -157,6 +157,20 @@ void mte_enable_kernel_asymm(void)
>                 mte_enable_kernel_sync();
>         }
>  }
> +
> +int mte_enable_kernel_stonly(void)
> +{
> +       if (!cpus_have_cap(ARM64_MTE_STORE_ONLY))
> +               return -EINVAL;
> +
> +       sysreg_clear_set(sctlr_el1, SCTLR_EL1_TCSO_MASK,
> +                        SYS_FIELD_PREP(SCTLR_EL1, TCSO, 1));
> +       isb();
> +
> +       pr_info_once("MTE: enabled stonly mode at EL1\n");
> +
> +       return 0;
> +}
>  #endif
>
>  #ifdef CONFIG_KASAN_HW_TAGS
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 890011071f2b..28951b29c593 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -552,9 +552,11 @@ static inline void kasan_init_sw_tags(void) { }
>  #ifdef CONFIG_KASAN_HW_TAGS
>  void kasan_init_hw_tags_cpu(void);
>  void __init kasan_init_hw_tags(void);
> +void kasan_late_init_hw_tags_cpu(void);

Why do we need a separate late init function? Can we not enable
store-only at the same place where we enable async/asymm?


>  #else
>  static inline void kasan_init_hw_tags_cpu(void) { }
>  static inline void kasan_init_hw_tags(void) { }
> +static inline void kasan_late_init_hw_tags_cpu(void) { }
>  #endif
>
>  #ifdef CONFIG_KASAN_VMALLOC
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 9a6927394b54..2caa6fe5ed47 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -41,9 +41,16 @@ enum kasan_arg_vmalloc {
>         KASAN_ARG_VMALLOC_ON,
>  };
>
> +enum kasan_arg_stonly {
> +       KASAN_ARG_STONLY_DEFAULT,
> +       KASAN_ARG_STONLY_OFF,
> +       KASAN_ARG_STONLY_ON,
> +};
> +
>  static enum kasan_arg kasan_arg __ro_after_init;
>  static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
>  static enum kasan_arg_vmalloc kasan_arg_vmalloc __initdata;
> +static enum kasan_arg_stonly kasan_arg_stonly __ro_after_init;
>
>  /*
>   * Whether KASAN is enabled at all.
> @@ -67,6 +74,9 @@ DEFINE_STATIC_KEY_FALSE(kasan_flag_vmalloc);
>  #endif
>  EXPORT_SYMBOL_GPL(kasan_flag_vmalloc);
>
> +DEFINE_STATIC_KEY_FALSE(kasan_flag_stonly);
> +EXPORT_SYMBOL_GPL(kasan_flag_stonly);
> +
>  #define PAGE_ALLOC_SAMPLE_DEFAULT      1
>  #define PAGE_ALLOC_SAMPLE_ORDER_DEFAULT        3
>
> @@ -141,6 +151,23 @@ static int __init early_kasan_flag_vmalloc(char *arg=
)
>  }
>  early_param("kasan.vmalloc", early_kasan_flag_vmalloc);
>
> +/* kasan.stonly=3Doff/on */
> +static int __init early_kasan_flag_stonly(char *arg)
> +{
> +       if (!arg)
> +               return -EINVAL;
> +
> +       if (!strcmp(arg, "off"))
> +               kasan_arg_stonly =3D KASAN_ARG_STONLY_OFF;
> +       else if (!strcmp(arg, "on"))
> +               kasan_arg_stonly =3D KASAN_ARG_STONLY_ON;
> +       else
> +               return -EINVAL;
> +
> +       return 0;
> +}
> +early_param("kasan.stonly", early_kasan_flag_stonly);
> +
>  static inline const char *kasan_mode_info(void)
>  {
>         if (kasan_mode =3D=3D KASAN_MODE_ASYNC)
> @@ -219,6 +246,20 @@ void kasan_init_hw_tags_cpu(void)
>         kasan_enable_hw_tags();
>  }
>
> +/*
> + * kasan_late_init_hw_tags_cpu_post() is called for each CPU after
> + * all cpus are bring-up at boot.
> + * Not marked as __init as a CPU can be hot-plugged after boot.
> + */
> +void kasan_late_init_hw_tags_cpu(void)
> +{
> +       /*
> +        * Enable stonly mode only when explicitly requested through the =
command line.
> +        * If system doesn't support, kasan checks all operation.
> +        */
> +       kasan_enable_stonly();
> +}
> +
>  /* kasan_init_hw_tags() is called once on boot CPU. */
>  void __init kasan_init_hw_tags(void)
>  {
> @@ -257,15 +298,28 @@ void __init kasan_init_hw_tags(void)
>                 break;
>         }
>
> +       switch (kasan_arg_stonly) {
> +       case KASAN_ARG_STONLY_DEFAULT:
> +               /* Default is specified by kasan_flag_stonly definition. =
*/
> +               break;
> +       case KASAN_ARG_STONLY_OFF:
> +               static_branch_disable(&kasan_flag_stonly);
> +               break;
> +       case KASAN_ARG_STONLY_ON:
> +               static_branch_enable(&kasan_flag_stonly);
> +               break;
> +       }
> +
>         kasan_init_tags();
>
>         /* KASAN is now initialized, enable it. */
>         static_branch_enable(&kasan_flag_enabled);
>
> -       pr_info("KernelAddressSanitizer initialized (hw-tags, mode=3D%s, =
vmalloc=3D%s, stacktrace=3D%s)\n",
> +       pr_info("KernelAddressSanitizer initialized (hw-tags, mode=3D%s, =
vmalloc=3D%s, stacktrace=3D%s stonly=3D%s\n",
>                 kasan_mode_info(),
>                 str_on_off(kasan_vmalloc_enabled()),
> -               str_on_off(kasan_stack_collection_enabled()));
> +               str_on_off(kasan_stack_collection_enabled()),
> +               str_on_off(kasan_stonly_enabled()));
>  }
>
>  #ifdef CONFIG_KASAN_VMALLOC
> @@ -394,6 +448,22 @@ void kasan_enable_hw_tags(void)
>                 hw_enable_tag_checks_sync();
>  }
>
> +void kasan_enable_stonly(void)
> +{
> +       if (kasan_arg_stonly =3D=3D KASAN_ARG_STONLY_ON) {
> +               if (hw_enable_tag_checks_stonly()) {
> +                       static_branch_disable(&kasan_flag_stonly);
> +                       kasan_arg_stonly =3D KASAN_ARG_STONLY_OFF;
> +                       pr_warn_once("KernelAddressSanitizer: store only =
mode isn't supported (hw-tags)\n");
> +               }
> +       }
> +}
> +
> +bool kasan_stonly_enabled(void)
> +{
> +       return static_branch_unlikely(&kasan_flag_stonly);
> +}
> +
>  #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
>
>  EXPORT_SYMBOL_IF_KUNIT(kasan_enable_hw_tags);
> @@ -404,4 +474,6 @@ VISIBLE_IF_KUNIT void kasan_force_async_fault(void)
>  }
>  EXPORT_SYMBOL_IF_KUNIT(kasan_force_async_fault);
>
> +EXPORT_SYMBOL_IF_KUNIT(kasan_stonly_enabled);
> +
>  #endif
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 129178be5e64..cfbcebdbcbec 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -33,6 +33,7 @@ static inline bool kasan_stack_collection_enabled(void)
>  #include "../slab.h"
>
>  DECLARE_STATIC_KEY_TRUE(kasan_flag_vmalloc);
> +DECLARE_STATIC_KEY_FALSE(kasan_flag_stonly);
>
>  enum kasan_mode {
>         KASAN_MODE_SYNC,
> @@ -428,6 +429,7 @@ static inline const void *arch_kasan_set_tag(const vo=
id *addr, u8 tag)
>  #define hw_enable_tag_checks_sync()            arch_enable_tag_checks_sy=
nc()
>  #define hw_enable_tag_checks_async()           arch_enable_tag_checks_as=
ync()
>  #define hw_enable_tag_checks_asymm()           arch_enable_tag_checks_as=
ymm()
> +#define hw_enable_tag_checks_stonly()          arch_enable_tag_checks_st=
only()
>  #define hw_suppress_tag_checks_start()         arch_suppress_tag_checks_=
start()
>  #define hw_suppress_tag_checks_stop()          arch_suppress_tag_checks_=
stop()
>  #define hw_force_async_tag_fault()             arch_force_async_tag_faul=
t()
> @@ -437,10 +439,18 @@ static inline const void *arch_kasan_set_tag(const =
void *addr, u8 tag)
>                         arch_set_mem_tag_range((addr), (size), (tag), (in=
it))
>
>  void kasan_enable_hw_tags(void);
> +void kasan_enable_stonly(void);
> +bool kasan_stonly_enabled(void);
>
>  #else /* CONFIG_KASAN_HW_TAGS */
>
>  static inline void kasan_enable_hw_tags(void) { }
> +static inline void kasan_enable_stonly(void) { }
> +
> +static inline bool kasan_stonly_enabled(void)
> +{
> +       return false;
> +}
>
>  #endif /* CONFIG_KASAN_HW_TAGS */
>
> --
> LEVI:{C3F47F37-75D8-414A-A8BA-3980EC8A46D7}
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZe6F9dn8qGbNsgWXkQ_3e8oSQ80sd3X%3DaHFa-AUy_7kjg%40mail.gmail.com.
