Return-Path: <kasan-dev+bncBDW2JDUY5AORBJPQRPCQMGQEFFXMZKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7238AB29E73
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 11:53:43 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id ffacd0b85a97d-3b9d41cec2csf3318999f8f.0
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 02:53:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755510823; cv=pass;
        d=google.com; s=arc-20240605;
        b=Oycku/8UosxjPRVLq4iJ0S6mM9H9UGzKCLnotCC4oY6XtKLs/lPVBvcx8tULEb9Juk
         KdIkAjM1bBio+uieI3su064tGctvZQO/uOBTIgFIm2Bt0jiIxBYGm5Vmcw7AJVHx4tLQ
         tiBkV+FqStkxGfxLx86e9dVD3HOEiLZhANJcocR/EdfuXomLErqPFhOAdY49W7mW0mXT
         JS5/n8aQBGd55wXqL2DTVhYAibPnf1qQ0qA9yGkcQMLyvj2aMdG3DBBm7cJd4d4FsXQv
         R7/SZ6uTr+/zjBPM1VoHJhaksUI4/RSn26s+/1CVkw35zY2Escalk92PpqJmR6NV6jiA
         4Eng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=KpyhwrRTs+Q/15TZ/sYRu38rF091r1V4Y/kuuxqnykg=;
        fh=IJ9SUMmrlQcxIR/VILDF1drevCGvWFEI8tPh/12s8Ms=;
        b=kkcZCgcGXHXW6E8VnLKIzaFB2j9mGtpwnLIPjR0DuVbTSGvb9PeUEBdSiGWTG4t5pn
         Rveu3wZPlEfzHxU93IEFGs2kIts2b6VMFOBNadvBKRPlPN93Oh4fiV0YjLYifPTZaOBG
         /+1lNbbBVQTwc9vQd1EJHrGQNrSmMy3S94fQtMjUvPBrvVjJoyO/eyLjhGyhXcZHmWpL
         +DIpds2DBJ24SPizoo3T57ba+XKrJ9C4FPD9KY1uWpdQEaRvrBKl8MtmyiidRQrwk/GG
         +kQy3dzqBfuaicowkGVS6fGZVz+FplAqtRSezGnMVGvQj0ZxSApmx/ydV6aYcUT51Sy2
         k/dg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=BLddTIYL;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755510823; x=1756115623; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=KpyhwrRTs+Q/15TZ/sYRu38rF091r1V4Y/kuuxqnykg=;
        b=Xzyf0slG48qm4dKt813Qv1AFQIBBefTUab0lMv9G9AvbYhHMAZyu4wVr+bW+jwwgKw
         CdDUmG/mdxlb6bXQRAZeeU4+/yIuaINwcCK97pp8V5Xvp2sE4xalBaWR23tBAdYPIM7F
         NrsrmUOwHt5eqzMWAquxVOZiCWN19kCEfb++SWaPbSo4WNCMDsBDE/YzvwqPRzdX5QU2
         NJLhq+tCMiMOCUZfYtlrplARtx3S37rFZdqGmi42UmDkHXj++qz2USJU749bzfZEbekd
         lmBiIjwDEIpe92FmYlIGMwHJUjdi2EptKhilPXh7Cmnv3A15RlxhxzDtvPkPeO7atzgC
         HMVg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1755510823; x=1756115623; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=KpyhwrRTs+Q/15TZ/sYRu38rF091r1V4Y/kuuxqnykg=;
        b=dUDIHLaNM7FcnlOnhSJXJlupgJHj56Q0HpslwnZ64l7EOXTgwDvs1cRmB+jZ6faojG
         BhaHC7SgBLqQiY5JnzF1ObS4MUcKo5l1JGLPQ+nKMBk1j90WdJOeLFH0Q1nhU/eS9LwE
         mt8oDdWmcdmMvtYyMnebOmWCtfcgFMPa4tKwMADnDfDWKlZ+TCzGKiixCed/RBMYALmn
         CcZ8NGh4FrNveheIMbbgCoa8HZBeN/PbfSZrIVi8ban2yb8unFExImNvFQtTrM+WEpId
         KZ7KDE43b6N40dHpO8OgAllerXm2Z/HaX26lLylBoJJqxLGvoc789JorTq+XXsrm1Vwl
         eECA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755510823; x=1756115623;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=KpyhwrRTs+Q/15TZ/sYRu38rF091r1V4Y/kuuxqnykg=;
        b=c8gl8DZdXsie8YZNSq/oPV2pjPBHpx4jRODUAnGruONm7+Q0HrzncVajygEHgh/HH6
         mRCc7q1psZfEGiU0Y4ISwANIktJml2Vti8NPTSCTDsFvFtkC3fURgmCspEe75KiOj5kj
         ocQ2/bGCbbBrxEWKgB0PXw9Pp/YpvUxt7W3E5c1As+4XVfltCFdFgabQZ+UzDIxlQvP8
         4wWAXdema9L2lUvqVpcadl9tjyBnn4E/2dYbly/WKJ//jV0pnaUQgShXDSr1PkOX3Xes
         W4UBVuA/dytWThQE3ITCbMfXV63Cw0GKPKk0sVsuj7uXlq66+ZAVc5PeJKlWUOeDq6BN
         3ejA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUbXoJMlIEwvPBUzxw0QJhG6FDZDOr1C53SYWgg8zEHMNVBBaz2rbQiOmEI3wTyFUBe1JaL1Q==@lfdr.de
X-Gm-Message-State: AOJu0YwI+xvlG8F6UIwaTB41kCrIs8BSeGmNS/sGtYLrX2GSW6s8kfkh
	XhtEtJ89HUxbLcHxLy4JrU2iMExWz8AroGGrXp7BXG36FP8pSupFVR85
X-Google-Smtp-Source: AGHT+IEW1ZbmeaVcZzDrXCfgLqXrHfd/z3iaXQYvmehe9dE/0Ljrk3BugLtvCwsKMWbQmjUJ5yUGKA==
X-Received: by 2002:a05:6000:250c:b0:3b7:8473:31c3 with SMTP id ffacd0b85a97d-3bb6646e10amr8293281f8f.9.1755510822550;
        Mon, 18 Aug 2025 02:53:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcCOEBjJVUpkF7c6V1AlBFju2wtsCkMIl+VSykSrfIY7w==
Received: by 2002:a05:600c:1c10:b0:459:e761:bc87 with SMTP id
 5b1f17b1804b1-45a1f963dfdls17388425e9.0.-pod-prod-02-eu; Mon, 18 Aug 2025
 02:53:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVJx7F6uwxt2TJQx6KVJ3+Xk8flpFCAOT+2aKJPHvk5BH/2Q165DBIlk+ht+x7yovbfwqdjTzLn65U=@googlegroups.com
X-Received: by 2002:a05:600c:4fc5:b0:459:dd16:ddde with SMTP id 5b1f17b1804b1-45a218497b7mr68233725e9.23.1755510820025;
        Mon, 18 Aug 2025 02:53:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755510820; cv=none;
        d=google.com; s=arc-20240605;
        b=dOWjZWiKEo0EW0RvQUqncCfWeKmNo+1KDvYsAnD54VABd5jXr+P4JpFDNscCxFErHY
         EKmlS4wl/b3Z0ZW0mKF4vzbvamP2HnoT1KQ4RKrV9OQOGCqLcqreno0E+3/ZKQH1tdSi
         ClmwIbDoOYWu1z5qE4KgavLiJQ9BXT81zMEdX7RpYb6lUiHKnC8O0CjaSDL4dJoyMtW8
         aZ4LCMcime5/2kCoAwVYS5vwTaSGeE+1xZolni3Q1mwwr2EGDP2onnatIbrphCDx/ONb
         dCEo4EBoe8UuJeNF+wsUViEDScv9fsuEZkGBqy4OBNbNS07RT13Q1hNLLhw8ZeI6JzDx
         eC3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=7aUrhtA5C8N8LDrztESsi6kkNfyVuogrllyu5DxXOhU=;
        fh=LjXWt9DhNY8P8yd7Udlrx4MJKXvuZpnuS6PP7j20tOI=;
        b=iA3tUojSoZh2Qc1BsXN6g6irJdC+AFuLLfuOKhtdvVkgaPknrAZHShzlqRTCzc0p5z
         eapRO0aVV6SOUXDS9sV4qZtVjYqoucXExZ7Y1kFOAyKTdEcVV2cpmAw1tX4aGWZXUJsI
         ikbnIewljeP0q8sLy1GcQzZ7iApv5HVbqgmIGeJG3kkurEqsVnt8yaW0hNA4y4amReAG
         S9Hf9NMVmMMdquiqUWuIH3JBudRigVHNL4NA4bDIyYdDLyx22UkXpsF9BWtUQc95vFe3
         dea4dkz7loQHjXBwcWKX4k6C9Hl7k3Pt5J6QswWzb35a4QXatGaLBNxmBiXY2wah7Y4o
         V3yg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=BLddTIYL;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42e.google.com (mail-wr1-x42e.google.com. [2a00:1450:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3bb61de4249si109821f8f.4.2025.08.18.02.53.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 18 Aug 2025 02:53:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) client-ip=2a00:1450:4864:20::42e;
Received: by mail-wr1-x42e.google.com with SMTP id ffacd0b85a97d-3b9edf4cf6cso3708296f8f.3
        for <kasan-dev@googlegroups.com>; Mon, 18 Aug 2025 02:53:39 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU1Il4sjmCpqCzleccjtdxSu4feRml/wBRlTA5VyM+iALhtZOIj3JDnyeZMzdjUgb75tQRONvoaN64=@googlegroups.com
X-Gm-Gg: ASbGncuW9hl9MBlS7tR5g5NvsVyBV28NWBmd4wkNLPhZKj5k+du7u2/GU+xALo8sZ3e
	2tl2FrJwVX2MnTyDSYazxs1S8gKoCX+KJZsWzvVbq2ZCaJ3g0NEAkIAvOha4hfA8Vsjv0IPwt1J
	Cg9bgYDq+ILqpLa2YamRkajjBiw6xHEzkvWESIzWVSUvIfApfuLlQ29e4Uf7cW+IXlW68eeU5nF
	VL+KDzYoA==
X-Received: by 2002:a05:6000:2382:b0:3b7:664a:8416 with SMTP id
 ffacd0b85a97d-3bb672ef363mr7732028f8f.23.1755510819196; Mon, 18 Aug 2025
 02:53:39 -0700 (PDT)
MIME-Version: 1.0
References: <20250818075051.996764-1-yeoreum.yun@arm.com> <20250818075051.996764-2-yeoreum.yun@arm.com>
In-Reply-To: <20250818075051.996764-2-yeoreum.yun@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 18 Aug 2025 11:53:26 +0200
X-Gm-Features: Ac12FXzRBfgg3LizE0EW60Q0iO4G5vgy9DjWhPtH5IcEjjDvGoLaCnutYA-AZ-c
Message-ID: <CA+fCnZcce88Sj=oAe-cwydu7Ums=wk2Ps=JZkz0RwO-M_DjfVQ@mail.gmail.com>
Subject: Re: [PATCH v4 1/2] kasan/hw-tags: introduce kasan.write_only option
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
 header.i=@gmail.com header.s=20230601 header.b=BLddTIYL;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e
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

On Mon, Aug 18, 2025 at 9:51=E2=80=AFAM Yeoreum Yun <yeoreum.yun@arm.com> w=
rote:
>
> Since Armv8.9, FEATURE_MTE_STORE_ONLY feature is introduced to restrict
> raise of tag check fault on store operation only.
> Introcude KASAN write only mode based on this feature.
>
> KASAN write only mode restricts KASAN checks operation for write only and
> omits the checks for fetch/read operations when accessing memory.
> So it might be used not only debugging enviroment but also normal
> enviroment to check memory safty.
>
> This features can be controlled with "kasan.write_only" arguments.
> When "kasan.write_only=3Don", KASAN checks write operation only otherwise
> KASAN checks all operations.
>
> This changes the MTE_STORE_ONLY feature as BOOT_CPU_FEATURE like
> ARM64_MTE_ASYMM so that makes it initialise in kasan_init_hw_tags()
> with other function together.
>
> Signed-off-by: Yeoreum Yun <yeoreum.yun@arm.com>
> ---
>  Documentation/dev-tools/kasan.rst  |  3 ++
>  arch/arm64/include/asm/memory.h    |  1 +
>  arch/arm64/include/asm/mte-kasan.h |  6 ++++
>  arch/arm64/kernel/cpufeature.c     |  2 +-
>  arch/arm64/kernel/mte.c            | 18 ++++++++++
>  mm/kasan/hw_tags.c                 | 54 ++++++++++++++++++++++++++++--
>  mm/kasan/kasan.h                   |  7 ++++
>  7 files changed, 88 insertions(+), 3 deletions(-)
>
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/=
kasan.rst
> index 0a1418ab72fd..fe1a1e152275 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -143,6 +143,9 @@ disabling KASAN altogether or controlling its feature=
s:
>    Asymmetric mode: a bad access is detected synchronously on reads and
>    asynchronously on writes.
>
> +- ``kasan.write_only=3Doff`` or ``kasan.write_only=3Don`` controls wheth=
er KASAN
> +  checks the write (store) accesses only or all accesses (default: ``off=
``)
> +
>  - ``kasan.vmalloc=3Doff`` or ``=3Don`` disables or enables tagging of vm=
alloc
>    allocations (default: ``on``).
>
> diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/mem=
ory.h
> index 5213248e081b..f1505c4acb38 100644
> --- a/arch/arm64/include/asm/memory.h
> +++ b/arch/arm64/include/asm/memory.h
> @@ -308,6 +308,7 @@ static inline const void *__tag_set(const void *addr,=
 u8 tag)
>  #define arch_enable_tag_checks_sync()          mte_enable_kernel_sync()
>  #define arch_enable_tag_checks_async()         mte_enable_kernel_async()
>  #define arch_enable_tag_checks_asymm()         mte_enable_kernel_asymm()
> +#define arch_enable_tag_checks_write_only()    mte_enable_kernel_store_o=
nly()
>  #define arch_suppress_tag_checks_start()       mte_enable_tco()
>  #define arch_suppress_tag_checks_stop()                mte_disable_tco()
>  #define arch_force_async_tag_fault()           mte_check_tfsr_exit()
> diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/=
mte-kasan.h
> index 2e98028c1965..0f9b08e8fb8d 100644
> --- a/arch/arm64/include/asm/mte-kasan.h
> +++ b/arch/arm64/include/asm/mte-kasan.h
> @@ -200,6 +200,7 @@ static inline void mte_set_mem_tag_range(void *addr, =
size_t size, u8 tag,
>  void mte_enable_kernel_sync(void);
>  void mte_enable_kernel_async(void);
>  void mte_enable_kernel_asymm(void);
> +int mte_enable_kernel_store_only(void);
>
>  #else /* CONFIG_ARM64_MTE */
>
> @@ -251,6 +252,11 @@ static inline void mte_enable_kernel_asymm(void)
>  {
>  }
>
> +static inline int mte_enable_kernel_store_only(void)
> +{
> +       return -EINVAL;
> +}
> +
>  #endif /* CONFIG_ARM64_MTE */
>
>  #endif /* __ASSEMBLY__ */
> diff --git a/arch/arm64/kernel/cpufeature.c b/arch/arm64/kernel/cpufeatur=
e.c
> index 9ad065f15f1d..505bd56e21a2 100644
> --- a/arch/arm64/kernel/cpufeature.c
> +++ b/arch/arm64/kernel/cpufeature.c
> @@ -2920,7 +2920,7 @@ static const struct arm64_cpu_capabilities arm64_fe=
atures[] =3D {
>         {
>                 .desc =3D "Store Only MTE Tag Check",
>                 .capability =3D ARM64_MTE_STORE_ONLY,
> -               .type =3D ARM64_CPUCAP_SYSTEM_FEATURE,
> +               .type =3D ARM64_CPUCAP_BOOT_CPU_FEATURE,
>                 .matches =3D has_cpuid_feature,
>                 ARM64_CPUID_FIELDS(ID_AA64PFR2_EL1, MTESTOREONLY, IMP)
>         },
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index e5e773844889..cd5452eb7486 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -157,6 +157,24 @@ void mte_enable_kernel_asymm(void)
>                 mte_enable_kernel_sync();
>         }
>  }
> +
> +int mte_enable_kernel_store_only(void)
> +{
> +       /*
> +        * If the CPU does not support MTE store only,
> +        * the kernel checks all operations.
> +        */
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
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 9a6927394b54..df67b48739b4 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -41,9 +41,16 @@ enum kasan_arg_vmalloc {
>         KASAN_ARG_VMALLOC_ON,
>  };
>
> +enum kasan_arg_write_only {
> +       KASAN_ARG_WRITE_ONLY_DEFAULT,
> +       KASAN_ARG_WRITE_ONLY_OFF,
> +       KASAN_ARG_WRITE_ONLY_ON,
> +};
> +
>  static enum kasan_arg kasan_arg __ro_after_init;
>  static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
>  static enum kasan_arg_vmalloc kasan_arg_vmalloc __initdata;
> +static enum kasan_arg_write_only kasan_arg_write_only __ro_after_init;
>
>  /*
>   * Whether KASAN is enabled at all.
> @@ -67,6 +74,8 @@ DEFINE_STATIC_KEY_FALSE(kasan_flag_vmalloc);
>  #endif
>  EXPORT_SYMBOL_GPL(kasan_flag_vmalloc);
>
> +static bool kasan_flag_write_only;
> +
>  #define PAGE_ALLOC_SAMPLE_DEFAULT      1
>  #define PAGE_ALLOC_SAMPLE_ORDER_DEFAULT        3
>
> @@ -141,6 +150,23 @@ static int __init early_kasan_flag_vmalloc(char *arg=
)
>  }
>  early_param("kasan.vmalloc", early_kasan_flag_vmalloc);
>
> +/* kasan.write_only=3Doff/on */
> +static int __init early_kasan_flag_write_only(char *arg)
> +{
> +       if (!arg)
> +               return -EINVAL;
> +
> +       if (!strcmp(arg, "off"))
> +               kasan_arg_write_only =3D KASAN_ARG_WRITE_ONLY_OFF;
> +       else if (!strcmp(arg, "on"))
> +               kasan_arg_write_only =3D KASAN_ARG_WRITE_ONLY_ON;
> +       else
> +               return -EINVAL;
> +
> +       return 0;
> +}
> +early_param("kasan.write_only", early_kasan_flag_write_only);
> +
>  static inline const char *kasan_mode_info(void)
>  {
>         if (kasan_mode =3D=3D KASAN_MODE_ASYNC)
> @@ -257,15 +283,26 @@ void __init kasan_init_hw_tags(void)
>                 break;
>         }
>
> +       switch (kasan_arg_write_only) {
> +       case KASAN_ARG_WRITE_ONLY_DEFAULT:

Let's keep this part similar to the other parameters for consistency:

/* Default is specified by kasan_flag_write_only definition. */
break;

> +       case KASAN_ARG_WRITE_ONLY_OFF:
> +               kasan_flag_write_only =3D false;
> +               break;
> +       case KASAN_ARG_WRITE_ONLY_ON:
> +               kasan_flag_write_only =3D true;
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
vmalloc=3D%s, stacktrace=3D%s, write_only=3D%s\n",
>                 kasan_mode_info(),
>                 str_on_off(kasan_vmalloc_enabled()),
> -               str_on_off(kasan_stack_collection_enabled()));
> +               str_on_off(kasan_stack_collection_enabled()),
> +               str_on_off(kasan_arg_write_only));
>  }
>
>  #ifdef CONFIG_KASAN_VMALLOC
> @@ -392,6 +429,13 @@ void kasan_enable_hw_tags(void)
>                 hw_enable_tag_checks_asymm();
>         else
>                 hw_enable_tag_checks_sync();
> +
> +       if (kasan_arg_write_only =3D=3D KASAN_ARG_WRITE_ONLY_ON &&

We already set kasan_flag_write_only by this point, right? Let's check
that one then.

> +           hw_enable_tag_checks_write_only()) {
> +               kasan_arg_write_only =3D=3D KASAN_ARG_WRITE_ONLY_OFF;

Typo in =3D=3D in the line above. But also I think we can just drop the
line: kasan_arg_write_only is KASAN_ARG_WRITE_ONLY_ON after all, it's
just not supported and thus kasan_flag_write_only is set to false to
reflect that.

> +               kasan_flag_write_only =3D false;
> +               pr_warn_once("System doesn't support write-only option. D=
isable it\n");

Let's do pr_err like the rest of KASAN code. And:

pr_err_once("write-only mode is not supported and thus not enabled\n");



> +       }
>  }
>
>  #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
> @@ -404,4 +448,10 @@ VISIBLE_IF_KUNIT void kasan_force_async_fault(void)
>  }
>  EXPORT_SYMBOL_IF_KUNIT(kasan_force_async_fault);
>
> +VISIBLE_IF_KUNIT bool kasan_write_only_enabled(void)
> +{
> +       return kasan_flag_write_only;
> +}
> +EXPORT_SYMBOL_IF_KUNIT(kasan_write_only_enabled);
> +
>  #endif
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 129178be5e64..c1490136c96b 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -428,6 +428,7 @@ static inline const void *arch_kasan_set_tag(const vo=
id *addr, u8 tag)
>  #define hw_enable_tag_checks_sync()            arch_enable_tag_checks_sy=
nc()
>  #define hw_enable_tag_checks_async()           arch_enable_tag_checks_as=
ync()
>  #define hw_enable_tag_checks_asymm()           arch_enable_tag_checks_as=
ymm()
> +#define hw_enable_tag_checks_write_only()      arch_enable_tag_checks_wr=
ite_only()
>  #define hw_suppress_tag_checks_start()         arch_suppress_tag_checks_=
start()
>  #define hw_suppress_tag_checks_stop()          arch_suppress_tag_checks_=
stop()
>  #define hw_force_async_tag_fault()             arch_force_async_tag_faul=
t()
> @@ -437,11 +438,17 @@ static inline const void *arch_kasan_set_tag(const =
void *addr, u8 tag)
>                         arch_set_mem_tag_range((addr), (size), (tag), (in=
it))
>
>  void kasan_enable_hw_tags(void);
> +bool kasan_write_only_enabled(void);

This should go next to kasan_force_async_fault().

>
>  #else /* CONFIG_KASAN_HW_TAGS */
>
>  static inline void kasan_enable_hw_tags(void) { }
>
> +static inline bool kasan_write_only_enabled(void)
> +{
> +       return false;
> +}

And this too.


> +
>  #endif /* CONFIG_KASAN_HW_TAGS */
>
>  #if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
> --
> LEVI:{C3F47F37-75D8-414A-A8BA-3980EC8A46D7}
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZcce88Sj%3DoAe-cwydu7Ums%3Dwk2Ps%3DJZkz0RwO-M_DjfVQ%40mail.gmail.com=
.
