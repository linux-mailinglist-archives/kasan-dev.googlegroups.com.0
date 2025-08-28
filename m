Return-Path: <kasan-dev+bncBDW2JDUY5AORBNHRYLCQMGQEMCJVO5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id D03ADB3AB55
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 22:14:45 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-45a1b0071c1sf6526345e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 13:14:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756412085; cv=pass;
        d=google.com; s=arc-20240605;
        b=XcYU+0TJcZKE17SgNmFMqiuOJipWwRFoe+Ml+VtqwdsMbDgNNJ83AJzCCzGBjjV/Q3
         GQqt71pIy8GZzf503yt33ceF0y79kKA3q5+dyaLGztZP/cdmPyLCNBvrgLp7O6k8d99L
         1fM7/JScw7d5YR+gWTlXGbddu8Yoy9pgeyhCZw4tKUolT61vNo0LXlKD4UaPWYn7faYv
         gwGKbCDl144yI3AsqvuXLBpagJIkqPIj3IkrkP79nnRHFbDztZcF43gdaA1HXcBGwRYD
         fpgVVDFa3TahqToRCC3wEQ1oWtF3AcIAiPzg15QsF3e0EHc4C1PkIVG31cuTNyOQV7qz
         4r4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=lC60O9GKafrWe2dUsu9PjvkPDNBEyyHIYh+sS/gXH/4=;
        fh=uyvg1XZ523SU6/bViKKWg0Ag0a/ptFsJm6pr0Ev9CeA=;
        b=NfE0oHidx1g4z0ejWwhNm0RM6fq6Hn8ZLj6B2N8aBSFoSKyqYVP/mw78bxZqQ0S/cS
         gSNhe5RXVlV51U79zg+uRiZpNcEHfUypn+Vhrsb47l/aTY9cQzb6P/sGsbXB9/62I629
         xRWMU4Q7qnHN7jGv7cAEkEWoiqM998RMtfMdeLyT42v5Fv78eS0Py+TXSykogo8OvSQs
         A3ReCEw/BpzlqvzNP2AIKlsZRWDq0pbrp5v+mhxD3nqkkRfGUKWDN23KCZnpWFR0F55o
         r8ASM2STOkVq4Gq+m+aKWdaRAxtX0A9GMbeFLzttPvqXnwRv7CzYY5K7ULDRLGkqRzFE
         lBNA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lwxYEFmr;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756412085; x=1757016885; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=lC60O9GKafrWe2dUsu9PjvkPDNBEyyHIYh+sS/gXH/4=;
        b=oyeaWbTtRsLXzYhEHWo9l3Du+ZdOWyTGLpeBERrM8YGPukloqeIOmxR1Hq60YmMtBA
         rSHYu/SxkyiX+D5CIlOi3yENUhnPkN+vRKjRlQW8+KxwaPlCPvbePtETTeO3cneUG//z
         RGs8AKqIg4SzBNW1bRnykP0gbs6pdXVsOjEI+96Q+yQo+Y2MPvGIg7iSNvMgXI3yGupo
         +O9ARBmaSTvniZmaluO0DKuHp5Ug+KGGAffN4UDoPTTlfL7rRJRg2OhuLvQzLGKsptsb
         DwBfXf2fsIdlIzV73PMYkDQtqO/tYaQ6tsb68saGhqNSI7v0l60dNp1c2VCaP8nbyDbZ
         p5dA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756412085; x=1757016885; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=lC60O9GKafrWe2dUsu9PjvkPDNBEyyHIYh+sS/gXH/4=;
        b=GNC5w14SAqc5LkRtW8Sdl6GNgYqX1wzCDJ9c+jI+42DZ81478XYEsbsLd1cQj8XI/v
         iVtVGbH8/F5TMmQkVjObRpC1FUjQY/Mbo/fJIoGWsu/Ir0a5VnJcuGPbLq6InYcPTPcE
         lwceLAzFaQFmh+zzeLmeojzvJwQlizoud3VAbzk2LsrOG/25ZXk6uXr5cool0nfHM/Ps
         nszgigPBT3DSQbE9MPZR/3HMAsprg4T9M2/AGmYOTTVQop9bvfZMnUdEDD/iTspTEk7W
         9s9swl+dPhpjNFPoaMBNN7JcPE2D7AnAlIfO5TawOtfPEioQ9fpP6xQWF+bPJFc6esRr
         VPHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756412085; x=1757016885;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=lC60O9GKafrWe2dUsu9PjvkPDNBEyyHIYh+sS/gXH/4=;
        b=ayZZSQ+Ba21YTowqktgXx9CS9WixMhQp+KmAOzWF8rfs8Yq+urABVLIV2z84GgWtIc
         T2+rwP9rbq0RTHjly+ammYH2P7XWViQ7gaJQ6ZHCNt6sS8LEbBG/DsevNipcroPZwlnK
         YE00Liwxit4bp7q7teY3sTJjEAQc5NtZzEE/xpxl/syCNmkydKwwtd1ik6FVtImGtbtD
         RHoHUo8hLrJL1QSb/5WnweRNv9YHWGR3BKrTR50ltHNHJF3jdlBHzV6hZ4Lk+wOATWJ9
         jFgQ6Rds+VbVouTBHbUbtJ3Xia9itrin0/oZSorRtAO7ML53vmLGEzg8JbHzVxtrjDTc
         gYuA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWuvmVoL/7nXJw9VxcNr0vuRJQTdeHcqt9N9g/xTC+4naaLVJ3qeGTDx7jsZPXWi5esp3fOLw==@lfdr.de
X-Gm-Message-State: AOJu0Yx+PAegcKiSqoVYwA0m5hMmfRaLJqM+MXYjEpYrrfIwC68pEu1L
	/aThh6xwFf7bDsWQ4rtMvHe+x1TCTlB1Nl154lVOpZjaZsFyeog9OySN
X-Google-Smtp-Source: AGHT+IHwpYpcj4PhSlX6lWcu6OdIJMl6hDbYHGpFgAl8jf3O32dy12YEQDYv7SE/KRBROju4grb3kA==
X-Received: by 2002:a05:6000:4387:b0:3b9:7c1f:86b1 with SMTP id ffacd0b85a97d-3c5dc731447mr17888504f8f.37.1756412084793;
        Thu, 28 Aug 2025 13:14:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdfKwFfeYTaowWEosTZMZamaGhCFHUiP+ujdYpvuRxcFQ==
Received: by 2002:a05:6000:2005:b0:3b7:8a12:d1ef with SMTP id
 ffacd0b85a97d-3cde269d5aels633379f8f.1.-pod-prod-06-eu; Thu, 28 Aug 2025
 13:14:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW3o9/ZNpXvpHvjFYQtF3UUwdW1JyNAmgbhAka+NnRFWtrYMZVVLmpkEIArHyfJgV/XS87gnd6d/XI=@googlegroups.com
X-Received: by 2002:a05:6000:18a6:b0:3cb:3490:6ba5 with SMTP id ffacd0b85a97d-3cb34906f9amr6867347f8f.9.1756412082050;
        Thu, 28 Aug 2025 13:14:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756412082; cv=none;
        d=google.com; s=arc-20240605;
        b=k5ZzOUe32xZazNGk+1l0Ir+Gf8j1W52DmZdF7ugaV5wTIs/DWDYhiMvSmPmhjQWOj2
         YTD0iBviLudgCb2B5FOa4xvJLVMWb8t38MLVifBSU6DZo/pmZ3QZs0WCdV8gRX02iooZ
         CMBvaQ8+chpEXbiINOnPg1fb99DNGWVDD/IdLGT5ToVnpgIk8QGD2lkw/fLt8pDwaV6s
         UVDH/uR5GOPTZICDzYuonUNXyX0jIpRdGQB8Agny6+bbDTCKjN97N2z+dhByi5uU+UD3
         MVk9IAUiNnW2s/2NZu/+ZTZoxB7Zry/UHMMRvXTwo2UB9YTqKy8p8R2ST/RsJ8NRo1XR
         u1Ew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=1gnvrp+Bx3ZYJFKBzNh94mqis3ow5fvVnk0m91vI1jw=;
        fh=32MrhURxuBaS0V29PsNK7lLzEHV4yM4WEw4spALPEoE=;
        b=gvVm7/83aMmEROgYpy+vzBTpD6df6cK+LuTKwqc0YeGOvaMASZ3PXLAexV2KApk055
         Xx9bF/QBatJ2bkYcDDEkrbOcnTb7XCvVP4EELQi+1EH80pHXUYFyDpX/LYi0h30dZcIh
         IlMdLbIvt5kgthol/CRJ8HKmECGKD7xgQ1NKOoNlVeUyX79/Tr2X+CL8oDY66d5Vkzv7
         KGlvp5Dylz5duKqI1ZVTNm8xuch0yFYERqIaHWJ0m9+wGdbnfkvFDrAfkGQmDNy6Gbbf
         wnniTCbpNUnrzfThGbiFXtkEF97zh3urMRicTUfFajjIX1ob0fBN0ligYXKUJ+zWeNiQ
         DQhQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lwxYEFmr;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x335.google.com (mail-wm1-x335.google.com. [2a00:1450:4864:20::335])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3cf26c281f7si10197f8f.1.2025.08.28.13.14.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 28 Aug 2025 13:14:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::335 as permitted sender) client-ip=2a00:1450:4864:20::335;
Received: by mail-wm1-x335.google.com with SMTP id 5b1f17b1804b1-45a1b05ac1eso7412325e9.1
        for <kasan-dev@googlegroups.com>; Thu, 28 Aug 2025 13:14:42 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXz42xe0M8G3wRl0o0o7NKU6KvBS09g734s19N1dFSTv4J675SsdT6kbk6yHO7OH5u8nCJ/SdSRqF0=@googlegroups.com
X-Gm-Gg: ASbGncvRAhiqlGxcA8obusnmDzo5O0m8pkwr/gFQ5MlvDNCuEziQqv4FjqwfAr/EPIu
	qGaKyZTu9FmtiGzAeFarlkLWVTbL8iyRHK8Vyu6HXyBIT2+RWDLCnuZuEEa4TTliCJRusHAJ9Pw
	OXx+6yLtdw5MAFmOXR5/Uif/mMr7dLWUieRGh3CJ4G0egDwYyOuR8NNnxgGEGqJJYAD8HdvIZGv
	I4i/HIu1z4DtynDncxl0nU9rKpezCk=
X-Received: by 2002:a05:600c:4683:b0:458:bfb1:1fc7 with SMTP id
 5b1f17b1804b1-45b5179cc59mr217845785e9.6.1756412081217; Thu, 28 Aug 2025
 13:14:41 -0700 (PDT)
MIME-Version: 1.0
References: <20250820071243.1567338-1-yeoreum.yun@arm.com> <20250820071243.1567338-2-yeoreum.yun@arm.com>
In-Reply-To: <20250820071243.1567338-2-yeoreum.yun@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 28 Aug 2025 22:14:29 +0200
X-Gm-Features: Ac12FXyhL3jNKGMqxsJ0nOjlFtUtP70OOH_yRbqkrkgUfzCeogdUcj5xo329MPY
Message-ID: <CA+fCnZfv6G19P=bWqEUpbA36E9zaHBqDBZyDYV5YnMuAX1zGug@mail.gmail.com>
Subject: Re: [PATCH v5 1/2] kasan/hw-tags: introduce kasan.write_only option
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
 header.i=@gmail.com header.s=20230601 header.b=lwxYEFmr;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::335
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

On Wed, Aug 20, 2025 at 9:12=E2=80=AFAM Yeoreum Yun <yeoreum.yun@arm.com> w=
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
>  arch/arm64/include/asm/mte-kasan.h |  6 +++
>  arch/arm64/kernel/cpufeature.c     |  2 +-
>  arch/arm64/kernel/mte.c            | 18 ++++++++
>  mm/kasan/hw_tags.c                 | 70 +++++++++++++++++++++++++++++-
>  mm/kasan/kasan.h                   |  7 +++
>  7 files changed, 104 insertions(+), 3 deletions(-)
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

Nit: a dot missing at the end of the sentence.

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
> index e5e773844889..54a52dc5c1ae 100644
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
> +       pr_info_once("MTE: enabled store only mode at EL1\n");
> +
> +       return 0;
> +}
>  #endif
>
>  #ifdef CONFIG_KASAN_HW_TAGS
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 9a6927394b54..334e9e84983e 100644
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
> @@ -67,6 +74,9 @@ DEFINE_STATIC_KEY_FALSE(kasan_flag_vmalloc);
>  #endif
>  EXPORT_SYMBOL_GPL(kasan_flag_vmalloc);
>
> +/* Whether to check write access only. */

Nit: access =3D> accesses

> +static bool kasan_flag_write_only =3D false;
> +
>  #define PAGE_ALLOC_SAMPLE_DEFAULT      1
>  #define PAGE_ALLOC_SAMPLE_ORDER_DEFAULT        3
>
> @@ -141,6 +151,23 @@ static int __init early_kasan_flag_vmalloc(char *arg=
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
> @@ -257,15 +284,28 @@ void __init kasan_init_hw_tags(void)
>                 break;
>         }
>
> +       switch (kasan_arg_write_only) {
> +       case KASAN_ARG_WRITE_ONLY_DEFAULT:
> +               /* Default is specified by kasan_flag_write_only definiti=
on. */
> +               break;
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
> @@ -392,6 +432,26 @@ void kasan_enable_hw_tags(void)
>                 hw_enable_tag_checks_asymm();
>         else
>                 hw_enable_tag_checks_sync();
> +
> +       /*
> +        * CPUs can only be in one of two states:
> +        *   - All CPUs support the write_only feature
> +        *   - No CPUs support the write_only feature
> +        *
> +        * If the first CPU attempts hw_enable_tag_checks_write_only() an=
d
> +        * finds the feature unsupported, kasan_arg_write_only is set to =
OFF
> +        * to avoid further unnecessary calls on other CPUs.
> +        *
> +        * Although this could be tracked with a single variable, both
> +        * kasan_arg_write_only (boot argument) and kasan_flag_write_only
> +        * (hardware state) are kept separate, consistent with other opti=
ons.
> +        */
> +       if (kasan_arg_write_only =3D=3D KASAN_ARG_WRITE_ONLY_ON &&
> +           hw_enable_tag_checks_write_only()) {
> +               kasan_arg_write_only =3D KASAN_ARG_WRITE_ONLY_OFF;
> +               kasan_flag_write_only =3D false;
> +               pr_err_once("write-only mode is not supported and thus no=
t enabled\n");
> +       }
>  }
>
>  #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
> @@ -404,4 +464,10 @@ VISIBLE_IF_KUNIT void kasan_force_async_fault(void)
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
> index 129178be5e64..844eedf2ef9c 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -431,6 +431,7 @@ static inline const void *arch_kasan_set_tag(const vo=
id *addr, u8 tag)
>  #define hw_suppress_tag_checks_start()         arch_suppress_tag_checks_=
start()
>  #define hw_suppress_tag_checks_stop()          arch_suppress_tag_checks_=
stop()
>  #define hw_force_async_tag_fault()             arch_force_async_tag_faul=
t()
> +#define hw_enable_tag_checks_write_only()      arch_enable_tag_checks_wr=
ite_only()
>  #define hw_get_random_tag()                    arch_get_random_tag()
>  #define hw_get_mem_tag(addr)                   arch_get_mem_tag(addr)
>  #define hw_set_mem_tag_range(addr, size, tag, init) \
> @@ -451,11 +452,17 @@ void __init kasan_init_tags(void);
>  #if defined(CONFIG_KASAN_HW_TAGS) && IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
>
>  void kasan_force_async_fault(void);
> +bool kasan_write_only_enabled(void);
>
>  #else /* CONFIG_KASAN_HW_TAGS && CONFIG_KASAN_KUNIT_TEST */
>
>  static inline void kasan_force_async_fault(void) { }
>
> +static inline bool kasan_write_only_enabled(void)
> +{
> +       return false;
> +}
> +
>  #endif /* CONFIG_KASAN_HW_TAGS && CONFIG_KASAN_KUNIT_TEST */
>
>  #ifdef CONFIG_KASAN_SW_TAGS
> --
> LEVI:{C3F47F37-75D8-414A-A8BA-3980EC8A46D7}
>

For the KASAN parts:

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZfv6G19P%3DbWqEUpbA36E9zaHBqDBZyDYV5YnMuAX1zGug%40mail.gmail.com.
