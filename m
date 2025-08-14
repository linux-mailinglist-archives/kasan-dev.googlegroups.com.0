Return-Path: <kasan-dev+bncBDW2JDUY5AORBNO46XCAMGQETC36TDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id E37B5B25AA8
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 07:03:50 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-3b9e41037e6sf199744f8f.1
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 22:03:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755147830; cv=pass;
        d=google.com; s=arc-20240605;
        b=aLP/zWXXXE/qjWji+Jrj0gcx0UYnBQFB5Bz+IMF+phofuHrQCVOVQG5nDM/mGwMGXy
         cXpJYDUzkMPSn0H3Rzb4MqDAi1accPkg6oa0CPhpw7J0phllWBRku4TljTtmitnV+2qW
         LZ+GxwO3Zqgukx4tfxvx73DObkAR6ZcONjLrdYXdUJt+5h3300CXK4cLhDMVajWx+dZt
         /iuUDzI36uuGhKbe4IOQg54vf9sn/d+fFiejGDS0zoyKc3XXXNMFT5N42xkGEzK/BgTr
         Qo88IyHYVn75ubcQX8VBev5GpmQJBtYGXXtGngY8JLYxcxEqGlUVi6RLl766gDV+sShf
         mNoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=WPcipAPrnn6SkSrAQLLH+CN1L1H8p+p7loSIWqopK1A=;
        fh=cfPmjo+75FZ2NfgRT9a6U1fEE66qRkAelhGaI/1d9tw=;
        b=ILfuSfWjVar/Gy9mG8/c6n/+ftvuCMlNvkLrNsZ4H3FTraShBigx+737tAJHFLR7LY
         AhtRguc8BAprc3sqvk+b1cCQI/Da/qn7DdrHYiHdd6KSIzmq6nguFFwssuRoHw5SJxPc
         YDGaxJlqjyLf9bS2zevohHWEsOgq9yx0C9XBTL3NSvu8M4D2vVXt/kK2sRx/s8bfQZkv
         oY3af4Bcb1fpoCUzN2UKuf08I++FIkHO4A0V8iBUXk1kopwSKFTx3X+MgKsyf3KZteRG
         EcqOOoTHBvrCTsqBMMQLV4o+EVz5XxaqHRI9FGX2Cw9EbSsz3Novrvt0kjdkKX4pCDBz
         I1xg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=TlhEifBv;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755147830; x=1755752630; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=WPcipAPrnn6SkSrAQLLH+CN1L1H8p+p7loSIWqopK1A=;
        b=GbNt2qej6Xx5+ntlofHYJU/R3y0Ur4bCBSLG1Q9uPtNY2DEdMoSKizC2zmP2Q9ZqHl
         WVVPw86iA+BP3OVIHcSJ9ZplljgTM5QffRTn91SOrVmdvxdXFoZuIsryRyhdDRWP1gri
         Q1eOiwgkozDf+ksmTpSRm7DYdG72qIQeXx+BeL5Us+WQTnvkG1AS/lNV5w1/Zt21GqiM
         Oz5axhXJPWf+kAcUnEek79gR9TGojYS2yzDrUAY3LLkvZ6QJkbfB4Fmku720aGE87pjF
         Mlj2FU2O5Fz/9gWgisFHZhF7SO/yh0IOWMQCWZv9e9YhjhxjojljVs1xhRVJ1soAozEM
         MfwQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1755147830; x=1755752630; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=WPcipAPrnn6SkSrAQLLH+CN1L1H8p+p7loSIWqopK1A=;
        b=hZYT+S29iGeqp55ERQPqc7a861eC1BCD6FcfhTCOAMlOCDbcivKU0/WTR2MWAR5D1n
         F9G1HY1wMZkTrNKq/nwjx09tdvdCckSAMJcuAxCJucS5brrb6KZv88HwUXQrZm2VDdlA
         anTZo4Om1MHAA58WWQlDi4ugex1UgwMmA/t38rHXeQy6VlgDpRuXmdKKUK8XtgTiIS1g
         D2WRYGv2J0eCwN7MvruNcg6aJ6Z6DiwpnO8TA3XlLNE3ySW+6nyKiuISkuuR/QL8NqXn
         3avwSmrxbIqBLSvEKnxplCGfBk2VjSpJ3Nc7YOMstnP4gxG6LAAusBsz72RU3ZMQDPka
         Zhqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755147830; x=1755752630;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=WPcipAPrnn6SkSrAQLLH+CN1L1H8p+p7loSIWqopK1A=;
        b=sx3B6y3kcZbhWxPocqlaPW7LyXPBSbAYVT063hn0zwDfl+EqP3Tc1ZE6xDV6iuO7hh
         EvjmBHyd1tk08WCz07JtGebPaL5h9IdvBuflfUswoHz6X14rji85QrwRuippIMTluxVw
         CXMbBRLetSovNagywR7IDAKwGzbVSRSFQm5dH3DoFGt4i/E2qTWkDgQ6K+3s6RplgtFB
         soZ2ko6Wd+XcKyduEdcCZfy8j7ahmd99sXrTZU4gO9bknTgYm6Z6r01wwSXApE5rKKZ0
         9/06hYg6kZbPPaAnNTsaOZml/9dzhTXpLVIFwQmmworH1AjQC7yvuP+cn8UdOrbZ/Eje
         Ck0Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWBixgFDiVjee2F4qWXSOe1WfF25Q6Hl2LhrQcz9o8YzOsVfTbSBzRewq2Cl1yhdVHkr3pFwQ==@lfdr.de
X-Gm-Message-State: AOJu0YxHLQ7+RNKAVfW9mPGxSwJPwPIb/rM0XhVLLoTN/R2YnHaW4uzP
	PpbX83kHx9KsszxPD92VtpWLrOXu829t7+GHiGv/47ZXRTOI2kihXtn1
X-Google-Smtp-Source: AGHT+IFrJ8fXUJgKfpPCglbNfy5KeI/dBJC1t30W8n2zjj9JzmL32f9YdPa4lPt7nNrmyMKLKPHv3A==
X-Received: by 2002:a05:6000:26c9:b0:3b9:1c62:efb0 with SMTP id ffacd0b85a97d-3b9e4177509mr1090565f8f.17.1755147829779;
        Wed, 13 Aug 2025 22:03:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc5IRfOfjrI+F3DTKbcv/9CWaOQGt5Df+bycemfoy6Ucw==
Received: by 2002:a05:6000:2893:b0:3b7:9282:b6ee with SMTP id
 ffacd0b85a97d-3b9bfe82600ls208191f8f.2.-pod-prod-06-eu; Wed, 13 Aug 2025
 22:03:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW9HgAnrM9JQarLsgVG/3kp8FEZ5NCbDGpE3DVabvVTjrsnt4Dmpe2yoLxs1ax9kgWcwejxBxrzZjM=@googlegroups.com
X-Received: by 2002:a05:6000:2503:b0:3b7:9b4d:70e9 with SMTP id ffacd0b85a97d-3b9edf5b318mr1103804f8f.43.1755147826894;
        Wed, 13 Aug 2025 22:03:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755147826; cv=none;
        d=google.com; s=arc-20240605;
        b=HfrqZpNQi3f3Ak1lu3UigrjiCAijDF77axfDB5HpPNz3K/NiF8LPspsl1V29ngDiwo
         0i0D59bGb9F7+Kx/Ds/zDV92PIo+m+C1KT8ddks+54rDOJtQR0/SAp/g2l358l4j+W5m
         KEbtGJJ5eypOg46SwOH+AEfRqMtuf9fDUkHyXSrJJpL1cnPhweT9geL83DMSZkqgWEWD
         fJ3LDZHWKihH9KblN+7DTKwf66uLE92rt+TTpQswHi+aKw7fTv5nEOY4AQgBhlHNQKYp
         Bygt72H8ro6E3oi8zjUXlg0UtfHbc6ZrL6BirnCkqruQws1O7Sn4dO5jYgqx4SLgbFYK
         5IAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=pW2IKQF7j9mZWFismjJbM7MyE155/GaGBWF52ohr4tg=;
        fh=f13iPGf6/rSQTz2tC3dzIQqzYdy2DqEI/I/KQjY438c=;
        b=Vi+n7wKQsaenI+6Io6dLSCy7NqhMKL7J2IHy0kEf+inbwvOmWMmaZ/PgzFdMPG4fS9
         1eqLNcDfp2vz9pT9RX1ib8Yk2IlO5Xe8KUBrLwOOQpvDSY+I76P1+UQusISvhwID0m8y
         abY5Klaak65vo6ANRLF43dhlZOBq0y/AWH7nCYAtLlJmqeWIRztSrKa0MkWCxHxHNgJR
         EcdK/mwaiBNODYZfovhTWwo6t/uH6lcR+E4P7CP+x9JMlgzwSloafiOFGtwFMCEujOEk
         xEeACJuBFEpRrYHWCO4bc1sDeotNc3BvurkUIqBX/j51wZmOI/C7tTe3fUXZ4pqoZjeg
         uD5A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=TlhEifBv;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x436.google.com (mail-wr1-x436.google.com. [2a00:1450:4864:20::436])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45a1c61a8absi128715e9.0.2025.08.13.22.03.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Aug 2025 22:03:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) client-ip=2a00:1450:4864:20::436;
Received: by mail-wr1-x436.google.com with SMTP id ffacd0b85a97d-3b9df0bffc3so241841f8f.1
        for <kasan-dev@googlegroups.com>; Wed, 13 Aug 2025 22:03:46 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWnIU20PWPC474xJ6zBWhtd9FO1VKzbrEj2IqcvP1qSzuO6r81knfc1QOx5Eqm8MglCeJS5HOFT/50=@googlegroups.com
X-Gm-Gg: ASbGnctb7uWG4crN+yhtqJfpDhPZWOIwR7QJdxpo6Fu3Y/weuC9Wqk0BhZpMvIIoNPd
	2SPb7vQGsnT35VEC3ySchKgNTWzWuswpop/EnXI93W577lcVIQpJzhEPP0wglp+wWlD/pP7rgGh
	8JGySgQRz2T22x8N0eafcK++GR5HuGfVpCOiIUpR5mn0Z4vF9h4HQp3XtzZOsJKgwqA3xjlFkyB
	1brcvPT8w==
X-Received: by 2002:a05:6000:24ca:b0:3a6:d93e:5282 with SMTP id
 ffacd0b85a97d-3b9edf7fdcbmr1203348f8f.59.1755147826108; Wed, 13 Aug 2025
 22:03:46 -0700 (PDT)
MIME-Version: 1.0
References: <20250813175335.3980268-1-yeoreum.yun@arm.com> <20250813175335.3980268-2-yeoreum.yun@arm.com>
In-Reply-To: <20250813175335.3980268-2-yeoreum.yun@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 14 Aug 2025 07:03:35 +0200
X-Gm-Features: Ac12FXxBGO26NYRCWV_AgLObziM7IFpY6wdJZ5x9xu9uGkMLHTUun4-BDhxGOCU
Message-ID: <CA+fCnZd=EQ+5b=rBQ66LkJ3Bz2GrKHvnYk0DQLbs=o9=k0C69g@mail.gmail.com>
Subject: Re: [PATCH v2 1/2] kasan/hw-tags: introduce kasan.store_only option
To: Yeoreum Yun <yeoreum.yun@arm.com>, glider@google.com, Marco Elver <elver@google.com>
Cc: ryabinin.a.a@gmail.com, dvyukov@google.com, vincenzo.frascino@arm.com, 
	corbet@lwn.net, catalin.marinas@arm.com, will@kernel.org, 
	akpm@linux-foundation.org, scott@os.amperecomputing.com, jhubbard@nvidia.com, 
	pankaj.gupta@amd.com, leitao@debian.org, kaleshsingh@google.com, 
	maz@kernel.org, broonie@kernel.org, oliver.upton@linux.dev, 
	james.morse@arm.com, ardb@kernel.org, hardevsinh.palaniya@siliconsignals.io, 
	david@redhat.com, yang@os.amperecomputing.com, kasan-dev@googlegroups.com, 
	workflows@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=TlhEifBv;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436
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

On Wed, Aug 13, 2025 at 7:53=E2=80=AFPM Yeoreum Yun <yeoreum.yun@arm.com> w=
rote:
>
> Since Armv8.9, FEATURE_MTE_STORE_ONLY feature is introduced to restrict
> raise of tag check fault on store operation only.
> Introcude KASAN store only mode based on this feature.
>
> KASAN store only mode restricts KASAN checks operation for store only and
> omits the checks for fetch/read operation when accessing memory.
> So it might be used not only debugging enviroment but also normal
> enviroment to check memory safty.
>
> This features can be controlled with "kasan.store_only" arguments.
> When "kasan.store_only=3Don", KASAN checks store only mode otherwise
> KASAN checks all operations.

I'm thinking if we should name this "kasan.write_only" instead of
"kasan.store_only". This would align the terms with the
"kasan.fault=3Dpanic_on_write" parameter we already have. But then it
would be different from "FEATURE_MTE_STORE_ONLY", which is what Arm
documentation uses (right?).

Marco, Alexander, any opinion?

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
> index 0a1418ab72fd..fcb70dd821ec 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -143,6 +143,9 @@ disabling KASAN altogether or controlling its feature=
s:
>    Asymmetric mode: a bad access is detected synchronously on reads and
>    asynchronously on writes.
>
> +- ``kasan.store_only=3Doff`` or ``kasan.store_only=3Don`` controls wheth=
er KASAN
> +  checks the store (write) accesses only or all accesses (default: ``off=
``)
> +
>  - ``kasan.vmalloc=3Doff`` or ``=3Don`` disables or enables tagging of vm=
alloc
>    allocations (default: ``on``).
>
> diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/mem=
ory.h
> index 5213248e081b..ae29cd3db78d 100644
> --- a/arch/arm64/include/asm/memory.h
> +++ b/arch/arm64/include/asm/memory.h
> @@ -308,6 +308,7 @@ static inline const void *__tag_set(const void *addr,=
 u8 tag)
>  #define arch_enable_tag_checks_sync()          mte_enable_kernel_sync()
>  #define arch_enable_tag_checks_async()         mte_enable_kernel_async()
>  #define arch_enable_tag_checks_asymm()         mte_enable_kernel_asymm()
> +#define arch_enable_tag_checks_store_only()    mte_enable_kernel_store_o=
nly()
>  #define arch_suppress_tag_checks_start()       mte_enable_tco()
>  #define arch_suppress_tag_checks_stop()                mte_disable_tco()
>  #define arch_force_async_tag_fault()           mte_check_tfsr_exit()
> diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/=
mte-kasan.h
> index 2e98028c1965..3e1cc341d47a 100644
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
> +static inline int mte_enable_kenrel_store_only(void)

Typo in the function name. Please build/boot test without MTE/KASAN enabled=
.

> +{
> +       return -EINVAL;
> +}
> +
>  #endif /* CONFIG_ARM64_MTE */
>
>  #endif /* __ASSEMBLY__ */
> diff --git a/arch/arm64/kernel/cpufeature.c b/arch/arm64/kernel/cpufeatur=
e.c
> index 9ad065f15f1d..7b724fcf20a7 100644
> --- a/arch/arm64/kernel/cpufeature.c
> +++ b/arch/arm64/kernel/cpufeature.c
> @@ -2404,6 +2404,11 @@ static void cpu_enable_mte(struct arm64_cpu_capabi=
lities const *cap)
>
>         kasan_init_hw_tags_cpu();
>  }
> +
> +static void cpu_enable_mte_store_only(struct arm64_cpu_capabilities cons=
t *cap)
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
> +               .cpu_enable =3D cpu_enable_mte_store_only,
>                 ARM64_CPUID_FIELDS(ID_AA64PFR2_EL1, MTESTOREONLY, IMP)
>         },
>  #endif /* CONFIG_ARM64_MTE */
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index e5e773844889..8eb1f66f2ccd 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -157,6 +157,20 @@ void mte_enable_kernel_asymm(void)
>                 mte_enable_kernel_sync();
>         }
>  }
> +
> +int mte_enable_kernel_store_only(void)
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
>  #else
>  static inline void kasan_init_hw_tags_cpu(void) { }
>  static inline void kasan_init_hw_tags(void) { }
> +static inline void kasan_late_init_hw_tags_cpu(void) { }
>  #endif
>
>  #ifdef CONFIG_KASAN_VMALLOC
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 9a6927394b54..c2f90c06076e 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -41,9 +41,16 @@ enum kasan_arg_vmalloc {
>         KASAN_ARG_VMALLOC_ON,
>  };
>
> +enum kasan_arg_store_only {
> +       KASAN_ARG_STORE_ONLY_DEFAULT,
> +       KASAN_ARG_STORE_ONLY_OFF,
> +       KASAN_ARG_STORE_ONLY_ON,
> +};
> +
>  static enum kasan_arg kasan_arg __ro_after_init;
>  static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
>  static enum kasan_arg_vmalloc kasan_arg_vmalloc __initdata;
> +static enum kasan_arg_store_only kasan_arg_store_only __ro_after_init;
>
>  /*
>   * Whether KASAN is enabled at all.
> @@ -67,6 +74,9 @@ DEFINE_STATIC_KEY_FALSE(kasan_flag_vmalloc);
>  #endif
>  EXPORT_SYMBOL_GPL(kasan_flag_vmalloc);
>
> +DEFINE_STATIC_KEY_FALSE(kasan_flag_store_only);

Is there a reason to have this as a static key? I think a normal
global bool would work, just as a normal variable works for
kasan_mode.

> +EXPORT_SYMBOL_GPL(kasan_flag_store_only);
> +
>  #define PAGE_ALLOC_SAMPLE_DEFAULT      1
>  #define PAGE_ALLOC_SAMPLE_ORDER_DEFAULT        3
>
> @@ -141,6 +151,23 @@ static int __init early_kasan_flag_vmalloc(char *arg=
)
>  }
>  early_param("kasan.vmalloc", early_kasan_flag_vmalloc);
>
> +/* kasan.store_only=3Doff/on */
> +static int __init early_kasan_flag_store_only(char *arg)
> +{
> +       if (!arg)
> +               return -EINVAL;
> +
> +       if (!strcmp(arg, "off"))
> +               kasan_arg_store_only =3D KASAN_ARG_STORE_ONLY_OFF;
> +       else if (!strcmp(arg, "on"))
> +               kasan_arg_store_only =3D KASAN_ARG_STORE_ONLY_ON;
> +       else
> +               return -EINVAL;
> +
> +       return 0;
> +}
> +early_param("kasan.store_only", early_kasan_flag_store_only);
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

"CPUs"
"brought up"

And please spell-check other comments.

> + * Not marked as __init as a CPU can be hot-plugged after boot.
> + */
> +void kasan_late_init_hw_tags_cpu(void)
> +{
> +       /*
> +        * Enable stonly mode only when explicitly requested through the =
command line.

"store-only"

> +        * If system doesn't support, kasan checks all operation.

"If the system doesn't support this mode, KASAN will check both load
and store operations."

> +        */
> +       kasan_enable_store_only();
> +}
> +
>  /* kasan_init_hw_tags() is called once on boot CPU. */
>  void __init kasan_init_hw_tags(void)
>  {
> @@ -257,15 +298,28 @@ void __init kasan_init_hw_tags(void)
>                 break;
>         }
>
> +       switch (kasan_arg_store_only) {
> +       case KASAN_ARG_STORE_ONLY_DEFAULT:
> +               /* Default is specified by kasan_flag_store_only definiti=
on. */
> +               break;
> +       case KASAN_ARG_STORE_ONLY_OFF:
> +               static_branch_disable(&kasan_flag_store_only);
> +               break;
> +       case KASAN_ARG_STORE_ONLY_ON:
> +               static_branch_enable(&kasan_flag_store_only);
> +               break;
> +       }

Let's move this part to kasan_late_init_hw_tags_cpu. Since that's
where the final decision of whether the store-only mode is enabled is
taken, we should just set the global flag there.

> +
>         kasan_init_tags();
>
>         /* KASAN is now initialized, enable it. */
>         static_branch_enable(&kasan_flag_enabled);
>
> -       pr_info("KernelAddressSanitizer initialized (hw-tags, mode=3D%s, =
vmalloc=3D%s, stacktrace=3D%s)\n",
> +       pr_info("KernelAddressSanitizer initialized (hw-tags, mode=3D%s, =
vmalloc=3D%s, stacktrace=3D%s store_only=3D%s\n",

Let's put "store_only" here next to "mode".

You're also missing a comma.

>                 kasan_mode_info(),
>                 str_on_off(kasan_vmalloc_enabled()),
> -               str_on_off(kasan_stack_collection_enabled()));
> +               str_on_off(kasan_stack_collection_enabled()),
> +               str_on_off(kasan_store_only_enabled()));
>  }
>
>  #ifdef CONFIG_KASAN_VMALLOC
> @@ -394,6 +448,22 @@ void kasan_enable_hw_tags(void)
>                 hw_enable_tag_checks_sync();
>  }
>
> +void kasan_enable_store_only(void)

Do we need this as a separate function? I think we can just move the
code to kasan_late_init_hw_tags_cpu.

> +{
> +       if (kasan_arg_store_only =3D=3D KASAN_ARG_STORE_ONLY_ON) {
> +               if (hw_enable_tag_checks_store_only()) {
> +                       static_branch_disable(&kasan_flag_store_only);
> +                       kasan_arg_store_only =3D KASAN_ARG_STORE_ONLY_OFF=
;
> +                       pr_warn_once("KernelAddressSanitizer: store only =
mode isn't supported (hw-tags)\n");

No need for the "KernelAddressSanitizer" prefix, it's already defined
via pr_fmt().

> +               }
> +       }
> +}
> +
> +bool kasan_store_only_enabled(void)
> +{
> +       return static_branch_unlikely(&kasan_flag_store_only);
> +}
> +
>  #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
>
>  EXPORT_SYMBOL_IF_KUNIT(kasan_enable_hw_tags);
> @@ -404,4 +474,6 @@ VISIBLE_IF_KUNIT void kasan_force_async_fault(void)
>  }
>  EXPORT_SYMBOL_IF_KUNIT(kasan_force_async_fault);
>
> +EXPORT_SYMBOL_IF_KUNIT(kasan_store_only_enabled);
> +
>  #endif
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 129178be5e64..1d853de1c499 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -33,6 +33,7 @@ static inline bool kasan_stack_collection_enabled(void)
>  #include "../slab.h"
>
>  DECLARE_STATIC_KEY_TRUE(kasan_flag_vmalloc);
> +DECLARE_STATIC_KEY_FALSE(kasan_flag_stonly);

kasan_flag_store_only

Did you build test this at all?


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
> +#define hw_enable_tag_checks_store_only()      arch_enable_tag_checks_st=
ore_only()
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
> +void kasan_enable_store_only(void);
> +bool kasan_store_only_enabled(void);
>
>  #else /* CONFIG_KASAN_HW_TAGS */
>
>  static inline void kasan_enable_hw_tags(void) { }
> +static inline void kasan_enable_store_only(void) { }
> +
> +static inline bool kasan_store_only_enabled(void)
> +{
> +       return false;
> +}
>
>  #endif /* CONFIG_KASAN_HW_TAGS */
>
> --
> LEVI:{C3F47F37-75D8-414A-A8BA-3980EC8A46D7}
>
> --
> You received this message because you are subscribed to the Google Groups=
 "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion visit https://groups.google.com/d/msgid/kasan-dev=
/20250813175335.3980268-2-yeoreum.yun%40arm.com.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZd%3DEQ%2B5b%3DrBQ66LkJ3Bz2GrKHvnYk0DQLbs%3Do9%3Dk0C69g%40mail.gmail=
.com.
