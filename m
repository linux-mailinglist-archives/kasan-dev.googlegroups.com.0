Return-Path: <kasan-dev+bncBDW2JDUY5AORBDMSZPDAMGQEX6RZ72Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9EE68B96CC8
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 18:21:35 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-46dee484548sf13050545e9.2
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 09:21:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758644495; cv=pass;
        d=google.com; s=arc-20240605;
        b=iRRDzHAtMH/cZxcdftvid0ud+QS3gSxvdTshusUEDOgq9UylIGzSKiNgahsDxtH0W8
         6vf7DA8mBLv6D0pvmMjI38FI461VxWOXJK5VYlnseoKiB8JR8FWklwzsPsQxXpEYjZgQ
         78XwUUYPfuvsl4I0R78AaPrs/c/zMNXFpuKSsjAxuhoMNoplGvCHBj2zLWBJVyUhe67O
         TeTTvLgMxwfTShqbn6j6CWWC1zcF+47VSOb02dGmdg1H/6mmrbVDB0nGbcrhAalf2oFy
         tXlyVGFiWch2+6MguXJ8sk3DjXpbAA0xu20s+uTaEcjQaTbEN4Fbpql735QbOPezWPHT
         L39A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=NGGfWzDEKlGZqiga4ewsQOcb1EWjZNGYOO0071N1+OI=;
        fh=lZ953CoqBUcPV79LGjl2xwSF2x8eC3mFSHWwsSoR1X0=;
        b=brtwYWmmr3SKFcehj8gkNPQ1wnCR18gK6eE2hFw2bThKgSFx6APnvC8/KXvAYp1K25
         JheWuaoaFTynyWBmnMwoJlEBCVGnleOxTCRcHYHlLlVfi41icuPHoqhlInXTeVB5WDsU
         M7BsKQ3JFwZGQqLfx6HJuAEdgd+xRT+X3lxlKF81tcs1AfgzMSy6wnkuSFSuOHDYLVxv
         LHETQDbQ84qxJnnLEBTMAgt7EiMWNF0oAB16BfctyyxQsvGQ2bhq30tsGs2FR/ufNrUY
         Od2vL5WTJOX2bUXr7MCh58eaRpRjXKHzSR4Xk/bQ2Oxodjb7R9J8sH6cBFHBswELO5OD
         ejOA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=TPrkJXOm;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758644495; x=1759249295; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=NGGfWzDEKlGZqiga4ewsQOcb1EWjZNGYOO0071N1+OI=;
        b=DEFnK8n+TiOx+NzYSmW/Og2bFaCvqfWCQ3a8W1j0JfMfPyKascZWyQN6SKReRBFION
         1FtlUGNHArD4Bh3xySatFyiN6s04XC2YoVy/XLCXHWg2TySfUg/bLOkKGP6N/Nn5Gx5F
         7Sivc0rz4F8slRe1v4FPtHDsOD+JGkG1HETbg52z1wqaerYXhyu9dF+2g2hPL95JY1Qn
         eUrHQa+1hISyn17PRnHtEAiwgTIvW7a9x2e4WTX54K939c0cu4R2jnK05XYr3ISj3CdN
         AmoxKHWU5wYMG3LwR+QZOHWijSSlv5dwTXYdEoadNwVV0hCcUhMUEVZwbYf+x3/MxWYp
         XqDQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758644495; x=1759249295; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=NGGfWzDEKlGZqiga4ewsQOcb1EWjZNGYOO0071N1+OI=;
        b=KelxC5Ovrg+RQzcLMBHDvO0ec3bnVQ139vIh3p/zD0eM4y/GcsJU4C7LIL85I07HX3
         od6tuQGGz465PILoC0tDmFIqejqLO2GOVfcgjY0od+InVopTLqBVYKwScKeF+6Ojr8cc
         ICS+xRspoDKxGsjBCs9KiTx7GdK8k5vZHFh+cEf3xqIWDqkqz4GSVTNeecsDC2t3Tw61
         8UHw2Opz8gq2tJKIKyCpGwzDPLPfEPUeJLFbdNZIaFcxzrTN6L7AXFn+ih2+xztgMacG
         Q5Z/9L803MfKTVYk6RuLuk8dJHmjuMH0MBn4EeHNWXZIFF2+PPmRZ6cRGC4OYASOmmlG
         9t1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758644495; x=1759249295;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=NGGfWzDEKlGZqiga4ewsQOcb1EWjZNGYOO0071N1+OI=;
        b=GPOFRTq8wwHgd2wrkJXyPNnRZYiJ7aItPaYTu2xF/fg2sEY6HJThQsIpUnlwV4P7Hm
         SM2x2fDmu/WOBNGpcLt13YSDYtkF3PHEa74IvhFA7o9R3ARx1seECqnWYH9M5syzWXsd
         4fQNUt+BIj96J42ZAwbEcFWOxJHJdRdde++U/4apD9FYABBcIb0KQDInHUju//OA9zeJ
         mslIIdKkShAifuzm8hsuA25yUJdh6e/JOSuVMGm3R1vGZ59Y7zx9VxnrVWZKdWXRtXMu
         JCYTCNAoeGRHZcfzL1POj4Nv8kmR7TWB4Xl4R/+351u/1BjuXl2NTyje9mSVgP5Av9ao
         677g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUc4g8H29XkbuA5NkRd6BtfPYVSE0hWKMwaz5l7bPi42dNUTDgaCukKQkA2Mr7ygeF+GTwKtQ==@lfdr.de
X-Gm-Message-State: AOJu0YxXrjmNmek1n2kCN1o3y4ienb/nhidDELhgFoYz1Xq0+bHzUx1x
	ihS8/u6QoOhBuMHcNiCGx3hLTyK7SzbHSx0aZyJ3KbA7Q0FTxPlK0daB
X-Google-Smtp-Source: AGHT+IHuZI/ouIRHOJIT7pmzC4XOyQsldYWWNwwL78OWL45gDDQtwAZH4ETLixH7z2d/KCjswmCcTw==
X-Received: by 2002:a05:600c:524b:b0:45b:9a7b:66ba with SMTP id 5b1f17b1804b1-46e1d98f7c2mr31486395e9.14.1758644494313;
        Tue, 23 Sep 2025 09:21:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4xGzZVVvBDnCSShYhYOmYiTUBaqToxkNlrPv6A1+u5vw==
Received: by 2002:a05:600c:a46:b0:45b:6a62:c847 with SMTP id
 5b1f17b1804b1-4653f351759ls29616805e9.0.-pod-prod-08-eu; Tue, 23 Sep 2025
 09:21:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUpgvl4CQ2aJ7zGIofQWOIvHiTTSW399pyYoYG6mXuFVOfyuLfBcZD453gvyyBfMBfc7w7u9BcpYhA=@googlegroups.com
X-Received: by 2002:a05:600c:a01:b0:45f:2cd5:5086 with SMTP id 5b1f17b1804b1-46e1d97463dmr35074545e9.3.1758644491346;
        Tue, 23 Sep 2025 09:21:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758644491; cv=none;
        d=google.com; s=arc-20240605;
        b=ffZhvF3uPdaTDIR9MQELlCqtxYH3ug6eAH7bPPsOILY8XycyRIoj9ro7dSs1UzYoCK
         332NDfKaX2yRyNgIOHpG1fQqM+vKHjCmNpF0Vo7iNtOced3JpiXbvPeZu8S7jsKyZDkw
         4C/Pej6JZ7F4fgoMShr5oMCm6Knx3x1Yz9sMUdyMnN1YvxhzVTqjPe22MTyLUlP3ufkV
         4rKTqCJfLebfYqDYmXLpPMVamCwgRVuhr8Ma6DC6gj55MtsmB9mRcX/kmnYp+JLUF0o9
         bS8wdpZku4gSjZWNepgRR4NcEvh0CW6rgO9X0cMCwTdOIcqKhQAoW6j7bzMhNYYN5IsB
         EZjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=hX/x2YQu8IshGIhtT2j6+6VZWl/6xDk05tyNGFgYJMM=;
        fh=6OxN/wIhHpIWkVIg32hPfFhiWtaDE7EkfCjrV2BUqTk=;
        b=G+XNrRD5R3M0x9Kn3Fe8YtMBzYmZw7aUy7cWrbpAGlR6lie/evKJeUsPz4pUffmp5v
         S0iLFht9RkH0qZAA2GQ4zKPKy49AEEr+YiKG8hOkx9i/r/kLFj80SG7qgZ3TOqqSGRj/
         dYwFlaAQUP66Payb6foHaAUX2kuMJ8NYuYneBOhg4SkWwvUY4X9e8hmCWuTJRPgLSGQ5
         yxLN4PUiU+tTeuNe21kjtdJLlFEMq8UXuYmNYNWhxzDK7unjmDqa8zHvGbIki1OIIgyZ
         kwNNsoABGy1WIAX7fUXs+RbhMkLrjopuEh4JcBMzI6qwTXcaW3WyoQjky5rRXDnBiCU5
         7NYQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=TPrkJXOm;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32c.google.com (mail-wm1-x32c.google.com. [2a00:1450:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-46e231ecb40si104015e9.1.2025.09.23.09.21.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Sep 2025 09:21:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32c as permitted sender) client-ip=2a00:1450:4864:20::32c;
Received: by mail-wm1-x32c.google.com with SMTP id 5b1f17b1804b1-45dd513f4ecso42921375e9.3
        for <kasan-dev@googlegroups.com>; Tue, 23 Sep 2025 09:21:31 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUoGHHc7B3LFXB6nXo8MxCpIcOedLkCxtzRJcrg2HLynhLrRi0bipsmFJIz1Vgc34nClaguM8DyJE4=@googlegroups.com
X-Gm-Gg: ASbGncuzo88m9UAkN3hLBL/WT7dB48St8FQqPGTtB20HHqEHD+Gvp2fAnKFI7jQHaif
	cHuGqUTwElRcZTkGSsN3kSzK4XM3CBoSRjKNq8tvCJoXbJLDCp+FFv32Qsk3oH3cBa0/3vmO6kZ
	rUKpzjDtjJS930IyWwdpkRw1QkqE55xHuTAAg0UVEXuKuoomcle9k+i50cWVgeSxMfDmZ2QtxKB
	8ymCbFiRw==
X-Received: by 2002:a05:6000:2012:b0:3e5:190b:b04e with SMTP id
 ffacd0b85a97d-405c9a01b60mr2346265f8f.37.1758644490092; Tue, 23 Sep 2025
 09:21:30 -0700 (PDT)
MIME-Version: 1.0
References: <20250916222755.466009-1-yeoreum.yun@arm.com> <20250916222755.466009-2-yeoreum.yun@arm.com>
In-Reply-To: <20250916222755.466009-2-yeoreum.yun@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 23 Sep 2025 18:21:19 +0200
X-Gm-Features: AS18NWDlzRK91ohBlIigdupIpzh6rhNy0WQJ68f3CbaJYvAQUJclJ8mywpVCdno
Message-ID: <CA+fCnZdRySvANWkT1oK38Ke1Uf9yUm1qyb5-vatJhZR+-eay5g@mail.gmail.com>
Subject: Re: [PATCH v8 1/2] kasan/hw-tags: introduce kasan.write_only option
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
 header.i=@gmail.com header.s=20230601 header.b=TPrkJXOm;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32c
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

On Wed, Sep 17, 2025 at 12:28=E2=80=AFAM Yeoreum Yun <yeoreum.yun@arm.com> =
wrote:
>
> Since Armv8.9, FEATURE_MTE_STORE_ONLY feature is introduced to restrict
> raise of tag check fault on store operation only.
> Introduce KASAN write only mode based on this feature.
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
> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
> ---
>  Documentation/dev-tools/kasan.rst  |  3 ++
>  arch/arm64/include/asm/memory.h    |  1 +
>  arch/arm64/include/asm/mte-kasan.h |  6 ++++
>  arch/arm64/kernel/cpufeature.c     |  2 +-
>  arch/arm64/kernel/mte.c            | 18 ++++++++++++
>  mm/kasan/hw_tags.c                 | 45 ++++++++++++++++++++++++++++--
>  mm/kasan/kasan.h                   |  7 +++++
>  7 files changed, 79 insertions(+), 3 deletions(-)
>
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/=
kasan.rst
> index 0a1418ab72fd..a034700da7c4 100644
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
``).
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
> index ef269a5a37e1..1f6e8c87aae7 100644
> --- a/arch/arm64/kernel/cpufeature.c
> +++ b/arch/arm64/kernel/cpufeature.c
> @@ -2945,7 +2945,7 @@ static const struct arm64_cpu_capabilities arm64_fe=
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
> index 9a6927394b54..646f090e57e3 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -67,6 +67,9 @@ DEFINE_STATIC_KEY_FALSE(kasan_flag_vmalloc);
>  #endif
>  EXPORT_SYMBOL_GPL(kasan_flag_vmalloc);
>
> +/* Whether to check write accesses only. */
> +static bool kasan_flag_write_only =3D false;
> +
>  #define PAGE_ALLOC_SAMPLE_DEFAULT      1
>  #define PAGE_ALLOC_SAMPLE_ORDER_DEFAULT        3
>
> @@ -141,6 +144,23 @@ static int __init early_kasan_flag_vmalloc(char *arg=
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
> +               kasan_flag_write_only =3D false;
> +       else if (!strcmp(arg, "on"))
> +               kasan_flag_write_only =3D true;
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
> @@ -262,10 +282,11 @@ void __init kasan_init_hw_tags(void)
>         /* KASAN is now initialized, enable it. */
>         static_branch_enable(&kasan_flag_enabled);
>
> -       pr_info("KernelAddressSanitizer initialized (hw-tags, mode=3D%s, =
vmalloc=3D%s, stacktrace=3D%s)\n",
> +       pr_info("KernelAddressSanitizer initialized (hw-tags, mode=3D%s, =
vmalloc=3D%s, stacktrace=3D%s, write_only=3D%s)\n",
>                 kasan_mode_info(),
>                 str_on_off(kasan_vmalloc_enabled()),
> -               str_on_off(kasan_stack_collection_enabled()));
> +               str_on_off(kasan_stack_collection_enabled()),
> +               str_on_off(kasan_flag_write_only));
>  }
>
>  #ifdef CONFIG_KASAN_VMALLOC
> @@ -392,6 +413,20 @@ void kasan_enable_hw_tags(void)
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
> +        * finds the feature unsupported, kasan_flag_write_only is set to=
 OFF
> +        * to avoid further unnecessary calls on other CPUs.
> +        */
> +       if (kasan_flag_write_only && hw_enable_tag_checks_write_only()) {
> +               kasan_flag_write_only =3D false;
> +               pr_err_once("write-only mode is not supported and thus no=
t enabled\n");
> +       }
>  }
>
>  #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
> @@ -404,4 +439,10 @@ VISIBLE_IF_KUNIT void kasan_force_async_fault(void)
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

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZdRySvANWkT1oK38Ke1Uf9yUm1qyb5-vatJhZR%2B-eay5g%40mail.gmail.com.
