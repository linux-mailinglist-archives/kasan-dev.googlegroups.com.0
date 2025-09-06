Return-Path: <kasan-dev+bncBDW2JDUY5AORB7WZ6HCQMGQE7FUNS5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id EE542B4757D
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Sep 2025 19:18:55 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id ffacd0b85a97d-3dc3f943e6esf1901742f8f.2
        for <lists+kasan-dev@lfdr.de>; Sat, 06 Sep 2025 10:18:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757179135; cv=pass;
        d=google.com; s=arc-20240605;
        b=BCEE1NsyEeYV8BOU4kROheZn2MqMzPfE6JY06vvPI3FllpyoT22Q+9r3q52aY7h3D/
         hlQ/7ZsJQwJV9mSwEbjCr+NxTfhY1n70ulTXoATRnt0NctPfLwn3P9+XKTdWUZdTs7bH
         qbLG48C6K0xQHqlLYOIDgc6UzJ7A9uS/HCG0Ptl5TxAQ5JHS9hx2/bqGc2C571fSkreZ
         ClYcqIZAdBp9Zi8MRk8A0R3dniFNPLckIyT9eAlThy1/iXiOq5tX1sjpPz3sSPFfoF2n
         lEnzMyHlYmpG0X3yR2DbXfrRrLDlMpDtq5TVLGT/s1phumTipyENRifwMn/aznVYY+4a
         pvLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=8Fcd40wrOKQOGyCbgFg0S5WRZ39Ob972HggChB3O0Ro=;
        fh=k/4Y3YfAuIAISBIz5ppfoimWRHkEhOv3hDBZV3/PU9s=;
        b=VqqiPSt2EVrjIzYqv5FWNLo9YGftufbUvuPYZzo+b0Y9oEcNddDq6oZZHdiIOW+Kom
         hqpQ2cSBmwPOarjRcpRbEB4Unm92dNuBDdGx5i6VJ7z8HgDzk64cTX50mkTr+Hjls1hT
         qEKFlN67a3nf0QSx9+yr7E5q0DMyXXr9Ml1HCl98JEuL+5fQ33QX0V/cr9Ceqd/fpbFY
         8bGhXuIrjN9Ioy6Rnd3wULWwq1Twgjen7WhAy6RmMVXeeVtw/Yv3GgfHl+bR0CNkxly0
         4Va0F5pPfjiEtGIEoyTcj1QbeOquBeyOPvjAG6+Va+jyFEVZHqnotrh2FMMSk43liImQ
         Eneg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FB7waePS;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757179135; x=1757783935; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=8Fcd40wrOKQOGyCbgFg0S5WRZ39Ob972HggChB3O0Ro=;
        b=c1AcfFW5m5iDRNn3m5YbYyoIwDUllELqVMOkx0h2kEvRvLkjYQxXGKElL2lAri+Id7
         8Gk7tgHMpj3xbO2BjVZezoFmB7+3QWhrmut2csV/x/Ea98rKYhNaFoUMKTe5cdvU3ny0
         eEaWR1oEPqm5Q7xOL2j7Qv0oLFOjf1iLr1QC8UXP8xTOYvrTvV2/5dkKSyCdMKix7RKS
         xpmQ3SAKmCjyOiPZI0SVS1ivzJtKL9sek2AO5tVZ5vNfdemwFEtrnzBlVtl5Yi/xKWgD
         BW7zSUepnBvnD7c8k/FV7GCXQ+0bX8nNjpLamEv5rhbZXCdN3PgChi2kH3UVsAcJ8+sj
         zxYw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757179135; x=1757783935; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=8Fcd40wrOKQOGyCbgFg0S5WRZ39Ob972HggChB3O0Ro=;
        b=PpSi/ZbHF0e5PQ2s/krTn8AzgeVsUWp8Gp60n73WsOHimlvDJiJChIPEzLgxPGclOY
         OwH5kYnSSZscj6YxXGHdYeCzcbwB6euTVpHDeAsdfQIa/VQmD7VrUIWmxe1lWIuwpH3s
         amQ5TCDgw9hIMY6foUVzvujvuCt3W0sUMY+3FFkNU1E1Zd/NG5WK+dLuh8quesNDy3On
         P7gzBcAYsocZ7j7cdrVezvcRMyPVh+5cNKUY8Y7I9jyPDCWf9Lkgi5HyC3UTMtuwrh45
         d7gP1SJGN5DGZv1CSiwlSaRTu3GSVy5KcKpjqmc6dR8QZjVJk8Z0hcu16B9sZC5Ryxfu
         EAuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757179135; x=1757783935;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=8Fcd40wrOKQOGyCbgFg0S5WRZ39Ob972HggChB3O0Ro=;
        b=NkDcg7FFVWfuUa2qPOUyHRbNUHibbgsooIDgc8XiBqMIivG+fjlTj5XwA6U8v6PSFY
         Vli5226mk3n4W4e0vwitjKqFQbIGtpJrr4AnvIMRaGESGnSTlNaQy08YcsX9N+IqF/Do
         A5lTG89lEx+U1Nnp9qwdZy7uIiTmX+S49wiCC46t7hjO3b13z8T0hABuKymaJOkcgdrg
         FI9y3mUkj6XaGXxKICh6KwmDQMjKGVHbEpooWB4IKxa9hkcJ0E0tej1CoS+JdiedYcQY
         nPotcxldHgJ0WGKQz3bVPD2KKYjzr1qiB6WWHwjhxbdYTO3JKiEA5kXgRhsv6iw8nARP
         xUkg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWdc+BbuDRcAX67t2WJLhOQr8oMb6lptJZZoc0iAO1ogcwjpmFNEEudmIG2N4aD7UiZp+t6qQ==@lfdr.de
X-Gm-Message-State: AOJu0Yx+rzDdw472QiWluonGb84yBAFwi8X9nP4Fv4MliVvqv7R0EbJg
	HxoS6yikISstHhUdDBPdhATAxhCcUqayQHSYLDEBR1xurqAXBqqtT8b5
X-Google-Smtp-Source: AGHT+IEaaLZ0dCAZScaws4sEljYmSve53TkQVfXGahC4o+kQpQStXOtKgXJIg6DAxbILlv3EmuxjWg==
X-Received: by 2002:a05:6000:420f:b0:3d9:70cc:6dd2 with SMTP id ffacd0b85a97d-3e64317eedfmr2811656f8f.40.1757179135051;
        Sat, 06 Sep 2025 10:18:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdNU8kBTjQocBZ0R8AFrfTWnKclmmUCL94NBya/zDwk4Q==
Received: by 2002:a05:600c:628d:b0:456:241d:50c3 with SMTP id
 5b1f17b1804b1-45dd85146abls10196455e9.1.-pod-prod-08-eu; Sat, 06 Sep 2025
 10:18:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXyMhBmcVAKFwwj09KymkcmuCKXp+ssPedClPxkF/N29CIywcOTwza1sVvwvmO90+k03pg44DtzTUU=@googlegroups.com
X-Received: by 2002:a05:600c:c4ac:b0:45d:d97c:236c with SMTP id 5b1f17b1804b1-45dddecdaf1mr18359615e9.21.1757179132557;
        Sat, 06 Sep 2025 10:18:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757179132; cv=none;
        d=google.com; s=arc-20240605;
        b=H74ZJpAoUyiMvRNLz/vzouzsRvOZM+NxSaDC1+OIUpE5JPocym+fqjBtAGezfv7W6H
         upVbwS69QZUl2AK+Hz8ApINh30PZAI20ltMkRrr3/gIfntUHD/AzpnBNhMOCFsogHC4/
         vfkdx69IRQp5cGEJ48m0UXRN/cnUOHlEoGsWyTVu8klmaLUBMA8pLKoeHwt24hZdkErf
         15EXEku6LPEHevyrPIvIVNdEM1dao8P/Blk1QrA72ItZBhTNyjWAZMRktMOnnYbDf6H9
         1hqGLGbGA4W5tMDTsQrau33TyUThK7KYBbQh68MYl4trpmdbeMtm0nyeRA2Yi5jDtKhY
         DYiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ZvnXgjkKA1Pp2ZMyBbTXIoHx/IW3dCtqfz+u+Yq42DE=;
        fh=GEKkYAAte23u1/6ALAKXTEQ58IitEAOTP1PGji1XYKk=;
        b=bNLfGfmQ8kjNbkjKDQPCRvE97QfFKHq02Ax9+wH10yT8SvAVXWTLf6WMTFLgJkOTlB
         9RgxwXHXXO/naKR7XtexJG/+WiDD/pGuMzIMidMhOF31BgaUBtOFi7y3oIb3nq90Ryuf
         TdQfS7QlASOZ5i5wyL92dk1x6LITl/0a2D6uSZKDxiU4BJIHLOMjMRyA3PvtbNsY9t56
         N+G3E4T/BhyfhlWIE5IBzm+gF0BHQdAVAMnPNTtuECxgcFBbKQIjCGIv9o8rMvdfgyJY
         raJAPMzyJS2chMAe/wBx9Uo195fQMXhs9NUB27IQBUVrou1H/fn7Z6/gXRBh34y7E2DZ
         xZYg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FB7waePS;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x431.google.com (mail-wr1-x431.google.com. [2a00:1450:4864:20::431])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3e278ac83dasi136289f8f.4.2025.09.06.10.18.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 06 Sep 2025 10:18:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) client-ip=2a00:1450:4864:20::431;
Received: by mail-wr1-x431.google.com with SMTP id ffacd0b85a97d-3c46686d1e6so2122484f8f.3
        for <kasan-dev@googlegroups.com>; Sat, 06 Sep 2025 10:18:52 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWcQWw59trlZKcyjAcdYCMpJI/Vt3tECw27nwnA9/EIp3fIj0B7oJSVMrbJ8SvLhoF4XBVFmLimDPM=@googlegroups.com
X-Gm-Gg: ASbGncuYq+1dkp6GpmWMT8WfIuglay/dqCAEVOlIr/mtzPRMIwUtlw8Ez+YrBrk3PJa
	2CXAp5d6hy5vOP4OWO1g1UX1HVOzVNZgk7Ge29pLB91LxB8j7yUecahroAW1j26m6ZaehM1SMDF
	zJcEh3sPGnpL4cb+2BGd4YOKmaGYwy5yQYJAsg/acazCHpnbnZtYYyXJbAZWrPCoqH8EslvbYaU
	X8np5Ty10qejSQn23w=
X-Received: by 2002:a05:6000:2910:b0:3e3:f89:ea31 with SMTP id
 ffacd0b85a97d-3e643c1e706mr1880888f8f.61.1757179131893; Sat, 06 Sep 2025
 10:18:51 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com> <c9dfcee8bd04161394f41a21f78fc3e01a007ddb.1756151769.git.maciej.wieczor-retman@intel.com>
In-Reply-To: <c9dfcee8bd04161394f41a21f78fc3e01a007ddb.1756151769.git.maciej.wieczor-retman@intel.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 6 Sep 2025 19:18:41 +0200
X-Gm-Features: AS18NWAE44l-F8fxYkxmWh2eLEtrt0fldHS7j-JrDWBIap-lKzv70eyY1F7Ln-M
Message-ID: <CA+fCnZcBGhToB+pOhn+ACahyqVLWJ_7cnqBNZC5ob77wZD5iJw@mail.gmail.com>
Subject: Re: [PATCH v5 12/19] x86: Minimal SLAB alignment
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: sohil.mehta@intel.com, baohua@kernel.org, david@redhat.com, 
	kbingham@kernel.org, weixugc@google.com, Liam.Howlett@oracle.com, 
	alexandre.chartre@oracle.com, kas@kernel.org, mark.rutland@arm.com, 
	trintaeoitogc@gmail.com, axelrasmussen@google.com, yuanchu@google.com, 
	joey.gouly@arm.com, samitolvanen@google.com, joel.granados@kernel.org, 
	graf@amazon.com, vincenzo.frascino@arm.com, kees@kernel.org, ardb@kernel.org, 
	thiago.bauermann@linaro.org, glider@google.com, thuth@redhat.com, 
	kuan-ying.lee@canonical.com, pasha.tatashin@soleen.com, 
	nick.desaulniers+lkml@gmail.com, vbabka@suse.cz, kaleshsingh@google.com, 
	justinstitt@google.com, catalin.marinas@arm.com, 
	alexander.shishkin@linux.intel.com, samuel.holland@sifive.com, 
	dave.hansen@linux.intel.com, corbet@lwn.net, xin@zytor.com, 
	dvyukov@google.com, tglx@linutronix.de, scott@os.amperecomputing.com, 
	jason.andryuk@amd.com, morbo@google.com, nathan@kernel.org, 
	lorenzo.stoakes@oracle.com, mingo@redhat.com, brgerst@gmail.com, 
	kristina.martsenko@arm.com, bigeasy@linutronix.de, luto@kernel.org, 
	jgross@suse.com, jpoimboe@kernel.org, urezki@gmail.com, mhocko@suse.com, 
	ada.coupriediaz@arm.com, hpa@zytor.com, leitao@debian.org, 
	peterz@infradead.org, wangkefeng.wang@huawei.com, surenb@google.com, 
	ziy@nvidia.com, smostafa@google.com, ryabinin.a.a@gmail.com, 
	ubizjak@gmail.com, jbohac@suse.cz, broonie@kernel.org, 
	akpm@linux-foundation.org, guoweikang.kernel@gmail.com, rppt@kernel.org, 
	pcc@google.com, jan.kiszka@siemens.com, nicolas.schier@linux.dev, 
	will@kernel.org, jhubbard@nvidia.com, bp@alien8.de, x86@kernel.org, 
	linux-doc@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
	linux-kbuild@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=FB7waePS;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::431
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

On Mon, Aug 25, 2025 at 10:29=E2=80=AFPM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> 8 byte minimal SLAB alignment interferes with KASAN's granularity of 16
> bytes. It causes a lot of out-of-bounds errors for unaligned 8 byte
> allocations.
>
> Compared to a kernel with KASAN disabled, the memory footprint increases
> because all kmalloc-8 allocations now are realized as kmalloc-16, which
> has twice the object size. But more meaningfully, when compared to a
> kernel with generic KASAN enabled, there is no difference. Because of
> redzones in generic KASAN, kmalloc-8' and kmalloc-16' object size is the
> same (48 bytes). So changing the minimal SLAB alignment of the tag-based
> mode doesn't have any negative impact when compared to the other
> software KASAN mode.
>
> Adjust x86 minimal SLAB alignment to match KASAN granularity size.
>
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> ---
> Changelog v4:
> - Extend the patch message with some more context and impact
>   information.
>
> Changelog v3:
> - Fix typo in patch message 4 -> 16.
> - Change define location to arch/x86/include/asm/cache.c.
>
>  arch/x86/include/asm/cache.h | 4 ++++
>  1 file changed, 4 insertions(+)
>
> diff --git a/arch/x86/include/asm/cache.h b/arch/x86/include/asm/cache.h
> index 69404eae9983..3232583b5487 100644
> --- a/arch/x86/include/asm/cache.h
> +++ b/arch/x86/include/asm/cache.h
> @@ -21,4 +21,8 @@
>  #endif
>  #endif
>
> +#ifdef CONFIG_KASAN_SW_TAGS
> +#define ARCH_SLAB_MINALIGN (1ULL << KASAN_SHADOW_SCALE_SHIFT)
> +#endif
> +
>  #endif /* _ASM_X86_CACHE_H */
> --
> 2.50.1
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZcBGhToB%2BpOhn%2BACahyqVLWJ_7cnqBNZC5ob77wZD5iJw%40mail.gmail.com.
