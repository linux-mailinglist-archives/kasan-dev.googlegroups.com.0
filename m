Return-Path: <kasan-dev+bncBDW2JDUY5AORBSOT3G6QMGQEP5EPNMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D3EDA3CD99
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Feb 2025 00:31:39 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-30a323c6748sf1781621fa.2
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Feb 2025 15:31:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740007883; cv=pass;
        d=google.com; s=arc-20240605;
        b=YNrP+vPg4bbBIEU5sSWh1pKo+tMaq8ulgfW6mV77J2WVJrM9VI90716e+itVXWgzol
         +6DxZJXvDKEc91OKtQpWIXktOrGTKSalnbPxiTWpsCcwn3amx2M9HjI57W2HQHuB71hC
         RFypcMYT2Jxy6J4IShCPME77Kd6E6hie4fpZJs2bYce2F7q1v34AqTOHbSaw8o+r3QnR
         rndOmSeBZN2PVgZSlsIdkHNkVXMsuXwAXajI0dJ8ypB3p0YS/9ZmC1PvnaZGQ94tXg8t
         O98JvExGF0qC1VW6IssdqPtu4EbrUZBFjGgNrY23Y3DQI+ozw58FekWzyVo+6RydpSGJ
         RaxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=UIm1LU868Mx1qNrQMbmIugaB08W9W2sC8UdmcVS7qgo=;
        fh=Kaad7tuV/0SjbX6qBKXlNYWJ5fghLy4bcuxlFlqPthg=;
        b=B5uqByl9BD1x9wH5KGVftJKzB4sVk7Wj53tQJJdSAR9mtGQimoklbT1IU1KXP7U0v5
         eWP+wgY1a7AGuu8mk4VUP4HYSaPCACQpufivhqQ/wnGAZ1kZip/H9sDNT8ba7QarsXma
         4xSabyQb58CjRDx7g0tbiG5DR8C3rAO/rK+bRufUhINlbBC0tDiMDh+CXxCsVMj86tGl
         5fHmc1KezAR95RoPkv4P+YuvfMasff383+rI0OLPdhKTR6LyOFrzUwlI89uKMue8JvqC
         hSGiaIprBULBAchy4XQVRR6oy7GO3yP9Mcy3iU5hspA1bd1CA3Pzz8TbsFy6UQyCGSty
         hg1A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=diD0HreC;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740007883; x=1740612683; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=UIm1LU868Mx1qNrQMbmIugaB08W9W2sC8UdmcVS7qgo=;
        b=bh0DQaRCGEWK829lLCDR5ZgWjc2AxCzkGrDPw34g/LraWgoH8aSos66X7cecFNNd2M
         LM1FgaFG7SoJ/CY/A4D4fEiiqO9nu4FJCHjxnrnyslG7GgUigyXs/jU8fboD8o42848+
         /FX+01xlbEXSrSy4hDM0DtZNzflfleKqfHrD1d4AlieGLlksFGpQAS7ibaRJuAc8x5cR
         RnoYwzAomSdFzu6HTpJQNiUU4YA+N/D6cMBujlzgRW/ytlRHe9yAWwjhy/mRmM2m0lbE
         UxhebCno+94uhg41mzBaHGPYPzmgX+nLHogeG40omGjMsVgXFyE8YsIBgxSVXpUFeNsW
         9mvA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1740007883; x=1740612683; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=UIm1LU868Mx1qNrQMbmIugaB08W9W2sC8UdmcVS7qgo=;
        b=cgJOkyrc3e9ji1SnhaBWdBg3BuB77vJw/Ibz2S8WDcVy08bPlpo75dLor0Qya2rIlt
         g9qRg36yQD0fdDlp+mw2XtceLlRDBvAVNCz61OMybKRNNMtnMIZWiLHAQ5WwRF+9X2+H
         TKtX0N1YlxHVIlhAakZ2uOgFhOrGRiBAg2so1X03QuzpoEaxZXp9b5kqCqx54VBuu8Hh
         KplTcBu2TrIv6KxvwAKeTKcudcmRmTe1ojRhIniibWkO2tEHQvyLuUN/lTOLyNp2rNRX
         69s+DK+0jHCNb7XBfQQXvgX9zLJc0kTi6GdBF3ZaXoSZLSMkBW81XKgu9A5U53MTosaM
         O2Dg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740007883; x=1740612683;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=UIm1LU868Mx1qNrQMbmIugaB08W9W2sC8UdmcVS7qgo=;
        b=xL3l6Ded8jvdWKs4XFgrx8Tm6oThl3jH8Cgn5ilDLMFJ5tJaj3j0ByFpvFx3c1aqjW
         PaCrBP7cXf7Vm4LOY67st/ljMQP3Vg9Wa5gw1+WocF66KCQz1T4I2me54ltW6Vnu3frK
         WiYWaKzHlOFuyMJeJd8tDb+JE7rZPfitJI4RvQauzvjAyA/5WxLzob1pJNfIjunUYYkK
         xRCH7KljbqllmEIcJIRgn+qfioiK5Tm/De+Ijn1ZZcMnP7p5hKSQc3aoTR5us4zQbccK
         kgOw05Soh695aFykWfD+KGA56pT+zXuxxTiYNSakmieabP7VmtM+KboRt2VLk+LueoWP
         HmqA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCURAlgWuHaYjtlITcdC11yNeQ/bpJfNLwoNt3scBFqteSwAzyt0zcUFFXch7PKSx1vePLlG8A==@lfdr.de
X-Gm-Message-State: AOJu0Yy30+Cdn291tO+ng1xWjg705QSlkpIGdmhpQ6nCbVAl4ChaFuYf
	i3Ss9rjkpgD4Fl3Ay4BG1qjIvOp+oIyxV+YO5rQxty0AvmbfDWyN
X-Google-Smtp-Source: AGHT+IHF6pvk8OJWjeTe1NbN9Zq8vccK48+jlo8rGEJNHdePCS0RqzGNh+3KHrEG+tWVSaMNZd91kg==
X-Received: by 2002:a2e:95d7:0:b0:307:e0c3:5293 with SMTP id 38308e7fff4ca-30927b26e9amr53264091fa.36.1740007882181;
        Wed, 19 Feb 2025 15:31:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVF3jvdCf7F9MFblvkFA8B8HnM4JuAIcdRWKoOlEv5+n2w==
Received: by 2002:a2e:a986:0:b0:30a:355a:213e with SMTP id 38308e7fff4ca-30a4ffd5735ls914151fa.1.-pod-prod-04-eu;
 Wed, 19 Feb 2025 15:31:20 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXedjkCI4xelRy7xSO/v9cXxf/USBKX1BVUPbS0dL3mvH4Sx8lUkrR4MpNfgUYNBIcH2stk3wUepws=@googlegroups.com
X-Received: by 2002:a2e:9f54:0:b0:309:2012:cc61 with SMTP id 38308e7fff4ca-30927b19bfbmr49030401fa.29.1740007879800;
        Wed, 19 Feb 2025 15:31:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740007879; cv=none;
        d=google.com; s=arc-20240605;
        b=C8KgokRtj2bDI+5i6smtZaewq5uCqUKN40lZCX5nLyyns5eHhGnmyHpd+Oc1wW0eLQ
         t2CD41GASDpoxoIxOcB0P3AOjCjjSpLJtgtyb1FJjaMPO71NJt2UDgk6WU/2dAkfioAz
         4GtSL3L9Fta51NYXBHShuSujIJ4JRDIwUFXcRwcA0x+Ee2HzcuRzhQTVZD3mM7q2imZn
         8IZobpA5MKpJNvwXBjYycYD6ocJQ/eS1ZtFWzxl0ftHYHxo1zDxrTgCemzJ3tFGqievO
         k3n9wMyM6dt1JcCwu5xGqhbBNuguMJRBZbBzuCA2o12uH5JjsnVw5gfyNICAMh501HTq
         DdmA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=vTgTbeY1aqQKxUER4SE5xysBw6pVVMa23Uc6KxK62yU=;
        fh=cLPj/4urX8lXOKhFIq6Y9WKGnY1JVDWBd7H6qtpdm8k=;
        b=k+6fwDBJtBoD+wQX4qWEsTxMNuvtpRN/41Awk9NH4AAiHheZZuZ6f1BVT75YUO08TD
         SnLVrKw6w80sdcwzWoXHAxzxlVDjRdybSzLxOiH1/2SPFL++uHhK5RT7MlANdTZOf2Ph
         HK+Cm/QUund4xujCoNchKXR/6SqBQWLRgY2uWAhcN7fvEt+wurtI103v9vgZ8l/So4KZ
         hL1yKzjdUUQQ08tjh6h5yVFclQOlvM05QDcfik47sL4w6AeJHPvzyINt05wl2UhxnEXO
         EvEYZ5yhm1RCyszrngHqhbaf4pUSpJkHfvSz1WyDnQ3MgbNTgmTG6hhgkSf9B/R3L+KD
         Fhmg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=diD0HreC;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x431.google.com (mail-wr1-x431.google.com. [2a00:1450:4864:20::431])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-30a2d977986si1516051fa.6.2025.02.19.15.31.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Feb 2025 15:31:19 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) client-ip=2a00:1450:4864:20::431;
Received: by mail-wr1-x431.google.com with SMTP id ffacd0b85a97d-38a25d4b9d4so174811f8f.0
        for <kasan-dev@googlegroups.com>; Wed, 19 Feb 2025 15:31:19 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWqTlZGtYrL50mllAnpA5raovuN48/Z02kZh7OT6jKddoJ8lRVrmXrEJ8ZuhAjoDGlfs9BLQyuOdVE=@googlegroups.com
X-Gm-Gg: ASbGnctNNpZxJMROebt/eX3ePKWAFX1W+GDd82nz5vPVgUyzUfSlBqigheeP57Og9bR
	YFflOl9H0D3E2jldUsnIcngQVfVUiWQXaT5xPXIUDOBVqpZ3DLSVPezwlELtaEG1msiPki00urD
	c=
X-Received: by 2002:a05:6000:1844:b0:38f:4d40:358 with SMTP id
 ffacd0b85a97d-38f4d400751mr11293670f8f.9.1740007878898; Wed, 19 Feb 2025
 15:31:18 -0800 (PST)
MIME-Version: 1.0
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com> <2a2f08bc8118b369610d34e4d190a879d44f76b8.1739866028.git.maciej.wieczor-retman@intel.com>
In-Reply-To: <2a2f08bc8118b369610d34e4d190a879d44f76b8.1739866028.git.maciej.wieczor-retman@intel.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 20 Feb 2025 00:31:08 +0100
X-Gm-Features: AWEUYZkbmdm-WfLa0PA56ZfKvrD8Lj6e3So80KOsOkQ_JlKSdX3epi4Hoik-GnA
Message-ID: <CA+fCnZdtJj7VcEJfsjkjr3UhmkcKS25SEPTs=dB9k3cEFvfX2g@mail.gmail.com>
Subject: Re: [PATCH v2 13/14] x86: runtime_const used for KASAN_SHADOW_END
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: kees@kernel.org, julian.stecklina@cyberus-technology.de, 
	kevinloughlin@google.com, peterz@infradead.org, tglx@linutronix.de, 
	justinstitt@google.com, catalin.marinas@arm.com, wangkefeng.wang@huawei.com, 
	bhe@redhat.com, ryabinin.a.a@gmail.com, kirill.shutemov@linux.intel.com, 
	will@kernel.org, ardb@kernel.org, jason.andryuk@amd.com, 
	dave.hansen@linux.intel.com, pasha.tatashin@soleen.com, 
	ndesaulniers@google.com, guoweikang.kernel@gmail.com, dwmw@amazon.co.uk, 
	mark.rutland@arm.com, broonie@kernel.org, apopple@nvidia.com, bp@alien8.de, 
	rppt@kernel.org, kaleshsingh@google.com, richard.weiyang@gmail.com, 
	luto@kernel.org, glider@google.com, pankaj.gupta@amd.com, 
	pawan.kumar.gupta@linux.intel.com, kuan-ying.lee@canonical.com, 
	tony.luck@intel.com, tj@kernel.org, jgross@suse.com, dvyukov@google.com, 
	baohua@kernel.org, samuel.holland@sifive.com, dennis@kernel.org, 
	akpm@linux-foundation.org, thomas.weissschuh@linutronix.de, surenb@google.com, 
	kbingham@kernel.org, ankita@nvidia.com, nathan@kernel.org, ziy@nvidia.com, 
	xin@zytor.com, rafael.j.wysocki@intel.com, andriy.shevchenko@linux.intel.com, 
	cl@linux.com, jhubbard@nvidia.com, hpa@zytor.com, 
	scott@os.amperecomputing.com, david@redhat.com, jan.kiszka@siemens.com, 
	vincenzo.frascino@arm.com, corbet@lwn.net, maz@kernel.org, mingo@redhat.com, 
	arnd@arndb.de, ytcoode@gmail.com, xur@google.com, morbo@google.com, 
	thiago.bauermann@linaro.org, linux-doc@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, linux-mm@kvack.org, 
	linux-arm-kernel@lists.infradead.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=diD0HreC;       spf=pass
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

On Tue, Feb 18, 2025 at 9:20=E2=80=AFAM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> On x86, generic KASAN is setup in a way that needs a single
> KASAN_SHADOW_OFFSET value for both 4 and 5 level paging. It's required
> to facilitate boot time switching and it's a compiler ABI so it can't be
> changed during runtime.
>
> Software tag-based mode doesn't tie shadow start and end to any linear
> addresses as part of the compiler ABI so it can be changed during
> runtime.

KASAN_SHADOW_OFFSET is passed to the compiler via
hwasan-mapping-offset, see scripts/Makefile.kasan (for the INLINE
mode). So while we can change its value, it has to be known at compile
time. So I don't think using a runtime constant would work.

Which means that KASAN_SHADOW_OFFSET has to have such a value that
works for both 4 and 5 level page tables. This possibly means we might
need something different than the first patch in this series.

But in case I'm wrong, I left comments for the current code below.

> This notion, for KASAN purposes, allows to optimize out macros
> such us pgtable_l5_enabled() which would otherwise be used in every
> single KASAN related function.
>
> Use runtime_const infrastructure with pgtable_l5_enabled() to initialize
> the end address of KASAN's shadow address space. It's a good choice
> since in software tag based mode KASAN_SHADOW_OFFSET and
> KASAN_SHADOW_END refer to the same value and the offset in
> kasan_mem_to_shadow() is a signed negative value.
>
> Setup KASAN_SHADOW_END values so that they're aligned to 4TB in 4-level
> paging mode and to 2PB in 5-level paging mode. Also update x86 memory
> map documentation.
>
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> ---
> Changelog v2:
> - Change documentation kasan start address to non-dense values.
>
>  Documentation/arch/x86/x86_64/mm.rst |  6 ++++--
>  arch/x86/Kconfig                     |  3 +--
>  arch/x86/include/asm/kasan.h         | 14 +++++++++++++-
>  arch/x86/kernel/vmlinux.lds.S        |  1 +
>  arch/x86/mm/kasan_init_64.c          |  5 ++++-
>  5 files changed, 23 insertions(+), 6 deletions(-)
>
> diff --git a/Documentation/arch/x86/x86_64/mm.rst b/Documentation/arch/x8=
6/x86_64/mm.rst
> index f2db178b353f..5014ec322e19 100644
> --- a/Documentation/arch/x86/x86_64/mm.rst
> +++ b/Documentation/arch/x86/x86_64/mm.rst
> @@ -60,7 +60,8 @@ Complete virtual memory map with 4-level page tables
>     ffffe90000000000 |  -23    TB | ffffe9ffffffffff |    1 TB | ... unus=
ed hole
>     ffffea0000000000 |  -22    TB | ffffeaffffffffff |    1 TB | virtual =
memory map (vmemmap_base)
>     ffffeb0000000000 |  -21    TB | ffffebffffffffff |    1 TB | ... unus=
ed hole
> -   ffffec0000000000 |  -20    TB | fffffbffffffffff |   16 TB | KASAN sh=
adow memory
> +   ffffec0000000000 |  -20    TB | fffffbffffffffff |   16 TB | KASAN sh=
adow memory (generic mode)
> +   fffff40000000000 |   -8    TB | fffffc0000000000 |    8 TB | KASAN sh=
adow memory (software tag-based mode)
>    __________________|____________|__________________|_________|_________=
___________________________________________________
>                                                                |
>                                                                | Identica=
l layout to the 56-bit one from here on:
> @@ -130,7 +131,8 @@ Complete virtual memory map with 5-level page tables
>     ffd2000000000000 |  -11.5  PB | ffd3ffffffffffff |  0.5 PB | ... unus=
ed hole
>     ffd4000000000000 |  -11    PB | ffd5ffffffffffff |  0.5 PB | virtual =
memory map (vmemmap_base)
>     ffd6000000000000 |  -10.5  PB | ffdeffffffffffff | 2.25 PB | ... unus=
ed hole
> -   ffdf000000000000 |   -8.25 PB | fffffbffffffffff |   ~8 PB | KASAN sh=
adow memory
> +   ffdf000000000000 |   -8.25 PB | fffffbffffffffff |   ~8 PB | KASAN sh=
adow memory (generic mode)
> +   ffe0000000000000 |   -6    PB | fff0000000000000 |    4 PB | KASAN sh=
adow memory (software tag-based mode)
>    __________________|____________|__________________|_________|_________=
___________________________________________________
>                                                                |
>                                                                | Identica=
l layout to the 47-bit one from here on:
> diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
> index 6df7779ed6da..f4ef64bf824a 100644
> --- a/arch/x86/Kconfig
> +++ b/arch/x86/Kconfig
> @@ -400,8 +400,7 @@ config AUDIT_ARCH
>
>  config KASAN_SHADOW_OFFSET
>         hex
> -       depends on KASAN
> -       default 0xdffffc0000000000
> +       default 0xdffffc0000000000 if KASAN_GENERIC

Let's put a comment here explaining what happens if !KASAN_GENERIC.

Also, as I mentioned in the first patch, we need to figure out what to
do with scripts/gdb/linux/kasan.py.

>
>  config HAVE_INTEL_TXT
>         def_bool y
> diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
> index a75f0748a4b6..4bfd3641af84 100644
> --- a/arch/x86/include/asm/kasan.h
> +++ b/arch/x86/include/asm/kasan.h
> @@ -5,7 +5,7 @@
>  #include <linux/const.h>
>  #include <linux/kasan-tags.h>
>  #include <linux/types.h>
> -#define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
> +
>  #define KASAN_SHADOW_SCALE_SHIFT 3
>
>  /*
> @@ -14,6 +14,8 @@
>   * for kernel really starts from compiler's shadow offset +
>   * 'kernel address space start' >> KASAN_SHADOW_SCALE_SHIFT
>   */
> +#ifdef CONFIG_KASAN_GENERIC
> +#define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
>  #define KASAN_SHADOW_START      (KASAN_SHADOW_OFFSET + \
>                                         ((-1UL << __VIRTUAL_MASK_SHIFT) >=
> \
>                                                 KASAN_SHADOW_SCALE_SHIFT)=
)
> @@ -24,12 +26,22 @@
>  #define KASAN_SHADOW_END        (KASAN_SHADOW_START + \
>                                         (1ULL << (__VIRTUAL_MASK_SHIFT - =
\
>                                                   KASAN_SHADOW_SCALE_SHIF=
T)))
> +#endif
> +
>
>  #ifndef __ASSEMBLY__
> +#include <asm/runtime-const.h>
>  #include <linux/bitops.h>
>  #include <linux/bitfield.h>
>  #include <linux/bits.h>
>
> +#ifdef CONFIG_KASAN_SW_TAGS
> +extern unsigned long KASAN_SHADOW_END_RC;
> +#define KASAN_SHADOW_END       runtime_const_ptr(KASAN_SHADOW_END_RC)
> +#define KASAN_SHADOW_OFFSET    KASAN_SHADOW_END
> +#define KASAN_SHADOW_START     (KASAN_SHADOW_END - ((UL(1)) << (__VIRTUA=
L_MASK_SHIFT - KASAN_SHADOW_SCALE_SHIFT)))

Any reason these are under __ASSEMBLY__? They seem to belong better
together with the CONFIG_KASAN_GENERIC definitions above.

> +#endif
> +
>  #define arch_kasan_set_tag(addr, tag)  __tag_set(addr, tag)
>  #define arch_kasan_reset_tag(addr)     __tag_reset(addr)
>  #define arch_kasan_get_tag(addr)       __tag_get(addr)
> diff --git a/arch/x86/kernel/vmlinux.lds.S b/arch/x86/kernel/vmlinux.lds.=
S
> index 0deb4887d6e9..df6c85f8f48f 100644
> --- a/arch/x86/kernel/vmlinux.lds.S
> +++ b/arch/x86/kernel/vmlinux.lds.S
> @@ -353,6 +353,7 @@ SECTIONS
>
>         RUNTIME_CONST_VARIABLES
>         RUNTIME_CONST(ptr, USER_PTR_MAX)
> +       RUNTIME_CONST(ptr, KASAN_SHADOW_END_RC)
>
>         . =3D ALIGN(PAGE_SIZE);
>
> diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
> index 299a2144dac4..5ca5862a5cd6 100644
> --- a/arch/x86/mm/kasan_init_64.c
> +++ b/arch/x86/mm/kasan_init_64.c
> @@ -358,6 +358,9 @@ void __init kasan_init(void)
>         int i;
>
>         memcpy(early_top_pgt, init_top_pgt, sizeof(early_top_pgt));
> +       unsigned long KASAN_SHADOW_END_RC =3D pgtable_l5_enabled() ? 0xff=
f0000000000000 : 0xfffffc0000000000;

I think defining these constants in arch/x86/include/asm/kasan.h is
cleaner than hardcoding them here.







> +
> +       runtime_const_init(ptr, KASAN_SHADOW_END_RC);
>
>         /*
>          * We use the same shadow offset for 4- and 5-level paging to
> @@ -372,7 +375,7 @@ void __init kasan_init(void)
>          * bunch of things like kernel code, modules, EFI mapping, etc.
>          * We need to take extra steps to not overwrite them.
>          */
> -       if (pgtable_l5_enabled()) {
> +       if (pgtable_l5_enabled() && !IS_ENABLED(CONFIG_KASAN_SW_TAGS)) {
>                 void *ptr;
>
>                 ptr =3D (void *)pgd_page_vaddr(*pgd_offset_k(KASAN_SHADOW=
_END));
> --
> 2.47.1
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZdtJj7VcEJfsjkjr3UhmkcKS25SEPTs%3DdB9k3cEFvfX2g%40mail.gmail.com.
