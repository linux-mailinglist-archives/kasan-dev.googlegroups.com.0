Return-Path: <kasan-dev+bncBDW2JDUY5AORBQHPR66QMGQE2JXI2CA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 7DD1CA29DA2
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 00:44:02 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-436379713basf1285395e9.2
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Feb 2025 15:44:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738799042; cv=pass;
        d=google.com; s=arc-20240605;
        b=SHXWHEkVTno2TmN9GW/5aNzDW7WuHxdHnB6k1xh8PMBxnlom4vfW4fjJdMHmfcInid
         Asnc64xTqgeR9wt2s+ojfrwiDBfBTpDr6tZSvVnQh9tv3lIrffwynZy3BNn2KF1WXsOz
         K7fZ/OAXzhWdHMh8x5KHW06fnj3vNAvBQz8d9u712sjm+qTiFc5rwUUYxYR4wJX+FlAj
         Q+wg/dCpMZPwmN36bhVnl89njuj5Ar/o1JcpqzbI/0OJMtbzaj/fkbt1Gd6mf4/Mlyky
         JwbI+QelqKHKFmxX/4Uurkd9LyuUKVmYZhU+pQ4nWSF5LBNlBd+rHrn0X7mmVrLRNhzQ
         IwSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=oxx5d4arRYi8UQ3e19zu2lEIeqeQWihBfh/wzj+JE64=;
        fh=gBBIRGaRe+dHCWEzU69II4UNERf8ej/oWIsaHByE/Is=;
        b=DmeuvTGZPk0n0vvhFfLHu+HShpxl21wI9NoFWoaNmQzIaswGnc8CwTDlDA9EYD4tK2
         fTRaNJpDlekhLdN/Rn/Mys8bK0Ask7DijXnJjTvNp+kSEo1JZqmmVqEzhUa2r2EQCc2U
         Na0YMNEZWl/0FC4RUlGY4I4o9xi00oUQJEzARC2TKTjSwzf+iFgubYdUBb/zqVQ292K1
         fUwMPbLL7fxR5X3GIFywDOkHld/Wl6BNZykjQSfQy6sMulBHT211LZorGe66GlLE2ViS
         I4KR/I/VLSVaSElH/kjo3vBZUfJNCPeNHcXPZSmJAWLjphTQgb8G+gOacemx91s//8qR
         Ydxw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=JUzWPSXT;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738799042; x=1739403842; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=oxx5d4arRYi8UQ3e19zu2lEIeqeQWihBfh/wzj+JE64=;
        b=Ygx6WC0MCj/7CE/FgRQrm+Dspo8eVgjEmW1hsq5IQ9tsJUu/wrCOKUCocZhaEa09Rr
         F0z+RHB9boCWL6GSd0eBb+J3vHPdrN4TlXYlryMzT37W2JUDTvIPnJO4xxV2FJh+Vq6+
         BlI/DV81SWuxljJ40SAKR5DpOWQuf1wp7JZK3P1WGn76VjDCC7yfm6DeILzUx68w/hYD
         ZrJIP3AgBj1sJaumEtwD09evxD10Uvf3hvMxmp9WzbGrlqxtut2LMT2pk/WSPfaS595Q
         tdMN/JBurg02u0BwX2NbwCmBirqRleZwKheXyDaXMXk+A5QGQts4R9GZIpIbtHPuLOVz
         DchQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1738799042; x=1739403842; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=oxx5d4arRYi8UQ3e19zu2lEIeqeQWihBfh/wzj+JE64=;
        b=dpV19sBUD7liBffrMJNovwjanYG+ZluhV2dmW0QBQgrU6dQuUiADPVi+tfvJMOfu11
         EgeS9nbhfjN2flMkAYJY48ZpeLT1G6nIlP0VtMxv+L20Az6UtWteB+/g+W5Cggeb2G2I
         mKRBTl+iNPXoy3Vf6kIzEbeYccnXsePCfsBG6Ym3ICer5bJwZy3Xwl2HOu/8/Ogum6ui
         JFfbKbi5d4ivXEyzsxXDrrN9cuPC441OGMUlaFgprBqtRQpLNvJNKAmheuAsTry6BoBA
         lbIUQ2pIRNnRdqZMhLPpYobqciDQLzgBKLkVT4ejc/Ybm7Jlq2x6hZNhLCqoiaxATGI5
         WijA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738799042; x=1739403842;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=oxx5d4arRYi8UQ3e19zu2lEIeqeQWihBfh/wzj+JE64=;
        b=dgBtUbFrxeqe1HezmUJ6s9AiJF97dQ2ENbC/cUO5G9mNbNn5PIBPYosSp1K/G+xBDq
         0Xci5+eHzOpyFR68kbjZYIwC3GLUZjZr8qWW61rGibiQXPDnVfjoOIGEiexkkEHAGWLw
         Y6wPjAsKDFxS2cLm8QOVmlsPC2dX5C4zLZAVwemHHgpO6QA27TpcAEAXdhk6xKxkO+jp
         4zVusNBTSA9wW618fapf/pzZv71TdvEoEiXKcjnnvoXT0jfxdSf39MMAQyHyGlo5t7I8
         V25p9HWc9Gb5IffFmCjs9HhSJ9HttCFxM+7/fi0ilYDrYJjJV0jsG+8MEY23A5k1ALrR
         YICg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVXrFzUlhsxjK8Z4770k1BgRmdkghWvet4+5lEnB9B9dCeMtx7rGhqezzOcALO3bGaOehw88g==@lfdr.de
X-Gm-Message-State: AOJu0YzrpOdsZxiSqOs87c8btieClpW3DX5nynWODSW+1VSePOoOhOQb
	uXXkTcu7LpZ9hpiaVTxhVZvE08AR0neCjOBsAwXyA2jnYfCbxDZ0
X-Google-Smtp-Source: AGHT+IGu55xtDoJZdcZUzz6WTVjQRVqhIDiDAT+CP4EES/BFIPNqS4/BnK/mxh9BtlZlb/kDLthEPw==
X-Received: by 2002:a05:600c:548e:b0:436:5fc9:309d with SMTP id 5b1f17b1804b1-4390d56f569mr43248945e9.30.1738799040397;
        Wed, 05 Feb 2025 15:44:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3496:b0:436:1a8a:2376 with SMTP id
 5b1f17b1804b1-43912b33826ls1551895e9.2.-pod-prod-03-eu; Wed, 05 Feb 2025
 15:43:58 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVPD2hZEFoPO3P4Or0GgVVES5AGLy0RlsCZ89XMN9QlSflRTOc5z2jfLyLuGoOBzU6+SuHQj3PfDTk=@googlegroups.com
X-Received: by 2002:a05:6000:1787:b0:38b:da31:3e3e with SMTP id ffacd0b85a97d-38db48813c1mr3701929f8f.28.1738799037728;
        Wed, 05 Feb 2025 15:43:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738799037; cv=none;
        d=google.com; s=arc-20240605;
        b=fMBWL1aWYpl2qu6S3Zz1EqE5qt1nps2/yxkyTS2cL81A61Tt9fg1J7a03ngHYwbSiY
         OE5Tw6A58WvHJ2oGAv/IpupPZ0GpR9/gYqCgWQ2puoT8LtXZTtBcNCUuz0uowhdjJnO1
         F7FLigRhlM+lr0RKyQKxOW9kdURC5ckHTsf04Nw/c7f+Q1fKagVC5+woTUBSB7oV9cvd
         +rOURcAwmR1Q86DS9BUm2F5gdP2cohYwrHzclTjCQ8g1XdcAz07MkX9sWmHNRNPkv1Aq
         UeZidoZQKI6i/iEq3zWt3oqrRqIQqlW1cKkxdsXV9o+2PnyRK3jtyUaPKHIGw2D5Y8Lg
         PO9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=aGo4tCOA20uwm5WJCsot6mmTXWb0qFu219UCGH8y36Q=;
        fh=1x8LQJtESPTQiyNwp7P+N8jvnLgA/m6SpUX0AXbz4nY=;
        b=VGgqQS3hRy6cexhbSO0/FdlW2p3vek+ueurbMs6bKhTB6ufRHRsJ9PDQCfkEna+OD7
         rKODh7UBobBIcNxpJNCvIMwe04ix2M5GpjkPLOePafCS5CRpZ/pEUmuSPAcSZYLHvH1i
         ADvUE3OMHG6DN5gDlf5d+E8oev9T0stTGM6u+9Vkrp4fAGWWLhLqyVPNFNLRleAkhOkN
         aydatx4fEt6sCFpY9ZdWj3cI9PiWfwXc7OAeULm+QA2jSDEbZE0ZYQ+8Ly+5eaejEuuL
         DlKhmatQcJErUQJFqgxhsDyEooydPvRzfgNwTV82AAnDfdheyPnsNs7+WND6PRyqWoLp
         hIgg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=JUzWPSXT;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x430.google.com (mail-wr1-x430.google.com. [2a00:1450:4864:20::430])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-38dbde0e6d0si2398f8f.3.2025.02.05.15.43.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 Feb 2025 15:43:57 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) client-ip=2a00:1450:4864:20::430;
Received: by mail-wr1-x430.google.com with SMTP id ffacd0b85a97d-38db8f8786fso140089f8f.1
        for <kasan-dev@googlegroups.com>; Wed, 05 Feb 2025 15:43:57 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVh6+cjTL7ioGYFwni7EhKaxvCKpJBKUW/jWQ4OXr2Jlu4M9eQm24mwXQElDf5PsCAt5nuSG7ZHRqA=@googlegroups.com
X-Gm-Gg: ASbGncu943MIgMDJLSTEDqFNt6DVK35OVXItIDyhZFRHCkqqSTzxD0SmW6K5huiPQtG
	B7pxPWnlksG3v/HldM/dXssmItBwNcFKZMKfsZSc2BgORgLYFfSa6crsZnHtLNoUFNG0lIPhnVQ
	==
X-Received: by 2002:a05:6000:11c3:b0:38c:617c:ee22 with SMTP id
 ffacd0b85a97d-38db48e8e74mr2835161f8f.54.1738799036822; Wed, 05 Feb 2025
 15:43:56 -0800 (PST)
MIME-Version: 1.0
References: <cover.1738686764.git.maciej.wieczor-retman@intel.com> <808cc6516f47d5f5e811d2c237983767952f3743.1738686764.git.maciej.wieczor-retman@intel.com>
In-Reply-To: <808cc6516f47d5f5e811d2c237983767952f3743.1738686764.git.maciej.wieczor-retman@intel.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 6 Feb 2025 00:43:46 +0100
X-Gm-Features: AWEUYZm1UyfErQs1w01vhNGFZmNjvN3ORJYc2s5iPoOpZVl-pALgPbNFMXszvaU
Message-ID: <CA+fCnZd3sP1_x2c5FvztA6LzsBY3Fq3cD5cJ6FQ+FAnmawe06Q@mail.gmail.com>
Subject: Re: [PATCH 01/15] kasan: Allocation enhancement for dense tag-based mode
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: luto@kernel.org, xin@zytor.com, kirill.shutemov@linux.intel.com, 
	palmer@dabbelt.com, tj@kernel.org, brgerst@gmail.com, ardb@kernel.org, 
	dave.hansen@linux.intel.com, jgross@suse.com, will@kernel.org, 
	akpm@linux-foundation.org, arnd@arndb.de, corbet@lwn.net, dvyukov@google.com, 
	richard.weiyang@gmail.com, ytcoode@gmail.com, tglx@linutronix.de, 
	hpa@zytor.com, seanjc@google.com, paul.walmsley@sifive.com, 
	aou@eecs.berkeley.edu, justinstitt@google.com, jason.andryuk@amd.com, 
	glider@google.com, ubizjak@gmail.com, jannh@google.com, bhe@redhat.com, 
	vincenzo.frascino@arm.com, rafael.j.wysocki@intel.com, 
	ndesaulniers@google.com, mingo@redhat.com, catalin.marinas@arm.com, 
	junichi.nomura@nec.com, nathan@kernel.org, ryabinin.a.a@gmail.com, 
	dennis@kernel.org, bp@alien8.de, kevinloughlin@google.com, morbo@google.com, 
	dan.j.williams@intel.com, julian.stecklina@cyberus-technology.de, 
	peterz@infradead.org, cl@linux.com, kees@kernel.org, 
	kasan-dev@googlegroups.com, x86@kernel.org, 
	linux-arm-kernel@lists.infradead.org, linux-riscv@lists.infradead.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
	linux-doc@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=JUzWPSXT;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430
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

On Tue, Feb 4, 2025 at 6:34=E2=80=AFPM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> Tag-based KASAN (on arm64) works by generating a random 8-bit tag and
> putting it in both the top byte of the pointer (that points to the
> allocated memory) and into all bytes of shadow memory that correspond to
> the chunk of allocated regular memory. Each byte of shadow memory covers
> a 16 byte chunk of allocated memory - a value called KASAN granularity.
> This means that out-of-bounds memory accesses that happen inside the 16
> bytes can't be caught.
>
> The dense mode offers reducing the tag width from 8 to 4 bits and
> storing two tags in one byte of shadow memory - one in the upper 4 bits
> of the byte and one in the lower 4. This way one byte of shadow memory
> can cover 32 bytes of allocated memory while still keeping the "16 bytes
> per one tag" granularity. The lower 4 bits of each shadow byte map bytes
> of memory with offsets 0-15 and the upper 4 bits map offsets 16-31.
>
> Example:
> The example below shows how the shadow memory looks like after
> allocating 48 bytes of memory in both normal tag-based mode and the
> dense mode. The contents of shadow memory are overlaid onto address
> offsets that they relate to in the allocated kernel memory. Each cell
> |    | symbolizes one byte of shadow memory.
>
> =3D The regular tag based mode:
> - Randomly generated 8-bit tag equals 0xAB.
> - 0xFE is the tag that symbolizes unallocated memory.
>
> Shadow memory contents:           |  0xAB  |  0xAB  |  0xAB  |  0xFE  |
> Shadow memory address offsets:    0        1        2        3        4
> Allocated memory address offsets: 0        16       32       48       64
>
> =3D The dense tag based mode:
> - Randomly generated 4-bit tag equals 0xC.
> - 0xE is the tag that symbolizes unallocated memory.
>
> Shadow memory contents:           |0xC 0xC |0xC 0xE |0xE 0xE |0xE 0xE |
> Shadow memory address offsets:    0        1        2        3        4
> Allocated memory address offsets: 0        32       64       96       128
>
> Add a new config option and defines that can override the standard
> system of one tag per one shadow byte.
>
> Add alternative version of the kasan_poison() that deals with tags not
> being aligned to byte size in shadow memory.
>
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> ---
>  include/linux/kasan.h | 18 ++++++++++++++++++
>  lib/Kconfig.kasan     | 21 +++++++++++++++++++++
>  mm/kasan/kasan.h      |  4 +---
>  mm/kasan/shadow.c     | 33 ++++++++++++++++++++++++++++++---
>  4 files changed, 70 insertions(+), 6 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 03b440658817..ea0f5acd875b 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -35,6 +35,24 @@ typedef unsigned int __bitwise kasan_vmalloc_flags_t;
>
>  /* Software KASAN implementations use shadow memory. */
>
> +#ifdef CONFIG_KASAN_SW_TAGS_DENSE
> +#define KASAN_GRANULE_SHIFT    (KASAN_SHADOW_SCALE_SHIFT - 1)
> +#define KASAN_SHADOW_SCALE_SIZE        (1UL << KASAN_SHADOW_SCALE_SHIFT)
> +static inline u8 kasan_dense_tag(u8 tag)
> +{
> +       return (tag << KASAN_TAG_WIDTH | tag);
> +}
> +#else
> +#define KASAN_GRANULE_SHIFT    KASAN_SHADOW_SCALE_SHIFT
> +#define KASAN_SHADOW_SCALE_SIZE        (1UL << KASAN_GRANULE_SHIFT)
> +static inline u8 kasan_dense_tag(u8 tag)
> +{
> +       return tag;
> +}
> +#endif
> +
> +#define KASAN_GRANULE_SIZE     (1UL << KASAN_GRANULE_SHIFT)
> +

Is there a reason these definitions are added to
include/linux/kasan.h? At least within this patch, they are only used
within mm/kasan, so let's keep them in mm/kasan/kasan.h.

>  #ifdef CONFIG_KASAN_SW_TAGS
>  /* This matches KASAN_TAG_INVALID. */
>  #define KASAN_SHADOW_INIT 0xFE
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 98016e137b7f..d08b4e9bf477 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -19,6 +19,13 @@ config ARCH_DISABLE_KASAN_INLINE
>           Disables both inline and stack instrumentation. Selected by
>           architectures that do not support these instrumentation types.
>
> +config ARCH_HAS_KASAN_SW_TAGS_DENSE
> +       bool
> +       help
> +         Enables option to compile tag-based KASAN with densely packed t=
ags -
> +         two 4-bit tags per one byte of shadow memory. Set on architectu=
res
> +         that have 4-bit tag macros.
> +
>  config CC_HAS_KASAN_GENERIC
>         def_bool $(cc-option, -fsanitize=3Dkernel-address)
>
> @@ -223,4 +230,18 @@ config KASAN_EXTRA_INFO
>           boot parameter, it will add 8 * stack_ring_size bytes of additi=
onal
>           memory consumption.
>
> +config KASAN_SW_TAGS_DENSE
> +       bool "Two 4-bit tags in one shadow memory byte"
> +       depends on KASAN_SW_TAGS
> +       depends on ARCH_HAS_KASAN_SW_TAGS_DENSE

I think this should also depend on KASAN_OUTLINE: Clang/GCC aren't
aware of the dense mode.

> +       help
> +         Enables packing two tags into one shadow byte to half the memor=
y usage
> +         compared to normal tag-based mode.

But adds some performance impact?

> +
> +         After setting this option, tag width macro is set to 4 and size=
 macros
> +         are adjusted based on used KASAN_SHADOW_SCALE_SHIFT.

I think this paragraph is an implementation detail and we can drop it.

> +
> +         ARCH_HAS_KASAN_SW_TAGS_DENSE is needed for this option since th=
e
> +         special tag macros need to be properly set for 4-bit wide tags.
> +
>  endif # KASAN
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 72da5ddcceaa..0e04c5e2c405 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -128,9 +128,7 @@ static inline bool kasan_requires_meta(void)
>
>  #endif /* CONFIG_KASAN_GENERIC */
>
> -#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
> -#define KASAN_GRANULE_SIZE     (1UL << KASAN_SHADOW_SCALE_SHIFT)
> -#else
> +#ifdef CONFIG_KASAN_HW_TAGS
>  #include <asm/mte-kasan.h>
>  #define KASAN_GRANULE_SIZE     MTE_GRANULE_SIZE
>  #endif
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index d6210ca48dda..368503f54b87 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -123,7 +123,8 @@ EXPORT_SYMBOL(__hwasan_memcpy);
>
>  void kasan_poison(const void *addr, size_t size, u8 value, bool init)
>  {
> -       void *shadow_start, *shadow_end;
> +       u8 *shadow_start, *shadow_end, *shadow_start_aligned, *shadow_end=
_aligned, tag;
> +       u64 addr64, addr_start_aligned, addr_end_aligned;
>
>         if (!kasan_arch_is_ready())
>                 return;
> @@ -134,16 +135,42 @@ void kasan_poison(const void *addr, size_t size, u8=
 value, bool init)
>          * addresses to this function.
>          */
>         addr =3D kasan_reset_tag(addr);
> +       addr64 =3D (u64)addr;
>
> -       if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
> +       if (WARN_ON(addr64 & KASAN_GRANULE_MASK))
>                 return;
>         if (WARN_ON(size & KASAN_GRANULE_MASK))
>                 return;
>
>         shadow_start =3D kasan_mem_to_shadow(addr);
>         shadow_end =3D kasan_mem_to_shadow(addr + size);
> +       addr_start_aligned =3D round_up(addr64, KASAN_SHADOW_SCALE_SIZE);
> +       addr_end_aligned =3D round_down(addr64 + size, KASAN_SHADOW_SCALE=
_SIZE);
> +       shadow_start_aligned =3D kasan_mem_to_shadow((void *)addr_start_a=
ligned);
> +       shadow_end_aligned =3D kasan_mem_to_shadow((void *)addr_end_align=
ed);
> +
> +       /* If size is empty just return. */
> +       if (!size)
> +               return;
>
> -       __memset(shadow_start, value, shadow_end - shadow_start);
> +       /* Memset the first unaligned tag in shadow memory. */
> +       if (addr64 % KASAN_SHADOW_SCALE_SIZE) {

So this is required, because KASAN_SHADOW_SCALE_SIZE is 32 but minimal
slab alignment is still KASAN_GRANULE_SIZE =3D=3D 16... We should at least
hide this check is under IS_ENABLED(KASAN_SW_TAGS_DENSE).

> +               tag =3D *shadow_start & KASAN_TAG_MASK;
> +               tag |=3D value << KASAN_TAG_WIDTH;
> +               *shadow_start =3D tag;
> +       }
> +
> +       /* Memset the middle aligned part in shadow memory. */
> +       tag =3D kasan_dense_tag(value);
> +       __memset(shadow_start_aligned, tag, shadow_end_aligned - shadow_s=
tart_aligned);
> +
> +       /* Memset the last unaligned tag in shadow memory. */
> +       if ((addr64 + size) % KASAN_SHADOW_SCALE_SIZE) {

Would it be possible to move this part to kasan_poison_last_granule()?
That functions seems to be serving a similar purpose but for the
Generic mode.

It might also be cleaner to add a kasan_poison_first_granule() that
contains the if (addr64 % KASAN_SHADOW_SCALE_SIZE) check.

> +               tag =3D KASAN_TAG_MASK << KASAN_TAG_WIDTH;
> +               tag &=3D *shadow_end;
> +               tag |=3D value;
> +               *shadow_end =3D tag;
> +       }
>  }
>  EXPORT_SYMBOL_GPL(kasan_poison);
>
> --
> 2.47.1
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZd3sP1_x2c5FvztA6LzsBY3Fq3cD5cJ6FQ%2BFAnmawe06Q%40mail.gmail.com.
