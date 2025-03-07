Return-Path: <kasan-dev+bncBCU4TIPXUUFRBBOFVK7AMGQEADVGI2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B207A561E6
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Mar 2025 08:38:47 +0100 (CET)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-2ff581215f7sf2818274a91.3
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Mar 2025 23:38:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741333126; cv=pass;
        d=google.com; s=arc-20240605;
        b=NhG4ea+6+mOTerN2j9j1J/TDUyfsaJTQkXMaz3wNjG92lRew6Vp6yd9V35/bB3777l
         ejSUVsnbRfyPAArwNxcRpcDISN/6VFDR0PP24ZI81gQfv02yxu8uYgTQizQHxE933Vjf
         uYJqNENUiKaNyx3+go1sBAP1QNuNLLCIFiFR4popOUf8D8zQrDRy124QLFi7Dfbxttmy
         lLk1glsl3Zeqd5YRNVVCu+eXA5R6bPhYVGp4S9cp8hdoo3Jj4CPpJM8RUyu6Lo3VgPUe
         I5SpRoFHtx0nmw3d574ACSiFGseIPXLxLvedo7nIhiIkEDST3e17OujNxGHBXe2QakWg
         bZLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=TeJ6mrVTVR55xvrCenc180c8tA6U0Tn0lXCtJpK9ovk=;
        fh=jzTMCPW2GgRvArcq+Jz8+u8lweK+L9Grk2t+TLeVkFY=;
        b=WKKJ2+b0g42rYmpI25Uq3Qb/ldeD7tL1cFehLMaErJLMgLrhiTJ0GjgrcDWkDhXVNL
         MSCaThX4rdNTHwM1An3UsLi+GFZORkCdeh2qHmB76q0NZZY+6WxdV72paBaygLMDEJni
         Fwrm4tvvlM0IegaQGPrE/0qvnsY8QKiFfggk+9oWEfC58Fmmexx0GYYlqSdUEE5jY3sM
         0FRQMBr/PvwaagfxGjCLC9cZTaYfjz+hj/QertV6p9Y5QxuHkeudNYge44MmKdy95HYa
         UFArKVtrnkehZaLu875ulIJxupkNXnpoHNQh8KAiw4jjw4r19wfU/I99PtihxPMpJVQ9
         bqLQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GgnKYnOV;
       spf=pass (google.com: domain of ardb@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741333126; x=1741937926; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=TeJ6mrVTVR55xvrCenc180c8tA6U0Tn0lXCtJpK9ovk=;
        b=RIWQUzuGyumklE2uGN3R7QCxlcjlLZB2wlJuQaow60X91njYWZRpWPrDxQ4FgZ0XaY
         RvEDSPtnE5IXcldrpwhheQEzUlVSssUmtGorgv4+XF5BGbteb57Rgpd2ST0nUM5lXXXx
         e7htf+P6OnOyT5VGI7Y+DzbVpkTY49ygFIlpm3OWk1dtkRuQ/xOOJMI9+bcO4G1qT6p4
         1x3MmEep4NtY2AJcsV315LsDqZXQ/3MyMrxfll/zNeaj2uVAcidlpfWN7lNibwEljVZd
         sX+uTHCnuDE8RuN/a3vSxz9ye4Di5M+xe51cCT+6IynJabqIaYS6pBrPPNNMVPt6AzNK
         MjcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741333126; x=1741937926;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TeJ6mrVTVR55xvrCenc180c8tA6U0Tn0lXCtJpK9ovk=;
        b=S+lWlqCV5gy5qXr+yEM1f+P/ee7V3HKVuJP2W7vc2YigMexP/lUrX6XtxlYlHUV2m+
         KLQMRa3EV2fZXAhlgcOEgMwPyqb+dqe2rQaR9C6rmaRMUosdgcxY7a4z58Zcp0LRTgvX
         ewjlm0axBzfY29SAkekppD0t1+G/noayuO8LZYkKGZ+n9b5cEY0+3qRyFDK6XeaFMAfx
         tq9eIiYh+cmChU8maCVgFvy4VbRC8cNbfnQZSPLqLBtbBEYksqdacgLVTnWyEH+PfADv
         Miyz49EMEwkQJ9ecuZxrlcDVHOyKeKwq7LW1HYtLDBWYAp4+B1rHDlC/R8bAOZwOMowN
         QKdA==
X-Forwarded-Encrypted: i=2; AJvYcCWDBCjh6CeLoJvRycAHRCkFjqZiO+vF3jjdS+B9rVeiZyzBL+VvuTsiKgwnSHnv1qRCOsz4Zw==@lfdr.de
X-Gm-Message-State: AOJu0YzbhIh1FUoSgpXwg/nmHzECFeCqm1uqlQ+YTeOwDvojJjT0/1kU
	zo67PgZwBHnbyrz0/m6Ra3KGBuRLA7bL0fQ9sWcQJxSIGBf/CsuF
X-Google-Smtp-Source: AGHT+IFrCKMHnuvXTS+AsRPLWYMZtfzABgTeqsh+/iHviZ6yhvhgZIyPRGGC2wCOZB0CnfvUPKCyBg==
X-Received: by 2002:a17:90a:d605:b0:2ee:db8a:2a01 with SMTP id 98e67ed59e1d1-2ff7cf128cdmr3523923a91.30.1741333125547;
        Thu, 06 Mar 2025 23:38:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVG3P9s/NRHCJ3cc4f5/JmyY0+FGoCPPL7p/zotImK53og==
Received: by 2002:a17:90a:f00a:b0:2f8:3555:13c3 with SMTP id
 98e67ed59e1d1-2ff6289d673ls1712461a91.2.-pod-prod-09-us; Thu, 06 Mar 2025
 23:38:42 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU55ungHU6Sn8ZtnRBbT4HRy2tgjO+WVWhk6RHCN/M+jahg3U3pPD+6LbmP40UTL6/I93MX8Zzv5O8=@googlegroups.com
X-Received: by 2002:a17:90b:4c44:b0:2ff:4e8f:b055 with SMTP id 98e67ed59e1d1-2ff7cf14526mr4012511a91.35.1741333122577;
        Thu, 06 Mar 2025 23:38:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741333122; cv=none;
        d=google.com; s=arc-20240605;
        b=j4a85BvDpksUuVE+xNWpkqfFzbnynHeOIpDHYpHyKpfecVPKB0/UVu7Q/OAEJ+3Kg2
         vXDFjeflWmsBisL5LGLwFcGLFw5fF2VY8ifXm8TCKdxqDqcR6+3uJZpTo77xx2Jgphl3
         yC10tZj4H8IOja2EtYKehtrjFJGcyuNQNIYiu+MZYaTn60wypVmMv9hZgVDNA7aMFTax
         tXXA0xfqMBRYrt9KzfUgtEWEXNX+tekfA/WKW/QseTWVfIMsaXJ5YVkHdzYT7lX6UhqU
         k01h2S3dQsKvXKh16hAtU+eQPB+k5gPZ25kP3y7KnqG0WPfmTRRDZpzf/eQOHpEA67qg
         mopQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Bv2bhPZva6gHXHw0NJH39PcDZGk29eqJhi4KHNncWvk=;
        fh=R8VparEAPLrh2fQ+lEf432lr7IsPI6uF3OUT3PdhNDU=;
        b=Y0uB818V8IFwwh/pM4z0hbPCoR16WBUpMch7bJkwgowoTno5o9lhH6gh77PdFIGdTz
         iO+cjQlpwJ41EZLQdgmTSMzPuqRezNydnn1u998LzccIu1ywM4gybwcl0vco0XQfO+ZQ
         fh8JXmxam9MK68APE8dQSiOe+LdW+kKBlQWAjrdL6YSdp6C5mUYfiOGegz9w316wLpOo
         filuSjvfmyiEIkCnS21dp4fsTam94Hs7M4E3ze0lp58nqhhGUcrIm++xrdKP9uAFa5VQ
         zLm5vCmC6BB4jH7hWhnPOMUJJuvqc6mL20fYXOOPbck0HxTOBFUenUoqUD8mLt63J6il
         V3hg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GgnKYnOV;
       spf=pass (google.com: domain of ardb@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2ff798e8cd7si88267a91.0.2025.03.06.23.38.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 06 Mar 2025 23:38:42 -0800 (PST)
Received-SPF: pass (google.com: domain of ardb@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id E20AA5C041E
	for <kasan-dev@googlegroups.com>; Fri,  7 Mar 2025 07:36:24 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 5F726C4CEE7
	for <kasan-dev@googlegroups.com>; Fri,  7 Mar 2025 07:38:41 +0000 (UTC)
Received: by mail-lf1-f50.google.com with SMTP id 2adb3069b0e04-5498c156f1dso1595166e87.3
        for <kasan-dev@googlegroups.com>; Thu, 06 Mar 2025 23:38:41 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWYgf2sg+OW/rlkJYVm4PRkshFYj133B567mIkdxrZeZLN/gy0obbUhso0S61fiyKybUcbvtVxolEA=@googlegroups.com
X-Received: by 2002:a05:6512:3a84:b0:549:4e7b:dcf7 with SMTP id
 2adb3069b0e04-54990e2bc5fmr933581e87.3.1741333119619; Thu, 06 Mar 2025
 23:38:39 -0800 (PST)
MIME-Version: 1.0
References: <20250307050851.4034393-1-anshuman.khandual@arm.com>
In-Reply-To: <20250307050851.4034393-1-anshuman.khandual@arm.com>
From: "'Ard Biesheuvel' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 7 Mar 2025 08:38:28 +0100
X-Gmail-Original-Message-ID: <CAMj1kXFufE9UPGMsqv1ARWm6SyUCcJL+m4F4mWa0jCyhJqf2Jg@mail.gmail.com>
X-Gm-Features: AQ5f1JriIKmYESFhu_hdqeBJJ4pUmzhqZbcCfIaI5Z54kn_AuewlUh9N2EpQZFI
Message-ID: <CAMj1kXFufE9UPGMsqv1ARWm6SyUCcJL+m4F4mWa0jCyhJqf2Jg@mail.gmail.com>
Subject: Re: [PATCH] arm64/mm: Define PTE_SHIFT
To: Anshuman Khandual <anshuman.khandual@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Ryan Roberts <ryan.roberts@arm.com>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ardb@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=GgnKYnOV;       spf=pass
 (google.com: domain of ardb@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=ardb@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Ard Biesheuvel <ardb@kernel.org>
Reply-To: Ard Biesheuvel <ardb@kernel.org>
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

Hi Anshuman,

On Fri, 7 Mar 2025 at 06:09, Anshuman Khandual
<anshuman.khandual@arm.com> wrote:
>
> Address bytes shifted with a single 64 bit page table entry (any page table
> level) has been always hard coded as 3 (aka 2^3 = 8). Although intuitive it
> is not very readable or easy to reason about. Besides it is going to change
> with D128, where each 128 bit page table entry will shift address bytes by
> 4 (aka 2^4 = 16) instead.
>
> Let's just formalise this address bytes shift value into a new macro called
> PTE_SHIFT establishing a logical abstraction, thus improving readability as
> well. This does not cause any functional change.
>

I don't disagree with this goal, but PTE_SHIFT is really not the right
name. Given that PMD_SHIFT is the log2 of the area covered by a PMD,
PTE_SHIFT should be the log2 of the area covered by a PTE, and so
defining it to anything other than PAGE_SHIFT would be a mistake IMO.

Given that we are talking about the log2 of the size of the area
occupied by a descriptor, perhaps {PT}DESC_SIZE_ORDER would be a
better name?




> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Cc: Mark Rutland <mark.rutland@arm.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Ard Biesheuvel <ardb@kernel.org>
> Cc: Ryan Roberts <ryan.roberts@arm.com>
> Cc: linux-arm-kernel@lists.infradead.org
> Cc: linux-kernel@vger.kernel.org
> Cc: kasan-dev@googlegroups.com
> Signed-off-by: Anshuman Khandual <anshuman.khandual@arm.com>
> ---
> This patch applies on v6.14-rc5
>
>  arch/arm64/Kconfig                      |  2 +-
>  arch/arm64/include/asm/kernel-pgtable.h |  3 ++-
>  arch/arm64/include/asm/pgtable-hwdef.h  | 26 +++++++++++++------------
>  arch/arm64/kernel/pi/map_range.c        |  2 +-
>  arch/arm64/mm/kasan_init.c              |  6 +++---
>  5 files changed, 21 insertions(+), 18 deletions(-)
>
> diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
> index 940343beb3d4..fd3303f2ccda 100644
> --- a/arch/arm64/Kconfig
> +++ b/arch/arm64/Kconfig
> @@ -323,7 +323,7 @@ config ARCH_MMAP_RND_BITS_MIN
>         default 18
>
>  # max bits determined by the following formula:
> -#  VA_BITS - PAGE_SHIFT - 3
> +#  VA_BITS - PAGE_SHIFT - PTE_SHIFT
>  config ARCH_MMAP_RND_BITS_MAX
>         default 19 if ARM64_VA_BITS=36
>         default 24 if ARM64_VA_BITS=39
> diff --git a/arch/arm64/include/asm/kernel-pgtable.h b/arch/arm64/include/asm/kernel-pgtable.h
> index fd5a08450b12..7150a7a10f00 100644
> --- a/arch/arm64/include/asm/kernel-pgtable.h
> +++ b/arch/arm64/include/asm/kernel-pgtable.h
> @@ -49,7 +49,8 @@
>         (SPAN_NR_ENTRIES(vstart, vend, shift) + (add))
>
>  #define EARLY_LEVEL(lvl, lvls, vstart, vend, add)      \
> -       (lvls > lvl ? EARLY_ENTRIES(vstart, vend, SWAPPER_BLOCK_SHIFT + lvl * (PAGE_SHIFT - 3), add) : 0)
> +       (lvls > lvl ? EARLY_ENTRIES(vstart, vend, SWAPPER_BLOCK_SHIFT + \
> +       lvl * (PAGE_SHIFT - PTE_SHIFT), add) : 0)
>
>  #define EARLY_PAGES(lvls, vstart, vend, add) (1        /* PGDIR page */                                \
>         + EARLY_LEVEL(3, (lvls), (vstart), (vend), add) /* each entry needs a next level page table */  \
> diff --git a/arch/arm64/include/asm/pgtable-hwdef.h b/arch/arm64/include/asm/pgtable-hwdef.h
> index a9136cc551cc..43f98eac7653 100644
> --- a/arch/arm64/include/asm/pgtable-hwdef.h
> +++ b/arch/arm64/include/asm/pgtable-hwdef.h
> @@ -7,40 +7,42 @@
>
>  #include <asm/memory.h>
>
> +#define PTE_SHIFT 3
> +
>  /*
>   * Number of page-table levels required to address 'va_bits' wide
>   * address, without section mapping. We resolve the top (va_bits - PAGE_SHIFT)
> - * bits with (PAGE_SHIFT - 3) bits at each page table level. Hence:
> + * bits with (PAGE_SHIFT - PTE_SHIFT) bits at each page table level. Hence:
>   *
> - *  levels = DIV_ROUND_UP((va_bits - PAGE_SHIFT), (PAGE_SHIFT - 3))
> + *  levels = DIV_ROUND_UP((va_bits - PAGE_SHIFT), (PAGE_SHIFT - PTE_SHIFT))
>   *
>   * where DIV_ROUND_UP(n, d) => (((n) + (d) - 1) / (d))
>   *
>   * We cannot include linux/kernel.h which defines DIV_ROUND_UP here
>   * due to build issues. So we open code DIV_ROUND_UP here:
>   *
> - *     ((((va_bits) - PAGE_SHIFT) + (PAGE_SHIFT - 3) - 1) / (PAGE_SHIFT - 3))
> + *     ((((va_bits) - PAGE_SHIFT) + (PAGE_SHIFT - PTE_SHIFT) - 1) / (PAGE_SHIFT - PTE_SHIFT))
>   *
>   * which gets simplified as :
>   */
> -#define ARM64_HW_PGTABLE_LEVELS(va_bits) (((va_bits) - 4) / (PAGE_SHIFT - 3))
> +#define ARM64_HW_PGTABLE_LEVELS(va_bits) (((va_bits) - PTE_SHIFT - 1) / (PAGE_SHIFT - PTE_SHIFT))
>
>  /*
>   * Size mapped by an entry at level n ( -1 <= n <= 3)
> - * We map (PAGE_SHIFT - 3) at all translation levels and PAGE_SHIFT bits
> + * We map (PAGE_SHIFT - PTE_SHIFT) at all translation levels and PAGE_SHIFT bits
>   * in the final page. The maximum number of translation levels supported by
>   * the architecture is 5. Hence, starting at level n, we have further
>   * ((4 - n) - 1) levels of translation excluding the offset within the page.
>   * So, the total number of bits mapped by an entry at level n is :
>   *
> - *  ((4 - n) - 1) * (PAGE_SHIFT - 3) + PAGE_SHIFT
> + *  ((4 - n) - 1) * (PAGE_SHIFT - PTE_SHIFT) + PAGE_SHIFT
>   *
>   * Rearranging it a bit we get :
> - *   (4 - n) * (PAGE_SHIFT - 3) + 3
> + *   (4 - n) * (PAGE_SHIFT - PTE_SHIFT) + PTE_SHIFT
>   */
> -#define ARM64_HW_PGTABLE_LEVEL_SHIFT(n)        ((PAGE_SHIFT - 3) * (4 - (n)) + 3)
> +#define ARM64_HW_PGTABLE_LEVEL_SHIFT(n)        ((PAGE_SHIFT - PTE_SHIFT) * (4 - (n)) + PTE_SHIFT)
>
> -#define PTRS_PER_PTE           (1 << (PAGE_SHIFT - 3))
> +#define PTRS_PER_PTE           (1 << (PAGE_SHIFT - PTE_SHIFT))
>
>  /*
>   * PMD_SHIFT determines the size a level 2 page table entry can map.
> @@ -49,7 +51,7 @@
>  #define PMD_SHIFT              ARM64_HW_PGTABLE_LEVEL_SHIFT(2)
>  #define PMD_SIZE               (_AC(1, UL) << PMD_SHIFT)
>  #define PMD_MASK               (~(PMD_SIZE-1))
> -#define PTRS_PER_PMD           (1 << (PAGE_SHIFT - 3))
> +#define PTRS_PER_PMD           (1 << (PAGE_SHIFT - PTE_SHIFT))
>  #endif
>
>  /*
> @@ -59,14 +61,14 @@
>  #define PUD_SHIFT              ARM64_HW_PGTABLE_LEVEL_SHIFT(1)
>  #define PUD_SIZE               (_AC(1, UL) << PUD_SHIFT)
>  #define PUD_MASK               (~(PUD_SIZE-1))
> -#define PTRS_PER_PUD           (1 << (PAGE_SHIFT - 3))
> +#define PTRS_PER_PUD           (1 << (PAGE_SHIFT - PTE_SHIFT))
>  #endif
>
>  #if CONFIG_PGTABLE_LEVELS > 4
>  #define P4D_SHIFT              ARM64_HW_PGTABLE_LEVEL_SHIFT(0)
>  #define P4D_SIZE               (_AC(1, UL) << P4D_SHIFT)
>  #define P4D_MASK               (~(P4D_SIZE-1))
> -#define PTRS_PER_P4D           (1 << (PAGE_SHIFT - 3))
> +#define PTRS_PER_P4D           (1 << (PAGE_SHIFT - PTE_SHIFT))
>  #endif
>
>  /*
> diff --git a/arch/arm64/kernel/pi/map_range.c b/arch/arm64/kernel/pi/map_range.c
> index 2b69e3beeef8..3530a5427f57 100644
> --- a/arch/arm64/kernel/pi/map_range.c
> +++ b/arch/arm64/kernel/pi/map_range.c
> @@ -31,7 +31,7 @@ void __init map_range(u64 *pte, u64 start, u64 end, u64 pa, pgprot_t prot,
>  {
>         u64 cmask = (level == 3) ? CONT_PTE_SIZE - 1 : U64_MAX;
>         pteval_t protval = pgprot_val(prot) & ~PTE_TYPE_MASK;
> -       int lshift = (3 - level) * (PAGE_SHIFT - 3);
> +       int lshift = (3 - level) * (PAGE_SHIFT - PTE_SHIFT);
>         u64 lmask = (PAGE_SIZE << lshift) - 1;
>
>         start   &= PAGE_MASK;
> diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
> index b65a29440a0c..90548079b42e 100644
> --- a/arch/arm64/mm/kasan_init.c
> +++ b/arch/arm64/mm/kasan_init.c
> @@ -190,7 +190,7 @@ static void __init kasan_pgd_populate(unsigned long addr, unsigned long end,
>   */
>  static bool __init root_level_aligned(u64 addr)
>  {
> -       int shift = (ARM64_HW_PGTABLE_LEVELS(vabits_actual) - 1) * (PAGE_SHIFT - 3);
> +       int shift = (ARM64_HW_PGTABLE_LEVELS(vabits_actual) - 1) * (PAGE_SHIFT - PTE_SHIFT);
>
>         return (addr % (PAGE_SIZE << shift)) == 0;
>  }
> @@ -245,7 +245,7 @@ static int __init root_level_idx(u64 addr)
>          */
>         u64 vabits = IS_ENABLED(CONFIG_ARM64_64K_PAGES) ? VA_BITS
>                                                         : vabits_actual;
> -       int shift = (ARM64_HW_PGTABLE_LEVELS(vabits) - 1) * (PAGE_SHIFT - 3);
> +       int shift = (ARM64_HW_PGTABLE_LEVELS(vabits) - 1) * (PAGE_SHIFT - PTE_SHIFT);
>
>         return (addr & ~_PAGE_OFFSET(vabits)) >> (shift + PAGE_SHIFT);
>  }
> @@ -269,7 +269,7 @@ static void __init clone_next_level(u64 addr, pgd_t *tmp_pg_dir, pud_t *pud)
>   */
>  static int __init next_level_idx(u64 addr)
>  {
> -       int shift = (ARM64_HW_PGTABLE_LEVELS(vabits_actual) - 2) * (PAGE_SHIFT - 3);
> +       int shift = (ARM64_HW_PGTABLE_LEVELS(vabits_actual) - 2) * (PAGE_SHIFT - PTE_SHIFT);
>
>         return (addr >> (shift + PAGE_SHIFT)) % PTRS_PER_PTE;
>  }
> --
> 2.30.2
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAMj1kXFufE9UPGMsqv1ARWm6SyUCcJL%2Bm4F4mWa0jCyhJqf2Jg%40mail.gmail.com.
