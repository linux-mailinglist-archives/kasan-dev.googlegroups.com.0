Return-Path: <kasan-dev+bncBDW2JDUY5AORB25K6O2QMGQEK2S4NBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 533B8951F58
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 18:03:57 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-2f1752568cfsf473241fa.1
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 09:03:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723651436; cv=pass;
        d=google.com; s=arc-20160816;
        b=POdFmdwiWXrW4y4B6AKA/AETOAwaNrD+uZ5iwvqZzINb2tYp4vWRpzApOlKqDEzxbW
         x3SNFwahE0NkQ5mTCPCeXm+BNma33EZ/BCpKZO63fBAMqxt+hC6bRh1/HrQrXhuEsQKD
         Z/hTDAlfo+yHt7+NWoL6e5pezw3ki5fU12OSrK9u0QcLHjGnUwiJEGVV824t8fpk+lOi
         T93cBkg6apXu5vmMOJcDwRRD3uZqSJdknsxZ9mX01JlXN8EkL4BHbmJADOoqhP/8NPjL
         fnaFVR7+KJPrHWIBBeC1Gt4p9k6pXf2d2zbSeBBZq12KGfPjt1NPOqRQ9Q41Z0eBXRT3
         DkCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=Wz7jxxGY1S8s6JRDQShuuptQOoZOMC0lpxsG+5KSBCY=;
        fh=wSUtrSn2z1LBodmtKe2lVWF5gF+SNFs2wMn173nuFao=;
        b=C4MW6DdMkp9+WQaFG7AB1X4Ab3ikuTwnCHQQX48JmjV4OdjWw2MvQYo8uOckxdMnpe
         CdScs4a4856fnq5d8kmPqBigZgjzYXCdK6/DNI8zD4CgsWBX/Y484mEk0+BGGHEa++sz
         QWDtkzjtXUCNih9fswt0U+pvAf1OjEL2EKC97BrH4S94rXAo/b3m18qkukf9g0H5JDNl
         cllxR73X5qZ0uoyXa67UYPc/WWvu2QrLUjsd21Gp330thmCeiy1XCMN7Nj4s+AFXwX30
         RU0pCYWjj3mTD40iVvOnyrTCUiOFkf75Aop1+xdbDnpMr74lJJIPieb/2D7dhqMK6B0a
         k78A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=TqSj2y2V;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723651436; x=1724256236; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Wz7jxxGY1S8s6JRDQShuuptQOoZOMC0lpxsG+5KSBCY=;
        b=EzmGvGBlAO4iV4xIro9TOBoyW5ess5N/VXWJqtf+azqVEurHPRA//x8pZxLFIvCmw5
         fYwqkigaF/qWsu1+VxLTIQs3DfExXvw/xmTH3eBIDL5Snd4V8bi8j9hkzC3nJBPUuZvk
         b7n5QXURfvqHwXrTtl796CyoW2kNow+T05J6Gj7V3D4H8qK7XrVJz3FrMfyzX72A+JDW
         AgUZMp1CarrjjWbyPJ9tAgzrFH59U6EwpMqQZC1D3dyBD2Z/o2aPTANJTRCVt0eQ+ekP
         hCk4Dj078s5A7MtqRsSV/WPCdGtgIZGOY6RfVqEgA9/3VwN/H0FBa6z3cVRE7cz2DbKK
         axuw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1723651436; x=1724256236; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Wz7jxxGY1S8s6JRDQShuuptQOoZOMC0lpxsG+5KSBCY=;
        b=Ys4jCyQcBT97AzxFIQT4oOoVUJ6dRvYIRgzf7iPuPpp1uSgbanilX/MrtjTxCTfmvA
         5U1tXaG2uLIQDGlVUaIqESBDfUhOmbTHW3ccUMAUPl2x8lU7uZLpk/qKMG3nxNzPzswz
         zacln2GjaSb54+WXXWfsJQP8WdnkBk7LFP8nptCUv1M52Lagh5+PyqNgsmrWwyY8t9nD
         2H+uSN9HtTd31kL1Bsdnm6f0Zmt8JV6JH+Q3SCAsLWFMHNtXDDVNGA6kxOCVTuFr2+P3
         ALX070chk7L64tEkl18741ZcdBEtIAjJk72kn4/xd4iiCxNfvlv3PrE9Tdc4eKIXhyvJ
         LvbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723651436; x=1724256236;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Wz7jxxGY1S8s6JRDQShuuptQOoZOMC0lpxsG+5KSBCY=;
        b=Mb/nN/JVujzy8F4gm5YSxUH/Lp+oG1AEgsRFbvfLeigFEDV8eS7tuv62Vue2oAkcnl
         zUY7sgMTqBIAnXH/e4DgNyOZgdImcLYQ4C0knbJbp7+7OEZbi8cmS/16ArvlYaEmLF96
         I0DW2LFlJiFM6iiU2r+EZ7QqmkA/2YMDxOnyljwb72Ztz9EujJcUfhNEKxPUV45+ABbe
         lHBomw56/srZDni96mQ09wrS54arQCU7xfzdh+tM9uhffZV2xxP2CH8AF6FaPAk+XKfY
         xiNRSritSO95M0ee+1caWySlVhvs+SpJexsAQ/pOhkbisLD/xjvCFaLtUHTJEM8ZhXG3
         /gDw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWk03HaG3aZiuI+AVbpCPbR3ig7s6zmyOV56T7JpVbqF241fRbSppSg5irEUONn4kipjJ20rpY+IRAEkxQyozQcZi3U4E2iCQ==
X-Gm-Message-State: AOJu0Yz2MnLLBqKADeGCNqNfrZrvbHFOhWPcxt0nPF7HIshBVoKL1K/X
	hvncdsde31FVIRBloWEDPjy5W9ZaYkALAXkAfNbvYyJkWXLON8GH
X-Google-Smtp-Source: AGHT+IG9E/BRnRcTOJEYDFMmDLHlbN9lAqx740kENN8dFWjl6Kgoctzov5kNrANIauc5ZknxTMkzZQ==
X-Received: by 2002:a2e:bc1a:0:b0:2ef:2472:41c7 with SMTP id 38308e7fff4ca-2f3aa1c9518mr29234301fa.7.1723651436092;
        Wed, 14 Aug 2024 09:03:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:354c:b0:58b:b493:fcc9 with SMTP id
 4fb4d7f45d1cf-5beb36cb84fls33132a12.0.-pod-prod-03-eu; Wed, 14 Aug 2024
 09:03:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVLdidD83cYNGKz8oMxiQCzJ0nkJQc+AI9qMLJJiSnhBl8P/J/4c5gZEM0hybfaIPkcVJauMaqE6DjY6poyiYFO18XrTn00p+kbTg==
X-Received: by 2002:a17:907:60cd:b0:a72:4281:bc72 with SMTP id a640c23a62f3a-a8367079b24mr162630066b.63.1723651434013;
        Wed, 14 Aug 2024 09:03:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723651433; cv=none;
        d=google.com; s=arc-20160816;
        b=LJwImd1lAzE32waem7x2z2owbIJSKS+2FbHSdbf0D8sVbpdTeXL0BKcPls1l7XFqck
         eUimMsX7hkA/lzoIeRHUIuwrcvqAy8lvR5D55geocUPMCn8CD/6EkcdjR3LB53SJIKSt
         n7v/UI9E3daMtrhZsXoTaAu/8bzA19ZpWkk4uQw0NGRluEKbTPpQNBoCrZjQ+wjjsdj6
         lau77+Ii2TM1o+a4JkjJE5HW9k+fjIFN7Fgw9pc1KHhoHJtunplnkfZPJow7eVhEfQUz
         N+8ULqQcVtupp6p/ZBW6wiJAz4LpePneU1XaskglBtr/j7wAw3PYNeIqagA4JeVAqtZn
         jjTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=iMDoYmsc39gb6yuKfl0P727Axl9w4fP7q/FSOzu+ECI=;
        fh=MGQzz4fP2FChiYrO5vJlwAXWayrSH7Ct7gQ2FOcD1Hc=;
        b=hRsw8rtfgorPWEq03Hqts1mzf6abovIz9jLFyDK5M5XDkl+cY94a2DuIotQ9zCNkQt
         Dl+YXpeEweSEsx7s3F+kaN++7c3cqNbDiEzsUXSuJGi+b3o9SX0tbtvQesyszI3WGlM9
         XhY2KKVvllekyjdnLiLjVk5XodfvXPkRImn9B7TTvLme93KXlFqrcYmL53yG+GT8lr7X
         QAqTubl3RW//Dn8gD74XEsDIndtmQtdE78DWeRhyKDc9tMrKPYcBxKx2N5NbaWeppxN9
         c6eX8l7dhhURnGAgkbGaJBgrPVFRlgi9OghoKbOKuf62JLtEBuLdpBUgen6aY+Sxl1bT
         MonQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=TqSj2y2V;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x436.google.com (mail-wr1-x436.google.com. [2a00:1450:4864:20::436])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-a80f3b36b24si9379966b.0.2024.08.14.09.03.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Aug 2024 09:03:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) client-ip=2a00:1450:4864:20::436;
Received: by mail-wr1-x436.google.com with SMTP id ffacd0b85a97d-3685b3dbcdcso41529f8f.3
        for <kasan-dev@googlegroups.com>; Wed, 14 Aug 2024 09:03:53 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUBYrdqYnz8N6oc9e8txg+ofyLoSQhSiaPAhdN4bXz86K2HgDJ3n05Bxv0008mtqULArTEgmxVODypHgy5FhA2gSuro5l/ptAEKIA==
X-Received: by 2002:adf:e64f:0:b0:367:98e6:362b with SMTP id
 ffacd0b85a97d-371777e5ea7mr2514710f8f.42.1723651433003; Wed, 14 Aug 2024
 09:03:53 -0700 (PDT)
MIME-Version: 1.0
References: <20240814085618.968833-1-samuel.holland@sifive.com> <20240814085618.968833-2-samuel.holland@sifive.com>
In-Reply-To: <20240814085618.968833-2-samuel.holland@sifive.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 14 Aug 2024 18:03:42 +0200
Message-ID: <CA+fCnZcd0jg5HqQqERfqTbVc-F2mYsq=w4aek8pQSCEPXyRG7w@mail.gmail.com>
Subject: Re: [RFC PATCH 1/7] kasan: sw_tags: Use arithmetic shift for shadow computation
To: Samuel Holland <samuel.holland@sifive.com>
Cc: Palmer Dabbelt <palmer@dabbelt.com>, linux-riscv@lists.infradead.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, llvm@lists.linux.dev, 
	linux-kernel@vger.kernel.org, Alexandre Ghiti <alexghiti@rivosinc.com>, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	linux-arm-kernel@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=TqSj2y2V;       spf=pass
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

On Wed, Aug 14, 2024 at 10:56=E2=80=AFAM Samuel Holland
<samuel.holland@sifive.com> wrote:
>
> Currently, kasan_mem_to_shadow() uses a logical right shift, which turns
> canonical kernel addresses into non-canonical addresses by clearing the
> high KASAN_SHADOW_SCALE_SHIFT bits. The value of KASAN_SHADOW_OFFSET is
> then chosen so that the addition results in a canonical address for the
> shadow memory.
>
> For KASAN_GENERIC, this shift/add combination is ABI with the compiler,
> because KASAN_SHADOW_OFFSET is used in compiler-generated inline tag
> checks[1], which must only attempt to dereference canonical addresses.
>
> However, for KASAN_SW_TAGS we have some freedom to change the algorithm
> without breaking the ABI. Because TBI is enabled for kernel addresses,
> the top bits of shadow memory addresses computed during tag checks are
> irrelevant, and so likewise are the top bits of KASAN_SHADOW_OFFSET.
> This is demonstrated by the fact that LLVM uses a logical right shift
> in the tag check fast path[2] but a sbfx (signed bitfield extract)
> instruction in the slow path[3] without causing any issues.
>
> Using an arithmetic shift in kasan_mem_to_shadow() provides a number of
> benefits:
>
> 1) The memory layout is easier to understand. KASAN_SHADOW_OFFSET
> becomes a canonical memory address, and the shifted pointer becomes a
> negative offset, so KASAN_SHADOW_OFFSET =3D=3D KASAN_SHADOW_END regardles=
s
> of the shift amount or the size of the virtual address space.
>
> 2) KASAN_SHADOW_OFFSET becomes a simpler constant, requiring only one
> instruction to load instead of two. Since it must be loaded in each
> function with a tag check, this decreases kernel text size by 0.5%.
>
> 3) This shift and the sign extension from kasan_reset_tag() can be
> combined into a single sbfx instruction. When this same algorithm change
> is applied to the compiler, it removes an instruction from each inline
> tag check, further reducing kernel text size by an additional 4.6%.
>
> These benefits extend to other architectures as well. On RISC-V, where
> the baseline ISA does not shifted addition or have an equivalent to the
> sbfx instruction, loading KASAN_SHADOW_OFFSET is reduced from 3 to 2
> instructions, and kasan_mem_to_shadow(kasan_reset_tag(addr)) similarly
> combines two consecutive right shifts.

Will this change cause any problems with the check against
KASAN_SHADOW_OFFSET in kasan_non_canonical_hook()?

>
> Link: https://github.com/llvm/llvm-project/blob/llvmorg-20-init/llvm/lib/=
Transforms/Instrumentation/AddressSanitizer.cpp#L1316 [1]
> Link: https://github.com/llvm/llvm-project/blob/llvmorg-20-init/llvm/lib/=
Transforms/Instrumentation/HWAddressSanitizer.cpp#L895 [2]
> Link: https://github.com/llvm/llvm-project/blob/llvmorg-20-init/llvm/lib/=
Target/AArch64/AArch64AsmPrinter.cpp#L669 [3]
> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
> ---
>
>  arch/arm64/Kconfig              | 10 +++++-----
>  arch/arm64/include/asm/memory.h |  8 ++++++++
>  arch/arm64/mm/kasan_init.c      |  7 +++++--
>  include/linux/kasan.h           | 10 ++++++++--
>  scripts/gdb/linux/mm.py         |  5 +++--
>  5 files changed, 29 insertions(+), 11 deletions(-)
>
> diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
> index a2f8ff354ca6..7df218cca168 100644
> --- a/arch/arm64/Kconfig
> +++ b/arch/arm64/Kconfig
> @@ -402,11 +402,11 @@ config KASAN_SHADOW_OFFSET
>         default 0xdffffe0000000000 if ARM64_VA_BITS_42 && !KASAN_SW_TAGS
>         default 0xdfffffc000000000 if ARM64_VA_BITS_39 && !KASAN_SW_TAGS
>         default 0xdffffff800000000 if ARM64_VA_BITS_36 && !KASAN_SW_TAGS
> -       default 0xefff800000000000 if (ARM64_VA_BITS_48 || (ARM64_VA_BITS=
_52 && !ARM64_16K_PAGES)) && KASAN_SW_TAGS
> -       default 0xefffc00000000000 if (ARM64_VA_BITS_47 || ARM64_VA_BITS_=
52) && ARM64_16K_PAGES && KASAN_SW_TAGS
> -       default 0xeffffe0000000000 if ARM64_VA_BITS_42 && KASAN_SW_TAGS
> -       default 0xefffffc000000000 if ARM64_VA_BITS_39 && KASAN_SW_TAGS
> -       default 0xeffffff800000000 if ARM64_VA_BITS_36 && KASAN_SW_TAGS
> +       default 0xffff800000000000 if (ARM64_VA_BITS_48 || (ARM64_VA_BITS=
_52 && !ARM64_16K_PAGES)) && KASAN_SW_TAGS
> +       default 0xffffc00000000000 if (ARM64_VA_BITS_47 || ARM64_VA_BITS_=
52) && ARM64_16K_PAGES && KASAN_SW_TAGS
> +       default 0xfffffe0000000000 if ARM64_VA_BITS_42 && KASAN_SW_TAGS
> +       default 0xffffffc000000000 if ARM64_VA_BITS_39 && KASAN_SW_TAGS
> +       default 0xfffffff800000000 if ARM64_VA_BITS_36 && KASAN_SW_TAGS
>         default 0xffffffffffffffff
>
>  config UNWIND_TABLES
> diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/mem=
ory.h
> index 54fb014eba05..3af8d1e721af 100644
> --- a/arch/arm64/include/asm/memory.h
> +++ b/arch/arm64/include/asm/memory.h
> @@ -82,6 +82,10 @@
>   * the mapping. Note that KASAN_SHADOW_OFFSET does not point to the star=
t of
>   * the shadow memory region.
>   *
> + * For KASAN_GENERIC, addr is treated as unsigned. For KASAN_SW_TAGS, ad=
dr is
> + * treated as signed, so in that case KASAN_SHADOW_OFFSET points to the =
end of
> + * the shadow memory region.

Hm, it's not immediately obvious why using a signed addr leads to
KASAN_SHADOW_OFFSET being =3D=3D KASAN_SHADOW_END. Could you clarify this
in the comment?

Let's also put this explanation into the KASAN_SHADOW_END paragraph
instead, something like:

KASAN_SHADOW_END is defined first as the shadow address that
corresponds to the upper bound of possible virtual kernel memory
addresses UL(1) << 64 according to the mapping formula. For Generic
KASAN, the address in the mapping formula is treated as unsigned (part
of the compiler's ABI), so we do explicit calculations according to
the formula. For Software Tag-Based KASAN, the address is treated as
signed, and thus <EXPLANATION HERE>.



> + *
>   * Based on this mapping, we define two constants:
>   *
>   *     KASAN_SHADOW_START: the start of the shadow memory region;
> @@ -100,7 +104,11 @@
>   */
>  #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>  #define KASAN_SHADOW_OFFSET    _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
> +#ifdef CONFIG_KASAN_GENERIC
>  #define KASAN_SHADOW_END       ((UL(1) << (64 - KASAN_SHADOW_SCALE_SHIFT=
)) + KASAN_SHADOW_OFFSET)
> +#else
> +#define KASAN_SHADOW_END       KASAN_SHADOW_OFFSET
> +#endif
>  #define _KASAN_SHADOW_START(va)        (KASAN_SHADOW_END - (UL(1) << ((v=
a) - KASAN_SHADOW_SCALE_SHIFT)))
>  #define KASAN_SHADOW_START     _KASAN_SHADOW_START(vabits_actual)
>  #define PAGE_END               KASAN_SHADOW_START
> diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
> index b65a29440a0c..6836e571555c 100644
> --- a/arch/arm64/mm/kasan_init.c
> +++ b/arch/arm64/mm/kasan_init.c
> @@ -198,8 +198,11 @@ static bool __init root_level_aligned(u64 addr)
>  /* The early shadow maps everything to a single page of zeroes */
>  asmlinkage void __init kasan_early_init(void)
>  {
> -       BUILD_BUG_ON(KASAN_SHADOW_OFFSET !=3D
> -               KASAN_SHADOW_END - (1UL << (64 - KASAN_SHADOW_SCALE_SHIFT=
)));
> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> +               BUILD_BUG_ON(KASAN_SHADOW_OFFSET !=3D
> +                       KASAN_SHADOW_END - (1UL << (64 - KASAN_SHADOW_SCA=
LE_SHIFT)));
> +       else
> +               BUILD_BUG_ON(KASAN_SHADOW_OFFSET !=3D KASAN_SHADOW_END);
>         BUILD_BUG_ON(!IS_ALIGNED(_KASAN_SHADOW_START(VA_BITS), SHADOW_ALI=
GN));
>         BUILD_BUG_ON(!IS_ALIGNED(_KASAN_SHADOW_START(VA_BITS_MIN), SHADOW=
_ALIGN));
>         BUILD_BUG_ON(!IS_ALIGNED(KASAN_SHADOW_END, SHADOW_ALIGN));
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 70d6a8f6e25d..41f57e10ba03 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -58,8 +58,14 @@ int kasan_populate_early_shadow(const void *shadow_sta=
rt,
>  #ifndef kasan_mem_to_shadow
>  static inline void *kasan_mem_to_shadow(const void *addr)
>  {
> -       return (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT)
> -               + KASAN_SHADOW_OFFSET;
> +       void *scaled;
> +
> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> +               scaled =3D (void *)((unsigned long)addr >> KASAN_SHADOW_S=
CALE_SHIFT);
> +       else
> +               scaled =3D (void *)((long)addr >> KASAN_SHADOW_SCALE_SHIF=
T);
> +
> +       return KASAN_SHADOW_OFFSET + scaled;
>  }
>  #endif
>
> diff --git a/scripts/gdb/linux/mm.py b/scripts/gdb/linux/mm.py
> index 7571aebbe650..2e63f3dedd53 100644
> --- a/scripts/gdb/linux/mm.py
> +++ b/scripts/gdb/linux/mm.py
> @@ -110,12 +110,13 @@ class aarch64_page_ops():
>          self.KERNEL_END =3D gdb.parse_and_eval("_end")
>
>          if constants.LX_CONFIG_KASAN_GENERIC or constants.LX_CONFIG_KASA=
N_SW_TAGS:
> +            self.KASAN_SHADOW_OFFSET =3D constants.LX_CONFIG_KASAN_SHADO=
W_OFFSET
>              if constants.LX_CONFIG_KASAN_GENERIC:
>                  self.KASAN_SHADOW_SCALE_SHIFT =3D 3
> +                self.KASAN_SHADOW_END =3D (1 << (64 - self.KASAN_SHADOW_=
SCALE_SHIFT)) + self.KASAN_SHADOW_OFFSET
>              else:
>                  self.KASAN_SHADOW_SCALE_SHIFT =3D 4
> -            self.KASAN_SHADOW_OFFSET =3D constants.LX_CONFIG_KASAN_SHADO=
W_OFFSET
> -            self.KASAN_SHADOW_END =3D (1 << (64 - self.KASAN_SHADOW_SCAL=
E_SHIFT)) + self.KASAN_SHADOW_OFFSET
> +                self.KASAN_SHADOW_END =3D self.KASAN_SHADOW_OFFSET
>              self.PAGE_END =3D self.KASAN_SHADOW_END - (1 << (self.vabits=
_actual - self.KASAN_SHADOW_SCALE_SHIFT))
>          else:
>              self.PAGE_END =3D self._PAGE_END(self.VA_BITS_MIN)
> --
> 2.45.1
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZcd0jg5HqQqERfqTbVc-F2mYsq%3Dw4aek8pQSCEPXyRG7w%40mail.gm=
ail.com.
