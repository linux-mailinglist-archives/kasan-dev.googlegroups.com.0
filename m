Return-Path: <kasan-dev+bncBDW2JDUY5AORBAUH4W4AMGQEVXHP37I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 48E599AD421
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Oct 2024 20:42:12 +0200 (CEST)
Received: by mail-ed1-x53d.google.com with SMTP id 4fb4d7f45d1cf-5cb7fd2a28csf35447a12.3
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Oct 2024 11:42:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729708932; cv=pass;
        d=google.com; s=arc-20240605;
        b=fNSRpLbL1iEmheg/pf4jUq0AeNX/GD9qI9tCoOyxiCX6lPy0YXUc7u/yh+FIFjEMqT
         L80oII4AxP/cBtt5CjNrDlWr8dDM+fOMaZd7vfyh8X6Q5ZtQ3YRTJ3VAejG1f8WRXcuZ
         fdsc9nsWv1HNnK6iNGj3XLhAVnF8PSuFcpEKGEvDuuN7dkuO9Rxkeoji6jNw2MogH8RT
         hZ01yPTUz3gvJpf+bK5arlmvqHjHQThFR+IoZFAwujVDtVyF1KDpVNCoBcDVDGDeLT9p
         4HH80Vc+UP1GB4bxxlTjC79JHyklBRZYV4ZYvWKzwlL9/C4h1XK63lfeBAF45x2brB9s
         AMqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=9lmhCoAoMmHqomMThUzIr/xjDiHosaLLsZqC10mpiE0=;
        fh=CIJJCMpWXey1DfoZJIJdmMWO9Km3uvy5SRpLxiDfoxQ=;
        b=hZ2v5HZCVs6ZzattDxPHuhg0lylX2XFf0OXewqkJq6iX0NegTdMneBT4PtjokiVOqE
         Tsea5jiuu1dVEFgULOXTeaVgptke8SyS1PT3Skch48z+/YCeMhqDhGr3VVRqhV0Olmdl
         PiSoy75ej8uuqUss/JRBMYzBiIqzQAgIPrPz1T1cGbBVk1/gAb254xZjImHvD99QARsO
         OPv5Srtmt4Kmhs9/u3d2qJtMaYrOqbJ3UsiKAxYQczwFwucddkV3tXL+5jBXeu2PkWJM
         TqnFrol0RmcUmOljCBWiZQ9CLEOheP5ZlRL+DQhWpB7CWT67JGqAbezDhVjkNX7zVaMj
         /GNg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UgsFwYIx;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729708932; x=1730313732; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=9lmhCoAoMmHqomMThUzIr/xjDiHosaLLsZqC10mpiE0=;
        b=BFuCz17wopPz92cmkB4oXq+iMPkgm3IlpF5P8gl6CwW0VOOLCEAF7SIfzSw50t0vmG
         nK3jsf0jgfhV6a7KfDuFjwaxcaAb0UaWDppxUm7n4WmNdN+rvaFqiwd0hI9ojsYhgzi2
         UynoCy+FglclZmVbBOWEMDGH+hbN56LwneEyFJdKmXlfGaBURF3EGHZqdvayUBBcgyhJ
         Z2IjIvefo/sHGBRhB9t8PZMK3NK9zA7YPBlr1XEJzeDwV3XZHuPXuyPdUsrYzNA69axE
         ciGi7ZU7OSWC7Z5pCjfOAUSCKXoVpydYKk1rOe//m+gGvvHyTyLUujyb0u+5axq3eduR
         6A9Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1729708932; x=1730313732; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=9lmhCoAoMmHqomMThUzIr/xjDiHosaLLsZqC10mpiE0=;
        b=aKB0NKPWOfidmrY765o6GMrNYaef3RktBBcSuwWYXhch6F53M6DOohxX+HDTlxTEGr
         TZr/ctPzV9VJcKhCfLeaWCzbe6bAFMV8RLbp9CKXr/mhJcvEeEFbqK9lxm6C/5/Hrc3m
         Txuy6rph3LCDhfKfRgesu4Qex64zCa8KhxTuzSNkbh/td1B6/V9/DWWI8VWvL1g+qtBN
         Ofj6RLJ6jF78WarOTVAYOOLI3K3iikYA0fnRgAaHE0DkI/R/LSnMsfgN2AEmdhzE2oGo
         4nZ0svEW7pC9jGWGKbGwtnDBptWbdo/TING5a3kTerEchI28CsPl8ePqzkfRt8KHv4Wg
         FnFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729708932; x=1730313732;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=9lmhCoAoMmHqomMThUzIr/xjDiHosaLLsZqC10mpiE0=;
        b=WWGJHX5lCNAb9U4JTcsqY8rXD69QELcfeUjFIdlYZyuM5GbpX7JYj+d15LHvOkBKDO
         ACiFy7QEva8usZnszOpo2LnpI5floC2rWsn1gp1toBPv0ETGoqauJRyHSSn5qjxzUiz6
         QXaq9PIwRVRZbmQoEnVqyg55S4LuE/zEO6CNjhziE2AXeSiQLX18dY1bvbOIV8s+Z2gv
         pdlbTSclG+x1+Ylm2wyPpws+nAsm/euVDlQBVeBXrJKJ8lZoMggTfCkhMcSM5Ez7/ms4
         Wyi9kqeX1d8d+mHCIam4GN9wpIiosvi7CCbPymyXu7agvm+40vrw3zDtbHnGbY+4pUq6
         Egpw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWadDe6SkNaoXHcAYt0TSp+PB3z7PU55JwnWL9TDf2A3Z6/U3828oMyeewMOf994jWxQkfJaA==@lfdr.de
X-Gm-Message-State: AOJu0YymWqoRiqoHkcaU3KoTthsxk7LibQkujWAkoSkGJ8Zfo10pOFZ4
	SNggeujWR7VQKMhrwHvyxy3trEaeHyMebC8oiOSJrDiGPRZmUKi3
X-Google-Smtp-Source: AGHT+IFKDSWZuS7uPzrlDj3IYCyofhpBJZuHWhOewmXPuMl2iiBh0Wdb3eTa5IkRy0sGmv7/wN9qsA==
X-Received: by 2002:a05:6402:1d4d:b0:5cb:7294:fc71 with SMTP id 4fb4d7f45d1cf-5cb8b190801mr2795837a12.13.1729708931244;
        Wed, 23 Oct 2024 11:42:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:4304:b0:5c9:3fa:8237 with SMTP id
 4fb4d7f45d1cf-5cb999db1aels78880a12.1.-pod-prod-06-eu; Wed, 23 Oct 2024
 11:42:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXYzvEKbUotOlWgZ3sv96IVdxt00DCWTG0/LwViH2gqZ/soDbH7YFiHK7eHICfJ7LFDjaqolVyv+FQ=@googlegroups.com
X-Received: by 2002:a05:6402:3485:b0:5c8:bb09:b417 with SMTP id 4fb4d7f45d1cf-5cb8ab05ab0mr2966413a12.0.1729708929231;
        Wed, 23 Oct 2024 11:42:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729708929; cv=none;
        d=google.com; s=arc-20240605;
        b=CDOma6NLAw5ZOKc8Pir7m026LHOCozLpoxogsVaZpbHoeirvIupDxMrBLfB73/SG6p
         Wv+KxLmn2ARIuFauSDHNpEvoYICMiHoI3YR+NhE72fGMh/hUwL7Ry8FSHZ2sSARZlJdK
         BLc2SrGH9C12HVixGapH3ekbjy0l1SR+irMtRINiDCEbUJZUlXXt5g8OMlS8hOIDfw1t
         2RaRarKi9DwIGIsQClJ2dAg220FiJU+hNa0n7XqB41Zq2PHxYw5FMrAUY5F/z0kMumc/
         JnkpjNPn2QlAZFTL3y2LgKNa63MbxACLoGBKOOPjs2wsyYsrPnDLBCQffUZye3bldNFK
         MXRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=dnCz4Gz0DfA3iJQbcwkn7pdP+4IKH3HjV3Yhmz6VCSY=;
        fh=VOyo51YwLABbZpUAAj71sTz5SFPRSBT7yuzNW8PXNoA=;
        b=U4bVoL7bGk2LRe7dD14+rj+bwjiIgm4DhdIQycI/FIY1oukiAJBKKxKbV38eoNqBJz
         JUJqc76+sHHnhySBqGk09EeOkQFcmFh00LeyZ4hEDJ6LHBdG/3czuTXjaF7rgIahmarR
         ceJnTevj4cIQ3JURPNm5qMc3gT9YDY0rnPW2hFMeBejn57NjAhqLXRwoAUlQK7nMetTg
         f+H79jUj4KsUuDQOABudanKicvtQZh9XQ+smPIAC1NudoitZCZfUntS+EVhe9Rcq220M
         WSIN/H6oxe/M86ct4cwg4D2tmSLsVK2efZNfOBmWXYQjPR0G5DGp5Z5FvSuz4Uz4pp/7
         IQKQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UgsFwYIx;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32a.google.com (mail-wm1-x32a.google.com. [2a00:1450:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5cb670ee987si277546a12.4.2024.10.23.11.42.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 23 Oct 2024 11:42:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32a as permitted sender) client-ip=2a00:1450:4864:20::32a;
Received: by mail-wm1-x32a.google.com with SMTP id 5b1f17b1804b1-43155abaf0bso941915e9.0
        for <kasan-dev@googlegroups.com>; Wed, 23 Oct 2024 11:42:09 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX2wJ7TwLn4iOtxPXN+XmnOeqNZxk9Aoshe5auQuaxtosVtHc54dBR8DsySNf8Q1Tdlck1O9QoV9VI=@googlegroups.com
X-Received: by 2002:a5d:5257:0:b0:37d:614e:2bc5 with SMTP id
 ffacd0b85a97d-37efcf1dbb3mr2066652f8f.29.1729708928528; Wed, 23 Oct 2024
 11:42:08 -0700 (PDT)
MIME-Version: 1.0
References: <20241022015913.3524425-1-samuel.holland@sifive.com> <20241022015913.3524425-2-samuel.holland@sifive.com>
In-Reply-To: <20241022015913.3524425-2-samuel.holland@sifive.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 23 Oct 2024 20:41:57 +0200
Message-ID: <CA+fCnZeBEe3VWm=VfYvG-f4eh2jAFP-p4Xn4SLEeFCGTudVuEw@mail.gmail.com>
Subject: Re: [PATCH v2 1/9] kasan: sw_tags: Use arithmetic shift for shadow computation
To: Samuel Holland <samuel.holland@sifive.com>
Cc: Palmer Dabbelt <palmer@dabbelt.com>, linux-riscv@lists.infradead.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, llvm@lists.linux.dev, 
	Catalin Marinas <catalin.marinas@arm.com>, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	Alexandre Ghiti <alexghiti@rivosinc.com>, Will Deacon <will@kernel.org>, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	linux-arm-kernel@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=UgsFwYIx;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32a
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

On Tue, Oct 22, 2024 at 3:59=E2=80=AFAM Samuel Holland
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
> Changes in v2:
>  - Improve the explanation for how KASAN_SHADOW_END is derived
>  - Update the range check in kasan_non_canonical_hook()
>
>  arch/arm64/Kconfig              | 10 +++++-----
>  arch/arm64/include/asm/memory.h | 17 +++++++++++++++--
>  arch/arm64/mm/kasan_init.c      |  7 +++++--
>  include/linux/kasan.h           | 10 ++++++++--
>  mm/kasan/report.c               | 22 ++++++++++++++++++----
>  scripts/gdb/linux/mm.py         |  5 +++--
>  6 files changed, 54 insertions(+), 17 deletions(-)
>
> diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
> index fd9df6dcc593..6a326908c941 100644
> --- a/arch/arm64/Kconfig
> +++ b/arch/arm64/Kconfig
> @@ -418,11 +418,11 @@ config KASAN_SHADOW_OFFSET
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
> index 0480c61dbb4f..a93fc9dc16f3 100644
> --- a/arch/arm64/include/asm/memory.h
> +++ b/arch/arm64/include/asm/memory.h
> @@ -80,7 +80,8 @@
>   * where KASAN_SHADOW_SCALE_SHIFT is the order of the number of bits tha=
t map
>   * to a single shadow byte and KASAN_SHADOW_OFFSET is a constant that of=
fsets
>   * the mapping. Note that KASAN_SHADOW_OFFSET does not point to the star=
t of
> - * the shadow memory region.
> + * the shadow memory region, since not all possible addresses have shado=
w
> + * memory allocated for them.

I'm not sure this addition makes sense: the original statement was to
point out that KASAN_SHADOW_OFFSET and KASAN_SHADOW_START are
different values. Even if we were to map shadow for userspace,
KASAN_SHADOW_OFFSET would still be a weird offset value for Generic
KASAN.

>   *
>   * Based on this mapping, we define two constants:
>   *
> @@ -89,7 +90,15 @@
>   *
>   * KASAN_SHADOW_END is defined first as the shadow address that correspo=
nds to
>   * the upper bound of possible virtual kernel memory addresses UL(1) << =
64
> - * according to the mapping formula.
> + * according to the mapping formula. For Generic KASAN, the address in t=
he
> + * mapping formula is treated as unsigned (part of the compiler's ABI), =
so the
> + * end of the shadow memory region is at a large positive offset from
> + * KASAN_SHADOW_OFFSET. For Software Tag-Based KASAN, the address in the
> + * formula is treated as signed. Since all kernel addresses are negative=
, they
> + * map to shadow memory below KASAN_SHADOW_OFFSET, making KASAN_SHADOW_O=
FFSET
> + * itself the end of the shadow memory region. (User pointers are positi=
ve and
> + * would map to shadow memory above KASAN_SHADOW_OFFSET, but shadow memo=
ry is
> + * not allocated for them.)

This looks good!

>   *
>   * KASAN_SHADOW_START is defined second based on KASAN_SHADOW_END. The s=
hadow
>   * memory start must map to the lowest possible kernel virtual memory ad=
dress
> @@ -100,7 +109,11 @@
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
> index 00a3bf7c0d8f..03b440658817 100644
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
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index b48c768acc84..c08097715686 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -644,15 +644,29 @@ void kasan_report_async(void)
>   */
>  void kasan_non_canonical_hook(unsigned long addr)
>  {
> +       unsigned long max_shadow_size =3D BIT(BITS_PER_LONG - KASAN_SHADO=
W_SCALE_SHIFT);
>         unsigned long orig_addr;
>         const char *bug_type;
>
>         /*
> -        * All addresses that came as a result of the memory-to-shadow ma=
pping
> -        * (even for bogus pointers) must be >=3D KASAN_SHADOW_OFFSET.
> +        * With the default kasan_mem_to_shadow() algorithm, all addresse=
s
> +        * returned by the memory-to-shadow mapping (even for bogus point=
ers)
> +        * must be within a certain displacement from KASAN_SHADOW_OFFSET=
.
> +        *
> +        * For Generic KASAN, the displacement is unsigned, so
> +        * KASAN_SHADOW_OFFSET is the smallest possible shadow address. F=
or

This part of the comment doesn't seem correct: KASAN_SHADOW_OFFSET is
still a weird offset value for Generic KASAN, not the smallest
possible shadow address.

> +        * Software Tag-Based KASAN, the displacement is signed, so
> +        * KASAN_SHADOW_OFFSET is the center of the range.
>          */
> -       if (addr < KASAN_SHADOW_OFFSET)
> -               return;
> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> +               if (addr < KASAN_SHADOW_OFFSET ||
> +                   addr >=3D KASAN_SHADOW_OFFSET + max_shadow_size)
> +                       return;
> +       } else {
> +               if (addr < KASAN_SHADOW_OFFSET - max_shadow_size / 2 ||
> +                   addr >=3D KASAN_SHADOW_OFFSET + max_shadow_size / 2)
> +                       return;

Hm, I might be wrong, but I think this check does not work.

Let's say we have non-canonical address 0x4242424242424242 and number
of VA bits is 48.

Then:

KASAN_SHADOW_OFFSET =3D=3D 0xffff800000000000
kasan_mem_to_shadow(0x4242424242424242) =3D=3D 0x0423a42424242424
max_shadow_size =3D=3D 0x1000000000000000
KASAN_SHADOW_OFFSET - max_shadow_size / 2 =3D=3D 0xf7ff800000000000
KASAN_SHADOW_OFFSET + max_shadow_size / 2 =3D=3D 0x07ff800000000000 (overfl=
ows)

0x0423a42424242424 is < than 0xf7ff800000000000, so the function will
wrongly return.

> +       }
>
>         orig_addr =3D (unsigned long)kasan_shadow_to_mem((void *)addr);
>

Just to double-check: kasan_shadow_to_mem() and addr_has_metadata()
don't need any changes, right?

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

Could you also check that everything works when CONFIG_KASAN_SW_TAGS +
CONFIG_KASAN_OUTLINE? I think it should, be makes sense to confirm.

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZeBEe3VWm%3DVfYvG-f4eh2jAFP-p4Xn4SLEeFCGTudVuEw%40mail.gmail.com.
