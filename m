Return-Path: <kasan-dev+bncBCMIFTP47IJBB5XR3K4AMGQEVUSI5OQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id AB8219A9122
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2024 22:26:32 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id 46e09a7af769-7180fe954a7sf2333821a34.3
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2024 13:26:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729542391; cv=pass;
        d=google.com; s=arc-20240605;
        b=WNLCGxf51+ZcplxRcwR+nIUJW+RMZoIvG6uTwEeE0VXLknoMUjTimwVNIy0TbWpRFo
         fA6XiVgW2+XRURGKywyIx3fN4dDaObAO+ILTfxvRvNMikkeDEFH57SdR17mLInMDf9yM
         u4yJE+U878ICBCAYXhNJ5Zh6fvy7ARvPcW+IBZhU+O/7qb7YdhXLyL9y4SaYnpdYH9Pa
         3ZiMCHWhHBcgZlxS2H/LkkTR6aaTZCqHPuCAB5PWvuXYLApyqS+WjYe8OX4WRy9oPqm8
         1YKlQYNtBoRHVn4VRhAW0aQRSHa4r6xFEZalFmFBJx3ZQJQJ7RM49ETxYXmdkCRQNste
         Hflw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:content-language:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=D+FjSjaT0XwsooK9TN/CYPk9SmKSt1L/nv2v+WOhQLA=;
        fh=edaBCPpE5N5iTnH/K7SQ9epXKRlRsJHLui/HTkz7DzI=;
        b=S/n2KNuN5I97cK8NOAVi/fZb72z++/p/kpxZ8LNQlQfzlC0fC35MIx1ljQe9dwA9bW
         I0WLz77tsXIBflE2ZYAZd6saWHOwFQjajuWdbP8kCVDzKLnZ8jVziIC9XpStEfVdTnJK
         SdEdQTokq9L0IYejfMleMTAoZnjZlKIrlTD6gGQAZK1IaCxf/jLph/9CMIxlawZYP47w
         u+tZ8xcB1MzQZlsuMw6L9Wh8vPxwYyZe1JYRCtqCQ+xQdf0KZ5kx8i8nna6gGGMW/FPh
         YjNF5POIOgq91J4FO7PVGH1cdIPzQKUwTiUtqzQzjjWnESaqZxI+xGaZ26oV4U0fJzsf
         87TA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=LYDqphPU;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2001:4860:4864:20::35 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729542391; x=1730147191; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=D+FjSjaT0XwsooK9TN/CYPk9SmKSt1L/nv2v+WOhQLA=;
        b=TSlMsyYExj3dtHgqyK+kt25VZg0v/V5EUCp+DrqiSBoDLizy7hD6DQ/nOCvL+0jBZH
         J+pNiMmZng5RSUnYqRs+losU0QgcD6S7c3gm2WSPjQYn726Aegz/i1gmE5bdbQ6a9zAM
         aJz6+Vsw118vIyAkghSzUh4rQPbmffW41WsohhP/Kf9JJ3KDjB3DpkTyYZ/bG5EWloqD
         ZDWNfjQDpgrWJ3CDbRRqkKismAVjsn/6z5XEWLp1aZRFEljzNx22zT+aRS9k9iHm/ivc
         JRXYy+J/hWivoTkF3YgMlBCqrGbTx6MmivSi621FJ7uCk4YLQYKV/f3/OzmAHUWoAV7B
         3pRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729542391; x=1730147191;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=D+FjSjaT0XwsooK9TN/CYPk9SmKSt1L/nv2v+WOhQLA=;
        b=OL/1ZE6HsXhUZRH2VEJz0QXe3oboc6HYGyn5oeusljnpWlJe76l1LE/NILcZoa4mX8
         tYdhBKK9lisCo9jixI0jhsItab948kK87SjO/yY/qQj50hckydfbd8OdMApzD/EuR9pc
         Ar9oSFXtFJ7p6GwvuyMk39VQBWNpfLRaUA5vgXZFhuwucFOx+dLMZY6vdeQaMM7H+zRH
         l9ef71VTpCBD5d+FRgGW2Kp0gSK54jcXeN2Alxvcqz42eeahl0G4kMtsRODLAMzo8Pv+
         +6zBgDWXe75qvyVhLFZ1CwHPo3gOKu8sHrG30sO5AsO23vdrH/bT5Nzhr2XP8KctokjP
         DMxA==
X-Forwarded-Encrypted: i=2; AJvYcCU9ebVc1cSl8O++z1nz8yvkXs+TtiDYmJSVg/kPtNgPIEio7iz6JYIDi8dUSyL8jMYb5Hz5MA==@lfdr.de
X-Gm-Message-State: AOJu0Yyy3K6baX+P1PI3LE7q9s3Ygf236ibs7XpltgLp6NpnpVsPsq+A
	hgSiekt83CNHiC3QeEHLoNA+v/tEup5NLj9UI3lkfRi1nmbnDm+X
X-Google-Smtp-Source: AGHT+IEnYrSoKxXFwJq72u+jZAYuQlMvbeo4hfD0HMVkrkjerl5/VdQZiuasCWKJuKO576q/vgx+pg==
X-Received: by 2002:a05:6830:3149:b0:718:d7c:2eef with SMTP id 46e09a7af769-7181a89efb4mr10202666a34.22.1729542391081;
        Mon, 21 Oct 2024 13:26:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:e642:0:b0:5e3:b43c:a787 with SMTP id 006d021491bc7-5eb6b77c384ls112684eaf.0.-pod-prod-06-us;
 Mon, 21 Oct 2024 13:26:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWbZyTE6DAGlOHPdXt8BmuOselOnFmFyigjqfmA79ppWelQsTgxJvLzSiFlsU53TyZxP7TFUjF17rs=@googlegroups.com
X-Received: by 2002:a05:6358:9883:b0:1c2:f482:5bf7 with SMTP id e5c5f4694b2df-1c39e021065mr434761355d.25.1729542389991;
        Mon, 21 Oct 2024 13:26:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729542389; cv=none;
        d=google.com; s=arc-20240605;
        b=CI27GkL/sHJuQAE0mwu+eUsQ8XtdRVIMMaIeYge6q8p2V0J7rwzXaDC3T+LN9QsNE2
         rOuzzsu09KOszVtbOXZeFbZV3qocg+PI5+AcimdWS3oO2acddwsLN0yLusfOY6cLW3Zl
         JrqmgqSCien76aR6b7Lvmo85T1vcOSGnQz92imTQhP5VC7KONcuNzAXMGTihqP5CG/U9
         pVi7MrB6sDyWBxTR7Vz5ngzXL+kGWy2IqOE8dioQTuqPBZdWdz8cIS7rj+DnlR51ZMyt
         OgrGMVIATgXoxPuXZZLiEr+51soIuXXwBIgXlvz79/GdQiuo/Qu1sI1vHxOyEobNWm0D
         wHDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=P+68g9n32g9C+8SvfHBjSGSr/gvAiFPiTke9yTa/MWY=;
        fh=Ng4pniCJQRMi9kvqYCJT0kv+axKfxZzME/i9z9YfPxw=;
        b=IVquLLPtU9tTg/e4wtq2LhikWZQCaeOWkef5WfIliuUx7tq/PtPWkp8u7OFro7aA32
         gvJhwnN3fxL7dj8rNibmeDCfVBGTQROLubf8kb514ps7GvVpb6wyIY5nGqWkm1YpD/2T
         BZTn3oDSOjPj9x94JvRSnWgKBy4qXV8IDLqPRS4Bsypa0qRvQFetaph0weTXQN65vpu4
         pykqS4qVseJ3gCGHU8QaBwcjVL9I0UsjHjvnMryyOCTENUP3YI/u3hpD/pQHKyKr11by
         xLd0PJAj6QJT6/J/zeuhyOSVhrZblzsjxWyzwFtvya8Tcg/QBQPvANdRJKFQqawnnPcw
         D9Iw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=LYDqphPU;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2001:4860:4864:20::35 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-oa1-x35.google.com (mail-oa1-x35.google.com. [2001:4860:4864:20::35])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6ce009f5092si1499296d6.5.2024.10.21.13.26.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Oct 2024 13:26:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2001:4860:4864:20::35 as permitted sender) client-ip=2001:4860:4864:20::35;
Received: by mail-oa1-x35.google.com with SMTP id 586e51a60fabf-288fa5ce8f0so2044061fac.3
        for <kasan-dev@googlegroups.com>; Mon, 21 Oct 2024 13:26:29 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVwfxizltUvsIMMmclS70LANwVXfQ1dAe2COdrcmb4TaICYh8uGfG+P1Z3MZt7lGrctC6xPsOScFRQ=@googlegroups.com
X-Received: by 2002:a05:6871:1ce:b0:250:756b:b1ed with SMTP id 586e51a60fabf-2892c2abea0mr11300516fac.19.1729542387778;
        Mon, 21 Oct 2024 13:26:27 -0700 (PDT)
Received: from [100.64.0.1] ([147.124.94.167])
        by smtp.gmail.com with ESMTPSA id 586e51a60fabf-28c792b25fcsm1301917fac.32.2024.10.21.13.26.26
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Oct 2024 13:26:27 -0700 (PDT)
Message-ID: <5e6d9e76-f0f1-497c-ad49-5f705b188912@sifive.com>
Date: Mon, 21 Oct 2024 15:26:25 -0500
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [RFC PATCH 1/7] kasan: sw_tags: Use arithmetic shift for shadow
 computation
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Palmer Dabbelt <palmer@dabbelt.com>, linux-riscv@lists.infradead.org,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com,
 llvm@lists.linux.dev, linux-kernel@vger.kernel.org,
 Alexandre Ghiti <alexghiti@rivosinc.com>,
 Evgenii Stepanov <eugenis@google.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 linux-arm-kernel@lists.infradead.org
References: <20240814085618.968833-1-samuel.holland@sifive.com>
 <20240814085618.968833-2-samuel.holland@sifive.com>
 <CA+fCnZcd0jg5HqQqERfqTbVc-F2mYsq=w4aek8pQSCEPXyRG7w@mail.gmail.com>
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
Content-Language: en-US
In-Reply-To: <CA+fCnZcd0jg5HqQqERfqTbVc-F2mYsq=w4aek8pQSCEPXyRG7w@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=LYDqphPU;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2001:4860:4864:20::35 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Samuel Holland <samuel.holland@sifive.com>
Reply-To: Samuel Holland <samuel.holland@sifive.com>
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

Hi Andrey,

Thanks for the review!

On 2024-08-14 11:03 AM, Andrey Konovalov wrote:
> On Wed, Aug 14, 2024 at 10:56=E2=80=AFAM Samuel Holland
> <samuel.holland@sifive.com> wrote:
>>
>> Currently, kasan_mem_to_shadow() uses a logical right shift, which turns
>> canonical kernel addresses into non-canonical addresses by clearing the
>> high KASAN_SHADOW_SCALE_SHIFT bits. The value of KASAN_SHADOW_OFFSET is
>> then chosen so that the addition results in a canonical address for the
>> shadow memory.
>>
>> For KASAN_GENERIC, this shift/add combination is ABI with the compiler,
>> because KASAN_SHADOW_OFFSET is used in compiler-generated inline tag
>> checks[1], which must only attempt to dereference canonical addresses.
>>
>> However, for KASAN_SW_TAGS we have some freedom to change the algorithm
>> without breaking the ABI. Because TBI is enabled for kernel addresses,
>> the top bits of shadow memory addresses computed during tag checks are
>> irrelevant, and so likewise are the top bits of KASAN_SHADOW_OFFSET.
>> This is demonstrated by the fact that LLVM uses a logical right shift
>> in the tag check fast path[2] but a sbfx (signed bitfield extract)
>> instruction in the slow path[3] without causing any issues.
>>
>> Using an arithmetic shift in kasan_mem_to_shadow() provides a number of
>> benefits:
>>
>> 1) The memory layout is easier to understand. KASAN_SHADOW_OFFSET
>> becomes a canonical memory address, and the shifted pointer becomes a
>> negative offset, so KASAN_SHADOW_OFFSET =3D=3D KASAN_SHADOW_END regardle=
ss
>> of the shift amount or the size of the virtual address space.
>>
>> 2) KASAN_SHADOW_OFFSET becomes a simpler constant, requiring only one
>> instruction to load instead of two. Since it must be loaded in each
>> function with a tag check, this decreases kernel text size by 0.5%.
>>
>> 3) This shift and the sign extension from kasan_reset_tag() can be
>> combined into a single sbfx instruction. When this same algorithm change
>> is applied to the compiler, it removes an instruction from each inline
>> tag check, further reducing kernel text size by an additional 4.6%.
>>
>> These benefits extend to other architectures as well. On RISC-V, where
>> the baseline ISA does not shifted addition or have an equivalent to the
>> sbfx instruction, loading KASAN_SHADOW_OFFSET is reduced from 3 to 2
>> instructions, and kasan_mem_to_shadow(kasan_reset_tag(addr)) similarly
>> combines two consecutive right shifts.
>=20
> Will this change cause any problems with the check against
> KASAN_SHADOW_OFFSET in kasan_non_canonical_hook()?

Yes, this check needs to be updated. Now kernel addresses map to a negative
displacement from KASAN_SHADOW_OFFSET, and user addresses map to a positive
displacement from KASAN_SHADOW_OFFSET. My understanding is that this check =
is
supposed to be a coarse-grained test for if the faulting address could be t=
he
result of a shadow memory computation. I will update kasan_non_canonical_ho=
ok()
to use the appropriate check for KASAN_SW_TAGS in v2.

>> Link: https://github.com/llvm/llvm-project/blob/llvmorg-20-init/llvm/lib=
/Transforms/Instrumentation/AddressSanitizer.cpp#L1316 [1]
>> Link: https://github.com/llvm/llvm-project/blob/llvmorg-20-init/llvm/lib=
/Transforms/Instrumentation/HWAddressSanitizer.cpp#L895 [2]
>> Link: https://github.com/llvm/llvm-project/blob/llvmorg-20-init/llvm/lib=
/Target/AArch64/AArch64AsmPrinter.cpp#L669 [3]
>> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
>> ---
>>
>>  arch/arm64/Kconfig              | 10 +++++-----
>>  arch/arm64/include/asm/memory.h |  8 ++++++++
>>  arch/arm64/mm/kasan_init.c      |  7 +++++--
>>  include/linux/kasan.h           | 10 ++++++++--
>>  scripts/gdb/linux/mm.py         |  5 +++--
>>  5 files changed, 29 insertions(+), 11 deletions(-)
>>
>> diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
>> index a2f8ff354ca6..7df218cca168 100644
>> --- a/arch/arm64/Kconfig
>> +++ b/arch/arm64/Kconfig
>> @@ -402,11 +402,11 @@ config KASAN_SHADOW_OFFSET
>>         default 0xdffffe0000000000 if ARM64_VA_BITS_42 && !KASAN_SW_TAGS
>>         default 0xdfffffc000000000 if ARM64_VA_BITS_39 && !KASAN_SW_TAGS
>>         default 0xdffffff800000000 if ARM64_VA_BITS_36 && !KASAN_SW_TAGS
>> -       default 0xefff800000000000 if (ARM64_VA_BITS_48 || (ARM64_VA_BIT=
S_52 && !ARM64_16K_PAGES)) && KASAN_SW_TAGS
>> -       default 0xefffc00000000000 if (ARM64_VA_BITS_47 || ARM64_VA_BITS=
_52) && ARM64_16K_PAGES && KASAN_SW_TAGS
>> -       default 0xeffffe0000000000 if ARM64_VA_BITS_42 && KASAN_SW_TAGS
>> -       default 0xefffffc000000000 if ARM64_VA_BITS_39 && KASAN_SW_TAGS
>> -       default 0xeffffff800000000 if ARM64_VA_BITS_36 && KASAN_SW_TAGS
>> +       default 0xffff800000000000 if (ARM64_VA_BITS_48 || (ARM64_VA_BIT=
S_52 && !ARM64_16K_PAGES)) && KASAN_SW_TAGS
>> +       default 0xffffc00000000000 if (ARM64_VA_BITS_47 || ARM64_VA_BITS=
_52) && ARM64_16K_PAGES && KASAN_SW_TAGS
>> +       default 0xfffffe0000000000 if ARM64_VA_BITS_42 && KASAN_SW_TAGS
>> +       default 0xffffffc000000000 if ARM64_VA_BITS_39 && KASAN_SW_TAGS
>> +       default 0xfffffff800000000 if ARM64_VA_BITS_36 && KASAN_SW_TAGS
>>         default 0xffffffffffffffff
>>
>>  config UNWIND_TABLES
>> diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/me=
mory.h
>> index 54fb014eba05..3af8d1e721af 100644
>> --- a/arch/arm64/include/asm/memory.h
>> +++ b/arch/arm64/include/asm/memory.h
>> @@ -82,6 +82,10 @@
>>   * the mapping. Note that KASAN_SHADOW_OFFSET does not point to the sta=
rt of
>>   * the shadow memory region.
>>   *
>> + * For KASAN_GENERIC, addr is treated as unsigned. For KASAN_SW_TAGS, a=
ddr is
>> + * treated as signed, so in that case KASAN_SHADOW_OFFSET points to the=
 end of
>> + * the shadow memory region.
>=20
> Hm, it's not immediately obvious why using a signed addr leads to
> KASAN_SHADOW_OFFSET being =3D=3D KASAN_SHADOW_END. Could you clarify this
> in the comment?
>=20
> Let's also put this explanation into the KASAN_SHADOW_END paragraph
> instead, something like:
>=20
> KASAN_SHADOW_END is defined first as the shadow address that
> corresponds to the upper bound of possible virtual kernel memory
> addresses UL(1) << 64 according to the mapping formula. For Generic
> KASAN, the address in the mapping formula is treated as unsigned (part
> of the compiler's ABI), so we do explicit calculations according to
> the formula. For Software Tag-Based KASAN, the address is treated as
> signed, and thus <EXPLANATION HERE>.

Here's what I plan to include in v2:

KASAN_SHADOW_END is defined first as the shadow address that corresponds to
the upper bound of possible virtual kernel memory addresses UL(1) << 64
according to the mapping formula. For Generic KASAN, the address in the
mapping formula is treated as unsigned (part of the compiler's ABI), so the
end of the shadow memory region is at a large positive offset from
KASAN_SHADOW_OFFSET. For Software Tag-Based KASAN, the address in the
formula is treated as signed. Since all kernel addresses are negative, they
map to shadow memory below KASAN_SHADOW_OFFSET, making KASAN_SHADOW_OFFSET
itself the end of the shadow memory region. (User pointers are positive and
would map to shadow memory above KASAN_SHADOW_OFFSET, but shadow memory is
not allocated for them.)

Regards,
Samuel

>> + *
>>   * Based on this mapping, we define two constants:
>>   *
>>   *     KASAN_SHADOW_START: the start of the shadow memory region;
>> @@ -100,7 +104,11 @@
>>   */
>>  #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>>  #define KASAN_SHADOW_OFFSET    _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
>> +#ifdef CONFIG_KASAN_GENERIC
>>  #define KASAN_SHADOW_END       ((UL(1) << (64 - KASAN_SHADOW_SCALE_SHIF=
T)) + KASAN_SHADOW_OFFSET)
>> +#else
>> +#define KASAN_SHADOW_END       KASAN_SHADOW_OFFSET
>> +#endif
>>  #define _KASAN_SHADOW_START(va)        (KASAN_SHADOW_END - (UL(1) << ((=
va) - KASAN_SHADOW_SCALE_SHIFT)))
>>  #define KASAN_SHADOW_START     _KASAN_SHADOW_START(vabits_actual)
>>  #define PAGE_END               KASAN_SHADOW_START
>> diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
>> index b65a29440a0c..6836e571555c 100644
>> --- a/arch/arm64/mm/kasan_init.c
>> +++ b/arch/arm64/mm/kasan_init.c
>> @@ -198,8 +198,11 @@ static bool __init root_level_aligned(u64 addr)
>>  /* The early shadow maps everything to a single page of zeroes */
>>  asmlinkage void __init kasan_early_init(void)
>>  {
>> -       BUILD_BUG_ON(KASAN_SHADOW_OFFSET !=3D
>> -               KASAN_SHADOW_END - (1UL << (64 - KASAN_SHADOW_SCALE_SHIF=
T)));
>> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
>> +               BUILD_BUG_ON(KASAN_SHADOW_OFFSET !=3D
>> +                       KASAN_SHADOW_END - (1UL << (64 - KASAN_SHADOW_SC=
ALE_SHIFT)));
>> +       else
>> +               BUILD_BUG_ON(KASAN_SHADOW_OFFSET !=3D KASAN_SHADOW_END);
>>         BUILD_BUG_ON(!IS_ALIGNED(_KASAN_SHADOW_START(VA_BITS), SHADOW_AL=
IGN));
>>         BUILD_BUG_ON(!IS_ALIGNED(_KASAN_SHADOW_START(VA_BITS_MIN), SHADO=
W_ALIGN));
>>         BUILD_BUG_ON(!IS_ALIGNED(KASAN_SHADOW_END, SHADOW_ALIGN));
>> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
>> index 70d6a8f6e25d..41f57e10ba03 100644
>> --- a/include/linux/kasan.h
>> +++ b/include/linux/kasan.h
>> @@ -58,8 +58,14 @@ int kasan_populate_early_shadow(const void *shadow_st=
art,
>>  #ifndef kasan_mem_to_shadow
>>  static inline void *kasan_mem_to_shadow(const void *addr)
>>  {
>> -       return (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT)
>> -               + KASAN_SHADOW_OFFSET;
>> +       void *scaled;
>> +
>> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
>> +               scaled =3D (void *)((unsigned long)addr >> KASAN_SHADOW_=
SCALE_SHIFT);
>> +       else
>> +               scaled =3D (void *)((long)addr >> KASAN_SHADOW_SCALE_SHI=
FT);
>> +
>> +       return KASAN_SHADOW_OFFSET + scaled;
>>  }
>>  #endif
>>
>> diff --git a/scripts/gdb/linux/mm.py b/scripts/gdb/linux/mm.py
>> index 7571aebbe650..2e63f3dedd53 100644
>> --- a/scripts/gdb/linux/mm.py
>> +++ b/scripts/gdb/linux/mm.py
>> @@ -110,12 +110,13 @@ class aarch64_page_ops():
>>          self.KERNEL_END =3D gdb.parse_and_eval("_end")
>>
>>          if constants.LX_CONFIG_KASAN_GENERIC or constants.LX_CONFIG_KAS=
AN_SW_TAGS:
>> +            self.KASAN_SHADOW_OFFSET =3D constants.LX_CONFIG_KASAN_SHAD=
OW_OFFSET
>>              if constants.LX_CONFIG_KASAN_GENERIC:
>>                  self.KASAN_SHADOW_SCALE_SHIFT =3D 3
>> +                self.KASAN_SHADOW_END =3D (1 << (64 - self.KASAN_SHADOW=
_SCALE_SHIFT)) + self.KASAN_SHADOW_OFFSET
>>              else:
>>                  self.KASAN_SHADOW_SCALE_SHIFT =3D 4
>> -            self.KASAN_SHADOW_OFFSET =3D constants.LX_CONFIG_KASAN_SHAD=
OW_OFFSET
>> -            self.KASAN_SHADOW_END =3D (1 << (64 - self.KASAN_SHADOW_SCA=
LE_SHIFT)) + self.KASAN_SHADOW_OFFSET
>> +                self.KASAN_SHADOW_END =3D self.KASAN_SHADOW_OFFSET
>>              self.PAGE_END =3D self.KASAN_SHADOW_END - (1 << (self.vabit=
s_actual - self.KASAN_SHADOW_SCALE_SHIFT))
>>          else:
>>              self.PAGE_END =3D self._PAGE_END(self.VA_BITS_MIN)
>> --
>> 2.45.1
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/5e6d9e76-f0f1-497c-ad49-5f705b188912%40sifive.com.
