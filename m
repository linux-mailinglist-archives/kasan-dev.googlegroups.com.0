Return-Path: <kasan-dev+bncBD5N3VM65EKRBWHZ727QMGQE2CB7G2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 1CFCBA90618
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 16:21:14 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-43947a0919asf45509585e9.0
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 07:21:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744813273; cv=pass;
        d=google.com; s=arc-20240605;
        b=Jw+PMtPANn9Sh0qWQ8gsa8KedCgJBAYiIm5NK6a0rJpXvA44lQsHRP9S+JEtrox7hX
         vr3S5Hnt+SyGTaccfOfeFT0qHM6neH/uSrRgt2A/jHJepdHj2sCSx1sZbru6U/ityXjZ
         A+r+fONf8SRRt80zpSb5QRfJ1wMpIBwIWH/kF8iB62bOsmOPP6x0jXUOhC44jux195gI
         0UxFTsamqERXOknd8TfYnbmRePfGtawiMaczsky2gH5L/7sH2UwaFdtOzOy8H8wPaGI9
         CKecDB1QMPwxEKie94R7cFE5zK7zzlXzkfmYrUdc0kqburDSbelwJddkfjskjSyPAuW+
         npgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=9HQcgFpO5vySweGuHfPI+9BNGMLqAL/eTlGGFCxlOeo=;
        fh=n55A1hey8V8F62ymbUGmUCxPY5m/Qu5/FWGk357DLrk=;
        b=ghRaUaBr8WqIK0Ybaaxybgy+sst7KEJowGcERvnF8RLCsi8V7MvUcO/cpa6ZHBU2Mp
         KWWx0FID0LS+08b/4j9yReXv7bWs8nlDouQYpNzTOtv5euZ3i+UQOFSjzBtHvXvEr+Fg
         wKLcETG85BQ7LFlaTAFKg+Jko4E3ZfzecoUeMbMHsqmomjVXZVFqQeQMcRhkFKcNlGnl
         bMMccJjxA16nBqDxcpQYteOBWwuZbidrQEVw1uE3y1II8cBnI81aApjN8dxexoJwv3HY
         MQKMn1+T/A0rYiJrsxsEO6kJkXmOPctB4fBpCAkuxY33RSYP/GbhrVYrscJDJKlEpsD7
         RL7Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ja+0otxf;
       spf=pass (google.com: domain of ubizjak@gmail.com designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=ubizjak@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744813273; x=1745418073; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=9HQcgFpO5vySweGuHfPI+9BNGMLqAL/eTlGGFCxlOeo=;
        b=WZavMEQkNevw7jVzZegkndR8tpuR3E4NyGl0PGeMqW3DLq8p1zkDCuhRSr4Hmv0prK
         hrWpG4dK3CLoEgJOcYYbvhI2XTbrUw9lTWwZg7kUUnT/FM9aes2+qGD5KW2p2MYCh/q0
         +eVq1e3HOvDndSxIYxwmTnIIpRsq2+6N3q+4X1cBSi5ZeUPLdF2qOeiBreTAjmc/23T+
         U4d0kWjxxHxB+slfBm++lKGOZgKB1WtzTIc2BVN9GRqZ9QcUv7RrzGAskyWBZyskNTf2
         d2u2v+ScWhZt/PKY8G56rM9F+4AGpGCkiIj4CpddPGAYvcdkOn4UQ9kZ/ON9jEzCcFhk
         Tc2w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1744813273; x=1745418073; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=9HQcgFpO5vySweGuHfPI+9BNGMLqAL/eTlGGFCxlOeo=;
        b=BOA9CBJQV5uD+XJM+u94DJfNWdFgCeMrBeQXINx+H/ia4W2gwc0zxDywCec34wx52D
         U7azdqucMaGYqapYsXADf+GkLe09ic2WwSuDeI1L8FRN0RO49StiD32VLn/eXe0KHwT1
         7CF9IhydxMP0TqvZWIKnR4TnVkrflPylyWNn1DN9PgPI4d9xBC3JvV5jiV8PG9FC+nYO
         oE5OvrGB795s2Z7mqDwAJHLlce/qQm4MIHRTQkoEbMu9Ppc6Cn4K7Q311tSPtwdvJnQW
         ZyfeV84FLe3MPku9RFMqrT/nvFaQpcMdfLPft6KsJDwuaYpeLy67P9c2HJ5M9xKo6rDy
         K+cQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744813273; x=1745418073;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=9HQcgFpO5vySweGuHfPI+9BNGMLqAL/eTlGGFCxlOeo=;
        b=UhTKtlXiK7ekKmHMsum9icU+RwEN7LTBK4czeD0B7/H6nMwvqMNI22KRZxk+kiVntE
         GwYQOUsqkwssMEHI2jGDRo6+vnnMsxkSA81RbNcTt/RMzD19iZqkBKAXGASvnRZ1kIoB
         2wnR+SOc19CTyRymuMn1yCIs7W38KaDehr1goCpyazMLUS+KbgxC0L7ry8Vy0wxlYdF8
         NvdYVEViffI/QOTmRzoHRABojRPD/z8MwVKek4YzH0k4maVfpGiYt6et1bXRnRsOs23w
         ChmNSEBkrBk5VO4JvXDqGfS0G5D2gYVWQ/bn3w/Q+f3Z9ZT1ZpN2QfaqOhs+RwpYDEkk
         r3WA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUHrANl64sgXIFKp3ta3/Dr+7AILenNoiQEZquchQOMTIt0D4CQZasgvLZw8SGlipPWMd9lLQ==@lfdr.de
X-Gm-Message-State: AOJu0Yy1KyhkJPw2v50mwOi152haTD/NLhMYVAV4QXt8rJtqboW6jAtI
	yStxXA+QdEgWYzq77xCX8kHkgOIn+bRCqehIzX+RHakJqtSpxGpS
X-Google-Smtp-Source: AGHT+IGD+3iJxUMyw/dBXzeA/UZ1yauRqGu1H30n9zIl+zX64O5v1BrCh0ET7OqlBzeFLT/hjKy/SA==
X-Received: by 2002:a05:600c:1c99:b0:43c:f3e4:d6f7 with SMTP id 5b1f17b1804b1-4405d6bf4camr24111665e9.31.1744813272810;
        Wed, 16 Apr 2025 07:21:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAKV3qQHtrXMAAfVW6AKz+MaNzvbUkVkHHqkBLy6Tosbjw==
Received: by 2002:a05:600c:3d0f:b0:43c:ed2c:bcf2 with SMTP id
 5b1f17b1804b1-43f2c5553a3ls18509655e9.1.-pod-prod-05-eu; Wed, 16 Apr 2025
 07:21:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX5ZRINtz1J41P2Zs4GhJ6eNSwvUgiW7QR5HQLT2w6RG8CA7lYXYaeJBwdyb0wtPBMJuh4IUBZLFTo=@googlegroups.com
X-Received: by 2002:a05:600c:a46:b0:43c:fe9f:ab90 with SMTP id 5b1f17b1804b1-4405d6bf2b0mr16527515e9.28.1744813270102;
        Wed, 16 Apr 2025 07:21:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744813270; cv=none;
        d=google.com; s=arc-20240605;
        b=eXEh6TZw1THIhRh0Lvc32+GSh/9EoyZxG0qbD/Mr1DicIVgWnAHM/4czim0m1sNoEO
         iKNQlEqh7TQmkEHxbt5+UGJ6vWOiFY0Cw8qRE2YIUQEgnKK2+Snppa9Ewyamc+ZSbYc2
         u1wv/elc9kVPCvUJLZ3W26ptulKVLYKupcyj2ffTXlPTe+CRYun6ovQuDxdzkU8O4y5W
         BBjoQXN5rQvdG2NcUfxN7s+0mtcBB8EDalYZT6HpVsW/AFUGRKY7zRvSgibJedUyWnqI
         yYLW8It4KMa4mn+U5KFqeIwuoTH3gcBiDuoPDlY9/5fcOy11VU+pPLVv+ZQrOh1zlw0j
         s5AA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=vXnvk8XQNhx0TXzhv37WADjp3Ermfxa39z+e6RYkwbc=;
        fh=UjnpsdipCBMgrTEvvizhgK4Zy1t9Y+rdgkA9HUIL0vY=;
        b=WPd+C1m6HUbZIKvyTon3KRMDL4CUr44eFFsZ/FyvIjb6ws/0xUJKwMrJ2WRHSwfDBI
         hAL8Bzb4ZejUf/2zOMtGG3I3RCkA46aScDSd0TAKBIcbXZOpuxK3kQMrFj3HZXOsoWyN
         7tl9l40GMU6jVrC2kr4ohMg/SFdEj1oLXjolDgH0N5m6pRVHFJ5wuGq/ioPA42xTSMZ0
         nrezLcOZgXp+F/w2EW6siutuOlUKbn64OWlw9X2NYYALh+yPHRskFEmcjBw3yMx71/QI
         xIlNKjrHpIbAd1rGU/n7I/Ycy7kx1QK516noxyEkynXeSn7C0pQBVM99+bJX25gvzCVp
         qimA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ja+0otxf;
       spf=pass (google.com: domain of ubizjak@gmail.com designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=ubizjak@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x532.google.com (mail-ed1-x532.google.com. [2a00:1450:4864:20::532])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-44045a6cbfbsi2966165e9.0.2025.04.16.07.21.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Apr 2025 07:21:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of ubizjak@gmail.com designates 2a00:1450:4864:20::532 as permitted sender) client-ip=2a00:1450:4864:20::532;
Received: by mail-ed1-x532.google.com with SMTP id 4fb4d7f45d1cf-5e61d91a087so10100005a12.0
        for <kasan-dev@googlegroups.com>; Wed, 16 Apr 2025 07:21:10 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVPaYCcHbRkg1Y8wFJkcP4MML7zKsVRXLWkeK5nO6Zz8Zt2KGbChURcU5/RafOZJMyEOVQ9WNysr8A=@googlegroups.com
X-Gm-Gg: ASbGnctQ1gq86qijZ9UQL6qQtmNuglXQ4cErY496qHuVEI/TSRjcj92R26ymmS+oAnr
	3cdg+ty++B+11QnBwE7YwauNKidwSdXrUpTn/KiJMnl2m/9+721Tn8Zbr5XcN941iF9cc90z7dz
	qw+fAYGv9bts41CNV6bJWQiLcbQSsRY9/uNAnwnoEwO/qJEUn0fWPPOxDMHj5p7bgwyklGjqLSJ
	Axi+q8ags2iJ3SRzyGWomdUwJP3MDa7pG6ZFMOlqPji4589FNk7HTOfTjFSClhv6hjWCzgQ9L+y
	HR4IGUwTdaDKZUtdD2mjnPXJyqt9zq09YAaopJpP4MHuAl3InlNe
X-Received: by 2002:a05:6402:4017:b0:5e6:17d7:9a32 with SMTP id 4fb4d7f45d1cf-5f4b746d191mr1948775a12.18.1744813269430;
        Wed, 16 Apr 2025 07:21:09 -0700 (PDT)
Received: from [192.168.1.100] ([46.248.82.114])
        by smtp.gmail.com with ESMTPSA id 4fb4d7f45d1cf-5f36ef56ea4sm8877286a12.25.2025.04.16.07.21.08
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Apr 2025 07:21:09 -0700 (PDT)
Message-ID: <cb6d98dc-49e9-2d3b-1acc-f208e4fd13fc@gmail.com>
Date: Wed, 16 Apr 2025 16:21:07 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.15.1
Subject: Re: [PATCH 6/7] x86: objtool: add support for R_X86_64_REX_GOTPCRELX
To: Alexander Potapenko <glider@google.com>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, x86@kernel.org,
 Aleksandr Nogikh <nogikh@google.com>, Andrey Konovalov
 <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>,
 Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov
 <dvyukov@google.com>, Ingo Molnar <mingo@redhat.com>,
 Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>,
 Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
References: <20250416085446.480069-1-glider@google.com>
 <20250416085446.480069-7-glider@google.com>
Content-Language: en-US
From: Uros Bizjak <ubizjak@gmail.com>
In-Reply-To: <20250416085446.480069-7-glider@google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: ubizjak@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ja+0otxf;       spf=pass
 (google.com: domain of ubizjak@gmail.com designates 2a00:1450:4864:20::532 as
 permitted sender) smtp.mailfrom=ubizjak@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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



On 16. 04. 25 10:54, Alexander Potapenko wrote:
> When compiling modules with -fsanitize-coverage=trace-pc-guard, Clang
> will emit R_X86_64_REX_GOTPCRELX relocations for the
> __start___sancov_guards and __stop___sancov_guards symbols. Although
> these relocations can be resolved within the same binary, they are left
> over by the linker because of the --emit-relocs flag.
> 
> This patch makes it possible to resolve the R_X86_64_REX_GOTPCRELX
> relocations at runtime, as doing so does not require a .got section.
> In addition, add a missing overflow check to R_X86_64_PC32/R_X86_64_PLT32.
> 
> Cc: x86@kernel.org
> Signed-off-by: Alexander Potapenko <glider@google.com>
> ---
>   arch/x86/include/asm/elf.h      | 1 +
>   arch/x86/kernel/module.c        | 8 ++++++++
>   arch/x86/um/asm/elf.h           | 1 +
>   tools/objtool/arch/x86/decode.c | 1 +
>   4 files changed, 11 insertions(+)
> 
> diff --git a/arch/x86/include/asm/elf.h b/arch/x86/include/asm/elf.h
> index 1fb83d47711f9..15d0438467e94 100644
> --- a/arch/x86/include/asm/elf.h
> +++ b/arch/x86/include/asm/elf.h
> @@ -63,6 +63,7 @@ typedef struct user_i387_struct elf_fpregset_t;
>   #define R_X86_64_8		14	/* Direct 8 bit sign extended  */
>   #define R_X86_64_PC8		15	/* 8 bit sign extended pc relative */
>   #define R_X86_64_PC64		24	/* Place relative 64-bit signed */
> +#define R_X86_64_REX_GOTPCRELX	42	/* R_X86_64_GOTPCREL with optimizations */
>   
>   /*
>    * These are used to set parameters in the core dumps.
> diff --git a/arch/x86/kernel/module.c b/arch/x86/kernel/module.c
> index 8984abd91c001..6c8b524bfbe3b 100644
> --- a/arch/x86/kernel/module.c
> +++ b/arch/x86/kernel/module.c
> @@ -133,6 +133,14 @@ static int __write_relocate_add(Elf64_Shdr *sechdrs,
>   		case R_X86_64_PC32:
>   		case R_X86_64_PLT32:
>   			val -= (u64)loc;
> +			if ((s64)val != *(s32 *)&val)
> +				goto overflow;
> +			size = 4;
> +			break;
> +		case R_X86_64_REX_GOTPCRELX:
> +			val -= (u64)loc;
> +			if ((s64)val != *(s32 *)&val)
> +				goto overflow;
>   			size = 4;
>   			break;

These two cases are the same. You probably want:

		case R_X86_64_PC32:
		case R_X86_64_PLT32:
		case R_X86_64_REX_GOTPCRELX:
			val -= (u64)loc;
			if ((s64)val != *(s32 *)&val)
				goto overflow;
			size = 4;
			break;

Uros.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cb6d98dc-49e9-2d3b-1acc-f208e4fd13fc%40gmail.com.
