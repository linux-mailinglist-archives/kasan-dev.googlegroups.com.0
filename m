Return-Path: <kasan-dev+bncBCSL7B6LWYHBB3W2UXFQMGQEV334EYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id F076CD29123
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Jan 2026 23:42:55 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-59b7e2b4a18sf892975e87.3
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Jan 2026 14:42:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768516975; cv=pass;
        d=google.com; s=arc-20240605;
        b=Lkndy83KVkdep01K7ypdYNE11fDzf9i0YCgv+K7n3NePquoSzVe6l0/tNYkgQFBLZm
         2PYhJhGpky+GQs4qFYkRrMoiixY8WDtQ3YU8ANUTuJUIJMy5fxheOWyV8oinfzN9PP+Z
         4XE/kMbXhL3zLP98YwF2JTb01nfNfNys1XwIfvz6CPVfK4+SpBgKagdp2pNg3xlWwILV
         4AmXjtIE06+oWKs498KWyLxjiXHtvGzCz4fz4Wb+CpEUCqWDnlbWEuEvaUWpbld01QHg
         vCmgxO6tWlXbjVhDTmp7YRp2PqWa2bRkkTmnzNHQCgmr33BAMINUmlbLaYMVi0blqjzQ
         CMRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=E/PCJpY3zO+WG+8hYqfiBdqteJNX0MLMJYg39rIohOs=;
        fh=4UqlElnJoPs0bW/Z9WoEEUwN+tMo3K6FzJH8kaZ2qFM=;
        b=BdJv5UmB/uBsVyOFU13y26oKnuZ0Xut+oPhqd+xasAOm6qB0eVujHbOCGJGZemeZv4
         NNxX1ZIdCdii3ENIV/kk05BkWnVwQOzyzI8J+92jULjolWfahxxzYfsT4lo0pr0kskL/
         XE6VBcnRc5ULMUs4Rt6L4O/lNRavYKaY4xpkiRTDESxXObob9uB3748e+Z7toICpORrS
         WC+JNEpCxyx+SIjjhuN5PnbVExvLqmR3qQOkmYcwL485sbXMAundewXCqvGOcDPaIfnB
         WM3JtZOoH6qDI8rjEJbhtYlZMazwHui2vfFD2YGzOe2aO7u7BXZ7za+CLWR0QdLAP8ne
         G6Og==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=A4s7l6Kq;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::135 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768516975; x=1769121775; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=E/PCJpY3zO+WG+8hYqfiBdqteJNX0MLMJYg39rIohOs=;
        b=RKWsVNxMI42C/WfxkJgqDG/SHJd262pCBK+eq8jPTZWSFfESwE+QtGSiDWzsgzTy+0
         gj0xeFfyalcX1uKif83e5AJRbO1WOejz++4EneUJ+JuA3fOEyVezlwG8ONonFJ3B5NF/
         HoEINPBLuArFg6mPEMn9mkYdNgARvSF6KdrosqVdG7HeqKG8h2RO4zvKYTXEj9kPzWNA
         AQUzap/YdDnx3fODC5eonSu48dJyPzlBuMNP9WfAR2mA4eG+JdM1Agh1xc5N+8f9PGYU
         zdpaJod41lVVwKWYvZEo0vGIKqOgniKIwgygem0DVoPIVYl0RNEZTBLTWeEO+i3eq4ht
         TEKA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768516975; x=1769121775; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=E/PCJpY3zO+WG+8hYqfiBdqteJNX0MLMJYg39rIohOs=;
        b=TX+z/2dK+twKln8CeIdHCH2ICqITP5KGpC0I1CxpaHOyVG34iFT6/0MQ0evCHn90Nd
         ME7WRYcVd6JoJZu9vO0cKHD0VFhUKVETcqPM/7jyL35ZkxSxVTXxvaXzMdhbts7vAduC
         MWFRlhTsqKC1EmaK+sXUFTYE8AHd7FxfmzMVa00qU2/Oh56iUkNGdime8BR5lwDzZmPC
         X6/8KHKb/Qww5R4yNHQngxyA5NZqRVuVoxSfDr/K4bJ/3pq9hV2zOiiFaXzj6/hMu95e
         IHteIqUDpICTun2/5iqlZBbib/H/nRU1sR5fDZB+ypgKbvMSx3aR/FBtgkMN+AdtD587
         YksQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768516975; x=1769121775;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-gm-gg:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=E/PCJpY3zO+WG+8hYqfiBdqteJNX0MLMJYg39rIohOs=;
        b=u9UIMqDCtAz9ayaF9tVW7VYnpl16fXZSRk0iogCxnpHoSnRpJN2Croh1YiC+HDr0Qc
         HYmrMW1ZxIM0kaI0atJwAH//a5WLFHjuLM3uJjVAztFBs+JUV+gi8K5R2CTN4eswo5YH
         dQyPS++e8pWfdYCa010ctZ4FYCToj9eKJk5ocl7x2k4PI46MVP9mrTp9BQ4ZpKCtB3GJ
         yee/G4OKDR0mFzSmTRvXaFh20XClToXQIHfe9/bbUAVHRwN6WRMXLcDFcW8rmnTjFbEe
         WHu1gyo4mo7DdNvB9W/dsGC8UwSZohD0yk1JmnRflV3E18DFjjKZCuqlEbemuzzZuAy6
         FB9w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWsQ4eDJsvtY84bkzsMdkmK5gKdTuGbKwAWoxVJDEB4YxJUNiG+A69J/0I6VsqCPx5FvMfEsA==@lfdr.de
X-Gm-Message-State: AOJu0Yx49jc0APF/VwV71NIZNwb688cUA0Fs1ejB3bIRp3P44SWZaddV
	x5gCWqgyBz3EkVxQHDJnFENTV96MwsbhYcDjNdV10OVuNLjCV2Ge3X/x
X-Received: by 2002:ac2:51c9:0:b0:59a:123e:69ab with SMTP id 2adb3069b0e04-59baeeb1a6bmr350177e87.10.1768516974843;
        Thu, 15 Jan 2026 14:42:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FxD0VDZiBhR0EXMSdRiyfldk6L6bsXe5hHx45SdyjbhQ=="
Received: by 2002:a05:6512:23a7:b0:59b:a040:2eb6 with SMTP id
 2adb3069b0e04-59ba7188ee6ls482711e87.1.-pod-prod-02-eu; Thu, 15 Jan 2026
 14:42:51 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUTRNVSO2z4Kj3+7Jl+OR7cuNdt7hmfs5Q2UDiCTuR7/1iecwfyoIwXrCeDUff7z/z7iF95dM5JqqE=@googlegroups.com
X-Received: by 2002:a05:6512:1050:b0:59b:7a80:3b66 with SMTP id 2adb3069b0e04-59baeef85e9mr311450e87.35.1768516971569;
        Thu, 15 Jan 2026 14:42:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768516971; cv=none;
        d=google.com; s=arc-20240605;
        b=k/of4krzSyczWtU7LSbQjuphJXGliT4y1Zd0V3D4XSyCUaqFgpyziJlwraB5EKN9oR
         BCUY3ACq/IsyH3NUKh4n5GIAVLk+Ujo23uyHwoQKf+qxV4eYJGtX/gPCw/ff5RW+Ijh6
         sXDuS+8i4ge84ADXhjxva5lYty2lMkCShp4nyKH6zDne6OlOC/LHY4KdIHr1occRJZWs
         fzzq1HxKfIt1O52DRD+28Nm/xEPT6QKHF6xOr5vVKgTawL4YOkTOnQMS9uivOeJinOUP
         YrkeOm69FO9IdEtuy+A2eRy/H8ZejmIyWmWGYbAFxLrTkfBLi2UvdysqC8n02UFhqqjC
         d7zg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=vQuagjPxslA3/GbLy8OgugPdFRJI5tMwgAjobUXXgeg=;
        fh=ecPMEQ/ew4pANEVwoW1MaVtGmHXTLvVXgCufL76NhIA=;
        b=IsCAS8+EutzUmhrbp6dzldO32Dzfi7Sng4TsChE7jitcD+hhXLq+cHv5mm6lY8yjf0
         eqLkRiFxz9RUzJvQnltJi+nLNjlS6SNvcURoI/5elREfmvTxijEhGNU+MwOS3gIkCYmo
         yYJIkVFXn8ZC1hxj4QROrJ/i9LKuOvGd+RGV+otuC7pcvNKJSkY3j/rHpnY19LK8N3AN
         8qGEtyIR5zAuBxH/jwDIUhwfbr0x+DX1X56Ki/3Vp7o/39wBQArormNHSIXjHt9zhkRs
         79O4iC9hMxnvpjBDPalNaiy6YL2gOi+KU8zcd0JBgphri4rZfJOVGHbvt5tor4RCoQNE
         4uLw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=A4s7l6Kq;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::135 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x135.google.com (mail-lf1-x135.google.com. [2a00:1450:4864:20::135])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59baf3a1d4asi13316e87.8.2026.01.15.14.42.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Jan 2026 14:42:51 -0800 (PST)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::135 as permitted sender) client-ip=2a00:1450:4864:20::135;
Received: by mail-lf1-x135.google.com with SMTP id 2adb3069b0e04-59b75f0b8ecso193586e87.3
        for <kasan-dev@googlegroups.com>; Thu, 15 Jan 2026 14:42:51 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWdnubY9NChpsnM5R7wuDt2QBgWcnwF+09LcaXOiSpFAh+lcKEgVbAd0p7XZFb0UiGldy/Kntr+hZU=@googlegroups.com
X-Gm-Gg: AY/fxX5OwJv2FD0gueSkhsStbJfY/jihMpPvIisLF2VLsVihRLv7bwFdsfN6xX/UXYT
	0OnrEF775p55c7kygrSudMm1CUsxY3ScdsaYfUxh/Q3XgT2vO4VSu9LSDGHTdZ2Q3tyzhdh3PHx
	Xb5wiqpChIQHZYuoVE+h+CB3WxktjtP+pxPdwEWsx/dxOjxag2vP+8x4ppLjOnyx0BmD5vsiVY2
	OAaKIItwaxgomR78rqmRBlICbrZDRAcnowKaUrToCapzjNWwQoPyNnNWetsQzTCbuSr3SyonfiV
	uIzkzUXNRAHaEN/ayeL0TegfhSix9xb+IEviGfuqXfgeVySNYsLh/WObP8sthgxND/KTMv951yr
	BmX3+WARiyO5qYyamsa/K5lVsfCKt8KeC5WiPeQS0KnKhHKWrXltbTIE48M+2mktsw9PxQVTlsg
	JRxWdCm/Vx1Lyp30Ljqvw=
X-Received: by 2002:a05:6512:63d1:20b0:59b:7be4:8c40 with SMTP id 2adb3069b0e04-59baef130e4mr131958e87.8.1768516970797;
        Thu, 15 Jan 2026 14:42:50 -0800 (PST)
Received: from [192.168.0.18] ([87.116.178.235])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-59baf35434bsm209044e87.45.2026.01.15.14.42.47
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Jan 2026 14:42:50 -0800 (PST)
Message-ID: <2592f303-05f5-4646-b59f-38cb7549834e@gmail.com>
Date: Thu, 15 Jan 2026 23:42:02 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v8 01/14] kasan: sw_tags: Use arithmetic shift for shadow
 computation
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Jonathan Corbet <corbet@lwn.net>, Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Jan Kiszka <jan.kiszka@siemens.com>, Kieran Bingham <kbingham@kernel.org>,
 Nathan Chancellor <nathan@kernel.org>,
 Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
 Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>
Cc: Samuel Holland <samuel.holland@sifive.com>,
 Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>,
 linux-arm-kernel@lists.infradead.org, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, llvm@lists.linux.dev
References: <cover.1768233085.git.m.wieczorretman@pm.me>
 <4f31939d55d886f21c91272398fe43a32ea36b3f.1768233085.git.m.wieczorretman@pm.me>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <4f31939d55d886f21c91272398fe43a32ea36b3f.1768233085.git.m.wieczorretman@pm.me>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=A4s7l6Kq;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::135
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
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



On 1/12/26 6:27 PM, Maciej Wieczor-Retman wrote:
  
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 62c01b4527eb..b5beb1b10bd2 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -642,11 +642,39 @@ void kasan_non_canonical_hook(unsigned long addr)
>  	const char *bug_type;
>  
>  	/*
> -	 * All addresses that came as a result of the memory-to-shadow mapping
> -	 * (even for bogus pointers) must be >= KASAN_SHADOW_OFFSET.
> +	 * For Generic KASAN, kasan_mem_to_shadow() uses the logical right shift
> +	 * and never overflows with the chosen KASAN_SHADOW_OFFSET values (on
> +	 * both x86 and arm64). Thus, the possible shadow addresses (even for
> +	 * bogus pointers) belong to a single contiguous region that is the
> +	 * result of kasan_mem_to_shadow() applied to the whole address space.
>  	 */
> -	if (addr < KASAN_SHADOW_OFFSET)
> -		return;
> +	if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> +		if (addr < (unsigned long)kasan_mem_to_shadow((void *)(0ULL)) ||
> +		    addr > (unsigned long)kasan_mem_to_shadow((void *)(~0ULL)))
> +			return;
> +	}
> +
> +	/*
> +	 * For Software Tag-Based KASAN, kasan_mem_to_shadow() uses the
> +	 * arithmetic shift. Normally, this would make checking for a possible
> +	 * shadow address complicated, as the shadow address computation
> +	 * operation would overflow only for some memory addresses. However, due
> +	 * to the chosen KASAN_SHADOW_OFFSET values and the fact the
> +	 * kasan_mem_to_shadow() only operates on pointers with the tag reset,
> +	 * the overflow always happens.
> +	 *
> +	 * For arm64, the top byte of the pointer gets reset to 0xFF. Thus, the
> +	 * possible shadow addresses belong to a region that is the result of
> +	 * kasan_mem_to_shadow() applied to the memory range
> +	 * [0xFF000000000000, 0xFFFFFFFFFFFFFFFF]. Despite the overflow, the
                  ^ Missing couple 00 here

> +	 * resulting possible shadow region is contiguous, as the overflow
> +	 * happens for both 0xFF000000000000 and 0xFFFFFFFFFFFFFFFF.
                                  ^ same as above

> +	 */
> +	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) && IS_ENABLED(CONFIG_ARM64)) {
> +		if (addr < (unsigned long)kasan_mem_to_shadow((void *)(0xFFULL << 56)) ||

This will not work for inline mode because compiler uses logical shift.
Consider NULL-ptr derefernce. Compiler will calculate shadow address for 0 as:
      (((0x0 | 0xffULL) << 56) >> 4)+0xffff800000000000ULL = 0x0fef8000....0
Which is less than ((0xFF00...00LL) >> 4) +  0xffff800000000000ULL = 0xffff800...0
So we will bail out here.
Perhaps we could do addr |= 0xFFLL to fix this

> +		    addr > (unsigned long)kasan_mem_to_shadow((void *)(~0ULL)))
> +			return;
> +	}
>  
>  	orig_addr = (unsigned long)kasan_shadow_to_mem((void *)addr);
>  

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2592f303-05f5-4646-b59f-38cb7549834e%40gmail.com.
