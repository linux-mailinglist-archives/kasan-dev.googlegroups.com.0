Return-Path: <kasan-dev+bncBAABBNW65PEAMGQEHW2YKMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 19437C6351A
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Nov 2025 10:47:36 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-59580c95819sf2951621e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Nov 2025 01:47:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763372855; cv=pass;
        d=google.com; s=arc-20240605;
        b=Hg26oVqZXsLL+h0hBhFuzem3LJDzYeEpkxRiCZMU9483PPefxN/EL41JSQSi6CcbF2
         aW9nBhsJCdnz9TOksJorxmEfpPA9HYkwU7bPwIrrKGievdn8MS3eeld/K5pX0Pc+5n/b
         MXwshO938rRLp/0+abZ6sxG3Py8Zv0znJvscYfDCiFqKCuGMGhnAX79I9BMw1tsVt97m
         sz+nFi2ZFynNbN3ALoFxd0NLodmcMlUgoPS9IgKFVIC47DSQMIxGqBfJzwq7TMLBqK0u
         RMHGBdJ0XXC6sap7wcsrxQB4xnOQF+iQkOdUEnC3oQBxQSz6+jSPh4JPEFEWjPEdcwIG
         X59g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=vPfOh4rXRXZDKIOPhic/FNvQGhmB1F+wd70QZIuDwAU=;
        fh=c+owpa7v45nyaNiTJRXuf1jVoZqXsYBq2cEyDTvH6l0=;
        b=XznUyyAyEgkLrkDtRL12or3Uqagz0ZDzT503cXjHegXYX3PU6GCZ651QRExAk5cAUh
         x+EoD4uVkSrLALzs4qTWbbbEr7DJTDCNaH11zOUP3x1mGUZqk8y48MjVKKI2SoyVAgzk
         QDOTUuqGC/beU8V2tgWVpb2yNYJq+rP3j/TyQuCD13TpEEwYA6lqA9C7H2bhaf0ZAYUt
         kSDow3kTQQmAvo7G9nfGAeXLfIt9SxVTl/S8kdEQ0m0tLyG8MACGp8iEAZwyDKbxGShl
         FAnCWqpdnTi5KZ0T6l8l74jXiO7+mK/C41rS983PKE8nzXoL4uYkUwv7GIqyeeaGxkFR
         5yZg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=mcrsu2KI;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.119 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763372855; x=1763977655; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=vPfOh4rXRXZDKIOPhic/FNvQGhmB1F+wd70QZIuDwAU=;
        b=hZueZlMtFw5IsvdyJRshK//ponix0BsiyKI1jvg2zpg5ZxZWSw4dBBNCZL4sRpAudW
         LuIAwh3bZbdyFfHUOsvtXGETxtx+CLdcuP1jRECf6ool8uhujF/qBqckDTGQSXspaWbm
         os0Wl2tLGjSh1argljAsUQ8fR1hzeYxgIriUNJeZsgRD68qRvA7XP8WXbrJGoE52OCXY
         kFyrbbr2MZbzd1pqskqKSeka9Ra151o0+T47woFt+Whlt0WvQpdgCGrdIr4ZUy9wWLdE
         oHEgZPu4oJ36yyaqo/rTE6feoQ5ekCefz5YjFy9mHjSNf8OeGUSi8+YKPfBiX5ct6Imd
         4BwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763372855; x=1763977655;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vPfOh4rXRXZDKIOPhic/FNvQGhmB1F+wd70QZIuDwAU=;
        b=pr+DPII+2zYJYtZi8Ciji15Un5yLMmmv3vgMWjsCSCMmasPo2uVEKtAp1aW8IK8hrE
         7FaV8SkWOKPPKoy2Uj36Bhs/FZefEsQnpwyHFwLJ6dP3DhVzu3kZQyEWAL4IsNeha/fX
         krZV4WL6GANhVXjQjYtEIBN8Pn7ehnOgsF+ujD0xsDA3dHAobh19/JeWiiBG56rkftsD
         zavnDZ8C4JcW/E0s9uTI6GX6dEUfpbNL/AoeVBi8A8ZeVIE7fznucdbilrngWOcqV2Z9
         m7vgDO0xPZuL1WMliSGxc4sPqXHZHaNa+FkMr4NOM55REEOTg+RTENSc75SiTbF6n73H
         czpQ==
X-Forwarded-Encrypted: i=2; AJvYcCWNbvwRfnBdgr8bfZrWkqSXr5jHDKdtT4Yqn0PolRgLfvKgC530pJeIC98OdjxDdnDcpf2HTw==@lfdr.de
X-Gm-Message-State: AOJu0YweQCnYVE7ctgiqjD52P1uVEsfOg4dKf49m60HUnmFEHiOwMDQi
	mWNxHt06+cjD68DVfjAQwUqcO9AmBh+Wgek7xopN8gZPJ7QbBt2Kt7jZ
X-Google-Smtp-Source: AGHT+IEXEHmnyBGw6fL/4PynYQHVcSl6fiXPpsjK4sPBT6K2dYmKzaZnF/p4C24Q5b1VdMNH0G2sKg==
X-Received: by 2002:a05:6512:3d21:b0:594:31af:4de0 with SMTP id 2adb3069b0e04-59584150c6amr3379364e87.0.1763372854791;
        Mon, 17 Nov 2025 01:47:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZYz3tkl3hNw5GUxGGxWtAv3ChPusX7udiKz0zMDqIgbA=="
Received: by 2002:ac2:5688:0:b0:595:94db:3e17 with SMTP id 2adb3069b0e04-59594db3f1els158430e87.1.-pod-prod-03-eu;
 Mon, 17 Nov 2025 01:47:32 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVjg+abnMP5A5E1xfYQwbJlDfHhV1jqjnAOZKNjDr/T64rgTlwUdAFUiBlsUm6QPpcTH9QXHMUebmQ=@googlegroups.com
X-Received: by 2002:a05:6512:39cf:b0:594:49ed:3cf0 with SMTP id 2adb3069b0e04-595841fe719mr3337172e87.36.1763372852452;
        Mon, 17 Nov 2025 01:47:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763372852; cv=none;
        d=google.com; s=arc-20240605;
        b=eULuCKidS+8OR4c0z1zUI1CsnYN7/nRCDzSz14dNDR1M+bNMkGS2S8fUsXBAnGwV63
         WiAaZfQ9poQOPu10nxrUQeBO7TAp6OhntwESbuVct1dAcSlSw88UH+y0QhCcYQMInFls
         Yl4sDb2+tswFfM7z62mlfRVCTArAmIKXSi6oiQGG7+NY8yg1ESOAM8dfD6uqjG+otcx7
         aCfyuCXHbGnOZVkJFiTntwrUm5ZNhIBLWygT9unH7xOotrcsW+7ajT0K1FLa/GTmMbyY
         ih3ydLTnao/Qw2ll/QuKedZqY8mp7F2tOLXSl6/J1F+XWq+zIIGDu0gPQ/GAvXblXKyb
         RDbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=ihq7qfJz6+gs5FNsdIMwz9cXAydO9ORjjGo1TVl8LXw=;
        fh=/crQiC7490kIRJaaNZ1YB5fp3BQM35ydbTqiqFTk25g=;
        b=amq9eLTdP9Qp5/8DOauDOnUK4u883b82w1bAiYO71DE2dFed5QhI6ey8GPMxjXW6Qp
         /Fc6d8THC5qqvs+B/BvhLhfrJYnwXvAtePQ0jdbylnv4PA58SvgUQp8rsYFxUvIlWYMH
         sdSjLQxjH411LLxhAj8/HYO+LpnbXeQx6pGBqm9f+s5b7QwRBTCvFWn6/jbVGGtjpZYm
         kHr0EYYN3+i03BiAPJPkzZtqwnl2/Kodi+YSAsW/ffsCpLwAvBHvN9zcedzyBYzXeVkY
         OX+jwNlEHg7naVZYfoY6Ks2fKX1ntCaly0V2hzDEuNuFIHiSotbzBPTbu8Al8ijDeNLO
         SjNw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=mcrsu2KI;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.119 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-106119.protonmail.ch (mail-106119.protonmail.ch. [79.135.106.119])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-595803d582fsi234206e87.6.2025.11.17.01.47.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 17 Nov 2025 01:47:32 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.119 as permitted sender) client-ip=79.135.106.119;
Date: Mon, 17 Nov 2025 09:47:20 +0000
To: Peter Zijlstra <peterz@infradead.org>
From: =?UTF-8?Q?=27Maciej_Wiecz=C3=B3r=2DRetman=27_via_kasan=2Ddev?= <kasan-dev@googlegroups.com>
Cc: xin@zytor.com, kaleshsingh@google.com, kbingham@kernel.org, akpm@linux-foundation.org, nathan@kernel.org, ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com, glider@google.com, mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com, ardb@kernel.org,
	Liam.Howlett@oracle.com, nicolas.schier@linux.dev, ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, rppt@kernel.org, will@kernel.org, luto@kernel.org, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, linux-doc@vger.kernel.org
Subject: Re: [PATCH v6 15/18] x86/kasan: Handle UD1 for inline KASAN reports
Message-ID: <a4vtlaxadmqod44sriwf2b6cf5fzzvngl6f5s2vg6ziebahjtv@yctbqspkdn2b>
In-Reply-To: <20251111102719.GH278048@noisy.programming.kicks-ass.net>
References: <cover.1761763681.git.m.wieczorretman@pm.me> <8b0daaf83752528418bf2dd8d08906c37fa31f69.1761763681.git.m.wieczorretman@pm.me> <20251111102719.GH278048@noisy.programming.kicks-ass.net>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: c252819bcd42668f3ed4c2d3435f49dcbb5a823f
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=mcrsu2KI;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.119 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: =?utf-8?Q?Maciej_Wiecz=C3=B3r-Retman?= <m.wieczorretman@pm.me>
Reply-To: =?utf-8?Q?Maciej_Wiecz=C3=B3r-Retman?= <m.wieczorretman@pm.me>
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

On 2025-11-11 at 11:27:19 +0100, Peter Zijlstra wrote:
>On Wed, Oct 29, 2025 at 08:09:51PM +0000, Maciej Wieczor-Retman wrote:
>> From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>>
>> Inline KASAN on x86 should do tag mismatch reports by passing the
>> metadata through the UD1 instruction and the faulty address through RDI,
>> a scheme that's already used by UBSan and is easy to extend.
>>
>> The current LLVM way of passing KASAN software tag mode metadata is done
>> using the INT3 instruction. However that should be changed because it
>> doesn't align to how the kernel already handles UD1 for similar use
>> cases. Since inline software tag-based KASAN doesn't work on x86 due to
>> missing compiler support it can be fixed and the INT3 can be changed to
>> UD1 at the same time.
>>
>> Add a kasan component to the #UD decoding and handling functions.
>>
>> Make part of that hook - which decides whether to die or recover from a
>> tag mismatch - arch independent to avoid duplicating a long comment on
>> both x86 and arm64 architectures.
>>
>
>> diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
>> index 396071832d02..375651d9b114 100644
>> --- a/arch/x86/include/asm/kasan.h
>> +++ b/arch/x86/include/asm/kasan.h
>> @@ -6,6 +6,24 @@
>>  #include <linux/kasan-tags.h>
>>  #include <linux/types.h>
>>  #define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
>> +
>> +/*
>> + * LLVM ABI for reporting tag mismatches in inline KASAN mode.
>> + * On x86 the UD1 instruction is used to carry metadata in the ECX register
>> + * to the KASAN report. ECX is used to differentiate KASAN from UBSan when
>> + * decoding the UD1 instruction.
>> + *
>> + * SIZE refers to how many bytes the faulty memory access
>> + * requested.
>> + * WRITE bit, when set, indicates the access was a write, otherwise
>> + * it was a read.
>> + * RECOVER bit, when set, should allow the kernel to carry on after
>> + * a tag mismatch. Otherwise die() is called.
>> + */
>> +#define KASAN_ECX_RECOVER	0x20
>> +#define KASAN_ECX_WRITE		0x10
>> +#define KASAN_ECX_SIZE_MASK	0x0f
>> +#define KASAN_ECX_SIZE(ecx)	(1 << ((ecx) & KASAN_ECX_SIZE_MASK))
>>  #define KASAN_SHADOW_SCALE_SHIFT 3
>
>> diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
>> index 6b22611e69cc..40fefd306c76 100644
>> --- a/arch/x86/kernel/traps.c
>> +++ b/arch/x86/kernel/traps.c
>> @@ -179,6 +179,9 @@ __always_inline int decode_bug(unsigned long addr, s32 *imm, int *len)
>>  	if (X86_MODRM_REG(v) == 0)	/* EAX */
>>  		return BUG_UD1_UBSAN;
>>
>> +	if (X86_MODRM_REG(v) == 1)	/* ECX */
>> +		return BUG_UD1_KASAN;
>> +
>>  	return BUG_UD1;
>>  }
>>
>> @@ -357,6 +360,11 @@ static noinstr bool handle_bug(struct pt_regs *regs)
>>  		}
>>  		break;
>>
>> +	case BUG_UD1_KASAN:
>> +		kasan_inline_handler(regs);
>> +		handled = true;
>> +		break;
>> +
>>  	default:
>>  		break;
>>  	}
>
>> +void kasan_inline_handler(struct pt_regs *regs)
>> +{
>> +	int metadata = regs->cx;
>> +	u64 addr = regs->di;
>> +	u64 pc = regs->ip;
>> +	bool recover = metadata & KASAN_ECX_RECOVER;
>> +	bool write = metadata & KASAN_ECX_WRITE;
>> +	size_t size = KASAN_ECX_SIZE(metadata);
>> +
>> +	if (user_mode(regs))
>> +		return;
>> +
>> +	if (!kasan_report((void *)addr, size, write, pc))
>> +		return;
>> +
>> +	kasan_die_unless_recover(recover, "Oops - KASAN", regs, metadata, die);
>> +}
>
>I'm confused. Going by the ARM64 code, the meta-data is constant per
>site -- it is encoded in the break immediate.
>
>And I suggested you do the same on x86 by using the single byte
>displacement instruction encoding.
>
>	ud1	0xFF(%ecx), %ecx
>
>Also, we don't have to use a fixed register for the address, you can do:
>
>	ud1	0xFF(%ecx), %reg
>
>and have %reg tell us what register the address is in.
>
>Then you can recover the meta-data from the displacement immediate and
>the address from whatever register is denoted.
>
>This avoids the 'callsite' from having to clobber cx and move the address
>into di.
>
>What you have here will work, and I don't suppose we care about code
>density with KASAN much, but it could've been so much better :/

Thanks for checking the patch out, maybe I got too focused on just
getting clang to work. You're right, I'll try using the displacement
encoding.

I was attempting a few different encodings because clang was fussy about
putting data where I wanted it. The one in the patch worked fine and I
thought it'd be consistent with the form that UBSan uses. But yeah, I'll
work on it more.

I'll also go and rebase my series onto your WARN() hackery one since
there are a lot of changes to traps.c.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a4vtlaxadmqod44sriwf2b6cf5fzzvngl6f5s2vg6ziebahjtv%40yctbqspkdn2b.
