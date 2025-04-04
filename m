Return-Path: <kasan-dev+bncBD22BAF5REGBBBF2YC7QMGQETIRDRRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id C9214A7C2EA
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Apr 2025 19:55:17 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-3d5bb1708e4sf47031725ab.3
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Apr 2025 10:55:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1743789316; cv=pass;
        d=google.com; s=arc-20240605;
        b=jo9lAwWBg2nNPmSMknoBX3UX6ebCXJOMAWsLERSPVidFVTGTYlIx6CqbQAJXD51HtG
         ooL903hugWuGtU52jPGpCNi6zZJGJiQw2zLBY8E7tT6G/Qu4tp/p8sOZ95NChofJNvZp
         YgDqM0xCDtbHkU+qweYW2h9ed4rZIc9O3CTTJdRY5RAibB2zsLffoQ5FfZW9ziA6XTfR
         GKYPQuGPk0YoEgu1ZQaMUNpdydy3O05wWopBkS/xcPdPLtsCgZ/wFdm6EI6P8J+c5EOX
         96dDP67jR9sGv3H2i3l2GiZwDX5blKsCMIzT3MFpb7Fx81Z+X+seXOCsqOHCNO18rUB2
         GwrQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=kjdSzj3Qeivy2egkleIUp19ZNR/dcD/PvOGC+Xdr5j4=;
        fh=pBcQzTlH14jy5IiyJEaMB2/fhfWVm6Fg4shk+D1vii4=;
        b=DYk/Rb01KzsEdCwPU1USQDvpUikIsB/YOfln5xkMlBdYA53PxT7ki2x6UOsKz5XbJq
         LkJ+3GndsGfDfmOvx/nlw4zj3CLLzgaG2c/CH3g5x2KCkV7XlaHtT2d1FfUj7bke2TVk
         bC1ExE7+eVwVThsrhzZBYosXvwbTZ7INDsqfdCygO9xOQFQYfI+tQ3q2xZOgIj6EAa7k
         FEQXq31fUf5eJiakAanI3Vvls2+pwqoTJblglGz7obMfCHp7XRn4Rz1ID5R/ydIrlIQ8
         y8agCITwsXRToTY79b+0qTByUEQ3JrM4kVwNij1AHMx/X5ynAVjMgh2GDOwXxQai8k7h
         ZQpw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=cS5RBcX8;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 198.175.65.18 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1743789316; x=1744394116; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=kjdSzj3Qeivy2egkleIUp19ZNR/dcD/PvOGC+Xdr5j4=;
        b=hIP6iH9IOyTOrPAiLC3oWyF3iwYSxkVbuivqFWv8Rj7xyNDD83hVeoltoWwJj6jedC
         byRkGAouJEMAVL7uU3Vz37DUDJ1RLd664Hj8Q7pzM/yateLL/td5RxlxUvClAC6G2/8Q
         z74c/qepfh0+jAUnL0GkcUWAr1W1wIwE7eLYxroqAG5ptB8KdIG6O1ZhVXCMd6jsDsyv
         VKgmkr70+00/AWq2M5s52u6Ebfa/mHfLWQ/yz2s7XVmZdCXL1G3xx5ZvytJSy7BOPUA7
         wtAqTBL2iNg6D26fZR1bKhbp+w31A3dZ3d4HJGpCoNluD2s4VouMmqua7WJfNFIw2ykp
         MsFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1743789316; x=1744394116;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=kjdSzj3Qeivy2egkleIUp19ZNR/dcD/PvOGC+Xdr5j4=;
        b=QB13h33qYyf+d6lXZfAWECELwz9/4MtD+aebFZQaAuaWQP8SQbZ4J4qbBJGtRI+dmf
         zvHkby9PeUB2dL4gG+Dbrlx9dxBbD3LyFW//ng0kdtvDiA7Hwh0zv43rgZ+p2pH1KdU9
         VE25KcwBc83TrG9gwylvEcPqSQGJaA/xG2BiM6Sj1/B7nSowsUxg+KITx2tp02v1qhQJ
         d0NUlmyCOcdtxTR64XMGeKf5ZegbBsHmh1aPeEVCJOWpi96Vg4Zmsbpy0mz53hYCXTZB
         c0Ps2b0zsj95ARr8PFVTsfB0AfLwzrEjkpwgu/xZ3btWOVOlZn3QIFD+pMMZswM3mBup
         ylNA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW+vJGRYgTNMIucinfLGncawphrqApFLFSeSsfSYROhH7hj23sown8FRp7/FMyEzX7sVJ42Yg==@lfdr.de
X-Gm-Message-State: AOJu0YweOI3sKG6Vz5DuQ5jMtTg8xVYH6ARlybmV2Xkf9SF/x6J8zeeB
	6Yy9HeqGBTf+4pbB/SJfV6eop8HAQpniaw77ilflEUAOEhS3Trer
X-Google-Smtp-Source: AGHT+IGSDgAhDW9j995oKleHM52ZhI20ARKChG9GfkyElbVWHNFS9xl+kebtUaNpL499h/4vyIoLKw==
X-Received: by 2002:a05:6e02:156b:b0:3d3:dfc2:912f with SMTP id e9e14a558f8ab-3d6e3efbc2amr54308015ab.7.1743789316491;
        Fri, 04 Apr 2025 10:55:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPALr4LTnVvIbN2y+yhABqVvrJ1ypEhc8OYrNZlh6nCOkfw==
Received: by 2002:a92:d581:0:b0:3d1:a26f:e248 with SMTP id e9e14a558f8ab-3d6dc9c8ac2ls5202015ab.1.-pod-prod-05-us;
 Fri, 04 Apr 2025 10:55:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW3b/DEvRxndMsRT6XURC+aNyZdhIE4U1sySuJeM7ACt1v5LyoY+EOk8rLmfbDoxr8EYXyvsJWKd3c=@googlegroups.com
X-Received: by 2002:a05:6e02:156b:b0:3d3:dfc2:912f with SMTP id e9e14a558f8ab-3d6e3efbc2amr54307565ab.7.1743789315798;
        Fri, 04 Apr 2025 10:55:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1743789315; cv=none;
        d=google.com; s=arc-20240605;
        b=OqtzJGs5yqNpHLrnhJgEs4pHHwhrlZHlU8rFauZeMizTHpHl3/0lVMi2yTXpDQt/pc
         bFdK9vP3rx6O1WLG3zyFFeV1u2gp2i4ZuCEZZoh70ZtKIPvs4fh/ciXPGrTJv2O6X7oi
         kUtRvgl7Rrw5PQzo2cDMhMPQ6/nhKNHYPlCxG24HVOFn4XfWukRtN6d/MNq/8UWVdUSQ
         kQpd3EnSeYWauh1HlovZmxZXbLUdzB+W3/V7j5Nnn0BKnS6fcymEe1uW/epHfEAwNqiJ
         Qjhqsdr2JH8WRgAcVyhIzrTE0Ndi480AmIQVIkmdKEXyKZ13xNuRUpkvyiGNvmUzFpnf
         xlXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:content-language
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=OvgULkyAd91bfBJhci113TYF0W+Q694yEAcCw33C8+k=;
        fh=qAclqxczifa7kqZeY+RB5PN2iG3DrlxE7ZoinyFrUhQ=;
        b=SO86d+CbIguQsv0RRzlK0FCZygIRKzqnDMLfcj0CWFYJiFOauTq9Rcekw2u1cs40Jq
         dSC+ZChIvq/YgAksVj07mvyXEc/18cfJkD3AWX4At+z4vqlGdmyxamXOy6Ma23DEF/A8
         YTg01EqfzU7lsfDxvr8T4iUuQPAtP/toCl2D8O1A4kxagB8aWAox61NmEFhYlqIXFJmx
         1++vknUiDNhwZ/9muMTlxPyrhRKGLavpcYZ6ohBVN+tKwy1Va/AEjbh8+kUd94RKVBGJ
         By4JxouUAEpwxDS9XMSqWthv2XLLL8VV53bmbHi81xWSz8riPEqqq1sjVCWm6Kt3ykLA
         IVOQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=cS5RBcX8;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 198.175.65.18 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.18])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4f4b5d1c29asi188705173.5.2025.04.04.10.55.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 04 Apr 2025 10:55:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of dave.hansen@intel.com designates 198.175.65.18 as permitted sender) client-ip=198.175.65.18;
X-CSE-ConnectionGUID: B9XSYfVzS5Sx98F4HFBeVQ==
X-CSE-MsgGUID: MhRNiW2uTFufsBKBHHzHyA==
X-IronPort-AV: E=McAfee;i="6700,10204,11394"; a="45379465"
X-IronPort-AV: E=Sophos;i="6.15,189,1739865600"; 
   d="scan'208";a="45379465"
Received: from fmviesa003.fm.intel.com ([10.60.135.143])
  by orvoesa110.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 10:55:14 -0700
X-CSE-ConnectionGUID: XcFkPhxZTJWIrLqhXG8wPg==
X-CSE-MsgGUID: DQH8Q7APT5qgIEL6nrV9GQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.15,189,1739865600"; 
   d="scan'208";a="131512363"
Received: from daliomra-mobl3.amr.corp.intel.com (HELO [10.124.223.29]) ([10.124.223.29])
  by fmviesa003-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 10:55:10 -0700
Message-ID: <c797714b-4180-4439-8a02-3cfacd42dafe@intel.com>
Date: Fri, 4 Apr 2025 10:55:09 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 11/14] x86: Handle int3 for inline KASAN reports
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, hpa@zytor.com,
 hch@infradead.org, nick.desaulniers+lkml@gmail.com,
 kuan-ying.lee@canonical.com, masahiroy@kernel.org,
 samuel.holland@sifive.com, mingo@redhat.com, corbet@lwn.net,
 ryabinin.a.a@gmail.com, guoweikang.kernel@gmail.com, jpoimboe@kernel.org,
 ardb@kernel.org, vincenzo.frascino@arm.com, glider@google.com,
 kirill.shutemov@linux.intel.com, apopple@nvidia.com,
 samitolvanen@google.com, kaleshsingh@google.com, jgross@suse.com,
 andreyknvl@gmail.com, scott@os.amperecomputing.com, tony.luck@intel.com,
 dvyukov@google.com, pasha.tatashin@soleen.com, ziy@nvidia.com,
 broonie@kernel.org, gatlin.newhouse@gmail.com, jackmanb@google.com,
 wangkefeng.wang@huawei.com, thiago.bauermann@linaro.org, tglx@linutronix.de,
 kees@kernel.org, akpm@linux-foundation.org, jason.andryuk@amd.com,
 snovitoll@gmail.com, xin@zytor.com, jan.kiszka@siemens.com, bp@alien8.de,
 rppt@kernel.org, peterz@infradead.org, pankaj.gupta@amd.com,
 thuth@redhat.com, andriy.shevchenko@linux.intel.com,
 joel.granados@kernel.org, kbingham@kernel.org, nicolas@fjasle.eu,
 mark.rutland@arm.com, surenb@google.com, catalin.marinas@arm.com,
 morbo@google.com, justinstitt@google.com, ubizjak@gmail.com,
 jhubbard@nvidia.com, urezki@gmail.com, dave.hansen@linux.intel.com,
 bhe@redhat.com, luto@kernel.org, baohua@kernel.org, nathan@kernel.org,
 will@kernel.org, brgerst@gmail.com
Cc: llvm@lists.linux.dev, linux-mm@kvack.org, linux-doc@vger.kernel.org,
 linux-arm-kernel@lists.infradead.org, linux-kbuild@vger.kernel.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, x86@kernel.org
References: <cover.1743772053.git.maciej.wieczor-retman@intel.com>
 <012c84049b853d6853a7d6c887ce0c2323bcd80a.1743772053.git.maciej.wieczor-retman@intel.com>
From: Dave Hansen <dave.hansen@intel.com>
Content-Language: en-US
Autocrypt: addr=dave.hansen@intel.com; keydata=
 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
In-Reply-To: <012c84049b853d6853a7d6c887ce0c2323bcd80a.1743772053.git.maciej.wieczor-retman@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dave.hansen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=cS5RBcX8;       spf=pass
 (google.com: domain of dave.hansen@intel.com designates 198.175.65.18 as
 permitted sender) smtp.mailfrom=dave.hansen@intel.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On 4/4/25 06:14, Maciej Wieczor-Retman wrote:
> When a tag mismatch happens in inline software tag-based KASAN on x86 an
> int3 instruction is executed and needs proper handling.

Does this mean "inline software"? Or "inline" functions? I'm not quite
parsing that. I think it needs some more background.

> Call kasan_report() from the int3 handler and pass down the proper
> information from registers - RDI should contain the problematic address
> and RAX other metadata.
> 
> Also early return from the int3 selftest if inline KASAN is enabled
> since it will cause a kernel panic otherwise.
...
> diff --git a/arch/x86/kernel/alternative.c b/arch/x86/kernel/alternative.c
> index bf82c6f7d690..ba277a25b57f 100644
> --- a/arch/x86/kernel/alternative.c
> +++ b/arch/x86/kernel/alternative.c
> @@ -1979,6 +1979,9 @@ static noinline void __init int3_selftest(void)
>  	};
>  	unsigned int val = 0;
>  
> +	if (IS_ENABLED(CONFIG_KASAN_INLINE))
> +		return;

Comments, please. This is a total non sequitur otherwise.

>  	BUG_ON(register_die_notifier(&int3_exception_nb));
>  
>  	/*
> diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
> index 9f88b8a78e50..32c81fc2d439 100644
> --- a/arch/x86/kernel/traps.c
> +++ b/arch/x86/kernel/traps.c
...
> @@ -849,6 +850,51 @@ DEFINE_IDTENTRY_ERRORCODE(exc_general_protection)
>  	cond_local_irq_disable(regs);
>  }
>  
> +#ifdef CONFIG_KASAN_SW_TAGS
> +
> +#define KASAN_RAX_RECOVER	0x20
> +#define KASAN_RAX_WRITE	0x10
> +#define KASAN_RAX_SIZE_MASK	0x0f
> +#define KASAN_RAX_SIZE(rax)	(1 << ((rax) & KASAN_RAX_SIZE_MASK))

This ABI _looks_ like it was conjured out out of thin air. I assume it's
coming from the compiler. Any pointers to that ABI definition in or out
of the kernel would be appreciated.

> +static bool kasan_handler(struct pt_regs *regs)
> +{
> +	int metadata = regs->ax;
> +	u64 addr = regs->di;
> +	u64 pc = regs->ip;
> +	bool recover = metadata & KASAN_RAX_RECOVER;
> +	bool write = metadata & KASAN_RAX_WRITE;
> +	size_t size = KASAN_RAX_SIZE(metadata);

"metadata" is exactly the same length as "regs->ax", so it seems a
little silly. Also, please use vertical alignment as a tool to make code
more readable. Isn't this much more readable?

	bool recover = regs->ax & KASAN_RAX_RECOVER;
	bool write   = regs->ax & KASAN_RAX_WRITE;
	size_t size  = KASAN_RAX_SIZE(regs->ax);
	u64 addr     = regs->di;
	u64 pc       = regs->ip;

> +	if (!IS_ENABLED(CONFIG_KASAN_INLINE))
> +		return false;
> +
> +	if (user_mode(regs))
> +		return false;
> +
> +	kasan_report((void *)addr, size, write, pc);
> +
> +	/*
> +	 * The instrumentation allows to control whether we can proceed after
> +	 * a crash was detected. This is done by passing the -recover flag to
> +	 * the compiler. Disabling recovery allows to generate more compact
> +	 * code.
> +	 *
> +	 * Unfortunately disabling recovery doesn't work for the kernel right
> +	 * now. KASAN reporting is disabled in some contexts (for example when
> +	 * the allocator accesses slab object metadata; this is controlled by
> +	 * current->kasan_depth). All these accesses are detected by the tool,
> +	 * even though the reports for them are not printed.
> +	 *
> +	 * This is something that might be fixed at some point in the future.
> +	 */

Can we please find a way to do this that doesn't copy and paste a rather
verbose comment?

What if we passed 'recover' into kasan_report() and had it do the die()?

> +	if (!recover)
> +		die("Oops - KASAN", regs, 0);
> +	return true;
> +}
> +
> +#endif
> +
>  static bool do_int3(struct pt_regs *regs)
>  {
>  	int res;
> @@ -863,6 +909,12 @@ static bool do_int3(struct pt_regs *regs)
>  	if (kprobe_int3_handler(regs))
>  		return true;
>  #endif
> +
> +#ifdef CONFIG_KASAN_SW_TAGS
> +	if (kasan_handler(regs))
> +		return true;
> +#endif
I won't get _too_ grumbly about ti since there's another culprit right
above, but the "no #fidefs in .c files" rule still applies. The right
way to do this is with a stub kasan_handler() in a header with the
#ifdef in the header.

Actually, ditto on the kasan_handler() #ifdef. I suspect it can go away
too and be replaced with a IS_ENABLED(CONFIG_KASAN_SW_TAGS) check.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c797714b-4180-4439-8a02-3cfacd42dafe%40intel.com.
