Return-Path: <kasan-dev+bncBD22BAF5REGBBI4HYC7QMGQEGQSW7JQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D3D1A7C142
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Apr 2025 18:07:01 +0200 (CEST)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-2c855402a6dsf1472960fac.3
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Apr 2025 09:07:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1743782820; cv=pass;
        d=google.com; s=arc-20240605;
        b=DlqWdu83FIb5Tc7/qWZoagerBcRFDLBGkW4lNhaYUDxcn7bPHsiUGy8WA4DDDIIDN7
         idSqTjL3y1Zds2Gb655DSsn+nv0gV0aOnECB2+9K4W7ME0zn++cSZJWADId/GbrgTWrf
         PfJ8aI33GU3dUDQJ7suL6mBglWUv7KoYGuOZHCOhGc7DpocyvCbnOf/EXCrnyDE/39e0
         /bVLt/dfDYYcHIBul21bblabVnD9nzpVv+Eqk8Kq50DxJB/q/WX7DS2ShwEmgQmmjJWr
         tY0wVoBGhRKkEj91VgGYreferrZWwd4jcAju42e+1ewwLucJeF8TSf+HHExmbM3O/I9a
         GjWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=1e1/y5Sl5Y4s7RdP4rl8UpXjr8WklEmqkQFsn17kGXk=;
        fh=uygVShtiDaCUKLaE5to/raTM3q4DTGNt67nKEFEz7nM=;
        b=Mbli4QF36fMZdISFbAEmVwAU/sW8+JOOrqUe6mPqsfbGx7G+/GXCwXbDLd2zz7YwsN
         QSpqPMkd1A94L6eh5k2Ht2A15SAxA7KpzrJs9A8mP/h8hRjfj8sQJssgbUQy7WQX8Chh
         fe/POMbp0XeTolb/8g/biuX0zM407GnNpz/rh2Cz576VGsqDuLEBmQ0eUdNsYXqn7/v7
         VdwHbTs+7XVyPGpR4EjKtYij9rUhJUt5FLqbUf2Tz5h49wwE8KTaqw06//8rkGLMN3ux
         SPYAX/aBukABGVzJQgwnXaEBcFx+kVwXnj7dqo04EKtXNsKbquWxkzSu3SYbE4bV60wh
         ly3w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=aaju+rqW;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 198.175.65.14 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1743782820; x=1744387620; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=1e1/y5Sl5Y4s7RdP4rl8UpXjr8WklEmqkQFsn17kGXk=;
        b=H1AXE4iuxKgJ9BzuCOK0rMTeRqUubC1KYg3Sk89h4+VMGL/cKjRQXBLWosNJ71in6J
         WtDO08T/M+aQnSPDuIM5vEqHdzBLO1TTDAgzd2EkorUxaq82utMgQ/BAxd/HIWf8ofvE
         UM9Oa8R++rDkH+DnItF41hkMmuaOHYLGGhHr9ORKs4jqb7WsHAoNY26qUn9rKZ3rWId/
         dJCM3GD8IjneQXxYNzu0Yc6Q/2vBICBdSmC/stVEl9G+Xa90LRDbbLQxIlGctHSfJUMI
         6y4TsfS0V9JPEfJhIuan4oTaexWdfcVqD86rdAxtbvDmR/qMEm9vGNlPY5xEzhs+VNc8
         urlQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1743782820; x=1744387620;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=1e1/y5Sl5Y4s7RdP4rl8UpXjr8WklEmqkQFsn17kGXk=;
        b=cuuxrmdHqJXqR7wIWA4ngyFAdBknYKZ3fiNLTm3h7u5FHpocHdJoEP6EMES28NGxgp
         Xm/reilnsgzxk6s+zHj4rNX217VhFNEpDWQIzyrWe4gacPvcqSX3PHqYjBJUGB86zQdt
         GjYQTCGU7Rww0XDky9jF3Kj8lKPOX8rBQfb4ZQ0ne4SdavmpBM7rrqf6j1ztQtQYz42O
         Re/12zAJDXjttUVA+bKdoE94BG83zZUbeq2LPulpHBLvPyAAdvANz7XyjkUsyh5WyFlD
         tYtO0m2TiaAcClw2B3Tj+Y/+b8aN37ajCLOIk2iP/0Ng0SEinHjIsmUmjZ1FWnepIQug
         AVrQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUMNxvwcdYXQlOubxj74lslMfG7adiqzvz1qHyqaVg1758YY1/5+i73XloC4ucWvJZmVR+oHg==@lfdr.de
X-Gm-Message-State: AOJu0YzJ2o41+J1eZHYkzwNaboqJRdtozwnk8pSiMWg3PNaT20du5AYo
	3sZdKHLtFWBeUnRytaMzbpE+wWvRPQVNdmtc7DFyVl72MJ3sa8jX
X-Google-Smtp-Source: AGHT+IFUlZ57YrWCWXRzwOwmDdri+DtCqAzSI82LA1LQyqd+1gmKgjXQSacbVQCK1kHXXGwFgWjs4w==
X-Received: by 2002:a05:6870:724f:b0:289:2126:6826 with SMTP id 586e51a60fabf-2cca1b60ac2mr2138896fac.30.1743782819859;
        Fri, 04 Apr 2025 09:06:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAKdoBOPf0P0Y1SK7JA4dDSkLyaok+5tbobR7dl9IMtOWA==
Received: by 2002:a05:6871:210e:b0:29f:aff3:65c8 with SMTP id
 586e51a60fabf-2cc7ab39c20ls867414fac.2.-pod-prod-08-us; Fri, 04 Apr 2025
 09:06:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWXfwhvWbM4cpcCYwuLPnmgKPSfP9gfKmxdToaTwr3wlppcQ1J0nzWIivToHAMhiwFxiSXQuqGoMqc=@googlegroups.com
X-Received: by 2002:a05:6870:5d87:b0:2bc:61b3:b0ec with SMTP id 586e51a60fabf-2cca191a7b0mr2141677fac.9.1743782818933;
        Fri, 04 Apr 2025 09:06:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1743782818; cv=none;
        d=google.com; s=arc-20240605;
        b=dUIqJE5YjkRuE1qi+ygUwIhjwB783Ew9O61Veejfp6DQESYfTL4Q8phXLjAVci/1fN
         tLhDGbbJuiVpXzK2kcRzLVYinLsAHq5MhgPsKO6kgDfAIBcPVHtty/s7MdejtnLXnkD4
         LamizaxAxlYBamSYAxHXAGP8L+10/F62TNK5kK3CVt8cOfqPQCsOai3urjECGd6eTkWr
         pIZCVz0VjKC+d1QVGw6rzSHijq0VPeQu4JgiMJKDOeo3alfcoHPMM8hLIVX99SHO8Dw3
         UgbPUr4nSKs4IsBv2PKkSx8YdKFNRqVShIV+zWGQH8QyYTkN6zn8i1wwiivf+/NiDoBW
         Fung==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:content-language
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=gZZdXY01HwinpOfDX0scOXOqRXZ1fOWsPF1WPbAPzUc=;
        fh=qAclqxczifa7kqZeY+RB5PN2iG3DrlxE7ZoinyFrUhQ=;
        b=lHmiRlQjkP4I+zdGXrxu7QWD4GMf4XEd8pVe+zvys4tGDfYm+c0O11HLBW+J9WnYA9
         CLYILlIvsDKm853uU6Ie0rDbLqMv3Qth57c4nNjlSE4BE8Om5lGgbDtZQou08MZY8B35
         2vumbL8kN28IWc2r9dozh2eem/MWYElBo3afSjxwyxw9Wbxyyrkoo0D4NA00urb5Kson
         tLaACrrW/bUOH7GVC2Qre5esMTMiQzUFrRVMGRldSHa3pvRJfhPU1z0ISVQ4EqzAA54A
         4YbOrPFDQMZi3rpn4DYVXNoSW0mwOBm9fRC2UeoPHrXqw6Cv5lb+tMCGC8f6gyaKyTE2
         2KxQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=aaju+rqW;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 198.175.65.14 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.14])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2cc84b34132si171247fac.3.2025.04.04.09.06.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 04 Apr 2025 09:06:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of dave.hansen@intel.com designates 198.175.65.14 as permitted sender) client-ip=198.175.65.14;
X-CSE-ConnectionGUID: KkwcVJgBSZqEKuf/N3oEqg==
X-CSE-MsgGUID: SOIr5zbKQy2/lyQJzctncA==
X-IronPort-AV: E=McAfee;i="6700,10204,11394"; a="49022873"
X-IronPort-AV: E=Sophos;i="6.15,188,1739865600"; 
   d="scan'208";a="49022873"
Received: from orviesa001.jf.intel.com ([10.64.159.141])
  by orvoesa106.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 09:06:57 -0700
X-CSE-ConnectionGUID: cO+Z9NzfR/u/1zgGGwdspw==
X-CSE-MsgGUID: 96Ikxg4US7+bKvi55n+CVw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.15,188,1739865600"; 
   d="scan'208";a="164554384"
Received: from daliomra-mobl3.amr.corp.intel.com (HELO [10.124.223.29]) ([10.124.223.29])
  by smtpauth.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 09:06:54 -0700
Message-ID: <3fd46452-fc96-4d50-9c40-a8a453d58f40@intel.com>
Date: Fri, 4 Apr 2025 09:06:51 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 03/14] x86: Add arch specific kasan functions
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
 <e06c7c0fdbad7044f150891d827393665c5742fd.1743772053.git.maciej.wieczor-retman@intel.com>
From: Dave Hansen <dave.hansen@intel.com>
Content-Language: en-US
Autocrypt: addr=dave.hansen@intel.com; keydata=
 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
In-Reply-To: <e06c7c0fdbad7044f150891d827393665c5742fd.1743772053.git.maciej.wieczor-retman@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dave.hansen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=aaju+rqW;       spf=pass
 (google.com: domain of dave.hansen@intel.com designates 198.175.65.14 as
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
> +static inline const void *__tag_set(const void *addr, u8 tag)
> +{
> +	u64 __addr = (u64)addr & ~__tag_shifted(KASAN_TAG_KERNEL);
> +	return (const void *)(__addr | __tag_shifted(tag));
> +}

This becomes a lot clearer to read if you separate out the casting from
the logical bit manipulation. For instance:

static inline const void *__tag_set(const void *__addr, u8 tag)
{
	u64 addr = (u64)__addr;

	addr &= ~__tag_shifted(KASAN_TAG_KERNEL);
	addr |= __tag_shifted(tag);

	return (const void *)addr;
}

Also, unless there's a good reason for it, you might as well limit the
places you need to use "__".

Now that we can read this, I think it's potentially buggy. If someone
went and changed:

#define KASAN_TAG_KERNEL	0xFF

to, say:

#define KASAN_TAG_KERNEL	0xAB

the '&' would miss clearing bits. It works fine in the arm64 implementation:

	u64 __addr = (u64)addr & ~__tag_shifted(0xff);

because they've hard-coded 0xff. I _think_ that's what you actually want
here. You don't want to mask out KASAN_TAG_KERNEL, you actually want to
mask out *ANYTHING* in those bits.

So the best thing is probably to define a KASAN_TAG_MASK that makes it
clear which are the tag bits.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3fd46452-fc96-4d50-9c40-a8a453d58f40%40intel.com.
