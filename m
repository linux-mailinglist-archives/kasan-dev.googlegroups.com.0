Return-Path: <kasan-dev+bncBD22BAF5REGBBGUYYC7QMGQE5EDPFII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 139C5A7C1AC
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Apr 2025 18:43:08 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-4768f9fea35sf53336721cf.2
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Apr 2025 09:43:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1743784987; cv=pass;
        d=google.com; s=arc-20240605;
        b=LqQGKM0FLP6j/4aXML2G/GQbfUaUCZYzqEXWETqlWh4TVopNt/4ofYUzV5cjDNtHsC
         SRJG15yPZggGXOnacqCvxQVff8PYs3xSzxHL/UdrMLsgl5pWDQtEWTbzHItElgkK4Qfg
         h6+iOL3l7FmEgs6rkTVzUb/LX+jWOZwDGHgquaSpFQEwFx+TNB1frhIjUse9O+KqZ3NW
         PhlKWVdKY0waK/xXx2Un2QG0r47FyoUvTdE8m+2rg+VQ53wpfuiquVSe/95bAzDjAoqv
         MjYTgVxmDe0aN7FXQGdlCZkHy3zgt0ra93P3HDWNztVIBMISQ0DQj09RH+QCz/mHjQmA
         ucLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=gwGUdvh1tcg7jXBbnvdaIhGGdXtWY5s7//4bQA6t4B8=;
        fh=HCkaPazutZz+fuC3ORemzyXSDWMaEECPrl7w1zDE2JE=;
        b=ZBUjHECWHqc2vo3k37QyHrD3FZtww9WH5LakSqWYorzoWFlK8AaBmwwV2X6WxW7I+E
         15CR4jjG1i1zf9rgkaK4NkubiHZEEGKN0bG0nFTGliBbGZ0E7ztHMMdKWM4Iuj5oP2c+
         sEzTNJq1EVpZOhmTQQXw9qDLPUy7TtFTudWprq8FDae2JhJnSMkQnx2IeSbMs+gBx+4O
         jgIY0ripviG1rFT4de/oO0zWhSCWwbsFTq9kNy9HZjiZxRp99PxGBVru61xiC8RakEtP
         Hx+JnfKt2x3QLQjclGKjHw9l92Nhy8houToJ8yMUwWa1LRdPyEzWZarzSajBb8COQNOC
         aZwA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=fSlWoSJU;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 198.175.65.10 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1743784987; x=1744389787; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=gwGUdvh1tcg7jXBbnvdaIhGGdXtWY5s7//4bQA6t4B8=;
        b=P8PVIslpWoymckSmlvE7iltxT2fL6g/VwI3CtScZ7JLKFnIkFoE8+JVM60Eev3PSzp
         LqwLa3GE1+opqZpojlCeEPHgfkms0GIk97rbtvDX15ZP04FBpNVVHIbGYLaBNhQciMuT
         w5JLHGpY8dvOaMPFgzX451zrcn35UUKQHhbvm2sgiqcAEPL/oA0pt63iQZD+tj3RPJF5
         1rOdyiqtyjjUSEvhjIfDjlC+7b6jf5W5FBX1n51d0XVpNVjwdayO77IEvo1UvjCZgU6k
         1ATqt+ljD7+Mk5ioEydBfOAlY4IsLmgiTamvOX04bMOazDHFWMRsZyKIc/0LrXdw6fU/
         PVaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1743784987; x=1744389787;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=gwGUdvh1tcg7jXBbnvdaIhGGdXtWY5s7//4bQA6t4B8=;
        b=rAiOuwpcMZuVBFFlU95THf+7WFn8XcTee17g1u91mGjD8v+qOQKK5Npnzw6aR0nTu9
         CoquUUOpD+uzKyrL65nGskZcIfdVehHPLTZOcAv5Md5JdeQRiiFenEO1L2rglls9U/6D
         mwQlEXfWK0tViUhDhW1izSID8kMrrVCc1SH/UORpfGs2q8gumJFGOUmD/KKxRxvUUrxt
         7qTTEYv93osABJUiaPLbFehoZXIzAoXs3RsLMWYGCFmO+VIZ8vOBIIEmwQ1JMOqeT83y
         io4qOHsiL3gySLWSqxY3tg6zVlYOk6GcenMsB/54giRHXLGJoJxIAjDCenD5xdB4PTUH
         L+aQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV1KWpkryE3VuUQ8Px3wux6Hg549Ut6PJPMwVaF1KGFpJ6J1xuzBxLvYn0C+LjcD5Fmi0kfAA==@lfdr.de
X-Gm-Message-State: AOJu0Yz5/f29VhqaT2KS67ILntBQ2MOW0OOygdZJICUT6/ajfaKkYd4Y
	K9eS5WbJBnHXah1wJ1x4iAna1wcFuMSIzpW1F2pzit6oyUB4MUBk
X-Google-Smtp-Source: AGHT+IFfcdmPmXAeMlQcb+VT1/d9eIVOUnw+u2NtQ7YHFFTteSMoQHltHKXaa9sPIjIp+z/IykJ8GA==
X-Received: by 2002:ac8:7d8f:0:b0:476:8a83:9617 with SMTP id d75a77b69052e-47924936c1cmr60179671cf.21.1743784986575;
        Fri, 04 Apr 2025 09:43:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJkvxf1ROcB9vixojnq/7o/xyof+fYYdDcZOtSMnbV/nQ==
Received: by 2002:ac8:45d2:0:b0:477:7740:602b with SMTP id d75a77b69052e-4791639b121ls39955771cf.2.-pod-prod-06-us;
 Fri, 04 Apr 2025 09:43:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUv3xOSM/0X9IZFaX29aKjCP8/HzWoz0QQ5O9z4tnkJxoVRxEvSIziTsVbF7EOVA0Mxz0ngw24NRy4=@googlegroups.com
X-Received: by 2002:a05:620a:371e:b0:7c5:4463:29a8 with SMTP id af79cd13be357-7c774d277cemr496783685a.11.1743784985702;
        Fri, 04 Apr 2025 09:43:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1743784985; cv=none;
        d=google.com; s=arc-20240605;
        b=AvH8zQMmxqcK9+ZykA8vMHESq/EkXZb+T9JCtZXB737IOHn+NOshCoUgYCT01AZPLM
         MpBCjF+I8a5rvczaZ9S2+XEuv5O8nUyWJi4aEre6W+b4rTInY11PE8NOKYz1LF+ju2Sw
         r0DNEsbBAZ1YGsfCTXWjjqbc7grOPjXa48wFnam1Pl/zD152b8nGY/ndg705iaoM796i
         9io3b6Sdv7WvBp1N/kuJ7CbcykNTzPtR2527lL5rjlg7wFLXzq4kQjlL/SNKclD9v5hb
         fF122Q3ampDEhzbV4dogA2RTo5Aq5x6G9eW5ghk9xydr4Ne2rK4mpIigYBHXHojDb7i2
         U2fg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:content-language
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=OzojHud39nt00GD/h/ywEEk61yp2JqZv8ZDTN7g0ftA=;
        fh=qAclqxczifa7kqZeY+RB5PN2iG3DrlxE7ZoinyFrUhQ=;
        b=BEHSw8ZSuBMND0RjcK+1Hk+clEgHPExMip3+JxjEVfpBYQKVI3Y5sySOrgxMS5AcOX
         iFXAGlF8b94b2p+mgEayimU2BKGq0wFmxwG6z1XuA4TdScmVYli8hC9uXeBy0cnhU0co
         k8P0xdOiWYI2GC2yoNK1Ocgli5JmjLOsW/z+HF64Bb7DkKqWdLOqOugTEnkXl/EKRzbe
         RDq6hXm4/2/4XFg97+dDEDAisbR4D5dceGjklwqaUH+i6K5PNFFVh2AC0zIpj3HK8wY/
         9wdIDz5CZwFshlwUb6z9ciVFC6zHsIsjEQtaqR2dE4jrTJjZmnSps0ZdjCgxDQ7XlNUx
         Qv0w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=fSlWoSJU;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 198.175.65.10 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.10])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7c76e73d603si19552685a.1.2025.04.04.09.43.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 04 Apr 2025 09:43:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of dave.hansen@intel.com designates 198.175.65.10 as permitted sender) client-ip=198.175.65.10;
X-CSE-ConnectionGUID: GzehcGskS3CgKSV9kraTMA==
X-CSE-MsgGUID: LvE0UWe9TFSAkILRhx5MEw==
X-IronPort-AV: E=McAfee;i="6700,10204,11394"; a="62631324"
X-IronPort-AV: E=Sophos;i="6.15,188,1739865600"; 
   d="scan'208";a="62631324"
Received: from orviesa010.jf.intel.com ([10.64.159.150])
  by orvoesa102.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 09:43:04 -0700
X-CSE-ConnectionGUID: PNDCImh2SwmUq/OXMReN8A==
X-CSE-MsgGUID: 2z30JdBbQJeAh01BitZsnQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.15,188,1739865600"; 
   d="scan'208";a="127247176"
Received: from daliomra-mobl3.amr.corp.intel.com (HELO [10.124.223.29]) ([10.124.223.29])
  by orviesa010-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 09:42:57 -0700
Message-ID: <257b39a5-69bf-4e6d-844b-576e9c9d2e7d@intel.com>
Date: Fri, 4 Apr 2025 09:42:55 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 05/14] x86: Reset tag for virtual to physical address
 conversions
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
 <a8332a2dc5b21bd8533ea38da258c093fb9f2fe2.1743772053.git.maciej.wieczor-retman@intel.com>
From: Dave Hansen <dave.hansen@intel.com>
Content-Language: en-US
Autocrypt: addr=dave.hansen@intel.com; keydata=
 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
In-Reply-To: <a8332a2dc5b21bd8533ea38da258c093fb9f2fe2.1743772053.git.maciej.wieczor-retman@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dave.hansen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=fSlWoSJU;       spf=pass
 (google.com: domain of dave.hansen@intel.com designates 198.175.65.10 as
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
> +#ifdef CONFIG_KASAN_SW_TAGS
> +#define page_to_virt(x)	({									\
> +	__typeof__(x) __page = x;								\
> +	void *__addr = __va(page_to_pfn((__typeof__(x))__tag_reset(__page)) << PAGE_SHIFT);	\
> +	(void *)__tag_set((const void *)__addr, page_kasan_tag(__page));			\
> +})
> +#endif

Is this #ifdef needed?

I thought there were stub versions of all of those tag functions. So it
should be harmless to use this page_to_virt() implementation with or
without KASAN. Right?

I'm also confused by the implementation. This is one reason why I rather
dislike macros. Why does this act like the type of 'x' is variable?
Isn't it always a 'struct page *'? If so, then why all of the
__typeof__()'s?

Are struct page pointers _ever_ tagged? If they are, then doesn't
page_to_pfn() need to handle untagging as well? If they aren't, then
there's no reason to __tag_reset() in here.

What was the thinking behind this cast:

	(const void *)__addr

?

Are any of these casts _doing_ anything? I'm struggling to find anything
wrong with:

#define page_to_virt(x)	({													
	void *__addr = __va(page_to_pfn(__page) << PAGE_SHIFT);
	__tag_set(__addr, page_kasan_tag(x))
})

... which made me look back at:

	static inline const void *__tag_set(const void *addr, u8 tag)

from patch 3. I don't think the 'const' makes any sense on the return
value here. Surely the memory pointed at by a tagged pointer doesn't
need to be const. Why should the tag setting function be returning a
const pointer?

I can see why it would *take* a const pointer since it's not modifying
the memory, but I don't see why it is returning one.


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/257b39a5-69bf-4e6d-844b-576e9c9d2e7d%40intel.com.
