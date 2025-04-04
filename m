Return-Path: <kasan-dev+bncBD22BAF5REGBBDNAYC7QMGQEWOE3NAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 30051A7C1F5
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Apr 2025 18:59:59 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-3d453d367a0sf49940055ab.3
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Apr 2025 09:59:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1743785998; cv=pass;
        d=google.com; s=arc-20240605;
        b=dQ6Cp9febGTrSFcuh4qkU+hLZ5qyaPemZTck617iEnedMbxI6O0TZoM4L5yMSuQQ1W
         1d/+TXwxMGcjQ1dA4FjrP5u2HVAjyBIeFGN8xKbfElDIi4Fd1ycKz+A0oXEbODvJA/Yw
         5GRJZ1xzdbbNlec7Zr3PBD4jliLKzNcLS+o7lbGCxruwbxfYDOucnqdT0nI5HJUjwQw0
         08ZjI4JBMbAa7C20l9t98gC9smVXQMstIn+Nal50XfTGRbQl6Gw50f6VzDCmU5hh/JGb
         Wzf5pyfjyh8ARC/hWdqqcIhtpAtaZvS9UgV2NViDHDMjn/BA2z0dffxZsJXo7XHfBfnY
         3OSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=2kAF+yYK2gG1Ltgc2sFa6s5ZNn7X74Hg/oP0NunldUE=;
        fh=ad5TzhpOws+1tOwNnGQMQrsokFODlI96eVR45gjfe5s=;
        b=h3Adkg9dTPFMNkX9gt4SiKjWwR2La+prBrzS/PVT6HsxNhN5uKT6XU52KwAx7Oumdf
         AfUeu2ohStTSm8rYOr8np09qGBqSAst6HF1JYKDfYbwMKV2I0vqaYo3GIuHUUHMjGcCJ
         iLgPqYKVndnOntz9mK15kaEs+4+IkKez7AuMZ8yUaZumfqGiF/aoq3ksjzMuc5qcEZQO
         IF5v+vLLIPNeg1jK/QAq+Z6ZF/SWR7d495PrrzasVhvDo1YHK9fmpTb77kmB+//Z6eJV
         zaXZMoKfYpFRFGBZ3ucRJl4YeklPiW6RCK2kAyCVhHE5SYQMeU8x/Qb5oCMEx9633TZ6
         wifw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=cEHCzGjG;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 198.175.65.16 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1743785998; x=1744390798; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=2kAF+yYK2gG1Ltgc2sFa6s5ZNn7X74Hg/oP0NunldUE=;
        b=PI+LUSsAtIFh7/mzp1AL5IdbLCmPh1zZMtoPk5LpnOqExhpy6O4LrPQaFx8WmOsmGM
         zmQn5vvxjzb8wS613gvDMjj1Q/lJzf+ImYbxXVo6g28ObzXswEpPJbRhy9i/Fut+qfaa
         lXdo+slC8IUj1K2x2IKkJRA2jZdt2W/c+RukcYBORXvyhM3wOwwq+TpVC5OG5HbjKUX5
         kVQv10y7CCxaWbhGg/aBOCwbBi0J7Oxz4AAOI1LG1g8lf7bqv5zzFg/UimwAlkktJDvx
         88uivmX0Mv6AXDdnQAmiBldqYVlt+dlrKdh12ruRaj/cJCssPrsMoL2Mqbq4hMiJvK1u
         F5lA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1743785998; x=1744390798;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=2kAF+yYK2gG1Ltgc2sFa6s5ZNn7X74Hg/oP0NunldUE=;
        b=eW0E6yE7ErwfqzQTggfSyFM053g0TxPzc1r1Q07KT0pAqQpfdIrgGOETuCK+8YZ5/l
         ShEteFwQxcjFYTOVSH4gZcNwv6N/GaTffkwnRiBOCT7etHp1P8Pxm2FZNLWkgJTXcHRv
         QyzcMQ9IwZfjcPjuSZXysH1hG5kJI8ppZOTaPL7qqFD+RgS0qrUAWBYxqiXFmIYsimGt
         DTq6PgqxjZfFUDOz/A6yeRGhSpzXbzWn+1EoFEVRqO2/b41rDNmvyvtho7LICzZViTc0
         5m4WPSMY8PbrZS/wMzHDawxOpujLgBCU3vTTzWHg/IgTEwaJ8eGUdRWyIIBJ8kdSHkg5
         JpKA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXc56RoHun+wOOuyIjwXdkeAa3kylifyt8SuK6Ex2y5yzT3BfrkxgmvlAXv5slv6ug51C28CA==@lfdr.de
X-Gm-Message-State: AOJu0Yzk/a7FCkVU1ZuNrvu7PZmTOftYphZUEgbZFwgOwReJ9lYxG91c
	gC5J5mhtmM3tQs54+zwXMYoqVsWlYqGR01Xn6k+SaDQr1KiEatMm
X-Google-Smtp-Source: AGHT+IF+MDWnpuOM5wpNHi26XXinvsyLxkLKponhp4i8eVuqs7+n07ZbZNldnT7N4QmVk0FxWPWAxg==
X-Received: by 2002:a05:6e02:1686:b0:3d4:3d5d:cf7e with SMTP id e9e14a558f8ab-3d6e3f6589dmr44073735ab.16.1743785997975;
        Fri, 04 Apr 2025 09:59:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAIdBMM7QaxQWr0l1EKeiKwoY7EA77ESoBkAswFPwtVrMQ==
Received: by 2002:a05:6e02:1748:b0:3d2:ab3a:2d23 with SMTP id
 e9e14a558f8ab-3d6dc9ecb36ls31571055ab.2.-pod-prod-01-us; Fri, 04 Apr 2025
 09:59:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVaoOyIQs7TZVQppCMymtYk6fr2yNlXYp2ThRcsQ+jym+EELTs9N5e9oTuShgB9ZtNoeehS2zixrnU=@googlegroups.com
X-Received: by 2002:a05:6e02:1c2b:b0:3d0:239a:c46a with SMTP id e9e14a558f8ab-3d6e3f056admr43902585ab.9.1743785997095;
        Fri, 04 Apr 2025 09:59:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1743785997; cv=none;
        d=google.com; s=arc-20240605;
        b=fCeR16Lvo2cgcxrglXGrhFqMXJtAdL6CVY+LmlHetITihX4/soWEibX3WRDqi/CLGi
         sxKHSLIa7PvZymJp0rf1LjwzkzSr9V3YDOgcBtAjBRsCIyiJuvNecHvhJe33KCtu45NS
         /yQAK83Hz6WJTszLZ5XZ68KpEqeoi7p8gIMugbMi7QmHM2qLG7t9UMlTBkGnEWkU7UCa
         3Mja9RLJwoZzyl8GnAOzGNXpzE2pSBhGeX9r20GQm8ofUmdMf8FP+1kEuvlsg4SMPv0Z
         yrjzYQJmdYqSzPXT04ECwnayOF1zGlJxt26tsrMaKO1NDCAJOFjrzIgWkZckSvskQkwg
         Y9tw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:content-language
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=16EO5gHAYM3HfAoKbUWH4VAGtB0baKyya/lFzoHjEKQ=;
        fh=qAclqxczifa7kqZeY+RB5PN2iG3DrlxE7ZoinyFrUhQ=;
        b=kgnuCday2nYhjPBplusxWAHFpKrXyAlUPfgo+feYE92Y2k+WQBdC7fltMN4cW1sdyG
         yn/y0luKc8x0DMdaLu0IhU8a2GnfrqFms8ySOQU/IazBL9Xm8OvU11AYRsVtXdHrwoQX
         ustnuuYJeV3Cozijjl3Uns11ZpXl8QJbsz6JH1qNqGIh9057j9QxMAgJbA5tFCb/NL52
         by6/m/wGEu4b3lhFTttnnK2pJkJXWT8ygrEW+AaTiLUCIyNlCTHYHP6oAYbGvm1FYpm3
         F0+tuV8piYM6CA18yj7t5vwAF/uvT3pfVCF49resmrcatKSJlVRjVMilOPErLR2XLi79
         peyg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=cEHCzGjG;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 198.175.65.16 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.16])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3d6de98a040si2235495ab.5.2025.04.04.09.59.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 04 Apr 2025 09:59:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of dave.hansen@intel.com designates 198.175.65.16 as permitted sender) client-ip=198.175.65.16;
X-CSE-ConnectionGUID: Es+Q2YjnQkKOOC+14SLCQQ==
X-CSE-MsgGUID: dpi6cAj6SuOF4O0nKQLrGg==
X-IronPort-AV: E=McAfee;i="6700,10204,11394"; a="45323561"
X-IronPort-AV: E=Sophos;i="6.15,188,1739865600"; 
   d="scan'208";a="45323561"
Received: from orviesa007.jf.intel.com ([10.64.159.147])
  by orvoesa108.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 09:59:55 -0700
X-CSE-ConnectionGUID: nVEgby4lRBOEOo0i/NiK6Q==
X-CSE-MsgGUID: CnVOypTjRUKrXxLXzYnmog==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.15,188,1739865600"; 
   d="scan'208";a="127875646"
Received: from daliomra-mobl3.amr.corp.intel.com (HELO [10.124.223.29]) ([10.124.223.29])
  by orviesa007-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 09:59:51 -0700
Message-ID: <ceade208-c585-48e7-aafe-4599b1a06b81@intel.com>
Date: Fri, 4 Apr 2025 09:59:49 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 09/14] x86: Minimal SLAB alignment
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
 <173d99afea37321e76e9380b49bd5966be8db849.1743772053.git.maciej.wieczor-retman@intel.com>
From: Dave Hansen <dave.hansen@intel.com>
Content-Language: en-US
Autocrypt: addr=dave.hansen@intel.com; keydata=
 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
In-Reply-To: <173d99afea37321e76e9380b49bd5966be8db849.1743772053.git.maciej.wieczor-retman@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dave.hansen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=cEHCzGjG;       spf=pass
 (google.com: domain of dave.hansen@intel.com designates 198.175.65.16 as
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
> Adjust x86 minimal SLAB alignment to match KASAN granularity size. In
> tag-based mode the size changes to 16 bytes so the value needs to be 16.

I feel like we need a _bit_ of a discussion of the impact here. We are,
after all, trying to get this feature into shape so that it can be used
more widely outside of just debugging environments.

What's the impact of this in a production environment?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ceade208-c585-48e7-aafe-4599b1a06b81%40intel.com.
