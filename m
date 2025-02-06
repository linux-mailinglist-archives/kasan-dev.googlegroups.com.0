Return-Path: <kasan-dev+bncBD22BAF5REGBBDWZSS6QMGQENOHATPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 08FA7A2B449
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 22:41:37 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-43623bf2a83sf11013695e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2025 13:41:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738878096; cv=pass;
        d=google.com; s=arc-20240605;
        b=YQsuKe4ITYOsWhlc0IOjX1/c0quRqOnwUunCevMDGsj2sCdlW/o/UIsBGEa+LXr5PD
         0pskhfvV+QkcY2JNWEq0Ugo3e5vTxuGSPp4TwTZRxIubt0KuEPlLCPiDDx6LQhETT5xs
         jBdaC5NWK40EUgwpetGoxFFWdjQQ/xlacjIbT5IPm9+fBtXruopW1LkgDcAHavQvq3no
         UORw40ZVjMowTt7o5ZKArVzRTGUpa/FGwv3z0E5fGiK7Wu/zUZsmY0dsGvOp9mM+NWvY
         cdFv4BnHuZMq3IjqDoOH7gA+6JXZ+J5EQT+AK9SPswbwtfBsAiOzjPb66bTCw1LpUbtC
         XSQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=gDKbPTOsfakQMWhJSE8oRbmbi4fnFJgffj5hd7csxXg=;
        fh=TuPCve1rEaD8vmdlpkdWmM+k2keRSXjhvWox5d2wLxM=;
        b=ifDt2WdFY7H7/z+fQOzbLsvn1YNOVSCUUic6DfJ7EN9usN3G0Btrdy9JmmyJA816u8
         qDMv4Y25WggIWBKJ6eSBiwLcZdPJjkiHU9kui0CjXRBRIRqz3EzejAJp1h3juHtsqrkI
         R8Km20159Iee8spFPtS2t/jOazAnD7ZBwEt6svx2QoG7SLzhzNk2yr6ehpEqa3uRN+D0
         x4oXt9k2BkN5SDX1rjetA4ZydrPsN2qxq8IdbDU4M2JyUrc/pRfUH+tOcCeiQjjjzQ0s
         N4+cxVuBff7vZpQzje657UKbHUeAQY1LAIP5Qx+4ZgjEMUJVrETijIhr9P3PI6fuhGnq
         55PA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=H+sGcSUs;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.13 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738878096; x=1739482896; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=gDKbPTOsfakQMWhJSE8oRbmbi4fnFJgffj5hd7csxXg=;
        b=ZiUVpvtY2Ibo1gjtxJ3/coQsE2QKRkxXvkg7t4AiNQj9tv7YAFtesQwQeBfjUvQRo3
         N3kfsOpv17CFdOL9AncjMoOKLSpK/bGLnlfs/Q09Hi6T9706gGrSDF0yCsNuOxb/1+0e
         yYXIKZdCWguH88AZTFkKv5qVEF1tBCRGkHt3u25jGnz0MPFXqmcJMou5b9Hy3DLpQt2R
         oRLkfYlYlTf+8pkt2Tf56TsVpVbL2sgGDh91BBfzn9dUElhrr0bseGbzPZdDJQ4I6S28
         3NFfca8p+0T7Ujs2IpIemDB7x1B//uh0ZBlfuv6SRg/eTB2ELcefZbmykQMPUWcLvGmH
         vcNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738878096; x=1739482896;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=gDKbPTOsfakQMWhJSE8oRbmbi4fnFJgffj5hd7csxXg=;
        b=lxH7X/EepD0ohOaDxJaJK2+XJK2ZdlxA4dfkxoC2ZiCPLkimOi7cOQWGKobIA120Ot
         /tP6RKgZXtMsgxkQveRtbxNx1fKeFis8U/JBF74wyRX/eWGbfhm1sRsfex4Z8+LTx5+K
         1EYSw+kkIdtzroEv/KBrOUchGJH1SNelaL4LDVIIp293uqzAaF4hMKIWv+dlVof34Ds8
         ZbZv3x7amf/qJokrO7gF3W5CUi15udFRJlhip+XJeHYQEFRTIjeBOTZ3p4K81Wz9fb4T
         sMmQjJ27R5/WFahcy/ReTVR2lMK5yLjDjZkGaqkkN77IdWIOKNNvoJm50+KqQx6ldoiG
         XKdA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUnPfcIBsqXB7UpVOaYw6y+uBtQDl1tV5zQmY+wp+pyGakTkBqG2pbXS6u2E6VgmJ6NAPxPAQ==@lfdr.de
X-Gm-Message-State: AOJu0Yw16VfMdF+F/eNvFRiwgniwYo1EXK5ePktx6MaI3D1Lla+7mcfR
	W7pStmwdRrLmxubPNyOJLQRqXEn0ZO8sYiwEdgKenLSb9Y63nB0K
X-Google-Smtp-Source: AGHT+IGFcBXQ1MGu6weRElRteD+DADAyDR6bBPfkcBPsq5VStgum1miW3iKUwSyjwnkrpKVoIgzWog==
X-Received: by 2002:a05:600c:4e09:b0:434:f623:a004 with SMTP id 5b1f17b1804b1-43924993304mr10094505e9.16.1738878095020;
        Thu, 06 Feb 2025 13:41:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:b51:b0:436:5d0c:e9c6 with SMTP id
 5b1f17b1804b1-43924c40136ls969685e9.0.-pod-prod-02-eu; Thu, 06 Feb 2025
 13:41:33 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWY6theoCpuIqCR/2wba7jJMv7L4NrhrRiY7nwqRtv9+EfoV2FDr4YN2IbFvtiLqZhRErG7fWTrr+8=@googlegroups.com
X-Received: by 2002:a05:600c:4e09:b0:434:f623:a004 with SMTP id 5b1f17b1804b1-43924993304mr10093775e9.16.1738878092682;
        Thu, 06 Feb 2025 13:41:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738878092; cv=none;
        d=google.com; s=arc-20240605;
        b=E6Rm/9laFSRu5glicil0Qj+WnapC8eOW4frggIw2h1lGzNCGDteHP/ylSMIInidnYW
         dfGGJKkEzbAY5HiHaWlICx58srkhzi5VCdF1wFpSHJh3YfdBQMGJmTPdLzDF72+l5E+t
         gle2GGr3fbHvfNU2a6EHm7GqQK/5+36T42UL2ofNqrroWReAnTz8lub3VWDDrHSIwEem
         0O+Jw4rOprj0i6GhSF0AXB9lt1byU2MywEI0aoSIusC11NOQd1ZQIXGwRSQfolyli1bn
         rjRCbJuYI/759dmq+iTphpx35h8UkGRhuKhnOFq7UCHJRASr2qIocAywUJb5RoIumJLi
         dT8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:content-language
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=NeDnFLaKGvuySzyK3meW59DOx+khnPVBrD4h1MU9GXs=;
        fh=8nnuGwI06vUJm+K8HVPP05emxDSk026qbbKZ/yoL0yw=;
        b=Zk3QM1fT5KvUTiCSSvXn0VFVURcTMFUHDa+sNqUK8SpkI0ImmSyFhz+0v6v8pbU8h7
         eqtiTKl8OAFCU+6ordYrGNPW0UmtY9Ph1LKasPJLHnil/68bWJV7JV0kdAxKvKobl9Pg
         /IDHv4yr49JmxfZ+9x2dXeuFHOkyr1EgbCH77hBzyGsUShAPYDxSEiDI8zrLykbpGa8p
         2JitGsRMx+Ob9Zi+lc8HDK6yO02rZu0davYzNQXnei7mlz1LIhz9ICmezXHNo7dKCvan
         zlhkIxHnWXVrtL8JgTGF3eVVvBsLoAxuiwiY7gXlOLhhF/BuOVjeToTckGfbp5Tqm2Z0
         3TDg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=H+sGcSUs;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.13 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.13])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4390692a173si5916575e9.0.2025.02.06.13.41.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 06 Feb 2025 13:41:32 -0800 (PST)
Received-SPF: pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.13 as permitted sender) client-ip=192.198.163.13;
X-CSE-ConnectionGUID: vvFyagQRTZGbi8JiT88stg==
X-CSE-MsgGUID: tgIBfPbjS0CJbRDNCgsl0Q==
X-IronPort-AV: E=McAfee;i="6700,10204,11336"; a="42345037"
X-IronPort-AV: E=Sophos;i="6.13,265,1732608000"; 
   d="scan'208";a="42345037"
Received: from orviesa005.jf.intel.com ([10.64.159.145])
  by fmvoesa107.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 06 Feb 2025 13:41:28 -0800
X-CSE-ConnectionGUID: 6H771ns0SpuSxG9hNzP1oQ==
X-CSE-MsgGUID: Z+csMKT7SBO/Wvx19isNiQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.12,224,1728975600"; 
   d="scan'208";a="116528569"
Received: from dnelso2-mobl.amr.corp.intel.com (HELO [10.125.111.17]) ([10.125.111.17])
  by orviesa005-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 06 Feb 2025 13:41:27 -0800
Message-ID: <239de2b9-0787-4105-a481-418dbd4d861e@intel.com>
Date: Thu, 6 Feb 2025 13:41:29 -0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 00/15] kasan: x86: arm64: risc-v: KASAN tag-based mode for
 x86
To: "Christoph Lameter (Ampere)" <cl@gentwo.org>,
 Jessica Clarke <jrtc27@jrtc27.com>
Cc: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, luto@kernel.org,
 xin@zytor.com, kirill.shutemov@linux.intel.com, palmer@dabbelt.com,
 tj@kernel.org, andreyknvl@gmail.com, brgerst@gmail.com, ardb@kernel.org,
 dave.hansen@linux.intel.com, jgross@suse.com, will@kernel.org,
 akpm@linux-foundation.org, arnd@arndb.de, corbet@lwn.net,
 dvyukov@google.com, richard.weiyang@gmail.com, ytcoode@gmail.com,
 tglx@linutronix.de, hpa@zytor.com, seanjc@google.com,
 paul.walmsley@sifive.com, aou@eecs.berkeley.edu, justinstitt@google.com,
 jason.andryuk@amd.com, glider@google.com, ubizjak@gmail.com,
 jannh@google.com, bhe@redhat.com, vincenzo.frascino@arm.com,
 rafael.j.wysocki@intel.com, ndesaulniers@google.com, mingo@redhat.com,
 catalin.marinas@arm.com, junichi.nomura@nec.com, nathan@kernel.org,
 ryabinin.a.a@gmail.com, dennis@kernel.org, bp@alien8.de,
 kevinloughlin@google.com, morbo@google.com, dan.j.williams@intel.com,
 julian.stecklina@cyberus-technology.de, peterz@infradead.org,
 kees@kernel.org, kasan-dev@googlegroups.com, x86@kernel.org,
 linux-arm-kernel@lists.infradead.org, linux-riscv@lists.infradead.org,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev,
 linux-doc@vger.kernel.org, "Shutemov, Kirill" <kirill.shutemov@intel.com>
References: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
 <8bd9c793-aac6-a330-ea8f-3bde0230a20b@gentwo.org>
 <F974BA79-80D8-4414-9DFD-1EEF9395143C@jrtc27.com>
 <72837fcd-97a8-c213-0098-c8f308c3415d@gentwo.org>
 <29A74A26-E922-4A4F-9B4A-8DB0336B99DF@jrtc27.com>
 <94f81328-a135-b99b-7f73-43fb77bd7292@gentwo.org>
From: Dave Hansen <dave.hansen@intel.com>
Content-Language: en-US
Autocrypt: addr=dave.hansen@intel.com; keydata=
 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
In-Reply-To: <94f81328-a135-b99b-7f73-43fb77bd7292@gentwo.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dave.hansen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=H+sGcSUs;       spf=pass
 (google.com: domain of dave.hansen@intel.com designates 192.198.163.13 as
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

On 2/6/25 11:11, Christoph Lameter (Ampere) wrote:
> I also see that KASAN_HW_TAGS exist but this means that the tags can only
> be used with CONFIG_KASAN which is a kernel configuration for debug
> purposes.
> 
> What we are interested in is a *production* implementation with minimal
> software overhead that will be the default on ARM64 if the appropriate
> hardware is detected. 

Ahh, interesting. I'd assumed that once folks had in-hardware tag checks
that they'd just turn on CONFIG_KASAN and be happy.  Guess not!

> That in turn will hopefully allow other software instrumentation
> that is currently used to keep small objects secure and in turn
> creates overhead.
OK, so KASAN as-is is too broad. Are you saying that the kernel
_currently_ have "software instrumentation" like SLAB
redzoning/poisoning and you'd like to see MTE used to replace those?

Are you just interested in small objects?  What counts as small?  I
assume it's anything roughly <PAGE_SIZE.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/239de2b9-0787-4105-a481-418dbd4d861e%40intel.com.
