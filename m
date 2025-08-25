Return-Path: <kasan-dev+bncBD22BAF5REGBBZ5OWPCQMGQEXFI5GKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B647B34E20
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 23:36:41 +0200 (CEST)
Received: by mail-yb1-xb3c.google.com with SMTP id 3f1490d57ef6-e953a49de25sf3129564276.2
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 14:36:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756157800; cv=pass;
        d=google.com; s=arc-20240605;
        b=Gxw6odelrV1PTmA+7q2J93VKLQAE86LY34DYeEK+Ik3dxS0dD8Yh+dHfAC4n6jpTrj
         g3Ttu5SRVof9GjqnGMzwc4v5IeWvuHOSQ/0UIf0vDtOMZTKPBKFFASr4g4rtLmDJgWg8
         oU6jY/9FmJblAzclLg/YP0lqWbAVv6YL9574GopVJIgpPtpa8o1veLuWgMxzhWjX/LiU
         joxCmC3mEnJbjBiqHr4menN5pMlWjr6ARCMnznvlPamuIKOSsoonRp8A015zLkZs3EIW
         dCrWbZG2r/JSX/9YI5xSM6sM1LoaeqN/ly0BOYQLc05NxERjelEj1umkezsJn8tZX+nH
         crUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=82VFQ80ILrfjD+gHfwDOJhE9JJjx528/OJHMjMDgBjk=;
        fh=ylz/wAlHx+x/zQ1dMGGQA99exu/uiMxM55zQF5kp++8=;
        b=dfkxseuQz+z/lbdBnTbREYV/0N108AJKAcs28nyhb071ESweNr4Bdlte2ZJGCUNHQD
         rrZS5EDpZ1fV2XZJ8NJOX0sxyQan75bt27+0vrh9zLl0lvjMC/ROL7Ksq+P7/cL4eX6L
         2lQx9HT7hBi4KtsbXPmvs7cPTv7/ZpG80dOQEQ9eu3uxHjVEwDNbQtHBLTdOamo666+p
         oPgDv4ThGq4/an+3fa25f2jo/BhXXIkHlvxROt+UeCD4RgaNM1DRj+uiqCoRbpUWhNU1
         KaXzEjgykLDSYdnw1LYThlsg+QfKSbmUzSHGLmL7ojapkc/qTOr7XncMK7QkrzMBSYMp
         QMQw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=I4PYupYi;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.10 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756157800; x=1756762600; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=82VFQ80ILrfjD+gHfwDOJhE9JJjx528/OJHMjMDgBjk=;
        b=MIEKlztkU8UUgOYwaWM2REgfenIvOq5iPUb4vph2S6ArPOTSqfs7BcYaa/2Yr6eeZO
         p66Ov+3TkSkvLnuBZftyHbk9Zogwxx9iM9VBI7hZlzTkYoIWIAQGx0anSJKVQuK830YD
         JMGj9iphFp9Lge6VV+f+ib4jBjOwjZB3YvL6cJDVI4vL2eV9oCuysJBTN62npKElWNZn
         EgrvH9Z07ZcSoyAGg6Cg0qjRaARDDMGAP9tHaFXk0t3tBD//rKdhphR6VZ2UjuHLoT3J
         sOjji5CX//2LooAouIf2PM7SXYeWRj6zhR8AVQJnwsqresShOT1XA0KOSscVX2pPk51f
         eRGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756157800; x=1756762600;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=82VFQ80ILrfjD+gHfwDOJhE9JJjx528/OJHMjMDgBjk=;
        b=w7QFNQ4cB6HNTJWX3D0xZGBEyZs4lCbg4kgKpFyO/9ki9OzhGmifpvhdfMNkyzkAXk
         gAeXfybHxe+c3T+xmhcuGhhtuDNDRp0NEe13960iXe7GLy+vYv0v1hiTvPLO+f9pZOG2
         AkP/VNItcQ8ndcr8caFe/3Cq3n+q/LzQxAnk/eGO/lLndaDWzFLn31qe1YJWrwEjbo2p
         gCAiLk6Lt1KKbmveTawSUsru/1xWdtI3Dja8mnuKsb6Fgpo0bi9p0syBy3m6VYG7qPMH
         7n/pZ0zx9Lqz89hK2LQFaqYgbjBzRirj3MsRYoXKIZro5jp5rxYYdyXEboISGyyP381h
         HcpQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXo0MeTyg4vqNFKLLhO7PbOp9uIyPV4iWpZccPfpRlnRorlQYuJjEM8KmFLIkZbZCyL8OLlpA==@lfdr.de
X-Gm-Message-State: AOJu0Yz/8ui10BFhcTOwKARjcQFKHL06BPj6AMfOw/JgMixi12a1wz/k
	tHgerI2hcuRDZRzLTB0CLOv83qFRCLPV2lZgupy2jvy9GfnN6hq0k3fN
X-Google-Smtp-Source: AGHT+IHM4mm/so7C5ST6SuTI6VnoyEN5JwanY65GUpLunToN0vWva7Q2RcKNRWXKMR7PADh4gyaFaw==
X-Received: by 2002:a05:6902:70d:b0:e95:245e:47b3 with SMTP id 3f1490d57ef6-e95245e5663mr10913162276.9.1756157800067;
        Mon, 25 Aug 2025 14:36:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc4kJoCAbkiPDK6YWiYDTmMIfStx8rHA80NGMbKR4UvwQ==
Received: by 2002:a25:b215:0:b0:e93:468a:9d9a with SMTP id 3f1490d57ef6-e952c426a87ls2218168276.0.-pod-prod-02-us;
 Mon, 25 Aug 2025 14:36:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWUILtkLA/4rtX6d9sQYzQJ/SnkqdYahMAphliqHYvUP5n7VqEEhzLE35QBPFhOnQ+S+ugbjPtww9k=@googlegroups.com
X-Received: by 2002:a05:690c:9c0e:b0:71f:c5f0:339f with SMTP id 00721157ae682-71fdc2b77bbmr142895897b3.4.1756157799177;
        Mon, 25 Aug 2025 14:36:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756157799; cv=none;
        d=google.com; s=arc-20240605;
        b=MkQbajL9gUcD+fbXwy8hct8DpPdQfUlGyqmkKfOE7KFTeb+TkJ+eQfcLkGicL8I2Yj
         cPEbXNC9yCzk5P7aEPkHQ77KcjU56WSg/ZUzuQHrNYlWgLqkT1HyD0B92C8aDTaNK8Uw
         ZKfN8Dsra01PCgkos/F7ZZ0V/r2omGKK29xIq7sX/Eif24ZPW2f9nsHr1b7yGaLD66PI
         vXY/CSh8W7ghjnmp4V0I5WO+gXrHycO0K7jE/ZIHHB/1ASIvIvwNgyHcP+6qN3v03OCv
         Pqd5PqOxdMUe0KmjCTPXufV7BOpqD5JkV1IVoEuTcyt7i2xwpGkrEsUkgdmT85G/FiN5
         TatQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:content-language
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=RQ7UtJJtP138+Cx1GgszqhG1nv85BE+7ClwFkts6QSs=;
        fh=kXX7M19RObhgf3pcFw5x+L3s8rLFRcLDUOEzhQwzqlA=;
        b=DmR0NtdoJeCClugx1caQb261N0tT0qFeJKh6zli+iENdm/l1znWxWwVNsubsjVLeN0
         HiejM9maSj5pjob1RJr2+3fV4chlwdO5IC/a0LTS/Hc6gzDBIFm48poE0G8z7deYV4Ti
         XrltfYwRFB1nWa9nVSsK7zAXusyllac+Evd2R0ivcu6MiBk1/Jq+blhH9k4IQY+uctku
         Q+c6MQbB1GZenVFHp3jJney/jZMKfukI8/NmgSKTu48vRKBBgTtHJRq0LmVd6Mfr1iIA
         +OtlZgS7ADnq6nDYGrl88D3O95F54l1A7uuX1GebGlzAlmjttee+MvSYLWtynWeuRRwA
         M87A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=I4PYupYi;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.10 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.10])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-71ff184f3e9si3465217b3.2.2025.08.25.14.36.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 25 Aug 2025 14:36:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.10 as permitted sender) client-ip=192.198.163.10;
X-CSE-ConnectionGUID: DqOzojJAQWKq1cpWyxXLyg==
X-CSE-MsgGUID: JUEHVTAIQjmMyTCy/z1WkQ==
X-IronPort-AV: E=McAfee;i="6800,10657,11533"; a="69754684"
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="69754684"
Received: from orviesa003.jf.intel.com ([10.64.159.143])
  by fmvoesa104.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 14:36:37 -0700
X-CSE-ConnectionGUID: /uyCc6NjR9KW4BMqoy2VlQ==
X-CSE-MsgGUID: 9k1EwDU6QcGQHDVezqm8Xg==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="173575364"
Received: from gabaabhi-mobl2.amr.corp.intel.com (HELO [10.125.108.229]) ([10.125.108.229])
  by ORVIESA003-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 14:36:35 -0700
Message-ID: <c68330de-c076-45be-beac-147286f2b628@intel.com>
Date: Mon, 25 Aug 2025 14:36:35 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 10/19] x86: LAM compatible non-canonical definition
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>,
 sohil.mehta@intel.com, baohua@kernel.org, david@redhat.com,
 kbingham@kernel.org, weixugc@google.com, Liam.Howlett@oracle.com,
 alexandre.chartre@oracle.com, kas@kernel.org, mark.rutland@arm.com,
 trintaeoitogc@gmail.com, axelrasmussen@google.com, yuanchu@google.com,
 joey.gouly@arm.com, samitolvanen@google.com, joel.granados@kernel.org,
 graf@amazon.com, vincenzo.frascino@arm.com, kees@kernel.org,
 ardb@kernel.org, thiago.bauermann@linaro.org, glider@google.com,
 thuth@redhat.com, kuan-ying.lee@canonical.com, pasha.tatashin@soleen.com,
 nick.desaulniers+lkml@gmail.com, vbabka@suse.cz, kaleshsingh@google.com,
 justinstitt@google.com, catalin.marinas@arm.com,
 alexander.shishkin@linux.intel.com, samuel.holland@sifive.com,
 dave.hansen@linux.intel.com, corbet@lwn.net, xin@zytor.com,
 dvyukov@google.com, tglx@linutronix.de, scott@os.amperecomputing.com,
 jason.andryuk@amd.com, morbo@google.com, nathan@kernel.org,
 lorenzo.stoakes@oracle.com, mingo@redhat.com, brgerst@gmail.com,
 kristina.martsenko@arm.com, bigeasy@linutronix.de, luto@kernel.org,
 jgross@suse.com, jpoimboe@kernel.org, urezki@gmail.com, mhocko@suse.com,
 ada.coupriediaz@arm.com, hpa@zytor.com, leitao@debian.org,
 peterz@infradead.org, wangkefeng.wang@huawei.com, surenb@google.com,
 ziy@nvidia.com, smostafa@google.com, ryabinin.a.a@gmail.com,
 ubizjak@gmail.com, jbohac@suse.cz, broonie@kernel.org,
 akpm@linux-foundation.org, guoweikang.kernel@gmail.com, rppt@kernel.org,
 pcc@google.com, jan.kiszka@siemens.com, nicolas.schier@linux.dev,
 will@kernel.org, andreyknvl@gmail.com, jhubbard@nvidia.com, bp@alien8.de
Cc: x86@kernel.org, linux-doc@vger.kernel.org, linux-mm@kvack.org,
 llvm@lists.linux.dev, linux-kbuild@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 linux-arm-kernel@lists.infradead.org
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
 <c1902b7c161632681dac51bc04ab748853e616d0.1756151769.git.maciej.wieczor-retman@intel.com>
From: Dave Hansen <dave.hansen@intel.com>
Content-Language: en-US
Autocrypt: addr=dave.hansen@intel.com; keydata=
 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
In-Reply-To: <c1902b7c161632681dac51bc04ab748853e616d0.1756151769.git.maciej.wieczor-retman@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dave.hansen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=I4PYupYi;       spf=pass
 (google.com: domain of dave.hansen@intel.com designates 192.198.163.10 as
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

On 8/25/25 13:24, Maciej Wieczor-Retman wrote:
> +/*
> + * CONFIG_KASAN_SW_TAGS requires LAM which changes the canonicality checks.
> + */
> +#ifdef CONFIG_KASAN_SW_TAGS
> +static __always_inline u64 __canonical_address(u64 vaddr, u8 vaddr_bits)
> +{
> +	return (vaddr | BIT_ULL(63) | BIT_ULL(vaddr_bits - 1));
> +}
> +#else
>  static __always_inline u64 __canonical_address(u64 vaddr, u8 vaddr_bits)
>  {
>  	return ((s64)vaddr << (64 - vaddr_bits)) >> (64 - vaddr_bits);
>  }
> +#endif

This is the kind of thing that's bound to break. Could we distill it
down to something simpler, perhaps?

In the end, the canonical enforcement mask is the thing that's changing.
So perhaps it should be all common code except for the mask definition:

#ifdef CONFIG_KASAN_SW_TAGS
#define CANONICAL_MASK(vaddr_bits) (BIT_ULL(63) | BIT_ULL(vaddr_bits-1))
#else
#define CANONICAL_MASK(vaddr_bits) GENMASK_UL(63, vaddr_bits)
#endif

(modulo off-by-one bugs ;)

Then the canonical check itself becomes something like:

	unsigned long cmask = CANONICAL_MASK(vaddr_bits);
	return (vaddr & mask) == mask;

That, to me, is the most straightforward way to do it.

I don't see it addressed in the cover letter, but what happens when a
CONFIG_KASAN_SW_TAGS=y kernel is booted on non-LAM hardware?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c68330de-c076-45be-beac-147286f2b628%40intel.com.
