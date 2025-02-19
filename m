Return-Path: <kasan-dev+bncBDW2JDUY5AORBV6S3G6QMGQEG7OKAUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 30E6FA3CD80
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Feb 2025 00:29:30 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id ffacd0b85a97d-38f2ef5f0dbsf115443f8f.2
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Feb 2025 15:29:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740007769; cv=pass;
        d=google.com; s=arc-20240605;
        b=HHukd2quJXAElDdGm69mNprH+Y5YzDTckEHUf0CbnUVZx7qXKWU5yvE/kMIaUeSO0W
         xS1kredLxDs+tz84K3XbnQNrlYqpobg2TWiKgipQ98WbG3nj4DMKmnDDfdycXn9U8enw
         G93lk76YqTlvR7XhC6Ps+ZWTtCos+Ziez+kCS9it827x/0B1edh9/6CPfjB0ARinJI2o
         nNTyQhkv1u5apHhzHfO7zvdwycViv1MObMho/rVbYC6+btN70HHVxVSk1SFUtu+gx0pe
         iHt+RWIP39JV+iPIJaDVfj686o5v90adqNObtpcWJcIUfR7JXiCrziaHZMMlkGnWZxyv
         iuwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=D80CMkKfHAm6Wv/HNrcs6r+FGC2ucqPI7F//yt7i7EI=;
        fh=ZUGn6SWGwilxbF/JfpY22x5L6octtGZhribsMng524Y=;
        b=jzPzRCnYqKCDaWpgrU26S//Pwi+5DBq/gb1401pM5rOUz4VRkVhubWCojLNJX76czH
         /MiI8VgA6XahQpMZ9EACSwHUlvwer1F6nhNqM/ufqN5zrthRS66//FuZiD8q6lK9r0ha
         T+xx8I1D5ZvmF3VKOOqAcb9p0kHMBg1kMYzixhH9UiF2j05ioFhvNm2ZLEEVqTaISVL9
         KP7lGi+4F7xlMOBDifqLAq3wNmjrPZgIsyRiaPPQBaJ2Z6qqOMysfVKIDo/crgYUpfeE
         dninwgJVsGCNq2+9QdzDfWKHO7p01UEiVD/sj/ypc+hRY0CmJbiQ1qal6al3plO5xbsy
         naaw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HJBFPP78;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740007769; x=1740612569; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=D80CMkKfHAm6Wv/HNrcs6r+FGC2ucqPI7F//yt7i7EI=;
        b=myDFHEJV6GzkXiwkhhROoxSHkuCA28M9s6uiPCb2jX8Gfbm6h1oneP8Vid2dmabaqS
         10TLqH4thPCo0ldgj7rFVPvMnZU8S5S6gwmiEVc4tjofXwfK8k4A4z24rt4+JNwvMNu6
         KuFp4i/9Cs9pthStkdI0EYwIKsrcrsBoprKs3ZM6PuqY4EULAgsMjuXRr5UAsidHMST0
         hNpnVENfu7GOg5a5X9rlwUlljszBZEHKfDBZByZt5wDNKT8kocvIUxP1C8s6IpJ2p08z
         fqMydmq5zzh5niTLf0g/afvHY+dP6cBBCU7k2UcXclYOmwsERpI0CjBZMMvW9TMsjUjJ
         1UMw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1740007769; x=1740612569; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=D80CMkKfHAm6Wv/HNrcs6r+FGC2ucqPI7F//yt7i7EI=;
        b=YfxWTBQXvaUkbga9qlKvAJjbIebQxeZpJCk8qlWX7OK0V9O0CuLPXhH6qYsL4jCVVZ
         SvlmXjyk3aLoF3KzGE4HEwAVRWaujdD4iaWD0/Xn5WTIj7i1vwkHiTtJ6u4PDnZTqdZu
         oUzBgrM/o3ykcZnOpUQJZbnYwkYi0VRWuZaX0ADsFqC9SA3LpuZ0M6qMJla38wJYpVPw
         AuTzrlYEyf30kL/2kFWyIqTEMANHlKtvdPwYs+XHAVwf9CbyIB7H8XuAovQ+Ze8xrsh4
         R/dwmotGbe7BpAxLbu96mzQ4LG3YGz5KKiDCgYZDdDcX8+BkrYi+OuH1rs0Dd/ziIByq
         B7ZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740007769; x=1740612569;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=D80CMkKfHAm6Wv/HNrcs6r+FGC2ucqPI7F//yt7i7EI=;
        b=JH2J8uEUNkirdAtbm23hLHMhy0GEmcDgXaUl5R2tLKiOTgUCOOACaES/VcNGzJBwu+
         xJXjF8O7YvIK50lhIyw95kdbQoUwmDGBdIK6UpBmA/T43lnlgrKEMWKqAS/jHCcJY+ot
         DIA+qtobJWJheyTxGYDzSlItKWBG/Pac0piL7R+Ycb3vkdomJJkQWqmnVNdAOSRrZzNs
         A0/Df7X2kuq5MKhy2XmbnSBr1Tm6G9CcXG48AHZdmAs0k6520ktL397GWeiuPIfL5B1y
         Ma93RTs5BsiShnS7CLdPkUVPNkZBqhpHelTYgjgDPgZZshy/I5F4R8aKQGdAY7mX2btU
         bJMw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVhyX46kCQFQPZHRz+gM3NH9HcPLCHebS+ggtHip7/UO17YAw20LEI1u5Y0lPwZQmiHNF4HPg==@lfdr.de
X-Gm-Message-State: AOJu0YwyZbBXgsbhM3DFQjTaXa49HqCcB3WGjtNnw0YXLExdgnU5wXc5
	JbtbsOvIpoYwSba0HObtVSdh4Pdw8dfZVNcvikYtug1vBWqiKcdB
X-Google-Smtp-Source: AGHT+IFfY3QUXgES4s/qS4O04/ryJjBdHyCN2SVorsitYaIT3w7N5uOo5iALG/t97JxToMjkAxfK7Q==
X-Received: by 2002:a5d:6d06:0:b0:38f:4cdc:5d36 with SMTP id ffacd0b85a97d-38f4cdc605bmr12471560f8f.43.1740007768051;
        Wed, 19 Feb 2025 15:29:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHPZOMToK4i6d6meavh1VrrAXgpx7Ufy9EQjG+TxLGQ6Q==
Received: by 2002:a5d:5f88:0:b0:38f:21ce:c3c8 with SMTP id ffacd0b85a97d-38f6148e7e0ls151074f8f.2.-pod-prod-06-eu;
 Wed, 19 Feb 2025 15:29:26 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW3akJyVU0QY9TtmKgBVA9j7uVzI9nCCiNomTFnLK8cCMI/LLrL1ABaG5MqcQb17GepAMCotOLWF9k=@googlegroups.com
X-Received: by 2002:a05:6000:402a:b0:38d:e48b:1766 with SMTP id ffacd0b85a97d-38f33f118c8mr17522646f8f.6.1740007765873;
        Wed, 19 Feb 2025 15:29:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740007765; cv=none;
        d=google.com; s=arc-20240605;
        b=GuPWZSRQ9oH9o9h82I8jHVqLRjKWyVprfgu8FWRQ0c/xey718dx+W3v1hy1GRDSwq/
         XDV0Y5+OvactIgscD9Y98cyP98Ghfzc134bSAPVIa+ew82XRx5iYNcUX6gYGt+JawE/n
         iydBe4umTLW56kZ/NAV7MLBSyosPjmcvb1Hax1ITI4WBmOdgDVC6o2FZKRWcn/oSG4R9
         TMw8xbgMfDMjchnRjtmj/UbIrt7iydxnSzKbz2UhDOife2zACcHkdEontSV8FXEmbBn4
         gZLg0rQxK4Zt21oA3ooMj11tw9GDSz+zQ4LuolH1vHMX7P2nV+XcWU54UgpiqEulYMY/
         xc+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=u+Z72BjPvgymywo1G2IEaCTWsaSUq22tibKSRVUM8fs=;
        fh=L4IzSXUO588syKOxFEItOWiYrkeplzy//ShrSgTYyQQ=;
        b=TLfcpa4+YSuoo1qwwYixdt29Hb/+7NmeB8CppUV5B2F32TAP6q4PjNOhVhoYr0GcUi
         LGz9FJBfBLr7UQBG24K0/YcODtmYvbGZ97HHEmRUJl4789FClyxYIJhkLz7uAkCqOxWg
         ANDk9F4Zbuxm8nV9OO+Gf0/qQDOY0owy9e/EOuQIsOMsTZDFWvTALcU04479q70th1uf
         fkos3auyAICDxXyMQaCldAYybKlEuKqcmp5lh6fp26TqIVIKD5+mrkNU+xexpmM8XTaq
         7mufQYkoaRM6C4Y6TMR2j+H3sfkRMkd03vyoKpLyEYIPwRtv+xEv7oAz07DDvil82JBz
         a7zQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HJBFPP78;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x430.google.com (mail-wr1-x430.google.com. [2a00:1450:4864:20::430])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-38f2589a0e6si466028f8f.1.2025.02.19.15.29.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Feb 2025 15:29:25 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) client-ip=2a00:1450:4864:20::430;
Received: by mail-wr1-x430.google.com with SMTP id ffacd0b85a97d-38f3ac22948so173134f8f.0
        for <kasan-dev@googlegroups.com>; Wed, 19 Feb 2025 15:29:25 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWDs9QMrQy/GzF5Uj80gZD8BE+yfBg4iyRqh0wSRxZ4jHCFQoRbrYw8vXQRN6SVZn0PWon4Qg2as+I=@googlegroups.com
X-Gm-Gg: ASbGncuEBRJLUxfjJzGZdpyZyGWkiSQkNBgkjRBdxkMq7g6SeVk1lPt0/vfqbpEin3s
	CK+3ERN4U0qsl8APKsFoUnVBAPOSudkifm9CDn5+VDfz/lz1jveMFEVtPeTN23r5CsUbBM4v25g
	4=
X-Received: by 2002:a05:6000:1541:b0:38f:3b9b:6f91 with SMTP id
 ffacd0b85a97d-38f3b9b7389mr13650940f8f.12.1740007764962; Wed, 19 Feb 2025
 15:29:24 -0800 (PST)
MIME-Version: 1.0
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com> <168f775c4587f3a1338271390204a9fe16b150dd.1739866028.git.maciej.wieczor-retman@intel.com>
In-Reply-To: <168f775c4587f3a1338271390204a9fe16b150dd.1739866028.git.maciej.wieczor-retman@intel.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 20 Feb 2025 00:29:14 +0100
X-Gm-Features: AWEUYZki4d9AxVn53RP0a8dYXmP1qdo-p1R_9kMFX3Z6ke5F2uBlC11QXpcsGtE
Message-ID: <CA+fCnZcVSwUAC9_xtVAHvO6+RWDzt6wOzWN623m=dT-3G=NnTQ@mail.gmail.com>
Subject: Re: [PATCH v2 01/14] kasan: sw_tags: Use arithmetic shift for shadow computation
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: kees@kernel.org, julian.stecklina@cyberus-technology.de, 
	kevinloughlin@google.com, peterz@infradead.org, tglx@linutronix.de, 
	justinstitt@google.com, catalin.marinas@arm.com, wangkefeng.wang@huawei.com, 
	bhe@redhat.com, ryabinin.a.a@gmail.com, kirill.shutemov@linux.intel.com, 
	will@kernel.org, ardb@kernel.org, jason.andryuk@amd.com, 
	dave.hansen@linux.intel.com, pasha.tatashin@soleen.com, 
	ndesaulniers@google.com, guoweikang.kernel@gmail.com, dwmw@amazon.co.uk, 
	mark.rutland@arm.com, broonie@kernel.org, apopple@nvidia.com, bp@alien8.de, 
	rppt@kernel.org, kaleshsingh@google.com, richard.weiyang@gmail.com, 
	luto@kernel.org, glider@google.com, pankaj.gupta@amd.com, 
	pawan.kumar.gupta@linux.intel.com, kuan-ying.lee@canonical.com, 
	tony.luck@intel.com, tj@kernel.org, jgross@suse.com, dvyukov@google.com, 
	baohua@kernel.org, samuel.holland@sifive.com, dennis@kernel.org, 
	akpm@linux-foundation.org, thomas.weissschuh@linutronix.de, surenb@google.com, 
	kbingham@kernel.org, ankita@nvidia.com, nathan@kernel.org, ziy@nvidia.com, 
	xin@zytor.com, rafael.j.wysocki@intel.com, andriy.shevchenko@linux.intel.com, 
	cl@linux.com, jhubbard@nvidia.com, hpa@zytor.com, 
	scott@os.amperecomputing.com, david@redhat.com, jan.kiszka@siemens.com, 
	vincenzo.frascino@arm.com, corbet@lwn.net, maz@kernel.org, mingo@redhat.com, 
	arnd@arndb.de, ytcoode@gmail.com, xur@google.com, morbo@google.com, 
	thiago.bauermann@linaro.org, linux-doc@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, linux-mm@kvack.org, 
	linux-arm-kernel@lists.infradead.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=HJBFPP78;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Tue, Feb 18, 2025 at 9:16=E2=80=AFAM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> From: Samuel Holland <samuel.holland@sifive.com>
>
> Currently, kasan_mem_to_shadow() uses a logical right shift, which turns
> canonical kernel addresses into non-canonical addresses by clearing the
> high KASAN_SHADOW_SCALE_SHIFT bits. The value of KASAN_SHADOW_OFFSET is
> then chosen so that the addition results in a canonical address for the
> shadow memory.
>
> For KASAN_GENERIC, this shift/add combination is ABI with the compiler,
> because KASAN_SHADOW_OFFSET is used in compiler-generated inline tag
> checks[1], which must only attempt to dereference canonical addresses.
>
> However, for KASAN_SW_TAGS we have some freedom to change the algorithm
> without breaking the ABI. Because TBI is enabled for kernel addresses,
> the top bits of shadow memory addresses computed during tag checks are
> irrelevant, and so likewise are the top bits of KASAN_SHADOW_OFFSET.
> This is demonstrated by the fact that LLVM uses a logical right shift
> in the tag check fast path[2] but a sbfx (signed bitfield extract)
> instruction in the slow path[3] without causing any issues.
>
> Using an arithmetic shift in kasan_mem_to_shadow() provides a number of
> benefits:
>
> 1) The memory layout is easier to understand. KASAN_SHADOW_OFFSET
> becomes a canonical memory address, and the shifted pointer becomes a
> negative offset, so KASAN_SHADOW_OFFSET =3D=3D KASAN_SHADOW_END regardles=
s
> of the shift amount or the size of the virtual address space.
>
> 2) KASAN_SHADOW_OFFSET becomes a simpler constant, requiring only one
> instruction to load instead of two. Since it must be loaded in each
> function with a tag check, this decreases kernel text size by 0.5%.
>
> 3) This shift and the sign extension from kasan_reset_tag() can be
> combined into a single sbfx instruction. When this same algorithm change
> is applied to the compiler, it removes an instruction from each inline
> tag check, further reducing kernel text size by an additional 4.6%.
>
> These benefits extend to other architectures as well. On RISC-V, where
> the baseline ISA does not shifted addition or have an equivalent to the
> sbfx instruction, loading KASAN_SHADOW_OFFSET is reduced from 3 to 2
> instructions, and kasan_mem_to_shadow(kasan_reset_tag(addr)) similarly
> combines two consecutive right shifts.
>
> Due to signed memory-to-shadow mapping kasan_non_canonical_hook() needs
> changes - specifically the first part that tries to deduce if a faulty
> address came from kasan_mem_to_shadow(). Previous value of
> KASAN_SHADOW_OFFSET prevented any overflows when trying to map the
> entire linear address space to shadow memory so the check in
> kasan_non_canonical_hook() could consist of only checking whether the
> address isn't below KASAN_SHADOW_OFFSET.
>
> The signed memory-to-shadow conversion means negative addresses will be
> mapped below KASAN_SHADOW_OFFSET and positive addresses will map above
> KASAN_SHADOW_OFFSET. When looking at the mapping of the entire address
> space there will be an overflow when a big enough positive address will
> be passed to kasan_mem_to_shadow(). Then the question of finding
> addresses that couldn't come from kasan_mem_to_shadow() can be reduced
> to figuring out if the address isn't above the highest overflowed value
> (most positive address possible) AND below the most negative address
> possible.

Is there any reason we need this change for x86 SW_TAGS besides the
optimization benefits?

Is it required for the "x86: runtime_const used for KASAN_SHADOW_END"
patch? If so, please check my comment there first.

>
> Link: https://github.com/llvm/llvm-project/blob/llvmorg-20-init/llvm/lib/=
Transforms/Instrumentation/AddressSanitizer.cpp#L1316 [1]
> Link: https://github.com/llvm/llvm-project/blob/llvmorg-20-init/llvm/lib/=
Transforms/Instrumentation/HWAddressSanitizer.cpp#L895 [2]
> Link: https://github.com/llvm/llvm-project/blob/llvmorg-20-init/llvm/lib/=
Target/AArch64/AArch64AsmPrinter.cpp#L669 [3]
> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> ---
> Changelog v2: (Maciej)
> - Correct address range that's checked in kasan_non_canonical_hook().
>   Adjust the comment inside.
> - Remove part of comment from arch/arm64/include/asm/memory.h.
> - Append patch message paragraph about the overflow in
>   kasan_non_canonical_hook().
>
>  arch/arm64/Kconfig              | 10 +++++-----
>  arch/arm64/include/asm/memory.h | 14 +++++++++++++-
>  arch/arm64/mm/kasan_init.c      |  7 +++++--
>  include/linux/kasan.h           | 10 ++++++++--
>  mm/kasan/report.c               | 26 ++++++++++++++++++++++----
>  scripts/gdb/linux/mm.py         |  5 +++--
>  6 files changed, 56 insertions(+), 16 deletions(-)
>
> diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
> index fcdd0ed3eca8..fe7d79b447c3 100644
> --- a/arch/arm64/Kconfig
> +++ b/arch/arm64/Kconfig
> @@ -426,11 +426,11 @@ config KASAN_SHADOW_OFFSET
>         default 0xdffffe0000000000 if ARM64_VA_BITS_42 && !KASAN_SW_TAGS
>         default 0xdfffffc000000000 if ARM64_VA_BITS_39 && !KASAN_SW_TAGS
>         default 0xdffffff800000000 if ARM64_VA_BITS_36 && !KASAN_SW_TAGS
> -       default 0xefff800000000000 if (ARM64_VA_BITS_48 || (ARM64_VA_BITS=
_52 && !ARM64_16K_PAGES)) && KASAN_SW_TAGS
> -       default 0xefffc00000000000 if (ARM64_VA_BITS_47 || ARM64_VA_BITS_=
52) && ARM64_16K_PAGES && KASAN_SW_TAGS
> -       default 0xeffffe0000000000 if ARM64_VA_BITS_42 && KASAN_SW_TAGS
> -       default 0xefffffc000000000 if ARM64_VA_BITS_39 && KASAN_SW_TAGS
> -       default 0xeffffff800000000 if ARM64_VA_BITS_36 && KASAN_SW_TAGS
> +       default 0xffff800000000000 if (ARM64_VA_BITS_48 || (ARM64_VA_BITS=
_52 && !ARM64_16K_PAGES)) && KASAN_SW_TAGS
> +       default 0xffffc00000000000 if (ARM64_VA_BITS_47 || ARM64_VA_BITS_=
52) && ARM64_16K_PAGES && KASAN_SW_TAGS
> +       default 0xfffffe0000000000 if ARM64_VA_BITS_42 && KASAN_SW_TAGS
> +       default 0xffffffc000000000 if ARM64_VA_BITS_39 && KASAN_SW_TAGS
> +       default 0xfffffff800000000 if ARM64_VA_BITS_36 && KASAN_SW_TAGS

Ah, we also need to update Documentation/arch/arm64/kasan-offsets.sh,
these offsets are generated by that script.

Let's also point out in the commit message, that this change does not
move the location of the shadow memory but only changes the way that
location is calculated.

>         default 0xffffffffffffffff
>
>  config UNWIND_TABLES
> diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/mem=
ory.h
> index 717829df294e..e71cdf036287 100644
> --- a/arch/arm64/include/asm/memory.h
> +++ b/arch/arm64/include/asm/memory.h
> @@ -89,7 +89,15 @@
>   *
>   * KASAN_SHADOW_END is defined first as the shadow address that correspo=
nds to
>   * the upper bound of possible virtual kernel memory addresses UL(1) << =
64
> - * according to the mapping formula.
> + * according to the mapping formula. For Generic KASAN, the address in t=
he
> + * mapping formula is treated as unsigned (part of the compiler's ABI), =
so the
> + * end of the shadow memory region is at a large positive offset from
> + * KASAN_SHADOW_OFFSET. For Software Tag-Based KASAN, the address in the
> + * formula is treated as signed. Since all kernel addresses are negative=
, they
> + * map to shadow memory below KASAN_SHADOW_OFFSET, making KASAN_SHADOW_O=
FFSET
> + * itself the end of the shadow memory region. (User pointers are positi=
ve and
> + * would map to shadow memory above KASAN_SHADOW_OFFSET, but shadow memo=
ry is
> + * not allocated for them.)
>   *
>   * KASAN_SHADOW_START is defined second based on KASAN_SHADOW_END. The s=
hadow
>   * memory start must map to the lowest possible kernel virtual memory ad=
dress
> @@ -100,7 +108,11 @@
>   */
>  #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>  #define KASAN_SHADOW_OFFSET    _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
> +#ifdef CONFIG_KASAN_GENERIC
>  #define KASAN_SHADOW_END       ((UL(1) << (64 - KASAN_SHADOW_SCALE_SHIFT=
)) + KASAN_SHADOW_OFFSET)
> +#else
> +#define KASAN_SHADOW_END       KASAN_SHADOW_OFFSET
> +#endif
>  #define _KASAN_SHADOW_START(va)        (KASAN_SHADOW_END - (UL(1) << ((v=
a) - KASAN_SHADOW_SCALE_SHIFT)))
>  #define KASAN_SHADOW_START     _KASAN_SHADOW_START(vabits_actual)
>  #define PAGE_END               KASAN_SHADOW_START
> diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
> index b65a29440a0c..6836e571555c 100644
> --- a/arch/arm64/mm/kasan_init.c
> +++ b/arch/arm64/mm/kasan_init.c
> @@ -198,8 +198,11 @@ static bool __init root_level_aligned(u64 addr)
>  /* The early shadow maps everything to a single page of zeroes */
>  asmlinkage void __init kasan_early_init(void)
>  {
> -       BUILD_BUG_ON(KASAN_SHADOW_OFFSET !=3D
> -               KASAN_SHADOW_END - (1UL << (64 - KASAN_SHADOW_SCALE_SHIFT=
)));
> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> +               BUILD_BUG_ON(KASAN_SHADOW_OFFSET !=3D
> +                       KASAN_SHADOW_END - (1UL << (64 - KASAN_SHADOW_SCA=
LE_SHIFT)));
> +       else
> +               BUILD_BUG_ON(KASAN_SHADOW_OFFSET !=3D KASAN_SHADOW_END);
>         BUILD_BUG_ON(!IS_ALIGNED(_KASAN_SHADOW_START(VA_BITS), SHADOW_ALI=
GN));
>         BUILD_BUG_ON(!IS_ALIGNED(_KASAN_SHADOW_START(VA_BITS_MIN), SHADOW=
_ALIGN));
>         BUILD_BUG_ON(!IS_ALIGNED(KASAN_SHADOW_END, SHADOW_ALIGN));
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 890011071f2b..b396feca714f 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -61,8 +61,14 @@ int kasan_populate_early_shadow(const void *shadow_sta=
rt,
>  #ifndef kasan_mem_to_shadow
>  static inline void *kasan_mem_to_shadow(const void *addr)
>  {
> -       return (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT)
> -               + KASAN_SHADOW_OFFSET;
> +       void *scaled;
> +
> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> +               scaled =3D (void *)((unsigned long)addr >> KASAN_SHADOW_S=
CALE_SHIFT);
> +       else
> +               scaled =3D (void *)((long)addr >> KASAN_SHADOW_SCALE_SHIF=
T);
> +
> +       return KASAN_SHADOW_OFFSET + scaled;
>  }
>  #endif
>
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 3fe77a360f1c..5766714872d3 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -645,15 +645,33 @@ void kasan_report_async(void)
>   */
>  void kasan_non_canonical_hook(unsigned long addr)
>  {
> +       unsigned long max_shadow_size =3D BIT(BITS_PER_LONG - KASAN_SHADO=
W_SCALE_SHIFT);
>         unsigned long orig_addr;
>         const char *bug_type;
>
>         /*
> -        * All addresses that came as a result of the memory-to-shadow ma=
pping
> -        * (even for bogus pointers) must be >=3D KASAN_SHADOW_OFFSET.
> +        * With the default kasan_mem_to_shadow() algorithm, all addresse=
s
> +        * returned by the memory-to-shadow mapping (even for bogus point=
ers)
> +        * must be within a certain displacement from KASAN_SHADOW_OFFSET=
.
> +        *
> +        * For Generic KASAN the displacement is unsigned so the mapping =
from zero
> +        * to the last kernel address needs checking.
> +        *
> +        * For Software Tag-Based KASAN, the displacement is signed, so
> +        * KASAN_SHADOW_OFFSET is the center of the range. Higher positiv=
e
> +        * addresses overflow, so the range that can't be part of
> +        * memory-to-shadow mapping is above the biggest positive address
> +        * mapping and below the lowest possible one.
>          */
> -       if (addr < KASAN_SHADOW_OFFSET)
> -               return;
> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> +               if (addr < KASAN_SHADOW_OFFSET ||
> +                   addr >=3D KASAN_SHADOW_OFFSET + max_shadow_size)
> +                       return;
> +       } else {
> +               if (addr < KASAN_SHADOW_OFFSET - max_shadow_size / 2 &&
> +                   addr >=3D KASAN_SHADOW_OFFSET + max_shadow_size / 2)
> +                       return;

Ok, I think this would work for what I had in mind.

However, I just realized that this check is not entirely precise. When
doing the memory-to-shadow mapping, the memory address always has its
top byte set to 0xff: both the inlined compiler code and the outline
KASAN code do this. Thus, the possible values a shadow address can
take are the result of the memory-to-shadow mapping applied to
[0xff00000000000000, 0xffffffffffffffff], not to the whole address
space. So we can make this check more precise.

> +       }
>
>         orig_addr =3D (unsigned long)kasan_shadow_to_mem((void *)addr);
>
> diff --git a/scripts/gdb/linux/mm.py b/scripts/gdb/linux/mm.py
> index 7571aebbe650..2e63f3dedd53 100644
> --- a/scripts/gdb/linux/mm.py
> +++ b/scripts/gdb/linux/mm.py
> @@ -110,12 +110,13 @@ class aarch64_page_ops():
>          self.KERNEL_END =3D gdb.parse_and_eval("_end")
>
>          if constants.LX_CONFIG_KASAN_GENERIC or constants.LX_CONFIG_KASA=
N_SW_TAGS:
> +            self.KASAN_SHADOW_OFFSET =3D constants.LX_CONFIG_KASAN_SHADO=
W_OFFSET
>              if constants.LX_CONFIG_KASAN_GENERIC:
>                  self.KASAN_SHADOW_SCALE_SHIFT =3D 3
> +                self.KASAN_SHADOW_END =3D (1 << (64 - self.KASAN_SHADOW_=
SCALE_SHIFT)) + self.KASAN_SHADOW_OFFSET
>              else:
>                  self.KASAN_SHADOW_SCALE_SHIFT =3D 4
> -            self.KASAN_SHADOW_OFFSET =3D constants.LX_CONFIG_KASAN_SHADO=
W_OFFSET
> -            self.KASAN_SHADOW_END =3D (1 << (64 - self.KASAN_SHADOW_SCAL=
E_SHIFT)) + self.KASAN_SHADOW_OFFSET
> +                self.KASAN_SHADOW_END =3D self.KASAN_SHADOW_OFFSET
>              self.PAGE_END =3D self.KASAN_SHADOW_END - (1 << (self.vabits=
_actual - self.KASAN_SHADOW_SCALE_SHIFT))
>          else:
>              self.PAGE_END =3D self._PAGE_END(self.VA_BITS_MIN)

We likely also need to update scripts/gdb/linux/kasan.py.

Also, later in the series, you change KASAN_SHADOW_OFFSET from a
config option into a runtime_const, which AFAIU would make these
scripts stop working.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZcVSwUAC9_xtVAHvO6%2BRWDzt6wOzWN623m%3DdT-3G%3DNnTQ%40mail.gmail.com=
.
