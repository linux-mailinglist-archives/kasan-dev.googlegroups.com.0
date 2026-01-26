Return-Path: <kasan-dev+bncBD22BAF5REGBBN4337FQMGQEETXPIJY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id IKhPGrvNd2mxlQEAu9opvQ
	(envelope-from <kasan-dev+bncBD22BAF5REGBBN4337FQMGQEETXPIJY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 21:25:31 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id E4D8C8D0A5
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 21:25:30 +0100 (CET)
Received: by mail-pg1-x53f.google.com with SMTP id 41be03b00d2f7-bce224720d8sf2695181a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 12:25:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769459128; cv=pass;
        d=google.com; s=arc-20240605;
        b=TevNybb5u5VQRaQkbR28KDKSHPEX01NYcQM6PaASAyMtOxGPy6MUkx3j5207ui4mEG
         8wCpt0BqrxSLxoediJjkPm4N483jQQ2N69k5g3i9t60vv8UzlH2GRSTcyvr9LVH+PwlE
         WrKDcP/85SghWJCjPdbG6h0uJQQRDYIQ4fYt5yf+8uqGWFfjBHHypJIcn7A7kSpAdVE5
         R1ssKQ58Dh8WwlmjITJNK6u3FbO7sfz8fruYQzs68jc6PQTuK9kW0XZgc+6bOdCBC+QF
         oSfFGWJz6cdWlYasNt6TRsjsKE7K59AvOyUmK+s4RxNw0Odp/2/QPz3F2n6T+NSGRQNL
         iPGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=y+65f7R6ZWJZe8ai6EV3t+AS6WbDjQtHwG28mU7YsdY=;
        fh=vdRTNVaRqfE2G6A5+5Kq2HmocdyIffCKx7KLfPauPgs=;
        b=XT0euIiH7xIwSdaAlyDGmu7n1+Ny0pMqsIWYVhBs/0ElIp9rAWxlGiJrZBGC9cL8jd
         0KCIacyLs+s/fkpuLWikPnSsnW2Y0pu3ZoiWRfAzYSB2ODvn8Z/88zcGP2TvD2JHyn2+
         4e14MqzrDXwrtD8ihodQV3+MinlvJ7kSKArpwBUtnGYDU8jmN6MZdQD3xqVuYz3ipwwm
         62cVZ0es8L5rZOpVVTQL517NOGPfg8EU3cF7bO9j1e5KMNI3+Bzwgshr3VABl87djPrP
         yia4lwmx7loc5qBScFJBiAiQ9Ht9/vTUkLRtsExxoiQ1T/ESDUTCtH+fnxj8vQpHMfzW
         Zibw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="PGVG0H/H";
       spf=pass (google.com: domain of dave.hansen@intel.com designates 198.175.65.21 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769459128; x=1770063928; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=y+65f7R6ZWJZe8ai6EV3t+AS6WbDjQtHwG28mU7YsdY=;
        b=PSkVrubzBckLmm8uhQN1nJKUnW3HICxOgkvidWFYF7giwq1ydKfe7Qoasnrq5Liv/d
         1/8fiQ/EikkAcw7cg9Xj+MpWOLuBkjlop+a+CFF4UAoXBPa04qDXHJwyiIqA3tLmj2l/
         QcV6kcN+lev1R18zpU9FZSO4Ox/5NiSvgMlVZznGUP17k1NHUzgIFz0p7ovIZWfeRGut
         Zi8wvtLUPJEVO5VglOwoXXAk8AyvossvMJXBwOkAdvR7diZ/NnQOj7G3grOYNwXCygPS
         Ex2pYlLxeUKKbLQPSOwI0FOeyfc1265wGHmyPZwia5QmxEqYIi/d9v5dz22T7Ga2onBe
         39Yg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769459128; x=1770063928;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=y+65f7R6ZWJZe8ai6EV3t+AS6WbDjQtHwG28mU7YsdY=;
        b=Xt5FQAIk3M4IMIDA8kbPa8zLcfVujA1bDg1pbVVHC8/Hfyptqcgi3eC8fqK3e+Tunf
         x3wCJT88m4sGjLChm3C5wNlY47RZVucvRM0LPI7DykBGqOg44QyLMAoeUKNK2UbQco6I
         sLw6RtefvS+QOrq9mIAR32sZVKYUO9+c2iSTMnnf2CkM8ippULjg0r8n/2f4CyXiE3nX
         9mtXEGcryHcaYn1KfACyzqkK5YSzlKmzEF4OZPsRhRIoiT0WbW0ZnCWppC3lzoW8304y
         i4Z0LQgRacZcQ6Kb0AYucoG8GHEIVy7q9rm2tKqecWE40S+Tj/kNT/LSDksV2O/46qBq
         sEeQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXDVtV+wlzO5BugJ6NEZLPPmnFzU0n7b+M8bVsz6O3W9yRbWtpvWLhPPoHvthpoALaBkpf2rA==@lfdr.de
X-Gm-Message-State: AOJu0Yx/4wauIs9uUEY/jkAtZRM5U2r5knKLVhCjF9L97ZaIenguZHC5
	LJ/FZNcjysOfuq41WEQFZST5tZeznX155SNGjuDsBln3bfM73662VOm6
X-Received: by 2002:a17:90b:578e:b0:34c:c50e:9b80 with SMTP id 98e67ed59e1d1-353c4186babmr4676600a91.27.1769459128195;
        Mon, 26 Jan 2026 12:25:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GL0IejamaVyIyoN3QwgVWDUOMte5P96ai12VjAB+qe+w=="
Received: by 2002:a17:90b:3d8:b0:343:63b8:b29c with SMTP id
 98e67ed59e1d1-353359685bbls3566201a91.0.-pod-prod-02-us; Mon, 26 Jan 2026
 12:25:26 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXhoaRQrRD0/dpwylOcBCEtyf854M2SMBrdcFcnCaBctNi4QQENRJZj6hBMQ+IiM5SFk3Oa01sMPYo=@googlegroups.com
X-Received: by 2002:a17:90b:1807:b0:352:de8c:7270 with SMTP id 98e67ed59e1d1-353c40eae14mr4690902a91.9.1769459126672;
        Mon, 26 Jan 2026 12:25:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769459126; cv=none;
        d=google.com; s=arc-20240605;
        b=LOXR4V2292MeAx7Dd8wSMOlL3nG0EpSc8IKnHJzzb6aWxfAdy7LwwID477tPkssrev
         GqDHytxxKc+ms23sHrgK1g7OlCaRndnokAafYHIroL/EtYalGgT9yUTtRAmG2mBaGqo8
         1mZ2I/kVLblmVD/5Z+oR+O4FDHRnWQrnYi4rVlPu3lpm1+q4gGXPe+6xYVYrQIHao6YK
         6PjkFrZArxNiOjQ7hiaIikFZqzfG3VkG1kDyKMmcDIC5KPUALYfzqMX3W0BC0umHpcpq
         F5Vw9txCahi9DevYvL0x8SdPzPz/LPdC6N+RicXcQ/h0D1uXKMnyfbcxnV/ZoMZPsZl1
         lDOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:content-language
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=i7pqKvsRC8yjf5XdGLaUET06tvrLrYMpGKhNEU3XjW4=;
        fh=FSKZqXmXDORPBdXhR2/BF0k0Rv4y+eokrzgDNL0tgAQ=;
        b=SrdHo3nfBqTlwCp2d7Vy00tq3a+31FQofZ0J3CuE6Mpb1cRtkEn0BVd78fH6zHFaTB
         U9hFqdAZM9NdSysJ/jVEt5ft1kAmt+lF96vTD4d871pWKNns4GlO1AkCQdgw4PuU+iTt
         hl12LHiIELCa3HhmlalaTgWif2AFbB07AN6dZqbgsELOj9qZ6y3ZiDii2saRF4Rk+BkT
         mTXR/yGfTrex+xZ79rPq7CtX82hHdpAwUNth1jTbnh5+r1S4JfkiZEpqt2UonXiF42RQ
         iaJum2GXUgkyz3BXEKBVNk+L8ybhe9Us1KCt1iDcNl5+spDU/BIf0VVA92uuoYUzl/Pg
         1gPQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="PGVG0H/H";
       spf=pass (google.com: domain of dave.hansen@intel.com designates 198.175.65.21 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.21])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-353f6143531si1598a91.3.2026.01.26.12.25.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 26 Jan 2026 12:25:26 -0800 (PST)
Received-SPF: pass (google.com: domain of dave.hansen@intel.com designates 198.175.65.21 as permitted sender) client-ip=198.175.65.21;
X-CSE-ConnectionGUID: fzCB6RZERyWXJI/LAV3BCQ==
X-CSE-MsgGUID: 52PPQFxuQFOb99gwY2r0Bg==
X-IronPort-AV: E=McAfee;i="6800,10657,11683"; a="70549140"
X-IronPort-AV: E=Sophos;i="6.21,255,1763452800"; 
   d="scan'208";a="70549140"
Received: from fmviesa004.fm.intel.com ([10.60.135.144])
  by orvoesa113.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 26 Jan 2026 12:25:24 -0800
X-CSE-ConnectionGUID: D22qx1PxTdKchJ9NKPUH4A==
X-CSE-MsgGUID: 6yTB2nUPTpWUjMz34tdYOA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.21,255,1763452800"; 
   d="scan'208";a="212637940"
Received: from rchatre-mobl4.amr.corp.intel.com (HELO [10.125.109.65]) ([10.125.109.65])
  by fmviesa004-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 26 Jan 2026 12:25:23 -0800
Message-ID: <64b91595-1305-4b64-bcce-a6913f76ade0@intel.com>
Date: Mon, 26 Jan 2026 12:25:22 -0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [REGRESSION] x86_32 boot hang in 6.19-rc7 caused by b505f1944535
 ("x86/kfence: avoid writing L1TF-vulnerable PTEs")
To: Borislav Petkov <bp@alien8.de>,
 Ryusuke Konishi <konishi.ryusuke@gmail.com>
Cc: Andrew Cooper <andrew.cooper3@citrix.com>,
 Andrew Morton <akpm@linux-foundation.org>, Marco Elver <elver@google.com>,
 LKML <linux-kernel@vger.kernel.org>, Alexander Potapenko
 <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
 Dave Hansen <dave.hansen@linux.intel.com>, X86 ML <x86@kernel.org>,
 "H. Peter Anvin" <hpa@zytor.com>, Jann Horn <jannh@google.com>,
 kasan-dev@googlegroups.com
References: <20260106180426.710013-1-andrew.cooper3@citrix.com>
 <20260107151700.c7b9051929548391e92cfb3e@linux-foundation.org>
 <CAKFNMokwjw68ubYQM9WkzOuH51wLznHpEOMSqtMoV1Rn9JV_gw@mail.gmail.com>
 <20260126195431.GDaXfGd9cSwoH2O52r@fat_crate.local>
From: Dave Hansen <dave.hansen@intel.com>
Content-Language: en-US
Autocrypt: addr=dave.hansen@intel.com; keydata=
 xsFNBE6HMP0BEADIMA3XYkQfF3dwHlj58Yjsc4E5y5G67cfbt8dvaUq2fx1lR0K9h1bOI6fC
 oAiUXvGAOxPDsB/P6UEOISPpLl5IuYsSwAeZGkdQ5g6m1xq7AlDJQZddhr/1DC/nMVa/2BoY
 2UnKuZuSBu7lgOE193+7Uks3416N2hTkyKUSNkduyoZ9F5twiBhxPJwPtn/wnch6n5RsoXsb
 ygOEDxLEsSk/7eyFycjE+btUtAWZtx+HseyaGfqkZK0Z9bT1lsaHecmB203xShwCPT49Blxz
 VOab8668QpaEOdLGhtvrVYVK7x4skyT3nGWcgDCl5/Vp3TWA4K+IofwvXzX2ON/Mj7aQwf5W
 iC+3nWC7q0uxKwwsddJ0Nu+dpA/UORQWa1NiAftEoSpk5+nUUi0WE+5DRm0H+TXKBWMGNCFn
 c6+EKg5zQaa8KqymHcOrSXNPmzJuXvDQ8uj2J8XuzCZfK4uy1+YdIr0yyEMI7mdh4KX50LO1
 pmowEqDh7dLShTOif/7UtQYrzYq9cPnjU2ZW4qd5Qz2joSGTG9eCXLz5PRe5SqHxv6ljk8mb
 ApNuY7bOXO/A7T2j5RwXIlcmssqIjBcxsRRoIbpCwWWGjkYjzYCjgsNFL6rt4OL11OUF37wL
 QcTl7fbCGv53KfKPdYD5hcbguLKi/aCccJK18ZwNjFhqr4MliQARAQABzUVEYXZpZCBDaHJp
 c3RvcGhlciBIYW5zZW4gKEludGVsIFdvcmsgQWRkcmVzcykgPGRhdmUuaGFuc2VuQGludGVs
 LmNvbT7CwXgEEwECACIFAlQ+9J0CGwMGCwkIBwMCBhUIAgkKCwQWAgMBAh4BAheAAAoJEGg1
 lTBwyZKwLZUP/0dnbhDc229u2u6WtK1s1cSd9WsflGXGagkR6liJ4um3XCfYWDHvIdkHYC1t
 MNcVHFBwmQkawxsYvgO8kXT3SaFZe4ISfB4K4CL2qp4JO+nJdlFUbZI7cz/Td9z8nHjMcWYF
 IQuTsWOLs/LBMTs+ANumibtw6UkiGVD3dfHJAOPNApjVr+M0P/lVmTeP8w0uVcd2syiaU5jB
 aht9CYATn+ytFGWZnBEEQFnqcibIaOrmoBLu2b3fKJEd8Jp7NHDSIdrvrMjYynmc6sZKUqH2
 I1qOevaa8jUg7wlLJAWGfIqnu85kkqrVOkbNbk4TPub7VOqA6qG5GCNEIv6ZY7HLYd/vAkVY
 E8Plzq/NwLAuOWxvGrOl7OPuwVeR4hBDfcrNb990MFPpjGgACzAZyjdmYoMu8j3/MAEW4P0z
 F5+EYJAOZ+z212y1pchNNauehORXgjrNKsZwxwKpPY9qb84E3O9KYpwfATsqOoQ6tTgr+1BR
 CCwP712H+E9U5HJ0iibN/CDZFVPL1bRerHziuwuQuvE0qWg0+0SChFe9oq0KAwEkVs6ZDMB2
 P16MieEEQ6StQRlvy2YBv80L1TMl3T90Bo1UUn6ARXEpcbFE0/aORH/jEXcRteb+vuik5UGY
 5TsyLYdPur3TXm7XDBdmmyQVJjnJKYK9AQxj95KlXLVO38lczsFNBFRjzmoBEACyAxbvUEhd
 GDGNg0JhDdezyTdN8C9BFsdxyTLnSH31NRiyp1QtuxvcqGZjb2trDVuCbIzRrgMZLVgo3upr
 MIOx1CXEgmn23Zhh0EpdVHM8IKx9Z7V0r+rrpRWFE8/wQZngKYVi49PGoZj50ZEifEJ5qn/H
 Nsp2+Y+bTUjDdgWMATg9DiFMyv8fvoqgNsNyrrZTnSgoLzdxr89FGHZCoSoAK8gfgFHuO54B
 lI8QOfPDG9WDPJ66HCodjTlBEr/Cwq6GruxS5i2Y33YVqxvFvDa1tUtl+iJ2SWKS9kCai2DR
 3BwVONJEYSDQaven/EHMlY1q8Vln3lGPsS11vSUK3QcNJjmrgYxH5KsVsf6PNRj9mp8Z1kIG
 qjRx08+nnyStWC0gZH6NrYyS9rpqH3j+hA2WcI7De51L4Rv9pFwzp161mvtc6eC/GxaiUGuH
 BNAVP0PY0fqvIC68p3rLIAW3f97uv4ce2RSQ7LbsPsimOeCo/5vgS6YQsj83E+AipPr09Caj
 0hloj+hFoqiticNpmsxdWKoOsV0PftcQvBCCYuhKbZV9s5hjt9qn8CE86A5g5KqDf83Fxqm/
 vXKgHNFHE5zgXGZnrmaf6resQzbvJHO0Fb0CcIohzrpPaL3YepcLDoCCgElGMGQjdCcSQ+Ci
 FCRl0Bvyj1YZUql+ZkptgGjikQARAQABwsFfBBgBAgAJBQJUY85qAhsMAAoJEGg1lTBwyZKw
 l4IQAIKHs/9po4spZDFyfDjunimEhVHqlUt7ggR1Hsl/tkvTSze8pI1P6dGp2XW6AnH1iayn
 yRcoyT0ZJ+Zmm4xAH1zqKjWplzqdb/dO28qk0bPso8+1oPO8oDhLm1+tY+cOvufXkBTm+whm
 +AyNTjaCRt6aSMnA/QHVGSJ8grrTJCoACVNhnXg/R0g90g8iV8Q+IBZyDkG0tBThaDdw1B2l
 asInUTeb9EiVfL/Zjdg5VWiF9LL7iS+9hTeVdR09vThQ/DhVbCNxVk+DtyBHsjOKifrVsYep
 WpRGBIAu3bK8eXtyvrw1igWTNs2wazJ71+0z2jMzbclKAyRHKU9JdN6Hkkgr2nPb561yjcB8
 sIq1pFXKyO+nKy6SZYxOvHxCcjk2fkw6UmPU6/j/nQlj2lfOAgNVKuDLothIxzi8pndB8Jju
 KktE5HJqUUMXePkAYIxEQ0mMc8Po7tuXdejgPMwgP7x65xtfEqI0RuzbUioFltsp1jUaRwQZ
 MTsCeQDdjpgHsj+P2ZDeEKCbma4m6Ez/YWs4+zDm1X8uZDkZcfQlD9NldbKDJEXLIjYWo1PH
 hYepSffIWPyvBMBTW2W5FRjJ4vLRrJSUoEfJuPQ3vW9Y73foyo/qFoURHO48AinGPZ7PC7TF
 vUaNOTjKedrqHkaOcqB185ahG2had0xnFsDPlx5y
In-Reply-To: <20260126195431.GDaXfGd9cSwoH2O52r@fat_crate.local>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dave.hansen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="PGVG0H/H";       spf=pass
 (google.com: domain of dave.hansen@intel.com designates 198.175.65.21 as
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.11 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	MIME_GOOD(-0.10)[text/plain];
	DMARC_POLICY_SOFTFAIL(0.10)[intel.com : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	FREEMAIL_TO(0.00)[alien8.de,gmail.com];
	FORGED_SENDER_MAILLIST(0.00)[];
	TAGGED_FROM(0.00)[bncBD22BAF5REGBBN4337FQMGQEETXPIJY];
	RCPT_COUNT_TWELVE(0.00)[15];
	MIME_TRACE(0.00)[0:+];
	FROM_HAS_DN(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_NEQ_ENVFROM(0.00)[dave.hansen@intel.com,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	NEURAL_HAM(-0.00)[-1.000];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,intel.com:mid,mail-pg1-x53f.google.com:helo,mail-pg1-x53f.google.com:rdns]
X-Rspamd-Queue-Id: E4D8C8D0A5
X-Rspamd-Action: no action

On 1/26/26 11:54, Borislav Petkov wrote:
> [    0.173437] rcu: srcu_init: Setting srcu_struct sizes based on contention.
> [    0.175172] ------------[ cut here ]------------
> [    0.176066] kernel BUG at arch/x86/mm/physaddr.c:70!

Take a look at kfence_init_pool_early(). It's riddled with __pa() which
calls down to __phys_addr() => slow_virt_to_phys().

The plain !present PTE is fine, but the inverted one trips up
slow_virt_to_phys(), I bet. The slow_virt_to_phys() only gets called on
when highmem is enabled (not when the memory is highmem) which is why
this is blowing up on 32-bit only.

The easiest hack/fix would be to just turn off kfence on 32-bit. I guess
the better fix would be to make kfence do its __pa() before it mucks
with the PTEs. The other option would be to either comprehend or ignore
those inverted PTEs.

Ugh.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/64b91595-1305-4b64-bcce-a6913f76ade0%40intel.com.
