Return-Path: <kasan-dev+bncBD22BAF5REGBBI5C3K7QMGQEKGUNYWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id BC5BBA82A16
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Apr 2025 17:24:20 +0200 (CEST)
Received: by mail-qk1-x73f.google.com with SMTP id af79cd13be357-7c0b0cf53f3sf1060801785a.2
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Apr 2025 08:24:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744212259; cv=pass;
        d=google.com; s=arc-20240605;
        b=TbNm82b4QzdW7vcBBChzDDxZssPEFZaU4Oqnnd4rMHlfhSYaGxAAkKwzfvXv07irs2
         O4JGlVf9qGUitAb8Q7XuKbMXO3aPiIGQzjwDDixIP8BD9w9CI8DpcNcacDzYfE6vnPqN
         0PFvEMFYFq3R40itP6LDOuCUTWQlCHvzyTqS77cl+0/NpbN8ZxNOlXGvhjYPV+jn1wg+
         3ftmzhhu9R0GyuJbclQSTfEBC470c4WkFy3HpHp/4sfoDwLLhbJjaHn2tBpqch/j2zgF
         bYCs1JwtbJJMuwK5HEhMnu6JtgKnZxDvVpB5oULZO9336ALa0YD7Jmxvq/wGdXHJSJxK
         wDyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=BgqEg10pem/QYZ7j3BShRZj7taKtvr4vjYc53HOyNQg=;
        fh=x412oqK80KYb4mVM024liNbGj7FKj7zMlLLtqXfp5hM=;
        b=MkuV2/mRKUMYMUuddEyzPjWDvAzFP6WlCOObsFpKHHJsuH/DxqeuZNN86H+FHIoTi6
         6UxkvOpwrlrI7txk3YucgThdcMRddhnY8brxhFkb7ao6U+eyiHglD7X7wC+QGzjXA77R
         FJ6uVNGTl6PLAdcDnLHWrUz9SxPqUabIog5BumzLkkFF0IVIofU8FHopqYU6QLSFEEVK
         NhRKXsL35VOfIa08V1Pk6KHJGVVkjSdvN2LMxTRNJRY5lArYiSAKZRbBbVQevALJU8oN
         oVFSKWZOV7Unw+laxliUs8CzEDWXV5O1lCb7aTgEvuV6wXS87IW5fCqgpppmaDkPDh78
         h8/Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Ng4dtN5a;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.7 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744212259; x=1744817059; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=BgqEg10pem/QYZ7j3BShRZj7taKtvr4vjYc53HOyNQg=;
        b=WveZpCwtb6sYDw288BLVAdQ1Raqw3EeUlAyhMpF88vtkrd5MIctPUm3LaCtCC58bdU
         BJY7vGREi/ZfozwRDq138fPzekAp+UZHgZ7FmLwenoC20vg2hAV+qYkMqi7NqcICwRY4
         rEsgovwqt+v9PNSr2e0iIwHr7vQhVSq276bFh4M60HAIFahtcBWeW74otPVLKMQJyvMI
         AO1raBvnFyOLbsswU5uZUwwczo8ZdxxXmvjtLCEQSyZbGYBEBOGZ15ay6CWalInTlsV4
         ZbZIv/PEzxeFZFaLk7upxHjLVqMo3KdpOdJlP9agoMJ/BTtPd50vcSjT3keghh3M5dgz
         wsXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744212259; x=1744817059;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=BgqEg10pem/QYZ7j3BShRZj7taKtvr4vjYc53HOyNQg=;
        b=GYiWLS/MFvCZyZyVConljvER+DmVo/W2J5ZW7EMh1Z2bbWq6nqF/lv/Ra3WOxbyXwr
         ZaIev22ejZCS10VPcB2ypj/LPr/CA8nvPTurLlUVtuXe+ZeJdsGbl9wmhCqN7VJSt/hr
         zkoXZlPNbC1JzsUkHESofukWKL2OIW4LC8TW1/Mb8yu38ViXOB1aPu2ZjtXeqQTcn9dm
         N3YVJA/H8tF9M5ZU9pja3juyNGZ2kuX6HHzlmj9NqoeWspAWpFVmiNFfH+e47zsOphsx
         LBIWrDIJM+jpH4FPLJQxalg2DSkpZ7s2nLS6HufzSCVPUW+VUIp4R/IiOnYdk8i7kAqy
         Q5VA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWUkZmqgwQltX2reMKYistzHgAjxeV4/aTRaSzUldeIGIcKGJ48Nw7V3rrxYHWqcmHlAtEUCg==@lfdr.de
X-Gm-Message-State: AOJu0YxgjmD3wWeydgVVRBkumquffY1bFJyWTp0ZHKh1WEStOrqJphxW
	cyb2raY5wgGokpKxXryAmWrpTnTqWT2mimmpRTPqpOdjwEboTNyZ
X-Google-Smtp-Source: AGHT+IGgxMAbpyf9ylKlV8S+Ee87S1Cy4DPPhnbdCXg0nTkDehkTI/2iJAgMtCCf6c7ixRatxPcCnQ==
X-Received: by 2002:a05:620a:19a7:b0:7c5:5d4b:e63c with SMTP id af79cd13be357-7c79dea5a60mr410497185a.47.1744212259272;
        Wed, 09 Apr 2025 08:24:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPALtbJWFJLLPiqBuYBR1MEhUaewV01RSfBfQbdYpycF36w==
Received: by 2002:ac8:777b:0:b0:476:7bf7:255e with SMTP id d75a77b69052e-4796b48a87als306791cf.1.-pod-prod-05-us;
 Wed, 09 Apr 2025 08:24:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWjS46uc7VJ4PFU0pL1yktY9QK3afYSEdjgealJKdEG99n7ptarWratFiVilrevGBc2WYWgeH9vzNg=@googlegroups.com
X-Received: by 2002:a05:620a:6003:b0:7c5:642f:b22c with SMTP id af79cd13be357-7c79ddaca47mr431201285a.20.1744212258324;
        Wed, 09 Apr 2025 08:24:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744212258; cv=none;
        d=google.com; s=arc-20240605;
        b=P/C+qzUaZLV6Rk5Gldg1OklD/7EOGpmRpWVQ2WrO/Hnxe11UUqodnoBjyK7BSY9l6W
         7iaQBzIamBFES+l3q8y73/wxgY9pwm6255QbjPURbvt3a9vPgLbFLz4DvuNJfYWeSIDA
         vWoQPGvnO6a8X9HS80vBFUt0CzgOt8jAhtzdE0OQDl1YescMFGEQCtOqq4seM+URHuad
         5yTYWq7ejwOkarc0J2WKHt6PYcDVXrLrM2B+WoE+ZId7xLHzQq4owsg6+/g1Ki5JYEaQ
         pY3j1KBm4AE5e2d0UZvWx1zShhP8vyfaE6teq6kNoWs/TIIoZz+sXnIFkPTgysf1YETO
         I37g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:content-language
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=jjKgBs5srjsBGMlFpLxdjtc7AXpFCectewEAIlOUF9w=;
        fh=gGPVKbHUX2Omcvuc8J48EMglbdecp5b+AI6gox0GcQM=;
        b=b8jlgYmKW/NA+UJdK0bdeQjrJ0gvvp77gNU3r9H7TB1x9Y3rfUEPVB+cNG1tlgmb+R
         1cneP79Q9XjTFoqRa3QbNuSMFgCk5EflZuQ0ixI+bWi0ZEYObLfMeUyi8oNfAAJICgh2
         rdAVA11qu9tZIFQnHxfTEg8Rig7kglQodrJZtXaYyWpY5fidOH2hfjbmAuv4TVgk6Vsb
         9lDMGXfz7wPp5qJJrYx46xWA/ZQTmniyfuaTqWVw9J6tLEoWLc7Nyc1BusmOuWp6kDRO
         aquyzGkaQc3uofzeErOewiMlufneMMUN7/twZpVCRBQbZUlFvQbsBnHkHDH3HJH6r2/l
         VZQA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Ng4dtN5a;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.7 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.7])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7c7a11dc9f2si6856985a.7.2025.04.09.08.24.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 09 Apr 2025 08:24:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.7 as permitted sender) client-ip=192.198.163.7;
X-CSE-ConnectionGUID: BYgyQ2UuRXyCKHUp1+IfMA==
X-CSE-MsgGUID: xWfPXoiORcurPB5rYqvmiA==
X-IronPort-AV: E=McAfee;i="6700,10204,11399"; a="71071403"
X-IronPort-AV: E=Sophos;i="6.15,200,1739865600"; 
   d="scan'208";a="71071403"
Received: from fmviesa002.fm.intel.com ([10.60.135.142])
  by fmvoesa101.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 09 Apr 2025 08:24:16 -0700
X-CSE-ConnectionGUID: djvQwLdiSIOUrXyaz6HO3w==
X-CSE-MsgGUID: GE/MdNfoTNa8pIrfVyB5NQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.15,200,1739865600"; 
   d="scan'208";a="151793818"
Received: from sramkris-mobl1.amr.corp.intel.com (HELO [10.124.220.195]) ([10.124.220.195])
  by fmviesa002-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 09 Apr 2025 08:24:14 -0700
Message-ID: <0770a3d4-c8ff-4172-9eda-c9debfee6d03@intel.com>
Date: Wed, 9 Apr 2025 08:24:11 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 09/14] x86: Minimal SLAB alignment
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: hpa@zytor.com, hch@infradead.org, nick.desaulniers+lkml@gmail.com,
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
 will@kernel.org, brgerst@gmail.com, llvm@lists.linux.dev,
 linux-mm@kvack.org, linux-doc@vger.kernel.org,
 linux-arm-kernel@lists.infradead.org, linux-kbuild@vger.kernel.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, x86@kernel.org
References: <cover.1743772053.git.maciej.wieczor-retman@intel.com>
 <173d99afea37321e76e9380b49bd5966be8db849.1743772053.git.maciej.wieczor-retman@intel.com>
 <ceade208-c585-48e7-aafe-4599b1a06b81@intel.com>
 <czzcsmwaf42v47arvmwgrh4p7h3misoarremtc7r2cme2ceuud@yya5jfuqhuye>
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
In-Reply-To: <czzcsmwaf42v47arvmwgrh4p7h3misoarremtc7r2cme2ceuud@yya5jfuqhuye>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dave.hansen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=Ng4dtN5a;       spf=pass
 (google.com: domain of dave.hansen@intel.com designates 192.198.163.7 as
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

On 4/9/25 05:49, Maciej Wieczor-Retman wrote:
> The differences looked mostly like noise, sometimes the higher alignment would
> use up a little bit less memory, sometimes a little bit more. I looked at all
> values in "cat /proc/meminfo".
> 
> Is there some slab/slub benchmark for the kernel that would make sense to
> checkout here?

You don't need to benchmark anything. Just mention that it will waste
memory and also give *some* ballpark estimate on how much. Just looking
at your laptop's /proc/slabinfo would be a good start.

Oh, and it wouldn't hurt to find out when and why the minimal slab
alignment got dropped down to 8 bytes. I _thought_ it was higher at some
point. Presumably there was a good reason for it and you're now undoing
part of it.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/0770a3d4-c8ff-4172-9eda-c9debfee6d03%40intel.com.
