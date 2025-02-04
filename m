Return-Path: <kasan-dev+bncBD22BAF5REGBBEECRK6QMGQEMNTBSMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0337EA27D00
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Feb 2025 22:05:24 +0100 (CET)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-467b19b5641sf125475231cf.3
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Feb 2025 13:05:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738703120; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZLcyTGRjzW3fzT241JlmUrWgzjah504R0LN8KCwksHvxl6u8mH11szYHfxaB7yTF+A
         aEWiSgxEgItqiszK5XyNAEeCmx7FDsdMQr4II6GnLb+TAmhGQuVWK1lir1uclr5oNjRa
         F4E8Py35FzW6vYxCmiLaLG4/bt4JGwRUU5Z6s15VzafV15Pkt0743lj9NCaZkXIQeLcO
         CuOTPcxStjeOJef0J9ngIMyPktu6UQhCUiwoy3i1serrv+9jBwW6sXoKpLDtrLOr3Ule
         oyiynwVToAfequD99Gdx5QOAoMEZdNbIBh6G+qxwiqz02zUb5BIQRLdobJgxepONGa4d
         5NLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=FT2Pg6aRjJdunRdEYetogd9jJELupPJUKCDKlJFGVWQ=;
        fh=f8YHZ7zkdSgaaiwYmgqXqn0ZaZ6FoFxkExF++wWeg7o=;
        b=kRJYay46pPNiO4qOiBQx4qqPY9EOAPrxYfOt4rOuEcb1IDLzi96jToenBOIs3NRk9I
         ZRqGBS4z/yX5f5/m4TbnlyZymgBnEZhKDOQUi7WYjDtTtZC94ZEVOCp7pWKMJTLarGyS
         hW7GRZ8Tk3HwHWHWsH2daFL7PLrEbnpcUe7UhutLca811TJ6DvOkBFZXef4WFqJwvBDo
         WWm65SjqPeHRuztVGnsgBYmdjr5q3RBEviGlHQaj2k23WycTvtJOOWPJeKPPkELcetJW
         2e2ubMOgRBz3zaMfO31dP913KYQTJEPfqAQlCv80FMB77Ve/SuOZLYkw68Efxjl7rQdb
         ue/g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=bSlr9VRB;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.16 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738703120; x=1739307920; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=FT2Pg6aRjJdunRdEYetogd9jJELupPJUKCDKlJFGVWQ=;
        b=EXJWZ1Nq3+K0PzkLAJsk50jEq78xdCCLWWyHwLEl2F5MvdvSprr/F7YFWc4k8ahs2p
         GuAw+0d6zGmAzNV/irrMENuAqiQt5C394WmrMmbqT3greyfFGFm+uf31oD2+grStPrFT
         mBwGYp7F3rkUqAKV+kdGJeVyt41zqOguC40njQ5F83aIx21A7SnZaKd1F5QWo776MByx
         DtJ8ErnhSenWdVz0pmJlWMlUn3gXoAg5w+Wt0DMGDbRs7rA0hHUVfQgy4qo1BaibntB+
         BYrqXIL63OMcI22YL1SoqOduiNv4MJRmwOER+xTcMguWULL0fePnJUqAos3Lz5D9zLdq
         vUYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738703120; x=1739307920;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=FT2Pg6aRjJdunRdEYetogd9jJELupPJUKCDKlJFGVWQ=;
        b=XrV65MLeo1OKfVp7E1hcF1b+GUjioqlfPj+KEcflnG0RiSwNnLV+OeHmmquIjnoxCa
         tH7M1VqNztWyc3HHyW2rQj2xZwXzMH/20nH4MlYE/Tf1JaaaRMzIu9U8q4rKX26G7ezx
         TRS1Yx5/aCS7dznSARhEY9U/i9EmJekMoCtcmltHLVfbpIcTzdVCy1P4Tf5wDSlQCDWi
         cfGj05jXHvzDUMrmyw9SF7x7vtdvcys8GG7eQDmdSjeipvlNQGEJnM/RxWUPnhFPcUoQ
         ZF9+GrGis/QqmN3ZKLz5yI6puLSRKtzVsBxzyYzuuNGly6PS6j1fLD4exHfoa3d9rEPj
         1Fng==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWQZpqwwAe86mm5rF0Z4KhFkFtjf5zE1By4Y+bHnE0w+ru1PGwc9hv+DXyFWjpDPbJoAgxFQg==@lfdr.de
X-Gm-Message-State: AOJu0Yw3qnRQx4E25tRzj2wZQk5WZzwNguveY0oh6Ti9R0TD8iY//lrF
	dqItv27zjp9M/LCZKp8lpn3pYxw/HnFQKCW90qYqdyp4nsIavjeP
X-Google-Smtp-Source: AGHT+IFrcyO9DPbb6xQsnacGLef5VptaVuWm/fhTyRpFuPheOnEPWUiRKM25s3dhorx7zSbvntTv5Q==
X-Received: by 2002:ac8:57d5:0:b0:466:93e2:8ba5 with SMTP id d75a77b69052e-470281855c4mr2819111cf.5.1738703120408;
        Tue, 04 Feb 2025 13:05:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4dc3:0:b0:467:77d8:69e7 with SMTP id d75a77b69052e-46fdcfa56b8ls31536161cf.2.-pod-prod-05-us;
 Tue, 04 Feb 2025 13:05:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUD87esmSjLqgj4TkDZvgQdJ2kZ+Tc0a/z/bX89JXK5KJOZ99OWJSpiCGyVPscdgt/JKvmOdQ1RogQ=@googlegroups.com
X-Received: by 2002:a05:622a:4296:b0:467:5a0b:de08 with SMTP id d75a77b69052e-47028185a16mr2821351cf.8.1738703119439;
        Tue, 04 Feb 2025 13:05:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738703119; cv=none;
        d=google.com; s=arc-20240605;
        b=PCe2/YVB9D3XkZj4JLSQXevyc7Wcu/hYfcvbgjI7REywQH6HRg1DlhUneKvQ2NGdCf
         1XiRvtUj4DPjg+zI+FtqRwmpoJwfCUdUSjhbOgZomm+cTfxaDZV7a5H8LU5Ls2/zatYa
         ZCK54bjvEk2ZIGgdK1q+4IENDg4fJDnvyczlVdbC7OfdmHofFRKW6kh9km490LBc9umg
         SdLrGzIlPquFaZC9ZLJq7ETE84tcXOvCdeWGMcevCxNT6JcsSFSF2KvVY7UyB2MsnLDK
         QfWHep9rduzLtyQBAWHD8STJHtMk15mfrX+osOAO3SazVc7SW0Q9rxEy2iYJIqy2y/HF
         Tp6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:content-language
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=mFeVnLEntDf1bN/pJP1ebUHZJ/lJIjQ1Hr/LKvw+RgU=;
        fh=PTwfmvNQjNSqg0pHPHKOUJJFLXr6jiIsJJlEgHJNEEk=;
        b=IwIis5nFRyJ9sczSrCqUvxMA8iS3Hz9h0ZxsVBD6kHLEkDyQaaeZpSZyphWplzUQOe
         IaoEcPGnfxx4m8YqI5PU/xoOqFevWhpzT2igXJqsLh/M7Go6QZQS7AcJvLiQc7RbvhKQ
         IxORiNrMwqfpUda+Yq29IsiJco9cf2JUky8cPuEqF5tLSFmgfhfxcU6BANhh8r8SIu54
         W8Xr90yvpOGi6M1zepLDeoaCJg/No77svypxcAKQ9gCerVzaRk64pa/90Fpf/mrUafMF
         Ltg4dRAGZAVUvlLWCXfyuI8RPz6d/ZAl4IqtAPVdItC7qy6+ux1pcZS3QFUVEhsdM3BJ
         Graw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=bSlr9VRB;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.16 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.16])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-46fdf1b9f04si5168031cf.4.2025.02.04.13.05.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 04 Feb 2025 13:05:19 -0800 (PST)
Received-SPF: pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.16 as permitted sender) client-ip=192.198.163.16;
X-CSE-ConnectionGUID: jkzkZEjrSByFv3J7OEboQw==
X-CSE-MsgGUID: n5v+3Y8OSwGgVXc8qE/tow==
X-IronPort-AV: E=McAfee;i="6700,10204,11336"; a="26849370"
X-IronPort-AV: E=Sophos;i="6.13,259,1732608000"; 
   d="scan'208";a="26849370"
Received: from orviesa005.jf.intel.com ([10.64.159.145])
  by fmvoesa110.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Feb 2025 13:05:18 -0800
X-CSE-ConnectionGUID: 9dF2FT5NRFWiRHULia/eYQ==
X-CSE-MsgGUID: L8qAtL/DQqe33Kcw+D4mcQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.12,224,1728975600"; 
   d="scan'208";a="115895089"
Received: from jdoman-mobl3.amr.corp.intel.com (HELO [10.125.110.55]) ([10.125.110.55])
  by orviesa005-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Feb 2025 13:05:17 -0800
Message-ID: <fb30574a-d238-424c-a464-0f7a5707c46a@intel.com>
Date: Tue, 4 Feb 2025 13:05:18 -0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 00/15] kasan: x86: arm64: risc-v: KASAN tag-based mode for
 x86
To: "Christoph Lameter (Ampere)" <cl@gentwo.org>,
 Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: luto@kernel.org, xin@zytor.com, kirill.shutemov@linux.intel.com,
 palmer@dabbelt.com, tj@kernel.org, andreyknvl@gmail.com, brgerst@gmail.com,
 ardb@kernel.org, dave.hansen@linux.intel.com, jgross@suse.com,
 will@kernel.org, akpm@linux-foundation.org, arnd@arndb.de, corbet@lwn.net,
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
 linux-doc@vger.kernel.org
References: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
 <8bd9c793-aac6-a330-ea8f-3bde0230a20b@gentwo.org>
From: Dave Hansen <dave.hansen@intel.com>
Content-Language: en-US
Autocrypt: addr=dave.hansen@intel.com; keydata=
 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
In-Reply-To: <8bd9c793-aac6-a330-ea8f-3bde0230a20b@gentwo.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dave.hansen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=bSlr9VRB;       spf=pass
 (google.com: domain of dave.hansen@intel.com designates 192.198.163.16 as
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

On 2/4/25 10:58, Christoph Lameter (Ampere) wrote:
> ARM64 supports MTE which is hardware support for tagging 16 byte granules
> and verification of tags in pointers all in hardware and on some platforms
> with *no* performance penalty since the tag is stored in the ECC areas of
> DRAM and verified at the same time as the ECC.
> 
> Could we get support for that? This would allow us to enable tag checking
> in production systems without performance penalty and no memory overhead.

At least on the Intel side, there's no trajectory for doing something
like the MTE architecture for memory tagging. The DRAM "ECC" area is in
very high demand and if anything things are moving away from using ECC
"bits" for anything other than actual ECC. Even the MKTME+integrity
(used for TDX) metadata is probably going to find a new home at some point.

This shouldn't be a surprise to anyone on cc here. If it is, you should
probably be reaching out to Intel over your normal channels.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/fb30574a-d238-424c-a464-0f7a5707c46a%40intel.com.
