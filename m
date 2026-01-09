Return-Path: <kasan-dev+bncBDAZZCVNSYPBBB4MQTFQMGQECZ3PFGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 7DF60D0A76E
	for <lists+kasan-dev@lfdr.de>; Fri, 09 Jan 2026 14:43:37 +0100 (CET)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-888881a1cf7sf7904236d6.3
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Jan 2026 05:43:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767966216; cv=pass;
        d=google.com; s=arc-20240605;
        b=KDknwKVtHRQ8Wzql1oo+SK3yZdQhVZ2IPTMTNGMzJt8gNvFp+TEYyeomm0XE4TvDak
         GpagiXV0BplwGyQLyBiQRzSbpSWuT/rHdA/o8rGdVkncAddZcYltUfZwqBQ0fnSDDNsp
         Z3/RZYom21QweMqc6quAZMPT5j1nMpUeGBu0mIzjo0H/srUH5crbzW5dwGgGQzputYSH
         9OP0v8nECOrnRSQAh2rY6rMdb8dzrRGGqZ1i1k7iYVWFtPCZHI7C/wqGxBQ/+/f8Ea4e
         QBbVz9zt6U3f/himppU4Yah+M1YhQPSJvyQdBHg7htH+hrhNOLauLHncf6UZpGGE71MP
         ZQSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=eFUHCHSQ+CPisZZ7HEm1yVSod2RMcmuWbAqil56EGTU=;
        fh=WS80eyzY7ojphj17ibIZj843i1Lq6BthMQnsZLTe0Hg=;
        b=BdfJXzHleYZb1Erh4eMxfuK4Mqs06A/hfJtgnEsNFTjYQ7LY9IVzXWcBVxIylF2Qa/
         fn3hyOnme5e7WIbGJrrhwGubZd4XBlPTuUuG1jHRf7zBXhT+c8j3OCQByxLHsQCvsmR7
         wNMImrtQGqpw609VYd0570sT3+KJnR+/lkpmmFpKVWic+VbTqy8iZQ17d666EFrNXx4H
         oXp6SP8SAnQPSts3LUJxhTU7aSanrsXkI3fOoGcrBscp/ADJAAVXnSO35SQHx8oHn1h8
         8YxpwPN01/HVxfxI77L4GxJS+HzN6RCnfB+VInY6hMivWiwDpEAfQYg5kb+rStAmWnNN
         xy+g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jq8+HDoW;
       spf=pass (google.com: domain of will@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767966216; x=1768571016; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=eFUHCHSQ+CPisZZ7HEm1yVSod2RMcmuWbAqil56EGTU=;
        b=OsfQx1sfNEVVBIb9QA3SVUdn+aQRA8PyDgPdw9oLfeh2h/D/FAdvRzO1NMcXCYPGHi
         /TVUl0h03ZnjdxfSBY/XCGeMsHxAVgQJP6o23BW53Mdzsd3J34+pks2CxkAN+nnk2AHH
         aEYs8cr3JGSN/W8kS4Puak32kOHpXZ2MHQZM9JWkFn2RG+58P+1kVGkcRdtWvI1382mB
         qW/zB4eGikSV/3nxGYzE8KSG8um1cjD2T+DI5Gujrj1w0ss5wjpiKXrvBq+9wFCYE1pQ
         OOSfVoGn0DyXwXDqWn7IpPNjdHgxLF0v+B/hGOwE394cA1CZCOSnCAV+yJ1X7nVvrA2w
         hAvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767966216; x=1768571016;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=eFUHCHSQ+CPisZZ7HEm1yVSod2RMcmuWbAqil56EGTU=;
        b=QGGIVFbBLN6/vzys/9VsJSKgFZLNnbSQMpWGXV6EARDFH6m89XG7IVDRDA65quK+5P
         TYwu/KsTwX7UzYxe5mx47JgD/gWI2KzPukTuhY6WRKPZekwvufAQQmn/T5CIMbALFOYC
         FzWCXPXrl1mnXLFAWKD1lYsJphlFg4cdQDsK/DTTk244JVA0YAPui0h2IQmPMnTUgtcS
         FefIkaYcjJr/Dk47u4s17wPXFAB4ft32M9PYKMhIA5Lkixswg9dcXW8hDsuQH9yVDVLq
         rSC7lu6A69r8FI+NBK9L3GJIm0st/laXQ/gRJmRn0tDSlXCSZcUPnBfZ8h0RInF9Jj5j
         kkFA==
X-Forwarded-Encrypted: i=2; AJvYcCWHbct1UzfuMKdDv3A9A8DwP+z/LE8etBjWYkiRtHGs0v7lwDmP2E9oVZqPPXOBqRq+MhYUlw==@lfdr.de
X-Gm-Message-State: AOJu0YwoA46YM0d6q2A5ql1onE1iKF2DVk4N2xlDuwWWkfOtVRLrLH7I
	otevnSp2uL23pj/m77n263+Qc8A4+4WHr335BjWE+k13t7qGmkZjdGgw
X-Google-Smtp-Source: AGHT+IG9H/8QBzKQ78OaiGKI/hDq5UQEjC3HLEgP7xadHy5Itxt0vmQAZmLUZhVTtVYqIyxu3c5FGg==
X-Received: by 2002:a05:6214:19eb:b0:88a:51ff:6054 with SMTP id 6a1803df08f44-890840e8102mr108797486d6.0.1767966216087;
        Fri, 09 Jan 2026 05:43:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EVtdSKtdcGI6M5436anMycRB0z2ig+1O83V3Dyao7+Pg=="
Received: by 2002:a05:6214:2407:b0:888:1f20:6a87 with SMTP id
 6a1803df08f44-89075545796ls47955086d6.0.-pod-prod-04-us; Fri, 09 Jan 2026
 05:43:35 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW1SYN8EuvHIwqYVghAKOChz2RiuJOZlExyVTXgXcW/yDwIv1tdPeDMYVXH4iSn/q64yVPl2z7f7uc=@googlegroups.com
X-Received: by 2002:a05:6102:2b8c:b0:520:dbc0:6ac4 with SMTP id ada2fe7eead31-5ecb5cbbd4fmr4490916137.2.1767966215292;
        Fri, 09 Jan 2026 05:43:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767966215; cv=none;
        d=google.com; s=arc-20240605;
        b=iEqEMVJeCklAlFvyxqUDFlE7+QR8qjTrynTRJiAi91CElxiuMe2dcqAi7Eo43Re4tO
         5BDLBDMP5XNYAJ8dF4xuuiYd+fi1ycAA0RaJGTu2BAylc40KHut0Yr53Rd3J9YIAFeAB
         wjj8Q/fuZ3ekxsx8SE6sJmi0Z6QF3/l8VxKQ43eavFNl7zeFYpLRd/vI+3Z5LUSxEiMX
         aNp61QS2c2Tg2zLwvJlMdEtEsyIL5heY60hwHivQElORSuzvPZxNznXDY/Df1gn0Bvpa
         98jdxEchlAKrpprMZKxqW+uJ+WhiQvqZkup4cBsCnr/3JKKQNaX8fiElhqeVCd9BrDfa
         Qc2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=FWIjlFv6jJqppx2LoyUbbHVPgKacvPuyCBOajXnJvKU=;
        fh=0klHsykIlYA0L02PWevGOvSi1jbl2pNEFV7/5iwQ0Zw=;
        b=PoADvseGSrTvqXXYPXJuGgUmcvuSRVNR7MQTLlYzHLfuLEzCyaCFOCbmAuHyR0/uqR
         8fZjA50ofuzQPAxPDfRFgy99ek5hSq0ZTHRQVszfvGnH3mdZO0tb8xP4YAfhHcvPjUWT
         HPgCdQY6O2nN93rYH9nLK9ZNQKGNpra+uuiMUIAU7aqinV6reCDL2P6uKI63mzdeaonC
         2jfF5GVXTulbS8YqAuAfRD9+irOUzZhdXrARitJ/M+uwMzBFojF7fBy8t2CC6b8wHY7v
         Wl6hbIbyTOrrRAsFAMTRYdurzTE2Oh5Y5pqjg6jNkFEjGorSsHKwXSR6RBSYcSNgURnN
         YTBw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jq8+HDoW;
       spf=pass (google.com: domain of will@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-5ef9a7a41b1si49000137.2.2026.01.09.05.43.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 09 Jan 2026 05:43:35 -0800 (PST)
Received-SPF: pass (google.com: domain of will@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 4A75D40539;
	Fri,  9 Jan 2026 13:43:34 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4A0C6C4CEF1;
	Fri,  9 Jan 2026 13:43:29 +0000 (UTC)
Date: Fri, 9 Jan 2026 13:43:25 +0000
From: "'Will Deacon' via kasan-dev" <kasan-dev@googlegroups.com>
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	David Hildenbrand <david@redhat.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>,
	Suren Baghdasaryan <surenb@google.com>,
	Michal Hocko <mhocko@suse.com>,
	Samuel Holland <samuel.holland@sifive.com>,
	Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org
Subject: Re: [PATCH v7 02/15] kasan: arm64: x86: Make special tags arch
 specific
Message-ID: <aWEF_eJ9Bnn5-8dZ@willie-the-truck>
References: <cover.1765386422.git.m.wieczorretman@pm.me>
 <0db7ec3b1a813b4d9e3aa8648b3c212166a248b7.1765386422.git.m.wieczorretman@pm.me>
 <aV_v18YWCHXMETVK@willie-the-truck>
 <aWEDDjQms8zbMgsB@wieczorr-mobl1.localdomain>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aWEDDjQms8zbMgsB@wieczorr-mobl1.localdomain>
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=jq8+HDoW;       spf=pass
 (google.com: domain of will@kernel.org designates 172.234.252.31 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Will Deacon <will@kernel.org>
Reply-To: Will Deacon <will@kernel.org>
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

On Fri, Jan 09, 2026 at 01:37:49PM +0000, Maciej Wieczor-Retman wrote:
> Hi, and thanks for looking at the patches!
> 
> On 2026-01-08 at 17:56:39 +0000, Will Deacon wrote:
> >On Wed, Dec 10, 2025 at 05:28:43PM +0000, Maciej Wieczor-Retman wrote:
> >> From: Samuel Holland <samuel.holland@sifive.com>
> ...
> >> +#ifdef CONFIG_KASAN_HW_TAGS
> >> +#define KASAN_TAG_MIN		0xF0 /* minimum value for random tags */
> >> +#define KASAN_TAG_WIDTH		4
> >> +#else
> >> +#define KASAN_TAG_WIDTH		8
> >> +#endif
> >
> >Shouldn't this be 0 when KASAN is not in use at all?
> >
> >Will
> 
> This file (as well as the x86 version) gets included in
> include/linux/kasan-tags.h:
> 
> 	#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
> 	#include <asm/kasan-tags.h>
> 	#endif
> 
> 	#ifndef KASAN_TAG_WIDTH
> 	#define KASAN_TAG_WIDTH		0
> 	#endif
> 
> So the 8 or 4 value is only assigned if SW_TAGS or HW_TAGS are enabled.
> Otherwise it's set to zero.

Thanks for the explanation, I'd missed the conditional inclusion of the
arch header.

In which case, the arm64 side looks fine to me:

Acked-by: Will Deacon <will@kernel.org>

Cheers,

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aWEF_eJ9Bnn5-8dZ%40willie-the-truck.
