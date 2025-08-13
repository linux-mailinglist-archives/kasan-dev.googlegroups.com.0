Return-Path: <kasan-dev+bncBDBK55H2UQKRB66Y6LCAMGQED6APNJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A83EB24D09
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 17:17:17 +0200 (CEST)
Received: by mail-ed1-x53e.google.com with SMTP id 4fb4d7f45d1cf-61865148a8fsf967257a12.2
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 08:17:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755098236; cv=pass;
        d=google.com; s=arc-20240605;
        b=d5r5xiv/Fx/MnFWdu94XX9NLjoFybrMyTWpq+WecikKbe1zvET6vR2PZ1HPz1MNujB
         5WYXSzcRbE4QEd6oQAuQ267gA6+NzJdHjEh8P83A5uzy7/HVmKmyNQW8bVpoy+stYdYd
         YiEgz7lciclEpPQLXGMWgdgwhZLxvAjjgLQFoZf50MDoZauzWipTHBRe3rH4LkXeroAG
         IWkGrgQoBqm6hxcrU2ybcL6c8pmIEKz4HXDj/hCm8zPgjSNlgCggem9TZr9RBn+M1N1N
         mSoCJVzZ1Afrf+LtTwOl8oNBu+/9UD4lMRiq2+XhDXHhmmCrDeM7cInfIL6HQ0kUqL9D
         7Ieg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=CiS6aski1bzLqw96hDJvBthJAIfxVDDlHuXTKGfrEgE=;
        fh=xYYKzJa/zxqmd8ZX6WoOYVjwRRBbYe8Q+U/vW73iw0s=;
        b=PCYcL6hny4ZZM0+UXj9Cewbmt8bviU5tS2kqKtJNiUoVNIUiBi/TXBY9dMqqXP82Pf
         s1x9fANK1imyxCeH2JvNlPee84OZzkVOEsYYGn7DypGl3p4GXPdCB9ji/BcVB/EV7BcP
         htF3nHLBdL2R/O2+DwG3y4gHLAx4XEUfA+p2eSXpWcwvuse9J9r64xwIA/3S3t/BbqYA
         B2Kq7y5V7pyaD4Q+DZcmk5PjtXLfiZt5B4Kw0+z6UHO5/wW7YR45O0XGISXdVSkRM/xJ
         hAqGd+9vzzIaJ1Hrt1beA2IkI9fIIkksznC5jTWXMf1vm9LEBzhbbEt6oGz9fTTFOYgb
         ID7w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=WxLyCH8i;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755098236; x=1755703036; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=CiS6aski1bzLqw96hDJvBthJAIfxVDDlHuXTKGfrEgE=;
        b=HMufdeShOE+HlonmPq8ySMfJi0wIdTO65hT5rtKlJcxc8Aj7BAAl8vangj6oVVJud2
         nqsRigXGSjwXOswimRXd0KhU2YDmfE/0qxQL2TxWwhdNWm83zGzoHC4bNk2mpU490CjQ
         uXNjmopr3+vAsTw6iI2KBE917d4VHqyK01JySqxkatj3n0LSkDnNJYZ5zL06pAaZ2yqI
         nQbFKB3UTWGBQFmkBJx4OXFevr5QTTw3++hSvIQ8wpkmHclSpk323LbVvXtPg1Gl+6sV
         PtN9myrn+8GOrIPBVOD+PrnotBRotFSCDAmdGKVa2HPlWy61O72jXf690P2MK8ZhBsmm
         kX4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755098236; x=1755703036;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=CiS6aski1bzLqw96hDJvBthJAIfxVDDlHuXTKGfrEgE=;
        b=Usee7FPZ3fiAIO7MbQNRkP7FPwHdzUVlrBQ1IU2lPn/k83cr0ndOw2Eg5xFi0Fh3EM
         6O6VpzYg6aWWmNX/6eRGD2yeBL9xt/QO+R/kcQepCVM1ajvQvFNaT0Ws1Nztq2s6JaxC
         CNQ0d29XKfUfPCaK+/s4pgdOMHeAbEYdU7IUV4w2B913Gk54Fu3bPva8UDIybHGvOM02
         irO1JE1PCldziuBH3tbNaP8EtjZS/Z/hZYGzYlKdDykSAfUuRfdt0vtCFcf1j+72Ibde
         J1Xv5CC0M3fDc/nWPfekPeMSsoHjUkXXLZgRPPAsvmiiIRImag5GXhyb1zACsf5ZEf4k
         GPMA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXsNruc8jndyVjKhvf2+mEOmVmtLttthqsC4z59f7eEXAxoZnX9gWXPQGavv0638pj85Bx87w==@lfdr.de
X-Gm-Message-State: AOJu0YxIXoWWTxDi3TiCWx3tTE4yEM3b6XT379O+HNIu1pYfU1mp58yB
	yWVAwTQ8awnG3Q1UMts+Zj4goAiAXSiir7Hr8rZ/4+TIbw8/K0JKrvgA
X-Google-Smtp-Source: AGHT+IF9q3EO2BqafsC+NW6Xrb4RwswMgvUsF88ksLn+QQphtiQnqlpSxNbEqzrRCZl/9tTeAeanDA==
X-Received: by 2002:a05:6402:5108:b0:617:b28c:e134 with SMTP id 4fb4d7f45d1cf-6186b4b828bmr2757178a12.0.1755098236217;
        Wed, 13 Aug 2025 08:17:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeRp8ahYuA9uWa2w457OLgc1PbxQYCF8A6FelKTgY9xmA==
Received: by 2002:a05:6402:46c7:b0:618:8825:4bd with SMTP id
 4fb4d7f45d1cf-6188825056dls138807a12.2.-pod-prod-02-eu; Wed, 13 Aug 2025
 08:17:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVBM4Evm3rBcU5TmDl4pUsjLI9QnO820Ghtfhds94Kv6I0s6GA0LUIwYSpiIQwtdBGy63BgVNSZucI=@googlegroups.com
X-Received: by 2002:a17:907:7b9e:b0:af6:3194:f024 with SMTP id a640c23a62f3a-afca4d09bd1mr283388666b.13.1755098233257;
        Wed, 13 Aug 2025 08:17:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755098233; cv=none;
        d=google.com; s=arc-20240605;
        b=luBsExs+2F+fLHHhqG+qdeF1q3WWZ6DpC8Gcm759/axOZSuTIpOmcHLJD1aMlnk67p
         U1Kpgfk+zWN0LvBdneSJhCWlotCeZjd4Ww+NlWloJV/fLgIy5gDoCIcpZhfnR0SQBNjb
         HEtWKwfvAbn/NxE8N5FaFZU1NdyF2s/UEP/UPdq2hBSlsxWTZ71Gq3zQQdasyf1GxJpW
         HSo04ikyPw+9QZcq/8RZeWLXv5nlzgXnz/eFIUSNNW7O/USC5TNA/DoxRlIuSB/IcnO7
         lmQQU4sHfCPQ02GIAU2Cmmhjnl1a7uiKeLwgVDVqoFkEY4mNx03CEdMaKIsGkHYBfNIg
         Ubgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=pNSPGI3nahSLz3vSSHU/GM73uUfkJwp5wjG48WP8eNs=;
        fh=/VQt35BaQ4BGPRlk/c/1bxVgilIVwwPQ7yAE8MRtwj8=;
        b=lQ//mQtlJFbwFtsTB8X+JLFQut7yD1OAcBgz3571WY8QevHWqmzS4e5In4a4a2PMw8
         Bl/vq2Y5cUoj/mI1wUC2AfrdRHNM/n5wkFqQjEJxwVxZTzrpo/pOOpmEjJG+6u0jkZiX
         xVAaZzQaNwwNSOGY2HuUPG9aNfzwf8oOpY0oN3F0nQsBKCEFiywW9qX0tJc40V0iHqP2
         Ztc+J76ykLHJKrlqrFiFBEXJ/EKzjXMJ8cwuxmpz9o4TgKC4B/gSpv2N4HpokfZy+XJn
         hqxmdaT0mrvctOwzAg1XKMqEWeDILJhIW8rerWgwDudzuJCmDZlpuEb/44XCyN+HzsZN
         PUNw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=WxLyCH8i;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-af91a0c4398si69623866b.1.2025.08.13.08.17.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Aug 2025 08:17:13 -0700 (PDT)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1umDDr-00000009rE7-0bsA;
	Wed, 13 Aug 2025 15:17:04 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id C17623001D6; Wed, 13 Aug 2025 17:17:02 +0200 (CEST)
Date: Wed, 13 Aug 2025 17:17:02 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: nathan@kernel.org, arnd@arndb.de, broonie@kernel.org,
	Liam.Howlett@oracle.com, urezki@gmail.com, will@kernel.org,
	kaleshsingh@google.com, rppt@kernel.org, leitao@debian.org,
	coxu@redhat.com, surenb@google.com, akpm@linux-foundation.org,
	luto@kernel.org, jpoimboe@kernel.org, changyuanl@google.com,
	hpa@zytor.com, dvyukov@google.com, kas@kernel.org, corbet@lwn.net,
	vincenzo.frascino@arm.com, smostafa@google.com,
	nick.desaulniers+lkml@gmail.com, morbo@google.com,
	andreyknvl@gmail.com, alexander.shishkin@linux.intel.com,
	thiago.bauermann@linaro.org, catalin.marinas@arm.com,
	ryabinin.a.a@gmail.com, jan.kiszka@siemens.com, jbohac@suse.cz,
	dan.j.williams@intel.com, joel.granados@kernel.org,
	baohua@kernel.org, kevin.brodsky@arm.com, nicolas.schier@linux.dev,
	pcc@google.com, andriy.shevchenko@linux.intel.com,
	wei.liu@kernel.org, bp@alien8.de, ada.coupriediaz@arm.com,
	xin@zytor.com, pankaj.gupta@amd.com, vbabka@suse.cz,
	glider@google.com, jgross@suse.com, kees@kernel.org,
	jhubbard@nvidia.com, joey.gouly@arm.com, ardb@kernel.org,
	thuth@redhat.com, pasha.tatashin@soleen.com,
	kristina.martsenko@arm.com, bigeasy@linutronix.de,
	lorenzo.stoakes@oracle.com, jason.andryuk@amd.com, david@redhat.com,
	graf@amazon.com, wangkefeng.wang@huawei.com, ziy@nvidia.com,
	mark.rutland@arm.com, dave.hansen@linux.intel.com,
	samuel.holland@sifive.com, kbingham@kernel.org,
	trintaeoitogc@gmail.com, scott@os.amperecomputing.com,
	justinstitt@google.com, kuan-ying.lee@canonical.com, maz@kernel.org,
	tglx@linutronix.de, samitolvanen@google.com, mhocko@suse.com,
	nunodasneves@linux.microsoft.com, brgerst@gmail.com,
	willy@infradead.org, ubizjak@gmail.com, mingo@redhat.com,
	sohil.mehta@intel.com, linux-mm@kvack.org,
	linux-kbuild@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	x86@kernel.org, llvm@lists.linux.dev, kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v4 13/18] kasan: arm64: x86: Handle int3 for inline KASAN
 reports
Message-ID: <20250813151702.GO4067720@noisy.programming.kicks-ass.net>
References: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
 <9030d5a35eb5a3831319881cb8cb040aad65b7b6.1755004923.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <9030d5a35eb5a3831319881cb8cb040aad65b7b6.1755004923.git.maciej.wieczor-retman@intel.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=WxLyCH8i;
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org
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

On Tue, Aug 12, 2025 at 03:23:49PM +0200, Maciej Wieczor-Retman wrote:
> Inline KASAN on x86 does tag mismatch reports by passing the faulty
> address and metadata through the INT3 instruction - scheme that's setup
> in the LLVM's compiler code (specifically HWAddressSanitizer.cpp).
> 
> Add a kasan hook to the INT3 handling function.
> 
> Disable KASAN in an INT3 core kernel selftest function since it can raise
> a false tag mismatch report and potentially panic the kernel.
> 
> Make part of that hook - which decides whether to die or recover from a
> tag mismatch - arch independent to avoid duplicating a long comment on
> both x86 and arm64 architectures.
> 
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>

Can we please split this into an arm64 and x86 patch. Also, why use int3
here rather than a #UD trap, which we use for all other such cases?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250813151702.GO4067720%40noisy.programming.kicks-ass.net.
