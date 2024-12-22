Return-Path: <kasan-dev+bncBDOY5FWKT4KRBRGJT65QMGQEDRJWOPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 725A79FA51B
	for <lists+kasan-dev@lfdr.de>; Sun, 22 Dec 2024 11:07:02 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-2ef9b9981f1sf4559184a91.3
        for <lists+kasan-dev@lfdr.de>; Sun, 22 Dec 2024 02:07:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1734862020; cv=pass;
        d=google.com; s=arc-20240605;
        b=kx3kKcpPXDBRSmYUCEHHaR4CULskO1NV9ipZQKKwGkCcmCWQblNravCJAUQlj10Y2L
         +vDBLfhpZ48IGo9DJ587NyXf+SSXX79/2bI1RcolS1UlZM1v3SmhNlg94PR8VPERXYzF
         5Sw2n4kbPJqz/dWmZxT87QkfrJL4RVz1teO+IDyregjEAr6QE0+RiqjhaDN3ZdEdAsY+
         oGZOg8mvOP/kYs+BX0/Xk0dabavf3QT46T8pYU1tQiQF3oNXp48ckUX/er8keXBRHoS7
         FTt8OEzC5zuefOnpYrg/rQM6gZsNec4Y9navikC8WfsdUrIp8ZxXuZJjDJCSdhs/bGQ6
         lz5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=zHGI0IYPT+xRD/3uxpD3SI736Z3koLvXRMv1Ei52Y/c=;
        fh=AnPzz6q5xriUZCDGFmm4WHbCw4eg69v5WQ5NpZCeHR8=;
        b=S/YuUlQKkF0dBJV/oXOReTM6WY33m+n1e5FnGtammG0WhaXTwp49/VsUkJtaQBSp0A
         ZsZFn7GldK2Of6o3zRuvN4lHVAJ5qKDu76zVdobDbSOLb0rDt8LABwIMbDeTUewAeNFf
         3qY0vNxQUQkOWlFGJSS1pvSzghHXqx4hpJ7HaagWHBieTd5bTkpAJ2Uwq/jZSO0p8E25
         DiPukX6uW5CtaSgR61pEfMfPBdGTg0J4yk9DgMcm+D1smAWwPGcyhTIvr5CnR48/mupv
         CB6CyOz5KRvEKYDmT9jtDFXOdHIGtpibSHH1Owoy7nACcBHU9RvWZr7H+MOfNGRSnFPG
         Uk6g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=s3+eZLw2;
       spf=pass (google.com: domain of rppt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1734862020; x=1735466820; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=zHGI0IYPT+xRD/3uxpD3SI736Z3koLvXRMv1Ei52Y/c=;
        b=U+fvqqws7o5m5D/bm9/R8ZAoW86vqOjWifIQeBcg77d1KqfZ5fPNIm27yunQuiQDOS
         gkY8HTFY/oqUbzKUbWSz0FsYVP8HamZHSQUVw3z8stuEq5CZempEshsGLojCZ5282pge
         mn1oaIF1Pd8JKbES40/mG25Li1l5zt8c4eXGPCrFxoQLKpgPm8IqY8vGHLVRT8zk8SG0
         MxoxTrDX+3MPz767+ifCMkX3jyaDQqO7px/iIC6ANJx1Z8aMWbIAvN2vdgZ4d7YSnjp1
         im8BohQ71bKmsFRp5YtUTECdxykRk5Y0hoMds/sjgCDspW6WwLsjmeeUOL+G2muRhxzo
         u5fA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1734862020; x=1735466820;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=zHGI0IYPT+xRD/3uxpD3SI736Z3koLvXRMv1Ei52Y/c=;
        b=jxF8wHpgbEKyeckV/CByV3cBl+JASMRzplxRUYs7JQqacNHbqi6S69nCpVIRrlyuWX
         TEWKNe/0DjxpD15gIquqkgH7KzVNBjWFdU/N9OOQGv5ZJQicP8GCZec8rGUhO+Jhnt9s
         gVKivYBeseDx13zmmJCxKhYgpjNRyfib1CNY5/Hu8wkWiZXXnxMgn24fdr4+SH4rz9A6
         NmLMAXCym40WtrGFMsM2Xwb9GOFl1OK20NNz7gS08Wfp3vVejnb3uedH6fEdMtsfL5VK
         vH3TsLZZX1ur8Si5HdnupliSS+9pikQdOvCrGihxq/vCy+ix9m6+BEFZfu+qkQkq5hgg
         NkEg==
X-Forwarded-Encrypted: i=2; AJvYcCXBhpSQB8QFu8AqW5hiVI4D9rxK7+Me8HWLPkbYH8QwdlyGvx6jumKEKuYvV0mBNdp1RTB+Ew==@lfdr.de
X-Gm-Message-State: AOJu0YwxHlH9eEHk61E+RSlyNa7yAV3b/dyoho/eFsgOVM4jOVoUe18m
	XLbGFw3gPHUckcfHBAmDn1xvPC//Q07nProxre+qYKDr7MhLPffW
X-Google-Smtp-Source: AGHT+IE2OvMNsME5FDqP5Rg4b8F4jkfcRkpIRzfA+oyP7Sg36GG3LNUzgQPj4X75MljI2jWyCO521g==
X-Received: by 2002:a17:90b:3ccb:b0:2ee:b2e6:4276 with SMTP id 98e67ed59e1d1-2f452eb3788mr12889472a91.27.1734862020642;
        Sun, 22 Dec 2024 02:07:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:6d26:b0:2ee:edae:763 with SMTP id
 98e67ed59e1d1-2f442de68abls2293334a91.0.-pod-prod-06-us; Sun, 22 Dec 2024
 02:06:59 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUyR20xDgl57UpuPw0B6mcdqbJwPLsEUn/pfyN/aFLmlCvtYOeqGJ8sJfH1Se7gEcytgNw46KMOksY=@googlegroups.com
X-Received: by 2002:a17:90b:3ccc:b0:2ee:b8ac:73b0 with SMTP id 98e67ed59e1d1-2f452df9f10mr12954599a91.2.1734862019282;
        Sun, 22 Dec 2024 02:06:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1734862019; cv=none;
        d=google.com; s=arc-20240605;
        b=TP9ymU3ho/GzwhrVlouUM2B1MLz6lztmiA08wOBtdZlI9Nuf58V0Bhj+gLICT+bioM
         lvp8m6qoo286vqwPVsxIPtkE+f5mc2Dmfld4KVY4deh70kYoFhErLAx3a5I5w1RfyOC9
         odytPX2qlToV7Y54+6BTbsML0j7dxHlYi+zCoM3pmb8Qg2knKfyUl0QX6Jt/mO34CuyJ
         ZtFBXE0bN1m1wY2bGV3M3k76p+plMiEMzK45kMQhCaq48XhVyKYzrZXPR6nuXBzJD0KX
         Z0pP+79Flg5ofNR4ijvP1hkTh9CB/g7aWZJeWe4Z7o8AF+Zom/meYncXYNQRx0wmx9Np
         DrmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=+hFbeVZytTc7as3NSImfMf3crm19rt/Slw/x+P9Woiw=;
        fh=tGqoAiTlMTEo+sQKfNmP3kNjBDekxVPOTyrqWrdYUX0=;
        b=LbscqKs788scocomQGQJ/hMoK+sOY1jhXn9dIGwajggqXU46DBmuYNVsti8bwZbate
         3n2Q2yb1ubQ38F3mkmdESyBRLzFo8I/VAEWZrnhXIAbL/708731Wifefask6t3Lxk3wW
         pbbQNA9hPUwvClLtOU2mGO4Wr9QitXL/ZcbhuZOZc2tpmY0gfqw6YRrffn+hl4QVX3cw
         FBcljZ/O2ikGvyRv2QGDi85JcV1PtNRekdodX6Zgr4TKiJsGO74sCU5g2ziLCMnaJ8ij
         DxkLr1bZIHfcIcbLMjOa6QMJ1UNLnBvYSmR1Gq3XCQAIKrqqQ2jDzJlvnXaI0Ka5DI9X
         0zNg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=s3+eZLw2;
       spf=pass (google.com: domain of rppt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2f2d9dd490bsi551335a91.0.2024.12.22.02.06.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 22 Dec 2024 02:06:59 -0800 (PST)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 018E35C4689;
	Sun, 22 Dec 2024 10:06:16 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D7832C4CECD;
	Sun, 22 Dec 2024 10:06:32 +0000 (UTC)
Date: Sun, 22 Dec 2024 12:06:22 +0200
From: "'Mike Rapoport' via kasan-dev" <kasan-dev@googlegroups.com>
To: Guo Weikang <guoweikang.kernel@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Geert Uytterhoeven <geert@linux-m68k.org>,
	Dennis Zhou <dennis@kernel.org>, Tejun Heo <tj@kernel.org>,
	Christoph Lameter <cl@linux.com>,
	Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
	Sam Creasey <sammy@sammy.net>, Huacai Chen <chenhuacai@kernel.org>,
	Will Deacon <will@kernel.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Oreoluwa Babatunde <quic_obabatun@quicinc.com>,
	rafael.j.wysocki@intel.com, Palmer Dabbelt <palmer@rivosinc.com>,
	Hanjun Guo <guohanjun@huawei.com>,
	Easwar Hariharan <eahariha@linux.microsoft.com>,
	Johannes Berg <johannes.berg@intel.com>,
	Ingo Molnar <mingo@kernel.org>, Dave Hansen <dave.hansen@intel.com>,
	Christian Brauner <brauner@kernel.org>,
	KP Singh <kpsingh@kernel.org>,
	Richard Henderson <richard.henderson@linaro.org>,
	Matt Turner <mattst88@gmail.com>,
	Russell King <linux@armlinux.org.uk>,
	WANG Xuerui <kernel@xen0n.name>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Stefan Kristiansson <stefan.kristiansson@saunalahti.fi>,
	Stafford Horne <shorne@gmail.com>, Helge Deller <deller@gmx.de>,
	Nicholas Piggin <npiggin@gmail.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Naveen N Rao <naveen@kernel.org>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Geoff Levand <geoff@infradead.org>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Heiko Carstens <hca@linux.ibm.com>,
	Vasily Gorbik <gor@linux.ibm.com>,
	Alexander Gordeev <agordeev@linux.ibm.com>,
	Christian Borntraeger <borntraeger@linux.ibm.com>,
	Sven Schnelle <svens@linux.ibm.com>,
	Yoshinori Sato <ysato@users.sourceforge.jp>,
	Rich Felker <dalias@libc.org>,
	John Paul Adrian Glaubitz <glaubitz@physik.fu-berlin.de>,
	Andreas Larsson <andreas@gaisler.com>,
	Richard Weinberger <richard@nod.at>,
	Anton Ivanov <anton.ivanov@cambridgegreys.com>,
	Johannes Berg <johannes@sipsolutions.net>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	linux-alpha@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org, loongarch@lists.linux.dev,
	linux-m68k@lists.linux-m68k.org, linux-mips@vger.kernel.org,
	linux-openrisc@vger.kernel.org, linux-parisc@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org,
	kasan-dev@googlegroups.com, linux-s390@vger.kernel.org,
	linux-sh@vger.kernel.org, sparclinux@vger.kernel.org,
	linux-um@lists.infradead.org, linux-acpi@vger.kernel.org,
	xen-devel@lists.xenproject.org, linux-omap@vger.kernel.org,
	linux-clk@vger.kernel.org, devicetree@vger.kernel.org,
	linux-mm@kvack.org, linux-pm@vger.kernel.org
Subject: Re: [PATCH v6] mm/memblock: Add memblock_alloc_or_panic interface
Message-ID: <Z2fknmnNtiZbCc7x@kernel.org>
References: <20241222054331.2705948-1-guoweikang.kernel@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20241222054331.2705948-1-guoweikang.kernel@gmail.com>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=s3+eZLw2;       spf=pass
 (google.com: domain of rppt@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=rppt@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Mike Rapoport <rppt@kernel.org>
Reply-To: Mike Rapoport <rppt@kernel.org>
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

On Sun, Dec 22, 2024 at 01:43:31PM +0800, Guo Weikang wrote:
> Before SLUB initialization, various subsystems used memblock_alloc to
> allocate memory. In most cases, when memory allocation fails, an immediate
> panic is required. To simplify this behavior and reduce repetitive checks,
> introduce `memblock_alloc_or_panic`. This function ensures that memory
> allocation failures result in a panic automatically, improving code
> readability and consistency across subsystems that require this behavior.
> 
> Signed-off-by: Guo Weikang <guoweikang.kernel@gmail.com>
> ---

...

> diff --git a/include/linux/memblock.h b/include/linux/memblock.h
> index 673d5cae7c81..73af7ca3fa1c 100644
> --- a/include/linux/memblock.h
> +++ b/include/linux/memblock.h
> @@ -417,6 +417,12 @@ static __always_inline void *memblock_alloc(phys_addr_t size, phys_addr_t align)
>  				      MEMBLOCK_ALLOC_ACCESSIBLE, NUMA_NO_NODE);
>  }
>  
> +void *__memblock_alloc_or_panic(phys_addr_t size, phys_addr_t align,
> +				       const char *func);

Please align this line with the first parameter to the function.
Other than that

Acked-by: Mike Rapoport (Microsoft) <rppt@kernel.org>

> +
> +#define memblock_alloc_or_panic(size, align)    \
> +	 __memblock_alloc_or_panic(size, align, __func__)
> +
>  static inline void *memblock_alloc_raw(phys_addr_t size,
>  					       phys_addr_t align)
>  {


-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z2fknmnNtiZbCc7x%40kernel.org.
