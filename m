Return-Path: <kasan-dev+bncBCZKRZXNVMJBB36RT25QMGQEHD4QPNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id D8BAA9FA420
	for <lists+kasan-dev@lfdr.de>; Sun, 22 Dec 2024 06:51:45 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id 4fb4d7f45d1cf-5d3eceb9fe8sf2894154a12.3
        for <lists+kasan-dev@lfdr.de>; Sat, 21 Dec 2024 21:51:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1734846705; cv=pass;
        d=google.com; s=arc-20240605;
        b=YSRGfM+EZDxmomKfG/b9VS8aOBt+P8PsEqp06lyMYaAluz5wPkJWLtCYMx8O66nZK/
         rApznZTv+75+oHJBO+wGMgY30HiGjK9AauUuzcr40fre7z+cIGVWha0C0Issd8p4T74K
         Alvg7v4ryqKGV3arIf8/YWgnhpwsntEYplAINrLWYKRbQ5iLSBuLcuCHu+P8Z1cK0wUH
         +tH+pvICKJGyPakEKorJ47MrGzMwl+MxEv/oBLxFVPouV2ht1gu5GdSOeQLf9fUp4cGK
         0l3UZ7EMgtWcX0I+hLumPQZP8X2A46fw1XA8eGlP/q/e/7B7HZ0YOw3mjlOYrwlr3zA8
         HtLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:user-agent
         :references:in-reply-to:date:cc:to:from:subject:message-id
         :dkim-signature;
        bh=poE7bE8FRqlUjwzzJrjnZNM63s3mjnTnYsxhvfkRTBw=;
        fh=rM3PdoCRKUP9nYYwZ1s2LZW1lU4BkOgAHV1m/GWwaic=;
        b=B0Be34aFpBLHA76+1kLPg1ZY9naFoQ3TpnT42dXFNOk1bBFf1ngvwMMPAGQyhtEzE9
         6HaSrXxF4pja7xZJuaGmutFrd3H6cv7QCSA2JNhar1fpZilMsbk2el9IntPBKNfhLAsT
         04vIHEvfZEz1hLXBD7dajZEpNleKrxzNoAKxMvSiOLsueUzWT7jXlwxfYlNFe4kPe/G9
         Lu6i/FcJpU2sQKIaL2Fmj9ljBv8FHPlo08FRyn3Tz10tqt4An0anaFZA0j+BtIQ7rXMW
         V2ymGKP04FOT5vsC5CjrvSVrRhDL4K69rZam2XutYZeTS1Mo+4k1Ym7w78gl+tYt7G9t
         ssAg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@xry111.site header.s=default header.b=nZcUQW1T;
       spf=pass (google.com: domain of xry111@xry111.site designates 89.208.246.23 as permitted sender) smtp.mailfrom=xry111@xry111.site;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=xry111.site
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1734846705; x=1735451505; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:date:cc:to:from:subject
         :message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=poE7bE8FRqlUjwzzJrjnZNM63s3mjnTnYsxhvfkRTBw=;
        b=tc0TjnbMIc7udVa1NPuuExdzDD+hWl9ByMy9BNeWVSYKTKJWk681Fd14DLzs8Q7nMn
         c7ug/6GBYxV9eFheROeC84ixCYlo6OTrIwbEbqPHIx8QCmF0xXjM77SreDWAX4/cERcp
         78oCwkPHoh0lNE48/8VFaHI1+bvqSr5lv76uM4CeYkoHatDcPfl6+nVw+KHGio512cSW
         MXdtJsC6kpLZl4jorxDfqM2LGs50mdvz4CyG6CXjq4CFaQWTpONy3QxE8whihVuBv6CT
         4dJaUpWR8nfTYBSGmlj09Gvou698vGAS7pJRgkYPeybaNf/tQj/cTwcp1OPCtJFFpPgq
         ercA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1734846705; x=1735451505;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:date:cc:to:from:subject
         :message-id:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=poE7bE8FRqlUjwzzJrjnZNM63s3mjnTnYsxhvfkRTBw=;
        b=VzhFI732EIDGF7yNDPvtgFj6CGqlu0nTPN911eysZFpceGRnAVYy5sHpZWoq2d5tDE
         62B4eO1PFaEZ7zSpGitICJAwkUjggM7EwCHRnjDSDHRC5NNRohkweUIx+NBg2U/Fjmf2
         7UGcDIJSRRZVt3vXRxJYYCMctfyHnhmer0qe/sZfpkSLB5X42VENzbKICMVqSns55mrD
         C1GX+zYa9Zd0vlhgao5dx3iSfeoMxWGq2VAI4bkcSLe1NbIxqYnUUwcGos9j1qUu0Xxr
         qbyjDeas37LfvtZ4yi0RWGW2PlCCYUvnNCassvUcR4+fpuG1m0+d6p8g/+BgHqJW3Oau
         qe4Q==
X-Forwarded-Encrypted: i=2; AJvYcCVF7IrIueNeeJHdCbfTif/rarhfODb7zZ+omhXSq8Rp5NGzq+QHa9TrLyd6Z9l/Gdhy1FW2Ug==@lfdr.de
X-Gm-Message-State: AOJu0Yw/+sY1vLZUMUsqR8w7l3QqRwFX6pa5+pNmUJ9B9YU+6kIzV1MJ
	VMpIEnim1dqJM6wNLztYfapgg8nZfwDVPu1N60RZqLnOE3Ho29UO
X-Google-Smtp-Source: AGHT+IEQ+RgOzJ4s2AMSMVzq1DnTbJVmhwc2cYFAZhJXFr7FonfyKrkNOyCLt3iVdGJAiZSZivr5pg==
X-Received: by 2002:a05:6402:5255:b0:5d3:cfd0:8d4b with SMTP id 4fb4d7f45d1cf-5d81de38c45mr7102229a12.33.1734846703941;
        Sat, 21 Dec 2024 21:51:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:9e66:0:b0:5d0:d5d6:eb6e with SMTP id 4fb4d7f45d1cf-5d8025a6c66ls98484a12.1.-pod-prod-07-eu;
 Sat, 21 Dec 2024 21:51:41 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWy/W70Rk5yr1cVVq+XtexgFLTKEtJIRU8Hlz8k9eXbmd32CqL2yy6pM8B0YzGii0xBerHPBhlotVI=@googlegroups.com
X-Received: by 2002:a05:6402:3224:b0:5d4:34a5:e2f4 with SMTP id 4fb4d7f45d1cf-5d81de38bdfmr7839657a12.31.1734846701493;
        Sat, 21 Dec 2024 21:51:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1734846701; cv=none;
        d=google.com; s=arc-20240605;
        b=ORyhzB2umeun/dQR0WYlSJJWCT3WOIo49wsTWhgJRSCFZ8N83vkrgMwk9Wp2/VMkVZ
         VCe5OYQAEliwL+SH347X4wF68Wd6tUJrHInZOv8bbCtgJC+0mC5hbGpUCyJAC4hMFnHf
         M9CWEABywFq0ppqs2iFrRKbQAGS1Supoglwh3rU0nqB1WGCCtM8VGnPvEK0oSkv8UusH
         fVSwfVjTJkjV/2/yqLpv01NCBGKcIRUcIVqczkTLU/aGDW/n9zn75Ozq8yYAy8YYkmOg
         F4p1t+vt63A8UmJtZ6vegoAhK8elWaS7YlS83SZCndmAZ7L7AW18pUWSu4eBMpvy2uho
         9M1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=73Spy65y75EOyPTSc0iJv9YfbS1W2aMnBGueFT4LSeE=;
        fh=EctJlecwkpLxxQ+i3ZVelo6Lqll0fP7CAgERK0ArqmM=;
        b=T3Q0CL83ObXvlbCRBzWwxt9UwCbDwLfyffJSkKu7EQnThsRosi/ruhoSVpLE4tep6n
         oLW/eMzu8wBydjTlmnSDxBTCnIw1O9k2hWwmuv/iWfSK2A+eJT4JmVbppi88+6en4Gqy
         bfYJyTWAQPLJrji4XWhA9eoIR5l1rqKjEuwnyt0xhmMrxUjUhOfUK6jc44oI8lHFF1w8
         n88eagYFZjeGFDiDvU+EhAH/PdYz0ButkTVHa+Sw5qP7UH2s0RK3hH83nhfru7meRome
         aUjF/vtrheP7ovsXh8ULibt8eiGAEzt7zoBxiE7MmTRx3ClM7pZyBw4ugXneqj+0J02c
         i8Og==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@xry111.site header.s=default header.b=nZcUQW1T;
       spf=pass (google.com: domain of xry111@xry111.site designates 89.208.246.23 as permitted sender) smtp.mailfrom=xry111@xry111.site;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=xry111.site
Received: from xry111.site (xry111.site. [89.208.246.23])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5d80677ca54si108967a12.2.2024.12.21.21.51.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 21 Dec 2024 21:51:41 -0800 (PST)
Received-SPF: pass (google.com: domain of xry111@xry111.site designates 89.208.246.23 as permitted sender) client-ip=89.208.246.23;
Received: from [192.168.124.9] (unknown [113.200.174.52])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (prime256v1) server-signature ECDSA (secp384r1))
	(Client did not present a certificate)
	(Authenticated sender: xry111@xry111.site)
	by xry111.site (Postfix) with ESMTPSA id 16E7F1A3FB1;
	Sun, 22 Dec 2024 00:51:09 -0500 (EST)
Message-ID: <02d042a6590ddb1fadb9f98d95de169c4683b9e7.camel@xry111.site>
Subject: Re: [PATCH v6] mm/memblock: Add memblock_alloc_or_panic interface
From: "'Xi Ruoyao' via kasan-dev" <kasan-dev@googlegroups.com>
To: Guo Weikang <guoweikang.kernel@gmail.com>, Andrew Morton
	 <akpm@linux-foundation.org>, Mike Rapoport <rppt@kernel.org>, Geert
 Uytterhoeven <geert@linux-m68k.org>
Cc: Dennis Zhou <dennis@kernel.org>, Tejun Heo <tj@kernel.org>, Christoph
 Lameter <cl@linux.com>, Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
 Sam Creasey	 <sammy@sammy.net>, Huacai Chen <chenhuacai@kernel.org>, Will
 Deacon	 <will@kernel.org>, Catalin Marinas <catalin.marinas@arm.com>,
 Oreoluwa Babatunde <quic_obabatun@quicinc.com>, rafael.j.wysocki@intel.com,
 Palmer Dabbelt <palmer@rivosinc.com>,  Hanjun Guo <guohanjun@huawei.com>,
 Easwar Hariharan <eahariha@linux.microsoft.com>, Johannes Berg	
 <johannes.berg@intel.com>, Ingo Molnar <mingo@kernel.org>, Dave Hansen	
 <dave.hansen@intel.com>, Christian Brauner <brauner@kernel.org>, KP Singh	
 <kpsingh@kernel.org>, Richard Henderson <richard.henderson@linaro.org>,
 Matt Turner <mattst88@gmail.com>, Russell King <linux@armlinux.org.uk>,
 WANG Xuerui <kernel@xen0n.name>,  Michael Ellerman <mpe@ellerman.id.au>,
 Stefan Kristiansson <stefan.kristiansson@saunalahti.fi>, Stafford Horne	
 <shorne@gmail.com>, Helge Deller <deller@gmx.de>, Nicholas Piggin	
 <npiggin@gmail.com>, Christophe Leroy <christophe.leroy@csgroup.eu>, Naveen
 N Rao <naveen@kernel.org>, Madhavan Srinivasan <maddy@linux.ibm.com>, Geoff
 Levand	 <geoff@infradead.org>, Paul Walmsley <paul.walmsley@sifive.com>,
 Palmer Dabbelt	 <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>,
 Andrey Ryabinin	 <ryabinin.a.a@gmail.com>, Alexander Potapenko
 <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
 <dvyukov@google.com>, Vincenzo Frascino	 <vincenzo.frascino@arm.com>, Heiko
 Carstens <hca@linux.ibm.com>, Vasily Gorbik	 <gor@linux.ibm.com>, Alexander
 Gordeev <agordeev@linux.ibm.com>, Christian Borntraeger
 <borntraeger@linux.ibm.com>, Sven Schnelle <svens@linux.ibm.com>, Yoshinori
 Sato	 <ysato@users.sourceforge.jp>, Rich Felker <dalias@libc.org>, John
 Paul Adrian Glaubitz <glaubitz@physik.fu-berlin.de>, Andreas Larsson
 <andreas@gaisler.com>, Richard Weinberger	 <richard@nod.at>, Anton Ivanov
 <anton.ivanov@cambridgegreys.com>, Johannes Berg	
 <johannes@sipsolutions.net>, Thomas Gleixner <tglx@linutronix.de>, Ingo
 Molnar	 <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen	
 <dave.hansen@linux.intel.com>, x86@kernel.org, linux-alpha@vger.kernel.org,
 	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, 
	loongarch@lists.linux.dev, linux-m68k@lists.linux-m68k.org, 
	linux-mips@vger.kernel.org, linux-openrisc@vger.kernel.org, 
	linux-parisc@vger.kernel.org, linuxppc-dev@lists.ozlabs.org, 
	linux-riscv@lists.infradead.org, kasan-dev@googlegroups.com, 
	linux-s390@vger.kernel.org, linux-sh@vger.kernel.org,
 sparclinux@vger.kernel.org, 	linux-um@lists.infradead.org,
 linux-acpi@vger.kernel.org, 	xen-devel@lists.xenproject.org,
 linux-omap@vger.kernel.org, 	linux-clk@vger.kernel.org,
 devicetree@vger.kernel.org, linux-mm@kvack.org, 	linux-pm@vger.kernel.org
Date: Sun, 22 Dec 2024 13:51:08 +0800
In-Reply-To: <20241222054331.2705948-1-guoweikang.kernel@gmail.com>
References: <20241222054331.2705948-1-guoweikang.kernel@gmail.com>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.54.2
MIME-Version: 1.0
X-Original-Sender: xry111@xry111.site
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@xry111.site header.s=default header.b=nZcUQW1T;       spf=pass
 (google.com: domain of xry111@xry111.site designates 89.208.246.23 as
 permitted sender) smtp.mailfrom=xry111@xry111.site;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=xry111.site
X-Original-From: Xi Ruoyao <xry111@xry111.site>
Reply-To: Xi Ruoyao <xry111@xry111.site>
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

On Sun, 2024-12-22 at 13:43 +0800, Guo Weikang wrote:
> Before SLUB initialization, various subsystems used memblock_alloc to
> allocate memory. In most cases, when memory allocation fails, an immediate
> panic is required. To simplify this behavior and reduce repetitive checks,
> introduce `memblock_alloc_or_panic`. This function ensures that memory
> allocation failures result in a panic automatically, improving code
> readability and consistency across subsystems that require this behavior.
> 
> Signed-off-by: Guo Weikang <guoweikang.kernel@gmail.com>
> ---


Please try to avoid bumping the patch revision number so quickly.

And if you must do it, you should embed a ChangeLog of your patch (below
this "---" line) so people can know what has been changed.

-- 
Xi Ruoyao <xry111@xry111.site>
School of Aerospace Science and Technology, Xidian University

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/02d042a6590ddb1fadb9f98d95de169c4683b9e7.camel%40xry111.site.
