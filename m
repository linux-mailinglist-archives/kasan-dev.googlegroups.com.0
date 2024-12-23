Return-Path: <kasan-dev+bncBCZKRZXNVMJBBPM4US5QMGQEG6ZKGFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id A59569FAAF6
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Dec 2024 08:16:15 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-5f06787ea2esf2747363eaf.1
        for <lists+kasan-dev@lfdr.de>; Sun, 22 Dec 2024 23:16:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1734938174; cv=pass;
        d=google.com; s=arc-20240605;
        b=lYU2PWW6ZuouEFh7fvX3/128N2x64Dn8CTuPbFDclBI1afQwYM9q6ScEFTVv5xGm7y
         F4EFOkQ401uxVq38XrWvdKqlunApUgcOyecS2htMdZvulX2vFXOa2h3zOIcUTXZsat0Z
         dsP5n4j58KhEqb0FFkMi0QvUx3ZO36fx01foMQj7XMCDN2bkM6p5sGFsfvGjWeB3HAsZ
         KhRAgyzp3gqZbkYnrLisRiVosRGA8B+DSpnWo3g/okaC6jHUwC4MMg7HR6Ted+ZcqewJ
         Zmd092dyzvExJjq847/RykeokkcbraeYsArLcev3BSzyZRlXSDpUf7WOO9cNHdbDmUqe
         RrkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:user-agent
         :references:in-reply-to:date:cc:to:from:subject:message-id
         :dkim-signature;
        bh=xwxrT7ndKytGn5e5G2unmYWDvjYl6EK631kZfpkCmrI=;
        fh=SqOQxG70D4+aPz7lrv/E76bN5Xf97UW1dqiGSYQTvHk=;
        b=OxJhtNMqPAVrlLWNPz/1He8YWxuDFn0aUNd0Cc0NmY4NStV9BeASgIcW9lSXd8Hk+o
         4iKQ+UDB9Bk4wGl7oWqylCgK3BmiHCkgjCOPMMEJ8G0Tcf4s7cyGNKkefnoCS+cFM3HS
         VBb5gXRgKHNK4fwnPlyKJQx3MnlE0V0SOKDEL9YBPrAzWQOamU6eHnsoLFBBvmIGntMi
         jdy0T1xQqztDIiSW/GRMxor3VBQ4ucI+iTj+7J1Kze1bsJ1Ck1GQEEgAEq2TRdRbuKgi
         zhSXwRPhiyrNwLvdIQ0C7dppO08RbbepvNeK6IYTb2Ht+4JaqF3YomTmLs7rBTea8y5r
         qKiQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@xry111.site header.s=default header.b=dYLhBand;
       spf=pass (google.com: domain of xry111@xry111.site designates 89.208.246.23 as permitted sender) smtp.mailfrom=xry111@xry111.site;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=xry111.site
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1734938174; x=1735542974; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:date:cc:to:from:subject
         :message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=xwxrT7ndKytGn5e5G2unmYWDvjYl6EK631kZfpkCmrI=;
        b=mx8Ykm5EddCh0kZNihmjk1Wi2RzPp1VwrkZTFMHdNKGCtlhMN5k9pdb1uU55tb+vw4
         PTW150+9JuqjgQOYS6bUkVrWFloFw818rWe2HV5XD3AelhHdPiI6+iclVMr7QGoW6tkH
         KiAn/3w+MnI4KyFrwGUyF+3jTGYeGk0IjzgckIKVpxdgImTQM0cJJGcULy35S7CmCm6R
         2wyAvBhKHbYQMjAnmn3+K1KRVI3FANg1AGF5CyVE2z0WdTa4GvpqnrS02MzlDOaAuzJq
         9dJ2l0b2DlSw57ewAV00TBZop11RfKdDuL3XgSOPxnShfeJo3iz/l9ufrAodlIWnAVdh
         JLIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1734938174; x=1735542974;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:date:cc:to:from:subject
         :message-id:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xwxrT7ndKytGn5e5G2unmYWDvjYl6EK631kZfpkCmrI=;
        b=Wu43p6RFE6dMk6CSY7Omug4tWrv+RdDuk1R4nj3AfzjqX3PiUgB6tQ/YvBV5AKvNdw
         Jd0mI3la1i1DRwExkCuhvU1xvqF3NJ6xvrTVoLGJFPuNN8J4Rk1OJQcpyGE3JlGOJfsU
         GBt2W6mLUd50jrHfO7Hk4gw18gDV5yEdQBwz8+0+F8LtDMnRISQxW1jM9Xz8vB7SMgfk
         wlrVIZvUy+I8AZCufEaPGFN7EWbtOWVtaiQquD71JHoyKXBMV5qtXaIX+9uBywwVE1KL
         J3RsoZRR4KObtbLKVMfckNxlKh/7h3XvuhL5zDb6Myvamekg8Vl1NEUEy4JFWFVaJkTx
         iDfg==
X-Forwarded-Encrypted: i=2; AJvYcCUtMbzoX5CccDdjS25iqlms/ALWlor6fo3v/A8Jv9YEA0hrWWp4UKTopR68v9t+xbT5BwiozQ==@lfdr.de
X-Gm-Message-State: AOJu0YzHJ0cQPNgnPVmWYGZAHSoh1UiOI0UaskU61ilot25gOdWzcLOo
	N65UzCfqRWiO9QkUWEXdyrzQP2nWIE9nAN8sPNMWRFbeH4m+Exua
X-Google-Smtp-Source: AGHT+IHt19ZqeDAnL+8xP/kH6wrpH7dsEWwoNQ4RM4AB1vPtcHNSdY00/M/5wjmjBX/xZwF744IDjw==
X-Received: by 2002:a05:6871:630e:b0:296:e698:3227 with SMTP id 586e51a60fabf-2a7fb3e1e99mr6316314fac.36.1734938173746;
        Sun, 22 Dec 2024 23:16:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:22c8:b0:29f:bc7e:8f4e with SMTP id
 586e51a60fabf-2a7d0bf96c1ls447766fac.1.-pod-prod-05-us; Sun, 22 Dec 2024
 23:16:13 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW/5NHUVYvEWzXeEGDbQY737h4CCsmvIOVgL/M654yZSoyXdivP6mU4sQUMjapFf9dMYCAx8plJseE=@googlegroups.com
X-Received: by 2002:a05:6871:620a:b0:294:cac8:c780 with SMTP id 586e51a60fabf-2a7fb00b1aamr6821250fac.6.1734938172901;
        Sun, 22 Dec 2024 23:16:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1734938172; cv=none;
        d=google.com; s=arc-20240605;
        b=gaLj7KaJ3XUqGQeH1npqq5fU2rhKW+SLxbNwlkj+kh2KEpTjJ/jLJkKxAtwkeY5wdz
         47MAMhy6yuam3ULqAo5iscHQHEw0m52YBCcfZJ8CS1wdhoGt4uKNZC/uY2SC7hdfnI+0
         TjZ+S9pRYirCIi7oIxItbMvdn4RT+CnGggVBCFBasWHnSQ5Cp2PY912321GPoa+E1HdV
         atgDRg2ahCaYly7gMygre1jWwj9EA/W9fKQN1uLg/tu3AiFcL2/3zUJn7nn2C9sMFPdZ
         bJxinG5MXG28yYyse6mIDm76kd0PoDwID0caLka0Y9NUgu2RgB81ark9BOBTSetOv3IH
         7oIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=ecGpjQJ+dPTMtl9IS6T8Zx3DPG9sUHrYzmuZ6ugsSWw=;
        fh=AhTNiJas1G4BBieXUHFiuJKSu4uV1YpSktn8HqxAMr0=;
        b=Sxls3Vo5G7J4DmLeVzBTnajU4vX81nUUVq4ASLuzB0tVcc1ms053hdiolvYswJ3Blr
         GODwyRoo2hMghqfRwVAIQiz7j1CxY/fn4RwzbRjqiOzAnPmB8iXDwaVTpZXY1qhhNT6H
         CZSr7fSpHlBDG547lEAFqI/enCrPwFv0+GlKOkoEyQwIUhgDCkIns7YgYz2dgCMFMU05
         OLSIMQt866kY5crKp8CatlkTDEU7I43G80ZXatIg2GWfzRvz8EcgSaYFvBVvhM0vSBT1
         2ZlKbK7f6k7066e6bbgQFww6MblWoOP7uCv4k3fIXROmC+yN2MO9Q3wMyBXXU3Z226W1
         TVKw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@xry111.site header.s=default header.b=dYLhBand;
       spf=pass (google.com: domain of xry111@xry111.site designates 89.208.246.23 as permitted sender) smtp.mailfrom=xry111@xry111.site;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=xry111.site
Received: from xry111.site (xry111.site. [89.208.246.23])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2a7d751e740si410969fac.2.2024.12.22.23.16.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 22 Dec 2024 23:16:12 -0800 (PST)
Received-SPF: pass (google.com: domain of xry111@xry111.site designates 89.208.246.23 as permitted sender) client-ip=89.208.246.23;
Received: from [127.0.0.1] (unknown [IPv6:2001:470:683e::1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (prime256v1) server-signature ECDSA (secp384r1) server-digest SHA384)
	(Client did not present a certificate)
	(Authenticated sender: xry111@xry111.site)
	by xry111.site (Postfix) with ESMTPSA id 1944F67671;
	Mon, 23 Dec 2024 02:15:35 -0500 (EST)
Message-ID: <6ac0e0f71990e5a8dc52f00c737cdf56916e0d4e.camel@xry111.site>
Subject: Re: [PATCH v7] mm/memblock: Add memblock_alloc_or_panic interface
From: "'Xi Ruoyao' via kasan-dev" <kasan-dev@googlegroups.com>
To: Mike Rapoport <rppt@kernel.org>, Guo Weikang
 <guoweikang.kernel@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Geert Uytterhoeven	
 <geert@linux-m68k.org>, Dennis Zhou <dennis@kernel.org>, Tejun Heo
 <tj@kernel.org>,  Christoph Lameter	 <cl@linux.com>, Thomas Bogendoerfer
 <tsbogend@alpha.franken.de>, Sam Creasey	 <sammy@sammy.net>, Huacai Chen
 <chenhuacai@kernel.org>, Will Deacon	 <will@kernel.org>, Catalin Marinas
 <catalin.marinas@arm.com>, Oreoluwa Babatunde <quic_obabatun@quicinc.com>,
 rafael.j.wysocki@intel.com, Palmer Dabbelt <palmer@rivosinc.com>,  Hanjun
 Guo <guohanjun@huawei.com>, Easwar Hariharan
 <eahariha@linux.microsoft.com>, Johannes Berg	 <johannes.berg@intel.com>,
 Ingo Molnar <mingo@kernel.org>, Dave Hansen	 <dave.hansen@intel.com>,
 Christian Brauner <brauner@kernel.org>, KP Singh	 <kpsingh@kernel.org>,
 Richard Henderson <richard.henderson@linaro.org>, Matt Turner
 <mattst88@gmail.com>, Russell King <linux@armlinux.org.uk>, WANG Xuerui
 <kernel@xen0n.name>,  Michael Ellerman <mpe@ellerman.id.au>, Stefan
 Kristiansson <stefan.kristiansson@saunalahti.fi>, Stafford Horne	
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
Date: Mon, 23 Dec 2024 15:15:34 +0800
In-Reply-To: <Z2kNTjO8hXzN66bX@kernel.org>
References: <20241222111537.2720303-1-guoweikang.kernel@gmail.com>
	 <Z2kNTjO8hXzN66bX@kernel.org>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.54.2
MIME-Version: 1.0
X-Original-Sender: xry111@xry111.site
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@xry111.site header.s=default header.b=dYLhBand;       spf=pass
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

On Mon, 2024-12-23 at 09:12 +0200, Mike Rapoport wrote:
> On Sun, Dec 22, 2024 at 07:15:37PM +0800, Guo Weikang wrote:
> > Before SLUB initialization, various subsystems used memblock_alloc to
> > allocate memory. In most cases, when memory allocation fails, an immediate
> > panic is required. To simplify this behavior and reduce repetitive checks,
> > introduce `memblock_alloc_or_panic`. This function ensures that memory
> > allocation failures result in a panic automatically, improving code
> > readability and consistency across subsystems that require this behavior.
> > 
> > Changelog:
> > ----------
> > v1: initial version
> > v2: add __memblock_alloc_or_panic support panic output caller
> > v3: panic output phys_addr_t use printk's %pap
> > v4: make __memblock_alloc_or_panic out-of-line, move to memblock.c
> > v6: Fix CI compile error
> > Links to CI: https://lore.kernel.org/oe-kbuild-all/202412221000.r1NzXJUO-lkp@intel.com/
> > v6: Fix CI compile warinigs
> > Links to CI: https://lore.kernel.org/oe-kbuild-all/202412221259.JuGNAUCq-lkp@intel.com/
> > v7: add chagelog and adjust function declaration alignment format
> > ----------
> > 
> > Signed-off-by: Guo Weikang <guoweikang.kernel@gmail.com>
> > Reviewed-by: Andrew Morton <akpm@linux-foundation.org>
> > Reviewed-by: Geert Uytterhoeven <geert@linux-m68k.org>
> > Reviewed-by: Mike Rapoport (Microsoft) <rppt@kernel.org>
> > Acked-by: Xi Ruoyao <xry111@xry111.site>
> 
> If people commented on your patch it does not mean you should add
> Reviewed-by or Acked-by tags for them. Wait for explicit tags from the
> reviewers.

And:

 - Acked-by: indicates an agreement by another developer (often a
   maintainer of the relevant code) that the patch is appropriate for
   inclusion into the kernel. 

I'm not a maintainer so I even don't have the right to use Acked-by :).

-- 
Xi Ruoyao <xry111@xry111.site>
School of Aerospace Science and Technology, Xidian University

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/6ac0e0f71990e5a8dc52f00c737cdf56916e0d4e.camel%40xry111.site.
