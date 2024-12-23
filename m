Return-Path: <kasan-dev+bncBDOY5FWKT4KRB4U2US5QMGQEFWDL5IQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C5089FAAE7
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Dec 2024 08:12:53 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-2ee6dccd3c9sf3565103a91.3
        for <lists+kasan-dev@lfdr.de>; Sun, 22 Dec 2024 23:12:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1734937971; cv=pass;
        d=google.com; s=arc-20240605;
        b=VZU0ysFUy3/YRpzQURXV2CEO2IcFpS0p+2ym7vpxlEooVP5PKyYh/I+hGXwLC2Edgr
         IRc0ZMKvXBBvaxs28ULMX/E3yUntSctSWfnBcZmTffHEW+xObanvs3BHQd/8pUTEJJL3
         2lUPa3LZLz1odijZDSV6sC6UPzeQaYpdxqdKdQGG8p1hPJBNxPNCN7sQ9oDH5dQMFGEg
         BWCWkEjsmMA+h4PnskpymcizMyOzbxbh9lOn4FsEZgXBMTQ9pOmptTiHd6lfXGH5kt7L
         K14YC2dUyzTM2XdM5DK+oQhcmH0Kuqvu2jK1W2TyVdp2Z/LZhsq3IzpICUqufj+gZezZ
         Eaeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=z934rt/1EOiN/cSPJymk+1HjbEU6vOdd/+LmrUFkf6I=;
        fh=CFxIjG0Oh2qmJOLYJrWgUsZ7jv/s+bUnWaP0w1HsjYc=;
        b=FlIeD1T0f8l9Z0Y48fp+ZR/MzosF6qQsugjZTupPh7KvJG2ly/PKFQIhwkgPZTRiR1
         Qm6IPEbKLCEDt02H7NTzvLFXSEKYkm+Faz4bxSLMSY1BxaGw2hvLjCKBFlfhmKXjh0qu
         rZ9PzmvpB81sLz8Gltat5v8YrZfewfNfNcxyFKx5qlQoaAgux5H5tEnUVIfRRbSZGAxp
         lOKF7os7pB91aj5wUu1zF6zQm0qE6+ZkgWxk4apHRJhfjB+KQf8aw3nOWQ6/Cl5byIC2
         xNTfZOysG4NAZFYg8z4Ai9am/95xT62RzsWJLNuoFfV9LIAGdAWHtZ/lMAWHbXn4FPhT
         fPLw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PadoaIur;
       spf=pass (google.com: domain of rppt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1734937971; x=1735542771; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=z934rt/1EOiN/cSPJymk+1HjbEU6vOdd/+LmrUFkf6I=;
        b=qWNYPGyMheoEg9EKAX/1fBaIpICucylD4ODlmn3J157uQPKibkUZ1+aBGBz+j9alnK
         pNXkTFd+EDrnC7VQ7u+Cu4S8YWfjOk1pu8v4dzclSy0opl18sU+L+UvXk30zclBizafq
         jkydUB83mFEJWAYdHCo2ZvqnNPMx7NnWsG7nHzSs/qx9ublQSJ895kwLPgkdTA5X0BG9
         Kx8MmgXLpfLYARVsKURmBY7G5Ktxlozy/AIA0THz7OZD3hplFarDppmH7l1bnJdfKXcD
         X3fDarXTDQ4FSGcPzy5o3vXVpGqFO7s2sRtie/UApmxQl/wySQcnNqeLiI7BhFyzL8Xj
         2UqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1734937971; x=1735542771;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=z934rt/1EOiN/cSPJymk+1HjbEU6vOdd/+LmrUFkf6I=;
        b=jRiES8G7m3gx0SbYlziC1C1RrzfKWe+Nw3MyRHv0IXUIWKqj8y03XfoR7ZCufbQav0
         KaZUGIUsJeKfcG6n+6fyqlb7ltsYkxN8iE8JWD68cM24/L0xJcxbNF/6vdADKwj1OeKi
         tGhydl8nHnW+pFlhxeIlaiz9LgFR75IG6v1tG5xBlJnfoYTXnCcb52XeVl6VYiThKyaW
         gijHUbBDtN/nU0tsgYBdyXcWqeW9bTs6Uuhdwwjd+bMvPYVqELXiKek/xt0GclYbNUvW
         3qFIK/EtDAlO3a9dOyzEvUNT2rkqpHKQ8rqifL2mJfSnVGPlWnnlyBMUIMpSeFZYvHLZ
         NV9g==
X-Forwarded-Encrypted: i=2; AJvYcCUDudf0nGxqWjioqqOHLXHe5swtXIIyA6u4a4kkSd9jrZpr1Xtwx/skGFu5/03xj323oWIoww==@lfdr.de
X-Gm-Message-State: AOJu0YySQO19BlJqtTX7bU6nylTrXmIVRHH7xSzAbfRGi99oZywaJcEe
	49bLH0mAykBWP+Z1q9jItGnHSFbnn78sN8DLon0vfp0I7TaML2E+
X-Google-Smtp-Source: AGHT+IGSr87dq5YZfFA7Zo/jjuqJui12I/sfEudkSYBIhCQPVDGR3a/9cenpvpvv+3q6hQvPZ+pxTw==
X-Received: by 2002:a17:90a:e187:b0:2ee:d024:e4e2 with SMTP id 98e67ed59e1d1-2f452dfaec0mr18216911a91.7.1734937971228;
        Sun, 22 Dec 2024 23:12:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:cf91:b0:2ef:8da3:a6a3 with SMTP id
 98e67ed59e1d1-2f4430bdee3ls101091a91.1.-pod-prod-02-us; Sun, 22 Dec 2024
 23:12:50 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWHdn0nxiwDss7akTiDfd80eWRg0JdKoWCO+L0TgTfJu6ZV5tro6tQRsZGqhZaBb6u7XuNas/TupBA=@googlegroups.com
X-Received: by 2002:a17:90b:50c7:b0:2ee:c04a:4281 with SMTP id 98e67ed59e1d1-2f452dfb023mr16466259a91.6.1734937969841;
        Sun, 22 Dec 2024 23:12:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1734937969; cv=none;
        d=google.com; s=arc-20240605;
        b=H8SuSYa2aliCmyQExoXmjZVxs8Ofi2Yzz7c8uA7DATDwGyZQr9T/8BreGC07UtX945
         YrKjzUDLy4vzfToAKvwsvu8qs4B0lb7WHKo5iVOCRx3nd8YvjGvSwOCZNG/Hg7tZdLpy
         V4+45xmlOFTMDkgMf0hupD/Oas7fyyfmogku/XoAniSGKTLIb/vLDB32uZkd+boUmgvo
         wILCRA34bmBO8+/irUdHjYR9qx25eQWp5VaORnuu0CXCZnigDIuYls0tFQmxrd4BNuIB
         rpMSFUuqz1aYzRPIUaL/oOfNteM58nUC9stAGyltRfKAQf4/HWYCPb62e5jx5kwBLsZu
         kB3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=tpXH6fpTjEphVQKpFxQ2V5QkwIF19GVaeym7wiAED5s=;
        fh=hBm1NBUoRubn/P0WyRaw6PHBn2wmSrEOmphI6eHoy6I=;
        b=dq9aASYeEMoheVjHm9E5VlpT0Y3MQJJ//1sVPtxKaP+W6eHlr/oLb8r8gOPncTo81T
         ig47PkpCyitCFzpdIzDQeTSbG7jVWAsT2fSxKteHylBwP3jCLBL62RgCtwX6f4Bpp0+3
         4KN7ukIEH7pnwIni1AJcImRVk1007QRKnzNVl5/hKitHMk9QMBd1XoWasd5UIOXCk001
         LezEIie5L2HVE/eyIi0unMbtQCI4AIsty/Lv8+SUambf1cl9RmfG6SzF2cV4ElhR8Hto
         ej504JbN4FokY1/hx6IWH++tZZbIVoZpHH0PNReVhDu00w93wMDbjXT54ADYtDdm0SlY
         N/mQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PadoaIur;
       spf=pass (google.com: domain of rppt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2f44786ac46si534023a91.3.2024.12.22.23.12.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 22 Dec 2024 23:12:49 -0800 (PST)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id C64ED5C4A8D;
	Mon, 23 Dec 2024 07:12:06 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A2221C4CED4;
	Mon, 23 Dec 2024 07:12:24 +0000 (UTC)
Date: Mon, 23 Dec 2024 09:12:14 +0200
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
	linux-mm@kvack.org, linux-pm@vger.kernel.org,
	Xi Ruoyao <xry111@xry111.site>
Subject: Re: [PATCH v7] mm/memblock: Add memblock_alloc_or_panic interface
Message-ID: <Z2kNTjO8hXzN66bX@kernel.org>
References: <20241222111537.2720303-1-guoweikang.kernel@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20241222111537.2720303-1-guoweikang.kernel@gmail.com>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=PadoaIur;       spf=pass
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

On Sun, Dec 22, 2024 at 07:15:37PM +0800, Guo Weikang wrote:
> Before SLUB initialization, various subsystems used memblock_alloc to
> allocate memory. In most cases, when memory allocation fails, an immediate
> panic is required. To simplify this behavior and reduce repetitive checks,
> introduce `memblock_alloc_or_panic`. This function ensures that memory
> allocation failures result in a panic automatically, improving code
> readability and consistency across subsystems that require this behavior.
> 
> Changelog:
> ----------
> v1: initial version
> v2: add __memblock_alloc_or_panic support panic output caller
> v3: panic output phys_addr_t use printk's %pap
> v4: make __memblock_alloc_or_panic out-of-line, move to memblock.c
> v6: Fix CI compile error
> Links to CI: https://lore.kernel.org/oe-kbuild-all/202412221000.r1NzXJUO-lkp@intel.com/
> v6: Fix CI compile warinigs
> Links to CI: https://lore.kernel.org/oe-kbuild-all/202412221259.JuGNAUCq-lkp@intel.com/
> v7: add chagelog and adjust function declaration alignment format
> ----------
> 
> Signed-off-by: Guo Weikang <guoweikang.kernel@gmail.com>
> Reviewed-by: Andrew Morton <akpm@linux-foundation.org>
> Reviewed-by: Geert Uytterhoeven <geert@linux-m68k.org>
> Reviewed-by: Mike Rapoport (Microsoft) <rppt@kernel.org>
> Acked-by: Xi Ruoyao <xry111@xry111.site>

If people commented on your patch it does not mean you should add
Reviewed-by or Acked-by tags for them. Wait for explicit tags from the
reviewers.

And don't respin that often, "Reviewers are busy people and may not get to
your patch right away" [1].

[1] https://docs.kernel.org/process/submitting-patches.html


-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z2kNTjO8hXzN66bX%40kernel.org.
