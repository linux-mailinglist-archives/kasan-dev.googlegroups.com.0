Return-Path: <kasan-dev+bncBDZ2VWGKUYCBB7NDUS5QMGQES3JONMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id B4D639FAB1F
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Dec 2024 08:32:14 +0100 (CET)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-6d931c7fc26sf63273106d6.3
        for <lists+kasan-dev@lfdr.de>; Sun, 22 Dec 2024 23:32:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1734939133; cv=pass;
        d=google.com; s=arc-20240605;
        b=Utm3pDd5V6ZpZCeWle3aYQjeUbFXFM2KpYJLiFO19/YGz7k5uJLXg/ViHcLKPk3BT5
         JvB03LSAcht7zUtGfV6WadwqJGza/adnQSYYhtdUvaN9A2x3iBZx1krPCveFs2U30kPI
         Uu+mtGpXTuFZCGaoh9TJkxvH7P9auFyY5C58HboN5gxA7D/H7orhdTpExEsLdHL6yTu8
         siE8n6N0o7tfuc8xW5XZooPd38gNBxg6z4GjrHlZPpWxb06KLCgCE4A7XT3tOdU0PUiI
         t1pTNd+NKXkLs/oZKjx5Po4NDG6dGLwtCy9WmmsWJuaI7uE9U3asLgjKSv88Oa1yBizk
         4HwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=rqXo4HnG9+HzExBui4TRzTCFiuidpZdMjUEkTGP8SAk=;
        fh=2rykY1aDrvOcE8a/HzXjzVzfw0hEhKQb6+gyy/G5erA=;
        b=V4PoDnpfNoIpIXvDhGaYMLtK59Ki761svPYodCrHWJNfow3G3yUBL7q10/XqLqO/cG
         Ebpt1twzrJL0PufWcijJ/KAacxab5ICGIz7XMsV0UmfRVQQT5xGiYH+lGlOXy0nEb1/w
         QZORuDmO3D2NGRCUcU3YolArh05mozzbtzMGUl3OvbsQ79MvkdfHnmXuL8gK9jUMOibx
         jk0lydM3SFy7omkVrLcYRFeQsXavyp22sBSuNK3k+tMSWBMc8XtofMaYe7x159+SQsO5
         lgiwhPAR7dDRG/Ax+R8qGHXIQGaArh25caBaXCfSFNFciS9bExByS7xaf4jXoiOqVHHK
         GEhw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="SwPprwE/";
       spf=pass (google.com: domain of guoweikang.kernel@gmail.com designates 2607:f8b0:4864:20::1131 as permitted sender) smtp.mailfrom=guoweikang.kernel@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1734939133; x=1735543933; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rqXo4HnG9+HzExBui4TRzTCFiuidpZdMjUEkTGP8SAk=;
        b=QrbbsUkrKr9YJVoZ2sZ7i7jkEhPeMqcXxAuOjcqdw391lrjCM3kl/ILgXM3fdj7GGf
         iEa0gsd6QDZrObLQchtDTVyCmuNU2zByJ58IBrskptRJUNXSTzA4UFRkWrGQlV9El45A
         0fxP7JrdFfusWjUJOBCoixAxRQckyYlZjLImGTPliK0ck98m9j6DJyyQxSGuOCms5KJY
         UKxA5irTnCTeiaDa9yOoIXDIZ8cDA6k7qc8LWCN3D/4X5EtRY6nkOLPSwBTY9P78urOt
         1XWn66zj5932Me9L+OT8d+RtBZGZDVlVSadRMX039XdUQDXoNKd6GnYGUoB4pF09oRZA
         9mpA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1734939133; x=1735543933; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=rqXo4HnG9+HzExBui4TRzTCFiuidpZdMjUEkTGP8SAk=;
        b=PkvT5ivwZ74WnDXY0hZD1ebzBHFj5t9uAGe8FSuLpsM2aaGbYYnGbYFNBiKYNsn+5N
         h10YIyr0BBxHeIwjhiutWG6JqZcROwyLRZsyF1KQJkrvjqRRPQ4CjBw1ifFI+C10HhJL
         XEdi6DlasP0h8pv35VO5m0OipHiZ02Nm+kO1F5YS2j/Qq0E5A3RUmeAvvHtjgfOXhAdW
         3ahfo1r0npYLXyKtZoOZWtsvIb8tuBahZdq0u5z0zGaCKtvUiitv6R92FmBbt5tLcg/b
         +c4y+T6HCpTFEcFkO11VGQ8P6w+E/YQ0c/1CUAcqq1VURz0kKKXJeXHvCyztaqulPZ4D
         WIOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1734939133; x=1735543933;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rqXo4HnG9+HzExBui4TRzTCFiuidpZdMjUEkTGP8SAk=;
        b=cUTPlZQY+veCTZA7lfi9YTXEOUy2fs4jxMBheEafz/ZKWzvd3PO/cxTZvjX1mKWsMW
         +K5UKeHIHT0sNJGWmjAgM7uHIPl0qT3XBlRyotYcaIG0kBaNW69FLrJGQAnNsy5PLgNb
         c9jafYwax5lSmB4Z1qJdTnd7Uj6yYfyA7IiE60JCalRgHVCnrtYIfnceoLBupDyPwA+R
         pwn24+vYt39Nhry5TtM93qwLHfLW1XxgfOm+408v4wk7py5bhDwGp/b6iiNY0T87t3h5
         QTqWTpJpMUQWiFYwF/8jDHR81dLYi1+A79QhGMDLm6mP5ROcyDCyEgnpbV6AHEkMBuT3
         mKqg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX6LvJV3l/5Xh2RTqWKWyNP+iIlR3M9JapUBti7wKLT6+sa3tq2RIjwYObw1SIt2HuIuvWKjg==@lfdr.de
X-Gm-Message-State: AOJu0Yxo/AzFVCx2WBABi+NBMZRRILxqE7FUgd6BJhENlyy8jHUOoMGB
	VBevpe/c96SCDqYQgD7gs2pBsD2x4d026rfU8OS2E51aYNo6WGs0
X-Google-Smtp-Source: AGHT+IEV42BrnwW0hvMl4+tgHvcXJWuH7JiMvE25s07fy/usw+mApxCQ4tsPMayj5sf3YcUTxnexAg==
X-Received: by 2002:a05:6214:3111:b0:6d8:aa52:74a3 with SMTP id 6a1803df08f44-6dd2335811cmr216971496d6.28.1734939133260;
        Sun, 22 Dec 2024 23:32:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:f9d1:0:b0:6d9:86b:cc0c with SMTP id 6a1803df08f44-6dd1549dc3dls60544396d6.2.-pod-prod-05-us;
 Sun, 22 Dec 2024 23:32:12 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWCtJmlor7QNDOcHpI+7ObFRDtNiRf2OBB4GRUaJxT5UncCRIzA75TnTqv10S4wLVTYdTawOdgDpqQ=@googlegroups.com
X-Received: by 2002:a05:6122:4f8a:b0:518:8753:34a6 with SMTP id 71dfb90a1353d-51b75d6fb15mr8976631e0c.10.1734939132493;
        Sun, 22 Dec 2024 23:32:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1734939132; cv=none;
        d=google.com; s=arc-20240605;
        b=J2pkQF2fPjzIprXFpGN3Jaqzg4+m0iVYvz9uD89cZ8NI/xtHkaSCimvTcEJfgFid5x
         wP/5nuWlt9PH5IR/dPTZ1UAWc2y5avLq254Jel8u8UAvhijw0utdIWH2gJDZBpSHxn+v
         kJekYcfLpLH2BwiyFeJJStTRjZvjIn8664zE7tSiwihehRsyroMkJmn+6UCbThTAE8Sx
         cHTs/1HbYAdWFnWqE1ZQ/QYVAnlFH+qTrbLW2AUHarfM1le/JKQm3dcaroSM4XJiqfHK
         /3TqJ8x5+R7GwjP2OBPKygt0DkWU7uppc839/SF/VATNhgF1ldRpM8KWnr6qHgSUDV5S
         xUbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0v6aG1YFkKVxPZgrKFkppCnD7setaclMAdKcShBz7Ms=;
        fh=XdIodtShxW4iwCOc0KpBSZj6A64yGz7gbHByNNzlkBU=;
        b=O/ecoMvEcfhDAIj+Tukn4NtvhS0s4VE5DqU+YsAaCCI+pJvJHfaNFIN3Lk1s6PKMvv
         N9mHklVumhqbRJEh4mFSRDPtS/lakHA20tWg2vYxvEI1gZMN18drrp7uRwGmcP9DZY+Y
         QuKysHWiqvLtVyisSz6iWsey0RkxP2yh4LtAqHs49+MAmpAf5ufHlVuZAq1jbDK/g/Ye
         shhXvQnyhySyGSWikGA9WgVwS0Eqq+20/ALuhC8A22efW+Z2FqQkAq4CQ75ryB3PCBEF
         BiZYacaD12raRV9VCj85S3KaUiKOZSKW1sdE+LGFuWL71RWvvBpYGzhyzcqXCmW63TTE
         yztw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="SwPprwE/";
       spf=pass (google.com: domain of guoweikang.kernel@gmail.com designates 2607:f8b0:4864:20::1131 as permitted sender) smtp.mailfrom=guoweikang.kernel@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yw1-x1131.google.com (mail-yw1-x1131.google.com. [2607:f8b0:4864:20::1131])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-51b68cf47cesi282480e0c.5.2024.12.22.23.32.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 22 Dec 2024 23:32:12 -0800 (PST)
Received-SPF: pass (google.com: domain of guoweikang.kernel@gmail.com designates 2607:f8b0:4864:20::1131 as permitted sender) client-ip=2607:f8b0:4864:20::1131;
Received: by mail-yw1-x1131.google.com with SMTP id 00721157ae682-6eff4f0d627so33673037b3.1
        for <kasan-dev@googlegroups.com>; Sun, 22 Dec 2024 23:32:12 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCX2DYhuAI2VV23hMHfw/jKMp4WFriPRJ3x99JO8BwMbHk20SPdwTWa8icQELOIav3Pn1oFvJ3CPKow=@googlegroups.com
X-Gm-Gg: ASbGnctSCQcbJdoYhtzcXW6PJPhDeGGSnrnejZfAcF1YYSn98Cwt39jEANDWbj0GwBu
	/iCFwNxmC0ikqCyKnRQwJtcjJVbzRBGNZ8u9mkKk=
X-Received: by 2002:a05:690c:6e0c:b0:6ef:6b56:fb46 with SMTP id
 00721157ae682-6f3f824cb08mr87351047b3.40.1734939131915; Sun, 22 Dec 2024
 23:32:11 -0800 (PST)
MIME-Version: 1.0
References: <20241222111537.2720303-1-guoweikang.kernel@gmail.com> <Z2kNTjO8hXzN66bX@kernel.org>
In-Reply-To: <Z2kNTjO8hXzN66bX@kernel.org>
From: Weikang Guo <guoweikang.kernel@gmail.com>
Date: Mon, 23 Dec 2024 15:32:01 +0800
Message-ID: <CAOm6qnkRUMnVGj7tnem822nRpJ8R6kFVf6B4W9MhMSBQY8X7Kg@mail.gmail.com>
Subject: Re: [PATCH v7] mm/memblock: Add memblock_alloc_or_panic interface
To: Mike Rapoport <rppt@kernel.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, Geert Uytterhoeven <geert@linux-m68k.org>, 
	Dennis Zhou <dennis@kernel.org>, Tejun Heo <tj@kernel.org>, Christoph Lameter <cl@linux.com>, 
	Thomas Bogendoerfer <tsbogend@alpha.franken.de>, Sam Creasey <sammy@sammy.net>, 
	Huacai Chen <chenhuacai@kernel.org>, Will Deacon <will@kernel.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Oreoluwa Babatunde <quic_obabatun@quicinc.com>, 
	rafael.j.wysocki@intel.com, Palmer Dabbelt <palmer@rivosinc.com>, 
	Hanjun Guo <guohanjun@huawei.com>, Easwar Hariharan <eahariha@linux.microsoft.com>, 
	Johannes Berg <johannes.berg@intel.com>, Ingo Molnar <mingo@kernel.org>, 
	Dave Hansen <dave.hansen@intel.com>, Christian Brauner <brauner@kernel.org>, 
	KP Singh <kpsingh@kernel.org>, Richard Henderson <richard.henderson@linaro.org>, 
	Matt Turner <mattst88@gmail.com>, Russell King <linux@armlinux.org.uk>, 
	WANG Xuerui <kernel@xen0n.name>, Michael Ellerman <mpe@ellerman.id.au>, 
	Stefan Kristiansson <stefan.kristiansson@saunalahti.fi>, Stafford Horne <shorne@gmail.com>, 
	Helge Deller <deller@gmx.de>, Nicholas Piggin <npiggin@gmail.com>, 
	Christophe Leroy <christophe.leroy@csgroup.eu>, Naveen N Rao <naveen@kernel.org>, 
	Madhavan Srinivasan <maddy@linux.ibm.com>, Geoff Levand <geoff@infradead.org>, 
	Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Heiko Carstens <hca@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>, 
	Alexander Gordeev <agordeev@linux.ibm.com>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Sven Schnelle <svens@linux.ibm.com>, Yoshinori Sato <ysato@users.sourceforge.jp>, 
	Rich Felker <dalias@libc.org>, John Paul Adrian Glaubitz <glaubitz@physik.fu-berlin.de>, 
	Andreas Larsson <andreas@gaisler.com>, Richard Weinberger <richard@nod.at>, 
	Anton Ivanov <anton.ivanov@cambridgegreys.com>, Johannes Berg <johannes@sipsolutions.net>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, linux-alpha@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, 
	loongarch@lists.linux.dev, linux-m68k@lists.linux-m68k.org, 
	linux-mips@vger.kernel.org, linux-openrisc@vger.kernel.org, 
	linux-parisc@vger.kernel.org, linuxppc-dev@lists.ozlabs.org, 
	linux-riscv@lists.infradead.org, kasan-dev@googlegroups.com, 
	linux-s390@vger.kernel.org, linux-sh@vger.kernel.org, 
	sparclinux@vger.kernel.org, linux-um@lists.infradead.org, 
	linux-acpi@vger.kernel.org, xen-devel@lists.xenproject.org, 
	linux-omap@vger.kernel.org, linux-clk@vger.kernel.org, 
	devicetree@vger.kernel.org, linux-mm@kvack.org, linux-pm@vger.kernel.org, 
	Xi Ruoyao <xry111@xry111.site>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: guoweikang.kernel@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="SwPprwE/";       spf=pass
 (google.com: domain of guoweikang.kernel@gmail.com designates
 2607:f8b0:4864:20::1131 as permitted sender) smtp.mailfrom=guoweikang.kernel@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

Mike Rapoport <rppt@kernel.org> wrote on Monday 23 December 2024 at 15:12
>
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

First of all, thank you for your reminder and patience. In fact, this
is the first time I received a patch discussion when submitting a
patch.
About Reviewed-by or Acked-by tags, I will not add it myself in the
future. Regarding this patch, do I need to provide a new patch to
update it? Or will you modify it?  Looking forward to your reply

>
> And don't respin that often, "Reviewers are busy people and may not get to
> your patch right away" [1].
>

OK, I will be more patient and update after confirming that there are
no more comments.

> [1] https://docs.kernel.org/process/submitting-patches.html
>
>
> --
> Sincerely yours,
> Mike.


--
Best regards,
Guo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAOm6qnkRUMnVGj7tnem822nRpJ8R6kFVf6B4W9MhMSBQY8X7Kg%40mail.gmail.com.
