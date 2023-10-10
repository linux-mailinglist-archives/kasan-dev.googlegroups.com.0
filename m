Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBNMSSSUQMGQEKYDZABA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 87ABE7BF590
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Oct 2023 10:20:07 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-2c12a8576d4sf43960621fa.3
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Oct 2023 01:20:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696926007; cv=pass;
        d=google.com; s=arc-20160816;
        b=CRPCJd/7FOTQyWn4ZmKDTQ449RZeJ1y1wxW8cZtY6Ee5qaLIHjaITOK/+DQ9B5Upro
         EKA5ZdeHrFS4hRZJBkY1NbV9SMT+Vd6PuQoFdSPDO7QyzzStnbjsWrjyWT3jri1nIL1w
         CxpYbPY1dhF1wbR0m4SNbWo2lhATlp0wmlnJ6cWQQnTwimNy4Dn8zCJwvIco+BYL5tnu
         EA5jewV/1UuRxRFfYZRCSiz66YtsnZNd1jayHhVU9RsZGTbc7nC3U2+F50c5S85+tJQh
         cjSpF6O9pkp1HUgfh57nGNlK4fCb8/EbCpBNGvjr3s7n0k+R+2JgHkBrucjGbEU3m8Hl
         yaQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=5aYGrntQtx4oV1EF1v18dUQcL4akc/THVitM4f+1t24=;
        fh=tMvHKGT1+QcASgZQMJhW3iAjRPPaJkqDzc/tI8OKJZo=;
        b=U12sAyaSipAnOpFDokxIsYlejkPzRWdPd8HZtG7lz0gIS6YWQibJBuKWlvIsL92svR
         4g2zUlY8lIvw0IH+OHtHX60p0Y27JAyj089uU2Sf9f8oT47RnhU2zE2gv+Pdy2JGyd34
         ll4PEA0SigDu7VHLg6E7GyOP5e1oqi43oVGKjwuOLxYlhJmA7JNKlOkOLQsFIzpJp+nM
         wsMk7ITFsVMmKoRFZ4+DlbHgaCkClo99PJRgSeAkBgpdk4aYhh78QSWa5vjTBDhNUNnm
         7x4rbED/OxbyteSBnHQPQO3d1R/XgavfimLT7Qe43iWkOFlWx4s2HB+0VnBL9O3Kuwna
         HHuQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=YO31Bh3h;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696926007; x=1697530807; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5aYGrntQtx4oV1EF1v18dUQcL4akc/THVitM4f+1t24=;
        b=AEQvDSPl3ezvJ1JC9CZr+FOp6rBrApbY/nV9rpClOg95OgKJ8Eu7iuCqNXTa2rWVdj
         kK85Nw67pydsAcgL9OFekSAFqTBbpeqVQUQkCLPvR+d4uHW2xH6BqhmsFuWy6VM16OEN
         60p/IOc5trS4FiMUG7xUyA7pnzwpjHXVo/AkyWnSXtsKnIxgbfaMopVQLR/D4yw6qAcf
         tWEsABrErpctB+/cSroVOCB4C220AvkuNksDJpIhq7TJ2b8Gag5JmBkWB/T0m17LqiYj
         Ra/vdkhdzoZYSGzKXpL8B2jQy+xXVofZ/jQ1jU5MQeKAEN3ISJffRgMza7SLguPtsdCt
         13aw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696926007; x=1697530807;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5aYGrntQtx4oV1EF1v18dUQcL4akc/THVitM4f+1t24=;
        b=pVGRU2Tof+yM5W29pAXwEFCYfXf8mdDDbA+4BAJjBa03fDOHYuNEaAt2hctBZlJYTK
         9//cg2RAbkuZZiVgcX5JiT3Ss3ycWzw+9w8Y5PjxZQ9M/96eUrhoM3+xOp8oqrQByA1Q
         nXdxzs/Vc1gylX4jj6rtvQAeza2ZXkZur9gspINRiqsE57ACt4KHZfXdoaHmvM+odbpb
         swafqzw0TdeBBxqi2oPeerFDDGG8O82EkmEPLAffuaUtbQuwhrZWo2pfX7RklJWJfeaA
         rcTLmibo/YBfGoGUlMIeD44pyZWQQKOonOXvXJX2Upf/Y+9CKuM0VPSNYh/AzDd7JOtZ
         83Rw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yz9hehAilPuC0GtN7epaW70dtAYKVQk/zuEORgIyOUyy/TX+yIi
	l1NzffDLT0GImfdGLKLZ1H4=
X-Google-Smtp-Source: AGHT+IGcZpwLz+WzUIW7C+8qRQaAxGX8SUOcCWhiFuI2MtuMM34zLzl6V/EJhsTONhDfqPPYIvdBvg==
X-Received: by 2002:a2e:2e15:0:b0:2bc:f439:b5a5 with SMTP id u21-20020a2e2e15000000b002bcf439b5a5mr17512437lju.14.1696926005897;
        Tue, 10 Oct 2023 01:20:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9114:0:b0:2bf:f477:1994 with SMTP id m20-20020a2e9114000000b002bff4771994ls634534ljg.1.-pod-prod-09-eu;
 Tue, 10 Oct 2023 01:20:04 -0700 (PDT)
X-Received: by 2002:a2e:90c7:0:b0:2bc:cff6:f506 with SMTP id o7-20020a2e90c7000000b002bccff6f506mr14720280ljg.0.1696926003968;
        Tue, 10 Oct 2023 01:20:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696926003; cv=none;
        d=google.com; s=arc-20160816;
        b=ZKTZYnR5QPQfPSHGFRN20+NcmYcaLUD2mRw/ciB86KnpOhBIKC/jnwHplwL9g4eqyi
         943ikKJ2VI1lOA5QZsnQiW/h+7c4YIjAXHQSOK4s6yJsJ6mBgKtJS8lzfZq2zudX0+Wx
         8SZQS0NpXvHQNvyWehXmvneT09laKgGHaExb5Gbwef7PkwvXsAtkVXjq4B5UUK0M45wm
         4Lu8sDiF3gcIqoLzNvoD8lZmKMvwszODv1V3xCER1W7aH/15F/32gEZZAslxKcntofsp
         1cGcoxnkzGhdBMP0GzlnpzwyN3zLXOl3rqJ9MrLk8b+yOPpshqJute8iY09zffZWKbeW
         +llw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=E9CMcde7JhHmBwITrfwM1TdYK1kSavxuW5gL57dtmNY=;
        fh=tMvHKGT1+QcASgZQMJhW3iAjRPPaJkqDzc/tI8OKJZo=;
        b=V3RiyCur5B/vlsoJJ8Sw/I1svR0/nf0Ab947JdQ2SR4HdWGz1QLKDgy/H+mnitI/tc
         3QfA6+bQsTLPuOmCK2tPz/iDuJ8PBxXHlIXrXpFgc4OmRpZIzGRBnbqTeyYCt9C3dOSU
         rPeRo3vjDIGx9kC3XZr3Ik8tslyA4tRYRxwdY36GDo75T+LUZrRyMH8CLYkRdlPcZu9g
         k4lY2KcmkHYK+Ga/FtC7pftEpqBmMVWWBZzU7TdWEiiLV2G3TuMMlSMynQX+GlO/HaBg
         7cSoRiMbC7P4OQWOqcvh8cJ2w0tzAy9P9QgSoJ45kwNl0JX7oheDXGQXh5ej+h8mN5Fm
         I6bg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=YO31Bh3h;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.alien8.de (mail.alien8.de. [2a01:4f9:3051:3f93::2])
        by gmr-mx.google.com with ESMTPS id i22-20020a2e8656000000b002bfbc15cfefsi718868ljj.6.2023.10.10.01.20.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 10 Oct 2023 01:20:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as permitted sender) client-ip=2a01:4f9:3051:3f93::2;
Received: from localhost (localhost.localdomain [127.0.0.1])
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with ESMTP id 08C6C40E01AE;
	Tue, 10 Oct 2023 08:20:03 +0000 (UTC)
X-Virus-Scanned: Debian amavisd-new at mail.alien8.de
Received: from mail.alien8.de ([127.0.0.1])
	by localhost (mail.alien8.de [127.0.0.1]) (amavisd-new, port 10026)
	with ESMTP id Rlcgad57B5RT; Tue, 10 Oct 2023 08:20:01 +0000 (UTC)
Received: from zn.tnic (pd953036a.dip0.t-ipconnect.de [217.83.3.106])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature ECDSA (P-256) server-digest SHA256)
	(No client certificate requested)
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id 8C73140E0187;
	Tue, 10 Oct 2023 08:19:39 +0000 (UTC)
Date: Tue, 10 Oct 2023 10:19:38 +0200
From: Borislav Petkov <bp@alien8.de>
To: "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	Peter Zijlstra <peterz@infradead.org>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	Fei Yang <fei.yang@intel.com>, stable@vger.kernel.org
Subject: Re: [PATCH] x86/alternatives: Disable KASAN on text_poke_early() in
 apply_alternatives()
Message-ID: <20231010081938.GBZSUJGlSvEkFIDnES@fat_crate.local>
References: <20231010053716.2481-1-kirill.shutemov@linux.intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231010053716.2481-1-kirill.shutemov@linux.intel.com>
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=alien8 header.b=YO31Bh3h;       spf=pass
 (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as
 permitted sender) smtp.mailfrom=bp@alien8.de;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=alien8.de
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

On Tue, Oct 10, 2023 at 08:37:16AM +0300, Kirill A. Shutemov wrote:
> On machines with 5-level paging, cpu_feature_enabled(X86_FEATURE_LA57)
> got patched. It includes KASAN code, where KASAN_SHADOW_START depends on
> __VIRTUAL_MASK_SHIFT, which is defined with the cpu_feature_enabled().

So use boot_cpu_has(X86_FEATURE_LA57).

> It seems that KASAN gets confused when apply_alternatives() patches the

It seems?

> KASAN_SHADOW_START users. A test patch that makes KASAN_SHADOW_START
> static, by replacing __VIRTUAL_MASK_SHIFT with 56, fixes the issue.
> 
> During text_poke_early() in apply_alternatives(), KASAN should be
> disabled. KASAN is already disabled in non-_early() text_poke().
> 
> It is unclear why the issue was not reported earlier. Bisecting does not
> help. Older kernels trigger the issue less frequently, but it still
> occurs. In the absence of any other clear offenders, the initial dynamic
> 5-level paging support is to blame.

This whole thing sounds like it is still not really clear what is
actually happening...

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231010081938.GBZSUJGlSvEkFIDnES%40fat_crate.local.
