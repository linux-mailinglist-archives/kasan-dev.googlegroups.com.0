Return-Path: <kasan-dev+bncBDZ2VWGKUYCBBG5DTK5QMGQEVPFYRUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id C28889F9FF7
	for <lists+kasan-dev@lfdr.de>; Sat, 21 Dec 2024 10:59:56 +0100 (CET)
Received: by mail-yb1-xb3a.google.com with SMTP id 3f1490d57ef6-e38dbc5d05bsf4208140276.1
        for <lists+kasan-dev@lfdr.de>; Sat, 21 Dec 2024 01:59:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1734775195; cv=pass;
        d=google.com; s=arc-20240605;
        b=X43psqBjjqojXAsioFCS6Ln4qxEv1iVg6/pUHHbbjLa0zi/9TzdRyQgjpwMRvaSeLV
         o/mBB8jbVrnmH4PU+tLYlCMfsJ39ID4tCOgKthYiGHQMoZbJu37LML/c7WxRk5bahEEq
         s4Z/RuBOrAGlD/PsfW1HqmnsSY2/ivXIkIuFjzmgjP4ardyfGSOVaK/GXKA9BZDFhWKU
         a4xYPTa+TDTbDAsow/fLlWJo+MagvFtQUcHgPENh9/jHMN7+KHoA8cWffPqzgSjfV8TP
         0g/Zyq4T31X+TbmfkBXnaeKKHeb+46zMGoDhwrdogoqTYRXD7PhZNewbPuqNlmw/M09X
         wrmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=uKIexKbA6U/1n/ueTFCCUGeAR/H0r9Ugr1+qTbGHJgo=;
        fh=1IZjTLbpSoYCOelwK3FEOZBw6CEyJ6dPry7F6sOc9TQ=;
        b=Wgals55DoarNOGWO6pHVTrdAGsayWkrnIQuTmZZgXSnv3PJqRN4xUpYbJMEyiQEjZ2
         dRaZCCAUj23v+mWBKpSxB49JpenUI2JVPbiX0X6nsB/rpwf9nIhrJ58v6GjzwvxhDNJV
         Ab69qpi3roCB3MmfbQpdkah9n4rit2X4Ir1Y/565Efim6vWdgrBIm6VovGlujc3z3smU
         GcSivbYo4lG04ZpQlNRCUsdAnewwDAyVZROTCytXnIvpyBhXRXUhqS24S9ggScPfAmGW
         pcgHatQ5q2tsnhBDo7mGhN2K15fs6IZJBQzC/9n5d7EFqG8VltUx6Px8pc8EBpwq2iTh
         LHSA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=SNUPoSBP;
       spf=pass (google.com: domain of guoweikang.kernel@gmail.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=guoweikang.kernel@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1734775195; x=1735379995; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=uKIexKbA6U/1n/ueTFCCUGeAR/H0r9Ugr1+qTbGHJgo=;
        b=sFLTF//9JbxUY/X86cVl0lOWrHGPhyz1lmjGL70CcbbrScFbX+ym/jZZHRdFPxSa8k
         1xok+yAdEaXNp7xNA0GdcNL8JEiX2V/YaPNGCFDuoEBuUbLQuGs29iEo21YxwVsI+avb
         bJgvo7+ld7qMNRJKES//uwkud9Kr3P9kGm15WeDhumweCN3X2j78Wv33CbsQTMwgEwzc
         lvv/664587jzjlO3yLGRusnWZ0hgUcGuGdlCWrhP6uACBtV98WFgBm5c/Onag9+sX62/
         HvDq8wVGXaK3IZMgKWaO4mkekn5y84RKP0U9CGXqrxloF5IKoW2p8xFGAgSZPanHM9Ih
         NAjw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1734775195; x=1735379995; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=uKIexKbA6U/1n/ueTFCCUGeAR/H0r9Ugr1+qTbGHJgo=;
        b=Nzc4DfZ93JnGtc8MvtMWe6l0UtgZn2iXpQWJKTxmS2HBPrhTiwZJ/jMvLqBczmhqKl
         eG0h/7gfEuGUBDQMW55NwUjBCPp+FJGvQ3KkE0KILnLyso8wqTtdDKeZlGTb9aUwEwSz
         X9kkCD+LIlJdA2+9wlkTzFm5vGcKR6vCcUpoQJJiWy7fPOaJ+lfCO2XNcdx5b7f7kKGf
         nWhT6K6lbxv3KEDJ1NmfRd1uALzKp+hzkwL8EHets5m0+SnlzOn4GeJc2Sbz8RU+Zzbd
         is0Yg6EUF/vBDO2guLi1StR9MPGv4Cehvx3qpmW7ZGIjs4KV+Vw542+bzSdiScNXtwF6
         BkSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1734775195; x=1735379995;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=uKIexKbA6U/1n/ueTFCCUGeAR/H0r9Ugr1+qTbGHJgo=;
        b=JHuOWIvoNQr0PxJPzTm2HychWtpF2uOsuxyJuJsXHnTJmbaxxs0NePDDszEbH5k1j2
         ni9Na/F96DX7O1MzNSAgg/2/RbO2y7oEqGdf/IR9WWlLrSchlGQ6tLj4d4Fslcy+8dEz
         yRO3j82/vO0yKaoQAjykxqck4kRT7Py9WUkBxEel3IJmkGrb2p57FX+fqAHcOwKtHLFI
         r0vgPKuC66DprgkjGJ22zPeCIA4Tw0zf2HQy+kWnTMyZ+KzQZudHcoMkixBG/+GEVPFY
         sYJcyITQYvKvks9wIXvVEA/UQOyuFofDi4ahKxT++t9slCuZzfkxggT8WPnQnhDw06T8
         1FPA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV4P9VNHBmdjFdkC/BWsQSO3/vj3EUNl/D4q9QdnheW+CRi/OjffKafiEl3rgXEWmAjsATVGg==@lfdr.de
X-Gm-Message-State: AOJu0YzwtohJ1JIl40uI4MMA4kKqg6WJvWjKTNRsxdsgRDUIftvy1Rxd
	ll1QA8/xeKVqVEQdwB133o5tJ00kAHklzGEOq8JpeC4/0HRPwCi1
X-Google-Smtp-Source: AGHT+IEZLdLZKhZnGdvztLiqpbCfWp7L/PQKNQ6jpOybCD2T3p+S2q+VCCZ7H7H7u2/kbJ/8/SH+xA==
X-Received: by 2002:a05:6902:1288:b0:e38:f30e:9b52 with SMTP id 3f1490d57ef6-e538c1e2579mr4371266276.4.1734775195390;
        Sat, 21 Dec 2024 01:59:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:ad4f:0:b0:e30:e1d9:fe2c with SMTP id 3f1490d57ef6-e5375fdb21dls266661276.1.-pod-prod-03-us;
 Sat, 21 Dec 2024 01:59:54 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWfUhgohOKZXtFCzE07sf52ItZKPjjjTDRgUyFNvJ5+A+O/hO2n4rHqFYJd6cpef7leOotvRABGoAI=@googlegroups.com
X-Received: by 2002:a05:690c:6a12:b0:6ef:6a71:aa55 with SMTP id 00721157ae682-6f3f7f31653mr51760577b3.0.1734775194329;
        Sat, 21 Dec 2024 01:59:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1734775194; cv=none;
        d=google.com; s=arc-20240605;
        b=E6hpoVkvD3f1pd2uRprYz0B4wiZBrNgmDHckOo2u18LulH3B4cGbd4Sp6Gt3TOL0d6
         1ifv+CWX+Jxljk+DyHZebPzTw5dvbgeNPBJs2cTX5XIwiJ7U7xFYSXKpyleXFew19JU0
         pvIegY8J8tLbs8QS09lyhrEW83CBUhtCgFELgY8v2RffCipFrKML4ZSFI1GltoIaQ3He
         efT+Lee9E2Wb1xRk0nLDxSkja/iF+309Rc1LW4ipDZnzW22PTmRaQsqSMN8+nph2ZDxI
         G9dntEqm+zlk6cYVKpBFRGAuGmA8RDYNjX8adfAHSg8HgWs0ToEr/AIrYI/h5GO5ExBy
         lXNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=egHprya5wIN6bGofZtv4dfpbBXKQe0iUzhyvNvr/kt4=;
        fh=mDA2w1HjV1o0rojkxQuczTZNJMk2tcaELnIfuIZoHwY=;
        b=GbZvfhEd7m6ttzGsZfDiShmC/QaiTjCrIeXAjB+nvw6ZKgBm7F1p0rpgBFv0Uynt9P
         QuO/mTumCkavMKHwaNJia6UqVqPo1cRzwO9Sp3yRYaNpUieznoAlko27MAncOpfI9OcK
         xU0AxzgPGH2mxIXUIXLLhllL5iZ2UWY2Rz6kWzSWuKpHxkQKUA2+CSGUPHEfN1E661k0
         lGedTbh2j8HnYrjqpvvZb+I19pceYg49UnwDoiGFbw/HH6logmAURJvjVRP8OGyLTb22
         FLf6dh5P1CoKoVpZ1dWMtxX79JJzANt5KRd3RxiuVKlSHmOQtAh3y8NNPHxSlrSeaymh
         7jeQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=SNUPoSBP;
       spf=pass (google.com: domain of guoweikang.kernel@gmail.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=guoweikang.kernel@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yb1-xb2f.google.com (mail-yb1-xb2f.google.com. [2607:f8b0:4864:20::b2f])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-6f3e73b3e29si2550627b3.1.2024.12.21.01.59.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 21 Dec 2024 01:59:54 -0800 (PST)
Received-SPF: pass (google.com: domain of guoweikang.kernel@gmail.com designates 2607:f8b0:4864:20::b2f as permitted sender) client-ip=2607:f8b0:4864:20::b2f;
Received: by mail-yb1-xb2f.google.com with SMTP id 3f1490d57ef6-e53a5ff2233so166052276.3
        for <kasan-dev@googlegroups.com>; Sat, 21 Dec 2024 01:59:54 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWtCy3Wogq6ez/u+AXuBXxwyPzK4PHH9uY2a0UFz2PIguxqVczXzEmgClV/btA7nQa506RyR4g90i4=@googlegroups.com
X-Gm-Gg: ASbGncujazdq0Pfq4iNHwwtFqrN/8EKw/nb4xWubt/JUlIF9zgz9vd4byu3crXSR7l9
	5ctppwqAC4N6pKOxggT0pmJiD0YvktbM9uZ69qag=
X-Received: by 2002:a05:690c:4b13:b0:6ef:7036:3b25 with SMTP id
 00721157ae682-6f3f8216b3cmr49229327b3.31.1734775193934; Sat, 21 Dec 2024
 01:59:53 -0800 (PST)
MIME-Version: 1.0
References: <20241220092638.2611414-1-guoweikang.kernel@gmail.com> <20241220150623.278e8fa9f073b66dc81edfe6@linux-foundation.org>
In-Reply-To: <20241220150623.278e8fa9f073b66dc81edfe6@linux-foundation.org>
From: Weikang Guo <guoweikang.kernel@gmail.com>
Date: Sat, 21 Dec 2024 17:59:43 +0800
Message-ID: <CAOm6qnnFDjyiQvUmyVA4iq5aJAO8NC=wcAvpKscvfRZKPnzkYw@mail.gmail.com>
Subject: Re: [PATCH] mm/memblock: Add memblock_alloc_or_panic interface
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Mike Rapoport <rppt@kernel.org>, Dennis Zhou <dennis@kernel.org>, Tejun Heo <tj@kernel.org>, 
	Christoph Lameter <cl@linux.com>, Thomas Bogendoerfer <tsbogend@alpha.franken.de>, Sam Creasey <sammy@sammy.net>, 
	Geert Uytterhoeven <geert@linux-m68k.org>, Huacai Chen <chenhuacai@kernel.org>, 
	Will Deacon <will@kernel.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Oreoluwa Babatunde <quic_obabatun@quicinc.com>, rafael.j.wysocki@intel.com, 
	Palmer Dabbelt <palmer@rivosinc.com>, Hanjun Guo <guohanjun@huawei.com>, 
	Easwar Hariharan <eahariha@linux.microsoft.com>, Johannes Berg <johannes.berg@intel.com>, 
	Ingo Molnar <mingo@kernel.org>, Dave Hansen <dave.hansen@intel.com>, 
	Christian Brauner <brauner@kernel.org>, KP Singh <kpsingh@kernel.org>, 
	Richard Henderson <richard.henderson@linaro.org>, Matt Turner <mattst88@gmail.com>, 
	Russell King <linux@armlinux.org.uk>, WANG Xuerui <kernel@xen0n.name>, 
	Michael Ellerman <mpe@ellerman.id.au>, Jonas Bonn <jonas@southpole.se>, 
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
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, Len Brown <lenb@kernel.org>, 
	Juergen Gross <jgross@suse.com>, Boris Ostrovsky <boris.ostrovsky@oracle.com>, 
	Chris Zankel <chris@zankel.net>, Max Filippov <jcmvbkbc@gmail.com>, Tero Kristo <kristo@kernel.org>, 
	Michael Turquette <mturquette@baylibre.com>, Stephen Boyd <sboyd@kernel.org>, 
	Rob Herring <robh@kernel.org>, Saravana Kannan <saravanak@google.com>, Pavel Machek <pavel@ucw.cz>, 
	Yury Norov <yury.norov@gmail.com>, Rasmus Villemoes <linux@rasmusvillemoes.dk>, 
	Marco Elver <elver@google.com>, Al Viro <viro@zeniv.linux.org.uk>, 
	Arnd Bergmann <arnd@arndb.de>, linux-alpha@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-arm-kernel@lists.infradead.org, loongarch@lists.linux.dev, 
	linux-m68k@lists.linux-m68k.org, linux-mips@vger.kernel.org, 
	linux-openrisc@vger.kernel.org, linux-parisc@vger.kernel.org, 
	linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org, 
	kasan-dev@googlegroups.com, linux-s390@vger.kernel.org, 
	linux-sh@vger.kernel.org, sparclinux@vger.kernel.org, 
	linux-um@lists.infradead.org, linux-acpi@vger.kernel.org, 
	xen-devel@lists.xenproject.org, linux-omap@vger.kernel.org, 
	linux-clk@vger.kernel.org, devicetree@vger.kernel.org, linux-mm@kvack.org, 
	linux-pm@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: guoweikang.kernel@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=SNUPoSBP;       spf=pass
 (google.com: domain of guoweikang.kernel@gmail.com designates
 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=guoweikang.kernel@gmail.com;
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

Andrew Morton <akpm@linux-foundation.org> wrote on Saturday, 21
December 2024 07:06:
>
> On Fri, 20 Dec 2024 17:26:38 +0800 Guo Weikang <guoweikang.kernel@gmail.c=
om> wrote:
>
> > Before SLUB initialization, various subsystems used memblock_alloc to
> > allocate memory. In most cases, when memory allocation fails, an immedi=
ate
> > panic is required. To simplify this behavior and reduce repetitive chec=
ks,
> > introduce `memblock_alloc_or_panic`. This function ensures that memory
> > allocation failures result in a panic automatically, improving code
> > readability and consistency across subsystems that require this behavio=
r.
> >
>
> Seems nice.
>
> > ...
> >
> > --- a/include/linux/memblock.h
> > +++ b/include/linux/memblock.h
> > @@ -417,6 +417,19 @@ static __always_inline void *memblock_alloc(phys_a=
ddr_t size, phys_addr_t align)
> >                                     MEMBLOCK_ALLOC_ACCESSIBLE, NUMA_NO_=
NODE);
> >  }
> >
> > +static __always_inline void *memblock_alloc_or_panic(phys_addr_t size,=
 phys_addr_t align)
>
> We lost the printing of the function name, but it's easy to retain with
> something like
>
> #define memblock_alloc_or_panic(size, align)    \
>                 __memblock_alloc_or_panic(size, align, __func__)
>
You're absolutely right, this was an oversight on my part. I=E2=80=99ll mak=
e
sure to update it with the correct function name.
> > +{
> > +     void *addr =3D memblock_alloc(size, align);
> > +
> > +     if (unlikely(!addr))
> > +#ifdef CONFIG_PHYS_ADDR_T_64BIT
> > +             panic("%s: Failed to allocate %llu bytes\n", __func__, si=
ze);
>
> Won't this always print "memblock_alloc_or_panic: Failed ..."?  Not
> very useful.
>
As mentioned above.
> > +#else
> > +             panic("%s: Failed to allocate %u bytes\n", __func__, size=
);
> > +#endif
>
> We can avoid the ifdef with printk's "%pap"?
>
I appreciate you pointing this out. I wasn=E2=80=99t aware of this approach=
,
but it=E2=80=99s a great idea. It definitely simplifies things, and I=E2=80=
=99ve
learned something new in the process. I'll incorporate this into the
code.
> > +     return addr;
> > +}
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AOm6qnnFDjyiQvUmyVA4iq5aJAO8NC%3DwcAvpKscvfRZKPnzkYw%40mail.gmail.com.
