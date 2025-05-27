Return-Path: <kasan-dev+bncBDCPL7WX3MKBB4XD2TAQMGQESAZIIQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 34C6EAC46C8
	for <lists+kasan-dev@lfdr.de>; Tue, 27 May 2025 05:31:00 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id 006d021491bc7-60212c73868sf2155344eaf.3
        for <lists+kasan-dev@lfdr.de>; Mon, 26 May 2025 20:31:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1748316659; cv=pass;
        d=google.com; s=arc-20240605;
        b=gDwbqLT43th9O+6aqM99Vu7lVc2UekOxIBQ9sHB+v4jX+uEpFhSGdrZ9Z4Xh5RAwcy
         1DET/AFMHwkIzlbf6cDdcb1Ret53yuTFN60UhLWDfUout3snnrgkHAyUDrQNaAhr8t/z
         fnk69S90Oxx+8gAOEeKsef8zJDvShVqPLam728mAGxdzj0vvwkjVkd5hpLlll4Th/Q5o
         qXK/e1XNgAjkbVkQLLfbzPzyBiyqfrwJKO9Lx19/cuehbRaCJmxz00L2ofD+5Eyp9APo
         YeRX/KeI504fJtE1CwsmkdOe4xD9IrXteiSk/mFakNaZkpSYQSJAbiJjQJlLyIdaOKrF
         WZ4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=MnBpc/3wJik5x6aiCnpjQoxXvdL2qVVZhE9vE1PD0go=;
        fh=Gde7R5nKKAe1qp8xR/YEkJRXFttxyp8dMEFh+Q8X++Y=;
        b=Oocv2G4c9NCiOgk0G2igtkzqmD5mSnRLmzqLzq+AHY1AQL74orncNRPpwMjSyoBC98
         C1cxoBkcsAzQ+XMp2aAubyF4QHj9jRcZNuUw/5Raom6VvXN9HEAhhGUDfMI/Mf9KFGai
         GatqL60PnmJOVMDbRuFJr37MY72hGNJqO865bNp7AT9zoqu4zD9tTKr2vTviDwppRd6X
         yUGgCmV9OFN5qMCi/5WbmR9ggrIKi3JWedO+bnYIydvZiRcme7jSFnvrxwbr6tecnZgk
         r1mLqa9kHG+wVWVjpMHPt7/liR8wtZ4+YJGkY8bsFOjT2ItMn+mpziClOCDY358PeiK/
         FACw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PDpCasoc;
       spf=pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1748316658; x=1748921458; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=MnBpc/3wJik5x6aiCnpjQoxXvdL2qVVZhE9vE1PD0go=;
        b=XgXLDhHip2tEhmUZmwWcWu6zO6PqeeQnnviiubBEEEb+J1etUrusQEZM5Hjfg2rda6
         2mQNs68huSYmKLJZZDlTh3X815iSZGHXhZrC285ecD7H4mXRVGHosgJOZHXggqH0dmep
         +xQ+8d2qoy+cUNIW3yIl1okgYAxty67ziGuM1JPqIPMozga/qmDgRHM5riXMLxNmAFcC
         twLGkDWKsaRV+fxr7qR4UN0o1+OCy71nBD7HSibmbuIJqMGwcLZKepEZ+BApfnbZZc1w
         4yQrG/PSyhi2zlnCbViazQWHUzP/TfV/3RFCcLd4YboDGFZQ/IKQXCUZ2nhb4igirWlB
         +MNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1748316658; x=1748921458;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=MnBpc/3wJik5x6aiCnpjQoxXvdL2qVVZhE9vE1PD0go=;
        b=gmVGPqTLrnH7EIjDVdAgZnQz9U0QmlGF3H1a+KTOnEkdiVyoiqyKXjQ5ubOrZ+KsyD
         5WwSAg4TeVnI+M6k28FkzQMMR9q99GuLGnK3xoxfatyAULxrB5ZdULTmV+pL3L9iwPZb
         OWd5e82KxOmJdvX4rF1/mkV8k2JOp7K9WJX1SIsGm1eaTZHSCFsQFm823aHyI4cGDjwB
         FJYBMYuyBKF2yBJ9yRpQugAX6RgzfhJ/H4fv7gVOJN5R8lcSoipeyQaZxCEUpvQXD/HI
         sRB+iBIO2LwRd+nEqssWyB9FfNfVFieZhQBG2NhZXLv7bxEppE+bq/ITgEsgtPtzMNkx
         +D+g==
X-Forwarded-Encrypted: i=2; AJvYcCU68OQqTYY0GO/Ua4UAbdQ2uyhz8ZsNeDddXinXV+IHouGvW92fHMDQjV+gg0Somz1hNs9Rqw==@lfdr.de
X-Gm-Message-State: AOJu0YyWl2yAS08mJD/M2K20oPj7S7HxPrshduh1sSt1gr77ge+zwkjQ
	c+QPvjtOWcYobOQTwJMfQIwrIQxZPFLBvJuoIyhySNQksynKxuMdT8GH
X-Google-Smtp-Source: AGHT+IE1rVKtRztGeSbxlKQVeBcGo/oKRqR8wD6T6Y0xoLbFe+MJUv8ZxUu7X1woBV7d55aPgNfqjA==
X-Received: by 2002:a05:6820:4b95:b0:60b:cd81:9079 with SMTP id 006d021491bc7-60bcd8195f7mr322567eaf.5.1748316658571;
        Mon, 26 May 2025 20:30:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBG13s2exQBmr+ph8fs98NNri/GRjGsMLp6HqC/KoJaNDw==
Received: by 2002:a4a:e219:0:b0:608:3554:1a64 with SMTP id 006d021491bc7-60b9f4e9bfcls868939eaf.0.-pod-prod-01-us;
 Mon, 26 May 2025 20:30:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWlzCUNTzBOC1OgCKvLG53cdsUy3rYVrREwlVYdlxEwW7YIc4kctGmWqvHf6dWgqq3I5qRNwawcwLY=@googlegroups.com
X-Received: by 2002:a05:6808:3307:b0:3f8:e55c:16d6 with SMTP id 5614622812f47-4064684d0dfmr6493102b6e.28.1748316657357;
        Mon, 26 May 2025 20:30:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1748316657; cv=none;
        d=google.com; s=arc-20240605;
        b=YLc+Z2UotMgV2Mk9a7TMPdWrWUZCRRtq/CZisNd8gKE7L7Cg08jcdqfQZjMitGVncV
         KWDm+Rd/qVr3wKAmDWji4hhUzpvrWUrcY/l5rdzxS+cyCNNBlniQSOurH+bocWNkLvSi
         Mt4uex6BcYOouzlkhfYV114GYFyh05+cx0JEIDoO4+ssqxTm96JKb8kazQVKOWEFYqYG
         BqIv8ACtO+d4MO/m6mEW9/NlqUecEvCWer2vHbewqPrx268gSd9d6j4REDb1y+2YrLnl
         l8DgiMBnLsBaRNWX27z908KRF8XQemtl+MgEcdoS8zT+1WqgV4lwduMbluJetiNUJdWa
         E6Hg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=SDrfCgmMTs1VuKzAuYTBlXP2aVvXV8ECpqmQImLT4bc=;
        fh=p4fvIaqFMe8iwYkETGsqIw9syhqKnxmLDxbKT0ubeL0=;
        b=DNPeSippFF8zqCUEqvpNmIoT6FYr6/AtGgcKv9TDLgpjgL2NtsgNuirmhrgWCoD7JY
         Ebiyo65JN30p1Jhuc/HhWdVNL0CoH6fJeQ5sQKVw+hl9BlT3bMPtHAwL4pZtSUesZRxt
         /Lisp5EBlwYsjdUKD4Ygiwf40hJ1GoG53JrZX311V5tQLOsKFy9MegNkTA4vppRhADSC
         IH4mVfqrhKWfhVeY4DgmQ9w+8ih7A8fxngtfeipH7ZjrhNmNyKtbcbw+y8r/f42x8ymC
         yh23mD5I8ODK23hjX+XBEGlT7HvMlWkukKpjx6emIVylukMkTYSd0RzqJrHUO5Z9n6CV
         HI1w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PDpCasoc;
       spf=pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-404d97d0133si31480b6e.1.2025.05.26.20.30.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 26 May 2025 20:30:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 3A5BE6113B;
	Tue, 27 May 2025 03:30:56 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D4DDFC4CEEB;
	Tue, 27 May 2025 03:30:55 +0000 (UTC)
Date: Mon, 26 May 2025 20:30:52 -0700
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Ilpo =?iso-8859-1?Q?J=E4rvinen?= <ilpo.jarvinen@linux.intel.com>
Cc: Arnd Bergmann <arnd@arndb.de>, Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Paolo Bonzini <pbonzini@redhat.com>,
	Vitaly Kuznetsov <vkuznets@redhat.com>,
	Henrique de Moraes Holschuh <hmh@hmh.eng.br>,
	Hans de Goede <hdegoede@redhat.com>,
	"Rafael J. Wysocki" <rafael@kernel.org>,
	Len Brown <lenb@kernel.org>, Masami Hiramatsu <mhiramat@kernel.org>,
	Ard Biesheuvel <ardb@kernel.org>, Mike Rapoport <rppt@kernel.org>,
	Michal Wilczynski <michal.wilczynski@intel.com>,
	Juergen Gross <jgross@suse.com>,
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	"Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
	Roger Pau Monne <roger.pau@citrix.com>,
	David Woodhouse <dwmw@amazon.co.uk>,
	Usama Arif <usama.arif@bytedance.com>,
	"Guilherme G. Piccoli" <gpiccoli@igalia.com>,
	Thomas Huth <thuth@redhat.com>, Brian Gerst <brgerst@gmail.com>,
	kvm@vger.kernel.org, ibm-acpi-devel@lists.sourceforge.net,
	platform-driver-x86@vger.kernel.org, linux-acpi@vger.kernel.org,
	linux-trace-kernel@vger.kernel.org, linux-efi@vger.kernel.org,
	linux-mm@kvack.org, "Gustavo A. R. Silva" <gustavoars@kernel.org>,
	Christoph Hellwig <hch@lst.de>, Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	LKML <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	kvmarm@lists.linux.dev, linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org, linux-hardening@vger.kernel.org,
	linux-kbuild@vger.kernel.org, linux-security-module@vger.kernel.org,
	linux-kselftest@vger.kernel.org, sparclinux@vger.kernel.org,
	llvm@lists.linux.dev
Subject: Re: [PATCH v2 04/14] x86: Handle KCOV __init vs inline mismatches
Message-ID: <202505262028.E5B7A7E8@keescook>
References: <20250523043251.it.550-kees@kernel.org>
 <20250523043935.2009972-4-kees@kernel.org>
 <ba4f4fd0-1bcf-3d84-c08e-ba0dd040af16@linux.intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <ba4f4fd0-1bcf-3d84-c08e-ba0dd040af16@linux.intel.com>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=PDpCasoc;       spf=pass
 (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

On Mon, May 26, 2025 at 12:53:13AM +0300, Ilpo J=C3=A4rvinen wrote:
> On Thu, 22 May 2025, Kees Cook wrote:
>=20
> > When KCOV is enabled all functions get instrumented, unless the
> > __no_sanitize_coverage attribute is used. To prepare for
> > __no_sanitize_coverage being applied to __init functions, we have to
> > handle differences in how GCC's inline optimizations get resolved. For
> > x86 this means forcing several functions to be inline with
> > __always_inline.
> >=20
> > Signed-off-by: Kees Cook <kees@kernel.org>
> > ---
> > Cc: Thomas Gleixner <tglx@linutronix.de>
> > Cc: Ingo Molnar <mingo@redhat.com>
> > Cc: Borislav Petkov <bp@alien8.de>
> > Cc: Dave Hansen <dave.hansen@linux.intel.com>
> > Cc: <x86@kernel.org>
> > Cc: "H. Peter Anvin" <hpa@zytor.com>
> > Cc: Paolo Bonzini <pbonzini@redhat.com>
> > Cc: Vitaly Kuznetsov <vkuznets@redhat.com>
> > Cc: Henrique de Moraes Holschuh <hmh@hmh.eng.br>
> > Cc: Hans de Goede <hdegoede@redhat.com>
> > Cc: "Ilpo J=C3=A4rvinen" <ilpo.jarvinen@linux.intel.com>
> > Cc: "Rafael J. Wysocki" <rafael@kernel.org>
> > Cc: Len Brown <lenb@kernel.org>
> > Cc: Masami Hiramatsu <mhiramat@kernel.org>
> > Cc: Ard Biesheuvel <ardb@kernel.org>
> > Cc: Mike Rapoport <rppt@kernel.org>
> > Cc: Michal Wilczynski <michal.wilczynski@intel.com>
> > Cc: Juergen Gross <jgross@suse.com>
> > Cc: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
> > Cc: "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>
> > Cc: Roger Pau Monne <roger.pau@citrix.com>
> > Cc: David Woodhouse <dwmw@amazon.co.uk>
> > Cc: Usama Arif <usama.arif@bytedance.com>
> > Cc: "Guilherme G. Piccoli" <gpiccoli@igalia.com>
> > Cc: Thomas Huth <thuth@redhat.com>
> > Cc: Brian Gerst <brgerst@gmail.com>
> > Cc: <kvm@vger.kernel.org>
> > Cc: <ibm-acpi-devel@lists.sourceforge.net>
> > Cc: <platform-driver-x86@vger.kernel.org>
> > Cc: <linux-acpi@vger.kernel.org>
> > Cc: <linux-trace-kernel@vger.kernel.org>
> > Cc: <linux-efi@vger.kernel.org>
> > Cc: <linux-mm@kvack.org>
> > ---
>=20
> > diff --git a/drivers/platform/x86/thinkpad_acpi.c b/drivers/platform/x8=
6/thinkpad_acpi.c
> > index e7350c9fa3aa..0518d5b1f4ec 100644
> > --- a/drivers/platform/x86/thinkpad_acpi.c
> > +++ b/drivers/platform/x86/thinkpad_acpi.c
> > @@ -559,12 +559,12 @@ static unsigned long __init tpacpi_check_quirks(
> >  	return 0;
> >  }
> > =20
> > -static inline bool __pure __init tpacpi_is_lenovo(void)
> > +static __always_inline bool __pure tpacpi_is_lenovo(void)
> >  {
> >  	return thinkpad_id.vendor =3D=3D PCI_VENDOR_ID_LENOVO;
> >  }
> > =20
> > -static inline bool __pure __init tpacpi_is_ibm(void)
> > +static __always_inline bool __pure tpacpi_is_ibm(void)
> >  {
> >  	return thinkpad_id.vendor =3D=3D PCI_VENDOR_ID_IBM;
> >  }
>=20
> Hi Kees,
>=20
> What's your plan on upstreaming route/timeline for this? I'd prefer to=20
> retain full control over this file as we were planning on some=20
> reorganization of files into lenovo/ subdir.

I'm not in a big rush. I'm hoping to have this all in place for v6.17,
but the Clang feature won't be in a released compiler version until
September. :) I can send this bit separately for your tree.

Thanks for taking a look!

--=20
Kees Cook

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
02505262028.E5B7A7E8%40keescook.
