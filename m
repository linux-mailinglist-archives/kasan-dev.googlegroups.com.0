Return-Path: <kasan-dev+bncBCU4TIPXUUFRBAXM7TBQMGQELEIEJXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1139.google.com (mail-yw1-x1139.google.com [IPv6:2607:f8b0:4864:20::1139])
	by mail.lfdr.de (Postfix) with ESMTPS id 324C2B0D22B
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Jul 2025 08:56:04 +0200 (CEST)
Received: by mail-yw1-x1139.google.com with SMTP id 00721157ae682-7194c6ce830sf63111667b3.1
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Jul 2025 23:56:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753167363; cv=pass;
        d=google.com; s=arc-20240605;
        b=b5k1YWpg+HUf0uW0Cg1yf19wPRmyDlQl4eDAK+21F4u4hgX7V1nPn+rT+i+hPuhbvb
         bwCWESdekEUX/qD3jIsikCVW3oiYLd5i2uf1al4OgElp8mDK3RmuN8zFYhzOBs3BnH3w
         WCxfjLVhiNvxIXAWc3RoThjY9xkjjJWYGT0N4isrT25lUqTedCzAMwD9zbAg9xjvI9Pd
         1/l5oKbkbZHOmv+NZXLX3K0MokYfFy+LxvQ1VPl403G0CAG6UWghJQNBEBGf67Y3DWvK
         W/llZzuR5fiXdJRYrzZXxMEn300ziUPWVvYpiGWPiX2nmQM124xNB/8rufoTKB0ZWwGF
         IUiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Dl7jzOS9siO9VzFctOVNAlOqIZxzBBQdjqYe/dJNtLc=;
        fh=4iKWgKLNNwoDFEdmTgGZmzQKJnipUkYJv6qInQ7/TFM=;
        b=jc0kUb/oL0UgSp+9lclWbSYIeao6RL7FtxYnoO651DbE09uyD54RPaxP8wDsTyQZkt
         ubNm1Qu6UWlxBsHA46PSEx2ZqagT2N9MM02HiGTrn/jtQjwxSbRivzvB07ReMw7E9xTK
         TR/fi+YixauWj0CpYNHKssTEaYcgzCZQzvfaaGlUkSfpsXDkPkQxH+KagZL9b4BE462O
         sDjyzqPrjwEjEL86RpR2IgttFRtOHbH0i3YI14a3IpFq//43Ry3re6TxOmZEeBx5haby
         iZX39O9OSSNyQri47uYqf409TTtUJ8X8xSgO3mzfSwPs/1ZCT21WpWa1HkazvsoWOe67
         GiOA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=CpfcgUnu;
       spf=pass (google.com: domain of ardb@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753167363; x=1753772163; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Dl7jzOS9siO9VzFctOVNAlOqIZxzBBQdjqYe/dJNtLc=;
        b=A9fBOpO0rm9JLz2L08lP12LXWTBiTCZGVIgBqwn2ILSfQ2ihZ8j8Z0wsjK5HaFoaXS
         fUK2azy9188Wfjsm9cFl94C5bOK19n+dcuWrsCj2NYEu5xrhmjkTdxSgU3UXU/zqFitb
         qAhBzHCjbFg7T3U5ObGQSwHUJK2JnYQ4cKpWYvvYmwnwBZeMhRhV0w6yAFnyDN8hSCIP
         jcymdZ+HmIPAmELHYwQmd5s1zqQW4oe6fejcvJgoYumymPOroYuJri1ulqiZKEi9YwEW
         iasFElvqSkxYzUyDKV7pQkXYJW7eP0WMiAQjxuB76c8mHjE2C1ElVAh4Zjc8MQA/jy4P
         yaLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753167363; x=1753772163;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Dl7jzOS9siO9VzFctOVNAlOqIZxzBBQdjqYe/dJNtLc=;
        b=VwfJdXM8fhfcNJLLSRBB8dverfOtYjFuSyhXL5YOZIg2UihS0TPBg/whc+MacJxWiX
         lRZpRVy5v6EzdEDU3F49SUNsulZms0Yh40Tr65O1mZlepHPhyr9BRFgbtq3bs75vABf+
         wS9LWAhpBnFwp/X8xj2aBowl9Fbsu2WwvkejGwgipRwoguOGCaJu/Ly0PQ52fSh9Imct
         6HIOkVi5xBP73qIkTIbGF4g5i/zjq9VLHmDag9NjnRr87zhY+G0QX9f1fCe721qz8kYK
         lcDEVUjMwYRdK2w7jel9MCjZlAhmaboi11TOv93COFHQa5Xn8zJXYu1OqAR4X3A0k4Hy
         u5EQ==
X-Forwarded-Encrypted: i=2; AJvYcCV9lBNfb7NHXCnLSSyAoEj1NRNq12bUA2A8V6EaC/4IpnIAW33cVmYn1yrJqdfxGKtI4G2l/Q==@lfdr.de
X-Gm-Message-State: AOJu0YyG7mZadQbt9L17WUec+zi31gNLqjSnoUU+yJ6zVkgUX1SWjoNA
	qKBkt073czHHLt3wm9J8o48OfJ9TX/SXGEIWhvQ2WyIRvzXDI3sRlYrN
X-Google-Smtp-Source: AGHT+IE6Lyt3yng+keI0g1Vzb+gZzOi7Cr5cjmwitimPbQUbEMYNtNo5MrOFRPhjH/vFpZWUTGWJAQ==
X-Received: by 2002:a05:6902:2388:b0:e8b:bd51:f480 with SMTP id 3f1490d57ef6-e8bc24397eamr26785616276.6.1753167362553;
        Mon, 21 Jul 2025 23:56:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfAYguUWVJ6q/McoZdK5xt4Rv6TGGh1hfr4zUy8xmKXOg==
Received: by 2002:a25:29c1:0:b0:e8b:ccea:f31d with SMTP id 3f1490d57ef6-e8bd46b3ca8ls4672764276.1.-pod-prod-06-us;
 Mon, 21 Jul 2025 23:56:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX76j9Wf8YCcMytba51AAdrYCH2fpSL9Df/TGpH3gggZJD0dyMIyjtVvVcKjhh2W/wsj63uezMiDwM=@googlegroups.com
X-Received: by 2002:a05:690c:b96:b0:70e:6333:64ac with SMTP id 00721157ae682-718370b0d82mr301803507b3.10.1753167361460;
        Mon, 21 Jul 2025 23:56:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753167361; cv=none;
        d=google.com; s=arc-20240605;
        b=JTB5RWzsWuncFakrgTT8fYYjNTUltqlo/VX6zfrVjj0sUThShNVnVg9c22skWqaquH
         pwERqv5Vglr0xHseoQc9l+shAANXsEyoz55+dvqrS5bMWT80vFS/5fatxoJLRFLDAHYY
         tktDvl+YzDD/cmAEXNf7ch65QdsmR86bURqjAp3Trc49Y6uC113q3BPPFh11Naif/6Xj
         j8K/36mgD8iDNUtUHhasoe1vvdNRsTXh6JliLTE3auvusdq+95jNh13O+HEA+cx347q8
         tuAZNPsefAG4GSxHMdms2EMbRt8cEXLQBlD99WbCoPd1Yc2GNCTC4OAmwKNGGOo4I1Xb
         UJOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WBGgbxt8MKz5LketeO1zUYFxZOLJFPQlwgRW6vu/bXs=;
        fh=gy+QaR8/NI5f+aeaazyqCpzI/OxaksrklH77/UJG8es=;
        b=jiOyezI1yY1V1/hlUclz6IeqN098BsmpX/aQTmVxPltqNJ0OcraC0B8BXXyRYEWSfs
         MdWnPKWNOPn/eC+niN5YKa/fXjegQWkyPwSgXGz04Ca6ipHAxW1Abcz2l9WQ7IP6CuTf
         hTo0o4kloyvKNR03Vxm5bvQwFMRDtfX678kCU9fw5uAawXLamfKbWgke1S3fFfdpXpl6
         tOCPMzOwJK8hrCbyy0Gh9ehyYrTSup82pFOmQSKI74XKvJ+BUMwmT9E5IfJkcNvFLoHy
         q6icAAz/PHhCAQvTU6knYtCKQajKG+ZSuk2PGHQbpAD2s9e2qFDbvEJNwsKdPbr3gGpU
         Z2ug==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=CpfcgUnu;
       spf=pass (google.com: domain of ardb@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-719530fd9c8si3984727b3.1.2025.07.21.23.56.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Jul 2025 23:56:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of ardb@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 1DFDAA54E32
	for <kasan-dev@googlegroups.com>; Tue, 22 Jul 2025 06:56:01 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A18C3C116C6
	for <kasan-dev@googlegroups.com>; Tue, 22 Jul 2025 06:56:00 +0000 (UTC)
Received: by mail-lj1-f182.google.com with SMTP id 38308e7fff4ca-32b43c5c04fso55580331fa.0
        for <kasan-dev@googlegroups.com>; Mon, 21 Jul 2025 23:56:00 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWPgb/+rnoaeU4eKmz9FMFmLRa0r9jA+6oJ5fPjw7G39kZY0vpJjpzlqUoQMa7hedYnBkj5RGkjwiw=@googlegroups.com
X-Received: by 2002:a05:651c:b11:b0:32b:952f:3e0 with SMTP id
 38308e7fff4ca-330d25506d3mr8241951fa.7.1753167358762; Mon, 21 Jul 2025
 23:55:58 -0700 (PDT)
MIME-Version: 1.0
References: <20250717231756.make.423-kees@kernel.org> <20250717232519.2984886-4-kees@kernel.org>
 <aHoHkDvvp4AHIzU1@kernel.org> <202507181541.B8CFAC7E@keescook>
 <CAMj1kXGAwjChyFvjQcTbL8dFXkFWnn9n47bkN7FP=+EsLNsJdg@mail.gmail.com>
 <aH42--h-ARsvX5Wk@willie-the-truck> <202507211311.8DAC4C7@keescook> <202507211349.D93679FB25@keescook>
In-Reply-To: <202507211349.D93679FB25@keescook>
From: "'Ard Biesheuvel' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 22 Jul 2025 16:55:47 +1000
X-Gmail-Original-Message-ID: <CAMj1kXGoy7D+_hKyQrT_uXdjuFMYGUEMDYdRf6mx69PLeuBQQg@mail.gmail.com>
X-Gm-Features: Ac12FXxN7NYW1J5gsbL-uJ8eWKShqoH6QBvGfux9lCX9EcW_ZhNmDxq92IzpXG0
Message-ID: <CAMj1kXGoy7D+_hKyQrT_uXdjuFMYGUEMDYdRf6mx69PLeuBQQg@mail.gmail.com>
Subject: Re: [PATCH v3 04/13] x86: Handle KCOV __init vs inline mismatches
To: Kees Cook <kees@kernel.org>
Cc: Will Deacon <will@kernel.org>, Mike Rapoport <rppt@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, Paolo Bonzini <pbonzini@redhat.com>, 
	Vitaly Kuznetsov <vkuznets@redhat.com>, Henrique de Moraes Holschuh <hmh@hmh.eng.br>, 
	Hans de Goede <hdegoede@redhat.com>, =?UTF-8?Q?Ilpo_J=C3=A4rvinen?= <ilpo.jarvinen@linux.intel.com>, 
	"Rafael J. Wysocki" <rafael@kernel.org>, Len Brown <lenb@kernel.org>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Michal Wilczynski <michal.wilczynski@intel.com>, 
	Juergen Gross <jgross@suse.com>, Andy Shevchenko <andriy.shevchenko@linux.intel.com>, 
	"Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>, Roger Pau Monne <roger.pau@citrix.com>, 
	David Woodhouse <dwmw@amazon.co.uk>, Usama Arif <usama.arif@bytedance.com>, 
	"Guilherme G. Piccoli" <gpiccoli@igalia.com>, Thomas Huth <thuth@redhat.com>, Brian Gerst <brgerst@gmail.com>, 
	kvm@vger.kernel.org, ibm-acpi-devel@lists.sourceforge.net, 
	platform-driver-x86@vger.kernel.org, linux-acpi@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, linux-efi@vger.kernel.org, 
	linux-mm@kvack.org, Ingo Molnar <mingo@kernel.org>, 
	"Gustavo A. R. Silva" <gustavoars@kernel.org>, Christoph Hellwig <hch@lst.de>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Masahiro Yamada <masahiroy@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Nicolas Schier <nicolas.schier@linux.dev>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Bill Wendling <morbo@google.com>, 
	Justin Stitt <justinstitt@google.com>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-doc@vger.kernel.org, 
	linux-arm-kernel@lists.infradead.org, kvmarm@lists.linux.dev, 
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org, 
	linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-security-module@vger.kernel.org, linux-kselftest@vger.kernel.org, 
	sparclinux@vger.kernel.org, llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ardb@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=CpfcgUnu;       spf=pass
 (google.com: domain of ardb@kernel.org designates 147.75.193.91 as permitted
 sender) smtp.mailfrom=ardb@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Ard Biesheuvel <ardb@kernel.org>
Reply-To: Ard Biesheuvel <ardb@kernel.org>
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

On Tue, 22 Jul 2025 at 06:49, Kees Cook <kees@kernel.org> wrote:
>
> On Mon, Jul 21, 2025 at 01:14:36PM -0700, Kees Cook wrote:
> > On Mon, Jul 21, 2025 at 01:47:55PM +0100, Will Deacon wrote:
> > > On Sun, Jul 20, 2025 at 04:10:01PM +1000, Ard Biesheuvel wrote:
> > > > On Sat, 19 Jul 2025 at 08:51, Kees Cook <kees@kernel.org> wrote:
> > > > > On Fri, Jul 18, 2025 at 11:36:32AM +0300, Mike Rapoport wrote:
> > > > > > On Thu, Jul 17, 2025 at 04:25:09PM -0700, Kees Cook wrote:
> > > > > > > When KCOV is enabled all functions get instrumented, unless the
> > > > > > > __no_sanitize_coverage attribute is used. To prepare for
> > > > > > > __no_sanitize_coverage being applied to __init functions, we have to
> > > > > > > handle differences in how GCC's inline optimizations get resolved. For
> > > > > > > x86 this means forcing several functions to be inline with
> > > > > > > __always_inline.
> > > > > > >
> > > > > > > Signed-off-by: Kees Cook <kees@kernel.org>
> > > > > >
> > > > > > ...
> > > > > >
> > > > > > > diff --git a/include/linux/memblock.h b/include/linux/memblock.h
> > > > > > > index bb19a2534224..b96746376e17 100644
> > > > > > > --- a/include/linux/memblock.h
> > > > > > > +++ b/include/linux/memblock.h
> > > > > > > @@ -463,7 +463,7 @@ static inline void *memblock_alloc_raw(phys_addr_t size,
> > > > > > >                                       NUMA_NO_NODE);
> > > > > > >  }
> > > > > > >
> > > > > > > -static inline void *memblock_alloc_from(phys_addr_t size,
> > > > > > > +static __always_inline void *memblock_alloc_from(phys_addr_t size,
> > > > > > >                                             phys_addr_t align,
> > > > > > >                                             phys_addr_t min_addr)
> > > > > >
> > > > > > I'm curious why from all memblock_alloc* wrappers this is the only one that
> > > > > > needs to be __always_inline?
> > > > >
> > > > > Thread-merge[1], adding Will Deacon, who was kind of asking the same
> > > > > question.
> > > > >
> > > > > Based on what I can tell, GCC has kind of fragile inlining logic, in the
> > > > > sense that it can change whether or not it inlines something based on
> > > > > optimizations. It looks like the kcov instrumentation being added (or in
> > > > > this case, removed) from a function changes the optimization results,
> > > > > and some functions marked "inline" are _not_ inlined. In that case, we end up
> > > > > with __init code calling a function not marked __init, and we get the
> > > > > build warnings I'm trying to eliminate.
> > >
> > > Got it, thanks for the explanation!
> > >
> > > > > So, to Will's comment, yes, the problem is somewhat fragile (though
> > > > > using either __always_inline or __init will deterministically solve it).
> > > > > We've tripped over this before with GCC and the solution has usually
> > > > > been to just use __always_inline and move on.
> > > > >
> > > >
> > > > Given that 'inline' is already a macro in the kernel, could we just
> > > > add __attribute__((__always_inline__)) to it when KCOV is enabled?
> > >
> > > That sounds like a more robust approach and, by the sounds of it, we
> > > could predicate it on GCC too. That would also provide a neat place for
> > > a comment describing the problem.
> > >
> > > Kees, would that work for you?
> >
> > That seems like an extremely large hammer for this problem, IMO. It
> > feels like it could cause new strange corner cases. I'd much prefer the
> > small fixes I've currently got since it keeps it focused. KCOV is
> > already enabled for "allmodconfig", so any new instances would be found
> > very quickly, etc. (And GCC's fragility in this regard has already been
> > exposed to these cases -- it's just that I changed one of the
> > combinations of __init vs inline vs instrumentation.
> >
> > I could give it a try, if you really prefer the big hammer approach...
>
> I gave it a try -- it fails spectacularly. ;) Let's stick to my small
> fixes instead?
>

Fair enough :-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAMj1kXGoy7D%2B_hKyQrT_uXdjuFMYGUEMDYdRf6mx69PLeuBQQg%40mail.gmail.com.
