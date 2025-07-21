Return-Path: <kasan-dev+bncBDCPL7WX3MKBB46P7LBQMGQERTQ6BFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 90073B0CC1B
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Jul 2025 22:49:57 +0200 (CEST)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-2ffb3834eb5sf3317453fac.3
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Jul 2025 13:49:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753130996; cv=pass;
        d=google.com; s=arc-20240605;
        b=B8Y4NqujQhKnbSCgrqK0U0J1yIuWZKRKkS59c4zDozPQlgQDtf0YGd/Tb/D5OpPUdt
         eNfbERBBdLpB4AxwIOb1mHpFlbonIAqzpvWTMqo9BnUYueZPqKrITe3dkYZ0N0DE6g/U
         +a+uRyiQx42NsZ25YpQcFVXvwVXnNuEBj5kvoxn16w82JByYzfq+sBABF1rEThVilCOf
         6V21veoCw4Hn7zZo4jZ21I5ubGKeb+cAnhw09hYfXDweAuIJ+Asl6+UP92Q1bAvJQ6PH
         xVuOn71raoPgeQGrU4IceAAA6jp3a7aK1KRM1xW9k66vcTn4joA/MOCRdLquQA54wlja
         AHwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=oT9E66+KL+Rhg9KvHyUDZVs7y86TU35UkSQ9CUVjzMM=;
        fh=c13yvT2PQX/iUQaWnewZ3oD7pK4mHwnci9u65k/uB/E=;
        b=X2ZZgV9rRbmFSyEgorkdOZN7K3eXFWHsaPINMbew1kIS7QPuR3WfZPD489uIdetr3Y
         NKCHQbPaS/31wrEL2ceeL2ArihXN16u6p2mcQy60BzUscv6+ITNWBj0BIjg+2GSXFAhZ
         KP4tnHx3hCT53AWzQYSUyCc95y0tyIWf5pK/DHGThxq6ds0VIYIeL8BOvOgDRAweP4RI
         /D0si/iXO4/ijIWolEUG/Ld3p25vEdUgNDQ+Sd2z0hqsTGEXWWlZjUphyo9eFy43RsQA
         JKKS8NDM0TX/U7jn8N8gVMv3y3G8V5M0xkJbDW3g5dSmLXnFo2mi8p8OqwgCsrKRjCmB
         5UiQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=USwBlGGy;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753130996; x=1753735796; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=oT9E66+KL+Rhg9KvHyUDZVs7y86TU35UkSQ9CUVjzMM=;
        b=UxLrx35wmkwXETbve/zNuUm3U08pZdEnfoe0HRBGGZO3Jy47IpyX25EDQ5LB8q3fqZ
         54VpjcL1a6FGTEIoptXCS/4IliCOgknTVoKpiF8uig1kDPs29ANXVelaTddDVmGApCBj
         raXwe6sMHX9FHb4F5w3OGlLs4s3guohUo4+98X6qzOsDpgB9v6Lo68Vz2hKukuEnJbu2
         hW/j2X4bP3ZKJFVaWUY2f643vQl6ElKRAAjpeRlro0yhQAnE1U97UtXDXZDHlAwuOcix
         nqDtiwX0oZPpAPF/zeYl9cZEHJS6xrU4STd71DOe5PaFK2CHvU1fzw/X4d9c6nC5P4aN
         7JCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753130996; x=1753735796;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=oT9E66+KL+Rhg9KvHyUDZVs7y86TU35UkSQ9CUVjzMM=;
        b=Ju6SGDn+JrgLxXBnV16Vk8Q4gS2fTP/UVZHsd0NvI4qMnEkc8xD6maxTgDVVOSW8et
         mybSFGy9+vpUH7P2lmW2H4/gnB/R3aLCYPtuNCQI9Vty5sdDhlagq6B+tpOXSKep9asL
         5qUTwPmcYE/Nbvqtl32pqwQc/cHXliHyM6mmLBiFgeW4xYFDGV/6E5NzXeu89pPf0fuY
         YmBoDY2WAo2nent+a1OfRcl4vU6DKipY2zfPppHxZ9szqpHLY1rW9aY+0WwdpNZuW8dp
         NqglV79/rJ5ZCGEVyRv9TqbkJmcfwBFpY+tyMwBGLh5SiHemcfBEAp92RXHPiS8xbAzI
         A6Rw==
X-Forwarded-Encrypted: i=2; AJvYcCWygebqOb69MD8lJnv7FwYSLWyvc2+TcFEwr+S5MOrdmRPc321kzttaOQkFh8W/yn5CJnGwMg==@lfdr.de
X-Gm-Message-State: AOJu0Yzuwrjg4vk+TdDB2iahwA9MRaK0qwNvNO0GErX2JPnzoa3PY6+I
	en6ZXSP4BVsLsqAqThOb+25vrAXvMu7QXySxLvJ13cKudIIXlLsaQmfs
X-Google-Smtp-Source: AGHT+IEq9Puj5/QF2Rj36z+OV6X6GSDb2W1rNDtviKbl4n24KoANBAYWiHXxEuxT0gl9GQJhcah88g==
X-Received: by 2002:a05:6871:6d01:b0:2e9:1c4a:9fdc with SMTP id 586e51a60fabf-2ffb22e5d34mr15636195fac.17.1753130995973;
        Mon, 21 Jul 2025 13:49:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZde+uMliOhGj1XWzvQToAFq8dfvGpV5XwOjBGOlXUOCIw==
Received: by 2002:a05:6870:8804:b0:2ef:3020:be7e with SMTP id
 586e51a60fabf-2ffca981814ls2002763fac.1.-pod-prod-06-us; Mon, 21 Jul 2025
 13:49:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWTj42V5yD6Jpizg3aHZa6FQXRHclPx+PyFIzqq2oYect6H7a8fOf5qSt08AlUSP5P0Mx3UX2iPxrU=@googlegroups.com
X-Received: by 2002:a05:6830:64ca:b0:727:3957:8522 with SMTP id 46e09a7af769-73e662d8d9dmr16685131a34.20.1753130995210;
        Mon, 21 Jul 2025 13:49:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753130995; cv=none;
        d=google.com; s=arc-20240605;
        b=d3Pau6F+rxYnN2N1vlfqXZ20wN0voyIiKxFDUvQFMVT68kzrBQkU1+3vTzuUdL41Sd
         YrEZFfLvsNr1EJ3gjtTJzuFbuY7ePKdMG3U3veHgxlEK1HBcHonDcUSrdkmRSRzMBdti
         kpl7cyVaMWutWA6pFc006hr9QcvBXfFF75IIvsZ7eMiD89/jVKk9HrfQDbr1X2j+lkX0
         fTrlxD3IrvPlzB2hHHjaTFxX/xbLrkxIVWGMhF7Ipg9oOKJuWdEtrQ2oR5Lb6bcflSrR
         6uOIfjleAtqGvxUOqtDWJ/LL1m7Cau4ARk/3kQuo9vcUgSCqu8hs4MCq6frA0QAUTvOt
         oRtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=TgY4TtZ2A2t9T1odFgdUEhawq4pWen4ruPSFuhNnlGo=;
        fh=tZyt6e0HlhPmBOSekvjLfrL8od2tSeZQJlfFsWQOwgU=;
        b=gWj79FkS6Rncf4C2qjuqbJCzyOwDuh4ylLlLj6uOWtg2wRTy9dyArpz9+Mj00hJEWy
         LfX95feER4wWcqSNbSmXF6G7H0V2xZK4PmymZ505/CH0LCX8rC/ZwbmuR14an8BPUsfJ
         ywBUt71vKg6hkFXNiyumYPJsULVUbSZYZGQgDDSISnqPpNPucgnIv6ZRdJMlfOSSkgG4
         Pj1zd6NJuffxtA5MDHtsr+4bPgWe3U5eUVkXG1xJ8fs/0Ce6ProuiJF0NEz3wGwQN3wE
         FNqI8Hl8UNxVl1KZ+AFCVQ6vDr2XuQO/eFaxpTTaUv9ZMhhLS13tZRyOb+4OcXyAnT3M
         4Q+A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=USwBlGGy;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-615bcab4e94si70363eaf.1.2025.07.21.13.49.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Jul 2025 13:49:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id A6BBA5C4B8E;
	Mon, 21 Jul 2025 20:49:54 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 464E6C4CEF4;
	Mon, 21 Jul 2025 20:49:54 +0000 (UTC)
Date: Mon, 21 Jul 2025 13:49:53 -0700
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Will Deacon <will@kernel.org>
Cc: Ard Biesheuvel <ardb@kernel.org>, Mike Rapoport <rppt@kernel.org>,
	Arnd Bergmann <arnd@arndb.de>, Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Paolo Bonzini <pbonzini@redhat.com>,
	Vitaly Kuznetsov <vkuznets@redhat.com>,
	Henrique de Moraes Holschuh <hmh@hmh.eng.br>,
	Hans de Goede <hdegoede@redhat.com>,
	Ilpo =?iso-8859-1?Q?J=E4rvinen?= <ilpo.jarvinen@linux.intel.com>,
	"Rafael J. Wysocki" <rafael@kernel.org>,
	Len Brown <lenb@kernel.org>, Masami Hiramatsu <mhiramat@kernel.org>,
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
	linux-mm@kvack.org, Ingo Molnar <mingo@kernel.org>,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	Christoph Hellwig <hch@lst.de>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-doc@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org, kvmarm@lists.linux.dev,
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
	linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-security-module@vger.kernel.org,
	linux-kselftest@vger.kernel.org, sparclinux@vger.kernel.org,
	llvm@lists.linux.dev
Subject: Re: [PATCH v3 04/13] x86: Handle KCOV __init vs inline mismatches
Message-ID: <202507211349.D93679FB25@keescook>
References: <20250717231756.make.423-kees@kernel.org>
 <20250717232519.2984886-4-kees@kernel.org>
 <aHoHkDvvp4AHIzU1@kernel.org>
 <202507181541.B8CFAC7E@keescook>
 <CAMj1kXGAwjChyFvjQcTbL8dFXkFWnn9n47bkN7FP=+EsLNsJdg@mail.gmail.com>
 <aH42--h-ARsvX5Wk@willie-the-truck>
 <202507211311.8DAC4C7@keescook>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <202507211311.8DAC4C7@keescook>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=USwBlGGy;       spf=pass
 (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
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

On Mon, Jul 21, 2025 at 01:14:36PM -0700, Kees Cook wrote:
> On Mon, Jul 21, 2025 at 01:47:55PM +0100, Will Deacon wrote:
> > On Sun, Jul 20, 2025 at 04:10:01PM +1000, Ard Biesheuvel wrote:
> > > On Sat, 19 Jul 2025 at 08:51, Kees Cook <kees@kernel.org> wrote:
> > > > On Fri, Jul 18, 2025 at 11:36:32AM +0300, Mike Rapoport wrote:
> > > > > On Thu, Jul 17, 2025 at 04:25:09PM -0700, Kees Cook wrote:
> > > > > > When KCOV is enabled all functions get instrumented, unless the
> > > > > > __no_sanitize_coverage attribute is used. To prepare for
> > > > > > __no_sanitize_coverage being applied to __init functions, we have to
> > > > > > handle differences in how GCC's inline optimizations get resolved. For
> > > > > > x86 this means forcing several functions to be inline with
> > > > > > __always_inline.
> > > > > >
> > > > > > Signed-off-by: Kees Cook <kees@kernel.org>
> > > > >
> > > > > ...
> > > > >
> > > > > > diff --git a/include/linux/memblock.h b/include/linux/memblock.h
> > > > > > index bb19a2534224..b96746376e17 100644
> > > > > > --- a/include/linux/memblock.h
> > > > > > +++ b/include/linux/memblock.h
> > > > > > @@ -463,7 +463,7 @@ static inline void *memblock_alloc_raw(phys_addr_t size,
> > > > > >                                       NUMA_NO_NODE);
> > > > > >  }
> > > > > >
> > > > > > -static inline void *memblock_alloc_from(phys_addr_t size,
> > > > > > +static __always_inline void *memblock_alloc_from(phys_addr_t size,
> > > > > >                                             phys_addr_t align,
> > > > > >                                             phys_addr_t min_addr)
> > > > >
> > > > > I'm curious why from all memblock_alloc* wrappers this is the only one that
> > > > > needs to be __always_inline?
> > > >
> > > > Thread-merge[1], adding Will Deacon, who was kind of asking the same
> > > > question.
> > > >
> > > > Based on what I can tell, GCC has kind of fragile inlining logic, in the
> > > > sense that it can change whether or not it inlines something based on
> > > > optimizations. It looks like the kcov instrumentation being added (or in
> > > > this case, removed) from a function changes the optimization results,
> > > > and some functions marked "inline" are _not_ inlined. In that case, we end up
> > > > with __init code calling a function not marked __init, and we get the
> > > > build warnings I'm trying to eliminate.
> > 
> > Got it, thanks for the explanation!
> > 
> > > > So, to Will's comment, yes, the problem is somewhat fragile (though
> > > > using either __always_inline or __init will deterministically solve it).
> > > > We've tripped over this before with GCC and the solution has usually
> > > > been to just use __always_inline and move on.
> > > >
> > > 
> > > Given that 'inline' is already a macro in the kernel, could we just
> > > add __attribute__((__always_inline__)) to it when KCOV is enabled?
> > 
> > That sounds like a more robust approach and, by the sounds of it, we
> > could predicate it on GCC too. That would also provide a neat place for
> > a comment describing the problem.
> > 
> > Kees, would that work for you?
> 
> That seems like an extremely large hammer for this problem, IMO. It
> feels like it could cause new strange corner cases. I'd much prefer the
> small fixes I've currently got since it keeps it focused. KCOV is
> already enabled for "allmodconfig", so any new instances would be found
> very quickly, etc. (And GCC's fragility in this regard has already been
> exposed to these cases -- it's just that I changed one of the
> combinations of __init vs inline vs instrumentation.
> 
> I could give it a try, if you really prefer the big hammer approach...

I gave it a try -- it fails spectacularly. ;) Let's stick to my small
fixes instead?

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202507211349.D93679FB25%40keescook.
