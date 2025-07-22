Return-Path: <kasan-dev+bncBDAZZCVNSYPBBPVE73BQMGQEDG22ASQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id A1BA1B0DACA
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Jul 2025 15:29:36 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-6fb3bb94b5csf84068046d6.2
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Jul 2025 06:29:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753190975; cv=pass;
        d=google.com; s=arc-20240605;
        b=XibX9CflILn0f2xw+QhFg/YnhQ6rMnQlm+2BRmNHec1VTzlUYBvlqgPUAcd1Qe4Ihf
         vy1yyhFO6mRgs8j+zqCRxUZnm4NZqX5TGIcTXkywmwRzqqXF48i6w9JHCbKR3I2DhihF
         RSzXegjZ1Vgf5YyiVxXRIGkcphLzfdAScL28ygoEiBmmWi6XyU7LBOqeSdJOznwXZXSU
         uFUehs/T0z6jcLQx/v6Bt0YVQPSx5APkJR7yMWSS+pKIBACyQ0vlsDX7tLahkAqamp5U
         sCBRu9/tlaCXgPLb5LTaqf43K9Ql5Z1PAbAA3S8YHvI7vtVI3eRTkcmcORGSba0nyyzi
         IvjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=HsEiirtHk07eLfJh5fNbZiJKHjpVdzWxs86wsGQySak=;
        fh=xPviNPx3KY79PgulM9UydiDsHc1rutl7Dz9Pu6sxnGg=;
        b=M3MobxzAMTyeIjNGDQ0T4mpplZ20BRyXL6kaNEXW+kVxO044mgzUV0b9CV5w/Kqrfb
         6QEAFlT5NwsQJF6TAAvHH65XOgLaZMIyGof6gldQDGPoPbIuYh/RqYOEpQ+2idYrflso
         DzLz/KOQ4Q+1g/pBzYTvbaNfjZ7MhJSAynUZODcE2jLBfWO5ioOpR02bblEvqM7lZJC6
         Jh/XuWQ+RxZZI8TVIqQ2H5F1Xyntax6xHuG6V9d+ez5stnIfDdlj4ja3RIMV5SmYENIr
         Hkk9D4xZmWXfY00PLviAc0SKKx/1K+Fvr56etGVGl06yWZb5uz8vFRI9e7ecRKYq8rZw
         c6yg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=icCzbYE3;
       spf=pass (google.com: domain of will@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753190975; x=1753795775; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=HsEiirtHk07eLfJh5fNbZiJKHjpVdzWxs86wsGQySak=;
        b=hdaDYcGtClQ3RoGSfNfuf5pqfGel997ArLrqV7CLnQ3i/QXfKFQNGJI3/r55SwVzYu
         DXW6YMlMaJ8Y4z7ECINST+h31f5D1T7xJIp4g9ED+YzsHv1Q9lUhxLU3p4cQzCMRdRNa
         0QCzNEhpEWEW6dP33vL3keRubIo4TX+XtEh0f1jMvmpd/UdhycEYZTR/fV9VPlohAdyi
         MBxkeRcBfdyqZVT1Kjx7yJIJmlu2FUgw+J2eWYHDg9cgsKXmQv7mhHNhuj6T8ObcWqUq
         iYGD6Yip1dFE4fZ9f9L/Y2sMsZAy7q+zaDG/bGzn/TC4J/v+Ms/nvcFWNhXfhmZitGhk
         ic7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753190975; x=1753795775;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=HsEiirtHk07eLfJh5fNbZiJKHjpVdzWxs86wsGQySak=;
        b=Ihm2gUFApoy0eYglkyTUPyNdjNjNez/Rj5RarLXxpZZdTq4/yktrq8K1jYb0fbXJnL
         ewz6C0/AjHAkWGgufsvcgeFeqU9oua9x3LHOCe88GQ6Dr7rZc8aX/y3dwJ40PM2yxlAx
         YWzQfmHa+3ufAJYGjioxaCj7Kdp3K3smwzF/FjYQl4h4vo3tv74912oevK3h4sjTydEk
         lPDhtyhAaHpIyT/tiMXZ3EB98u79zqHRee+w6Zy/DeyYVKS2oEYXk78Vhfm363/NnqAy
         p2eJg7rwTKFKVdx0W8u6YGJLbhrZAF8m0BKnKVw1BFXx2SNlnKVVtEC8pPX9lZrRRI6l
         JaBw==
X-Forwarded-Encrypted: i=2; AJvYcCXvCyEL3wDh7VpGHt7e6tLcC91Xme3B32phrl8psw73Ay2ibXlzctEw86kmYMS5EIIDS+sD3g==@lfdr.de
X-Gm-Message-State: AOJu0YwCHloFiLUOKPIZvuGS0ORpDjtBnw8sqM7AWs/L3AC8XEkGYBx+
	GJCkZcHRUsjU+dVRip9nHqqKk1Eo+zW/YLXSyBg23Ngzs+uD6iBP249C
X-Google-Smtp-Source: AGHT+IEp/GYTf7KX7bi/pTe3YGz2UzwViwULUlt2VCkcaqVlB3JYwTzjQrF5kkM85eW/4cqFwEFsYA==
X-Received: by 2002:a05:6214:4608:b0:6fd:5cf4:cbb0 with SMTP id 6a1803df08f44-704f4aac3bemr379974786d6.25.1753190975033;
        Tue, 22 Jul 2025 06:29:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdYKE/yeI14PuZjE3xb1waGT7+hxKJZMy1w+pTvs+e2Rg==
Received: by 2002:ad4:5ba1:0:b0:6fa:c3dc:b004 with SMTP id 6a1803df08f44-70504c49387ls89151766d6.2.-pod-prod-01-us;
 Tue, 22 Jul 2025 06:29:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXB4VEU9XO+6pTgf4qhefhU0ncgn4ujJZxWLOnIRnBsYfWa9buTdH1y6ItnxYV5VcMjgafGYPo1aLE=@googlegroups.com
X-Received: by 2002:a05:6102:2911:b0:4e9:b0ec:9682 with SMTP id ada2fe7eead31-4f899a43b45mr13302954137.24.1753190974014;
        Tue, 22 Jul 2025 06:29:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753190974; cv=none;
        d=google.com; s=arc-20240605;
        b=TOeN6sL0pOlr8nMTnHvDtKw4nK4+/ut38cgF2Uc2nifSdFrDjabPYCCwrOB0UjUzT/
         oNVgpm3QJ+wQgCQRRdN3VDjL+lMBnA9W1WhuapHQKgIX5Yt/XMncGLWyIJhFAni7abaf
         Q7tCzZtJv24oVdyJ/SNRHGWtQH6WU08BnwDqKAWO56GxReso2ExX1453/oyk7cCYsvUg
         Nc7NwssxjJpKc/ntvnm71t8kyCZLjNlFewFQTvaHy6nH7ovrX6/7lsEzssmRhwEgOmTE
         /zYKGjSgFUAzBge+4RNKarwCwp6nm/ZXOEVnZM0wrzyrQGBQOuEPV23MyOcc+mpx2Q/4
         HtMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=1rBiQqj/Tcg+yYn70Z3uULhGEZLBEASKzOk/gNIAvos=;
        fh=cS6wsqnowDty06PO1WPvODhS5pY7/VvhPJakQXenp/0=;
        b=KyuDNdXX0nmka6qgawEE6hOhBUjhompc87Z5mCjzTF1Rzm2unIrJqxwWIqtO9Cu+td
         5arYwqfl4e5E1D5ySFfCzjuDs4yVLogvLsb6smMUZxukjBi9P371whpCNFJ6TR1RGMKJ
         +QQuEQTpyp3GdETlnk7Crsnp+nEZXa9BGzlFuVMpCLxDAvJI9DsJNX54lIa9jl/8U1hM
         JIpYSjcUCpMenI6Y0zA0UCAqwk/bef2EcIwQhpM0vxcvjUkvPY8Wb1BVVaKLKpZA+7K/
         sOhN1UYv3SC9GytM++EIi9mtiSGwEcOBfr3LvOXQDUb00sAf/fhmene/CcjwLRmzkdK2
         V27w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=icCzbYE3;
       spf=pass (google.com: domain of will@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-88b0ac07270si592961241.1.2025.07.22.06.29.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 22 Jul 2025 06:29:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id EB0C9439BA;
	Tue, 22 Jul 2025 13:29:32 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4B00BC4CEEB;
	Tue, 22 Jul 2025 13:29:23 +0000 (UTC)
Date: Tue, 22 Jul 2025 14:29:19 +0100
From: "'Will Deacon' via kasan-dev" <kasan-dev@googlegroups.com>
To: Ard Biesheuvel <ardb@kernel.org>
Cc: Kees Cook <kees@kernel.org>, Mike Rapoport <rppt@kernel.org>,
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
Message-ID: <aH-SL2V2bSPkJ18o@willie-the-truck>
References: <20250717231756.make.423-kees@kernel.org>
 <20250717232519.2984886-4-kees@kernel.org>
 <aHoHkDvvp4AHIzU1@kernel.org>
 <202507181541.B8CFAC7E@keescook>
 <CAMj1kXGAwjChyFvjQcTbL8dFXkFWnn9n47bkN7FP=+EsLNsJdg@mail.gmail.com>
 <aH42--h-ARsvX5Wk@willie-the-truck>
 <202507211311.8DAC4C7@keescook>
 <202507211349.D93679FB25@keescook>
 <CAMj1kXGoy7D+_hKyQrT_uXdjuFMYGUEMDYdRf6mx69PLeuBQQg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAMj1kXGoy7D+_hKyQrT_uXdjuFMYGUEMDYdRf6mx69PLeuBQQg@mail.gmail.com>
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=icCzbYE3;       spf=pass
 (google.com: domain of will@kernel.org designates 172.234.252.31 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Will Deacon <will@kernel.org>
Reply-To: Will Deacon <will@kernel.org>
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

On Tue, Jul 22, 2025 at 04:55:47PM +1000, Ard Biesheuvel wrote:
> On Tue, 22 Jul 2025 at 06:49, Kees Cook <kees@kernel.org> wrote:
> >
> > On Mon, Jul 21, 2025 at 01:14:36PM -0700, Kees Cook wrote:
> > > On Mon, Jul 21, 2025 at 01:47:55PM +0100, Will Deacon wrote:
> > > > On Sun, Jul 20, 2025 at 04:10:01PM +1000, Ard Biesheuvel wrote:
> > > > > On Sat, 19 Jul 2025 at 08:51, Kees Cook <kees@kernel.org> wrote:
> > > > > > On Fri, Jul 18, 2025 at 11:36:32AM +0300, Mike Rapoport wrote:
> > > > > > > On Thu, Jul 17, 2025 at 04:25:09PM -0700, Kees Cook wrote:
> > > > > > > > When KCOV is enabled all functions get instrumented, unless the
> > > > > > > > __no_sanitize_coverage attribute is used. To prepare for
> > > > > > > > __no_sanitize_coverage being applied to __init functions, we have to
> > > > > > > > handle differences in how GCC's inline optimizations get resolved. For
> > > > > > > > x86 this means forcing several functions to be inline with
> > > > > > > > __always_inline.
> > > > > > > >
> > > > > > > > Signed-off-by: Kees Cook <kees@kernel.org>
> > > > > > >
> > > > > > > ...
> > > > > > >
> > > > > > > > diff --git a/include/linux/memblock.h b/include/linux/memblock.h
> > > > > > > > index bb19a2534224..b96746376e17 100644
> > > > > > > > --- a/include/linux/memblock.h
> > > > > > > > +++ b/include/linux/memblock.h
> > > > > > > > @@ -463,7 +463,7 @@ static inline void *memblock_alloc_raw(phys_addr_t size,
> > > > > > > >                                       NUMA_NO_NODE);
> > > > > > > >  }
> > > > > > > >
> > > > > > > > -static inline void *memblock_alloc_from(phys_addr_t size,
> > > > > > > > +static __always_inline void *memblock_alloc_from(phys_addr_t size,
> > > > > > > >                                             phys_addr_t align,
> > > > > > > >                                             phys_addr_t min_addr)
> > > > > > >
> > > > > > > I'm curious why from all memblock_alloc* wrappers this is the only one that
> > > > > > > needs to be __always_inline?
> > > > > >
> > > > > > Thread-merge[1], adding Will Deacon, who was kind of asking the same
> > > > > > question.
> > > > > >
> > > > > > Based on what I can tell, GCC has kind of fragile inlining logic, in the
> > > > > > sense that it can change whether or not it inlines something based on
> > > > > > optimizations. It looks like the kcov instrumentation being added (or in
> > > > > > this case, removed) from a function changes the optimization results,
> > > > > > and some functions marked "inline" are _not_ inlined. In that case, we end up
> > > > > > with __init code calling a function not marked __init, and we get the
> > > > > > build warnings I'm trying to eliminate.
> > > >
> > > > Got it, thanks for the explanation!
> > > >
> > > > > > So, to Will's comment, yes, the problem is somewhat fragile (though
> > > > > > using either __always_inline or __init will deterministically solve it).
> > > > > > We've tripped over this before with GCC and the solution has usually
> > > > > > been to just use __always_inline and move on.
> > > > > >
> > > > >
> > > > > Given that 'inline' is already a macro in the kernel, could we just
> > > > > add __attribute__((__always_inline__)) to it when KCOV is enabled?
> > > >
> > > > That sounds like a more robust approach and, by the sounds of it, we
> > > > could predicate it on GCC too. That would also provide a neat place for
> > > > a comment describing the problem.
> > > >
> > > > Kees, would that work for you?
> > >
> > > That seems like an extremely large hammer for this problem, IMO. It
> > > feels like it could cause new strange corner cases. I'd much prefer the
> > > small fixes I've currently got since it keeps it focused. KCOV is
> > > already enabled for "allmodconfig", so any new instances would be found
> > > very quickly, etc. (And GCC's fragility in this regard has already been
> > > exposed to these cases -- it's just that I changed one of the
> > > combinations of __init vs inline vs instrumentation.
> > >
> > > I could give it a try, if you really prefer the big hammer approach...
> >
> > I gave it a try -- it fails spectacularly. ;) Let's stick to my small
> > fixes instead?
> >
> 
> Fair enough :-)

(but please add the helpful explanation you provided to the commit message!)

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aH-SL2V2bSPkJ18o%40willie-the-truck.
