Return-Path: <kasan-dev+bncBDCPL7WX3MKBBLV77LBQMGQEV6SSKLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 10FB2B0CB6B
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Jul 2025 22:14:41 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-236725af87fsf65624885ad.3
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Jul 2025 13:14:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753128879; cv=pass;
        d=google.com; s=arc-20240605;
        b=brZ17zixzOQw4NtyP0QFoV18pvMqdCFlGJFQWVmLa9g9zrVlChsiHv1J85CsF0VQ6k
         62tPD4KSDFIJpKRqmI2FUsaybtiokr4vGORRhImruCB+xp4mgT4R2s40s2vvXX+6GMMo
         8CKJPQV8rguBzG1jkPGlne5eVLXazGtcAX7W2tvr1q3D12+et+fwS7oLGOjRwmTV0sPa
         0qUKN1UBGwPzjBPO638Rqt0/pGQ7Vn98uiqtZRQHmw6Fky8gmNx3L0uAJ1eAQrmPTt4L
         I8WTbgPCjAloATC3WRJ99JSQbsys5Y8lyY85VB4qbKJyrcV91hJQjDq5ZNBYTpGnHTm2
         k5mA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=4kgqaxj8yAESn3fAJmvzXzgYQW1pKxhiT9Tal11sdoA=;
        fh=YLQqqv/5Qc3TCBCzpgLyfcNvjEATd+TqzlEKTSS2xyg=;
        b=fYCh10gBSTb67s1aULuDzFPUBuBgvRPyfqExlL9PtZmx7rNuF2RjEPwjy7PJ/lWGXx
         1X6VlUDUO2Xu44J08DnRss6ZpoWHKyP4XYnt/QzVAdwntApwFPTIlI4y77oJ7bi9euk9
         yas9xaTmUhefH7Zie/FhVSuBnWP2BXBfMMErRiYWjX9F3LOeiNXmElNVJawfeCiEVi/c
         fqgMUiJAX5xWSexlq6+rT2W/sgmqbvHCD7PTEEGJUjlAiJfA3z6H4eqvONLscTd1VJWL
         u6ccm3bPzLUEI4IsDuoFE8rsnicdIbaCA6/3f3nNWZrSQAk4MKvP6Mdj5Lnu2hWDm1aT
         Fvgw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=lFAdcpLW;
       spf=pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753128879; x=1753733679; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=4kgqaxj8yAESn3fAJmvzXzgYQW1pKxhiT9Tal11sdoA=;
        b=TuIEgq5sCk+CUWTO8+txv7k5JcFEQN4GRudQ539zZvLJzHVS+Gj50o7iqum7tDS2HZ
         6+gtgv+LwSlkFXYwVlRPHnvIaNPANxKHIj9e6QhWihaJxxynoZeYfBEEaIbaaIZfumBQ
         h6eaHspQcUgh0H/qLS3yHpNnlha0Q6iqYO52bEHGYGyoIHAXRKGq3aEshmYMxv0M93uL
         PblUkikllnLlu7Pp5q6l7R5f56R6hzquu6Y6f6SJOi3YVYrWSkjZNUprte7ClCxOZhRI
         +RwvCLX/32gv0IMSWJI5FdCRN47HtrRfLWt8Tq6jT/7BXVfMSuM1GEhJofXZjwiGQ1v1
         mdjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753128879; x=1753733679;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=4kgqaxj8yAESn3fAJmvzXzgYQW1pKxhiT9Tal11sdoA=;
        b=LUix6KmllM7iVtPNlKKk8fc/ndxVusdJrRKMk3bliIbJqKyIJ4ZokNEHpNKh/VG9Zn
         budtYQZIX0X24aoqTfCi/fcDXsqi++7hDGyvERVLQR+m4CVeY/tHFVKQtApkiIOT5aOb
         XzYstNElHTjYCA0UFZqybVfyK9UhXkDmmvQiAmHrFdeHEqDbDUJsKeWEmkMmFvmYwI6y
         W2uV5FWi2xAApQwOy5e55Pdx3hb+4gwZ1o2Op0VefysUfpSVVzW2TA6ozm1ewM1fcMmp
         w99YAPmjdUM3JpcnBuGyAqtfZWNWAbjkypdzIYlPsJaxoAoE6NO3nwiBE9KaMK0OnLuP
         d0/Q==
X-Forwarded-Encrypted: i=2; AJvYcCXdP+vmNhRlrPkWUeybd+ZcXDfH3j6hmgfDWBEbzDbazZziZ4DCTmNFbFARoJmG6TcamkpF8w==@lfdr.de
X-Gm-Message-State: AOJu0YwAteEB01pSSObZHmhunI67Foixg48y78GHDrg0BNOIzy2Nelgz
	yMdAl6jBQhVLL4qcYKKzS08sl6oYLJdO0ic2wxJr0bxunokMKKDgPfgn
X-Google-Smtp-Source: AGHT+IFBQQWh5+rwZQgLZJwWY3DhE3XgxekUsDVHQfgoEQ6v+/3PJqzQeu0MTjd6lvrJriQfRBLHSw==
X-Received: by 2002:a17:902:f68c:b0:234:d7b2:2aab with SMTP id d9443c01a7336-23e302a27abmr237685065ad.14.1753128879010;
        Mon, 21 Jul 2025 13:14:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf7Zut2SHugGxiaBRcP6rHB8ButXzeDZ0as1POmaGP8fA==
Received: by 2002:a17:903:13cc:b0:234:d1d3:ca2 with SMTP id
 d9443c01a7336-23e2ecf5cdels32164045ad.1.-pod-prod-03-us; Mon, 21 Jul 2025
 13:14:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXqLy8e4KjO9arPjxHX1vxILa9QweGaY9Es4EYBEes971ihVicsbA1H3WSVZgwWyGvH17DHckwBEhI=@googlegroups.com
X-Received: by 2002:a17:903:228d:b0:238:2437:ada8 with SMTP id d9443c01a7336-23e3038466bmr266069745ad.48.1753128877713;
        Mon, 21 Jul 2025 13:14:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753128877; cv=none;
        d=google.com; s=arc-20240605;
        b=VHufzK0iShgFZ8bl9CjlYaB14qagLg/CW07CjNolPMl+I6TO/qa4TyRWP5qlbyDJZ5
         qSifZGMbROA4PTnpz3NqVkUFBlVrSI0UzlRetn4L6dgpWuPFuiEcddtpmVmNAFDvTowN
         0nJcN/qA8OdHfmv2K3J2T92vkmTJ+lMn6JIZ5wriAXsxxs9AxGIgPpU/+iiJpkOjWeXB
         dTBHmtG9z5KB3Bz4bL3T8ne/q1sxn9UCGvCExJn+szPItz9sL5MeLX9YcF/oA+Yl+N+I
         vEwz4p2zglNwPIMAIhB2qRl/87OXHY7Ua7MmHhUgzEdC97JeGNsutIqRKRdU/y11e53h
         VhoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=u/NyKUxBiS0QG5jJhquPTyFd9NQpPurrr/JYyOYtD/w=;
        fh=tZyt6e0HlhPmBOSekvjLfrL8od2tSeZQJlfFsWQOwgU=;
        b=VbJWQcIXRCW9qeVkGnCL2THFqQDeUfJSaF+u2Ge26AL52DYgLuD69hfpqOf1LFGmhx
         Gck5bWhdoS9CYgznkYaUjCm2ZpviXNRFFpHLQKzT4fXsxj5PdIYPlTNJSA+no1lINy2V
         /Z+RBdlJY2njHNaFrZ3fgnntDgLqvRAg6oXdUMbIc0U+e2cfLuUTRs/Uk/aLuZXsJjTc
         cZime1SETQHQVdiIYDEi7OwlzeDxCimXOT7SGK3QDzN/1ZjkoAZICnVmNumaWFD/pulO
         oAejMwDjE1EsJD9nAZ4Hr1qls7IwwHfZ6PJ6sgyPj/XOcubwDRisNrfsvc2eV45lf04Q
         048w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=lFAdcpLW;
       spf=pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-23e3b6bafdesi3514955ad.8.2025.07.21.13.14.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Jul 2025 13:14:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id D3432A55D87;
	Mon, 21 Jul 2025 20:14:36 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 75591C4CEED;
	Mon, 21 Jul 2025 20:14:36 +0000 (UTC)
Date: Mon, 21 Jul 2025 13:14:36 -0700
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
Message-ID: <202507211311.8DAC4C7@keescook>
References: <20250717231756.make.423-kees@kernel.org>
 <20250717232519.2984886-4-kees@kernel.org>
 <aHoHkDvvp4AHIzU1@kernel.org>
 <202507181541.B8CFAC7E@keescook>
 <CAMj1kXGAwjChyFvjQcTbL8dFXkFWnn9n47bkN7FP=+EsLNsJdg@mail.gmail.com>
 <aH42--h-ARsvX5Wk@willie-the-truck>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aH42--h-ARsvX5Wk@willie-the-truck>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=lFAdcpLW;       spf=pass
 (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted
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

On Mon, Jul 21, 2025 at 01:47:55PM +0100, Will Deacon wrote:
> On Sun, Jul 20, 2025 at 04:10:01PM +1000, Ard Biesheuvel wrote:
> > On Sat, 19 Jul 2025 at 08:51, Kees Cook <kees@kernel.org> wrote:
> > > On Fri, Jul 18, 2025 at 11:36:32AM +0300, Mike Rapoport wrote:
> > > > On Thu, Jul 17, 2025 at 04:25:09PM -0700, Kees Cook wrote:
> > > > > When KCOV is enabled all functions get instrumented, unless the
> > > > > __no_sanitize_coverage attribute is used. To prepare for
> > > > > __no_sanitize_coverage being applied to __init functions, we have to
> > > > > handle differences in how GCC's inline optimizations get resolved. For
> > > > > x86 this means forcing several functions to be inline with
> > > > > __always_inline.
> > > > >
> > > > > Signed-off-by: Kees Cook <kees@kernel.org>
> > > >
> > > > ...
> > > >
> > > > > diff --git a/include/linux/memblock.h b/include/linux/memblock.h
> > > > > index bb19a2534224..b96746376e17 100644
> > > > > --- a/include/linux/memblock.h
> > > > > +++ b/include/linux/memblock.h
> > > > > @@ -463,7 +463,7 @@ static inline void *memblock_alloc_raw(phys_addr_t size,
> > > > >                                       NUMA_NO_NODE);
> > > > >  }
> > > > >
> > > > > -static inline void *memblock_alloc_from(phys_addr_t size,
> > > > > +static __always_inline void *memblock_alloc_from(phys_addr_t size,
> > > > >                                             phys_addr_t align,
> > > > >                                             phys_addr_t min_addr)
> > > >
> > > > I'm curious why from all memblock_alloc* wrappers this is the only one that
> > > > needs to be __always_inline?
> > >
> > > Thread-merge[1], adding Will Deacon, who was kind of asking the same
> > > question.
> > >
> > > Based on what I can tell, GCC has kind of fragile inlining logic, in the
> > > sense that it can change whether or not it inlines something based on
> > > optimizations. It looks like the kcov instrumentation being added (or in
> > > this case, removed) from a function changes the optimization results,
> > > and some functions marked "inline" are _not_ inlined. In that case, we end up
> > > with __init code calling a function not marked __init, and we get the
> > > build warnings I'm trying to eliminate.
> 
> Got it, thanks for the explanation!
> 
> > > So, to Will's comment, yes, the problem is somewhat fragile (though
> > > using either __always_inline or __init will deterministically solve it).
> > > We've tripped over this before with GCC and the solution has usually
> > > been to just use __always_inline and move on.
> > >
> > 
> > Given that 'inline' is already a macro in the kernel, could we just
> > add __attribute__((__always_inline__)) to it when KCOV is enabled?
> 
> That sounds like a more robust approach and, by the sounds of it, we
> could predicate it on GCC too. That would also provide a neat place for
> a comment describing the problem.
> 
> Kees, would that work for you?

That seems like an extremely large hammer for this problem, IMO. It
feels like it could cause new strange corner cases. I'd much prefer the
small fixes I've currently got since it keeps it focused. KCOV is
already enabled for "allmodconfig", so any new instances would be found
very quickly, etc. (And GCC's fragility in this regard has already been
exposed to these cases -- it's just that I changed one of the
combinations of __init vs inline vs instrumentation.

I could give it a try, if you really prefer the big hammer approach...

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202507211311.8DAC4C7%40keescook.
