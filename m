Return-Path: <kasan-dev+bncBDCPL7WX3MKBB4U75PBQMGQEU74P75A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 25C78B0AC4D
	for <lists+kasan-dev@lfdr.de>; Sat, 19 Jul 2025 00:51:32 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-4ab68cc66d8sf48152551cf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Jul 2025 15:51:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752879091; cv=pass;
        d=google.com; s=arc-20240605;
        b=W/UgJ13b2Q8lyG86EKSkRXfIyDbDllfwHQWooNXS0GO4Z/vw8mM+FQXLQbsemxOCPM
         i0RZQNFlHgpGuRRRx74NOdoPMhmC7hQSwy7JgCz3wfxFOJzli6JR03cByLGpQ+MYf2hx
         XoIQOlftrliP9MROa9mLtXqQ9WwGv2lkw909/kQhyCzykMTV+BLsfFjem3pJ0EzoAGxA
         X+qzDsav7R0y/D821p/MLzVwXfMP54NsQ4oRdhmVEiGO8c/Ffm5oOE2S4su9wl668kKx
         mnaX49nVynOIzgQFeW4hOnj67yd6Qc7VDUSBxJD13zT60zFGOe/b7A1ECVE50Dz9v8k+
         I/jw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=seCxzLj/W1PDVXNtKdis2xypTYgIkaZvbGZ18UNuZ3M=;
        fh=cGC45MZE4gonCWglqPTNr86khFOSFau0M3Z3OP3+93Y=;
        b=CCFbKhbOfmWXZetwnosmEvij4+u0kRJilg1fVVlX5FUFnQbto5ZQMnAGc1bE7/LjKZ
         39VWbNDj7ZmK81UMWaAvOAvZyAe6cY9aZpiqBenPJDiFsFXC3cw8tUOyCWx+Oc0iJQNN
         rfeP26PURDugKvFbu7tLOt1Svty+v7S+en0qUq+QLMWkH5SJi9nc3Ykg9B5ahX2fcKz+
         4ECet9mr8K9R40sU8yjgxN6cjQeJTNpqxQ8mMiLzSENfIxwG1NQgfPlapJIWHnF49ld8
         gLlLvdx83gqXqz9LxgPSEt8FPvfVg5oD2ooVm1thTFE34/t0lV7mlYPldzNQhqzgcMCf
         9idg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VmiVcikE;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752879091; x=1753483891; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=seCxzLj/W1PDVXNtKdis2xypTYgIkaZvbGZ18UNuZ3M=;
        b=b+fJ3uViS5fZESAJcumPS5FaKMWW7sptYjMHaV93N3GGWmmf1ZjbdE/pj9w3zV6TLF
         61xNrQI4zGQo6LxR9xWPGdO1Gj03xZIsfH9s44ZDFURbPYS3m/U1UgRM6ElStxxTI/kI
         y7hb7uO8K/Ir+5jarRRWDtlnvKFPHxp/vz6jgxUnDYT4wzUweDRAkXVQh4fLPoOUztFN
         urExaIxJKpPGxeYnTyAurG38d3nJukjT0Fw7z6FKEK2kpXqN5q43/9tiqiDmFs15hdox
         3HyYEVWYMSnJg/KkCMFIArQeWPHMWjjbPR6lMNetRDqlZcb/82gHqw7BTvLD8byuVIkT
         TQNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752879091; x=1753483891;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=seCxzLj/W1PDVXNtKdis2xypTYgIkaZvbGZ18UNuZ3M=;
        b=Q4nE20KSXiuHicH2BYFeJMRHJmNx6+xdq4VXrzgbmw1nWigcDZRWP9lv9Paf6wGraL
         fSj6f+F/T7i70NjsjB5ZXaeiGfiqIoxDc36GwRQ7LIEuMGMOloPUtC94OYVchZ2F8PHg
         P2xm8p6QUTNWlBCuVpyDNg+xwZZ6hNnTjxpErqJmsY36yDWkqB9GhlQ4cJHmnZBA/jTf
         HMTVQNhCBw26eHLoDl9NiWtptsQshI+9UEesJehQ/PihHhw/BVI/x87QHY71HKRS+xbR
         V6aTW4aTmzF0JMsAbQsZEu0IXsnaBnfuJjPZwBxNrbkn1knyJwHvriSmMX0Ee0h6mWQE
         UBPw==
X-Forwarded-Encrypted: i=2; AJvYcCV1vikimGmOOBnZXQMWRxsvkzEsmOyYJeBQrma2FGYOOScwLfsYsuO2IYROGQEon4MBkywRMw==@lfdr.de
X-Gm-Message-State: AOJu0Yy8aVDKgo5rW3UncHiUqjtARi1fNcvKoKTloz58FIlwXnKQesnk
	kwk/5WAoSQi7HwCfmgrbYuBm26VzhPJ6oE4Kt593ntagWk4B8ldG/bUP
X-Google-Smtp-Source: AGHT+IF6XkrUpTR/AswEibfI3EG4pbwKIy0Tdd66KsRHSwcjvHHY09fgkC0UrI4W7qxJA7vcqaN+vg==
X-Received: by 2002:a05:622a:993:b0:4ab:5c1b:4d29 with SMTP id d75a77b69052e-4abb08bcc18mr88358961cf.20.1752879090910;
        Fri, 18 Jul 2025 15:51:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdl3epRuBnb3OnmVgZCl1SxOvNKm8fqe0IHu546gJXlew==
Received: by 2002:a05:622a:1a28:b0:4ab:6d4c:21ba with SMTP id
 d75a77b69052e-4aba18ae3b8ls27822751cf.0.-pod-prod-00-us; Fri, 18 Jul 2025
 15:51:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVy9aYF+eqCRcyvg+ScIgYK6ZI74FJ1h33Ralh90O64kWNrXZ7jwtPAy4fNpMhnfNz/SHE/Vhpgs/Y=@googlegroups.com
X-Received: by 2002:a05:622a:5e83:b0:4a0:92a8:16ba with SMTP id d75a77b69052e-4aba251c3dbmr119755731cf.3.1752879089555;
        Fri, 18 Jul 2025 15:51:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752879089; cv=none;
        d=google.com; s=arc-20240605;
        b=LST8+p81QG+3qBlZ3ney7tlcdxVjA9yBS9wqu8dER55izM6NmIZGUD46d22e/M8CNF
         16hfdMHYK0zK0Svvo7ZGA2CKiB/7OD7RYkQosK83f2kcLuu7GoCZzEin4DIRQe/PF38Q
         Pb5+SZprb1jvhAXj8q9U8W5SkaSIxqb7JVIfqufaVNmp9J9qa+tHr+v7MSrigXYDmypz
         WVMoSzqidJKiZtJA5NeTgpA55KMupVLKjhK/ljoQwsdkUvzN+1/xVuZoxOH8/SLmkwQj
         hDqp9fXNgGqCg2LZSupNqjC5ZQZvYONYGVLG8QUBI6EMxWVL8FUnIkF0U4wZh8lVtGmO
         s7Mw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=TiUhvpXDad+ClqTl7bM8rtEMRDTcE9fVcXdDCASyHwQ=;
        fh=iu8wwEpojM1mlt1r5mldxzZ9I2e62EFmOvwhgHXi/2s=;
        b=WqGhOBCpsHpjxb4lYY//JLnWWDh81KUlsgzsL7csp9LuB7swiUIyZWpORTvLxyBXnB
         S4T8ug3zmlRChfPW4vziY/uinJL5w1q7kBz+LvqyOcD3UPV3cnrLe5wJ7Tiph44PwkKy
         /gMD3nFU7/nGHON83MgsBLQw65Dxdq+STbU3Qjjtui92J7r9BCDWWMuSNRYpB44sF+F+
         EwZ77dmALgD/TEs2ccQEogfXFO//RDzzueX5Anx3NJOl7jVXXHJ3K1xUUESyX6SaaN/v
         RZTIHTajRxrvpM/3ngW3BaNLYCB/uA1zkYaTnE9CpKxDNepADLK39OLaxkZnAHQcdMtT
         RiUw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VmiVcikE;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4abb4afb3besi1453791cf.5.2025.07.18.15.51.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Jul 2025 15:51:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 1C057A57714;
	Fri, 18 Jul 2025 22:51:29 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A58ABC4CEEB;
	Fri, 18 Jul 2025 22:51:28 +0000 (UTC)
Date: Fri, 18 Jul 2025 15:51:28 -0700
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Mike Rapoport <rppt@kernel.org>, Will Deacon <will@kernel.org>
Cc: Arnd Bergmann <arnd@arndb.de>, Thomas Gleixner <tglx@linutronix.de>,
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
	Ard Biesheuvel <ardb@kernel.org>,
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
Message-ID: <202507181541.B8CFAC7E@keescook>
References: <20250717231756.make.423-kees@kernel.org>
 <20250717232519.2984886-4-kees@kernel.org>
 <aHoHkDvvp4AHIzU1@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aHoHkDvvp4AHIzU1@kernel.org>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=VmiVcikE;       spf=pass
 (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as
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

On Fri, Jul 18, 2025 at 11:36:32AM +0300, Mike Rapoport wrote:
> Hi Kees,
> 
> On Thu, Jul 17, 2025 at 04:25:09PM -0700, Kees Cook wrote:
> > When KCOV is enabled all functions get instrumented, unless the
> > __no_sanitize_coverage attribute is used. To prepare for
> > __no_sanitize_coverage being applied to __init functions, we have to
> > handle differences in how GCC's inline optimizations get resolved. For
> > x86 this means forcing several functions to be inline with
> > __always_inline.
> > 
> > Signed-off-by: Kees Cook <kees@kernel.org>
> 
> ...
> 
> > diff --git a/include/linux/memblock.h b/include/linux/memblock.h
> > index bb19a2534224..b96746376e17 100644
> > --- a/include/linux/memblock.h
> > +++ b/include/linux/memblock.h
> > @@ -463,7 +463,7 @@ static inline void *memblock_alloc_raw(phys_addr_t size,
> >  					  NUMA_NO_NODE);
> >  }
> >  
> > -static inline void *memblock_alloc_from(phys_addr_t size,
> > +static __always_inline void *memblock_alloc_from(phys_addr_t size,
> >  						phys_addr_t align,
> >  						phys_addr_t min_addr)
> 
> I'm curious why from all memblock_alloc* wrappers this is the only one that
> needs to be __always_inline?

Thread-merge[1], adding Will Deacon, who was kind of asking the same
question.

Based on what I can tell, GCC has kind of fragile inlining logic, in the
sense that it can change whether or not it inlines something based on
optimizations. It looks like the kcov instrumentation being added (or in
this case, removed) from a function changes the optimization results,
and some functions marked "inline" are _not_ inlined. In that case, we end up
with __init code calling a function not marked __init, and we get the
build warnings I'm trying to eliminate.

So, to Will's comment, yes, the problem is somewhat fragile (though
using either __always_inline or __init will deterministically solve it).
We've tripped over this before with GCC and the solution has usually
been to just use __always_inline and move on.

For memblock_alloc*, it appears to be that the heuristic GCC uses
resulted in only memblock_alloc_from() being a problem in this case. I
can certainly mark them all as __always_inline if that is preferred.

Some maintainers have wanted things marked __init, some have wanted
__always_inline. I opted for __always_inline since that was basically
the intent of marking a function "inline" in the first place. I am happy
to do whatever. :)

-Kees

[1] https://lore.kernel.org/lkml/aHouXI5-tyQw78Ht@willie-the-truck/

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202507181541.B8CFAC7E%40keescook.
