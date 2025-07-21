Return-Path: <kasan-dev+bncBDAZZCVNSYPBBCXO7DBQMGQEFQ2HYSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A1F0B0C459
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Jul 2025 14:48:12 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-700c2d3f3d6sf38306916d6.2
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Jul 2025 05:48:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753102091; cv=pass;
        d=google.com; s=arc-20240605;
        b=MajaLvTVMZZLcPmX/ngcxYmcs2CGg8tdP33AQlU0fc0glRgecCW5PQ5nw3OkmO57W8
         7abX6F2UVzHP8M08Bw+oLYyKgJnj6niSeLEuXI2qTUOt2RdYtO/vre4PoOYUB1RTfRC8
         nOehJfEVpt+0WWOWn2njXNlahQgKSUvxO4tONrSD3dL9WoW8ovsHAdjqZ3rw6n3hHpAP
         kouy8o5WXpmPlFB1BSRtdXujVKeKFf/IsbntVgbgFddJbPj5+aoU4NsCB/vkh5o5x2mf
         HmcS/K+V8GSoDhlV3eesnDeBDa9PRuoA/u5KRnZz2nipt6QyimCrMtDIqSMvvoi5YIH+
         wRKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=xE4nh0NEgNt1h2vBDFkh14j3Oszu9w1ikEpbO2T62HQ=;
        fh=fpJOJlfaWIV0ApXJ/OHkvC6joGGFBhBNcZNX8UWjxHI=;
        b=P88/CNbEYN39647CpATCde47++UmeIHSatiK7AcxUGc7wQkCLg5j63XRxWtDADwmRa
         pAo51DokNq5jPAry2Xcogs0+ab1Cmkz1QauvkyJG5m0fVEJgVMwUKYR77rtuH+2OUSvx
         FVEb1eytw24mSzxhpFZWmN/oexdP6cxc5MFG5eOi1N097xYYX/YC3Q0wBvACTDbRajZc
         oS+QlZn5TXVhI6LdJqgaeuYy6Ir/eZnckwYXEUXk/wZ1BJxwKZNVsTh4W/5lOEhApDYe
         2k+JMWxd0Xx/dDlVKJNNPiEGARCO9r7rKi39xFnbJT6u8va0KAwXYN6f+/samw11/MYf
         46wQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=R8evXuR+;
       spf=pass (google.com: domain of will@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753102091; x=1753706891; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=xE4nh0NEgNt1h2vBDFkh14j3Oszu9w1ikEpbO2T62HQ=;
        b=uD9HbrvuPF6dVe+mSMQeieCjOlyou+n9dndFYNKi5krdvHAM1Fz05KsaIWNzz5TqDK
         8uWlzRzcsyzTigntd5mubdomFvbHzVnVP3LpKneJlp1Zz8C4ErV4xiLEv6gc0Jitc9JL
         8rI7Wb5qW3pP8iggebKtVHw7rPuYE2Zfjf0EiQiItMzZo7xt7qw0DcdKn2IXrninmoxA
         hh6dO8KrcSaMvDR/haOhYOTOKB/zSVs4ALAxmMbLukIXcWpNIRqg+HbYrgwI26d6r9M0
         HPo+MI3ltSzrMeNNcRo7vUNaElZRPLc4gsDJ+ZVDx0vpVIF8nYHkzfTnnbh4ZR3F7xzH
         H/Tg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753102091; x=1753706891;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xE4nh0NEgNt1h2vBDFkh14j3Oszu9w1ikEpbO2T62HQ=;
        b=azRIju/G3FUr5eJJPB25mmbHTWO+GOtMLoiCLIhjhc7XP8rpCOPlK9WuJsj6rvec0t
         yDdm+7noqh6bmq6jJUZ2H+T/zB6eXpo1Zh3jnLiRDx0JCfSZu/W1maSAl+rgYngS2UIB
         cp0SmAb0/82O6/E8YbvrQGf2Zyx3vITcq9NkpUYpD1KO0NK+zuY9vMrtY9f7ZFTAybBg
         oJ2tYi6ng+HhvQ9Ck8L1pvxcTuH6U1dKttQ60vy3m2mAdXywmj60zaFhPVYPTaMGx2PI
         FuqyLsj0i7JdiKFiRKoDCp8IlXxjzCaLe8i7VPspsVLozx4VdWkqxUz9uWggfAhWqZIf
         nLXQ==
X-Forwarded-Encrypted: i=2; AJvYcCXA1eY8W29iB/qNB0WSPODsy4Uma8ILLYRd45GkxRIvkgf4vWiWJNi1i9dsgpP8Er7Ys/tfAg==@lfdr.de
X-Gm-Message-State: AOJu0Ywkk3yHDaXCry6DAa1/Q3JLT7yG+UOu70lJsO9kJp58bu5bepl2
	MU7gt0yLMPHUjE6E7hktsecoYTfB0vVd4LAardS2dCiRxuAYC18OH361
X-Google-Smtp-Source: AGHT+IGK/9THeCOqqw8a2iXYeOMHaKt3BDyqOctA1mdWttOUV1ObCVtQTut55ROFB+OskY1rMLVuuQ==
X-Received: by 2002:a05:6214:1d26:b0:704:df9c:b595 with SMTP id 6a1803df08f44-704f69d27e8mr248395266d6.9.1753102090955;
        Mon, 21 Jul 2025 05:48:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdnNbtukPAvTveQtAZ596yMzNspNjQW8uDQOW5RD3yqQQ==
Received: by 2002:ad4:5cc4:0:b0:6fb:4df4:35dc with SMTP id 6a1803df08f44-70504c0ab4els60124536d6.1.-pod-prod-08-us;
 Mon, 21 Jul 2025 05:48:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVQA57hP3j/QyvG6Aljw38TlxXXT9ua/1j7VRawCQsFpWp/PeKSI4YF66wsVxEr/iYeOR9hnI9ngNY=@googlegroups.com
X-Received: by 2002:a05:6214:5d90:b0:6fb:35f8:a984 with SMTP id 6a1803df08f44-704f6b12744mr234360036d6.44.1753102089634;
        Mon, 21 Jul 2025 05:48:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753102089; cv=none;
        d=google.com; s=arc-20240605;
        b=IbPTjXsi2xVEo7SJhQqJgDKaSY3f9U0K7zbe+1DFkoMTKrAIeVnDQGp7DJx8ggkBLX
         3TYOd8KoxBO1a9/ZwkDytUZnETbBcized0z9Xw03kV3HJl5P9mlTeTAg3UAjGPm0jR/v
         zNTlhAOXcszy/PVNMZ3Rjln1mVuf15jLJPhJwM1nZcfS4J4Ja6uronEgIYLpj5eEpBoV
         BBHc38CYfWyGnqNCguzeCdBoHBbb0muuuzqHvU+ugWozYqz8UJ+Fhe8PMxcMqfzKXr76
         rSKTL1fvKdnhb6DfmiQWihueDNI2f625Wn5IrQHlp2mFmP8uq4sknVa5KCJwB4yU4GRw
         9Spw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=JNY/7LVwGObkKrkAzqd3rzEZ1tZqg3bLZxiEvapvi/A=;
        fh=cS6wsqnowDty06PO1WPvODhS5pY7/VvhPJakQXenp/0=;
        b=j/m8LsR5eXDLKEBNGphIEVAluviH/es7flG/uBTHqMlmd6liP9JZFU0zZBi6qd8HrG
         ZCqXDJ4itnNbCg9HJDsn9k8tnprGOz4zksTS9phl02jG+3OUY9P+p6QQ8GrgBq48g16X
         0mZdlJznKOotanUCw4YRLPxa2tMoL3Z01o9/rIgMEheNuuSQhS8mtXdsK5mhBdh0MtiA
         Vn+CFovuCH5nlhS/jlmfUA4PX7Sj3aMDWQAZoVbwi/FBhvVmRCJi/9gNXKbstgKFkTw2
         mDXeoHo/QKmzuetvYsijIy0bcsMVSdw4bW33Q2RvAnCKUqkvOrAtetyEuYY/B2PY324k
         VSUw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=R8evXuR+;
       spf=pass (google.com: domain of will@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-7051b4f2642si2034016d6.0.2025.07.21.05.48.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Jul 2025 05:48:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 8073E43CF0;
	Mon, 21 Jul 2025 12:48:08 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E2550C4CEED;
	Mon, 21 Jul 2025 12:47:58 +0000 (UTC)
Date: Mon, 21 Jul 2025 13:47:55 +0100
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
Message-ID: <aH42--h-ARsvX5Wk@willie-the-truck>
References: <20250717231756.make.423-kees@kernel.org>
 <20250717232519.2984886-4-kees@kernel.org>
 <aHoHkDvvp4AHIzU1@kernel.org>
 <202507181541.B8CFAC7E@keescook>
 <CAMj1kXGAwjChyFvjQcTbL8dFXkFWnn9n47bkN7FP=+EsLNsJdg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAMj1kXGAwjChyFvjQcTbL8dFXkFWnn9n47bkN7FP=+EsLNsJdg@mail.gmail.com>
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=R8evXuR+;       spf=pass
 (google.com: domain of will@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=will@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
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

On Sun, Jul 20, 2025 at 04:10:01PM +1000, Ard Biesheuvel wrote:
> On Sat, 19 Jul 2025 at 08:51, Kees Cook <kees@kernel.org> wrote:
> > On Fri, Jul 18, 2025 at 11:36:32AM +0300, Mike Rapoport wrote:
> > > On Thu, Jul 17, 2025 at 04:25:09PM -0700, Kees Cook wrote:
> > > > When KCOV is enabled all functions get instrumented, unless the
> > > > __no_sanitize_coverage attribute is used. To prepare for
> > > > __no_sanitize_coverage being applied to __init functions, we have to
> > > > handle differences in how GCC's inline optimizations get resolved. For
> > > > x86 this means forcing several functions to be inline with
> > > > __always_inline.
> > > >
> > > > Signed-off-by: Kees Cook <kees@kernel.org>
> > >
> > > ...
> > >
> > > > diff --git a/include/linux/memblock.h b/include/linux/memblock.h
> > > > index bb19a2534224..b96746376e17 100644
> > > > --- a/include/linux/memblock.h
> > > > +++ b/include/linux/memblock.h
> > > > @@ -463,7 +463,7 @@ static inline void *memblock_alloc_raw(phys_addr_t size,
> > > >                                       NUMA_NO_NODE);
> > > >  }
> > > >
> > > > -static inline void *memblock_alloc_from(phys_addr_t size,
> > > > +static __always_inline void *memblock_alloc_from(phys_addr_t size,
> > > >                                             phys_addr_t align,
> > > >                                             phys_addr_t min_addr)
> > >
> > > I'm curious why from all memblock_alloc* wrappers this is the only one that
> > > needs to be __always_inline?
> >
> > Thread-merge[1], adding Will Deacon, who was kind of asking the same
> > question.
> >
> > Based on what I can tell, GCC has kind of fragile inlining logic, in the
> > sense that it can change whether or not it inlines something based on
> > optimizations. It looks like the kcov instrumentation being added (or in
> > this case, removed) from a function changes the optimization results,
> > and some functions marked "inline" are _not_ inlined. In that case, we end up
> > with __init code calling a function not marked __init, and we get the
> > build warnings I'm trying to eliminate.

Got it, thanks for the explanation!

> > So, to Will's comment, yes, the problem is somewhat fragile (though
> > using either __always_inline or __init will deterministically solve it).
> > We've tripped over this before with GCC and the solution has usually
> > been to just use __always_inline and move on.
> >
> 
> Given that 'inline' is already a macro in the kernel, could we just
> add __attribute__((__always_inline__)) to it when KCOV is enabled?

That sounds like a more robust approach and, by the sounds of it, we
could predicate it on GCC too. That would also provide a neat place for
a comment describing the problem.

Kees, would that work for you?

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aH42--h-ARsvX5Wk%40willie-the-truck.
