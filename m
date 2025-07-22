Return-Path: <kasan-dev+bncBDZMFEH3WYFBBXEW7XBQMGQEK5AOC2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B8D4B0D48A
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Jul 2025 10:27:10 +0200 (CEST)
Received: by mail-oi1-x237.google.com with SMTP id 5614622812f47-41e90f5d1ecsf5087236b6e.1
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Jul 2025 01:27:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753172828; cv=pass;
        d=google.com; s=arc-20240605;
        b=idUhlgAxH64cOQU1//d/imw8o5XiUWUgFkDPB+Gb0axFAkEd6okx7OPcaY5a41jdK6
         YgdOQuvtDWxTMs4RDoZG/FEOnKWhkxHjSmoScKZnkod5QeWh5PTBD6JmuvlYUsTkAZhn
         9RWImlmYMNZ/67SHCJN68QCEx9vLqo4J98HxOymqXFAd/r5bA/juM9TZDfpC6Sd18QaW
         gZY5VNlyUX4HirmTyJjNm8c55El3SyTbfwBpTv/KJLWZJoVU70FPXReSf7J83+oT6+GP
         IuxKBBE17EHUbgxGyfoMaPTFAcY4AIa5+fKdEynR9oJGY72IohX8dFpVDiVt9nimJOZT
         uElQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=edwHXMLcfApG0qtZRTcwLuKVbKmIc1iMGLwzVMkYz00=;
        fh=1DrQQuvtni8k0EmIOh5jZ16ack72zDZiEVCzwEKO3wA=;
        b=avsN8RelE5cwdFMvJbK+EK7QnJiJq16C6fd/fxCD9PMPO9tKbouNUvZuAWNgTSItmM
         XJ66LSBDIGweXoah1ieoyJ/GwouhmCXf1crRI6wwnpNltOoNjjADYjAC/EA3Lw7aemJp
         T0uVb4gG2fDpSckul1D3eNabbOUOmV3PXWRccDF+FTy0/BjTcgwmyqsA3Aw48lH8g78v
         K733MdnfSauiygLJuBFDf664VChIqaeH9/J5BtS04JwAyfCrVY37VBsopG79qGykln9s
         snuhT5fni2tRs/FPo8vbgXhacUqSXkulHC+gTPBOghorChKOzuNsHudXK16oZOaJFOgD
         7oyw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ftIKtFsS;
       spf=pass (google.com: domain of rppt@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753172828; x=1753777628; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=edwHXMLcfApG0qtZRTcwLuKVbKmIc1iMGLwzVMkYz00=;
        b=JJvBWlP/5TRqRlB3QxfpBT8hsRCZZSCWa0iXRjcy4GvHLs8bhQisowdmtJRSqqLf+d
         OyD3OcRV9k341uNpIOH4qoFQWas8kmJVWIabW+X4YA3XlJrl93UWjiEPX6ec0VZaRmq9
         RTw3LaQ/sCV5ZYhw4wxbpaULhTQxfvbaXztsmA07fY2tQnphn1vKDjWlnG+YZmCy/COj
         eSLZdkt9OEiaCr6xPEIvBGJGXBF4A3GmvIAC+h3sp0lQlxYTaI6wg0UCZQaAS8smyFHR
         bL9OrssUBkP6e00nhVYZPb5udZdEsm6D33psFCQuX1rRSPvEVm5Tk9WeDhrNMjELmcpT
         ia8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753172828; x=1753777628;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=edwHXMLcfApG0qtZRTcwLuKVbKmIc1iMGLwzVMkYz00=;
        b=qh2c5Q3KCvOl3tiH3rlwltvmrRrOYpkLto7DO1KTpFXeoC/v8TU0s0jGZu3IkS4MYw
         WJo+SfONnDC3Ml8VMgSxpiOZJHMMoSZPdbY7uj/QVovLI2kKdLn11rIHMM2jwxmwb28X
         WsOA4IjQzWt6omYioJRBNvfMdIgG1YehsDBMmxFGmyZ7H/iG3XA1bUyjXo2TLsrCwKX/
         YgS58zAA9derqJFk5/PlRVZkCP6+fVSg0qJAwMxfyDtpvHsN4F7fmaBTHgcq0YUfAPZ6
         RkKbiYHSOY8oxzADwoI5iqNp0TqM6S8LqY1WyjSaKjZe43jugPENZtmWWQciWJQhkBmX
         A9WA==
X-Forwarded-Encrypted: i=2; AJvYcCUglVnPfBuv1MKsnHz0JjrOreiyad4rAtjNTZY4C5gI5Lw0o4CWKBiaNgNfL4Oowa1YH9i+XQ==@lfdr.de
X-Gm-Message-State: AOJu0YyZhnEfN8jepaqZ7hZctMFj/WjSx6UeHaPHIdH7mC73VIc1czP9
	yxUR227gCycna87SfIcSx8MULtbwoVXARE9svVwoPfj/9G99IyR9+4P/
X-Google-Smtp-Source: AGHT+IHIplB8K16RFz0P+Z7vZcd0uaur0aPQDn0iviEDhZMZ+ReZK//A+l6X6rdbFYPh0pXoONEg6w==
X-Received: by 2002:a05:6808:bc5:b0:406:71fd:b610 with SMTP id 5614622812f47-41d0594b2cfmr15441003b6e.33.1753172828452;
        Tue, 22 Jul 2025 01:27:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZekIjiib/Tl5kFOly35FbwYUjgm5ScO6PFUfmDJiYWHhw==
Received: by 2002:a05:6820:4707:b0:615:a1f7:ff82 with SMTP id
 006d021491bc7-615ac6e88f8ls1322956eaf.2.-pod-prod-09-us; Tue, 22 Jul 2025
 01:27:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUrn3rm9lGDbhwYkvVgyG+MiSYq6PIkJwTYPJrpE53Btv+tnRrN58x9G8w6CbVNytZg4OIw9BdjkyQ=@googlegroups.com
X-Received: by 2002:a9d:6014:0:b0:72b:a465:d955 with SMTP id 46e09a7af769-73e6615cac7mr14842443a34.12.1753172826846;
        Tue, 22 Jul 2025 01:27:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753172826; cv=none;
        d=google.com; s=arc-20240605;
        b=TbLSp4HzI2PIcDlBo5Z8Wmj+T5/zdnMbQJMbm/KkGVZ5eUYHszmA4MKSzljc4SmEkS
         mgvv1QCORT5ldGlYdjpUvTsEUuxgDS+wGxFj7WL9K4jPjchJeJxRWWWEu+FZcebD6zau
         8PmrK9bynZYEfh+9zp/f5htD2CequUmNqXo9LbsSkfwIjwuJRIgmLyd0XYTP8RTff9jf
         Kag9PD/DX4KpD8VPt2FFre/9xQ8J4tUyMLEtL7IjyCqLhERSpFjK7RO2w3bfESo5rTtq
         OkS96DOEH/cc4iW1nY2vwAwBy48Iv9JDfn0Q+8XziwOoio8Vq2D4YV4gSBOKFheorBIf
         hR5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=DbOnJHGDVjc2/tyeEkcbXWv/oF5daTXS/lsYhGkGX7g=;
        fh=5Lu7pGtvKbOWCgU3d4KCBMiFviOER21POJg6PXZUv8U=;
        b=TZDbjVjZ6bDQd4rC+YvEFZ7LKcOYzKhRkb+flnHxm/sjkW99NblBRaN0TwVppvIbhf
         U/AAD3ENE6agNXFeNRgOz1/rPjxomjHLvu4CrnIEHsIoAfpRVIyq714YsyfRlMH2SYqO
         cj+afxLrjwDDPMg6iUKeFU5Wq1Rp4L7Tb/4W0iwkUbY+ULCOUhnHFRzLiBm+T0Eeqmt+
         480/tFLYB2oM/FGSVoXSV7z96D8tfK1sD1bAgRhsHMSMWfr3RFdKLyoctARqX0af04uN
         i+2X9fs/iz/uMCD8dQqv08L6Ocxymw1e+ALWkE1+KUlFTBRmLi8fnxfrCFG1PBStHvA0
         JEOQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ftIKtFsS;
       spf=pass (google.com: domain of rppt@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-73e83bacc25si478316a34.5.2025.07.22.01.27.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 22 Jul 2025 01:27:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 017F7600AC;
	Tue, 22 Jul 2025 08:27:06 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7A537C4CEF5;
	Tue, 22 Jul 2025 08:26:50 +0000 (UTC)
Date: Tue, 22 Jul 2025 11:26:46 +0300
From: "'Mike Rapoport' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kees Cook <kees@kernel.org>
Cc: Will Deacon <will@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
	Thomas Gleixner <tglx@linutronix.de>,
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
Message-ID: <aH9LRgiiXQdABrd6@kernel.org>
References: <20250717231756.make.423-kees@kernel.org>
 <20250717232519.2984886-4-kees@kernel.org>
 <aHoHkDvvp4AHIzU1@kernel.org>
 <202507181541.B8CFAC7E@keescook>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <202507181541.B8CFAC7E@keescook>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ftIKtFsS;       spf=pass
 (google.com: domain of rppt@kernel.org designates 172.105.4.254 as permitted
 sender) smtp.mailfrom=rppt@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Mike Rapoport <rppt@kernel.org>
Reply-To: Mike Rapoport <rppt@kernel.org>
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

On Fri, Jul 18, 2025 at 03:51:28PM -0700, Kees Cook wrote:
> On Fri, Jul 18, 2025 at 11:36:32AM +0300, Mike Rapoport wrote:
> > Hi Kees,
> > 
> > On Thu, Jul 17, 2025 at 04:25:09PM -0700, Kees Cook wrote:
> > > When KCOV is enabled all functions get instrumented, unless the
> > > __no_sanitize_coverage attribute is used. To prepare for
> > > __no_sanitize_coverage being applied to __init functions, we have to
> > > handle differences in how GCC's inline optimizations get resolved. For
> > > x86 this means forcing several functions to be inline with
> > > __always_inline.
> > > 
> > > Signed-off-by: Kees Cook <kees@kernel.org>
> > 
> > ...
> > 
> > > diff --git a/include/linux/memblock.h b/include/linux/memblock.h
> > > index bb19a2534224..b96746376e17 100644
> > > --- a/include/linux/memblock.h
> > > +++ b/include/linux/memblock.h
> > > @@ -463,7 +463,7 @@ static inline void *memblock_alloc_raw(phys_addr_t size,
> > >  					  NUMA_NO_NODE);
> > >  }
> > >  
> > > -static inline void *memblock_alloc_from(phys_addr_t size,
> > > +static __always_inline void *memblock_alloc_from(phys_addr_t size,
> > >  						phys_addr_t align,
> > >  						phys_addr_t min_addr)
> > 
> > I'm curious why from all memblock_alloc* wrappers this is the only one that
> > needs to be __always_inline?
> 
> Thread-merge[1], adding Will Deacon, who was kind of asking the same
> question.
> 
> Based on what I can tell, GCC has kind of fragile inlining logic, in the
> sense that it can change whether or not it inlines something based on
> optimizations. It looks like the kcov instrumentation being added (or in
> this case, removed) from a function changes the optimization results,
> and some functions marked "inline" are _not_ inlined. In that case, we end up
> with __init code calling a function not marked __init, and we get the
> build warnings I'm trying to eliminate.
> 
> So, to Will's comment, yes, the problem is somewhat fragile (though
> using either __always_inline or __init will deterministically solve it).
> We've tripped over this before with GCC and the solution has usually
> been to just use __always_inline and move on.
> 
> For memblock_alloc*, it appears to be that the heuristic GCC uses
> resulted in only memblock_alloc_from() being a problem in this case. I
> can certainly mark them all as __always_inline if that is preferred.

We had a few of those already converted to __always_inline, so I'm ok with
continuing to fix them one at at time. Gives a feeling of job security ;-)

> -- 
> Kees Cook

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aH9LRgiiXQdABrd6%40kernel.org.
