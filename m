Return-Path: <kasan-dev+bncBCU4TIPXUUFRBTMQ6LBQMGQENRD2JZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1138.google.com (mail-yw1-x1138.google.com [IPv6:2607:f8b0:4864:20::1138])
	by mail.lfdr.de (Postfix) with ESMTPS id 51CEAB0B3AF
	for <lists+kasan-dev@lfdr.de>; Sun, 20 Jul 2025 08:10:24 +0200 (CEST)
Received: by mail-yw1-x1138.google.com with SMTP id 00721157ae682-710f05af33esf45244837b3.1
        for <lists+kasan-dev@lfdr.de>; Sat, 19 Jul 2025 23:10:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752991822; cv=pass;
        d=google.com; s=arc-20240605;
        b=UExsKcaLF2pC7LaBdnR3ntN0Nzza3YkTGYk6W1DaqJ4VkfZgH2gbrxPLdPAqnPTd1a
         sMQGFHtYR97jhE5BxV0+VGPCmJVZpDxz9lC9otYT+l7NNclf5/Bz1G675icFSxBRBtdK
         ScpNM66hq858B6Gy4y8TK+NkHJM4P9kqWub4MSo67F0zn2R8Gw5PLhNqOJy5Mzmqp7lM
         xthaNTF34ZzYM3uWa+qMYvleiM3gJ7ysFekdlJWF9f6tUUTZG5++0sadI9WBXCT7q7zl
         yxNNut/Pb5mzEExvc20Mm6c19Z42CbuV/V5jYU6DfhKwtXb7hR4xRuqUb6kptECMVjD/
         QfMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=4lTQ6geqFhBWbth6vDUnO6FEuY+SuGeeIKQbhlOkavQ=;
        fh=kJ0We8vr4h2a18t3GGLT6zEyFaNHOW7G2dywpzNM5WU=;
        b=TsnkmMKiKP2oDt3W/di5xqqG8HP+H7HzdrrcuUo03DmEeNtG/Y65OdNKOiRS66frZw
         sToOnlDpztdj9QUSCxmcd0EhDtsmIHLcsW4OBSXNipV+b+BnnitbY3QiND0jprp43c9P
         1nypv8rtvByeUnaM+b7W9bySN5zskcwo/wgkPg1M7OHD+Dkf9TLE6hoacexlIAzrv1Dj
         mYhuYuOKxlN/1z6JRS5pAM3uoqCvAMJqpIQniU8PkOjddZXgkNsDObDu1M3BVsoquQ/m
         UcH60TVXW9UbVhnveG0rOm24EF6R/6+Fq5afWJ+H+tFm4YFofFzv+JQKfTbmB6FY+01w
         PwVQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HcocEkaA;
       spf=pass (google.com: domain of ardb@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752991822; x=1753596622; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4lTQ6geqFhBWbth6vDUnO6FEuY+SuGeeIKQbhlOkavQ=;
        b=pwkT3eejszlgA5njjTvDgVpo3cvAcyR3H4XRfD9hpgU9Q7+5XEdvjUzXrTuoBovRi3
         bFRXUarEOyygOiyrxzUm9+v/imKM0WsLV2Zzwu5jRvvhTSmssHVn5p0AYZwF6nqrE7o3
         g0vC7xELeoiQmNryb+HdbqJ8f1omseRf4g9cHWC1TzBJtOqgQZrSdq0ErJHbN5qB0aOF
         ig9m+GDEEDQknYOiG0TnyStYyMP5wlatnRAfzpCAtuL4L2JzBd6Nn+K51rY3vL6xxfrZ
         fDhInyDuNNoWfv4lKg2I5gnsayKyhct3t/Ifj3jiOqRHi4An+Qy3/wRsGTG+YMdUMKjD
         QLkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752991822; x=1753596622;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4lTQ6geqFhBWbth6vDUnO6FEuY+SuGeeIKQbhlOkavQ=;
        b=DpLE8FTSGxaaIJOc4cZUcY0PIMBaFd5jok1urggIf8Fyq0pNnZPmRyO7DjTA+abOPi
         /6KDLAsVxcz/Bze0bE02bZNj/JCfXrOH8QKE8ZYrVHJ9yZMi5Cunz49xwNOfM3t9j28p
         cJux80J9jAghVoAAnavicwJ0zK9Tuv3JiWvSY1dLXOCfYs7nQZS5SK2W56bOE61U9J7i
         bWoSvre+NIuA0vKeG8F2jNFh6lG2Dla2EVVLDk9UkmF0sOhSk991IfcVo6+FX8YE8br5
         KDZkZJfukDPD/78teA3toqUSDg/A8TuElHIjRbU85k0+uZLWMRJbeg+n0NwkM1t1RW3b
         bZTQ==
X-Forwarded-Encrypted: i=2; AJvYcCX4TZdZhVM2IbnYlHni2ESvGk3bs96ZoI8X2Vi8eNcDV5KGmyPM9wAsYScU9hn4zig/AR+/sQ==@lfdr.de
X-Gm-Message-State: AOJu0YyJgq+nXHw/PRh0Fw/PDlalBtVLyFA5sQ2fJcQEQt4V69bZOwhJ
	WY0aNjGzZaLRGiYMeb/pkqYWRIV4qGB009QCApDAWMsIIEO0YUF5+Ppb
X-Google-Smtp-Source: AGHT+IFIH8+J6aA/8hIl9AWg4l0yzjAiyy+unsbaUTyaJUb4Mkp3K/2cnMKjNQmK9w90lIln4waK8Q==
X-Received: by 2002:a05:6902:120d:b0:e82:99:efaf with SMTP id 3f1490d57ef6-e8bc261f718mr17019199276.31.1752991822228;
        Sat, 19 Jul 2025 23:10:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZetKN/DK9/ljr15ClaHcyBrXjfvVTOL4YskBAzqdI+Bzg==
Received: by 2002:a25:6911:0:b0:e87:c996:a13 with SMTP id 3f1490d57ef6-e8bd467bb8cls3342655276.2.-pod-prod-05-us;
 Sat, 19 Jul 2025 23:10:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVsYSpU/N31KzQS/aR5tL95AqxqmAXKNr60nJmv7JeKI5nR2+N6hTzzvJhci+rmVbqWL7FWOMZbOrg=@googlegroups.com
X-Received: by 2002:a05:690c:628a:b0:70f:83af:7dab with SMTP id 00721157ae682-71836c259b7mr187158997b3.4.1752991821019;
        Sat, 19 Jul 2025 23:10:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752991821; cv=none;
        d=google.com; s=arc-20240605;
        b=PWR0PkucQLjjqrFklp42VMMHyamwYhQ49XwHa531gJVAYzS5MCnxr6/0oVhoMxO56p
         4Rd9vzALkxJktPu66YYtGj20qKDx6/KXqxhmJ8hUosLX5yx4rkkNaaDTmpS7wqCXu9ZO
         5f0Y5chi3Wi6AdVcDKUHw1Vi7y3Lv9FOkd1KbZO7Kxk95STqZwDhz27grWr0EjKWkn8l
         LwajVpv61xJcCjtazRy3D5arei44wueW2n8DgDb9B2VfZxNfRBjE//YZo1x8lG77VCzV
         OBA3OmxVrlZS1qU1aT/PDvsNKVWIZzNfw7NSboMeT+np7d2AFBA0+FL0hXEPvBXIEvub
         6R4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=t2QvY3fOBT8/ZYLhOHy9kLcm/GpPoBHvrrqhkIbhsag=;
        fh=VvGnyQlWJJlu/Uv3NZDrC+OKFQ2Esczi1apb75EUsxI=;
        b=MqCBH17TeMHvFPQnouiMwpBtkdO58RY/hzt44/ciGRd5+Ry57LxHjLsrYySNXAaXfl
         CEXrDJlEZUyFtpAJ+2Um6j7rc6rWZTjIo5cBW3CVGP8HYJyaGoioGoVn0/IfMxQssnAZ
         +GL71XtXrCOdhTy/4nKf8NtgUzSZiCf2IwlcIDVSdK8tQ/+xmjLhQUSNbCYlXn5/q5cf
         NxH12Tak5YJxAcGMd+dDq1t/vcPseuOd0+lD3yEssleGQ4XoTwVq1k/gkDiEuXBhW1P2
         1lYR7czowSDUFopEcuXXUrpyWDd961Z1OT5lDNimQ+DGi8OcSOvubcZGqZ/NjCRZL65w
         irlA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HcocEkaA;
       spf=pass (google.com: domain of ardb@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-7195324ca70si2105287b3.2.2025.07.19.23.10.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 19 Jul 2025 23:10:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of ardb@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 57A40A512B0
	for <kasan-dev@googlegroups.com>; Sun, 20 Jul 2025 06:10:20 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8761EC4CEE7
	for <kasan-dev@googlegroups.com>; Sun, 20 Jul 2025 06:10:19 +0000 (UTC)
Received: by mail-lf1-f50.google.com with SMTP id 2adb3069b0e04-5561c20e2d5so4375223e87.0
        for <kasan-dev@googlegroups.com>; Sat, 19 Jul 2025 23:10:19 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVq4VrC/MvcWWl0gGVUMbw9tCM5Yn+qM807AtM0bodcspLhEHg3YD/PX78vDfHQktitTVLZNRXcItw=@googlegroups.com
X-Received: by 2002:a05:6512:2301:b0:553:5176:48a with SMTP id
 2adb3069b0e04-55a31843110mr2007807e87.21.1752991817889; Sat, 19 Jul 2025
 23:10:17 -0700 (PDT)
MIME-Version: 1.0
References: <20250717231756.make.423-kees@kernel.org> <20250717232519.2984886-4-kees@kernel.org>
 <aHoHkDvvp4AHIzU1@kernel.org> <202507181541.B8CFAC7E@keescook>
In-Reply-To: <202507181541.B8CFAC7E@keescook>
From: "'Ard Biesheuvel' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sun, 20 Jul 2025 16:10:01 +1000
X-Gmail-Original-Message-ID: <CAMj1kXGAwjChyFvjQcTbL8dFXkFWnn9n47bkN7FP=+EsLNsJdg@mail.gmail.com>
X-Gm-Features: Ac12FXxx6bD_QGQsGFgOANxpcIEdVmgITnXc8yZmdE0EdDE9cBbQCb787bRnEwA
Message-ID: <CAMj1kXGAwjChyFvjQcTbL8dFXkFWnn9n47bkN7FP=+EsLNsJdg@mail.gmail.com>
Subject: Re: [PATCH v3 04/13] x86: Handle KCOV __init vs inline mismatches
To: Kees Cook <kees@kernel.org>
Cc: Mike Rapoport <rppt@kernel.org>, Will Deacon <will@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
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
 header.i=@kernel.org header.s=k20201202 header.b=HcocEkaA;       spf=pass
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

On Sat, 19 Jul 2025 at 08:51, Kees Cook <kees@kernel.org> wrote:
>
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
> > >                                       NUMA_NO_NODE);
> > >  }
> > >
> > > -static inline void *memblock_alloc_from(phys_addr_t size,
> > > +static __always_inline void *memblock_alloc_from(phys_addr_t size,
> > >                                             phys_addr_t align,
> > >                                             phys_addr_t min_addr)
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

Given that 'inline' is already a macro in the kernel, could we just
add __attribute__((__always_inline__)) to it when KCOV is enabled?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAMj1kXGAwjChyFvjQcTbL8dFXkFWnn9n47bkN7FP%3D%2BEsLNsJdg%40mail.gmail.com.
