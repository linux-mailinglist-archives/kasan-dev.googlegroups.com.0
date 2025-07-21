Return-Path: <kasan-dev+bncBDCPL7WX3MKBBOWA7LBQMGQEVXHDL4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C2B6B0CB8A
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Jul 2025 22:17:00 +0200 (CEST)
Received: by mail-io1-xd38.google.com with SMTP id ca18e2360f4ac-87c13b0a7ffsf625283739f.2
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Jul 2025 13:17:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753129019; cv=pass;
        d=google.com; s=arc-20240605;
        b=HwoxYpwlaMn1VcxssvpSgEVsZyVW2MWOixjeAxQZerV3AFXlzog2lUkf16VyYHvxQF
         0OCQms67QUO99bnT4rxYDB3aVzAHfnPRBEq9ntn64MzPi8OAwZgVCcXDCJT5RhUFJWAA
         FLwA8DJEbEarGcd8Y9RvCURgLym5AW4ElOJpSQSZtnF8IiHPUj7UuYQ1GQ47D4ctlnSj
         p003gHlp6SqbK6hEYqWqmOz4wioOCOkwOz7rRZ571cPYgoJuF8PnA2szJNBchPr3/wiO
         pOd9wp00/i7aYxtLKUaHDeWcx1l3UhR4SAzHtkPSeER+RivW2751aYdSdhhqjZu6T8pK
         GQmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=lDw1qpOO66P/SmUin8c85TZ3nJnNzEYVKHPXzthNVN0=;
        fh=KdIFNRwxu49SbBUxoNQ2MnmkqI2KBvUZJVgX8ehTG7c=;
        b=dlEJHTaTahEf87DTl6gmzNDOuuEmFstS4KyDAXo4w8rReEczuyWzE7QJiWP8NTQDsY
         GhaBVnKfy/Pe0SpptYbq6hDMw9C+AFBMLd1PmxpiDrgI+lXugAF+UEtQdSile7XyRxIL
         VkNWiHOdX7/xENuxYCtm4SgLpun7DfxYiYsrGzjpX1jFcr1XZlJii/BANa40cHVDRj4R
         eLpv+Y/imMYrN1YHGeBByljI17SVyYTI3Crj+ES/tnAbXspncG10dy7nC+yopfAs2NWX
         SMMjFfn5uUHZXnVmu8xzclZ8poBBaqqmQWe2vcpvYu9b7HLIvB/0uCz6pVCHobLVoCMk
         xuJQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OZTE06mj;
       spf=pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753129019; x=1753733819; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=lDw1qpOO66P/SmUin8c85TZ3nJnNzEYVKHPXzthNVN0=;
        b=igSZL6nGW8FGSGL6AXsCDrAcJonWTKmXCycEfqkof7zA8RdhEOQjQpjKekLkuJBOTK
         iI84Fp0twcewp6v5AQxHlLJxGcl5O6pjKDybNg/Gbe94V5LS7dYgba/LlHnTuo9hM7Sm
         vJHMwEAP9E/iKQYPuvbNSO9WJVCJ5KjFhxBkE1Lns7gMmWV2zOVuaecDwcLYOiqCne9x
         yLsu7uFlMXo4hyDdEbnnbPeKj6Snss4a32aw2KG+uhY9tQXgxmivK662ZA91t0cqPrYm
         lJYEBffN5GMymVi87i9ii2RK2yF+zfQKyAQOqrglcaXbZtdB1JRe8D+Ipx+mIg+OUvwH
         rdDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753129019; x=1753733819;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lDw1qpOO66P/SmUin8c85TZ3nJnNzEYVKHPXzthNVN0=;
        b=Np3rrZE567JMnkJTSgnBrGbAOi+hVQVcaDUJvP6uMk1Qs/teoujPp7Hd/KhSoisqzq
         lLSfqKryFqCkN8xvYwhgCswix5LsFeYHHsDWAHzMN0l9EbWxj0H3/bQfBgADd7UHzFAt
         Rg0i5FSksNa/NJl5475joSr/OLai8f0VXlKYHOOxgQgP5wkT2iysIWniLhZxSdR3jbrW
         qW9GLSJTlaV/BkJQ+N8Yd37sdcf40DDhquMPWdc2aP/esHJImoXgDaP9i3WIA+Acwa4z
         7qEBPnUVcpIukPTs8P/tyPWkKuTfnakt/zllazWnuC5Appnvn9rHkvLkdgH9jls7cAY/
         00qQ==
X-Forwarded-Encrypted: i=2; AJvYcCWFAmL6cAcuQvDcrVy/bqyQkYcF6hEaQZWlwCeZgozXLYmffsx5/GArvu6wwCg05dJffOedWA==@lfdr.de
X-Gm-Message-State: AOJu0YyCEcfnjY8yvIrCVBljUW0LNTciVzBmoLkS5SvyOQ18WzJl2n7h
	rBYCg22N6sgPgem4dEWpnLqGczq0t4gCrKZkwI948MY28QqOSPG7Wuka
X-Google-Smtp-Source: AGHT+IHVZDwOHkIoDW9coyaCiuEalJDR8697ueG/2hm/WFeVaSkgorY6OgeYIoAmFitxBn4l+CM91A==
X-Received: by 2002:a05:6e02:160f:b0:3e2:a06e:952 with SMTP id e9e14a558f8ab-3e2a06e0c3amr142240605ab.12.1753129018852;
        Mon, 21 Jul 2025 13:16:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdzJp+7kKklvJfv5egji24ztyI3AA/mZB64RYM4pg4thQ==
Received: by 2002:a05:6e02:4813:b0:3de:143a:a012 with SMTP id
 e9e14a558f8ab-3e2b0e5b4fbls11799835ab.0.-pod-prod-01-us; Mon, 21 Jul 2025
 13:16:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVlzeXG+rtGNAma7ILAnRjfpsKH23mggei6Kfiyxy5NSGosq3TvsaUk56SvzH61lnH3dXOUr2j8f08=@googlegroups.com
X-Received: by 2002:a05:6602:13c5:b0:869:d4de:f7 with SMTP id ca18e2360f4ac-879c0935f49mr3338618739f.12.1753129017686;
        Mon, 21 Jul 2025 13:16:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753129017; cv=none;
        d=google.com; s=arc-20240605;
        b=kpNPydRxeqRc6ejrI5xkJPo4Yl4RFS5FfNRedNznfH6zsMvFsmgoRHAjKU2yiHNTxi
         Bnj33bF6OkG7nEh07wq5KEtjkT/HDkMBIvAuuCalxMem5Pb6Gz+YOZKHxeD5Q03PXHXl
         krPeE8dpuU0KieIQ15TtNnkVEVIKIP2IYVx1fSlY7D12rfYfCNdxTnrmNf7c//uKdF7u
         Xcly8XXXiHep+H8wxRFRVnZltbStL9ap9zKZpBGOvQl2hUUbM7xAwhwQCV6xc2uXuPcz
         BTMdsxVnAD+6pnkqdPexpLFpRte8nBt9+BS+zGLf2GSRQ760qbnho2st88xyB77uYcOR
         3Yow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=pC6N5OITXZeC0uUkeAFleXNH6YpHOYQFRnwNz1YKGyA=;
        fh=45P6/SuRMEwQHG0WwBen0ELtD+kaRUlqMjRG17C5src=;
        b=b+0aXObcOj5fLn4c9YfVQK+Nk/j1PJm6hEbhpr5XCqRwCX6FXQp8D0ypids0BsjzoW
         XS7ZcY/YUrhhF6iNhncWubtqn0Y7qaiyvpxiYjYWV7DRLrbZ6pxhd7vaniftrM+HjsZR
         USPuO6Ba7rwJEiO2Tm/UbmCo+1StZk+3tVWVYGTl9pxGk0nfc5ECSxIwGr/fJi2mAPsJ
         GG5sN5Aai/dgrg9vAWzEkuw6tJwsL+Kgd65WPfuQCaGno+VCFTCuZgUWMf+GD3Dcqq0A
         78jbe/iZGWMJXR04KSFfZaRUsPh1gcSoKF4Xr7MxKcIJxlNAON5TDUH/+AlKucq5OddF
         KLRA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OZTE06mj;
       spf=pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-5084c59cba7si221931173.0.2025.07.21.13.16.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Jul 2025 13:16:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 42D9A5C5950;
	Mon, 21 Jul 2025 20:16:57 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D4CE8C4CEED;
	Mon, 21 Jul 2025 20:16:56 +0000 (UTC)
Date: Mon, 21 Jul 2025 13:16:56 -0700
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Nicolas Schier <nicolas.schier@linux.dev>
Cc: Arnd Bergmann <arnd@arndb.de>, Ingo Molnar <mingo@kernel.org>,
	x86@kernel.org, "Gustavo A. R. Silva" <gustavoars@kernel.org>,
	linux-doc@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	kvmarm@lists.linux.dev, linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org, linux-efi@vger.kernel.org,
	linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-security-module@vger.kernel.org,
	linux-kselftest@vger.kernel.org, Christoph Hellwig <hch@lst.de>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, sparclinux@vger.kernel.org,
	llvm@lists.linux.dev
Subject: Re: [PATCH v3 01/13] stackleak: Rename STACKLEAK to KSTACK_ERASE
Message-ID: <202507211315.5164A33E@keescook>
References: <20250717231756.make.423-kees@kernel.org>
 <20250717232519.2984886-1-kees@kernel.org>
 <20250721-spiked-adamant-hyrax-eea284@lindesnes>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250721-spiked-adamant-hyrax-eea284@lindesnes>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=OZTE06mj;       spf=pass
 (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted
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

On Mon, Jul 21, 2025 at 10:02:36PM +0200, Nicolas Schier wrote:
> On Thu, Jul 17, 2025 at 04:25:06PM -0700, Kees Cook wrote:
> > In preparation for adding Clang sanitizer coverage stack depth tracking
> > that can support stack depth callbacks:
> > 
> > - Add the new top-level CONFIG_KSTACK_ERASE option which will be
> >   implemented either with the stackleak GCC plugin, or with the Clang
> >   stack depth callback support.
> > - Rename CONFIG_GCC_PLUGIN_STACKLEAK as needed to CONFIG_KSTACK_ERASE,
> >   but keep it for anything specific to the GCC plugin itself.
> > - Rename all exposed "STACKLEAK" names and files to "KSTACK_ERASE" (named
> >   for what it does rather than what it protects against), but leave as
> >   many of the internals alone as possible to avoid even more churn.
> > 
> > While here, also split "prev_lowest_stack" into CONFIG_KSTACK_ERASE_METRICS,
> > since that's the only place it is referenced from.
> > 
> > Suggested-by: Ingo Molnar <mingo@kernel.org>
> > Signed-off-by: Kees Cook <kees@kernel.org>
> > ---
> > Cc: Arnd Bergmann <arnd@arndb.de>
> > Cc: <x86@kernel.org>
> > Cc: "Gustavo A. R. Silva" <gustavoars@kernel.org>
> > Cc: <linux-doc@vger.kernel.org>
> > Cc: <linux-arm-kernel@lists.infradead.org>
> > Cc: <kvmarm@lists.linux.dev>
> > Cc: <linux-riscv@lists.infradead.org>
> > Cc: <linux-s390@vger.kernel.org>
> > Cc: <linux-efi@vger.kernel.org>
> > Cc: <linux-hardening@vger.kernel.org>
> > Cc: <linux-kbuild@vger.kernel.org>
> > Cc: <linux-security-module@vger.kernel.org>
> > Cc: <linux-kselftest@vger.kernel.org>
> > ---
> >  arch/Kconfig                                  |  4 +--
> >  arch/arm/Kconfig                              |  2 +-
> >  arch/arm64/Kconfig                            |  2 +-
> >  arch/riscv/Kconfig                            |  2 +-
> >  arch/s390/Kconfig                             |  2 +-
> >  arch/x86/Kconfig                              |  2 +-
> >  security/Kconfig.hardening                    | 36 ++++++++++---------
> >  arch/arm/boot/compressed/Makefile             |  2 +-
> >  arch/arm64/kernel/pi/Makefile                 |  2 +-
> >  arch/arm64/kvm/hyp/nvhe/Makefile              |  2 +-
> >  arch/riscv/kernel/pi/Makefile                 |  2 +-
> >  arch/riscv/purgatory/Makefile                 |  2 +-
> >  arch/x86/purgatory/Makefile                   |  2 +-
> 
> Did you miss arch/loongarch/Kconfig by accident?
> 
> $ git grep -Hrne ARCH_STACKLEAK
> arch/loongarch/Kconfig:127:     select HAVE_ARCH_STACKLEAK

Oh! Yes, I missed that when I rebased to v6.16 (which added loongarch
support for stackleak). Thanks for catching that!

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202507211315.5164A33E%40keescook.
