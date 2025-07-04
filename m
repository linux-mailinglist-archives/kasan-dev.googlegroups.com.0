Return-Path: <kasan-dev+bncBDAZZCVNSYPBBNVQT7BQMGQE5DGZ64Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id B101EAF9444
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Jul 2025 15:33:44 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-2369261224bsf11295185ad.0
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Jul 2025 06:33:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751636023; cv=pass;
        d=google.com; s=arc-20240605;
        b=S593JoTF2ynw7UZC9ZhGKfBSBwTWskxkR2hJ5fFkJXkiE7J+7FDhoKk996wTGiYtbd
         UKusn/V23cEm0ewzkHDON0ZsDanB5lc6/JIEmwl9SJFOEFsxo/b4VrR8z1CWZDiHZCNn
         q/rYwmFQGegGh7JoM0k5XxwXN1RXYludr+iVrsWWuoxSPvnJwpctzYcOPKUeMDvpqqHU
         pLNFDCPi2fPf+1l+sVS7fdYe0TNoRMT+ZLTbUjov1DJ9ahbNUnvQLsIorY+6TdUNGP83
         zLAnVBtzqwjS1GpIIkc/XSz4JPWQnt2HFIoyQln9ItZuJ7+rZt9YeDBPV8Sj9PGFFkkr
         xziw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=10wcrt564i1CrJ9u1JrxVUHNMXGn4KIBNkcmtHvb5a4=;
        fh=8nzpywTovNpVFbvpinDWCFmfammmB3shfS25pVIsR4g=;
        b=USR0lsVKKEITzv/GneHZpRMRrNj8ZTCafBUJMP17fiS718M6Exelvxn4qZt/8WNFuU
         KKtybu4QYXp2ap5sTJAWg0xISpR3vXmxknxvl1PLe9aYJpailZWK6WaP7cW76errynhk
         WugmY7zHMzwqrxPOWcuFYj6DyDe+Eey+85+peEhu5J2x7yA4GevlFzK87/uu6VI8iXFl
         7n53VRNYz9DGuT3KFWGsyFPtGk41T0pi4f/RDBtnDfWW38MtSzJgSTeMxZppEPcZ7Gq+
         ZVLjTF9NfraVsFcYApt03jOrFxax6aWn59DQglM9yIXq+YMJEcXlOEbsJt313HcQceWt
         OoDQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=pHxzUfPa;
       spf=pass (google.com: domain of will@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751636023; x=1752240823; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=10wcrt564i1CrJ9u1JrxVUHNMXGn4KIBNkcmtHvb5a4=;
        b=N5/0vXu/RekjwE61NkOJZwGzLVfmbWn1N5DaSAY7WHaSnqskWGiZlmNK/oqrF02YQ2
         O6Ed8Vtvb55oGgFnquh8wDecnvtPA9ALYmXUKQ/CMnGHuWHsh+XnBezoHptevBPmNYe8
         VpBDbQjpNTLjR5qHsJqAlqqvJgNrEAHe6dqZ9ukpzee2RF13ek0VGOr1ZgVQWuaO0Mh/
         LQEcPw2gyMXTMTzQvkJ12q7XBR5VEhKpSKBeOtWQeU9Pkcl0c+0NthHimH53DFvqAWLk
         mCKqOkPiRVEgrHGniKabhkKSTw8yVuFxijEySjIJ6G+/Zo55clsYe2Wuhl7q34gvOGog
         5Ixw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751636023; x=1752240823;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=10wcrt564i1CrJ9u1JrxVUHNMXGn4KIBNkcmtHvb5a4=;
        b=lfNJRJ3Qd6YfH7VDawnKGLv8Zw4E9gCH9ZqNfMKeamu8SlNedxc1VRyWCk0x4WPMRt
         MiWqUpDmV0Hb4VtJPKgqOaiYCMmvBzIezLKhIZLGo8jsD7bYUAyEK6XsiF/rI+fSUuJt
         wual9XCt4d5eNUMjS4yGdxUe2kxkt2UyxWLXxfDc1u67qP7Rcc4Wu6soF1NiQCRqdNc/
         kjGHi0cc0olp9Amy2MgG15mNzqhYXhDZ9vlRkpmsfP2OJ55vrf/twfHedZjiI2Ro8ARA
         07QVlpQ26En2kTr4qnDHDezDBPXz6j69i+sKN/GHX3uRIsqzJ4KlWgLHHHq7ANcY1m/z
         x+zA==
X-Forwarded-Encrypted: i=2; AJvYcCX9uS5NNgYxOuSo+MemR+bCGgbxTWsgxfK2ssb82dhPyiSjhYJPw1K+9HdNuosL8+kmySGZ3w==@lfdr.de
X-Gm-Message-State: AOJu0YwfJgj+txbrgYX+S25CvyeS6ifI0q+VWXH4dNj8JW5SVUHVQ6tJ
	bU94ETjA2ImafefeEIosXLsT117DryagCjaa7SBrWdn6LRkcdCIbQhcx
X-Google-Smtp-Source: AGHT+IEns+NJzThUn9x6318Fcy0RpBnrMJ2XDRU9I8hac6zJiXFORRv6bxHfTm1fpBy+bcrbTSbwrg==
X-Received: by 2002:a17:902:da84:b0:234:e7aa:5d9b with SMTP id d9443c01a7336-23c87484443mr31043765ad.23.1751636022851;
        Fri, 04 Jul 2025 06:33:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc+A4ZtQbpdaAgKJIi3vC5B9xxbUuPzuNlDXE3e8D55Xg==
Received: by 2002:a17:902:d48e:b0:224:781:6f9c with SMTP id
 d9443c01a7336-23c89ac246bls4848965ad.0.-pod-prod-08-us; Fri, 04 Jul 2025
 06:33:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUZK+ANvyuH7CLQSEVKw7RVGJaiuchKZsRSE030xWdUn3X2K3g3U+ObUVvb5rZrqRGQuyh5jqchgSw=@googlegroups.com
X-Received: by 2002:a17:902:f611:b0:234:a139:1216 with SMTP id d9443c01a7336-23c875b0929mr38277505ad.44.1751636021563;
        Fri, 04 Jul 2025 06:33:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751636021; cv=none;
        d=google.com; s=arc-20240605;
        b=fROCELw8tj58UugDOELNBUX5W1Z+JGx1khX1UViXIbt8ctdI4Q28+TuKqKg+PeE6T4
         wUq7bZcKTjvCj8WO951Ze+EzKogI5kvq8YiZ36ahlnRGNaCvaM7vcKK/8yOhAKLsTsL+
         sdsf+C/Y9Ju3l7n7RyLnqWEuMGPh4lQybWcK9lVCV9jtUHCiCeddhT+fcKKrTsNUzhJz
         a++Sq0SQB/6iK5jNYHThuP2qR7uii6kScYbkJ0d2o6A5Y/EDKIQyylMSroZuwQdk3cMi
         r3dWL8aatJmiT0cBk173LbtpLULPcrJqWDRZ/I1Yvn/gUgXa6Lhw5BA8Ip6FzQHMTND9
         aY6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=WbSext6onKKjDs37MnisE73O5uppHzZhzD+iEHs4084=;
        fh=oKEf5EmXQJ6vCnIpZujbodl3hofPfjYlAAKQylwS4sQ=;
        b=EQbQy83JqsojxKfDHQ734XWlA5m6Gf0RWy8kfX7Xqi35wjr73xpnkmp0KpG6OiZds8
         XaoMSZpeo85jBmefBQ6JmYr8mD35TnIpBBTDlqhaKYGw/aWyrcKv9bmorOS6D+5KkUgb
         xh7KC3XaxFPQSbSp6fp7JgTiDAuHxyi79R8bvksvdAbZqvnDiO49LobYCoaeaXS7xdR3
         E4kQxLr5XPQ+sMkJYYZARzpcFqokRstQUiB+rLRXakaQtffb7QIULNhwHgMBv2DCrqj+
         TaBuJ9Ety0n50jdbz9PJHpeWZK8NSN97EIIN+xqmQJizuF/+u6Occhm77nhnnxFajZ+1
         VhhA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=pHxzUfPa;
       spf=pass (google.com: domain of will@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-23c84189e7esi1008185ad.0.2025.07.04.06.33.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 04 Jul 2025 06:33:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id EF3AE5C5C2B;
	Fri,  4 Jul 2025 13:33:40 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9B6DFC4CEEE;
	Fri,  4 Jul 2025 13:33:38 +0000 (UTC)
Date: Fri, 4 Jul 2025 14:33:35 +0100
From: "'Will Deacon' via kasan-dev" <kasan-dev@googlegroups.com>
To: Breno Leitao <leitao@debian.org>
Cc: Ard Biesheuvel <ardb@kernel.org>,
	Catalin Marinas <catalin.marinas@arm.com>, usamaarif642@gmail.com,
	rmikey@meta.com, andreyknvl@gmail.com, kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org, kernel-team@meta.com
Subject: Re: [PATCH] arm64: efi: Fix KASAN false positive for EFI runtime
 stack
Message-ID: <aGfYL8eXjTA9puQr@willie-the-truck>
References: <20250624-arm_kasan-v1-1-21e80eab3d70@debian.org>
 <aGaxZHLnDQc_kSur@arm.com>
 <CAMj1kXFadibWLnhFv3cOk-7Ah2MmPz8RqDuQjGr-3gmq+hEnMg@mail.gmail.com>
 <aGfK2N6po39zyVIp@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aGfK2N6po39zyVIp@gmail.com>
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=pHxzUfPa;       spf=pass
 (google.com: domain of will@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=will@kernel.org;       dmarc=pass
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

On Fri, Jul 04, 2025 at 01:36:40PM +0100, Breno Leitao wrote:
> On Fri, Jul 04, 2025 at 10:26:37AM +0200, Ard Biesheuvel wrote:
> > On Thu, 3 Jul 2025 at 18:35, Catalin Marinas <catalin.marinas@arm.com> wrote:
> > > On Tue, Jun 24, 2025 at 05:55:53AM -0700, Breno Leitao wrote:
> ...
> > > >  arch/arm64/kernel/efi.c | 9 ++++++---
> ...
> > > >  static bool region_is_misaligned(const efi_memory_desc_t *md)
> > > >  {
> > > > @@ -214,9 +215,11 @@ static int __init arm64_efi_rt_init(void)
> > > >       if (!efi_enabled(EFI_RUNTIME_SERVICES))
> > > >               return 0;
> > > >
> > > > -     p = __vmalloc_node(THREAD_SIZE, THREAD_ALIGN, GFP_KERNEL,
> > > > -                        NUMA_NO_NODE, &&l);
> > > > -l:   if (!p) {
> > > > +     if (!IS_ENABLED(CONFIG_VMAP_STACK))
> > > > +             return -ENOMEM;
> > >
> > > Mark Rutland pointed out in a private chat that this should probably
> > > clear the EFI_RUNTIME_SERVICES flag as well.
> > >
> > 
> > If VMAP_STACK is a hard requirement, should we make CONFIG_EFI depend
> > on it for arm64?
> 
> What about if we make CONFIG_EFI select VMAP_STACK? I think it is more
> straight forward from a configuration perspective.
> 
> I thought about the following. What do you think?
> 
> 	arm64: EFI selects VMAP_STACK
> 
> 	Modify the ARM64 Kconfig to make the CONFIG_EFI configuration option
> 	automatically select CONFIG_VMAP_STACK.
> 
> 	The motivation is that arm64_efi_rt_init() will fail at runtime if
> 	CONFIG_VMAP_STACK is not set, so the patch ensures that enabling EFI
> 	will always enable VMAP_STACK as well, and avoid having EFI disabled in
> 	case the user didn't set VMAP_STACK.
> 
> 	Suggested-by: Ard Biesheuvel <ardb@kernel.org>
> 	Signed-off-by: Breno Leitao <leitao@debian.org>
> 
> 	diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
> 	index 55fc331af3371..cc2585143f511 100644
> 	--- a/arch/arm64/Kconfig
> 	+++ b/arch/arm64/Kconfig
> 	@@ -2437,6 +2437,7 @@ config EFI
> 		select EFI_RUNTIME_WRAPPERS
> 		select EFI_STUB
> 		select EFI_GENERIC_STUB
> 	+	select VMAP_STACK
> 		imply IMA_SECURE_AND_OR_TRUSTED_BOOT
> 		default y
> 		help

I would actually like to select VMAP_STACK unconditionally for arm64.
Historically, we were held back waiting for all the various KASAN modes
to support vmalloc properly, but I _think_ that's fixed now...

The VMAP_STACK dependency is:

	depends on !KASAN || KASAN_HW_TAGS || KASAN_VMALLOC

and in arm64 we have:

	select KASAN_VMALLOC if KASAN

so it should be fine to select it afaict.

Any reason not to do that?

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aGfYL8eXjTA9puQr%40willie-the-truck.
