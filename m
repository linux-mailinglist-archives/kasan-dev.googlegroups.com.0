Return-Path: <kasan-dev+bncBDTMJ55N44FBBXMVT7BQMGQEIA4IQCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id EC4B2AF92C7
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Jul 2025 14:36:48 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id 4fb4d7f45d1cf-6076ad0b2f1sf827696a12.0
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Jul 2025 05:36:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751632608; cv=pass;
        d=google.com; s=arc-20240605;
        b=BOXF7fINV7WYIok3vMFJtkIL9HkHbMMdDHtZlP32qkO5KRyaZb1+QCCH8msuzkrIh5
         1RqhviF4MGQJlS1Y2D0BnaQTLGIB/qeNk3Y5Hjo+ymz4PSgIoDivrO2raFJ3d7jCVhiA
         rgnvyNQLxSmYLK6IibCW68PFmkG3AWP55AjnCvVrUUb2IFByPTU0I6tNbOqGnWI2GavM
         SL7hWXO7vQDjs9ztwUL9FwKH8yFITgL0A8X7Us+BhltLkdTUeP/n5Z+D3F+RBi4Gte1O
         AePYeEZtW5TRpR7wFm/Fha3I6DVvRJtU2xX33JEAM2s1ktoUVMuZ8lmuFxNhCa8qe99j
         t89Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=HAbHqYal1y9OZsc8vliN+/9pB1N++noxYz+Oq5+sYdg=;
        fh=H1xpqIL/0V2TkQNym4NXaRQNKuErfWHhjkMW+oy3DSo=;
        b=QAJrTLwPqc2akkXfHY856CiT1uvELoxPFi8Tjg/BPaVQN5edVTubAP/w7uVvzYMCBw
         7qlBt3lNFdORBw2LQZiN05aUojGnLYwls+f5hdGp6nrCSPtwoDxK7JtWa3w0/Vx1ceoS
         O6d1m+MS7K4/3hjRIipu5AaTY08J91SfNuAJPoW58B7OgJDHpw51PpJ6lxc/rmIgdrZw
         ZBd16SID+uYBPy19Js9BgWO2gJZqmcbwaxGT1R32X9BddgfG8uZC7TTdgZ/IrdwjjCOX
         RtZ3bGrqFTyaOY90L2dcenVCAsHnOjMR28xwFs8WBtaCU3V50ErLD96x2gUdrt/rF3mk
         JyEg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.208.46 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751632608; x=1752237408; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HAbHqYal1y9OZsc8vliN+/9pB1N++noxYz+Oq5+sYdg=;
        b=b8Ny2eGG+HLyH6XTBGeV/21Y2cF0zq0xpikAUOPqwMZ+0xOld9Pg3Bbzq3yaoWGxMP
         dbzcoIAKV8LTG++vacLNh5nXazYdM83QQUwiSORqM3fremJTBp998sB3ICeiw8Omceb+
         Cu4AYRzF7wCv67OqNfCOfccUped7v+wZlktNRmx/+tW3Z8pDruCPTHgM7Uy6TeMWlj1T
         rbxw0ciCLJxlbQ+F7gCXyXzxMZF9A0Mk6yBw17chzMn2+Q4323358bUbO9lkGxB022QZ
         8J72KznSF0WJm8rHWXU8RBEwQMF3WLyS6ZMLwwc2totCdmGRrozHv1r93n4MJxoDD/EE
         vdFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751632608; x=1752237408;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HAbHqYal1y9OZsc8vliN+/9pB1N++noxYz+Oq5+sYdg=;
        b=cl1N8QB26e5bh6YzJuXtyeKkqgyWUgJs6kI+BmiAU2myJWp2+ESrxjdBB19/L9SI0z
         oD4JaFmdsayguMjUCYSbqecWrw1A8DE0x7wBT+Av7GhAC+6kgOk/IydJOYVYPjsYOsYz
         b5ZmVdsXvbQJJRJzlFwNuFjl4412GScHz+LRqF72fVzvMuAK94OcPN/GP8OmdpO9nX7M
         KhyCQbAW07DKDFUclBrBbfezuAn7wBmpzb/UXaHKCSnVq3mNRm7nkRxc2L2wGXTxegm3
         /kstbP460KJJDkiHeniFw743s2xNREtoyOpFnNtEsLw7TNl+9TtCpNPVCF/rTgH43mlQ
         gNEg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWHuxO3M8V39l+2b6ML3LxQf7ELlV2As/FEghqI+Kbyh5kmV3WF3qLMAWf8sAwGvG8km8UlWg==@lfdr.de
X-Gm-Message-State: AOJu0YyfU4CGOF0wiULloZEmXeBO9mbAjp/MGGnJcP02XhGSFZ8NeHfm
	YSId4NiseENwoDdlSumt7ohRLcpT10sf+M04o6JShWMksK+VWb8YBJcv
X-Google-Smtp-Source: AGHT+IEa7aXSlghIUkjZsfOkQ2AmE2HaEXFzOXv2ANFQpEnthf7zPdpLIOpCU8a4NSFJr2/R4LYzwQ==
X-Received: by 2002:a05:6402:5210:b0:608:6734:7744 with SMTP id 4fb4d7f45d1cf-60fd2f854f1mr2500613a12.7.1751632606913;
        Fri, 04 Jul 2025 05:36:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdQcLyZd+a+goauFscx2RN93x/Eo0IGK8KJE0FmojLY1Q==
Received: by 2002:a05:6402:84f:b0:5e7:88ec:e96d with SMTP id
 4fb4d7f45d1cf-60fdb651b57ls390617a12.2.-pod-prod-05-eu; Fri, 04 Jul 2025
 05:36:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV35UMB21hRYfONnsQGIaA2YQ9j8LmRI5lBjrvXQnD353Fq5aPOaKDAKcWqtuz2fJ0WZiAMFrPXV0I=@googlegroups.com
X-Received: by 2002:a17:907:60d4:b0:ad8:9257:5737 with SMTP id a640c23a62f3a-ae3fbc814ccmr238390966b.25.1751632603293;
        Fri, 04 Jul 2025 05:36:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751632603; cv=none;
        d=google.com; s=arc-20240605;
        b=cw/wBdNSYISAyitZojfmiOOlRFjrNneqamwKGxM2l0dnSM2lxrqicQ0bulZr3OpUBX
         ogWzBRzx4313YYykpTdJXs3vJcG9iFmnt/qefAEqlsMfy1bEdCSMmh3srobvKE6/4eCs
         AavRo+PGnMx7zWb9wxX2QGTetUDhBHjjyzcZEwFQxzNfqi5fNZSW/qSH/xgM7YANsHhk
         mHxgT/rB1dHYBX614AmObPAEKN9jRJ5USj5jSPOglqe4YwGlSXrGcUnRTuiWClkCi/31
         BJBqZjGBvog0L8WhyEAkbmUbGM7zSrSjbqC83FV1c/DyVHdrosxpZWWHYckUJ2fGM1GN
         GwzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=YW8Mdm8VBfi1qlOCL6Pf2QZ+6mI2RYO5Q+XtAXUgQJ4=;
        fh=diTzhwP0MWr5jydknocsY5/NQjpU3U8ZCCsUdU5Q3o4=;
        b=b1IYruqZ2SysI694W9lI9V9c6ukAvOmo7Al25kzpapT23Vue6gmQ9MiQceoh2Fasb4
         W4G4D2o7NTH3pqEOCH+kTqZm4o4u2Y8AfrKHVZ2usn29XNzO97kCkKyZ7LPDASbfzIzd
         XNx4L70zhkaXipewUXIs18jEWce7Rhcn773nsl+GaoRPOT1nkBH49Pw4MF037cdOP7p3
         3ZRNFmDQhpGZrXOtIf3igSanIAecawZtFg34g5E6ksRPS4jhKpMZCg/meqPSYWI2oce8
         ZD+1wJ5bV3LO8/EcVY8CzP1H7mUsv9qj7a9IqwgpCMeiAP55tKcSXa5UPwhLn7LSgXKP
         Q4zQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.208.46 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
Received: from mail-ed1-f46.google.com (mail-ed1-f46.google.com. [209.85.208.46])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-ae3f69554afsi5576066b.2.2025.07.04.05.36.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Jul 2025 05:36:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of breno.debian@gmail.com designates 209.85.208.46 as permitted sender) client-ip=209.85.208.46;
Received: by mail-ed1-f46.google.com with SMTP id 4fb4d7f45d1cf-605b9488c28so1450770a12.2
        for <kasan-dev@googlegroups.com>; Fri, 04 Jul 2025 05:36:43 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXP4u4YrAz0Tz3yLPfcQSqKdaXkCk223kI0mPkYsYfInoGLgFSdxgxFwo0Cx+b6PmmkiQWY0qAY14s=@googlegroups.com
X-Gm-Gg: ASbGncvQbVnsYcO0E/nByOH4p4AAGJ9SOMJU2BPzWGdqgyXim+6LUMv4+MNCsuGKer6
	hGbx12whHfkbU1TJH7JQmHoqvwgF2pPc+aXgYkxMaYs+l6jojN1PFIZjC957JoboANghOmhVaik
	cPMURH3BZQkbz2/szc5RRMD0et+BHBpyDaN25XFtv52Rphd+yu5/fV6WDAGFkTEMxqsDIFQbzAD
	ZJ0x8rRxB+3SpgDvfKMVq80Y1cvkGiQ8H+NLXPln/2IHKCKMAZgLNg9Z49pHJEP3/CRoNVCJQKA
	CRxl9PVCtC2X0Q66DuoDBJ9hIlwN8bzP8JAepny5H/z3usL8o2e0/vEHwSM=
X-Received: by 2002:a05:6402:2103:b0:5ff:ef06:1c52 with SMTP id 4fb4d7f45d1cf-60fd2f84f16mr2179344a12.3.1751632602449;
        Fri, 04 Jul 2025 05:36:42 -0700 (PDT)
Received: from gmail.com ([2620:10d:c092:400::5:c915])
        by smtp.gmail.com with ESMTPSA id 4fb4d7f45d1cf-60fc81a70e4sm1285566a12.0.2025.07.04.05.36.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 04 Jul 2025 05:36:42 -0700 (PDT)
Date: Fri, 4 Jul 2025 13:36:40 +0100
From: Breno Leitao <leitao@debian.org>
To: Ard Biesheuvel <ardb@kernel.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>, usamaarif642@gmail.com,
	rmikey@meta.com, andreyknvl@gmail.com, kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org, kernel-team@meta.com
Subject: Re: [PATCH] arm64: efi: Fix KASAN false positive for EFI runtime
 stack
Message-ID: <aGfK2N6po39zyVIp@gmail.com>
References: <20250624-arm_kasan-v1-1-21e80eab3d70@debian.org>
 <aGaxZHLnDQc_kSur@arm.com>
 <CAMj1kXFadibWLnhFv3cOk-7Ah2MmPz8RqDuQjGr-3gmq+hEnMg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAMj1kXFadibWLnhFv3cOk-7Ah2MmPz8RqDuQjGr-3gmq+hEnMg@mail.gmail.com>
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of breno.debian@gmail.com designates 209.85.208.46 as
 permitted sender) smtp.mailfrom=breno.debian@gmail.com
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

Hello Ard,

On Fri, Jul 04, 2025 at 10:26:37AM +0200, Ard Biesheuvel wrote:
> On Thu, 3 Jul 2025 at 18:35, Catalin Marinas <catalin.marinas@arm.com> wrote:
> > On Tue, Jun 24, 2025 at 05:55:53AM -0700, Breno Leitao wrote:
...
> > >  arch/arm64/kernel/efi.c | 9 ++++++---
...
> > >  static bool region_is_misaligned(const efi_memory_desc_t *md)
> > >  {
> > > @@ -214,9 +215,11 @@ static int __init arm64_efi_rt_init(void)
> > >       if (!efi_enabled(EFI_RUNTIME_SERVICES))
> > >               return 0;
> > >
> > > -     p = __vmalloc_node(THREAD_SIZE, THREAD_ALIGN, GFP_KERNEL,
> > > -                        NUMA_NO_NODE, &&l);
> > > -l:   if (!p) {
> > > +     if (!IS_ENABLED(CONFIG_VMAP_STACK))
> > > +             return -ENOMEM;
> >
> > Mark Rutland pointed out in a private chat that this should probably
> > clear the EFI_RUNTIME_SERVICES flag as well.
> >
> 
> If VMAP_STACK is a hard requirement, should we make CONFIG_EFI depend
> on it for arm64?

What about if we make CONFIG_EFI select VMAP_STACK? I think it is more
straight forward from a configuration perspective.

I thought about the following. What do you think?

	arm64: EFI selects VMAP_STACK

	Modify the ARM64 Kconfig to make the CONFIG_EFI configuration option
	automatically select CONFIG_VMAP_STACK.

	The motivation is that arm64_efi_rt_init() will fail at runtime if
	CONFIG_VMAP_STACK is not set, so the patch ensures that enabling EFI
	will always enable VMAP_STACK as well, and avoid having EFI disabled in
	case the user didn't set VMAP_STACK.

	Suggested-by: Ard Biesheuvel <ardb@kernel.org>
	Signed-off-by: Breno Leitao <leitao@debian.org>

	diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
	index 55fc331af3371..cc2585143f511 100644
	--- a/arch/arm64/Kconfig
	+++ b/arch/arm64/Kconfig
	@@ -2437,6 +2437,7 @@ config EFI
		select EFI_RUNTIME_WRAPPERS
		select EFI_STUB
		select EFI_GENERIC_STUB
	+	select VMAP_STACK
		imply IMA_SECURE_AND_OR_TRUSTED_BOOT
		default y
		help

> > (but let's see if Ard has a different opinion on the approach)

> I think this is fine - the stack just needs to be disjoint from the
> ordinary kernel mode task stack so that buggy firmware is less likely
> to corrupt it, and so that we can recover from an unexpected
> synchronous exception more reliably.
> 
> In that sense, the old and the new code are equivalent, so no
> objections from me.

Thanks. I will send an update with the update that Catalin and Mark
suggested.

Thanks!
--breno

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aGfK2N6po39zyVIp%40gmail.com.
