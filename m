Return-Path: <kasan-dev+bncBCVLV266TMPBBXMNV7AAMGQEW2Y4ELQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id E70B2A9CF9D
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Apr 2025 19:31:11 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-316c3874f3fsf11063381fa.0
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Apr 2025 10:31:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745602271; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZoZJeXLp4g6W0VVjDoukVHAMfpiRIfKGw/lgwTpe3selCC8bdeui6pMvS0gkg0Py/Y
         EhdkA2jyaa3esQgYdCbRFgmWSyFwTIekXP2J+TPD8JujFrY/4wT2z8ag/u6s7qqlb7Un
         1Z6odCLMJUN1vy2Gg7eXhJne1Uieo9XCDhai7VDcwfBUWHsKow3cMqQWSjsegHfD0/08
         BZTbFIYg8VXeKtLmprGSGWtPqZVZ7IaW3x7I0cViGkB9+B/xC/bahJ5BN48IP6Jp+c2h
         cHzFdlua74kmeBbi17S/YvxUPrmysn88+5quAhYP+BCypVr8hGx1h/kqzSjFsboEZY0J
         4lcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=5hk5sUA8oCijrws/EJQb/Y5lM+OQ2UQNopVN4jIIhAo=;
        fh=zY1/nshI3wH5yt5S81igH3ORWnGN1ivsS3vsIf1w+z0=;
        b=e7FiPzNehUsRO5FaiPPimS0GprWeLKmN6uT6QdPur6g7NCWz1IB6GweV34dew/PKUq
         Q8NxHGdjrY6Hm9I1uqBbLoRfKULU7Qd5es5fx2ISTYpXcRWlSzzA6A/B2H1aRZYMbzb1
         eRdYDVy0Ai5L5/mGBW18POrB1VGvgkOxsI6GY0Q5dhzRiREmHM351p51U2fGrDVWu0mb
         NlTiKSmDs+7F1mSU22F9opaVs7q2KIbnhGkE4SPRZWrLNwKm64+kD3AmBvb/i/T1AY2f
         7DE2q81wk8O9JMKV/3c3cSo8qFc0rpMjY4PWRC8YHJ/qJibuLxVgsZCwXhE6ur7kGOmw
         GD5Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=wwxnHPYi;
       spf=pass (google.com: domain of smostafa@google.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=smostafa@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745602271; x=1746207071; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=5hk5sUA8oCijrws/EJQb/Y5lM+OQ2UQNopVN4jIIhAo=;
        b=QTP8QW85+vRdL4d/5/lkonT3k7hRwfSMsxOB3nVDqN7towOnkM+RS+kqX+r2JlPGXT
         aLlk3BigFhYwDqx2OdMXG97ADWG9oWmFAvrBOis/oDNu5ev4qFvMqphxJeMaOAx2ys9g
         AIKfvAgn0ORMDj89zZQGss8DyJIRgBYrqeKdfNgLxRGQMhFxMqSB83asjUI9pIbxbw79
         BcKzRHUmb7m2LRjKFTbbC6A4wluCeltwkN4vo0tQWs9ezDuutiSixUnsgAaS5iCmp41R
         A3CS7NUwA+jfDfiIG4poc+5srGKGwtNCkhc2P4ydvmHGFsFZb2EwA5SZKK9yP/3pGMj1
         xu4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745602271; x=1746207071;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5hk5sUA8oCijrws/EJQb/Y5lM+OQ2UQNopVN4jIIhAo=;
        b=exZzDYnJf3N8TNNyUQV6hzqe3aH8hM37kw6LlLsHPEJEPZyVfx5XSGduUj8g0m64+D
         d3NT1XG18PSpWk/GMTWshK7P7MA2Et0bSe2NIPm18w7wDI3d/vzSR+Uohl4I+Z6gle7I
         7zbgR7aLL+Aj7ww8NxWAXDaMfUCQ3EU8rhSn8J8YU6k8/XEmRX5M5l80Y79m2FjNTe7k
         FDo+ks3GXiTSjRqX0JOnLVoP25cVcpEZGitXPmGCyuu6sx0C/DxYCj6hBuOJbvWfzh4O
         VtK8R2MSYCNxaKKfCxc9uHdC7QYpbcTMhqLopwOWLNn7CBk0XtP7f6QxFeLXOP7dgYmM
         u0Ug==
X-Forwarded-Encrypted: i=2; AJvYcCUH8hSBVcBLUmYdiZn1E1bJq3nHLmUWkVp3+lPussx0uNA4ViLB4b/T0lfkJ2Hzsk+9QtYn+Q==@lfdr.de
X-Gm-Message-State: AOJu0YwiAKPG1zN7WUERCmw0w2V5p5f2Bkviq5gffrQpjtegCmgL4Ybq
	O1pcYXUcmmog/XIWvcAUqkzZU35Tm6j1Mg+INqwZYe1NFVfjBhK6
X-Google-Smtp-Source: AGHT+IGA+w5pq3Ei0HJ7hgqv1jLa9e6FbCN5XJ9jLsBTUuNTBYNwP1mJLHNZOxY5v5XVNdIcyk8bbg==
X-Received: by 2002:a2e:b88a:0:b0:30c:dbf:519f with SMTP id 38308e7fff4ca-319ddd66a48mr426861fa.35.1745602270066;
        Fri, 25 Apr 2025 10:31:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBH+EXmSq+ZfEacoJm6CItLoGluwGq3y90XOOx/Uuctc3Q==
Received: by 2002:a2e:8e94:0:b0:30b:fc92:55c1 with SMTP id 38308e7fff4ca-3177e46cbcels3814321fa.0.-pod-prod-06-eu;
 Fri, 25 Apr 2025 10:31:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWO78FDN9s8yh8PHGqJBpuKePc+yAyur0qoa1qVLI+xVe1xc2zxlT4eGS1movbSYfYdd9sybcxFI3Q=@googlegroups.com
X-Received: by 2002:a2e:a808:0:b0:30b:f2d6:8aab with SMTP id 38308e7fff4ca-319dd6a15c3mr459401fa.32.1745602267085;
        Fri, 25 Apr 2025 10:31:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745602267; cv=none;
        d=google.com; s=arc-20240605;
        b=TC7DdwxzQ+1+Fbr1CYRjkc61lcY4WBaGU5KVh66sI3sWTp38W7OTJUj1Ge0MnqdovW
         K2DDVKEWJvgAkQkT5WBt2Eh1iCDKbvdeawjY3HIHmS0fc9M7zkTi0TJZRapOLeD6dqRp
         oDn/X2mQoip7gvZBcaqg8zdawQ+3X/tqN/D6py0IQ4C1/RC14ilCleW62vma3XFiZp2O
         pk1ZdoUW1cMzoVOk/VIQ7R9v4mc9potjsN2k47V1fhtaOlBKm6qFVovznQa+8mYqDymE
         pTSe6ZSeINKfgp00idkfF89DoprpPKenw6IC+ePsysEfP8E0xtVmQEMEubZdWA9tpRRo
         cmQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=JFiaMWMIJ6jFGDzd2ejMDb6Y0fvSj84EWSVaMESBeFo=;
        fh=OVY6sA/99bjThPTvMqLa5M6QaU41nNxntg1NEXuLv34=;
        b=WLkMPKGySysK1N4PHyF2omoPGB/UQYXvioOZt3uwzKM2kHe7HFsNfY74F8yAtSLqTz
         pSJGPfVxW0CL6kNIujfc8XTHBX7edgyqj+5uKP0Tw7/YJLBsy42/hikj/wAJAYzpQsOQ
         latjPHe8tK+I4quiSpqPVK7kkjdI2ll3kYMYkpn6UqQ+tL0ggZ6KatkC/Drzdc/Gn02t
         /udiog1aGOCkkWiHqnEW7TYkoDyfSbQSxs6Ddjr1nx3/8amS3aDXtLUq7B7FrDcKY2mB
         vYIDVC9DJy/H+zDkdWhO6Rx6ZnSntqjnt36lPfbwREz8Xl+309kNA0EH7pehmdrld6t4
         2YUQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=wwxnHPYi;
       spf=pass (google.com: domain of smostafa@google.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=smostafa@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32a.google.com (mail-wm1-x32a.google.com. [2a00:1450:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-317cf74efcdsi827181fa.1.2025.04.25.10.31.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 25 Apr 2025 10:31:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of smostafa@google.com designates 2a00:1450:4864:20::32a as permitted sender) client-ip=2a00:1450:4864:20::32a;
Received: by mail-wm1-x32a.google.com with SMTP id 5b1f17b1804b1-43cfe808908so3485e9.0
        for <kasan-dev@googlegroups.com>; Fri, 25 Apr 2025 10:31:07 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXL/WMSg1lWWNAYBbjKHk2skLlgKUA0I8CnAb94Mj+5PwNXmXj3qTHxr12nKbX8LTjfgaNi6HCNKt8=@googlegroups.com
X-Gm-Gg: ASbGncv5t8C1Q7tlPJ7ndG7R+QX/rZHlAlhtcFk1/RfWmsQ8mRqcQat26qC/CV2Nva/
	rTFZ8ZcGK5z5OP8VVHaVAsou41xtx1bO0u7MnWeQjb1RjbGROTq/LB+wSbEUUptJ9hbMsVBa108
	DLoYc7kZD9COAWs2y7Yk6DVkwK5o1DhfRskpRbsm2waq7m8tdfmsDnUyS8tJZ4iVKcsL08ktbOV
	dRq5BAshDiL0kyeZriaTAbL9sxt0yXHWHyEsdL5wY6OAjyGNTW6bq7prMMph78sjsOSb0Xqjfg2
	vDWFjLWYSjlzp3LjajbiCbdmKwik9TdEhjTn6/GJ8B+oKRcUchLtT13Bsr7ny6JqBK7cW0JtJVS
	vE3s=
X-Received: by 2002:a05:600c:1c8b:b0:439:8f59:2c56 with SMTP id 5b1f17b1804b1-440abc6d38bmr9835e9.2.1745602266145;
        Fri, 25 Apr 2025 10:31:06 -0700 (PDT)
Received: from google.com (202.88.205.35.bc.googleusercontent.com. [35.205.88.202])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-4409d2dfc2fsm62434785e9.33.2025.04.25.10.31.05
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 25 Apr 2025 10:31:05 -0700 (PDT)
Date: Fri, 25 Apr 2025 17:30:57 +0000
From: "'Mostafa Saleh' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kees Cook <kees@kernel.org>
Cc: kvmarm@lists.linux.dev, kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	will@kernel.org, maz@kernel.org, oliver.upton@linux.dev,
	broonie@kernel.org, catalin.marinas@arm.com, tglx@linutronix.de,
	mingo@redhat.com, bp@alien8.de, dave.hansen@linux.intel.com,
	x86@kernel.org, hpa@zytor.com, elver@google.com,
	andreyknvl@gmail.com, ryabinin.a.a@gmail.com,
	akpm@linux-foundation.org, yuzenghui@huawei.com,
	suzuki.poulose@arm.com, joey.gouly@arm.com, masahiroy@kernel.org,
	nathan@kernel.org, nicolas.schier@linux.dev
Subject: Re: [PATCH 3/4] KVM: arm64: Introduce CONFIG_UBSAN_KVM_EL2
Message-ID: <aAvG0br0XT9BFZ6S@google.com>
References: <20250416180440.231949-1-smostafa@google.com>
 <20250416180440.231949-4-smostafa@google.com>
 <202504161250.CC5C277A@keescook>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <202504161250.CC5C277A@keescook>
X-Original-Sender: smostafa@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=wwxnHPYi;       spf=pass
 (google.com: domain of smostafa@google.com designates 2a00:1450:4864:20::32a
 as permitted sender) smtp.mailfrom=smostafa@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Mostafa Saleh <smostafa@google.com>
Reply-To: Mostafa Saleh <smostafa@google.com>
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

On Wed, Apr 16, 2025 at 12:54:21PM -0700, Kees Cook wrote:
> On Wed, Apr 16, 2025 at 06:04:33PM +0000, Mostafa Saleh wrote:
> > Add a new Kconfig CONFIG_UBSAN_KVM_EL2 for KVM which enables
> > UBSAN for EL2 code (in protected/nvhe/hvhe) modes.
> > This will re-use the same checks enabled for the kernel for
> > the hypervisor. The only difference is that for EL2 it always
> > emits a "brk" instead of implementing hooks as the hypervisor
> > can't print reports.
> > 
> > The KVM code will re-use the same code for the kernel
> > "report_ubsan_failure()" so #ifdefs are changed to also have this
> > code for CONFIG_UBSAN_KVM_EL2
> > 
> > Signed-off-by: Mostafa Saleh <smostafa@google.com>
> > ---
> >  arch/arm64/kvm/hyp/nvhe/Makefile | 6 ++++++
> >  include/linux/ubsan.h            | 2 +-
> >  lib/Kconfig.ubsan                | 9 +++++++++
> >  lib/ubsan.c                      | 6 ++++--
> >  scripts/Makefile.ubsan           | 5 ++++-
> >  5 files changed, 24 insertions(+), 4 deletions(-)
> > 
> > diff --git a/arch/arm64/kvm/hyp/nvhe/Makefile b/arch/arm64/kvm/hyp/nvhe/Makefile
> > index b43426a493df..cbe7e12752bc 100644
> > --- a/arch/arm64/kvm/hyp/nvhe/Makefile
> > +++ b/arch/arm64/kvm/hyp/nvhe/Makefile
> > @@ -99,3 +99,9 @@ KBUILD_CFLAGS := $(filter-out $(CC_FLAGS_FTRACE) $(CC_FLAGS_SCS), $(KBUILD_CFLAG
> >  # causes a build failure. Remove profile optimization flags.
> >  KBUILD_CFLAGS := $(filter-out -fprofile-sample-use=% -fprofile-use=%, $(KBUILD_CFLAGS))
> >  KBUILD_CFLAGS += -fno-asynchronous-unwind-tables -fno-unwind-tables
> > +
> > +ifeq ($(CONFIG_UBSAN_KVM_EL2),y)
> > +UBSAN_SANITIZE := y
> > +# Always use brk and not hooks
> > +ccflags-y += $(CFLAGS_UBSAN_FOR_TRAP)
> > +endif
> > diff --git a/include/linux/ubsan.h b/include/linux/ubsan.h
> > index c843816f5f68..3ab8d38aedb8 100644
> > --- a/include/linux/ubsan.h
> > +++ b/include/linux/ubsan.h
> > @@ -2,7 +2,7 @@
> >  #ifndef _LINUX_UBSAN_H
> >  #define _LINUX_UBSAN_H
> >  
> > -#ifdef CONFIG_UBSAN_TRAP
> > +#if defined(CONFIG_UBSAN_TRAP) || defined(CONFIG_UBSAN_KVM_EL2)
> >  const char *report_ubsan_failure(u32 check_type);
> >  #else
> >  static inline const char *report_ubsan_failure(u32 check_type)
> > diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
> > index 4216b3a4ff21..3878858eb473 100644
> > --- a/lib/Kconfig.ubsan
> > +++ b/lib/Kconfig.ubsan
> > @@ -166,4 +166,13 @@ config TEST_UBSAN
> >  	  This is a test module for UBSAN.
> >  	  It triggers various undefined behavior, and detect it.
> >  
> > +config UBSAN_KVM_EL2
> > +	bool "UBSAN for KVM code at EL2"
> > +	depends on ARM64
> > +	help
> > +	  Enable UBSAN when running on ARM64 with KVM in a split mode
> > +	  (nvhe/hvhe/protected) for the hypervisor code running in EL2.
> > +	  In this mode, any UBSAN violation in EL2 would panic the kernel
> > +	  and information similar to UBSAN_TRAP would be printed.
> > +
> >  endif	# if UBSAN
> > diff --git a/lib/ubsan.c b/lib/ubsan.c
> > index 17993727fc96..a6ca235dd714 100644
> > --- a/lib/ubsan.c
> > +++ b/lib/ubsan.c
> > @@ -19,7 +19,7 @@
> >  
> >  #include "ubsan.h"
> >  
> > -#ifdef CONFIG_UBSAN_TRAP
> > +#if defined(CONFIG_UBSAN_TRAP) || defined(CONFIG_UBSAN_KVM_EL2)
> >  /*
> >   * Only include matches for UBSAN checks that are actually compiled in.
> >   * The mappings of struct SanitizerKind (the -fsanitize=xxx args) to
> > @@ -97,7 +97,9 @@ const char *report_ubsan_failure(u32 check_type)
> >  	}
> >  }
> >  
> > -#else
> > +#endif
> > +
> > +#ifndef CONFIG_UBSAN_TRAP
> >  static const char * const type_check_kinds[] = {
> >  	"load of",
> >  	"store to",
> > diff --git a/scripts/Makefile.ubsan b/scripts/Makefile.ubsan
> > index 9e35198edbf0..68af6830af0f 100644
> > --- a/scripts/Makefile.ubsan
> > +++ b/scripts/Makefile.ubsan
> > @@ -1,5 +1,8 @@
> >  # SPDX-License-Identifier: GPL-2.0
> >  
> > +#Shared with KVM/arm64
> 
> Nitpick: Please add a space between "#" and "Shared", and end the line
> with "."

I will fix it in v2.

> 
> > +export CFLAGS_UBSAN_FOR_TRAP := $(call cc-option,-fsanitize-trap=undefined,-fsanitize-undefined-trap-on-error)
> > +
> >  # Enable available and selected UBSAN features.
> >  ubsan-cflags-$(CONFIG_UBSAN_ALIGNMENT)		+= -fsanitize=alignment
> >  ubsan-cflags-$(CONFIG_UBSAN_BOUNDS_STRICT)	+= -fsanitize=bounds-strict
> > @@ -10,7 +13,7 @@ ubsan-cflags-$(CONFIG_UBSAN_DIV_ZERO)		+= -fsanitize=integer-divide-by-zero
> >  ubsan-cflags-$(CONFIG_UBSAN_UNREACHABLE)	+= -fsanitize=unreachable
> >  ubsan-cflags-$(CONFIG_UBSAN_BOOL)		+= -fsanitize=bool
> >  ubsan-cflags-$(CONFIG_UBSAN_ENUM)		+= -fsanitize=enum
> > -ubsan-cflags-$(CONFIG_UBSAN_TRAP)		+= $(call cc-option,-fsanitize-trap=undefined,-fsanitize-undefined-trap-on-error)
> > +ubsan-cflags-$(CONFIG_UBSAN_TRAP)		+= $(CFLAGS_UBSAN_FOR_TRAP)
> 
> Another minor style request: please name this "CFLAGS_UBSAN_TRAP"
> (nothing else in Kconfig uses "FOR" like this, and leaving it off sounds
> more declarative).
I will fix it also in v2.

> 
> >  
> >  export CFLAGS_UBSAN := $(ubsan-cflags-y)
> 
> Otherwise, yes, looks good.
> 
> -- 
> Kees Cook

Thanks,
Mostafa

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aAvG0br0XT9BFZ6S%40google.com.
