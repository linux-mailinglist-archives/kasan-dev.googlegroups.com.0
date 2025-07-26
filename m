Return-Path: <kasan-dev+bncBD4NDKWHQYDRBNGJSDCAMGQEQM4PDBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 89A00B12835
	for <lists+kasan-dev@lfdr.de>; Sat, 26 Jul 2025 02:43:34 +0200 (CEST)
Received: by mail-oi1-x23a.google.com with SMTP id 5614622812f47-41bfd8ccb17sf2035074b6e.1
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Jul 2025 17:43:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753490613; cv=pass;
        d=google.com; s=arc-20240605;
        b=Wj2kvtht+h3D80tu744fEtMsfhdWQXbPH25JX6ArpCZl1bVoorrXOvUv2D+vBjyqTh
         8HAJGnhh8IvKj0eBFPMiYsnTIfRWPddM6JP/rPnifpsDTSqhM+/FK4fFJwpoGhN9epvl
         ps4dklJD8ZWd0TcP7OserZjnoa50BZ8w9NrJj98Mny43/WntYSnfOeQpKuhPTfmGDdPk
         09bgNgn+IgHrORtaNNVQmSyY8wYlcmjLsc2RfyG88HkeBo8TUkpzNiWUqOlkv9urkJaw
         jtqr0FkHjKpW1//VTwHR5LaCNJ1r6l8bdmvM1Wjraqioaomou4KmtB67zb4RukSfgN2n
         /xDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=R+ysn+yTLe8bF0N3289oQHWI7kun59VghJq9bUuvGlA=;
        fh=9p0uM2QeQVFMGpy3Fu/R6IzujeR8+pnmBxJkpaoByZo=;
        b=EFiEsAWHpfUAz5qTWFc2nP7yAd7e7Qv/Ys1glN62lpSLVCx/UzNB8YntkbyTrP1pFj
         RqLbBPnxceNgXXp6NQvrx9ZRKYvhOMS649FrsVZpB2v0zhz/8W15zYhJes7bjkOY0x8c
         OJLgTSIo6humI8Of/V+3rqM5cpxZSPw3Accx63bj8/RIiHq3bJCA+/cv6DcZMvab+BKm
         3eN4jRX7AyA+bTZyE3fataWgbVh6CZl8EOSjEDDneYW1ud/ywrh1tng7w4LwjQcwM6/M
         pYgy04/C4K6dD3xgrFmKbkT8162HCxvKxocx2Sr2ySPH6mxWWZc+fepGUzwfJZWV/bKz
         tacA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kBaBfcy8;
       spf=pass (google.com: domain of nathan@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753490613; x=1754095413; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=R+ysn+yTLe8bF0N3289oQHWI7kun59VghJq9bUuvGlA=;
        b=lCvr0vmhlzDeNqowwiF/1KTX7Q4Rh75hWA5mBa0emHwf+u94MhDiSRmmBHflNV5y86
         BDehn5sSs6+Vc/MNv0I22u1iSUbUKuYYQ2ESgEqL0dDtsxYKdg6r20XmQR+wRBL7m0On
         GEtfqtBJhU3j/IcArLJpEcFn+vrwb4ILgHx/Hi6vdmTTROEqfCg5kcICj2yFE3bwELyQ
         AvXcMpKoE4huTC39HDVc6dtV7iD0aHVaZZ0v8tUvJQTGro/GwXA18yJcpgGD3d4vfOF7
         Pbwu5xSHOsVcLVMwpRTbNMX9X54EedEjT10tfdnFOWLjQhAX/A62Ab4bC2YHKB1wGtua
         /JYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753490613; x=1754095413;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=R+ysn+yTLe8bF0N3289oQHWI7kun59VghJq9bUuvGlA=;
        b=NV5kEWZKqB09zXLQVIsUuus9EeOOHaB0S6eophcQfqlka6twa7RJsmDyJaKsK7wu+l
         gjXy8ZzgzSZmVddR5+mWNCEK0CNaNuMCbM73Ecaq8h6hnODmV99qNAL8JLLpiQsb1uIX
         41uzgGJU6UnTQRH1jEqsjGgWULxseqazLnUMKnXc5aYJOkEZ7CMPeIXMfuA4uQNwn1q2
         mCZP8rabQ/0AsJRLTHqOdEvwFZoYBzhHZfbZKXsaWae4UIlxNrRtC4L5zjRR/fJCjKCE
         +K0dVik4DmgRYKu7EPsSkiN9L+gZbxr07sLsSH8dVfq4aWBPkjI09NPnM8V5OAddHm7t
         50Og==
X-Forwarded-Encrypted: i=2; AJvYcCVtROCV1Yw6ed7/U1Jq0csGwi7yR6v+Ve1i6U4A4Sv50srbm3hq7EJaoQcv0WJP8oKj/Vq9Xw==@lfdr.de
X-Gm-Message-State: AOJu0Yz2++5vX9vap2Ku601+DvZJIe155k4VyRmL96bIuiYrV+iY/aN9
	Z9B2mTXNJJozq554vsXp8LlbZFdYfumxQaVvzfAboCUAWNCDvaLN9PMC
X-Google-Smtp-Source: AGHT+IEsUG4eg8KKH9QDeUMHVsvkvcR9z23G8ZHDeCOIl+rE/ruVYLUq0srl522Oh40SYCAC0+NROg==
X-Received: by 2002:a05:6808:3506:b0:40a:729d:82f3 with SMTP id 5614622812f47-42a55f4d507mr4437656b6e.1.1753490613158;
        Fri, 25 Jul 2025 17:43:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeKoJbwh/DaUw8lhFXZpvrglPXOjJZnL51ubJ5QOJT3Aw==
Received: by 2002:a05:6820:16ac:b0:611:75c3:8e3 with SMTP id
 006d021491bc7-618fa27f0b3ls1014102eaf.2.-pod-prod-00-us; Fri, 25 Jul 2025
 17:43:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV7ovMO8yrRrWp6VgmVKxpQYQxcXwdXjENCSvRvFxnJ4k0trumFWRB7tkrSSd2JkYAcisfscBJHZJU=@googlegroups.com
X-Received: by 2002:a05:6830:911:b0:73e:9bf2:92a8 with SMTP id 46e09a7af769-7413ca05568mr2570289a34.3.1753490612212;
        Fri, 25 Jul 2025 17:43:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753490612; cv=none;
        d=google.com; s=arc-20240605;
        b=XYfl0PRW6I/NeivBA3tN4KnufUbTuutcOxf1yCtoT3wDNsoqwdbh7jmuqQ3stChlN1
         bm55bQa04knN8ikprvyjtS+QRsPf3FpHTe4iXECWaD/S2tMRWop9AySwsgL2Fgkf5kmS
         R/XgUArjnGAqvaLaLP8CI5EiEnsoCQ2SJsBq6RBzwTcttFkfKgs9AvK46cXS+8KzT5bJ
         rV9FKzberr+vmp8vUxfPyIB+W5onX3DXpYKCdCy/XmLDyY7lhwPfdjmeg3dp/GhAt6M0
         igHV/NGk51JWaMYaw6YdnIvvQWiRaONeGai2dZJBu4K73Kwsr17twHTOYeLit3xlfCnI
         U1WA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=1sAzsEOvW+OhZvMm5Zu/ODZB3aFKVogO7ESRBoesTkU=;
        fh=R47WBNijYjVQohjAp2AvznUZnpXtZATwO2qSib63zaw=;
        b=d+kk180hq4pwaZCjcK2PvrKIfO9nfM47soFgA/elzrYxprvl+5vYFU9sh3kmMKqyTA
         2zEySdLy6dOXcz8rwfr2b7Wd9mO5O1Hixs+B8FDatqLtOFCP7pGPidogxHgsGLYUNykS
         M5gDqGusoy6ongpjpx7lIZa3rQTEg0td2wG2KAPJ32Eny87kY+2C6swJRBE3Y+nZ2kqz
         tIeUZOoYPu4w66BgfW+TzbLVgt1QWiaNA9Fz6ZgmWeEghStKLyGezy/E3Nvc/nazXHik
         TjzORB4utSVPVG2WYDEKUnWR83aJApEAY0hArYiixG4YUCjqDjZ9cB3ElIvo80LlmzBW
         Ep6g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kBaBfcy8;
       spf=pass (google.com: domain of nathan@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-741481ef779si44456a34.3.2025.07.25.17.43.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 25 Jul 2025 17:43:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 31FE3A567D6;
	Sat, 26 Jul 2025 00:43:31 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B1170C4CEE7;
	Sat, 26 Jul 2025 00:43:16 +0000 (UTC)
Date: Fri, 25 Jul 2025 17:43:13 -0700
From: "'Nathan Chancellor' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kees Cook <kees@kernel.org>
Cc: Arnd Bergmann <arnd@arndb.de>, Will Deacon <will@kernel.org>,
	Ard Biesheuvel <ardb@kernel.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Jonathan Cameron <Jonathan.Cameron@huawei.com>,
	Gavin Shan <gshan@redhat.com>,
	"Russell King (Oracle)" <rmk+kernel@armlinux.org.uk>,
	James Morse <james.morse@arm.com>,
	Oza Pawandeep <quic_poza@quicinc.com>,
	Anshuman Khandual <anshuman.khandual@arm.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	"H. Peter Anvin" <hpa@zytor.com>,
	Paolo Bonzini <pbonzini@redhat.com>,
	Mike Rapoport <rppt@kernel.org>,
	Vitaly Kuznetsov <vkuznets@redhat.com>,
	Henrique de Moraes Holschuh <hmh@hmh.eng.br>,
	Hans de Goede <hansg@kernel.org>,
	Ilpo =?iso-8859-1?Q?J=E4rvinen?= <ilpo.jarvinen@linux.intel.com>,
	"Rafael J. Wysocki" <rafael@kernel.org>,
	Len Brown <lenb@kernel.org>, Masami Hiramatsu <mhiramat@kernel.org>,
	Michal Wilczynski <michal.wilczynski@intel.com>,
	Juergen Gross <jgross@suse.com>,
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	"Kirill A. Shutemov" <kas@kernel.org>,
	Roger Pau Monne <roger.pau@citrix.com>,
	David Woodhouse <dwmw@amazon.co.uk>,
	Usama Arif <usama.arif@bytedance.com>,
	"Guilherme G. Piccoli" <gpiccoli@igalia.com>,
	Thomas Huth <thuth@redhat.com>, Brian Gerst <brgerst@gmail.com>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Hou Wenlong <houwenlong.hwl@antgroup.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	"Peter Zijlstra (Intel)" <peterz@infradead.org>,
	Luis Chamberlain <mcgrof@kernel.org>,
	Sami Tolvanen <samitolvanen@google.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	Andy Lutomirski <luto@kernel.org>, Baoquan He <bhe@redhat.com>,
	Alexander Graf <graf@amazon.com>,
	Changyuan Lyu <changyuanl@google.com>,
	Paul Moore <paul@paul-moore.com>, James Morris <jmorris@namei.org>,
	"Serge E. Hallyn" <serge@hallyn.com>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	Jan Beulich <jbeulich@suse.com>, Boqun Feng <boqun.feng@gmail.com>,
	Viresh Kumar <viresh.kumar@linaro.org>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Bibo Mao <maobibo@loongson.cn>, linux-kernel@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org, x86@kernel.org,
	kvm@vger.kernel.org, ibm-acpi-devel@lists.sourceforge.net,
	platform-driver-x86@vger.kernel.org, linux-acpi@vger.kernel.org,
	linux-trace-kernel@vger.kernel.org, linux-efi@vger.kernel.org,
	linux-mm@kvack.org, kasan-dev@googlegroups.com,
	linux-kbuild@vger.kernel.org, linux-hardening@vger.kernel.org,
	kexec@lists.infradead.org, linux-security-module@vger.kernel.org,
	llvm@lists.linux.dev
Subject: Re: [PATCH v4 0/4] stackleak: Support Clang stack depth tracking
Message-ID: <20250726004313.GA3650901@ax162>
References: <20250724054419.it.405-kees@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250724054419.it.405-kees@kernel.org>
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=kBaBfcy8;       spf=pass
 (google.com: domain of nathan@kernel.org designates 2604:1380:45d1:ec00::3 as
 permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Nathan Chancellor <nathan@kernel.org>
Reply-To: Nathan Chancellor <nathan@kernel.org>
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

Hi Kees,

On Wed, Jul 23, 2025 at 10:50:24PM -0700, Kees Cook wrote:
>  v4:
>   - rebase on for-next/hardening tree (took subset of v3 patches)
>   - improve commit logs for x86 and arm64 changes (Mike, Will, Ard)
>  v3: https://lore.kernel.org/lkml/20250717231756.make.423-kees@kernel.org/
>  v2: https://lore.kernel.org/lkml/20250523043251.it.550-kees@kernel.org/
>  v1: https://lore.kernel.org/lkml/20250507180852.work.231-kees@kernel.org/
> 
> Hi,
> 
> These are the remaining changes needed to support Clang stack depth
> tracking for kstack_erase (nee stackleak).

A few build issues that I see when building next-20250725, which seem
related to this series.

1. I see

  ld.lld: error: undefined symbol: __sanitizer_cov_stack_depth
  >>> referenced by atags_to_fdt.c
  >>>               arch/arm/boot/compressed/atags_to_fdt.o:(atags_to_fdt)
  make[5]: *** [arch/arm/boot/compressed/Makefile:152: arch/arm/boot/compressed/vmlinux] Error 1

when building ARCH=arm allmodconfig on next-20250725. The following diff appears to cure that one.

diff --git a/arch/arm/boot/compressed/Makefile b/arch/arm/boot/compressed/Makefile
index f9075edfd773..f6142946b162 100644
--- a/arch/arm/boot/compressed/Makefile
+++ b/arch/arm/boot/compressed/Makefile
@@ -9,7 +9,6 @@ OBJS		=
 
 HEAD	= head.o
 OBJS	+= misc.o decompress.o
-CFLAGS_decompress.o += $(DISABLE_KSTACK_ERASE)
 ifeq ($(CONFIG_DEBUG_UNCOMPRESS),y)
 OBJS	+= debug.o
 AFLAGS_head.o += -DDEBUG
@@ -96,7 +95,7 @@ KBUILD_CFLAGS += -DDISABLE_BRANCH_PROFILING
 
 ccflags-y := -fpic $(call cc-option,-mno-single-pic-base,) -fno-builtin \
 	     -I$(srctree)/scripts/dtc/libfdt -fno-stack-protector \
-	     -I$(obj)
+	     -I$(obj) $(DISABLE_KSTACK_ERASE)
 ccflags-remove-$(CONFIG_FUNCTION_TRACER) += -pg
 asflags-y := -DZIMAGE
 
--

2. I see

  kernel/kstack_erase.c:168:2: warning: function with attribute 'no_caller_saved_registers' should only call a function with attribute 'no_caller_saved_registers' or be compiled with '-mgeneral-regs-only' [-Wexcessive-regsave]
    168 |         BUILD_BUG_ON(CONFIG_KSTACK_ERASE_TRACK_MIN_SIZE > KSTACK_ERASE_SEARCH_DEPTH);
        |         ^
  include/linux/build_bug.h:50:2: note: expanded from macro 'BUILD_BUG_ON'
     50 |         BUILD_BUG_ON_MSG(condition, "BUILD_BUG_ON failed: " #condition)
        |         ^
  include/linux/build_bug.h:39:37: note: expanded from macro 'BUILD_BUG_ON_MSG'
     39 | #define BUILD_BUG_ON_MSG(cond, msg) compiletime_assert(!(cond), msg)
        |                                     ^
  include/linux/compiler_types.h:568:2: note: expanded from macro 'compiletime_assert'
    568 |         _compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)
        |         ^
  include/linux/compiler_types.h:556:2: note: expanded from macro '_compiletime_assert'
    556 |         __compiletime_assert(condition, msg, prefix, suffix)
        |         ^
  include/linux/compiler_types.h:549:4: note: expanded from macro '__compiletime_assert'
    549 |                         prefix ## suffix();                             \
        |                         ^
  <scratch space>:97:1: note: expanded from here
     97 | __compiletime_assert_521
        | ^
  kernel/kstack_erase.c:168:2: note: '__compiletime_assert_521' declared here
  include/linux/build_bug.h:50:2: note: expanded from macro 'BUILD_BUG_ON'
     50 |         BUILD_BUG_ON_MSG(condition, "BUILD_BUG_ON failed: " #condition)
        |         ^
  include/linux/build_bug.h:39:37: note: expanded from macro 'BUILD_BUG_ON_MSG'
     39 | #define BUILD_BUG_ON_MSG(cond, msg) compiletime_assert(!(cond), msg)
        |                                     ^
  include/linux/compiler_types.h:568:2: note: expanded from macro 'compiletime_assert'
    568 |         _compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)
        |         ^
  include/linux/compiler_types.h:556:2: note: expanded from macro '_compiletime_assert'
    556 |         __compiletime_assert(condition, msg, prefix, suffix)
        |         ^
  include/linux/compiler_types.h:546:26: note: expanded from macro '__compiletime_assert'
    546 |                 __noreturn extern void prefix ## suffix(void)           \
        |                                        ^
  <scratch space>:96:1: note: expanded from here
     96 | __compiletime_assert_521
        | ^
  kernel/kstack_erase.c:172:11: warning: function with attribute 'no_caller_saved_registers' should only call a function with attribute 'no_caller_saved_registers' or be compiled with '-mgeneral-regs-only' [-Wexcessive-regsave]
    172 |         if (sp < current->lowest_stack &&
        |                  ^
  arch/x86/include/asm/current.h:28:17: note: expanded from macro 'current'
     28 | #define current get_current()
        |                 ^
  arch/x86/include/asm/current.h:20:44: note: 'get_current' declared here
     20 | static __always_inline struct task_struct *get_current(void)
        |                                            ^
  kernel/kstack_erase.c:173:37: warning: function with attribute 'no_caller_saved_registers' should only call a function with attribute 'no_caller_saved_registers' or be compiled with '-mgeneral-regs-only' [-Wexcessive-regsave]
    173 |             sp >= stackleak_task_low_bound(current)) {
        |                                            ^
  arch/x86/include/asm/current.h:28:17: note: expanded from macro 'current'
     28 | #define current get_current()
        |                 ^
  arch/x86/include/asm/current.h:20:44: note: 'get_current' declared here
     20 | static __always_inline struct task_struct *get_current(void)
        |                                            ^

when building ARCH=i386 allmodconfig.

3. I see

  In file included from kernel/fork.c:96:
  include/linux/kstack_erase.h:29:37: error: passing 'const struct task_struct *' to parameter of type 'struct task_struct *' discards qualifiers [-Werror,-Wincompatible-pointer-types-discards-qualifiers]
     29 |         return (unsigned long)end_of_stack(tsk) + sizeof(unsigned long);
        |                                            ^~~
  include/linux/sched/task_stack.h:56:63: note: passing argument to parameter 'p' here
     56 | static inline unsigned long *end_of_stack(struct task_struct *p)
        |                                                               ^

when building ARCH=loongarch allmodconfig, which does not support
CONFIG_THREAD_INFO_IN_TASK it seems.

Cheers,
Nathan

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250726004313.GA3650901%40ax162.
