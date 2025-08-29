Return-Path: <kasan-dev+bncBD4NDKWHQYDRBUOVZDCQMGQEGQ57WRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id C1592B3C4E7
	for <lists+kasan-dev@lfdr.de>; Sat, 30 Aug 2025 00:33:54 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-4b302991816sf42599821cf.0
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 15:33:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756506833; cv=pass;
        d=google.com; s=arc-20240605;
        b=eFCODaAf3NB3G/1NdBiiknaYKtfY2YVi39z4diZR/u51XXMnyGx6/RkMry6PkSuEIW
         kTt9NuWEUcRBKxStLeOFYMCSpGuixksLAljRi0KLYHmbk9NRsLiRe/pwM2dYEJFQgOLd
         iZNLxkIgwRE2M5h5f4hmp9jLPu6c8BzVA2MUcSqcuvREcujsVgVAcbXjtqndZ8eP30JF
         97bGkOFBmU003K1NjdaFHwJ4mzMGo2OYfXiqqMksNS9b+amrYHgJi7AU/m1Elq3hvC/w
         qKRqMuL6jcaNwlQKTbTKGHPUO+BNx9iLDvvh9JaxnfJ92RvXSRKRPPYjh28gq73dykv6
         PwkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:date
         :message-id:subject:references:in-reply-to:cc:to:from:dkim-signature;
        bh=A1dAExsd4V6jmz74pcT7BUecR9w+nrb3MU/qF9Qk4tY=;
        fh=zw8Au/n0DEVxB4HSJUlsuyx9Zw6Y2znjmURy1nL71Gk=;
        b=FuTJU5oa6/hOLqGlrKCg+RkUkexh7Jqp/q5zW1Ut3tkFleVE8EB+fS44py4LbDcASJ
         rcr967Cs1ESuzhNl6ZThIWc0h6r/xwphkMP4w8h67seHGWBxovQSZnJglrUSUCmPqrKV
         3bNXA7uiXfAvYaG4zx/mtwlTV1QoCJsGJT3+PvNilYSritM4CqLZrkacIpKrba7lBxfJ
         O94GzL9oWbz0ry3YauBkr7rSSirlGX1YIUaXeyyQ1LnxNlLA1KAu94JdAU/+Xs7uVeiK
         7ROYQ2ZjwB7sRZG6P4hjiPTlI983WQXjKE1MuSznM4SEOqUXN2I44n0zkcwJz/tDBDCS
         8zHQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=CeI1Uyyw;
       spf=pass (google.com: domain of nathan@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756506833; x=1757111633; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :date:message-id:subject:references:in-reply-to:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=A1dAExsd4V6jmz74pcT7BUecR9w+nrb3MU/qF9Qk4tY=;
        b=Uh4/JrhpVXwOdOVxodg1wsbidrp4ohU2CE5M56j+UQWSVvSu+n3+t5fq/e5C7QZhe1
         id1SeqltXh43uaQwcNSCanWIiYGseGcoKcIJH+LRB/3H807NpYYCQ6O43O+lv8AgizNw
         DzV56B08Govk6t8y5PaGUgaw4Mn9SKXjQN8thxqAIswjlBgLoBthnHNcp4rRYR3AMvKI
         +JiPHLzxXy2TqLIT/d88Pf4C+/sdrVAaxWUww3S5gBaN3BTTRVi4FTxZzic+aNUz/S2L
         ATKiZWxtt6JlD7Yum4tpPnzweSwDQqiW9JMPCW1TzFAi9XC/doWBIY5HxHrlG9Yga/TH
         3Gow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756506833; x=1757111633;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :date:message-id:subject:references:in-reply-to:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=A1dAExsd4V6jmz74pcT7BUecR9w+nrb3MU/qF9Qk4tY=;
        b=RKc6WRpjUedstNXDJdFlv7egeDhFl3mEuvY0/saUXecTHId5z4bUz0R1EOKBjn6Nk2
         ik8J7WoSa2gYxi6ocBxzYPp7nBfN5plePEOQErsUAVxuSlU/ByjaMRK3j5VqdUqdEak9
         saZwDnvFBHJDq3bc/APSzGw8Qxhtm0SXWyLMQkEHaDWlv9NNkJez+ZCkI2+Kn75YKRET
         HWWWfSfK9TWowKiGP92d0/sWjug1pAgmklcyMItTduuu7WSPEuAA3+0CmwCNjEAccnta
         S2WA9Y+bMAPDFFWM8qRSKStg3llnpluKAdEJw+vyvlvqynu3+PNDoZlYngbF7VNayteU
         bDAQ==
X-Forwarded-Encrypted: i=2; AJvYcCWko0sG9qqksdQwxw81oii8zxBWGXcpeLoE8moe//5sJZujE5GCEBAu+XreuRbMCZP1+1kM0w==@lfdr.de
X-Gm-Message-State: AOJu0Yxpbui4NTNv1QOLQXcK5NlyVumfVacap5lexaW/9YB3hNwXAxbs
	PBrE/+CLk3TmzYw7+cNFtktwogGl+EnB22wiE3pq0+27bz7A/XkCEjyA
X-Google-Smtp-Source: AGHT+IHh2hXWvvyj1AVRLcjEypGkkDDgCiDQie7TR8UdBEMwWZdki3GajtUCQP4xwfeP7Y/2GAiDEA==
X-Received: by 2002:a05:622a:4e86:b0:4b0:7d7c:7ae2 with SMTP id d75a77b69052e-4b31d844979mr2822971cf.20.1756506833362;
        Fri, 29 Aug 2025 15:33:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcqDP0CVQC8ngZGeDAtsg3KeNc4YMS2vcNJk+ulPo5txg==
Received: by 2002:ac8:7dd1:0:b0:4b0:9935:4645 with SMTP id d75a77b69052e-4b2fe62370fls37268661cf.0.-pod-prod-05-us;
 Fri, 29 Aug 2025 15:33:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUY/x/icXvYCovDjogTTGd6axER+gcMzotgbLeg3NVoZMtKCN1qO9iEB94u+1Qd8HdmvOY/l5bhQ8M=@googlegroups.com
X-Received: by 2002:a05:620a:29d4:b0:7e8:5fce:91c1 with SMTP id af79cd13be357-7ff21cfd12amr41426285a.0.1756506832540;
        Fri, 29 Aug 2025 15:33:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756506832; cv=none;
        d=google.com; s=arc-20240605;
        b=aNgChxtG4k9jFHK772iFGJ7lmZ0ARnMsldsKVBGl8Ojpoo9B34XJ0KWY9iHJ4CCsLG
         Jue4bqK0CnRW4WfFs48cF8hcy/pp0/h8RFXiMqbMdsCD+T4L6CT5+3UUP9Mqk3XtiwpP
         yUrduV6PkYqFd9BtNIRefRx3rHABSHJW86GpAlctHDyJ5Rjwq7UXUMY0NBRLcw1jwdLa
         QaGsnTXPfJ4p/L1GFVfbrXshmQQ8+nRticv3Em5F75un/xRYLrtLOiKkGCZhbm/zK6uF
         LzOdyRpxzM8VK7uPbJiV14f+1uFoGhf7nwmLB9MkIqdOYN71SfXTuaosxMsD1aUqCTr3
         LlHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:date:message-id:subject
         :references:in-reply-to:cc:to:from:dkim-signature;
        bh=kZBy6mGm/GWgsSmHcenYbJqYC61GyZljRKOGMCQEJWk=;
        fh=pUDPfDHwJMRvCLjm/srwucEBg32BqOTSDLW3gsAgSIk=;
        b=PVTuUjdMm0AYTqKJ2dEw9vY/LDxKmrPse9IZ1s8gCN95dWUeVBjhgaCj6W0p1dOxOf
         iRop+3oKdzHbtA5As9ET1MwAz8+86mA4EIZeOKMtHDL+gG7eDPFmYzBwWADlv00CWSue
         8Wf92/pUHRHkAEc0MQ8axPzyFDH7rxKfHr0a8iPTzDqELIfQS9M0iNCk91ACnpU0irqP
         lq1/pkZdh0/KFECrLgLDonDFQxWvg2wySJ8pv/9hJqTF2PPdlSjbPrYKTH+lx5PapvcK
         gmx0aA/oBL30GnCBjW5iy+ufnUNSPhBA2pNXMb8WUB95wVWrzyhprY7vE2Bd5/1SFF5m
         RrEg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=CeI1Uyyw;
       spf=pass (google.com: domain of nathan@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7fc0cbe82a9si17171485a.1.2025.08.29.15.33.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Aug 2025 15:33:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id B33664534D;
	Fri, 29 Aug 2025 22:33:51 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 5459DC4CEF0;
	Fri, 29 Aug 2025 22:33:46 +0000 (UTC)
From: "'Nathan Chancellor' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org, Nathan Chancellor <nathan@kernel.org>
Cc: Arnd Bergmann <arnd@arndb.de>, Kees Cook <kees@kernel.org>, 
 Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, 
 Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, 
 llvm@lists.linux.dev, patches@lists.linux.dev, 
 Nicolas Schier <nsc@kernel.org>, linux-kbuild@vger.kernel.org, 
 linux-hardening@vger.kernel.org, Russell King <linux@armlinux.org.uk>, 
 Ard Biesheuvel <ardb@kernel.org>, linux-arm-kernel@lists.infradead.org, 
 Will Deacon <will@kernel.org>, 
 Thomas Bogendoerfer <tsbogend@alpha.franken.de>, linux-mips@vger.kernel.org, 
 Madhavan Srinivasan <maddy@linux.ibm.com>, 
 Michael Ellerman <mpe@ellerman.id.au>, Nicholas Piggin <npiggin@gmail.com>, 
 Christophe Leroy <christophe.leroy@csgroup.eu>, 
 linuxppc-dev@lists.ozlabs.org, Palmer Dabbelt <palmer@dabbelt.com>, 
 Alexandre Ghiti <alex@ghiti.fr>, linux-riscv@lists.infradead.org, 
 Marco Elver <elver@google.com>, 
 "Peter Zijlstra (Intel)" <peterz@infraded.org>, kasan-dev@googlegroups.com
In-Reply-To: <20250821-bump-min-llvm-ver-15-v2-0-635f3294e5f0@kernel.org>
References: <20250821-bump-min-llvm-ver-15-v2-0-635f3294e5f0@kernel.org>
Subject: Re: [PATCH v2 00/12] Bump minimum supported version of LLVM for
 building the kernel to 15.0.0
Message-Id: <175650682606.3003527.17329504429724755241.b4-ty@kernel.org>
Date: Fri, 29 Aug 2025 15:33:46 -0700
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Mailer: b4 0.15-dev
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=CeI1Uyyw;       spf=pass
 (google.com: domain of nathan@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass
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


On Thu, 21 Aug 2025 14:15:37 -0700, Nathan Chancellor wrote:
> s390 and x86 have required LLVM 15 since
> 
>   30d17fac6aae ("scripts/min-tool-version.sh: raise minimum clang version to 15.0.0 for s390")
>   7861640aac52 ("x86/build: Raise the minimum LLVM version to 15.0.0")
> 
> respectively. This series bumps the rest of the kernel to 15.0.0 to
> match, which allows for a decent number of clean ups.
> 
> [...]

Applied, thanks!

[01/12] kbuild: Bump minimum version of LLVM for building the kernel to 15.0.0
        https://git.kernel.org/kbuild/c/20c0989283564
[02/12] arch/Kconfig: Drop always true condition from RANDOMIZE_KSTACK_OFFSET
        https://git.kernel.org/kbuild/c/65aebf6f5880e
[03/12] ARM: Clean up definition of ARM_HAS_GROUP_RELOCS
        https://git.kernel.org/kbuild/c/02aba266e391f
[04/12] arm64: Remove tautological LLVM Kconfig conditions
        https://git.kernel.org/kbuild/c/23cb0514208da
[05/12] mips: Unconditionally select ARCH_HAS_CURRENT_STACK_POINTER
        https://git.kernel.org/kbuild/c/e633c2e78fd1c
[06/12] powerpc: Drop unnecessary initializations in __copy_inst_from_kernel_nofault()
        https://git.kernel.org/kbuild/c/488954ca195d0
[07/12] riscv: Remove version check for LTO_CLANG selects
        https://git.kernel.org/kbuild/c/6578a1ff6aa49
[08/12] riscv: Unconditionally use linker relaxation
        https://git.kernel.org/kbuild/c/7ccbe91796d7b
[09/12] riscv: Remove ld.lld version checks from many TOOLCHAIN_HAS configs
        https://git.kernel.org/kbuild/c/87b28d71396bf
[10/12] lib/Kconfig.debug: Drop CLANG_VERSION check from DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT
        https://git.kernel.org/kbuild/c/a817de20091c3
[11/12] objtool: Drop noinstr hack for KCSAN_WEAK_MEMORY
        https://git.kernel.org/kbuild/c/573ad421cc551
[12/12] KMSAN: Remove tautological checks
        https://git.kernel.org/kbuild/c/5ff8c11775c74

Best regards,
-- 
Nathan Chancellor <nathan@kernel.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/175650682606.3003527.17329504429724755241.b4-ty%40kernel.org.
