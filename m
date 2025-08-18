Return-Path: <kasan-dev+bncBD4NDKWHQYDRBN7PRXCQMGQEYHL7Y5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id F3357B2B0F2
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 20:58:00 +0200 (CEST)
Received: by mail-io1-xd3d.google.com with SMTP id ca18e2360f4ac-88432e62d01sf604833439f.3
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 11:58:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755543479; cv=pass;
        d=google.com; s=arc-20240605;
        b=g8QEIklAHc464t+wx6F7rKra4hlxzDis7hDLgOnQQWQuqAGSxbZOY5mmwSW0Rkci9+
         DKzgmdU+fFAbc00rKjJPdCKdVP5tm6WJ+oaai+7voNZHtkyjGAgZh+7Bab18J6udHjE9
         hS5W76HJzGlabp85YDYIfBPC4d0ia+aMbYdNGNfKGf3zTiGrhNfeA7krxKqeoxOjw2VG
         Mi3Stu/Pid8sUS6AgUtDA1Pqgx8HvfdIsQDBzP/pQgW/cL2KW89AYSXZLiuxJEotZi6c
         d2RqfpfnGrJL7mmqwjGX9EqIwoD+V9qcKfWvAozOTnB4MbMynijd2mKU0FrTrIJAjT5U
         SwiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:mime-version
         :message-id:date:subject:from:dkim-signature;
        bh=0FPCo/Ez1tTdctWanxUcVPXYwcXF/qdckMLmJaCckAw=;
        fh=zWA/uzWh75/HX2KTJ9AJTvDsbnr2ItCtlP6WeZQkP00=;
        b=JDbWMqJ09Gjg05HHGdItWLTrcEAlouOYrTmYJa8S4GdKBiJ33zK0H5aqqPCHEnt39R
         7JxFEyYu4qnob9jTYdpiNN65ykRd65LKlmL9EHQTrP5qS4lBhiMHbB54LlgXsRgM/C3h
         J3X33A8QMu/8WrkUiUosEj01CYYkvLVo0JX0lMzfh+inJTvh69+ViFaEcVBenRgY2OWj
         NX8yg/ZBSfuT2HG9l7vc7YWnx+o6AtmJKXFbt5jSBWv26qdQz4OC+6kISM/IlHsll9ZX
         2fMj8OClm4O/IKJKc7AsRObMLijVIkJzNNZFSItTZ0AODB+BoBx6YNcPYJKeluUdXTVA
         2G2Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=TO8hGFu9;
       spf=pass (google.com: domain of nathan@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755543479; x=1756148279; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :mime-version:message-id:date:subject:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=0FPCo/Ez1tTdctWanxUcVPXYwcXF/qdckMLmJaCckAw=;
        b=juiM8pKx4kjtmUZCZreXNQxEBGkuUkUbirhjdNJhbGWIsp7KQwVK+aJpVoXdqhhIzI
         ib3Nwp949Duu/E5ptEXijDIAil/sFobV0G8vxoZssNPDDr+3B+vkQIHbVGtCJtNagcZY
         Ng7nO+so+Yjp6zc6X0oDD6+vE/7hgr7MQSzi9ULOWwBYrdgU/CZ8ZMPFcERDf5DJkyoo
         vGbDGPuQkaDUKqTZKxRb7cG8OoulYNJLBvPYjtThXI8PNT+3Z9NBcnmHSynKF2uBVw7J
         IERw05lT53qlRcfTEfkY3G15jvSgxGPCKV6d0xoXDlbgPoZRNZP2FP9+VP4UrUn2Dzil
         fdoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755543479; x=1756148279;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :mime-version:message-id:date:subject:from:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=0FPCo/Ez1tTdctWanxUcVPXYwcXF/qdckMLmJaCckAw=;
        b=T3Mu5JEzSE18WwuYB4lglPMO5MdCjHBnEm4b1AV60NQfTcLj6oSls1lyOvPRcFGGct
         p5Wsh4g8aXAa1/UJBkKlrajLx1uWE4XVYgOW5Go9vh8ou3M8PYrudmXEIbglS9pxzkVW
         s4mzdFo02f78oLKtVaE3eXv69QUXQ3A5tvDNQDQs7CRn9xVFiFmLXi36Lz2QOwLqU6Nl
         Gmp2l+0xQh2uSo5j+CgWTwXn/T5rbpunDpnRKl7k1dgU7chK5K25lUnPepQn9dZs8xbT
         V25QbuSOnmqK4/d9LV3ukpi57eH02oOgV0qOb0Kgm5MQB+6yDGjfP7BkBbclNu2SBD3Q
         wcwQ==
X-Forwarded-Encrypted: i=2; AJvYcCWk9IIuOhTzljK/KVUv+Mvo/RKI9VDcnxk2j4Zgbb7Z4swd875lLYPQOIW4uq5YMUY5CoiFiA==@lfdr.de
X-Gm-Message-State: AOJu0Yy9DlqQ+Ebjb7plFGdqIXTjRxJZUFSQPb7S9pEK/9PqX8SM7nKs
	jdrdvJI2jmHeFoE6EP+TBHr0oCeWhKG5fAl39Hm2QcE1KVUzGYJ/Vmlk
X-Google-Smtp-Source: AGHT+IFWNPcZ59/LV/Ka3Nn4x1kefiYjMYXjEgwCSYgzdeXDrzQ64pPajaArUty4p5U3X9v4wiAvWQ==
X-Received: by 2002:a05:6e02:190f:b0:3e5:4942:88dc with SMTP id e9e14a558f8ab-3e67532cdcemr6672745ab.9.1755543479344;
        Mon, 18 Aug 2025 11:57:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeQg0p9+9YESdOWw30eN1Nb+cauMa39klfpiDkqzOtajA==
Received: by 2002:a05:6e02:481b:b0:3e5:5703:c19a with SMTP id
 e9e14a558f8ab-3e56f8e9dcbls35861125ab.1.-pod-prod-09-us; Mon, 18 Aug 2025
 11:57:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCViMDVEHRnjmUt3Y6edsnhLNUO9Pg2Dqu3ST8TSYaEu5HHewRSRDCwhEfQ7QOm1/EJIKx06j0tlk2c=@googlegroups.com
X-Received: by 2002:a05:6e02:1a63:b0:3e5:504b:420c with SMTP id e9e14a558f8ab-3e6753b225amr7250105ab.18.1755543478353;
        Mon, 18 Aug 2025 11:57:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755543478; cv=none;
        d=google.com; s=arc-20240605;
        b=M/yyKCpEgFfWYnt543JHLnhTC+nacsFjVrAG5imh57RnkLVaCo2fMZCEfutq/ftUaO
         nwzzfBtxpTIIgWUmVJ8NTJ7zwpaslM6y7eeOyax532HJb6z2MPyyQFWfosWh1kMyuCku
         +c7uir4kHIEE0lxKYTD6yEPx07DJNSKVxktFLsDh0YAEl9X5i7tVVULzGKYRKNMkV2eQ
         RXnqoi2BsRENyeKIJk8PRtK1sLSV3Y5a1pvoDW3D8Xs88U4+LncPJmXj0OrQ9n0hpQiV
         x0XFiueEEvtlZpJBb15OulUWTzUtkg6VH6N5lGM/42u15Hn93rsTr83f2MnhKuLEw3Ru
         UtZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:content-transfer-encoding:mime-version:message-id:date
         :subject:from:dkim-signature;
        bh=TBN15g8rAP23J96r4n28IjSBg+WDu3nayiyCti2V2i8=;
        fh=95F30c+JRlV+mlMaeHFAqbV0iOFTop4NzcI0aw2wCxY=;
        b=KEDsKRVu2l7TkPUUgOQIPPL6pxWda5Q3rG+xqW8eACvZYVVSpGSjpgBsOMoFJ4AbjF
         bCtx4bSW7wcc49rYsbkDrnWgfStt/d8gJ/tBQAbJIgiEUmTUOngj0gQDSd2I6+2gMpik
         tfnL0tB4KVbtE4G83hlM3HypdQA9z3V3oaISc6p3+/6DfH6PSnuV5SSvwFPpOPnTK7hJ
         eB9sYvrbLu7BV6swUkVOrT7rkV4+Ta/ot6kfFeupkzWL9Jc0hDsXTJM+NgsiAheCUCxh
         i8/M6n0miG7sYJ3/BN10WZLRgQkluZq7ae4txGI44aT9TzRlU9hNamvUB7u1EUUrh4Nn
         sk2w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=TO8hGFu9;
       spf=pass (google.com: domain of nathan@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-50c94afae79si288257173.7.2025.08.18.11.57.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 18 Aug 2025 11:57:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id A05445C62C9;
	Mon, 18 Aug 2025 18:57:57 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7007FC4CEEB;
	Mon, 18 Aug 2025 18:57:39 +0000 (UTC)
From: "'Nathan Chancellor' via kasan-dev" <kasan-dev@googlegroups.com>
Subject: [PATCH 00/10] Bump minimum supported version of LLVM for building
 the kernel to 15.0.0
Date: Mon, 18 Aug 2025 11:57:16 -0700
Message-Id: <20250818-bump-min-llvm-ver-15-v1-0-c8b1d0f955e0@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-B4-Tracking: v=1; b=H4sIAIx3o2gC/x3MwQoCIRCA4VeROe+AY0zRvkrsoa2xBtRESQLx3
 Vc6fof/71ClqFRYTYciTat+0gQtBh7ve3oJ6nManHVsL2Rx/8aMUROG0CI2KUiMV3Yn8iT7mRl
 mmot4/f23t22MA23HpyFmAAAA
X-Change-ID: 20250710-bump-min-llvm-ver-15-95231f1eb655
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Arnd Bergmann <arnd@arndb.de>, Kees Cook <kees@kernel.org>, 
 Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, 
 Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, 
 linux-kernel@vger.kernel.org, llvm@lists.linux.dev, patches@lists.linux.dev, 
 Nathan Chancellor <nathan@kernel.org>, linux-kbuild@vger.kernel.org, 
 linux-hardening@vger.kernel.org, Russell King <linux@armlinux.org.uk>, 
 Ard Biesheuvel <ardb@kernel.org>, linux-arm-kernel@lists.infradead.org, 
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
 Thomas Bogendoerfer <tsbogend@alpha.franken.de>, linux-mips@vger.kernel.org, 
 Madhavan Srinivasan <maddy@linux.ibm.com>, 
 Michael Ellerman <mpe@ellerman.id.au>, Nicholas Piggin <npiggin@gmail.com>, 
 Christophe Leroy <christophe.leroy@csgroup.eu>, 
 linuxppc-dev@lists.ozlabs.org, Palmer Dabbelt <palmer@dabbelt.com>, 
 Alexandre Ghiti <alex@ghiti.fr>, linux-riscv@lists.infradead.org, 
 Josh Poimboeuf <jpoimboe@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
 Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
 kasan-dev@googlegroups.com, Alexander Potapenko <glider@google.com>
X-Mailer: b4 0.15-dev
X-Developer-Signature: v=1; a=openpgp-sha256; l=3422; i=nathan@kernel.org;
 h=from:subject:message-id; bh=qBGPy4AI12NWfHAvs72tXhhLkggZ76cCh4aJ0zfhg4o=;
 b=owGbwMvMwCUmm602sfCA1DTG02pJDBmLyxfkKs9J3XvmTW/HPLXzb2LV/ble9105em3NlZSrK
 rcn6luu7yhlYRDjYpAVU2Spfqx63NBwzlnGG6cmwcxhZQIZwsDFKQAT2WLNyLDcY1peR8tewSkT
 F3NPCHvlGPr7vt3zpq/7/opaMwrfUPdmZDjG+/9Q5BeZLcKLVm0XPXCDawGDjEHkhrzAGu39rXt
 Z47gA
X-Developer-Key: i=nathan@kernel.org; a=openpgp;
 fpr=2437CB76E544CB6AB3D9DFD399739260CB6CB716
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=TO8hGFu9;       spf=pass
 (google.com: domain of nathan@kernel.org designates 139.178.84.217 as
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

s390 and x86 have required LLVM 15 since

  30d17fac6aae ("scripts/min-tool-version.sh: raise minimum clang version to 15.0.0 for s390")
  7861640aac52 ("x86/build: Raise the minimum LLVM version to 15.0.0")

respectively. This series bumps the rest of the kernel to 15.0.0 to
match, which allows for a decent number of clean ups.

On the distros front, we will only leave behind Debian Bookworm and
Ubuntu Jammy. In both of those cases, builders / developers can either
use the kernel.org toolchains or https://apt.llvm.org to get newer
versions that will run on those distributions, if they cannot upgrade.

  archlinux:latest              clang version 20.1.8
  debian:oldoldstable-slim      Debian clang version 11.0.1-2
  debian:oldstable-slim         Debian clang version 14.0.6
  debian:stable-slim            Debian clang version 19.1.7 (3+b1)
  debian:testing-slim           Debian clang version 19.1.7 (3+b1)
  debian:unstable-slim          Debian clang version 19.1.7 (3+b2)
  fedora:41                     clang version 19.1.7 (Fedora 19.1.7-4.fc41)
  fedora:latest                 clang version 20.1.8 (Fedora 20.1.8-3.fc42)
  fedora:rawhide                clang version 20.1.8 (Fedora 20.1.8-3.fc43)
  opensuse/leap:latest          clang version 17.0.6
  opensuse/tumbleweed:latest    clang version 20.1.8
  ubuntu:focal                  clang version 10.0.0-4ubuntu1
  ubuntu:jammy                  Ubuntu clang version 14.0.0-1ubuntu1.1
  ubuntu:noble                  Ubuntu clang version 18.1.3 (1ubuntu1)
  ubuntu:latest                 Ubuntu clang version 18.1.3 (1ubuntu1)
  ubuntu:rolling                Ubuntu clang version 20.1.2 (0ubuntu1)
  ubuntu:devel                  Ubuntu clang version 20.1.8 (0ubuntu1)

I think it makes sense for either Andrew to carry this via -mm on a
nonmm branch or me to carry this via the Kbuild tree, with the
appropriate acks.

---
Nathan Chancellor (10):
      kbuild: Bump minimum version of LLVM for building the kernel to 15.0.0
      arch/Kconfig: Drop always true condition from RANDOMIZE_KSTACK_OFFSET
      ARM: Clean up definition of ARM_HAS_GROUP_RELOCS
      arm64: Remove tautological LLVM Kconfig conditions
      mips: Unconditionally select ARCH_HAS_CURRENT_STACK_POINTER
      powerpc: Drop unnecessary initializations in __copy_inst_from_kernel_nofault()
      riscv: Remove version check for LTO_CLANG selects
      lib/Kconfig.debug: Drop CLANG_VERSION check from DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT
      objtool: Drop noinstr hack for KCSAN_WEAK_MEMORY
      KMSAN: Remove tautological checks

 Documentation/process/changes.rst |  2 +-
 arch/Kconfig                      |  1 -
 arch/arm/Kconfig                  | 11 ++++-------
 arch/arm64/Kconfig                |  5 +----
 arch/mips/Kconfig                 |  2 +-
 arch/powerpc/include/asm/inst.h   |  4 ----
 arch/riscv/Kconfig                |  5 ++---
 lib/Kconfig.debug                 |  2 +-
 lib/Kconfig.kcsan                 |  6 ------
 lib/Kconfig.kmsan                 | 11 +----------
 scripts/min-tool-version.sh       |  6 ++----
 tools/objtool/check.c             | 10 ----------
 12 files changed, 13 insertions(+), 52 deletions(-)
---
base-commit: 8f5ae30d69d7543eee0d70083daf4de8fe15d585
change-id: 20250710-bump-min-llvm-ver-15-95231f1eb655

Best regards,
--  
Nathan Chancellor <nathan@kernel.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250818-bump-min-llvm-ver-15-v1-0-c8b1d0f955e0%40kernel.org.
