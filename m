Return-Path: <kasan-dev+bncBD4NDKWHQYDRBDEZT3CQMGQEWMVXG4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id A0B1DB3081B
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 23:15:57 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-70a88ddec70sf15111316d6.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 14:15:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755810956; cv=pass;
        d=google.com; s=arc-20240605;
        b=OW6NfncB39ZLVm+kWYo8yg2G+dXyoKxbA5vHir6q6b8e8C/7RfaRH+jfLZVj5pJBjj
         ACxBw9XzAzskvQj0vZ5feuwULfCKS6q5Zo9NeYbrmY0JjSXMSlIErkhZ8gwkytUSMKdv
         SALzb2vG0WegiLrY93Miukg8k0CgK+xqZBBXNTB2IH6I8nuZG+cMGAANU8aHVVgp6OU1
         hm12T7SBVnpKCh4vd2fTw87lm5dWNh4+iSKJOn+uVho7/CZ0voTWi+YNnU+O8kOQ8WeV
         /gB3U7CTnswGZfgWPuH2gg/LKh6Kxsbe6mBVC2+LKnFrUi1vygAafwWqHDlRXwxLpcij
         YuOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:mime-version
         :message-id:date:subject:from:dkim-signature;
        bh=a9zXdJB3A/5TgNf7yRk4ojrZ1Rci0LhZodPQ2s4FP9I=;
        fh=oPruR3bZTTrEX2+pQ77s2qxb1bQ41ngBNGJ5cF5F39E=;
        b=iFbXwT+yk5XT5DZMoJ9/iI2ajQYCk7KQAC/G+30K3uOrdCR1KT41HDdkHRUwnE0RUu
         n8M+G+3VHbIJLa8SCCMXYQ2FzrN8c4zFd/wyGP7hFY7GZhgIhUjeuvgzSFiWO21Ga8Bj
         bmYyN/3TmnPMKwJiqaTL3W+STV2VZWiLZIOP3/YcaR67gJMd4pyJwMNwQsLYoDaGkYd7
         gCwqIRF0j64yHIvpBVqNMqUrp+V+QmsWgtq4AYkMxfMtjGRHmw6QdlwxpkJUHzdwwfqI
         AkgSp2ygdBiztTm1iRIrCRKoXEM0zu3qPA/fWW3lzNaJjnp3aLliEa1OcOb43uQZOnCY
         d9ug==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=uQZ01Sr4;
       spf=pass (google.com: domain of nathan@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755810956; x=1756415756; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :mime-version:message-id:date:subject:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=a9zXdJB3A/5TgNf7yRk4ojrZ1Rci0LhZodPQ2s4FP9I=;
        b=qFSUyjiu939BY4JkmqtouQaLu6LqLr1aNFbNwPM88jcg3O1djNWATyt4V0xfCdW5zv
         C6/K0AXFuwcTGgekKl60XlRP09TFb4hPdXjsbZcn8cwlGgowkrjGOruc+EtCupQu56g1
         gFDwh5R3+SRTkmEUKWsSJefd7y+yzyneiXXNQuHGeHh5OVNV5cBcVFTnq5ZvW5vX+vzX
         cF53Z4LmVaDKwD9YwHiyFgbTJ0xz5bN9Wo3qmxNuzCFOAx+jhfAxQJ+rb4NZ/2/ocLHK
         mVQ7nzO5vVcSUjjgCCDOUK3seh+5NheeruloVE8jlUIR1W+HLoQ2NbQABZO9IUrc0ufE
         2l7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755810956; x=1756415756;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :mime-version:message-id:date:subject:from:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=a9zXdJB3A/5TgNf7yRk4ojrZ1Rci0LhZodPQ2s4FP9I=;
        b=i/hDKE88N0gODgmOgGUdrKkaz+5l+JWfxP1/sb2n/zA6IB5zO96Cj7QT8dWFaF4Pmr
         2MFZdloMzpwxz+bwUPqLF8W070DLQ4RgjMIU6PaXqBk0jTPdbNsM3sLNQd9WgxtfHTQd
         TeNQfxphRoTc68CvTMariUQQoWVpFp+OZrNFDcOiu3+7aB5opIc2nx8ZixH/aiBUuM2V
         0nFc6234HRQWJoA337PweC+ri4WQnAj//ziy9Pvvl/9X+CW1mNRXnYMfAOslkfNpk8Mq
         0KQVLvuYDMbsg+iSmcOY1Jfzj2dwKVipHD+SjYt+LUz1kI7GkpMAZCrQT5K53XLGQ9cV
         2c9A==
X-Forwarded-Encrypted: i=2; AJvYcCVXFfwqL5G6ANQFrfuK9cGZzcK+uw5uBtl9SMxb9jMHfia2V7nbej+wwJV4XRkL1XgUktYpbA==@lfdr.de
X-Gm-Message-State: AOJu0YwYccTmTKFS6ZrWXSI92ci07ansz/ABhj/bTogKq0tGwhz4dZgE
	sKzYRFJZpFVMN9YGeNeiZjSyF1n+M6a2v+dArlk9pbskXC3AcxpXzlFy
X-Google-Smtp-Source: AGHT+IH7tTGnlT2RfPyJ6Z0nwJJRm7EGu4r2JVTduLbUFxa8g/uvmwF8MCnciFQEnOAZMywQhR4PHw==
X-Received: by 2002:a05:6214:411c:b0:70d:6df3:9a86 with SMTP id 6a1803df08f44-70d973f3120mr12083066d6.54.1755810956379;
        Thu, 21 Aug 2025 14:15:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfE5cXpeXohxGiEzaSPIpDJ5Cr0MA5eExZY6Yucemy8CQ==
Received: by 2002:a05:6214:19e7:b0:70b:acc1:ba4f with SMTP id
 6a1803df08f44-70d85c82980ls21219296d6.1.-pod-prod-08-us; Thu, 21 Aug 2025
 14:15:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU6PmtwZ9Jo5lJiQzKtC8+PXOy41c13dAHkHAv2RB9RqkoXhn4Sfh/559OmQK+56npFvcsfmWW98Pg=@googlegroups.com
X-Received: by 2002:a05:620a:7119:b0:7e6:2610:f2e4 with SMTP id af79cd13be357-7ea10f74320mr119581385a.3.1755810955451;
        Thu, 21 Aug 2025 14:15:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755810955; cv=none;
        d=google.com; s=arc-20240605;
        b=G+9KfR18vJ/A2EBJStwbDKQ3f1O9Jq9o/g8idkTvo4DoJnIyhSf06TRm3g1thsxUgI
         A74b+R5kRr9txacCf9MeayoMy0YOVtYNi0Hh2PdcNpR/RXu6EBhiFS/IUrszu3UjCjDI
         /y9uEc+eM7FlCSPr0mF7HF6+aHU07POhjVFd6QUzFeC/J3UTAuWRYtPCHTcYuB1MBTyy
         PIv20GUIO57fVCJtCynoOfn2ffBuRFEyLHj7eykzkB/EWKncqO2NN+nJeVl+bhYfXeL6
         9dkY1U5/aPCi4FobeLxouhvGOCkRAy/2HZrpC1yYKUEyxb8ysuWZKB5dUEIGLyCBpvpJ
         y92w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:content-transfer-encoding:mime-version:message-id:date
         :subject:from:dkim-signature;
        bh=9AFaKTNpzu3Wl7g0cbSUK5dGjCeHRl49IBORR+ozh/Y=;
        fh=f9eUvFa/iS+Gk46l3VyeWMGM6wdaUlh66hhH0v/Tkhk=;
        b=X9dGNtygpC6OQZmiPyFwWqx3d2Em+LLh6JSjzHDSkMdMEGgX/oLM3xokbTTBVrSacF
         gz2tza/tClwOP3aiq4UQVQaeWqvfAsH4DbRAyjgIevVNLer1rfjo6gnuSBByshu3DFb4
         DUgIg/WjFpuHLSzkiEkV+HI462V8lK/osl45YD8WYO/KP+9ySDvz7hFwpMQpmka4acuh
         FAEVbmBTXSfaMr1XJpYnPeYxmsO4ZRi0R1/y05wS6EisCu3rSx8LvpDmGFnulD+Cwatw
         xdCDC3pWbt9+7cxn9xwccZfG354sGJY0PNDSM4gKW/l2tUzQOzSQatSPamIHpCJd70Gi
         2mAw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=uQZ01Sr4;
       spf=pass (google.com: domain of nathan@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7e87e1b2e4csi63058185a.4.2025.08.21.14.15.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 14:15:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id C7E18601F8;
	Thu, 21 Aug 2025 21:15:54 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id AE9A8C4CEEB;
	Thu, 21 Aug 2025 21:15:48 +0000 (UTC)
From: "'Nathan Chancellor' via kasan-dev" <kasan-dev@googlegroups.com>
Subject: [PATCH v2 00/12] Bump minimum supported version of LLVM for
 building the kernel to 15.0.0
Date: Thu, 21 Aug 2025 14:15:37 -0700
Message-Id: <20250821-bump-min-llvm-ver-15-v2-0-635f3294e5f0@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-B4-Tracking: v=1; b=H4sIAHqMp2gC/22NQQ6CMBBFr0Jm7ZhOzSi48h6GhcAAE6GQVhsN4
 e5W3Lp8L/nvLxDEqwQ4Zwt4iRp0cgnsLoO6v7lOUJvEYI1lcyKD1XOccVSHwxBHjOKRGAu2B2p
 JqiMzpOnspdXXlr2WiXsNj8m/t5dIX/sL5pT/D0ZCg3VeUWPaglnM5S7eybCffAfluq4fb81km
 bkAAAA=
X-Change-ID: 20250710-bump-min-llvm-ver-15-95231f1eb655
To: linux-kernel@vger.kernel.org
Cc: Arnd Bergmann <arnd@arndb.de>, Kees Cook <kees@kernel.org>, 
 Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, 
 Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, 
 llvm@lists.linux.dev, patches@lists.linux.dev, 
 Nicolas Schier <nsc@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
 linux-kbuild@vger.kernel.org, linux-hardening@vger.kernel.org, 
 Russell King <linux@armlinux.org.uk>, Ard Biesheuvel <ardb@kernel.org>, 
 linux-arm-kernel@lists.infradead.org, Will Deacon <will@kernel.org>, 
 Thomas Bogendoerfer <tsbogend@alpha.franken.de>, linux-mips@vger.kernel.org, 
 Madhavan Srinivasan <maddy@linux.ibm.com>, 
 Michael Ellerman <mpe@ellerman.id.au>, Nicholas Piggin <npiggin@gmail.com>, 
 Christophe Leroy <christophe.leroy@csgroup.eu>, 
 linuxppc-dev@lists.ozlabs.org, Palmer Dabbelt <palmer@dabbelt.com>, 
 Alexandre Ghiti <alex@ghiti.fr>, linux-riscv@lists.infradead.org, 
 Marco Elver <elver@google.com>, 
 "Peter Zijlstra (Intel)" <peterz@infraded.org>, kasan-dev@googlegroups.com
X-Mailer: b4 0.15-dev
X-Developer-Signature: v=1; a=openpgp-sha256; l=3775; i=nathan@kernel.org;
 h=from:subject:message-id; bh=pOQAZPk+siIZkKBpkkHyydqf+iJWdipFSBVhf2HWXnk=;
 b=owGbwMvMwCUmm602sfCA1DTG02pJDBnLexp5jt71uLBmLnPYsZJXWxZZ/jvpEC46Jadf9c7Uw
 ETlF/9MO0pZGMS4GGTFFFmqH6seNzScc5bxxqlJMHNYmUCGMHBxCsBEbpkw/I9487fgnDGfn0/r
 3M6FSqzXJdY9UrRtFZK/fJjFtn+JsiAjw7+LX1KSfVQYtyp9370iKU3tw4SvX9nUW67uL1go/I+
 LnxkA
X-Developer-Key: i=nathan@kernel.org; a=openpgp;
 fpr=2437CB76E544CB6AB3D9DFD399739260CB6CB716
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=uQZ01Sr4;       spf=pass
 (google.com: domain of nathan@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
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

I plan to carry this via the Kbuild tree with the appropriate acks.

---
Changes in v2:
- Add two new patches for RISC-V to clean up more LLD_VERSION checks
  (Alex)
- Pick up provided tags (thanks all!)
- Link to v1: https://lore.kernel.org/r/20250818-bump-min-llvm-ver-15-v1-0-c8b1d0f955e0@kernel.org

---
Nathan Chancellor (12):
      kbuild: Bump minimum version of LLVM for building the kernel to 15.0.0
      arch/Kconfig: Drop always true condition from RANDOMIZE_KSTACK_OFFSET
      ARM: Clean up definition of ARM_HAS_GROUP_RELOCS
      arm64: Remove tautological LLVM Kconfig conditions
      mips: Unconditionally select ARCH_HAS_CURRENT_STACK_POINTER
      powerpc: Drop unnecessary initializations in __copy_inst_from_kernel_nofault()
      riscv: Remove version check for LTO_CLANG selects
      riscv: Unconditionally use linker relaxation
      riscv: Remove ld.lld version checks from many TOOLCHAIN_HAS configs
      lib/Kconfig.debug: Drop CLANG_VERSION check from DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT
      objtool: Drop noinstr hack for KCSAN_WEAK_MEMORY
      KMSAN: Remove tautological checks

 Documentation/process/changes.rst |  2 +-
 arch/Kconfig                      |  1 -
 arch/arm/Kconfig                  | 11 ++++-------
 arch/arm64/Kconfig                |  5 +----
 arch/mips/Kconfig                 |  2 +-
 arch/powerpc/include/asm/inst.h   |  4 ----
 arch/riscv/Kconfig                | 21 +++++++--------------
 arch/riscv/Makefile               |  9 +--------
 lib/Kconfig.debug                 |  2 +-
 lib/Kconfig.kcsan                 |  6 ------
 lib/Kconfig.kmsan                 | 11 +----------
 scripts/min-tool-version.sh       |  6 ++----
 tools/objtool/check.c             | 10 ----------
 13 files changed, 19 insertions(+), 71 deletions(-)
---
base-commit: 8f5ae30d69d7543eee0d70083daf4de8fe15d585
change-id: 20250710-bump-min-llvm-ver-15-95231f1eb655

Best regards,
--  
Nathan Chancellor <nathan@kernel.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250821-bump-min-llvm-ver-15-v2-0-635f3294e5f0%40kernel.org.
