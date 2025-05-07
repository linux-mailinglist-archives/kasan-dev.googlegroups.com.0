Return-Path: <kasan-dev+bncBDCPL7WX3MKBB46G53AAMGQE33U75CY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id B01B4AAE898
	for <lists+kasan-dev@lfdr.de>; Wed,  7 May 2025 20:16:31 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-4769a1db721sf1921501cf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 07 May 2025 11:16:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746641790; cv=pass;
        d=google.com; s=arc-20240605;
        b=akPUmVKhWxWZePy5GGv3XyV0mjH21flROadS63aS7TX0oYqvKOntZtGoEW0cO7NAuO
         boxBjbv5lksMk/JbFvCxWtwviHmZoydxVcKqU8p2ukn0Bbka1eKWvl+rBD1cLaCKe7EP
         7QmTcUGXTz5hhvF/LnSBM28KLq0QjrURkn8ba/VXVpvCT6FNVDhXjyu6BijjwFcSXU1K
         b+Oy0aS7kAP0zMu7dNmhJXSWTcYTFPV8gDvniyigI6jnbV//gBeyLGFJpkDzfFs0aw07
         c9w/iPziRrLPFx9UmHR4LOaCcpBErCIbQ/NW/R/b+8d4YcrSFgZT/iZ1ZSp5PNIdek+h
         wUFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=V1VWrtfm0jYLDdCVv+BNwyiDR0cWZRcPh4AoUraVaFk=;
        fh=9reByRq+mZE3TKSCdK07GAuOhqLRsrC7iuPnavdSdBs=;
        b=Z50QgjfrhyB1lvJhaH4G9mH8l6xw1hwRAwwpFY4R7FmXb6F7VL0d7LoPCIX99KfHMz
         Tgg9kT9X0NTiXJcQVUUB9T7NYO0I8l5qWw1tPJVE3+H8rvPg1R2EVPiiFtUqBQkn/clX
         +/WQpLiVXXkKN/ct/pz5ibir4rm34tdfBdJIv4wnGZ8OMekDjTvxF0aaOLAi1KQK+jjk
         Ez1kVVR9Q8AZbkjq1sBIMhtO/Z2y9PerOryekeKIfbqk2/HuI2oSg5S4ZRhcKnFU+NB3
         qbZtpY/F7UjkjDO8sQcQFXRLEqHTL5QRbdFuSHF15t5w+WVRtg2JnwpKiP3Bao8tVxir
         +CSA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=BC9uw5GO;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746641790; x=1747246590; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=V1VWrtfm0jYLDdCVv+BNwyiDR0cWZRcPh4AoUraVaFk=;
        b=I7gf2S9Sa45YNnOdRfixJhUTerWE7oZ4sV9a2Mgmyr/9Y6sQr8hN/3M6EhhtE6YUn4
         S4vab8lshXdb4tRzpYtf5Y7U8OmFpdd4p6F5DrnV9qZD05WrLs4dmUFo90A1IpoM9etq
         F9S3+4k80jMMd4qa35u+uIBlL1iTQza2T6QYqcb9j5yvp/wx/8kBWAqKCsb1bsQT96Ri
         o/0deK54zzQ75XQKGAAhC2Kv0zcFlQa5sklvuFH0QRomdwmq4a9r2oU0otkno3UFGv5E
         tSM4nAFgoRqJi+4/a4V3L59acFzx3BL4ew/+lYuVUoEW7fs/D25+UmOpTMq1bqf1iIJ8
         vfYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746641790; x=1747246590;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=V1VWrtfm0jYLDdCVv+BNwyiDR0cWZRcPh4AoUraVaFk=;
        b=ozpCZl5X66MlOraRg0y3ma9w6lZ4K48tM3zvcBp0/1FSZZSWoD5U1wBCD52YdgdpSu
         StuxM83I3s5OqFMcb1rhnvllMDK3vDROxbqzkf39BFiA0qnV+dnIxokzy+tBDyhvlbd7
         0gwfdPnBlCmOdwJglBG0lp4GwjXgg13rJoz3dAIunTHm4d5UEX1VHyfhRdx7ZCabWwtI
         IDGFaqudT3dteQGEnGwFrbjGEbNULuMzjGJ8jPE7/+rwc5KghOX3yoUYhDngTNvT3/zv
         V3NX/K60yBNvfSA8sjiZdLS3vYLtLM2TQCgBJiNeVnJysJpzSDpZbdxuS6gWO5LDPa05
         3dpw==
X-Forwarded-Encrypted: i=2; AJvYcCUrnfCFGA4vt2sd0XTZzPeqZMYDr/sK83Ec4zFHGDdU9LBgfZI1Ef2rnODVZcBbsp/ykEbGbQ==@lfdr.de
X-Gm-Message-State: AOJu0Yy8t5FynHwO+dV9NICwBViCNmeZniT9z5hVmbWaatUFL67rJn5r
	trAYZthl/msvf8xN9D1/dBgAFnxiqQPl3G4hYCNZhr0SIOEnxsR3
X-Google-Smtp-Source: AGHT+IF0vjr15i4/W9SCGChu5OVRNLgFECdIv48EFjaEQAJpeIYHtSLzku1FYvXShbPa1JyCEjz12Q==
X-Received: by 2002:a05:622a:4d47:b0:477:dcc:6c18 with SMTP id d75a77b69052e-49225b383f5mr76895811cf.14.1746641780063;
        Wed, 07 May 2025 11:16:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHyO36pQX2ABRCpMCrSbtEVPHRv1VSNsLrWif5KxCpyUw==
Received: by 2002:a05:622a:250c:b0:47e:c50e:95f6 with SMTP id
 d75a77b69052e-4944948000als2380291cf.1.-pod-prod-06-us; Wed, 07 May 2025
 11:16:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU9pGAN3VrrAUgcIHn/yGbRfOCI19L9jWcNhYoe9vEYBn6yoOwMWmNXFwy4oGlDd/w4TNccwvxromg=@googlegroups.com
X-Received: by 2002:a05:620a:600a:b0:7c5:407e:1ff8 with SMTP id af79cd13be357-7caf736f3e0mr531139285a.2.1746641779157;
        Wed, 07 May 2025 11:16:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746641779; cv=none;
        d=google.com; s=arc-20240605;
        b=ZIWOcbjyJddoSVW6DaSrjBUWs1Lb8GmKf5cs4RADOMW+1xSJ8CDz2hrCSAw6pa5D48
         EPOQvbWgIxt4QgjgUuGgplIxikS5YbnGWYFVSy/NgM894OPCtVdpZY2mWDQ3dtgB5Y49
         PqH5IBPYKtu89I0OZqOHu2TkKqkOaQiFK9jpE/1ybo+iA/ojb963PdOo3ZdqWmghmpUi
         o2Nqqpjf+JDfl0wzEcoGlHvyxneN/N/bg7p7VNU0mNY0ixPMfysWNzxb8sTMaDcPqPRx
         D1bhA4y0GmpGX/sGmElGj+g20XlhDhE7J+dkLLAiV+QEHYybnSevar4spFkM8O+1yDgk
         Fs6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=588ABMbq1VMpf5fTo+jtcv84XIC4xdQpMVZmd3w3dGs=;
        fh=zycgEl+1nSr/uEFwJ9RlK4/BTsqgjrj7fd+U8rQE3i0=;
        b=Aakpm6ZkXSokhMXkq6OAD1CEHGax64FbMKwP+sw9CXJAwM8+RfSYtQ6OJzeUHQDvwd
         hm4rVN2zQY1z+diNhG3YIiP+TFsN9spQ41/L30TiI3jhIeqiMIGPhd8Q8DQROQdkZUxS
         /QZYL08mWpnIEZvJUOr3Im0V6oqwTL22L8nOzEFbBkBzMoo3QQW6gxVwHeqi2/AR2bsJ
         7rSoTcIWlTK0aCp5Ag1NKQbuU5VGymSYqdNEFAdMKss3Mq6nXGMs7H4jW+0Nnz/ePnfL
         QIgw/SMk1WO6ccGXtfpwQm5mDv5cwZkxpaLIXAPwmmAbaLWnSWZkJKuqkX3fPfryoGGp
         vQBQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=BC9uw5GO;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-8780b004a40si481150241.2.2025.05.07.11.16.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 May 2025 11:16:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id A7C3FA4D92E;
	Wed,  7 May 2025 18:16:18 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 36E0CC4CEE2;
	Wed,  7 May 2025 18:16:18 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Kees Cook <kees@kernel.org>,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	Christoph Hellwig <hch@lst.de>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	linux-kernel@vger.kernel.org,
	x86@kernel.org,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	kvmarm@lists.linux.dev,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-efi@vger.kernel.org,
	linux-hardening@vger.kernel.org,
	linux-kbuild@vger.kernel.org,
	linux-security-module@vger.kernel.org,
	linux-kselftest@vger.kernel.org,
	sparclinux@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH 0/8] stackleak: Support Clang stack depth tracking
Date: Wed,  7 May 2025 11:16:06 -0700
Message-Id: <20250507180852.work.231-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=3469; i=kees@kernel.org; h=from:subject:message-id; bh=QgH8ehGN6f9HfgN0XYJ8BWQbTspcTZep+O49/EkwCxs=; b=owGbwMvMwCVmps19z/KJym7G02pJDBnSi7OXB/nf2/RYVPv/qsRZa9yqy1d3KRS0fd0+3e/0Z mOmo6+/dpSyMIhxMciKKbIE2bnHuXi8bQ93n6sIM4eVCWQIAxenAExkaTfD/4gpl7Tzdxoot/B1 XkiZEXAzf8mNdas/f/b9e06jz0Os9y/DP5NK7e6JV6Unzc9+dL7NyOhP2UaDL/szeOxaV8Zseb3 iAisA
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=BC9uw5GO;       spf=pass
 (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as
 permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
Content-Type: text/plain; charset="UTF-8"
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

Hi,

As part of looking at what GCC plugins could be replaced with Clang
implementations, this series uses the recently landed stack depth tracking
callback in Clang[1] to implement the stackleak feature. Since the Clang
feature is now landed, I'm moving this out of RFC to a v1.

Since this touches a lot of arch-specific Makefiles, I tried to trim
the CC list down to just mailing lists in those cases, otherwise the CC
was giant.

Thanks!

-Kees

[1] https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-stack-depth

 v1:
  - Finalize Clang URLs for landed feature
  - Perform CFLAGS enabling more sanely, as done for randstruct
  - Split __no_sanitize_coverage into separate patch
  - Update hardening.config and MAINTAINERS
  - Fix bug found with nvme tree
 RFC: https://lore.kernel.org/lkml/20250502185834.work.560-kees@kernel.org/

Kees Cook (8):
  nvme-pci: Make nvme_pci_npages_prp() __always_inline
  init.h: Disable sanitizer coverage for __init and __head
  stackleak: Rename CONFIG_GCC_PLUGIN_STACKLEAK to CONFIG_STACKLEAK
  stackleak: Rename stackleak_track_stack to __sanitizer_cov_stack_depth
  stackleak: Split STACKLEAK_CFLAGS from GCC_PLUGINS_CFLAGS
  stackleak: Support Clang stack depth tracking
  configs/hardening: Enable CONFIG_STACKLEAK
  configs/hardening: Enable CONFIG_INIT_ON_FREE_DEFAULT_ON

 security/Kconfig.hardening                  | 25 ++++++----
 Makefile                                    |  1 +
 arch/arm/boot/compressed/Makefile           |  2 +-
 arch/arm/vdso/Makefile                      |  2 +-
 arch/arm64/kernel/pi/Makefile               |  2 +-
 arch/arm64/kernel/vdso/Makefile             |  3 +-
 arch/arm64/kvm/hyp/nvhe/Makefile            |  2 +-
 arch/riscv/kernel/pi/Makefile               |  2 +-
 arch/riscv/purgatory/Makefile               |  2 +-
 arch/sparc/vdso/Makefile                    |  3 +-
 arch/x86/entry/vdso/Makefile                |  3 +-
 arch/x86/purgatory/Makefile                 |  2 +-
 drivers/firmware/efi/libstub/Makefile       |  6 +--
 kernel/Makefile                             |  4 +-
 lib/Makefile                                |  2 +-
 scripts/Makefile.gcc-plugins                | 16 +------
 scripts/Makefile.stackleak                  | 21 +++++++++
 scripts/gcc-plugins/stackleak_plugin.c      | 52 ++++++++++-----------
 Documentation/admin-guide/sysctl/kernel.rst |  2 +-
 Documentation/security/self-protection.rst  |  2 +-
 arch/x86/entry/calling.h                    |  4 +-
 arch/x86/include/asm/init.h                 |  2 +-
 include/linux/init.h                        |  4 +-
 include/linux/sched.h                       |  4 +-
 include/linux/stackleak.h                   |  6 +--
 arch/arm/kernel/entry-common.S              |  2 +-
 arch/arm64/kernel/entry.S                   |  2 +-
 arch/riscv/kernel/entry.S                   |  2 +-
 arch/s390/kernel/entry.S                    |  2 +-
 drivers/misc/lkdtm/stackleak.c              |  8 ++--
 drivers/nvme/host/pci.c                     |  2 +-
 kernel/stackleak.c                          |  4 +-
 tools/objtool/check.c                       |  2 +-
 tools/testing/selftests/lkdtm/config        |  2 +-
 MAINTAINERS                                 |  6 ++-
 kernel/configs/hardening.config             |  6 +++
 36 files changed, 122 insertions(+), 90 deletions(-)
 create mode 100644 scripts/Makefile.stackleak

-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250507180852.work.231-kees%40kernel.org.
