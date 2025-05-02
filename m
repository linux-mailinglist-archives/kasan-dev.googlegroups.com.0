Return-Path: <kasan-dev+bncBDCPL7WX3MKBBD5N2TAAMGQE5NBDFLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id AE491AA79C6
	for <lists+kasan-dev@lfdr.de>; Fri,  2 May 2025 21:01:37 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id 41be03b00d2f7-af5156fbe79sf2680178a12.1
        for <lists+kasan-dev@lfdr.de>; Fri, 02 May 2025 12:01:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746212496; cv=pass;
        d=google.com; s=arc-20240605;
        b=lvDT2QI5FKvKRJdk2J6DNrN2MAGTF7Xv0p0IfA3p1WvL8EuxJKMzsXOyaBqXxD4fmY
         rZ2QFwObS8tyCyELrm/Ikop0r03vbUMZSgOJerJHZSqj39fbwF9Vq9jktr0mUk4DbT8J
         fK4XaKpxUvMU3sqbKxnfWVH5V1FYWHGWsevg7Ba1mVqLpQqo53JC33lZpYLxXcOo6Qb3
         HomIk3p89IqqL+l7I3B9qXGZEKtqnFIe0dCEeaqQH5NaLSFF+pd6B1DVEVhjJQLoNULu
         7hHkcwrKIAKYUte0cgG5HebHKORqEGaP3UvSZIgGNybf/tsfrhqQhb/totEv5NvmnZwf
         vSjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=QNyso5H3+Xv30JjPtCQMlbu2OU6O2hmx/x0dIIAa9tE=;
        fh=VULKki6NIrXjQ+JVFGI2Txv2udkTRJlQRhPOxNMUJxY=;
        b=AbdlTQvn3gOw1IR+9L6Tj2WgerLR4lDJ2H8QDkIFYtntyPoxgVzUxTTVlQfKFeqDBI
         eOzjGkYz/+qEfDEss9hvfQ5fC0+mlV5MFSWQij/DGxzMRffqNxcL17S5nhFMGdIISpqB
         lG3gq3nbaM/Vx/aLSrecVm0yjo6K+O2MmetuR93EUzipjHn/A7/dqZL3GETKWqRyRcnB
         GoZBFgrk0RG+c3DBNO3PJ3moFcSVys8BZz3oH6DVxgcX5ilrmjaPtK8zbJlN1S9ZoBoj
         0wYQjagRw6JzYlZfDw2dsRAYXn1IGFWlQu00JU3JPJJwbNio/hBV7EaDnhn375OuD5LX
         O4NQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ad1pf0qY;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746212496; x=1746817296; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QNyso5H3+Xv30JjPtCQMlbu2OU6O2hmx/x0dIIAa9tE=;
        b=YasxylysM2jtYfmvxguDp16HmsY/o+Ic26Le25BbbwrLFw57nY4WY+lZe4bpKsamnU
         lb431yJ/aw1YAaj/d8GIflhcXLWzRDnxAMRqsTaMbKE+xO8OW3Dpwtyr6teDeVDyJiIQ
         ihW3q4n2ld1c0ZutOEG8qn5eaiR2o8wmDpnnMkTrr/ab2zrdf2sG/TL17oXSSxjZJByZ
         mmSZFvJOjagAy3wlb9aGpPsl6SfsLuvs5L1MnLg0eX5w+9MzHjUcGuqJhwk53LitRCWo
         bOVovDu8w3EZRay0l29Mrgs5jKPcBPrnlQcY/msjHBGMJDY6aA4pHsC+6QdFcHACvXfo
         H4xQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746212496; x=1746817296;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=QNyso5H3+Xv30JjPtCQMlbu2OU6O2hmx/x0dIIAa9tE=;
        b=V+N53L2uzKB+RJuZwsuGM/wvyw5hLvhGQ2K1ggm63EXvdR3MVLslreBGUjDP1YWy+/
         jT7Ktg56uJcTKhSN2scq/vOkAHYF6ZisQmZQw+eTt4N611pxn98IVyGVo6By9nCVWFFy
         hw8/7xRotHlkA02rdYnSmMjSihnzvDtwUgvbXtoUEQVpPEbhdrZhiUIQX0vYZ5Lemglu
         r5nLBadU6Q+0547a65KwoiXCwgOSE/HTcj7CEhHVskwz2ENexnzY708Z/0txafYC/69M
         Hlrv4YqeCBrh+SdDIAmuP/l87Ev04NIzZWjfwve+k7COpX1UgypGnI6NEHjcr2r1rfnS
         oJ6g==
X-Forwarded-Encrypted: i=2; AJvYcCX2N5gdbUAuMZktREGzyfCZrMqQCnwrc2mK8RF2KN9jkDvErXw5eF+BPNCPq7YQrX0XDVEdHg==@lfdr.de
X-Gm-Message-State: AOJu0YwqxzuyU7bMSY2J6uVI3W+Oul2iBUfFLqhnZDKbPJZAY4u2+546
	uaOMs61IwktZoUbv2izuMQibcJAf4S0xESkHQJ1ExzUGlmEtcy9s
X-Google-Smtp-Source: AGHT+IEKU4xZ9F+psOHbPtdTKMb6iiTUTjESPIE2QIXPLWYBgVhVuSW19yddNi7/uduUAZOn8Qy+Zg==
X-Received: by 2002:a17:90b:1f86:b0:2ee:df70:1ff3 with SMTP id 98e67ed59e1d1-30a4e412100mr7261208a91.0.1746212495656;
        Fri, 02 May 2025 12:01:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHonF2a/5py6iH4TZt6b8OjNkumx+ASVjo0bJXryzAy7A==
Received: by 2002:a17:90b:570d:b0:2e2:840e:d4a7 with SMTP id
 98e67ed59e1d1-30a3e8920b1ls2308113a91.1.-pod-prod-06-us; Fri, 02 May 2025
 12:01:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVKF1iTJGkQQ+x7Fw0GhIGM4kPdMDxgyQJU7Oe7ilhL3FSrEDnCSahBCuvrjCpGq4f6+8XwU95Eg8w=@googlegroups.com
X-Received: by 2002:a17:90a:dfc5:b0:2f4:4003:f3ea with SMTP id 98e67ed59e1d1-30a4e6addf7mr7070733a91.33.1746212494128;
        Fri, 02 May 2025 12:01:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746212494; cv=none;
        d=google.com; s=arc-20240605;
        b=jPJ+aVxXmeVY7vXfY1Cd3rJlzP8oC3IB+Sh79n+z+ZnSQdhyEvghK0prJqOOJ9NIKI
         l/zoZhvumWlzuPaiImyi32UY5jYjDwg6MuQCB8nX4nteTMs0PfY44D9NiZdA33LA/VOD
         GTqQ/G371PSQtNA2bpkAFnI4yH/+EBYMg+pbq/oKT10jy1KRs7RWH7cEd6+/Yc/8UKW6
         DTFsnjLv+6LQaRXJJOOZw5LXUbqX9pc4+GTDFHk7TLBMrQjILH+42TD5AGNI0lIzcq9q
         QwTsH0POmjYbu96Y+R+1rscoBpV9ZBfn48lOkeP9Y7EaQE+vm3tuNjCX3tzRRdLVVVIo
         GGyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=LNQ9DkKl6qCmFIej/fFnSuqjjjkR0T0oF8RPjcQSQRQ=;
        fh=8MWqTkfDK7bYZ64Lxary++A5R54oiOC6Xmmuq8Oyits=;
        b=i8offfbGIhH7C5H6f2YkzhjbK1CIofkz4CZk0WsKTBb+VTZUwwIepROm0nWXS6nLAO
         0jHGHuysrfRHppm8exlgoh5CDjabgk5ybhwMOcbCh2EwAfaUZHxL9QyPYe+SWI3Z69Ur
         bXLetHftAwEuwizKRVZvwtQ3dRNPH2McFMhcexHuD/pqMkF0058aubc+FVV/XcICqWMG
         K/DTHUeInAkaxGveU7KcF56ouku4bwviz8gE2B9eyOIPWCXXMFN7c+zEoR2MvaKndzWx
         7i0eaWOYFtzgY4advaO4xqEHSCUVb0YzBjV3v2PALU5szLjzcvzx0xc/hn8njVJx+E5H
         YSbw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ad1pf0qY;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-30a263d59c1si503630a91.1.2025.05.02.12.01.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 02 May 2025 12:01:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 32F0160010;
	Fri,  2 May 2025 19:01:04 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 96E94C4AF0B;
	Fri,  2 May 2025 19:01:32 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Kees Cook <kees@kernel.org>,
	linux-kernel@vger.kernel.org,
	x86@kernel.org,
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
	kasan-dev@googlegroups.com,
	llvm@lists.linux.dev
Subject: [PATCH RFC 0/4] stackleak: Support Clang stack depth tracking
Date: Fri,  2 May 2025 12:01:23 -0700
Message-Id: <20250502185834.work.560-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2385; i=kees@kernel.org; h=from:subject:message-id; bh=1wZOixwKxeQr1a/J8UDK8Pi43lF4NiEy/AG7Bfq7Re4=; b=owGbwMvMwCVmps19z/KJym7G02pJDBmiYq0zXwVaP2MzO3LzSIm1wIuVjpVbzNOfXP638PIW1 evsBc8fd5SyMIhxMciKKbIE2bnHuXi8bQ93n6sIM4eVCWQIAxenAEwk6QfDb9YtkgtfuS4K4mA/ bzvl+EbWn7wiUjFvVCN5Q1IPTbA6XMjI8Fxv72puDZ2kv5tVLwqtW5KzIaDc7Xzr9HCGstmZxw5 6MwEA
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ad1pf0qY;       spf=pass
 (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
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
implementations, this series uses the recently proposed stack depth
tracking callback in Clang[1] to implement the stackleak feature.

-Kees

[1] https://github.com/llvm/llvm-project/pull/138323

Kees Cook (4):
  stackleak: Rename CONFIG_GCC_PLUGIN_STACKLEAK to CONFIG_STACKLEAK
  stackleak: Rename stackleak_track_stack to __sanitizer_cov_stack_depth
  stackleak: Split STACKLEAK_CFLAGS from GCC_PLUGINS_CFLAGS
  stackleak: Support Clang stack depth tracking

 Documentation/admin-guide/sysctl/kernel.rst |  2 +-
 Documentation/security/self-protection.rst  |  2 +-
 arch/arm/boot/compressed/Makefile           |  2 +-
 arch/arm/kernel/entry-common.S              |  2 +-
 arch/arm/vdso/Makefile                      |  2 +-
 arch/arm64/kernel/entry.S                   |  2 +-
 arch/arm64/kernel/pi/Makefile               |  2 +-
 arch/arm64/kernel/vdso/Makefile             |  1 +
 arch/arm64/kvm/hyp/nvhe/Makefile            |  2 +-
 arch/riscv/kernel/entry.S                   |  2 +-
 arch/riscv/kernel/pi/Makefile               |  2 +-
 arch/riscv/purgatory/Makefile               |  2 +-
 arch/s390/kernel/entry.S                    |  2 +-
 arch/sparc/vdso/Makefile                    |  3 +-
 arch/x86/entry/calling.h                    |  4 +-
 arch/x86/entry/vdso/Makefile                |  3 +-
 arch/x86/include/asm/init.h                 |  2 +-
 arch/x86/purgatory/Makefile                 |  2 +-
 drivers/firmware/efi/libstub/Makefile       |  6 +--
 drivers/misc/lkdtm/stackleak.c              |  8 ++--
 include/linux/init.h                        |  4 +-
 include/linux/sched.h                       |  4 +-
 include/linux/stackleak.h                   |  6 +--
 kernel/Makefile                             |  4 +-
 kernel/stackleak.c                          |  4 +-
 lib/Makefile                                |  2 +-
 scripts/Makefile.gcc-plugins                | 13 +++---
 scripts/Makefile.ubsan                      | 12 +++++
 scripts/gcc-plugins/stackleak_plugin.c      | 52 ++++++++++-----------
 security/Kconfig.hardening                  | 25 ++++++----
 tools/objtool/check.c                       |  2 +-
 tools/testing/selftests/lkdtm/config        |  2 +-
 32 files changed, 105 insertions(+), 78 deletions(-)

-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250502185834.work.560-kees%40kernel.org.
