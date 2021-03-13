Return-Path: <kasan-dev+bncBC447XVYUEMRB7EJWKBAMGQEJA7WMJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 233B8339D34
	for <lists+kasan-dev@lfdr.de>; Sat, 13 Mar 2021 10:25:17 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id s10sf12359166wre.0
        for <lists+kasan-dev@lfdr.de>; Sat, 13 Mar 2021 01:25:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615627516; cv=pass;
        d=google.com; s=arc-20160816;
        b=TlEo/yzW6M1zuUqzGfWYa1Gbb1PuR2mReAxcGVF2Ur8KA9ljU6g1ktF6n5Q1TAOEbe
         7Ea5fO5Aw/45+QdmtBcJprPIz6S/y5DR+VO/4xsbqtlhlqbKTZsdObpQwnNYJmZfLmup
         ZwD7Wr3DcaGaW0e6oLIDBg3bnYwy0p3fbW+NHJMcX6wwdSPXkx+pe1yCiz0Y/51zdc2H
         ACk8j2l1+ATAE132OYZ8rVHgO4N9HVAwy2cKOOzGHqsIvuEI7XPbdGYgwH+87E/lmaz2
         ci+Vl9YPqsylKo0qHl/RtqZBLVD2McozNe23oExo4rg9JVWVk7SJoZ2fUUyhGPk/UK7i
         NixA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=ibONLqMoic786Mqj72uV6XPw0CQsw8/iIIimtBlBKyY=;
        b=STpDwKzih3gjj7Ji6ap2F0PU8o3fZA6H6M4HEb7THGVzJFuuU5cEtYD0sGlwM5+Vl8
         MAnLMMXcz04zhGYrbw25CmwUsEp5XhDBa5cWMoDAKU68P0giSTvM4NT0Ye1qJiPU0riQ
         3Sx5nXVlUAcQIvtNlom/bbyuZjNXQ5JAiPugOMm19nzz6FQq3U6dEt+0wbRbDwBWLpcJ
         8g/8r7njOpbzOC1ExoUQ3C9g5FBEVYdjRyeVQVX+6BhF/mkXcJLdsXFB+o620H40eMFt
         swu46JPuw9I+ZvdGzuAFjPZGrbX6y+n8ZjJIcy1/p97pJbBtOG95gN8S2iCM9OYrsabE
         VfjQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.197 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ibONLqMoic786Mqj72uV6XPw0CQsw8/iIIimtBlBKyY=;
        b=iKJs3v/U7MdMikgicb0V6omePb6P7S86kTiGD3BmqdY3DFyfwclGSDAMvkFxY+LClR
         1U33WLe6acP9BmLJ6oS+cATAyLgokDWWiSc5s1zfSD1R/vy0wF2F6Y2lOHY+5PNUZFe4
         Yj8x3L0YTfU33V/k7GO7nkFqzhNkaHs2qT7lbCxrAEd9ZzuqMIN1BsIuTQOwCwUdhYJn
         Y7xvwsMwqiKy18pqDHphraxxNctu46wgQ86RCTg5L7LvB75H7KvtAz3vSV04EKAwrs65
         QWxlijmsQ2+OP3mjq/57lFcDamw+esQSZ2UOcCguKE8KUqnacn3gdKpiZh1bJUJM50lz
         cpvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ibONLqMoic786Mqj72uV6XPw0CQsw8/iIIimtBlBKyY=;
        b=IidoR+s/uUhAwca+wtDW08VsYCIPJbJpvIs+bCdmg5DakvgJlLQdFVV7byYnPZc140
         lfLEuQIkh85imRtADEycmACCW4bDYI3KV4Ci/XhzGpeawNht7VH7V3Cd2TsMY0oDQjhm
         jTYxR7ZQ6kTbLjjsIgNSZF6xxsRPTwD9K3NiVxXVt+4LXbQJ4oV0svy3yUi+8SdH0fx+
         r+jHhIQJKqR/k1cw+sp+60b0IoSly2392B1m76vXua9nL1uJYLVGzLzMQqE39dMhLekM
         Jo6pNgTcp42PghaqY5brghXIY0pVH9cqB9094QeU33RZmqkSs2iGAZm5ViTJyuoa6Eqk
         RY/g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5303Ttdhgd4ncXYcQrLCtHwMunw8kWDONi3kuzRdi4BAkBDNhWok
	WyEMGxZ0DiSaD74TRO2+32c=
X-Google-Smtp-Source: ABdhPJz46bkrY6FKPmH43zEN8kIWyFICoio1x3Jy2QZ1/PuC4NShr0UDAIluwmncNGZNhFjIhGSYzQ==
X-Received: by 2002:a7b:cb04:: with SMTP id u4mr16733649wmj.122.1615627516896;
        Sat, 13 Mar 2021 01:25:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c047:: with SMTP id u7ls5804794wmc.1.gmail; Sat, 13 Mar
 2021 01:25:16 -0800 (PST)
X-Received: by 2002:a7b:cc1a:: with SMTP id f26mr16844048wmh.19.1615627516078;
        Sat, 13 Mar 2021 01:25:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615627516; cv=none;
        d=google.com; s=arc-20160816;
        b=z0+cW2dU708vhdx3g9jTH/XAg8fJosJPCzVuabkDd1tK2XdxVgu3BFvRBq4itTILJ9
         w3QLlSOJl4Nnz5+zM+dRBlJRzmfw6lzK8ht4u/SzDtMvkd9c8dQL9hqcpQJTnCwJ/hZA
         npWd9E2InX0AtLovpnPzHE960WqvhlFqaNDFoSysNLR6VleYIyney+5gGrLeOfmEO1oy
         ZFj7b68YFvdFlZGmKi4J4Kcmq/Po9bVyBXXCYGFWcemRybJnzqeWyP3GJFYiVs8Hgo0B
         J9vcnYnTKl7XhNZnyc4316yBoH5V5JniRTf8YGP0pznJhMJsfvToaB841gROi6+5PFs8
         PWPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=cgF/cnTR5pivoHaP9SYs3dcV7ZI5KyrACSoleu8IMlA=;
        b=galQFERO+9rMrzra89kERi4DfxV+GeWI3FO3E0GHuOAoGG4KYaACtIlYxFjQ0CmBvj
         lceipZKzm8nq6Vt672xSq+y24TP37/MkZ4cy7wVbU5CGgdAed46qlcehgGr9/KrCf+rP
         dcj1JBlfUtpLXLRP2cEdFHcw5tLdPAvRQ2Nv6xTPYYkQ45JxAIdBUfn0aeKxNqGOSzAK
         NSqY8lcxTrLdU+iIYFgx9cvauiT9bzIYMnFxUdAHGdd/qqn4O45OHEjpXV1FNCYnKyow
         biKNd9SwjNoli+DhZQGUwaPMbPc1EJVhuf6P9MMkzy3n+tACT+A3QSWq9KGDlUJIrmpe
         dyPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.197 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay5-d.mail.gandi.net (relay5-d.mail.gandi.net. [217.70.183.197])
        by gmr-mx.google.com with ESMTPS id q145si346538wme.1.2021.03.13.01.25.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sat, 13 Mar 2021 01:25:16 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.183.197 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.197;
X-Originating-IP: 2.7.49.219
Received: from debian.home (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay5-d.mail.gandi.net (Postfix) with ESMTPSA id 32F551C0003;
	Sat, 13 Mar 2021 09:25:10 +0000 (UTC)
From: Alexandre Ghiti <alex@ghiti.fr>
To: Jonathan Corbet <corbet@lwn.net>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Arnd Bergmann <arnd@arndb.de>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	linux-doc@vger.kernel.org,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-arch@vger.kernel.org,
	linux-mm@kvack.org
Cc: Alexandre Ghiti <alex@ghiti.fr>
Subject: [PATCH v2 0/3] Move kernel mapping outside the linear mapping
Date: Sat, 13 Mar 2021 04:25:06 -0500
Message-Id: <20210313092509.4918-1-alex@ghiti.fr>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.197 is neither permitted nor denied by best guess
 record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
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

I decided to split sv48 support in small series to ease the review.

This patchset pushes the kernel mapping (modules and BPF too) to the last
4GB of the 64bit address space, this allows to:
- implement relocatable kernel (that will come later in another
  patchset) that requires to move the kernel mapping out of the linear
  mapping to avoid to copy the kernel at a different physical address.
- have a single kernel that is not relocatable (and then that avoids the
  performance penalty imposed by PIC kernel) for both sv39 and sv48.

The first patch implements this behaviour, the second patch introduces a
documentation that describes the virtual address space layout of the 64bit
kernel and the last patch is taken from my sv48 series where I simply added
the dump of the modules/kernel/BPF mapping.

I removed the Reviewed-by on the first patch since it changed enough from
last time and deserves a second look.

Changes in v2:
- Fix documentation about direct mapping size which is 124GB instead
  of 126GB.
- Fix SPDX missing header in documentation.
- Fix another checkpatch warning about EXPORT_SYMBOL which was not
  directly below variable declaration.

Alexandre Ghiti (3):
  riscv: Move kernel mapping outside of linear mapping
  Documentation: riscv: Add documentation that describes the VM layout
  riscv: Prepare ptdump for vm layout dynamic addresses

 Documentation/riscv/index.rst       |  1 +
 Documentation/riscv/vm-layout.rst   | 63 ++++++++++++++++++++++
 arch/riscv/boot/loader.lds.S        |  3 +-
 arch/riscv/include/asm/page.h       | 18 ++++++-
 arch/riscv/include/asm/pgtable.h    | 37 +++++++++----
 arch/riscv/include/asm/set_memory.h |  1 +
 arch/riscv/kernel/head.S            |  3 +-
 arch/riscv/kernel/module.c          |  6 +--
 arch/riscv/kernel/setup.c           |  3 ++
 arch/riscv/kernel/vmlinux.lds.S     |  3 +-
 arch/riscv/mm/fault.c               | 13 +++++
 arch/riscv/mm/init.c                | 83 +++++++++++++++++++++++------
 arch/riscv/mm/kasan_init.c          |  9 ++++
 arch/riscv/mm/physaddr.c            |  2 +-
 arch/riscv/mm/ptdump.c              | 67 ++++++++++++++++++-----
 15 files changed, 262 insertions(+), 50 deletions(-)
 create mode 100644 Documentation/riscv/vm-layout.rst

-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210313092509.4918-1-alex%40ghiti.fr.
