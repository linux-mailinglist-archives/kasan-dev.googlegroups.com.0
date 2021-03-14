Return-Path: <kasan-dev+bncBC447XVYUEMRBC5GW6BAMGQEQZHIYXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id C363833A3BA
	for <lists+kasan-dev@lfdr.de>; Sun, 14 Mar 2021 10:10:36 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id s17sf11138486ljs.19
        for <lists+kasan-dev@lfdr.de>; Sun, 14 Mar 2021 01:10:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615713036; cv=pass;
        d=google.com; s=arc-20160816;
        b=lBA6YqXkho4AzNUyEs+bzhT26QgWkFtt9qmdwSx57ah2aNvR40CkZOW/DBw4zh+3jT
         KFLvTZbMjAu953u9AvQp8gQNGPXOLGwrTBcMrtahe4E6zT/ui4WZDZ0GWx2wLhXwTkfS
         zKOTH+Y6PmSJEQojLXKUJEXZ8VF1YCteZjrSSUo780gxeTNz9TAPm4znarO0oMQkJ6Fo
         HHzZl75cOLCYI8bI1+2+FvJ0Y0Ctw5w0vc47BTNwipIgQb4zEfNli1jXZJiQ2mtxHs/r
         muMVyCczoFNPs9C8uEufc4PJGIkgHFfxiMinbBnwDOVAaKbRAgsZH+seO8ONiRhKX8Zf
         mGYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=VoGDALtzUskmvx7fJ+QVn8zVX4Oc9V81iLOti+gsNwA=;
        b=nH1yhC/pHPDvFjZ/bLc1fha1SfrX0i3KhlGSN6v1WG21BD85fEDzSTLRNC6gaqXzM6
         t1/Ze3MCRB1qHOrNV2NcAWEpZDDDdlxL3tCx55Wx8L5KE2VntBVF0t0ihBprcyqyl4Aa
         HaheejKCuetKdpqvjf3DS/cYFDf+JiLuLnlJFaHi19lRcN9RGvdSWfLYtiXaQL40EhAi
         xVNi2eYCUWnKYyPHV1Xl8hNmBJRuVHEHOKlRGOxVLbmwCIKUp4oNtAUusNylrJckqbPh
         VMFTQCYnKsQSHTB9rfxM90lnbWFRnwPeQ28YdHPwG8ilUsffwTCYoQNiqpnBnP/G58uI
         sE9A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.200 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VoGDALtzUskmvx7fJ+QVn8zVX4Oc9V81iLOti+gsNwA=;
        b=NVjqbJbNz8yIMZlNguW+E07DWc/NTKwHEPuN+oM4mlPuRmtqtVmrGf2+fFtRnb5oxg
         cpW2+FO9pFXHjAgdxuxdzYj55OdYK4C+k2M0mGSLnmNHX4gRYQVC7XYfqHl+oz1Pb1qu
         nw4GFACpv1bTsjQwHNJJD8dVoCiOO9rp+XMkZ8r9gmcijjDXGseFObhhX935RnfG7M9j
         vUY2YbIcPLNzC6XU4N7nv6lOZcRc4+LKbw7fKcFYKMlErUzLFKmGcDF14ZJ93lwaaKGy
         seN7BUBcx1II7l/O7T4SbIWMN9jb/ijzbovjD7HJsp6I/WW1jq6b8Z0b+Z9qeYz63gk9
         0ebA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VoGDALtzUskmvx7fJ+QVn8zVX4Oc9V81iLOti+gsNwA=;
        b=MnAc5geAFeg4L8gDWNC/DXpkgPuysYR2E14DOLQcfPrUFtlZ63AF7JjZUfwAeB2AN7
         2VPJ7uv2/qwrXIDOTzoXumRKxKwVQLMwnbg4s3RFtIyHN0liPG5/E0bR8H3130eYIEaS
         aeCjyiF9hl+4YJORQP2jSoUQPvZUmVL0Gsb5bO3Ya7HxUbDDiFjt9ZEKf1jVnua1yBWj
         9t4IN0TsPCsIn8SDEpTkWCH7iu2G+gSdk61WXgt6ELsWgaLzZJzLpetz5skh/fIOwiVj
         7RvHO1IZ4NgbFDfAzBjY0Phl6l5+i+Isc+7FA/DGogxvbZJwnLLDZuU7hkcJ5zim++1H
         gBEg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532xjDSeCtr9GAD8xTzbbwYK5leeUevpqK5Xvij4d2r2D3WqoErq
	Msq548juhiajs5JOQzmC2eI=
X-Google-Smtp-Source: ABdhPJwIW/RYcHWAkhbGCzUyzI1Q59L+zyb50sMkWt9lr4Ws+wgW6ruXCKWgTfnhoetFDfDI0FFmPA==
X-Received: by 2002:a05:6512:3083:: with SMTP id z3mr4850311lfd.453.1615713036144;
        Sun, 14 Mar 2021 01:10:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:e86:: with SMTP id 128ls1212541lfo.0.gmail; Sun, 14 Mar
 2021 01:10:35 -0800 (PST)
X-Received: by 2002:a05:6512:3298:: with SMTP id p24mr4526557lfe.221.1615713035099;
        Sun, 14 Mar 2021 01:10:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615713035; cv=none;
        d=google.com; s=arc-20160816;
        b=Me6r4jkGJ6BmCgHgtpbf5inkkTt0qHXVh+co2DosIXjO605mIpQFeQBopy9wxlUAaI
         Jk8Z0IQVmOXVbRczU1+aI9lKuDkSlsR1iKnplUMfPjgOyflo/Ame3WLD5FmIUYw0FPvj
         xg8Fs9Q8eiTh0LYv3rDCmGPsRWg4Jd9guZgla2TZxcGc2cQT8MaI4ROewNW5tW5rjkmx
         p81b/B0G3T2VE0ENfRtWGkl9/E7Kz6OjH3aVI0wGFdWRrUNuHrzUoYZ2yddP1yeRXv2q
         9qXG5CTdvdUKuoO+11DVJBRxr2gL9VZGTxx4zBa6ZHYO0i4+07FX+ni4SLESIxslPD50
         lIyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=GOR5RsNWUiNiaJdJqWQ/aqWEVkCX/WJoZ8GEKxIYRyo=;
        b=WCkXUDumxANFeiaZOY1NWE9QKrn97e+gWHP7rF1uQIWnZ5xI8LARazDNE3Ocs14tLy
         ud6Q0BumeGHqBa/J5wtdnr317EKUu5NyiThCQS9llYrJHBdstpd6zl72xi8IvZWQV3JW
         rzj9vtH9qtKVPmGMYRt41MepzbiAQSru1WgkN6a5sUUjorvQDoETgspMEACh0afQ6qUg
         EdfLiKQtm6lFYhQQxi5qvQsS6xypron0yVk2fYO5JP4WizY3wEVLtH7NVlG18ppkiQ3I
         h7Ah1GCSnFTuZUrzQ7BRBY1e4s807fA+e469QUcpYAWBkdQgn4YB2t1bUKZ651ZnCoxO
         Lx1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.200 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay7-d.mail.gandi.net (relay7-d.mail.gandi.net. [217.70.183.200])
        by gmr-mx.google.com with ESMTPS id a10si486672lfs.11.2021.03.14.01.10.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sun, 14 Mar 2021 01:10:34 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.183.200 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.200;
X-Originating-IP: 2.7.49.219
Received: from debian.home (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay7-d.mail.gandi.net (Postfix) with ESMTPSA id 7201E20002;
	Sun, 14 Mar 2021 09:10:29 +0000 (UTC)
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
Subject: [PATCH v3 0/3] Move kernel mapping outside the linear mapping
Date: Sun, 14 Mar 2021 05:10:24 -0400
Message-Id: <20210314091027.21592-1-alex@ghiti.fr>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.200 is neither permitted nor denied by best guess
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

Changes in v3:
- Fix broken nommu build as reported by kernel test robot by protecting
  the kernel mapping only in 64BIT and MMU configs, by reverting the
  introduction of load_sz_pmd and by not exporting load_sz/load_pa anymore
  since they were not initialized in nommu config. 

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
 Documentation/riscv/vm-layout.rst   | 63 +++++++++++++++++++++++
 arch/riscv/boot/loader.lds.S        |  3 +-
 arch/riscv/include/asm/page.h       | 17 ++++++-
 arch/riscv/include/asm/pgtable.h    | 37 ++++++++++----
 arch/riscv/include/asm/set_memory.h |  1 +
 arch/riscv/kernel/head.S            |  3 +-
 arch/riscv/kernel/module.c          |  6 +--
 arch/riscv/kernel/setup.c           |  5 ++
 arch/riscv/kernel/vmlinux.lds.S     |  3 +-
 arch/riscv/mm/fault.c               | 13 +++++
 arch/riscv/mm/init.c                | 78 ++++++++++++++++++++++-------
 arch/riscv/mm/kasan_init.c          |  9 ++++
 arch/riscv/mm/physaddr.c            |  2 +-
 arch/riscv/mm/ptdump.c              | 67 ++++++++++++++++++++-----
 15 files changed, 258 insertions(+), 50 deletions(-)
 create mode 100644 Documentation/riscv/vm-layout.rst

-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210314091027.21592-1-alex%40ghiti.fr.
