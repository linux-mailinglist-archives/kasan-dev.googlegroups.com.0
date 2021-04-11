Return-Path: <kasan-dev+bncBC447XVYUEMRBUONZSBQMGQEXUQX2CQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id C98AB35B618
	for <lists+kasan-dev@lfdr.de>; Sun, 11 Apr 2021 18:41:53 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id a24sf3712823ljp.16
        for <lists+kasan-dev@lfdr.de>; Sun, 11 Apr 2021 09:41:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618159313; cv=pass;
        d=google.com; s=arc-20160816;
        b=cLu13lujpiYyKWxPY3MsedFhVCCvdoadJIyr1bx6dUSpqd6UZKvGlJjiJOeV4RDWp8
         uTC7dMmLUJNH7fEpClq5BzaHRCJfXvJBO/8SAaeakBJ+xov33zZepzDvHlF0QTRCaulr
         Tb1LkKW52Jr8qRH9MlGVhrcwkN79ps39p5GP2lkbWQGjkXzaMFb9R83nAMzbPCqeYB/O
         z/8Musx9t5pZKuldBxEMuM+og2VlQ2TQOokFq871YvhS+jowiT2UOjehWGUg4RueQY0A
         hR/8EZYaoxxP62IV028whPyPpWMya9OXnJIvuMOvhmLl7najLcEfz1MKWKKHXRwORZ5T
         QPrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=qD/x1hUyCgVkjGrm9G2z0KVWagF+vrLyb1rfpYrZg/E=;
        b=G+7R5avt6sjRaMV3IUEy6KDeZXx8moT7RQv+na772icijDOo8fVpZ99Z3Lx3SHJyLn
         IkVJHcynvrMlrx7vKF0NFhj1EKwtEPCXCMEXv6m0Lr7ftiQWg8CvT0isTDXgd7fVKu3O
         E+e0OQzXlURAdgp2d+aO8J2K7BLsEI7zOCnOIcpwqXapNxlxR6D7iQ9/+vX1p9RrHFM1
         nRiW9AHomnaLAAj5dte4bgQIyFL1rUBFvEWm5c/J3dQMAOGfPPabB5RlzOVpPSqHX3Z7
         F1WvwrkQZNxNANbtYGSzm5fzdI6oEOer0lce2WIFGT7uQ4Cm1TfeF4yktfl8RZn1e/0/
         mFJw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.193 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qD/x1hUyCgVkjGrm9G2z0KVWagF+vrLyb1rfpYrZg/E=;
        b=nC2pMKlZnU3wOlS8trniScPaBpyia2Lmli0oOpdY6pw3YqjBGbuP3QfLWV9ShCv4rB
         T+bCrAj8qttluyb2EQHYRAaXBtDdor4UvCpBE1XQXm5W0JNR/z47BS4Ccq4velqRRJMS
         wd6RfiCY6iMGml0sBTn+70bBEIat8Ctq4mQG9BlJ4LT9F7vOqK166GWaTZ4OiYrLyq6C
         1Yw4a9ag7XwT0crRZ+TeAy3xz4WPjy06I4Js1vBoTHGCss4d4kRc9+0Xi1mrI8LVgFlX
         rqR6lVGug4msSwILb5TvAlt2OG09r92MJCNXUP9JlTpFEwVhLnYzkS1akCP5n3t5dNXV
         pRTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qD/x1hUyCgVkjGrm9G2z0KVWagF+vrLyb1rfpYrZg/E=;
        b=QcO5OrruWGu0i1iXeVsXD6C7udioSny+elNTsS19W8V7ajF9HfhEFMCh4DmEx/49Hq
         JY65z2OclJyaegFjIN9kOcNlP+VB01g7tpL2kSMYIrOZ4NMRYDL6wfYY99g+s5CeeCjD
         vtitzsBat3oMwX+0GvNX4cljYtTdJxl/rD7t0ZPzERub4AmR3HSOHOKjF2tpHsYQPRby
         TpW7OIMnpqMWHA8B+Lbn4qOiYgGer4fyMrj+pTTEeV2dhou5BVyUQ5b+XkFdfCjblqVr
         R3CJSJkex7gpRny5crFEHlDObRqn7Yk3NAL1TyagTJ7EAytWenZ8xEdnosQbTqdbhJDd
         LYPw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530a5+u2R2jbjiv2TJNvHaNNcJjzZWFHWro8SvFbJKpdth12Ld/l
	4ApEl4aUsRoN+3/sUqWuQBw=
X-Google-Smtp-Source: ABdhPJzZEMcp+Bh925xVcriiDPxhPySV5PGatLoaE7Ua1mCn0CLOGM7NvSUI85l6MfF/aVO1wMnQMw==
X-Received: by 2002:a05:6512:66:: with SMTP id i6mr14079365lfo.474.1618159313284;
        Sun, 11 Apr 2021 09:41:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b95:: with SMTP id g21ls601546lfv.1.gmail; Sun, 11
 Apr 2021 09:41:52 -0700 (PDT)
X-Received: by 2002:ac2:4d07:: with SMTP id r7mr1876027lfi.158.1618159312341;
        Sun, 11 Apr 2021 09:41:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618159312; cv=none;
        d=google.com; s=arc-20160816;
        b=IjXffbu06WxoBo2SdajlsNtk5uBAvZwBym2eDoeiiwp2VmZxCcYpoxBqN9aA0Rx2zR
         cPEMHD5XoHk1sC2jo5hweJ5+vW2XVwt81d5C+NeLcQ0hc9srwnCkvdS68KoKb9m+fOGl
         B9L7zsGnKvphH9TtaZ67YUOU1Evo5HRlQAuXiet7O6EKg1zSG90QBNHcwpjc5P+7HNRV
         pBWI2u6s1oCYTpUFIsq6uifBcNraIRXjQvt+HoMLLdE1yL6nwHZxgoy6Wfq/QKK1Sl0m
         D2v+MAyCQOOylfu+MS9FCZb3kjggCmp1cFlbHThcQsVdan0Z30hj0y7p6b2BPb9oj/cL
         W2yg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=Ch/IfGD5PGyjnqwG0mYAKGWiVWhbCS/KfAIOn22xtx8=;
        b=yMOkTnDMRAI2+W4hnadkqSin1LFCUpEJTihXAek7eux6qOcg4yJDmotpvBq+rNktn9
         iKZbVKMoy7J6z5WtG9Z6hZXly1YOMO6Tkmmhm2A3DFyb3qr56h22vvyKJ2T2Ek/Uk/iL
         y+Bp5B4nEetBbNSwp6UTQEwmz+O57ttDVuMsCIXrpeMfyIpm3lWFsk/2dgkVbJ4VZH/O
         4QXYuEUV7vlck8JjNFMrwxQBUf5XhHGVYZf0aCYaNLKamsyKFM2sGUOExIMLDw/tDayp
         DYLxzBl05GpdG8vyfn5NzhgnteXLli0ijdOoRqI8tqVP437Wasow2MFndeTa71M/ykN3
         gjjg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.193 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay1-d.mail.gandi.net (relay1-d.mail.gandi.net. [217.70.183.193])
        by gmr-mx.google.com with ESMTPS id u11si576752lfi.6.2021.04.11.09.41.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sun, 11 Apr 2021 09:41:52 -0700 (PDT)
Received-SPF: neutral (google.com: 217.70.183.193 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.193;
X-Originating-IP: 2.7.49.219
Received: from debian.home (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay1-d.mail.gandi.net (Postfix) with ESMTPSA id 4736C240012;
	Sun, 11 Apr 2021 16:41:47 +0000 (UTC)
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
Subject: [PATCH v5 0/3] Move kernel mapping outside the linear mapping
Date: Sun, 11 Apr 2021 12:41:43 -0400
Message-Id: <20210411164146.20232-1-alex@ghiti.fr>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.193 is neither permitted nor denied by best guess
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

Changes in v5:
- Fix 32BIT build that failed because MODULE_VADDR does not exist as
  modules lie in the vmalloc zone in 32BIT, reported by kernel test
  robot.

Changes in v4:
- Fix BUILTIN_DTB since we used __va to obtain the virtual address of the
  builtin DTB which returns a linear mapping address, and then we use
  this address before setup_vm_final installs the linear mapping: this
  is not possible anymore since the kernel does not lie inside the
  linear mapping anymore.

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
 Documentation/riscv/vm-layout.rst   | 63 +++++++++++++++++++++
 arch/riscv/boot/loader.lds.S        |  3 +-
 arch/riscv/include/asm/page.h       | 17 +++++-
 arch/riscv/include/asm/pgtable.h    | 37 ++++++++----
 arch/riscv/include/asm/set_memory.h |  1 +
 arch/riscv/kernel/head.S            |  3 +-
 arch/riscv/kernel/module.c          |  6 +-
 arch/riscv/kernel/setup.c           |  5 ++
 arch/riscv/kernel/vmlinux.lds.S     |  3 +-
 arch/riscv/mm/fault.c               | 13 +++++
 arch/riscv/mm/init.c                | 87 ++++++++++++++++++++++-------
 arch/riscv/mm/kasan_init.c          |  9 +++
 arch/riscv/mm/physaddr.c            |  2 +-
 arch/riscv/mm/ptdump.c              | 73 ++++++++++++++++++++----
 15 files changed, 271 insertions(+), 52 deletions(-)
 create mode 100644 Documentation/riscv/vm-layout.rst

-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210411164146.20232-1-alex%40ghiti.fr.
