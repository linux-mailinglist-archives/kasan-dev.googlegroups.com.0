Return-Path: <kasan-dev+bncBDGZVRMH6UCRB7XWR63QMGQETQ2EK7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 90ED6977B6B
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Sep 2024 10:44:47 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-3a0862f232fsf18444335ab.0
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Sep 2024 01:44:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726217086; cv=pass;
        d=google.com; s=arc-20240605;
        b=b+GD8uF/Ei0URifIeYPDibix/Xh066YWstCbii+EkxIGYdkMjRTvG8a7qopEhxeO6n
         B4R3Os8LPm2/Y4Rl6kXoC535MNPBZ03ifwaCHMWPQfOgtyei5hx2inVsxqx2GT3FxQV4
         4hZSD/T4ZKb57usqjy2aZXub5WrNqBrk3++FtzgP9flnHzBay3kMcCqf8k8dbqsX8V0q
         yHP2xCMObW0x0Q8tkP4fgefHNQptGMmfj1jwIhD5yOKGJNqGcioqU8k8dIIldQRmW7d+
         2cvjeqdffOBGdgMihRecVN6voT6Saqdd7J3MJVw8mmsQG0X6WofMb3+TeskFMtU82GfW
         2UPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=s9KM0iE9hH+8Xu363txPUZorVxbvA3t7dofW1s7iYNU=;
        fh=Q5z8sjFFFCR27flqwxzhKvewWN+wGdSZeLWaouS606M=;
        b=SItfmOc/NHUz7BryDi0Gk4ae9Zqm+8dbTNBPlwn9bhYxh9rOzgI3eJjJJKEzFyyfWh
         SKmoFt47lmF5zL7GmSihGBKdxz1cjivSt0qagtcCIetFaP/+kPo74v0ogBZbS2FuDSQm
         U8UltMExOuJS23rCqtdJz/m6wi+6osfsllfUWBGcNx7bgld1j9KnclvaZPFETV4ImHrN
         lJClcnLJcosqIcTYAQryv/d+PGH4qLlAZYItRCm2zGcRcPbTRkhsO1g7NwjOXi72S7Wq
         dPwR1DETK9H6cCRuA/fWINrqDGGyMHNa7eCpH3hJP22JqEAz2EXexsE4dGkRy5SMOX+m
         QCVA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726217086; x=1726821886; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=s9KM0iE9hH+8Xu363txPUZorVxbvA3t7dofW1s7iYNU=;
        b=qwbirqyCbN2HIPY1K782JlKlUBQdPUlSNvTbOzpw5t/nlw7OOhDzHvmO1c7A9OCMGf
         NfQAW0Puvu+qg+sOp40DqhpcJIhlPjnlPEKHVydbh72QPJSoFd+HWciCVXN6dWC+aPvW
         RTqk1W2VyASouy+KNX1UHrmkk/vmMkEJcF0cAGEcWZ0M1fUBCLor0Z5oTcF9Tx5UqIiZ
         lxopxAqbMxUbL3S5A0JV0o6/12cLEctWoQeNTdEYhGmhirS7mNhm6KowOoBoQ12jbdYl
         FeZmD9n2rvYdnTaV+v6MG71j2gzj7QSKvhsJ/sGAoWbNSOxWKv+5jFVsw98xmCp1c923
         hr6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726217086; x=1726821886;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=s9KM0iE9hH+8Xu363txPUZorVxbvA3t7dofW1s7iYNU=;
        b=DLS+UeCrxrCxGSCpOzUJ4nBfMsfhdInE69sY8XVk3FqJWHsT2ttCX8le2pHH18Kek4
         Mt3b6a8EbkeZrBHbjw/7LXi3TxVWSztq0ck0Ka4N6J7Gm1W5oa0aWB6z8Ay+4LYTm3Af
         4m/Hi0WjA3EN+6WSZKQOg9JPH7LeNdJswzgrHqb5JgMR3GT6Q2sjxvHAEkqHoDtpX5+p
         6//awcuUI6+/RbwX1eMTlx8uCbkAqoN3xZTodAB4r7BKzjY3sspaLBDXV0M6NSilhLDX
         OL7DO2YomPFZZVDMJ78ZBFpBMYfxKCUd5GHSM+FE3H2ktGnzDKHKFkp1FqsLvte8vog0
         xSPw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW0WMravJVluc12OdG2C6y/alL9Z5Yys7j6MoxS7ySPUygFatd6v1+w28CJMGOiuM+uHnRUbg==@lfdr.de
X-Gm-Message-State: AOJu0YxuaxAvbMiOtZ4nt7HqGYwBfcF3utfAIpGeaFpAZdwNABPtK8aR
	ktyptbloBSDYj2v6+QFBYDpiFdFAVx/6/jkuGRKDBlB/Mxzohx+Q
X-Google-Smtp-Source: AGHT+IH+uovEiOoZbCcTkVSP3J0MubdqjMP78K3+zSjr+EUxs6qWHaa1OGRDe0ZVEJRF12pdr0XCjQ==
X-Received: by 2002:a05:6e02:1a42:b0:39f:5c5f:e487 with SMTP id e9e14a558f8ab-3a084954fbdmr61509895ab.17.1726217086162;
        Fri, 13 Sep 2024 01:44:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:19cd:b0:39d:52b9:5478 with SMTP id
 e9e14a558f8ab-3a084090238ls11814555ab.0.-pod-prod-01-us; Fri, 13 Sep 2024
 01:44:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUulYgL/2lzFWH6q2c2keg6fFQdZexkPmFPi3L14wuw1vyZFMmQkT3IfEn2C9in/iILNcfAVVpc5WE=@googlegroups.com
X-Received: by 2002:a05:6e02:12c5:b0:39f:5efe:ae73 with SMTP id e9e14a558f8ab-3a0848eb2admr60761525ab.5.1726217085163;
        Fri, 13 Sep 2024 01:44:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726217085; cv=none;
        d=google.com; s=arc-20240605;
        b=UPPwqRCtlozRpkGKs5PV2jbGkentR98HSt63obYY9h0/RWxyUhaQtA8ATh9UJfNlQc
         TN8ecZQHHV+rw6Z+dsYjW/C0i5VvaLBvq4u3gcFL+1EZ+RYnEyhxgvlL/7oQA5Lp/taU
         wuLnaLjZAzsUKCn8qEiMLlngfxpDH0unA6KdxOLGO5GW4O1STgUhKEUanrgbbpOsHvAy
         4Rz934KgRkJlV/rIPc6Jm81n8FrEsNn5lI5Y4FJifJfplhlJB7dmsUMwsWcq9eXvOI5E
         Q1OsQnIEPyL5jF5OXT90PEFrIIm1J5Vnuymyt4BuYH6TVZoRAs6IHmJPFWrkA9JyBw7d
         x0Uw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=18N/S+ZKANNLFViFzY2Ut3pdWgH6ZrJNTuJtauAGQYo=;
        fh=UQNaMAYHGrpcz1A3KIVW4uNQRqY/Xs/Tgi5PZeMplwM=;
        b=kMy3CO9PYVJTaK1UodySR0wy62V5hePf3pHnBR5iinKHKdmL7zejTu8PdUEJnBLaeI
         gfLvZpvE5q/sjXecQBms2PqGz9Py+I5tIffmITDX5wgJkfi+RaSkVJtdF+aaYFcJXOAQ
         eNSYfIJs7mxXzodRfKvTZuF5DAn+sJRhAfaSw1aN8DhdPLJHsiG37djCLqdumwTtRnjS
         ZdcaSyk4pzkuASM9zgTb/vTUReQFl+R0f7bKYfdAId06bo8PkAIjx92JNP2P5ZTtXIqS
         jDNK6u7qH3vJUyl00kuN8LakMoFEUkWMeGyUUmFPhKIthQUkG30TXotLNor9Fw7I8OzG
         BcFQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 8926c6da1cb9f-4d35e256ab3si183085173.0.2024.09.13.01.44.45
        for <kasan-dev@googlegroups.com>;
        Fri, 13 Sep 2024 01:44:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id B45C813D5;
	Fri, 13 Sep 2024 01:45:13 -0700 (PDT)
Received: from a077893.blr.arm.com (a077893.blr.arm.com [10.162.16.84])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 7F3B23F73B;
	Fri, 13 Sep 2024 01:44:40 -0700 (PDT)
From: Anshuman Khandual <anshuman.khandual@arm.com>
To: linux-mm@kvack.org
Cc: Anshuman Khandual <anshuman.khandual@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	David Hildenbrand <david@redhat.com>,
	Ryan Roberts <ryan.roberts@arm.com>,
	"Mike Rapoport (IBM)" <rppt@kernel.org>,
	Arnd Bergmann <arnd@arndb.de>,
	x86@kernel.org,
	linux-m68k@lists.linux-m68k.org,
	linux-fsdevel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-perf-users@vger.kernel.org
Subject: [PATCH 0/7] mm: Use pxdp_get() for accessing page table entries
Date: Fri, 13 Sep 2024 14:14:26 +0530
Message-Id: <20240913084433.1016256-1-anshuman.khandual@arm.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
X-Original-Sender: anshuman.khandual@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

This series converts all generic page table entries direct derefences via
pxdp_get() based helpers extending the changes brought in via the commit
c33c794828f2 ("mm: ptep_get() conversion"). First it does some platform
specific changes for m68k and x86 architecture.

This series has been build tested on multiple architecture such as x86,
arm64, powerpc, powerpc64le, riscv, and m68k etc.

Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: David Hildenbrand <david@redhat.com>
Cc: Ryan Roberts <ryan.roberts@arm.com>
Cc: "Mike Rapoport (IBM)" <rppt@kernel.org>
Cc: Arnd Bergmann <arnd@arndb.de>
Cc: x86@kernel.org
Cc: linux-m68k@lists.linux-m68k.org
Cc: linux-mm@kvack.org
Cc: linux-fsdevel@vger.kernel.org
Cc: kasan-dev@googlegroups.com
Cc: linux-kernel@vger.kernel.org
Cc: linux-perf-users@vger.kernel.org
Cc: kasan-dev@googlegroups.com

Anshuman Khandual (7):
  m68k/mm: Change pmd_val()
  x86/mm: Drop page table entry address output from pxd_ERROR()
  mm: Use ptep_get() for accessing PTE entries
  mm: Use pmdp_get() for accessing PMD entries
  mm: Use pudp_get() for accessing PUD entries
  mm: Use p4dp_get() for accessing P4D entries
  mm: Use pgdp_get() for accessing PGD entries

 arch/m68k/include/asm/page.h          |  2 +-
 arch/x86/include/asm/pgtable-3level.h | 12 ++---
 arch/x86/include/asm/pgtable_64.h     | 20 +++----
 drivers/misc/sgi-gru/grufault.c       | 10 ++--
 fs/proc/task_mmu.c                    | 26 ++++-----
 fs/userfaultfd.c                      |  6 +--
 include/linux/huge_mm.h               |  5 +-
 include/linux/mm.h                    |  6 +--
 include/linux/pgtable.h               | 38 +++++++-------
 kernel/events/core.c                  |  6 +--
 mm/gup.c                              | 40 +++++++-------
 mm/hmm.c                              |  2 +-
 mm/huge_memory.c                      | 76 +++++++++++++--------------
 mm/hugetlb.c                          | 10 ++--
 mm/hugetlb_vmemmap.c                  |  4 +-
 mm/kasan/init.c                       | 38 +++++++-------
 mm/kasan/shadow.c                     | 12 ++---
 mm/khugepaged.c                       |  4 +-
 mm/madvise.c                          |  6 +--
 mm/mapping_dirty_helpers.c            |  2 +-
 mm/memory-failure.c                   | 14 ++---
 mm/memory.c                           | 59 +++++++++++----------
 mm/mempolicy.c                        |  4 +-
 mm/migrate.c                          |  4 +-
 mm/migrate_device.c                   | 10 ++--
 mm/mlock.c                            |  6 +--
 mm/mprotect.c                         |  2 +-
 mm/mremap.c                           |  4 +-
 mm/page_table_check.c                 |  4 +-
 mm/page_vma_mapped.c                  |  6 +--
 mm/pagewalk.c                         | 10 ++--
 mm/percpu.c                           |  8 +--
 mm/pgalloc-track.h                    |  6 +--
 mm/pgtable-generic.c                  | 24 ++++-----
 mm/ptdump.c                           |  8 +--
 mm/rmap.c                             |  8 +--
 mm/sparse-vmemmap.c                   | 10 ++--
 mm/vmalloc.c                          | 46 ++++++++--------
 mm/vmscan.c                           |  6 +--
 39 files changed, 283 insertions(+), 281 deletions(-)

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240913084433.1016256-1-anshuman.khandual%40arm.com.
