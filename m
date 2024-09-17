Return-Path: <kasan-dev+bncBDGZVRMH6UCRBUXAUS3QMGQE4J4BU6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id D90E997AC13
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Sep 2024 09:31:32 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id d2e1a72fcca58-718d6428b8bsf6823977b3a.3
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Sep 2024 00:31:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726558291; cv=pass;
        d=google.com; s=arc-20240605;
        b=GaYi4Ys8yFYppcSTRv7nEWSI4Upt4+9jJrvznMbou8zVs0Pp0PYiX+TF7VvRLFJm+j
         xYUNVBY0BB2eaHaNXk5VR/EkSBqLfYknBWA3IxCnxJgE8diAdQIdN9iR8BOo1G9KBcpx
         hcnAjknPQyAL3/3yvv7ql1v0AxcqVTICW1PG6vOMbvHb+DnkrT8qEJREdKKQc3Gn9psq
         CI3h8vTzg9EIf96NRIWt0wQvBAO6uPYMWg+wtmwZkPbryV9D7iK24t0eVBikjgbcwQUs
         npfpenUTxX5dLGU7brj0CpgIVx2LlJMBP5GWGWoZvOULR3e2anhiC4CrI1NyPE4gU0BV
         xVpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=kb2R4gWV6mh9NkFvh22Nd55AGdHoPpV+YMw8Ef3IvQc=;
        fh=OzZiBatuOBYvJdjLcD3cdakjSBNm/lpEGTIbzk/Jw6M=;
        b=K2VR5KAyaM16LIT299gktcfdoPvVAexNkvu32p9Q1Bf3045+MrQwBWKT4FCKx/Ttyw
         5pxyk5QgQw1kdo0Ybvnc+pwnmECRZiLFGDcgFL1YtlyLk8WldKOrhO76PpGswA5qrJ+K
         qmunhyx0rn0tWFK441ji11EDt1YlFfCjFcpH+5Tcy3FUEBFDVwk4h4CA5NZ2UcDbCW8j
         va7Mvi2IAkX64eDp3PFC10q8BrIYqnV6XkBdwh+cGrsXzKnu97dVX82yj3YvzVuesF1g
         V0NMbxz7ITItofUyvLvFdgmxGZASQrij30lfUPLE6lghCirTW1ZEqG8lXnPaGBnKoiap
         v+Lw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726558291; x=1727163091; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=kb2R4gWV6mh9NkFvh22Nd55AGdHoPpV+YMw8Ef3IvQc=;
        b=Xxd96VUy8WAgQvaI7JH9akdjMm1GGHRbUlcSdZ1PQpRDCeNFKEHM/YMPa6R4j+aV0L
         7KxRC5KRn05vbgCS6jwMD7lm+4nLqsyvvHYs044/kqmkWn6uK5wtb6cmzoKPfIJEDjIC
         Kx4/Sy6hTvb1sZoFHLufM/k1n/dMP+AaYVAwg9r1D/nsznDt4CNuzSI+DWojM0v9c1g5
         Y8YVzD93fdgmJ1z8MTDvVE0+W8yOyPWWpR5IV4/tYZA/vjUaVVBNs8qlXcLGLLmbVRmw
         U0VxdZGAfn+rDFFoYiqvgY3GUU3yIIjxVyGfZNB3IF5UhqznMgNaVQA9mJZPfAX9Zcgj
         JtFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726558291; x=1727163091;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=kb2R4gWV6mh9NkFvh22Nd55AGdHoPpV+YMw8Ef3IvQc=;
        b=vIUuC2xOakNd0QlCU9Or6HdW2zNUUXuzCPgd0XVD9yYndXYDIniFeKPYLS6sxeAxPX
         w5d/RiefwRbjiQ3LYrgZgRY//GYw9I/TPtO9k4/79fh9HLZrevTOap6Dv88vqpgHDA1e
         y/mVZlsfXQJOwXLfKcEG+NBcSVCdWDS6Jv8hmC+SVWj+qsDQYXP0FQzXnap0yChcHufX
         jPf+zowefGsxyzqVuSwoBdWHD/yw9MYpLFiABYiw3Rtw2qkiFktcDexK87PZDa8yakn+
         5Wt6PSHZFRTdrimTtTMsquY47JxNvCZ9C9uG0lGOmqnw7TgYdZav3EuH9Fnr25LN5wCR
         UOZQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVLsaqo4yma52gki77MBBIqAqJe5icylNBSaLdRwfMO5Mdiy3XtHgzPyjaA06H72kAy6mKPmg==@lfdr.de
X-Gm-Message-State: AOJu0Yy5OlIDRRyxg5sCm3qYkuh6oF+I8dHqAX6y05ruBbXVLLWhrix4
	v6O1eGJ6IKP49ljZR9tpjOEq/ZN4dgv+aK73jFugcbjj23hP+Hbm
X-Google-Smtp-Source: AGHT+IGzG4eeFnBYdm6Cp754i0r1ck0MJr6SsbBTs8h3M/PG8i3J3Nuqp1tQ/X8vtWQK8OLcJtprvw==
X-Received: by 2002:a05:6a00:650b:b0:714:291d:7e47 with SMTP id d2e1a72fcca58-719260826c0mr19514109b3a.10.1726558290961;
        Tue, 17 Sep 2024 00:31:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1804:b0:714:37eb:eb5d with SMTP id
 d2e1a72fcca58-71925a0c623ls4574691b3a.2.-pod-prod-01-us; Tue, 17 Sep 2024
 00:31:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWBYmbYqmBTkIOzakwbp8p96w7ilz5iUQZZ2bI1MP5yV5oAPJjBYAxsaEyz27BGDIMtmG6bleCaT68=@googlegroups.com
X-Received: by 2002:a05:6a21:1807:b0:1d2:e839:11b9 with SMTP id adf61e73a8af0-1d2e83912e7mr520123637.14.1726558289335;
        Tue, 17 Sep 2024 00:31:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726558289; cv=none;
        d=google.com; s=arc-20240605;
        b=AdsarF7vc4sSOoO09cotIpGAh/bnjc1AVNVJP535NwdlZpbF1XsN680VPnzc25j/sW
         yr908vjKdXPp3WpUHv+DiIYCX7KMHnKjwMyQO5Ls6TAUomwfwDXFK/ApyViOtaKCd4zE
         Y3J+FzGgzNTZH09FN0rYBSBTMvHKW5lKYHcQNfpcaN9Kv3AVXxT+AnS+4SekCsMQjJqf
         ejfPsKuWGgfPo9vHqbQKzit7Fr0kgnPk/daDD8JaOpM2Ci2SWEDLewWd0bdygaR4qnKQ
         JipED0VCZOiSHze2dC9444jGM1bdjANiCJ2RxQy7HiJG126iYB1UH00netZ8EClzNDLt
         2s3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=9j+eEexw0pwPhbimlz/fltFkGnw7JabcD0F6Vy6jlyg=;
        fh=UQNaMAYHGrpcz1A3KIVW4uNQRqY/Xs/Tgi5PZeMplwM=;
        b=QmPilIuYrVzC+rqhXs5FTiZsaFE4eTkRPcAyFom4K8EOiMiIF4ii/NoNRqQgDKR3Xa
         QM1fpTAZrwlfPeDR8JvE304JqGrrEDvrkM85mULjEiB9x0Fgtyqop3BM24UWehdINTNy
         3FvIFVSxrW4jekYJoIeZwXf3Jb5MGs39h2BCbuyO1LFeUZLJo4BRRVqNHOYSfb3L0c6y
         M7K4y8gD8egQdpoJmJBWd52TIrTNH3dGI0POxMyqFE2izVokvzfm3woPaJedD+QDBK3X
         63IA/5hDq7DFN2ExeW3jYMDz0wxqO6lkby6cBf47fPHXttLzY2f+HAnSC/L7f/dzFVfx
         T2sQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 98e67ed59e1d1-2dbb9d83497si408874a91.3.2024.09.17.00.31.29
        for <kasan-dev@googlegroups.com>;
        Tue, 17 Sep 2024 00:31:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id AF4CF1063;
	Tue, 17 Sep 2024 00:31:57 -0700 (PDT)
Received: from a077893.arm.com (unknown [10.163.61.158])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 904823F64C;
	Tue, 17 Sep 2024 00:31:23 -0700 (PDT)
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
Subject: [PATCH V2 0/7] mm: Use pxdp_get() for accessing page table entries
Date: Tue, 17 Sep 2024 13:01:10 +0530
Message-Id: <20240917073117.1531207-1-anshuman.khandual@arm.com>
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

Changes in V2:

- Separated out PUD changes from P4D changes
- Updated the commit message for x86 patch per Dave
- Implemented local variable page table value caching when applicable
- Updated all commit messages regarding local variable caching

Changes in V1:

https://lore.kernel.org/all/20240913084433.1016256-1-anshuman.khandual@arm.com/

Anshuman Khandual (7):
  m68k/mm: Change pmd_val()
  x86/mm: Drop page table entry address output from pxd_ERROR()
  mm: Use ptep_get() for accessing PTE entries
  mm: Use pmdp_get() for accessing PMD entries
  mm: Use pudp_get() for accessing PUD entries
  mm: Use p4dp_get() for accessing P4D entries
  mm: Use pgdp_get() for accessing PGD entries

 arch/m68k/include/asm/page.h          |  2 +-
 arch/x86/include/asm/pgtable-3level.h | 12 ++--
 arch/x86/include/asm/pgtable_64.h     | 20 +++---
 drivers/misc/sgi-gru/grufault.c       | 13 ++--
 fs/proc/task_mmu.c                    | 28 +++++----
 fs/userfaultfd.c                      |  6 +-
 include/linux/huge_mm.h               |  6 +-
 include/linux/mm.h                    |  6 +-
 include/linux/pgtable.h               | 49 +++++++++------
 kernel/events/core.c                  |  6 +-
 mm/gup.c                              | 43 ++++++-------
 mm/hmm.c                              |  2 +-
 mm/huge_memory.c                      | 90 +++++++++++++++------------
 mm/hugetlb.c                          | 10 +--
 mm/hugetlb_vmemmap.c                  |  4 +-
 mm/kasan/init.c                       | 38 +++++------
 mm/kasan/shadow.c                     | 12 ++--
 mm/khugepaged.c                       |  4 +-
 mm/madvise.c                          |  6 +-
 mm/mapping_dirty_helpers.c            |  2 +-
 mm/memory-failure.c                   | 14 ++---
 mm/memory.c                           | 71 +++++++++++----------
 mm/mempolicy.c                        |  4 +-
 mm/migrate.c                          |  4 +-
 mm/migrate_device.c                   | 10 +--
 mm/mlock.c                            |  6 +-
 mm/mprotect.c                         |  2 +-
 mm/mremap.c                           |  4 +-
 mm/page_table_check.c                 |  4 +-
 mm/page_vma_mapped.c                  |  6 +-
 mm/pagewalk.c                         | 10 +--
 mm/percpu.c                           |  8 +--
 mm/pgalloc-track.h                    |  6 +-
 mm/pgtable-generic.c                  | 30 ++++-----
 mm/ptdump.c                           |  8 +--
 mm/rmap.c                             | 10 +--
 mm/sparse-vmemmap.c                   | 10 +--
 mm/vmalloc.c                          | 58 +++++++++--------
 mm/vmscan.c                           |  6 +-
 39 files changed, 333 insertions(+), 297 deletions(-)

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240917073117.1531207-1-anshuman.khandual%40arm.com.
