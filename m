Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBWVFV23QMGQEF5M5GFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A9A297C2E0
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Sep 2024 04:56:30 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-20535259f94sf5813645ad.1
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Sep 2024 19:56:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726714587; cv=pass;
        d=google.com; s=arc-20240605;
        b=N9FwxE3gUclrbvryLZJAWgeib6bcore05e6QEuerkcB37atTHI8OgHXnBKRCAg2V2e
         Q8TBhKIT5pO+dRXy0QNzjK2h1Y6KG/GwN1V9GYzYjY8LQ0JrhpJPFMNir3kqmXzVuk0Z
         J76tA8ZTVvPknHQtHTUzJypO1ozzE4AMg9xZG9QfuztZrAfw5MOII9Gi1iZsYQb0I/X6
         emMit4x1VPQXANlBBtmTpsdhpLHY5cpY86EHdEw3KDEI5H6V9ZNwVCnNQvN51+OrhMLS
         z8v973K2drM6M7iCauC78cACDjeDIGGmue7r2hi3E4vKD8KZMOCy/BbHcgnV1//ZOZgt
         UWdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=N3B5dAwAhj8gaFVNT9zRigA74sbZ4gkfU1dUdRFBfiM=;
        fh=a5TEb+JrHVVhWxigF6x4UIv9OmiHvIcK4Tr/6phaDi0=;
        b=IT8k01oD9vCnI79AeCPPvwpYob5dj7Of3VP1EZbhE0RZ1ToLu0bpLc24qx/rFDLXh+
         sZ0R3xbEigQSOHHBHwLTyBPR/ZmZQJ+mNSY31vBVerIX1WJUPDg5dugS5rR1iI3iV2jl
         Mvdl8RvBXZxoyw5IkDf/iHDPr2nRHVo1Gk/afvk7H0SvU/ZsllsovoGwN7fSBovQ0Es0
         xS05bQUZcRUGUIgxlSDpaHbq83cRKwfwlDYTliC0EHCb/jdqmn57Cgp3deuoWsih6tPA
         CpvRdiDiNwveVKdPWnlxk349g7adB2kggvjrz5bMhob5n+qV390k12B91laVP/+qD6Xn
         dozA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=eYXn7OXH;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726714587; x=1727319387; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=N3B5dAwAhj8gaFVNT9zRigA74sbZ4gkfU1dUdRFBfiM=;
        b=YBb9kGgjarIuoOAvLsrlmliSMZt4Yl0kY3F1pdJIyKAkCuIHRBLEXeTCLr59gN2GPV
         yEZnLbwEJ9UzaYpuMRkB6YUCONaRBe8CTBDcNH0q2O9qcjYtawpJHe7m6c1P4HAi8mUo
         j9asLVGYaHkWJ/Yr7EoQDpSTGxLJ62Don29Pf6A9TUhbeR0Po7vMnIovMk0P/WTJDkx4
         tnZW/mnfqJkNFx2FDjVbEWRoEin41+PLEpxTDqhA9RFP1e39pPU1w7Aw4P3eMKc/g9si
         8mjRuTYcT7xnzUepm7ccQ6f2D+La2G9FLkQeAlGaEfAJuldkyEdiXzgXz1zenjvO1zW5
         N5Tg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1726714587; x=1727319387; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=N3B5dAwAhj8gaFVNT9zRigA74sbZ4gkfU1dUdRFBfiM=;
        b=L+uF86yWyJA/+0IrGhe7FFJYLHhIHTc0XN2vwzw5aM3QYSqQWxHhkf9LW5BJ+l7g5r
         3xCyOeZ9QoyYGSSdnwuFSg5bFqd6/Rf+4JlQCnD5/0xeRxIPJ7VOWBd8cjfncvzsV7bF
         cvKrOEjvRJRSkTIrHiFSYoIfQN0b0jTqtj03Dtp5Ri104+AFXecFDLVrtI1T72p743Mp
         p8VzOgR1ODHTXqo+7RDoSB/upF2CGH9tuk4RpQ32PdpT54et9+Nrx42gTcgk0otDocPY
         aCgpZlk3ONYLkCk5beHiYpM5WuwDDS6cExWOaGG927C40FoENHZzDGUS/UDrNLps/7hc
         wgKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726714587; x=1727319387;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=N3B5dAwAhj8gaFVNT9zRigA74sbZ4gkfU1dUdRFBfiM=;
        b=bFZFMuPP4Lm7O6un3PUlB4r4HggOptbc7GfmtCB4OCxARPGGIdqM07XbSjlpbIU9hx
         nvdfvzwvb8mYA89E1xazE9sASES7045UeD33oVIvmeMs5SGekoEJhxvBc79885eXucQe
         VuOR5RLQgh5DYfz5wZkP5GVM+63EwWwDJsGgvk5VspOoCBbZTEvZgFfBLoDFKULmYmlJ
         70R71o8WkcL6UhEITDQavaPZW+ccvJXaucESSOpE35DIG3eMWIPe4dMRXP3p2CyY7SEB
         tUnE9dop3Kj3DKxokKPID8e3YqNnNWkwb1V49o/JEzEijPbjh75x0aDzPeFlewu2uhoj
         7Ycg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXl5vkmmt5pGM6cDf6fqaqQNfYO6cLYIabSQqIPWJCsCIgNrqgozsaThAUBLqqlhLu3+Wv+dA==@lfdr.de
X-Gm-Message-State: AOJu0YxkElxddNak+w9boYG3hMQco1OSGDYEyG1MYPHJyVWzAifWWxLd
	geD+T+/R+PnAbbxsrTVISOk1b1ZNWZ+5L0m412vsRP39cjsLXw4Q
X-Google-Smtp-Source: AGHT+IGtSPzuNEkOWtShI/eHBujjKheLzEpEL0HuRTK9vf9P3pLDOZyB7Z4SYVHyPRVm8AfdvpRRiQ==
X-Received: by 2002:a17:903:22ca:b0:206:a913:96a7 with SMTP id d9443c01a7336-2076e4616e2mr361492345ad.44.1726714586853;
        Wed, 18 Sep 2024 19:56:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d2ce:b0:205:909a:f7c8 with SMTP id
 d9443c01a7336-208cc01e1a3ls4732495ad.2.-pod-prod-07-us; Wed, 18 Sep 2024
 19:56:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXoTaAWnkXcCNrAJF0glKh0FQqKngj5hnQXwQLl3vVGXFWg4x5DoeV4+Dsm/rSkOPM5psknhd2t0UM=@googlegroups.com
X-Received: by 2002:a17:903:2281:b0:201:f8b4:3e3c with SMTP id d9443c01a7336-2076e36c158mr385579595ad.12.1726714585254;
        Wed, 18 Sep 2024 19:56:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726714585; cv=none;
        d=google.com; s=arc-20240605;
        b=V3lUNEVZrFmItnXbzg/o5r7mmy5XY9ZuJ79ZwWSev+w15/gEMdkRlnu4BUYfQKNcH9
         MYvAyzg6x6nIrVJNQntfWMIY8X+9jJhHSX/9nI24f+yTznkXijG1oxb/Q7FdczNjUnEy
         +CAKdXWyVlWVKb0sc+EI5xt2isUdpGIUXtgS+s9qlheNGgp3USy1uArgYoA/4H9E7C/d
         lmm6tkZhQaOMx4m6Km1WZfc3fBpJz7umVwxUcZfOeOZsicpsuH0qJO5uh7H6pmAhsUns
         /LkQyBrfnsGqVo0vyNPhoyJF6t7gkGrKiW6bdroe9jBQ4jkN1z0AYE3ulJpN9bFk/v/C
         UDAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=5GJhA0mjEPdtfqnf/P6njWML6hfKb60sWwrvJGKoU+s=;
        fh=H0hI2LCI8Ov6jJZlS6s2rg9Xu2FkzGnQ/hslIak9j4Y=;
        b=HcVQ70zUxzPtGoGn0eIVK07OrL/M4C4C5lzTwQJzFxN0iR0dDrKETyxE/adGtHWGiv
         mbVbLJbHGGHIeMBwdDz08igkmu+yzRNforJ2HjZWxlW55NBvGyNNZ5yZYpT0qWQ4BAgO
         XOupbICchYgdLQ26GSHx/XFKnQW+51CyCaK9Tc1/Xh1MfJ9LWGmewmy6ZfBR1kJ8YTxg
         frSnLzqjHy3VaJttP2M1I+JuEt1PVoyUeIUDGk76ZKmKoPbuOw1nBh+Y8aYE6G+DMJwl
         hdiUK1SrHZXOaZrtXQ1zwEJ3TAYPF48QSwzEq7QltZ09QttIGT5zUxde0zjx2tRAgHls
         Atlg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=eYXn7OXH;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62a.google.com (mail-pl1-x62a.google.com. [2607:f8b0:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-20794611769si4017855ad.5.2024.09.18.19.56.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Sep 2024 19:56:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::62a as permitted sender) client-ip=2607:f8b0:4864:20::62a;
Received: by mail-pl1-x62a.google.com with SMTP id d9443c01a7336-207115e3056so3701055ad.2
        for <kasan-dev@googlegroups.com>; Wed, 18 Sep 2024 19:56:25 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXo/aEEITxnAUdd5TcmhX5ZPIuwJ2aDi6ml+iiRY2K5HIx1hnA198p0gC/9e+m/9iGgVfQ5rtkSD3E=@googlegroups.com
X-Received: by 2002:a17:903:1252:b0:204:e310:8c7b with SMTP id d9443c01a7336-2076e3f7347mr313393475ad.34.1726714584737;
        Wed, 18 Sep 2024 19:56:24 -0700 (PDT)
Received: from dw-tp.. ([171.76.85.129])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-207946d2823sm71389105ad.148.2024.09.18.19.56.19
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 Sep 2024 19:56:24 -0700 (PDT)
From: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
To: linuxppc-dev@lists.ozlabs.org
Cc: Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Hari Bathini <hbathini@linux.ibm.com>,
	"Aneesh Kumar K . V" <aneesh.kumar@kernel.org>,
	Donet Tom <donettom@linux.vnet.ibm.com>,
	Pavithra Prakash <pavrampu@linux.vnet.ibm.com>,
	Nirjhar Roy <nirjhar@linux.ibm.com>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev@googlegroups.com,
	"Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
Subject: [RFC v2 00/13] powerpc/kfence: Improve kfence support
Date: Thu, 19 Sep 2024 08:25:58 +0530
Message-ID: <cover.1726571179.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=eYXn7OXH;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::62a
 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

This patch series addresses following to improve kfence support on Powerpc.

1. Usage of copy_from_kernel_nofault() within kernel, such as read from
   /proc/kcore can cause kfence to report false negatives.

2. (book3s64) Kfence depends upon debug_pagealloc infrastructure on Hash.
   debug_pagealloc allocates a linear map based on the size of the DRAM i.e.
   1 byte for every 64k page. That means for a 16TB DRAM, it will need 256MB
   memory for linear map. Memory for linear map on pseries comes from
   RMA region which has size limitation. On P8 RMA is 512MB, in which we also
   fit crash kernel at 256MB, paca allocations and emergency stacks.
   That means there is not enough memory in the RMA region for the linear map
   based on DRAM size (required by debug_pagealloc).

   Now kfence only requires memory for it's kfence objects. kfence by default
   requires only (255 + 1) * 2 i.e. 32 MB for 64k pagesize.

This series in Patch-1 adds a kfence kunit testcase to detect
copy_from_kernel_nofault() case. I assume the same should be needed for all
other archs as well.

Patch-2 adds a fix to handle this false negatives from copy_from_kernel_nofault().

Patch[3-9] removes the direct dependency of kfence on debug_pagealloc
infrastructure. We make Hash kernel linear map functions to take linear map array
as a parameter so that it can support debug_pagealloc and kfence individually.
That means we don't need to keep the size of the linear map to be
DRAM_SIZE >> PAGE_SHIFT anymore for kfence.

Patch-10: Adds kfence support with above (abstracted out) kernel linear map
infrastructure. With it, this also fixes, the boot failure problem when kfence
gets enabled on Hash with >=16TB of RAM.

Patch-11 & Patch-12: Ensure late initialization of kfence is disabled for both
Hash and Radix due to linear mapping size limiations. Commit gives more
description.

Patch-13: Early detects if debug_pagealloc cannot be enabled (due to RMA size
limitation) so that the linear mapping size can be set correctly during init.

Testing:
========
It passes kfence kunit tests with Hash and Radix.
[   44.355173][    T1] # kfence: pass:27 fail:0 skip:0 total:27
[   44.358631][    T1] # Totals: pass:27 fail:0 skip:0 total:27
[   44.365570][    T1] ok 1 kfence


Future TODO:
============
When kfence on Hash gets enabled, the kernel linear map uses PAGE_SIZE mapping
rather than 16MB mapping.


v1 -> v2:
=========
1. Added a kunit testcase patch-1.
2. Fixed a false negative with copy_from_kernel_nofault() in patch-2.
3. Addressed review comments from Christophe Leroy.
4. Added patch-13.


Nirjhar Roy (1):
  mm/kfence: Add a new kunit test test_use_after_free_read_nofault()

Ritesh Harjani (IBM) (12):
  powerpc: mm: Fix kfence page fault reporting
  book3s64/hash: Remove kfence support temporarily
  book3s64/hash: Refactor kernel linear map related calls
  book3s64/hash: Add hash_debug_pagealloc_add_slot() function
  book3s64/hash: Add hash_debug_pagealloc_alloc_slots() function
  book3s64/hash: Refactor hash__kernel_map_pages() function
  book3s64/hash: Make kernel_map_linear_page() generic
  book3s64/hash: Disable debug_pagealloc if it requires more memory
  book3s64/hash: Add kfence functionality
  book3s64/radix: Refactoring common kfence related functions
  book3s64/hash: Disable kfence if not early init
  book3s64/hash: Early detect debug_pagealloc size requirement

 arch/powerpc/include/asm/kfence.h        |   8 +-
 arch/powerpc/mm/book3s64/hash_utils.c    | 364 +++++++++++++++++------
 arch/powerpc/mm/book3s64/pgtable.c       |  13 +
 arch/powerpc/mm/book3s64/radix_pgtable.c |  12 -
 arch/powerpc/mm/fault.c                  |  10 +-
 arch/powerpc/mm/init-common.c            |   1 +
 mm/kfence/kfence_test.c                  |  17 ++
 7 files changed, 318 insertions(+), 107 deletions(-)

--
2.46.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1726571179.git.ritesh.list%40gmail.com.
