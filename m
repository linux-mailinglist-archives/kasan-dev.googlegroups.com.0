Return-Path: <kasan-dev+bncBDS6NZUJ6ILRB7EMW64AMGQEGAH57QI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 8650499DB86
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2024 03:33:50 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-2e3984f50c3sf21074a91.1
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 18:33:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728956029; cv=pass;
        d=google.com; s=arc-20240605;
        b=L/Ffd2IKhryFv8EA/GJJq0hbfmPH0PyVGqD5P9U6GBvHZkfyySrlCcIPvpfz06sLpw
         1DbfPH/T8Ujlrr3w4hj0AV08A4XGFa9jFh81+6oKSi95Tv3DnaQL+H6Q+JIlCdh4WmwO
         WaF6JFA90/MF7MBnRicn+fPnSVjOyrm1bZiuC+mshs+yV+CxKJ0TuaWzy6zSmsdAiVfS
         Y25XT0c/J8ez9PI0s6rTYjWtBhsU+cj1wjecB1F7GDUGwvxEJIyz84Vi3JEoEsMnd+5N
         FG383WgXdDqb8akqw/N+FYrjDQB33KT3mqXBHsv1bxLG2nwlOyVCSgTeCSrUN0AE58kn
         5S+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=AM+tWlEDoVY3SZVGc3HGpPTFJ8PJScQCJiPLYNDTdzw=;
        fh=ON2DRjQtp+P9P3fTiejJb+fZjy2VijUmwUbvgwKCkII=;
        b=PfwYcG60P8oW5cPBtBwztmPdDsjom8P2OuFn0oSIoy2mk2LMJ/wfO4lOxQQ71BQ5h5
         THvEs6SSQJh9KwtKwUy2hB92klMq59iu7Q/HMX5Iiq5xTWIM/d1TWO0nMOkMIEY15Jeq
         1JxlJSm3ltXPiZjKou0Y/Zmsnah6xqDrWXdWx3rEzoAVcUehdq6puPYSs5fw8f8lrl5w
         oTPpg+5FFh01ymJl3NmwGltVRfZ+rN6IFNrUXiPZYrhasi9GDcLottCjC79ERG5+75S7
         okZM5FUR3Sg9GSxo6eyXTHRPBtJvGPsBkXYP91UB0qE52dZW5i39Hty7MEk6dQTojh6b
         JTXg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=iPBoZgQE;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728956029; x=1729560829; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=AM+tWlEDoVY3SZVGc3HGpPTFJ8PJScQCJiPLYNDTdzw=;
        b=glVuv007hTO4ni/IQ8cqWBAO0VUqwj+7hK06EMa7MGV/kkjbPN64xmNNct1rnoY9VP
         kXY82PSXHKGNx2iDIndy/81i5wTkEY1rqVI8iznDPyLK2qbpbuJ4mWnTlBaFVhanGaNG
         9FqC7X7UpWKjK+yU8O4GCZxiHjFJvmD+yUMSnjS90N+M6NR3QXzsqFcWf1k69EYH1XAp
         jIXiEiSsSuvM7kVoyJN+b9Qdw1h8wEqQQN/hN4RaprWHjlkISGqHYr4Z7gtQrGHpdGng
         k/0k7mMRXAtQi5WMJGDosjoewyslq8H8O/UTOUPc86mvIN82ZcJsmEuymnyuFJRiDUrv
         o7Ww==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728956029; x=1729560829; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=AM+tWlEDoVY3SZVGc3HGpPTFJ8PJScQCJiPLYNDTdzw=;
        b=G/6LoyUqmYvvPOSCcD9EPxACdHT2tKUDECRrPDmAJOHFx0setnOLGqhdRAfkG0IN3S
         +wQqjIU+QmaZA2OtFDucAbt99NuwCtx6oElMB7JbO0koZU5VSvnQiAx4E0mDN9752Gq8
         3sLlVK+NezvLnBfq8ajnh5Y0eQDFkygmCd104Gnr0u6wSfQ59o+nn4BGk8xxlMwOuO52
         IGLT8G3tvf5G3QXwXAPBPiKf9JKSsSmySIN8PFvg/CzAi/+5BAt4wOohKAiYO80a9ar+
         FNHLNn1Bx+KFs3m7OdYgFveAQ9U168j0Kc/eD2AamHSdcEqxzFTUV8zj/QLYmTuVrKFu
         xOZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728956029; x=1729560829;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=AM+tWlEDoVY3SZVGc3HGpPTFJ8PJScQCJiPLYNDTdzw=;
        b=HI+E0FGXOo83+kxw88O3I11B4enLPBnCnCwKiY60ojKI/LopzvgMioKQeZEDn3OLw1
         Mb+YLqujij4eOGDCwHLW1hhy3Z/8J7jn5WXmYLdTeqPCbpfo8Sgg/TTijRckj9TpOBVq
         VdgyJV9alYeqtS+fo/w0f74hSxndcIbEgznBBaejibyknuJ7G3tQYV6AV4xTzzJgWDVm
         OfYYlL7JVPgOnwUjIK2md5V7VsSaa1X4bEUx1ZMTSkp0yyynWh3izhvQyBdTo5LXBa0q
         Y1/bWZ+SmTsO4ARAtkAtYgmzTYNV+3N1465tccFhoE0g79Lc6LrXECrj38wUf9TuWXFb
         Nswg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV21t4nhReFN+LS4jWcXnlqaKZNtmHjZGK2BbEYTOpu8ut1FhtGuZ8/EFABHZ87rGJ+rmy4vw==@lfdr.de
X-Gm-Message-State: AOJu0YzdLtkKpVjIkUgZ1iVdNhvqtncEvImgndfbCXzEDhTJ7aYzoqP9
	W0K0AOA2LVN6mYrdZbcy4fnyX/ykr5VZHj7Am/fYnGYEcJVtmjbL
X-Google-Smtp-Source: AGHT+IE2kO3JvLu/o+a9nO4LBfNUFuyLRJUCS8pmDXA8YTxMzFYIQqgPrFHOgCZas2ChQkwbnQlIsQ==
X-Received: by 2002:a17:90b:4b8b:b0:2e2:9077:a3b4 with SMTP id 98e67ed59e1d1-2e3151b8a44mr13136611a91.7.1728956028578;
        Mon, 14 Oct 2024 18:33:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:1908:b0:2cb:5bad:6b1a with SMTP id
 98e67ed59e1d1-2e2c81bcaf6ls1511323a91.0.-pod-prod-05-us; Mon, 14 Oct 2024
 18:33:47 -0700 (PDT)
X-Received: by 2002:a17:90a:db97:b0:2e2:e769:dffe with SMTP id 98e67ed59e1d1-2e31535385emr13480956a91.30.1728956027140;
        Mon, 14 Oct 2024 18:33:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728956027; cv=none;
        d=google.com; s=arc-20240605;
        b=SSR8U/vLeBkUYDVEJO2oENEMXK4syRMiZ5NUf3HEIyJ2zilF5Tqmo5J3WfTl9TRhhK
         ROu17YTEe0tgq9d9/Dybs1FF6Xhg3U4E7PCnLrO8zNX8aq8j+TmrpYUZCUBX6/LFX4Df
         8veaC+ccda5Evu7Zl9ozGXm9hr3pwHuGr9hQEBZE5BOJwDvySISDI9Mfl10UlDpkWBjR
         PDKDZbTVivr5VClYJPThMLz+KFt+FFk3zE+YByoR++aa5hnrCoNe2645Lav1JKznZya4
         Jy4kxT3rHJV0wWZEtZj6n9IUM+TTwCHvKIy8LB5mZ8kCVR3FbN1jwOmVje7Ym2qN6hzK
         Z71Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=/FgRTRf0le7Jh2w75CMwMOtbUSojhg+y46VXsqNVeW4=;
        fh=Bj4mozzLk9zJsLtJNyH+nEsVaBAd92VPaXopXx18a2s=;
        b=GDOoA4UkzEWS8YOArJMGzXjGCM0aEgubHnvR7ooTCA6jut/im7iDQTNS40MMNOoXTz
         CiY6tXz7MpL5eMrrHvFu5QrIPUqjlah6C15bqi1Z3YsRAHGouo4eJ6pTXXV8WU+p6AHn
         MX44+nPK+BR/isdvWEDhtJJEZ3BdYXs56OcpuibrFm+FXGng2sdNB20C9XGepXmXr26p
         3UH2/efYYndgd24uM7mOJz1ZzDgZqpqXTr7Aj2KEBTqQhGzVdNfk9ae9iTAQe/tTHXl1
         AkRaG24TIDyqEo+pxua8Ztqjih1gsctCH28mDi1BlDZdBolihcQzlqi0DktPdhza+Opl
         Z+zQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=iPBoZgQE;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52e.google.com (mail-pg1-x52e.google.com. [2607:f8b0:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2e2d3f64eb1si1045458a91.1.2024.10.14.18.33.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Oct 2024 18:33:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::52e as permitted sender) client-ip=2607:f8b0:4864:20::52e;
Received: by mail-pg1-x52e.google.com with SMTP id 41be03b00d2f7-7e9fd82f1a5so3093507a12.1
        for <kasan-dev@googlegroups.com>; Mon, 14 Oct 2024 18:33:47 -0700 (PDT)
X-Received: by 2002:a05:6a20:9f4a:b0:1d5:1729:35ec with SMTP id adf61e73a8af0-1d8c955c8ebmr16914023637.7.1728956026633;
        Mon, 14 Oct 2024 18:33:46 -0700 (PDT)
Received: from dw-tp.. ([171.76.80.151])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71e77508562sm189349b3a.186.2024.10.14.18.33.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Oct 2024 18:33:45 -0700 (PDT)
From: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
To: linuxppc-dev@lists.ozlabs.org
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Heiko Carstens <hca@linux.ibm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Hari Bathini <hbathini@linux.ibm.com>,
	"Aneesh Kumar K . V" <aneesh.kumar@kernel.org>,
	Donet Tom <donettom@linux.vnet.ibm.com>,
	Pavithra Prakash <pavrampu@linux.vnet.ibm.com>,
	LKML <linux-kernel@vger.kernel.org>,
	"Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
Subject: [RFC RESEND v2 00/13] powerpc/kfence: Improve kfence support
Date: Tue, 15 Oct 2024 07:03:23 +0530
Message-ID: <cover.1728954719.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=iPBoZgQE;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::52e
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

Resending v2 for review comments.

This patch series addresses following to improve kfence support on Powerpc.

1. Usage of copy_from_kernel_nofault() within kernel, such as read from
   /proc/kcore can cause kfence to report false negatives.

   This is similar to what was reported on s390. [1]
   [1]: https://lore.kernel.org/all/20230213183858.1473681-1-hca@linux.ibm.com/

   Hence this series adds patch-1 as a kfence kunit test to detect
   copy_from_kernel_nofault() case. I assume the same might be needed for all
   other archs as well (Please correct if this understanding is wrong).

   Patch-2, thus adds a fix to handle this case in ___do_page_fault() for
   powerpc.

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

Summary of patches
==================
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
rather than 16MB mapping. This should be improved in future.

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1728954719.git.ritesh.list%40gmail.com.
