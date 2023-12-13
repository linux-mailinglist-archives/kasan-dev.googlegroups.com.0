Return-Path: <kasan-dev+bncBCM3H26GVIOBB5775CVQMGQEIUA74PQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id F3D308122EB
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 00:36:24 +0100 (CET)
Received: by mail-pf1-x43b.google.com with SMTP id d2e1a72fcca58-6cea5fce6c9sf8833769b3a.0
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 15:36:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702510583; cv=pass;
        d=google.com; s=arc-20160816;
        b=y9ub8VpOD0mleI0EwrcRlE4+kQaT5L4fZlu+8ka9laPzaeoV/iouAP3n/pWHBfiR28
         y2y4SdlIRIyb1ydh1tTxNzmcxa4teCHgvr6tHyPg8VWbS1kiB3QZwLYUb51HEErrfyqU
         Yb94CpkIhCO7jUw7qx7oqotFV54OvNh3WNfbRVayg6aUaXc/5ZhZ99tt7f4+BjJGAw0B
         7LbNt0giCsZ1VuftDKBEmTGsTc7hfl/1CKtzUM7m089EJu5vSEug+7MTUNrw+EAUfTit
         NXLWLFryTWfnDphcpg3FTNGi+nKxe5W/rhyBfimNTCMVuklfaMtWhe5IyYDm5aew6+18
         BLRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=J1vbOQiMDZBNob3OC8i1Nwfw4nn90ho1gK4VG8/fPmc=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=VMdIi4FtIU9Chmb8joFMSPt6+zaW9nDJIclDFxD7AgihZJyRLBfha0DYy1BrJBtcjT
         /jIxbSM6yuMS/alIvJC9VgZyKKFSoKXR5yRJ6zHWfJe+QwlTDEaSZDS7j6PEW43cRiN2
         JHVqtSG10KSZ+hbp+QCcWS9iZalZwpLJB+1Hv5OIMi4CfdGBKSmzijLNdwb6BK5Mk7V6
         O/2QJb/JwsVkJnoB4En+d0ZhHqe9rfviQt1FM3VZ7oB3XzVWIDArgmZgSNllfsehK4ax
         WXQcruPaZpNihDQbyn7iiuCRFPDEftP5abKJiYpjQhilnZ4cCmmvONjB4WphbT8NYE/u
         cB4g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=N6W1XFpH;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702510583; x=1703115383; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=J1vbOQiMDZBNob3OC8i1Nwfw4nn90ho1gK4VG8/fPmc=;
        b=OyzJVxRi7sH9RyOSXcQJZE+e3Z131uhKIM7C5OU5trn7MXmOVP121XaWXF2s4y+gk+
         fGOEJOiFoTFJVJ26PUz9DpHIjasgTr2Qilgw0R54nGMC+jWsfIk8tjBFXNq/ZBRlw8Ih
         wS6f9A+u721UUEYwfToF8YUKgwuN+xzxZ0lc5ujrmhxn/6Vgjlw8UL7YkYvPAdA2EUx+
         1XTOrlO8B0k04JpUPDyT65iY5UHb3XsN4mLBu8wrBtBIuX2IRLpA9Gzzq0DkZAkra2VA
         HYQ9zqdQMYhshFDEJgiOCFWu8wW6dF2qfMyBX/7TXB8FmKeEyih3trnZRQ8dWLZDK2Pq
         yJPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702510583; x=1703115383;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=J1vbOQiMDZBNob3OC8i1Nwfw4nn90ho1gK4VG8/fPmc=;
        b=ehuYOq+UdZD/tuUr2HLFKYrn1ny2vu7fcCE6liJqarlwtcQ/R4G/5VPAmb3TiCQyz/
         y3Dme6NjLvasICHB1Tobk5c1ZWyTKwUS5xoXmM3uIIU84uMno2BvUPMyIBXjTyaKLti7
         03vQ+K3RnV+fBX4ISo+6ogOxSWzaq4QvL9Km3PpFb5XOFIxYUZruxwNJvhLXWj7T1pe4
         4PuQiz7RgoWk6NRIyY8ZoBuSoc25J4NyGXVXlnKAQ8jRuPBtmZ+jjknYszODAiqP+rNs
         UsQFx4r2Gbj6Wws0jl1cxeM8ulvLZuWsYLZ6OOvC0RyHEFymLQRBCtW4uIjMMRY2681H
         lt5w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwxED0/Iu/yw6awnGsBQSGUwErk/FfB8HSdFOEdkVt/HNjX63zu
	rQWlcs6mJv0OuBUEFCpKrVU=
X-Google-Smtp-Source: AGHT+IEZy86Bq96TV1MVel69KOzqxkJXto9V2QnDaH9/Ez7IAXA9/kVHo2kEtCn2Kf7Pye6/o48mSQ==
X-Received: by 2002:a05:6a00:4b0e:b0:6be:25c5:4f74 with SMTP id kq14-20020a056a004b0e00b006be25c54f74mr10675501pfb.13.1702510583371;
        Wed, 13 Dec 2023 15:36:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1d8c:b0:6ce:2ffb:18d with SMTP id
 z12-20020a056a001d8c00b006ce2ffb018dls2375679pfw.2.-pod-prod-08-us; Wed, 13
 Dec 2023 15:36:22 -0800 (PST)
X-Received: by 2002:a05:6a20:1604:b0:190:3b35:5999 with SMTP id l4-20020a056a20160400b001903b355999mr11719098pzj.9.1702510582341;
        Wed, 13 Dec 2023 15:36:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702510582; cv=none;
        d=google.com; s=arc-20160816;
        b=vUhUGOwuQmF3kvGfGK4p6ha1ILxhwZPrp2gQpU4Zca+IFSz4mjmnOQA6OjB3GHKbco
         OZuz8LDHcZ0wqfWL3D5c8INY5a/Jgf3TVJRCTmLDikkjGrqkbtRrJFPp7PZvQ2NbKFwr
         LYK+PFVxyvo7Wy38eBMHAdp+RCLALnKSw/64OiCsA1XBDblHKHZk0SZbKmXG1+Gagvz3
         d6O7hmuAJA77J3n6+UVi+LHMHQmDFMRX8On2dgrJRlmdSMZ0eDFhVYciO54TPdrObgTn
         nhbQS9SNq/VXcLSY9QIIvm6fPPwP+Sx9VM8730ls4tzCDW/j8RrkP8z66+QWsr4bVnfs
         TEBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=1sqwURtrRmpH1GSUKQpPj5IkE7uQ5w4CTeMN57eEciQ=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=YDIK7OPPYrNFtd0Jz0jqkxC0zNVchpUug1uBoTZmtvdCm150ko9iYNE8z/bWYWp8+B
         hv6Cffm+NW29gcSZdyB3q5aeuHO2Lb5RteLAHxW/5UI04iEuzwNskbNCG934HloSS5Ll
         rmysetUWicpBQHCSFSNJG6RN9tFGYZZa0gK9x4Jub2+QktyrYfsT0iyw/MUk0c7J/Pyt
         q/bLLmFpfNtYqFdx+9t8qTGypGRAiSGQAccwvNuimGQzBN35Em8JLGEGiaVTS4J+b3jJ
         nQQgXVv1zyO6/WNy7laDdczFFxYa1yum94hbhy9nJzZilXWqOWoq5Dq+sVBkK0LL0/wl
         nTDw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=N6W1XFpH;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 34-20020a630d62000000b005bd70dedbc3si950168pgn.1.2023.12.13.15.36.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 15:36:22 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDKbIKL023765;
	Wed, 13 Dec 2023 23:36:17 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyktbv0q0-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:17 +0000
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BDNCtRu028993;
	Wed, 13 Dec 2023 23:36:16 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyktbv0pc-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:16 +0000
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDGkI3H014819;
	Wed, 13 Dec 2023 23:36:13 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uw42kg1x2-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:13 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BDNaAMr44237472
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 13 Dec 2023 23:36:10 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 18DFE2004B;
	Wed, 13 Dec 2023 23:36:10 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A01C320040;
	Wed, 13 Dec 2023 23:36:08 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.171.70.156])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 13 Dec 2023 23:36:08 +0000 (GMT)
From: Ilya Leoshkevich <iii@linux.ibm.com>
To: Alexander Gordeev <agordeev@linux.ibm.com>,
        Alexander Potapenko <glider@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
        Heiko Carstens <hca@linux.ibm.com>,
        Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>,
        Masami Hiramatsu <mhiramat@kernel.org>,
        Pekka Enberg <penberg@kernel.org>,
        Steven Rostedt <rostedt@goodmis.org>,
        Vasily Gorbik <gor@linux.ibm.com>, Vlastimil Babka <vbabka@suse.cz>
Cc: Christian Borntraeger <borntraeger@linux.ibm.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com,
        linux-kernel@vger.kernel.org, linux-mm@kvack.org,
        linux-s390@vger.kernel.org, linux-trace-kernel@vger.kernel.org,
        Mark Rutland <mark.rutland@arm.com>,
        Roman Gushchin <roman.gushchin@linux.dev>,
        Sven Schnelle <svens@linux.ibm.com>,
        Ilya Leoshkevich <iii@linux.ibm.com>
Subject: [PATCH v3 00/34] kmsan: Enable on s390
Date: Thu, 14 Dec 2023 00:24:20 +0100
Message-ID: <20231213233605.661251-1-iii@linux.ibm.com>
X-Mailer: git-send-email 2.43.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: 561mDTmsINwMN72Ah6BOtZlL15AzLfxe
X-Proofpoint-ORIG-GUID: Ogx47gAVtFngw5Il2WLfvhq0DJQYKCB0
X-Proofpoint-UnRewURL: 0 URL was un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-13_14,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 malwarescore=0 impostorscore=0 clxscore=1015 adultscore=0 phishscore=0
 mlxscore=0 bulkscore=0 suspectscore=0 spamscore=0 mlxlogscore=999
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2312130167
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=N6W1XFpH;       spf=pass (google.com:
 domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender)
 smtp.mailfrom=iii@linux.ibm.com;       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
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

v2: https://lore.kernel.org/lkml/20231121220155.1217090-1-iii@linux.ibm.com/
v2 -> v3: Drop kmsan_memmove_metadata() and strlcpy() patches;
          Remove kmsan_get_metadata() stub;
          Move kmsan_enable_current() and kmsan_disable_current() to
          include/linux/kmsan.h, explain why a counter is needed;
          Drop the memset_no_sanitize_memory() patch;
          Use __memset() in the SLAB_POISON patch;
          Add kmsan-checks.h to the DFLTCC patch;
          Add recursion check to the arch_kmsan_get_meta_or_null()
          patch (Alexander P.).

          Fix inline + __no_kmsan_checks issues.
          New patch for s390/irqflags, that resolves a lockdep warning.
          New patch for s390/diag, that resolves a false positive when
          running on an LPAR.
          New patch for STCCTM, same as above.
          New patch for check_bytes_and_report() that resolves a false
          positive that occurs even on Intel.

v1: https://lore.kernel.org/lkml/20231115203401.2495875-1-iii@linux.ibm.com/
v1 -> v2: Add comments, sort #includes, introduce
          memset_no_sanitize_memory() and use it to avoid unpoisoning
          of redzones, change vmalloc alignment to _REGION3_SIZE, add
          R-bs (Alexander P.).

          Fix building
          [PATCH 28/33] s390/string: Add KMSAN support
          with FORTIFY_SOURCE.
          Reported-by: kernel test robot <lkp@intel.com>
          Closes: https://lore.kernel.org/oe-kbuild-all/202311170550.bSBo44ix-lkp@intel.com/

Hi,

This series provides the minimal support for Kernel Memory Sanitizer on
s390. Kernel Memory Sanitizer is clang-only instrumentation for finding
accesses to uninitialized memory. The clang support for s390 has already
been merged [1].

With this series, I can successfully boot s390 defconfig and
debug_defconfig with kmsan.panic=1. The tool found one real
s390-specific bug (fixed in master).

Best regards,
Ilya

[1] https://reviews.llvm.org/D148596

Ilya Leoshkevich (34):
  ftrace: Unpoison ftrace_regs in ftrace_ops_list_func()
  kmsan: Make the tests compatible with kmsan.panic=1
  kmsan: Disable KMSAN when DEFERRED_STRUCT_PAGE_INIT is enabled
  kmsan: Increase the maximum store size to 4096
  kmsan: Fix is_bad_asm_addr() on arches with overlapping address spaces
  kmsan: Fix kmsan_copy_to_user() on arches with overlapping address
    spaces
  kmsan: Remove a useless assignment from
    kmsan_vmap_pages_range_noflush()
  kmsan: Remove an x86-specific #include from kmsan.h
  kmsan: Expose kmsan_get_metadata()
  kmsan: Export panic_on_kmsan
  kmsan: Allow disabling KMSAN checks for the current task
  kmsan: Support SLAB_POISON
  kmsan: Use ALIGN_DOWN() in kmsan_get_metadata()
  mm: slub: Let KMSAN access metadata
  mm: slub: Unpoison the memchr_inv() return value
  mm: kfence: Disable KMSAN when checking the canary
  lib/zlib: Unpoison DFLTCC output buffers
  kmsan: Accept ranges starting with 0 on s390
  s390: Turn off KMSAN for boot, vdso and purgatory
  s390: Use a larger stack for KMSAN
  s390/boot: Add the KMSAN runtime stub
  s390/checksum: Add a KMSAN check
  s390/cpacf: Unpoison the results of cpacf_trng()
  s390/cpumf: Unpoison STCCTM output buffer
  s390/diag: Unpoison diag224() output buffer
  s390/ftrace: Unpoison ftrace_regs in kprobe_ftrace_handler()
  s390/irqflags: Do not instrument arch_local_irq_*() with KMSAN
  s390/mm: Define KMSAN metadata for vmalloc and modules
  s390/string: Add KMSAN support
  s390/traps: Unpoison the kernel_stack_overflow()'s pt_regs
  s390/uaccess: Add KMSAN support to put_user() and get_user()
  s390/unwind: Disable KMSAN checks
  s390: Implement the architecture-specific kmsan functions
  kmsan: Enable on s390

 Documentation/dev-tools/kmsan.rst   |   4 +-
 arch/s390/Kconfig                   |   1 +
 arch/s390/Makefile                  |   2 +-
 arch/s390/boot/Makefile             |   3 +
 arch/s390/boot/kmsan.c              |   6 ++
 arch/s390/boot/startup.c            |   8 ++
 arch/s390/boot/string.c             |  16 ++++
 arch/s390/include/asm/checksum.h    |   2 +
 arch/s390/include/asm/cpacf.h       |   3 +
 arch/s390/include/asm/cpu_mf.h      |   6 ++
 arch/s390/include/asm/irqflags.h    |  18 ++++-
 arch/s390/include/asm/kmsan.h       |  43 +++++++++++
 arch/s390/include/asm/pgtable.h     |  10 +++
 arch/s390/include/asm/string.h      |  20 +++--
 arch/s390/include/asm/thread_info.h |   2 +-
 arch/s390/include/asm/uaccess.h     | 111 ++++++++++++++++++++--------
 arch/s390/kernel/diag.c             |   2 +
 arch/s390/kernel/ftrace.c           |   2 +
 arch/s390/kernel/traps.c            |   6 ++
 arch/s390/kernel/unwind_bc.c        |   4 +
 arch/s390/kernel/vdso32/Makefile    |   3 +-
 arch/s390/kernel/vdso64/Makefile    |   3 +-
 arch/s390/purgatory/Makefile        |   2 +
 drivers/s390/char/sclp.c            |   2 +-
 include/linux/kmsan.h               |  33 +++++++++
 include/linux/kmsan_types.h         |   2 +-
 kernel/trace/ftrace.c               |   1 +
 lib/zlib_dfltcc/dfltcc.h            |   1 +
 lib/zlib_dfltcc/dfltcc_util.h       |  24 ++++++
 mm/Kconfig                          |   1 +
 mm/kfence/core.c                    |  11 ++-
 mm/kmsan/core.c                     |   1 -
 mm/kmsan/hooks.c                    |  23 ++++--
 mm/kmsan/init.c                     |   5 +-
 mm/kmsan/instrumentation.c          |  11 +--
 mm/kmsan/kmsan.h                    |   9 +--
 mm/kmsan/kmsan_test.c               |   5 ++
 mm/kmsan/report.c                   |   8 +-
 mm/kmsan/shadow.c                   |   9 +--
 mm/slub.c                           |  17 ++++-
 40 files changed, 360 insertions(+), 80 deletions(-)
 create mode 100644 arch/s390/boot/kmsan.c
 create mode 100644 arch/s390/include/asm/kmsan.h

-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231213233605.661251-1-iii%40linux.ibm.com.
