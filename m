Return-Path: <kasan-dev+bncBCM3H26GVIOBB76R6SVAMGQEVRV2RLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id AF4FD7F388F
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 23:02:40 +0100 (CET)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-6757f3d7911sf38172906d6.1
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 14:02:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700604159; cv=pass;
        d=google.com; s=arc-20160816;
        b=BRLmIAC1VZgsfmsZ1Ych/62qzzg0wqkQLkF2A2JPaa2xp6YU22VaPi2qCIQ25WOO35
         EYrF8Cqw/CRug4GWZa8ZlGaEOF+fwVan2mEHbAW4Zt7XoXsOHQs7kw8r6lJ3jmGYI1j4
         Pkn20kQgc3BdtqYo/PyHYqosgXDnHoYeD/EmOcIwsudibRTzEftslZoUVOfY3T46sYm8
         E5e19x9D5xiyaiPzxAM5dWF3I8+1fhuqEMUiGo3Gy4Bw8JwELwLzjixAeBumJ8nLFfTh
         sOuXj/E0iGHx/5h2nh1T8hVNibwsfIWvKL4hY7BWGw6ZfGB6tP/J7HV7IcPgPlaGaFeG
         gz2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=TdYsHoBvwDGyTRK6MTllksXmqsGZKtURTFYjmW0TYws=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=qGDJnXDi5gUyKwisePszBO7vUJJYWzUppWsr09BglMa/IoLZMfJ4AY1dWS5Ph+8DFf
         RQRp08KilSjxoiCsB5BlH62rS/sjFd2NeiFHxAQkKS8W7gLpjS+jUrIfDZvQHxYc3GnM
         sp3Bl3EZz+LEVHNCwUTmtIhXPTkUriEkCiWpgxKIFsM6y3WM7gUYcmN7H8j0biWoKDd2
         /ob3XWt11Ru9OrM8yRsjm9IB56znn6wiEot9ckhn7Dqxllkasw5IaODqddhPOi9c1yec
         U9kZJwXV4dr0jYQj+MZmTQoc0PXONEaUoKfHrBTU5KWSCReiRAY8B5EICc5y9FHsY02Q
         orng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=iiGY++jx;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700604159; x=1701208959; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=TdYsHoBvwDGyTRK6MTllksXmqsGZKtURTFYjmW0TYws=;
        b=D5otTE6MTkwzzlk+aEcP3Vl1NpmGuOEtscj9r8pp9Z8ORE1F3XuK7HI8PJNaN4z+bY
         hlLPlrHQHsdqMjM+xmxYG3P6OWz1LWadvvRgfL2m7+dzoqFyBMdq5myI4dzsjmP8gmCk
         CrdjL5X7PsWejzyURwCtmhddTEcTIEwJdpL6YkUVxeOgBfASOjnx9ZXuIb0FzE19Tiik
         hI5zW4ioyZL9iOImMlQnriKLkjpRBLI4EfkQqnSzTrw7BmxKk+4OjeqpZfSmwEvBuSKO
         gef18q/+yC7BugYwbWuFKbH3P5evM8Pg/ZJNzFnBMGSiwZQkiN+iJYBBqcoQPzH4+oa+
         kXKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700604159; x=1701208959;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=TdYsHoBvwDGyTRK6MTllksXmqsGZKtURTFYjmW0TYws=;
        b=SYOv04NYUAHKn1wj/ALhDV8N3UcHIRL9GtYdgUmGWL8cuA1oIAqa+iof2pccBqH7th
         pLFag0z4MuvMBx6EDtxNAOtisJrLSvfZrdSY9/MtGpQJy2s5BBO5EdmwtrUAf/0aSfYs
         5vN6o6vraGaQUIm4xBdc2l4U1IyVbnMSS5iZkS9+cAQuMELIgF4m6fxTDeDQiEUsPUBi
         gXlNypltne791RNBczNT1BUDOqBeMpKljgPsGsYNRrmBzkQddQ4iskCfj+j2yMWCTz+R
         12S+K1VDXVlL+jI5c0EMqeUwwDVweY4jSpgjX1wqUIOMv7HUrYgGGK0yX39WWx6zXu5+
         rJCw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Ywo5bcSzYq9AE2PFJidp0LwGWudQYIZLO3CLHNm67AbJefycJUl
	pu5Lu2dkgvKdtIohhrLwiLs=
X-Google-Smtp-Source: AGHT+IFS3FDPOq0PgEsZt1jAen6Z44afl8Sqxln5IfqRTi2JhwCqNdaNLWSHOukiHPIczuViqAtQfA==
X-Received: by 2002:a05:622a:92:b0:41c:d41b:1b99 with SMTP id o18-20020a05622a009200b0041cd41b1b99mr543958qtw.35.1700604159722;
        Tue, 21 Nov 2023 14:02:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5704:0:b0:41e:89db:3bf4 with SMTP id 4-20020ac85704000000b0041e89db3bf4ls902916qtw.2.-pod-prod-08-us;
 Tue, 21 Nov 2023 14:02:39 -0800 (PST)
X-Received: by 2002:a05:620a:a0a:b0:779:859a:5ef8 with SMTP id i10-20020a05620a0a0a00b00779859a5ef8mr356662qka.31.1700604158881;
        Tue, 21 Nov 2023 14:02:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700604158; cv=none;
        d=google.com; s=arc-20160816;
        b=gT7OKZPHhzVUhzMSRSZ3FlXc5Vcml9zj7WbfqC2tvWe6NAX2V+5LwGcm+Z0CN0fI5e
         fbhvv6imi5JxUipoYXluFsx7366wSnsiI2bXbPzWVWuTIPV3qUj313wE+Lq9DJsRZD/D
         8jSsHWXq4WXC2f7ov4h3n4dQzLwBoPv3QxV6So9IZzaeS2SFpteM4Au3EDz/PBGPWmDy
         10gBcYGRCdsDr9+47a7CN1N4romvdg4SiI3xjty51bH1k4MZwiMR3Qo/Ul0yiG9pckoy
         g4uM3GtZEa8jrTQWMWM78UqX92dQ3/WCUnIvRuxZQi0vmvkdfJ+//tq2lFY08BcEvofU
         Hs5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=RjV0VmLpgTE5xRgs1VZtKHdQWOiG339HDEHFOroOwi0=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=GFGX5EQ+/2v88wDSB0WRV3Mb1J7Op3wccMGr9bJY2RzYQfwaGSiLiXE0FmscCpAx54
         sv+bdbR+6Z2bHwCkn8bPkYRprrczkJpyRDu89Qvx3E7OE7Cjsw1849eh+vzhAQyy9J4d
         dd3wOoko2pb332HYzjydNsN3WNaEmAKlkiJBzNqS9B+j8z1oDmzcLP3HOWY+dFyrkJYL
         DnjFo4J77SG1S9bbA3UDIVAStJ2/OMl69HKLOL2sg9FOv5He9MpH/FDYcHYgx2LEbMJO
         SIcDlwJo6qlplQHvklLzaH6XAcgPuS1E3CSFsiLaVSBrib9qNGG+mT8OQHcdIeMItZZW
         zvGA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=iiGY++jx;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id bv20-20020a05622a0a1400b0041812c64692si1666287qtb.3.2023.11.21.14.02.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Nov 2023 14:02:38 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353723.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLNPPt004548;
	Tue, 21 Nov 2023 22:02:36 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4dw0vq3-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:36 +0000
Received: from m0353723.ppops.net (m0353723.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3ALLcJr7014500;
	Tue, 21 Nov 2023 22:02:35 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4dw0vcv-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:35 +0000
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLnQNN022908;
	Tue, 21 Nov 2023 22:02:05 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uf7kt3yyb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:04 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3ALM22eL40108430
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 21 Nov 2023 22:02:02 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 1122220065;
	Tue, 21 Nov 2023 22:02:02 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 923EB20063;
	Tue, 21 Nov 2023 22:02:00 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.23.98])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Tue, 21 Nov 2023 22:02:00 +0000 (GMT)
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
Subject: [PATCH v2 00/33] kmsan: Enable on s390
Date: Tue, 21 Nov 2023 23:00:54 +0100
Message-ID: <20231121220155.1217090-1-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: ueXSjJJuaiHBGWPQrdyNp8xXxndxHB57
X-Proofpoint-ORIG-GUID: luvmym5bCCb5oBro4vkAQpcqqUvW6UFi
X-Proofpoint-UnRewURL: 0 URL was un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-21_12,2023-11-21_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxscore=0 mlxlogscore=963
 spamscore=0 suspectscore=0 phishscore=0 priorityscore=1501 malwarescore=0
 clxscore=1015 impostorscore=0 adultscore=0 bulkscore=0 lowpriorityscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2311060000
 definitions=main-2311210172
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=iiGY++jx;       spf=pass (google.com:
 domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender)
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

Ilya Leoshkevich (33):
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
  kmsan: Introduce kmsan_memmove_metadata()
  kmsan: Expose kmsan_get_metadata()
  kmsan: Export panic_on_kmsan
  kmsan: Allow disabling KMSAN checks for the current task
  kmsan: Introduce memset_no_sanitize_memory()
  kmsan: Support SLAB_POISON
  kmsan: Use ALIGN_DOWN() in kmsan_get_metadata()
  mm: slub: Let KMSAN access metadata
  mm: kfence: Disable KMSAN when checking the canary
  lib/string: Add KMSAN support to strlcpy() and strlcat()
  lib/zlib: Unpoison DFLTCC output buffers
  kmsan: Accept ranges starting with 0 on s390
  s390: Turn off KMSAN for boot, vdso and purgatory
  s390: Use a larger stack for KMSAN
  s390/boot: Add the KMSAN runtime stub
  s390/checksum: Add a KMSAN check
  s390/cpacf: Unpoison the results of cpacf_trng()
  s390/ftrace: Unpoison ftrace_regs in kprobe_ftrace_handler()
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
 arch/s390/include/asm/cpacf.h       |   2 +
 arch/s390/include/asm/kmsan.h       |  36 +++++++++
 arch/s390/include/asm/pgtable.h     |  10 +++
 arch/s390/include/asm/string.h      |  20 +++--
 arch/s390/include/asm/thread_info.h |   2 +-
 arch/s390/include/asm/uaccess.h     | 110 ++++++++++++++++++++--------
 arch/s390/kernel/ftrace.c           |   1 +
 arch/s390/kernel/traps.c            |   6 ++
 arch/s390/kernel/unwind_bc.c        |   4 +
 arch/s390/kernel/vdso32/Makefile    |   3 +-
 arch/s390/kernel/vdso64/Makefile    |   3 +-
 arch/s390/purgatory/Makefile        |   2 +
 include/linux/kmsan-checks.h        |  26 +++++++
 include/linux/kmsan.h               |  23 ++++++
 include/linux/kmsan_types.h         |   2 +-
 kernel/trace/ftrace.c               |   1 +
 lib/string.c                        |   6 ++
 lib/zlib_dfltcc/dfltcc.h            |   1 +
 lib/zlib_dfltcc/dfltcc_util.h       |  23 ++++++
 mm/Kconfig                          |   1 +
 mm/kfence/core.c                    |   5 +-
 mm/kmsan/core.c                     |   2 +-
 mm/kmsan/hooks.c                    |  30 +++++++-
 mm/kmsan/init.c                     |   5 +-
 mm/kmsan/instrumentation.c          |  11 +--
 mm/kmsan/kmsan.h                    |   9 +--
 mm/kmsan/kmsan_test.c               |   5 ++
 mm/kmsan/report.c                   |   7 +-
 mm/kmsan/shadow.c                   |   9 +--
 mm/slub.c                           |  12 ++-
 38 files changed, 345 insertions(+), 74 deletions(-)
 create mode 100644 arch/s390/boot/kmsan.c
 create mode 100644 arch/s390/include/asm/kmsan.h

-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231121220155.1217090-1-iii%40linux.ibm.com.
