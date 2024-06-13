Return-Path: <kasan-dev+bncBCM3H26GVIOBBQVFVSZQMGQE5ONMZNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 369849076D1
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 17:39:48 +0200 (CEST)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-24c501a9406sf824847fac.3
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 08:39:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718293187; cv=pass;
        d=google.com; s=arc-20160816;
        b=A2P+ubpM9OjlbaQ2Uh8VXWAHQxsOQWk0tFRiPe/3BYT2Wy3YrnPLFtiv1OzkSI45ww
         jjL9sQ3zRuViUgiwUAiYfbrRn39atBRRYULcoz311lmonRgf/n+VDwtdVRafOYh3l6Xa
         gXTzdpYxroUne9zl8M1J2jLOetF7i7k8ffN6o12s+zMrrFhbfzzO92sZSntXFlIExfyV
         iEf2hZ9ByF3jxYfnCAF9KzPl58n3SkGV4CMH9KTAW7Sa01s77RcceIZulHo5ksO3c0Zp
         OoQZ9pE3ahrN5btuo8b6cL070gLzlKEFmGoGGQlhvB4O1TBK5nVj3eptBvZDbGih+cIb
         LKdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=bAN0C/q+RVeZlk4mEP+GNXxCzYmrkNAFPFBg2S+gpd8=;
        fh=oHGvBoUCsc6bG73n9C2BpjfedQRCU9Jmpq07WCDGlS4=;
        b=rCkFLuxbTSAGMRfPTqI3FaDjgFVN9mfX9W2xXgs/0IP3J4TmCpK06n7/zKgTyUNjmu
         GGNky1Xr+kNnGSfP2/xLVwrJ/3pXVOFK/D5TgdjA8X7g6G4s5IsFbRPDGzYc4UjYs0hF
         6ssGNbRU2VdRX4gYbWqP7D5s1cZa2+vaalHOlw2C9ULOqgsHjnQgSh8DiCXVFQzobA/p
         VHCoHmMEtdeRiP22vZcFf8NueOBh6Z32ELMAX/3Pk4TkX8R1WLtn25iB8Hv0xRIvUfUh
         be/swCVuu5jNmF+DuYxkDaeNSLwDh9Ww2xTbjVngtQ4NjH5b4EC3Vo+wTgObAj0yZyIj
         4vXw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=H2sbdGrW;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718293187; x=1718897987; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=bAN0C/q+RVeZlk4mEP+GNXxCzYmrkNAFPFBg2S+gpd8=;
        b=lQMVYqph0aiGmGM3XkBJzxhsb8hMcjcqx0Gfwu8XXfFCrmgFDIDPakr9jDdkzYBzGX
         xsSJPit+Xtx/WGu12TZ7W7ibcjotZ/1xjVN+M5Qkkqob6hDY0IvpJ8YrYibfJ17DU6bR
         b9J37Uxs/DSGuBOX5GfbFzR3scChfOC/X+dDTtJZyXen47xFibMLVAVNjgl2yd5G00iX
         nTo0tkffcG/0hAct2dBO7Ojujvs7dcgm5HTwJ2O2axdKxBcE2VM37N4pw3NEWfi27icY
         Pr7nnJMAU/65/NxIs+IfPmwXeSznW7iEYjT+no1/82M6cjrX8WCndoMKwnCglQmRAI0O
         u73Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718293187; x=1718897987;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=bAN0C/q+RVeZlk4mEP+GNXxCzYmrkNAFPFBg2S+gpd8=;
        b=fW+NtCIDs8qiUElzbXxW1WFAyVUmoQFYgN7nN3vb8CR8JXGebvtJRLV24G2Yo5QWC9
         3ua1aaLi9r756bfwA87iQwwORWnx2imzOst/helU55w24nh4+4NHqLd+c5e30r98unY3
         u4TfAsVkqGvPek+Y2WJSvFKMl8ciuedNxoneHza7kPEkkRsSYohyLPDkcdfh1nKtGZSU
         ahOPQY9RGcxij3vNsPw+wy0UZdmHSIQrZ9mWj3mz2NocBfDnqBFQRqq+4woQ4KPQgdAd
         QQ0Y3sab7COPyd1aGFARXMDFo4lWXhitJNRQuvInAqGwhiN9ZfWBJvggVJGIwcbzhe7e
         4ScA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUQw2/sJ+qFtNiiMiimCn+95cn1O2y3iAlxi2FDnHKbdsM0hep0Z4Yx/hgviXY8o4ifvuQRO+haHV5agMgHP2z2xZ7ZCSVSaw==
X-Gm-Message-State: AOJu0YyOu5eVcdlmoR55nEwSp/yd15y7ib4bZypjgILG7PXinTG1EbWW
	7RQYioo1LsVE4Z6MbpvQb7bpBjD5NI7f4QG1qUirTQNpKdsYbjUS
X-Google-Smtp-Source: AGHT+IEM1glv033zU2CqqhzTERzPq1T8rBv81Y1L3UVvbzd1jH4m+1s5KEwN2MoF7LdxWEgTkaF95Q==
X-Received: by 2002:a05:6871:b21:b0:254:9ff5:a032 with SMTP id 586e51a60fabf-25514fb50bemr6073481fac.47.1718293186442;
        Thu, 13 Jun 2024 08:39:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:718f:b0:254:6df2:beae with SMTP id
 586e51a60fabf-2552b6aac4cls1146160fac.0.-pod-prod-04-us; Thu, 13 Jun 2024
 08:39:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXcdSG26x5gOJroMMMJGb++EVlP1UGfLbKjwg92uT13Tpe4tJj8Mq+CouSJTKG4/gcArWN0oM5WYht5al93NB5e8CSd03S8+6qftg==
X-Received: by 2002:a05:6871:5b13:b0:250:6be5:1fc5 with SMTP id 586e51a60fabf-25514f321bemr5922631fac.38.1718293185455;
        Thu, 13 Jun 2024 08:39:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718293185; cv=none;
        d=google.com; s=arc-20160816;
        b=B8pEG34Q3Lo9OPVoxg6EpMIIyEaE+AWLDfTV0wJpOF8tXrsLxdpOUxHYpk4ZsUG5Ac
         UEJe38VLfUbGqziexgPNTTCo7rT1AJvdFZTIBIV0NcWqthCPgHbW/E9YE8A3+Db4Su/c
         ONJAE/orcSpOervhs8QbVfPSIOSgSu16ThojGuPFNAT2nnZ9N7kC5I2eVl2DCoi9UYxG
         Vj6QUTVtVxbEnoLFoJOEy4j3uyDNyxXDX2jVh6JxqvE0YefPKfjhTkdd06AY4vrEuq4c
         Z4tzgtJjIen/e4N8Pyul7bbysrhXcvRy/kGU8Ib2LI+jBvHNADGBMGuPJkWKP2Ge7vZy
         T3oQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=gbdYbORHBggEAMihYZ79uciBWOZ8cFup1GK6fqgEVTE=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=zfS0mnfi5yqdJgWrTbnRXngSYRBNWEB51nhbbSuBCR18II6kkF8Dj0jKxMkb6GNmJ4
         AEySGcug13xpfXueKJG2DVCmkSZBQOOYR9auE5RjYksvREWR6aAHTmFp2Mk8E5+d137Z
         pvv1ZDjm+Lfcxp9rwRmU+L3syhNVlCcWzby4bACgHl4lzM84dqlZCqfckvN0daQkZy+p
         mvJOGs4zPbzl/gjedMg15z/KE2Qe9D1MfSIhYgdw31mUFnkUWfcxoEY3YBVWQQa38VIr
         hGcbPMTXksr8/K3L3GFY74vkZLJd/0p9BJVbccG8qGZwLJwQhRnw46QG/LsUMuiC5BZE
         bStw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=H2sbdGrW;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-6fb5ba85bbcsi77694a34.5.2024.06.13.08.39.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 08:39:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353726.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45DFPivk001998;
	Thu, 13 Jun 2024 15:39:40 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqq4rt36b-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:40 +0000 (GMT)
Received: from m0353726.ppops.net (m0353726.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45DFddrD026714;
	Thu, 13 Jun 2024 15:39:39 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqq4rt365-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:39 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45DELP7M008731;
	Thu, 13 Jun 2024 15:39:38 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yn4b3rk01-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:38 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45DFdX3C33292934
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 13 Jun 2024 15:39:35 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id E24412006A;
	Thu, 13 Jun 2024 15:39:32 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 60CDD20065;
	Thu, 13 Jun 2024 15:39:32 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 13 Jun 2024 15:39:32 +0000 (GMT)
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
Subject: [PATCH v4 00/35] kmsan: Enable on s390
Date: Thu, 13 Jun 2024 17:34:02 +0200
Message-ID: <20240613153924.961511-1-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: qnmHc0KAbWUlA4xk_JpMbkaaf2iKvy9B
X-Proofpoint-GUID: yJiNbIz8eZt6EvVuayS5N8D-uKmwJYPf
X-Proofpoint-UnRewURL: 0 URL was un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-13_08,2024-06-13_02,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxlogscore=999 adultscore=0
 spamscore=0 mlxscore=0 priorityscore=1501 bulkscore=0 malwarescore=0
 lowpriorityscore=0 clxscore=1015 impostorscore=0 suspectscore=0
 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406130109
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=H2sbdGrW;       spf=pass (google.com:
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

v3: https://lore.kernel.org/lkml/20231213233605.661251-1-iii@linux.ibm.com/
v3 -> v4: Rebase.
          Elaborate why ftrace_ops_list_func() change is needed on
          x64_64 (Steven).
          Add a comment to the DFLTCC patch (Alexander P.).
          Simplify diag224();
          Improve __arch_local_irq_attributes style;
          Use IS_ENABLED(CONFIG_KMSAN) for vmalloc area (Heiko).
          Align vmalloc area on _SEGMENT_SIZE (Alexander G.).

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

Ilya Leoshkevich (35):
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
  kmsan: Do not round up pg_data_t size
  mm: slub: Let KMSAN access metadata
  mm: slub: Unpoison the memchr_inv() return value
  mm: kfence: Disable KMSAN when checking the canary
  lib/zlib: Unpoison DFLTCC output buffers
  kmsan: Accept ranges starting with 0 on s390
  s390/boot: Turn off KMSAN
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
  s390: Implement the architecture-specific KMSAN functions
  kmsan: Enable on s390

 Documentation/dev-tools/kmsan.rst   |   4 +-
 arch/s390/Kconfig                   |   1 +
 arch/s390/Makefile                  |   2 +-
 arch/s390/boot/Makefile             |   3 +
 arch/s390/boot/kmsan.c              |   6 ++
 arch/s390/boot/startup.c            |   7 ++
 arch/s390/boot/string.c             |  16 ++++
 arch/s390/include/asm/checksum.h    |   2 +
 arch/s390/include/asm/cpacf.h       |   3 +
 arch/s390/include/asm/cpu_mf.h      |   6 ++
 arch/s390/include/asm/irqflags.h    |  17 ++++-
 arch/s390/include/asm/kmsan.h       |  43 +++++++++++
 arch/s390/include/asm/pgtable.h     |   8 ++
 arch/s390/include/asm/string.h      |  20 +++--
 arch/s390/include/asm/thread_info.h |   2 +-
 arch/s390/include/asm/uaccess.h     | 111 ++++++++++++++++++++--------
 arch/s390/kernel/diag.c             |  10 ++-
 arch/s390/kernel/ftrace.c           |   2 +
 arch/s390/kernel/traps.c            |   6 ++
 arch/s390/kernel/unwind_bc.c        |   4 +
 drivers/s390/char/sclp.c            |   2 +-
 include/linux/kmsan.h               |  33 +++++++++
 include/linux/kmsan_types.h         |   2 +-
 kernel/trace/ftrace.c               |   1 +
 lib/zlib_dfltcc/dfltcc.h            |   1 +
 lib/zlib_dfltcc/dfltcc_util.h       |  28 +++++++
 mm/Kconfig                          |   1 +
 mm/kfence/core.c                    |  11 ++-
 mm/kmsan/core.c                     |   1 -
 mm/kmsan/hooks.c                    |  23 ++++--
 mm/kmsan/init.c                     |   7 +-
 mm/kmsan/instrumentation.c          |  11 +--
 mm/kmsan/kmsan.h                    |   9 +--
 mm/kmsan/kmsan_test.c               |   5 ++
 mm/kmsan/report.c                   |   8 +-
 mm/kmsan/shadow.c                   |   9 +--
 mm/slub.c                           |  17 ++++-
 tools/objtool/check.c               |   2 +
 38 files changed, 361 insertions(+), 83 deletions(-)
 create mode 100644 arch/s390/boot/kmsan.c
 create mode 100644 arch/s390/include/asm/kmsan.h

-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240613153924.961511-1-iii%40linux.ibm.com.
