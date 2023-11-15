Return-Path: <kasan-dev+bncBCM3H26GVIOBBS6W2SVAMGQEDVEE3EA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 303A67ED20A
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 21:34:21 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id d9443c01a7336-1cc40eb7d54sf1384565ad.2
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 12:34:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700080459; cv=pass;
        d=google.com; s=arc-20160816;
        b=bDO1tmUj/kWOPL5pCCry0D1BYX5ZwQoBWD0rB38GeBWjjV3Cdm3lVWmmHlNr1qCAuY
         Vzh3rtTU5FEMY9vMgineWNXt2emuUvI5PoPBW1KReoUoVen3JgWIl8TyQZiD3vb+Nvvr
         zmxshZ4BGDb8sJ6iBNa6xHpV9sicUZFY42f1KB6eXjUajZZiK9mBVD32UDVmLi4EVs6h
         zcDbnEX+Kc1HDRwwF/vb4xJpsmGKD336BRzPecdLRvdTtOMLnHH9Br7eQMOnHIIQ5nhc
         QlyT2ueHTcu4Zwmolg8/xw4sggkNagPNmZ4bp5vkdb0GWc/i5mxkbbOwxOuijQsUvt7S
         x8Pg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=OR0m+8EJeaINnafI9t0wBGB3FAxA4rgMPiioFG5xhWE=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=NG7x5wohsvyVesCeB5DCR0iszJuopF7CEaW0uzvV0DXd5BE08/IFebOtEfQxbGgBrV
         GeD4Vi1WdXKNQZp3vAG99jiVgRedrgvteO9UQ0v8yhF2Leen7cHjzkR5ivv1PCsP+3ST
         ai03i+viiT5LFyLeIge3WBFzH6nevufFZgIVq8P1V33cUA/q+Q5xTh/7rWegVvVp6Ras
         UEFpDL/BEVxH0c8lzuzwQ5S993tkHTmuO9AfkboLn4SHVYEj3oyBkMRBu/qYaqbmPW/0
         /5YN4PrqDZ+1In386Fn90lqi9irWwnW40Cb0l6mqgltBnixuvF4ae2CYO/srXrPFpp7K
         8WxA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=lVtuxA53;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700080459; x=1700685259; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=OR0m+8EJeaINnafI9t0wBGB3FAxA4rgMPiioFG5xhWE=;
        b=NaXaBdC/ScgoiMA57MD4NtJk1YzoO+/uiIv85ExpCJrAmunxTYHMSOeviCGv7C6hxh
         8DZQDox68oXEd1USBZRuJ53Y5z1FdCr0f6w1DI4M+nfSfqC8DZ+1cXLYJTO6cbul6Cqu
         LZF/D/FhRonB5WLTpYblbFpTib4hFrOAETQsTKZSJYZY6gRQ/vZoxVgCUFfoyrv7jtkS
         tiSt3CvXpYiAErMxFEgoZUKyW3pIVaoEBPZ4jIGF7ipqwOC0OiwRdDHMqW4QqqIx7nsz
         Ofv1HypBct/IZGnOpBO/AxUG+je/lqomqhHYp2mVL7pNQRRvILH+ajBKUJEN+nVus1cF
         nv7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700080459; x=1700685259;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=OR0m+8EJeaINnafI9t0wBGB3FAxA4rgMPiioFG5xhWE=;
        b=Wguv6hRgzhEBkrMF+XRiL2E83cIKlUIia8bvrWIxmLEVWgsKLYBeRgwaxvQQjRU2zl
         A5I3wYo3RIewKOKTsOzfkolQnXRFZVLCwHpymbFtMpzsBvNm8LoK4nAy/3czq2BnNdC4
         IZrDvRz6bj+ijPFXz/L4FBq5DCi2tbAuKv7CKN4Wo239HbwDmPvsCm6gzAn9U+0Io2iR
         J9bASyvESFV++i3GVLiqxU2hyOZbCJnjvks5jbsdssqKJhvI+KbH52lZtKKW6wFEY5CB
         8VnWfMSfzqntwAlIEtOes+bGZ19alMioWX2OMmcb/zkhk0PDcL4xn5ARmrSOuqhE1N8q
         mD9Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yx39fPi6o8G8Nz7aTF4RJnf6Vl4/X82SlpzJ5QOSqY1DlC6HeMC
	hiEdmtCFDRfVmVkQivPVULc=
X-Google-Smtp-Source: AGHT+IH1QWvMZJbplVK/AmjCDYif8iLRb50kU+NIfTbNGfow0TzaKjafyq8zVdMJiR2ctl+E1uKK+A==
X-Received: by 2002:a17:902:6901:b0:1ca:87e0:93e3 with SMTP id j1-20020a170902690100b001ca87e093e3mr5896008plk.7.1700080459302;
        Wed, 15 Nov 2023 12:34:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:230e:b0:1c9:ad79:64b9 with SMTP id
 d14-20020a170903230e00b001c9ad7964b9ls101881plh.0.-pod-prod-05-us; Wed, 15
 Nov 2023 12:34:18 -0800 (PST)
X-Received: by 2002:a17:903:2591:b0:1ca:8e43:765d with SMTP id jb17-20020a170903259100b001ca8e43765dmr5407430plb.64.1700080458229;
        Wed, 15 Nov 2023 12:34:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700080458; cv=none;
        d=google.com; s=arc-20160816;
        b=O+99j3bDN8CtCMilq6gEOEjFURUvxqvvtm32m2yz2Q+GRZoNf5TYQvE4oj0Qhn4gxq
         aMc4JM4LOOcKLYZ0ZuZpVU7wsZBzZeis1Mzugtsi1PfvUchO6Gyh/cjRwJEHG0KLvYFm
         2A866FTU0FTpixTygtlYpU7g6cpY/eAIo3rpuU7rhx4N5ilzVSWh+qIGXBWKbBg3awIN
         XiklmarhOLyf0Vp9+uEixrF/U6XFIl224H7YuMR8KhTXmb780djHWMx+oTj7v3/QnywI
         aSJjUGDVtW+zi/PaElHera9v0jErmqII52MPEx96MrJeDoTydX9n/7yBEd1RBV9nbbh9
         Mpxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=ZvlPFgCBT1EmH5DZbvTajf8H3CytU5Hp1eV8d/t1KuQ=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=FmLmnSiQqHs4pFVme6qvD/cwOucOrnPVtlt5Pb7hKxZc/Vbu2zjKXXVenWkhet+P7P
         5HVoYtdC4N+WGivden/yVoQsP0ubq048uMzF3iuK3x95IRTeWHmdnEKeGkNclF9mjBUa
         BmpMG7OeYLiGVmAk4tGDcenQ/Zt1YdUBvz2N/PuVSdmkHEHgttNBfiE9WImDPxCe9A/+
         poodUPfeSRv7N0PuUZrCwHjpzT76IuM1JhSpS/y12u32X0uUoWL3YJrkdA59nKUd2VRF
         f0NFnvu4T9X9xkG7iqkINOodUXW+Tgg4jNRjHCSFbxWTUMeqrt6zAvLYBP1OuqPjOrh+
         6MLw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=lVtuxA53;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id x6-20020a170902ec8600b001b816e24eabsi367158plg.4.2023.11.15.12.34.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Nov 2023 12:34:18 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353728.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKWucR031174;
	Wed, 15 Nov 2023 20:34:13 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud543g10h-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:12 +0000
Received: from m0353728.ppops.net (m0353728.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3AFKYBS4003580;
	Wed, 15 Nov 2023 20:34:11 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud543g0yw-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:11 +0000
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKIvA1015481;
	Wed, 15 Nov 2023 20:34:10 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uamxnj0hb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:10 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3AFKY7n744434146
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 15 Nov 2023 20:34:07 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id DE54B20043;
	Wed, 15 Nov 2023 20:34:06 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 835E020040;
	Wed, 15 Nov 2023 20:34:05 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.9.51])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 15 Nov 2023 20:34:05 +0000 (GMT)
From: Ilya Leoshkevich <iii@linux.ibm.com>
To: Alexander Gordeev <agordeev@linux.ibm.com>,
        Alexander Potapenko <glider@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
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
Subject: [PATCH 00/32] kmsan: Enable on s390
Date: Wed, 15 Nov 2023 21:30:32 +0100
Message-ID: <20231115203401.2495875-1-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: s_HIgjGFEkw2r82SbnJKsme_JpUxwIpl
X-Proofpoint-GUID: O24-gF0cUI_VPwI0_OAIJDvWxXDnx7n2
X-Proofpoint-UnRewURL: 0 URL was un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-15_20,2023-11-15_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0 phishscore=0
 spamscore=0 adultscore=0 priorityscore=1501 suspectscore=0 clxscore=1011
 mlxlogscore=999 bulkscore=0 mlxscore=0 lowpriorityscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2311060000
 definitions=main-2311150163
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=lVtuxA53;       spf=pass (google.com:
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

Ilya Leoshkevich (32):
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
 arch/s390/boot/Makefile             |   2 +
 arch/s390/boot/kmsan.c              |   6 ++
 arch/s390/boot/startup.c            |   8 ++
 arch/s390/boot/string.c             |  15 ++++
 arch/s390/include/asm/checksum.h    |   2 +
 arch/s390/include/asm/cpacf.h       |   2 +
 arch/s390/include/asm/kmsan.h       |  36 +++++++++
 arch/s390/include/asm/pgtable.h     |  10 +++
 arch/s390/include/asm/string.h      |  49 ++++++++-----
 arch/s390/include/asm/thread_info.h |   2 +-
 arch/s390/include/asm/uaccess.h     | 110 ++++++++++++++++++++--------
 arch/s390/kernel/ftrace.c           |   1 +
 arch/s390/kernel/traps.c            |   2 +
 arch/s390/kernel/unwind_bc.c        |   2 +
 arch/s390/kernel/vdso32/Makefile    |   1 +
 arch/s390/kernel/vdso64/Makefile    |   1 +
 arch/s390/purgatory/Makefile        |   1 +
 include/linux/kmsan-checks.h        |  26 +++++++
 include/linux/kmsan.h               |  14 ++++
 include/linux/kmsan_types.h         |   2 +-
 kernel/trace/ftrace.c               |   1 +
 lib/string.c                        |   6 ++
 lib/zlib_dfltcc/dfltcc.h            |   1 +
 lib/zlib_dfltcc/dfltcc_util.h       |  23 ++++++
 mm/Kconfig                          |   1 +
 mm/kfence/core.c                    |   5 +-
 mm/kmsan/core.c                     |   2 +-
 mm/kmsan/hooks.c                    |  30 +++++++-
 mm/kmsan/init.c                     |   4 +-
 mm/kmsan/instrumentation.c          |  11 +--
 mm/kmsan/kmsan.h                    |   3 +-
 mm/kmsan/kmsan_test.c               |   5 ++
 mm/kmsan/report.c                   |   7 +-
 mm/kmsan/shadow.c                   |   9 +--
 mm/slub.c                           |   5 +-
 38 files changed, 331 insertions(+), 81 deletions(-)
 create mode 100644 arch/s390/boot/kmsan.c
 create mode 100644 arch/s390/include/asm/kmsan.h

-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231115203401.2495875-1-iii%40linux.ibm.com.
