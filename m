Return-Path: <kasan-dev+bncBCM3H26GVIOBB5GL2WZQMGQELBQO5GA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id B26B49123C5
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 13:37:25 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-4405784484esf22107011cf.3
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 04:37:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718969844; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y6MiaLeiz9HXS5QrtHJWiKqafDiR0g8UxIfQXEyEAZk4+Hs57QMl5Ufi1mpDBU5CbZ
         8k5EHqCE5l5LcIrWyS7G07Ln+kEh45s1Y2Cg1j/Vdossd2zqA9//EB0Gle0VSmVnopL7
         4XbygEPpowHjlTyNnOsvSWyZ+A3EiOq01WNR0YWkvQJLBWefVxWLpbpw3zkfnMg1yKZ9
         f+YhqWvPUjHOF/dOeq/xvNxzj6FeFYRnh+Rr9afyoGuFVBwtdPdAHJkFJJGFDOatvIkl
         Crkk+PLZRFNz8oD7l4RS/qaT9eeXORr72E+9fnegapEtv6oFR2i7CVu/FAn3+NTK/OlH
         nogw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=I1SGy2vpoml06SuxAVIvbhJNoYADb1SdLbnW23zrMeU=;
        fh=/i/8hddldK1dyoMKtnQIERXVP0TqIunjIbxVFgH915k=;
        b=V4f/10o6sffBYbYUN9wqljZuntxXghSA4zKoDD7HUOrZxaPrejb1WETGCYY5VrRItx
         sqi8yZrGjKh1KQPRIoKwUHl9MH3bo64qWz+ktEwNMsO6D2C4Al/+hgZyuzten+rdhl35
         M8RE5ZwEMGLyNI/nyuUeEyqKeCYHBva0wcpq/XSyzvW/tmR/EYeBj27CZZ1RdtdkACbZ
         LUwt4ACyGTamlsrdAUtVAtmzeNAR6MX/OjVY6ku/u/hDBqj/3vWfidP07YhF+Gc8oG0e
         fQ47OBlIH0cA1+S66X3r5c5olAYOmWkh+EKaLVHzprrsrodc7zGGM1ellhciriu3wDK+
         QE5Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=C9tQpxfJ;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718969844; x=1719574644; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=I1SGy2vpoml06SuxAVIvbhJNoYADb1SdLbnW23zrMeU=;
        b=AwPJFifZ6Z0sCJTAT1+NXycmtFbIEhCrFcdFoq3ut0/dJfuFDZz7pFkY4BveohcmJz
         FszR8D9A+4n7QxsObJdVLgwX8iQBXcxJYkrBMFVMqXFdeAOE4PwTaMFnqUwi+eRGyoWf
         0PL32XNNF0glZ/oU2J093ekj3KRwD17zh+lrv0HMAP+XyJ6fWngJcf8OL5ax5WaGsAvM
         12rUTeQS0wYF4mSQRIQL2CUjek2PuHH4yhU0Zx0zDit1Tw8p9f6mLPklDK9WJz/JLMzP
         Vml18T/QmC4dLX0MNLO4vH9HsCrhnZGbFAjcM2t7cq/nhDwVzmx0jmt+K22ATm4CJMEE
         omkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718969844; x=1719574644;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=I1SGy2vpoml06SuxAVIvbhJNoYADb1SdLbnW23zrMeU=;
        b=L2KmDidvEJi6Kx+QRd/luC9jdSAQK7fdDLqgfFXIX2iZF1Zkim+k0Mn8y7l/imnPF4
         xLD6TNNSfWu8cN1OMHxw5xtSTD5DjGv2f7uRT7OWArFJx6sP+2UKzn2k0hszUak0n0hB
         rf7yv+4KDk6JCI0M+iAVdfMME1srxJq85QW3M08kptDajk8LYtMFoDwFcJ/2IFFfsuMb
         P4iESyQQTzq/2Jj53bZeKMlZ720FFxsTl6VE2IAiWWyrcVxpxs/rt0ChbJYNDFlWnTOY
         p4JqmbxjC1shPIxkwNFvaIv94BPZ6KcmMt6VjLhwio26cqM234B4jURL+d+2BnuVA/Gg
         kaTA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWEuBgGJUVvwAMpzZpkK864lR5qLiVqOzTdceQGZq8bDf66J6QpSUSiMw0PwkOXRtX4Id7wlaj5l/Us4HitE2PMJYMJtmQsRw==
X-Gm-Message-State: AOJu0Yw8BWri6NSuQliCNd36Y66ki4emAeHdl2UpHaW5ZyhIpdqBK9se
	ai8BACpHKzG//4BP56uMFxL/3y+OpYR/sNsL9ak+qt/6Afg8oUPk
X-Google-Smtp-Source: AGHT+IEX+p4NJRVTqkp1Z/ZuHHhGrdQihJ0oM2wQiZSdEAdJpSp05C/HqIp9/nQPm3BPsaXNQ7eEMw==
X-Received: by 2002:a05:622a:28d:b0:441:2fd0:e090 with SMTP id d75a77b69052e-444a79d20c9mr91001821cf.34.1718969844361;
        Fri, 21 Jun 2024 04:37:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1909:b0:440:c5bc:db8b with SMTP id
 d75a77b69052e-444b4be6390ls27755061cf.1.-pod-prod-05-us; Fri, 21 Jun 2024
 04:37:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVwjw6uvMal3C42COi47ujzm2v7D6A4cWArIym1hg45T8PlCmAh7BNceBqTv6wGyAgQ3RLFIYOKsuOBtqF9ur6JJdxVEmuxN7SDVw==
X-Received: by 2002:a1f:7ccc:0:b0:4ef:5757:f91f with SMTP id 71dfb90a1353d-4ef5757fe63mr217911e0c.10.1718969843483;
        Fri, 21 Jun 2024 04:37:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718969843; cv=none;
        d=google.com; s=arc-20160816;
        b=WBrRIVCHmy/IPBg+qt0zaIWFTDobm2/zE991UaIjgu7pSvgP3R778ZEPmi2lgnei2y
         B1jp+oPM3jBKnWwMNlkHHOkVMoGkh8U/239Kpmk0I3kPuZj0h1EkW+aOJdDcUssIV8Z/
         CnbkzF4JJy1zQ1tCCKA7AJt3lmmc6dqO85fNWrBc5XO44wZwug5FclYperUR0fsnju9r
         ap7b9e6qn/yW6ZgAsWRmJHoRfOHLmAxEn0Uu3ehhqwowCo7OWEtzJPNes2/MyEJH8/f0
         H88IwKEkF6v5RSm2/hbB7y+EUZoHUAqf4hIw+T6SXX/yl9Bbp8zh15hLQg/4P7wAdf8m
         tp/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=LD4y64NXjfsWIMTssA+LHzsu6fB1ePs+Yjvug9wx+Yk=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=aLw2oL3YMzaOPf4JYntiGicg44AnH/kJLeGghmhC9xS2XY1F4u4YSMtFh8/Z/rPdQU
         xP+WhJ6JdekSMHpDkYQj190ad5igPdTzqL+gNIzSOP/I/9Mc9zJQVyBer4OSqa4LoIBg
         YC6Jm+gaFEZxJAKyk2j/qTnDde5LaMvhl/EOA02sfBnfIZDj9Z7khz2qj0wIQQU6EB+4
         Q30nI4o0UueYe2Nqh2fE7lD2hX/bl4KnHPzpDvKduysGU2tAWQNu2gfbwHetCHxXmWBY
         dnBpwXg+gO1KZqTezukvGvHpgcaIvQTp4hXFhT7p+yJ4YKDLqUV8zPMkM/8sdS4gb0IA
         7M2g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=C9tQpxfJ;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-4ef4672b312si85273e0c.3.2024.06.21.04.37.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2024 04:37:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353728.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45LBSaKx028638;
	Fri, 21 Jun 2024 11:37:17 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw8p080mb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:17 +0000 (GMT)
Received: from m0353728.ppops.net (m0353728.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45LBbGeB008753;
	Fri, 21 Jun 2024 11:37:16 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw8p080m3-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:16 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L97SQx019946;
	Fri, 21 Jun 2024 11:37:15 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yvrqupvyf-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:15 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45LBb9Mi19136862
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 11:37:11 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 1C3BE20040;
	Fri, 21 Jun 2024 11:37:09 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 7B3942004B;
	Fri, 21 Jun 2024 11:37:08 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 11:37:08 +0000 (GMT)
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
Subject: [PATCH v7 00/38] kmsan: Enable on s390
Date: Fri, 21 Jun 2024 13:34:44 +0200
Message-ID: <20240621113706.315500-1-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: fBcB1S0a0ZcmDcjFwjNRhDtTMO9ibhv3
X-Proofpoint-ORIG-GUID: sdukBvbsRI7ijb82kB8u2lBcB9wtwI2P
X-Proofpoint-UnRewURL: 0 URL was un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-21_04,2024-06-21_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxscore=0 adultscore=0
 suspectscore=0 priorityscore=1501 spamscore=0 malwarescore=0 clxscore=1015
 impostorscore=0 phishscore=0 mlxlogscore=999 lowpriorityscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210084
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=C9tQpxfJ;       spf=pass (google.com:
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

v6: https://lore.kernel.org/lkml/20240621002616.40684-1-iii@linux.ibm.com/
v6 -> v7: Drop the ptdump patch.
          All patches are reviewed.

v5: https://lore.kernel.org/lkml/20240619154530.163232-1-iii@linux.ibm.com/
v5 -> v6: Include KMSAN vmalloc areas in page table dump.
          Fix doc comments; use KMSAN_WARN_ON (Alexander P.).
          Patches that need review:
          - [PATCH 16/39] kmsan: Expose KMSAN_WARN_ON()
          - [PATCH 32/39] s390/ptdump: Add KMSAN page markers

v4: https://lore.kernel.org/lkml/20240613153924.961511-1-iii@linux.ibm.com/
v4 -> v5: Fix the __memset() build issue.
          Change the attribute #defines to lowercase in order to match
          the existing code style.
          Fix the kmsan_virt_addr_valid() implementation to avoid
          recursion in debug builds, like it's done on x86_64 - dropped
          R-bs, please take another look.
          Add kmsan_disable_current()/kmsan_enable_current() doc;
          Fix the poisoned memchr_inv() value in a different way;
          Add the missing linux/instrumented.h #include;
          (Alexander P.).
          Patches that need review:
          - [PATCH 12/37] kmsan: Introduce memset_no_sanitize_memory()
          - [PATCH 13/37] kmsan: Support SLAB_POISON
          - [PATCH 17/37] mm: slub: Disable KMSAN when checking the padding bytes
          - [PATCH 36/37] s390/kmsan: Implement the architecture-specific functions

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

Ilya Leoshkevich (38):
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
  kmsan: Introduce memset_no_sanitize_memory()
  kmsan: Support SLAB_POISON
  kmsan: Use ALIGN_DOWN() in kmsan_get_metadata()
  kmsan: Do not round up pg_data_t size
  kmsan: Expose KMSAN_WARN_ON()
  mm: slub: Let KMSAN access metadata
  mm: slub: Disable KMSAN when checking the padding bytes
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
  s390/uaccess: Add the missing linux/instrumented.h #include
  s390/unwind: Disable KMSAN checks
  s390/kmsan: Implement the architecture-specific functions
  kmsan: Enable on s390

 Documentation/dev-tools/kmsan.rst   |  11 ++-
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
 arch/s390/include/asm/kmsan.h       |  59 +++++++++++++++
 arch/s390/include/asm/pgtable.h     |  12 +++
 arch/s390/include/asm/string.h      |  20 +++--
 arch/s390/include/asm/thread_info.h |   2 +-
 arch/s390/include/asm/uaccess.h     | 112 ++++++++++++++++++++--------
 arch/s390/kernel/diag.c             |  10 ++-
 arch/s390/kernel/ftrace.c           |   2 +
 arch/s390/kernel/traps.c            |   6 ++
 arch/s390/kernel/unwind_bc.c        |   4 +
 drivers/s390/char/sclp.c            |   2 +-
 include/linux/kmsan.h               |  76 +++++++++++++++++++
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
 mm/kmsan/kmsan.h                    |  33 ++------
 mm/kmsan/kmsan_test.c               |   5 ++
 mm/kmsan/report.c                   |   8 +-
 mm/kmsan/shadow.c                   |   9 +--
 mm/slub.c                           |  33 ++++++--
 tools/objtool/check.c               |   2 +
 38 files changed, 445 insertions(+), 110 deletions(-)
 create mode 100644 arch/s390/boot/kmsan.c
 create mode 100644 arch/s390/include/asm/kmsan.h

-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621113706.315500-1-iii%40linux.ibm.com.
