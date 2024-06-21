Return-Path: <kasan-dev+bncBCM3H26GVIOBBQ4R2OZQMGQEPJPUSII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 42852911748
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:26:45 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-4415b409145sf16005351cf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 17:26:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718929604; cv=pass;
        d=google.com; s=arc-20160816;
        b=dyI3Z3LvwFhZLJMjIUIqi6PIKFs/ThT4WttD69g5VQ0fzvOWmY2130vj8pkZfDWSeO
         vDno0lTrjKWv6cWep31rU/ZEvpP9GENsxafiD3Vb+IMS8sH+2BSdTJRQTRyWnUZswcUQ
         6p73figDW6z2YKahf3noSxDtYduVZpkcqU7ABtZi/FRtPL4ErLjQ0LYNVzo6Z5RCqBXa
         MepUjI2j7GhACv2egZ5OYfGCEu69ikmNnhh73ls2WUn085L9lN8CLj0tPtqKO+a5MNC5
         xpo2vUamiKeoRKH7ovLSaG32lSITmJzQSkdWxnYcwdvFMUidUAmjuwcmR+8oP0v4mOML
         LUqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=RkospgKIjSje+O4etrOGklkm4HrCkUqtzKeUnO0Zndk=;
        fh=jzJo3BKOoHEkUyt0iP0QqeFfmAvtiv10DpCENODUDRs=;
        b=csHwMiKxS1FvnBlW5jawBsLazjj0UoAgh4lr1CdRBgSH8Z2XYY2wai6FBr805mzK5T
         XZ2h3wqQrCdg4mW1LATjAWtCu7fRvgDZd4KCjxgGdcD/pPT8a96OULqcSuGrhNQbVoLU
         YXz0QjW58N0/K3NZGnZuSRAuifusqTEH+NiafdcUaCHunc7AVfs4zOQ7UeATjv7kXBBZ
         KfQYlA8AnjXXI8F09AC68r2daYBezUJSX/BKw9iCrd01uK03Cewfp3hPksoZ0WTnN+Z2
         Az7wufuoV1bCxC8ZUPW5KgSsOLdkrTHXHeFaB2UOuJRBNSn4VbsPwv58rrNAGoqkT8M+
         xA4A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=pJ6slaBz;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718929604; x=1719534404; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=RkospgKIjSje+O4etrOGklkm4HrCkUqtzKeUnO0Zndk=;
        b=RpJTb1OUwyUG2q5c6QsXcMief3MwSI03NBW5ppioa5VOMt0/PjpLFnUfj/wzD6peTm
         agJm9EdJ2gZcwSRJQk2/hWzpOQcv1QMojN0CtWjVpM4HKvFG3tFYcbEMw2JVsp3qjJNh
         LVh3VoV6YwbpW8Yl3XhhQrKhMRuybekacJ5JA3NC6KCk2kGQ0ueSdF+zJpZNn8JN1Z4i
         kR6siMkKT/VdgXCJcFVe+JGsd6FWY0HkRNynjNliVKpqwCZBfVy2Sdxr/6PRsUmmNFsv
         l1Ov5edwl5q7/MsOqXFlF3TRUEmKgzSRfcxepgmRp1Jo5uuAH1q7/uGT6kjUPI6jfS7n
         C9zw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718929604; x=1719534404;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=RkospgKIjSje+O4etrOGklkm4HrCkUqtzKeUnO0Zndk=;
        b=GMSgJHeYnODcsO/DuwwPv46p2C0E+OFeEtn+uvMRtuSsC6Syc2Ga6k1pBgjEV7V2hY
         flnijjzJGKi6jeJBoczLOCFiWCynzkwqBPlqpVEs4B0EivaVCqoUZsVAPrCPlZ43np95
         QnJJ/8zFGKB3iasUcxv1t64ypxGQvbyF29dsxxPdg4kzVG+DsVndCDYu3ZC22UGl4Gll
         y0FFoQamZEC7kpZFq8Cxn/PVOo4Km3H3RWXmBMmgHW8kzaC/0uiNAhszK9k6B2xEQ3N0
         wX/8vCqnTJZNib2ipfSHTuF7F2bjMcemqZ2qiHo+UAEX46BrbMhYPkHwfDuY9kL+l3DZ
         1Scg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXQmfZhFHL69vs8U8kwbOynUxVr3cJwxCdv+SUEepK+wqslvwgx93YMUqh8Y+cG6E09//L0n1S3B+7cTd1p/OgpwcmapQ1Zzw==
X-Gm-Message-State: AOJu0YxgCpxI5SjL4FDKK4CJDzJ/aZodlR4iJHd+E3YFMhRhLDjyu1qg
	gzL9JfwbnRmRURRIRm+Ck388/bzFooo3m+kZGRxh1klgiHRS/nQn
X-Google-Smtp-Source: AGHT+IHcBkPvD3R3yIdffivwAoUP8/ITgclq1vB197ZCfGOUb0c44qYmqBsRcJtqdvreB7P85ibcog==
X-Received: by 2002:ac8:58c9:0:b0:43f:f07a:2490 with SMTP id d75a77b69052e-444a79a9a0emr78806771cf.11.1718929603934;
        Thu, 20 Jun 2024 17:26:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4148:0:b0:444:b60d:da80 with SMTP id d75a77b69052e-444b60de15dls12795261cf.0.-pod-prod-02-us;
 Thu, 20 Jun 2024 17:26:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXGl2Th/K3/+fDnlIjD+yOdZ0KW4M/ovNN6od1K0GEizOf4msYFCCZ6ssnBhtMY9l/b55OeCUWwGQw93OZAJanGC/7wttTDLBhH4g==
X-Received: by 2002:a05:6122:32cb:b0:4ec:fabd:d4ab with SMTP id 71dfb90a1353d-4ef2770f3efmr7916205e0c.8.1718929602452;
        Thu, 20 Jun 2024 17:26:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718929602; cv=none;
        d=google.com; s=arc-20160816;
        b=mJI8ulCb81QbI8kAf8yBfOcvGaw7sNCN0YRlUEVIYWLE7Gj+/0qEve4crPg6XwTft6
         31OTTGnpNTCP3QCImxhwnJjbsrWck0LsmNouqc2KatlXXjeCiFYTdWRSc2/yQ3GwjuWf
         0a3bRUIeR8exb96AE5JtU8s5k/WURPnbLF2hxjg02oQsPDQ476btsKOrZzUPlYUe1jxW
         fVC+8LR2aY3VkcncDK0RxgBRMcy1BtO2g2kP1q12Ck6OK1G9SYHrAcbmbp3pNSAe697a
         22LZZu8Lw0Quk98nlAfLmanpaXa5dD0tHZRMMxziETaKc71UbovTbHRMKqe/TB6NjSUA
         oZwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=f+9pzbH54LbTBRr6pc8icwWBlweOhXihEdfbWvpllXU=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=pGHJi//AbFqKqgpob5Va9bJba2zQmYZffuvtZ4NfNO+wnBp4QDXhZFJaf5v5Aoyx6V
         VqerwlPbjHjMMb9C8g4pCyk0IXg5lM+RT3KU9bWEk2jhnrNqVJ3dk+kEgl66cmVyM3ua
         iF6Zgnn3cHJmenL/R3Haeux9vCzSC36D42j/D//kWaHYGvcADuGz6xUAGt4gd3TPynY3
         xc0oNTOsPNpQerJUWrG9SEeYim5SRJQEXfPTUQn+oLInbw39Odl6wTKp21vLeyXEqcZg
         wLP5NsfUxaFflzT0aN7FXf3HcJaBLfmZOOLUOLzYmWCTCFqqlhLfxS2u9u7ESDLH8Led
         FBmQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=pJ6slaBz;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-4ef4672b312si30031e0c.3.2024.06.20.17.26.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 17:26:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45L0OAQK018979;
	Fri, 21 Jun 2024 00:26:27 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvw8c06ya-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:27 +0000 (GMT)
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45L0QQwa022515;
	Fri, 21 Jun 2024 00:26:26 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvw8c06y4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:26 +0000 (GMT)
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L0LbS4025654;
	Fri, 21 Jun 2024 00:26:25 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrqv2nk6-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:25 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45L0QKTE48562568
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 00:26:22 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 005352004B;
	Fri, 21 Jun 2024 00:26:20 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id C01BB20043;
	Fri, 21 Jun 2024 00:26:18 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.44])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 00:26:18 +0000 (GMT)
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
Subject: [PATCH v6 00/39] kmsan: Enable on s390
Date: Fri, 21 Jun 2024 02:24:34 +0200
Message-ID: <20240621002616.40684-1-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: NGnA0wB8e_HKang9Cd7fUkLp0kysg8ni
X-Proofpoint-GUID: vHoH39FNKmVCDU_CEqJaR3sUi3DJzSJe
X-Proofpoint-UnRewURL: 0 URL was un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_11,2024-06-20_04,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 phishscore=0 mlxscore=0 bulkscore=0 priorityscore=1501 spamscore=0
 impostorscore=0 clxscore=1015 adultscore=0 malwarescore=0 mlxlogscore=999
 suspectscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210001
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=pJ6slaBz;       spf=pass (google.com:
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

v5: https://lore.kernel.org/lkml/20240619154530.163232-1-iii@linux.ibm.com/
v5 -> v6: Include KMSAN vmalloc metadata areas in page table dump.
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

Ilya Leoshkevich (39):
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
  s390/ptdump: Add KMSAN page markers
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
 arch/s390/mm/dump_pagetables.c      |  30 ++++++++
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
 39 files changed, 475 insertions(+), 110 deletions(-)
 create mode 100644 arch/s390/boot/kmsan.c
 create mode 100644 arch/s390/include/asm/kmsan.h

-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621002616.40684-1-iii%40linux.ibm.com.
