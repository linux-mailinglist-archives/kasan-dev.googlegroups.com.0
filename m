Return-Path: <kasan-dev+bncBCM3H26GVIOBBKX2ZOZQMGQE2MU3DBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 80D5390F296
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:45:48 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-375d2ddeffbsf75325505ab.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 08:45:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718811947; cv=pass;
        d=google.com; s=arc-20160816;
        b=hrxDmdoh1FeVMD0oAmHWLQVwO1JhMYWk7gd3k6ghgaCqzVEzn4MFf4o2duezqXR1TR
         lTj7kKNZaNvMxQdfuZBM4iCFq45+aSjYKBeXvYibjplR/PG4gvqS4FqwYPgxmtORnABo
         W1QYnCAZ7I4gpcYZXLdm8/mSxR6fXVv5uGfjvwCuqFNHHO6M0lszprpDP4fkyyksb1rT
         OV2DK4wRvNxQMSjJ3Ydv1/Qrl6cBgNwMKteJcrUXRSpdWyeYcK3VJCc6u5QyOz9iS2xQ
         esoLBTaCcJEBZOAPmy2Dg1rkx8WyRcHoigi9bEOQViqK/gTsetsY6ELqd4SHTa5GsiGM
         Js8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=H/THdlAnXs6qZwAJkFu4Ep0bcKkeU6pJhW7e/kIj8Jk=;
        fh=gXqzystph6sU1VuFaXwvcX3I6cWz7TkHtf7PbSE/33c=;
        b=JTtU1JNT9gXpizpgK+8SJeNDWn9rMiBQlh7qwC0MIUbWe5cpzwAmpN38h00DdCHwM4
         hCcIslnbwbeDB5Fx4/W1k54Ijc2DnrDH6Tt4mhQ3wvLUlIphaTDZBzFsawophHK2wlXD
         S6Q1eOZDCQm7rp+vGcjWosmyHz3sYb6JtKY3rJeoBNmJdPuLClWmH7OJm5yJhagy1cmx
         pbEeC2OQwdOAiByirY/mGliZQCKwIxuprSbJQpccOKiv2WKbqkroSezpLntxdI2Lmxxu
         YVHq2bdma0q01d8id4r/JzLf/XIqErKVgReed16+giEH3/99RdI9JIVtiFgp9YeXvfjc
         DQmw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=YMobYKzP;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718811947; x=1719416747; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=H/THdlAnXs6qZwAJkFu4Ep0bcKkeU6pJhW7e/kIj8Jk=;
        b=IxMMeqcpazXo6Urtopl4Ke5CxHCYBGNuly034O9DwesmugCOo6DkoIDNjdyG2GP8+B
         RVnqvSI7flFqgIMVOBhjdY2zxfsXSxQfTYsAUhoCXwKgszZ1tLzaAwbqugrbHXHueJjW
         Jl1JmNItDx3kJN9kRIfgvzlrycQCbfgU8LfM4ylEjmzOlKwmeMturW22KNe2E/J9bg7e
         gG+yiFtauBgP0CNv4zSakn8q62QBrqpvA2a2vKY0REja//LbAYXv/sruc0vD8BrIblqF
         FWgYk0Uz/08W7wKme/yVa+aEuCdvraxSeniklZ3AQISQuUqkER41bJtAuGKBl+aPWbrV
         kmiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718811947; x=1719416747;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=H/THdlAnXs6qZwAJkFu4Ep0bcKkeU6pJhW7e/kIj8Jk=;
        b=Jwzc217ieXi8x/Lnh0j1mK5XZ5Vch/TerTVuFme5Zb/QqwenRClDdnoGV3FekVKnjg
         YY/vQ1tA2RDsVcEl1Zh5IrVioBfgwvzT5+vmyREbVc/m18SLx70WkJ1Zb+yIJMLopkNK
         w4yJJsIFSM1/171KX829r6CM0XArWj6LVvF40qqwIPrjxzMKzP+nnV5LjND0kjYM6sc6
         pJVcmWoASMC32yFhE2Jv1FK0BEeQo5tewJ+UrSg+YiCxrPInP02H9M88oO/BNqlIG0Na
         sNPgtpP12hM4rV9QpdWQ/L30/yLaAFABy4qQMzhhZBnsp9SzXt5zrKMzY4AqLgJ0BYl9
         lyGA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVHA1BATii+GOB93eAW9vLuiRxmQqO60OvlOEr17Mt5GMOHReezTgy+xfU+SGaJDGG5+X0Wqb28pk818kt0jm9UYyh+kEiMEw==
X-Gm-Message-State: AOJu0YwYxoHGSS1EelC5dVioaBoKWT+YcbFv4gNTvxMeQsyfnrf2sO/l
	twXDoSi+f+TqzxovN/dLjMaLlnu0VbhzDmgKcAg3gjMsIXuc16uz
X-Google-Smtp-Source: AGHT+IFI5fU1omG0WgTXXvOqiZ/ViI4IMYXtj8dRinVWN4phHDb5cO24faJL5bANB8PSa1YcHw3hWA==
X-Received: by 2002:a05:6e02:20e9:b0:375:a85c:5fbb with SMTP id e9e14a558f8ab-3761d6b3489mr33892665ab.17.1718811946716;
        Wed, 19 Jun 2024 08:45:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:3a84:b0:375:ae19:e63e with SMTP id
 e9e14a558f8ab-375d5661ce0ls52956225ab.1.-pod-prod-06-us; Wed, 19 Jun 2024
 08:45:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVTq1A3RyLVux/pZOLQ9f7o0tiOF6jxcj4X4B/gNUJ7+zDyUHBaQgWo2/YwXRrU6NwabGjrkXVfd3u79F+HIq/ctz14jaCSJgcqwA==
X-Received: by 2002:a05:6e02:1e08:b0:374:aa60:a5c3 with SMTP id e9e14a558f8ab-3761d706e24mr32254365ab.28.1718811945901;
        Wed, 19 Jun 2024 08:45:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718811945; cv=none;
        d=google.com; s=arc-20160816;
        b=d1/CCVxYxvNpHBo6zK50jlHrf8q+pvGkTzonPq5Sl+590RCVau+IBfJit5gd6/+qbu
         cbSITeP4XuajCJ6VZL+WTq/Y4QVNftRYbFl4Bhz27wjhpCmAFzovHomKJ4IaifPHKbgI
         iB9Gm+IIZDtzS+S6Hqx3NLq3vFX+2153+z2CpWC7/oAmgDfOwrDruCS01ENmr1nICazO
         ok+s0PagmrSjZmDDqwFL+Lvt3SBmZbwoK7+wC3mClaV6tI9sN7vuyPHf+UCtWh88jixO
         YjhtsTHlMIXPCkI8QMnsM42J15LWpPU125+KpKtDtj4yD9EZJeSiBbGRci6K+/whsufT
         3RmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=VJm6hHtzjQFz8J3NZNwSDelkZcJL0K6VTSMOnj1lXFA=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=usY/VjtMrmoGqhTRxwWE0V5hC0xHdWa2VYyanVh2Hj9YYEqVguTGBgYWI4qXXO0Qam
         vlCxQDUsKZgBAuk4vY3EXkXDR/lFffefP+wPuwU3tYOfUgPPKx/sZCx6y11j4//zlVXa
         7hiOOyF14i07l3St5041jKNnNTOzGTlzzLBKto+dNipOBgjpLpdtgiJ6Rw35+S786zCu
         Dpmo6TUMXeyYHxdo2ojueq6WJNmxHJQYCon+8wDKe4FXxHJlUhmIOUfl2Qa0ZSm/az1w
         OJH1FYuez/E5WM0vwyXzky/yNG5lzatlocWFKM9YcyGm4Y9TN7SkC7xLpMNQ/UGduAsS
         ZEtg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=YMobYKzP;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-375d87380f2si6361815ab.4.2024.06.19.08.45.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jun 2024 08:45:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353726.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45JFPmSj005019;
	Wed, 19 Jun 2024 15:45:41 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv1jfr5b3-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:41 +0000 (GMT)
Received: from m0353726.ppops.net (m0353726.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45JFjeGk005715;
	Wed, 19 Jun 2024 15:45:40 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv1jfr5ax-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:40 +0000 (GMT)
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45JF4DXR006227;
	Wed, 19 Jun 2024 15:45:39 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3ysn9ux8km-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:39 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45JFjX5J49086752
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 19 Jun 2024 15:45:36 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id D17162004B;
	Wed, 19 Jun 2024 15:45:33 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 7303720040;
	Wed, 19 Jun 2024 15:45:33 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 19 Jun 2024 15:45:33 +0000 (GMT)
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
Subject: [PATCH v5 00/37] kmsan: Enable on s390
Date: Wed, 19 Jun 2024 17:43:35 +0200
Message-ID: <20240619154530.163232-1-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: nseo2CrAOTqXwQL8a_EKoWmLo2KBtae_
X-Proofpoint-ORIG-GUID: 7JzeidV5Q06ua732x0AojvNF0TR0sYGs
X-Proofpoint-UnRewURL: 0 URL was un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-19_02,2024-06-19_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 adultscore=0 mlxscore=0
 lowpriorityscore=0 phishscore=0 clxscore=1015 bulkscore=0 malwarescore=0
 mlxlogscore=999 suspectscore=0 priorityscore=1501 spamscore=0
 impostorscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406190115
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=YMobYKzP;       spf=pass (google.com:
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

Ilya Leoshkevich (37):
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
 arch/s390/include/asm/pgtable.h     |   8 ++
 arch/s390/include/asm/string.h      |  20 +++--
 arch/s390/include/asm/thread_info.h |   2 +-
 arch/s390/include/asm/uaccess.h     | 112 ++++++++++++++++++++--------
 arch/s390/kernel/diag.c             |  10 ++-
 arch/s390/kernel/ftrace.c           |   2 +
 arch/s390/kernel/traps.c            |   6 ++
 arch/s390/kernel/unwind_bc.c        |   4 +
 drivers/s390/char/sclp.c            |   2 +-
 include/linux/kmsan.h               |  46 ++++++++++++
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
 mm/slub.c                           |  33 ++++++--
 tools/objtool/check.c               |   2 +
 38 files changed, 410 insertions(+), 87 deletions(-)
 create mode 100644 arch/s390/boot/kmsan.c
 create mode 100644 arch/s390/include/asm/kmsan.h

-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240619154530.163232-1-iii%40linux.ibm.com.
