Return-Path: <kasan-dev+bncBCM3H26GVIOBB7OL2WZQMGQEVSNABDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3236C9123D7
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 13:37:35 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-37629710ab1sf174155ab.0
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 04:37:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718969854; cv=pass;
        d=google.com; s=arc-20160816;
        b=c38PGZiTyPbylg4MfhVw3pbeAuTTaqy2hq/FACtf3YVix/26rP5FmDswJ6SmxUei6a
         pOOGZPW2ixJ9YUv5LvkQ1yFeryjWRVMeOFwRSzT2/M41eROjk3teDv50rqUcOE1KsHVU
         5cCw0OfbQ7LKAOqWS0qNkhl5F8SZZ6UXZWuTQ9RHcO1jQ12CqXvrRudIyWdYb3k048pb
         HP107PGeCsTCRxFZR+lZP794+uG0j8IVbCq1oOZ0Yjri8eWotmU8BPOunbu2wdkwrIAb
         Qw+XX0oIYEHrYNy/d0m9I/UsdHTvCb3y7g7TObtAySbCloDclRxmxRSFGld4wN/0yEBU
         ioOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Q/FsJJ+OlJYyV9TYkAeYZ2/dct214zDZAIRbF07YXiU=;
        fh=4yH5rgGpuWp3+Mven4g/oXHyC9d4Tdj29RegV9TylQ4=;
        b=qbBuX/VjOeu5yIaN6Sj5IlP9H7wNwW1IRtBNZ5DsVAtt+IExmJFgPFuSYP2h65fqoJ
         5g4Dcgw9q+LiCiGM4T73DHetuCzdkcpj+4b5DJj1EM6gIVJNF0UDgovDyhRjm4WcZI5L
         Za2NL+1KAADN5QpesxuavMt7oalE6nQREb80finowIE6Q30UhGN3BZfAn4jo3VxsPa/m
         gTESzDaEq9HwfyPvC5zWa/+t5PQEPXjVDXt/aHGicbZXpodYK5K4ni0q7g6mepdVknmn
         HsjLRif2KTLzHyNkoPFtHVCzzQMDdJCG5wvL7YlRGLkhNT8BMx46i6M9QxYXTijAqwSE
         tNkQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=EVMWG01B;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718969854; x=1719574654; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Q/FsJJ+OlJYyV9TYkAeYZ2/dct214zDZAIRbF07YXiU=;
        b=Pva708iT1TKFUi3DWdnGvxmVdxWdpnnJDGuYmfLNQTWc0x1sCs6wcNqsBtVyIZZtoY
         MzyhyoX6uSTB1J1faidTE0DiinDD6bFVtgNRM3isE55niT1TjQMwh585gLsncsj8Te84
         aEbHKu0iuzI3pPC5QqVxkppXc/6AETMLECNBWQEeg1Z3yFkKmvk4Xm29JpXXbpkX6i6H
         caYjlxdQjlEL/1Z/RA1SptYdMSyE2YkRFvQqkh5LHoai5rZzM/AXTJyspLD4/JeUT1Td
         CIdc0YYWAbJgqyaUAzn0YPYI3z39vpus4BOFkNDop3VcPDQDgFdhyPNn8KFhieBb/rJQ
         YcZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718969854; x=1719574654;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Q/FsJJ+OlJYyV9TYkAeYZ2/dct214zDZAIRbF07YXiU=;
        b=oxo5pKBH5x/4SLcZxISX/aBXios9GS7D2U97uism/H+GckvrjNuyJ+Nw/3JRDWiaKK
         yLLWNKBxj+kPr5HNgtVz9P2G63NtYPxyEQttUItWNttcJYEjWC4jJalakDmyb0rOIiCO
         BsYKi2TUJdmHW5k+H973Ysv0qcGPKMUV4kknDS5rvVYkkRRpXh+VGWS6meE/8SOUnny+
         kpHEGtxxCoGQ5EnKjHorYLEcSA4I03Ao4RLkz7Q5JzLe3A/ibX+EjoNAHB4sSKTGIV9G
         i9d4Lk+Aqt5oeMMd2qcJkIUtzwt0LH4AoLngu9kbrRAKZ0NAjIyPziIQ7m5r5BO0GRYD
         9UdQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUVg3qOEMoiEWg775lso1bzPld/wx1OILYbBlI040wjKin6BnKMBszm6hRQX6XA4X+RUgukablcKg+Qvp0zDfp2QQeDB1Ry4Q==
X-Gm-Message-State: AOJu0YyhY9xqG20lBccLVW4GBowNeIRXRouzeUEc/W2+yKUeetytrtZd
	IunePLMJ3wqkz3OeRtIjRJICw2ftVx8RzCJTZBIGkpyaOaugVn0S
X-Google-Smtp-Source: AGHT+IGmDmIOaYyU19XEyanvoodqRmJJLwjlky9QJATYNWhQZTY6NNPQNDZbUAtBkn+JZdCFfSwPqw==
X-Received: by 2002:a92:c889:0:b0:375:98f7:6683 with SMTP id e9e14a558f8ab-3762f4ff7f2mr2082285ab.29.1718969853866;
        Fri, 21 Jun 2024 04:37:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c248:0:b0:375:a281:a669 with SMTP id e9e14a558f8ab-37626ae41e0ls15477635ab.2.-pod-prod-05-us;
 Fri, 21 Jun 2024 04:37:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVK++QcWjVAnQJ6NPYwL5wkgJxQHR7ZzLcwQ50SkYXqPqr2/mzIRa2NjzmJWrPLJZWrRIPit37oWZ7dfa5sVKsDM30QK+WhQPdC/A==
X-Received: by 2002:a05:6602:640c:b0:7eb:8874:99d7 with SMTP id ca18e2360f4ac-7f13ee68466mr961625039f.14.1718969853152;
        Fri, 21 Jun 2024 04:37:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718969853; cv=none;
        d=google.com; s=arc-20160816;
        b=elmryqYrYJBblxuULG9qAKY3u9DDGVLTXPkijZ82XpqjYKe8As1311Is2NefyCEswm
         h6TFLhySkXbYB+euzzwq0bGP6oGRXFJo/Y/+X87KpySq5pml3DTOOWeWMQ1aUI6PYSK0
         Njr4WudyWN80ruea33toX3DecFGFtpAZtST165uEwqWo7zFpisjY4q/0mJtQZDnBEBOm
         tEBf48fEE7xBu1IQUGo9Q8AzluH+z+tRUtgdBQJXj9/BpuFBlZZFABgYWWYaEFtym6r9
         VgugjVH7jAUGUqLUiGOIlPg4m0RetLGwzPajUdlWObELIPBMCphM/ogRe8qrfat3z759
         Gq9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=o5OLh1G5igJ7wfCkEas83RRSlonR9xfZGMUuvDY/DE0=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=zhZcAdd+m+lIE48nTMy+XoqNSDZobCWWgksdmmYJrcdS5d1FVOgzZyWxVt9kknjlUI
         eBvjyFavXe9riQGZjI6EInONllxcQZkVgevqqyoUxICYkUtAMXo/Cbt4Zv3xT8ib7iXq
         KHhXqXMLO9RZWkCu4Ls2ww0GjHzkOE2SBEGqeAZVHbtz+rOi2dstIKBT2zZk3BUEGW7o
         l4z/zozvnpiAS2smEnu0HqP8xuSZja94MZs68cwG155WuDTXRiD/vGVJ+MJgGlTX2Stp
         LNVbmGZFKKI/hoHKlMW8ElQuK7Pp3M5T7F0jwo73B8HxwmnuEIb5aE6tvoPfjf+4fqys
         75vg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=EVMWG01B;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4b9d12706d3si45767173.6.2024.06.21.04.37.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2024 04:37:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353726.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45L9wphq019602;
	Fri, 21 Jun 2024 11:37:29 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw7by86pd-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:28 +0000 (GMT)
Received: from m0353726.ppops.net (m0353726.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45LBbS0q005032;
	Fri, 21 Jun 2024 11:37:28 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw7by86p9-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:28 +0000 (GMT)
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L9KGho030990;
	Fri, 21 Jun 2024 11:37:26 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yvrssxvbh-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:26 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45LBbK5U55378330
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 11:37:22 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id BF09520043;
	Fri, 21 Jun 2024 11:37:20 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 351DF2005A;
	Fri, 21 Jun 2024 11:37:20 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 11:37:20 +0000 (GMT)
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
Subject: [PATCH v7 19/38] mm: kfence: Disable KMSAN when checking the canary
Date: Fri, 21 Jun 2024 13:35:03 +0200
Message-ID: <20240621113706.315500-20-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621113706.315500-1-iii@linux.ibm.com>
References: <20240621113706.315500-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: qNNzZXoNK5Jx7e0m-RV4t8XuUyzuBdnJ
X-Proofpoint-ORIG-GUID: 9nqHha1GsHQHCk2fCPLnLz5EA_SBzbVx
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-21_04,2024-06-21_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015 impostorscore=0
 lowpriorityscore=0 adultscore=0 spamscore=0 suspectscore=0 bulkscore=0
 mlxlogscore=999 phishscore=0 priorityscore=1501 mlxscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.19.0-2406140001
 definitions=main-2406210084
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=EVMWG01B;       spf=pass (google.com:
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

KMSAN warns about check_canary() accessing the canary.

The reason is that, even though set_canary() is properly instrumented
and sets shadow, slub explicitly poisons the canary's address range
afterwards.

Unpoisoning the canary is not the right thing to do: only
check_canary() is supposed to ever touch it. Instead, disable KMSAN
checks around canary read accesses.

Reviewed-by: Alexander Potapenko <glider@google.com>
Tested-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kfence/core.c | 11 +++++++++--
 1 file changed, 9 insertions(+), 2 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 964b8482275b..83f8e78827c0 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -305,8 +305,14 @@ metadata_update_state(struct kfence_metadata *meta, enum kfence_object_state nex
 	WRITE_ONCE(meta->state, next);
 }
 
+#ifdef CONFIG_KMSAN
+#define check_canary_attributes noinline __no_kmsan_checks
+#else
+#define check_canary_attributes inline
+#endif
+
 /* Check canary byte at @addr. */
-static inline bool check_canary_byte(u8 *addr)
+static check_canary_attributes bool check_canary_byte(u8 *addr)
 {
 	struct kfence_metadata *meta;
 	unsigned long flags;
@@ -341,7 +347,8 @@ static inline void set_canary(const struct kfence_metadata *meta)
 		*((u64 *)addr) = KFENCE_CANARY_PATTERN_U64;
 }
 
-static inline void check_canary(const struct kfence_metadata *meta)
+static check_canary_attributes void
+check_canary(const struct kfence_metadata *meta)
 {
 	const unsigned long pageaddr = ALIGN_DOWN(meta->addr, PAGE_SIZE);
 	unsigned long addr = pageaddr;
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621113706.315500-20-iii%40linux.ibm.com.
