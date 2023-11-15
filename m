Return-Path: <kasan-dev+bncBCM3H26GVIOBB2GW2SVAMGQEX2OVZMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 621587ED227
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 21:34:50 +0100 (CET)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-1ea01dcf2ccsf1044595fac.1
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 12:34:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700080489; cv=pass;
        d=google.com; s=arc-20160816;
        b=gHrtgHlnaMeICx0LI4svf3FsPUG1FXq29BSt7ohKwrtY0dmOgwOM5Y3FoQSDn7InTk
         FZJGECvAcw19mf5vPwX+etK6MipWlyyyaDW1ngoD8L64l5wQoJQQAu2nGyly6Rc2bPE3
         0qI/pXhAvLDhXXTFIII9EuXNDcE8vayMa4aJYeKrSpVlTJUj902DXI0qbq3QO/Cbzkri
         +De5G4Ixe8bnPjQgeIneA4HUavi79LEvvN1tOS88dSPQt+yA/lbHWX6b3CoBo6kiUUKM
         GqP07nVtKOSTzNdFrTe4eulGrOmAjbQofmxGUleJt19qCjQJNAZSEqANQ4PkGOmn3afv
         U7NQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=53Y4Cc1cTvN8C5+7tvmWSGFSi9wA4eIWvt84H8/oc3M=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=AYGRCI0+79jKarRMobkIqkWV0/ugHvO3gt4cjFXK/R34d308GskBx6BYAIWiC/Kh95
         OjNhkgRIedNbczaWaLfXWA/iIC9od/gqi7EjMpeqtqF/8AsdxaUx2ohxKasEUaSCY6D0
         Cpq66TzWvv/VMzOQsTh27vXfQubXv2ShZgsnLlzHCh50o09xTMf8APj6fqedgodBvISp
         qahjg5VaKwtw8MGj0CI1m3QYC6FiP1BTwxHMzA9woSgnXuKtvzga1rCIdfj+a2Zw7Zlb
         kRVh3OMwyKx2pbjsSzRKwx+gfnZ9KajJqso9XX0kzjyNL1BpcLRmCdH8I6Z68B/Rm7KK
         ddgQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=YKFBdcKb;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700080489; x=1700685289; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=53Y4Cc1cTvN8C5+7tvmWSGFSi9wA4eIWvt84H8/oc3M=;
        b=JUlUpHRc7ieSaf6LqYJo76y6L9blhd4+sxmU5/1mKXCUgkSIjNnmbkTHfbyvW6JaHj
         4nZWMeKtTHm5OjlcT5V0sA+hPVmErEXyw5nWZrvlTdZNJJH6+dgEvzSFw6C9P7q7eQVT
         xOVjMeKyZPVnjfWbEh49oRfnhZAhqAAXE7TmOVDCQuFwqmTu1iXgp6v8AHqpgTE/uOt8
         uAfN0vSNU5JDLHAxJaU/M6iJkZd59to+AddfcYT5cc5sCqc5MsKhRML4jqk3Txlww0WC
         OZnQav3kXYTwsoFWq/dG48CzeYViT5NOEHWkYAkOmKS1S7im6Y1YSCgOCCvl2EnupvB/
         Nx6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700080489; x=1700685289;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=53Y4Cc1cTvN8C5+7tvmWSGFSi9wA4eIWvt84H8/oc3M=;
        b=TDGEXznC+pBes6t4cmJ+8yGzqLB95IoeWSlbVW5d2jQwEdQ9CstzcCgdPbXpTe3bsQ
         gUxopp81N1A/UTDbVWkomJs2DSjN7bWHHxbNJ/mKPFehNreIE94JEe8z2p9PFtJpHW6L
         mTQ0fIJ6LWe4UbpK30LMYNZw9/L7LITJ8552UEqTnzAdAJmLg4ieNv0ooV0cUYtWVn5P
         xXt0jWtwyUZ28Lx3kuYmdlChwAFfIjE5385K/nrCWNV5wNcy6JvFZSJ4e3GjlGP4xTEU
         LG5mwQ0SKaAnR6EiZC+hCnyeDKstxTN8iy3B6F1cSIAIsikQ59tNMXcs7HdVXjuM6qEa
         WhRg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Ywh6WFzV3Anf5v3lC5pUGobGvEotBrySxWQoyKoscQR9qidOjUk
	Z9aF1yFBi+Z+x++h+mTnze0=
X-Google-Smtp-Source: AGHT+IHBC+hd3j9MBK4Dz1tza5vXoY0l/SpxfgmHHDwypWTTe3GniY3zxeFslwTZZJyL43UjvD30CA==
X-Received: by 2002:a05:6870:be8d:b0:1ef:9668:b532 with SMTP id nx13-20020a056870be8d00b001ef9668b532mr3575827oab.0.1700080489030;
        Wed, 15 Nov 2023 12:34:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:9e43:b0:1e9:923e:98cc with SMTP id
 pt3-20020a0568709e4300b001e9923e98ccls136476oab.0.-pod-prod-00-us; Wed, 15
 Nov 2023 12:34:48 -0800 (PST)
X-Received: by 2002:a9d:64c3:0:b0:6d6:4a5f:47b4 with SMTP id n3-20020a9d64c3000000b006d64a5f47b4mr2710286otl.13.1700080488413;
        Wed, 15 Nov 2023 12:34:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700080488; cv=none;
        d=google.com; s=arc-20160816;
        b=dtadzYz054vCBVbuegtOER9OoboBjZmHyfv4QCT+WggRoxNdmTkj1VOPrTFigeigHu
         rpQBQYh2GJ/R4zCG7Nhhk2HLJesVmnZfREnPcjw6RnI8BYeE1/T2zGIMetGEixtYyuhv
         pRiCGSi+UGM0gqXnDs63Q9JKGG+FM98t3brR7bGJdJIIMMWJfMNF7WknpQYsVhTbfqJy
         EYzeaFOPwpJrYKtyseZFy1aV9DoIYRYKBoZFdX/Ap4FKJaGznsPop7wSgFaYvWGz5Qab
         8o2TG6rv8/VvUZmR8EaHsXFvtf5eveTR697xo36ywZp0BCey5Pw2xdViLkkR8X2rk6pT
         KgmA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=JR4hU8usmRDdin50s82nkAgu6ZMVd3+rhBewhZJH1Ks=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=KP6MI9UtlU3mIJiffzntvHu/a2JPk5A0Q1F2ZMz3wyDdUK1k0fh5Gebd49M9Op2frD
         QzfGScZPpJGq6nzOq69d199koryLUi0jZQcorqxOjWuTrvQc/zcKCY8KQC9MkLkxu6NM
         bJH2S9q2Ir21bV5drsUblCs/LnpYdcSWX/SkTliZTBkFaMPIZC+jtEKUAXmnboxOi3RK
         +g22VNCI3rI9UTJFlH9tm5PlxUgU9WXMyevCl5aYEWB+bmp7D/RoJyYeSQua0wddezQR
         5zlGs6+XGwzvWIVLvSmhM/II6KLlvh4V0vS44pQoRVuR2x7nlodsnrMxLIcX/4nb9XRx
         lL1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=YKFBdcKb;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id v10-20020a05683018ca00b006ce2f207148si644754ote.0.2023.11.15.12.34.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Nov 2023 12:34:48 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353729.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKRoBX004604;
	Wed, 15 Nov 2023 20:34:44 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud51q060w-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:44 +0000
Received: from m0353729.ppops.net (m0353729.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3AFKSEvw006055;
	Wed, 15 Nov 2023 20:34:43 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud51q060h-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:43 +0000
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKItrc010007;
	Wed, 15 Nov 2023 20:34:42 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uakxt2dv3-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:42 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3AFKYdCM65012072
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 15 Nov 2023 20:34:39 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 55E0920040;
	Wed, 15 Nov 2023 20:34:39 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id EA6ED20043;
	Wed, 15 Nov 2023 20:34:37 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.9.51])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 15 Nov 2023 20:34:37 +0000 (GMT)
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
Subject: [PATCH 18/32] lib/zlib: Unpoison DFLTCC output buffers
Date: Wed, 15 Nov 2023 21:30:50 +0100
Message-ID: <20231115203401.2495875-19-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231115203401.2495875-1-iii@linux.ibm.com>
References: <20231115203401.2495875-1-iii@linux.ibm.com>
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: FcmPA45PTLlNdzoYRSKo5ivTe4t5LzGg
X-Proofpoint-GUID: 9RBqKpW0ebiKf9o1-LJaYDwqoA8WDNjK
X-Proofpoint-UnRewURL: 0 URL was un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-15_20,2023-11-15_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 spamscore=0 impostorscore=0
 phishscore=0 suspectscore=0 bulkscore=0 priorityscore=1501 mlxlogscore=999
 mlxscore=0 adultscore=0 malwarescore=0 lowpriorityscore=0 clxscore=1015
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2311060000
 definitions=main-2311150163
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=YKFBdcKb;       spf=pass (google.com:
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

The constraints of the DFLTCC inline assembly are not precise: they
do not communicate the size of the output buffers to the compiler, so
it cannot automatically instrument it.

Add the manual kmsan_unpoison_memory() calls for the output buffers.
The logic is the same as in [1].

[1] https://github.com/zlib-ng/zlib-ng/commit/1f5ddcc009ac3511e99fc88736a9e1a6381168c5

Reported-by: Alexander Gordeev <agordeev@linux.ibm.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 lib/zlib_dfltcc/dfltcc.h      |  1 +
 lib/zlib_dfltcc/dfltcc_util.h | 23 +++++++++++++++++++++++
 2 files changed, 24 insertions(+)

diff --git a/lib/zlib_dfltcc/dfltcc.h b/lib/zlib_dfltcc/dfltcc.h
index b96232bdd44d..0f2a16d7a48a 100644
--- a/lib/zlib_dfltcc/dfltcc.h
+++ b/lib/zlib_dfltcc/dfltcc.h
@@ -80,6 +80,7 @@ struct dfltcc_param_v0 {
     uint8_t csb[1152];
 };
 
+static_assert(offsetof(struct dfltcc_param_v0, csb) == 384);
 static_assert(sizeof(struct dfltcc_param_v0) == 1536);
 
 #define CVT_CRC32 0
diff --git a/lib/zlib_dfltcc/dfltcc_util.h b/lib/zlib_dfltcc/dfltcc_util.h
index 4a46b5009f0d..ce2e039a55b5 100644
--- a/lib/zlib_dfltcc/dfltcc_util.h
+++ b/lib/zlib_dfltcc/dfltcc_util.h
@@ -2,6 +2,7 @@
 #ifndef DFLTCC_UTIL_H
 #define DFLTCC_UTIL_H
 
+#include "dfltcc.h"
 #include <linux/zutil.h>
 
 /*
@@ -20,6 +21,7 @@ typedef enum {
 #define DFLTCC_CMPR 2
 #define DFLTCC_XPND 4
 #define HBT_CIRCULAR (1 << 7)
+#define DFLTCC_FN_MASK ((1 << 7) - 1)
 #define HB_BITS 15
 #define HB_SIZE (1 << HB_BITS)
 
@@ -34,6 +36,7 @@ static inline dfltcc_cc dfltcc(
 )
 {
     Byte *t2 = op1 ? *op1 : NULL;
+    unsigned char *orig_t2 = t2;
     size_t t3 = len1 ? *len1 : 0;
     const Byte *t4 = op2 ? *op2 : NULL;
     size_t t5 = len2 ? *len2 : 0;
@@ -59,6 +62,26 @@ static inline dfltcc_cc dfltcc(
                      : "cc", "memory");
     t2 = r2; t3 = r3; t4 = r4; t5 = r5;
 
+    switch (fn & DFLTCC_FN_MASK) {
+    case DFLTCC_QAF:
+        kmsan_unpoison_memory(param, sizeof(struct dfltcc_qaf_param));
+        break;
+    case DFLTCC_GDHT:
+        kmsan_unpoison_memory(param, offsetof(struct dfltcc_param_v0, csb));
+        break;
+    case DFLTCC_CMPR:
+        kmsan_unpoison_memory(param, sizeof(struct dfltcc_param_v0));
+        kmsan_unpoison_memory(
+                orig_t2,
+                t2 - orig_t2 +
+                    (((struct dfltcc_param_v0 *)param)->sbb == 0 ? 0 : 1));
+        break;
+    case DFLTCC_XPND:
+        kmsan_unpoison_memory(param, sizeof(struct dfltcc_param_v0));
+        kmsan_unpoison_memory(orig_t2, t2 - orig_t2);
+        break;
+    }
+
     if (op1)
         *op1 = t2;
     if (len1)
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231115203401.2495875-19-iii%40linux.ibm.com.
