Return-Path: <kasan-dev+bncBCM3H26GVIOBBLGU6SVAMGQE6Y7CN2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B6607F38E9
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 23:07:42 +0100 (CET)
Received: by mail-oo1-xc38.google.com with SMTP id 006d021491bc7-58a773cb807sf5692357eaf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 14:07:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700604461; cv=pass;
        d=google.com; s=arc-20160816;
        b=eA1z+hGj7Jqa+WIShqGnh6WfeOgvF3rzTioAJEwXxpQPS8hTppzv4+WEPYM8J8Ui3z
         kAB103db+U6D9eumX7nAp8wNpmrFthVhGtKMChDHkeTehDbDRcQnjhYbUUgxAFxGvcMj
         DxBF1hzMb/w701PjtUsG1P62+zRxOh3gtL0fMMiHnmMc7Ysg72KFwSZ7Z6wYZWTkryGb
         BzPtD1HnEOybM+VS6OYLlGQd4QnwB/jGEcH6YZVKYkP8Vx3hL/2p8QoP+FcZfiwY0kmX
         y4hzCckCo9zTKdCcHTpAyGeWcqsY4k476Kbgl4AOMXV8PruEQs/xm/uBJgr3VFE1hyCu
         g6kA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=gj3K9cN7FjRE2Ypfp0g56+Q5kYVgtZlzrmaNhdGpn5o=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=JxR2RShCBk3b3CPoeJ7boXjFtenb2tJ7lt5zn5MCrl/iC2K1HRKYOFn7AAQo54vHeP
         Yq4bj8p3FsLny1djRjS7Fl6fUgaKdcc5o71s1ytblWrtNDoTzMBgt1lpRdprtxcwYuGe
         ZIllsSQAYpVYuovINk6e9ZmyZGXFxBh0bUPL1Bh+b7IC5KdKREFJ7wEZbnvt+KOyRL6E
         xyT701DoP9YwSWu9nzrb//NnHXxezuPzJmRbWuzT6um3bnpixJs3MBa5qnaFITYJeTE8
         2g+b30efZYv1kGqeWdOqLw3epcw8UTJaCMgzNT/jJIQhR2nB4JeA3hVHB16/cGfEMkJT
         qkyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=fjfJvzVH;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700604461; x=1701209261; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gj3K9cN7FjRE2Ypfp0g56+Q5kYVgtZlzrmaNhdGpn5o=;
        b=n8rGshT2jfr8sut1fRWNENuM6KnYAu0kpPG9HS3fS5EyIOm76+6vcjAhyf++arC2uH
         YTK+2rWpAtMl9eFVs0zeUvzANuE5qZrPvEX2WyMLELb4/Hiq19BnBFJ4RQMr10+UK17W
         3J2N549HxZ703eNjoyNdycy8qqKprK689D96n6bFz6Va1Nedx6WtsSY0QekoDk19o587
         EZI9YtO+Ir60OyCjy215HgT4xcw0DXlgrAq9dAd/tvbk4ekh4YP+jx0wx327GmtsdC74
         sMAeox9eum8jh7zM4kxIS/2MAMvn8hLCfOUUQB/Aaf+pgCd6w5ah9u49TB4LYZOXdpRT
         fadA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700604461; x=1701209261;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gj3K9cN7FjRE2Ypfp0g56+Q5kYVgtZlzrmaNhdGpn5o=;
        b=SminYdwO7AARl8IaLbZRSOVfNTGSlhFOUk3zThyF/WA6tWIZLCQmaVeoqlxeYjLzSo
         V0NhPlbEVMEUu9nkSLbkpef+hx8EyZAaeGg+CRL9dfINdmv0YiRetDrwNkwuCev1fjgZ
         QCdZ8hxXxgKjk0F25ymQFF3mqI8cHQ9ZLo87cukDfid2drMbllco0cRTI/w1tl8z6SVH
         CuZjunmW7oKc2mA7q0/XUrn396yT/NZu98/pnmnlfRBkwXO7IrCMWn89DykCetZ8ROba
         ICId1HCLofQfZm8k2ZEDblBtx2gz0QEQWMf+iFRbU5MBufySGaKrCR/6nyaG75pX+hvo
         p/+w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yxk4jt/pIiE7dlVXo07IJDY1UMm5vKFAsEp7/5TJ1mFUCdPYsIy
	qGtkFcvp+MC5mrxP4j+K/w0=
X-Google-Smtp-Source: AGHT+IETrUYHuRakzcp8+ZP1veDg7UNXqp37nrqWMhyJU7Zu66/wQZG3nv2QgVulnWMX1TE8Dfk1Og==
X-Received: by 2002:a05:6820:827:b0:581:d5a6:da4a with SMTP id bg39-20020a056820082700b00581d5a6da4amr974262oob.1.1700604460822;
        Tue, 21 Nov 2023 14:07:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:e82a:0:b0:58a:b02:fee with SMTP id d10-20020a4ae82a000000b0058a0b020feels757143ood.1.-pod-prod-06-us;
 Tue, 21 Nov 2023 14:07:40 -0800 (PST)
X-Received: by 2002:a05:6808:2908:b0:3ad:fe8d:dfae with SMTP id ev8-20020a056808290800b003adfe8ddfaemr512954oib.57.1700604460192;
        Tue, 21 Nov 2023 14:07:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700604460; cv=none;
        d=google.com; s=arc-20160816;
        b=Xw6VDxvXmFty7+kkF8skWWAeXx/xwCaJ/rrVIm2TzMuan3Q9cqEEaIUmfSpbH/case
         5LQPN3O4TZaGMGbkeMO6gP5wvGNGOFuqW0q5q+FdIi+FKKEDz6dPDEG3P8AbhCARmEiH
         rmi1LeaIPL33PBmTo/tO7BYYEIiO199YMQqoX7o+Nel96pSACK70xMrxivVYOyA0Uko3
         rw2MUQnsSJB8NbKmZeQc4G+mAOjfDfNaeg7hEYrwmZ3ozEUemIOXiJQDK2Ps1JrO7eIK
         X+rOqeKUbL+38g/zy0x/78bCXZcwxxkYMnRJxo0Rv5UMebzaf75r653WZUehK2bewu9U
         wBBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=JR4hU8usmRDdin50s82nkAgu6ZMVd3+rhBewhZJH1Ks=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=JW4Vuu9d8zZC1AWe5f4Lx/e8wZcWtpIGld+FZhzPoQCOfE1wnyTfqoNfSSONex4wv8
         Gp6ykhb17ZcOXS0Hmnj/Z0O3luHsQ8SYZKrvVLAz0eeyzXbuM7/ocUb2x5ytut/l8k38
         Yb2B3j99oZw66gUT2gbmKGEUbDV9xU7twNcgHO/y+N87uL66QxE1eG5NUz3D85aJi0zG
         LPNM2X78Q9mEpnNZlMDcSTZhO9XsIgPr8fFErw/478qnFD48PWZ30P6bI7Si5BPHXRSj
         EJO9BYdIZ4dxwhPQ8H+IWRAeT8oJPU9Tuhly67UBPyEWixSfdPcqzyMxsFc58EvtmCmS
         ou3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=fjfJvzVH;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id gl15-20020a0568083c4f00b003aef18f3442si1178147oib.0.2023.11.21.14.07.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Nov 2023 14:07:40 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLgdjh032016;
	Tue, 21 Nov 2023 22:07:36 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4pw8n01-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:07:36 +0000
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3ALLrw9W029168;
	Tue, 21 Nov 2023 22:07:35 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4pw8mwk-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:07:35 +0000
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLnQTH022903;
	Tue, 21 Nov 2023 22:02:42 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uf7kt402m-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:42 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3ALM2dYD27197992
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 21 Nov 2023 22:02:39 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 2955320067;
	Tue, 21 Nov 2023 22:02:39 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id AB05F20063;
	Tue, 21 Nov 2023 22:02:37 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.23.98])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Tue, 21 Nov 2023 22:02:37 +0000 (GMT)
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
Subject: [PATCH v2 19/33] lib/zlib: Unpoison DFLTCC output buffers
Date: Tue, 21 Nov 2023 23:01:13 +0100
Message-ID: <20231121220155.1217090-20-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231121220155.1217090-1-iii@linux.ibm.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: ruTC5AuaPKwZQpHq948qdO8nDc1ULPad
X-Proofpoint-ORIG-GUID: JcaizAaJdkvAFfBmibrb_MXa3cUIbOnh
X-Proofpoint-UnRewURL: 0 URL was un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-21_12,2023-11-21_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 spamscore=0 clxscore=1015
 impostorscore=0 mlxlogscore=999 phishscore=0 mlxscore=0 adultscore=0
 bulkscore=0 lowpriorityscore=0 priorityscore=1501 suspectscore=0
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311060000 definitions=main-2311210172
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=fjfJvzVH;       spf=pass (google.com:
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231121220155.1217090-20-iii%40linux.ibm.com.
