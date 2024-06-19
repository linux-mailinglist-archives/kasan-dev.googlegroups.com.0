Return-Path: <kasan-dev+bncBCM3H26GVIOBBMH2ZOZQMGQE2TQ7BSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 3123C90F2A5
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:45:54 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-5bad4f46273sf5566851eaf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 08:45:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718811953; cv=pass;
        d=google.com; s=arc-20160816;
        b=l5aAvolMb96agRlxvzVE5Ppbdgdn0h1/zpWnc7TElfH03bm6grVso16NquZ58OYqki
         CtAUJREQcg7ecf7VsQzbNj+pImMf98vfBfea+kEk8w0bw3GZaslD8ds1PB/M/1xD5/FS
         UdyvoSkes7NEykHTdmifS29Fjj5Lprlg/Sxd2AbeLvdyr+Jq2/NL5N2OLASBqFGsFbgu
         ECSDFpFPCp5Bidpi0wyHn5VQdd4DhxE4nmk7BreysLkEjVJB7/fbyg6QHUXR94abB6OJ
         NV6xzS4F4jdrrwqr89bC/8qn7ROipdUnCJiC6xTyH1L/h6//aRqzEs8fcBayAH4C7pe6
         6ESQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=0JqTUiCJa41mpuThP/KxzzbdbfVdObOmOJzTXt2sHA4=;
        fh=K4Qm69pNtMT9Uw9rG90/brlQkwB5vUPXkxWUCKaADdA=;
        b=hER94/rZcLaFN9l0LZFm4FH7k1Mr1a0uDbheM/Gm+PafsN4j1ayNJ2yB50mKfBVDPw
         4qUbSSZ/7/CpgKd7Vt7ThJ4m8TR+8N5otx/LtVlgZ8LDmNdS0WfJG9YqwGZtumzZj6cc
         PTdFS2VczzIcDwgM2lksGuUH3//nZqOQpBxbXO4/mR81QkjJw6qkep8/NCWrqg93ujlx
         r/pUy2RkhR3/F+ZXRubJ7X6oVwRjPPn84pLNS51iFIbmjjR3XojwZsovSQbMwURhlIK+
         2KWswQRFJRKyrv3MxtPttieqVHry4yZO23eJrmXmNn+0o5MWlf5Hh7dUIROUZgi7m4Un
         dNJA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=UdmUX2rS;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718811953; x=1719416753; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0JqTUiCJa41mpuThP/KxzzbdbfVdObOmOJzTXt2sHA4=;
        b=EQUuVGjpczX6DRdO6WdSfa3wqVJkkiugousW9YCijtpHxDZofO0UR4ktkZckGVgV0w
         8Xm4hwDBgAbNvWX/4pK/SCmw90Ktwo7m0ObhDazP//8oD7kdnTSVDh3BEi8/LcNt8DaF
         XsuQTvd1tbWh9gdDjxpNi1e74GrqAJLevooBQhsrMaIOnXRuLlxuia0D/QFQkFSmrLMr
         L6nFgBPCwTkRVZYEJMVBAxX9Hz4WnO72mtmb4JtEHf1SFG3VREh74sxzAW7B/0L13Dl/
         5jrISB6WTlLV4xgHJrOr4o2qxSrpjlFdRxZdHMD+5njfZHDscMR1DcyyZptDn328d7qh
         ft9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718811953; x=1719416753;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=0JqTUiCJa41mpuThP/KxzzbdbfVdObOmOJzTXt2sHA4=;
        b=fnsg5zD/kutLsNB4uj9dkTLUB+renNlt1s6gHHLFg+BzggM8Lm1rzTXSrKYmYwxxPT
         L2OkhCnoU5lzN4/zffGyvp1G9ovNAc2qv38JXNV0YP82t++pesaakYKhsurZd8X7G3RF
         4dUALYxSA2HnC1cTSPw0pHnwaYvzKWzJ+mq73Kfetnd9A7dDN9EZE4BlYUSOUZ7FzmJh
         7uYqmaPJYuloiw7K6nyYJZzR33nphnyIx+mLy2FBFTqY0euLHtqmrpXnjrxA17WrrdM+
         PypCtuZ0r2M3Wu5ZLRlAkEhoeI46vp3OC++GxDtovBnV14hRTkvZA9n5wY3YPCmWO7lN
         fIFw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVDn47JLt1YHD1gPwWnxTLHrzQ+vm1RU2x+bKGObJTJfuRhirgdHt02pAGw4maGWl6TdJbg+JMIEFKnmSs0hzFhka+1U6bzQw==
X-Gm-Message-State: AOJu0Yyl4uGUsvXssE/jY7a1ZSZQC/bN51ZZ/9jbK9cZmNFwpM6qkPDh
	E6EBf2ITftjymeWULGoqLr6trGfQ+ACtbI+4xMcaiCKeX9xVfk0g
X-Google-Smtp-Source: AGHT+IHoNjlo7u7SFqpsGnZ4DH8KriXPLqra4BrrFuDwkc5JFrBrRS5PwZ3yUozqGC2goTAhwVPyIQ==
X-Received: by 2002:a4a:d29b:0:b0:5bd:15fc:8feb with SMTP id 006d021491bc7-5c1adc24d49mr3085215eaf.7.1718811952896;
        Wed, 19 Jun 2024 08:45:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:5548:0:b0:5b9:d066:ebff with SMTP id 006d021491bc7-5bcc3e2b61fls8008509eaf.2.-pod-prod-02-us;
 Wed, 19 Jun 2024 08:45:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXIkCAk0HJwnh5yZmH+eJ9kjGOaZl0Wtc6K2AlDgDm7yviJqZnBxJKDWT796DA+CzgZjW0xxTEoxM13ZNLjCeCeBuT/pYtCWMrXyA==
X-Received: by 2002:a05:6808:1447:b0:3d2:2a0b:cf1b with SMTP id 5614622812f47-3d51baea35dmr3483876b6e.37.1718811952171;
        Wed, 19 Jun 2024 08:45:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718811952; cv=none;
        d=google.com; s=arc-20160816;
        b=QD/suhf17NyMLuS6mMPFN6u8BlIU/awIvLvGMLBpcio9JlFtjdtn5i2inWXRMv4Bvv
         mHgJJMZTgBPPeNuBW5qnVuRMGugMXT4BQlVBgvmUNtWERP0jXs4WgBDJac3z+u7M/N2m
         0Qr58W1IxjBiXRU0GaFgZtEB1zY3B1CB5d1xkPWRCc5Xp8Wt7V1AYb8m3wmMWIbUt9tS
         NoA6Blf16EDegLJAQxIvK8wpuLvvpuDYTgYUgiX0+wA6O2Mn4qSGVEQvIj01X4Sp2l4i
         QxjEXQwhltEiJ4xBlbGQN5MzevG+xtmhg04QP2ddhPZ6neB3vfsyylAXF6CCRowDW5tV
         /gdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=pcK1rMwKAY+PK8Ytyz/2vRX/RRHh9XTkiYTIv46ktrM=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=E6gOgEjUvxoyx70dKPJdWas2KAXsWqgVJHzKzYGmpyMCopZbKg2yBSZAohWKGnPZXc
         iPLwbPc5V4YZyZTKI/pep8RRS8XHVVjRZaaVc0VSQvxvF4l2oPFfLZVwIQ9V3HIH9Ubv
         2cT02NEMqp3NVBGtg6tS/xfvfcsH8s7XL/L44b29CHDojxIf5bTeOdSpiRDXKTe6HBED
         lBc7TN3W/2hEMfNyvSnaxhUB8GNbdDNn+04tmoOjMv3XKXD/1+ByZFm8AaP0uMm6vFge
         K8zTqOfHo6HfrLh/9ItL44Uob8MLcdVoP8TqwEBNS74QnGoXSobv8XXNH+RM72Wdu53c
         pBew==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=UdmUX2rS;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-444a41c5be9si1733901cf.2.2024.06.19.08.45.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jun 2024 08:45:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353729.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45JFSHmo028054;
	Wed, 19 Jun 2024 15:45:48 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv20g81kg-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:47 +0000 (GMT)
Received: from m0353729.ppops.net (m0353729.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45JFjl9B023058;
	Wed, 19 Jun 2024 15:45:47 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv20g81k9-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:46 +0000 (GMT)
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45JF4DXW006227;
	Wed, 19 Jun 2024 15:45:46 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3ysn9ux8mt-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:45 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45JFjeaP54788530
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 19 Jun 2024 15:45:42 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 7B54C2004D;
	Wed, 19 Jun 2024 15:45:40 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 2C0B320065;
	Wed, 19 Jun 2024 15:45:40 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 19 Jun 2024 15:45:40 +0000 (GMT)
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
Subject: [PATCH v5 19/37] lib/zlib: Unpoison DFLTCC output buffers
Date: Wed, 19 Jun 2024 17:43:54 +0200
Message-ID: <20240619154530.163232-20-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240619154530.163232-1-iii@linux.ibm.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: fNSA7rxQcjUO_BxsfnhTGdmZOWmRr0mq
X-Proofpoint-ORIG-GUID: 7QNT392Ow3-clchJoP3ZfMKSmByGf6eo
X-Proofpoint-UnRewURL: 0 URL was un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-19_02,2024-06-19_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 bulkscore=0 suspectscore=0 malwarescore=0 spamscore=0 impostorscore=0
 phishscore=0 clxscore=1015 mlxlogscore=999 priorityscore=1501 adultscore=0
 mlxscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406190115
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=UdmUX2rS;       spf=pass (google.com:
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
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 lib/zlib_dfltcc/dfltcc.h      |  1 +
 lib/zlib_dfltcc/dfltcc_util.h | 28 ++++++++++++++++++++++++++++
 2 files changed, 29 insertions(+)

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
index 4a46b5009f0d..10509270d822 100644
--- a/lib/zlib_dfltcc/dfltcc_util.h
+++ b/lib/zlib_dfltcc/dfltcc_util.h
@@ -2,6 +2,8 @@
 #ifndef DFLTCC_UTIL_H
 #define DFLTCC_UTIL_H
 
+#include "dfltcc.h"
+#include <linux/kmsan-checks.h>
 #include <linux/zutil.h>
 
 /*
@@ -20,6 +22,7 @@ typedef enum {
 #define DFLTCC_CMPR 2
 #define DFLTCC_XPND 4
 #define HBT_CIRCULAR (1 << 7)
+#define DFLTCC_FN_MASK ((1 << 7) - 1)
 #define HB_BITS 15
 #define HB_SIZE (1 << HB_BITS)
 
@@ -34,6 +37,7 @@ static inline dfltcc_cc dfltcc(
 )
 {
     Byte *t2 = op1 ? *op1 : NULL;
+    unsigned char *orig_t2 = t2;
     size_t t3 = len1 ? *len1 : 0;
     const Byte *t4 = op2 ? *op2 : NULL;
     size_t t5 = len2 ? *len2 : 0;
@@ -59,6 +63,30 @@ static inline dfltcc_cc dfltcc(
                      : "cc", "memory");
     t2 = r2; t3 = r3; t4 = r4; t5 = r5;
 
+    /*
+     * Unpoison the parameter block and the output buffer.
+     * This is a no-op in non-KMSAN builds.
+     */
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
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240619154530.163232-20-iii%40linux.ibm.com.
