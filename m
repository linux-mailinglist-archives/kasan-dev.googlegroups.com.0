Return-Path: <kasan-dev+bncBCM3H26GVIOBBSNFVSZQMGQETNPEVSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 12F9D9076E2
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 17:39:55 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id 006d021491bc7-5ba6394f7c6sf1074137eaf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 08:39:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718293194; cv=pass;
        d=google.com; s=arc-20160816;
        b=rCL8u+3E9jtJqtpJboOY+tQyqB/m2uBXt4pcYKTxBOHoDK/q7q/DodKnYi7jvIyWA4
         A6dTmd5ge8xyqVh0NxQaGNWKwvVPLqAXsmwYQJDQfOuH9q42xvBjv91dTJ4XvXxbCWB3
         aKWSG8KNRIgJY5OkinxgCmLAgn2qMq6PsJKaspzwuWea34uVzpKz5djwjNpBUckXPIp0
         O/2Spq/tLoADthmkjZfBhXmyfT78QjByE0BXiEnFzC0wGsknVf6373T/2j6LH2wcAZGl
         TXtzPKT5yeR8OfQOOJ/FCxhLaKrr3gV7fGokm58SULh+CD8nEXVOOQgZNPgf0UP8Z+T6
         Zudg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=G2V8Z4avnLugcOmk9uz7iMC59x5i158paiuy3ejN7LQ=;
        fh=RGH0alvkZstYOxaLCMDzMS/iBeWVpG5r1/LBW0eUYCk=;
        b=QVTxqI6F4SwcKvTKlyexXa0l2fXB347G5yaZkorSJTyjqNyOlEBuu3kEDLgqZtkiiK
         2187iINtTjjS28xjgXKo1cOSW21x65x+uy7/XDhl4RRySGkWnGfBlzkbao9McW0Cm/vD
         TkFvVwPO3DzB6buPx0BjfodglcPiFflA8cAUvFCUFJq416LYxXfO6lBpEY14MyYMlyzz
         kRrGsKPWmLpZX+afVexO3Es8c9mKCkDWsQafQv6k05XiWLf49cNNZTXy2D2YtHwNYelE
         jAo8OcrpFggDCgbxhoExxmOVqM62eXDbIm+eAKpYip6yDH+xAKYLZThxgol9ljT3jgZE
         /jiA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=TpSsq8cF;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718293194; x=1718897994; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=G2V8Z4avnLugcOmk9uz7iMC59x5i158paiuy3ejN7LQ=;
        b=KjzpP+CtA8T4PSrdLNw6VyhnZx8ZiGowBF3f+oILUL3tz/lOfQ5fanZDKNXEvhnsFo
         SXeXLnqasMxpaE1w8MTtbM5Rmu7t52Jn6ZvIsCR5B1gtuO8lc8glZte+lkPYmXOCJ40/
         HkPISj/vTDI1G1qHkpzIAdsze/Zwrd3z/85NHUuoKhNr+vHUzaCdasozJDrhSc12mN9t
         zF4kl7Xdd9eE/5yShs25VhEdDd+OrfF3u2PWrKZGzomI3eY6saoGd8Nk9wQ8KP6NqxLM
         TZVLcoV4MXpX0QjqZX/MoTSlulL7kZVhTdiVR7XyykxqhnNIxD/ABooalRcnVscFVNuC
         +kHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718293194; x=1718897994;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=G2V8Z4avnLugcOmk9uz7iMC59x5i158paiuy3ejN7LQ=;
        b=Q3sfz7C61Pyd3XbmzphW4EJuKdgj7hGKo9JXq/e8BXmVt9UUJL7IumIMQ6Gn2yucjX
         fw2zftK7gevljHjGmBNy3x3VKPCni7iWhdFL2hlj4nM/euezyx32h2iqV/zCBBdOAh6U
         TKldmzW/Bv+4aKybK8WDwFfexSw3qQ8rDzp/1r/fLafGw9+o+FuAJb09y4Zbr1N9RkgL
         ig/Jjadkd/4heUlFlN0Af+bGepQ/M/zARRyCifaH1oHtti4AikcB5tIEAbdOCMtKslG5
         7ADv2hyev30ZHAsCzcPzw+ZIkuZVEor2WZ4geVOgQkl7kkKAj9iEl5GD3m1KzeiJ0Yu8
         W3ow==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWEqoA8Wus616SIi60WxSKWwOLAm3yUifXzxPG7aAVxpz+lPc89rIC3HiO9KgFHA1zTxdctxQSX6/DUnLOZH9lKHFhltOqPuA==
X-Gm-Message-State: AOJu0YxWldwyx0Uu9Phwmko9WCexpuyT2eWA+x6W5DP9guCJsqtD7aHt
	rMKL4dcCNaN/5DpQ6zCTLgdOzX4WLeuSQ/xQiUp39kaAYcZDoczO
X-Google-Smtp-Source: AGHT+IGLIdukG/go0OBnFQyGL8MgdPsHjr+WX5E/tvmWjZDCR83GvfISgTytQjRH4ZMXS1K+UFLZgQ==
X-Received: by 2002:a05:6820:806:b0:5ba:f269:2af3 with SMTP id 006d021491bc7-5bdadc41ac8mr14190eaf.5.1718293193811;
        Thu, 13 Jun 2024 08:39:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:5896:0:b0:5ae:1f6c:897e with SMTP id 006d021491bc7-5bcc3e2ca6bls816201eaf.2.-pod-prod-04-us;
 Thu, 13 Jun 2024 08:39:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVMdMdkjxJ/sduuMWis4Es4aY4pF76niOwUxFaF0X6rQbro/QqXLA9hPCK/U92OjQhjKLFog29EC2ZdhMObgmmyuyz1bqGCNzq4kw==
X-Received: by 2002:a05:6808:1789:b0:3d2:25c6:c521 with SMTP id 5614622812f47-3d23e0ce2c9mr5390934b6e.51.1718293192908;
        Thu, 13 Jun 2024 08:39:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718293192; cv=none;
        d=google.com; s=arc-20160816;
        b=yp5fO5mExilQv54xfUZ/lrkFZdQqAr6OCGB6IBwr4uGqdHtMAaUVbi2U/a4Jr+ogLa
         o2H4Vyjj2kSmsLjjaXzwZ1Csd+/is63KyP0PKSC9Tu+u4WNt0QuRF0DP5zFSWVAjj2Bx
         FuZhrcr3oTz7x9pDHd6k89gzu0Tf1DtFZBIx2bK1lUaRBM9YBqGaP1neKu97wkh66lIK
         Ddac/GTM4jKtx6PsFMhr4ApQv8c0K9GbQ9BxsERh/MjE4aq1beOjb4DwSLivzj58OVpe
         6Ghcbt/T5gLY1QbSO5Sy4kRd1iCbsESfVg3iGLNjFWVbkHq0/bDscifKqgPUxay9iqwt
         i2fA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=pcK1rMwKAY+PK8Ytyz/2vRX/RRHh9XTkiYTIv46ktrM=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=k2iWUv03mJC3lAZi0ekKo1DByVoN8BpnkW0QwLtTZuRQlcVPYjBG4f73sYJjcsMvBI
         W2+u9AzrNOnNx3PTVGQZvIJRviB+3493SeAlqNiIEg4AAL1Pp+Ju7A4G+OA6B6yRFUsz
         E9M/KSL6UAS5b5/WsVZ/jY43WFJsZABLN18u2S64vaKF4STak1LNRTlN5O89y+kd7vni
         KiMlVGGknFL0cG1GDk9oQ1JYp8VEym6n4ex6KgqYeUIlFUB6vngz/avK6sEoOd1FSnU7
         yPY3hBtDbX7WN2dGXUwnTDwZzJqP6sg+muZZI3ehym84+davt4rA7ohpA7RmkGeHrBts
         jDkg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=TpSsq8cF;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3d247667130si88087b6e.2.2024.06.13.08.39.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 08:39:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0360072.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45DEQSMW026603;
	Thu, 13 Jun 2024 15:39:50 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqq4u2373-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:49 +0000 (GMT)
Received: from m0360072.ppops.net (m0360072.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45DFdn8N009704;
	Thu, 13 Jun 2024 15:39:49 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqq4u236x-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:49 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45DEAZNn008701;
	Thu, 13 Jun 2024 15:39:48 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yn4b3rk19-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:48 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45DFdgpn54854064
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 13 Jun 2024 15:39:45 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id CEE4A2006A;
	Thu, 13 Jun 2024 15:39:42 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 5C27C20067;
	Thu, 13 Jun 2024 15:39:42 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 13 Jun 2024 15:39:42 +0000 (GMT)
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
Subject: [PATCH v4 18/35] lib/zlib: Unpoison DFLTCC output buffers
Date: Thu, 13 Jun 2024 17:34:20 +0200
Message-ID: <20240613153924.961511-19-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240613153924.961511-1-iii@linux.ibm.com>
References: <20240613153924.961511-1-iii@linux.ibm.com>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: ZkRkVKlaPl-5RHA19x1OqnW-klsEghkh
X-Proofpoint-ORIG-GUID: Ftz9VuNKiSSNqeta_DO5F7fudUAWQDRT
X-Proofpoint-UnRewURL: 0 URL was un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-13_08,2024-06-13_02,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 phishscore=0 suspectscore=0
 clxscore=1015 impostorscore=0 adultscore=0 priorityscore=1501
 lowpriorityscore=0 mlxlogscore=999 bulkscore=0 malwarescore=0 mlxscore=0
 spamscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406130109
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=TpSsq8cF;       spf=pass (google.com:
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240613153924.961511-19-iii%40linux.ibm.com.
