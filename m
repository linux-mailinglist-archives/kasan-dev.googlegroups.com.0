Return-Path: <kasan-dev+bncBCM3H26GVIOBBEEA5GVQMGQEZZIXZFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 891D78122FA
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 00:36:49 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-35f78deb1acsf6868965ab.2
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 15:36:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702510608; cv=pass;
        d=google.com; s=arc-20160816;
        b=zpxIZvdNewkxDSAEdACtd8/A9uhu5KdtWYANAXCCl1xJSHHKhGoYyhlru0HzEJw/ee
         A/bAdZ5fuCwtDNUbrgpD1N1a91GwIpp6GV7deo3PI+iWAqAxRd74/qMC8xoRQ+7Ny6uK
         82sQybegNq00XMiY4kIgE2IglpsnytMNNXnL1Na25Dvhm340cm7FtOsdqNP6T3gybWIY
         ICiGsNyyQ6jR4WlcNeU0ZpiXQGdz4ePSE5vjPa7SUIAtUdhxUui+ojdL9UX4bW9H3urR
         baSR24ddIWPwQgYlrgsvvlW7nZ/qhvpHtRS3KwJKZpV5EeoMQrx6hHiRDBh20LcJB0j7
         iqxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=jfwI9AMyDOE4t4UUCMKSGfI4c7D39TDP052imr1jnps=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=Wx4JQN7ckMTe2ZpLVfAKYUrXyf+CaaIT9bQtQGmJh/e4m5O+Jxv/hnB/nN015m0Zqx
         EtHnTx89YdQTHC1DI7ezmHlHkO2p18PHT1WXVtIgnguBd2uZV2dojGgtYJ9jFKb6nI5V
         ddkhkjbPp+DIEmQSXVJh/zYrsNvWLDGL3QhAaSSF6x9KuF1L72zuUsAGqAPWPtJKdrVF
         EgGSwcFJRYS27RAKiwc0JmZqlWjNisHm/rrnAOFuRvrRZ+nzsPdtHO2XVFa9dWC8/xNH
         IMHABRiTgbsx0mQJsk0vsrwR0d+/VzuMAIgpkKXwgc6F8NuD8LUrBcmJFitnpZ3IiMBn
         +Dag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=sgnQGgAp;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702510608; x=1703115408; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jfwI9AMyDOE4t4UUCMKSGfI4c7D39TDP052imr1jnps=;
        b=fVA1GMjtA5IH+8k4ijFojm6RwUyVaFs2EV9LycSWzmSClb+aXlWIKwea54SXwpLLDO
         5Dua69cAk314LYoup3oOcN+9/IsACARF8vriMCpTXdP7c2TgrzJMUt3tvzETmnNa/bUW
         wlhfR/H59PQyjAutPnc1yANwiO3949cB61kvfnYx542Vk5RWhTnpFNeS/yh002YHE5ZK
         rkl0yPA7b9YcTe++iv7rF1cs0IeT/LobSRE7BM3GbzEfpzqxg8DELYgCWsWOMMD4Hn1E
         VzGqX/XNRynpS79ohSIGC8lWPnn9Cf7ESHwnLa+TvHrOy3BA0F4VZZayYdXq1nwsf8FE
         50yw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702510608; x=1703115408;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=jfwI9AMyDOE4t4UUCMKSGfI4c7D39TDP052imr1jnps=;
        b=riIbQuQOhugbeoOLmkdZEtitrRf5HxuhVsmimbXrTnt+d4J+fkzt5gbe2YaCgPQvbi
         rrFykw78XK8R3qsGq2I9P+dBHnCB8wBLzMSjvNLCn9u0gzI2qWQPy5MN8xAbkRHkLyG5
         HNKLCET/co/WfwdHdAZDl1R+7UNq0xcFYdEx+yGQ7pxrHxYqMxfnW0RtINFk8ihNB7wi
         eLJMzvGhtuCQCrgnsG6P9IQEdKPTlcMEOmyhl3Jk4idoviQlJUWwRaa0g3xdamAgSE8n
         4fFmuVXNyzIFjvw2ZGvc5jA42aTASnDxDwyHaLbaD3CXJpbbhq29sUp0IGUhIc07B9CX
         UvTw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzzegatNQXtzxO43X+ewm3jbWSBQq+76fbM87dIhbpuoglrt/FQ
	pK8Ij2shBPrNA531ibuR2Bw=
X-Google-Smtp-Source: AGHT+IEq5UjqgL4MX79d9mQu2A9zVb5+bsU24b+KjXx/SjkgSzB1ncIoccHQcMDs6HVggQ0DAPoVgQ==
X-Received: by 2002:a05:6e02:15c2:b0:35d:5846:377e with SMTP id q2-20020a056e0215c200b0035d5846377emr15154190ilu.12.1702510608364;
        Wed, 13 Dec 2023 15:36:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:6c7:b0:35c:b60d:4f23 with SMTP id
 p7-20020a056e0206c700b0035cb60d4f23ls618840ils.2.-pod-prod-04-us; Wed, 13 Dec
 2023 15:36:47 -0800 (PST)
X-Received: by 2002:a05:6e02:1b05:b0:35d:77b4:12f with SMTP id i5-20020a056e021b0500b0035d77b4012fmr13131407ilv.1.1702510607558;
        Wed, 13 Dec 2023 15:36:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702510607; cv=none;
        d=google.com; s=arc-20160816;
        b=NnB4p1FQksvFZcWZhHx+dMkcKP30TVJ9poI8iwS4u9+m8M92+OGOGRPHzkQ2DXXgSD
         gzlmhrTZjihSUoZPNMt3j3JIdOidVXRVgzphLJu6SuzSRu15+JGOPRqH6PvF5y00Rptp
         HWKD5AVaHjWX+E+GvRTf+gcf7+8ze+J9Cadssad1WXgVg9WIegcN2WXlY5HKRQ/HYBLY
         f5BrZeNZvKsvThirpEJE/QpJb/jql3C/tZF3EDJ2osdeYpvvxCv5FK+gPXmUisIwuJzV
         qa+BvZKuEvxoApWh28bMHusGjPESxUZy6KduNvbENJnB4vT31itaBNhKlMKnu7d7tSTm
         v9Tw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=MKNXtq5ajkWvcQiOoGs4LcPUtQ+3TCO4ZqWbvkFUWVs=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=Na9Wy433r9/AM/UH2YBsm9IYqHynJHAWX/VnFBWmT2dnhkutokErqLGqJEMrlEr8Mo
         jiL9k+ZzCkg+6PMjbh64Nx0chUebls7OfKRECuO1TjE9RduzfXH8CY14KZUKE58bG9IB
         vxPNC2h0dLf/VD7SfjF4cot3lZbiX3+pc+eMooWx7wKIAH0lf9Eag44dqb5rEkeUCpGc
         QLrtvVglg3DxfPiv5tLTFp6TYtBDI95waT2V66OpjpkE9Q8amcGbCSAD7fa2AYOXsWIR
         eaHHqR0fynHC75lUrpQw9J+yGvEU0+FVRKauWzWLGe8pXfh5rBd2WiNLpSlWarsnJpJj
         SolQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=sgnQGgAp;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id ep10-20020a0566384e0a00b0046662773e53si1197917jab.1.2023.12.13.15.36.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 15:36:47 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353727.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDMlp9u024703;
	Wed, 13 Dec 2023 23:36:42 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uybw52s1h-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:41 +0000
Received: from m0353727.ppops.net (m0353727.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BDNQLK4030990;
	Wed, 13 Dec 2023 23:36:40 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uybw52s19-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:40 +0000
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDNQTB3013878;
	Wed, 13 Dec 2023 23:36:39 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uw592c4gf-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:39 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BDNaaJH11797080
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 13 Dec 2023 23:36:36 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 5FA3720040;
	Wed, 13 Dec 2023 23:36:36 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id EF0802004E;
	Wed, 13 Dec 2023 23:36:34 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.171.70.156])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 13 Dec 2023 23:36:34 +0000 (GMT)
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
Subject: [PATCH v3 17/34] lib/zlib: Unpoison DFLTCC output buffers
Date: Thu, 14 Dec 2023 00:24:37 +0100
Message-ID: <20231213233605.661251-18-iii@linux.ibm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20231213233605.661251-1-iii@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: Um-xt4YHootM37dHUG8hwEcF0DUJln-L
X-Proofpoint-ORIG-GUID: -b8YHe7U_CbwRAQmSuApxveyqawrdKVk
X-Proofpoint-UnRewURL: 0 URL was un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-13_14,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 malwarescore=0 bulkscore=0
 phishscore=0 spamscore=0 suspectscore=0 clxscore=1015 lowpriorityscore=0
 impostorscore=0 priorityscore=1501 mlxscore=0 mlxlogscore=999 adultscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2311290000
 definitions=main-2312130167
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=sgnQGgAp;       spf=pass (google.com:
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
 lib/zlib_dfltcc/dfltcc_util.h | 24 ++++++++++++++++++++++++
 2 files changed, 25 insertions(+)

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
index 4a46b5009f0d..e481c6ea09b5 100644
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
@@ -59,6 +63,26 @@ static inline dfltcc_cc dfltcc(
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
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231213233605.661251-18-iii%40linux.ibm.com.
