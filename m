Return-Path: <kasan-dev+bncBCM3H26GVIOBBUER2OZQMGQEQHSOSVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1139.google.com (mail-yw1-x1139.google.com [IPv6:2607:f8b0:4864:20::1139])
	by mail.lfdr.de (Postfix) with ESMTPS id 36B83911751
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:26:58 +0200 (CEST)
Received: by mail-yw1-x1139.google.com with SMTP id 00721157ae682-62a08273919sf21705957b3.1
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 17:26:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718929617; cv=pass;
        d=google.com; s=arc-20160816;
        b=xVM8LNRQQ9IDFNNiai8a/2nJC3C+5f0R5UOEGKvzCNE9gOaVmg19UYy5UV966n8h0z
         wHXRhQcwx3I42mDvo+GaUtNAvj6h+UGNms3xpbs5Tx/MvDdxkfUi985Cp8J7Yyh+HgCo
         GfRLfgzBjDt4wnbi0zRGJmHy+7XS9KXEa7A5t2jVeTLWebz35KN4xI7Avo9jIQiv+2WG
         V860/lDYeoMi1sGcVi8bfSEwmgHitW0mbkLIU5Io9Ua+KKtc6ym5XBICcRtoiEsSRLle
         f+n0MoSiJ2KDRYn9ihKLrgTyJBrNgmk3zWri+LgXvb9RKzeBGMpfilD/iw7FGm5nepFS
         zwTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=9tx2Tjk1QtKMppK89jSR0IkvIsayY0Ea9JfJoSWigCM=;
        fh=+2vBrX49InqKrCqYWhZCipe+iUBZLMr3BE6ZTpHtvAo=;
        b=zd+Fb8R24urC/fgvRtR4ll8IHoartRY/fCxmcmlbNv/v452xSm9FiCJNXj5Uz3NXI+
         Ja9RzfZyU47daNIn660f6zYMNjjgmMXD7wIHxSoIhp8Mry69MaNj4OwOZBmOWuDX8vdP
         DjkRagOUYHTAw6rjp8V5OkzTPdQPiZJn24YuC7m0J0l/WDO+eUE7Drqm4fAhJAp/a3lk
         SIuLlhMN16O7pzfQVLgwInjAMEePiN88nOVl2YDR/bWdKMdH86ZdJGQi+ykhUlVkvaFD
         m7+kCcA7jksrN+LEzGEGEUewQTY6p6G2p+hsB6B5DP/VNo7JJWBv/7HiueHflss48786
         CDwA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=nZazUTOT;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718929617; x=1719534417; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9tx2Tjk1QtKMppK89jSR0IkvIsayY0Ea9JfJoSWigCM=;
        b=vej2lnTGhlWj1pJ/ZQBNK+OycnGwbP+6lpy2m2lahMbxo/ReANFf7szJVfHgQKffJV
         KJm9e+gQuPPZz94xpFg5JRUY4T/b3Nhda2I268z6SiwQarP0WQqe8gI3Zc7yV4V5Ls/g
         2BAR2Ui0rVQLm34Q1JcKcufs+maA2IseG9g5gtvZggsQH1mZO+3V7P8UsYoBvlbGTZTl
         gLaP0XSpCBJsP8Q3XU+UsJLAG0UjvMJazwKe82LIIikutEyz3r1l+Sa8tO+mZxa7Oqn0
         +n+091Lown5QZHQhJE43NInC4UAg+3fL9N+vYjqAWp/tcdAw5cZKmt0S8YSaJNgk9Fb4
         qprQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718929617; x=1719534417;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9tx2Tjk1QtKMppK89jSR0IkvIsayY0Ea9JfJoSWigCM=;
        b=RpQTiPzNvQ8Adwp6M5VdqSUyb2C/h4nefEtsAnuVLGB1+Xux7OakrJqE9Yj6GH+FNW
         VNxxp9QwnTLK6dZQEL9xN6zq7TLZJffoRaZ6aKHCMTL/sUL3foToBgg41btC5UgGO/Qs
         WXKSSotppmHiFa5hZpmBndKv/qAZ2V3VBMn9oMoAkYf5s7+LXpZYzmV/zjUzXv5A6oXt
         X7+kALhxzpCbuOzzSsJ8ZvYceXod2jDcuWTX/jb9yQn7IP8fhtTPQzWXuUvSseEFMtKQ
         FDUmKOExPdionXDRdWcKkH9DQL0zL7fDdzLQ93HyeF14b1R0g4qRwtMRP/3Xm1c4EyvV
         Aadw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUxDtryZ6KlUl6CvE2F0Z5d1GC+J7WB7XKHmMqSHRck7Bvg0g8vYXoB4p0TaefCGRhAiOoOlbTul3Iz8XQcJNER0Se+ATfP5A==
X-Gm-Message-State: AOJu0YyH7gYdHzSlg/IJzEb3eeZx47CXJGYyCzhcc2HwdF8R943Yk9L6
	xsYYoIPHzBQ23yOB7e7i3GRo5Cwb3agOUtmm7eJcZW8mkyFb3OXe
X-Google-Smtp-Source: AGHT+IGfhIN2TrobAHePKz5SIesvuaFU5DkN5dS8bj8JHKnd8fW7+po0dWkUAEvYzukF5y1RH5cLLA==
X-Received: by 2002:a81:8845:0:b0:61b:3348:34c0 with SMTP id 00721157ae682-63a8faf12fcmr64561957b3.50.1718929616790;
        Thu, 20 Jun 2024 17:26:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:4411:b0:6b5:268:d754 with SMTP id
 6a1803df08f44-6b51030178dls23305606d6.2.-pod-prod-03-us; Thu, 20 Jun 2024
 17:26:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXQd6pFxUJ47dafJJjm7YIWphj9VN020B5MctqZ7x4BG8J9U9d+MpDm7VLt2pxJRhkiQAPmWJsRFlRRC6neHtOvYxgMxcrJ00Tzmg==
X-Received: by 2002:a67:f448:0:b0:48c:4a87:ce32 with SMTP id ada2fe7eead31-48f1304ed9dmr7315121137.16.1718929615915;
        Thu, 20 Jun 2024 17:26:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718929615; cv=none;
        d=google.com; s=arc-20160816;
        b=ueA0QPR1U5CLmTWthJjaTA0c2l6/ZM3dtWK7BDRRAITtHRTNwBres1ySZXL9BJDhSj
         7OIKRFd8BaniNYPdUon58W8Eujp7YzIVvDCz1kX0DeRnbbmsjaXwqo37DFoJd44FDQ91
         JuDbPR5ngy5F5Zy+suLxKd6Pi06SJbSYmEz1FJsLEbPBB7Q2OEwiGfYJ6E6H/IKS+OlT
         aVBYz0QZLiFWtfDjHmS335o07KbKGrqlsiF6nif8+oassKemXf/dkyP+xrORJ45WBBRE
         5ccLmtPIJ+d9h/4rJutr4mJtuR2ffK4DhqhlQ5kuowAk4/FYdWhLux/UdKBISWkQ7pqM
         ObUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=pcK1rMwKAY+PK8Ytyz/2vRX/RRHh9XTkiYTIv46ktrM=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=xIgZs1Ic0bWgoA73UlzxoIpm1qMPSyUpfF/BzvVlrVwTBP6Hj1dSgbBkqgYLn7TwQ7
         f0ITUBGRt7xkezzw4ARqj07J6FvnmNBxbWSghesj/Th2SdueN5XHgY+NZbNQb7WysC98
         sGVI8XgliP1BUezmE5tIKUa9CNMj5cAs2j8lZKQRjy5BeR3EO71qh/68dHYtQsghvJ6i
         lfMxKXChmJeziGHylJ62i050u20n5uRzKjnUKye2zxQ3oifnXXw+7nOtDDvQruEYgcxG
         t3+Yqc2qEFizZnF4htEhduYAG2VyPKvkI9YgjJSGLwhsDGjLCxNtSXzqxHeSjicDM7+/
         OXYA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=nZazUTOT;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-79bce916ae8si2246085a.5.2024.06.20.17.26.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 17:26:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45KNoABD032764;
	Fri, 21 Jun 2024 00:26:52 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvw8c070w-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:51 +0000 (GMT)
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45L0QpEX022765;
	Fri, 21 Jun 2024 00:26:51 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvw8c070r-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:50 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L0P27B031899;
	Fri, 21 Jun 2024 00:26:49 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrspjmyx-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:49 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45L0QioE56164652
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 00:26:46 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 7056D20040;
	Fri, 21 Jun 2024 00:26:44 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 4EFBC20043;
	Fri, 21 Jun 2024 00:26:43 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.44])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 00:26:43 +0000 (GMT)
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
Subject: [PATCH v6 20/39] lib/zlib: Unpoison DFLTCC output buffers
Date: Fri, 21 Jun 2024 02:24:54 +0200
Message-ID: <20240621002616.40684-21-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621002616.40684-1-iii@linux.ibm.com>
References: <20240621002616.40684-1-iii@linux.ibm.com>
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: lBkuMSrPy1rZLOJYYHrXW-DlaDRQ8Mht
X-Proofpoint-GUID: AsxR3HdOanE4AiybmDh67tCIRsC6_PQH
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
 header.i=@ibm.com header.s=pp1 header.b=nZazUTOT;       spf=pass (google.com:
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621002616.40684-21-iii%40linux.ibm.com.
