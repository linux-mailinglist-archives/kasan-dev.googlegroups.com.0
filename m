Return-Path: <kasan-dev+bncBCM3H26GVIOBB7OL2WZQMGQEVSNABDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 146659123D6
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 13:37:35 +0200 (CEST)
Received: by mail-pg1-x537.google.com with SMTP id 41be03b00d2f7-717fdb2bf03sf113202a12.1
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 04:37:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718969853; cv=pass;
        d=google.com; s=arc-20160816;
        b=RYNvT+HxhEF4dVUR0tTtMdIdqkrjJMOwwRJ2+dNKvVibOu0HuRWRJeTWgPvyDXMqy5
         F/GVcfqjTy8t7NugEa9nCS1R6KPzpJBL3bq5d8EOVFXCCT1QNSRQbLAMQnl73lf6EBRl
         rKFkrC4seAMKTWYumAcC1/y+hGnNZTbizmqEhSZH7YryvTANGFHM22Tk+N3VMx76Df7Y
         2u4DbvDq+PE5mNbYwuCsfxDvvbOK9KwLjSMDpOfsF7ufFnup6mG4CQa9RwwaQK2TETNq
         aKlwRdBl0vXHPrRLNUk4txBy0tX29CnDdtcayh/3M/81h868RtlN0aWAYkGA+ZciN+lH
         szRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=k7Rd4jeCtKMLgqrZNSzwadq+682XQdAkh7r192q2YHE=;
        fh=VkRZnqliUPhWGlx5XMp1hiY2rsy/Tg+pDSD3KwW9C88=;
        b=Y5Fhj9MlxI6H3iZ974paGyamr3ezeumR56ZvZ0V2DbgMxqZpqbYdutJBbv0eaXuVHF
         WyuqtM9DjKtXSzpatE9smq9spJVH6fwzS5Qak7cy176ytGblCiQpNLpDW0KFGHZB/kEG
         02NbEvyj/oX7nZ2MzrkbxueegBQBph9zSFqMyJ+B0eX1oFlEgrQkPMDEJPnF96g8xsqe
         A23xMD5JTPGW5kLOi5563L5HF/Fn2xQ5lsWu8hdd2ftpRfXgL0Uf6bo7QWiOGqNCYgkv
         LNNGSw47kcETfA3qG/xRpJG3apEuCSKa75phwWe9amNL+9VfndJAYsDMdqqF1gG214QK
         WeJA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=KK5KFmUq;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718969853; x=1719574653; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=k7Rd4jeCtKMLgqrZNSzwadq+682XQdAkh7r192q2YHE=;
        b=kn3rTBvF/AwEXb4jGmNWUc79JEFWJP3NkdHEzu4I7ZWfzmlNVSrLFajbSnP+4me+0O
         yVJ85w6ceCc1fHmtYJiX+izbCOkaCc6WrqdiYn0wBuLzk2xile58wF/lTBBvJSEqp6LK
         lft++TGKYXg0HvrlBYFNRNv5d2y5J+vuCfM8zShTtVpDI/Di95acxxVsosSFW5u34YSu
         LStoBRFPLj2y7OEqpi6nBdh4BMSO1+OPdhdElO1aRS22qrRMq4kt0lnXbywZtixtRgKE
         bJsSSvqI5GGwxrlk6HsL57Aey/P3vlCSk7MRjW0hD6CQqwOQIea0smrEna5quCdBSTtP
         oPxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718969853; x=1719574653;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=k7Rd4jeCtKMLgqrZNSzwadq+682XQdAkh7r192q2YHE=;
        b=dDeipyBReO25yt1nYNfko+an1Xwv2zq4UEOLMUMw1sHy2HbF+tbfLF7uMd9BX8xDIN
         rNGrDTpIj6PwN4DR2wZxwNMme21V5QMyDkFLafsIKMbt5/OBK8YruUTxCkB5mOZv1C9j
         qL3+tE3gwHSlPwKXmCZRExVK3x2bP2b/31y9tUVf7xNIDzOelusQ2v24DEGDq7prHCSX
         P6xi6UPunR9vP78Xy70g0NhiQrLG1ZbJ3t0wEpCYvEShqXI1ROXQbeBYYnXZEZoA24eo
         PjS2x/Tan7cXjZ42bi5LvUGjxNHmtjyAW+23+QAlmmts0m8aWA8yNDN9a4N1KNXy+9SY
         KfBA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXDsLIC3NV+7lnfCbrhDnhW97GM34jKT7jHgpea3ny7oNSgCf5ElYVC7B2a0lC5C1hKRf1bbvYfZkddBAwARjyMYeTNsvJO3w==
X-Gm-Message-State: AOJu0YytYWh7Y3/XYXD16UOZXR5//25dUfVPtXuIcjj+zagEeYoseVO/
	ataAvcb6vC5f195PSf/IBVqP38TQLYksAzpjBM8MkPgM+cXqKZME
X-Google-Smtp-Source: AGHT+IF6qVX8b6fHbX2D+so7tAPtUOdM+14HW0hJljosX1xMPjT14CXLEBkJTxAHmfRIZ+uYzJzdeQ==
X-Received: by 2002:a17:903:230a:b0:1f9:dab3:b048 with SMTP id d9443c01a7336-1f9dab3b408mr46889705ad.32.1718969853542;
        Fri, 21 Jun 2024 04:37:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ea0f:b0:1f6:ee76:1b4c with SMTP id
 d9443c01a7336-1f9c50ca9e7ls16846125ad.1.-pod-prod-00-us; Fri, 21 Jun 2024
 04:37:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUpcLI66CSiwGnJMx2i4Sqe3nNU5rCzaD3KJ3HlpvJrK71gU3YR68mtgRBdB8Jz1VOUnq/rkZtxR/JkIirefcl3kDTgo280FJgY/Q==
X-Received: by 2002:a17:902:fc4f:b0:1f9:ab44:9ee8 with SMTP id d9443c01a7336-1f9ab44a162mr103300395ad.32.1718969852389;
        Fri, 21 Jun 2024 04:37:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718969852; cv=none;
        d=google.com; s=arc-20160816;
        b=t4PKNi3bevl/Tf8VbJVkq5XXSE/kVFxO7+fAJefcTAnwvZ5F6BBbAXTwnjkezUmPmF
         G+MsSM4Zn9KfmbjGvlGuZ0guBnXwDo+K7aFLG+gB5ikQGd7KJ2aNABstomYbbzCdCABl
         6tQeI/RirIJz7y+5aKoI+K00DtOoh+55dEXbD4kr+VbCC7V9pASSmx7yzywu2udOMtgp
         7FQ/NfvrVzyKsYj60qDu9f8N4qegVjp4YvETNFEhjSO2ZBOFYa2JxdPfzgVaba9ImaNW
         4c/rCMgirdIFjxE9Sz2kH2nCGeM8aWU74fBLDGCtz1I1uj4AEWUoji09wNX0cF4SgCNs
         YFKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=pcK1rMwKAY+PK8Ytyz/2vRX/RRHh9XTkiYTIv46ktrM=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=aoXSycjkFxeodWvz0i0OH3A/6yE4c4LVH1D7x6nqPcD+3kw4+AX7kRItu+HPjXnod3
         tzmFDYD40W+B2phOoF2Kpe5ybVQ1D3oLV+gK0Yci5Zwl1m+wvL0DJ8h9roQ/TYjdxKtl
         stCohbYtCzweDcL8LDtjA6GlWFWw7gkE2GvU4+J0LtwB9GUZbHLLMDPzQNYCGQlgEA36
         oDv8nPsPTFxBFzsp69DxtSCuRrSXfMQyZthKOOi0QIbo5O6CmpFPEAPG2mzTMMYLl9Vz
         Xwu+EXCgjTM5rebUK/zdQwz0NTzbngN9QdI9AQhBfwkMerJGx5qzrkaWwosNO2ULkSQV
         buMw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=KK5KFmUq;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1f9eb3b378esi428955ad.9.2024.06.21.04.37.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2024 04:37:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353722.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45LBQuHE001093;
	Fri, 21 Jun 2024 11:37:28 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw5krgf2e-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:28 +0000 (GMT)
Received: from m0353722.ppops.net (m0353722.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45LBbRMl016963;
	Fri, 21 Jun 2024 11:37:27 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw5krgf2a-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:27 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L9FnW9032319;
	Fri, 21 Jun 2024 11:37:27 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrsppv5q-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:26 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45LBbLhN37814576
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 11:37:23 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 5D8762004F;
	Fri, 21 Jun 2024 11:37:21 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id C90AE20067;
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
Subject: [PATCH v7 20/38] lib/zlib: Unpoison DFLTCC output buffers
Date: Fri, 21 Jun 2024 13:35:04 +0200
Message-ID: <20240621113706.315500-21-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621113706.315500-1-iii@linux.ibm.com>
References: <20240621113706.315500-1-iii@linux.ibm.com>
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: wJtOQ7TAKKf4TPkcI736NUE9Ic4mpwZq
X-Proofpoint-ORIG-GUID: GqZyPigDgr7xcJiQq6qOfnvPbViWBKhq
X-Proofpoint-UnRewURL: 0 URL was un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-21_04,2024-06-21_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0 clxscore=1015
 bulkscore=0 spamscore=0 phishscore=0 mlxlogscore=999 priorityscore=1501
 suspectscore=0 adultscore=0 malwarescore=0 mlxscore=0 lowpriorityscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.19.0-2406140001
 definitions=main-2406210084
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=KK5KFmUq;       spf=pass (google.com:
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621113706.315500-21-iii%40linux.ibm.com.
