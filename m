Return-Path: <kasan-dev+bncBCM3H26GVIOBBA6S6SVAMGQEKWYMKRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 842007F3894
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 23:02:44 +0100 (CET)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-1f939a530c1sf2703696fac.1
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 14:02:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700604163; cv=pass;
        d=google.com; s=arc-20160816;
        b=ItoEGjOA7sNB3fksiwybcew3UZw40FLXdyOAvrqWrseByN+FZ7prwzyd95/YmBRzAZ
         tM0F0pnRa256IKjYk8bqJO60T9B66Jk8P2QQhA+rXu6cb/P/4mnVD5gLG0InlXkMkJsD
         f5kIGACkM/tECFR4J7jKJRQJVC7ok5ZO1oJoaSPUAC+FzRBbxht7iyRIg7xGaIvb9zHY
         0LBZPma0IfG4d/jp25DFvbksQBKskFlD1G5f/XjLOAk5ANsRUvaupk9PCZld/NcunCkS
         MQiH9tBVYM79hGdPvgx0Yj1TlddKLn7D+CXG2drQuVQLwnDKAo4iH6pMX0HIorJrrhjg
         Lj8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=eZLB7kWJQRvAgM5HQ77DsnPYniMPV50fsfRN/WhKagc=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=fbOFRflPT+px/Ifs9zTmE2jz5pXvUlFKnHNrEBEvOLCN7g7uJQLpa9k7fAGtCsAlb8
         kO89ifR7xyJp8yZoeCvgNb7l2sw5tcIfR4OeGPqY/z7pur2PjKiamU6/FgFNiCRfX5aY
         aNobNsTsS6wMFRel+mXNVLgqGxQHTrDH5sd4uwSfjt/cUvqxhuuslALYHINb7BF0skW0
         AIqE+y7p3DBT+Oehzi0vKHCzQNkAOQkWVBx7sQfetrRPaz5Kextc1L6q0QbiANSgTTp1
         pbeC29PJx/Zx5oT0+JrkPILhUP4DyZiWy4n/3JCzltNCqfpGLbXpigtU23M/PI3tScDf
         QlhQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="W/CF/I1E";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700604163; x=1701208963; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eZLB7kWJQRvAgM5HQ77DsnPYniMPV50fsfRN/WhKagc=;
        b=wk1TVm0PWDfbAL1ywR4S+m3FW+hO47jWC50uOVp0Wi4Ws/NygvLwq1ISunVfXMIfar
         sk2mi3Ud71JpxamjOMGDHq5hmQxkHISCOGkddsq8GIerH/A0Ec53CUJXBpMih6a1wjAq
         hSaXBcOBWJJo7rAngQTCqZxECNiHcSCXEOy8mAzV7rnNOHR/5FXfL3hVFjx44m6rSsJ4
         Q+UqOkF7z14NeZbHv3g2MLt3PNzLoWrHJcNezAbleHnf6rAxsWgEGgwfXGZm3ydtoPgA
         XYTl8npWhNpptFXV66fdOJyKVIFjBYkIncWnQz0aFiLB1hWnkKCEae2/xC8EU0cn7aDk
         xxSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700604163; x=1701208963;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=eZLB7kWJQRvAgM5HQ77DsnPYniMPV50fsfRN/WhKagc=;
        b=LmAJRTMSaVd0z9KRQenK6kil/YcRBUb5dD36zFpxzrXvcN9LTpv45jlPKCU2nRPXev
         mlCy2yz6vrw7qzWL7XtJMxiwEinzU3q6gOKB6Q3RWn6JDr2s2j2BUjKnho0M7np7ZcXR
         qilh05SlLQtPILDOHkro7nHVrd7rf+iKKBkCL74wzpFDe8n60GakE+X/G8QwtSTy6rh7
         8FBH5qbTckG7+3gSqLu3wiP7lNXUCxtSMKzWsar6jGrTsC6KzVV5Z6vAoMGMj+fXFhal
         aPmlThTXLdCS7yOCASto5blpKYCaDyA6631GB5fbsHNUTtdSwWuG2k4U//cCbQ6ORdwe
         V7hQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yxo/UHfhi7xAIEHutbdJ3UT0CPwzXKkH/DaowyEOJ1ZihVFwzmx
	GAWxqnx7TwKeAIHv1RO0F38=
X-Google-Smtp-Source: AGHT+IECk4QX8xHNFecjqqhuenZGFGKf0ISZLC301eCznzDUEbCYso1/Xx8WWDMLMKLpdhOObqF8KA==
X-Received: by 2002:a05:6870:f80e:b0:1e9:bda0:771 with SMTP id fr14-20020a056870f80e00b001e9bda00771mr843031oab.4.1700604163343;
        Tue, 21 Nov 2023 14:02:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:8997:b0:1f5:bf3a:361b with SMTP id
 f23-20020a056870899700b001f5bf3a361bls1109783oaq.2.-pod-prod-09-us; Tue, 21
 Nov 2023 14:02:42 -0800 (PST)
X-Received: by 2002:a05:6870:4512:b0:1e9:68b5:d418 with SMTP id e18-20020a056870451200b001e968b5d418mr700961oao.34.1700604162743;
        Tue, 21 Nov 2023 14:02:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700604162; cv=none;
        d=google.com; s=arc-20160816;
        b=S7YKAzgbyT2JWF3ZUSyMiFmjtWOGd+F84lGwmdKtRM0HXwdH+elMjteesnAQpe/pUP
         l66kODMQxQ48mlDDV+YHV795/TsZw+Q4ROmUW6s1R8lmvmrKWndLIss1bkSygqqc8fE7
         1TMhmjd+B3QV9mMNOj/o5bL51X/3GvgKGNpE3Z11k4ht/5/C5lETo3u8rS7upxqqKgtS
         et1mHzif+NaFNWPqs1zYc7mLhPoe7DIPQTbSUoyp7/P/iLurLRO9H9eBrjiWI2dl5ZLa
         jHP9/IZEhaj9p9VoZOObc7YOCuw8AvDEP+h4jhmYuPn2uMK0KTI3SbePv8bJ668S8ZsY
         qBwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=CK3CSFhKHiUxb3M2GZk8QRFPFYlA6+i6yOOL0Bh28Bg=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=zItitWQIDhCXTvRBPXYdOPex2wQ/QycC3VeQuJnA9yDzKe3FloPbr/53AxZJJNsRVF
         GQXLpzyO3nl6DtKGZPjGEBt/yEAtCSkvjtfR2xnzYSFv3+m05yS0K654F3Fzgpr9TNQX
         X+URCsDG6UPoUPRPSyA6jlSGJJAL5FyxMrku1gJIb6l73bPrOPJDRmSt9NyhQPWFF3td
         v7NEs5uKTrBqdxNDXRL3A6KNkUOAUW3ewWZMoRugAubJW0CnL26tRohaDqiqdaQt2XXi
         CPgI1zRIqeS3zu12Y/Eg+3Dxr3OylOMjxOd+9ED2/ai8c7O1BARMif+xfAh/nZoBKCUw
         yZ3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="W/CF/I1E";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id gz6-20020a056870280600b001f94d83804asi620103oab.1.2023.11.21.14.02.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Nov 2023 14:02:42 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353725.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALKekZm011151;
	Tue, 21 Nov 2023 22:02:40 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh11we714-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:39 +0000
Received: from m0353725.ppops.net (m0353725.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3ALL31Hj002005;
	Tue, 21 Nov 2023 22:02:39 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh11we70q-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:38 +0000
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLnbrP007085;
	Tue, 21 Nov 2023 22:02:38 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3ufaa236g9-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:38 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3ALM2ZH943909796
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 21 Nov 2023 22:02:35 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 490F82005A;
	Tue, 21 Nov 2023 22:02:35 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id CFA4420063;
	Tue, 21 Nov 2023 22:02:33 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.23.98])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Tue, 21 Nov 2023 22:02:33 +0000 (GMT)
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
Subject: [PATCH v2 17/33] mm: kfence: Disable KMSAN when checking the canary
Date: Tue, 21 Nov 2023 23:01:11 +0100
Message-ID: <20231121220155.1217090-18-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231121220155.1217090-1-iii@linux.ibm.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: iUsqkWYyrhNADZGpwnA5Io58eqlH7Hnh
X-Proofpoint-ORIG-GUID: CgIeml__PbROJN7brRp4YdQnBlj9DIyx
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-21_12,2023-11-21_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 spamscore=0
 lowpriorityscore=0 bulkscore=0 impostorscore=0 suspectscore=0 adultscore=0
 malwarescore=0 priorityscore=1501 phishscore=0 clxscore=1015
 mlxlogscore=999 mlxscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311060000 definitions=main-2311210172
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="W/CF/I1E";       spf=pass
 (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as
 permitted sender) smtp.mailfrom=iii@linux.ibm.com;       dmarc=pass (p=REJECT
 sp=NONE dis=NONE) header.from=ibm.com
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

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kfence/core.c | 5 +++--
 1 file changed, 3 insertions(+), 2 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 3872528d0963..a2ea8e5a1ad9 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -306,7 +306,7 @@ metadata_update_state(struct kfence_metadata *meta, enum kfence_object_state nex
 }
 
 /* Check canary byte at @addr. */
-static inline bool check_canary_byte(u8 *addr)
+__no_kmsan_checks static inline bool check_canary_byte(u8 *addr)
 {
 	struct kfence_metadata *meta;
 	unsigned long flags;
@@ -341,7 +341,8 @@ static inline void set_canary(const struct kfence_metadata *meta)
 		*((u64 *)addr) = KFENCE_CANARY_PATTERN_U64;
 }
 
-static inline void check_canary(const struct kfence_metadata *meta)
+__no_kmsan_checks static inline void
+check_canary(const struct kfence_metadata *meta)
 {
 	const unsigned long pageaddr = ALIGN_DOWN(meta->addr, PAGE_SIZE);
 	unsigned long addr = pageaddr;
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231121220155.1217090-18-iii%40linux.ibm.com.
