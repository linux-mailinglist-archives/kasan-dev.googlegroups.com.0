Return-Path: <kasan-dev+bncBCM3H26GVIOBBIOS6SVAMGQEGKAYIQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A1777F38AE
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 23:03:14 +0100 (CET)
Received: by mail-qk1-x73c.google.com with SMTP id af79cd13be357-77d5ea55ca1sf87704885a.2
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 14:03:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700604193; cv=pass;
        d=google.com; s=arc-20160816;
        b=yqaYpywty+PQGcbLE1CL7Ab0GQndInBmgvkt7Y+1mSjpCyQ21IviAXprsYu0X0Jj4L
         mKz+FU1d3rltfjsQSZN8V6iYVtMS4ukre1peEgS6MVHYS7m/Te7rVdCSM0oN8nKTc/cG
         3qLL4hay/T87Mifx4G7wgOhEq1HbnkeTzcv0IETU7ZkvYWtyVRx0WA2qAJ+bM1j4gL4z
         RI4d1wyrUvPQqgW9vMUUpHmZUf40I33JyyvlOBAhnmfZf0vQY1rTuE/+H6ieU8tmBMH6
         3C2utRRZGHRyM7txIZ/NHTKfMwAQtLKvJTPQ6GvA0xwGltWCutS2mCEGwEIsFrd3RQnu
         jusQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=GCEEiB/UHBzOYeX2JuTy/cT+Gz/eyojycvQQqATdrIc=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=T8WboILdfPkpGc7IN1MHy9WTwEmeeLlChCr1YBme74NdXmFyFUBqeSwtRB2UQ5p85O
         0XK22aplYXQQJYfz+EhDq38viq7BZ3vXBTPO3n9zOldNhdpbvQjUA67esSDbii6B9iVi
         OIEr5FfJmxzqszIXpaLxl+nk0RsnxDjSITgKOgRjVzL4GoIR1aXSVy8+e3Fhus3Pusoy
         Fz7X2yYAGpLldw6xB9tnlho0YzaWfTw5tW2JWZ+tDYQwxL8wz0+R/nwg/cgxvySvSXaR
         hrvCtTCBunLIAu6FH+4hj8V3++quUNNE17dDQRFEVtzxh9KXYLVcBuL8rqgEMXiHBnFl
         THZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=h2hOgRWf;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700604193; x=1701208993; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=GCEEiB/UHBzOYeX2JuTy/cT+Gz/eyojycvQQqATdrIc=;
        b=HJvNIR+7KYUq324QVjHzFDzPeOQ7jWCzu/uBul0zwQ1RBbtVRwdAwts44p47fgvOOc
         HrM+G3i1fhBLUyA+j1ZqoOvnE/hfNOle226OU0LH4xuu0Ytgb0OznqmBN64f4wkqULm/
         ih97YLx/4AAK26HeIiakGtb2N1KnzrMuDRGc18LFdTTVzfToU6kFso5ZIr+hP5wsXAy3
         QprVYKLCjl12bGKO3P08y891GiZI07/y0RRSEQemhYg6iQAswAWxjEdDL3J57EXZutEk
         D9EhMOIIACApHWGa3EuQOewOJsdXsKKeO4SLI4EZMPVMRiUQU4yuv8GFo9YqyZ9fRf4/
         Intw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700604193; x=1701208993;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=GCEEiB/UHBzOYeX2JuTy/cT+Gz/eyojycvQQqATdrIc=;
        b=AfDz7uL/VSUuMXBQFrlLBIpd1gNKN+u2Oig4tmAk1lJ5dSAjqi6F8ZsLfqLYIEvXNK
         U3zJth4NeCjJFdK8TTE+9EHJVxfZWQWxLCU0Pd22gZrGjeqlqKbnDlpu5qbOUow/hLD+
         g7U1fxHjdudSQPFM2Wu0B9AaAQ7ScxJ7gdj1C7CA1x+NWZXzzc3srxsizTrFZ59QoSJk
         sBr7iaIljVIpVYbFD4Tk04AFtd99ot2d5/TyKrH1RslDQjsO0RKEl8Yh76gJG7aD41vo
         NK1z4QZj6zrmlOTup3CLXyihPlHxj3P2h9TvIguw8tDw6fry3MHt9X2F92drmrhtm7lV
         yQFg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwUZWbSS6fKlueVyQZI5g8TrQ/7QXAFgNE79fsghG6rMJhFgSpf
	xD4NS1k8Xna04L8yRVHA0CM=
X-Google-Smtp-Source: AGHT+IHAavHW14Vd7gBFv99qDIFZT8XhZVM3uPFjnGsFiHRopedMnZ4c6g1Ds+nhDOwZ+Zy7txz1uA==
X-Received: by 2002:ac8:5742:0:b0:421:aedb:def9 with SMTP id 2-20020ac85742000000b00421aedbdef9mr658472qtx.8.1700604193485;
        Tue, 21 Nov 2023 14:03:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5d05:0:b0:41b:5e46:aa61 with SMTP id f5-20020ac85d05000000b0041b5e46aa61ls683501qtx.1.-pod-prod-02-us;
 Tue, 21 Nov 2023 14:03:12 -0800 (PST)
X-Received: by 2002:a05:620a:494f:b0:77b:dd1d:2afb with SMTP id vz15-20020a05620a494f00b0077bdd1d2afbmr329655qkn.65.1700604192642;
        Tue, 21 Nov 2023 14:03:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700604192; cv=none;
        d=google.com; s=arc-20160816;
        b=Y9jvApGnj7mCGIrlZRzSv/IVYgsUlKolxOrUUEEK3eIyen67G/oHz2OnPLYPICGH6m
         f6wzFL5jYdpo/RuMuUHw/1NMiDhardvWv8ZvdOWti3wFDu2wWTGcCz0sKlWpaKQL22it
         Y7OIZB6qwrnOIYmte1uy2KpZyN8a2VmbUFzW+ZhkUt+X6DsKLi2qJ3pj3feEMyfj05SK
         vvXIrj9beK9+t/sHqGqhJBV2Y7Kn/8mshO4qvw59/OIdUTgYm0p3nP/eE8qUl+G8zT5u
         9uYJWDqyiTarHHXhnQUnl3XisvH3M0IHfwAF4kDp1RgvKCIkwLj7DhPinWp8YwvIysD5
         w2Jg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=EE06ddWkGjUoLWQv6bK2fGVp2A6oQUBHyPN+VxPRzzo=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=DEksXj/rkU8aZBFD5ZUOVxfbNQGXDxTC4NbqP5wWwgWz55fzdAcmFTAiHtT8KtofmK
         svT5BwjWF6AI+NvNyun6FMjokTmQtQy3F8TXJBaSMB0IF9h8hu+qfnuP8RCINQ96lOM1
         VHLQoXZO4hXW34I1SBzCaqZXHNlc48dzOR9q06PfgB2eXKqN6Afp4Iv5hxpNo6fJzXu5
         +v24wW3rDxOUmxQjAQzZfWgmiL6ZxcisuWAsgO73U42zW7jdHLFxNkU5j+MxzIw6RUWX
         dtjccocK/2n6jn9Tpr2MilEVZY9yXwnokI4K72mjNLzwtQcu2H2gF2X2hQ6T04hvpQcD
         3TuA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=h2hOgRWf;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id x10-20020a05620a258a00b007776e0097cdsi575587qko.0.2023.11.21.14.03.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Nov 2023 14:03:12 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353728.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLlOsS020122;
	Tue, 21 Nov 2023 22:03:08 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4s68ca4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:03:08 +0000
Received: from m0353728.ppops.net (m0353728.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3ALLmWB5023308;
	Tue, 21 Nov 2023 22:03:07 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4s68c8d-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:03:07 +0000
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLnSj4004674;
	Tue, 21 Nov 2023 22:03:06 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uf7yykvpq-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:03:06 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3ALM32Jm18416340
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 21 Nov 2023 22:03:03 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id DEEFE20067;
	Tue, 21 Nov 2023 22:03:02 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 72A0F20063;
	Tue, 21 Nov 2023 22:03:01 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.23.98])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Tue, 21 Nov 2023 22:03:01 +0000 (GMT)
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
Subject: [PATCH v2 31/33] s390/unwind: Disable KMSAN checks
Date: Tue, 21 Nov 2023 23:01:25 +0100
Message-ID: <20231121220155.1217090-32-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231121220155.1217090-1-iii@linux.ibm.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: t0hiZOuilBS-pse6Lg4l-pzI0i9JU7L2
X-Proofpoint-GUID: bHxC-ytlmBvIktmBU67IBrMaMN8bDPe8
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-21_12,2023-11-21_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 suspectscore=0
 priorityscore=1501 spamscore=0 impostorscore=0 mlxlogscore=865 bulkscore=0
 mlxscore=0 malwarescore=0 adultscore=0 phishscore=0 lowpriorityscore=0
 clxscore=1015 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311060000 definitions=main-2311210172
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=h2hOgRWf;       spf=pass (google.com:
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

The unwind code can read uninitialized frames. Furthermore, even in
the good case, KMSAN does not emit shadow for backchains. Therefore
disable it for the unwinding functions.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/kernel/unwind_bc.c | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/arch/s390/kernel/unwind_bc.c b/arch/s390/kernel/unwind_bc.c
index 0ece156fdd7c..cd44be2b6ce8 100644
--- a/arch/s390/kernel/unwind_bc.c
+++ b/arch/s390/kernel/unwind_bc.c
@@ -49,6 +49,8 @@ static inline bool is_final_pt_regs(struct unwind_state *state,
 	       READ_ONCE_NOCHECK(regs->psw.mask) & PSW_MASK_PSTATE;
 }
 
+/* Avoid KMSAN false positives from touching uninitialized frames. */
+__no_kmsan_checks
 bool unwind_next_frame(struct unwind_state *state)
 {
 	struct stack_info *info = &state->stack_info;
@@ -118,6 +120,8 @@ bool unwind_next_frame(struct unwind_state *state)
 }
 EXPORT_SYMBOL_GPL(unwind_next_frame);
 
+/* Avoid KMSAN false positives from touching uninitialized frames. */
+__no_kmsan_checks
 void __unwind_start(struct unwind_state *state, struct task_struct *task,
 		    struct pt_regs *regs, unsigned long first_frame)
 {
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231121220155.1217090-32-iii%40linux.ibm.com.
