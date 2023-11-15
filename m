Return-Path: <kasan-dev+bncBCM3H26GVIOBBT6W2SVAMGQEN7LLKXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9ED5D7ED20E
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 21:34:25 +0100 (CET)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-1cc52aba9f9sf268755ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 12:34:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700080464; cv=pass;
        d=google.com; s=arc-20160816;
        b=yZpqP5udX3nEj3jDgs4U5dYtnWtOZECZKoKvhzvh8cDQai3z7yNzb2YpOVbiSs5xoi
         HWHx1FawoVYJPDcvh9Jl5j3HsDCnJ9Sw12CNpKxB/UKigw8UmjACPPROCE7IyjtddtRD
         Zn7unq3w1M3zTInXtTqwDCU598ihKsglx0la/qqqUlLhqOj+E6B/fvBpahl+DnhGXIDj
         kMJIsZFQNc1ZOdEI9OVzwbUFcrKFkmaLf4X1wHNsbmlhWSF0eetZdeZljeLwDqKibyXe
         g1uduXV1Loqsl5b0wg7PqzcIvhoVOMPetUE26bxlTtumAz1AqOjNZiU3D99zYtpaL5k5
         tCgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=qpzIK81jYWEVgXuIAoH7BPdEazdqCFhWYBruoUsob1s=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=UOnA8iVZWyrw1iCGgMjF2siVr7P2y/dU+0qSc4DdHIEY2PkqwxxSCuHiQ3LUNKuJ7E
         XfQCr1PLxsALR16m1LGj+GT8TVA8Ot8lsmbtlMa//a6g7An5B5xA/8cj6JH2vLMh86vu
         I65Emvor/YopzI/azWNq2Yc91TPWixehmZmqLbp8FiN2NhePQphlWB/ioOfumqkCzuNm
         oSJkAk6mkLHn5CjqZlIfoFoxfQoDAzp1eMe8dgtxj8awCaqxye1VFvZl6lBngPPiQBWb
         6mvxndHtZ2zigmA/GATKzBLj2SRdBpU84VcV8HGSg4LOs8eIoFQpn+1sEOQBcT7e/v1s
         58sg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=GcIR3b9q;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700080464; x=1700685264; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qpzIK81jYWEVgXuIAoH7BPdEazdqCFhWYBruoUsob1s=;
        b=GCzl7ajsTEU5nPPW7mUDJ3DHOOGqBwdQb7MhcJM/c265uj8yG3hsHkgOVpnvrxkE7L
         kUiX56b0vQRNAvgw2nsZjjphctt3ry1x+/8ktmrPwQwhVzcixo6yC2GP1eu/FBgyuWXG
         SlEo74X58RmJPIy+8jT/QrAGFpBbvoxuHJrny8e6h5XXTMX+ES7wUtq2rOmaKgEwXlrE
         a074jlgpFfrrz4ANbtfEf/XQUt+th6M5goj9pSmXZy6lhx3ZoM3nunMtbPr+RenxT+j+
         onMBdxKt0UpdW3l/32ZMPwMLGr0+IrbZTAZztzUjS+O4ZFTA6SY6+MQ8Q97Wtjr5yGUl
         En4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700080464; x=1700685264;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qpzIK81jYWEVgXuIAoH7BPdEazdqCFhWYBruoUsob1s=;
        b=RlisJTHssGc74Q+yQic4z7pQmgk2gIqTmQnHm8eifKDxuUGW1vdnuOQ9B42Td5DCpF
         W8ND1RS3NO3dfwRgqhBe1zjaHbXwpT7jowwGGpUaoyE28sfrhvhZUB/9AS2uYTGvTgfi
         NelcWOEqpEYM5n9pk3vdajVI6X0YETXZJ2uC7hcxoZOs7cLTUwxryZbA2JpareS9wf/u
         qXRqZSYcnA6SzNMqknaBXaAKVvfaY5FPc09KpzlA1CITAck6S/e2a0bNMlAn6OC0M9Fl
         EEHAhaju0A6MF/PKBgsQgLzrOqcZUrLhjiLGR5Hllfn4gbGDwDGwP/BCGsdr5+Afkq+Q
         t6tA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YztFttIxvUdSeFv5Kkt+mjoTQneV3/dSSQAgoJjIitTnmXgCiAf
	UqjHyJZGMYo3GSDEtUrqP54=
X-Google-Smtp-Source: AGHT+IH1qFh/A6f4cOk1A+s0Mydqb6dMB/TVAgVoeYL7KS3VkjMHCyGZtepFL4UKbvTKr2FAyaclBw==
X-Received: by 2002:a17:902:c40d:b0:1cc:51d6:fb04 with SMTP id k13-20020a170902c40d00b001cc51d6fb04mr14576plk.26.1700080464014;
        Wed, 15 Nov 2023 12:34:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:f547:b0:1cc:47be:d811 with SMTP id
 h7-20020a170902f54700b001cc47bed811ls85214plf.2.-pod-prod-02-us; Wed, 15 Nov
 2023 12:34:23 -0800 (PST)
X-Received: by 2002:a17:902:ec84:b0:1c8:9d32:339e with SMTP id x4-20020a170902ec8400b001c89d32339emr7735367plg.50.1700080462878;
        Wed, 15 Nov 2023 12:34:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700080462; cv=none;
        d=google.com; s=arc-20160816;
        b=AQcsuxU1I8eij9GJqxNKSFj2crxTSRCB3zHNl4+0Y47vYHmW9vL8pdX/qle35yCWHQ
         1hgkQvHM2W30FNT9k5ex1Pr9Xo5r1VdU+rxgF9wZZDmw9VryYKZC8q5kodIt8eQqP1Z+
         ZLOHOFU8fLte5uRk3IKt7bRV5keHj+a6SdfMsrWrDIa1NbWfV5H/5OKLxvwo8Cyn8qAp
         hTQgQcnNE/EsSz6MeKx2qX4PEH6oixg+sOTWqMc1vB8FuLk9e/Cd/7DBKhAab02k/g7h
         XdZ1sRV/ke0YNVuufgCAVmtiaqZZrQl1ZsUO7p1pFvaV2c5+QcFN8Z6scIfFpYn1z/a/
         6BuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=bBfIBy0C0Xw8EuCg23xxzvNunOkz3EZNldxDrxgTNMo=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=DBkgbEVf71e6xzGfvR4kwe8KVevDQaMrb5qCZmJOBpqfdDgD1eEq+GVF5inumgJbo0
         KiWMF72z5lO8O1iP1LVUq1D1rodJQoZ0fU1KrWNyl0VPtCV6DRBXdo7WkKepoqgwOueO
         d0XIZmIdGSpb0+uO0Gmj1C7vZrQ1i2FE5UVRgnaZIXLLAyuUntfdMCjuMiHE/XVEJsGf
         7p3nVdVcZ898vIQfn0nWU/izxXYhcR3jE9DYDcNbPJyhyEwZ915L44D1ZIR2IaRizg5X
         Mbz1haT5tktNtLhg/+npC7LCaNIS/0Pk8QtKKeLM2MTJ1HbX/S6/cmVJ7x7etCzuIWHZ
         J0hw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=GcIR3b9q;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id b9-20020a170902d40900b001cc55bcd0f3si505542ple.1.2023.11.15.12.34.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Nov 2023 12:34:22 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0360072.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKTdTu023075;
	Wed, 15 Nov 2023 20:34:18 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud52r8439-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:17 +0000
Received: from m0360072.ppops.net (m0360072.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3AFKUIq6025708;
	Wed, 15 Nov 2023 20:34:17 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud52r842t-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:17 +0000
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKIuWO010012;
	Wed, 15 Nov 2023 20:34:16 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uakxt2ds4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:16 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3AFKYDek36045198
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 15 Nov 2023 20:34:13 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 6A6AB20043;
	Wed, 15 Nov 2023 20:34:13 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 1E0C020040;
	Wed, 15 Nov 2023 20:34:12 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.9.51])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 15 Nov 2023 20:34:12 +0000 (GMT)
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
Subject: [PATCH 03/32] kmsan: Disable KMSAN when DEFERRED_STRUCT_PAGE_INIT is enabled
Date: Wed, 15 Nov 2023 21:30:35 +0100
Message-ID: <20231115203401.2495875-4-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231115203401.2495875-1-iii@linux.ibm.com>
References: <20231115203401.2495875-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: JtgVFaj2CSjsbY-bGnFcv-BeNZNtZKL1
X-Proofpoint-ORIG-GUID: N2Kt8m8mfRl4GRFRsl6eHtmaF9f4tvzv
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-15_20,2023-11-15_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 bulkscore=0 impostorscore=0
 lowpriorityscore=0 adultscore=0 clxscore=1015 priorityscore=1501
 mlxscore=0 phishscore=0 spamscore=0 mlxlogscore=999 suspectscore=0
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311060000 definitions=main-2311150163
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=GcIR3b9q;       spf=pass (google.com:
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

KMSAN relies on memblock returning all available pages to it
(see kmsan_memblock_free_pages()). It partitions these pages into 3
categories: pages available to the buddy allocator, shadow pages and
origin pages. This partitioning is static.

If new pages appear after kmsan_init_runtime(), it is considered
an error. DEFERRED_STRUCT_PAGE_INIT causes this, so mark it as
incompatible with KMSAN.

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/mm/Kconfig b/mm/Kconfig
index 89971a894b60..4f2f99339fc7 100644
--- a/mm/Kconfig
+++ b/mm/Kconfig
@@ -985,6 +985,7 @@ config DEFERRED_STRUCT_PAGE_INIT
 	depends on SPARSEMEM
 	depends on !NEED_PER_CPU_KM
 	depends on 64BIT
+	depends on !KMSAN
 	select PADATA
 	help
 	  Ordinarily all struct pages are initialised during early boot in a
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231115203401.2495875-4-iii%40linux.ibm.com.
