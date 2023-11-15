Return-Path: <kasan-dev+bncBCM3H26GVIOBBU6W2SVAMGQE25AJGQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E7707ED210
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 21:34:29 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-1cc52aba9f9sf268895ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 12:34:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700080468; cv=pass;
        d=google.com; s=arc-20160816;
        b=Oij+mV0L74awMMpV33h16U9XQHSV4rNa17PF/D+sK8Kl+tTySwbGHuxtdkn5QIVujF
         1ZQJr6n3zzpuEln4PsTb2GZ8iJhWxwV0Hb4lkfDb7LNvqfX/lSuewFy6U06Q+uqCA8iN
         ogOUzUEolNwnKlB3r/wTjBqjwBv3ZD6TCYy0dDOlIomI2BqQnzq+3oCx4wKrMZGXwiO3
         5TF7C9CkYaXBdabHhsIby457FAPYlFUmEUx2EgqQ0TuexOH82nL+kX5MuwbulUedjUg6
         RFNXGzqfGzSQNSxThVHWqVwPx9TMfdRiY2Q33G9s/cRY74a3+qOpzNcvu9Q7bR3kL1El
         xBbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=YcdsmL4xHL4VX/7BDeI4wvZ6TiSb6EHZ+zcL5Rpi/SU=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=0Ie0i3eACuFbxH1Te0kS/jnnXE6ETVz/PjHo18yf6+REVjGfFVixIn6MDRYK0hkyzG
         HaVYEgSUdQUa6QN/6A86OnYgBBvBm9qg8lz5vf+SOqeJaVbFXaIM5P9fKARb5JhVX/xv
         z8Y59NxPbbRQXra7sHXoWChOOeqiLEY8uXvIP8Ndc1xdDE7dL819zrzSpclQsZVAxWuV
         BW71E8KAS2eL18c2BurlPLYzbBbUdBSFY1uNY9ZVG73HVgHehdYd0Y3UN5WIxosrta9H
         kW+Mv5AuMtxvbdFOG88wcBTJtg2x+1nU+x3TlPQDNZk2NKbpaEp21Mz6dIHo9IhYWFpB
         xGVw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=dg4iR7AS;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700080468; x=1700685268; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YcdsmL4xHL4VX/7BDeI4wvZ6TiSb6EHZ+zcL5Rpi/SU=;
        b=dpWmh/TPn0iBSnAli3AmarDHB0MPeSucDLdFaki07oJFFOA39QSM6tIEqTB2lum7m4
         n7w4Za8tLjtgPx79iXTc0El1IIdSh2c9R4sZ3+hlIZ6uMQ/PQUqcIoYl7Hf1sk9eSysF
         ns0LNAK03Qbub61RLt13asOfxHTYF9GIOC/l3dcxSBog4hLxGh3DYLY+J3JOITBLnQYX
         MpgQEkdDan2l4Q+mmWnnoZm6V8CkD2IVmK9KlZmA36CAHsx+UleVVrBRCMDx2o0BUuEx
         bHvbvH2awwmiBnU0TM9VTxgc+8lQR22bmogpNmFcX07x2hPsqjf9t2+/JkTnp3LFX6Jr
         afnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700080468; x=1700685268;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YcdsmL4xHL4VX/7BDeI4wvZ6TiSb6EHZ+zcL5Rpi/SU=;
        b=ZpHw9dv5b1l6lXUpYDIZ+HMe7WyW0LJAWSGOGidQXpWB6DDGLt9NVmr0sIb2P69zbY
         ZEVOCgJH9Eciw8X4ZWfg0Gj0LyVUOwVvliqTajl+AK3w+66lnWycdUkhxxjPjJJi8+Ts
         /IZVV+A4jt3v8xO/A6GK1rHJYQlNsLqw+ef7Z0rifReOYhNnz9DDwG8mnCwpIQQpdF+T
         dN3nFR0Dlq4mUhI0DUOgM7xiLhjKGE9fFErz97VUvcnw46IFppIQG5ORj33dOaitqphr
         UM03Y/FBmAa7pxMCvdQby7y4/ZDndZaVUsFfGV4Sb0M5QYA+RDXasPg7wSjB4KDn72q1
         4whA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxL8yQVHr4lOrGyykTfKWUQyQVB85cHX608KsdneKFzzwsyRpvk
	ePwLEvl8el2AOZHrfxHEYuQ=
X-Google-Smtp-Source: AGHT+IFFGXatC4viiuyk7pKkgHzc0LkBB4xvSwKcfONIsVazGadN+zKkA+mjtGueDzX9H6TLfwxr9g==
X-Received: by 2002:a17:903:483:b0:1cd:fb3e:2b2b with SMTP id jj3-20020a170903048300b001cdfb3e2b2bmr21744plb.7.1700080468059;
        Wed, 15 Nov 2023 12:34:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3d8d:b0:280:860:63c2 with SMTP id
 pq13-20020a17090b3d8d00b00280086063c2ls147856pjb.2.-pod-prod-05-us; Wed, 15
 Nov 2023 12:34:27 -0800 (PST)
X-Received: by 2002:a17:90b:33c7:b0:280:ff37:8981 with SMTP id lk7-20020a17090b33c700b00280ff378981mr11554312pjb.44.1700080466995;
        Wed, 15 Nov 2023 12:34:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700080466; cv=none;
        d=google.com; s=arc-20160816;
        b=wrQdmDW1whAeZyD9shQQ7s2iTFDCdZvhp9m/lEjo1ZZ59GykhwPmp/uVZD29dKGEQk
         qD72QSp1M5SgsTdVRfg911i3G8Ddt/io/YTOv2Z6od0jUFSiW2D0cUEdcvKRkACeOP6v
         8fF65JvP1BMx65qKKbFTWje7+JQCDmxpz7+kGhsCvTfbmmmbPyXmNCSOJqCo0qhWL0YN
         PVKp0CFRAzWdHV1WfhZcuWUasSjOcT/NIzCHVU+V66jX6XOuwXTv6xwiiaz8m7NyGyLq
         PaQeCdzDMI1yTeCZopqAw5tqTuHhrtTSXDsx7rkDtvxgqk4NlE6/iCcGIk6Z2lnx2HnX
         QwRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=VZEQ7DLTQn6OqQgSLo67A6SEZnv9L1qroObhIZ1xXOM=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=RU2mO49S11e0SzLPplmHeHMVMfGH7pFT3nzHKJZxVRcWfRQbAaVI++iPh5b3WbRnld
         sFP/XJhak3EzYKaRa17iOwXSnv3AJvOlZ+Iejd1ZasgvukMLXJJXm9C49gB/ar3BvB1F
         CouRVwYROJ7UTTLU5Wwtl2RbOzBfltIss3HhjSx1lZfjeFY4EWLuVlb2rdxiAswyvleG
         wtVKkvJ+etEJ2mjMaDesXjTduhIOe8jrxrqdTRcsGqG0G/+xghlsuRnVIlhEnDf8J+L8
         EWDyrl2uY3juHZigOO/KrdpLSJBgfqkAo2DRSBmEbvHvfFBgiIjFWDKN1Xs5QOMBzW1o
         xXMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=dg4iR7AS;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id so18-20020a17090b1f9200b0025c1096a7a4si37680pjb.2.2023.11.15.12.34.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Nov 2023 12:34:26 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353729.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKRRsu004222;
	Wed, 15 Nov 2023 20:34:22 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud51q05rc-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:22 +0000
Received: from m0353729.ppops.net (m0353729.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3AFKTACg008842;
	Wed, 15 Nov 2023 20:34:21 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud51q05r1-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:21 +0000
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKIuv7014594;
	Wed, 15 Nov 2023 20:34:20 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uaneksvrn-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:20 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3AFKYHqG45417192
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 15 Nov 2023 20:34:17 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 09B5420043;
	Wed, 15 Nov 2023 20:34:17 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id B202D20040;
	Wed, 15 Nov 2023 20:34:15 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.9.51])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 15 Nov 2023 20:34:15 +0000 (GMT)
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
Subject: [PATCH 05/32] kmsan: Fix is_bad_asm_addr() on arches with overlapping address spaces
Date: Wed, 15 Nov 2023 21:30:37 +0100
Message-ID: <20231115203401.2495875-6-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231115203401.2495875-1-iii@linux.ibm.com>
References: <20231115203401.2495875-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: NSV7ecFnmhdnhXadJujf6HXFiI7hMP7v
X-Proofpoint-GUID: A_uHNzfE3lkD9p6tFW_ky0Alz8aTnTpa
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-15_20,2023-11-15_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 spamscore=0 impostorscore=0
 phishscore=0 suspectscore=0 bulkscore=0 priorityscore=1501 mlxlogscore=922
 mlxscore=0 adultscore=0 malwarescore=0 lowpriorityscore=0 clxscore=1015
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2311060000
 definitions=main-2311150163
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=dg4iR7AS;       spf=pass (google.com:
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

Comparing pointers with TASK_SIZE does not make sense when kernel and
userspace overlap. Skip the comparison when this is the case.

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/instrumentation.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kmsan/instrumentation.c b/mm/kmsan/instrumentation.c
index 470b0b4afcc4..8a1bbbc723ab 100644
--- a/mm/kmsan/instrumentation.c
+++ b/mm/kmsan/instrumentation.c
@@ -20,7 +20,8 @@
 
 static inline bool is_bad_asm_addr(void *addr, uintptr_t size, bool is_store)
 {
-	if ((u64)addr < TASK_SIZE)
+	if (IS_ENABLED(CONFIG_ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE) &&
+	    (u64)addr < TASK_SIZE)
 		return true;
 	if (!kmsan_get_metadata(addr, KMSAN_META_SHADOW))
 		return true;
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231115203401.2495875-6-iii%40linux.ibm.com.
