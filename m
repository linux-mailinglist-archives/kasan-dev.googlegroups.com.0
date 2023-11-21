Return-Path: <kasan-dev+bncBCM3H26GVIOBB5OR6SVAMGQE6BOA76Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C25F7F388B
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 23:02:30 +0100 (CET)
Received: by mail-oo1-xc3d.google.com with SMTP id 006d021491bc7-587ac1e8eb1sf6373739eaf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 14:02:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700604149; cv=pass;
        d=google.com; s=arc-20160816;
        b=YbbDQFl+4a0aNQSs95fsTmePugI4wDWSG3APFEY8o/4Cd0t/9BPvyH7v5kEvcO50UW
         pbfUFLgK3OgdIj+isY4oS4aMm0XYt8hR+pKP6xmydDk6Or8D49Sy+MwtIfjowzmUwHNZ
         ZCoV5xAgrZGLPvjlkCX4ESaCy+x+dtZW4YRZTT3NLH7Bg6MEDYyKB4vEcD1SfDicvqPW
         KS/lOWpPqadas/okhH9m7aEbGgHkhT6KL1QQXSJVjWxBjCQ47fCo/R4cvnteNZ8iV93E
         /TtNqBaYMS6OcOmDWjT/T7foH2yJdD28pTsxXiWH2i90xC4kSRkMMueHfHhi/9X8n2fF
         dU3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=MpUI61ebfV0gCCQrkr5iagCpm9YOl2+4/hUuq6KR2Sg=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=rKiusKfA0UMWZFC94WlbYzjzqad0AY5vwM5guWuJN4nUm0KglORjyryjC7Eia/6MYF
         vNEnGGdwJNf+96BJuemYtzrSNgOBTwsScA940IL344WUWBKgHDJpOzbtVo1Nz96Qzhfh
         uSIdB8Xx31YOxPCMYhXAr+NZZ+WmVu/ic13r4wlwEOA33ciDdGYH0uXcfvabUhyjmJJ7
         dbQSs29MY8AGJkbGVJikPyZ0F3tAWfo8KHlLshsvLRNKesp841kN9V6nhPf1FkzEYdXJ
         eZBQChhr4KDXMerFWzIaEx3nIYPKOGVGjqj/VSbDno0iG+4N/uE2zyhhOi0pXMASsCOs
         5vgw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=QRMz0sVJ;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700604149; x=1701208949; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MpUI61ebfV0gCCQrkr5iagCpm9YOl2+4/hUuq6KR2Sg=;
        b=RVs+ek4XfsPcQtx3Fx15spvoRHmMlULCxSwV/V6yE90VTovQxExIN/7FX/u4vCgotx
         hijx6Lr7djvcHLvISmonPdKCWxLWLqsul1rAU32UvkJJN1AsA8F3zjYJzuj1+PyYiOrU
         Amrzb8NYFXYvUeAW9DskvvDP7bAs8tT2SJdLbXlUcPWM4Zs9AGnUHaJbdNCbNeNPJg+8
         W/fhOokkT0p+wj811CqyTJjs2qD3S5UnWD+a3ZRWdXlv3+jIvM3D2GBcoaGIUHUBNjVI
         VRPYaD0OAp9MXkL6cBBYrBlO8VL9MBfiOULahexSveocJvIGI97LRrfkpfM8zcIxbO0A
         6o/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700604149; x=1701208949;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MpUI61ebfV0gCCQrkr5iagCpm9YOl2+4/hUuq6KR2Sg=;
        b=QhZIDnvUS4y+mmPgKd1bI44ZHq72eogzTsqOsFYBn4vXBKGwe6weWOmdLGOVIqXgMx
         pkoRXkMCZH/KDGXqcXvoeMsYpKwLdbtgHF9zLcIQY/WrZe8BEMhU10VKTGTCGik8qd/L
         KUqXzbvWO4GmQmOdNIX3XaovsX/8rHcnyJzMDtp3B0LOMsQPttRfqsgg/lMR1XATfZ62
         PJh/9+Pzte58ixGa+5CftHHvx+fKwrHp1J133V+ZI/McetOw5en2sN4XoQKSPnpymghT
         X4wdR+SMsz2ra8NqH4t38qaEb41awSf7xAdJUBvZfgPNeTHDK0t0Hk19Yt+YGN5bq5Zs
         8V+g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yxxs54vrlvQj7ZgEvT0i4W/JS+ISChYfJCeTiDnePPfEkdDyWBD
	ygqiB7Ez5WdPvIxGiCKgt/Y=
X-Google-Smtp-Source: AGHT+IFks9sUdXb4RP2mCTD3y0I9XF4S7CAdMzwmPb6z0JY0r0h+UGM1tiy0NpqWMaSIMFp4efF7OA==
X-Received: by 2002:a05:6820:623:b0:584:1457:a52a with SMTP id e35-20020a056820062300b005841457a52amr713786oow.3.1700604149365;
        Tue, 21 Nov 2023 14:02:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:5890:0:b0:587:31f8:bc6d with SMTP id f138-20020a4a5890000000b0058731f8bc6dls4911812oob.1.-pod-prod-07-us;
 Tue, 21 Nov 2023 14:02:28 -0800 (PST)
X-Received: by 2002:a05:6830:18:b0:6d6:53f8:882 with SMTP id c24-20020a056830001800b006d653f80882mr597953otp.20.1700604148758;
        Tue, 21 Nov 2023 14:02:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700604148; cv=none;
        d=google.com; s=arc-20160816;
        b=mXTNnjaqpNrxwQocHa1DG+ylBcgQroXnuPpgmC4H/5LK96O01Dn/TwubRRysLW/kzd
         4mYrdma262szEWkjghjO8BSo8LlgeKMhGqNh3f1MNqh2sBHQf2i/4DQYINXQyF5YXVpC
         e/nbdUbaipgE0L/RIRMWqZM7kEP6AMsMBq/XDogy+lUCc/G4dWv7ERmMz+c+g98RIBqW
         7Lw3c9DP68s1LGIAGIep3MsPVJhm+rVgGzY/bwV+WnIDPuFeghEZZnmq69ouZrxsSlYV
         uKcvF1F3T2ypBiQ/cy8qgGnXd1IvA2wEOtRZZMl6zR5FOiQS9WNeb+so6LdJxsXjJbzS
         4MAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ezUWgZJfISejb8VTgAwaTpQHvkooR/+F6bZ5vCX0j5Y=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=pL2UVHc8MuoIksGs7rnFmwEt37kcfURQSBT1i3p+MTNg22tNT4hyrik7+CiNwRZFPt
         nxb6k4rqZV0sz0O/CxjLmYKOYm7Iy+F7HiI81TEEgv+xdhi6EmDQABUJvYyJceCyz64T
         K+S+vNkY9NKG9/UIWQbMBCM75sfo95CbFKlxUPF1r5F+sZCL9WXfeUZA9kXTKdib92dB
         OobxKBd05hWJs0eYgklLXMYabCB6KeOktx856jddFOCWa0bNTcoKnDqFMp/EDNQ+M7+K
         QdQXAb8GfcCnTAy8lJj0iCJZG9cJBv+dFjoW0GkAQc+yME2CpOgDLsLjuhk7hCOZAm9n
         lGmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=QRMz0sVJ;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id cg12-20020a056830630c00b006d69ecf7066si1825898otb.4.2023.11.21.14.02.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Nov 2023 14:02:28 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353726.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLfHvm025430;
	Tue, 21 Nov 2023 22:02:24 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh46a19w4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:24 +0000
Received: from m0353726.ppops.net (m0353726.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3ALLgCHI028952;
	Tue, 21 Nov 2023 22:02:23 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh46a19vf-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:23 +0000
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLnTm4010601;
	Tue, 21 Nov 2023 22:02:21 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uf93kujpk-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:21 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3ALM2IPS8389024
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 21 Nov 2023 22:02:18 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 735D120065;
	Tue, 21 Nov 2023 22:02:18 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 0600F20063;
	Tue, 21 Nov 2023 22:02:17 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.23.98])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Tue, 21 Nov 2023 22:02:16 +0000 (GMT)
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
Subject: [PATCH v2 08/33] kmsan: Remove an x86-specific #include from kmsan.h
Date: Tue, 21 Nov 2023 23:01:02 +0100
Message-ID: <20231121220155.1217090-9-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231121220155.1217090-1-iii@linux.ibm.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: dRc6yZvR5PaQdqGrvXEotBg-Og-UeQav
X-Proofpoint-GUID: 08q-yHVFGIS-b7rFJUsykSG5dMEIHHJf
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-21_12,2023-11-21_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 suspectscore=0 impostorscore=0 phishscore=0 priorityscore=1501 bulkscore=0
 adultscore=0 mlxscore=0 spamscore=0 mlxlogscore=999 malwarescore=0
 clxscore=1015 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311060000 definitions=main-2311210172
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=QRMz0sVJ;       spf=pass (google.com:
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

Replace the x86-specific asm/pgtable_64_types.h #include with the
linux/pgtable.h one, which all architectures have.

While at it, sort the headers alphabetically for the sake of
consistency with other KMSAN code.

Fixes: f80be4571b19 ("kmsan: add KMSAN runtime core")
Suggested-by: Heiko Carstens <hca@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/kmsan.h | 8 ++++----
 1 file changed, 4 insertions(+), 4 deletions(-)

diff --git a/mm/kmsan/kmsan.h b/mm/kmsan/kmsan.h
index a14744205435..adf443bcffe8 100644
--- a/mm/kmsan/kmsan.h
+++ b/mm/kmsan/kmsan.h
@@ -10,14 +10,14 @@
 #ifndef __MM_KMSAN_KMSAN_H
 #define __MM_KMSAN_KMSAN_H
 
-#include <asm/pgtable_64_types.h>
 #include <linux/irqflags.h>
+#include <linux/mm.h>
+#include <linux/nmi.h>
+#include <linux/pgtable.h>
+#include <linux/printk.h>
 #include <linux/sched.h>
 #include <linux/stackdepot.h>
 #include <linux/stacktrace.h>
-#include <linux/nmi.h>
-#include <linux/mm.h>
-#include <linux/printk.h>
 
 #define KMSAN_ALLOCA_MAGIC_ORIGIN 0xabcd0100
 #define KMSAN_CHAIN_MAGIC_ORIGIN 0xabcd0200
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231121220155.1217090-9-iii%40linux.ibm.com.
