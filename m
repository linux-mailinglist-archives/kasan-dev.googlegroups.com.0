Return-Path: <kasan-dev+bncBCM3H26GVIOBB76L2WZQMGQEJCEEEHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id EC1189123DB
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 13:37:36 +0200 (CEST)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-259836a7048sf2386736fac.1
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 04:37:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718969856; cv=pass;
        d=google.com; s=arc-20160816;
        b=Jt9CQU/eROW43atxmFwmCRG/TZ6fy/dxlXl92XIUt7doMi4PiXzrn37DIWgeRiXG61
         EXpJSYKwU1+IdCz8bqle0I1QfPfJgBowH31VyxxbJsw3lczguyxYl2shrEEQ4QqJ4y+U
         IiEFNsm+2G+YQKSd67G8Bv7obUA/Rl7uBhpMBeqi5MuM7VyhdakUAR6tYexf9zgFeOXh
         OmJPmD123YBqhxpZcIZ4w9nNQI5nEtPfqYL9SrrDT9S2WtG0nYc8i0g6EKMj7ITqfyaM
         WS5NiVhpsnUI3mbmaWV7gkBaKmVqNbaW9ggq7GC42a5gb5MbUbZQd4WXYzTdY0B/qJsG
         BTdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=NcTpbOWTOclxHTozfbi4UKFEQKgpVWC0dhk0VYM4IHM=;
        fh=O8PTdjGnYbvIQRkQGFexmeio6vtOuHtDIu1NNrvQg+g=;
        b=ibVVPP9Ck8Q/tJlieVm2Pg1Sb9QxZzAIg1bbqVifoP8wN07epwSRqFgpS47oqCAvpH
         SNh6+JrFAG4WLodtx0+qZ3cYxSnFOkQxlhVRD01bhLDUvXinnhVH0vsgA/YCfzKglt+N
         P/Wul7bJOIDU0N8WQeoxAhX+TZFJgFPa8q80ip9rmoAKFrNdwwa/BpAUMjZ/AxUlV27S
         Om3VIR9jlLY1eLrwOMoHZfQOEn3nsLDkXsJlA/O/DTzF2TLT6H1Rz23Oeq8N1ewPgoVh
         /6yarqVxsxbGCXgP+5qcm0tvTUenHcrgLmZe/7jAW9ZE1JYIGhPENtL/6iZfbEXFc1hn
         VUag==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=chlTLdV8;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718969856; x=1719574656; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NcTpbOWTOclxHTozfbi4UKFEQKgpVWC0dhk0VYM4IHM=;
        b=KJSAndUZI8pkfdxBhXtQxE8diRhg9IH/L6et+GlYpzgNxTubInnfMi/RnisMFKcGEM
         YEi9XUv0oz3zkkQtsRTFpoHHRS8NRGq3pWTNkDfireGmFB1dp3K9Nw46F4XPx0TKcdT+
         +sVplGsIxat0uz0igY7RPx0Pbr/AZTWEcZCNC+JIspjsKgNV61tYBEygdxIKD1K6ob+O
         VFamLHRIO28MQCsxZiUDqRq/g8NcJD+8ravNvnq+TpovTBY2Tjd6Juo3JWhDaFoXWOxF
         J3Y3Rvv7p/orcOsMF8k5Xt3IXpR7BkZ7gOrPJxLLxYgNmRGsO9AWAUtlJNf0JsyMN0QG
         WR1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718969856; x=1719574656;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NcTpbOWTOclxHTozfbi4UKFEQKgpVWC0dhk0VYM4IHM=;
        b=mz+48+idZsFLAFGFXMGAP92OEQi5FPmj7RVZOqqn2B36RYhiAoVx/OiaNup/tl+Uyi
         wke/pzr9mW1Z16YlRcekS04d+aBS6hw9051F4AHmjSPHDpXAYgAW6pOfxPAL5KQeGtHP
         NHUqY1KRsukEkmJAmzjYXwOp+9xcYy+tYy0f+m9Q2/2XMiT6fxQOef2HeNioZqkEc43f
         8xsqyUBVCsW42mUcBR1RrPKG+w9tlIoE/ewIxwuZnMMfA1dh/DF0IacS+BuAUJoPaO9H
         Tbh+RY2/lL9sP3gXlOolJSXZPJ3Vqza7SXMxxwh5xUII1D6nbtsvL3xeX8hm8IDDaAEa
         Y2pg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWMhabGwsYlbt38Yk6u7dXWmibiY3dwUVX4SuQf91t3lx3VWtxF2R/nRr2n7mxym71wiJly9cRnJsBErwtKNq5HR01FVPsIfw==
X-Gm-Message-State: AOJu0YzRp3uKIjNekGCtLr+GmOsQUmgDGbnOwjdNEl5PCl5YM0g4x5FY
	KU7YdTaFcK+w5bGE4GG8ujUHthZeetWcvVEImFvvxTQ8JRVTh87J
X-Google-Smtp-Source: AGHT+IEn9BkXf9uFL2NJprFMGvQvv8bLhqKluIdF2MOrulY2vjJa6Shw5yu+Qf6P8F6gDG+ldooGcQ==
X-Received: by 2002:a05:6870:658a:b0:254:a694:e684 with SMTP id 586e51a60fabf-25c94abd7f8mr8488550fac.29.1718969855764;
        Fri, 21 Jun 2024 04:37:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1c97:b0:706:352e:a218 with SMTP id
 d2e1a72fcca58-70640c5d8aals943655b3a.0.-pod-prod-07-us; Fri, 21 Jun 2024
 04:37:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVcnhHd4TQtEOLJ7Q/ytQ79bHBX1fYJXOxtfBl43zYhBU7c1Zi/ZpK9Gk4jGsf/bSgIAKfzdD71irG1m1Qu1UqEyQr2x3Ax2oN0mQ==
X-Received: by 2002:a05:6a20:3c92:b0:1b8:af57:7bc9 with SMTP id adf61e73a8af0-1bcbb4564b4mr10490331637.37.1718969854493;
        Fri, 21 Jun 2024 04:37:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718969854; cv=none;
        d=google.com; s=arc-20160816;
        b=P3M4NQ12AT17XgcdM0vgu5vKuZwB2Dk/9sd1g5tCfmKllY+4brV8hw0GKZrA3cfAlI
         cmnlq6oeL9BRQSOIIgItsLOtBYXZmixQFb+fV71oKwnkceXkqvLXkHzXF7dmvHY1UKlM
         YVhgvSjMECf3DnCZfdVDm26vIFzF4lkUkYI+SYCYB0CAjdVDgtVsqwSbF5PIGYg7/UEc
         U+2wvz1WSt6pBwJl/QZIMC5KnSXSP7iYOWIL173yBdI+tBxNpNrhhfWWfNsU8G0cOAoT
         vQ2RyJiSGwjrAliOMTqG6aivFZRPsNgGTJm2I9YCdUd9rGbQAwPd/nkSXP2rfRyB9AOD
         dxlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=WE3ASvt90HWWKhjLUTLn3R+jUtOfzIMMtdYDGL1//DQ=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=vjJXpKtu5uvzq7Q4RG7X8wHgZRvIe5Dh/elai9toQf7RgvCIQIHogp4WoLqoqWURNU
         aAzGdyUYgPAUmlxAidpQhNPFj+CbRu6NMefXK+MlKeNXU4M73RC2EyqLFiq+qKufEqnz
         AZqxX7g0+SiA5zNCK+yhQjabnmHXPxXk/NGjhmfLZDyiB+fwAfNFP2mp9S3F8k7DM1pn
         vVPVBfjOBvoAY39+vynvGoSxayQEpl8I+zK34sImDG2OmydgqJhGiSxl9/4QH0Nj780O
         896d4jR/CHkoNqsg1DZ4m22OKz53RdqG5IkS1fDhTZ0lQkjX16Ib80TaVgad4xieluL9
         WBFA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=chlTLdV8;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1f9eb2eef89si516155ad.1.2024.06.21.04.37.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2024 04:37:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45LBSmdx031827;
	Fri, 21 Jun 2024 11:37:31 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw8p2g0k1-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:31 +0000 (GMT)
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45LBbU7X014293;
	Fri, 21 Jun 2024 11:37:30 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw8p2g0ju-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:30 +0000 (GMT)
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L963JM025654;
	Fri, 21 Jun 2024 11:37:30 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrqv6w07-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:29 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45LBbOTv51970338
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 11:37:26 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 613F92004B;
	Fri, 21 Jun 2024 11:37:24 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id CBC1820063;
	Fri, 21 Jun 2024 11:37:23 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 11:37:23 +0000 (GMT)
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
Subject: [PATCH v7 25/38] s390/checksum: Add a KMSAN check
Date: Fri, 21 Jun 2024 13:35:09 +0200
Message-ID: <20240621113706.315500-26-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621113706.315500-1-iii@linux.ibm.com>
References: <20240621113706.315500-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: XJHRyrW6gEr7POyM_gQFseah-qSadybr
X-Proofpoint-ORIG-GUID: S4CNayQqicfQAiPhKJFBb26TKMLrWZr3
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-21_04,2024-06-21_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxlogscore=927 spamscore=0
 clxscore=1015 bulkscore=0 impostorscore=0 phishscore=0 priorityscore=1501
 mlxscore=0 lowpriorityscore=0 adultscore=0 malwarescore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.19.0-2406140001
 definitions=main-2406210084
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=chlTLdV8;       spf=pass (google.com:
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

Add a KMSAN check to the CKSM inline assembly, similar to how it was
done for ASAN in commit e42ac7789df6 ("s390/checksum: always use cksm
instruction").

Acked-by: Alexander Gordeev <agordeev@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/include/asm/checksum.h | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/arch/s390/include/asm/checksum.h b/arch/s390/include/asm/checksum.h
index b89159591ca0..46f5c9660616 100644
--- a/arch/s390/include/asm/checksum.h
+++ b/arch/s390/include/asm/checksum.h
@@ -13,6 +13,7 @@
 #define _S390_CHECKSUM_H
 
 #include <linux/instrumented.h>
+#include <linux/kmsan-checks.h>
 #include <linux/in6.h>
 
 static inline __wsum cksm(const void *buff, int len, __wsum sum)
@@ -23,6 +24,7 @@ static inline __wsum cksm(const void *buff, int len, __wsum sum)
 	};
 
 	instrument_read(buff, len);
+	kmsan_check_memory(buff, len);
 	asm volatile("\n"
 		"0:	cksm	%[sum],%[rp]\n"
 		"	jo	0b\n"
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621113706.315500-26-iii%40linux.ibm.com.
