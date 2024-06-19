Return-Path: <kasan-dev+bncBCM3H26GVIOBBMX2ZOZQMGQEA4EU7ZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 35B6B90F2AE
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:45:56 +0200 (CEST)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-5bb0480a36dsf6848009eaf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 08:45:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718811955; cv=pass;
        d=google.com; s=arc-20160816;
        b=jsc41ito4EQIzuqE2YshPom13UltnSu/m59A2g4libOd39eREuhEQysHc4BVtvnqOl
         eQ1rAmFM4uufrpeJ30IV/yamJCuUIFx+MbNk5LVIx+nvOcb4uN0tZo5OIHMxmeemsSG8
         MWb/+j+4mj+5FxOB3aegKAcSzMRHh5WuSlE8QaHHczYcAPtEEvbFu5KqQ7Gzr/eEACua
         x8ZM54odPLMIjuXEpRKgCydH5q892ZpYnUFPjBnMTa2yLzs+leXM9DlzzgQg0ZRIpUdG
         1Fx9DNDTFdSXhuYO+NLDGjPtXQGuCWRSM1Yd6radUh/rSCAQznv1yLUVUQub3X97HGzZ
         mL8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=8FmUs8DbX3cl7s9opgV8sMaZRhCESuLWpqfaXbWWxi4=;
        fh=vhstJ/QBQVdhI+CNtg8NZEITZzcIXvQnltSv1IkE/t0=;
        b=BFuzE+eP4aWfoIh40HNd9V2zhQPBU/nGuyDrka8Df5eHCobzOo0yFGn2UKQ9MFv22u
         XavLFkwRfJviQzaKzcjL6MERFIjXqVvxvkSaSaPfJqY683Ysap6nnTiu4bmji8j/gNny
         yC8bQ5uQ+tyzppos18TjWo/n5OXLLQPV77xHZpoM+K53IiEQufPd3ifgKUB4x7GEiWRq
         vO073OxjAgVjJJilTLM2wNt0vFyf25eOfI6cjI2+FFbargHKyjvTvcQVMT6+9UDV8XWL
         UUoGFOeIwU28JBzPC/NrRNwVpbIIYelpsr/iHzUSg1aoCoelgYra0LlnYwqqHGL4xTdY
         lQ8w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=I+jieaxF;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718811955; x=1719416755; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=8FmUs8DbX3cl7s9opgV8sMaZRhCESuLWpqfaXbWWxi4=;
        b=kyiBtbB6Zp27lkhipKmFHrM+GqxbXS4pJw7bK+KFwI2wGmKTMZOy6yxwpWwMG1b0V+
         +m+jDtN6ltG0PszzXtCOv7+KzIrN18TrrfczSuGL8jRdjOtyDbHxkbiTW2MIHKoeeUqT
         4GTU7t4g1da05sJh0AtSQS7eAfYMfJXucgAKDV5BKSJiSLzt2zEOS2kDmOrWV33XMQfY
         txRev5iFuMd4GLx6FQJWYlRyCUJgWEp+y9nDcw2yBxIxesT3ZUGZLfhRLhtO2X//MVAK
         YRU3c9qnyQrmngqpbcW0l4z3zm9qSuB3fdd9SDwLb6F+zfQPEDXqAi5lmxzZ/Wz7IzZn
         nEtA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718811955; x=1719416755;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8FmUs8DbX3cl7s9opgV8sMaZRhCESuLWpqfaXbWWxi4=;
        b=ujxVaFlBbDmQcRyil0OATQ99GVxBOstKGSxkBPwvdUkQ5n7Vye0YmMdq1oO0WR26B3
         lBmlwJUPdW0q9ZztmHsaRniCU9OOCiJWHYDKYI1ReM9otHXi4fJJBWwwk9FFkGjQMtjn
         tzSH8E8saoHyi+VNazlW7QqXTR7z5rdo0D1btEj438kw+3jIWQZ898Rnl3pHmWWxBC3U
         c6q+ege2zb+oaM+HdUsXGqxI9HdE0n8gDkbLp7FDXTwZZPxsD2cQrS6O8fGxDC4Nzs29
         zA0QIM9qKkTc9NxHZfjRAyRobtJgQJN/wLLysPUGUQd0Eji9kCv4+iOOFYZl7Bynfd3g
         4JsQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXvGsbvD2qgJGtHqhHmxdXtJD9j52QxWUyCq0L6VsMbSqVdu5s3HEkGfSTwep1R5lLa56MksLFUKPF5LOEPZN410YkptxLQbg==
X-Gm-Message-State: AOJu0Yx8aSnYSeqT3jBkh7Kau4cFgdQ5q9isbiTKhRm5UgwSbVp8nTjA
	r8rxaqPmdkbIHLyxq3ihcg/vajuVkPeTGdjVWuu21rmV/1t+jyYk
X-Google-Smtp-Source: AGHT+IGZ35131BuRwscpk7cep2yrPIG6mZbxpJFxrXuJ/jskfDCewNa97o/RFm3PKClv5Yhhoc1E3g==
X-Received: by 2002:a4a:d29b:0:b0:5bd:15fc:8feb with SMTP id 006d021491bc7-5c1adc24d49mr3085349eaf.7.1718811954972;
        Wed, 19 Jun 2024 08:45:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:305b:0:b0:5b9:db6f:1115 with SMTP id 006d021491bc7-5c1bfcf802als8199eaf.0.-pod-prod-02-us;
 Wed, 19 Jun 2024 08:45:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUfwb3uhoPTb45pJfoApanMn6QBhoySH4ZxXn1+ztDXqmiqjt0sNb4Mz03kJFBwgqUiMO0J7ox93BOxS+kTeux4wHVNp+1ikRzjhw==
X-Received: by 2002:a4a:3c5b:0:b0:5bb:294a:cb90 with SMTP id 006d021491bc7-5c1adbf1d68mr3149014eaf.5.1718811954077;
        Wed, 19 Jun 2024 08:45:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718811954; cv=none;
        d=google.com; s=arc-20160816;
        b=LVqfOGseHUzY0zUYEdl5TqYeme1LIgZG9hdvNXBwmmDxLWmR1J4PWLs3FVeXJkJZ2n
         xVSDzvFORZ8dWZiSqBtGXtMRzYQZxRHIjFkPU1ddOZRFi3oAYwm5PvNVg6kttIA0sGe/
         BQdzGlu/Ty0npJcoz47z0zexCik4UN+SeoXUKH1LdxEM06GSKzdC39sPIJa9DI0J9hBH
         ejMSljuurzhaxU9z19EjDAcGurtSuNL+RmmUCFTT2iKRFo8g4GXgsykzVXRXgfvew4HR
         aM4QDzEAEvtBweqcwEXJfaNLKvN1/+hZ4nWATbL7BKKltyyVA35P07ZKj1UgCPh1xg+J
         dZbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=erZvlatfvJVe/hx7BkMgZ/7G1oP598/R1HnuL1JF6tI=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=sQaud09KM5oq8IleOen7JSPOSCgaAAURAiIuAWeFZ8+wXsziGrGfqft+z+5dXUCsM/
         qk8/RjXfpoYgk7E++8Al3h48UepoTYiuBd4umajWB0yMs+6s75noCwA4d5OUB/QRqAew
         PkoEsrMfdUY81nMieJkUR/PYrKs0M3tbkyR9RRkbKF483ETCuUbi1v4tjjNlKAxeZHnq
         vPnd/agCYd4RAStVeEJgP4WH/qNWx7TkUbYpqCIVthkE6fBQZWFBSM6JQdvM3W5ikkl/
         URX8jheqGbN7yI0CnisYw6mrfdM4nLf8lL1KIT/y8ZabAil1yyg+IcI8SopwSt5l14HY
         f2AA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=I+jieaxF;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-5bd62c4ca61si886388eaf.2.2024.06.19.08.45.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jun 2024 08:45:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353726.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45JEwlSk023623;
	Wed, 19 Jun 2024 15:45:50 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv1jfr5bw-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:49 +0000 (GMT)
Received: from m0353726.ppops.net (m0353726.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45JFjnLw005799;
	Wed, 19 Jun 2024 15:45:49 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv1jfr5bq-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:49 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45JE5i63023914;
	Wed, 19 Jun 2024 15:45:47 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3ysp9qdyqj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:47 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45JFjfWA45154602
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 19 Jun 2024 15:45:44 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id D7DC52004E;
	Wed, 19 Jun 2024 15:45:41 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 88D4E20065;
	Wed, 19 Jun 2024 15:45:41 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 19 Jun 2024 15:45:41 +0000 (GMT)
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
Subject: [PATCH v5 23/37] s390/boot: Add the KMSAN runtime stub
Date: Wed, 19 Jun 2024 17:43:58 +0200
Message-ID: <20240619154530.163232-24-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240619154530.163232-1-iii@linux.ibm.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: YgmfPE7dzJnFHVsUSCo78DlzIaRJ2Pom
X-Proofpoint-ORIG-GUID: PRP7Ai0315YPaTCuzE1hfbsrj0IEqX63
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-19_02,2024-06-19_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 adultscore=0 mlxscore=0
 lowpriorityscore=0 phishscore=0 clxscore=1015 bulkscore=0 malwarescore=0
 mlxlogscore=999 suspectscore=0 priorityscore=1501 spamscore=0
 impostorscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406190115
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=I+jieaxF;       spf=pass (google.com:
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

It should be possible to have inline functions in the s390 header
files, which call kmsan_unpoison_memory(). The problem is that these
header files might be included by the decompressor, which does not
contain KMSAN runtime, causing linker errors.

Not compiling these calls if __SANITIZE_MEMORY__ is not defined -
either by changing kmsan-checks.h or at the call sites - may cause
unintended side effects, since calling these functions from an
uninstrumented code that is linked into the kernel is valid use case.

One might want to explicitly distinguish between the kernel and the
decompressor. Checking for a decompressor-specific #define is quite
heavy-handed, and will have to be done at all call sites.

A more generic approach is to provide a dummy kmsan_unpoison_memory()
definition. This produces some runtime overhead, but only when building
with CONFIG_KMSAN. The benefit is that it does not disturb the existing
KMSAN build logic and call sites don't need to be changed.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/boot/Makefile | 1 +
 arch/s390/boot/kmsan.c  | 6 ++++++
 2 files changed, 7 insertions(+)
 create mode 100644 arch/s390/boot/kmsan.c

diff --git a/arch/s390/boot/Makefile b/arch/s390/boot/Makefile
index 526ed20b9d31..e7658997452b 100644
--- a/arch/s390/boot/Makefile
+++ b/arch/s390/boot/Makefile
@@ -44,6 +44,7 @@ obj-$(findstring y, $(CONFIG_PROTECTED_VIRTUALIZATION_GUEST) $(CONFIG_PGSTE))	+=
 obj-$(CONFIG_RANDOMIZE_BASE)	+= kaslr.o
 obj-y	+= $(if $(CONFIG_KERNEL_UNCOMPRESSED),,decompressor.o) info.o
 obj-$(CONFIG_KERNEL_ZSTD) += clz_ctz.o
+obj-$(CONFIG_KMSAN) += kmsan.o
 obj-all := $(obj-y) piggy.o syms.o
 
 targets	:= bzImage section_cmp.boot.data section_cmp.boot.preserved.data $(obj-y)
diff --git a/arch/s390/boot/kmsan.c b/arch/s390/boot/kmsan.c
new file mode 100644
index 000000000000..e7b3ac48143e
--- /dev/null
+++ b/arch/s390/boot/kmsan.c
@@ -0,0 +1,6 @@
+// SPDX-License-Identifier: GPL-2.0
+#include <linux/kmsan-checks.h>
+
+void kmsan_unpoison_memory(const void *address, size_t size)
+{
+}
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240619154530.163232-24-iii%40linux.ibm.com.
