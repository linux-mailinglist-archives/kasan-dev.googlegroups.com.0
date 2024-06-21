Return-Path: <kasan-dev+bncBCM3H26GVIOBB7WL2WZQMGQEU6TUGCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 37B839123DA
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 13:37:36 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-44350001e65sf511921cf.0
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 04:37:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718969855; cv=pass;
        d=google.com; s=arc-20160816;
        b=n3Zt6MtpNjaRtfWLauxzmRxZAJJSvyD+fhJCpHOWYnRyM196/5q/mtSAV5+FHPhKd6
         Q8IWIphMzaikgCdvq2ktdiRK1GbH5zhDAYkuPM75y+O1wV2i+4Qi3ZUBjsYVAleQUKby
         HZ1MWSLPBZWN0BzWV6fn7iA0XuXgYJwq7gaMUe53kD6AUDF2VxRb9VbIDiKFxRTyXgUb
         diOqM0On0kjiGFJczzq7+rRgeqy/PHqe4GlKHM9NKzlQ2rMrqtKq/su+ytqKrKbY9M2X
         w+7IQP29g3wZzito8orGa/jXTdIuXrTYN2ZyrCuyTOQyiG1VF4ETmFAXsSke/MdCfVAH
         +3Xw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=InI4dW8uwt6Yz0ouQNVM7C7EWElbqz0POWOXQiJ7fY4=;
        fh=qdM15iRyATSlnulQDE5aoO6teEBidYVzJSJPZDyGZHc=;
        b=zROzglhH7UtaOXn1hqJ15rqIlFpb0q9sn0yEqLhRwsHUR5C++4H9lrnzx5VGoHC0zq
         IMRgo9tFRVbx184YiJARQIJBj3i+t7QIYdPfumbIKyTVJirCxrrxSwT0Egyh2UYja2zU
         vJvGBpFBMtOKOwzYBbbLE+rQAmupSI4Qo0qFNZPmUbX8GdPZv6Wrv8Plylondl6F83q5
         cCy1J4avEbK9BFWG7BkIR92jON+eoJmky4g6+QnYPjjdFERzj31BmZHylJeE1FiykgdL
         +puwUO3ttt+coLw/bmN9i4209zjIQ7KMrhh43T+EgSriT0fa5ZGdkMTnVQxQyVMSX42C
         iOhA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=DxC9YrH0;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718969855; x=1719574655; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=InI4dW8uwt6Yz0ouQNVM7C7EWElbqz0POWOXQiJ7fY4=;
        b=aIRwJ5G7niTKVDgQ5LZvc9cJvXQnXLjrb2qcKNHYjCXsLQcz+smGTOVtC1rxZmWx/m
         Y0Q9mXC0uQGCO2glA+CRll6pd1tDovCl5h5LU5sJkZ3Rl1W4YUD7hdTpAEDdV7HWvCW9
         VX0Ni1ToLMfFY8ywZNjdz4xmAk0rVZU7J1PtlTqtg4bfJ/3xq3fuXg51Nu6R1NDO2COU
         7OBoXhPCJ2o5GX+VBej4/ks39IbQA2VG61aNrcLeOJAizfGW0ut4bkeiDNkaoYhwk/eo
         3R8d15wYudOWBc74FWkfQZ/tNSyYkGwAiMdbcjRMcfY1Nahpb+Q28Zoz6BH6jGUHJ0LH
         f9WQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718969855; x=1719574655;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=InI4dW8uwt6Yz0ouQNVM7C7EWElbqz0POWOXQiJ7fY4=;
        b=KaieqjDA8GtUF3QWsMU2ChMyuYc28OW/9K0HNd4DMdN8s3kSImIKg6jLSrJImViuiG
         quUdeV9Ata4bJCIq491CmHAhknTIhklEgRFOl9oYzF5qM0SdUozgIZatdmz9PWdnvKNJ
         146rn19s/LHNWI8XiINGGzy2cOsrcBPFD2jAlBf6Riz6HNxU0n3JG0R/JeInfP96Qza+
         ra5AVXkPXoNg0LhHX/xnyI3MJxyPRLNYLYKDEDMjBttdHlUwGEIj2kcsgXaG/EAY7ttz
         SFDwvra7dem50guVcXP0Yzhh/Mx6eaVjlOGzUFZWRisyt5ourPvz9W+PwWFuDJZcjqw1
         Lyrg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXwBT3acbI3eymSGuZO4OIYcg/bdCt+LETYTOJvsezeXbqOdgIyxwhjuUWAmlEiCGnO/sY2fH8nAOdioPleWt1q3C6tMLUJDg==
X-Gm-Message-State: AOJu0Yy4HXqjjy5YRDnacst713u3u7kG3uHSCt4JtPPSoXXGhrc/i5dq
	VGlngvfs/uWEIIoaVAwh/yoCu50PE8EUXXQed6FB1jKnCm/1sTS0
X-Google-Smtp-Source: AGHT+IE3JxPsZmtxr0XjTCzX+mPx6yr9X4FPzA3WbgH8UJ8CrkRKEH4wwEeU4jh7c5z0gV2k5YEtHw==
X-Received: by 2002:ac8:5a8e:0:b0:443:7ef7:b02a with SMTP id d75a77b69052e-444c35d8b51mr2425941cf.11.1718969855145;
        Fri, 21 Jun 2024 04:37:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:e70c:b0:259:8c55:f25a with SMTP id
 586e51a60fabf-25cb580ebb9ls1440593fac.0.-pod-prod-05-us; Fri, 21 Jun 2024
 04:37:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVVaJf2lDhf3fXluHuw6Y0XigyVn+GGcNa7N+j4+aMxBAteHmdJ2nxcdov5/CmuygFQRS+Kd1j01KzguOjnI9n0TQV8xgtI9pZf+Q==
X-Received: by 2002:a05:6870:211:b0:250:6a57:e1d3 with SMTP id 586e51a60fabf-25c94d02f3fmr8577773fac.38.1718969854344;
        Fri, 21 Jun 2024 04:37:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718969854; cv=none;
        d=google.com; s=arc-20160816;
        b=vKukJ6wQkcLUYxDdZlvkxlvkH9LU9Gy/QQQJYoZ/+dmJyZXqpR6UkDb2AzI38YH+b7
         mmAhE++ZEeRUIMwT6/Y1N71I6Rq5gFAlhs0lJGasSzz5+IBLt/EhsY6kw5Zz1qgToE49
         qBh6gz3Pm/Eu852/Jrqco9YrlQoCmq27fbUuvmfSuz/bGehDTPX0C04tWCnnjh7YTtlh
         G0zhZldxrlPGK5Hde2A8Qb9QSaFQZhswJD/SyAZ37cmgdxaH1Uqahyjt8BKKsMn8oN0H
         LQSWw0McioQptYPqPoQytGqO0atFSK/+LVNw50FhEsPOAwKS/23WA61LI4G74A72XUty
         YV4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=erZvlatfvJVe/hx7BkMgZ/7G1oP598/R1HnuL1JF6tI=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=KHise9OZba14djOOm/Sh40AsOqI0a2dgob7gzjL825ALQykx3M5pVIULvZ7jDPcxOs
         i7gZXRBC50qvdTZCam/jYppSqS6ywDU4hOSGf+eoDk+y0Mrdov1Uh8m2UL1POUZ8+/Rl
         Spl41YGBvjkqrCOyuuf7VWwxEbHy/n4nI6BweyNhOrfuaex3YeGWL0IAMRq0yST6RH6Z
         Qm6Elmmw1k+f4BykEqElj0asXOa/1L7Ij/XTGtKupkSYjGK7rEIQ5aBSYDywpo+vd2ro
         xeqA9JTm+MJXa+ceKr92SonYe87cOym55uLCqTzwt9jaU3SuwnFmG0Rsd1cQF14hJzUO
         qv6Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=DxC9YrH0;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-25cd4c7d3c6si70038fac.4.2024.06.21.04.37.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2024 04:37:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353722.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45LBR6cr001379;
	Fri, 21 Jun 2024 11:37:31 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw5krgf2m-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:31 +0000 (GMT)
Received: from m0353722.ppops.net (m0353722.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45LBWqdJ011582;
	Fri, 21 Jun 2024 11:37:30 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw5krgf2g-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:30 +0000 (GMT)
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L9CfeQ025708;
	Fri, 21 Jun 2024 11:37:29 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrqv6w06-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:29 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45LBbNOn20251114
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 11:37:25 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id C1A742004F;
	Fri, 21 Jun 2024 11:37:23 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 37C4E2004B;
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
Subject: [PATCH v7 24/38] s390/boot: Add the KMSAN runtime stub
Date: Fri, 21 Jun 2024 13:35:08 +0200
Message-ID: <20240621113706.315500-25-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621113706.315500-1-iii@linux.ibm.com>
References: <20240621113706.315500-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: p0zIJbCSnkM2es8X-_i5LPorVdCAulWG
X-Proofpoint-ORIG-GUID: N52-iqLFxUlqfOzwf01LwPyXye5pwRf4
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
 header.i=@ibm.com header.s=pp1 header.b=DxC9YrH0;       spf=pass (google.com:
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621113706.315500-25-iii%40linux.ibm.com.
