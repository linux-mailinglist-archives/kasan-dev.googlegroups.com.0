Return-Path: <kasan-dev+bncBCM3H26GVIOBBXUR2OZQMGQEXQYJXYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1137.google.com (mail-yw1-x1137.google.com [IPv6:2607:f8b0:4864:20::1137])
	by mail.lfdr.de (Postfix) with ESMTPS id 1ECED911765
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:27:12 +0200 (CEST)
Received: by mail-yw1-x1137.google.com with SMTP id 00721157ae682-62d032a07a9sf24928857b3.2
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 17:27:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718929631; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZwQMkTA81y+K0l6fP/H4MNSHqWIErAqe570Ui7FlKUyYukLnyJt2S3gKO8wAzeOclX
         WyXKQXXJCuRuUpd6+UhXhlfGAaBB8l7sSdnPEvI+t+GqWFOJ79sPkmBV2Jzn4pF7us9p
         Akz52vEvU/cS6F5VwRIzn3VDquKcy7LDlmL6VGmvDnEUgs3q1DM0571VwMyN73YEsbG8
         Wr5iWR/n4aYXULKJJFk2Z/jddFTwHfQ8dNvCNmoD0V64UIMQ8S9W/0Fhz6EkC+jMLOQx
         u1c5ydIFf7W7v6J+1kIyPO+I7ob67iUqewP4MUDAUNdxYzv8EaTHzEn6yOHAHwfjLQm8
         XnXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=7r7avprmJTBBpu7FCTv7wKoQ9JtIkXzOFfhP48q2IDI=;
        fh=GBF7tCXMWZkJ6oTmLcqud4ITvKBUBWHopuVHGQzh6j4=;
        b=SCctgufuQixdOo7uv2cgW5Z8bEl5EGFZtYcTzyoz6MFbYHLez9VKfJR9qMVhJyp2fg
         noGsfh1AHnTfPc632VdVwYH1qhMZ8vDREhphWSosOHf5CSQ4AG5GLTlRAjWvhw/YC++9
         u/h7OL5q7/nARVRkxztPjM05QW1wDG6miv66pVpIt/oAl8wrrPXyxm00dz2ZRFfVwC0v
         pd3XqP8BLEAMI+BVzyLH95MN3mIHsrIvX0OghwW7JOnH3ng5WBJpaVnnjbUmNTVUYjl1
         XlENhPWxOWd2jOWcG7WIC53W/nWCVc7C3aoHtdTDIM3EKbsg1oG7Zv2Xw24kf416tyPy
         ND8Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="W/Djp9Zt";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718929631; x=1719534431; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7r7avprmJTBBpu7FCTv7wKoQ9JtIkXzOFfhP48q2IDI=;
        b=GnCEKEz/ugIDVFch5AFhAcrsN2KLhczpxuiBO+brPU8/kUhrspxrZ1RjFyVq39MOx6
         GSkRITiKnORkDmCLA4Y+k75PeMbRkM0SVewtWvND7LdN5ZPDZhMt7aALA/sbqJVMsx5u
         FK1l7AEk36Czb4xiojOvGBTLEvhfHXqiknm15Y2wtpeZzLfG/BUPeh+bsiLU/QT1aIvY
         bXuIc5edefDBdZMk12fLycliqWte/BxBXBg6vM9IeR/ElBf3J2OAC17oi/zTf1rj8lAi
         R5KyIcquLMb0KVIXK/87tbEhhAyphZ9bzWSfhWIB0u70LqLOOMh1Ds/KqEnbX11A9dX2
         8pYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718929631; x=1719534431;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7r7avprmJTBBpu7FCTv7wKoQ9JtIkXzOFfhP48q2IDI=;
        b=nIRgt6wtQoxVnmg6fakOvWQCtAw6E0tHLa+CEuJYl/Bpsp5OGpn6Mxm8bE/+Nzk9ZC
         ioAo2Iv1f2AWZT+aDIrhteAz3CnVL9xvIbYeGH0TAsK/t3uodedisIIWPY64c4wE5C/N
         p4tXVcWJVqmPx79xsD3r3wt6hz2Zu8CXDlLhyBJYKw2Tqq7Q7weEbFfwgSp4EKEs2TSE
         PRFY1NTqnKfTjQOIfBPd8ChO2RQrsdjNK2awNnPWvasfKLvA8nfeJBAXKb6PmkixLTdb
         0BUdFjksJNE+LzBAlOUn6xXXgCfi1dob5BpqcBxyfwT0othh6ardihNd7hou9ObVgYH5
         nKMg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX7ZltkgjPNTV0JOOcUh8fRO0F3FtxVLsQmEUl4hcdnWI7KaySrQmixAlZU6tFaX2M2W0g5nucdYijMT914q2dJ/RRv76huqg==
X-Gm-Message-State: AOJu0YzrgKxame0K8UoOvtw+pY4wDjbedBwXf2jfIB41dqF9FjRIpqJl
	jSshXmSJrUDwU/nnxzHNhpVxPoQH3lgDqnosKKYejndXjHmIimtF
X-Google-Smtp-Source: AGHT+IF2oi3FJSih6qpMCHXsw/kPZ4DmUDL8Ae8cdCmOm8aoSzkoJGfvehEScqQ9onM09VY937Rf9w==
X-Received: by 2002:a81:848e:0:b0:627:74ee:931b with SMTP id 00721157ae682-63a8d92322cmr73822517b3.6.1718929630941;
        Thu, 20 Jun 2024 17:27:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:4806:b0:6b0:8881:bc19 with SMTP id
 6a1803df08f44-6b510086f67ls21801706d6.1.-pod-prod-08-us; Thu, 20 Jun 2024
 17:27:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVekoeiPrqSwVkP5VXXifxnOmevGGsGb0pYqWryMqOIdK5iv/qA2jvqzP9kykU1kMzSrmkwExwDAXu11hEo8f0Q2yCUsdLaPVDXIA==
X-Received: by 2002:a05:6122:169e:b0:4ec:fe12:4559 with SMTP id 71dfb90a1353d-4ef27813b20mr7753757e0c.13.1718929630279;
        Thu, 20 Jun 2024 17:27:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718929630; cv=none;
        d=google.com; s=arc-20160816;
        b=1K0w+GfKsUYNyc+pck33H2ciINHQnVbB6v0oVfcIj/io9zZhKLMhCq5BFaX9LHQYEA
         WQmcpktE7onLEmLp5Lk/xsWJalVnSYmmKKDgd/09zXMcYES6METhvgbm99yy33WTCybb
         bDKBDKh5RJOyzD0XUrcsEnao+/ZOb0e+eWOG087fUtMvPeQ8wGZFyBagCdIVMTUG5hmT
         L/Tf2C8VBtEV+8q8CqUZ8UR1R2bq8njJcw5fdTp0awfyaMd5xsj2nQ9iMJbpVRhpJUKM
         6bX8thzCWs9WZ6bB1GP7ZysdPt0x+lvzIvuqpLZUlX6+eu4+XrTbhWQ6+Cpkg+fzW/5V
         XMWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=X1oGap99TVdqBvzHLWhv+TXBuFqzUMdrRG4OBua4bwY=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=C1ps2h3sHpM/p/lsTHObY1SexDtZUWHdba/p49CbSph2vTHOCnrj83ok3/E72RGHY9
         opIDRb05rmp2rkpZp+w92yzehXJs4lwdP0gGBxeTcxeMGSySRHq0bYQoWWo06UE1qsd6
         C4MuC+tO6dqSWVAngNDI/4RIFxCGcs4076ypC+bEX1OjBnT4NbzAo2cmrxpsq18aRy1q
         lcgpxnJkXmgnMyvMXFDy7aq4EdedKZTS01/Bk1hMl+fOsTPSMlzQFaI4hLZq2obyNHRr
         fcQ/b9X6rywyS4lQLWF5XPUmB1qrTMQI4OBIdI9sAOUxNcDDDhziZM34QSnSnAU0J+c4
         ac7A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="W/Djp9Zt";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-4ef4b3886b2si2596e0c.1.2024.06.20.17.27.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 17:27:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353726.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45KNQq5q017556;
	Fri, 21 Jun 2024 00:27:06 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvvrdr8be-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:27:06 +0000 (GMT)
Received: from m0353726.ppops.net (m0353726.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45L0QaaE009416;
	Fri, 21 Jun 2024 00:27:05 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvvrdr8bb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:27:05 +0000 (GMT)
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L0PHZm031330;
	Fri, 21 Jun 2024 00:27:03 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yvrrq2ncq-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:27:03 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45L0Qw3v46924224
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 00:27:00 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id E97EE20040;
	Fri, 21 Jun 2024 00:26:57 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id C698D20043;
	Fri, 21 Jun 2024 00:26:56 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.44])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 00:26:56 +0000 (GMT)
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
Subject: [PATCH v6 31/39] s390/mm: Define KMSAN metadata for vmalloc and modules
Date: Fri, 21 Jun 2024 02:25:05 +0200
Message-ID: <20240621002616.40684-32-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621002616.40684-1-iii@linux.ibm.com>
References: <20240621002616.40684-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: bwF18VfazW8eN9kbTGux1ece82genkGJ
X-Proofpoint-ORIG-GUID: vQS0SDPy88_48lPJre9HnK-Wr12hlnFB
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_09,2024-06-20_04,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015 impostorscore=0
 mlxlogscore=663 spamscore=0 adultscore=0 phishscore=0 mlxscore=0
 lowpriorityscore=0 malwarescore=0 priorityscore=1501 bulkscore=0
 suspectscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406200174
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="W/Djp9Zt";       spf=pass
 (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as
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

The pages for the KMSAN metadata associated with most kernel mappings
are taken from memblock by the common code. However, vmalloc and module
metadata needs to be defined by the architectures.

Be a little bit more careful than x86: allocate exactly MODULES_LEN
for the module shadow and origins, and then take 2/3 of vmalloc for
the vmalloc shadow and origins. This ensures that users passing small
vmalloc= values on the command line do not cause module metadata
collisions.

Reviewed-by: Alexander Potapenko <glider@google.com>
Acked-by: Alexander Gordeev <agordeev@linux.ibm.com>
Acked-by: Heiko Carstens <hca@linux.ibm.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/boot/startup.c        |  7 +++++++
 arch/s390/include/asm/pgtable.h | 12 ++++++++++++
 2 files changed, 19 insertions(+)

diff --git a/arch/s390/boot/startup.c b/arch/s390/boot/startup.c
index 48ef5fe5c08a..d6b0d114939a 100644
--- a/arch/s390/boot/startup.c
+++ b/arch/s390/boot/startup.c
@@ -301,11 +301,18 @@ static unsigned long setup_kernel_memory_layout(unsigned long kernel_size)
 	MODULES_END = round_down(kernel_start, _SEGMENT_SIZE);
 	MODULES_VADDR = MODULES_END - MODULES_LEN;
 	VMALLOC_END = MODULES_VADDR;
+	if (IS_ENABLED(CONFIG_KMSAN))
+		VMALLOC_END -= MODULES_LEN * 2;
 
 	/* allow vmalloc area to occupy up to about 1/2 of the rest virtual space left */
 	vsize = (VMALLOC_END - FIXMAP_SIZE) / 2;
 	vsize = round_down(vsize, _SEGMENT_SIZE);
 	vmalloc_size = min(vmalloc_size, vsize);
+	if (IS_ENABLED(CONFIG_KMSAN)) {
+		/* take 2/3 of vmalloc area for KMSAN shadow and origins */
+		vmalloc_size = round_down(vmalloc_size / 3, _SEGMENT_SIZE);
+		VMALLOC_END -= vmalloc_size * 2;
+	}
 	VMALLOC_START = VMALLOC_END - vmalloc_size;
 
 	__memcpy_real_area = round_down(VMALLOC_START - MEMCPY_REAL_SIZE, PAGE_SIZE);
diff --git a/arch/s390/include/asm/pgtable.h b/arch/s390/include/asm/pgtable.h
index 70b6ee557eb2..fb6870384b97 100644
--- a/arch/s390/include/asm/pgtable.h
+++ b/arch/s390/include/asm/pgtable.h
@@ -107,6 +107,18 @@ static inline int is_module_addr(void *addr)
 	return 1;
 }
 
+#ifdef CONFIG_KMSAN
+#define KMSAN_VMALLOC_SIZE (VMALLOC_END - VMALLOC_START)
+#define KMSAN_VMALLOC_SHADOW_START VMALLOC_END
+#define KMSAN_VMALLOC_SHADOW_END (KMSAN_VMALLOC_SHADOW_START + KMSAN_VMALLOC_SIZE)
+#define KMSAN_VMALLOC_ORIGIN_START KMSAN_VMALLOC_SHADOW_END
+#define KMSAN_VMALLOC_ORIGIN_END (KMSAN_VMALLOC_ORIGIN_START + KMSAN_VMALLOC_SIZE)
+#define KMSAN_MODULES_SHADOW_START KMSAN_VMALLOC_ORIGIN_END
+#define KMSAN_MODULES_SHADOW_END (KMSAN_MODULES_SHADOW_START + MODULES_LEN)
+#define KMSAN_MODULES_ORIGIN_START KMSAN_MODULES_SHADOW_END
+#define KMSAN_MODULES_ORIGIN_END (KMSAN_MODULES_ORIGIN_START + MODULES_LEN)
+#endif
+
 #ifdef CONFIG_RANDOMIZE_BASE
 #define KASLR_LEN	(1UL << 31)
 #else
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621002616.40684-32-iii%40linux.ibm.com.
