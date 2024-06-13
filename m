Return-Path: <kasan-dev+bncBCM3H26GVIOBBUVFVSZQMGQE6JW3ONI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id A35F69076F3
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 17:40:04 +0200 (CEST)
Received: by mail-io1-xd3e.google.com with SMTP id ca18e2360f4ac-7ebcbef22c8sf113517639f.2
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 08:40:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718293203; cv=pass;
        d=google.com; s=arc-20160816;
        b=ccs7y8t5deu2qIaJ+NolTpXfcaH2cEoVW9n4yS6aHVcxZO+/ijaL4O8iXBV1IWO++m
         RgQRByjGy2Yh0INEhML1czGChbC5Q3WtJuYWozIl1Pef1sXkXxdNuAiHzabNt5VJcvwD
         qDuYuY/wVBJhlb/NZAv6WTYQj3lJ/iDsIkTgazfc64SyPl++5aXgJgg/8WUtdllaaarD
         yYdSXQXjJoZKtCx9qIoddwpnf8n9J2CyRQhgVQ6+qjmekoIDJoqW1291sifbhly4xTb5
         t1Mr8V+ezKdAZj5C6jgvRiF1/wdcbf+heGOn9gAsmv+dG4QkSjUuyzK7HvLXvv5x1HPf
         mtYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=8JbF6RE5QD7yZoQ2Rsb11woro9gt+lMDKNsJDZIiFD8=;
        fh=iwCAKUChVAc/TLxO3gRrq6SA8AV7UBTFtb6h/lO/POQ=;
        b=cqvZ0hz/0Ds4wrpu/QVyvQfJEKakd1SmuKNRosSCmDFjB/r1BNTk2B4WJRCuG8UEEs
         /G23L6iOyQ/PKcJaYC9zAG9WZwMfR2aAh44E8ZweblTnH7wOUPPt0HMP2PheDmcSSzeD
         Yes+nFBKXfgfze/F8F6rG3R3+PAwClLISss60B9eK+HBOYgS0ohv1cq1axkDD/pGolSB
         F3VxCMvV0DQUpAXJ2e0xuyECDLdHhY4m0VieipworH+WE5RhUV7yJygwW/sW3a0YU9VB
         CPI47hq8NFfuMHzy547t65q8eHc4PLXg6qJRxHHfNCvk9WpFe9k2q1dDM+QII75plNga
         YnKA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=HmIS1qUj;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718293203; x=1718898003; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=8JbF6RE5QD7yZoQ2Rsb11woro9gt+lMDKNsJDZIiFD8=;
        b=Pygb27YeH0HANkOeVJWwN+Ti3u1vbZBttRumb4VNIc91N2AZFCX4oLmYcnqWIreD1w
         WwrKICAzyfjT7ewBbRncoAPqR/BFscutnyK+rKwraAgkt38g+qkDV1YUEvGOh3JOFbcl
         kgW5qbVrWLCXp76wchq8yiOFkia88J22m/tBIf68g/0D/hJ2Y/gkDqy0IS0M2HPrM6M2
         6HldytKRdKFwjnFUD0JJX5iaNZ+0lMlJCUhNw4v3J3vNjZYu9X9qKVKM8uMKhA9c8fjL
         0NM5AyYX3XREtrk4WKUGaBImNAb1EMyK/93fPywQJhA46yrdHFC3fMxfpii+FTnHjSsw
         rjNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718293203; x=1718898003;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8JbF6RE5QD7yZoQ2Rsb11woro9gt+lMDKNsJDZIiFD8=;
        b=Vm3d/Qdnsd7HQ7cXfa3uL+uHhdYkhsAJwuaRSv2FLD4MCkP/AoO9CmU/Zqg2Yrss3p
         0+JIs2CreJHq30OMFFVaVXTRSS4vKfHS8T4U+ZNloRu0YewNZCYfEe0tw24f4aLx80PF
         0F9d1FYn3K5vQn28z767kppeB2mYTEzWkOTlXqkSPZutcvgDBzu8xgfirSAEpUd4vTeW
         jvxyilZeKh+kIV8vlqvgQAk7PV67lJgzFqL4B3Pt1ZFr1hCl505hBXm4QTMJC9NNZij9
         7VOVJ6om45DjLoj02tQKUVTgJoQ+Ob6bWYPWX0iNJLS8FImX0Vxd+G1DXRR7F555hVFG
         /JbQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXlN/WAwsRU5MqhWHX2RGSUkahjHtSzDS9MSFOaX0wMWF/EVbk9ZMuNE1MKzvnwYZaYYBfFupuVCHYkaifG2F2HAECarefm3A==
X-Gm-Message-State: AOJu0Yx6GdYc2bKsGRveEhoU0cXu6EHJ7vaaJVhCyOhUWtjReUdgxqvU
	+LXjExKPz3bB3OjgzEQ8nWY3CuUlVflVOO/CZxmZ4bbC3SAlWmTa
X-Google-Smtp-Source: AGHT+IHud+nK/HModZH1zTqdtLwN4S3FopCdcl6dUIDtion4zySq1xqwBAYpg56mmvzFTHxWPu0P2w==
X-Received: by 2002:a05:6e02:184c:b0:374:aa87:bcc9 with SMTP id e9e14a558f8ab-375cd1f46e3mr51064345ab.24.1718293202940;
        Thu, 13 Jun 2024 08:40:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:3a84:b0:375:ae19:e63e with SMTP id
 e9e14a558f8ab-375d5661ce0ls9219235ab.1.-pod-prod-06-us; Thu, 13 Jun 2024
 08:40:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUy/zTG7p+OSBbEE08PKEbIEguumHNtCRrnhMR4lCIyCN7flCcSYtkbrw7n4bbNsZslsiDpa2mLkomMC5bNpv6NVfMcqCLNffHc/Q==
X-Received: by 2002:a05:6602:1644:b0:7eb:c68b:8250 with SMTP id ca18e2360f4ac-7ebcd18e41fmr638524239f.18.1718293201933;
        Thu, 13 Jun 2024 08:40:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718293201; cv=none;
        d=google.com; s=arc-20160816;
        b=ZR8P9wgyRK/2qZ8giYl77/6yS2T46x9qmrqx7vTz5ovbmWb63UVdFyTr3Dl8Il7ReF
         ZV6O4woibXa8NICirqeCST84S4e4vAyHm9FmIqPm6088gcS5PURu8N0PGIgfzM9iRh1h
         qORJrc4ttx/Dbd1A8ro2q1aIF9uS5NXVdaliT6L+Xpw4s5vSniNKDyUDXXNit96ZmLeM
         go8Wt5tN/q/M1myC7He60zGausk7+YgSr+RpMM5ZsVR3YyTDmP0N9fKSnibKIneeqsQ9
         YPGZvUycKZzs06GO2Npv1yPDREi1Aj3qi1HOV2i5ANxYL33pz2BIe1cFuSe3lluRtZO3
         M2uQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Lf8JDXEAibfeu4y+WuUMeyCObr8U6xtLlRth+wjWPFs=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=oRO1pZE1L2fiOTsSb8jMoJrxgT+V8ooBFyx2Mbbdjt/KjYa6aVznq3XClgELROf+ID
         KRav0TQdsK4CES9JKSDBcXNlmHSLSUMEXe47pU1wUSC8nQIMnD3CGmMVKzM2D9y8t4PC
         hOJ7+O31Mv8jJ/m61eUcsMGZ8YtfyrhelYcyr5TVQN0m624zJba19SwE5hReblmohDQU
         MSuGKyvgg8HM7vQI/afVTQBU1o1/rIFThsMluvgLaNHXo6skUv3/JtNqULsjs+RYMQsj
         MOSvsz1k0Mqd8HXgsjOdYlH8lpVMASfMrouCdIPtyUuGgDxQyWV9Pb7qcfzIzvala3kn
         2CEA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=HmIS1qUj;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-7ebdba20e5csi9561439f.1.2024.06.13.08.40.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 08:40:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353726.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45DFMPaL026307;
	Thu, 13 Jun 2024 15:39:58 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqq4rt37g-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:57 +0000 (GMT)
Received: from m0353726.ppops.net (m0353726.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45DFdvZk026874;
	Thu, 13 Jun 2024 15:39:57 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqq4rt37c-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:56 +0000 (GMT)
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45DEjjfs028690;
	Thu, 13 Jun 2024 15:39:55 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yn1mus9ga-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:55 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45DFdo1k49086754
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 13 Jun 2024 15:39:52 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id D49042004E;
	Thu, 13 Jun 2024 15:39:48 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 614DE2006E;
	Thu, 13 Jun 2024 15:39:48 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 13 Jun 2024 15:39:48 +0000 (GMT)
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
Subject: [PATCH v4 29/35] s390/mm: Define KMSAN metadata for vmalloc and modules
Date: Thu, 13 Jun 2024 17:34:31 +0200
Message-ID: <20240613153924.961511-30-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240613153924.961511-1-iii@linux.ibm.com>
References: <20240613153924.961511-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: pD6uyOhh-bdrq5oWD9AJUmqZbuVWYtd9
X-Proofpoint-GUID: hE3He5xumiJgo0Zbuv3p-52CPM54okmR
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-13_08,2024-06-13_02,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxlogscore=697 adultscore=0
 spamscore=0 mlxscore=0 priorityscore=1501 bulkscore=0 malwarescore=0
 lowpriorityscore=0 clxscore=1015 impostorscore=0 suspectscore=0
 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406130109
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=HmIS1qUj;       spf=pass (google.com:
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
 arch/s390/boot/startup.c        | 7 +++++++
 arch/s390/include/asm/pgtable.h | 8 ++++++++
 2 files changed, 15 insertions(+)

diff --git a/arch/s390/boot/startup.c b/arch/s390/boot/startup.c
index 182aac6a0f77..93775142322d 100644
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
index 70b6ee557eb2..2f44c23efec0 100644
--- a/arch/s390/include/asm/pgtable.h
+++ b/arch/s390/include/asm/pgtable.h
@@ -107,6 +107,14 @@ static inline int is_module_addr(void *addr)
 	return 1;
 }
 
+#ifdef CONFIG_KMSAN
+#define KMSAN_VMALLOC_SIZE (VMALLOC_END - VMALLOC_START)
+#define KMSAN_VMALLOC_SHADOW_START VMALLOC_END
+#define KMSAN_VMALLOC_ORIGIN_START (KMSAN_VMALLOC_SHADOW_START + KMSAN_VMALLOC_SIZE)
+#define KMSAN_MODULES_SHADOW_START (KMSAN_VMALLOC_ORIGIN_START + KMSAN_VMALLOC_SIZE)
+#define KMSAN_MODULES_ORIGIN_START (KMSAN_MODULES_SHADOW_START + MODULES_LEN)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240613153924.961511-30-iii%40linux.ibm.com.
