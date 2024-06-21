Return-Path: <kasan-dev+bncBCM3H26GVIOBBWUR2OZQMGQEXC6LSLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2AD3C911761
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:27:08 +0200 (CEST)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-24c487df201sf1076056fac.2
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 17:27:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718929627; cv=pass;
        d=google.com; s=arc-20160816;
        b=ywy8TcvS3OyBGvtUxM+8Yh0TP8j/LrzVfd0f0ZVIYPQzyvVpRc1xm3tn/HBZ1g2WMJ
         wChmLlusFoG4SSMESG4LSGGr7q6EgsH+CTr5E4Hl/IYL8MPZCpCeg1Q9rU1MGIAggvIR
         qTx5D/FP4wpZgl/Ef2/9yskTmjoulD63Gpk6aMdPYXSC3FRKvyoQb7LyLMFGreLFWBC9
         4IKgBpJJ9MlIuoCANuEolvN19QeQpJOb1c30GZgc4gvoT9b8VpU7YKZLDT1mSITz1rou
         cYS/0KUJUqSvRtPjBBu2LBy/JgowHdhN4jHFf0m8S6wVJokvKduQWkIRke5mpw9RU4FM
         UPtg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=KyX+5AMXisKqVw1bFLjaPDvgv7ykuhjcIR+XPoyTXQc=;
        fh=rYpdRDvfjtx5BhRyvviRz9uW5GUrGH5ZvOIVonZGbRY=;
        b=MyyUSoI3LGNejWVEZ+AEnEjJvUR3Np1B8xoK7twSlw2q0PfE/kvd5PEox+69igpKu7
         xut9iQEnYerAQETkYrICYZ3EwoD7/mpM8vtMiy31puJ+dJ+z+zmRS50PXPxhjFH8GYLw
         Fi/2pPAUAqDpBrz1Y2iRNh4/495CfiKzgyw+DfQtrNyZWZ3GKWUPVtr+bhP/AvFv0Wb+
         T8955Sphvlc16OdeowcEyjKLVg67hjDcNYujXpNskFZPI9oYG5nMAOSdvcW3CSyk+9TW
         JtpGez+RbUJBKPecgKKskfDH1/B4Xvt8Q0TjRKrnULqOrQTmUmKmKSnEmE0xnPRp8FEP
         yseQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=sUnHME64;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718929627; x=1719534427; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KyX+5AMXisKqVw1bFLjaPDvgv7ykuhjcIR+XPoyTXQc=;
        b=EHqdDd5wv5wnblk2Fdw84GTi5/1wuBM/jV7hPxyb61SIeCLLnXTXQi2C3F2UuL4nag
         lau8+SxTI4zK6gJegoEOlZRPcJ9hY4h4axhpq7O+dHObEkFm2+jY7rPeYaMuGVJjZvAb
         VktK0QTSqQFkb8E7slsXPmHl8VhsYHjI5JdzRBjdCiImRxLkXZGDCVr6o2rwM+Afuypk
         icmliv6XzFxzdKndvMHowtzFsGMW9scM2WndWDaIvHrbB90Xm03VH2l1Pu7Ly9hgbp2Y
         PVOMUFR5rCbjJ+mawiIU5KYLmM4pY1uBwQNbd4+CG/bvB1fhK+0XM1/ZsdDbPgTbJcdD
         v5+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718929627; x=1719534427;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=KyX+5AMXisKqVw1bFLjaPDvgv7ykuhjcIR+XPoyTXQc=;
        b=kVLdN0p9kbZI/hjIxH/+rOZ6ct5kQeO9Oe8lYg+QdO4XJWE5Kj2Wbd8dq/Hc85LZss
         goK66gjaVif/gSlafzX76seCxOWOKYSjPjW/BftR5Ecr6MqXpkhgKX+2zywiTpNFZVlz
         C8TwfXGkim1KIRFH9HuUbeIbiV6NxNQ696MmR3V3q3mAScPq9vLqbwQrRnlpGgtrJNXt
         FauOJMpL4Dj8CI3iOAl1bk0tsw8Z+MdXZ36L0SOka0iRHoUoYm3chZVG1J5XVBLb/V+z
         X8WVbfuM1P7LflxzmIzJZdy7Kra1o6McnWH/bZpJWZYku9D0xhB88zzR0N59hmTHHOYr
         J6EA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUOZ1Z6wcL+yq804OQj9uMHswa8198huIZYG2xvT0pdA83+iOQu8MwMUaaoirX2YCnF4xTOkBe4gjsT9iaeCrmP9mh8btcUbw==
X-Gm-Message-State: AOJu0YwdtNfkMZqqIGXJ7p5H5Mhoft6Gnh8aOu4nxgXu19nhYnXvV2WJ
	cZssJ9VZzFQKKwKk1iuaa6zLIqirc7NROIzonv0Jw7L43gArLReI
X-Google-Smtp-Source: AGHT+IH21h9JLmpHEtCk8km0/xelE0u8ZlhGU5Fx+aYkOCCY8PY5wYZ5hGhy5EnAexNhIxLKqjlcyg==
X-Received: by 2002:a05:6871:1cc:b0:255:d15:5acf with SMTP id 586e51a60fabf-25c94d05a09mr8342776fac.36.1718929626830;
        Thu, 20 Jun 2024 17:27:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:280d:b0:258:3c95:19a5 with SMTP id
 586e51a60fabf-25cb5f324c3ls902454fac.2.-pod-prod-06-us; Thu, 20 Jun 2024
 17:27:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXiYqkGv9QFBzPphNItyPKZW45HHcSJaWptK3fVo38mSTe+S0AKkUzqFxCym92CTQ6tFjxx8RjvAgoxQZ75NotCrCCfkbevGKKnxA==
X-Received: by 2002:a05:6808:210e:b0:3d5:29fd:c7fd with SMTP id 5614622812f47-3d529fdcab6mr3856384b6e.37.1718929625680;
        Thu, 20 Jun 2024 17:27:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718929625; cv=none;
        d=google.com; s=arc-20160816;
        b=egCqRDNL+5wbVysQ8vMm3ppzafUfHc2qJ6Ut/b5GXHHwSdROCAccOU+EPXZifkMTZG
         5517v9vS3N137lTB8aIpBKHj9wvkVdhQX7uY/RblLuiTYtCYJCtGRENEn7qQpr0NEjqO
         mHGzHkTOdO1mnDr3hyDFg2WF4NW+bAc41TM2NvNVoiCRLNJ+MxVc+yvDTmqbVUD9EkWG
         K+orMVsuz6NkZKBCjLevOLRmPOFe9LeEVHUU9FokkxE4d/QzNdBSMhKwkauXP0+mwaTE
         gn5+D/u9OXmrF56C1zO+mm2iOwdd7cygLRsEmBRS8KjnhKqoieuDSIkvGZxjC20PCrCB
         G+7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=lwqEGphQg9/N4AE+qTFRbf/COwqV90p8RxwOJfRaDvM=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=oMLURcEXABgLmCXPip5ZcspCYRSgSF/JaBwX2qtyUkzYZgVvJ8OPx+Yf6adgj3Fy5t
         ZG2tlF9rkXbcNIqhcvTVxsZRbA/NeZgc+tcvaYf2DQnKvAovWbqcIJld/SJuWgvHUuo5
         zM/8rE/S6Zu+pj/MTNXNt8CfIak+7x/JhX47aWJd+hwKS4jWkRjlkQ24EK+jtwOI2lWy
         OyyNQI2ZhFf8m9xkaZXIp4FrrFE2bX1oKr/biTjuD3KGEeZa4HR6PRsrdLNHuqo9PyAA
         kvQDLVTUAVsCq4JBp9UIieTPrc+OzxJuJcgRveiF2vIn/IP1HLqG6JYuDiUukvPmLpUI
         RzyQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=sUnHME64;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3d5346b0ba1si19008b6e.5.2024.06.20.17.27.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 17:27:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353724.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45L0R3tp023355;
	Fri, 21 Jun 2024 00:27:03 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvvs6g7ss-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:27:02 +0000 (GMT)
Received: from m0353724.ppops.net (m0353724.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45L0R29o023301;
	Fri, 21 Jun 2024 00:27:02 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvvs6g7sj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:27:02 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L0DBDN019999;
	Fri, 21 Jun 2024 00:27:01 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yvrqujnyv-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:27:01 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45L0Qt5m44761488
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 00:26:57 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 7DF2120040;
	Fri, 21 Jun 2024 00:26:55 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 5BB6820043;
	Fri, 21 Jun 2024 00:26:54 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.44])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 00:26:54 +0000 (GMT)
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
Subject: [PATCH v6 29/39] s390/ftrace: Unpoison ftrace_regs in kprobe_ftrace_handler()
Date: Fri, 21 Jun 2024 02:25:03 +0200
Message-ID: <20240621002616.40684-30-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621002616.40684-1-iii@linux.ibm.com>
References: <20240621002616.40684-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: N3pQcZOmYYu02d0GkX16fhENd3yleyOu
X-Proofpoint-GUID: f6nbbUMMpzabyYE5l2CvSVqR2_ItvZYT
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_11,2024-06-20_04,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 bulkscore=0 phishscore=0 impostorscore=0 malwarescore=0 mlxlogscore=999
 lowpriorityscore=0 clxscore=1015 suspectscore=0 mlxscore=0 spamscore=0
 adultscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210001
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=sUnHME64;       spf=pass (google.com:
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

s390 uses assembly code to initialize ftrace_regs and call
kprobe_ftrace_handler(). Therefore, from the KMSAN's point of view,
ftrace_regs is poisoned on kprobe_ftrace_handler() entry. This causes
KMSAN warnings when running the ftrace testsuite.

Fix by trusting the assembly code and always unpoisoning ftrace_regs in
kprobe_ftrace_handler().

Reviewed-by: Alexander Potapenko <glider@google.com>
Acked-by: Heiko Carstens <hca@linux.ibm.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/kernel/ftrace.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/arch/s390/kernel/ftrace.c b/arch/s390/kernel/ftrace.c
index ddf2ee47cb87..0bd6adc40a34 100644
--- a/arch/s390/kernel/ftrace.c
+++ b/arch/s390/kernel/ftrace.c
@@ -12,6 +12,7 @@
 #include <linux/ftrace.h>
 #include <linux/kernel.h>
 #include <linux/types.h>
+#include <linux/kmsan-checks.h>
 #include <linux/kprobes.h>
 #include <linux/execmem.h>
 #include <trace/syscall.h>
@@ -303,6 +304,7 @@ void kprobe_ftrace_handler(unsigned long ip, unsigned long parent_ip,
 	if (bit < 0)
 		return;
 
+	kmsan_unpoison_memory(fregs, sizeof(*fregs));
 	regs = ftrace_get_regs(fregs);
 	p = get_kprobe((kprobe_opcode_t *)ip);
 	if (!regs || unlikely(!p) || kprobe_disabled(p))
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621002616.40684-30-iii%40linux.ibm.com.
