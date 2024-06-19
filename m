Return-Path: <kasan-dev+bncBCM3H26GVIOBBNH2ZOZQMGQEKHJH33Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2CBB590F2B2
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:45:58 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id d2e1a72fcca58-7043008f4besf6682087b3a.2
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 08:45:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718811957; cv=pass;
        d=google.com; s=arc-20160816;
        b=OYoUN7AMw0tefxHHEUaKNdfaKpWc/LMQUmsC7gDFvAUxhXoFQpOuWrkkck3cwqJs2d
         Cl0FPRDPBsBTks9+Ldh7Mq1whvfi4bn5tyTbRYgWOdJGIoRwl6BTU5JIXHmWIEipfrkP
         dBVEG9Mv3fJS5vMmMa7WeBXW5hxBhnxHtWX/H0KxM3tqtSj3fCy3XQkW2SPQ1ePisOyR
         /rd0u1Ci5R3Y46Jva8YUejKwXna3vsidb5yt13liqJWNDeYkyoOC42ACktngIp00JNiI
         cvFn0HSTSkEPbPwdXmVOk325nMRqGMHNYBeAFFCP+76oe6mA3WSKAx3Vb8miHEA/9VtR
         zQjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=uyoUOHL0n79pqrUpHHD9C9AEvb5RcH6vx1Iqjp4QMbg=;
        fh=Tkr1swVDJ+7U6y20TYKqh4uFg5tuU4z7OzuwoP+F7e4=;
        b=r1mMQ1qXG/J92OH2WhQ+gXVMW1zvocXDS/NfiZh07W4smZL/Txndwi0upPJsS00839
         r0fNWElsWDziU8NK6IqWqk9oJyDP9IfAo4Ld4Lg9pmz1oqDjvZV1OyWk1qxoV+78JuKL
         bCsYLrhaLkNr4q2gM9M8bD2jCXiUbvtFp7TqIAOM9pYAC63gNoN/3G69trdBoEMWYwyz
         7yw6hGUpiL+VJs3P67ye8EdKQDgZhEHOcG09TnDZZ6VwQw11nUVqN2dw/1GQC5pHQ4Yj
         ltBttwxE13gnMxLtATWWHLxoU32LctjkDsxabMXnfLMiqjZCkGFUAJ/BdAwaepo3xZmY
         d0qw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=jtW3aDdN;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718811957; x=1719416757; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=uyoUOHL0n79pqrUpHHD9C9AEvb5RcH6vx1Iqjp4QMbg=;
        b=O/H9hZgqVYr9QDveFwJMphmzbpPztzCpsM3AOAJNLHumeY/8MorMC5DDaXzp9w2zXC
         WqLiBf+PmChsX8rgIKU0OE64P8fV43ZsbELTRBVv9Pdy2VdcX06z5S8O8p3Pwl26iKfB
         qG/9D8J4gr93Gyx/qZHRybPxuQCNGm4NiTqFlOCatuGMSxRKyYivKaemVFkUDcoMU++q
         bBIXgWX/UbbL925JQiSJFTHZc/4wPhAUxhVX6kvuPN+Fdq9XBZlwONMEn9q+uk0uCTwk
         kAGgLEa5lDFtCON4o3phSm2a8Genn5pxgVKltkjBSt+nBVMUUaim2j0WSr8ivEFeDUeX
         DoMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718811957; x=1719416757;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=uyoUOHL0n79pqrUpHHD9C9AEvb5RcH6vx1Iqjp4QMbg=;
        b=ZA2tMEOqELgnT3fDtzAIcUJfkXd8mXM6JZptKwaNZUgoolZOCImZXX44iCfKcosE8Z
         k+HgDjqKokPV5b6ZxunwbSlCPxX9d9TtoaG+U+6ERZf94wu3PliltAbZEAvoT1r46B6i
         mANtCoVwXaS3oqaU48/kvmWj33wefGWfvFZMrfHU0px1+h+ojJqzhgt1dS4Z2VRZs8pN
         jFM77n7cnEUWEP3CoanxZbTGpC4CDnbiPHEbq4PChp28EWKDsutV0JTkB0SDzNUb5Nzi
         N0M/WXLfDlbKqvZMm8BBezYUwwR+1cmVq92bu4zZFeBPt8ojwLAeDTjmOaTV/dk2e43E
         eY2g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVrsLGydK1gD+7niI3LKIE8TEpkGNnqoDJ8K+xptnIxutGwm1ORRJM8qpbxKicm9Eu0KDS4MZkaa3+ddo87v/KWeNqOPdvxgA==
X-Gm-Message-State: AOJu0YyCaqg5daB1bvkEHdUIVBrUbH/o5lvW2kIFemlt1DFkUSAxGl2S
	cAsrdLbUUFOaTEKVVEehZgObxwlCMYTPLAH/Y+1cX8japTT4Hn4p
X-Google-Smtp-Source: AGHT+IHPyhSAvDxI3BlgkmtUNRU+7sbWcub4x93b0SAo8IzwkbCkNipc6qyDikohz1AtNzPQpQNuUw==
X-Received: by 2002:a05:6a00:2b4b:b0:6ec:fdcc:40b9 with SMTP id d2e1a72fcca58-70629c42be9mr2664076b3a.9.1718811956767;
        Wed, 19 Jun 2024 08:45:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:2d15:b0:705:d081:de9b with SMTP id
 d2e1a72fcca58-705d081e053ls4008817b3a.2.-pod-prod-03-us; Wed, 19 Jun 2024
 08:45:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWV1T455yfUZ9gvbyvDFqW34dBXjl0dVMVKYWb/RxpnqXC2KYuGlbjnA4tylN/tgRTp+fIS3T4Ux94iQ3lXi0g+I3mMawRkK4zDMg==
X-Received: by 2002:a62:b60d:0:b0:704:37b2:4ced with SMTP id d2e1a72fcca58-70629c429c2mr2708036b3a.11.1718811955626;
        Wed, 19 Jun 2024 08:45:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718811955; cv=none;
        d=google.com; s=arc-20160816;
        b=U5TpBnOTL0rd2YMIYE+yoSF42wCyRb8aXG7a1dNOyTSYUSzbMdtYNHBVUrF3i2Rqq3
         9wPp9gnPJiYfqmeUdVajr34csuRijZNHDq8QJQiZcpqfFyvh2+rLddSDD0nW7AGGwTm4
         2xT9Xjl38wPqOvS8EQRiktQTC6l0Ch/p3qqrgj/R7UKOaxFHuL9CS267xywlUXF4skJE
         KfXdb/a0pSuCYO8rMJ33DjFUypu2OOlJ/MZkV9Vxcq6KDqcOkRozM/94fNDj/Iwe8eYl
         npDT/HFxlLWX2c/XBh864Vbf0o03UFDn6ZcLWFvloqY9ypLpWsnEuaE2mPNieXLmNAnP
         ddiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=lwqEGphQg9/N4AE+qTFRbf/COwqV90p8RxwOJfRaDvM=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=bImikq/0zLJEXzI6sntSXWiACv0NbjtcGaF5b3qRDzNytHnFEAcE1fyfksJcuDlgKS
         Zu4hOycoMoqUmxls0AQMEmVpU+X+jGeY71LA8gwnlyRu2uCgFqVhorM1RXbosR6/Vu/9
         Byuz7h7RZyBQI9k5EyMRyMbi29nsSH3hK1/xMn8FZ6aL5IMkr0eiQ+uM+FPnmNmSE0Pz
         24cadKCnAxkAylw4TNgC4DRacGMfUAYCwjTkQ/yuzy5lKZaB1xotkh4zy1QkVTbMIAk1
         OPC/Cbp5GqUgB0uwP0qDiF055bORf++dpB7pJSJqfmaHWAFz5oREB14Fud7+/QJjwrvh
         vsfA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=jtW3aDdN;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-705ccbb1c94si564889b3a.5.2024.06.19.08.45.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jun 2024 08:45:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353728.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45JFQjas016559;
	Wed, 19 Jun 2024 15:45:51 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv0p9gaun-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:51 +0000 (GMT)
Received: from m0353728.ppops.net (m0353728.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45JFjoqC015829;
	Wed, 19 Jun 2024 15:45:50 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv0p9gaue-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:50 +0000 (GMT)
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45JEp9OQ009921;
	Wed, 19 Jun 2024 15:45:49 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3ysqgmwmnn-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:49 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45JFjh4B47972654
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 19 Jun 2024 15:45:45 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 95B372004F;
	Wed, 19 Jun 2024 15:45:43 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 485C220063;
	Wed, 19 Jun 2024 15:45:43 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 19 Jun 2024 15:45:43 +0000 (GMT)
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
Subject: [PATCH v5 28/37] s390/ftrace: Unpoison ftrace_regs in kprobe_ftrace_handler()
Date: Wed, 19 Jun 2024 17:44:03 +0200
Message-ID: <20240619154530.163232-29-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240619154530.163232-1-iii@linux.ibm.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: 0DTAl8VJlmawXOc24fByYYgj3OqQ2QGR
X-Proofpoint-GUID: G1urgv0MUEMJWZnGw1LubSq_jdy_Ex4g
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-19_02,2024-06-19_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0
 mlxlogscore=996 clxscore=1015 mlxscore=0 spamscore=0 malwarescore=0
 adultscore=0 priorityscore=1501 lowpriorityscore=0 phishscore=0
 suspectscore=0 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406190115
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=jtW3aDdN;       spf=pass (google.com:
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240619154530.163232-29-iii%40linux.ibm.com.
