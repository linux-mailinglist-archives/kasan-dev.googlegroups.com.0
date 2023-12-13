Return-Path: <kasan-dev+bncBCM3H26GVIOBBGUA5GVQMGQEYPP3KEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 16E33812307
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 00:37:00 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-35e6f4e17b6sf61668975ab.0
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 15:37:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702510619; cv=pass;
        d=google.com; s=arc-20160816;
        b=MDQwjb/YjMJ6QROSlz3mh5rkZ+eH6SQE5RTYzoFr8UKcTD6iOFVqzAA8wiHzcwa9Fh
         jbEn6tUlJGd7GNhTOh3FEX0+9RDeAlwhtkC+ePisU6pEe4J9SJovx7aG5441JyB/+FRb
         T+L4Ts7FFG1cFTkI+u3V9Fish5HR4Uh6Fkgn69XTXgOfex2tHUqFB6Gt38exZThcKntA
         eGEmJjNFaMgLf8hGUwscYM5gvoZTs/+iWvn7zC9338JBZowM3jbnd4SSiCaUiihHDdqN
         Fq6VxLhnnFfsJnHNgiRq4jK2TiQhUe9i9wiImUiEg40vQGW/D5sFg/UM19xxCav5edSZ
         fmbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ZYENmW4TLm1+EhJIEpdLeN5dzz97cbd3Qvmi4bGF23Y=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=Io/4iueCAB6ayLxiut12UvO+z5X3gTb3Ur2lnSHh1rBPLuEEvHd7v5hnsClsZyrKZA
         qQlq8kBqS9cSbHVi5hoXs3VeJgxCHfFwWFgKQ7wlEa9vItenH2thR4BaSnCaU86q110o
         aZ/fKgPb46P4Z2ziTPCoGa2XJ+W4bsrQ2LiCShB8w+gbkB3ToADtrqpAQxrvtZz4ec1s
         vYO1YqJAllCV9oxMbUhGUib3I3ofFSe3h0sGn/CMRvYUrwcHSYz9UdJUbp8dO+PxuajF
         gp6HP898+6KajrjNrCYw6Kani/TE9QboL4QJCyDvKb6nObqEFEf0CSnRki//zCiQFBXB
         051w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=UQvBPDce;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702510619; x=1703115419; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZYENmW4TLm1+EhJIEpdLeN5dzz97cbd3Qvmi4bGF23Y=;
        b=FdW6e8Bhg3vXlS/MC3IJaaFdaLASgLvPO13NOnMHWOzgnkZzSH0+zLiAXuUloINql0
         3r6iVTUK14yj9798v4YPhNN+XoMyc5r8Z3vw7pwCUVSSdLZNpelHDpPH9u6D77x7KlEZ
         Tjg+rcTbv0tkGOqVBVsixvJJ64/IGhuTOkppnDxpSbetd0K7EzNlW5j7YAKmK9BY7h71
         ZL2e2d4amaYjSNWbB3N4qpsv9+f6ZiLXrf55e1xeMNlAHWf82mSJ9LqHfXUmKYUAFJ5e
         1d41XstAXK+s0F45uKYSSqG0yVwgc2FFug63GQ6qgbPnd22q32VEDCLy0GtEV3TPvM32
         OGJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702510619; x=1703115419;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ZYENmW4TLm1+EhJIEpdLeN5dzz97cbd3Qvmi4bGF23Y=;
        b=H+Jh2UdEsXOnNI40XtgD7pAhaPZAXbqvYiiPz912bIy9bXIkI7edEKbjPrWeJBpLRv
         Iew0Hw0yIvmUdyfoJ0D0o8tuZkHX7FersE0v4ZoIWEpFw8Tdrm6CnRseD02ZeWwqGPyw
         yJGIDdDE7BXMaG0e9ff+yFusnfBurno+r1cHPd/eWb+Cg+5buFIGVLqEW0AfQbrl/n+D
         F1Blv1+GlistEMVoua0jJvpMjhVu9fMXqKis26iVioMxQuYY6TZB2oRi6E/hJ6wy6+g1
         5YMMjtgVCUwBSV1NfpIqnPBwyvSReSb76pqoWKafRxNK3LAX1yiLq+Rvv0YkVhBF2H5c
         pLMQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzzMWr29HBL3Az5iUh6Dt3Pn2hXH3gKyQpjq1vUfAQuGSXMKuPm
	W3dH1Bucz7noAWqfXnC8lPg=
X-Google-Smtp-Source: AGHT+IEMIjoUSHDpSEWLbVhZ/3U5lR+Q7UGOKOPaW7AQmbNxvZZG7S0RNQZ4M1HVA2AZ64VzTohRGw==
X-Received: by 2002:a05:6e02:1a6b:b0:35d:176f:ffe3 with SMTP id w11-20020a056e021a6b00b0035d176fffe3mr11549355ilv.24.1702510618905;
        Wed, 13 Dec 2023 15:36:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:6c4:b0:357:3d9d:209e with SMTP id
 p4-20020a056e0206c400b003573d9d209els1645645ils.2.-pod-prod-06-us; Wed, 13
 Dec 2023 15:36:58 -0800 (PST)
X-Received: by 2002:a92:ca0c:0:b0:35d:a6af:5fc7 with SMTP id j12-20020a92ca0c000000b0035da6af5fc7mr12438853ils.53.1702510618038;
        Wed, 13 Dec 2023 15:36:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702510618; cv=none;
        d=google.com; s=arc-20160816;
        b=V3Bva2Zpvurdptyg1Pp3gaLmoKvr4j9nmpFyhWjBQ/C6ycQcay+bdqECHGNwJXyNuH
         UtFjDLnaCVb7wHyG22cdGZkdsDC5g1w+uUOad0CnkaPWTfSj1qWa2/jfmo6spXFb7oBE
         ssZOsVxtaU2GvgUA/pz89rWnnXH13tu0ak1vi6Ljzyran0KL4rTS16+La/YFrj/Vg++f
         Lbe6sOh9jtO4uADarlVv1UEA5qduu74JBQvdrpqUscDzan+eScGZ5cginLM0yjO8FBeR
         RAqWzExIVFUsEHT2OBOujRD3yy6FrlewUOnZvtWWmkhuuDUyqsZInprkzLRQG47C8rmH
         Vp/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=yXd/QnBGUJdt/j+AbcYrFLYUstfppznpbRVZrbXz5bE=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=FPnT8pwjSCe9UTAbFpwR2u57Qt3blG3/U2+vJlN5oI2GnvcS2QIt3V8Mq7h45xfHBF
         vkMC8jy7jHK0vUT4kPORYz46KAVEQK+gqXKXTtOdVwdKe0IDvmd0HH41UqSMLAWWnMF+
         nmaZCInzvo+irrDaBNlRRx6pCbEzs3ZR25xirg5cg9FgYt2Z9FfwZIqhuLCQbVbuQKpB
         9OPT1XcLtGoFufubNO7jFZmjuLav0WV1KzxKAOp09mMF3IZJFRVaLIQwZ6mfn4ai8lk/
         cZTMXjcFP/z/DxqpDWQaovkq8SSiGhJNqH6dmwPXLqaDpQPbMQkY4dGKMJ+zffMgwAYm
         qhjg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=UQvBPDce;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id m20-20020a056638409400b00466cb35d175si1024727jam.2.2023.12.13.15.36.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 15:36:58 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0360072.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDNHdSQ002591;
	Wed, 13 Dec 2023 23:36:55 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyp5cgb9n-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:55 +0000
Received: from m0360072.ppops.net (m0360072.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BDNKIc6008783;
	Wed, 13 Dec 2023 23:36:54 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyp5cgb9b-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:54 +0000
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDM1JcH012599;
	Wed, 13 Dec 2023 23:36:53 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uw3jp4nat-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:53 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BDNaoQW3801838
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 13 Dec 2023 23:36:50 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 369B720040;
	Wed, 13 Dec 2023 23:36:50 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id C2CFF20043;
	Wed, 13 Dec 2023 23:36:48 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.171.70.156])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 13 Dec 2023 23:36:48 +0000 (GMT)
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
Subject: [PATCH v3 26/34] s390/ftrace: Unpoison ftrace_regs in kprobe_ftrace_handler()
Date: Thu, 14 Dec 2023 00:24:46 +0100
Message-ID: <20231213233605.661251-27-iii@linux.ibm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20231213233605.661251-1-iii@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: ACOAldVmTa-efSmw5zkfDa-w6Y17kTOe
X-Proofpoint-GUID: 5ND1Qb23N4iVSC6c3VM8EXMJso6wjXqM
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-13_14,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0 mlxscore=0
 spamscore=0 malwarescore=0 mlxlogscore=990 bulkscore=0 suspectscore=0
 phishscore=0 priorityscore=1501 adultscore=0 lowpriorityscore=0
 clxscore=1015 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2312130167
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=UQvBPDce;       spf=pass (google.com:
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
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/kernel/ftrace.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/arch/s390/kernel/ftrace.c b/arch/s390/kernel/ftrace.c
index c46381ea04ec..3cc5e6d011a9 100644
--- a/arch/s390/kernel/ftrace.c
+++ b/arch/s390/kernel/ftrace.c
@@ -13,6 +13,7 @@
 #include <linux/ftrace.h>
 #include <linux/kernel.h>
 #include <linux/types.h>
+#include <linux/kmsan-checks.h>
 #include <linux/kprobes.h>
 #include <trace/syscall.h>
 #include <asm/asm-offsets.h>
@@ -300,6 +301,7 @@ void kprobe_ftrace_handler(unsigned long ip, unsigned long parent_ip,
 	if (bit < 0)
 		return;
 
+	kmsan_unpoison_memory(fregs, sizeof(*fregs));
 	regs = ftrace_get_regs(fregs);
 	p = get_kprobe((kprobe_opcode_t *)ip);
 	if (!regs || unlikely(!p) || kprobe_disabled(p))
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231213233605.661251-27-iii%40linux.ibm.com.
