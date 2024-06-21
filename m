Return-Path: <kasan-dev+bncBCM3H26GVIOBBYER2OZQMGQEDANV7WY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4EAA3911768
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:27:13 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-44055f6d991sf44272011cf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 17:27:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718929632; cv=pass;
        d=google.com; s=arc-20160816;
        b=B1EoqseVUVyiu8Q+gByiQw4+S4Uo4dIJrDzaNt3nwGvOULSp9E3tgbxeWR/E8jZcTQ
         rxcSsLcEUpfbBE3L+mDIlmSm1++Gybzaa15Qf8WzHR+dPHo5nzSWuUpwh/vRbkaW2xoq
         esqjoNRXDnL/9PqBeqvYCwRSzSa7+RUVkDRfiRWeTWBNJUBu5NA1tU0NQ1QAFUdEUZc6
         rzgPmo4LTJmXjmfQltwnZIQQRuWonzF0UXmHwxUENQhCofLIQZPYaEMGgNqm/weolbyL
         71qOCpuM1GQAWd39oAeajurSXIsZB6+7HiwkrhrSQlPMyghfV7+r84k6fzBjGqVEKaje
         0OOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=pn2l9H+sZz61CiBC7+3ZZkPrvwZbhLUDgpug1ltzCxA=;
        fh=x8Q8IzaVE2yOFO61StKuTasAuI70c1Bm4NwvxAmrhyM=;
        b=IwYQQTwCNUt8UDctCdaq8J7RA8h8CkaScdXuPK3ZGMms4ASapA5pNCsCn3v4GG0B5D
         XoBgdkYwiDLYgSKegQ3ZPcj7YfOBHCkEpullpeefotR296tToc6/NWXGECKL3CjI8AkD
         fdckCcakSric2D4iPG+CAcgxdOczXpabHvS4iFin2q1a9UrYpE/ldTk4c4RQ7wkmyj3O
         08RZ1l4BbBf57CEmRhvd5XcWvaOzKKUTAVZtHZ7FqtDZmCJN1LgqML9cKKDGKKIh9YhX
         JDJ8iodo/ScAnuRL9/PefteTbRjUHhRrbHVm5nlUjzIub0esHk8YwwZXuptToem1l8op
         DLeA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=MWkVIQH2;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718929632; x=1719534432; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pn2l9H+sZz61CiBC7+3ZZkPrvwZbhLUDgpug1ltzCxA=;
        b=t8ZH37Q+zIBGbKZs8UEgrFSA0NJzP7bZ7dAxDmhmBH6RfIF9ULjajGrwfbuYKrAjxu
         cVb+GUOkLn1C6tIRgdCbFnuIYcs9weS0EEruBJJgss08oP4XrvTenUN2i8NgIxIFrM0C
         mnxM/nQEF1HQVrPJxkIhGz8Ki0dM3VFQIgn+8qI57aQxYXPfNQc+U9WwwS2QBzHtPCmF
         dCQAA48HZQvX0IN1wKsoYMO8F7Oc0e6ImAwHuw4Q1UCSqnLdEmKuHXhv1iwcGsuqPiLT
         oOgU5fDi4I2ZN5IRnJrFQj4E6fD7ejXDDzOtZJfrCBT9qh9+as1n+sfoVYtRKTGJJiOX
         wH2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718929632; x=1719534432;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pn2l9H+sZz61CiBC7+3ZZkPrvwZbhLUDgpug1ltzCxA=;
        b=xR/SGsAP9IIUyYhIbd/xURqA9hdb341eTP7G4mXbUQWzHxJZSmgmB0+V7f0q3cf4V+
         opR8yv1YDsA9OQcsMy1JA1ULH2uC9W/1avR9JHYoi+6xW/du41NkXZ2sA4bbYBIRPYn4
         Xgc60ceVX2AoGaWOv0Xgqd3T+VF6CVhO1LMuPmJn5DlX70QTj+M7CJi4ix7kc96b7Zjo
         h4ROxDdREkqjazIkrNPBz6QdiISSSUM8SKINmWjVYtxh7H83LSmjUM6Md7rSWsRQ7gES
         l2Hw0tNDbY0I35cjB2jeyLbiX+rx87Ff4OYOWhbASMnegm6Pdlg6ED8QmlGMcnCOy1wX
         ExaQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUrVfPXBKPtpP/tMp9kaN/gWtddhWaP0I5RlVdF23fHJDNFkMYrLUUeVFz8O3YvvOmWhWMQHaJyJgaMU6lQC7b0iwCcQKmiBA==
X-Gm-Message-State: AOJu0YwOh3cjVgZq5z4eWKFwb6HN/amN3OCruerRkCg+h0Tnugqpv72X
	mqbhsGI/Cdf29yTzbUQSIaF+mhpRgVYg2dm63+XtvToLZlmrpW+Q
X-Google-Smtp-Source: AGHT+IFwNQGsBH2lNTWBtM0YHjjPEYoBmu4wAdDOQssxY9kv7E2DwQSIxslLAUb5ocvkscyQPFxedg==
X-Received: by 2002:a05:622a:34d:b0:444:9d20:ada with SMTP id d75a77b69052e-444a7886519mr122102541cf.17.1718929632309;
        Thu, 20 Jun 2024 17:27:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4612:0:b0:444:b66a:9fbb with SMTP id d75a77b69052e-444b66aaee1ls21835491cf.1.-pod-prod-00-us;
 Thu, 20 Jun 2024 17:27:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX2vEMa9xjWgOmO8Axl13/ltP/XWBj6KIQrJgmySQn27BdJ1ujyOvb2UJ6jntLbdafuFXb4BAbJv6m46W7zESdzgig4pquzP4x2aw==
X-Received: by 2002:a05:620a:29d6:b0:79b:bcee:d627 with SMTP id af79cd13be357-79bbceedc16mr837743385a.35.1718929631697;
        Thu, 20 Jun 2024 17:27:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718929631; cv=none;
        d=google.com; s=arc-20160816;
        b=Eps6geFceGUZc7AbhQxh1UxudPSphTocf8Fwl30izv0vMMCZ7/HTUQwjiPoSnZgk2f
         wGWNWtKfHp+ghDZO5tpGee0hBkuf/TFtevBMzO7XuI8DCif9J6koCWGLrGt/9StO03zW
         8+yxOk0r6Jk4EZ/+M/lVuByJB3y0uUWUUOJ+5ZKMca0TUqJGSM43T6q/BY10CWM3s5bd
         7A3kEDP5MQC6vMew57ZZSY9eZhTayj74gtGNh0UrV6TG8MYPOI/qioAY+MA1760gGp39
         uqvZ+Jes0K92tl8jmGk3IR714UUECr4P9urmIywEMbvkxUnNJjNPpGgZ3FCBC+pVtElf
         JfiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=aLe/3XBqno9Ykh6K8Gazkn5dKq5eSwzJESHfR5NZsd4=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=wN7XS4k5j+DHrUh+xht6Gfm8KigHOYoMa/wobmbUs0e0SncA1u9xmnaxRcjpdZE0QV
         hs0jCazTvJ5jTmVcQTLLqBCeKYBapx7sFR5Hg0vEzkYfO6bqtOKAXGUYpyvZ1RcY3Nl0
         uejHL9QEYPS/k8Hsb/vHxY0DGvVt09mjzKhGWxYTeqicY5xL4IpJY2o/0u30ovJRVAkI
         esdK83zMmt/XGrOwvToNP37E4NxXUKuCHoqjx14skCIfK9luLohn5+t7+VnUH9/ttUN7
         bVEopUgFqk+tX7BTw+dWBsN9jKHMHaqfy+u4XgFsGo+KrtgHRmga+mQDZnAGNvBX6vq9
         8kVA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=MWkVIQH2;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-79bce9007c0si2131585a.3.2024.06.20.17.27.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 17:27:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353724.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45L0QaZD022608;
	Fri, 21 Jun 2024 00:27:09 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvvs6g7t4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:27:08 +0000 (GMT)
Received: from m0353724.ppops.net (m0353724.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45L0R8VX023623;
	Fri, 21 Jun 2024 00:27:08 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvvs6g7t1-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:27:08 +0000 (GMT)
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L0HtwA007678;
	Fri, 21 Jun 2024 00:27:07 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrspamrt-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:27:07 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45L0R1BZ33817222
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 00:27:03 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 9540920043;
	Fri, 21 Jun 2024 00:27:01 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 741B12004F;
	Fri, 21 Jun 2024 00:27:00 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.44])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 00:27:00 +0000 (GMT)
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
Subject: [PATCH v6 34/39] s390/traps: Unpoison the kernel_stack_overflow()'s pt_regs
Date: Fri, 21 Jun 2024 02:25:08 +0200
Message-ID: <20240621002616.40684-35-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621002616.40684-1-iii@linux.ibm.com>
References: <20240621002616.40684-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: 7HiQQA-69o5o_-MXrm4M6CglmF_uNImL
X-Proofpoint-GUID: LT6lWUDGUXbUSf9OnEOs0dcsJ-g8S7zu
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
 header.i=@ibm.com header.s=pp1 header.b=MWkVIQH2;       spf=pass (google.com:
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

This is normally done by the generic entry code, but the
kernel_stack_overflow() flow bypasses it.

Reviewed-by: Alexander Potapenko <glider@google.com>
Acked-by: Heiko Carstens <hca@linux.ibm.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/kernel/traps.c | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/arch/s390/kernel/traps.c b/arch/s390/kernel/traps.c
index 52578b5cecbd..dde69d2a64f0 100644
--- a/arch/s390/kernel/traps.c
+++ b/arch/s390/kernel/traps.c
@@ -27,6 +27,7 @@
 #include <linux/uaccess.h>
 #include <linux/cpu.h>
 #include <linux/entry-common.h>
+#include <linux/kmsan.h>
 #include <asm/asm-extable.h>
 #include <asm/vtime.h>
 #include <asm/fpu.h>
@@ -262,6 +263,11 @@ static void monitor_event_exception(struct pt_regs *regs)
 
 void kernel_stack_overflow(struct pt_regs *regs)
 {
+	/*
+	 * Normally regs are unpoisoned by the generic entry code, but
+	 * kernel_stack_overflow() is a rare case that is called bypassing it.
+	 */
+	kmsan_unpoison_entry_regs(regs);
 	bust_spinlocks(1);
 	printk("Kernel stack overflow.\n");
 	show_regs(regs);
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621002616.40684-35-iii%40linux.ibm.com.
