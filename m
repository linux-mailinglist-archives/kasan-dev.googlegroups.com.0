Return-Path: <kasan-dev+bncBCM3H26GVIOBBF6S6SVAMGQEZL2C37Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 814907F38AA
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 23:03:05 +0100 (CET)
Received: by mail-pf1-x43b.google.com with SMTP id d2e1a72fcca58-6c334d2fd40sf8698011b3a.2
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 14:03:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700604184; cv=pass;
        d=google.com; s=arc-20160816;
        b=C063OXMKIS82BN/HAPqTqXnrvRaL/jB5ZXkKKkF9jw0+w1XUyixondXH3lH4TzvfOr
         8XOuHW13bgg95SuolUTMvzQpmcl3OkSpsH6hlzWkm+3EluSKPedHv9Rw9XG9xWOwy0CZ
         pgzOVEe4T4LZ9iM+2YxrD+84BZxc03mFsLrJt2rlRFC7xHGZ5uY3yN7B7PRlTa+LlNVE
         BKezV0x06ra/Ji8D6Mgkhp8WTzOJHamMMTxUuHYRodSeqllYPHe+0lpHVnJlFDDyHz+t
         TK1oEKQ3WiM0G6265G4UPRbZov6LMhSJ6OIPkYj3o6YShZqUkmFJqPzqpz4z/6djrPID
         zkkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=p5OyW/Z6jHkxKmYacCNTpBWk2U0qdY+44EgvGF9vXC0=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=PwaXIsx/myQSwiAUESXV4EPbywsBeu6fEKFwpBMLJgtnnYSakFNQOBrumkMFodcBb9
         P4C3oMxWfoWpctHwbSCXMa9Sdx+wo+EZk+7puDceLZiw15vUKnZ3pDUN2/FFZiJKqncb
         4XxztoQdUrfAFzxl1d+Vv8UAqcGClyrE3pCPPilX7c07OPy7GOX+EL9ogCrhGrYKiSVa
         B+LOUKC444cOVNpvtnFa5nX7QcNx06tmcS213pIFtQ6TaiLkzGZ2zq0oTHIIsfEJotR3
         C5ZilgMoUUnYbuuAM5y2//mz1J5gMwl6zIpqx1CsQ/ZvUo3AApw5t7qPbq8lyw0ks95H
         fOBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=duZRETGL;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700604184; x=1701208984; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=p5OyW/Z6jHkxKmYacCNTpBWk2U0qdY+44EgvGF9vXC0=;
        b=OjlrO6oQfWn3RrNTkFcieRQ+B/1lO2e5/3xeH0lZrC6IICSs6qGFMsxkzXjaRryrlX
         M9G5ej308IUXbd4U9dY7e/WLwWmIzsyQLIvNofTlv1u62asUQ4xTKne/ckXrEpagd6xT
         SwEOhcDLEWX0woMei4BPctu5MMpZ4vujydngIszTjQQEel+1rLephkOhvq2IJapopeNn
         hHf3hDV8nW34Kdt635pqMcI2FVUODlK0IQp9eXOczxQ6FhtvD+Uddr8SwimDl8o9mWL0
         i+ExXw7K8tFWE4LSYbbuj+P5+kJo/ydWOzqfRMncTOcAfoTSg0sKfRio1Ho3Hi4P958t
         cB7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700604184; x=1701208984;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=p5OyW/Z6jHkxKmYacCNTpBWk2U0qdY+44EgvGF9vXC0=;
        b=LeboiRKnKK9wt9PAnmbLnh9AUu4NCQKFkXYJ3fweAQkT4vgDtPdqXvazw0M89r1cUA
         S6hirVX6uLi5eojxe3VVdfi8df5vRe/E+uALkyOL2SEOiWP4+aYqdGUI+xNv1OPgqp9M
         eUItbTlXdwHqB3gFXPgjlRQUbffUz0HSQbmd3tZVBG9jpkHAJry+sGX+nBMia1vQ8WRR
         uxsg0DgG3le9UGnB44CoC5KJZb7c3ecFHE4+rOA+8b6dG92q+CoL8kTWUNGaZwDpL9v0
         RYWYkGy6IRCF7US6Ldf2UxijVciyWv9hV6hLvPdsvH4IcXOMi/TrP51FChmHn94BQEuj
         7gag==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Ywkegwvis5p9CrAzLQFAJcW4D05QK0nUfJRr2PNJVlw+UPbPLRu
	fn/lLWg+oDguvvDkm4Q1yM1WMw==
X-Google-Smtp-Source: AGHT+IEeMlcipVt/jzkpdjmSKBnjDHJIJYHPMDyWs45bXWYVt5uhnprLMUugH4LheQ/B+mD6ciKU5Q==
X-Received: by 2002:a05:6a00:278c:b0:6cb:70cd:9dff with SMTP id bd12-20020a056a00278c00b006cb70cd9dffmr617261pfb.1.1700604183912;
        Tue, 21 Nov 2023 14:03:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:3995:b0:6cb:a754:aa46 with SMTP id
 fi21-20020a056a00399500b006cba754aa46ls2156900pfb.0.-pod-prod-06-us; Tue, 21
 Nov 2023 14:03:03 -0800 (PST)
X-Received: by 2002:a05:6a00:4c18:b0:6cb:913d:2cc6 with SMTP id ea24-20020a056a004c1800b006cb913d2cc6mr577619pfb.15.1700604182984;
        Tue, 21 Nov 2023 14:03:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700604182; cv=none;
        d=google.com; s=arc-20160816;
        b=xQX3qYskrawcXeWFzGEArQDWYvSKdzOX83ua6XHqCcWo7CmovcWIgHiA8jjNr8+IHh
         Wf5IRNU0XLcT0S1OfVBjNz0uQQkC64Ds/BbEQjDzwcDp56yC/9hNUKN45WfNcsCmHvv5
         3NyIjMzUyH4itXcNYNQlkuF5XFWwHQFRP43VGmPim9MdfRsgabeMIlwC1HH30VQ1yCuF
         7Y+tTrfHLcEfUJk46LrX8gu/0GIPkKVbOMNmI0CNdnavYHnFMp8lbE1LQV3+r/Y5in2G
         tqXE9o2o9mXnNh5LJ0C0s1/X2If9i9TRBlOzeLh7fiXPV3+SnZPs7sx+LDFfPOzWZZI8
         3Zzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=txn0Nm3A6Bd+5R+yqHglUeHWs3ZVMkuzDYQpRh6ALKY=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=FO6o0vFTXwT80zK0F9KxvrIwNjK4TXnXsKn9eVbpFtcoviK1BMidqBKXgq9MmFZQXa
         q/qA9s0znzEZiQv5ZkH/ejXX6J7UEsRaxJez/OwovCj79hV51CksD3jvDW4GLLCxgW2Z
         7w6zWpQFFgXn7PS0efPM++GlLWg9Gxs49UB5R8qRi3sNJZ09+ylkYhAti6qREG0D1RZ1
         fSM3QOI4KkTkGxULlx7YEaFreYfh1oioStVm1JQottxvRi3mrKO2bYz+jbboyEaDZQzF
         /u06uUvRla8sxW9jgEwBKV9H0QN8+edK6JGi0jL2kMO6LgY2uXXpTXQ3yLfX1+1NAJ1n
         cMPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=duZRETGL;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id u4-20020a056a00158400b006cb536b0182si407944pfk.2.2023.11.21.14.03.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Nov 2023 14:03:02 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0360083.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLv796004910;
	Tue, 21 Nov 2023 22:02:58 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4wn85mt-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:58 +0000
Received: from m0360083.ppops.net (m0360083.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3ALM0860014409;
	Tue, 21 Nov 2023 22:02:58 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4wn85m8-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:57 +0000
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLnSTI004681;
	Tue, 21 Nov 2023 22:02:56 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uf7yykvn1-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:56 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3ALM2rb425494200
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 21 Nov 2023 22:02:53 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 38F6120065;
	Tue, 21 Nov 2023 22:02:53 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id BE9342005A;
	Tue, 21 Nov 2023 22:02:51 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.23.98])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Tue, 21 Nov 2023 22:02:51 +0000 (GMT)
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
Subject: [PATCH v2 26/33] s390/ftrace: Unpoison ftrace_regs in kprobe_ftrace_handler()
Date: Tue, 21 Nov 2023 23:01:20 +0100
Message-ID: <20231121220155.1217090-27-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231121220155.1217090-1-iii@linux.ibm.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: hRlHsFXomo1J7uOPJXryhcrVlsiqr6QU
X-Proofpoint-ORIG-GUID: afImpyl8SVQiG6DdG8YIWn3o7Hsfu1zO
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-21_12,2023-11-21_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 priorityscore=1501 suspectscore=0 adultscore=0 malwarescore=0
 impostorscore=0 mlxscore=0 bulkscore=0 phishscore=0 clxscore=1015
 spamscore=0 mlxlogscore=999 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.12.0-2311060000 definitions=main-2311210172
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=duZRETGL;       spf=pass (google.com:
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

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/kernel/ftrace.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/s390/kernel/ftrace.c b/arch/s390/kernel/ftrace.c
index c46381ea04ec..3bad34eaa51e 100644
--- a/arch/s390/kernel/ftrace.c
+++ b/arch/s390/kernel/ftrace.c
@@ -300,6 +300,7 @@ void kprobe_ftrace_handler(unsigned long ip, unsigned long parent_ip,
 	if (bit < 0)
 		return;
 
+	kmsan_unpoison_memory(fregs, sizeof(*fregs));
 	regs = ftrace_get_regs(fregs);
 	p = get_kprobe((kprobe_opcode_t *)ip);
 	if (!regs || unlikely(!p) || kprobe_disabled(p))
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231121220155.1217090-27-iii%40linux.ibm.com.
