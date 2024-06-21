Return-Path: <kasan-dev+bncBCM3H26GVIOBB4WL2WZQMGQETMHF2CI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 30DBE9123C3
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 13:37:24 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-3762a1c1860sf155595ab.1
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 04:37:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718969843; cv=pass;
        d=google.com; s=arc-20160816;
        b=cv6dsRl8b5Vhd3du483IUJlZJdd+O8lPMy6uuvjzJX10Vx71llIVtZLDS0yOe6U4Hn
         231yLngO1j8lNifJ2BygoDiXgHvGXEdAW0Y5xgOgw9OwhC3TlpLtdyMuY62Izrzd4s+J
         pqoQVpFl8W0jcTU59GfgGK4i6yqgvaDNeg00dG0xeoZtXnBX6CSnFI2pcdkGAiAhx+f8
         LQMla+ymXxb8fbhu3PAIo7MkITN2ecVApSq3XtSGCY4vPQBWwPmOxw3ufvKQjXxhG6PB
         AHD8VguReDLe3FMy3LZhcYHIQh/H94nqGFKIwKzxgxgE+kIBG7qfOjg7GT3X/nvAcC1O
         eh5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=RF3OJbCBAoZUdH7at07vF9x92vwAECqd0/6w4pK7EfI=;
        fh=B62Kpe2pAySFDApK8lPP8eWq1xUwjN7FsqtQS0+0Zfg=;
        b=OGP1qc/dlII9FSW8fKAbYHYsox/+2JlIcS8QEfnKWGa6yBDm9FeRhD5H7JxF2y9Tah
         uSFy3su7To4+nhCWYNsOqaPG0hMoxB2GVASyajd7hD3+62O/6dNgx0+1ZICCA+3Y45VF
         0LEWvWhY7lzq6jNyOnfu+6iuGXSTbQ3FfZmygXXg8o/EQo7ei3d92swCN0YLiXWvCPzd
         VVq6eEWMc4xUJ0LVGLgPVk5nTUBaxR/mNklcimvNY4HRlRaWXCmiWKxfwGO8SRwcPVcU
         dIcoBUtFNKCYX8a4S3KWMLungBWGIP0CCOyImPq7jJpHTqMoMczpextBREQ3XHXUUSo+
         Hkog==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=ViPKdPPC;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718969843; x=1719574643; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RF3OJbCBAoZUdH7at07vF9x92vwAECqd0/6w4pK7EfI=;
        b=uW67xZf/7nkQ6ZhdkNmtPwOHJWhAidRR3yhYLbaijYfLChGjsOICV8pIQxTxawbTN3
         E6xc7xRwrJi+sOjJsgF0M28/LmAJRs4u+RynnIh3lbErJuZcmmsFGJeXUd4Pnl0evgB7
         f5EEtc+uigCxWWqPCXpE9mRYmBcGTKkhZdpapdBrfMcoceZo2ggYnxACOPAXmRcPibZ7
         /4T8h6ZEf23rKUNkYdL8CdZZx/I9s+w51tuKdyMK5W3ViTHPZ7pnlda3SF9vDBgfZJPP
         z0zOMChHyy4c3/nwBBDOnDNi83OqINk3xPKQHDpm86mNgiAugsWXRum8vj0ObyGdZ1+g
         qXrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718969843; x=1719574643;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=RF3OJbCBAoZUdH7at07vF9x92vwAECqd0/6w4pK7EfI=;
        b=aoqbuEM7EUCIAMKptHewK3zcWiyh6SigSBIX3+WnK71sHzcH3pogY5taH8TXsauEF6
         KkTF6WtfdCu4UctZVbIqyTUyTUo6h4peIPZ4tyFyFIWbV91+l7J/HPbDB4U3OXO5AWke
         Ts4D5OkWdbAHupmKXC5fId+Vz48LlM0iYCWsymx0F80KmMwavda962T/kvPl+pLTOMlr
         mWi5t9Y1QsD3Nt1RaKe52R54R6HxzDs0P6V3+11bi7w3dgRITJnuNPF05VtFuJWpi0Zk
         NeCyra3t3ExNXQ00jV89NBSFC6yeYHPvRuMLgy6GT0MNCIOmplQyv7vBAYYo9NJ5/DmN
         chaQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU8QAova+97y0nR8GZWmKKRsVNTXCpBKGANPHy8EDOdLpU/TlyH9PUTQvWLwRKzIOCGNQfPubM4XMgyKi3bG4ZhMRk7XgbWSg==
X-Gm-Message-State: AOJu0YxO0f1pFZ16nOq0AQaOo04pa784DnciNcOOD79cAXGUV8I85dxA
	eU83DL+A3bXbaY2OUoNSrM233vIlaOth+rCW2g/Du+zwik4CT/zF
X-Google-Smtp-Source: AGHT+IFYNwUf4Tb8So60lcx7xhxE0zZLfLIeFSUElgAv9AlFAJmxSQbfuIPyDZe1NwwjVtQMDLjtFQ==
X-Received: by 2002:a92:da43:0:b0:376:2f51:34d4 with SMTP id e9e14a558f8ab-3762f5134fbmr1805615ab.9.1718969842890;
        Fri, 21 Jun 2024 04:37:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1a03:b0:375:ae19:e63e with SMTP id
 e9e14a558f8ab-37626b1e54dls16030595ab.1.-pod-prod-06-us; Fri, 21 Jun 2024
 04:37:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVv/0UgEIUYf6TF5qmtRHMdROjMR5MS0SLf4sHU7oOfiGt2jR5HQDTt+5l+yJsAuEtpaW0ihWn4yH5pCYFyflAakjus9Xhqme0lgQ==
X-Received: by 2002:a05:6602:15c3:b0:7ec:cf:1d3 with SMTP id ca18e2360f4ac-7f13ee8af04mr913231139f.19.1718969842100;
        Fri, 21 Jun 2024 04:37:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718969842; cv=none;
        d=google.com; s=arc-20160816;
        b=yWuXJyJy/hQdwUBEI/wxwlwHLffP/DGC2xulcSmk3arHTSAhg+tEJxPsI2UCl6GRcf
         BpfQ8yMES0C1m/ZtcrT1xZLMsyvAN4rOk36gSiet0JAmTxuHHp5eRhWnAJBNgHD/eq0E
         Ea00QWAZ7zWirEDO+pc/wgPwKaj/vGNBGTI+MYHLMTlx96A+vJv3F2oKgqdGAUeVmOyP
         PvWs3ryqCeG0ngPjzC0pJQ7Strk1ApwURwagunPSvxotDYR8fYXQww4cC7qhSknJImtQ
         Cs+QiTd20thbQZVdO5OJAcZ/0NrTuZhEabMAIWae2FdQg9dc8IkciWGLRU8cSRGzZYnP
         rYYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=kU/N+IjLjtGivjpGyVY04YO0GR9T1vNZaCjuWWP4qac=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=VvTPbYS2ca8Q9OvexmhkYqxSH2HlzkQ49yrnykijt7wMrJTxzPRwAJDRJyPZb55j5s
         mCuYB9d3ftKc8n6IHpjRzwm0tznhVKibNPzGXouZ8fcte8g93tYNPQCc+O+jcUrtDRHn
         RxIW9gwNhTAj13hQfY0M1my+ryc1IOCZULnIw9WISwrgxw73MsfPVSkJnxHbG+6hHbhi
         1laoOXPIP/C4R/r+Hpne1QBb4lhpLlbu0Il1QhMWJdPLpeE9MOELS7qJPTq687I8Fbmr
         vhavbVT7WZwysFADdpKYdsrVM4qgQIh0pdVZGAIIroGBNouZdPhLM1sqX46wQEnCo5Ue
         zSXg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=ViPKdPPC;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-7f391d4edfdsi4086039f.0.2024.06.21.04.37.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2024 04:37:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45LBSBUa019894;
	Fri, 21 Jun 2024 11:37:17 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw6ws09b4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:17 +0000 (GMT)
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45LBbGli001454;
	Fri, 21 Jun 2024 11:37:16 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw6ws09b0-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:16 +0000 (GMT)
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L9OhiN007658;
	Fri, 21 Jun 2024 11:37:15 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrspeupb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:15 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45LBb97g13500744
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 11:37:11 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id B19292004E;
	Fri, 21 Jun 2024 11:37:09 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 25F712004D;
	Fri, 21 Jun 2024 11:37:09 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 11:37:09 +0000 (GMT)
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
Subject: [PATCH v7 01/38] ftrace: Unpoison ftrace_regs in ftrace_ops_list_func()
Date: Fri, 21 Jun 2024 13:34:45 +0200
Message-ID: <20240621113706.315500-2-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621113706.315500-1-iii@linux.ibm.com>
References: <20240621113706.315500-1-iii@linux.ibm.com>
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: F1_JCUhnzC64Aj26DIom9R-aeHKzDwbZ
X-Proofpoint-GUID: ppnVlnvg0ssqFbVxEhp1S8OzAAw0DCcb
X-Proofpoint-UnRewURL: 0 URL was un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-21_04,2024-06-21_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 clxscore=1015 suspectscore=0 malwarescore=0 spamscore=0 phishscore=0
 priorityscore=1501 adultscore=0 mlxlogscore=999 impostorscore=0 mlxscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210084
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=ViPKdPPC;       spf=pass (google.com:
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

Architectures use assembly code to initialize ftrace_regs and call
ftrace_ops_list_func(). Therefore, from the KMSAN's point of view,
ftrace_regs is poisoned on ftrace_ops_list_func entry(). This causes
KMSAN warnings when running the ftrace testsuite.

Fix by trusting the architecture-specific assembly code and always
unpoisoning ftrace_regs in ftrace_ops_list_func.

The issue was not encountered on x86_64 so far only by accident:
assembly-allocated ftrace_regs was overlapping a stale partially
unpoisoned stack frame. Poisoning stack frames before returns [1]
makes the issue appear on x86_64 as well.

[1] https://github.com/iii-i/llvm-project/commits/msan-poison-allocas-before-returning-2024-06-12/

Reviewed-by: Alexander Potapenko <glider@google.com>
Acked-by: Steven Rostedt (Google) <rostedt@goodmis.org>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 kernel/trace/ftrace.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/kernel/trace/ftrace.c b/kernel/trace/ftrace.c
index 65208d3b5ed9..c35ad4362d71 100644
--- a/kernel/trace/ftrace.c
+++ b/kernel/trace/ftrace.c
@@ -7407,6 +7407,7 @@ __ftrace_ops_list_func(unsigned long ip, unsigned long parent_ip,
 void arch_ftrace_ops_list_func(unsigned long ip, unsigned long parent_ip,
 			       struct ftrace_ops *op, struct ftrace_regs *fregs)
 {
+	kmsan_unpoison_memory(fregs, sizeof(*fregs));
 	__ftrace_ops_list_func(ip, parent_ip, NULL, fregs);
 }
 #else
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621113706.315500-2-iii%40linux.ibm.com.
