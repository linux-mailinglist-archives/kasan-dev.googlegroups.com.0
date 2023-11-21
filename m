Return-Path: <kasan-dev+bncBCM3H26GVIOBBZ6R6SVAMGQE2463FKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id E3FB07F3889
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 23:02:16 +0100 (CET)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-1f5acba887bsf6854056fac.3
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 14:02:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700604135; cv=pass;
        d=google.com; s=arc-20160816;
        b=EdyYY6DVySNwM7G2L+bhZOmQ3qgWtf4dSlT69VVuxYLZjGRgHvBkqqD/N8KEhgOx0s
         Ga+s1B1cA4sV8ZAQk/f1d3hy9Mrrg0BEa/Askt87oxl6Vz9E18hlyNWXdanxnSIA8TYZ
         u9tiWUC5rcvl1de+sPlZdJKU24iXMOMxBKXS3By7Tr4MvGBcO3D2IRW/YrFIKJ1TZ/QN
         iFUONqlhWxJNqLWud+oFppKLHjs9LpTtiBtrbrG77hWmSZrga+J9gTNdMk7trI06jI1+
         odsVlXJuUzor+3MYT0xvloe1UTxjhESjfYXq8l/b+87ZpgJRocsXaza8wZ43HIYFIO3z
         IIqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=m5KEkbyBJF+5ChICZSraNkmBXcGzkzqKQWK19elX2hg=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=lsjb5AKfD5gSQ86e77atTT7rKjdqRUILEIyy8ZJUU2aDXRpu+IViTdAocQLGdPT16p
         X4SWGieN4q/c25ILtp8nsMN6HFmIoEYCV/wgQndvi5D8hQ8DkLk3kTCdwQSzmYoy4X9G
         aS5kh+dTb6Ct2B2k9L4yfjtOfNQS8//MWfDvEw7zZ/9nX60hBuaJmdLUX64ptAoIgTmB
         73OhwWjbW8SeEDd8OS5MuXdJJQa5F82bW3OdOQ/Sv0RlZfHiJPq8ocJgm7V2Ho90trNx
         mqxHx2PtZt6gOLi8zx8yMeZ64m+BEHsimALG1Ea8DkYsi9FG0Ln8QApbiQIcZGJaCZLI
         TAGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=pYvkaxpd;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700604135; x=1701208935; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=m5KEkbyBJF+5ChICZSraNkmBXcGzkzqKQWK19elX2hg=;
        b=BAQMjJy1fCLMGT0KfVeh1D616M96INhH6itPkS/qqGYVBsOUUY+zrM4ouqU6vFbhkO
         wElTzZHsYFyDMzXUKGntlZZEB7n0I62dDynVh4ZBqCxf6mwq1SdJ/mwG6AHDy7k+EgyE
         7pkpoZeEc3jNJWr+iStEA0YhHWka1xutI7Zae4+7j/dY+JJmNmLBexd/Mjt1xP2CxwkU
         B5IKeG/tlKv8Qr0JD0mYT1prYAAAhQWOUb80f0q90uvL/Jg0n1MjzXdtue0XslLV48Xi
         5W0tDd5izJev2Ml/aBjKEsxpdSQfYXuHOQXsdJAj0e163oXy28D/z2yDE1Z0JfEDtRPR
         XbhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700604135; x=1701208935;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=m5KEkbyBJF+5ChICZSraNkmBXcGzkzqKQWK19elX2hg=;
        b=saBv7U3QxxFTpUSvqf33C7rHpJawiKcWWjAIHJYP747aPMU+NKp1xUQX5rdfa8BcdO
         /ZX15ryTmb25PCRPrJUonItYywb1QUxQmCOKSirO6Herd5x581r9lQp+xEvTbkZkd65D
         t1iRq3IVUoDvBGxkWwMxFSCbthRoELTqOuXl6Aj182qCgNjCEoGI7rQ/8GPiapXCCfF7
         epb73chXHlhXOogWBjgwvwXO8LTdraeDMhy4aK//4i7OYUwh1UkHsTwM9B1DkAROYYRU
         jcLsmJijFAB2lfuaEbjVn3JadLVwcligqPjMSXK9citUDJFFFiYCDZQnGmokjqyhWuyX
         hUnQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxlnFsYe+vv5HpM7EUJj8v9tSRqjruVcxxVyQ7Z53tAabpAaFAF
	G4nzNl8UH6MrfOkeYQ//yQDRaw==
X-Google-Smtp-Source: AGHT+IHuBCuxZuYu9AsMpLSwDjTcyQrOYnhvk0vkKJOQxq8eoTSWVwdasYSwlqwskcBsTcnLcD7+0w==
X-Received: by 2002:a05:6870:9120:b0:1f9:3b64:6596 with SMTP id o32-20020a056870912000b001f93b646596mr682619oae.50.1700604135530;
        Tue, 21 Nov 2023 14:02:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:79a7:b0:1f5:cdb7:ef69 with SMTP id
 pb39-20020a05687179a700b001f5cdb7ef69ls754503oac.1.-pod-prod-04-us; Tue, 21
 Nov 2023 14:02:15 -0800 (PST)
X-Received: by 2002:a05:6870:158f:b0:1f4:d516:2e2b with SMTP id j15-20020a056870158f00b001f4d5162e2bmr734848oab.16.1700604134890;
        Tue, 21 Nov 2023 14:02:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700604134; cv=none;
        d=google.com; s=arc-20160816;
        b=yX8JKFPkNdmRCSc5BqotFWWHkRnfwNM+P2+SerljsWGYbEdqs73eJafXPbHq2zBtP1
         UAF3CVMhUS/cx8em6Q94necxNoqMYjXQWHPFg73dR26+hse7zbPjfK8RB2OoeHitdwz/
         ucGeRlMe4WvfTMRJLANXbyTojHQCIF7aRvnxXuWALSFmPw8Iywyi6J/B1HFhJrHT4d3E
         p+D9jg/ZnSLb3Qu2/gsa1r64sPS/bL+throU6CRsu1rN+wyclr6BOrftPFjcmV+6Ncc9
         VMPRymOHO5oCtYxNHMuOc7hUgISNC3Ek+ipcNz+nxKIWQWTDgc6BZIKHnm70wnJATQRk
         Ee3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=CZLHkQEJKjMWj9tFsHKzWIaMVL7MbTldFAitesNVJzU=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=hxBIgGZGQbrn/8+sT+74UBXKvAJyoZ6Oc+4JIo5wpE97+43i4dY4GuZunGasCs2Iyq
         ym9YNFtNJDxGS9AuDACetqYtqiLBLlyr/LVp6gIg4hD4E7U2a4Z18LdO649cw5+EMoQf
         z6kzrp5f+DSLdeNvUJL8hiP9hP/J2IztBsMi77v0SuIElmaMb6uhmW/0Ty3xXOKxafdg
         p8Q2FiShSF0qHcEZvgVqd3EY6t/53YvxWv+kZ8WdS0e31mk7aopDUzBdmiuRXurCeZ52
         v75rYfv7u2uQKyqMNWsrRDLJF7iP0CC4VYT2iBcUySOUmLV4G0JauiT13xC900jnQKdr
         /9EA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=pYvkaxpd;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id qh2-20020a056870bf0200b001e9dab71a2dsi1214110oab.4.2023.11.21.14.02.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Nov 2023 14:02:14 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLge2H032055;
	Tue, 21 Nov 2023 22:02:10 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4pw8etj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:09 +0000
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3ALLtc00001991;
	Tue, 21 Nov 2023 22:02:09 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4pw8esw-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:08 +0000
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLnSiV004674;
	Tue, 21 Nov 2023 22:02:07 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uf7yykveh-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:07 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3ALM246R19333858
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 21 Nov 2023 22:02:04 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 3F4FA20063;
	Tue, 21 Nov 2023 22:02:04 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id C52042005A;
	Tue, 21 Nov 2023 22:02:02 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.23.98])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Tue, 21 Nov 2023 22:02:02 +0000 (GMT)
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
Subject: [PATCH v2 01/33] ftrace: Unpoison ftrace_regs in ftrace_ops_list_func()
Date: Tue, 21 Nov 2023 23:00:55 +0100
Message-ID: <20231121220155.1217090-2-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231121220155.1217090-1-iii@linux.ibm.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: OE_2HhR7p8laIqszHIpA8sx3KovHtydB
X-Proofpoint-ORIG-GUID: 5HzIgJAoLjwL41V8x1uA2rXIn0syQQXg
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-21_12,2023-11-21_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 spamscore=0 clxscore=1015
 impostorscore=0 mlxlogscore=999 phishscore=0 mlxscore=0 adultscore=0
 bulkscore=0 lowpriorityscore=0 priorityscore=1501 suspectscore=0
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311060000 definitions=main-2311210172
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=pYvkaxpd;       spf=pass (google.com:
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

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 kernel/trace/ftrace.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/kernel/trace/ftrace.c b/kernel/trace/ftrace.c
index 8de8bec5f366..dfb8b26966aa 100644
--- a/kernel/trace/ftrace.c
+++ b/kernel/trace/ftrace.c
@@ -7399,6 +7399,7 @@ __ftrace_ops_list_func(unsigned long ip, unsigned long parent_ip,
 void arch_ftrace_ops_list_func(unsigned long ip, unsigned long parent_ip,
 			       struct ftrace_ops *op, struct ftrace_regs *fregs)
 {
+	kmsan_unpoison_memory(fregs, sizeof(*fregs));
 	__ftrace_ops_list_func(ip, parent_ip, NULL, fregs);
 }
 #else
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231121220155.1217090-2-iii%40linux.ibm.com.
