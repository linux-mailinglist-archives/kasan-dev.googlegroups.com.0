Return-Path: <kasan-dev+bncBCM3H26GVIOBBAWM2WZQMGQETRI3EHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A3E39123DF
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 13:37:40 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id 98e67ed59e1d1-2c78c2b7f4bsf1998785a91.0
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 04:37:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718969858; cv=pass;
        d=google.com; s=arc-20160816;
        b=JYd4I+1SzEp30OBdyZtgkpA1WzeQB04h2r945ithCqrnWO9SvUhcVWZOnyZ736aoxX
         qTyQl69BuK57Fq6agQmr19UszlQgwf4ldT1LKptAW1wj2lBht+RgHXXk3zOJLeFSZkii
         3Sx4GqvJ+CXmakRzv2wnqBNmmF/+9Shqk03WtXx7k6uE7zoBJL3bAuoJMAVNuzS5ExyJ
         rfHPQkfZz0XjQKSkKHKS+PD6Akcz2cQEcFkC2zapb+xHq5hVgNpkoFm7G4XDkmvMqzgV
         hOh5tAcTDWmNb5LX3rwgBBfqlbFcj8Q2QuHA+6DWa8yZknV4mbD/sTnQqgFm2E/FUjen
         bBew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=YMfJHS/t8/jkITEsZw7iOsohf9DGG6NSrDVbZEcFEv4=;
        fh=TITIXoTYmKkqymfx0SlE/bUSAK0fQuMk4PFz1SAoYx0=;
        b=jE9U6IuCVaB/t4h9FDGR+B3kA+8m2Fk3GN4ZjFOmCUBd42V6KMuzVOKYbEVDKhafXJ
         cpmX5VNNIWey0N3Hf5NcHBhROpIRHy9Cn6xReH51NDiwfRRZUc80wTuO4GJdwdC0t4A0
         ZJXj65WnnBWDNg7FvMmYKJKNTbO9Cy6RwElo4QReTSP4TH9oe7RL887g+LJPfgxOVbgv
         RSTJj1+vHkcgO3N6Ux2WAjXTPFsjyhp/ajUwnFLpBDHIWPlALzUVgsbRvpTbhaY0UVaM
         fKfj98vQS+XYVmWFiBdCFaqG1S4uozIn6qyafWYaNO68LL3U9/AjsIW/l+a35eo41Osm
         LV7g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=XJ53Nf9a;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718969858; x=1719574658; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YMfJHS/t8/jkITEsZw7iOsohf9DGG6NSrDVbZEcFEv4=;
        b=rzDwdn4+wXYit/B+aqVm3PizRupxT6kBKwtwjQFHHvFQXQHyE7/WpVbN4SJFaCKiLa
         DkMhdeeSZ8zwYCuPxEyHJnx2F6q6MtRVXsbe74LJZPgGwnorhKJB2+4R8bwiDk8bt0Ls
         kVg8PbnSVotJ1PAZgtSfvQLlwWpgLu7dq9AKgGwW56qoE7ColApA1HhJTYaizf1h1iLA
         Ap1LzbtGG+T9w9ZCSg08yYjxG+AaY477XLD0zPqCxaDo5vCDmeueiMBvEUFsHIacK1ta
         t7N+dbUaF1tppQsk8jlDviFJy+dN3vI0/675dtI5Sp/HjZsrd1bpI790kigG6eUD3T1J
         RzkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718969858; x=1719574658;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YMfJHS/t8/jkITEsZw7iOsohf9DGG6NSrDVbZEcFEv4=;
        b=aOeEWAqAElv0LgX7yFn8eebauskuZQB5myiAH6PqA8IYXAFmZfDt0vgHEYtQo7hNJb
         W9wu1BkX4FMMjZPjQtDmDTwij+LmfsCq1MWGfbEnPZAjEFJlhab1hG3AdYFBii3I4I6n
         14hvzbGpWnaKy1NQqPRcnQ/5T+BSj+3PNcaU47/hnYc9YbaF3W3X6f1e5FsVbHYO2ViF
         /nzpWPkD4Nsvw9BtRObhC53AyWFKQBLQZdpHKYeBVhCn9zq4vCCXs1DDZ8TICfqooXgf
         He3/serWoAsvpdE9acAE4t7Mh4jzuXKVPO96ZI+nM2yU2KekQbbZ6AJ3qqGFn6hYJYrG
         HRTA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXAiN9hkChbkVhfNeoj5UWmELaVsfaw3U047/nmfHDIATxO1exqJtU9qQuZmsMTw5N8JTdDPbFXj6vDAuXBEvhpeAn2lKReWA==
X-Gm-Message-State: AOJu0YzrH5b3HMRLF3jIdD+RRreMAgKkA/c/v7Rd1TG/rVTG4jMJWyir
	DexHpO048n1hFcCwitwxC5/CgVfc8afsm5AmErPeh8snYAQsEKNd
X-Google-Smtp-Source: AGHT+IEEcxmmeErXjIlxdj4yOdsRZdVj825sYza0VIVfwAtMrm2YLPOA84kUFfzb0s5qYB/j3LjN/Q==
X-Received: by 2002:a17:90a:b38b:b0:2c4:e2cd:9216 with SMTP id 98e67ed59e1d1-2c7b5afb4ffmr8232976a91.16.1718969858689;
        Fri, 21 Jun 2024 04:37:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4c49:b0:2c6:ea3d:6fa2 with SMTP id
 98e67ed59e1d1-2c7dfbe9813ls1191077a91.0.-pod-prod-08-us; Fri, 21 Jun 2024
 04:37:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUaoJk7BDHTgjkrWvBn2RGi5RyvP1STfb3O9mZebHBlxGwdfgqjbgUlBa/VPkwjvd2IJCf9BCE/olI69yDXxAPwZrwuj1H5J+w2VQ==
X-Received: by 2002:a17:903:1248:b0:1f8:3c5d:9eb with SMTP id d9443c01a7336-1f9aa3b1488mr98093915ad.7.1718969857565;
        Fri, 21 Jun 2024 04:37:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718969857; cv=none;
        d=google.com; s=arc-20160816;
        b=BKimrkdQTj0MVvozxz/w1irHXfgMcDOczJIuAvkQAYGtO7HJ655jZTE1krhW6mzCVC
         +Ygf/HsRjtfmF/0L71PgguTWjg2ma5Ns0iHm7ww6QTW6hrwDS1893pMYskUFbguYOgUC
         85Q0ut4Tzn/mijytYJ34okzO4M4p4FCOJOAOV4rcJW7ej7ID7/fmc3Rf12sGdFN+Bl/0
         fWrlrupOp55mXWakuigev7HTTaMa1AjxhIAivOiKVZCnt7V+VG1+e4kgZsNSxRaqhpNs
         J4zXz13eDJ48Rwkqm0q1XTbf+g6mBAHZJmmsJUV8aJxNhgJaBKQy2Kh4fZ3LexyLN/6A
         28eA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=lwqEGphQg9/N4AE+qTFRbf/COwqV90p8RxwOJfRaDvM=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=e/Cawj89UpZFVVLxC4IE/YWbjnSotBLdtLx+Yv+R36EaFUWZHTWv3mOgBNzpNFQONu
         EB5sOrkxR6vp/bH/wE+Cy4IZVPzJQWwq1q+c0z5nOooPXAPVS9/9OVFX1npqtLs0ke2S
         NftrsINEf0xhMfBhgCpOTFRUXCM4ylBV4CGuw4ngEQcnF/8/WXz+GR/7tVCtr6mbjecf
         78pbD6gSpLvjCCdpyjMv77hNtMtxQzy+/IyMxXqbgBRKC5ki/gp7UmXY4KzDPIxrColc
         lrnSM+2FUWuVmSInFJyz+g0oDdgl1na8g79U/yty7amHGFHFdsG/sWkMZjqcRf/cyTNl
         BjlA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=XJ53Nf9a;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1f9ec81a333si504015ad.10.2024.06.21.04.37.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2024 04:37:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0360072.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45LB34ZA015263;
	Fri, 21 Jun 2024 11:37:34 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw6wtrb1t-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:34 +0000 (GMT)
Received: from m0360072.ppops.net (m0360072.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45LBbXjl003837;
	Fri, 21 Jun 2024 11:37:33 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw6wtrb1p-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:33 +0000 (GMT)
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L9CeSe007669;
	Fri, 21 Jun 2024 11:37:32 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrspeuqb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:32 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45LBbQAh48628136
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 11:37:29 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id D7A9D20043;
	Fri, 21 Jun 2024 11:37:26 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 4E3DD2005A;
	Fri, 21 Jun 2024 11:37:26 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 11:37:26 +0000 (GMT)
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
Subject: [PATCH v7 29/38] s390/ftrace: Unpoison ftrace_regs in kprobe_ftrace_handler()
Date: Fri, 21 Jun 2024 13:35:13 +0200
Message-ID: <20240621113706.315500-30-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621113706.315500-1-iii@linux.ibm.com>
References: <20240621113706.315500-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: yhZa-GJwpXVc4D4zqRCXsxL90eVaByvk
X-Proofpoint-ORIG-GUID: -XJKREGYzHJTLdefTkmm922KFj1UHXvz
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-21_04,2024-06-21_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 phishscore=0 impostorscore=0
 mlxlogscore=999 mlxscore=0 bulkscore=0 clxscore=1015 malwarescore=0
 suspectscore=0 spamscore=0 adultscore=0 lowpriorityscore=0
 priorityscore=1501 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210084
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=XJ53Nf9a;       spf=pass (google.com:
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621113706.315500-30-iii%40linux.ibm.com.
