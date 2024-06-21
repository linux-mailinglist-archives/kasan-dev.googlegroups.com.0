Return-Path: <kasan-dev+bncBCM3H26GVIOBBUUR2OZQMGQEJLLNDOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 33CF7911754
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:27:00 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-2c7a8a79cebsf1595469a91.3
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 17:27:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718929619; cv=pass;
        d=google.com; s=arc-20160816;
        b=WBdaBj+mG0NTRZ1KBLBSZtH02DglAS8vkaHxVaYvNYjNdDbMm0JlLhMtJRvZLQbvFX
         Zh0QtYik/hw3grs4MpzGWYnqcE7a3A1gY65VnJZClFh7jIlIpbijCv6hN1+DAGFEgKnr
         jkPlRF7ET2q7qFXTPVq6jqtSInUZiavpisIUlD35YTDNcqiOZaA1evCx4I6VYLg2oHbG
         QNJP9pR7V4QTu5DdBfA8fDCzIRLyJKA0ayLf5pjhamZaijPPNXckPDBzg1gxeM+qxKI2
         BdX4zrGK542nvxgwpBwDiZe3vR8doVJLJFPanbZyG4oxCR73icYZu/iCg5QNm9cmyC6T
         gfdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=s3ckNdmen1J3Zt9ZI2+0htjpWmxMGzWTssqzbl+k+bg=;
        fh=I0BrMdnxWhUo4F2IDn43A0LtUAS/b6PNGnSyc3z9mxw=;
        b=qriJWlxUhnuIjkJ9IjyaHfnkDSW2NLu397XfHhx+SpVpzJXjFAC/2x5vjwOGKaEtGk
         PmODJxcKU2hjIzXAPATzS2bkLTABRsLO6Qe0fBZtMUnNnCbXPNdbPRWAkt+A6jn3jFn/
         vKczzSLYbb9BxLtCLoeO6LggoxUX7VIu6TkMzOwppHN9XTVlRDIPhwJoTgBfaCMD463C
         Zl+hJghxc/22y83xBKRHhtzlH5758sXIx4FfOOFPYJHVAjMZ7YqpRGsBF4NinDHbC5Cg
         rJ1eRKqPsFyst7Mhlb4I29ihyEundEulOukeiMeM6jhbUY+gIAUhlk38+OuhTk0EjTwl
         lrBA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=QLTiuUgz;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718929619; x=1719534419; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=s3ckNdmen1J3Zt9ZI2+0htjpWmxMGzWTssqzbl+k+bg=;
        b=NrraiBmhY4P0IMTjRj5DHFN/H8ISUU6gb2llK39KM27tO88MGJ7g92Oupxj+7q40yi
         4V3xnLe3e5qpQ0SgDFOWW39Q1UoLsoqQ5vAjPQz05Wo4AFjvZKLP0roIq02SbgCAxD0L
         SKK412dHoNbyvaOl5NkVd5u6jA8h/klBQqAC6vzJXNWmJ0jhaoYQeAlJjTz9iA3U3cMn
         Zh4vNP8dXU892I8877pMQjLHFahJCtzM2Lbxwl/4K4UTwQciglSK8K8V/mBJ8YAdO/pg
         88X1doL3UvHjFTI9mXHExYwO0b2A8o7AFdN03tVQpvaRqXI0hJqMr+BklWRkNQZSwM73
         sG4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718929619; x=1719534419;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=s3ckNdmen1J3Zt9ZI2+0htjpWmxMGzWTssqzbl+k+bg=;
        b=OTsQQw0AQ97YVne6Z8faB6U0ksoRwVxbuxDV/KhGvg3zTLTy93URhHl80+wDVHut0z
         Bbbxeoq86nCWKktE5EiYbp80BZ5NDts8j3Gqg5IocNC3oe+a15xO7hcu4/rAlH4c8tKl
         VaiE4Q750kpijAL3qnIsflf5P5oLFiVpFffPyhk7H6XS++zD3iFoSfqiy7GcoRITb0ng
         hpIGbTx10RO1q5EktTvIFG46g/ZYKIFxb1ntl4dTu6rEjVsBZ3Ud/F9cusxoIUpzmf4C
         lzOSJJjocUSFR/VTWmlnyKLmb/q0LyRmX4vBpUPPQzVnwL69uD2FgebwwVAx/zpyFJnN
         BBqw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUrDaFJtVZzRN3aS/1zGOdRFvtHRWTprKe27OPTPaqe7RyWDuutnVIugDu9vzy52ntub15/vdJBM3ieJLSJbIyGaRNOQ0Kfmw==
X-Gm-Message-State: AOJu0Yw3ILJWG09O3tIrWAor8gB6mK0Y7QkVtE6BpP8BXqo5ub9U6leO
	f8/WLSx/IfB+H1xtrJ7BjcdET2JdtixJIl0v8zDsQg++apraYNwR
X-Google-Smtp-Source: AGHT+IEDST0RCi0OXHYAIulf5qE2x4SHtT1JuHQoXWppGXWc90DDC8Etuvsq74KhFAGOyXuivxVOqg==
X-Received: by 2002:a17:90a:ff84:b0:2c7:ad68:f99f with SMTP id 98e67ed59e1d1-2c7b5d8ab06mr6275275a91.46.1718929618745;
        Thu, 20 Jun 2024 17:26:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:224d:b0:2c5:128e:240 with SMTP id
 98e67ed59e1d1-2c7dfefbd1dls985726a91.2.-pod-prod-06-us; Thu, 20 Jun 2024
 17:26:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX2ODEAdzx00JKdiD+c73BKBLk+aqsS9AcM1ZmzzUNsvdCldvosLKxYO+rUzcRnYlZviaudVuK0E7+I96VmL7Ce0WeNmakRDW/ksg==
X-Received: by 2002:a17:90b:3011:b0:2c3:48a2:6121 with SMTP id 98e67ed59e1d1-2c7b5d8ac1fmr6291593a91.45.1718929617608;
        Thu, 20 Jun 2024 17:26:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718929617; cv=none;
        d=google.com; s=arc-20160816;
        b=zRKvvNE1WJjQijlx4aycglHUy2uyCYcsCtODHsY744IR6BxOTprxFpRolYbdgVfjVF
         XSLtqgg8TR29rKGzuzDsG9qCt8LjpKXitgqBOitv7KmkHuSC7wHnTMIcUlStzwGCGaYe
         vrWSnbBtuKGFyYxyxbKXwiH3mVA9GgLTkZtkuYUBnDyQf3TRmNGren8cM7ItJkUQDvG7
         53Ud/1C7irAVOEVYMHijsqByYlAhrEL/nPDFs9jqGrviCGD7f28lwsKIisVKfBKXd92j
         Yuv4BSAkAUapCsf/ET7QFRdhMXqWuhO1iBJxZAbKukpiaVqQKyM9aLuk3N+XrzYpoD3V
         RCXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=eOJVqKOJuZasA86pPY8j/wtn7XC9Zj2RO1nXjWn3Mgo=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=sCyhQPAZZOM/mBSak8eDEol7LpGiYKltuCfKkuuhgeV+K7plzMdJjF2AVOoFFR0m7K
         nmTvdJtN7s0vlGDpG6bDZd69ul8qMiRg7BBQ1b0tVmHjElSApBstq2QXuA0scFb8vfrb
         kdW5BKFQOaUlaC9Z8sZUW0vRgcCcT8XOXUGUW3RqCENdVsi20uP4cPJcOCXyKUfJ+ex6
         Ss8PEdH0deyYgC8LXz/2H+4PZN9J5VZoH6K9UTLjiK1JEMbW4lNb9JBcMtH1Z3FaRaUF
         X2qpREtjuhwj4OcDvt7umWUw2R5Mq6bh3VeEnIMhG0ZXnPR7L5hRWz0BSL1RYFBr398x
         /NxQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=QLTiuUgz;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c819dee8d7si22663a91.0.2024.06.20.17.26.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 17:26:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353726.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45KNQYUQ017245;
	Fri, 21 Jun 2024 00:26:53 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvvrdr8ax-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:52 +0000 (GMT)
Received: from m0353726.ppops.net (m0353726.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45L0Qqh9009543;
	Fri, 21 Jun 2024 00:26:52 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvvrdr8au-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:52 +0000 (GMT)
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L0Htw4007678;
	Fri, 21 Jun 2024 00:26:51 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrspamq0-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:51 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45L0Qj8Z56492412
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 00:26:47 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A787F2004D;
	Fri, 21 Jun 2024 00:26:45 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 848A620043;
	Fri, 21 Jun 2024 00:26:44 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.44])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 00:26:44 +0000 (GMT)
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
Subject: [PATCH v6 21/39] kmsan: Accept ranges starting with 0 on s390
Date: Fri, 21 Jun 2024 02:24:55 +0200
Message-ID: <20240621002616.40684-22-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621002616.40684-1-iii@linux.ibm.com>
References: <20240621002616.40684-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: 1AqOcpwzwafdX484ppd5O8j1ZYWTiJo2
X-Proofpoint-ORIG-GUID: FgwbXccNBqEcPSn3Bplx5nbUcnlWVihd
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_09,2024-06-20_04,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015 impostorscore=0
 mlxlogscore=999 spamscore=0 adultscore=0 phishscore=0 mlxscore=0
 lowpriorityscore=0 malwarescore=0 priorityscore=1501 bulkscore=0
 suspectscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406200174
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=QLTiuUgz;       spf=pass (google.com:
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

On s390 the virtual address 0 is valid (current CPU's lowcore is mapped
there), therefore KMSAN should not complain about it.

Disable the respective check on s390. There doesn't seem to be a
Kconfig option to describe this situation, so explicitly check for
s390.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/init.c | 5 ++++-
 1 file changed, 4 insertions(+), 1 deletion(-)

diff --git a/mm/kmsan/init.c b/mm/kmsan/init.c
index 9de76ac7062c..3f8b1bbb9060 100644
--- a/mm/kmsan/init.c
+++ b/mm/kmsan/init.c
@@ -33,7 +33,10 @@ static void __init kmsan_record_future_shadow_range(void *start, void *end)
 	bool merged = false;
 
 	KMSAN_WARN_ON(future_index == NUM_FUTURE_RANGES);
-	KMSAN_WARN_ON((nstart >= nend) || !nstart || !nend);
+	KMSAN_WARN_ON((nstart >= nend) ||
+		      /* Virtual address 0 is valid on s390. */
+		      (!IS_ENABLED(CONFIG_S390) && !nstart) ||
+		      !nend);
 	nstart = ALIGN_DOWN(nstart, PAGE_SIZE);
 	nend = ALIGN(nend, PAGE_SIZE);
 
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621002616.40684-22-iii%40linux.ibm.com.
