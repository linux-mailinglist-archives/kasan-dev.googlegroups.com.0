Return-Path: <kasan-dev+bncBCM3H26GVIOBBTER2OZQMGQE2R7H32A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3748391174E
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:26:54 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-2c7a68c3a85sf1598309a91.2
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 17:26:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718929613; cv=pass;
        d=google.com; s=arc-20160816;
        b=yAM1vONtGgDuDs7+5OPRuoZUcta1q7+zNpMi/gpKsIyparl1IbhnHBHwPJDKrhAOYq
         g+ITEMXeb2CvIRI3wfDkKhWUiO0UeRf2i5bDk6V3HqKrgCM4PNEUyxLipMm+bLgCsvtp
         nD4VFoAfMufMa15ugcwi4uNN1weyIwXs47bjTcpFBrSEG0GLFoplYUWEZfpHoqyzMZgL
         v6K886hs4p7Fyogx8bFM/29SLzCD0hbpRh5Ek/t6avs2a/+DB9ha14/dBd5PH2971vu7
         MXKNqIhUnvuocz7C9ZVaRQCvRpYAYoTTD9YxfLPsRmkOfN6xA07Rp6ve+2nLi4UATn2v
         sXqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=5AfYihTrH7i2rIKgHGuufrQ17BYteei2fNBFfeSpGZg=;
        fh=KQRcgOJ5ZdMvEmMcDM82CXzASoUmbyUyYJWrEIaEn7Y=;
        b=CIgUgnr2FIBZsl2mTw85W0QkqRMg7qx8j6aEUT3Ghn7VpkBI6YnOfW7JMZh1A2sgg7
         b2iHWbTfhHAK3ttj+3j5jZLaBLuiPTvA1yhY61oGJOVI2+HPeebF9WHNq/n/sUUI2C/Z
         Ozx48J/r6/jXvYUmft21I+tiWYQ8CWUykJirOrG1GdAp/Io3sGAJX6gjBJTeu9c25LTs
         YwnHq4NEhge9nJXV5BUTRutROZyiHPaJg7kY4A7t8iY1NDFiLlbhk6EWDclL+BzQX0Z+
         Mh3rx2xTg4i+nF6wDnzqUzuvpFRdm4tQYKzRwLfke9Dhhs/p2K0RDenu7pOhRvgcdtjD
         oaYA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=s7jYJbCG;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718929613; x=1719534413; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5AfYihTrH7i2rIKgHGuufrQ17BYteei2fNBFfeSpGZg=;
        b=p3lfDgxOclbKG3hFjzv7xVnANyIiGiMaO28xb4pYFa1n7kB36rKIl7VKNgym46yKkL
         VY5vG2LAlSji/SvkkgbCQ0hPKY8TM7Ryh7vDu/2PP1w6FalbUVnXhxGCecTchwUHmmLs
         Lm+T2eBJkBZC/aLutTiyPZhN/GecWkUAjBVF0KlO6pKfbqZ+dz5ASoLy72pvyDMQL3xO
         brimItx9Wt0fJaDb90IN2QojOA/7ewdPJQuH5dgXhdeJw/OulX9rEkAydtY42f42PVyO
         Wpnp3WfOLi2Y0HxNy8fApRQpDzUQmDyKw9jF6C6GuhHLcTjDA9LE2DHS5hlHbm2WOcSM
         R2PQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718929613; x=1719534413;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5AfYihTrH7i2rIKgHGuufrQ17BYteei2fNBFfeSpGZg=;
        b=jNgvk4t0hAvMUNyMJpkxm5/WSZdqfvkk4sBAQ0wACIBuW7pD9IMSdpuT45jWTJgvXA
         GOLi+A1z2lsrizyu5ltYCtganU1awXsgSzvFw5tEQeYMUs97CAVe9UxAJXihJdGuQGAL
         2SArD+OpRR6MofJZk1UybvfeAnaC8LLN42DIG7nExz0mkFEZUvGK8FnCnMWwe97+GMPr
         qboV0cLrrN4ZVFzVarrHwHNUDkTo7GPPtd+BllwMZKoPDYcibLU3vc8hscy8s60V1TvM
         37NmlQh/kWuz0l+IWYzE3YpyEd8jo8oZ703WvfJjyqdspwZgIu6BMVttQMz3f7aljeYl
         OX/A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVc7jRf6HeaEYjUxkvQ5MX0hlfeOYFaisN3D4qbVfmnCTIMlgZoQWBuwB3wYT5/OHb36Ge5f/pun5ZQb105WwNM9PWMtvLcXA==
X-Gm-Message-State: AOJu0Yyq1nktfzrfgi9XXJ5uloXkwKfr7UYHAZUPBlMfGywsog+/sMVl
	KG1ZjBjc3sm7LrwVrNXWTfK5mk6Z5N3scrUa1CnjEwfp0aiNuKU6
X-Google-Smtp-Source: AGHT+IGCa/wpckWnqOc3X6aOqzAxSyEFlvcReOgu50+cO+ZAJGCxn9rCHfMbCyYkTjUm2vnan4o/iw==
X-Received: by 2002:a17:90a:fb4d:b0:2c7:899a:db31 with SMTP id 98e67ed59e1d1-2c7b5d51949mr6647011a91.33.1718929612717;
        Thu, 20 Jun 2024 17:26:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4c08:b0:2c2:cf68:663f with SMTP id
 98e67ed59e1d1-2c7dfbf1074ls1013269a91.0.-pod-prod-06-us; Thu, 20 Jun 2024
 17:26:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWh3I3ELXh87w2DrF/V/eHVoaFGk5Txwl348LH97xUrj7ozn2Ik4QBMJS7Y0xgDtjN9DFbTS+uYf0OxQRZDzIaNBBxiid4JcVK6Yg==
X-Received: by 2002:a17:90a:55cf:b0:2c8:81b:20f7 with SMTP id 98e67ed59e1d1-2c8081b22e2mr2097829a91.44.1718929611572;
        Thu, 20 Jun 2024 17:26:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718929611; cv=none;
        d=google.com; s=arc-20160816;
        b=hLYCIRRA2JY/QAk0vlb0tpMpXHVzFAQ6dm2xYnx1FC7cXNL+PgBybT23KNugaEBPiy
         OEZqaIVaE5UZcg+ZOTtyqDcatuRACYat17tmOTTPLllqSrO8hP5FztFSEuT7DMB+JA4B
         137n7/s+xMY6qLNkON4aAh7EjbK2ipgR1+czZlfQeInNXS7xPN4mpz1KxtaxncIWs9XT
         +iGVJXz1TIM0dgq/kWfv2EO+6kJGYEt7aMzwy8z9DPKJG5movbm6IzNR+Xo0SswC1Rql
         0Z9RAb6njeHhJH1e5RBDNdFhJNM+SGe0sucfTVq/ANeezEWVKO0LsfSnRNpaA40ZaGbW
         spxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=OuTJsGR9CKQp5KU/moT9q7/MyfMfBzEfOFMR8s/AFMc=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=KSbun62FeSdS/Wy1rEiThlXmsiJoSiXbg/qLgUy8lge8qnhhcFYqpzxGfIYIJ6vYhN
         KgxCNkHCf1YdrgdKWcW+2t5D4yLG3o2cqhWP/P1mYpTWhnvEJ2RlJJckkBft2+l8+Yyy
         yaDw+H3xdfJnMqtGhNfB6ntAGFJeLVwJXk0vbAjCfzt6jT317UP0Xydl6CMjhMq8naRE
         nETWETxIwVa+jjT3+JZDEzvKrpiniPy84WO8QAqtwsPh7O4S3tLVbcw90aQgS3N9TFRN
         S8M4KofAtwvhdN2+Bd0AECwcUxODT0jyTXBhsjkEEJhb6+Q5ZyWFvlAHW7IuKrxDoeMb
         7ATw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=s7jYJbCG;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c709e9f12asi352990a91.0.2024.06.20.17.26.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 17:26:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353728.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45L0QQ9Y007784;
	Fri, 21 Jun 2024 00:26:47 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvw8c875n-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:46 +0000 (GMT)
Received: from m0353728.ppops.net (m0353728.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45L0Qkd4007867;
	Fri, 21 Jun 2024 00:26:46 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvw8c875f-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:45 +0000 (GMT)
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L0IDHa030896;
	Fri, 21 Jun 2024 00:26:44 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yvrsstn22-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:44 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45L0QcWh49676562
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 00:26:40 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 56BB92004E;
	Fri, 21 Jun 2024 00:26:38 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 332632004B;
	Fri, 21 Jun 2024 00:26:37 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.44])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 00:26:37 +0000 (GMT)
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
Subject: [PATCH v6 15/39] kmsan: Do not round up pg_data_t size
Date: Fri, 21 Jun 2024 02:24:49 +0200
Message-ID: <20240621002616.40684-16-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621002616.40684-1-iii@linux.ibm.com>
References: <20240621002616.40684-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: l6sxtiSRHhh5e4E51hgME4dLqY6SYYPN
X-Proofpoint-ORIG-GUID: Syt3v-DmTGAUXBEEF_AcFeIe-H4mnIzm
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_11,2024-06-20_04,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 adultscore=0 phishscore=0
 mlxscore=0 impostorscore=0 lowpriorityscore=0 priorityscore=1501
 bulkscore=0 suspectscore=0 mlxlogscore=982 malwarescore=0 clxscore=1015
 spamscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210001
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=s7jYJbCG;       spf=pass (google.com:
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

x86's alloc_node_data() rounds up node data size to PAGE_SIZE. It's not
explained why it's needed, but it's most likely for performance
reasons, since the padding bytes are not used anywhere. Some other
architectures do it as well, e.g., mips rounds it up to the cache line
size.

kmsan_init_shadow() initializes metadata for each node data and assumes
the x86 rounding, which does not match other architectures. This may
cause the range end to overshoot the end of available memory, in turn
causing virt_to_page_or_null() in kmsan_init_alloc_meta_for_range() to
return NULL, which leads to kernel panic shortly after.

Since the padding bytes are not used, drop the rounding.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/init.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kmsan/init.c b/mm/kmsan/init.c
index 3ac3b8921d36..9de76ac7062c 100644
--- a/mm/kmsan/init.c
+++ b/mm/kmsan/init.c
@@ -72,7 +72,7 @@ static void __init kmsan_record_future_shadow_range(void *start, void *end)
  */
 void __init kmsan_init_shadow(void)
 {
-	const size_t nd_size = roundup(sizeof(pg_data_t), PAGE_SIZE);
+	const size_t nd_size = sizeof(pg_data_t);
 	phys_addr_t p_start, p_end;
 	u64 loop;
 	int nid;
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621002616.40684-16-iii%40linux.ibm.com.
