Return-Path: <kasan-dev+bncBCM3H26GVIOBB56L2WZQMGQES66HE7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id B69179123CC
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 13:37:28 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id d2e1a72fcca58-7043a7741cfsf2208578b3a.2
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 04:37:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718969847; cv=pass;
        d=google.com; s=arc-20160816;
        b=PmLjkpjL/x8vdwibIbQavK3dvJF45Sm3IhVqIIZ/FCtdztkHBQoN0lq0DY9Lqtoytz
         lSNl30pEcH2oatRZovGQA2S3nS1wd9EVSPcWH+AW4MbM39s5wAVoG+9Sq5qZ8aJT6Ahz
         9qBkyxklnwCwA11iZdRLyKe2Dn6fljaNGqrevUBke4Sxnv1axm1o7IkE/AurM6Q3QTVB
         EctqNhn6LCHG7xx5L1apddKBWxT2jl+yLa+/13qFSrSBJZtsJReLugL/4TcUmag2Jg0O
         AAwiW+NakqrwnAgcLH7jS3j2t1bea2Uw/T4g3kA7/XqXFjvKPF/EJrw1VQsFUtcb2+8i
         LLoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=eLiBV6yvuEp6tOWZCw55jgBIsR5sRLUUAhjHhio3i4Q=;
        fh=gk2RXpYkeBZSUTMw28b32A7rdEKGzC0CrnlTpqCqNh8=;
        b=NLm9wzUG3AsV3czuGAwT24SsTfwnfiVNdYnJyN1MSdB23+TxjNFrHXuXS9qZJLPzVn
         2fWIhlHHT3ATDJUVzD3UfFBZp+KTbqq/zI4gSum2e7D6fF76O2bKWYiqN1uO3g4Q7J4c
         1Uz7Dt1S7bDls0MQFrxtJxIDRg00mcfJR48VwgnDJbpbdXPEibvWXjiRUAvqP5xVeksg
         oNEzWXYBlbhFz2RlPrfxjy9C5R7/1jfql7MjiakO/F7fFcG40C4gqYfqVt45PIlI2euW
         FRhYqZrvSAgN8FatJbmOw9vMLLSYsWQsctMXTGUTIairC0WAc8mZFyNm9U3R+gZS/T+4
         BV/A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Bj2BUCD9;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718969847; x=1719574647; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eLiBV6yvuEp6tOWZCw55jgBIsR5sRLUUAhjHhio3i4Q=;
        b=dgQX6bIhI3b53OLDGkzPunALucx3RbnJVe4ybqFv7c+7acv7NejpDyx3yR8U4w3zV3
         eWmqbtVBu+s/Sicr2m3xCWz7Qq61FT93g5liwlrNwD4BvRnKyGOdGbWshXeqwe5W/Rfl
         dtshFamPP7UbmjWVGsUzS+C8my2Md+GHmBpOlQY7xnoM+HiZYgUB/Bk+FPOdt3HgNmjZ
         T1ibIDAnDTCYCJ/TvY0XJAsmURrMV9+X0fuzhPoJMkQCUPjhaWfOBdT/6QKjN710P5bW
         Rd1nXMqJs5+GrCFKTZfG1XddEwOXHuFngXJpHdvX3EjeNv8saNUOqEc3rugKXRPFoRPh
         U62w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718969847; x=1719574647;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=eLiBV6yvuEp6tOWZCw55jgBIsR5sRLUUAhjHhio3i4Q=;
        b=qDXh8nA0ESAiz0+wpOU1Iy1H9Z5cmpy3bNWQTaBoOfEbvJl/+Iwe5QxhglA+H4nsdJ
         qyhSXGhTl943E2T7YpB1SbfmIpgXPW8TFvkMGvzutMAlW4SeH0BksHA/PoTtFXp9s20y
         LxR6H+Zp8KCvoeghPgP3HggUdmxPaRQiYCv6/MwvSiOXoubLQEzZ7tpaP9dNe4f9jcXz
         MqX/HMPYIxxk8zd0Jpu8SJ4Qra2ara20TTqyve7EtaC6bYBJ67xBTxlbO65fPnnbAAMD
         JUD34pOFH3l3bvRlptqzk5QCS4Tp/p0afEX4c2R1+hEJVJ7gpEnGYlB7Jwi1/Fh4EBqQ
         9IDQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXwGpnERJguXPOGWILQUELUGlxxVAK5CKdPLZzUhUu/cz/x2RtaAo0IEUxoW7MEKJudQAdQM0WAzxFhKc3zBDoO7YphB4pFzA==
X-Gm-Message-State: AOJu0Ywc6/1g2ClVH+KfKz4B/gMt35s1f+EQ+BnaaQOJqWQqV/w4eQOd
	qp54Yew/H5k1WEA/KSfyGlztj7duK7fJX8+Wvt0mxp3NyQzPMUMG
X-Google-Smtp-Source: AGHT+IHEDx6W1JHKptZSmpbRC73x+TNcdsp96VR/+XZQcI9e2sfaSfffaeunns+LbecHgKud0z1vqw==
X-Received: by 2002:a05:6a20:6386:b0:1bc:b15a:49ff with SMTP id adf61e73a8af0-1bcbb640c26mr7984652637.47.1718969847228;
        Fri, 21 Jun 2024 04:37:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:4086:b0:705:e489:e87a with SMTP id
 d2e1a72fcca58-70640f9ac85ls1349599b3a.1.-pod-prod-09-us; Fri, 21 Jun 2024
 04:37:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVqD1YezGcixH4MMNT9qdvLpg+4RX6+MBCImUQm0eELjqZ8modqWHhjOO8bRCB6SFerbnZL6T+tREp6uPXzyTrrv6a6JspltofelA==
X-Received: by 2002:a62:e713:0:b0:706:5f74:b97b with SMTP id d2e1a72fcca58-7065f74bba6mr33739b3a.23.1718969846102;
        Fri, 21 Jun 2024 04:37:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718969846; cv=none;
        d=google.com; s=arc-20160816;
        b=tOFkKYmeK6UbKOk2eNG+ysdOD2VphS44h5VvE7oxXvcCtXT6tH1pFOSIwYX950aayi
         Pgf35w436hE1Yr/A0Eefhnl9iHnE0BVVcsnRsodCL16rvsBx4Oj0TExW7viMHgVDzDk1
         2O7FFcefUOiOhlZSROrT4Z05KjUZeOoUBI/7+LVoL5uHzcgYI9oLxt3EO9NOJb1MZ5yt
         vO7dZ7BwYBFqov+7QSuko65bYLFsVBFHM7imLBABR293Yxe2yDLRsmYXno98YQBEu572
         YAlpjDJ2Zsixst00wV3tpudO4mN9HW0lAFUyKXkU2Fs192g8LCHMisEqj0JPel2hcH6T
         6IKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=YaTjcojmIIYPSV3AqgAoZ8tGeMyuD+KvoajbKIBgv5I=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=PkuDZPL8QfZ0K0o+sreg3U/JpzpWhvwSLRedPj/xoxiquvV6m039TyKYnbore0RGhu
         img1CTjCmh6+TX4Xvdhujw+SKxkBQh3r/rOwQl1lznoKaQI+7Qn9qst2iyLDwQfvZxFx
         Vyl4T9wmO4uZCtWhw3nGequbnmQmKt5LwAvfAj1H2QnxU4HJQiT3qq8CwKa6NGBVSI0l
         MNWYGLuNOFO+re8sZCHaB7//bJ/WGboJtp/kTkqtRaPOZDFZ6hOtHlif+VW5kLG/pk83
         Y3WT1G8XLUuDYFcY/KP0ksM5S0qciUF2nOKy+xe3b2Jd2gwiMCyu4dhb291HKoUFUSRc
         nLPg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Bj2BUCD9;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7065284dfb9si41550b3a.4.2024.06.21.04.37.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2024 04:37:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353727.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45LBPWSM013251;
	Fri, 21 Jun 2024 11:37:21 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw7sv84ja-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:21 +0000 (GMT)
Received: from m0353727.ppops.net (m0353727.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45LBXowa027735;
	Fri, 21 Jun 2024 11:37:20 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw7sv84j7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:20 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L9F81K032326;
	Fri, 21 Jun 2024 11:37:19 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrsppv54-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:19 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45LBbEG856558060
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 11:37:16 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 00F3920065;
	Fri, 21 Jun 2024 11:37:13 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 682072004E;
	Fri, 21 Jun 2024 11:37:13 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 11:37:13 +0000 (GMT)
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
Subject: [PATCH v7 08/38] kmsan: Remove an x86-specific #include from kmsan.h
Date: Fri, 21 Jun 2024 13:34:52 +0200
Message-ID: <20240621113706.315500-9-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621113706.315500-1-iii@linux.ibm.com>
References: <20240621113706.315500-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: BpILiJ84wfMQc4OyrWWYtqK9HSl8OMnP
X-Proofpoint-GUID: DOan1dwqMWSOnCoi8hsLGLzYWLKMPAsY
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-21_04,2024-06-21_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 bulkscore=0 mlxlogscore=999
 adultscore=0 phishscore=0 clxscore=1015 mlxscore=0 spamscore=0
 malwarescore=0 lowpriorityscore=0 priorityscore=1501 impostorscore=0
 suspectscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210084
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=Bj2BUCD9;       spf=pass (google.com:
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

Replace the x86-specific asm/pgtable_64_types.h #include with the
linux/pgtable.h one, which all architectures have.

While at it, sort the headers alphabetically for the sake of
consistency with other KMSAN code.

Fixes: f80be4571b19 ("kmsan: add KMSAN runtime core")
Suggested-by: Heiko Carstens <hca@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/kmsan.h | 8 ++++----
 1 file changed, 4 insertions(+), 4 deletions(-)

diff --git a/mm/kmsan/kmsan.h b/mm/kmsan/kmsan.h
index a14744205435..adf443bcffe8 100644
--- a/mm/kmsan/kmsan.h
+++ b/mm/kmsan/kmsan.h
@@ -10,14 +10,14 @@
 #ifndef __MM_KMSAN_KMSAN_H
 #define __MM_KMSAN_KMSAN_H
 
-#include <asm/pgtable_64_types.h>
 #include <linux/irqflags.h>
+#include <linux/mm.h>
+#include <linux/nmi.h>
+#include <linux/pgtable.h>
+#include <linux/printk.h>
 #include <linux/sched.h>
 #include <linux/stackdepot.h>
 #include <linux/stacktrace.h>
-#include <linux/nmi.h>
-#include <linux/mm.h>
-#include <linux/printk.h>
 
 #define KMSAN_ALLOCA_MAGIC_ORIGIN 0xabcd0100
 #define KMSAN_CHAIN_MAGIC_ORIGIN 0xabcd0200
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621113706.315500-9-iii%40linux.ibm.com.
