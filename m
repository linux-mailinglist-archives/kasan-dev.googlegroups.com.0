Return-Path: <kasan-dev+bncBCM3H26GVIOBBAOM2WZQMGQEQKKTG3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 373339123DE
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 13:37:39 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id 41be03b00d2f7-6716094a865sf2019550a12.0
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 04:37:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718969858; cv=pass;
        d=google.com; s=arc-20160816;
        b=Jb/+Qx7I54nYPTMZRvHiKjKSJ1F0kJWM/w3khZNzV5yD2XvaPygtJRWk6CEx+8wkdR
         x8glpgR1MYHv3Fjn4xeT6N7MvK2jeBPi/cMjeQG4qtjLqwMJryC27K6dAdl8g2jAwKs4
         wRdxCedT85ezy8OWO5HOIdPyjSDUEWm/thIdhXtKQOo4Nvv2WWtB7MyFGVkbZ9TQRvdE
         CWEah+EUIQWAFAZf02K09zcdN1/B5GMJB3nlRWobxBaXeXo4cVoDY8fK5ubl1/+cM/0l
         lrzNbg+8T6T++45EhHKhizFbzk07LWxdEYTjgiLq9dLbOQySxreStBnHtPb5pmn84hwU
         Dn1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=g02UnFaYFLRXDMG9ubmP7ry3FUpCSJQENcUEjdFGdxo=;
        fh=aQrEQBBzpCOFXYvrwglQyJ5Tg2X6AwUKUFXSUdaA5M8=;
        b=tq1KRI9AOZyWmShZBohdm41KjJzNAsHfzss+1ho2jhDWGzZvneUyU+vt0N12U3TVa+
         8rkk5fFF68kEB9AIhl3/7cbtZbS61PyCD2fgIGoxPruAhm/rU3AyIq8FRjqm0Kyckru0
         EIwuzrHGIIS8Ck5LfkLLMExK7BvRkZm80RV9+3qvJR4YnGLxA0gUzRRJA/ui8M6jFmJN
         jC60sqzo5rJ6HeGZbryHLHt+CqkOmDHMaLN65RYe4I1Sp4H/BwGw1JwZro9Nv42VGOoa
         dt62UNephtlA4VRSdD6Ge8eRu401BKA0l4+JqxU8R6y94n7X9VVjDRecvhdP9d1ik/Xi
         wgMQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=amWRvAmR;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718969858; x=1719574658; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=g02UnFaYFLRXDMG9ubmP7ry3FUpCSJQENcUEjdFGdxo=;
        b=WKuAkUkDVRNo20DQ0qzq3QtEN+qvhJSfa+0pJiAEijYda3Ue2prsqTOKJvk6u9lOOG
         pg64KL4cc1F1uT6AwOw/XmFcTTk4BGp9M6Y7bmirOX0fbr+9g7jLDKG3pK1UYiPizGoS
         6rph6dwZxFmU1TxTwx85V0JQ6BZMdrlCQcmuGvmbQY1LuyJbSsDsN7iTiCkCSiy3eTld
         wF0laI+YQDtwEEQSVZNWqFm3Q8GXqOTPeEt25oUWE6jmE03T7fRSXFEHaM890vavc2Fd
         bRNrlXf46i1ZauenQl5+dYnWPpy2YLGYjVyzYDXZJoeZ7UE/dVY41Q1qXjGPEw31zzXY
         IjdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718969858; x=1719574658;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=g02UnFaYFLRXDMG9ubmP7ry3FUpCSJQENcUEjdFGdxo=;
        b=tv3xTKxNh/mNWMvZRF6CP/VcOuHlpLrtFh+F62lO0u8t/4JGvQdd7CGMZyhzmZ13vd
         ZX+WaxaESOrg3HtaNP0Lvi9MsTg9BFjEMx6t1PUVKSaFc9tTHQHJ+ASpr2T4PjRSW6AB
         fAwbgzn4ijNrISkuYt25StZDXo+HypR2cjxjxAXsoQY2XJenJ1gB3qA9U7phvhpmvszs
         GnFia4KKM6+kNuMWY3TRlJAEPbPKqD4Hj7sW3meelvO3DQa94iZ8Nkl516B0a+4TLMFZ
         HRFmYdbfzbiRMpjfwRfRFle2AYeZfX55OponVoCu+ouUKWL4pH40Xt8GS3Telnm4QblU
         9LJw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUcveGirnZpbFBHGHdMqI74Lfh85DxtgaqLSQbSbOSE+KbcDOijjf5qTNOS4qZydPsGxgQ+9mH/Rr3pg5ADCkgq4zn/zSYU6w==
X-Gm-Message-State: AOJu0Yyhrxd6zthzURyMLzK+A2lgF85BC6Tl+r7KWgBatHXNM6Em4Yz5
	l3afJ/AFuxGbM8yO/YAHJKL8h46XFAGaWZijYHHhFbjkegEr162C
X-Google-Smtp-Source: AGHT+IEGYMMbG8nvhpwzDf4sOmoII87FKqNjsi3CORhztYv5v4eOmEUQ2em0xl/NfNWZD/6nBMUtEg==
X-Received: by 2002:a05:6a20:4f8a:b0:1b5:834b:ad75 with SMTP id adf61e73a8af0-1bcbb6e1330mr7687973637.52.1718969857703;
        Fri, 21 Jun 2024 04:37:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:1bcf:b0:2c3:159f:cc9b with SMTP id
 98e67ed59e1d1-2c7dfedbbe8ls1155439a91.1.-pod-prod-02-us; Fri, 21 Jun 2024
 04:37:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUGlNllDV6919KRbb4Z9bt/vePC0nHnjXHiW7heB6ws/Ch8Jbh5q0X+P2clanyJWuYyOllxaK2wrQk0Jsqmk/7jsiQAW5w9XChblA==
X-Received: by 2002:a17:90b:a4c:b0:2c7:a905:74fb with SMTP id 98e67ed59e1d1-2c7b5dab4f8mr8145735a91.40.1718969856626;
        Fri, 21 Jun 2024 04:37:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718969856; cv=none;
        d=google.com; s=arc-20160816;
        b=kQPAN5xKM6kZzE3y4EtNgj0chVnDjeVRxbfRM+HZiGds6fFYDaLMQYaC/XHYwCZHzx
         LUnTSs5Vn0NhqyLt1FKZorJfrZbZnvV/lVuYfazirInNme+PHJ1rhkpL8lLe7G0/5qdt
         jwsmM9MQsG6ZbwMW8soo4bKjBXmNJRkHl7NDlGJPjhjODd2NaZnvkGs74zCdBDfRJdGY
         ylzvj5fDI7sMByA5/ED7I+mte+0+Ex8RuubxEi4+dJpjnXv0QkNdQ0mLEOfDKW9eUjSq
         waSLDYwhPHJAsgtNzn9OJ/QHbncdb7pP7qFwYLiO3I+kmROZq4RQesiARqhASpgtD+Hk
         u6GQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=tPY2/xfj0WoITwfgq4isE+nahUee+x7RgpdrRutXdLc=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=O9ArvSDLCK0e8G32Z2sB+xQP6N4SBQU99gGnlGLG91rh8AnaOD1qmqLw/0C2t74LQM
         xh45HcFrRSS24ytq80JSHe1GfsFDUGrbKg9+A4Ojo33KebCr52F1LHbmfJbR6QX35Umi
         L8NB5ouMpfwZYuYUnHs2CAZqhDNZluXYKgdvVhA4O6KPI7/Wqu3uY+2c3Ej3TNNxbuU/
         opAG7LR/APc+DigfRGbh4FAyiaKGNbh6QpB2TVKT2LNZcrYWyRxmsjWbWgpawmy3siFG
         /XiOT2WZw+coEBtsUmadD5KiE4AglGjhdAvRg0/sw+zoRsxwqLz+l/CIIQLN+YexWlzl
         vgIg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=amWRvAmR;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c709e9f07fsi1059101a91.0.2024.06.21.04.37.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2024 04:37:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45LBSoRS031855;
	Fri, 21 Jun 2024 11:37:33 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw8p2g0kb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:32 +0000 (GMT)
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45LBaDh2011409;
	Fri, 21 Jun 2024 11:37:32 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw8p2g0k4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:32 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L9ITHE019974;
	Fri, 21 Jun 2024 11:37:31 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yvrqupw0b-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:31 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45LBbPWL34603592
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 11:37:27 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 95BB820040;
	Fri, 21 Jun 2024 11:37:25 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 0C15F20063;
	Fri, 21 Jun 2024 11:37:25 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 11:37:24 +0000 (GMT)
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
Subject: [PATCH v7 27/38] s390/cpumf: Unpoison STCCTM output buffer
Date: Fri, 21 Jun 2024 13:35:11 +0200
Message-ID: <20240621113706.315500-28-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621113706.315500-1-iii@linux.ibm.com>
References: <20240621113706.315500-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: sJZxLZqi83f1gaq2C2xaVmzrDntGvdhy
X-Proofpoint-ORIG-GUID: 47w3i0YnpjSgJH2Im2QQDMm0uJXN-cRp
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-21_04,2024-06-21_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxlogscore=958 spamscore=0
 clxscore=1015 bulkscore=0 impostorscore=0 phishscore=0 priorityscore=1501
 mlxscore=0 lowpriorityscore=0 adultscore=0 malwarescore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.19.0-2406140001
 definitions=main-2406210084
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=amWRvAmR;       spf=pass (google.com:
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

stcctm() uses the "Q" constraint for dest, therefore KMSAN does not
understand that it fills multiple doublewords pointed to by dest, not
just one. This results in false positives.

Unpoison the whole dest manually with kmsan_unpoison_memory().

Reported-by: Alexander Gordeev <agordeev@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Acked-by: Heiko Carstens <hca@linux.ibm.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/include/asm/cpu_mf.h | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/arch/s390/include/asm/cpu_mf.h b/arch/s390/include/asm/cpu_mf.h
index a0de5b9b02ea..9e4bbc3e53f8 100644
--- a/arch/s390/include/asm/cpu_mf.h
+++ b/arch/s390/include/asm/cpu_mf.h
@@ -10,6 +10,7 @@
 #define _ASM_S390_CPU_MF_H
 
 #include <linux/errno.h>
+#include <linux/kmsan-checks.h>
 #include <asm/asm-extable.h>
 #include <asm/facility.h>
 
@@ -239,6 +240,11 @@ static __always_inline int stcctm(enum stcctm_ctr_set set, u64 range, u64 *dest)
 		: "=d" (cc)
 		: "Q" (*dest), "d" (range), "i" (set)
 		: "cc", "memory");
+	/*
+	 * If cc == 2, less than RANGE counters are stored, but it's not easy
+	 * to tell how many. Always unpoison the whole range for simplicity.
+	 */
+	kmsan_unpoison_memory(dest, range * sizeof(u64));
 	return cc;
 }
 
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621113706.315500-28-iii%40linux.ibm.com.
