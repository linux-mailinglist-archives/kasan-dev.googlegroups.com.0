Return-Path: <kasan-dev+bncBCM3H26GVIOBBVER2OZQMGQELFZWQVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113f.google.com (mail-yw1-x113f.google.com [IPv6:2607:f8b0:4864:20::113f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C5DA911758
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:27:02 +0200 (CEST)
Received: by mail-yw1-x113f.google.com with SMTP id 00721157ae682-630be5053casf29568147b3.0
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 17:27:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718929621; cv=pass;
        d=google.com; s=arc-20160816;
        b=AalEYYCHH4RTp9xFCS1w+GD/hDi8SDAs4EpLmndJUsxeXnm/DMbOr2R49U0aay2TzF
         vJlwpcjmLn19L19rsPJLW0CXA2ULMGcerLaLn6ADe9bUXUo5IbFijCrhO3CqUdr6v/FP
         Xqrh6LPmVVBVsRoS+PRrl65N8HhQ6fj1/ryvZ9eyE7ofKt0RTg+VRss/MdHv3EzlFROT
         gx4Mr0CFR2FRiIBHtm87jgYFryUw+D6m7cbiB9gOyIpz+LMsO3IAQVPI+ZMwunjt6NeH
         9oTie6xi4k/gYC+Yq8oOVN0SsE64UQKRJ1bywXEjzXCAQWCfDwG5LqURJD/2RM8o305i
         SN4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Dgd9huKpe2gYFfewgpP1kcWTvYHgWCpLgVx7i5tEJd8=;
        fh=t50tkiX+OWS5Zzo/paLjN+PDkzZa7CCqVQye9buwxes=;
        b=X+6CeTpfO407Xrx19wsmTmWzC+Fshhr8Vg2sZol2uplJQzIIWEHqz8cU82TTC0ooxO
         gAeuFiaEjwIoG1M1qVcbY2fxTNZ30wmifARcCSA2JMyxpNilseeChYFtDan15erF5c07
         0qwQ4+H8dkhpuKj2TkZjGnOe36y3M/x5uG4wlFxTBmxuoYv8snx2zPpO0mBzTOcU6G1D
         u+3hgk/Bc+sKGLQoVsqIIHT1cV0d8xPwFjQKRNOaalTQQ+bX/qyGGchKQ0wozROGhlCC
         9yfObFvIpHRwl+OJ5ztEOkwn1dH5s0NiEO01RBYH//BwCBalxfcKknIUWBXRl0JyoM4W
         DUhQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=JUnPueuq;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718929621; x=1719534421; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Dgd9huKpe2gYFfewgpP1kcWTvYHgWCpLgVx7i5tEJd8=;
        b=UnL+fQ8kKEm1HY2dvBJyDbRT0Q51tyffxi9mpsE8CcM9pcy9YssTy3Eu3xqWW19rF9
         m1zeX77bgs2bRB5sVtyxUXAhKKvkckmfB2UW+8ojAEN79laV3w5QI3M6epNCPdT0nvuS
         Jfw6rGa6uRLFsjNEtpnfeWkQD/aTd7M0a7Ys8MfEoPxcab1l1/XfVWMVdrar4DlHmm07
         PnXhXFnniKxQPTTKtOL307UWImIfNaiuE4lOsY3c0MUtvCw9y3VHhi4ECmBvl5abZjCM
         KCEHjH3f9YhPW+2ePuJwS3KFJga637hX4fKaM7GnKqhc9AH/q2Zpvo6Ux7cwjJheaF2d
         Ih3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718929621; x=1719534421;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Dgd9huKpe2gYFfewgpP1kcWTvYHgWCpLgVx7i5tEJd8=;
        b=Y0aMXdV557ode5zKAo58eK3LQ+S4taJ62FsSIHIWNxNnZpwnXYXQktplZGagVv6/+u
         rNLv7B3oXMRpVseknDOMaNQ7lXGzx+EcNgkYW2LLq2LibFspJiO/K2hiD6PqBBqmrbnL
         xpIYdHlHdtLrcZHg8eAF4t2ZIt+DP0uLm7m2q2BEfFS6H4eFnYRYrnwRnIZe2x5pNv4J
         40/fvGtkIpjJZu1P47k+pW4YgpEVjsrsqOln0qrDo+eMohjNxpGDHPhtJdraalEuts86
         iusp8CNwc0o9tSNTrCvPB0Jl3y5LzizSJ3zlIaS2mSFdl+wU0WKwspISnJY9/G/RP/fD
         TN8A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVlttvyeEDy6iNQ79zW6rxYvftM9v0GTUcNZBDJi/fJcoicSQKIWAITudXkSVI8lOECdKVcRQ8APZl6q/1jfbKVuqGw1IyoLA==
X-Gm-Message-State: AOJu0Yy9CRiSbWptecqP/bIhRPUju8CZcYiWaAq5DMP4c1uIW9tLFccJ
	qbwJ0ZpviCH1FT2cxFQcC7vI4dceKZN29HScQI8LCw8DzIzYky4O
X-Google-Smtp-Source: AGHT+IErQ41dQJJSzkfRnvwtgVcjRwZvpcjEa5Yd9s4fCvw7QUnDggqDsz8fIDEuq8kmoxfDkXRc/g==
X-Received: by 2002:a25:5f45:0:b0:e02:797f:56d2 with SMTP id 3f1490d57ef6-e02be18f269mr4977219276.9.1718929620898;
        Thu, 20 Jun 2024 17:27:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1005:b0:dfe:d0d8:ea2d with SMTP id
 3f1490d57ef6-e02d0a88555ls1536458276.0.-pod-prod-00-us; Thu, 20 Jun 2024
 17:27:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVMMnEGRdQCXgOW00Bp+EF2QP0FjY6hJULzurTJwr4HW+2WcgOeExRQJS1tfBYVmhtK+u205iz0OsO5dPlXL1doH3tNf9/yOeuzqA==
X-Received: by 2002:a25:8689:0:b0:dff:9d2:28c0 with SMTP id 3f1490d57ef6-e022450617amr7235006276.21.1718929620085;
        Thu, 20 Jun 2024 17:27:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718929620; cv=none;
        d=google.com; s=arc-20160816;
        b=avsgCo2F5aaKvA60AIBlPptC7Lu4KOJ77PLoOuK01fsGJNP8dPo2X+CJ7KTHW8GlSF
         XNTMXAfvJFYuOf0Hb5I6dtRY/TqSazSRwwa94V7nbiRBH3QM/dJEJbtZXjuDIprLbSeR
         IqWj7XosNk4PKOgvxcLxv1inJVVXQtqFNRunXsMsfc97MdEuxOuP9eF4rsPr14nZmHbs
         b5RXQBwvhqaCica6uNAH1dOYfANneU2pJLrpV1FWiCI7kUMTEEWcV0VdSr2v4QuvDmFK
         Yuu+R76S65js5n6QVkLd6OIfe5QBAY2KTybXJ0b5R0yy7jBoqqFvghmz9y8+0EH0qfh/
         YyEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=EM2Q29X1oynbiWdgAiIUaE04pJnjihVfcXc099lsq1w=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=UomjvlrqWO3cnWj7DZJXYZv59Q2S6UaeU3UUGdEs7rVv0qSBB1rEzS04dQZf89njqU
         dNNQzEuXJp73aWZmrxQ9CLLTcA+jwfAekurr8ztoY3bkYPsxcXHEcP/cy1FEvrbha7le
         8cxq694vDh65d6/HtQYfOw65FfkqzPgFDEN6fIpFvBMDcFHfMKVEP9/WeMWQIMRB6WiR
         E/eL2rAT/fjvBndqJMM0c01yyyP7Ev1+0ACgsKLQ9lfik8s4F00yw6iwIez/uCy7xp2v
         GC1N45sCcgV313a85duSps2bR7FvLGLLDnkHbWwyGpi57kqoCmmMOA2+5b7Fs5td3Z/m
         1LlA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=JUnPueuq;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e02e61359e1si24972276.1.2024.06.20.17.26.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 17:27:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353729.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45L0Qjxp017866;
	Fri, 21 Jun 2024 00:26:55 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvx4g02nj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:55 +0000 (GMT)
Received: from m0353729.ppops.net (m0353729.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45L0Qso5017969;
	Fri, 21 Jun 2024 00:26:54 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvx4g02ne-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:54 +0000 (GMT)
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45KLiBxI007687;
	Fri, 21 Jun 2024 00:26:53 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrspamqc-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:53 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45L0QmSs51315132
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 00:26:50 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 2432E2004D;
	Fri, 21 Jun 2024 00:26:48 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 00E0220043;
	Fri, 21 Jun 2024 00:26:47 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.44])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 00:26:46 +0000 (GMT)
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
Subject: [PATCH v6 23/39] s390: Use a larger stack for KMSAN
Date: Fri, 21 Jun 2024 02:24:57 +0200
Message-ID: <20240621002616.40684-24-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621002616.40684-1-iii@linux.ibm.com>
References: <20240621002616.40684-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: eIz9QFB34yT_9zDMbTspjjURecmQhbXd
X-Proofpoint-ORIG-GUID: T8FTzAuf5ejUZbTmqx1tz4sH7VNs5dv4
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_11,2024-06-20_04,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 bulkscore=0 impostorscore=0 mlxlogscore=869 phishscore=0
 priorityscore=1501 clxscore=1015 mlxscore=0 spamscore=0 suspectscore=0
 adultscore=0 malwarescore=0 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.19.0-2406140001 definitions=main-2406210001
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=JUnPueuq;       spf=pass (google.com:
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

Adjust the stack size for the KMSAN-enabled kernel like it was done
for the KASAN-enabled one in commit 7fef92ccadd7 ("s390/kasan: double
the stack size"). Both tools have similar requirements.

Reviewed-by: Alexander Gordeev <agordeev@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/Makefile                  | 2 +-
 arch/s390/include/asm/thread_info.h | 2 +-
 2 files changed, 2 insertions(+), 2 deletions(-)

diff --git a/arch/s390/Makefile b/arch/s390/Makefile
index f2b21c7a70ef..7fd57398221e 100644
--- a/arch/s390/Makefile
+++ b/arch/s390/Makefile
@@ -36,7 +36,7 @@ KBUILD_CFLAGS_DECOMPRESSOR += $(if $(CONFIG_DEBUG_INFO_DWARF4), $(call cc-option
 KBUILD_CFLAGS_DECOMPRESSOR += $(if $(CONFIG_CC_NO_ARRAY_BOUNDS),-Wno-array-bounds)
 
 UTS_MACHINE	:= s390x
-STACK_SIZE	:= $(if $(CONFIG_KASAN),65536,16384)
+STACK_SIZE	:= $(if $(CONFIG_KASAN),65536,$(if $(CONFIG_KMSAN),65536,16384))
 CHECKFLAGS	+= -D__s390__ -D__s390x__
 
 export LD_BFD
diff --git a/arch/s390/include/asm/thread_info.h b/arch/s390/include/asm/thread_info.h
index a674c7d25da5..d02a709717b8 100644
--- a/arch/s390/include/asm/thread_info.h
+++ b/arch/s390/include/asm/thread_info.h
@@ -16,7 +16,7 @@
 /*
  * General size of kernel stacks
  */
-#ifdef CONFIG_KASAN
+#if defined(CONFIG_KASAN) || defined(CONFIG_KMSAN)
 #define THREAD_SIZE_ORDER 4
 #else
 #define THREAD_SIZE_ORDER 2
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621002616.40684-24-iii%40linux.ibm.com.
