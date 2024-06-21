Return-Path: <kasan-dev+bncBCM3H26GVIOBBZMR2OZQMGQETSZGT2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id D08E191176C
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:27:18 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id 46e09a7af769-6f8ee93828fsf1701945a34.3
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 17:27:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718929637; cv=pass;
        d=google.com; s=arc-20160816;
        b=IY4MaPwnLZVAmd4iSuOUkIZZjOW/y9qRVFYvRdbw9eNVO/Gte7KFRdb5zOlFdYD0UT
         pqT8qE+K9XJNj72E2tPhl8GxBWQO/nsp6bjyCeSDIYj8pLMTN5FU+oRS77zhtolc4GMf
         mXdOhs1UOlOolRyZtRLHRTEYWN3g3FtFbajA0fyMAb7cc1MCzVNV/qG67ybm2PNVCxNy
         HP3Qqd1caNWV118qWxBxmunvOK5t7AVBQjEhlVjxJaQi1sPpb9yQ2rF2MJGG1xO8rtEf
         lC/OBqT/gLY2yHvvKjXyME71ahMXMD+l/YWpLRKBpelstlO71rEiaTDLHv87wuNdNAu0
         8a4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=EBIjdRZ+tkKoV+ewLs1FNspe8BhaM/hQjBLUtzaU3xU=;
        fh=Lx/HFSxGNZns1Y1YejAcRfEXYYSnyq0br7ThXDY1vpI=;
        b=bOS8JRcasyHjRWj7D5lys3C9J2CLfXlGSAseyaRL4VbpYaHttM80gjubftvBU8e0h2
         7H3Cz7stZiCAa17ybnQXn0TwL2Y2NjdC3IR6xqh//4hazPLXWeux+rRDAJNBngOqHQjW
         KKbN0sirnW7iSXSNTAP1WI76VAYmWS+lYlgG9fCIfNGal0o3XjyxTMHxx3aoxg9Q8aop
         4K0C3tqSEe9C8R3jFGQsfb+vqJunzIBqk0lRaOFU6QE/cH3aZGqlg44r62Rs/f4GMgHR
         sDp9ITwm+7W1p+byD1H3Ltrx/w52LxvbG1W7B2uOgvAiRahh80OzuqpDhVNxkHS+ZVU9
         ZIJA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=aIb6VgQ7;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718929637; x=1719534437; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=EBIjdRZ+tkKoV+ewLs1FNspe8BhaM/hQjBLUtzaU3xU=;
        b=HCxgzZl0SqJ72SHB5j41CXc+ZRZht4Hk66OeSZ9V9JnoQbCCeJTSia2s5uansRyVjv
         aeRdcaX2e5SpaLNd7253hbg64Xuyzn3XRRLkOwp+aFMqGdpI6dJX4ukHrh5tBatFSIox
         LVKXayHPLPuVQCzM9zb0rPrqIgUpXJ4tmDgwrG/ifw1h12osSYTQpdZEqDv2xnOW67fn
         obfyePOC21o33xhyNbcnYZTICGPaa0RnGcLRSsPo3789opTcuFL+2tZz6I3+L0kk/LJ0
         A5uHmbOmf7wpxFdV70wpEDv+0dNRyyaVjL4TyrxTjkr7NJjt7D+6HHMdW5hSC51LmFBb
         I2Xg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718929637; x=1719534437;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=EBIjdRZ+tkKoV+ewLs1FNspe8BhaM/hQjBLUtzaU3xU=;
        b=CpUoJFKjpuq1qIS3lXo/9seAUrni3Fq5mLB+n0p3X8rDkIJkk8ldI4g5kwUMFO2GbX
         MTxllwJ74iOTIPjLGclLBS1cawrTnTuO/bDOr+uxGkJaSZmLJKeB5ejUzRP4tiO1XN10
         oYpAMvgkkxqia7VHl4sJu6kHK9LzHcUlLw5UQmOlG2dpbiojLCXJL1VfQ3WBUeaVc0TE
         HtmLdyyoyNCmriLsjEoZap9Yipyar7Q8bpdr0JSKesMZQykqyKmIS2fNx8IsNhKpVh26
         tTKSX1Qc36jATA3SI2v4oV64vqrReX8TP3ESRY7iXzU94HPUIIwNi5WQ8RLWLG7D8uvm
         /SSw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV2WR7oeJi1+gPBvL4XWiHmNDR00WtlUSI/VgGBsj/Erfja0y0u7O/qZYNQ9KJ3GW14jILE4z+KWqQJOMliRIcJhTWvnk3ZRA==
X-Gm-Message-State: AOJu0YyyYE2eBWa3a9td7iYMHbOf+VLBcxKAW+encwi2n57y67OGh58N
	AqDRkQV+Bq8FFtihgIOYnN8YzXECks9tsQO0se9i/H+dwDdRWc2b
X-Google-Smtp-Source: AGHT+IGi133eCmmnD7lHQZPd9/xh+A7r3cJ4LDyHEttrqvY1X+67W+yCSUmtF3ORCLr9AKdhIJpNcQ==
X-Received: by 2002:a05:6870:d38c:b0:259:89af:7af8 with SMTP id 586e51a60fabf-25c948ec9bamr7572960fac.10.1718929637362;
        Thu, 20 Jun 2024 17:27:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:1602:b0:25c:b2c1:8559 with SMTP id
 586e51a60fabf-25cb5ea521els1478186fac.1.-pod-prod-09-us; Thu, 20 Jun 2024
 17:27:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXUej0ag+kgUQ/saCBpNnLkeEsTP5nyVClHAoDrE1IF9AyvWGbOROuxz+r3YuXls2taTPpeOg5fpF8jWwJxPOtgc4LtS6S3bkdVpA==
X-Received: by 2002:a05:6871:29d:b0:254:cbaf:1208 with SMTP id 586e51a60fabf-25c94997ff2mr7784674fac.18.1718929635938;
        Thu, 20 Jun 2024 17:27:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718929635; cv=none;
        d=google.com; s=arc-20160816;
        b=Ze5mh5uM1t09vvO/82BEqeCLH6AHOd5qJeFJ7RpLmy4pLtovnONzLieDVwWxHwmBCF
         hrj4+QookcUYiE0wC7s73pdvuT2SigMXCIe/2YrrZRi5/moRnU8aq7LkPOT0aVQsKEeV
         E873GOTQ0FeSBSFEFjF7cffbooOIAu8WZNYnVI/1BDUWg1kQ4ucLJ1AfVrkZ1PHOQu74
         unjxq0HbTL5iXZQwnqaH8PctOT4tbThFU08FCC8wt4t3avtv9FEFUaphDVS/0aPKkoFN
         J1lAjR1r0z80SjErt2yYu4vmtuhO28ox6yY5Uc7NqCGBoGSFB01qJ4bcccgm6uoLpEir
         YcXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=7JeBzaeHcq491tpoSsSSp7r/Korv/EUFDTbEVwfZL58=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=lZ67zDdpQpxnf53yhGnCLcI2sLuDML+a3RlX46oqA3RoPj92B+5jjFGTb02a6PQ61v
         97zds7swbx9/Xn1V85sMfp69H1vBeLrCOnKkiNSAzrORfZU+qD0No+ZSI1iGVkJVtPoH
         d70mm/jzep8Zpj8734jd185jRgWODX5EP0ESn/KeEz02m3t8koK9q57YDcgrdrZO5uHb
         39JwNdJAsrCbMWak2Ujv9++p80TRgMdcpAvfg9DID/s888irljMAdGIBJVpPo6h3qBhX
         /oLZ/PdYAA8UkTmZQC4Bqq9SVw0BnDLpqbkpDVXXRAkm/xBxzOBCKObxuuMVx7HBllgc
         0lsg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=aIb6VgQ7;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7009c7e448bsi17807a34.5.2024.06.20.17.27.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 17:27:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353723.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45L0R0sb029514;
	Fri, 21 Jun 2024 00:27:13 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvw8m05kr-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:27:12 +0000 (GMT)
Received: from m0353723.ppops.net (m0353723.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45L0RBvd030721;
	Fri, 21 Jun 2024 00:27:11 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvw8m05kk-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:27:11 +0000 (GMT)
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L0GVt9025708;
	Fri, 21 Jun 2024 00:27:10 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrqv2nqj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:27:10 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45L0R5MQ46465358
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 00:27:07 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 3FC7220040;
	Fri, 21 Jun 2024 00:27:05 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 1F5E82004B;
	Fri, 21 Jun 2024 00:27:04 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.44])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 00:27:04 +0000 (GMT)
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
Subject: [PATCH v6 37/39] s390/unwind: Disable KMSAN checks
Date: Fri, 21 Jun 2024 02:25:11 +0200
Message-ID: <20240621002616.40684-38-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621002616.40684-1-iii@linux.ibm.com>
References: <20240621002616.40684-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: Xga3aQKnQ9DmJLZYRCoEpzCagVb5KSSi
X-Proofpoint-ORIG-GUID: 13yGShyYUNJcAcP9nVDWJR7b0NO4Emrp
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_11,2024-06-20_04,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 phishscore=0
 priorityscore=1501 suspectscore=0 clxscore=1015 impostorscore=0 mlxscore=0
 bulkscore=0 lowpriorityscore=0 spamscore=0 mlxlogscore=886 malwarescore=0
 adultscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210001
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=aIb6VgQ7;       spf=pass (google.com:
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

The unwind code can read uninitialized frames. Furthermore, even in
the good case, KMSAN does not emit shadow for backchains. Therefore
disable it for the unwinding functions.

Reviewed-by: Alexander Potapenko <glider@google.com>
Acked-by: Heiko Carstens <hca@linux.ibm.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/kernel/unwind_bc.c | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/arch/s390/kernel/unwind_bc.c b/arch/s390/kernel/unwind_bc.c
index 0ece156fdd7c..cd44be2b6ce8 100644
--- a/arch/s390/kernel/unwind_bc.c
+++ b/arch/s390/kernel/unwind_bc.c
@@ -49,6 +49,8 @@ static inline bool is_final_pt_regs(struct unwind_state *state,
 	       READ_ONCE_NOCHECK(regs->psw.mask) & PSW_MASK_PSTATE;
 }
 
+/* Avoid KMSAN false positives from touching uninitialized frames. */
+__no_kmsan_checks
 bool unwind_next_frame(struct unwind_state *state)
 {
 	struct stack_info *info = &state->stack_info;
@@ -118,6 +120,8 @@ bool unwind_next_frame(struct unwind_state *state)
 }
 EXPORT_SYMBOL_GPL(unwind_next_frame);
 
+/* Avoid KMSAN false positives from touching uninitialized frames. */
+__no_kmsan_checks
 void __unwind_start(struct unwind_state *state, struct task_struct *task,
 		    struct pt_regs *regs, unsigned long first_frame)
 {
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621002616.40684-38-iii%40linux.ibm.com.
