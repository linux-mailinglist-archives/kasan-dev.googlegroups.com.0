Return-Path: <kasan-dev+bncBCM3H26GVIOBBNX2ZOZQMGQEXUHV4AY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 1095590F2B9
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:46:00 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id 006d021491bc7-5bae063353dsf5165803eaf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 08:46:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718811959; cv=pass;
        d=google.com; s=arc-20160816;
        b=XRqb7NdMxd9MGK8VpfxyuUDQ03XXipspuCcsJM+QI5VRidvLFWY+5e43MKwA+8Za6L
         lFQZccigg5hsB1GIlqsU/nKINYLw+dyCoJp7oc9IjEV/Elz0D/AssEjg6yc5lenGvSfM
         lgbDsISCGU0/Bgdl5RcEgx/NlKU8YAKk+1kwiuYPcUAQtwEtlQ7yxzp037LdB2AV4snp
         pT9Z1zWytSrxJf8wlpNCwyo2mNI+8q4l/7qu47CviiFJyrIWSZojYdqrmzJHa3afp5d5
         ZM+jCuc9FGgjklXXiLKcOu+9Pzq4LfSJigRjA6NgkiUddRje93syi9XZ+L/gia+1uYCB
         my6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=2e1AuY4BfL1lQFn4rX0iCW3MbGbT6GXxhiqspf7w6Pc=;
        fh=7QNjRO90++bWghSstKuoq19Sya5VE7rXwX4MjncM9JY=;
        b=uWx5bx6wHByz0HQe2CzX7ycgsUAC0aszofNd+KjmaqPc+LdmAYecoNB/UBRNMsXmPb
         5ez6ZVCwpUxhnGE99aN8P6EIMaa3P4qy88aQm6Eep4CrFt0RP/sSTBldF5O+EhzKXTm2
         ltrerB5hcIes+1XVF9LofJvnpRMYYXgaQ42FHgf/hDXZasZjeHZKGEP9pxbWtHGLOHTg
         w4V94BvqubHdrrvsntpFjTwv1Ha1EX51h5RDWaiB8l3ENKE12YGTf3JYx7hgHSmo8DC0
         81W3o82oiBSVZ2ysSyymtRIBiqFX/kL60lrNRSaU7ZK/UnHkmg+QOppOu0+SBUILx8Oi
         iVTw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=JEitRQTl;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718811959; x=1719416759; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2e1AuY4BfL1lQFn4rX0iCW3MbGbT6GXxhiqspf7w6Pc=;
        b=vACFMTSd3W3fbRfb7ZAsGlPcUYOmXNJ9QLEnkg9svcvA9xPBrC+u8kJlapimM/eq38
         EkhYpWBhczNKDpcX3fZmbjBh02tnOYt5X4cd0RHr1zBeFCoHh8dmLEI8UrJ3CxqMUsNA
         F1Cy9adsYBaQfTyPVNm4hO4dQ1ZCv2uTF/gt7PE59aG1TbUiMgsOfvcTuXxckW01tNfy
         0cPiQoU/sh2fi/aJqoB/2wZI6LWeJ8eD+afigaEeHayFne5/vZWoLSJzXpw6qOTNOchd
         hO25eLjSR/Kl3oASdaZqwaQHb/GeyBTLmO2ZMNCE/58+NZR3I3/+VHBvbGIG3RnMc4O2
         ylMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718811959; x=1719416759;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=2e1AuY4BfL1lQFn4rX0iCW3MbGbT6GXxhiqspf7w6Pc=;
        b=nOkYpd2+947cXvrHLyFe98WBOthef7gfTAUe7q6d/aF1kDe3RwcMgudfU8uhYR9BVg
         9uoismF4FOY8uH4lt3mfkx4uQOrlRykVk5y9R+y40Y+yNN/KrvQyMOBfBryURnLGsQLa
         OznuegH8TtKycPnR+eeP2zcCSk+YCxxlWwQNFsYhAKzvHvpYyvFI2J0+/B1LJLUaAZ1u
         Qu1k8Umldp1Nef/UVsRsSZWEO5rgAzrEDX0MIIriCECx6SeO562rmeBa4xyO4gYYxxPB
         O43qD/UHO0R6sqlYyY2Eusuen0ZoS3pcmnJ1IhukZlB/AEpCtFsO08fZoCRBDGWYciBB
         efBg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU2lJwv2dHKB2fgWF/fhWHNPlVQQm3uqDHn7DrvgZnjcRGOXn5Z6YQC33xE/SJc7h0sFI9lvVtteLSxwKQ9MZ8QGgeno85ptw==
X-Gm-Message-State: AOJu0Yyaco93DuMvML9ewrhBvDJkVFC9Ov/nTiW51/YusL0i+RSAiEqm
	YgX7z4O2i5+i5dCN9fii3jDsG31QvGPEB8bpHsJVBkcLHxJ4WIko
X-Google-Smtp-Source: AGHT+IHe+Aw9jNhMJgBPPzfuDAS7kzzSl//ROSEYkAwKJYQGRR+//IBhc9y2pMG7hHAEX2Ph5vxaYQ==
X-Received: by 2002:a4a:d29b:0:b0:5bd:15fc:8feb with SMTP id 006d021491bc7-5c1adc24d49mr3085550eaf.7.1718811958911;
        Wed, 19 Jun 2024 08:45:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:305b:0:b0:5b9:db6f:1115 with SMTP id 006d021491bc7-5c1bfcf802als8414eaf.0.-pod-prod-02-us;
 Wed, 19 Jun 2024 08:45:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXSPXGtDzS8yg+ZYrpWBO8U5NRoY2KrZdjO3LALxSIWVRC2bIf6GFxdGoDz8chhCmxHAuiHXXyVXJjca0GpM0gPFkjO5vROrUm6sw==
X-Received: by 2002:a05:6808:15a5:b0:3d2:1a92:8f4a with SMTP id 5614622812f47-3d51b9e2082mr3658467b6e.23.1718811958047;
        Wed, 19 Jun 2024 08:45:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718811958; cv=none;
        d=google.com; s=arc-20160816;
        b=sN/DMrGMBvlC8OJzcSlNFh4ehFfgNy5YDEMuSVkrWoK8vGh0lkOSj46tE6smGJMbcq
         3HF7ob/cKFC63Sfg6raJ0gC+A9j+ZGfqjWEuLktMD4nThDs8kfeWU5QPLnfsebt+KFQ0
         UFsacGjn1aBz+ZzHSoXM4+vbfgzGBgziLkOtoYDSWOhW5T4SSQjLse5VV5eZ9vKdc/Sa
         /wtJVER4CjDeyhz9DhMK6yH9vitSMrFa8VSr3u93mtTpuFv3U5sUlgC49Fdlb6vSsk6W
         n0WwA6x213dQ+FK7EOqpSQCyQ+RiR0AiFZCCGe4mhYyg4fNqeiqL46WZgQjROM22Zb5z
         v/lg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=7JeBzaeHcq491tpoSsSSp7r/Korv/EUFDTbEVwfZL58=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=MhRwb4cvzNkXS/9If10M3YcTuNd2Bg5ig8I26GbwJkbud2ikGUSnPSUP1v2yc4SM6f
         fLMH6W4ZS5Uh8Hka+IF7S6Bqw1HTZzGqISPg+bhOuK2mfH0Pi0hdxnOKaKMCPQGMO4qB
         M2EYhiQSF4kKcmFFmnC4wiusy0UjiGsgQ05WjuB2ZAzWIpjKp/yd0QACsesVOUqJ7IlH
         wF3CyzBU3lFiIMLnctNAUMQTEUf6BqBSORFEs6jveluletXL7Of+mR5eRDbd9s4kP5bS
         6Gtj1gjgviD5Wa7uqHRbt+2zXbfcT8rmmvQ38irJ8OJxhm8dDBRsbB1bFPdow1tRVp07
         iw2g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=JEitRQTl;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3d2479698b2si584074b6e.1.2024.06.19.08.45.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jun 2024 08:45:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45JEwexA003074;
	Wed, 19 Jun 2024 15:45:54 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv1jg854d-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:53 +0000 (GMT)
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45JFjq8B016396;
	Wed, 19 Jun 2024 15:45:53 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv1jg8548-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:52 +0000 (GMT)
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45JEN1Zp009422;
	Wed, 19 Jun 2024 15:45:51 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3ysqgmwmp3-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:51 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45JFjkcD16515562
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 19 Jun 2024 15:45:48 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 1258E20040;
	Wed, 19 Jun 2024 15:45:46 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id B7E8C2006A;
	Wed, 19 Jun 2024 15:45:45 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 19 Jun 2024 15:45:45 +0000 (GMT)
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
Subject: [PATCH v5 35/37] s390/unwind: Disable KMSAN checks
Date: Wed, 19 Jun 2024 17:44:10 +0200
Message-ID: <20240619154530.163232-36-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240619154530.163232-1-iii@linux.ibm.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: wuSJifTVMkWwcUJW5ETMmMRM2X1r_jtT
X-Proofpoint-ORIG-GUID: JX2DUdO-peLzJHQPotyrL20VIX6eOPir
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-19_02,2024-06-19_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxlogscore=886 adultscore=0
 suspectscore=0 spamscore=0 phishscore=0 bulkscore=0 mlxscore=0
 impostorscore=0 priorityscore=1501 clxscore=1015 malwarescore=0
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406190115
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=JEitRQTl;       spf=pass (google.com:
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240619154530.163232-36-iii%40linux.ibm.com.
