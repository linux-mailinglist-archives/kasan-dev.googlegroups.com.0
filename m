Return-Path: <kasan-dev+bncBCM3H26GVIOBB5GL2WZQMGQELBQO5GA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id F238F9123C7
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 13:37:26 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-1f71d5a85f9sf24250255ad.0
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 04:37:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718969845; cv=pass;
        d=google.com; s=arc-20160816;
        b=0CnNmr9neOIg8GdQOSvCouaAc5AuU4P4aRTnaTwn56kKlDepPq0Jeum4l3+A/Q5OPO
         EIqe2gDbXP7Pr9FfSBnxhs5LgZaJAjU5BZ8Ba+bwPpMBfsbmCImjzF0yNcg8yBHvCrrB
         SZNg+UK99N1P4QSLwMwx0zWikQuMrUTsQ7EY89fB1S6Zyy/Y763S0NARzrVPnabaTeZ2
         T2COrwSm4KC36hmXd/QI1DBx3oYWeREEMybCIwAqBjptKA2ddWWpQhyQNFYgbP1s7Sbt
         KXHlzmkGO477nLSp9TMImY5D1HqdvY19ue6dEvPII3x2k3itNv7L0vzHQrM6nJ97GSRr
         4quw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=6Wh2xtQFvmu5U1PNx2muBcbmdRPL030bxeN2yZxXn5M=;
        fh=QOYx8U5izR/HYdOgwI+qU1IY8emGzFhNAjL9kJIdX2M=;
        b=VN7AwZWh/Lv/V8CIrwPYT/KOPQA6TWVTqqc92y4m52hR6KPzEjdulNJBd1S627q8hz
         +8yvIfj2Qgo2hswLqII8WJQgdOFoKQ7D5qgjC/GcJjykF/z+o5iZmUQi8F0Nwb23SehK
         qim2BPei+pjNKfJE+LiPO2Sp6JZcehJFP2Kon6aaFEbsqnvbnb7hckVH20roAhrPutE0
         t8osBwAwqimNkGjGKuLfM/3pjm3sdkID2jC/MA9Eq4BlINd0vPefz3z2VTEbjM0u1vzv
         agE76178IO8Fb76BlmpPjba3PGCLvZxjKYBpLSP+KGVCKriKXBTZ5mmQEh2H+wbRIZ6F
         9Axw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=cs9bGDLb;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718969845; x=1719574645; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6Wh2xtQFvmu5U1PNx2muBcbmdRPL030bxeN2yZxXn5M=;
        b=TGGrYws27/qHZU58WDj3u0JK2birhSTJ2sVCGkFXW/v2gQSkK8ZSYG/jlahswjWPuL
         Rr2Of3eNXlfWB2fg6mcqYPSPzxBaLTHxZWSWnQ1ePo41frQM05xmfmz5X1UegB4YfrSa
         oUb7XmOs16jjMBAUezSY4evVOWKq7cl/w7seMn/MVjvX/W111AshcDYckLUoqyraPZGU
         Xo2gEbHJshBWeZqpda7omzzdWjMUdUvemFAsaLESqNuAF5Tma7RaxUlIhOpnvzdey9yc
         op+TZX1ec0He3tiAIn5doywx5ijpK8p31myC2nvSmPP1V4n/Z+pPo2WJ0t+seonOYU1u
         5Khw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718969845; x=1719574645;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6Wh2xtQFvmu5U1PNx2muBcbmdRPL030bxeN2yZxXn5M=;
        b=EBEdBqTuLG2cMRqkXeT+gpt4JY7NoseXwBBOPu8s7m8lDpI0XOQufJoua3OJraNQI3
         hTfkI5NSoPMdhkRCtJgtlmUMoj5tuwAKlNBY9aknIz6YLuAPPFrVFhzAHhYfDoaNf/sK
         RRRIUxKHT/0/qlhPAKhx9cnv02vn4U2bPH8e1NlTGcwBvqRE0wEczoCvvM3WlhGtSmwp
         5idcC7ZGyti7/CWriyOT9mER2Qe8VJz2vWv9lOWSlhye6dFTUmIQYc/kuEU+VE47yDt5
         kh/jfFvRafdxWuEvgqOBiz3Y0xUMQFIxqBJYqOGR0QaHyMRCyz8mDJ86rpHNMWf7eAQv
         E9xw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXLl4JABvJK8iJbXXzgnSbwVtInlgoNtTHV63zPmE5lSftDQ78qOccHJCVsFPWrV28rAII34b3eTJRXxctowFl8iUWOjo7HAA==
X-Gm-Message-State: AOJu0Yyn+VwWfpXT6l3uwMSkT000lPJwqSEbKj6mIt4XnVXrt2/UteGX
	CSR5A4oUdobRY7jR22YFoqn8xlNFCDx6qC50bDCzEYlgH5kCD9wz
X-Google-Smtp-Source: AGHT+IHb32+qMO9JDMhUeS+fAOoaCKqwQ7rOC6r79HdmljaqIR5CzQd5VUc122Bt0PSv7EL5M+J6eg==
X-Received: by 2002:a17:903:22c3:b0:1f9:edf6:d7a5 with SMTP id d9443c01a7336-1f9edf6d941mr17273025ad.1.1718969845137;
        Fri, 21 Jun 2024 04:37:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2303:b0:1f3:16fa:bc77 with SMTP id
 d9443c01a7336-1f9c50e8b29ls15130195ad.1.-pod-prod-07-us; Fri, 21 Jun 2024
 04:37:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWP2TtyP8H3IUduvJ/af5SEmhmXBhj8haiwmFseALAzoRvCWpyBjUuR6cczUGFSYDGhK0YxrwvKeAtprl9iLqu2yyhAth009jHTUg==
X-Received: by 2002:a17:90a:d90d:b0:2c7:1370:f12f with SMTP id 98e67ed59e1d1-2c7b5d935famr8395631a91.40.1718969843947;
        Fri, 21 Jun 2024 04:37:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718969843; cv=none;
        d=google.com; s=arc-20160816;
        b=kNwShgT/prQocebw53qe1P6kNT29LWNKZVnbzuiLR4r5cu0k8cQJLGG35hoZEwQfZl
         sXC+zKEEoY644sQ7t742eHJiWAl4bDyaH9INQv3MLkI1c5c/FP52piFiarqmE1GIekEy
         f4EQzEYHdJVF6Ux/r63B6YjaYJFFoOtOQfUsvsZ4tKMUq4veXto1G6VqUvcASexELJki
         oma+yy7jM1JSwehCVk8mf1/caamCqwFjCKiaOARUlW80PUTj3t/LlukMyacEbw/tbsOD
         EuWjH3jk28Vy6p3C9z70d/37yMGV9Edk8V9bu/C/9hFUZJcRo2+rtFzqQCfpdsHGlS80
         H8MQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Scz6uta8wJUcmkDwOaiOL8UogdsQpVaK9UJlhoWG7HU=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=Ya4lv9EOZoC9J9WzQZ3CmgddG9feYlsx2mxKOXRQRmnN1fU9TatM/oCvPEqnhCNp4n
         j2KSTdB5aQqPhmOTJ1teWkASiNDzUYcCYOE963R/h8lMgYiPa4n8a61uRuju5pTHCS0L
         LK0B8cJ2ndn6PEMH6HV3tn4EDBui2czxS0JVLkCfFfdXvdKa/oRepJT7r39Tv/1iGneD
         UcffJZRticEC7ZGcz1rLVwiBJ7mxZzoZm1W5CH6gX+Of+hMqU4P1NNuVh0yJAK7xp/3/
         tOVHH7EZz0RDr8N+Lk6ZCDJjj83mTOlV6PWN2EmHIufVWsOySAN9QmPR6nRCc/dFmQ8k
         XLSQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=cs9bGDLb;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c819dbfa52si60154a91.2.2024.06.21.04.37.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2024 04:37:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45LBQwae018581;
	Fri, 21 Jun 2024 11:37:19 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw6ws09b9-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:18 +0000 (GMT)
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45LBbIND001489;
	Fri, 21 Jun 2024 11:37:18 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw6ws09b5-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:18 +0000 (GMT)
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L9L3lJ007687;
	Fri, 21 Jun 2024 11:37:17 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrspeupg-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:16 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45LBbBuE21037512
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 11:37:13 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 888FE20040;
	Fri, 21 Jun 2024 11:37:11 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id F30A82004B;
	Fri, 21 Jun 2024 11:37:10 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 11:37:10 +0000 (GMT)
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
Subject: [PATCH v7 04/38] kmsan: Increase the maximum store size to 4096
Date: Fri, 21 Jun 2024 13:34:48 +0200
Message-ID: <20240621113706.315500-5-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621113706.315500-1-iii@linux.ibm.com>
References: <20240621113706.315500-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: wZIRW_dUwx-rNNfZ5WtyHnlnrpg7gkD4
X-Proofpoint-GUID: 7MrfeCQ_u52NejmfJE-8AosTU22Np6aR
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-21_04,2024-06-21_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 clxscore=1015 suspectscore=0 malwarescore=0 spamscore=0 phishscore=0
 priorityscore=1501 adultscore=0 mlxlogscore=742 impostorscore=0 mlxscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210084
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=cs9bGDLb;       spf=pass (google.com:
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

The inline assembly block in s390's chsc() stores that much.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/instrumentation.c | 7 +++----
 1 file changed, 3 insertions(+), 4 deletions(-)

diff --git a/mm/kmsan/instrumentation.c b/mm/kmsan/instrumentation.c
index cc3907a9c33a..470b0b4afcc4 100644
--- a/mm/kmsan/instrumentation.c
+++ b/mm/kmsan/instrumentation.c
@@ -110,11 +110,10 @@ void __msan_instrument_asm_store(void *addr, uintptr_t size)
 
 	ua_flags = user_access_save();
 	/*
-	 * Most of the accesses are below 32 bytes. The two exceptions so far
-	 * are clwb() (64 bytes) and FPU state (512 bytes).
-	 * It's unlikely that the assembly will touch more than 512 bytes.
+	 * Most of the accesses are below 32 bytes. The exceptions so far are
+	 * clwb() (64 bytes), FPU state (512 bytes) and chsc() (4096 bytes).
 	 */
-	if (size > 512) {
+	if (size > 4096) {
 		WARN_ONCE(1, "assembly store size too big: %ld\n", size);
 		size = 8;
 	}
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621113706.315500-5-iii%40linux.ibm.com.
