Return-Path: <kasan-dev+bncBCM3H26GVIOBB6X75CVQMGQELX5LAEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D73B8122EC
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 00:36:28 +0100 (CET)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-4258a2540cesf97262491cf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 15:36:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702510587; cv=pass;
        d=google.com; s=arc-20160816;
        b=ooq28Gn67s8+okM9XfnbQxCiKqul2dhS19g/ci0Ht9/dPFG9vaC7yI3vK1EgWg/Zkq
         LmczVf416l7f+fClcqSV6ZBBmBOWYhFoS+kbhcXEucfvnMLwu4oPidWSLU4FBhXBdu3E
         Jv7CqNbBXNug19pMy/CYOU3EMh1QoZBxM4pyCmiwkJROcFVUlG9kKefEh5FSxH4e2VWD
         uDbcrWmvh0K7HbJuFM8uusY4DUVWYt0jfF3YleQtphZ1NEdyWhpBl2rZ3gL/GV5kv7vh
         HHd9pRSBfE0t1wgBlctkIvFXD8OW3HxpSp7+LxjjnXFaHh9w/fh+fRabm58ETpybKtIN
         n+MA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=onQixkV+OmSEf66PunL3Jufg6nscrTbsQjTOTGZGrmk=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=Y/t33wxYYsh99vrXcBk/KYmpSRGlYM09+VjozmeA8IejxXE7bMuKVdTB4TVNS+dZaB
         /Gow+L4Q+XMfA26Hj1lOZxn4nvshkil8mJIuzZOFznFbtrq04QJVc6WzLHFHSxb4k22N
         5HhN2qMdhuZSTDdEznxGRlXdcFmfqv7AIQzpsuPGqxCoFjwBXII3cPPTHgIPCOyDOq7i
         mTnwc3WabW0LCWOuCO41nYKeAgri24Lw5LjiudwWWgbH62Ywsbs4kmcvzkDq1C448Ud8
         c0FTJNXA11VzxqPzIDMRSmQZYoOhlF07TaU2bwN3uFghGU+DTGBXzzBWWF1ZC8kLOxL+
         8qRw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=nk4LEosy;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702510587; x=1703115387; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=onQixkV+OmSEf66PunL3Jufg6nscrTbsQjTOTGZGrmk=;
        b=VGWfaTcILQ7LXO2cSizvuoyPsHZ3rqWB4Q/j76MVkD+CBo41/yE8SBjjfMOqZqDCm6
         /z+7Aqt6HbfNiDFx+YoXDLIKRaXExg9gjXgsXYIoSkeG97GP+DhQCucojNtdQanvspbR
         piCtkpfElojd1NNhOwC1xaK+G0WXq64ZoMFl4OINBB5xGdfE/+RMvQpvNQ/kN4rPmXh6
         x2jP0HZMe2BX1aQUBCrz+hVrnsjhiTubr32Bx9D/GeEqAWxBcPtOlwUZfKshJBUjPAbO
         dfRb4OgwCTb18Fm8HmhZLIfw44qKBa0whfWhViZLDFuGavLJTBPNfc6YnFpcGoypdYUE
         D/pQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702510587; x=1703115387;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=onQixkV+OmSEf66PunL3Jufg6nscrTbsQjTOTGZGrmk=;
        b=XBd3z45Stq4ocNOE+T+0i5hJ4fiL8yIgW6LoYrvE0N7I+e5PBh55ERhDoWcg1TT5No
         k/j5vaG8lAvNizdNGtdAg6ML2kPm4i4qTSsAsHntggw4jLyT4gHl0U25ewEhl464W9ik
         PMw4wlS/VlZtBray6+3S33EmRcpJ74TGuUy311+wkL+Bi+8bBLUSV0z8O+Z1WwbP+Ia3
         eREiHgH0UlnhqBNACgCrsd65fCPrkH4eB9ZeAPjVk8KG7Vi7PB7xFcXUcJ3xVM0BcaKZ
         4p9dWAJvS4Cz6T8U126A25zIG1jVbzs+zNtXZHqh1+Ry36o83SoraEo79TgTHVmx9dqY
         TbvQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzmLdiPEr3NZGPD32dCmlX8zPCK3SuV85fvMotO2xr8MeL1DMdK
	Q4DXlKTJNdbtT0c8ndBO1UY=
X-Google-Smtp-Source: AGHT+IGViI1kAFNPq0vXuaCCLKedtnRVWufjQb6fFD9kkEOEqVqtwn6r1lDr/1ZqK7RcKt5xFycn5A==
X-Received: by 2002:ac8:4e89:0:b0:425:4043:18a8 with SMTP id 9-20020ac84e89000000b00425404318a8mr12700626qtp.91.1702510587031;
        Wed, 13 Dec 2023 15:36:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:30f:b0:422:1bd:4708 with SMTP id
 q15-20020a05622a030f00b0042201bd4708ls2938314qtw.1.-pod-prod-01-us; Wed, 13
 Dec 2023 15:36:26 -0800 (PST)
X-Received: by 2002:a05:620a:1450:b0:77d:8999:100c with SMTP id i16-20020a05620a145000b0077d8999100cmr9958321qkl.56.1702510586090;
        Wed, 13 Dec 2023 15:36:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702510586; cv=none;
        d=google.com; s=arc-20160816;
        b=TcLrQWiXo7jC858YGnOvwxAANU5IVJMtjK0J5lUu4drNxlguktel1FXZTJrYyRgWL7
         mW4NohEUWPN5V9Thl3vwmlgy5Uw4gd/J9fTsRJwkekfX12+CFVLifov93G2P8GizcJtc
         nbtTts22QMRWGfkFv6M1LcOH5B9bJX1KRXPpH7bwyahoQsIWvU+Mft9esEE2QpbeVOCp
         0VRxKKxjd0D8IEI1xz5Kg1i4n91ek9Y/Sg6GwbYe5rKrXlbL9fJGx1Kbd5IEnJD+LAbL
         2ZA5YmwUX1jZO/ebYeqp2E0Crgu3pAFOCzYG2beT0DXgmYjnCUvOzqb0SqF9DfehbR+R
         i8Xg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=9jHmYIifCA/Cv8voPtUGM+O+6hs7C/6AvtqFmBPgBfQ=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=i1Z0BaC7B7fGELYRQHqQnHtKkmj+nGKduGslo6BrxkFSF5KKNHjBxXwMYixopPCdO+
         Y4eC2ztRGgkoEXpPDVeC0Lh78OVurDev+BFJ2Z+FT92zggM7RkmVwroZzb5TMk50NzL0
         v3LXLa8CiJ3ouVZY8D8VMYQenZvwMCY2w7rgmcRDZ4aOvwu9UfKnDYw3ZCpbZOaTsxQ2
         SqePZIlcapMPp5AiSH5FxB0PgHNiss89n+xjveGOPbKs7KHef73oQmxpGDvJXI9aRM13
         ssUMhBuYXv/XgDDJxwsPWBwZsVDud0vd9jV98nwW2O/pbMa3sKUG48vTf1p9Uh0ZzfpE
         DysA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=nk4LEosy;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id ss11-20020a05620a3acb00b0077f0dcac143si179531qkn.6.2023.12.13.15.36.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 15:36:25 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353722.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDMe3s0026112;
	Wed, 13 Dec 2023 23:36:21 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uymwuj57y-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:21 +0000
Received: from m0353722.ppops.net (m0353722.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BDNU3AN002417;
	Wed, 13 Dec 2023 23:36:20 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uymwuj57f-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:20 +0000
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDL4sC8028206;
	Wed, 13 Dec 2023 23:36:19 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uw2xyvrne-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:19 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BDNaGLO18743980
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 13 Dec 2023 23:36:16 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 39C452004B;
	Wed, 13 Dec 2023 23:36:16 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id C831E20040;
	Wed, 13 Dec 2023 23:36:14 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.171.70.156])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 13 Dec 2023 23:36:14 +0000 (GMT)
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
Subject: [PATCH v3 04/34] kmsan: Increase the maximum store size to 4096
Date: Thu, 14 Dec 2023 00:24:24 +0100
Message-ID: <20231213233605.661251-5-iii@linux.ibm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20231213233605.661251-1-iii@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: aeR8VIeI6zpfSNpYU8qb_ET1PqEGqPrH
X-Proofpoint-ORIG-GUID: BZJZfRMG0A4xrbOt-5TYJWqmvO4PPHL4
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-13_14,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 suspectscore=0 phishscore=0
 spamscore=0 malwarescore=0 mlxlogscore=673 priorityscore=1501
 impostorscore=0 adultscore=0 clxscore=1015 lowpriorityscore=0 mlxscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2312130166
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=nk4LEosy;       spf=pass (google.com:
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
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231213233605.661251-5-iii%40linux.ibm.com.
