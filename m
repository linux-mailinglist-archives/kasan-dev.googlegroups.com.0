Return-Path: <kasan-dev+bncBCM3H26GVIOBBGGU6SVAMGQEUUIYNTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 20BB97F38E6
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 23:07:22 +0100 (CET)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-35b069d2809sf23171795ab.0
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 14:07:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700604441; cv=pass;
        d=google.com; s=arc-20160816;
        b=jS3vI5YlwhZ+qOOC3Exvomrz/WMItseFBkfe82KmfL7yqfqEddP83UsVGhf8aQ9Bxm
         nNBGfdz9RrgQV9pvFAh1pmL7oZLl3rw+0XZJ7OBoINLvhLaQHiJv61fGmPYiSklslrat
         tzbof4iEmasxTRoNoxBCHoaEbMc/YviW63pKOkA7wuBSIWk6uT5mQQd/1oW/eJJnwXBl
         rJ36rvaw/0HqRhkLSthfTyo4kUMXRli37lWeLItjaLGHk7R7Q9UIbmBfzxBybdAMmCM3
         4X9KpPXAll7rqluuky2EkB8X/iBf80Bfl40ClNaeZKecGxAnBb7TUiBHQHUn+0G9b9i5
         OMzw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=u3wxy6PGpcFFhG+u9zL/3aTs0WlyKZGEFc5Gr6G3k4E=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=BlViXLWSKW3NI3tshZ9oeyK8QXsqt3o13Js49qxzg+EUbaqL+XOeADYC/kgA7n6j/W
         /vxcG3szrJD9Unh4x+STO4aF8NVMvGPd/TCBmeCBqotLOcdzaddTHhJHvW4ABoc3E4QL
         NXv8485gA1iASZzpl1mlr09+ZpQ+PMRF3KQBJ14sqLCXr5T7MHfNwCodkOsU4azj0gFF
         Uouk4K7n0B83U85Qzbhk9VbPCLF4GfZ3EXTSErg/4L+AAj1WxK8cY5U7C4NRAH67Ol+3
         67f3veK3WHzuXMO7dv+MsPOnCczq4ZEvMWnMV71mxFRRtRouELQ+IxG+HS+pIlNWSBQC
         qk1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=YRgWP0wp;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700604441; x=1701209241; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=u3wxy6PGpcFFhG+u9zL/3aTs0WlyKZGEFc5Gr6G3k4E=;
        b=bayBfBM9wZMFl25LBLoGdvhqukW/jkmzeCHuXCh8iRF4c5KCfZ6swAZFB16HDU5xCb
         xqGf0kk0eKow2i41BSwC2woly2ICd/5tBStgAuuAuqGAOLpMS7eT7D+I7Ta2Ne36+kJM
         ZBJqOpGtrQsSmCOMnuIrGSiObLlHWU+YP+QqLpPJRx7yfR+zQ0gmA5fvjyjrPJ7CgpcU
         5NeCSjzEySIm/BP6LIvjg7PyBR9uqJfLpxeoWPToCXKO69ogdqN+LdpIAgTBOuEdaoxB
         ZScjfv/eaBhhsezk+krbkf7uo2CQVA/wNDp4mPWjmrEgnMS5ZWLB8jKKKifKlON9JS9f
         3mLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700604441; x=1701209241;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=u3wxy6PGpcFFhG+u9zL/3aTs0WlyKZGEFc5Gr6G3k4E=;
        b=TqefmmCyUsVCDGHxa/uuektVQYgAmGDMcyaK2dJNJT06Ym9TIccRRqPHC3opJIhPKM
         MrUxO1s7oAoSvRPNjHxe2hRsjHWSHwUKfCou3KdYr0na6olbmbdeDrLcNV15VA/njWOG
         RiJ6SdUbwkbSKiMH8E9PnXJvaAkDOd6pv+etIxZMjAdksoKFD1xLoco0eN2Js/zmAmzc
         u0Z9h25zfsdAnIcKRZaTJy7RyMnTSpy9kmM0hTut9Gm6W3fLw4ZMfqHGHEorPVtzJCYe
         wrVfL+/wkTF9G5neE5SGWzOJQmEMQPL54HD1QhsE6sX5s/1Kri8Uu4wLYvFmA7iNAPZv
         wzcw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzizictEPbgh43OkKIdSDj6+hNqgR3e2xuWAnOlz52hF8DpWiV5
	4REJeITzlJO8/flwQVHOGGc=
X-Google-Smtp-Source: AGHT+IGMDPdk3NlEw6d7lsWF6y/1SFzwLH2G1t0ouy/zs+rijgeW0N+ggdEm6ew3vp4bVUILXkleqA==
X-Received: by 2002:a05:6e02:1d91:b0:35a:d61c:fa30 with SMTP id h17-20020a056e021d9100b0035ad61cfa30mr424875ila.0.1700604440939;
        Tue, 21 Nov 2023 14:07:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:2611:b0:35a:a617:5f3f with SMTP id
 by17-20020a056e02261100b0035aa6175f3fls3791772ilb.0.-pod-prod-09-us; Tue, 21
 Nov 2023 14:07:20 -0800 (PST)
X-Received: by 2002:a05:6602:25ce:b0:792:6963:df3b with SMTP id d14-20020a05660225ce00b007926963df3bmr218376iop.14.1700604440342;
        Tue, 21 Nov 2023 14:07:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700604440; cv=none;
        d=google.com; s=arc-20160816;
        b=nXYtvaTSpg4L1ojkNuuV0dOT1R3kqF7SkuTFoqr+27p0H5njA0NrAhB3k/nqFvjaBN
         ymH8Vv7ml1DY83I5shInr515Lw9xPftqpJ/f7y8p64Y0HiKf+EXdAhy8Q6k2zHB+5lyC
         B7nxR3Kawy3/Tfhda5yx9J/Ubr4Srjnx6QJbo7CvSxTlxVJiD8DQomogTTbUyLsPUpld
         Vh19mPtFDK/H62gV2QEjqJaELQ8eCW9USKuS6USH1x696JdFx0/gPh50vnzfxkRT/vrq
         hVjDTc9MfCIknhpjxmU4i6jd3N2RaW4hfvCdifu1/VtCQD2SpCmhGGNWTRYskwhXxB5y
         DAtw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=/jeu8ikBdkG3zT8cTTXDudBR3p8yyOmYypD5+KnSOCc=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=cz8Bb8p+ncIEDFbr/EagG6lKJzOqIGZvTaH2mXoHS4wCBk/bBIXAvWYK2QsFIBWYAv
         PXqA9yAihQgn/T05GaV3HByfZt31XidT6d5Mh4gjBIkgrxHpBRrMQDWO8sQ6d/cOhBpo
         a/I67Nesxidqn8sFcPsbpMiRHeEZ92Fu6oo23GkCck1KIfSVeghVxRGLoesWYKFIXK+V
         +nqajRgxsTH/ky3N2KjWmO5jt9FWt0R6nFAyAv6yNzi3WgumIvCXdq2BLvFXlzE64IGG
         NIqM3mWfj9P4qZzJ2No/yyySJl4yRl6BhucFVTY7I/YyWhJzeELL6RasIOfgvkqgdOq7
         Qd3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=YRgWP0wp;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id ba44-20020a0566383aac00b00439ca012a0bsi873575jab.6.2023.11.21.14.07.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Nov 2023 14:07:20 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLgcuW031958;
	Tue, 21 Nov 2023 22:07:16 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4pw8mky-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:07:16 +0000
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3ALLjHmh007105;
	Tue, 21 Nov 2023 22:07:15 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4pw8mk4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:07:15 +0000
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLnTYY010602;
	Tue, 21 Nov 2023 22:02:13 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uf93kujp7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:13 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3ALM2AvO17302090
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 21 Nov 2023 22:02:10 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 7730C20067;
	Tue, 21 Nov 2023 22:02:10 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 0FC5720063;
	Tue, 21 Nov 2023 22:02:09 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.23.98])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Tue, 21 Nov 2023 22:02:08 +0000 (GMT)
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
Subject: [PATCH v2 04/33] kmsan: Increase the maximum store size to 4096
Date: Tue, 21 Nov 2023 23:00:58 +0100
Message-ID: <20231121220155.1217090-5-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231121220155.1217090-1-iii@linux.ibm.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: z5-ZM4Gxzj6Ebmi_lGgdK9mg79HiPr-V
X-Proofpoint-ORIG-GUID: t3WD69eD7AqaziWdbzP9Q_VGrjo1ghsC
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-21_12,2023-11-21_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 spamscore=0 clxscore=1015
 impostorscore=0 mlxlogscore=696 phishscore=0 mlxscore=0 adultscore=0
 bulkscore=0 lowpriorityscore=0 priorityscore=1501 suspectscore=0
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311060000 definitions=main-2311210172
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=YRgWP0wp;       spf=pass (google.com:
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
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231121220155.1217090-5-iii%40linux.ibm.com.
