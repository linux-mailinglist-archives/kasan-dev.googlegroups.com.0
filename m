Return-Path: <kasan-dev+bncBCM3H26GVIOBBSFFVSZQMGQEF3GESHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id E53939076E1
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 17:39:54 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-2c2d2534c52sf1000199a91.3
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 08:39:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718293193; cv=pass;
        d=google.com; s=arc-20160816;
        b=wlyjOVrz2FAIaXjUC0NTrjo5A0s/Nolj8MYyYoz2fq7bGZjqyIxnctfqlgq69fkiAa
         AUhVpJEh0CmrgqL++JaU4RK3HC511dN5MgZCgQoCxYubv24cDDyQ3NyCzTPqXV416Ay7
         8Rux1T121zGAWl/RKArCWnwC6KXmmmScUHAiJZySFncAJYZ74Ocg4w8cmtQEQTmkzx49
         eqsT3vhgpl7yqNFFuaFC/Ch2L9OE/yqKbSt4kgK2eLnrU899Rc3u2epkKw1xCOItjNA9
         5NaZ9sondPAyabGhon4ugIIF8OquTkW4IIX6+bYcLQLRes5McHvLuPmrCzzBUcVzDN/P
         s2sA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=j9fpoeEdIG5XC51qouWsS/lEf3Kd18tASxanWkS2810=;
        fh=G8+4L4E/w3LUEg/G5+nj3ft/peTDL3/LLgPcrQmX7uc=;
        b=We45e7bVKFlwVmXQ99D5cLU2V6p9Mg8EgYfUVA0pMEeJRfgOhXNLBFK367jaW4PHMM
         Ke85oiphQuzwcpDbt0vWr63ZCHGvA7ihzzUKi8QiUZvd9Ckjm8d+CW4B7YXrmu1u1VEw
         rkLSmZ6iLKpoFmila8gtY+1MdDdGnnhqp5OJOAkl6Tjsdfbd/RBGFjNZ4RGYRO3Zcto8
         EE0thdjLbyNJyPDtrCxhsVmpWitf2DyW+xSHtYfTS/MsI+XR5pa982HzLd1opsjDHAFS
         pem/veuYlEjXxJBCfd8EOTdnOFZvfE3kjlKOyyLuUQ/vgDkm7n1pvOOzLkQbTuB7GMs4
         gP1Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=C9B3gD6x;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718293193; x=1718897993; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=j9fpoeEdIG5XC51qouWsS/lEf3Kd18tASxanWkS2810=;
        b=hIo53heW/wX2KRPLRiMJATSYsKG8RKPp+1oqLR1OgRyTrmWzAe8hfFELGXFq3Ibelh
         9Ze8D3BYgvfmc7LtKD50rNMxEW0FFEr18cpQg1RrfzOzIrXpEVax4xzd0B+0jwCX1ozy
         2DTwwgoa3V1PY53cL1wOHfi6enwBqsx2RdVLXCE6531X2oFe/fKcBw6fsXVvIee5e9Zh
         MWZ0pNNyqc98JIR5TYbVl7q6INxfy7xGlSg9rWHbPmgtTl2UcUt7XuqdcXT40parxb+p
         zFXZwqfB8NNyr63LROS2RcZrUUHzMMga62XAtZgzkIwNB9bae+hD+Kh2oSIdmHYUnIRv
         iLIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718293193; x=1718897993;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=j9fpoeEdIG5XC51qouWsS/lEf3Kd18tASxanWkS2810=;
        b=lc1zz0nqjKxerJXWGXpEcENAjjnySMfMt1Dnq0F5adJeW77R3xd8ZEetnwhhRQ6C4p
         gmPvytnekGLOYs52mw9tdTRTNb8oYWPFg5k+WRZQs8IpKVrGw/xrO1WNYw2SKl5nRtn3
         EptKeZ5vM8ssw7EtTr53SZA+C+UOkMekuo2cfGFbrgHsxQmWYg0Zw+mP5dyjygBRiIir
         +UFRb9woW8T4KqbA5OT6YYkVvXkt3CLwVePFgrM3bcbmwxaBbHuV95YRCgse1/gROnui
         yxPQcffJGL8+IaU+IC2hxmElxWqUH2TN0gG9nr+EtlHP+Wwabo6SGIdQrmx/oWyq4YCw
         dKmw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUHSZfaO5elODxsZ6KX+fRujBrBseTWOrQem4ZusSec7QdLAL5wwhmCFvKsh90nQESTt43x3DhSZmxcwrsreNrQo5S3nNiCjw==
X-Gm-Message-State: AOJu0YyrsRp2NxFotKoExN+h3RMei7ka5KUZXt1X4zcWHC9QJ6ac8K8n
	XAF1pSRGNCOcAiXd5Vht9BtU+5Ef6urIV0wrPrnou6Hd2WbB0RNd
X-Google-Smtp-Source: AGHT+IECfcr11jjbXDPcUIW6RVLgV1C7OeOGsqrzXWKDSIdJRqS4ozjNh2h1uA73gUbwnBlzQG4i/w==
X-Received: by 2002:a17:90b:148:b0:2c3:8c6:f827 with SMTP id 98e67ed59e1d1-2c4db1319d3mr144649a91.1.1718293193079;
        Thu, 13 Jun 2024 08:39:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:520d:b0:2c3:1e98:ecbc with SMTP id
 98e67ed59e1d1-2c4bde91b67ls138439a91.1.-pod-prod-08-us; Thu, 13 Jun 2024
 08:39:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXMMTg2rMxjEELGTXan7XaHKsBXsWcgGtqEfWnIAM5/0ueTDhcu6uW61URSwYFFYXGTqRTQ7xmkuyOUv/c3ZAxfd1FrbSFMeHhYyw==
X-Received: by 2002:a17:90a:fd13:b0:2c3:38f5:b3c4 with SMTP id 98e67ed59e1d1-2c4dbd440b7mr106334a91.42.1718293191931;
        Thu, 13 Jun 2024 08:39:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718293191; cv=none;
        d=google.com; s=arc-20160816;
        b=u7akRK0P0IONNMOa4A6ldYJbx/ftqcbQSDMKKvixbRSMMIUAV9mTZ0u7k8IYX4PnRw
         NjYp7qSVjXhnqsLoDGX2Yw8xst4Y2cNDG4dbT4iC8uWklCMVhyw70DVNCPIsHiUDp0y9
         h5oR9yH2/wNlDGPRwAvUCoOmhbjVvrTcnxfCEHY7KG6LgrjJOnc4P50M8+JCfnrSeDP3
         n0BWoY+ADuSJeRrgW8jNxlBLBvZxn8OYGCt1lHekAtTFhe3aDateriJf77jgxzMI6sNq
         XHRMaHO5Q6awNZv4KFueW8ra6ZWLdiw5nGlgVc2YNqTgm2BjCRf2KfHcBOYJGngB2bq4
         hkxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=CQQ3u2h7dcFLBX9YiN0MD8i5Yqiqh3Ez2ST5U0/0yhw=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=GAUPIRJHYklX59mEX/C0Wrc9mda3q5nDj2naQHHNAaTEHq87I93rrOgFqlxEw10IVF
         tNZ3ehanSlAExllWIu45hkRilF8Y0pEqCxZA5a5lt4D5WeaJNe61toTKr3gHznsvijFp
         yeVz3XNKPP/nb3nFrfKrof5sjf5sXaNK7g/4SXRu1CPwNFknYNeSWghx4HDZ6gICxvZL
         37HdsClGEJFw6rP7jBKkgfTDSfzOi6o1PJxmB5Ayek2ArC3RQVuu3DRmIxBTmFv9J+Ud
         0Nzn4JDdm0q9X1i+IlknkCBMkUtBrywhZykjq+Pf5Y5IGyb3WvuMex+2/2wORxwspB2s
         A2aA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=C9B3gD6x;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c4a60b89e5si228857a91.1.2024.06.13.08.39.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 08:39:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353722.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45DES86s002416;
	Thu, 13 Jun 2024 15:39:48 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yr1rbgdef-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:48 +0000 (GMT)
Received: from m0353722.ppops.net (m0353722.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45DFdlFo014327;
	Thu, 13 Jun 2024 15:39:47 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yr1rbgdeb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:47 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45DELP7P008731;
	Thu, 13 Jun 2024 15:39:46 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yn4b3rk0y-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:46 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45DFdfJD49217960
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 13 Jun 2024 15:39:43 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 30DB420065;
	Thu, 13 Jun 2024 15:39:41 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id B299920043;
	Thu, 13 Jun 2024 15:39:40 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 13 Jun 2024 15:39:40 +0000 (GMT)
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
Subject: [PATCH v4 15/35] mm: slub: Let KMSAN access metadata
Date: Thu, 13 Jun 2024 17:34:17 +0200
Message-ID: <20240613153924.961511-16-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240613153924.961511-1-iii@linux.ibm.com>
References: <20240613153924.961511-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: i6q6hWHhRl-wcxMBB5jGTOrB5o4Wtw90
X-Proofpoint-GUID: Hdll2VtH1-GxrpJV3pG_l093JfGpbX5F
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-13_09,2024-06-13_02,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0 mlxscore=0
 malwarescore=0 spamscore=0 clxscore=1015 bulkscore=0 suspectscore=0
 adultscore=0 priorityscore=1501 lowpriorityscore=0 mlxlogscore=999
 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406130112
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=C9B3gD6x;       spf=pass (google.com:
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

Building the kernel with CONFIG_SLUB_DEBUG and CONFIG_KMSAN causes
KMSAN to complain about touching redzones in kfree().

Fix by extending the existing KASAN-related metadata_access_enable()
and metadata_access_disable() functions to KMSAN.

Acked-by: Vlastimil Babka <vbabka@suse.cz>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/slub.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/mm/slub.c b/mm/slub.c
index 4dd55cabe701..a290f6c63e7b 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -829,10 +829,12 @@ static int disable_higher_order_debug;
 static inline void metadata_access_enable(void)
 {
 	kasan_disable_current();
+	kmsan_disable_current();
 }
 
 static inline void metadata_access_disable(void)
 {
+	kmsan_enable_current();
 	kasan_enable_current();
 }
 
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240613153924.961511-16-iii%40linux.ibm.com.
