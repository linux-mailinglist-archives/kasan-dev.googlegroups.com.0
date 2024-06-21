Return-Path: <kasan-dev+bncBCM3H26GVIOBB7WL2WZQMGQEU6TUGCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1FAEF9123D9
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 13:37:36 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-1ed969a5e4asf877845ad.0
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 04:37:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718969854; cv=pass;
        d=google.com; s=arc-20160816;
        b=bRkAnKB8Jpy6I7wnZq26GN7pyz5KfCJs/xUcaB6uQwVnECQk7PqSzqqZOQPOgTmT9J
         r6itbe/nt3q6r1Iv6jYWEir9L5rY+QjZ2TzFSwPRu02deqkLOlktm8OBe+G9cGNkgqLN
         MQ633exEOHvc3wP//qcF3bGQqbawxXIdAkvMoF+E5YbPngM9Q1FfX9IYagto33xVS8fZ
         LC6qm9R3M53ssnNqPs9fpC2nl1AO3r2emDgcV712AajbEDhyy3NNlLq90l3OAN9efy+R
         K6ZxEA0+onarzSLt+ltM++rFc3HRX6ERxDfT96x2aAFxeFrCf5zFv+TYTHuhVmOpIpAp
         Te3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=TG/zZG7/OIx4HkVFV4DiaOJBM0KPc+woZDQ+IgCotnQ=;
        fh=SMn3sriJsticvu8vH5WfDkih2KwVqlP2+hjY9WqGjZI=;
        b=j+HS9X+llH4IGu3DDD7bKGkkXJijguaZJWUJLjjQRB1XJYwhK2DjlCy15qj9I684yJ
         86jvyPs+qMmBk3xdnQwaTVgiKMWvixm21mdsEk8yWsE0oCxeElESkQnyHSPfj8LOoXYH
         47jhe5BkZGUnhAEiIozyerjNFl6C1gAscUo0uO5dhnrmlGDorovpA+ILt9BIVtD4OhLV
         gvGij2JEB/OlTe1lm2ospFpWBvxHjbv2aMop5c7GLHEzDRlzujMkI+UHF5vrWAmNFK0r
         H/oi+pof6WmmlTwsJpITRCACso5gxncTgOfuGBQlUTOP9ZOF4SsZGf1FnYPSrdCEuyW9
         pqag==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=BVvfizPq;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718969854; x=1719574654; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TG/zZG7/OIx4HkVFV4DiaOJBM0KPc+woZDQ+IgCotnQ=;
        b=FVO9fSfdDUwlQfz6OO5kcBWgS2lCvHP/9GSM52qZuBnl16Uei4U3uVlc6gnptqpx0q
         i0Q23xCzl3Nr1xPi0y/jVkxZEZF79vbE9fIBp0PNS7xHjQLUS3Kn7phL+efGMV1K7SqA
         vk0Vqrwxx25S95tfbMma7OtFmBgF6/PzelgakVON2jmn+rkb9zibkMzgCt1L4AHrq9lm
         YbXMZXVaKmpnlremo52wYO6im3x9cXyHmm1DXMwOXTLwRfqoHp0V3/7lWbzm6G6FKSZ+
         o2uaazTBXL6C6l5BpbKlhlpFExENq1dtSTJvUxn6cxIvHLVKSeB+PPmrlt7w/a7uJr8R
         DORA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718969854; x=1719574654;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=TG/zZG7/OIx4HkVFV4DiaOJBM0KPc+woZDQ+IgCotnQ=;
        b=T/SBgD0988NOon/nqT2u0+xlC6x51UR0oINABMgWKdOhYMcxmasTVvop0MmLVrf0w/
         pVh6iGzT5hYPCZRYhC+nVZa5Jx2H58tUymjyLlLo4XeMaXfuFoWNO6woxKAEvqrlDXAO
         yuGLKlZq3By3UeymxbH0Sr4Kj5SAIw8wPSZFP8EoH7cWxrcBAslUPBecCU6IwPfbcLLh
         qARBAT5KUyZ9p2FnejtOd0Or/aqd8HYWJAaICgh/uJq/WaF9mmC8JPz26oZEVGpAhnZz
         GPDKkUAw3Us5TD5JytR0Rkk7/hapxEjoUNsMf0yLESVUWEyYU3rciWqclOeorEMt8z/T
         wPSA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUcRKOUScJ/YA48rnxIZ9bqGFvrdSKNvUQ5w0mI95wtp/R/HGx6UEG4E97VaShjbum4vbUvv9H9lM/Qmf5EnfXiXfE0/Zu47Q==
X-Gm-Message-State: AOJu0YxJBkXqAm1eCjlpaxMy/gDDWCcS4H5bFdUp4PEMb8Y06bkGD6XC
	WEcX4CN+ZPuBk51sD0+duPSWW76UONY8LsW/T/DcQXCh9AMNsepl
X-Google-Smtp-Source: AGHT+IGd0Ebiin/okWBOYZYyZXbdQ2go7Q595myu+smbdBYDXnTP8ah8/sroJmCi7ejbZh0U0t9lyA==
X-Received: by 2002:a17:902:bc46:b0:1f2:fefc:e8e7 with SMTP id d9443c01a7336-1f9e7f87d32mr2821515ad.2.1718969854581;
        Fri, 21 Jun 2024 04:37:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8c07:b0:2c7:2285:963c with SMTP id
 98e67ed59e1d1-2c7dfbec39els967132a91.0.-pod-prod-07-us; Fri, 21 Jun 2024
 04:37:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX2fdK2HCNzIO7jz8y7552dtFGYuTPjhlgi7ESIbuJ9pi9sZgGhvZU5QlB7b04ayOAay2UHYI9fqGmo1NCOLlptJU24MPH454LmXA==
X-Received: by 2002:a17:90a:ec11:b0:2c7:c7e6:eb89 with SMTP id 98e67ed59e1d1-2c7c7e6ec06mr7487466a91.23.1718969853473;
        Fri, 21 Jun 2024 04:37:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718969853; cv=none;
        d=google.com; s=arc-20160816;
        b=wXMIO/ytKCwVt0WFe6lPbGWgFNtPaDmFGmr0XedbBRHgxXQ4hJphjc8UPsDK4FcVdO
         b3byg6NI/YW8e9hf7WsK8X/VD98aEMow/7yUdbo9IOSbSzwGnzEThxwTgSPbily7dbH8
         IJ4aBRzjchgyIwinUBdxipZvusdSVPLzBBeU2GCdkA/N13JJC16BYH/Q6fBHrzx7baTe
         YpXTC6jIo8fQr/M4toSHtXfpbHyBKfMNZJFAIZx9bZ5JjRuD88yAm6i+c7ly5j6L6ywI
         Q39/VAZOpR5m1A454WRJfYD/RASPVnNieAUZkiE70XhCoZQes4cHYiAS9FW9Riz/yi0T
         Trfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=OrFUkNCKCdyNkojULrcA9z04Ys3K5qGxpLIcxQ1wcAk=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=Gdd+513GrmWFJNCzqerf2ZW/Lh6AidvWs+/jxlGwnVhJD6HZuk1BukrISiI+IngGhs
         fNBPrwbDvlH3fiLq7z4RUdVT8PD7x74CaI7GjoHFK8665STQTadN9/BosrLCsKMwMwuE
         jNBpxca/6ZC41f6l8GWLaS5TG78BYEdSpzv19NRzSZtnbL2L0KhfNsah4UlUaLjqhFQK
         LxHrh9Rih+CORWoNBChP/9ejulomPjQschtFCwhQtzS5i8fp//o6jnGi0nEUxm1eCGFm
         tJmAhBIhXW9CSetwDExxE32SpAGaJmI1Nm1qgNuj6OmTtLVEKIJQwXYwW/sy4AEqrl7D
         9lhQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=BVvfizPq;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c709e9f12asi397510a91.0.2024.06.21.04.37.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2024 04:37:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353723.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45LAToPh001746;
	Fri, 21 Jun 2024 11:37:30 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw7t80449-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:30 +0000 (GMT)
Received: from m0353723.ppops.net (m0353723.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45LBaIkc002408;
	Fri, 21 Jun 2024 11:37:29 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw7t80446-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:29 +0000 (GMT)
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L9Lx4D030885;
	Fri, 21 Jun 2024 11:37:28 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yvrssxvbk-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:28 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45LBbM4U53281240
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 11:37:24 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 8F6B220040;
	Fri, 21 Jun 2024 11:37:22 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 06CBB20065;
	Fri, 21 Jun 2024 11:37:22 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 11:37:21 +0000 (GMT)
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
Subject: [PATCH v7 22/38] s390/boot: Turn off KMSAN
Date: Fri, 21 Jun 2024 13:35:06 +0200
Message-ID: <20240621113706.315500-23-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621113706.315500-1-iii@linux.ibm.com>
References: <20240621113706.315500-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: TSC_PCcgL4u2brPpF6RMrVNuprYHxa8t
X-Proofpoint-ORIG-GUID: SuT93WsKPhYGRA62ysZuVSH9DSmbhz4u
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-21_04,2024-06-21_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxscore=0 clxscore=1015
 suspectscore=0 bulkscore=0 mlxlogscore=752 spamscore=0 impostorscore=0
 priorityscore=1501 malwarescore=0 phishscore=0 adultscore=0
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210084
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=BVvfizPq;       spf=pass (google.com:
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

All other sanitizers are disabled for boot as well. While at it, add a
comment explaining why we need this.

Reviewed-by: Alexander Gordeev <agordeev@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/boot/Makefile | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/arch/s390/boot/Makefile b/arch/s390/boot/Makefile
index 070c9b2e905f..526ed20b9d31 100644
--- a/arch/s390/boot/Makefile
+++ b/arch/s390/boot/Makefile
@@ -3,11 +3,13 @@
 # Makefile for the linux s390-specific parts of the memory manager.
 #
 
+# Tooling runtimes are unavailable and cannot be linked for early boot code
 KCOV_INSTRUMENT := n
 GCOV_PROFILE := n
 UBSAN_SANITIZE := n
 KASAN_SANITIZE := n
 KCSAN_SANITIZE := n
+KMSAN_SANITIZE := n
 
 KBUILD_AFLAGS := $(KBUILD_AFLAGS_DECOMPRESSOR)
 KBUILD_CFLAGS := $(KBUILD_CFLAGS_DECOMPRESSOR)
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621113706.315500-23-iii%40linux.ibm.com.
