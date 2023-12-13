Return-Path: <kasan-dev+bncBCM3H26GVIOBBF4A5GVQMGQEQBWB57Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B45F812301
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 00:36:56 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-425a6272642sf85700021cf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 15:36:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702510615; cv=pass;
        d=google.com; s=arc-20160816;
        b=folbq7HllbglFFuEihDan/iBfmkJPRfbwOEvm55GXbxPQLZbiiVaag36mwWPj1vA4f
         aJSwd733EBtgtRJYkLP3Yyj4x986Bg9pDYGlWhasIt+wv4mlvuwLWEl72WKA7xXjFvgm
         soqp/WbHyifq5Yo85qez1dQyGesD5IcEPLmD7ii26bAOBUI8uO0PdR7YiMU1KHNQFrMW
         P4qOPZOK1CElhYPoPlYGTHCD5vWtfGMnrVHbO+XhexfchVRvBJTFAYjGxlMdzCaF9QLJ
         8oM96no0bro/qrxZojtWvn+TMPwMS7ar/bdNCXDjO6NOW8Fiy3ixlVg6vcFrZLmC8h2l
         J82Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=2s4gnT5hffDj26RDCqrkAKvgRIaU0YxCkRSZ89XeMCA=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=SZscZdOB9aw656XdAfEAM+J1TpwE2hbqIev0CtM3rLWYmtYQIhcyOKnUN3oRxow4wo
         T+Bmsmng0KT0wq7etaV981RfF5p+A/AUIhcSt+eFzS70ultmujufBkDAn9tx75O/Xidj
         kDsHNNI9ZX1IZATjI7nvkEvPhnPu0W7CEiVb6fq5BXMjjDGzBYoTe6S10UM5H97wb6lK
         NDau1u4+BPmGsuKr7HoVqW/RdchLKtaew8qMHVh1wVU9NK3vKAZFDjQQlo+NDN6zqJUp
         fW4HAnOMcgBMH/p7AiZ3zr8zv/gYV7UDPpUGtaxRXN3ddnolabPk3kjcM95UCxHwOLLW
         Sq1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="Rl/rKJ6n";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702510615; x=1703115415; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2s4gnT5hffDj26RDCqrkAKvgRIaU0YxCkRSZ89XeMCA=;
        b=CQ809UNYvM6fhAOFIpWpBGACcuBcM4ouHi/T5RY5YXjmVpi0FGIDH4x4iIqcWjZBc7
         ECyN2h7sapjOxjQkFhQ6t08DIdXTGkcIxye1/VNFfiDru1IGBWJyee7v9je/i9DOIEvo
         gyfi3U6D/uKAg0/rsOzWYlFUkzRy3lDj5+yFGfOsA0fiCT3tnouVQRh3SnhMj2GI1A3B
         H2qNcxulT2CwhdSaNMZcZvhgVtoznWf7DYn+jLE7vc4sXlPP0PxCift0G4kIJVPJmoAD
         s/hfZDk7BCwiCKlnYXLHvTOqXGRUW2Pz3J+cSLp4h/mJuKJC0Iy5u/mwU45I0WmOGe4E
         0f5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702510615; x=1703115415;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=2s4gnT5hffDj26RDCqrkAKvgRIaU0YxCkRSZ89XeMCA=;
        b=bjNBDBSrr9GIbuP+Yudv1A5ZXFXWo27F66cU0uTgJVziuM99wb3JHxw91a3YROZcZM
         ocSipoe2upYKKul1H++Oqpp6TiRm0z9Om14JQ+4Sp+9KOo5U/em8zj7Gp8YDLS/qyvIn
         PewEY3R95upTXai8DbMXnyfK3N1/VH0jWBK2o3Rh9AWMiFD6Ei85PZuuGyvzuRyN7E2M
         HOqst+A1eITDLzhiLNrmTk3kAQCXr4oLWI0Lfz5rmDfhuF+hhxMH0bOUkGcTnwf+fZfd
         pCgq+57HnDSIe9L+XqlioXEpFi+99sheWQWf3ieC47wBy4gN1diRjbmiZ5HIurSmpFZf
         DssQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxmaDnXIKYz+nFkf6Gojt3UN72nDwuun2FRs0oyk18MlFK/oVxY
	De6wiF4SvlF2+q4K6DNAVqc=
X-Google-Smtp-Source: AGHT+IGKOluBUcBrSmjwHHrFxLA6raYX63/k6gaWPPuVYkVFzKDBBbM/2NvBQkQsvu1fW3fxPsL+YA==
X-Received: by 2002:a05:622a:1cf:b0:418:1565:ed50 with SMTP id t15-20020a05622a01cf00b004181565ed50mr11083053qtw.66.1702510615691;
        Wed, 13 Dec 2023 15:36:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1aa4:b0:423:a0d4:8c61 with SMTP id
 s36-20020a05622a1aa400b00423a0d48c61ls2993996qtc.2.-pod-prod-09-us; Wed, 13
 Dec 2023 15:36:55 -0800 (PST)
X-Received: by 2002:a05:622a:1207:b0:425:4043:96d8 with SMTP id y7-20020a05622a120700b00425404396d8mr12138931qtx.101.1702510615032;
        Wed, 13 Dec 2023 15:36:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702510615; cv=none;
        d=google.com; s=arc-20160816;
        b=XExKy6PMESkhEIlHASAMWfHb/Z+gJ6SXmwpk6pQuG5Wa2J+ykC56o+/elRpk2E/qzD
         /UH3deYIvHgVKh+j4UnjQ7+6m7nPOlZePxzIy66S0fgUw1aTVzkI89LCyGGkP2Qc456e
         W8siazmqpCGGFUuyc1EJRWhaZryKj05o7NOC45NIDDIPzgtrHPQzKMx3qo9ZLNnFlCTs
         KGXbdj8hrxu9Z2z4s7rb5CJBW/tRhIT+wpyU4pMq8l/3jEBiSjXi8nYkq79pRgE1ybaj
         g8R9oRvR/buN54a+51NrQfjhVny3bBtPpZMU8byMjfVnWAZyIMEzGMDoKr1LDYCdZndE
         2JdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=45Nhhyp6yS18GqDvv/f0pUsyfshJSMjjruM4ZPbayJI=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=yKtie1SpnfcnCAbnjTeizgSZsLef0FfukVsUa81PUGaY2RB8Zb16hb2dK22poAqzdm
         cyAUeURIHIaLam1rEBHUFm5l+5/abKLI3vYgnio+A36QTRMIIGxbY7aEAGwh1TU2DQ6R
         tJ5nRNCXfikvKjP+pJOKY8rMmAPIIflrKO2JY+RiwqhyB9YOCBTW1UvO3W5bMREKdbYP
         aQOzHCRVb4ytWemRPXgcTB0ceZCqulieV9j0zcE5oFxWgZBsTDVc3yD0+LdY4mjASNha
         8p0c/kcdei5/4+8JwTRhWUsrwQYLRfQQc8C5VQrUH/CJyJU6BXIHrlNXJObvOnC9P3aW
         O5Uw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="Rl/rKJ6n";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id ew12-20020a05622a514c00b00423f3ace78asi2176115qtb.4.2023.12.13.15.36.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 15:36:55 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353724.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDMNCmT009101;
	Wed, 13 Dec 2023 23:36:52 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uynbt1cyf-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:52 +0000
Received: from m0353724.ppops.net (m0353724.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BDNPaWh016517;
	Wed, 13 Dec 2023 23:36:51 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uynbt1cx8-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:51 +0000
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDLqJBT012555;
	Wed, 13 Dec 2023 23:36:48 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uw3jp4na5-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:48 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BDNajA143975038
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 13 Dec 2023 23:36:45 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 9BEF220040;
	Wed, 13 Dec 2023 23:36:45 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 34F8220043;
	Wed, 13 Dec 2023 23:36:44 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.171.70.156])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 13 Dec 2023 23:36:44 +0000 (GMT)
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
Subject: [PATCH v3 23/34] s390/cpacf: Unpoison the results of cpacf_trng()
Date: Thu, 14 Dec 2023 00:24:43 +0100
Message-ID: <20231213233605.661251-24-iii@linux.ibm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20231213233605.661251-1-iii@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: 0dfgWLOx15d8NabICqrWpXu-GD2TJBSN
X-Proofpoint-ORIG-GUID: YuP1Sp6QRPB7FpPhup6bxOwBsE2f0Wqq
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-13_14,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 adultscore=0 clxscore=1015 bulkscore=0 mlxscore=0 spamscore=0
 suspectscore=0 impostorscore=0 mlxlogscore=768 phishscore=0
 lowpriorityscore=0 malwarescore=0 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.12.0-2311290000 definitions=main-2312130167
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="Rl/rKJ6n";       spf=pass
 (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as
 permitted sender) smtp.mailfrom=iii@linux.ibm.com;       dmarc=pass (p=REJECT
 sp=NONE dis=NONE) header.from=ibm.com
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

Prevent KMSAN from complaining about buffers filled by cpacf_trng()
being uninitialized.

Tested-by: Alexander Gordeev <agordeev@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/include/asm/cpacf.h | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/arch/s390/include/asm/cpacf.h b/arch/s390/include/asm/cpacf.h
index b378e2b57ad8..2bb6b4e7e082 100644
--- a/arch/s390/include/asm/cpacf.h
+++ b/arch/s390/include/asm/cpacf.h
@@ -12,6 +12,7 @@
 #define _ASM_S390_CPACF_H
 
 #include <asm/facility.h>
+#include <linux/kmsan-checks.h>
 
 /*
  * Instruction opcodes for the CPACF instructions
@@ -473,6 +474,8 @@ static inline void cpacf_trng(u8 *ucbuf, unsigned long ucbuf_len,
 		: [ucbuf] "+&d" (u.pair), [cbuf] "+&d" (c.pair)
 		: [fc] "K" (CPACF_PRNO_TRNG), [opc] "i" (CPACF_PRNO)
 		: "cc", "memory", "0");
+	kmsan_unpoison_memory(ucbuf, ucbuf_len);
+	kmsan_unpoison_memory(cbuf, cbuf_len);
 }
 
 /**
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231213233605.661251-24-iii%40linux.ibm.com.
