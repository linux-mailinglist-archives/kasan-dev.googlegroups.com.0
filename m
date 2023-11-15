Return-Path: <kasan-dev+bncBCM3H26GVIOBBVOW2SVAMGQEW7MYHAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7FB3E7ED213
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 21:34:30 +0100 (CET)
Received: by mail-io1-xd3b.google.com with SMTP id ca18e2360f4ac-7ad3237aa9bsf2656939f.1
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 12:34:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700080469; cv=pass;
        d=google.com; s=arc-20160816;
        b=MKT525UhgxGFo+jGhvUbVRQoRjk8nMuh4UlAUEsKSnVkgWEUITuLwQqsULkYed/fRW
         ZV9vqZQRItKmiWPhmNNnUg5WOnabtRexElMwFvkJEyMfrv6dmdVvyWMz7Bu8rIST9D4q
         OFiNP109lCnS8TIP+aYmwDPre27/7SllXQQaoEfxV8fCROARLcImbUOVcFHxZGSplPy1
         nstje16xz9MHvbrqZRKG1KIRuL/T8tITeAthrOx61lxzOyDm/14Y0WmenG635f66IwVa
         ssc7aqRrjbmRVfT+lmiI8uBqNZc1bPVjnkS0HbUWkowuLhjM8p5rqy3yKkB4/FLE8r37
         0KoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=bgpWQpnjj2yUYzvSr8Vt1zqcER5h8X6rJmeDsdOxwtE=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=unQ9AAb7OWMhp2aI5GbyBYM2N+wRnPfH1oWoLVBdvVDUyqVJdV+Rp+cFy50sjrARdH
         pVw0ABuimG+Uy8nSk2EAdNKonQl2RRRfui/u1zAXpI9SphMqr1MB4vnrxDRuO08Pz9fn
         DuGEzrvX/19OntTnMHh1Vp0/FUfLj0QIcs6xYE3orllrvys8KRg14GgJB0Sjx7EX/ugD
         UNMNDatiO7tHfk0YzLqbCOs1Up2mlOFfgToWNT6KjjEZ6EmuyQH43kn3zgN6yAN1oCHW
         2WFypux9wILRHrXAUILt7o4yzGKCjjFLJ8qBrPSDMDYIEQxFv1mdD66Mr7spmaciWfNx
         B8kw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=MJExlYpL;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700080469; x=1700685269; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bgpWQpnjj2yUYzvSr8Vt1zqcER5h8X6rJmeDsdOxwtE=;
        b=ggRpW/mmJ5IWkumDNFl3dt7+OTTloyTmmuxoSv/hx1olbWF8O9XC3Rpygox7qCIP3n
         49rXxztFkr7V5+lt2YMjWKMQtp3ymxpmuTz51InFbGhzl6m8SrHLVNf7Orv58AGshqU7
         nHU9OFuM/mk3XJqBnik/s2NDvnw9pAluQPa1TF/sGBPJYKa6BkjBLA01nIlEWCvgXVeg
         KItbE1CfMh0V8cL94QAJCht2JsGJ33fCII6dM8ghBlUDXsXpUm8yjAmXaZg9GnY6al03
         6dyG/koq4gI6cy7VOodvPMdhlG6E74jfG3xIBIRSsjtYKZUrBRFe9XomHnUntu12FNbu
         VFow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700080469; x=1700685269;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bgpWQpnjj2yUYzvSr8Vt1zqcER5h8X6rJmeDsdOxwtE=;
        b=sUSLdE1LFXAqqSwRWiVJMgZygOxvPm7PpARNWneGhCBE82CojgfHXzeLHgxyOlsLKw
         M7Hl6Fbkax7oQ8NBUcVed+2GySOF3zmW1ohp67VSfd8GxurcNyPAgbxDGPTV3ZsiQVud
         UKcaLXLWfBsozAS1IcCeVE1/NRkxhm2KMur4k5wJO6jakOCqBwP6DrDDcUc+F4f7Ek4l
         pSSnctYUbkTni8cVaZEP09PdPGZn18H1bq6QyhT2ZkLJTtEinbhv9T+KaNVOy63z7Py2
         7KvQRda2RQYwNEiDYz4+6Jcw4SSu8X6RQqkFl3QyAugwJF2c3jjdO+Q1DxkJloHymFDC
         JYUg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy7qYQWSEj0Ncwb5Gpzvp532BAR82flvuhtJwg3MuYfzlJm6muJ
	7dlvhatZgT2cD64Fgy8C2PM=
X-Google-Smtp-Source: AGHT+IH1ZVAO4WAu1sUD+wxIMnW2BnQTeZHq4063le99H51naUdDm2p6owJwuQs0ulInif+55WHyPw==
X-Received: by 2002:a92:c544:0:b0:359:4223:5731 with SMTP id a4-20020a92c544000000b0035942235731mr16727598ilj.30.1700080469293;
        Wed, 15 Nov 2023 12:34:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:de48:0:b0:348:81c5:d1cf with SMTP id e8-20020a92de48000000b0034881c5d1cfls66168ilr.1.-pod-prod-06-us;
 Wed, 15 Nov 2023 12:34:28 -0800 (PST)
X-Received: by 2002:a05:6602:b8a:b0:7ac:7cbf:972 with SMTP id fm10-20020a0566020b8a00b007ac7cbf0972mr18867109iob.12.1700080468677;
        Wed, 15 Nov 2023 12:34:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700080468; cv=none;
        d=google.com; s=arc-20160816;
        b=eaE8+kH6z2xgpxT4052vDw/5DpcdFGZok8FsHvIxQMw9OBvRtTQd3+UpK+D+a0ifFX
         FV00TEZtZJw/rlLwiaKlIepC2c5+8A/FBKYe4dlCQDtCSPTo9ZWH3jYVemxAl53sp7i/
         VxI8jR30mUfD32avDqsw+UbxexVB6N6Y9ixQKqPQTw8V7BksQBM6u43+i0r/qhcdS0Bg
         rYF7RPA4QVaaokjeqYUSebUWoxbVH6CTG6+2AJkolxBmMrn3XXzcMJ13BPi7GmO13QS8
         xlnmw4TVUuSToD6iVHNsU4vXx+4ShOzApcSkshcFj9AvzAQ+c7bxy04MflIuJK8pRoP2
         fE8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=WOj9NbaIG31eRcVAcdJNRN2GuttnZIt4WiIOTuHMBVs=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=JaLYtS89nhhtPhMf8RcQGag3hvJegpGZl5W2NH5qF8PRz6VJ9H2XT/TOMuUgS+lQMg
         cFtBgeMmRTPBC39Bqf+cYsBIOcXNbYttii8aSs8MqZDlvOK8pkC0TqlRnc7VXncNNFlh
         V/s+kax3Ir69XdqBE2U5oeIMHOD0dk7xAxhkx96Mkz6act0Q5A8erY4rJWcgR7fqFixW
         7nSlDP+BY7CybAF3IhQSS92yAMYBjy5+ECDfeNsFBm+HUD9qrocGbSPPAokPe2Kd09gL
         y62Ixd9DXxuaUq88Z9/xBgD8ROwW+Ms/GNdz6O3kHkkuo60svqP9qR/TDeAFCLl/qTYP
         R9pg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=MJExlYpL;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id cs23-20020a056638471700b004312fb02a61si1497916jab.4.2023.11.15.12.34.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Nov 2023 12:34:28 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353724.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKFcqh001581;
	Wed, 15 Nov 2023 20:34:25 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4v38cns-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:24 +0000
Received: from m0353724.ppops.net (m0353724.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3AFKSLRG001122;
	Wed, 15 Nov 2023 20:34:24 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4v38cnd-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:24 +0000
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKJ0eN021647;
	Wed, 15 Nov 2023 20:34:23 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uap5k9k97-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:23 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3AFKYKDa36045202
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 15 Nov 2023 20:34:20 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 7BB6C20040;
	Wed, 15 Nov 2023 20:34:20 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 2E66F20043;
	Wed, 15 Nov 2023 20:34:19 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.9.51])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 15 Nov 2023 20:34:19 +0000 (GMT)
From: Ilya Leoshkevich <iii@linux.ibm.com>
To: Alexander Gordeev <agordeev@linux.ibm.com>,
        Alexander Potapenko <glider@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
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
Subject: [PATCH 07/32] kmsan: Remove a useless assignment from kmsan_vmap_pages_range_noflush()
Date: Wed, 15 Nov 2023 21:30:39 +0100
Message-ID: <20231115203401.2495875-8-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231115203401.2495875-1-iii@linux.ibm.com>
References: <20231115203401.2495875-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: VFJOs4fGta1DSdAVChPTZKlQC1KrKYwA
X-Proofpoint-ORIG-GUID: 2OfAh22UbXV5iLL7SC5fqzTgA8shiavv
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-15_20,2023-11-15_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015 mlxscore=0
 suspectscore=0 impostorscore=0 malwarescore=0 adultscore=0 spamscore=0
 priorityscore=1501 lowpriorityscore=0 phishscore=0 bulkscore=0
 mlxlogscore=994 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311060000 definitions=main-2311150163
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=MJExlYpL;       spf=pass (google.com:
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

The value assigned to prot is immediately overwritten on the next line
with PAGE_KERNEL. The right hand side of the assignment has no
side-effects.

Fixes: b073d7f8aee4 ("mm: kmsan: maintain KMSAN metadata for page operations")
Suggested-by: Alexander Gordeev <agordeev@linux.ibm.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/shadow.c | 1 -
 1 file changed, 1 deletion(-)

diff --git a/mm/kmsan/shadow.c b/mm/kmsan/shadow.c
index b9d05aff313e..2d57408c78ae 100644
--- a/mm/kmsan/shadow.c
+++ b/mm/kmsan/shadow.c
@@ -243,7 +243,6 @@ int kmsan_vmap_pages_range_noflush(unsigned long start, unsigned long end,
 		s_pages[i] = shadow_page_for(pages[i]);
 		o_pages[i] = origin_page_for(pages[i]);
 	}
-	prot = __pgprot(pgprot_val(prot) | _PAGE_NX);
 	prot = PAGE_KERNEL;
 
 	origin_start = vmalloc_meta((void *)start, KMSAN_META_ORIGIN);
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231115203401.2495875-8-iii%40linux.ibm.com.
