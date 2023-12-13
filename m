Return-Path: <kasan-dev+bncBCM3H26GVIOBBC4A5GVQMGQE2N53A7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id ED5838122F4
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 00:36:44 +0100 (CET)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-425a62f0997sf78179551cf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 15:36:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702510604; cv=pass;
        d=google.com; s=arc-20160816;
        b=iv2KdCrjdWu5iUi6y+AU4WfUHToV8mpjMm3FERK7ued3A7p59aMkVsR58EPeMSQu5M
         ucolD+jZC+g/ouP8qSr0mvsJfBqdJqR9nex/74ZPjkY6aaTLRRSfZYgsy5EkroOZnOv1
         OHU5G6oGEkQMNpZlwoSLJF6pq65fFRE2SVG6vCt00fttNkpo286zwRejAizu/KUlr0aY
         cWu9XqvcjiYs8E3SWAjr8VcUs3t1w5KtqRdlxgYOw1Gxxhixyyuq22UDYVZpbE6EPtYY
         Reh0MxGOGv0YlQ6OV3fDen76Iv/FrJ91SWHQknWLET98vBBZjT5SMq7qUeTHttwUqHts
         gqaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=n+VULyn0/bLXhtcQ3c6XxyDJuUv/pvvx1zjlic/9BVU=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=0DvrfLs1tuk7AfNHXQ7aP0kNF7pUghNHWKnycYHEJXlPqHZtrHeTewpo/YD7Hm94gR
         Kqm5i1H5wqBAXIMmhPoIWlNuEDaC+dv061QHL7C3RVVyQTGGivMOSuAt9ZoLs5I6bqFu
         pZQP2fJmnOuvNKbpTsfmwMEcZJZZwoMUgAmvH2Q34U8IUoavoZ6OGQUSXTtSICtnAVhX
         mrJO82i3lfgzEOTrGLoocArvETPsFt5hn/Pz7OwiMlnueYebXyiyaZ7hLnkfX8mJYEwD
         vK97IV6UXPZKC6QoBtCkdIfOnBbTHRmVfPN5MJMjR4g+OvyQVjosmaxgdyTa0hAOxdtw
         O3qA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=UI9uSlKl;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702510604; x=1703115404; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=n+VULyn0/bLXhtcQ3c6XxyDJuUv/pvvx1zjlic/9BVU=;
        b=C4tCirpMds4u8tCTg06HRKeVVPCruFK7MrQaqYpNmi9SvxviCxPErJ5sOm6/kREOjE
         MQU3YXekyZkKDHwwuk36iPadKEg1cfqfJgatRU6AHXeBIuPR2EIQSCZeNHsfNRNmhugt
         Fens1mOGzM6og2ClZDgKiCf82CftiF1sNo9qZOtPmd49ogN6yx7TiuPW0vSnkgKlNrWA
         SuzNCzgLM+vhqNOfKY639fA38+/msABwh5T03BaKSP8b4Rh3A4B6NOPnapf8DudYeAaq
         o77i/UEe2Wj9xoFlc+87I5aaSmkI9/fn76I/QL6KiFYc9wlX/dCfpThCmk4r+GErzety
         +fIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702510604; x=1703115404;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=n+VULyn0/bLXhtcQ3c6XxyDJuUv/pvvx1zjlic/9BVU=;
        b=hBWuZFYHwqzw8aAxTRYtyjz6RA8cpnaj52zsJYlQwn+2XhgOp0bZ16eQpvCijSza+M
         xNh2yteAU1li8KLHwMRHtRA8f7VAluMImsvPtggf/n50nQuUVrOaBd6LnEWdofervtRK
         QtjHM0RDqVk84zUyU40FQjYLQ6GA9DIQIDQuYDaS1Wf+IUCPiyIZkCGIV8bDKyVMGT3d
         nSZOy40JlD2z0FcBQGQoFicVr4v4KVufM8HwWlvCvV4ES9S2DudvSzEoyYDDJxNDrDQj
         zuBpcWjr8FpeWYELlONzxBvMViUaqnjQvRHWyclH88LgPNDkheN4YSU/iTFZjnKk7JsJ
         Hyzg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzhG1tyn/GTgF7noaraSXB3GNtwRaoPkCz5Z7Uq8rfGMY+8S/jz
	duZ7rD17KWz/qw5cvwIvkZo=
X-Google-Smtp-Source: AGHT+IHVReGEla558jqeP+KcXoxBoa/iZ+oJ5M0WtNv1vssKsmtthtEjY7U52zLl1KW0hLumq923sQ==
X-Received: by 2002:ac8:59d3:0:b0:425:4043:5f4a with SMTP id f19-20020ac859d3000000b0042540435f4amr12485450qtf.136.1702510603906;
        Wed, 13 Dec 2023 15:36:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1815:b0:423:7c51:c729 with SMTP id
 t21-20020a05622a181500b004237c51c729ls852477qtc.2.-pod-prod-06-us; Wed, 13
 Dec 2023 15:36:43 -0800 (PST)
X-Received: by 2002:a05:622a:ca:b0:425:9382:6538 with SMTP id p10-20020a05622a00ca00b0042593826538mr11936144qtw.125.1702510603111;
        Wed, 13 Dec 2023 15:36:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702510603; cv=none;
        d=google.com; s=arc-20160816;
        b=rVaMQtJMfBm4q7UwuK2NFQaIq0qnmHhGpK1qNUBy4h8QWvRgdy8c6QvnG+fu63fAVa
         TZgm1I1dlw5aSdUG9kzdES/sMem47yFXScFc/XeBIpNRqznrzZcBUXXdzEyvg3GJJPKP
         h3/nhejARq5472r92S77sJJcNPNYXiPL8sVW1THPLamEvp4RFNXuDnMkZEkb5zntvwwC
         Iie9iebJN3hszpLFye2HXfyKomH/xEnKP5Uy13875eXWUwqZUhjnAnoJqDkP7jE5uINQ
         vQPEpy0ntCS1iQLhbitL+X0dc+IcgkHVIbvSOmrJvvky515ueIvoRnyObd+pyb4UCnwB
         x97Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=/+H88J6LmzDuOxLHJftJTV19pkCYIO+glC/rLzGPGs8=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=1AEfWD/0N5K78rYPb2dkPIgPW7+adKdsJ+iUj9sOjETObjeYyetgnMIRgynhUOwPeX
         6wOFSm9HZkUKFIwKldOY+3Pr8YUMEapSFP5zB9cCorEDS+rf9b41uAdgX9YJYbDCD1/R
         xGwFaepo3AiPrChKWsqdhhE0l3YILsleCE4nN+TeWcB+S55oK+///1ZOgc9DuAL0RYgx
         xvGsBYjAs65dRqCDUuk82hANABPjanCwkm8dQDzthHRKyrEy8XyZUlzSeF5CEbmwvajd
         ZrxLDAoa9lfxsgBWvl3n9+7vhqBO8SibcQ2GEghwAm/vwwJ9UN1C3Wmsbwnr7BpmttIe
         g/hQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=UI9uSlKl;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id bv9-20020a05622a0a0900b004239ed495d6si2321560qtb.2.2023.12.13.15.36.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 15:36:43 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDKbG6K023678;
	Wed, 13 Dec 2023 23:36:39 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyktbv0vc-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:38 +0000
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BDNLHVw018587;
	Wed, 13 Dec 2023 23:36:38 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyktbv0uu-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:37 +0000
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDGpBKh014833;
	Wed, 13 Dec 2023 23:36:36 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uw42kg1xm-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:36 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BDNaX8n4653612
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 13 Dec 2023 23:36:33 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 4F08920043;
	Wed, 13 Dec 2023 23:36:33 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id DCEF820040;
	Wed, 13 Dec 2023 23:36:31 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.171.70.156])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 13 Dec 2023 23:36:31 +0000 (GMT)
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
Subject: [PATCH v3 15/34] mm: slub: Unpoison the memchr_inv() return value
Date: Thu, 14 Dec 2023 00:24:35 +0100
Message-ID: <20231213233605.661251-16-iii@linux.ibm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20231213233605.661251-1-iii@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: kPY9E1UvYdSAN4yA0WGECmQaAwtxBTWd
X-Proofpoint-ORIG-GUID: zPDn9MZkVLtny7zKhboJlYnQt5V5Co18
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-13_14,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 malwarescore=0 impostorscore=0 clxscore=1015 adultscore=0 phishscore=0
 mlxscore=0 bulkscore=0 suspectscore=0 spamscore=0 mlxlogscore=999
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2312130167
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=UI9uSlKl;       spf=pass (google.com:
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

Even though the KMSAN warnings generated by memchr_inv() are suppressed
by metadata_access_enable(), its return value may still be poisoned.

The reason is that the last iteration of memchr_inv() returns
`*start != value ? start : NULL`, where *start is poisoned. Because of
this, somewhat counterintuitively, the shadow value computed by
visitSelectInst() is equal to `(uintptr_t)start`.

The intention behind guarding memchr_inv() behind
metadata_access_enable() is to touch poisoned metadata without
triggering KMSAN, so unpoison its return value.

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/slub.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/mm/slub.c b/mm/slub.c
index 2d29d368894c..802702748925 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1076,6 +1076,7 @@ static int check_bytes_and_report(struct kmem_cache *s, struct slab *slab,
 	metadata_access_enable();
 	fault = memchr_inv(kasan_reset_tag(start), value, bytes);
 	metadata_access_disable();
+	kmsan_unpoison_memory(&fault, sizeof(fault));
 	if (!fault)
 		return 1;
 
@@ -1182,6 +1183,7 @@ static void slab_pad_check(struct kmem_cache *s, struct slab *slab)
 	metadata_access_enable();
 	fault = memchr_inv(kasan_reset_tag(pad), POISON_INUSE, remainder);
 	metadata_access_disable();
+	kmsan_unpoison_memory(&fault, sizeof(fault));
 	if (!fault)
 		return;
 	while (end > fault && end[-1] == POISON_INUSE)
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231213233605.661251-16-iii%40linux.ibm.com.
