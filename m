Return-Path: <kasan-dev+bncBCM3H26GVIOBB5WL2WZQMGQEIEXNEWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 47C969123CA
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 13:37:28 +0200 (CEST)
Received: by mail-ot1-x338.google.com with SMTP id 46e09a7af769-6f9945ddb16sf1731586a34.1
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 04:37:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718969847; cv=pass;
        d=google.com; s=arc-20160816;
        b=Eg7o7Pxy5monTT0pb+KJ699KQ497KSEbJMYLXylRyNflqqMh0Aea1e5tL3UVZqZQbn
         fP4JVHvXwxNQgsUBiBjn1/qPGJUv+XTsnhTSonPjV197iaG60humj5ZnRUCT7TPv98/x
         fMQjHC/J9E8/bvzhfs9s/0UTD2RSp8/jsX4jmIXpJMwikxvRYN81nFoI7UQ906FgzT7+
         GlqDKC500NegevZ7fu6j0EwVh1QBxrTJEi6GXx0bilZdEfMQxprcuMliZt6ik01JiJGc
         55bBixkoCEQL2J4WWlsaLTmWcOaO8TriXHsbpyaT5RTZPXyoCO25B4bGqKPAGMm58/xG
         v8zg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ETaW+uNx97Z+EkxIETfNHnHhg+bp/K65CPRpDFrCiCI=;
        fh=8tK0/V05IY6rU8o1ElJVSX0CpZ8OmC7YFDjFmrogqgA=;
        b=FF5gAx8yi/gYvVTlIMCXwMlPEz7NAu/v0op/PG+EBFgheQfr+q+hyae+0FFI5XdInZ
         E34K3Qlq06K8N47537PmV6v+Zg9BIg4Obntv8gpzoXlpE2DUTu8UGj0dgMUHUHLDaNVA
         SKAcIyTvM7a52HKQKRz+/nb39JbRmm+iaJcamHOX3oKo9EKhRIZqLAOKmtdPFcE75Vte
         v+bTH2ATI9UjW+hT4NX9bi1usRQ2EBGM6eAc3AdTcpPRmlCIgI/Po/UNRCrgBZaUQf0m
         bC7VnnKBiIsAwqxzI2TOdeIiVVrSB4sGxhm2piJsvxICSRQVuwZt9wmilHKy3mnvvYyY
         buFQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=PXPuXODI;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718969847; x=1719574647; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ETaW+uNx97Z+EkxIETfNHnHhg+bp/K65CPRpDFrCiCI=;
        b=JBpPVrQlkeQPS5NqW5L04CSm/I7FP4sdwOj4qWr8dFwkJiWzZ8p4pLNO0OJjhpl+h4
         2HN30lvE+Kjg2wibvy46rRFYSWMPjXVE4u+kqVvUIeuAyA0vhCT2vXRRnC0LktUexHYB
         L18dqFxqKRsNCwVes49lDiT+r9Mo4Lk7dzxE3AVIf+Wk3/W1F8Ppaal/W8YMMQo/tNsZ
         zG+3kLUEtQ5LowMhNZhu20OhJYnzDelOQ60jpvI47B+8Q13Iah/nT6KWVxeOxggzcV3J
         UQ6BDiv8tSQUJa/yY2pXiCYk0KD6/RgdqR9hxcZL/Z5fjkQQkMD0I8ZDm9Ttz2tNGP5z
         f+1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718969847; x=1719574647;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ETaW+uNx97Z+EkxIETfNHnHhg+bp/K65CPRpDFrCiCI=;
        b=ZsK2G4C6kmD4Bs5+doiEAZWFGA3D3hFiLBAXj0PX9gjLeqfI38UcDta61DVJEYkhvc
         XCM8sBcBCxH7TT/SjsAzIOZg6BYKPthnJ+saxeFIeBa5XSSyLvXXUZr0YHDIWvf2yk3M
         seBoVwFZfXIA++XNrPEz+f7KnYjuigKilHAvBsrl3bIC6JEgSavL/YTyUpKIB5V6PyST
         rmGmjcNIU8k5e4m16XoQJ2O/biPmLsmU06Iw9eybcsyDrNaaS+BWofHBmm5pIQ/FUQ6v
         ss8BCFvc8yRrd1jjnB9dhyTE79ZYf3zff6iokRMyD2C3wcerh+dHOvdLlRQpkySpyfO1
         Mmyw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV5PQVPB3QuRPDOCFgtz4d2HxvKxLgIbtDbl9I/ZXW6/YaIf3y8S7mMqhz0xAOvLME42kdxTSkYBKsCvYmuqp4vhkwEKgaRdA==
X-Gm-Message-State: AOJu0YyHKXGEkee/Gyn/d2yNSLcqmcflUZx4MH1MQ+Abf3PEJxBrcIIb
	kYvRYX/TY5t601NB4rv281BSyY5YGXq39+mSJsjlR/wROKbNyL/T
X-Google-Smtp-Source: AGHT+IHnZ8CahsboRJ4IAndQfj96Jmdd7e7I0iOe90ygXuWX79Oe91Vmeg+pljd/q3qLFwtsZmCNOQ==
X-Received: by 2002:a9d:7a8f:0:b0:6f9:6e0b:4ac3 with SMTP id 46e09a7af769-70075f58568mr8979860a34.23.1718969846687;
        Fri, 21 Jun 2024 04:37:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:7646:0:b0:5c1:a666:5e5 with SMTP id 006d021491bc7-5c1c001cb1fls1891782eaf.2.-pod-prod-01-us;
 Fri, 21 Jun 2024 04:37:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWsF2G51D6Z1ZdvVqmEHJcwGRHpLtimb/kPtcyyWFx03PQ1wKjBXam39ODtfxQIzqCsE++/sLDflaCZPbxhwLI3sIvG3oawR0QmhQ==
X-Received: by 2002:a4a:d8d2:0:b0:5c1:ae2a:e03 with SMTP id 006d021491bc7-5c1ae2a0f6emr8013175eaf.3.1718969844261;
        Fri, 21 Jun 2024 04:37:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718969844; cv=none;
        d=google.com; s=arc-20160816;
        b=drahUUK2koxUxjr+5gv+p0N7Ub/h59uKDhUuOK7+VYoepJEPQCkzNP7sYSnzjPgfcq
         3dbJguvqivtjBy8X4bh1JIdIFTOPoDZvTJvzI3R60h8QREJvtDSn2+NHub3qXOntY2EL
         ORwe9Cu8vpyi1ycdr17q+nTEYpesBiMP4QaiJGT7g3YljTXAZOCNDy8PS9RXQPCwcqhE
         K1+Ie1SHWII1YQNJMoJfgW1eeOaVN13alEoH2ayubx3ZsfEN3yMRJ449JODuOzKyUmar
         KV8a3928Ypae62dxej7lbcEhSgcqWkvMebtVRk7GTNGl1Emwx+CGonvvwZxwS705+dfB
         WbaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=A5/DP3QFUFkYA2+5kJImY20b3CDMSHPGwimqBdu525I=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=GX7noVCKSnWp2w0EbKH7VlqJSqCy+RZXjp0HQij0/DX9I98zgb0yVjDAeGfhXC3Y9s
         Cht10XTFRcCaagx1VTMJ7L9IGg+KQilke821Vs/IaLbypEjHa9aFKJZQ6wxkAp/h5r8l
         xM69MkIPSBAWvWTn8ym5SyBWqK9aslhrekt0HbvFvjR6u3kmpXvLUednDe7F9Bqwuc1z
         4Ulo4bWYVBmkIkDeydW8nWpmw+Xj0yXLCe2PYmiFymvzwLd4uFiwKRfquiVziNzMu74X
         Ki4GuYILGr8Vr0eV4dOBxA8dCG35/s01iX5PTYBGT4zdcfzjYxUXP4nge+thqsz96Cx4
         66Lw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=PXPuXODI;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-5c1d59a0dd2si54090eaf.1.2024.06.21.04.37.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2024 04:37:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353727.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45LASSTU027155;
	Fri, 21 Jun 2024 11:37:18 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw7sv84j3-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:18 +0000 (GMT)
Received: from m0353727.ppops.net (m0353727.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45LBbHZe031826;
	Fri, 21 Jun 2024 11:37:17 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw7sv84hx-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:17 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L9F81I032326;
	Fri, 21 Jun 2024 11:37:16 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrsppv4x-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:16 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45LBbB7h33292802
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 11:37:13 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id E93AE20043;
	Fri, 21 Jun 2024 11:37:10 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 5A05C2005A;
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
Subject: [PATCH v7 03/38] kmsan: Disable KMSAN when DEFERRED_STRUCT_PAGE_INIT is enabled
Date: Fri, 21 Jun 2024 13:34:47 +0200
Message-ID: <20240621113706.315500-4-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621113706.315500-1-iii@linux.ibm.com>
References: <20240621113706.315500-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: KET90bWKVuHVgYUVZ0DHnTT0ONXLE0kP
X-Proofpoint-GUID: N6mQrpfA8-5n0u5DcJFndhfBkrE4DYMh
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-21_04,2024-06-21_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 bulkscore=0 mlxlogscore=999
 adultscore=0 phishscore=0 clxscore=1015 mlxscore=0 spamscore=0
 malwarescore=0 lowpriorityscore=0 priorityscore=1501 impostorscore=0
 suspectscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210084
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=PXPuXODI;       spf=pass (google.com:
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

KMSAN relies on memblock returning all available pages to it
(see kmsan_memblock_free_pages()). It partitions these pages into 3
categories: pages available to the buddy allocator, shadow pages and
origin pages. This partitioning is static.

If new pages appear after kmsan_init_runtime(), it is considered
an error. DEFERRED_STRUCT_PAGE_INIT causes this, so mark it as
incompatible with KMSAN.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/mm/Kconfig b/mm/Kconfig
index b4cb45255a54..9791fce5d0a7 100644
--- a/mm/Kconfig
+++ b/mm/Kconfig
@@ -946,6 +946,7 @@ config DEFERRED_STRUCT_PAGE_INIT
 	depends on SPARSEMEM
 	depends on !NEED_PER_CPU_KM
 	depends on 64BIT
+	depends on !KMSAN
 	select PADATA
 	help
 	  Ordinarily all struct pages are initialised during early boot in a
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621113706.315500-4-iii%40linux.ibm.com.
