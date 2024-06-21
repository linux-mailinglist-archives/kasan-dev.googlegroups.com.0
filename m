Return-Path: <kasan-dev+bncBCM3H26GVIOBB7GL2WZQMGQEG5F7DYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E7609123D5
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 13:37:34 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-259f021a915sf2214447fac.1
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 04:37:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718969853; cv=pass;
        d=google.com; s=arc-20160816;
        b=UO9PHxBG1PGCQqh4ykKZ0wQT10HtHzLWMYl4nEUKyXueqzEwl6RwyIfGC4HRG2JlWh
         X7h5guILKc1qqPZUrwvKp1ks55tXO/rTNPaIga7uyDsbiDbXrMf4ZmuY0giIL1ZGvvpD
         DKd2Yj40lzGKAWi1hwaIWDUTjgM5c9Oe6XkUilig7DvlLXsssGXXnWt47aOu5355Lt82
         s237Ru0Z5JWqe/Mn/gafn+Cb+IHEypp0BK1TTgfMDciWnJcBBIbd0/ZVH+UtsE8GPIXG
         HvELEJYZIZOiknO/HaYBZgCbS9XTED+vPo97WV/TX3sLJtS64bEN1pouR28JZwCPyUZO
         zLJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=bO8OCCvH1b90u/FQrfERYjKu8TTbBWaBgNZ3feXTPTA=;
        fh=ieIwmZxDzR0pBlmZi81w4MTARaakgcvR2lALPxpCoQM=;
        b=s+EGKN3FmBEEZv3ecSql8fjZ6ocJ7z7vh1iF+lWjTkC3CJO487zWaJaiy7RZdwI3jL
         veP0hOttDTwHeZ0xFfinFHAP3HG5LS5vcWPawUu1xJUSZRDAWwjMvgBOWT57CrEbgRPn
         JsOyPY5ayzJEvAoCWFaY4TVeNXYgcnmY3jCUgVB+QCeM2E+aqD3WGIFTnQOOmY4xO+4K
         ZWQgveziBc8C496n3KIqtJKoceTEvML3b8ugXf3uALb5Oas+RlygjTzFpmxkOVTLkcsf
         ImyMNuROivIfOoUV5/CcUxEnuNFzISnBZRFGLpLIoHc23AqylXNklTjEfZb57tvNzpHu
         Pt1A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="gCmb/jd+";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718969853; x=1719574653; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bO8OCCvH1b90u/FQrfERYjKu8TTbBWaBgNZ3feXTPTA=;
        b=OtV8tvpm1dniOeO6YQLf/yoaqA7EgIEy/UZ4Kt7jpgwXBjQQUTU/gtkDnu36xtpszr
         ahoKb739zNJ/woKUPrnZMnLQHcdBDx8Sr8dGKI9VFOeBag5TBCQLVpcCuAJ/YPBn95E7
         2eZVaHi/e8IzP7KJOYm0POJpbl0kJmBglz/qYzR0KLh8ZZ5fEinTCKQRPSNM6KVthR2a
         zzxnO6NFUoplS8tngjReRd8BkgvKgttjgbSBMC2YscPQa2lOX14ULrneNw2QBTVTA/hC
         3MSVzOM925B3us5Uyf2/rrVsA4ijjqFSvYpM3FVGqMYCIPeE88vtU3wz2YCA+/H6+PP8
         9D+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718969853; x=1719574653;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bO8OCCvH1b90u/FQrfERYjKu8TTbBWaBgNZ3feXTPTA=;
        b=X2PZruPGYAI74ITOKkdPrDfqf3PXaTyEZt+j0k3cNgw5D+CAkhrwgsISPu3XnlfiKM
         YUrIPMS5HnKolfGFQ6ygid/RBceT6TRfOBTZEGTYFF7jEPZupQuXJdBeWAC87Qc8B6J6
         OY3Ksd2jNnFAmIVJ8tlqrnXfHxlYd0NCvjoxVCkKKHisBmeqr8c+HzHI9lyFINVtmeMG
         +7iVxSn2PjYFQHUe71F5OlLVl9wnIhgN/xCG2WcKYeIteXvt5XfYUny/lZ30i9zIxHAF
         7sbm8SZypltngIl8Oo+VJkk4DM5nbWPfgPW3cV9eDSjbxAGzpgr5hLwwpoYjTkO/x4eQ
         FWFg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVp86bDwD0uwD8bvFUS31aEawwoXDGgeyv/22cv4icQKrf2xuKlP7ReRKgxEHHIacqrHFo5oghKEhz0ZOGD/EEA/LE/IwKpAg==
X-Gm-Message-State: AOJu0YxIapHCwEsJP2DraAuHdl1QXIq2AZx9Y8kvHFGIdWC3kMujfiiU
	m/h/9KE37iDPy8IjQpBRijuUarnwGih/vqftBI6EoCXoEq8v9GCU
X-Google-Smtp-Source: AGHT+IHWU8WDtxZuwHrDuqb2WAJjVwsCgxZ9Ra3fLU3vvbY/+v8twuZUUBEkt3OOmoPC0FNeqFTxiA==
X-Received: by 2002:a05:6870:e415:b0:24c:b654:c17a with SMTP id 586e51a60fabf-25c94d058cdmr9426891fac.45.1718969852920;
        Fri, 21 Jun 2024 04:37:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:3321:b0:24f:dd11:447f with SMTP id
 586e51a60fabf-25cb5ecba40ls406717fac.1.-pod-prod-06-us; Fri, 21 Jun 2024
 04:37:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVzqtvGvNHlFy7u7tZcGznyYrit+2jJqtvzoioqlNSHk6Ynb+R05UJTPdPPRnKeMSruCOC90LLgkc8Bh+nUP0wnrOdr0HqVIXDUVg==
X-Received: by 2002:a05:6870:471f:b0:25c:29d7:b791 with SMTP id 586e51a60fabf-25c949851a3mr8169525fac.15.1718969852153;
        Fri, 21 Jun 2024 04:37:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718969852; cv=none;
        d=google.com; s=arc-20160816;
        b=kX3J1oOofhidMIntGBonhanjBPs1jLqTsdoRuVFFHho4oFaet0t2G+GZhGSMSf0gbC
         rjEkZU73uIUkhcrzGv5IhDXCHlZlwsz8vgMZkr9rcthXF+IkYgiCw4Djs4qeRGD6MR54
         uB4PmUmQtUjjDmKuip9zrJiR8BjYn00pCu8IgzRTDeQC+xkZnyTqnhFfW6BKix4jI2/Z
         tsi9lcZZa7wlXqkKhhUf5fF5XD/WLDjpgq9Eyh6tengOxlP0s+WYbFP7Ye7SWykukycc
         W79wYOY6tXs4wBio1fGzTAFTOM6rXUf8Mrg4lijf86IchYldMz6yHy8C7PoOoQiyp3cM
         18rQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=DjuPcXR1BibZz5Ch991GiPtCxAY119xb/qfTqg6kigE=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=dWY13GBFKza3lhLquUhtuKL+4Jsse4jBfrRzLTRrwuff8q4/MICLpxeUhXehPCemDB
         /lNCir3juYKfgDhuEX8iP2aeioJAIc/WsjmY5B/BTCs28PuuhZtKeWmhi2yE6DHJ/ITJ
         qx7xWQ5r0TvZn6RA7kCS/vYgByUoOW6mp91TbfQo/94DeZ2to+wNFbtJdBqcpYtySVKc
         ZOqLAWfrgMzWRgbobmeojrNAmivLGTqdqmctPofep1gcA30yKkDCh2RBvVnVRCYBlqUN
         oYgW0tKN8/AYffpVcwMnzofH8esniRjXRlrCJ7jr5LOD+e3iNdm+GmHFLJIZFotWcBuc
         clXA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="gCmb/jd+";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-70651194b50si116637b3a.2.2024.06.21.04.37.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2024 04:37:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0360083.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45LBZFfl019981;
	Fri, 21 Jun 2024 11:37:27 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw49cgpwb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:27 +0000 (GMT)
Received: from m0360083.ppops.net (m0360083.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45LBbQpQ022007;
	Fri, 21 Jun 2024 11:37:26 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw49cgpw6-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:26 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L9H76V031933;
	Fri, 21 Jun 2024 11:37:25 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrsppv5n-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:25 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45LBbKJI51839450
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 11:37:22 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 2B0822004D;
	Fri, 21 Jun 2024 11:37:20 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 9548A20063;
	Fri, 21 Jun 2024 11:37:19 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 11:37:19 +0000 (GMT)
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
Subject: [PATCH v7 18/38] mm: slub: Disable KMSAN when checking the padding bytes
Date: Fri, 21 Jun 2024 13:35:02 +0200
Message-ID: <20240621113706.315500-19-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621113706.315500-1-iii@linux.ibm.com>
References: <20240621113706.315500-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: vituer1Uvt-m-Bx1xIgcKWanRH3GTkhf
X-Proofpoint-ORIG-GUID: v4Bwds8AEd2AHVddJ8G2HfSGwp0WqKu-
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-21_04,2024-06-21_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 bulkscore=0 mlxlogscore=999 adultscore=0 priorityscore=1501 suspectscore=0
 clxscore=1015 phishscore=0 impostorscore=0 malwarescore=0 mlxscore=0
 spamscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210084
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="gCmb/jd+";       spf=pass
 (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as
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

Even though the KMSAN warnings generated by memchr_inv() are suppressed
by metadata_access_enable(), its return value may still be poisoned.

The reason is that the last iteration of memchr_inv() returns
`*start != value ? start : NULL`, where *start is poisoned. Because of
this, somewhat counterintuitively, the shadow value computed by
visitSelectInst() is equal to `(uintptr_t)start`.

One possibility to fix this, since the intention behind guarding
memchr_inv() behind metadata_access_enable() is to touch poisoned
metadata without triggering KMSAN, is to unpoison its return value.
However, this approach is too fragile. So simply disable the KMSAN
checks in the respective functions.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/slub.c | 16 ++++++++++++----
 1 file changed, 12 insertions(+), 4 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index b050e528112c..fcd68fcea4ab 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1176,9 +1176,16 @@ static void restore_bytes(struct kmem_cache *s, char *message, u8 data,
 	memset(from, data, to - from);
 }
 
-static int check_bytes_and_report(struct kmem_cache *s, struct slab *slab,
-			u8 *object, char *what,
-			u8 *start, unsigned int value, unsigned int bytes)
+#ifdef CONFIG_KMSAN
+#define pad_check_attributes noinline __no_kmsan_checks
+#else
+#define pad_check_attributes
+#endif
+
+static pad_check_attributes int
+check_bytes_and_report(struct kmem_cache *s, struct slab *slab,
+		       u8 *object, char *what,
+		       u8 *start, unsigned int value, unsigned int bytes)
 {
 	u8 *fault;
 	u8 *end;
@@ -1270,7 +1277,8 @@ static int check_pad_bytes(struct kmem_cache *s, struct slab *slab, u8 *p)
 }
 
 /* Check the pad bytes at the end of a slab page */
-static void slab_pad_check(struct kmem_cache *s, struct slab *slab)
+static pad_check_attributes void
+slab_pad_check(struct kmem_cache *s, struct slab *slab)
 {
 	u8 *start;
 	u8 *fault;
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621113706.315500-19-iii%40linux.ibm.com.
