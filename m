Return-Path: <kasan-dev+bncBCM3H26GVIOBBR5FVSZQMGQEWWPCG2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 8DF249076DD
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 17:39:53 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-1f7166c6e1bsf8770655ad.0
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 08:39:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718293192; cv=pass;
        d=google.com; s=arc-20160816;
        b=HybsjrnHhWYOEeeKMx0VariWt9fouQhS9rzCuoGgjX7dqPLHYM2hMd5caS5UrjQ9vk
         yhzMzUYSJ0zhQUl89yLU8paTAWbtsk1nmvA+zyB5Qr5rfAkNo88cMIzCXa12hxmXDY1+
         lHLGgv19W9CypMwqkCs03qAOYSv1e1jiV0n3aXVWuyITtJYEAJUZXKhBk2K/7xfRvO4n
         sAsTw6ueoKArlgJOoFrszQwx87NA6O2C3h1eHQAFpllr1Ok4+y0NCgeauuAizYWcbMfY
         KDh8LjuDn8LOWF/p995mCH6OKiEHhsaXl/E4wheND+rZTh1C+XBKI8jLFUmLQuBZb+UB
         HHrQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=wgZAJQYwoKC+wcmLuJ9B/eLKRGtbYIM1Z3qZdBmbtsY=;
        fh=EjkcQSupwCwqTlRNitByaI9EWu8B65jbRPX2CTcZ2FI=;
        b=dMcf618i3ora2R489jToDzuB1PyeZU5hXWr5vWNhIAqQG7x8ynXdFaM6yu+FZ+3DXU
         ZdCZSX/lqvFgIFoYQwgnJIC9NPww6g4PpvZZt/3mLe6Ek+Zu0FvqhWQT2T6pzVGO7jGJ
         0LBqawYxIBuAhysy+wFSo9OyFlXsGN4DjGbdQQYvWruYP8H+DVEQ7ut2MCqedfugKBYq
         9Ltt0P+a+0ULXp9sZDr4XnfQWEi/Y8heN1Dx6kBVijvEZiP9Wrek+CLlQgStuAZWFL+f
         KxHVh5R5RwuRDKxEiMLsytgfjDU8qxJEZnbG4C53tvMY16Ot4OrWqfGJrU2DhhxRKzsW
         6KRg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=VORhykUz;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718293192; x=1718897992; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wgZAJQYwoKC+wcmLuJ9B/eLKRGtbYIM1Z3qZdBmbtsY=;
        b=Uv7+QeyxdcOhJLHv5wSSJVQJnVHGkMQYWLrdayQMQItIvHUNoODzvxABE6nGPF+dEn
         +oD2dTlS1F3NK8paUU9GXjoz8SOeOsuIPvsdgxUyXKF0yxdYzkfiC0yKqCCxGIISK6xl
         YyLQiV5MUYQGSFdBxQLl7tAlqnZemgWWLBvQ/+IhvqCwuSeBeBx0yYpcmoKlqUXDqQWe
         pv3gPo1OCLdK6Cu9mMfjrpa5QI1mzu+7R1w/DuuxoP5/e89kgp4vamnbT6Puao4hbcC7
         S3dNNdmzmQQ56pjnjs6APFSNxalbZbrvUKfRyBbWP/Vc3XHh4YzDKROwiKmB2tjvctR/
         WlKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718293192; x=1718897992;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=wgZAJQYwoKC+wcmLuJ9B/eLKRGtbYIM1Z3qZdBmbtsY=;
        b=ByrilOEVpNdjPduyTJyvwA8XwoFFJrPooCo+vmP+T0ph/bmMEXobQcNCFhXZjPh61v
         eHw9QzsUzp2dCzme2WsX3+fVYOYd6NYE9VwNhBxd7nacwhS8ZPBs3+D/V3ujKgUIvouz
         4rX99uUh6rGfz9pcbdgG88uWrymrt8I7nhaWOTBjcqYcBDP1864FQILH+fsrh/H8D0C6
         ZMUCb1XUQfQOPkIz9EHKOgQA+D4DSesthjBFkIVbDnznUDGPTvae+gPZVGdUHG5wF/GZ
         Lld0RPV7CYJ2l1PmtLUbDqwJQ1tmEHCyApwD8SKK5dNJnCoc4jCFr6icaQNrGRyFopVU
         oaTQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVw7+bOCmss2Bn9VRZNOR53xDDwnXQExg7X1O9iw/8XcNHyFgjZ715A5SWx2BJSOLL6lU782CTu2YG3MQEtkfuW5Jq9a+o5Wg==
X-Gm-Message-State: AOJu0Yw7Dz+3A6kl9YxPjc7CR1I1ocPUCzI+VP3aA6qYKUy+ef8PygUw
	6xBkxM0GD1z0e1TkVM1FbdL6j27IY80Q4q2wYPGW40HVKwqv3069
X-Google-Smtp-Source: AGHT+IGRKOC16ZqlHbfyF88l23n35JWDFwyF/nTzYGH4pv7MVBJTBllLqvtMljhRovOON0KT61t4EA==
X-Received: by 2002:a17:903:24f:b0:1f3:2d51:17a with SMTP id d9443c01a7336-1f8627cefd5mr281625ad.18.1718293192003;
        Thu, 13 Jun 2024 08:39:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:41ce:b0:1eb:1517:836a with SMTP id
 d9443c01a7336-1f84d439d5bls9132285ad.0.-pod-prod-06-us; Thu, 13 Jun 2024
 08:39:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX2ce0TRFcvGhuklaDdtaDVIwi/Y8s3ePnTrHZzdRD6ZCpd7PIuLLR8cYzdbIKfPry6uGhLyArw8GWWcdADxWl2Qq+GSNT3z8aF/Q==
X-Received: by 2002:a05:6a20:dda3:b0:1b2:b104:594 with SMTP id adf61e73a8af0-1bae7eb3b22mr175611637.21.1718293190906;
        Thu, 13 Jun 2024 08:39:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718293190; cv=none;
        d=google.com; s=arc-20160816;
        b=nL6FvnKML+3IJOQuHE1pRDqs7EXZb4E3iJfrKs0i5rp0wL0rhhgmvb2BwlzWDniUMf
         uhVqKgVRDgYC8Z0P0L8OHH9ez8GWsRoTS2UAaIE818sKtCVvf+WSy6J4E9cKW1BXDK5q
         It2CaYY1Iu1//4Eq3wQDzPLUbveDGTXWvP7y3ze/IleBgkFIBgu25cYuEtjNJWilKo9Z
         Oy3eNsWjMEvtiFssEtKuavbG/Pqdi/y7ojLVeWdOd0OVtRHrmPUoSAeRHjiB277OBeFG
         OQzh8b4X7l7Ueh2OfmdtquhsxXkeVvg+rbCELzu6GBLnOSpViQgrezGE+HnlvKBy+Rds
         yang==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=/gY59diCnvafEB+4mQiN4AxCmJVF2c9HWCLDsUZw+Ho=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=pwqbdNACSQQ6I2vE3qfMZeO/3dcHfh9gkw6QbTovixkD68KR9gfEhLrZDcC9uw2TIP
         E1+u4Zo1GIPlY6qARYQw3XDZy/XIjJpAh/HcVNdP1wPnDoNEtgfe8jagTog3DA8VHDH7
         e0EF/RbgEQ4MvbpRM/yIeYwnBgLdzdQUr8WbL3zePGGZSXIg2uvxdKJeoXi0bThdEhNB
         fTsGE11PGRzPJEgZApOLjxZ2znqsfaRlWTmYfXPfqnZ0OnKToR1n/gD/WomdxYiYvnPz
         JMZL6w2SBIHUybA9jqUf0LPH/kvmd9qjHA14+1RzBaP2JIZyhMKheR63N7tclUaQZX7/
         Z4fw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=VORhykUz;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1f855e2e1ebsi603015ad.1.2024.06.13.08.39.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 08:39:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353724.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45DEMmKu009466;
	Thu, 13 Jun 2024 15:39:47 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yr28g8buw-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:46 +0000 (GMT)
Received: from m0353724.ppops.net (m0353724.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45DFdkhn032507;
	Thu, 13 Jun 2024 15:39:46 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yr28g8but-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:46 +0000 (GMT)
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45DF54o7020086;
	Thu, 13 Jun 2024 15:39:45 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yn34nh0bu-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:45 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45DFdduK48365846
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 13 Jun 2024 15:39:41 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 7C5972004E;
	Thu, 13 Jun 2024 15:39:39 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 09E292006E;
	Thu, 13 Jun 2024 15:39:39 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 13 Jun 2024 15:39:38 +0000 (GMT)
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
Subject: [PATCH v4 12/35] kmsan: Support SLAB_POISON
Date: Thu, 13 Jun 2024 17:34:14 +0200
Message-ID: <20240613153924.961511-13-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240613153924.961511-1-iii@linux.ibm.com>
References: <20240613153924.961511-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: d5DLJuwF3n7IYysGR2MUKcLztsyMiSDS
X-Proofpoint-ORIG-GUID: gIfaDqrA226oT8V3lIkGJ1p31k8efaLW
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-13_09,2024-06-13_02,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0 bulkscore=0
 phishscore=0 clxscore=1015 suspectscore=0 priorityscore=1501
 malwarescore=0 lowpriorityscore=0 spamscore=0 mlxscore=0 mlxlogscore=999
 adultscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406130112
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=VORhykUz;       spf=pass (google.com:
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

Avoid false KMSAN negatives with SLUB_DEBUG by allowing
kmsan_slab_free() to poison the freed memory, and by preventing
init_object() from unpoisoning new allocations by using __memset().

There are two alternatives to this approach. First, init_object()
can be marked with __no_sanitize_memory. This annotation should be used
with great care, because it drops all instrumentation from the
function, and any shadow writes will be lost. Even though this is not a
concern with the current init_object() implementation, this may change
in the future.

Second, kmsan_poison_memory() calls may be added after memset() calls.
The downside is that init_object() is called from
free_debug_processing(), in which case poisoning will erase the
distinction between simply uninitialized memory and UAF.

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/hooks.c |  2 +-
 mm/slub.c        | 13 +++++++++----
 2 files changed, 10 insertions(+), 5 deletions(-)

diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 267d0afa2e8b..26d86dfdc819 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -74,7 +74,7 @@ void kmsan_slab_free(struct kmem_cache *s, void *object)
 		return;
 
 	/* RCU slabs could be legally used after free within the RCU period */
-	if (unlikely(s->flags & (SLAB_TYPESAFE_BY_RCU | SLAB_POISON)))
+	if (unlikely(s->flags & SLAB_TYPESAFE_BY_RCU))
 		return;
 	/*
 	 * If there's a constructor, freed memory must remain in the same state
diff --git a/mm/slub.c b/mm/slub.c
index 1373ac365a46..4dd55cabe701 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1139,7 +1139,12 @@ static void init_object(struct kmem_cache *s, void *object, u8 val)
 	unsigned int poison_size = s->object_size;
 
 	if (s->flags & SLAB_RED_ZONE) {
-		memset(p - s->red_left_pad, val, s->red_left_pad);
+		/*
+		 * Use __memset() here and below in order to avoid overwriting
+		 * the KMSAN shadow. Keeping the shadow makes it possible to
+		 * distinguish uninit-value from use-after-free.
+		 */
+		__memset(p - s->red_left_pad, val, s->red_left_pad);
 
 		if (slub_debug_orig_size(s) && val == SLUB_RED_ACTIVE) {
 			/*
@@ -1152,12 +1157,12 @@ static void init_object(struct kmem_cache *s, void *object, u8 val)
 	}
 
 	if (s->flags & __OBJECT_POISON) {
-		memset(p, POISON_FREE, poison_size - 1);
-		p[poison_size - 1] = POISON_END;
+		__memset(p, POISON_FREE, poison_size - 1);
+		__memset(p + poison_size - 1, POISON_END, 1);
 	}
 
 	if (s->flags & SLAB_RED_ZONE)
-		memset(p + poison_size, val, s->inuse - poison_size);
+		__memset(p + poison_size, val, s->inuse - poison_size);
 }
 
 static void restore_bytes(struct kmem_cache *s, char *message, u8 data,
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240613153924.961511-13-iii%40linux.ibm.com.
