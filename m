Return-Path: <kasan-dev+bncBCM3H26GVIOBB6GL2WZQMGQEWR5AAMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 47AAC9123CD
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 13:37:29 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-43fb0603968sf23723601cf.3
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 04:37:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718969848; cv=pass;
        d=google.com; s=arc-20160816;
        b=oV5EQAUvJ9ZDjfWKpGfZ343DZWD43nGs/jIOIdcqDdeqDIL4DTCUiK8TKTnxL/pAeI
         2Rz0xjc/D1d0xgMuwWnvCl9I7lxaxxvIuvSjhFhFeU/epm0za4YNPlB16t90/iV0J5YH
         a+60EeniEHO6POMnV5+GwYGX+UZCPnpgOOBtzmd/IeHu6YBYO2TTVQZ6616OpZZJmDvB
         l5vsQg//Sp/xUy/R+4wT5gh3tMPDv3kTB8nNAczpQ9B3TTn6NPIgsONRKCXLCO1FpQ9i
         9iqu/V+5au9VC+lcAckgiZQkZKAhmxPoHnLYv24TzAtuxP9sZtcFgxcLkL20OgKkjKHV
         3MKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=0tyBCI3KVD41HjaQyuetAI/lyOJwxZvZJELfLpUv4QY=;
        fh=YNCnShAsg5Rus9cUzLzCJQcfNdgjRK9mOJ5nixcldlg=;
        b=ZeLWPeUuOvDRHu0fp5sdZDHDCLcUtM+n7a/ByBGkmdgwCkCq5o9ldrJ4eTnIADEP0Y
         ViK4KW3MoEC2zPqXzqERk89COSaQpK1bFk7o8OyX4GQeRuyN7wysCqbfZEb/Hgzue9Up
         dDosgerReH/iTcSuPdlMhCGMOGLeS+3X48k4Ket8gvKrXt2kzJAtkdzVIdR+tKlu/U2e
         FckdcjOB7AwqKjHl34n9cQrlVipj8DvwHu6lQxK47j+dCnwa3v9a86+07+BFQyevyWd9
         zHxikapiRyn/bTkjgiNFCgMC6RfBxWny9qlrAlvDUPPWij3LH05gQE9DxoFKtrkcE0vs
         SB6w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=d53ohrC6;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718969848; x=1719574648; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0tyBCI3KVD41HjaQyuetAI/lyOJwxZvZJELfLpUv4QY=;
        b=pip8EESrsbzUOJsHhGCqjt3mBAGpWHoRJ7Wiphv5Y+rYnvHD4clx00kCf+38y3QCK6
         ki+7Kxl1QbVNLcvsdcqenzrvR2voiyOUqSAEspbF3DmN4AGV/7icyA0JY/yO/JvUrWeO
         EAcr4dOzWa1qmFacVpIeMHHmU6g9uRWpFzJJIo9MzRLo8JBFGdbtWtYRIvQ1lsmTXtmW
         25O572kxFIGd8lQgFhY7gRJvM80pzFbmkwKGq2tuHNFsoZDIkbqu3RPy54GeOvGU7sv4
         jBtccnUUeKzf55Q3t40zmyg43UyLFWYOruSQ6OoGvkZnfeq6Y/vUZGDsBm7rIb0sPbIm
         v9rA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718969848; x=1719574648;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=0tyBCI3KVD41HjaQyuetAI/lyOJwxZvZJELfLpUv4QY=;
        b=lQmJLlCer8uSidziGpGxXMlJF20rbmKJNa79/gorkxzp4ficNf7YmCP9r60dYk0nJ2
         gimsjlbAN2gPK71aIxaOQ3q+MyjYGo8mEo30UO4At40vv9IY05JgWWcImRRHv/Ziu1+Q
         AAjq+R/7y19P31l7k1tKOLGmjoKtaznsMDDfFr6WiPA684RTjy72DEiawi2+SVjEW6jA
         YyK8nV8zVYQu5SEWSsyYCkoY54oZS4KRNY/XtQ1IQz3VUkMSCteK9Epm9Njf5mYtBj5d
         /ojXYjqMFGPoBXolvBT3QmZdg9ahdtLhdzrXCRA4MOsAO3WsgysKpT0nxueSYXNLGHf7
         8aqg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWc/W1vElNe9djjamGpzk3mHBIbHJAMg/ncDoKHRGaeCqiLzMgFIwAe9HoITAsJjrDWf36qf+Opd1NuPRJd1Xsp2NnQ3Kvnng==
X-Gm-Message-State: AOJu0YwgreZOfpEa5TeDOaMO6QCDhvtcm/T1P5etuRZvwRTaVD9H9oDy
	dnh2I0nn4nWTYb+1DQMiL5hm2cGJ9IrjNHkLGVJHA+c8+CWE2vrk
X-Google-Smtp-Source: AGHT+IEJXTa5WelbvlJrFKL3DLkqGNTAAH+iTDmN6e2bcUWmX3MKsNtJf253PDSv5cfoxtdLir4iFg==
X-Received: by 2002:ac8:5e4b:0:b0:440:f0c1:1caa with SMTP id d75a77b69052e-444a7a6aecfmr78382041cf.65.1718969848294;
        Fri, 21 Jun 2024 04:37:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:207:b0:440:29:dfea with SMTP id d75a77b69052e-444b4bf0399ls20147131cf.2.-pod-prod-09-us;
 Fri, 21 Jun 2024 04:37:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVM7umHPyngtafUZukgXevD/tG3VVdB7hYJCRJwRFEX3RTt43+LFVX+S7uKZFprEYpYQ2eHWJJwWIDlIxfQ1BOV9D+LqYibvm/gvQ==
X-Received: by 2002:a05:620a:4403:b0:795:1ec4:8b65 with SMTP id af79cd13be357-79bb3e113bamr908850285a.7.1718969847675;
        Fri, 21 Jun 2024 04:37:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718969847; cv=none;
        d=google.com; s=arc-20160816;
        b=AkiYwOy2E5JYJWVlnIZzhVfUPVFdfGYdMyc83rt0slI5NPN6QGBgWc6dgwzO1eWw/2
         QLVKst/q6hKmtac3L85FzFZQzN5MIdzJiAOaVcTqCWiTIstwVzC8gy1bf74NcPJFrtj6
         SuSegJp2FKGL2WmFkvjZABAVfAe4HEdd5+YiH4htyedJXFHt65wPfvwRVTZ2brm+B4M+
         3fgtGknWp+ygE+fwxIkcOPchQdfVQSxnXJHbNKrFtw1TwyfdmreItZGM93uRCs0SD3Op
         Yysi6r7BLjhhkLxqTHm8sBLGCr2l4e+4XwV/atzLWkT8K6SZSyrJz2qOXZl942+P9KIH
         Y1QQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=iiouZTMCvClKngmKPn1JjWUn629yRa6ZHvuTIcvWLUs=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=KKoUDyeFeoswhjK/Ps0g/hArJ5KPu10xbC1u23cpBZhwpbUaZLExmM7K1+vAIYA2r/
         WUwRAltanXlbzw8bwWCIbyJ4UMMXesiEQseY8jdbz/3vPtmTzAW9+D2qh6/caJjtmZgN
         wYDClI/zbulaONUWzZdPjhq+Y6JdpRb8n5eHYzyp+g0Hyy9izbuEofozdzfVhgVN7fvh
         Gqfy8/vkvNdmDNQ/3BMVp6m6ZsP+HrQPoDM9hcWswphdNPgC36mI0ulBOYDJUh6BcSnW
         t96+6p4NU3BVRl49BHoLQo2KsoHh0eVvr7VkR+AxUdbmwLTU7x5DJHsN9CrZE0JHcZG2
         ZK7w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=d53ohrC6;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-79bce86d2c9si6137185a.2.2024.06.21.04.37.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2024 04:37:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353722.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45LBQuSl001097;
	Fri, 21 Jun 2024 11:37:24 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw5krgf23-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:24 +0000 (GMT)
Received: from m0353722.ppops.net (m0353722.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45LBbNal016934;
	Fri, 21 Jun 2024 11:37:23 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw5krgf20-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:23 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L9F81M032326;
	Fri, 21 Jun 2024 11:37:22 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrsppv5e-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:22 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45LBbH7Q35389942
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 11:37:19 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 2723B20040;
	Fri, 21 Jun 2024 11:37:17 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 8E34120063;
	Fri, 21 Jun 2024 11:37:16 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 11:37:16 +0000 (GMT)
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
Subject: [PATCH v7 13/38] kmsan: Support SLAB_POISON
Date: Fri, 21 Jun 2024 13:34:57 +0200
Message-ID: <20240621113706.315500-14-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621113706.315500-1-iii@linux.ibm.com>
References: <20240621113706.315500-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: AXXBYtapU_rN9jsF44FBcnAqK_EvV2WS
X-Proofpoint-ORIG-GUID: LrbOvUrt5ynjpDNlUNNtbRzRMwGJYhR6
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-21_04,2024-06-21_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0 clxscore=1015
 bulkscore=0 spamscore=0 phishscore=0 mlxlogscore=999 priorityscore=1501
 suspectscore=0 adultscore=0 malwarescore=0 mlxscore=0 lowpriorityscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.19.0-2406140001
 definitions=main-2406210084
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=d53ohrC6;       spf=pass (google.com:
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

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/hooks.c |  2 +-
 mm/slub.c        | 15 +++++++++++----
 2 files changed, 12 insertions(+), 5 deletions(-)

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
index 1373ac365a46..1134091abac5 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1139,7 +1139,13 @@ static void init_object(struct kmem_cache *s, void *object, u8 val)
 	unsigned int poison_size = s->object_size;
 
 	if (s->flags & SLAB_RED_ZONE) {
-		memset(p - s->red_left_pad, val, s->red_left_pad);
+		/*
+		 * Here and below, avoid overwriting the KMSAN shadow. Keeping
+		 * the shadow makes it possible to distinguish uninit-value
+		 * from use-after-free.
+		 */
+		memset_no_sanitize_memory(p - s->red_left_pad, val,
+					  s->red_left_pad);
 
 		if (slub_debug_orig_size(s) && val == SLUB_RED_ACTIVE) {
 			/*
@@ -1152,12 +1158,13 @@ static void init_object(struct kmem_cache *s, void *object, u8 val)
 	}
 
 	if (s->flags & __OBJECT_POISON) {
-		memset(p, POISON_FREE, poison_size - 1);
-		p[poison_size - 1] = POISON_END;
+		memset_no_sanitize_memory(p, POISON_FREE, poison_size - 1);
+		memset_no_sanitize_memory(p + poison_size - 1, POISON_END, 1);
 	}
 
 	if (s->flags & SLAB_RED_ZONE)
-		memset(p + poison_size, val, s->inuse - poison_size);
+		memset_no_sanitize_memory(p + poison_size, val,
+					  s->inuse - poison_size);
 }
 
 static void restore_bytes(struct kmem_cache *s, char *message, u8 data,
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621113706.315500-14-iii%40linux.ibm.com.
