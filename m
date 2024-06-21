Return-Path: <kasan-dev+bncBCM3H26GVIOBBSER2OZQMGQEDBGFULY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id BBAF591174C
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:26:49 +0200 (CEST)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-25cb2c198cesf2056036fac.0
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 17:26:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718929608; cv=pass;
        d=google.com; s=arc-20160816;
        b=kphn4eWki1R5UkGDHMtJ5D0HdgcUVwmRNm2YMUPguPUpsj69gWfyigivx24pMMVWqY
         nv86AVHpva2SD6zMGt0iU55uoyMKrYVMa4/x/fkSguGBV8C4ni0uLwVh41LD4dbUcqFN
         x2+IGNXSniQMQvBRthSQPncahzAji7kxF86Q5Suf63EnjIu76VVKe1La9GgZaXPje1OV
         OlMrythAiilGQPKLISJMXq24MnWUMJQATW/A+nfHeSQOUb2CEKPTo1tNfVcVFr3VDcIk
         0rPcb0AVGgt1sI/LcZtRZAgvfE+ekDC/1zXXxKGi0J9hJfHMoFqUIwyyRIwNA5JiqKz6
         kWDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=jHNrw+cF41XCDvHRWtYivtZEO1/MYwyw5fUHPsIIB9I=;
        fh=T6iOoNmeDn6bSt86iv5CuX42LRyRDM5VK99fuLTH8gc=;
        b=soA/NruNrhlJ1HjbNMGQB/ZaD0w1WZALweZaxcQnkqg6I5Q04aVJwMo7kDb98PTWEX
         Nmaec7KTE6ukBOiTOhwk1gJ38pe4TYDbxVISYhGGfjz5YwcmdVT3iFs5/zaUT8wdlxqr
         n2n82MWZjK0uvur1GbHAwfAkqNSdvYHU/1ALZTuNgyFO0Xh5lVeWRZHT4rDyPPC/Do1j
         3EN8Q8GCXseBriq3QaOvLgYT7oF9o6gmost6eXgiXKEq04FxeWfEnsoew8I7fjfKkUuE
         MuXHiNfAqoxa5/OgjcuT8wwXxoRRw4/CItN++nKAgYPj4RfDhS7I7U0UDbyO7Wibl0uZ
         QNzw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=B1UAL0du;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718929608; x=1719534408; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jHNrw+cF41XCDvHRWtYivtZEO1/MYwyw5fUHPsIIB9I=;
        b=LYUAm0Ky+gDuwpz2/BoeRLkuyOoM2BOJzoZ2Vbg28rMZF5xQISEF339sX/oMYCa2rL
         4Ku50/d59gXl78fVZoQpkNZuygJ1SJqKOhO1XyD7LdvnwT/haSCX3jAQ5PKPafE8qave
         Qy33iFczOPhkLB/RsWg5AZtrDSTBQ+duV2Kmrmjig9OlMGYrg5sEQ25z8wHgERKnAUDI
         rojaG9IukWfRVSBc+PhLRmzmfjeQ0x1P4FVeUhnae2YcJ28a7GRuvMBrRjCIkAh1YRv/
         4qQ/yGjGBPCUdPprFnv3bHRPW08PivayetMPVARKB85tRkcizQXQ9N5jwRo7vv+NIehr
         DLuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718929608; x=1719534408;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=jHNrw+cF41XCDvHRWtYivtZEO1/MYwyw5fUHPsIIB9I=;
        b=VuurC05TX2+B9Xf7ibTXqPGeruArA3yNTFS9NJT0ppBXH6PNRxFH+y/R0sxbg9NfL4
         pfxHtzy1nBfS0M/jombxf0aUchSqobxIUCySku1J1Sqgsw7Itma0y4yzCy/txA5fGN7O
         tftSQEpMgG8SQ/HvLv8znLDvFISA0PlRiA8RoAiykxwtkfW333LFzAjgWRHx4Pb5Y5q3
         6qjedfpzmI27HSEL3nEWEW6bxBH2s4z194QVrB9HSwxnTj3ojXIvBRiuxEbxSDicA2s4
         9BcSHXzIrz/vTK8f56iST1xRS0j7g0qqwn2FWD83wTwFfxPcYNVfPLhD9So9gDgYF214
         NtTw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUaYU/UE4W/ucPhl6uRo+mgci6RaHN22V/tN+h9K4pohO71XEAm+9dzqDpg7p+Ex5PyE9dpnZEgShmVYD4cuWcSGtZxTTIZ8Q==
X-Gm-Message-State: AOJu0YxHm3PyY9jKTtcK7yXcx2BsQYqWK55qurf3WDiQqHUBaTYlDLro
	3gQTIhWPlWRRGU/vA1DSpIdIROURHNUOtiwWsyB4yIhZh/nCjEBb
X-Google-Smtp-Source: AGHT+IHbEfkj9TH2MQ+rBd7po7CHgJeKAs4Zi9QclcivRfIDwCvGlszvO+3X/RBCo9cmR8LJB0+J2g==
X-Received: by 2002:a05:6870:b50d:b0:254:9501:db80 with SMTP id 586e51a60fabf-25c949a6b97mr8089724fac.14.1718929608550;
        Thu, 20 Jun 2024 17:26:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:204e:b0:24f:6f0d:5f4a with SMTP id
 586e51a60fabf-25cb5830058ls1519212fac.0.-pod-prod-01-us; Thu, 20 Jun 2024
 17:26:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUtV76uy0n3oIo+N0FFYow8rf9C+VLcEjp2SbVP+OtMe2uw7Fx8itZUgzq217iz5+M3B0czL86aIrJpWsR8jLjzR7s5hL7FhS3Tbw==
X-Received: by 2002:a05:6808:1153:b0:3d2:2ee4:458 with SMTP id 5614622812f47-3d51b9be53fmr7520448b6e.15.1718929607784;
        Thu, 20 Jun 2024 17:26:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718929607; cv=none;
        d=google.com; s=arc-20160816;
        b=a6Gi3CfIN6j7PyraWjLkGK6m3huS4cTEts2iRdZGMZJ07SK8jUwrmIpF4L0nWKEr7a
         N1bc9UMT0Wfa2en5Po565ZOykTT4btiOWJmY2iWIO6FpHqZ2lKp5S188GOAuR0wzqSDE
         FeQa7AVh93VbCcTOjhmwmHnjJOq+r0Y+4wPxlW4WcziHu6HhZoSPahrv5dKVsg4B8JZy
         alXZ1BiJSA/u6024mfvD2PVmX7znDUX/Dca/XNmFGGv6B1FVxHTsap6YXYlTAETsGBoB
         NtH7lnL4oYv1mSNPQ4aW2QqmEQ9EVvHV/wv3VrxWAXYPfaTkC7aj8Ekety3yIauolQOL
         mHAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=iiouZTMCvClKngmKPn1JjWUn629yRa6ZHvuTIcvWLUs=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=zo4MIoo0BUtazlojgs9bQYOeURC2gmwj/9ZUXOgcUXX+Vy29ZiLIumpoevdtzzOpxY
         68nCn6f6C2hEmNeXMaCahtSqVnPMDzy0WXzGjGQ6PI/smzzVNescvsdVp4MrVnceD1KV
         9Qo4GZrKXZwx9JVz2ypkk3kAbCaOZjDi9ShVKJdDINlfHTSDtsdV6sIiQDr7OLHDr7Xx
         xoxFLJmdCIHA+nhy+YIYyIg/b6dMvYGJoswRhhcSb6KyCjEvBtGnHCkpkzknBbzMgeLb
         UZ5/McqH/OC70oGt/mDszlImMUZNE3DjdYHaS2/K+kZsjjxo7puvvs08QErLkjYjDewW
         iM1w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=B1UAL0du;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3d5346875e2si20677b6e.4.2024.06.20.17.26.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 17:26:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353724.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45L0QhnS022702;
	Fri, 21 Jun 2024 00:26:43 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvvs6g7rp-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:42 +0000 (GMT)
Received: from m0353724.ppops.net (m0353724.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45L0QgSS022650;
	Fri, 21 Jun 2024 00:26:42 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvvs6g7rj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:42 +0000 (GMT)
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L0LGDS025644;
	Fri, 21 Jun 2024 00:26:41 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrqv2nm9-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:26:41 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45L0Qa6U19530072
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 00:26:38 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id DEF162004E;
	Fri, 21 Jun 2024 00:26:35 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id BE4312004B;
	Fri, 21 Jun 2024 00:26:34 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.44])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 00:26:34 +0000 (GMT)
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
Subject: [PATCH v6 13/39] kmsan: Support SLAB_POISON
Date: Fri, 21 Jun 2024 02:24:47 +0200
Message-ID: <20240621002616.40684-14-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621002616.40684-1-iii@linux.ibm.com>
References: <20240621002616.40684-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: NqZMycCOVADYhS-1sceU6oAJBHDthSX6
X-Proofpoint-GUID: GjgcOBy8XnMNvwuhP2fJxePLnBR37qk8
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_11,2024-06-20_04,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 bulkscore=0 phishscore=0 impostorscore=0 malwarescore=0 mlxlogscore=999
 lowpriorityscore=0 clxscore=1015 suspectscore=0 mlxscore=0 spamscore=0
 adultscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210001
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=B1UAL0du;       spf=pass (google.com:
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621002616.40684-14-iii%40linux.ibm.com.
