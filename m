Return-Path: <kasan-dev+bncBCM3H26GVIOBBLX2ZOZQMGQELCYSHCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113e.google.com (mail-yw1-x113e.google.com [IPv6:2607:f8b0:4864:20::113e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B21890F2A0
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:45:52 +0200 (CEST)
Received: by mail-yw1-x113e.google.com with SMTP id 00721157ae682-6311e0f4db4sf124925427b3.3
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 08:45:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718811951; cv=pass;
        d=google.com; s=arc-20160816;
        b=xUJjW9b075IPuavxIo0wLs8bHX0vKoa79Ub+2h1AW99zywfo22CBK6+Xg8b/j9RUv8
         ajBpY4RtsAOv8SCh+9UPbXkEozk5uaFgrJXBIVKC6QAgxn/kI5YNmitHGS76CycMZQE8
         jtGf/qNUmVH6/umRnrrmyDfGeCEGOJodKxK98Iuqc/gjxkp9v5nHNUanmlDsCjRKfR+w
         qiRPA92mvGpgTPX1H/MgZc1Tn3JA4TtSY3qADcYz6Tr0VJ1TM9VVIC6saQGyq9GbWNu1
         2cb/O5DN97gxaNSdYePJyKblmGsqQCsBwdwCEVhqi8x0fw35PRWXMElN079rIFbOPpWw
         fxPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=/cGn0+F+5YOB843jgVrM7VBZAJXEDhpWKBaM4lzyATo=;
        fh=39Rga37bhdWxZdFAJ0zSeRvJviLBy5AppqjWs0TbStk=;
        b=aAUcCq+cKXRWqk6AQXNMrl2IKlVtFzDHU78hfWXmja0YddjUoUzBIVZo7Rqeu7shxN
         7+op38ybBMv+a23OV1u2+DyIFC9fkRts9uPT/WHwhP1GHm0+iPIhBWSgq96Ix/uj5mAx
         hd1WUAlkvnRdFCYeAxW7/Yfi5sASrZBJJiEr40RZWpe1XA+AvFRN//I/mPartPmJk/mD
         n/AgJ7o5FOUh7AI+Ks4OZXn9J/IdgeBCg4cEvKp4EPYWytPFxoBcW+yD8hYgwg6i7FDo
         JCKInT5v2uPBTAKPeK7W97sG+cyOm8ephV70+3Q+aLsfM+E301h3o0LKGGlYj+HbZ2pX
         veqQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=LuP4TB7R;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718811951; x=1719416751; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/cGn0+F+5YOB843jgVrM7VBZAJXEDhpWKBaM4lzyATo=;
        b=jWKnBkQq7jkLoitYgA+LIYa70iNMeqS0Fl2JooZWMhC3ANgmzXBtbh9DqZSQBq3ord
         v5BikDdxFyOcdE6AtrUA6z5ZWzfCdvp7pIgqL72Um8N2XlT+BKrCtJ/O+OCmZF3Ak2xT
         x5moET4B7v66w1bmB12zESqzsiX6NIUKfug+qTP48YW7M/kHQ9YzMgA8bixKJjyqKMlb
         f+F9o1KM8cvn9EJNt2qt0+uehWgX/j1khx4Lkjb4CAICWcnX6lfauWsa67fma834RTJP
         gYSp3ohUdYJoUnpqw+FBP7vXqCR/VQPyjFdYGVWJl4it/gMilCexilgXEtSIQIs56ky+
         vDWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718811951; x=1719416751;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/cGn0+F+5YOB843jgVrM7VBZAJXEDhpWKBaM4lzyATo=;
        b=WVNOQuHD4Dt6skIp88jOJUKBkjG7eQA06eYuSDA+/TG9IXRotNWvJNoRmsPI1HDPXI
         v1pNxm3UENmdohnSvfX2mjkTiSjANCADY2wbOkrdxjY7sgWhveSUeiFsCgqsH/TvmnMh
         zrMAdCOuhoZCbXAhwznJqRAiKN+c5mlQsqVk21/3rnNbbgBkHKq9c+XEO67c3FkqrXhh
         9uftCUlAijV5NoJ48zqvlXepFPCz2UNgyd4yPwueKPJCNcdzw78D3x7mRZ392TEdGC39
         mB5Kw2GW2Kyx7Vqsxh/F5RJjKO3PV+omuoJBIa28EcTSdiAJOps81T5pc57Qh5ZzFBL+
         uuuA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVXS2iVmio7Van/MTAr6QQpXzlX/iiYTfrYuIV1pc2zihe9FMgoILfUgrjQ+HhX7WhHC2Tlt5XyG3CCMpih8tlBCf5m2FYvkw==
X-Gm-Message-State: AOJu0YwL7PSk0CHwcenFn9pIYQ8R1EiPHn8wdbTqzEizKtBh4ZZBH3fT
	7GkeLrWK24jdNmVAyk7x4qiNCT+ZtSUbUQWnPRDkAHZgaG7meQ0+
X-Google-Smtp-Source: AGHT+IFKG4OfUIjSMiNeGmzZHA6WsAC24Ey4nWBVRuakar8wRsC5uae9J7CNUkrCcL3GkC8vJmCnrw==
X-Received: by 2002:a25:8489:0:b0:e02:b518:7f15 with SMTP id 3f1490d57ef6-e02be1719b9mr3260376276.34.1718811951015;
        Wed, 19 Jun 2024 08:45:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1895:b0:dff:34c9:92f8 with SMTP id
 3f1490d57ef6-e02d0ac0766ls12861276.0.-pod-prod-05-us; Wed, 19 Jun 2024
 08:45:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVEl/6mDqIYruIzL8mU1cY2EN0DzdGxsKfKrWjUsFEtNL7mJWpX+HSNFeYTAKSma+WXbmms/NivLe0QlgLqQAKpYf9Aub7ZmVxJIw==
X-Received: by 2002:a25:df14:0:b0:e02:b90c:fc5 with SMTP id 3f1490d57ef6-e02be102341mr2970372276.12.1718811950308;
        Wed, 19 Jun 2024 08:45:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718811950; cv=none;
        d=google.com; s=arc-20160816;
        b=UdDPHq2dkhkrLKybzgTjs0FpJCboSsI5vX5jWrhEqm5kvsIyW0bpDc17gMHY7wg+Hi
         2BmmUm16wqIaJ2kv1UP84ySBiEac0NN5o7oGuKT8tCyKZ6bSuuuoR64zt0Tj2InVvZFb
         X0VdUKAnS1jMIruwrLBEyuSDQCjUiiwh1Uk14aZGAQmSM9yQmyxWZ6uewdfld1bRpuTZ
         2baZYg9c8LthlKb+QMQlAzeAGxmCqvqjvaFBLpYVGd8ASCNHbHA7FB2XQqB9l24tNUGL
         FDWDTgfPmUSCfB32ZT1wJPPSEsatixhJ3o5pfdx7H44wrYN6vK8xrUcaWaGLnc3X5YYn
         5SWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=s29Q5OzIygT4UHJ5zziThxrqJQB5H7WVOZbTWfWq5Kk=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=AOMlqizrPjiBPjMPZqMuLRR6NG92ujv+OUJ5WT8ALjAcraF6kTp7znSmcT3NzF7lAM
         Xxc4KmxG1Rw+uJ+hsZffmPFQqlWsYslYmoweocVRLGanJ6/9JREmgOCcg0sr2LpKd+IQ
         O3mB4rA1S1cOYWVFaEz5rTJFLLLHA1R5bWB5SchRtJVWLjOoG7fQmVDD1BwHK81okO2U
         azAAXWFwIU760Jkh6wP//oisUIJrJEmoutJ6zavwqoS5Nti0IHzqNzsXPta0HpO5ISeW
         1D2SHF/RL561bob2o2m0i/Sr48lHr2AYqjKRROxE7O8hjyIbRIY5DbJWPpM7Dn6FjN0E
         3XPQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=LuP4TB7R;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e02b85c0a9esi240895276.3.2024.06.19.08.45.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jun 2024 08:45:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0360083.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45JEQaiH000931;
	Wed, 19 Jun 2024 15:45:46 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yux3fgupp-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:45 +0000 (GMT)
Received: from m0360083.ppops.net (m0360083.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45JFjjgr005244;
	Wed, 19 Jun 2024 15:45:45 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yux3fgupk-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:45 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45JEmdqG013385;
	Wed, 19 Jun 2024 15:45:44 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3ysr03wkqp-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:43 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45JFjcVd50659768
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 19 Jun 2024 15:45:40 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 68C1E20049;
	Wed, 19 Jun 2024 15:45:38 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 1A7E220063;
	Wed, 19 Jun 2024 15:45:38 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 19 Jun 2024 15:45:38 +0000 (GMT)
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
Subject: [PATCH v5 13/37] kmsan: Support SLAB_POISON
Date: Wed, 19 Jun 2024 17:43:48 +0200
Message-ID: <20240619154530.163232-14-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240619154530.163232-1-iii@linux.ibm.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: KYH5t4Sb11YAqzz4oXvn4ytz6Vv06L_-
X-Proofpoint-GUID: guJGVNqH8e1n_84FGAC7fsHfL-QDgcCC
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-19_02,2024-06-19_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 bulkscore=0 clxscore=1015 phishscore=0 mlxlogscore=999 spamscore=0
 mlxscore=0 malwarescore=0 suspectscore=0 adultscore=0 impostorscore=0
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406190115
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=LuP4TB7R;       spf=pass (google.com:
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240619154530.163232-14-iii%40linux.ibm.com.
