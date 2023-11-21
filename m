Return-Path: <kasan-dev+bncBCM3H26GVIOBBAGS6SVAMGQEA3G3PAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id B739A7F3892
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 23:02:41 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-58ac3c313casf4790304eaf.3
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 14:02:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700604160; cv=pass;
        d=google.com; s=arc-20160816;
        b=TiFcZihezs7srJc+dsmTFE3vFzkMDHIxDNF3FUfZ0I7Hu5QxkSGpPC9w5o9L0Sdky9
         XJiGewveyPZXD/Rx0/NiKEoSzMFfr9FjDnHruUEgqMLdHclXoKJLWFWCexvax892h9J5
         7RwxB1B4Niab7u8nmxAjQ8/4TTSF41/1nkSmRjvoYVI3OEfAsRPf7UT1HrdoN23GVMDo
         tQPK0VfNF0Ht/rM6wUgHgG1VMLfMfwzEsE8Wd92FYv1Nweeim2mX74uqvSvcBHUqYka4
         DssP+RPKrp9mCkZY0Pqj5z47LgfvnQYeIBuv+O5Kwn871JmWP9GdOONVnm/3Hj8w6cM4
         0BXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=PHKJL6RU81bGiHtP81pXG93hkv29glPGYY2dLkkf6XA=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=sFwwCOxQKGpi3Oq83KV3kq3XKi3xTtC0L5qB0SegtSkRSszRHcyo7ORZmhMMxnNf05
         oYQ1YWea2G4qmbJB1JkylJkO4h63vldO1vVW2X4klK8QB2ES3Ph5XPhQ46ySLgpL22pG
         sLOyMpaAoG1Lu0du0DNh9kix1nFgBIPgMASofnQWKzJiU3VyO2pOqFI6xUnpawLQuKs0
         JIoGKhwV+Z9RYj3ZAo4yf1qlq2jIqoQAa6lmlimK2ijo6SkAkk4/JsXwGAgu4XTXp//W
         HnV/mJap9G/ogLEC4Y/I9Gs+haML4RARAfSi/bhHO0smsfogUmkJhvJK8pF1gXaiU/Rf
         MpAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=PE5rvZBX;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700604160; x=1701208960; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PHKJL6RU81bGiHtP81pXG93hkv29glPGYY2dLkkf6XA=;
        b=skxX6NkwG9JzKzpiHXbtCx/35wUBw603OxeplY6Hulp8q7NaiHSiH55VLnGvrgoXeM
         oZPPuzaZ1y52KWpumCdDhURhIeQzUokPmxs4ZVkBirc/KvlGT8+qGo5R8GVqwpQcJDRI
         qsrCx7Zf5l3zd7YN/HD4JFpoKCox19h6dNoSqx1rgZD8vgwsOWcRQMg6rBNB2/f465fJ
         qK/bFFJyGYrfiO9hGSl9vif9OURhJp4J0nT6G0iUtzg3GrmN5tSe/L1AsLDhUYJKtsCy
         4q/BIgXwj1PfN9LwI3W5S7U75CQ3+036vl80N4qyXJ2ib27SupYo1Is63wa/nz5ADg5H
         2HUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700604160; x=1701208960;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=PHKJL6RU81bGiHtP81pXG93hkv29glPGYY2dLkkf6XA=;
        b=wdjcA3iKfX3SfaFzDcPFGhvQ7HI03lnt0IXqplIE0JUElhpYE7ihUeytphvdm7yF1T
         VeRnK5LZ2exhbGHdD+hYUQY05cWmGQ45OwRJv/wDYHuF5/xlGobgiWPsXw/R3AQvjWK3
         6SimhczKz83M+dpj0M1Ob0q48hzgm4PdSxU7cmUic6Fb1k4Oh0aNgZ5Tr5Ujh8sgnNqA
         hWVnZ4EvT1xXBBc0ZGBBO+jkJPGO6lVjBF2rXjsGeiM4a9X/kB9Q/ctzsqJt6ryc1lbH
         bb/ozlenQ4HAuPn5vXCxEjQTJEOIz4e6D8gGjAV4WMbQY75EVnTTsdOAW1W+FKgMh4OX
         lgng==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwRIZLdaqoPlcyzHuM3qLsZCbTMTLVusnDnilpm38OsawQiatOB
	OU5p8ClScrEMGasrrYQp0A0=
X-Google-Smtp-Source: AGHT+IFjCWPCFPmYKF70reTRCRRBFAZ/UtSZWxotlR2eaKvV3ZQsy44fEIflKIj+g7q4zC1U5UTY3A==
X-Received: by 2002:a05:6820:222a:b0:582:1477:8362 with SMTP id cj42-20020a056820222a00b0058214778362mr948970oob.4.1700604160585;
        Tue, 21 Nov 2023 14:02:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:b87:b0:587:a4ff:5f8d with SMTP id
 eg7-20020a0568200b8700b00587a4ff5f8dls447925oob.0.-pod-prod-04-us; Tue, 21
 Nov 2023 14:02:40 -0800 (PST)
X-Received: by 2002:a9d:6755:0:b0:6be:ea3e:367 with SMTP id w21-20020a9d6755000000b006beea3e0367mr635548otm.23.1700604159776;
        Tue, 21 Nov 2023 14:02:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700604159; cv=none;
        d=google.com; s=arc-20160816;
        b=T1oZkyqQ3wkQyaxy+GSHQ9w0o9yWv87zo5ChHB8YJFtpjAKKnjp6ifD9RiYaQ0egvs
         8BHAng+tfAsTWlNgojCxvRhCN6icuiQbBTW12GtiMZ9hPlA8KH7hlRQjKnM2NycBfVqF
         WZRBANfp6Zmg8W/7En398zdOIuI6pAWEoryx4uEhP6ApeunJUz9vg6N1icBYTvAy93xW
         6ymPkC9kRjQ3FqWR38axa9hnJ7rhF76Ze46AHsDbbV58v2JzWZieIY7BYqqLdQ0anjMc
         iL2B25MZMzqeZhss6SWFQn5c/TWiJB+z4WU5NhagKs0a2/opPrkDmcS4HAhH/Uy4X1K3
         +B+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=8ulWVBzZN7+Eh8v1+pwjF8+VtqCEXlOniIAURZ6XsF0=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=MlwQasxCVZvrXmzTZMj02P8LYbECMz5HAcGDcTbI2guk6nW1iLMwx6EE7nk1D29GLx
         aYrA1OB5/Im607lj3VxJ+Ykq0ONycAXVtku/ayHtM9KbeYC0PxFAVP4pNh37wbo3yfAI
         rtjmtkMFbH/NQqINPO9jHU7EuNDu/P/pIe4ExzQCR5Uq6qb4RjurSZ4teTrcnT2pKILK
         +RQnSDnmdP0Otz1DqE9khFz43Ho8sFpidp3LdIWOH3+VgKHp9bfuAIWBY8O7GlQbyopQ
         g3DgS1r6iBnQaczYiD9tk3DXF+UCUHDfchPMXVzpSPtiPo30qWlheOnz1fJ70S1HLZPV
         4kgw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=PE5rvZBX;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id cg12-20020a056830630c00b006d69ecf7066si1825971otb.4.2023.11.21.14.02.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Nov 2023 14:02:39 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353723.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLNPww004545;
	Tue, 21 Nov 2023 22:02:36 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4dw0vpy-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:35 +0000
Received: from m0353723.ppops.net (m0353723.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3ALLmrxa011402;
	Tue, 21 Nov 2023 22:02:35 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh4dw0vnt-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:35 +0000
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLng01010753;
	Tue, 21 Nov 2023 22:02:33 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uf93kujq8-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:32 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3ALM2TVO53018986
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 21 Nov 2023 22:02:29 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id AEE5720065;
	Tue, 21 Nov 2023 22:02:29 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 47AD12005A;
	Tue, 21 Nov 2023 22:02:28 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.23.98])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Tue, 21 Nov 2023 22:02:28 +0000 (GMT)
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
Subject: [PATCH v2 14/33] kmsan: Support SLAB_POISON
Date: Tue, 21 Nov 2023 23:01:08 +0100
Message-ID: <20231121220155.1217090-15-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231121220155.1217090-1-iii@linux.ibm.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: Dk2pSCnouKh_Mi2qevl2yd6RHaco_mCa
X-Proofpoint-ORIG-GUID: IyYeO4Ls9Zhe1WDu9j0NdlseK0tlnQN6
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-21_12,2023-11-21_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxscore=0 mlxlogscore=999
 spamscore=0 suspectscore=0 phishscore=0 priorityscore=1501 malwarescore=0
 clxscore=1015 impostorscore=0 adultscore=0 bulkscore=0 lowpriorityscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2311060000
 definitions=main-2311210172
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=PE5rvZBX;       spf=pass (google.com:
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
init_object() from unpoisoning new allocations. The usage of
memset_no_sanitize_memory() does not degrade the generated code
quality.

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
 mm/slub.c        | 10 ++++++----
 2 files changed, 7 insertions(+), 5 deletions(-)

diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 7b5814412e9f..7a30274b893c 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -76,7 +76,7 @@ void kmsan_slab_free(struct kmem_cache *s, void *object)
 		return;
 
 	/* RCU slabs could be legally used after free within the RCU period */
-	if (unlikely(s->flags & (SLAB_TYPESAFE_BY_RCU | SLAB_POISON)))
+	if (unlikely(s->flags & SLAB_TYPESAFE_BY_RCU))
 		return;
 	/*
 	 * If there's a constructor, freed memory must remain in the same state
diff --git a/mm/slub.c b/mm/slub.c
index 63d281dfacdb..169e5f645ea8 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1030,7 +1030,8 @@ static void init_object(struct kmem_cache *s, void *object, u8 val)
 	unsigned int poison_size = s->object_size;
 
 	if (s->flags & SLAB_RED_ZONE) {
-		memset(p - s->red_left_pad, val, s->red_left_pad);
+		memset_no_sanitize_memory(p - s->red_left_pad, val,
+					  s->red_left_pad);
 
 		if (slub_debug_orig_size(s) && val == SLUB_RED_ACTIVE) {
 			/*
@@ -1043,12 +1044,13 @@ static void init_object(struct kmem_cache *s, void *object, u8 val)
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
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231121220155.1217090-15-iii%40linux.ibm.com.
