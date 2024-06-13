Return-Path: <kasan-dev+bncBCM3H26GVIOBBR5FVSZQMGQEWWPCG2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id AC30D9076DE
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 17:39:53 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id 3f1490d57ef6-dfe148f1549sf1390217276.0
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 08:39:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718293192; cv=pass;
        d=google.com; s=arc-20160816;
        b=DKbudJbQpJerjLNRxKpWHU3hY0acXg9sbcARsx3db5sE8OUGc678GuKNZ4obnY2m2U
         aWnL+isAJvTKNWQb38J6dgy/vfclAA3JpEHxVbFn9SSWXJRkkAU72qq29o/EHZrkJl90
         eQicF0LMk63YtetB+nX/DZrOaAbzheyzxMvUKrtuC/Sw7lNvNIK7iLfY+6EdB4A6+M+i
         emKsmpZKCeglW/Vs8mooYdGjvMWKjNxJRQAGBSu9CD3JsMGnmBfsKYxUlOXJSthSq5LC
         tDmHuW0AfNJeIRRGyN/rt3G2BTRMgYfnlGgJuN39vUlysmCOMR/M2AUoi6/xH+zrQaTo
         1bLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=z18lQPqorGO393rnU5scLQy1XOnQW31rQApdOQ9uaKo=;
        fh=Ak6iGJ14O+x5nhIk1Q9VdBnaWuQnguGjxU419RGwCFk=;
        b=TvNQ65m+V6VvB8AB8MZsY/E4i0O4Q901y4sSW1l/UeLhXBjrofn5QoohTA7gdzkLgZ
         /Z7KsrSyPUDVsFIktOy0/drEgv5iaVNH4a31zmu8vuzho7prrCFJJGaDBC2rhB+/0NTO
         tXLjg2H25YKgknnzqn3rj68yM14VJx6Q8HZPuWRkQrvITCtWXk49j+M+E/5fxWcp9cyX
         eOEYvmt25C8lN+4EXzDC9irOgAqdBrHqNvwNut4hMCIMx73D9ORVWOSISXUGA/DdkfR4
         fD5PLTcdrWtszgSkOBJhqt2CDbJdJv+JJenujX/5dP4DRcOIFSisikuEtVVY3oIEhNzx
         FMTw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=oo35mO8s;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718293192; x=1718897992; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=z18lQPqorGO393rnU5scLQy1XOnQW31rQApdOQ9uaKo=;
        b=WZsl2BkjulK+JcSw3YMEzkU9gTXPGZPN3kd6YnaZ8GGHwVaWbr6ZYYHf3mNOHrdFhE
         hNmo7vcG3hEsjj3HL1SqGnfiPp5eWGZtIne8C2Uhq1n94iJSgXVioehTq9frT9Sq2fTq
         t3w8emdtE1FjE4okiZqCyYiTjVNm8vmkue/VwL3H2r8b0WgYuQR3bSzlLVCspeH5vzRV
         By6VSbPV78gvBl4STKhvvN81GXmynmX4xc9CkwqbowGJjLT5iLMOAgZcMrPRCil3UNgX
         s/58W3SIs1kRlwqwEkXBpv6j81tl+L8v/Xl3Lk5kpTOX13wrlkee6570RlywMbgFyeQg
         opyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718293192; x=1718897992;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=z18lQPqorGO393rnU5scLQy1XOnQW31rQApdOQ9uaKo=;
        b=FCsOScsjjJFLV1VELveknTNWviVM77Pl/LMvv8zPZqFbX22Hfb4VVwflgNQA00AlEz
         42zNC8AXhswCfUECXF6uj5AHRMH28zgz359uxxGwohVpyAzAfx/LXUye9n7vrO8U7vb5
         h+AXY9+PNbh0Sy0Mn3IXbiTwmB2mr8KpPyjzUM6qNLCBwOwxHADzaVJLydJze5mtag82
         THmNf9p/GDI5UC66ao7aiy1eTuKOPLVkWsQuDdYn5/MU3x59mD51Qf1DiP1HkbD7klYt
         fdVe/sMRWSwCCL+rsbFeIX9IuKHjJRKA0LXanw6XRQmuI4KuDfynXHN3U4JWROreSpQ2
         XvJw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWy9EvSZQoL6FFy1jbhMPm9PQ0J+3GOp7VZYkKKRwmJIv71i6HMf/+Pd8NMbmKAi1pYmfXib92yyHfkfdinz4YhO2+kbUoxvQ==
X-Gm-Message-State: AOJu0YwrDJKkONqVIGgUSDRdaCBpmlbRnlxYYCZ9y120W7WBZqIKX8Xk
	EIHvDNxii39rwZAzcCOd59Al4lgqoUP896RklNrYujz7W7m2XkLv
X-Google-Smtp-Source: AGHT+IFUEJXdF34k95+O9JIQz1Myq/MtUbVXTUzXn6BCUVFH0+U8RliCow6GnRQRAT22787kZq8AUA==
X-Received: by 2002:a25:8892:0:b0:dfa:e130:3144 with SMTP id 3f1490d57ef6-dfe66a6b141mr5447935276.17.1718293192181;
        Thu, 13 Jun 2024 08:39:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1249:b0:dfe:54e6:8233 with SMTP id
 3f1490d57ef6-dfefe6e2bacls1770544276.0.-pod-prod-08-us; Thu, 13 Jun 2024
 08:39:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX68veZX5IBbfGH7VTwlQnDpS/flilCNL6onh/7sranTTLktIr+dBBL/sajXQXEJWBBN1qobfuMXqKrkMbhIekULfRscaToLez9pg==
X-Received: by 2002:a05:690c:f83:b0:618:8d66:8363 with SMTP id 00721157ae682-62fba947f3emr69566017b3.41.1718293190578;
        Thu, 13 Jun 2024 08:39:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718293190; cv=none;
        d=google.com; s=arc-20160816;
        b=HxqeoSOlZQnFjnkCwCxq3phOyMFLXAyAri+Il5N7EpHC6960c6+YNUMOdVy4Ds6eAP
         PBuZk4CTUggFwei32TJTvKLz2FXIcFDtje2Fs/cqHwqeF/GIUKAby/F3Wh/psNVvkFLZ
         tasIVDAnVskFKgA38fKarT4PPHWZ9GWfGFFsTHupTkbnVqPSdAQCCyeNe1gP3iXLsIMW
         7xiZ0csxxzogDDiQSx/DH6df2duKHNxw5OOWoNiZ3Hhw+gW/AbckWjY/IzTIjEYh4zM8
         rYriuPHB8Lr3MyTI6aVTsnmTdQAcOSEhgcEyvLU8Q0RTEySw/WNSrLyw292U7yWTQtD3
         WQ9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=3hDUyT9rvjh/uqttZeOy24s2Df+NNUjOmmqDaE5+6Vk=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=AKz3rxld02dTH7BGlJhZK7yzUkKnjUnSFM+L2ApjP2FjiBYJhC2fC3oNFDdQAyXyS7
         Bf42Dbrqs0PsMeiFUPaH/73tFvLpVMDQtTcKea+KkzyQLhoYgZyjmk9sNWw2n2g8DQ6w
         XCAKQyUA75WfZXS4RtMge0hNHiW0UVxHa6pDoF680iWvwWU7VL5d5rCW8E7UoibaVSis
         70cqFPK9Q+a08KBk38IwVSy15a08DAP0Myi8FfXNGnKq/a2Y5KmlBsqSBc5mbEnp/9zV
         wXrvLZju+koWNhqKdC4cLsSCYAP8zl3Hl3PoQi+u3nl8LCCXyedNYeZ8JKgk9tm25Wtm
         yekQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=oo35mO8s;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-6311b3fd52dsi781787b3.4.2024.06.13.08.39.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 08:39:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0360083.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45DEp8mB000837;
	Thu, 13 Jun 2024 15:39:45 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqrext11p-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:44 +0000 (GMT)
Received: from m0360083.ppops.net (m0360083.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45DFdi5h029681;
	Thu, 13 Jun 2024 15:39:44 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqrext11j-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:44 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45DF1l4j003930;
	Thu, 13 Jun 2024 15:39:42 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yn2mq916t-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:42 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45DFdahY56033716
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 13 Jun 2024 15:39:38 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id BB60A2004F;
	Thu, 13 Jun 2024 15:39:36 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 446BF2006A;
	Thu, 13 Jun 2024 15:39:36 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 13 Jun 2024 15:39:36 +0000 (GMT)
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
Subject: [PATCH v4 07/35] kmsan: Remove a useless assignment from kmsan_vmap_pages_range_noflush()
Date: Thu, 13 Jun 2024 17:34:09 +0200
Message-ID: <20240613153924.961511-8-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240613153924.961511-1-iii@linux.ibm.com>
References: <20240613153924.961511-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: 8E0Zbtz0t13y_6R44lPTfF_XRZ9IqBsC
X-Proofpoint-ORIG-GUID: TKPnZMb8tT_RMAgqeLavlGAFctQInKt3
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-13_09,2024-06-13_02,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501
 impostorscore=0 adultscore=0 suspectscore=0 lowpriorityscore=0
 clxscore=1015 phishscore=0 spamscore=0 mlxscore=0 bulkscore=0
 malwarescore=0 mlxlogscore=999 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.19.0-2405170001 definitions=main-2406130112
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=oo35mO8s;       spf=pass (google.com:
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

The value assigned to prot is immediately overwritten on the next line
with PAGE_KERNEL. The right hand side of the assignment has no
side-effects.

Fixes: b073d7f8aee4 ("mm: kmsan: maintain KMSAN metadata for page operations")
Suggested-by: Alexander Gordeev <agordeev@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
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
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240613153924.961511-8-iii%40linux.ibm.com.
