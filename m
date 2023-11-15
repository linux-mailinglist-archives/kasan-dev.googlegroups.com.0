Return-Path: <kasan-dev+bncBCM3H26GVIOBB2OW2SVAMGQEZPUUG7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id CCE957ED228
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 21:34:50 +0100 (CET)
Received: by mail-io1-xd3d.google.com with SMTP id ca18e2360f4ac-7a926469269sf1419939f.2
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 12:34:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700080489; cv=pass;
        d=google.com; s=arc-20160816;
        b=P7MNCgR0e02Jlh+V9oXEZgRvcWZ0jxhr5GyY5CgLZ2oMUm2fhnuhsTrDzBMfm2z3ao
         N8jJ5W22LSLdbo9lwHR9xF3XJSnknp7j47lS+dpfkzMGfvxed/FfvsYxUJ8nxgFeUu2f
         7uzyobemYSq2oODl8xl+0J3BPCSKG/KWzzoq6/8z8YPEctayxgI8Rvbd3NN1K+AhvGw4
         IoO4uDUO/jC+BanDea+sbQgUqcR7IKtOQwe5ZNaw2Ze3AkYW948VXHKkKFn89fdR+avZ
         57AqSkzmsPv6n4hxGZ+nOTRxaOIICVVbpI/ijncHkSikbvqivkG92C2NvKuCQjImSbNR
         EowA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=+lDrqIUPrGJhWGEG8CH/f/NytjSrBtr8ZM8GKTyIp3I=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=cW6P/vj9ki6qTYIjmXfDHLgruuPYkjLhbYMUPsZPlp/iS84s6sBEa8Wsr5UeY1rVek
         jLftpHf+l9aGMrG7MmVa6/II2ZvvD+wesi+QiUPdg94Q5eiHnPhIcVHUtJhf4PDLWS/9
         6wVcsW4NGWHuZRET3Zf2+nlsIUdfqN9r5+Lgl4KwWF5rGykhnzQtGHFXrbsq8v+MUSff
         hU0FSdKQrSCm6ZyY1/hkBtrtTYm61MFrBw6DYQVZsyi2Fo0bcFSReClnwoQiAV1IZfmK
         zVAssWXnAWdk44BVuApo/soH/wNcLiwThqPHa820tumWeczXtcRCZowI7lI2bewqMNp1
         3HYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=MKmcWWar;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700080489; x=1700685289; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+lDrqIUPrGJhWGEG8CH/f/NytjSrBtr8ZM8GKTyIp3I=;
        b=iiggdYW3g9KBASXAvC/FsfnFaAS/NOgfnacPstCvOdWcOy9vkbR1DZxOUD2750UdkT
         UEXQ6dCwZJ12c4FXRjfadyiPxrzd9KKVFpMxfZKdW4HQiRune6XSTOgnwh/OJL9BNY5r
         +dcBvOZkBmxUXk5vpVl2JW2mbZ3PA9vasXVgDPvwDpzZ1T//wHKzzmJzZrJ+JGKw4yK7
         Yg9eyJZVlKL3B7GrZOC4vpjfVbni0iXpEkwNKpDWQjhxSU6SuUnxYF+ZahdasF6L7+X5
         NdJ7TIGRXfxxG8uDdbfc73EFiVxPfOU4nGxRRvVghNcDzENDMdp3ayM/nbGGTg2SU5lD
         Tkmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700080489; x=1700685289;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+lDrqIUPrGJhWGEG8CH/f/NytjSrBtr8ZM8GKTyIp3I=;
        b=FnBbSnTQ6dXLT0q1eS5y8DvbBCugD1WxANPkzJG4pYHmIAmqPitIPd6yQcTw0vIdqy
         4bWam13JGmgB2ZGcue3lb9YcR1swbzxYGOX0B4d00B75vHNiyAetdBEH4OgZP6bnvFY9
         yKV0DcNfOmYav5LwediAuLi2JLE4dRKPgbtlOiDMVzUMpXA4Q5nO0bZv9vmctF0ebNKc
         p6hrytLS1+7e3tkN2225sO1ErGOGc2D6alOPvgX5H06bMeQOmjGaiNU81k3f2mTkKwlj
         WWzdgRXGSKLfg+UJgbzjDzOH1zzc6WKYrf7IVoXVrvtSJu4co/TFIBO6c9jWCNEr50Q9
         DsSg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzqUEER1Y6S9rHBk6jjpgWKRWJYpWFiTVl6Y9CnNkGH5rifLcdl
	7gz8m1c3u8/L4FDqu0NaMx8=
X-Google-Smtp-Source: AGHT+IGfWxV5xbY7spC6wZB/3IO6lZ+2bBrqr0aboJ8LNG2xBlvk2M4fM0vmoXKUTqTDtvbXVwVbUQ==
X-Received: by 2002:a05:6e02:1a8b:b0:34f:70ec:d4cf with SMTP id k11-20020a056e021a8b00b0034f70ecd4cfmr20275878ilv.8.1700080489754;
        Wed, 15 Nov 2023 12:34:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:2611:b0:35a:a617:5f3f with SMTP id
 by17-20020a056e02261100b0035aa6175f3fls83437ilb.0.-pod-prod-09-us; Wed, 15
 Nov 2023 12:34:49 -0800 (PST)
X-Received: by 2002:a05:6602:2e92:b0:798:2415:1189 with SMTP id m18-20020a0566022e9200b0079824151189mr19272082iow.12.1700080488822;
        Wed, 15 Nov 2023 12:34:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700080488; cv=none;
        d=google.com; s=arc-20160816;
        b=jU50omh81aFJw4bwVnn6gxhkkFS9PDrJauafiXjhO+H1o8zjHcNpO9l9Y1eUv12aYg
         dFPQCw2Fw01W432hJb2kUuQG+FzG6AxrVECWlXfeC+rL5HT3y3VNLkhIzm5nXmpFMRg+
         MjP4lkOkjfGildUWDthDB3oE5GWBazy382ZUBEjEz4dcCIpFnjqp3XXu2EpYfCs9PL10
         rZJMAySOqwPH9NoZqSU5F1YSuYVTCvCP5RTs5kWtwQJifPHO4rDTqqamb5T234b/d+oO
         2mx02vlnDLTpwBZ01QYOGu/4s4FLGxQmgAi1FG4lHxqjYzaVvAFgvuu8zWlHe8jA7Lvk
         tqAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=TskbhcdErPcFfha1b/s0fcuykpiIcbkPzbroc8ZK1SI=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=BuiI101YCSg2+iWR/QylmqsKNaJTSVT5e2HUkVbVxDYGsAseUbFEWP0h7bU0p5bpFC
         mYV8axAn0iVPM1LNa/+4kx3e0ExWghkf1E3oz3u3U0AmiD2K36jkX+wWc8aj1OrGk1ws
         N26jrEAtcd5NPeGcOTCRQT6fbcriGFZdpD9Co/3NJoBt5w6QOo06g018vS4iiXL2eVIz
         eYkULZhPcx8wXVoAE1Oc/DWAMe4a4JklY3U9qseotam+sJGYiwJRWqx07nud8xrEboq5
         2iQ4DFDbYr98yyM9zhU7OzXT19lRA6+MO1rBprVIUrIocvFv+x0qZmoIoxLUE2rWMvWH
         OJTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=MKmcWWar;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id cp14-20020a056638480e00b00437bda7a9c2si1460769jab.2.2023.11.15.12.34.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Nov 2023 12:34:48 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353722.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKXdxP001484;
	Wed, 15 Nov 2023 20:34:46 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4v2rb8k-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:45 +0000
Received: from m0353722.ppops.net (m0353722.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3AFKYj4B005400;
	Wed, 15 Nov 2023 20:34:45 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4v2rb8e-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:45 +0000
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKIvQS014607;
	Wed, 15 Nov 2023 20:34:44 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uaneksvut-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:44 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3AFKYfsg31523398
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 15 Nov 2023 20:34:41 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 12F612004B;
	Wed, 15 Nov 2023 20:34:41 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id B854A20040;
	Wed, 15 Nov 2023 20:34:39 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.9.51])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 15 Nov 2023 20:34:39 +0000 (GMT)
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
Subject: [PATCH 19/32] kmsan: Accept ranges starting with 0 on s390
Date: Wed, 15 Nov 2023 21:30:51 +0100
Message-ID: <20231115203401.2495875-20-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231115203401.2495875-1-iii@linux.ibm.com>
References: <20231115203401.2495875-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: NqSGEOhYCvXYjJ2gmAhd8EZAV9lDeRqN
X-Proofpoint-GUID: fI9InjhahjWpUFvyF7-N6n0DC7cim79b
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-15_20,2023-11-15_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0
 malwarescore=0 mlxscore=0 clxscore=1015 adultscore=0 spamscore=0
 lowpriorityscore=0 bulkscore=0 priorityscore=1501 phishscore=0
 mlxlogscore=981 suspectscore=0 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.12.0-2311060000 definitions=main-2311150163
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=MKmcWWar;       spf=pass (google.com:
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

On s390 the virtual address 0 is valid (current CPU's lowcore is mapped
there), therefore KMSAN should not complain about it.

Disable the respective check on s390. There doesn't seem to be a
Kconfig option to describe this situation, so explicitly check for
s390.

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/init.c | 4 +++-
 1 file changed, 3 insertions(+), 1 deletion(-)

diff --git a/mm/kmsan/init.c b/mm/kmsan/init.c
index ffedf4dbc49d..14f4a432fddd 100644
--- a/mm/kmsan/init.c
+++ b/mm/kmsan/init.c
@@ -33,7 +33,9 @@ static void __init kmsan_record_future_shadow_range(void *start, void *end)
 	bool merged = false;
 
 	KMSAN_WARN_ON(future_index == NUM_FUTURE_RANGES);
-	KMSAN_WARN_ON((nstart >= nend) || !nstart || !nend);
+	KMSAN_WARN_ON((nstart >= nend) ||
+		      (!IS_ENABLED(CONFIG_S390) && !nstart) ||
+		      !nend);
 	nstart = ALIGN_DOWN(nstart, PAGE_SIZE);
 	nend = ALIGN(nend, PAGE_SIZE);
 
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231115203401.2495875-20-iii%40linux.ibm.com.
