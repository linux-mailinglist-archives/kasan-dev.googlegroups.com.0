Return-Path: <kasan-dev+bncBCM3H26GVIOBBRFFVSZQMGQEEG2APGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id A6BED9076D5
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 17:39:50 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id 006d021491bc7-5ba793ceccasf1040794eaf.2
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 08:39:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718293189; cv=pass;
        d=google.com; s=arc-20160816;
        b=InZC/p1qz8zU9e0wxnU37dqflLcR/7aLeIW8QZwTaMYcvr2heFtGKpEwGvcXeg5G79
         IJv9s9Rf4CT0rtAilhT8YoG9Qh0TYXUBx95sacggnvw8CpZQhjXda/Jh4Q/2ccbdjF9z
         uep3nSWpD6hQGUfgGfH8QzVq9Y9uuBi1zUNusQu+8gw5NvN04Uwarb2l0RquL1vfvHjm
         lQHA9nX15gyrXA15LgPwp+yyM6nR1fMDsK5uTwY9uJTLBJ9B6mfjg54NRkk7MGDyYnsR
         WPHbrvqJWy/txZHGm13mRFXU+jhTXZcYhkysWZ06GvBXl17v2iT/Tz5j3g3fXGpNGsjV
         4g2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=fJmyRWjB0eLJ/YdYFwySvbgnYvTyZ+JNg1cfu8fvSjA=;
        fh=RMAzM928fany7p/OY68MhMguE7kjsC0RU4I0y4qd41s=;
        b=fA6mZjlaU8+h+ExxpjGqPqlpDSToupyzu/whD+jgjZFaTYR83QPsy3yApKK5e35bqC
         OZ6s3VSyMCnRW5Dqs18KcZZPwgiPHUby/svSROzK+N47weyJrwavBAtiJH2CBNlwmqDm
         lUwbdDXbcTWhU2dAo+ZBECArUcEGF6rBK9LsLJ9JSRAphIf/c/Y7Ukrb02vmcqNGlQwW
         V0R8ZbaWEp0LFCNiRAkTJTJM29Cgjg8H+N616AHaBFeQpowH+VQiAVvNOqs8NfyDnVjn
         NEj1MQU8DllrrXrfjaTz9VaduaHhCydefLM8NCfRYqzUXI4DitQwgG/4Nf9t/g6AHopu
         2iOw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=kMlxxcaM;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718293189; x=1718897989; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fJmyRWjB0eLJ/YdYFwySvbgnYvTyZ+JNg1cfu8fvSjA=;
        b=ofCcHHIikjyNIpOANFS8DPEwRL4q2fQYVJCKy3/9kanwF5TohkQbM1NGCAS1VjgkFG
         sv56ICukwiOAdpPYzh8XXWC73Xo+58byxrChIv0qxoTS+RiuQZr/9pfCagJq6lRuRRJm
         O6Evmdq0KQcM+uvRzvJHXeuI4FnjONncnbyVic2h1jrJ71m3uiD88OVyP1v+LfdooAct
         s/j30m4Gmt2NGyA+4VZ67fWApunSqLd/JfQKD1xG3kLNoAjx7XDM92QoAqO4WGpW5KZE
         dHVEO2qzw9wEx5k69hu7IN7WyOpZ56jZ0Um5JrEt66i7W8r37vVoNVDZUYk6O0L1FYbd
         G7Hw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718293189; x=1718897989;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=fJmyRWjB0eLJ/YdYFwySvbgnYvTyZ+JNg1cfu8fvSjA=;
        b=NnHKf50NNlY49CS0TkwB8NEM9Cf4/S+KNCfSYsy6xTOI1Ea2M6UNzSlrj+VMf/1CLN
         cGunrUJUrMGhKxXhxC3+DdnlTUbOrgUOGha4SWTh3vIyauM+UU39mpEbIi3e9PG041nH
         TbYgBqCYkVdKddrFMZwmzVHP1OI5m0PpL70NLcASaPgYwSexFzY3NeEo9Npbe6JYEFpr
         g5NR8yYEhWSvqkB6ohsUDlwHyr3vu+1B2xiqG7fSd8qtQjYc9Ru1kvNoYyQwgBFUUoxS
         HdjrrXvPSZTCm0bnoFAD0Q89n2YL73gvSUmQjiq/sE7aIvJ0rK0KJjAJqZde04c31TkJ
         G8Lg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWB9LCO/5G3FY/9AqL1EK0Luy3q0bdbVXtRHodAaIV6UwRFUNl4UCs9ogP1J4FGF7RoK6tLJttWeHQzo45PLVjyhQxkD3Ggvw==
X-Gm-Message-State: AOJu0YxK1cXZqQccO30wNbHy04uFZ7e/Jx1/rgFqWrk4qw3LXP+25RfB
	2cBCOghzsNd2aWWPI2vrdtYAj4Liul/YtSQAe7XTV2MHD2f9KGTr
X-Google-Smtp-Source: AGHT+IH/Up39yq/T6YYW2cCuCnHy3RUjQwZg5RAwujgh/Q6JHKvEJB0XA3RyHEXc10FW02TMWru3iQ==
X-Received: by 2002:a05:6820:16a9:b0:5ba:2d65:3fa0 with SMTP id 006d021491bc7-5bdadc8a668mr9384eaf.6.1718293189055;
        Thu, 13 Jun 2024 08:39:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:aa0a:0:b0:5bb:16d7:73fc with SMTP id 006d021491bc7-5bcc3e0ba68ls909747eaf.2.-pod-prod-05-us;
 Thu, 13 Jun 2024 08:39:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUGNC7cZyYKFrhjEOASszy5MyKfC2IsvHkEpt7GZg1N1qE12ZqiWIIvZlYpyRENY7gQ/rObrYkKmH/UbBOvzKji4sXO6goZ2VQR/g==
X-Received: by 2002:a9d:7416:0:b0:6f9:b1d8:65a8 with SMTP id 46e09a7af769-6fb9361b4dbmr96627a34.21.1718293188095;
        Thu, 13 Jun 2024 08:39:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718293188; cv=none;
        d=google.com; s=arc-20160816;
        b=OHVfTn7K4N//uXUhCK55dmiCf/EtSUBLINpLnmrTSK0C6MWHcg74MOL6BABAeL5iI3
         MyxVpzBTXhmrvpHZkxOABddmd2iLGQdFDUr91NXUV5rg/g6HAqrX3KfG5NAPCiFfnDwC
         O4e3sw/2MPgwZ9CLbsj8CidM/9kYUxO4tWagGaYxRj+4dgkdL6OhHeKprqNLB18MvQqu
         EHLSMqdEhKMcyP8c5RPozVh3IGKG6aWugtzX2qLu3zs97EtQ+3snRoB3wrPZKlBG7K2Z
         rsI2NnmnIptuI++YTsyrtk7xEel+DcC2LuR+lJdbWAlBxXqSrMZQTgiBJW5OjAWduDrY
         GKOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=B2wiMcD3tdJRzJi1KnXmn1aGmTaVwcFVLNTdCb0XDUM=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=cRmormJG8Z9xZS2xPDVeeVTrXtQu6Dv/8piTSzTWA+6luLj0xitig/IaXjx+cS27QC
         EPLRwIGwZDjMDL7b1Tn/1/EhTYLVI8lkBcsTnGKYBCBbG0ekXjIhgU8V/gslERnf6nTs
         WDfdl9VaeLnCybM/JDH7mznfTOYwOboJvvOhKbzckfNMxkI4na7NfqZOP37x3/7b/jS1
         mgnaJ7NYme2/z9FNcVeOYey06aXuxeM++M5NZ6Mvt8L18lvvkOyClP+6/XNIski4ux6z
         8AKfBpdGmJYpLANt63GwXvhPx8Ruh/zwUK0yrfgWUiMIa0Iyy5/cbvnOo1c24N1N4ykc
         Idwg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=kMlxxcaM;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-6fb5ba85bbcsi77696a34.5.2024.06.13.08.39.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 08:39:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353729.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45DDtsjK023397;
	Thu, 13 Jun 2024 15:39:43 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yr1pa8dkg-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:43 +0000 (GMT)
Received: from m0353729.ppops.net (m0353729.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45DFdgJl030060;
	Thu, 13 Jun 2024 15:39:42 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yr1pa8dkd-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:42 +0000 (GMT)
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45DEfGBf028808;
	Thu, 13 Jun 2024 15:39:41 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yn1mus9eq-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:41 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45DFdZOh39977468
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 13 Jun 2024 15:39:37 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A028B20043;
	Thu, 13 Jun 2024 15:39:35 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 2D09A2006A;
	Thu, 13 Jun 2024 15:39:35 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 13 Jun 2024 15:39:35 +0000 (GMT)
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
Subject: [PATCH v4 05/35] kmsan: Fix is_bad_asm_addr() on arches with overlapping address spaces
Date: Thu, 13 Jun 2024 17:34:07 +0200
Message-ID: <20240613153924.961511-6-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240613153924.961511-1-iii@linux.ibm.com>
References: <20240613153924.961511-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: m2P6CrVSnW19obyLML4nznDroFQOGAq6
X-Proofpoint-ORIG-GUID: xWANpGfDMqIjimQF0yIYY49eefKu2RCe
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-13_09,2024-06-13_02,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 phishscore=0 suspectscore=0
 priorityscore=1501 adultscore=0 mlxscore=0 lowpriorityscore=0
 impostorscore=0 mlxlogscore=951 clxscore=1015 malwarescore=0 bulkscore=0
 spamscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406130112
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=kMlxxcaM;       spf=pass (google.com:
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

Comparing pointers with TASK_SIZE does not make sense when kernel and
userspace overlap. Skip the comparison when this is the case.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/instrumentation.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kmsan/instrumentation.c b/mm/kmsan/instrumentation.c
index 470b0b4afcc4..8a1bbbc723ab 100644
--- a/mm/kmsan/instrumentation.c
+++ b/mm/kmsan/instrumentation.c
@@ -20,7 +20,8 @@
 
 static inline bool is_bad_asm_addr(void *addr, uintptr_t size, bool is_store)
 {
-	if ((u64)addr < TASK_SIZE)
+	if (IS_ENABLED(CONFIG_ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE) &&
+	    (u64)addr < TASK_SIZE)
 		return true;
 	if (!kmsan_get_metadata(addr, KMSAN_META_SHADOW))
 		return true;
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240613153924.961511-6-iii%40linux.ibm.com.
