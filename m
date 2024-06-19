Return-Path: <kasan-dev+bncBCM3H26GVIOBBLX2ZOZQMGQELCYSHCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id E256A90F29E
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:45:51 +0200 (CEST)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-25cb4261a5csf38647fac.2
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 08:45:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718811950; cv=pass;
        d=google.com; s=arc-20160816;
        b=xn0HIT75tCDW6ndYIHKefVZtVQcdnI8llcwfhtKa92CMoIKIWZnjbPbWSVG6gYoVaM
         uQUxGotkCm1VyaFo9fjxkRx/KmP9ikKdVlmJoGnZxAVdzBVeuaq3dXChHTTIrhXrFBqc
         DJDxjNqjKLwqHW4qJ4AKCAoHHRJGErBZm68h98m9hM66Sq0y3uqOQC6UcW5riEtk5jrH
         bnWIrVqFKMMjRKvICIp4OzSB9ROpOHMklwPh9rG4AAFi8uzJijhT+tzmM56PjO1785vA
         +utcSLPZwLYPAkuBt5gtfXP9aLS2IgGUhiJf9zOK5TBwINGLfgGJ2ThgJrZKio/9pT5Z
         kSvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=lSu4bz3Mg6VAWD2bU3sZp96Iip6j0MfAlbVw/7pE0PU=;
        fh=RFUzVyTThvBUWqcmFoMbd2Kkobik85hvziDnxseCNi4=;
        b=D1yjkW67Ysms2uWFhfiTZqY6PVg1+CsF1EdhVOmjnx0u3CQAY6chZBrCdZgj93fUDK
         +R2cDZ4wx5A+idNJjEjlrER9M+3i0LeWhVDkU9P0+LiKUfMbJxWWQN9r0BTAHTp3TGEP
         Cu5e3MV7nrC17cmCaQICWF6RgQp8JRUh3yyjtjdRRH1NqPYhxbLrW0bcpIUH7nr7eCT2
         wy0Zqf+Z4pGS+UX9dCZFOP82ZaEPKy9LzAncDc34RTHultmmoNX9psDwFmWwuDYmmhsZ
         j/aq/wEcLyYQ9JuOCAioyxt27an09emIODBbm8T3qPhagiBDuXmJWZQxleau0SnR4KXn
         ziFQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=GBGOGqpy;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718811950; x=1719416750; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lSu4bz3Mg6VAWD2bU3sZp96Iip6j0MfAlbVw/7pE0PU=;
        b=JIDpUH9MM0j6GXhZBFtzOtLgHY1vmQe4JWJCcBWfHyZPNW3WdeWxdRO7dh3GUd2w0C
         8zgA2Qag7RcyQ34mSaPGVDZ5mdfSrea8WGVqdv/xxn/Sc5a1+SA6rYwamcPk8LvG48eW
         6Y4O7fOyzpW8Vo2pOpA7Ls3uMf7dPsGppWd0Q8Yy/mY8E3WuQyR+wig2l1ACpvyv7slc
         BmsVHDFpBr8aKAAzJoSuLEUKj976mpjC+kjSGPrdZVa4/ur0hu4o709Cc3zkKcvO3EAp
         OIWg7W275ZDOCJKC5k2vccG6+53wgiBtI/+4Nv7EEV1/RM3vQXJr7qNmD03ePnBDK8pB
         VxPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718811950; x=1719416750;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lSu4bz3Mg6VAWD2bU3sZp96Iip6j0MfAlbVw/7pE0PU=;
        b=oKwqcm+PPHCyRuO57KbXYVZf5BN2yqFdbTdaaj1pwntFjqVVpOmxvIvFVxzYdEpiFd
         F4rp4aBhupK3ha5p/89w91u5XRdtqSj/+yMOX8RjExeonT66mPex+/4IPsHvrcPfb9m4
         2EiKwKA5iNsLyaKt8MmsNLwEi6rZ7hWRCVxY9KzyRNTO9ut9tb/cLM2C9bL1+GJTntSC
         1oLH3XuRxTVA4ZASFjyu9cZ2RA0A65EVTqmefSc0mGpb7V4+3KjRL8mNvCCxudyYTd+A
         rG/AOCoSb9/GJMvNEiyze0KvJ9t0vt2UNgYKSG+h6R3K2PsFou+0+jtsmafxZcTczI0q
         rVag==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUpaFaLgsEkOTnImpPTDeHWZ7hjatlkzSZF4O6zSOdH7w1bDHc1XL4pym94jn6pzBg/nkEe3v0jQAbbrzxyVhMFUupHuoVw0A==
X-Gm-Message-State: AOJu0YyGQTq5hs1t+HAoZXplItyB+mWx7BgsoDZ3fwr30GZBV0LrOkEB
	1ZcoHG+DLPLBbVspMZYkimeSjrzFzWyvfRqJHUEVyU0wFFBy0izr
X-Google-Smtp-Source: AGHT+IEJFOK1YpJVFNYVCJ+RfUiSEnP0eqDzgYygLqq/XvRwqKS/MLugBsdK1rWSNX4osJc4YoMOYA==
X-Received: by 2002:a05:6870:1716:b0:254:9ec6:c8cd with SMTP id 586e51a60fabf-25c948ec852mr3039646fac.7.1718811950340;
        Wed, 19 Jun 2024 08:45:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:eca2:b0:25c:b2c1:8569 with SMTP id
 586e51a60fabf-25cb2c19c97ls115916fac.1.-pod-prod-04-us; Wed, 19 Jun 2024
 08:45:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUrX4htmd/uq8uYZKnI/tMMKhhKX9HRsXgiSHLZ6KcOuwaXOjNJOXckz+TtoxLCCW6c2mtFepXIDyogiUPUw2oDSiBA5PekJr/Brw==
X-Received: by 2002:a05:6870:32ce:b0:255:1bb8:8602 with SMTP id 586e51a60fabf-25c94d02252mr3345865fac.37.1718811947407;
        Wed, 19 Jun 2024 08:45:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718811947; cv=none;
        d=google.com; s=arc-20160816;
        b=yfEOB9kJCUKxoq016ZJ/77v65rV/UhIxtH4hdLA8QiDNtP3VEthkkO5WELXI3uCKL4
         wan3Tfy2igC5CwLWTSDg5oalhfVcIpunRYkhm9Hk5asQTzLPD9TBGW+r1ZQiyHs2u3Fa
         n/ZWQbMPENrxrvC3NVjP3eQeqvgkTPAEeE1R+tkd1opT9buIe3M9fSL2BTKrSZ9mgDjr
         nfl/b99yGv5Dl82PsIYNSAVlS68UhpbcZosgEoRBk7vRSehAKh9DsCgy4huj2QcacmuS
         MpNx/CdiALP0XVJAYjmsZs1BYL1ezInQgcsRvq8asyRudfs4aAQSzuCw3jgFCa3Lhn5l
         0n7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=kU/N+IjLjtGivjpGyVY04YO0GR9T1vNZaCjuWWP4qac=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=wHXvPAA4foyo6qOJKRUB74KSO5SPwgxFEimydCaXUBddM5iclXg8N5l5ShECbzh7An
         hDaV+rh+JlrnRAqLCsyjURYghGiBrSdrn0cKLJh5xx8ZaUQRsVRV9BHUrr63L7Go3JQo
         b+TxzMZvhq+KnG6SMQqB41eAcGo5FYJ4+pOs57g3tvk2N640kGW5T3+uXlC0UzuJwhEK
         Cm0Ajv2vEHnIZkSfNNf4pzrG4SAS45SJpsYYN92QgUh2h3zEiE0MaeoEufi1A0xSgdde
         LQLOWAQfMnHues6b5/3uOeZizkMrRoSo4FHLPAIXBVKYhRK2sA33D4iJn3959NCkaarY
         mKJA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=GBGOGqpy;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-444a8830387si957151cf.3.2024.06.19.08.45.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jun 2024 08:45:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353728.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45JFR25k017473;
	Wed, 19 Jun 2024 15:45:42 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv0p9gau4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:42 +0000 (GMT)
Received: from m0353728.ppops.net (m0353728.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45JFjfHl015754;
	Wed, 19 Jun 2024 15:45:41 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv0p9gaty-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:41 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45JFhxil023990;
	Wed, 19 Jun 2024 15:45:40 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3ysp9qdype-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:40 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45JFjYUQ51904956
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 19 Jun 2024 15:45:36 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 3501220040;
	Wed, 19 Jun 2024 15:45:34 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id D73242004E;
	Wed, 19 Jun 2024 15:45:33 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 19 Jun 2024 15:45:33 +0000 (GMT)
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
Subject: [PATCH v5 01/37] ftrace: Unpoison ftrace_regs in ftrace_ops_list_func()
Date: Wed, 19 Jun 2024 17:43:36 +0200
Message-ID: <20240619154530.163232-2-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240619154530.163232-1-iii@linux.ibm.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: DjNn8wQivNgXS7aGEy7fFO0UzqFKCQyA
X-Proofpoint-GUID: dfntroPUBr8RU8mCueQtnLhKjRrBTJS3
X-Proofpoint-UnRewURL: 0 URL was un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-19_02,2024-06-19_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0
 mlxlogscore=999 clxscore=1015 mlxscore=0 spamscore=0 malwarescore=0
 adultscore=0 priorityscore=1501 lowpriorityscore=0 phishscore=0
 suspectscore=0 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406190115
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=GBGOGqpy;       spf=pass (google.com:
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

Architectures use assembly code to initialize ftrace_regs and call
ftrace_ops_list_func(). Therefore, from the KMSAN's point of view,
ftrace_regs is poisoned on ftrace_ops_list_func entry(). This causes
KMSAN warnings when running the ftrace testsuite.

Fix by trusting the architecture-specific assembly code and always
unpoisoning ftrace_regs in ftrace_ops_list_func.

The issue was not encountered on x86_64 so far only by accident:
assembly-allocated ftrace_regs was overlapping a stale partially
unpoisoned stack frame. Poisoning stack frames before returns [1]
makes the issue appear on x86_64 as well.

[1] https://github.com/iii-i/llvm-project/commits/msan-poison-allocas-before-returning-2024-06-12/

Reviewed-by: Alexander Potapenko <glider@google.com>
Acked-by: Steven Rostedt (Google) <rostedt@goodmis.org>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 kernel/trace/ftrace.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/kernel/trace/ftrace.c b/kernel/trace/ftrace.c
index 65208d3b5ed9..c35ad4362d71 100644
--- a/kernel/trace/ftrace.c
+++ b/kernel/trace/ftrace.c
@@ -7407,6 +7407,7 @@ __ftrace_ops_list_func(unsigned long ip, unsigned long parent_ip,
 void arch_ftrace_ops_list_func(unsigned long ip, unsigned long parent_ip,
 			       struct ftrace_ops *op, struct ftrace_regs *fregs)
 {
+	kmsan_unpoison_memory(fregs, sizeof(*fregs));
 	__ftrace_ops_list_func(ip, parent_ip, NULL, fregs);
 }
 #else
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240619154530.163232-2-iii%40linux.ibm.com.
