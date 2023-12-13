Return-Path: <kasan-dev+bncBCM3H26GVIOBB7X75CVQMGQE5TIE4SI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 0998E8122ED
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 00:36:32 +0100 (CET)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-591129c72d6sf4442994eaf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 15:36:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702510590; cv=pass;
        d=google.com; s=arc-20160816;
        b=O+it6e34r8Zzu92DVbiiDNqAawhdKq5ZZ5DhaenE/ZVWV+b6vbUt/lK/qJ869+rSPS
         Z5evL7ZLUu1IsKWHmTeYNadhqLIYHnS7ad0m+idaT9RjZO2/ej0qbTXzsVLTFdE+h5Z4
         ZEP26x5dn0bKFiOJeCzRv2ajo7vhrR/nlTjZvn+Jv7A8pzjvr2aL1cXP7MZ5H5bzZrFl
         qC2E/6hAqELoU7Qgp5LtOEUO5M89mJp4zftN2zEyisktQHMFpbijH1+ijxRpbHfyO/gq
         JhU1YvGxDciPAt29/W31M4ZsPyx6msxUtecTanQ3aMTKmjwq2jy8rSYIORde+NVOpqnj
         rRVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=j1GB2BSqLt9V867XG63rJ4yPwSqhI2BYMpaXwomfpoE=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=e6W+WuBiSyD+NPpZrC1HiskhmbDCK31KZUsFt7QCVZxnbo5Awl3g/M0UBdo1gmTngj
         NTO1yds/NOSm6iYE0w/EGUSr4gSKwX1C8c9Lxv4pb9E1AT1MU9FSO4CIruOqqZmk0Ot6
         Vtp3vPM0WlOZfGwbiWkAjp6FcHaDem33uxSwOBv13f9lxlUt5quMmWL2gT68/EO7px9q
         FD6cs4bsP9U2z1GUQuA38vZzxR04/+jvlGXGNfB/g6sYQcm03fpotv3KKbJ5J+/ucuh5
         1f4LQFnP5ySRKDlVkTa8YuS50kfZl2+JlcyHHjXifa/+qJ+vfCLscosZLoV+4QhrWIw9
         6pYw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="a/H46swg";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702510590; x=1703115390; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=j1GB2BSqLt9V867XG63rJ4yPwSqhI2BYMpaXwomfpoE=;
        b=cMnT7XV+v4qlFigvu8ueri6hsgFstRTzn56HfBd1zIwnuqM24Nih1SsVQW3X1o2Cqf
         Hch+TO58ypS2Cdf/RBYuHGhWc4Bk202tw/T5MiAjKOcP7Z7ai41hSpOcz0e4aILrMj05
         isPaGmeXGpRG6bm7bpQzI45jFLjapzpZ4giViyZy+b8PxgaEfskbqbCVX4BnuQE1NDya
         3yxFetzAApkmaRrAKLKj/OTEP8Cn4eTJtu3eXsyiGzqR3JOU5TGScnF57cUDYXX0N4q1
         JTtxSFHSqmh4RMj0KcIne9vGw/1qNxPn2PwEEjwv8CaA8h8o/HIWuZKx7zKm8nCL5ZcL
         tl0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702510590; x=1703115390;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=j1GB2BSqLt9V867XG63rJ4yPwSqhI2BYMpaXwomfpoE=;
        b=sQi15i00wt09BSnM8+F9UH3N+nR4C//Qa619lgVK4MoGfKIfaX2+hVseY1+Ff0OhnG
         LPIJLWtmDFU3XQMqBZWw1wOeOgW74aKocYhcS19QFHS7ax70wWqhQ/oehePKEc7OyeQt
         gp5GkCTHjClJm3TXGbSywhQkhUf1N3/sZYKc7DWeDT3OaTYrmkM9wnER6loFwurLsw26
         c9hi7fUOgYvLr+OWTNy8A+7Fw4LY2yFXWow1r8qkYGb/RtuKpPcvF/Jg39zUt9PKEqwg
         wQS9vYvpem9JGt7aQqPolG19G5xDOwwJNJwMAglkqaDBjieBjGleyxqAyPjLtCvJF1tU
         A6JQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxIWDqtzy7izW1if1je36uZtbw6BPQ8EqgdmFKO+3sdJrlblhDK
	oQmy5aT5xfK0q2h3IzO1lEo=
X-Google-Smtp-Source: AGHT+IH9iU6bVQXPdhqDVWd5Cml90AC3DBC0Z1bcsFD6qp4UcgZkc+eIj2jZZPq3tUKzERKIN7KjcA==
X-Received: by 2002:a4a:98ea:0:b0:590:f5fc:df58 with SMTP id b39-20020a4a98ea000000b00590f5fcdf58mr3879535ooj.17.1702510590421;
        Wed, 13 Dec 2023 15:36:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:1b95:b0:590:e812:c208 with SMTP id
 cb21-20020a0568201b9500b00590e812c208ls1588868oob.1.-pod-prod-07-us; Wed, 13
 Dec 2023 15:36:29 -0800 (PST)
X-Received: by 2002:a05:6808:4486:b0:3b8:b063:9b76 with SMTP id eq6-20020a056808448600b003b8b0639b76mr12679004oib.104.1702510589732;
        Wed, 13 Dec 2023 15:36:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702510589; cv=none;
        d=google.com; s=arc-20160816;
        b=a22Ng/pdXXm06KGEPDqforTtZMq8CZHnImoYyCIyA8o42eiA2Gpbje+wEAKo9PPDMm
         3PExySgZFSGDvERkIslPt5qZxaMscbBNcnmStejdP1IIoOUnxqct5F4BrpnYk4VVYDDk
         zvW8J0h6XSyWplX1s7CL7Z5o2jH69Ou3MrjBMTiVjV1cnlcCQeo2lDjjJ0TwzMchZNeH
         nUvs4JLG8hng131Bh8EPDg76iSpO4w+tTI3KHlHSiYYiQkE4R5ggi/0Rc52ZpVvvDh/x
         40aD6hypm50YrWvquMCXaQSTZRaKfya6ue9T9/RHEKxJobQUjJOk1RbVrJyRHlhPJaXF
         9Oug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=+JRbg3kPizc/tKO6MSNyeUjOi3r5ENUit3Ra9toPyEk=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=GhYs+POs3S4WvrrPa9rcXWoDimYsQiuMj2LOUqVgGjARCILvyJK0OIu4WHQvspD1+z
         gmJsBgVPYzlVlbH7tWEfj8iMEOKbUzWy+6akA6Jbc77WEIobRzEaAe1hYR3Ukf/TrrU6
         Difdrj3U2vImoti1DKF9aU3kGdTvvgknUbyUGhIY9hCZJ8rXYKY2BnR7JJ7SuimIDBFg
         i6E5oS1FjUrIlV3Gp4Blx4d4VezA0bNiCHb3ferh5N86HUXDq2BGGYh2j2eRqgR6TsmA
         BnI/7RoI1vc6mUp9zm+sfjj4G+9pVJCqZczCj6vzdOdeR6hYMXpbfa5BMW9uW5H5MndT
         imow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="a/H46swg";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id u15-20020a05622a17cf00b0042584494cb5si2472360qtk.5.2023.12.13.15.36.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 15:36:29 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353728.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDKaLvr003754;
	Wed, 13 Dec 2023 23:36:25 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uykek48y7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:24 +0000
Received: from m0353728.ppops.net (m0353728.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BDNQT09028957;
	Wed, 13 Dec 2023 23:36:24 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uykek48xm-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:23 +0000
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDL4sCB028206;
	Wed, 13 Dec 2023 23:36:22 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uw2xyvrnv-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:22 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BDNaJNT16188036
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 13 Dec 2023 23:36:19 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 46D0F20043;
	Wed, 13 Dec 2023 23:36:19 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id D4A3220040;
	Wed, 13 Dec 2023 23:36:17 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.171.70.156])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 13 Dec 2023 23:36:17 +0000 (GMT)
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
Subject: [PATCH v3 06/34] kmsan: Fix kmsan_copy_to_user() on arches with overlapping address spaces
Date: Thu, 14 Dec 2023 00:24:26 +0100
Message-ID: <20231213233605.661251-7-iii@linux.ibm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20231213233605.661251-1-iii@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: NvNFv9kzwaXyDaiNbiRkqnwnGpAGbYvC
X-Proofpoint-ORIG-GUID: 36qScC5OQSchjdmhk5MojrGx989GqACk
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-13_14,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 malwarescore=0 phishscore=0
 mlxscore=0 adultscore=0 bulkscore=0 mlxlogscore=748 suspectscore=0
 clxscore=1015 spamscore=0 impostorscore=0 priorityscore=1501
 lowpriorityscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2312130167
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="a/H46swg";       spf=pass
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

Comparing pointers with TASK_SIZE does not make sense when kernel and
userspace overlap. Assume that we are handling user memory access in
this case.

Reported-by: Alexander Gordeev <agordeev@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/hooks.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 5d6e2dee5692..eafc45f937eb 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -267,7 +267,8 @@ void kmsan_copy_to_user(void __user *to, const void *from, size_t to_copy,
 		return;
 
 	ua_flags = user_access_save();
-	if ((u64)to < TASK_SIZE) {
+	if (!IS_ENABLED(CONFIG_ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE) ||
+	    (u64)to < TASK_SIZE) {
 		/* This is a user memory access, check it. */
 		kmsan_internal_check_memory((void *)from, to_copy - left, to,
 					    REASON_COPY_TO_USER);
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231213233605.661251-7-iii%40linux.ibm.com.
