Return-Path: <kasan-dev+bncBCM3H26GVIOBBVOW2SVAMGQEW7MYHAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B19E7ED212
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 21:34:30 +0100 (CET)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-4219f585f25sf72601cf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 12:34:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700080469; cv=pass;
        d=google.com; s=arc-20160816;
        b=0lBrOpukgWTlJ0WiiYkNAw7u4/hJM+lK3kVG5h64f1ihAMfktR9eObMYDF1XX10Uh7
         Ni3KMZFx7P3FFHLjf3hc44Wtl48gZjNWWHpqZGeWpKIUWJL4P92Rg7gF7ON/4KYJdJlg
         Zu2as1y2e8sQS+8yceys3M70+0hdWAbH1/4c9Yjldt2KwIvOPf2FQXjHHtGLTeF8wU67
         z7ZpxxEgH0ILW8WGRlsdCwwD1p0TJrz+4V4DZJ0zpkDO3FoIjO300MP9u3qpgMPKIcXV
         wtRqcIzvN7t/2/5o5MufK4ZekNx+klj5F2/ajaztzch1ZpOvF2fwrjVGLMVzKGDOzXkN
         XDrQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=OqrnFVMJYfzpzGXf8P2BcDyj5tbp3OJ5EgegGEwKOVs=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=vAB9lkU26iyJB9f1w6nnI0QLEpcZ10DLBf0AA2ZOz6SaB0raqtjbnQdMu2mZ/eCeRK
         Nz6RHYrR592NKP0XoJbKlZRqmTkMb7CHNrkKrtqrWBdTbFwSgj7SG60LAWKDoA5xHEJW
         I496cHg90yb2/JgKlQ63Jq7Ek7i/QZgVS9SVKrDDdSWGaS4l51jU3Ee03KJkV28Jyvyv
         la+pd9Us6rV4ZmecgpeTBpn5JG2kQIBD8b8ZJXb2E8uimlVoOYPozUloy7GJBp06QtEv
         gp3gWP4Nx01LVnomuqA25eQ0azeA7TSxE9aCP/u2n7MI8jfJ/oK53LACycyyjBDCf7tA
         9cdA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=EmWgrT7y;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700080469; x=1700685269; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OqrnFVMJYfzpzGXf8P2BcDyj5tbp3OJ5EgegGEwKOVs=;
        b=qxswvDFz4cCQSJx9qJ5dSnZx9+pPZf0giTdQzxDdLTWf2M4apcn5r271oH+SNfFUZ9
         rCfSPf7gOQZt/Z63hgDzVQC2gWVYd5+DgBkGIfI42oXzcfiPvNGEumYHCTwKOCrAweOc
         pCY6wSxIfsWoCxRhrY8wwwcuL1Mu1Rgn6k67eK4eGZtnvyjXYbNPfvrSS06uuDerurJO
         1ys06KZvoE3oWC3bgPocchfL0tL+VQLw3GFbWefZDFYcrXTEHUGSr2Fhjg5EcaqT8Fww
         SAkAIw0KsS7n6+WZmp7BJQjnA/WjTUxjvdrczoXsGpJIDrneJ8cE0WXUL+bW7++iz7Oi
         457g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700080469; x=1700685269;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=OqrnFVMJYfzpzGXf8P2BcDyj5tbp3OJ5EgegGEwKOVs=;
        b=jW+qjRdOyBlc51kp34UKjwGzICX7SmGXPQjJELcseDYJFzulDoF7EVIomzqNgExMQs
         89qlRXgAEi5vxsmrrS9SeSN8lY19at1MqaO0mN5h0KCKVNn47QKlASIs0NP3FopoJkqM
         o1gxJgeNJJRofKLcNZfCk+R8dSymbWRJlKfLObaaSMuI4Jpo4hJXH1vPxrmdcoSjWvMZ
         3DrS0Akk+e3+O/R4Opi4msMqjRvjnZboHatuZY9PL/NvTu5lCQka+x1Dry3nOREhnsXj
         TR5PURdvvpJuOxHN2womID9I6fQy0I3GRiFWA8Vyyxhj0T2Bp3Xx5J99PPRZ/EcXGUq3
         VvFw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yx3YPEsO0RtgM3Fl76bBtSPta0lJdtvjIOHusk92T1guYfbjF85
	ykN0G0DtVZQF8BuHK7a9Z9g=
X-Google-Smtp-Source: AGHT+IEY51gY/KPvUxt8TTxjrKXD/Vu2Kjt1mH+GO4SO6bcf7njro20vqcaJnA+v8wqBx/1es7IcqQ==
X-Received: by 2002:aed:2798:0:b0:41c:bd1e:5a4b with SMTP id a24-20020aed2798000000b0041cbd1e5a4bmr18573qtd.5.1700080469232;
        Wed, 15 Nov 2023 12:34:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:8194:b0:1dd:6b48:3e25 with SMTP id
 k20-20020a056870819400b001dd6b483e25ls112735oae.1.-pod-prod-01-us; Wed, 15
 Nov 2023 12:34:28 -0800 (PST)
X-Received: by 2002:a05:6358:528e:b0:16b:c8cd:1f05 with SMTP id g14-20020a056358528e00b0016bc8cd1f05mr8269226rwa.17.1700080468385;
        Wed, 15 Nov 2023 12:34:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700080468; cv=none;
        d=google.com; s=arc-20160816;
        b=Lf0TssOCXbjRBVK9oSJy1PIUjQYdIt8qKB2pOtmL18hrYax9vAusDOf6aD69mY0y4x
         S2VITX2g11Yq/oGo3uh7zZdZ89kQzFrpdOuxhFyM7bNpb6XtPh9sd3gsIkw/+PIHtEpb
         XJ+20CiU7STGrEajmEJNUznclrb3jv6tZD7I8JLlZfgb9myZCFoKSKX2nDGZOdhkSkYq
         aNROVmIahnP3DK/hcJE2Ed5f3966bHvLja2NDVPwOYIU5bwkFWG22YKt9QSlZZ7EewlC
         n61/KYJK/nn2+sI5w/9iFA2vd2WJZL7z9BR9L32ToTSJzXEItdXXyyLdmCVT9tYIcrNr
         SrRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Px0rK9+UdAvKZPZ7DYl+Y7dmIAhcf5TJsq/L/AiJTMo=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=KQft8k+hVG7iDZgBeMOCM/PhQlDXeFrzDt7BQv3s2SqsTkO86J2vsxcXenybvwoySQ
         y6IAa+9hg5zbLQYIYKf3bijKCC6PS5oToCWiEKgdaxylLzzL17QbYgIDXjAXJwjUdJ79
         TYs4wQFPONDouf6ERUCkuYZaWKcuthbw3YRZDpXZ9sfKTb0R49C4QPySkOk5S8P26d9S
         3yvnRPA6I94jcTH3WFvpNOgjKh0xWiKhgLjhi4C/DdizlBaE9Pu4qUIHP/JgGvqaLMaB
         fmPs9TCnQwZjINUFEX+JCtWTTCE118SiBIwcsBFhYT5ztVPIViNnPinOGZv8zibo+wji
         vyEQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=EmWgrT7y;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id l84-20020a25cc57000000b00da06a7c4983si762353ybf.2.2023.11.15.12.34.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Nov 2023 12:34:28 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353728.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKWs2S030886;
	Wed, 15 Nov 2023 20:34:24 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud543g162-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:24 +0000
Received: from m0353728.ppops.net (m0353728.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3AFKWsDX030885;
	Wed, 15 Nov 2023 20:34:23 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud543g156-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:23 +0000
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKIxCd017495;
	Wed, 15 Nov 2023 20:34:22 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uamayj78r-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:21 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3AFKYIKS22938342
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 15 Nov 2023 20:34:18 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id C150F20043;
	Wed, 15 Nov 2023 20:34:18 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 76AD320040;
	Wed, 15 Nov 2023 20:34:17 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.9.51])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 15 Nov 2023 20:34:17 +0000 (GMT)
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
Subject: [PATCH 06/32] kmsan: Fix kmsan_copy_to_user() on arches with overlapping address spaces
Date: Wed, 15 Nov 2023 21:30:38 +0100
Message-ID: <20231115203401.2495875-7-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231115203401.2495875-1-iii@linux.ibm.com>
References: <20231115203401.2495875-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: HD7io_J1O9IEJux-CMEYdG8MJqs-tACj
X-Proofpoint-GUID: zQLNbotbJOONuucBdc1_g_GKmcQkwnzj
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-15_20,2023-11-15_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0 phishscore=0
 spamscore=0 adultscore=0 priorityscore=1501 suspectscore=0 clxscore=1015
 mlxlogscore=761 bulkscore=0 mlxscore=0 lowpriorityscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2311060000
 definitions=main-2311150163
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=EmWgrT7y;       spf=pass (google.com:
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
userspace overlap. Assume that we are handling user memory access in
this case.

Reported-by: Alexander Gordeev <agordeev@linux.ibm.com>
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
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231115203401.2495875-7-iii%40linux.ibm.com.
