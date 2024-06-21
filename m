Return-Path: <kasan-dev+bncBCM3H26GVIOBB5OL2WZQMGQEJAQOFKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5BDC49123C8
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 13:37:27 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id 5614622812f47-3d2412bb4b5sf2441396b6e.3
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 04:37:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718969846; cv=pass;
        d=google.com; s=arc-20160816;
        b=qad4anLDJYu4TXGM/jpKkZzwSA1vKm9Dgg9PBK85kEs4KJSnMjGgFeO0JKvSrB3Oce
         UcNlpWMy94tSVYs/E0egkGEHeUw94hSiKpE8vSDWyehwLTieV4hWkZcgclyxA02Y7ZXx
         Ap9cNUAeZniGegBxDhmkAQ2DlgAVtKNOhKI1JYifI4Lp04YFTaCsS20owkdqdMVwWXhT
         ANJzzBZfD9qz48Zf051Kb16MLXMCvGUL6xvpc1+L6XG7nb3cwM5zxEdgDjAV+lKAYKWA
         wEWDdKVhSEy0A3LG1Oht2/r5hr5xX14SpShY97yQflgOycOrPIFvlt+Alhxx4X4TzXnH
         oDdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=cFBvkTRzrneetBjQDyO4WGeyO1fmudLEjQlS58DE5jw=;
        fh=OsdozDvmKXWHETdWdl9dB4KMkiJAtGKighZbJEm0DDo=;
        b=g5B09uB0A0d6b1bHcTF/Q5PCFY+6a4WVQgPuVTeE3QudHzUNYoFls844192ux0HqY2
         wMYe4iOLTVKYEhzX9qF2FIj/9yeYFEI2aTfGoYmfLz6lBTDiTgj23pyAj8CAoNZFXTwa
         Gg52qoosDp2/ddQeu/Gcmvq10RE1W5RMpVu441X/nYV6dbtvBIUWb9FgAh8uCqp4kadu
         8DjxfcHADa7odjcjqiU29a/omjGX6YNJpXdZL+XKieF8ofh8ijUskCvLUFMZ83GAjj/i
         ZjvEbXDMNDsJ7Hc1UcnG5jNldGjcvQ9NgxjzFxJD15BxxWnpXczeW3CVfMhrZAvT10cY
         tWTw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=OuMN9lLw;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718969846; x=1719574646; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cFBvkTRzrneetBjQDyO4WGeyO1fmudLEjQlS58DE5jw=;
        b=tMlz/PODpw1yf+If55awdo6d3nszlAEm2NSVLrRivRQUBU9Ay9bFj6rfLAUslyCYGv
         qsZDe1h9pJmJ4I5EwTWZ6XFJ6lGDWR0olYK7lMIlj8qqCZT5zmjBB3YLDb6AkMYXSj+s
         /MEqeKsNuK8PwGywubA+nZl6YKSuWtWFE4eaInvAxZEdsMD8kWNF2SpjvNhgA16L/TcF
         dRVpWSmyRJGylgu6Zq2ggnFqYBcQrIVZvjeNp8QDLUlEoJjKi88TyHMC3SpZp5gh8Dvn
         YgdtIeSwhAgndDf3hMlg+/jlCPh7XNSHBdyl+V6wNMP0fWB0fJeTj6jSLJaq4ZE9Cwz7
         uJiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718969846; x=1719574646;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=cFBvkTRzrneetBjQDyO4WGeyO1fmudLEjQlS58DE5jw=;
        b=LKzJ7jyGX8MrNMI5p9bSGj9yEr2U2dGqBA490pY0PzM9Msu0Prg47+8iSp2xoaHLOj
         jOfppntnva50dquUKue0i9D+Y6/n0wb2ckd2i4NPXzzfF13QbAXMaGNbSN4HNOrREZC6
         VJo0pFLcB1ko9q57q9IuRQz4/JJC5X7i1oaFQ7SH2gXKGXXCG4Hfp4Hv/KyBFkpySGPj
         Z8rHpXHQH5SFNMh41ZnYtIOiGBbQcBSnXmC9VIPrUiQdY8y1aiWrFK8yF4hSDuMA5dgt
         y+wUplberS4q2L0VReBPotlFU4+gF8S9xXryzweERaNznL/CLkSh81lI/+HtgtYszsBh
         lVYg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUPUND4a9I0oTVrt+lrlrq0Kb6Hkt2bph0ruNRRFjFR5/5pPGl6w6P0urBY4cC2h3eO9YXuinqhuTql2H7L3sdNXt1GTDD0wg==
X-Gm-Message-State: AOJu0YzkYV0PpMXmYsi3Crc69vtkP0eqkm831nxDSs/zJp6pf9njXMvn
	jLZZWtT0V+RBRAa+w0wfPa5Y0tfZF2EwkR+iK9Kh39x9WkaadweD
X-Google-Smtp-Source: AGHT+IFz2hUOPvJbv9FvBbWMT2I9GJcP2yz9G5fCUnnMYQpinSzHUaeLTSv4dZ5OPORtwV1BzLvPaA==
X-Received: by 2002:a05:6808:448c:b0:3d5:1c76:867c with SMTP id 5614622812f47-3d51c768991mr8801166b6e.56.1718969845915;
        Fri, 21 Jun 2024 04:37:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1455:b0:440:3c7a:5e7f with SMTP id
 d75a77b69052e-444b4a0ac0fls24925821cf.0.-pod-prod-09-us; Fri, 21 Jun 2024
 04:37:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXNQe26Qtk0Sw8TMBFnEN3WqlKVEymoEcxtqjOjQvbTKqi+Ui+k8cMAudnpH9I4I9o12j58aaG72pLWwU7Yrew9Y4wSfXHYBlarTQ==
X-Received: by 2002:a05:6102:743:b0:48f:205e:9b8 with SMTP id ada2fe7eead31-48f205e0aafmr6072474137.34.1718969844943;
        Fri, 21 Jun 2024 04:37:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718969844; cv=none;
        d=google.com; s=arc-20160816;
        b=veJEY3pDY4IQRu4XjUl01SaCFfPvmZKj+qqV104dV29iGxtZQkgGtg5c0U4EZ5GFQU
         zWa4kVEe59PdvkBU6R5MhdrNLrD1RD7nhnURnl+UYPrCdsOJQV3vjltUfUpYY6OyTczT
         UjvLxMNCHmlWwwK8YRgnE9QiCkXKr3UyS43avDzMPClgiDF1I0+w3HvKOd5qS0h5LHkT
         l7m3G/u/we2efVcDkB0ic8d7oHuBot6PZtb9T5J27Ucp8bNoC7Olocbmzj4pB0Qocp7A
         hF3lC2IWCzSeNAQdisQVunIE9tn5HeZ8UwLhpVjtHP4xx7XoFC3YS4xSio/rUgoABdVc
         HzgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=1qF7H4bGHDZ6iOOMBP071rdyF1q1YAWA6gRStiWbHSM=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=NT2h9IaNcwvhmKLc4X0mUeaVE2OhSFZ6kSrnoktbDCxW+L+6K96pb1KnpWI+OwhwH+
         fRqBMBWRtU0EIgFS+pOFnF/jAmPVjJ+KGbh0hO0afDz1Px046NilouK14itFH5/9n6kL
         BmTOs2rw/SxZl7MbEAo0bYuMHnawv2rQLF0F9qDTkrElSwrxS0x+CzCKtQ4UkUz3Vmtf
         oYHYPy7Uap03mPcFf1Rr7fsxDnQfiVk1VOCy9fQXs3TQugM1m/D9Pj+vqeNap6BmG2Kg
         gQepFKAWU2t2Yk4gY4H4nurs4+dgvDiIipWKQ2Dnsm9xIfqTYvVqJppJCCpyKHGMo66b
         mFHA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=OuMN9lLw;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-48f331b693esi50501137.1.2024.06.21.04.37.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2024 04:37:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353728.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45LBTkcI029866;
	Fri, 21 Jun 2024 11:37:20 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw8p080mh-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:20 +0000 (GMT)
Received: from m0353728.ppops.net (m0353728.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45LBbJEh008790;
	Fri, 21 Jun 2024 11:37:19 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw8p080md-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:19 +0000 (GMT)
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L9OhiP007658;
	Fri, 21 Jun 2024 11:37:18 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrspeupj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:18 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45LBbCHq51380564
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 11:37:14 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id BE3F92004D;
	Fri, 21 Jun 2024 11:37:12 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 34A122004E;
	Fri, 21 Jun 2024 11:37:12 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 11:37:12 +0000 (GMT)
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
Subject: [PATCH v7 06/38] kmsan: Fix kmsan_copy_to_user() on arches with overlapping address spaces
Date: Fri, 21 Jun 2024 13:34:50 +0200
Message-ID: <20240621113706.315500-7-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621113706.315500-1-iii@linux.ibm.com>
References: <20240621113706.315500-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: ZhQY6_lca67g0ijpbVVKolBQCQddUqc3
X-Proofpoint-ORIG-GUID: _dvfEb5eIB4856vofN3h5INjSUP5phgP
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-21_04,2024-06-21_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxscore=0 adultscore=0
 suspectscore=0 priorityscore=1501 spamscore=0 malwarescore=0 clxscore=1015
 impostorscore=0 phishscore=0 mlxlogscore=799 lowpriorityscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210084
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=OuMN9lLw;       spf=pass (google.com:
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
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/hooks.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 22e8657800ef..b408714f9ba3 100644
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
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621113706.315500-7-iii%40linux.ibm.com.
