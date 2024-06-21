Return-Path: <kasan-dev+bncBCM3H26GVIOBBB6M2WZQMGQE7UEGHYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0334A9123E6
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 13:37:45 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-44350001e65sf512001cf.0
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 04:37:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718969864; cv=pass;
        d=google.com; s=arc-20160816;
        b=ePAjL2q+1bgXjEmtrv7xZLWjoBIPXNwXVfFNs9LL/ddd+L1ogfkz4JgCjAC9NG9Sww
         gRHPnA3nyW2/AAY5uu/LsSR6btxxvHW2user+fp6cysz1RYD0YWPueseaQ98Yf1MKxO2
         CTQI+FdrsaKcupAVJP+ysvVsisdXs0yMdfhjMUS+28boqtNhA8GgjH/TzocWZdXdJDGL
         7WqemJnUubhb2GJrUFX4dXSgUTn9+opZS5jZQx1EKsKPr7ioLyAZOxQ9bdbxa5PHjurc
         mLomFCnAkpmakZAd9NOJhNJhMJYySIVJ3JhgD8estBKy0FvqDL8DNkJexqsXYKIDQ+Wm
         1L6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=lSuriCDjWXfKprRRff3fYJKBfAsAuquqaM5lQmyqVYo=;
        fh=8u8fZSDybVUiSQyhprclaFIGSE1QarIqXYP7N4NZI9w=;
        b=ZEhmXi6HqLaXyb4k1m1aavZ+wgETiFhvb2V3/OUoDSAr2F8iGdslpssR0WqDxgvkLB
         NUFMRZKNeKNdR92TiMCxLQxWj8g19qfoWOIyOxhlwt+Ih5tws0yVKz/MqeLAWyjzK+xG
         0j0uXMIQbmkyw40ifmR0d35lx7v0Bo5YRYOGJporm0k3scOhRyU0dfxye20+fCu1j11a
         rWukggABBOwkp9oDkg6xfTZBfMd4BIBUZCoRtY9tAiQS7asrk+iOuPFNpvQVYGj54Epc
         1DUvHlydmFnJ6g5W874BhLfvtQSm5XQ8BY4d3Jrc9cSBLrZs+FIuffl3pkA1iPIw+YDt
         eOqA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=s5vlhwXl;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718969864; x=1719574664; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lSuriCDjWXfKprRRff3fYJKBfAsAuquqaM5lQmyqVYo=;
        b=R4RHOB+rDtoQnD/RIqxKXW7SLJ39H0rssp66b/mqW26Ekah9mlfGVCe9AinSnh09A6
         gy7W0np6hEcoNwl/UUp9Fz1nxFCQcXfGGWNqzppr02OIQRrjztNUW/XxMEXMAljwx7r1
         WGGVknGzsLgGYMsgDyiVvTR2YEj5pA2iH6wDnStglDC5KIvO2n3Z0AG+rJzm5qwRZ9fU
         t12uLkbZmWeVW5dEgyZ1ZSXuS1+5SvoEen5ZagOuydAGYa6Dtx5uW7YIxtO8bgLo+Uvc
         NK/thnu5+cPFIEZ51ghI9Cguz6R5trk7C95H7XWiIjjnlO2Bil2uqYgVThlSD3hX3uGI
         Wj5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718969864; x=1719574664;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lSuriCDjWXfKprRRff3fYJKBfAsAuquqaM5lQmyqVYo=;
        b=mmCpxcL4RKGxtG+VgtK6wmt9VMNhxpK96DyQo/7b4n6+n7bcNSxhVDnTWm8wA5ghj4
         /FSlhRHbTLRrLbszMqlPRxEY91nabgzJYOtDtVTndjK+tfTIiwaejly12JsUR/9RIEb3
         alxWhF0ql1htaK9yryzymg+dlJ/DqF8XHmOuG9IBq0Y9WyNyEsiHVDowNtXkY0utjKmE
         bO06tx/zqXIUIbDheE0/T1Z6WSwr0xhZw09kjuV/QuAHoxL1AKqYazmQh+yu30eGQl6k
         T85fp+vrs9Vvsp7SxRxuHsgLN4g2JiBh9d9jNT1N2lxGcnEKoYU8xtrDszjjvp6ukt5y
         erLw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWiK4/iZXcokMr/3zlYL6xoRdICr2iTJJuYjB3G+SugBEhARnQA9V2OIjsC+/irRQLJIPhMDFIdv8AGYqIJxQNIZn6QsgipqA==
X-Gm-Message-State: AOJu0YxWHaM1D93I0WMT/lk9gBQ6Qa+0wmxW5TuDSJJ0XVhqKCIKVXaN
	mGp129MTvD9au7Uc/XPENq1qssfYpMkse8o6BWhUZRTLWTqK2q5J
X-Google-Smtp-Source: AGHT+IGpRPnp2cziEWdmLgQ1QO+oNDjOF4MJ7SWUXHJAdbpb/j+WZY62j+7DnP7sJWjUVxKG4VySnQ==
X-Received: by 2002:a05:622a:207:b0:444:a760:55de with SMTP id d75a77b69052e-444c1b498demr3150111cf.24.1718969863874;
        Fri, 21 Jun 2024 04:37:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5dd1:0:b0:440:a6ed:f91e with SMTP id d75a77b69052e-444b4c19342ls25100491cf.1.-pod-prod-04-us;
 Fri, 21 Jun 2024 04:37:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXA5Aij769ywfD4Z41p/rzIIV0pRCECuARqU7Ut1dmH9IdwQIhtbLh+DTQEQ9VccmBTwJ/k/VGMzfbg4ZwnFB1BN0w+PESN3lQJHg==
X-Received: by 2002:a67:f2d9:0:b0:48f:159e:8eff with SMTP id ada2fe7eead31-48f159e9183mr7416677137.9.1718969863174;
        Fri, 21 Jun 2024 04:37:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718969863; cv=none;
        d=google.com; s=arc-20160816;
        b=NmbLV4zdkrVvY+JdvERZMiG1wdc1TwwSco5OxH+hnWLcKJ7c4lmpqthHfJ+D42XDLL
         Xl7Ghdt94TAj4hqwhXCenUsin/Sge8JfFoLcd5mpDG4g3XnHz3nDylmO7yx7KFHjNTxp
         iw8EeG+iq3uyCIY45Ty7QfqQBZqNTnjD/Cz0wmr3TvtGK13YX+7OF8z7/1FgmUU26Tl9
         QWm1Hn5AMDqBdU/+mo2idGZJjpwKr751qrFP8kshPf/+2mgIOClyTstFF1cns0GDEQBx
         aWxC9VC7lBZP4UX+GKlvbt4GdcObnwBPJmkhV14FO9vNxwT1bYUxwYA2sKTCw7vX3i8I
         iNfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=7JeBzaeHcq491tpoSsSSp7r/Korv/EUFDTbEVwfZL58=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=vAKPKa8KYoYsAwH9jXlmghBZgR0LQgcNl4xkxxuptp5yz5U6jAdd/6dG9GoZaXD1+p
         7t7tEicxy/VakH7yU3OfD1Q3CJ6AnZqC8RVpo6issH27B8oVsBrPX3iDoP9AXVZKzrb6
         mXx57iNfV2wm3eIrlTWnvDvYxVgOaVeUZH1okYYaaDpVmqj+pkWamju8VvkhkJBeFL7W
         6oOrxXzb9uVelPi0DvcUEdcGlcHurvp5/HTLZQip2HGX+wIpqNAq58/mlzwKgt6uh1zB
         h230OMrvDbHdbyJ9+/IWz9WCWuNaWITeRDaxX6/ZQN0MaKUc4HxjcRwS6nucomizXTmi
         4WNg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=s5vlhwXl;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-80f727295casi43543241.0.2024.06.21.04.37.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2024 04:37:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353728.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45LBSf2G028853;
	Fri, 21 Jun 2024 11:37:39 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw8p080nb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:39 +0000 (GMT)
Received: from m0353728.ppops.net (m0353728.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45LBbGeE008753;
	Fri, 21 Jun 2024 11:37:38 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yw8p080n7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:38 +0000 (GMT)
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45L95u7T030896;
	Fri, 21 Jun 2024 11:37:37 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yvrssxvc1-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 11:37:36 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45LBbVT348038282
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 11:37:33 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 2E31C2004D;
	Fri, 21 Jun 2024 11:37:31 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 97F572006E;
	Fri, 21 Jun 2024 11:37:30 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 11:37:30 +0000 (GMT)
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
Subject: [PATCH v7 36/38] s390/unwind: Disable KMSAN checks
Date: Fri, 21 Jun 2024 13:35:20 +0200
Message-ID: <20240621113706.315500-37-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621113706.315500-1-iii@linux.ibm.com>
References: <20240621113706.315500-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: zSzxBnNiRLG-D4DcHEnxIzI8xLfICJN1
X-Proofpoint-ORIG-GUID: PuVSxHAzakVrVjiND7EYgdN9hTCqZmCa
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-21_04,2024-06-21_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxscore=0 adultscore=0
 suspectscore=0 priorityscore=1501 spamscore=0 malwarescore=0 clxscore=1015
 impostorscore=0 phishscore=0 mlxlogscore=896 lowpriorityscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210084
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=s5vlhwXl;       spf=pass (google.com:
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

The unwind code can read uninitialized frames. Furthermore, even in
the good case, KMSAN does not emit shadow for backchains. Therefore
disable it for the unwinding functions.

Reviewed-by: Alexander Potapenko <glider@google.com>
Acked-by: Heiko Carstens <hca@linux.ibm.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/kernel/unwind_bc.c | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/arch/s390/kernel/unwind_bc.c b/arch/s390/kernel/unwind_bc.c
index 0ece156fdd7c..cd44be2b6ce8 100644
--- a/arch/s390/kernel/unwind_bc.c
+++ b/arch/s390/kernel/unwind_bc.c
@@ -49,6 +49,8 @@ static inline bool is_final_pt_regs(struct unwind_state *state,
 	       READ_ONCE_NOCHECK(regs->psw.mask) & PSW_MASK_PSTATE;
 }
 
+/* Avoid KMSAN false positives from touching uninitialized frames. */
+__no_kmsan_checks
 bool unwind_next_frame(struct unwind_state *state)
 {
 	struct stack_info *info = &state->stack_info;
@@ -118,6 +120,8 @@ bool unwind_next_frame(struct unwind_state *state)
 }
 EXPORT_SYMBOL_GPL(unwind_next_frame);
 
+/* Avoid KMSAN false positives from touching uninitialized frames. */
+__no_kmsan_checks
 void __unwind_start(struct unwind_state *state, struct task_struct *task,
 		    struct pt_regs *regs, unsigned long first_frame)
 {
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621113706.315500-37-iii%40linux.ibm.com.
