Return-Path: <kasan-dev+bncBCVZXJXP4MDBB4OPRXAQMGQEN46RIBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id D363AAB58E0
	for <lists+kasan-dev@lfdr.de>; Tue, 13 May 2025 17:40:35 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id 98e67ed59e1d1-30a91c0745bsf5490679a91.1
        for <lists+kasan-dev@lfdr.de>; Tue, 13 May 2025 08:40:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1747150834; cv=pass;
        d=google.com; s=arc-20240605;
        b=eN7jl8fxbiAh8KWXu+lHmnoSI9tt2eyNiFZu6I501wAWke7v4CrMvYxfecmDE6ARS/
         Wa+OsDyyT3GaWM1OvtQATe09cGfupCaqaC3HiYz3Y3tG1CuRpkJAJOCWdajWsmcw0hJp
         fpX/csxI1dZ5xunLiw21rUXCZI2hQRe4pFrbnY8GmLUgNpEfoTkh0hEKSVbqM6zKCPex
         IonpE08aGgNOjqDiknmsQNW5Ca8OkqQxuyw9xg7ywTtvufj9pFAOYLD6gnb1z6SO5Khz
         Cizb/2QHwypsf/MN9ZImatMLZo6xXEeeCmyqSaWE+Ax2zfK/qg/NhqjZvBMU8EOp3tBs
         pnJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=9g/0VoB4XPvx2UQdy84uaY9roN33g+V6xlTINADiHFc=;
        fh=I7pYjUHjhvLLKJ6DS0wo/eituHkq0XrPXL7gLIQeEW8=;
        b=igk+dwDZbWTzPjGd9i7oUisStQo7CGs/wf1CdcP4r9tE8FpzeZJKha5t3X0R2nY44X
         X4UgKw3hC/fKgcknkEI+2iLrFm/6aRoWhY5t2RzlNo0R9mj8lobZJJnwLqB0fLNZU1iS
         Cn01NXmlKpbQgpVZjac1/IEtoQVpROnjVchcX01/qQjIdqyLFthhj5TcRItc3m2jMub/
         mi0Zm6T8In5OBrZ8YWnhYx+mIl9V/QP5kQYrOa8nX75gKtxm35CZ6U/JyZ4Ndzl2nRaY
         QxuHpzLD54IhS3rpc6ULFrzcd4UJdh5HQ53CXRFPKNzCVZDNSsO3YwXqIRdzS2NCS20V
         G+Jw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=hxvAFFFb;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747150834; x=1747755634; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=9g/0VoB4XPvx2UQdy84uaY9roN33g+V6xlTINADiHFc=;
        b=K5wKiK4mrsOtWnZP9JP/eeUp7bhSuYVIf0n2lbAnjlAuu4xcznSdBzgVhtmWG0CpBL
         S1N95DxAyrRN0pnp63Gj0bxcegBOIPpjuLtam1KQNn9jFfbUn5ozn5msoRIvI79WAGMo
         dhOVcvGN65uxRREkY8mqIMd90xY1U2DXaVnGaddaXaTdbITxQAaCiBXZzP97CLoK+HMF
         f+6srzaoOdvLNo9EqLOyEL8jXKWx6m3usFxUPmzXyWqRa6e8NCz8iDts29XwUWte0SBT
         d6CawhicGAp+qsonULwZDKm21UGn81bNO4le6Ivh/b/JxXSUC9x0faUlLRUjTzKysQwj
         dFCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747150834; x=1747755634;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=9g/0VoB4XPvx2UQdy84uaY9roN33g+V6xlTINADiHFc=;
        b=t0PrkqZomkuiZzBy+Vl/xAz/Ah0e2vI5EdTk5D1RR0mBfP9MrrBW0XhIRhSESQAZ/a
         b1z2+hmt12yHIpPpqGO4zYe9rvqDsEqjEE3OhcU9E0Lxd9bF0VX9sMzlFqOx3352BsuX
         dLAK4UlLGdfPrrf5KLmivBPJHoumi1NMoKwUx5KF7Rn98zV6nFQBWDD7xQA/6lLBvLCO
         0jwG4aPNthZAisbPjMi9XBYoZ6KwTT4mvcFX7XqGhYBBLxNV9cWC2Tsqjk4Mu/al9g5v
         XyP5Q31vAOZVgRmvoosigyGW4Iv45oiDNRXHIKi5xrkRElAAjV0MxAdDftdH3KNPWzG9
         cglQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVQtLBvcmsgcAJYIdi4ZBBOCuzlDT9S1ye0TZcmkI89wWcMtkagoBk+X2/j9vGQEy3qOKRMbw==@lfdr.de
X-Gm-Message-State: AOJu0YxWyG3iDYNSiK7YEgTIWZgoQy/xPsLRYX0ifu8INYYLH5Fr4MNk
	L0kCDygFg0dwgZYUVvuoGMCBT9zAwdx/k16jWFIClqEb9yJ8mhT4
X-Google-Smtp-Source: AGHT+IG634cjuSQ4jSYfLPKP076e4GRmiNBpOiyegxZl0v4F9jSjG89bSugDsAZp/1uz1xabChXvnw==
X-Received: by 2002:a17:90a:d644:b0:2ee:c30f:33c9 with SMTP id 98e67ed59e1d1-30e2e6263afmr29476a91.14.1747150834080;
        Tue, 13 May 2025 08:40:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBG0RR82qJuomre/FXouDr8FOTPUMd2hyB5EB2ZrEy+iVg==
Received: by 2002:a17:90b:3008:b0:2fa:5364:c521 with SMTP id
 98e67ed59e1d1-30ad8ab7c93ls732153a91.1.-pod-prod-00-us; Tue, 13 May 2025
 08:40:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWq2mFcsz1KVaoyFvlEeV4VY4SHJwDyJ1nVyYJ93IHkihKo9lLOrkxW4u8491VHne4wlGHvtKMM2Uc=@googlegroups.com
X-Received: by 2002:a17:90a:d644:b0:2ee:c30f:33c9 with SMTP id 98e67ed59e1d1-30e2e6263afmr29318a91.14.1747150832695;
        Tue, 13 May 2025 08:40:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1747150832; cv=none;
        d=google.com; s=arc-20240605;
        b=LiIsYGyO4ePBdSV+UUA0OE3G1/hYURa4pDr42XSG9gpsBPk/WZpJNqAgW5Mna31ZME
         BaMnTeKM73Vd+qP9dqNJS2hx55c4I85Vb03hxQaB2nOZAzv7Y1FIu6jQxYK5dXxMLKB3
         YROrbxoD2ssE9IzFe+bT9simrTt9813fr3QjS9P3Fewofz3seO4OmmLVrDnOKUWDhVfy
         Jme5bPFhPQY6r5hjnPpWA/h5Afd//H5hGcT643G+RCxfDPzl9JOb6zmUBAu897heg1g1
         JkVMTqm99aXWk8JVT/r3EwgPyhNHPgCqDzhNFcr1HAwVV9EDk7bdEqTEaKScjvE5b4B+
         ux2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=CQfh1MzvC6iT6mM7lVHwgZXBAw8DRUvB7ncdS0TY2e0=;
        fh=JeYjkRDw/VSjlVIISM+t2OTgWgKSm5f4n50024gbhWA=;
        b=Ec3SCnkadDCbSpkQXKaO72N/mtiY2sB/m0tEevKY5qInlPKqDNuRMVPe1pRuYMXzGJ
         22nbEqlenrNlqrHlkclVPcIsTByg+Ngdu1XCJUHn2efbU2M+DQMVIHIO/FkrNvKDBA8r
         IYV4SMRWrkd2ao6xyn7EXSG2m4imQwIvWYWmDuyGHm07CWnibvTZ+739vEFFQuJUlzS4
         Rny1Ig1vBQPgacjlu+HaNsN8y/e8zw38Kai9vFfozGmntLs7fRg/emUpz8HYBulaGtU6
         PZl0cu5s3V0d1tPELgrRbbt9vU+K0RlkQLtCMrQY9J+1+2DTPS7+O/pN+AR/0KH+2KZT
         bToA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=hxvAFFFb;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-30e11f0776esi141728a91.0.2025.05.13.08.40.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 13 May 2025 08:40:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353725.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 54DDni6C032140;
	Tue, 13 May 2025 15:40:31 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46m7a70jc6-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 13 May 2025 15:40:31 +0000 (GMT)
Received: from m0353725.ppops.net (m0353725.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 54DFNlGl022147;
	Tue, 13 May 2025 15:40:30 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 46m7a70jc1-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 13 May 2025 15:40:30 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 54DBt8I0011552;
	Tue, 13 May 2025 15:40:29 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 46jku2be14-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 13 May 2025 15:40:29 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 54DFeSHS52822340
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 13 May 2025 15:40:28 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 4E17F20102;
	Tue, 13 May 2025 15:21:03 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 3AAFE20101;
	Tue, 13 May 2025 15:21:03 +0000 (GMT)
Received: from tuxmaker.boeblingen.de.ibm.com (unknown [9.152.85.9])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Tue, 13 May 2025 15:21:03 +0000 (GMT)
Received: by tuxmaker.boeblingen.de.ibm.com (Postfix, from userid 55669)
	id CCFCBE0609; Tue, 13 May 2025 17:21:02 +0200 (CEST)
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Andrew Morton <akpm@linux-foundation.org>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Daniel Axtens <dja@axtens.net>, Harry Yoo <harry.yoo@oracle.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
        kasan-dev@googlegroups.com, linux-s390@vger.kernel.org,
        stable@vger.kernel.org
Subject: [PATCH v8 0/1] kasan: Avoid sleepable page allocation from atomic context
Date: Tue, 13 May 2025 17:21:01 +0200
Message-ID: <cover.1747149155.git.agordeev@linux.ibm.com>
X-Mailer: git-send-email 2.45.2
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Authority-Analysis: v=2.4 cv=K8ciHzWI c=1 sm=1 tr=0 ts=682367ef cx=c_pps a=aDMHemPKRhS1OARIsFnwRA==:117 a=aDMHemPKRhS1OARIsFnwRA==:17 a=dt9VzEwgFbYA:10 a=M4n5Zv9w_bjhLjlc4U8A:9 a=zZCYzV9kfG8A:10
X-Proofpoint-GUID: DBBehTTBvX9qsC78fS4B-Pq9qcDH0x5W
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwNTEzMDE0OCBTYWx0ZWRfX3Ro2qgunbtst YpiEJWshZEpwgFgNh6DUgLqham72fs4BvvKMKutOoHPSH07AlpYe7pQ5YCi2HdZ5nILC75uCiju IWYImiPzfWf3podYFZOjSls1rcOdgk72yDa3rolzKL4vg7MxTtRRzOD7Zs54dCpcFIWuxuu+EK0
 QkIJ/BRGoGmhUCBjzaDyz1IMReBDty2ghHIQLCL1vaAhGz9JkAgbrDVty+dUOHB1jXN44t7HVJK cMtIYLYwLwmus3mL71kB6cl1K28JDvLF2O3KG8dkNu9dJXSM3ofh9geWQ4w/j6r7+O4igy6meEp 0nXf51BmQu16OcHzaLETtDpfMQ+PxaAqgY6hNFo+C5dr11+LBz1O0Gz/NEb1ZL+oousbZmNyN0g
 kS3cSLrkhmXIK/w+vptnwdeTNCkhyZ72QS3kKi57VyvofCfZSG4SaN1iUvPpz4AIUvoDujXn
X-Proofpoint-ORIG-GUID: eeJyLkhC8F1qa6Wbqxc-xE5X7ub4YSI3
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.0.736,FMLib:17.12.80.40
 definitions=2025-05-13_03,2025-05-09_01,2025-02-21_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 malwarescore=0
 impostorscore=0 bulkscore=0 suspectscore=0 spamscore=0 clxscore=1015
 lowpriorityscore=0 mlxscore=0 priorityscore=1501 mlxlogscore=721
 phishscore=0 adultscore=0 classifier=spam authscore=0 authtc=n/a authcc=
 route=outbound adjust=0 reason=mlx scancount=1 engine=8.19.0-2504070000
 definitions=main-2505130148
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=hxvAFFFb;       spf=pass (google.com:
 domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted
 sender) smtp.mailfrom=agordeev@linux.ibm.com;       dmarc=pass (p=REJECT
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

Hi All,

Chages since v7:
- drop "unnecessary free pages" optimization
- fix error path page leak

Chages since v6:
- do not unnecessary free pages across iterations

Chages since v5:
- full error message included into commit description

Chages since v4:
- unused pages leak is avoided

Chages since v3:
- pfn_to_virt() changed to page_to_virt() due to compile error

Chages since v2:
- page allocation moved out of the atomic context

Chages since v1:
- Fixes: and -stable tags added to the patch description

Thanks!

Alexander Gordeev (1):
  kasan: Avoid sleepable page allocation from atomic context

 mm/kasan/shadow.c | 77 ++++++++++++++++++++++++++++++++++++++---------
 1 file changed, 63 insertions(+), 14 deletions(-)

-- 
2.45.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cover.1747149155.git.agordeev%40linux.ibm.com.
