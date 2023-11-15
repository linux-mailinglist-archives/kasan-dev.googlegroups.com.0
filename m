Return-Path: <kasan-dev+bncBCM3H26GVIOBBAWX2SVAMGQEAWBCCMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 431D27ED240
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 21:35:16 +0100 (CET)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-27ffe79ec25sf1190722a91.2
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 12:35:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700080515; cv=pass;
        d=google.com; s=arc-20160816;
        b=ACKQklQZeyLw0hifDZGzD+XvBscqbeyZQEdtpH514WCFJv2Q/p5WM++omSsrlZYM0n
         L6C1Phw93fDpog0FQkkClz4EUoosVDs8PO1NCHuE99HpFvvg9jK3le5Jq3AGVZFxG/aS
         pNvBQaoX6yqd99S21PZ0b01gt7lHI60HG7GObovyX70MEjdWl9zVzy8xPpteV+yRjsHL
         ZNjsUMjdtJC+5IEafdcax7HypKmBzNQxYvwsEgpotLZ+jt7h27O9Zt//VD16r3khfIRo
         Tq4mopVzscUl5yYHV85Nla1l+rkuFKkrK65/+36LIZkKNJu9ApvYGC6qI0PLyY8dJLzS
         HhQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=pKF2FEMu1jzvsq+VKOPJzrOMC/SAKXaKVPwcs0SM6cE=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=IirkH8kHaVVf4AWmUuOpLHoWp0/AkGQ7FLWISrcM94RGnWyJT2u+GV0/Nui6AoOOLJ
         R5obRcZ4JtDHN8RviOeRe1xq2r59HfjG5PX5fZLORkBZ64jZR4ieljNI7Sfk93EQswIg
         Lele4yMG6nm7HMLctKmV1jZCXt+dNwc/R9G3wtXRJG8y+6REWtrQdlfJq9hX7zWwbNpG
         78y3xzHLexXSHKK6Mw0bWqj3zGQYaNA/CzesFoNNXmrBW5ey4hfBIkgCxQogPw5c4L6b
         xlP+uoBtaQCIKWrLFKArsB/75VIDC4XUvau/ap7YalqgtMom9Wf2lgoViny9uFJO6+UV
         h8TQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=cbZ558kb;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700080515; x=1700685315; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pKF2FEMu1jzvsq+VKOPJzrOMC/SAKXaKVPwcs0SM6cE=;
        b=d6s0Ov/HP5hoLb5TvNVe+tO2DlEkJ2cCdbT4wtkp891LG6R9vfk+VX94t4rPbx9HaH
         o6xNCZ427U14aVY6KAdjq4Feq6fX2P/ZoP8+yCLmSXb2OYVYhT+c2rtCwXHIrJOQCrMF
         I/5GeAWy8VImRmtS28A7WXbnEm9Ul2tPXumSmRAPYGlY+Vq5rwPfPz8MkXamA1pdxEB5
         YdGwfxY3ly6TMVWZkhsgKSDhfwLpE4yEpLomhHg/HBomQtBgpxO7QV0Ij6SHimXgiuYt
         JM498gVNrY38fAFN6hsKbQcrQi2W56p4K+oXPnJURXrCm2KJYgjJbyoCG+PQwlyAU2Pr
         jleg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700080515; x=1700685315;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pKF2FEMu1jzvsq+VKOPJzrOMC/SAKXaKVPwcs0SM6cE=;
        b=qVwk/oHEiDujpF3R3bMleD5gpBm7OljFPICtvZ0LBT5AGXY+k3mTmkyROnKhmzi8nP
         d/a0/PHRdjqBRMpfphzDdq12qBu2nBtBNt+w+yEL71MazG3uBkKvRvVfLC9Fj9dcyTKU
         i+GrISoOrWkZedhVaLjc7Bew6CtmMzJezX/tIuWbY5+PnRgrAYcMlBOzHPAOsqHydDY+
         QrKJ1yw0hLYFMJyZc6TEkAT+h2WDt+tL/nFt2GfLyvA2hiqSvax4s1NLbUfnog2oCbd6
         ZZujHPWFxpr4WQ3UltZxDCqz7PuK39e48vg67kffmtiGuxhpKxfT8lnCu8PuUXoonuwn
         /Mcg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yzx529ha44vO1Eawd+XRQ8Gi49p031Om08ItAMUrkTWJoPc80Og
	Ek3+gUGsVes7Y0+457h4lkY=
X-Google-Smtp-Source: AGHT+IFEmp44BOtglWJlbMVn43/xF+bLxbo6xZXxqu1IMYINMdaCe/9VIdqqIlXceipOZnnETGFMpQ==
X-Received: by 2002:a17:90b:4b90:b0:27f:fc2f:4831 with SMTP id lr16-20020a17090b4b9000b0027ffc2f4831mr13337247pjb.13.1700080514918;
        Wed, 15 Nov 2023 12:35:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:b12:b0:280:835:3955 with SMTP id bf18-20020a17090b0b1200b0028008353955ls106127pjb.0.-pod-prod-02-us;
 Wed, 15 Nov 2023 12:35:14 -0800 (PST)
X-Received: by 2002:a17:90b:2247:b0:280:c85d:450 with SMTP id hk7-20020a17090b224700b00280c85d0450mr11592518pjb.44.1700080513882;
        Wed, 15 Nov 2023 12:35:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700080513; cv=none;
        d=google.com; s=arc-20160816;
        b=CZBfm6JQvX+Kkq/lIjxbNO0fy2j1x8EH0hk23FbpLenmB8auP3ECGw8oE9Ov1zeTgO
         rAvvq62PcgLUL+iG8zqQSTu3pgvaV+iUZMuAwjFi5jGw8bpFMYpFuu4J+p0kZbrcUgWd
         e8Tg+nNxN4Nqks9AcqMxsDK7m5ewaZb/3nsC3ouK7a6ceJj7sJTuwGXbzDu/3mjcJ571
         1iPpO/sfSjb84dxSR6t8zK64Pmd5k3wBBZhnpcGpKeykOtLuWIgMSfqsAUfw/8YlDWd4
         AQ8Lubh56yVFKNg/02lMgAjDT5X3T/9UK9KMkZRqDMPOoHR1JEG0aHUTS86JDeZFxqpy
         bYTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=VRISF6fjkFQLGNL8R/C4iEGZtM1pujBZILDlqB1XNVQ=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=L0bG3bglkPgy5tCfjSIyM6e8devscZa29ulS0g0mWvn+HIU94phy7W4YuZ5KBF6M2q
         an5iZWq0gOpUt7pIzYysdYNu7bun19VoPQnvkEZFRYMolzyOUiylS2vUEItRZSEtk8Dj
         WbA6nvDcR6/NPFpahg9msUcIYQ8gbslwnZsy1QOBE8+iUgCjmiAYHTY3ThtNghyMb3nH
         IE3YdeMHOegwhu8h3UV8fux9SXTc6LrpTB4PXtYWCqcETCt0E4lvZsJI4r+a7n4mAnWa
         sf76VqMONyQAZVf61SaS+h/2u93uRnvh6iYIvs6wMyn0fIsWhIFUoeg7VR7Pe8NKEnFR
         TT2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=cbZ558kb;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id b9-20020a17090a9bc900b0027d0d9abe6esi33735pjw.3.2023.11.15.12.35.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Nov 2023 12:35:13 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353729.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKRwnS004994;
	Wed, 15 Nov 2023 20:35:09 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud51q068t-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:35:09 +0000
Received: from m0353729.ppops.net (m0353729.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3AFKSttQ007862;
	Wed, 15 Nov 2023 20:35:08 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud51q068a-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:35:08 +0000
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKIxYd014619;
	Wed, 15 Nov 2023 20:35:07 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uaneksw05-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:35:07 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3AFKZ39F14680708
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 15 Nov 2023 20:35:03 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A211A20043;
	Wed, 15 Nov 2023 20:35:03 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 530C720040;
	Wed, 15 Nov 2023 20:35:02 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.9.51])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 15 Nov 2023 20:35:02 +0000 (GMT)
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
Subject: [PATCH 32/32] kmsan: Enable on s390
Date: Wed, 15 Nov 2023 21:31:04 +0100
Message-ID: <20231115203401.2495875-33-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231115203401.2495875-1-iii@linux.ibm.com>
References: <20231115203401.2495875-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: 2vgw_DyCu_LXf49xJoaLzSkmo0C_QjrU
X-Proofpoint-GUID: jsb4NvqZ_AbBoKk-uNmxqfZ0Ve_6hGBS
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-15_20,2023-11-15_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 spamscore=0 impostorscore=0
 phishscore=0 suspectscore=0 bulkscore=0 priorityscore=1501 mlxlogscore=767
 mlxscore=0 adultscore=0 malwarescore=0 lowpriorityscore=0 clxscore=1015
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2311060000
 definitions=main-2311150163
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=cbZ558kb;       spf=pass (google.com:
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

Now that everything else is in place, enable KMSAN in Kconfig.

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/s390/Kconfig b/arch/s390/Kconfig
index 3bec98d20283..160ad2220c53 100644
--- a/arch/s390/Kconfig
+++ b/arch/s390/Kconfig
@@ -153,6 +153,7 @@ config S390
 	select HAVE_ARCH_KASAN
 	select HAVE_ARCH_KASAN_VMALLOC
 	select HAVE_ARCH_KCSAN
+	select HAVE_ARCH_KMSAN
 	select HAVE_ARCH_KFENCE
 	select HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET
 	select HAVE_ARCH_SECCOMP_FILTER
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231115203401.2495875-33-iii%40linux.ibm.com.
