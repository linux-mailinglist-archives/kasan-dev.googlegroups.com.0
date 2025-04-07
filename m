Return-Path: <kasan-dev+bncBCVZXJXP4MDBBKWWZ67QMGQELPQFLWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 080B3A7E382
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Apr 2025 17:11:40 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id 98e67ed59e1d1-30364fc706fsf4117708a91.3
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Apr 2025 08:11:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744038698; cv=pass;
        d=google.com; s=arc-20240605;
        b=CnTp7GJI7opJFCDPM4cBw8nuUmu/s9FINgPLGtepsuh7lyBSn6Bp7b2Rdr98cQ5S5Q
         FHQut7sqjF16zh7sR/B3uUPDIzM6GLVYvAXUgBvwIJWLGN9GmalY6JCVe+wSmISZIVKj
         cr5mVVBdYkZd+t4LVNCF3Gu7YgYs1crfEOn1FAm0vjlOtHv7UkaxVwoFO8YlQyYouNR/
         /Tix8yfsgKHZNq7AmyYAM7/ZlUpVcMqbqtmDawbch1RogwC4DarLtZBchicuI4zg866+
         0BE5246iKpATd+437Y6E5kcciuD++SsgU0XByiTIl2qKQ2N/ZLNczwYmci44PizkVfZM
         1aGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=jiWk2jkjpk++iRMb3fn8/1nV4J4JNrKcM6MD+vMGSU0=;
        fh=2MowfPuJq+w66+cRuAtZpkw0K5dKIkGpHGWSwOW2uyg=;
        b=DY0jnf+l3s1zxpWQz2p6JAWf/oxjheLZwrONoF+UEb1Fg86jAfBmDAgfZhVj1mISww
         eBY4g9Hdg49p7QG0ZtlVrfnhUOX8saEqlzMUo1GPPb+WyZOXkatN5pNd+5tLHv5Y7dfR
         2UbqdQN5GaOmx5PBPixBcPozEvL5vTCcCEnuIhQOH5wKEhxIonEFhP9Bo4Nfd+uBo2rx
         qGz53Fs9es5V2LADCAdLXt9lZUbVPqkrozME9/+9PP2N57qVPmajuX7QUDcAoyWRxtzd
         MLn0gspp8JdsTxorp+HJBVoUGcaQErWGCfHLCtLU4g7tpmF0eApONoBQKwWahrlWaqPe
         ddXQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="GG9/qRMT";
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744038698; x=1744643498; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jiWk2jkjpk++iRMb3fn8/1nV4J4JNrKcM6MD+vMGSU0=;
        b=fZtY1b7axpJkudXJ59EbKIuWR6XsFSs8ac9ApNtdktngs2xdSXAMspJo7ou6orBavE
         BZHSx3UQBtxX7/kxWhYCR6PoDWIk/ex1CHfVysPe6/qT9Hd8lfvd3mPQWtb+pfc32VFm
         JtXgK1RJ1JA3HFruUF9lM+VwZ2kA5FnuIZt92lSAwkNJgui6o2u/NV/ewATD3s8sqeW2
         nyESTt5yR24WzrbDBJv1ZZiIma9SdbcPiUOkfLFAfwSK8jZ6KLbUANa1QSOWW8xQFWhk
         xNCaVOxpXFhUzNSNCxMx8PaekJ8+gWTL2lEAcudE46SDSiTR144Ht4mdqFhXMozT0UZt
         RxPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744038698; x=1744643498;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=jiWk2jkjpk++iRMb3fn8/1nV4J4JNrKcM6MD+vMGSU0=;
        b=LI5ymtGWF7QLnGJ23oxvNfRAr9c4aOsUZrFeSZydbncyLKUvImgtCVQwCxBiBkudoN
         zGNoUSe1KegYr0zOB+zjMW6EwvHmaEWM3ieNl6sdmHxxN22dBUlGfqeTdAC4hkcvB7sL
         kD50j6IwlLhpRRNhpHVhb/xFzV5nGLXx+6Av5qRy4bjwvfQP/+EP8m5OgmIfHt9aboIY
         O2W8Y79qIxUnvkW8gsQ9RKwflH07fgM2pndi5/jKhkbUKNe9F7nipsCu4c9mpFoJqw/V
         6edkxXQ7NR00Kx757oACjctjdF9t1jrmpmV5NkC0NAEN0RcOQ6xLthSwEC1E86dpOqT7
         MwIw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU/HxMeQ2Fbn5w/d2367mc7vw8xkvjQX+o98cTBeq+D0+6Yalxa5GAZoqHaoAdIOnkUASjMSw==@lfdr.de
X-Gm-Message-State: AOJu0Yy8rsKDLOtb0+UkHD5a3GqvYrulQ1GMzH7PhbED4tgcFOlnd3eh
	eXIZQCIFsN0LHC39XkN8jiWLZne7/Pbw8j4YEsIuCHaDP9rc8gvj
X-Google-Smtp-Source: AGHT+IFPBNv/UnwlejaOi43F1nBvMRt5gPbOq9YTulCulAp0/7W7Ry4TzYIX3+R6aTp+eBy2sBPwmw==
X-Received: by 2002:a17:90b:1348:b0:2fa:157e:c78e with SMTP id 98e67ed59e1d1-306a4822fccmr18219620a91.7.1744038698335;
        Mon, 07 Apr 2025 08:11:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAKm/yqW0r51h6CJurCJWYJg7xVdRChDSt+2JT2QB97TQg==
Received: by 2002:a17:902:d588:b0:21f:7c14:e7f5 with SMTP id
 d9443c01a7336-229762092b8ls3953005ad.0.-pod-prod-01-us; Mon, 07 Apr 2025
 08:11:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVP5Fbeo2zdjIHXSg+I/RviCwW5zK+G7mxlPtWJw/TbO6wtqsIcRtWRkOIx6Sp5+s/BEX1O0CL5En0=@googlegroups.com
X-Received: by 2002:a17:903:2a88:b0:224:1074:63af with SMTP id d9443c01a7336-22a8a0a3963mr184994555ad.34.1744038697089;
        Mon, 07 Apr 2025 08:11:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744038697; cv=none;
        d=google.com; s=arc-20240605;
        b=MHhi6EAqFyE+K7SyqBNg7SAZ10UY+dY7eORw5p4Nm3TfK6mWB7wpaG0uWlDNRHK4Ny
         ia3xKNqawArmrCPXSW6jOIg22qYaRAk24o3gFx4w6seP4z1pNaYDLL4ZLuJJstLbih66
         oeD1bdIkr8CxyclKey2v0AMmg+kgwoRp2sEntz8vJGZtCIkqvEoNzm36vf5nGfA36SsI
         aKlen3Y2wsnFKItbge49F/MbVh0iC8i6Ul8bM6M3RQSrnBpH26tjRKdEmykMn9fbj8Ne
         ls9RdzfTyNth1nCd3NGNMDZB9pqKBULiv103Ez3zG2CGImvN/A+Tk8COdB2YRDzTTXXX
         S92g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=pLqNtHwxdz+KjzF0o4al3IuUdgKeg437/opuwF8rOgY=;
        fh=LVJPJYP2Tqlg8aWQBGa6aniChm4kWZS3hY9A1BPUb/I=;
        b=TAgNw8LySLjzpdxck9RGzOnsEadJTWlcp4cuQTvHluTZ8R7T5zeitdmbjrXk/8APFd
         O2H1NYNGi5U7Si2WLm8PM9Iv4PogiljjOxjq1T5wswTJ/M5xbmpMRWdD/MkTM8WbK8a4
         E1ud77q1V1x7v/aFJxntyUSVYJ8Dk/dnQ3Eo84cJiHJJxOLcCED5WfgH5TkfwKFRZgQI
         dD6QBPkeI3w0R8cg6vOqA6zfWlQMqKglgESl84y1lf3I7QZ8yAbQwSFKR55VYOYSxZBX
         RwacTuPRMmZxg2KX0eq+GC5KBRWId5NHjaCC8NJEFBsFIqBUDuyXakD5TAORv6umclqm
         Nrdw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="GG9/qRMT";
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-22978662385si4257785ad.10.2025.04.07.08.11.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 07 Apr 2025 08:11:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 537E3FIb025560;
	Mon, 7 Apr 2025 15:11:35 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 45vg4q8cmm-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 07 Apr 2025 15:11:34 +0000 (GMT)
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 537EoQ3W019216;
	Mon, 7 Apr 2025 15:11:34 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 45vg4q8cmf-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 07 Apr 2025 15:11:34 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 537EKIMr013925;
	Mon, 7 Apr 2025 15:11:33 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 45ufunecfm-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 07 Apr 2025 15:11:32 +0000
Received: from smtpav04.fra02v.mail.ibm.com (smtpav04.fra02v.mail.ibm.com [10.20.54.103])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 537FBVTI19595766
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 7 Apr 2025 15:11:31 GMT
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 03DF82004D;
	Mon,  7 Apr 2025 15:11:31 +0000 (GMT)
Received: from smtpav04.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id E2DFB20043;
	Mon,  7 Apr 2025 15:11:30 +0000 (GMT)
Received: from tuxmaker.boeblingen.de.ibm.com (unknown [9.152.85.9])
	by smtpav04.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Mon,  7 Apr 2025 15:11:30 +0000 (GMT)
Received: by tuxmaker.boeblingen.de.ibm.com (Postfix, from userid 55669)
	id 88272E175F; Mon, 07 Apr 2025 17:11:30 +0200 (CEST)
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Andrew Morton <akpm@linux-foundation.org>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Hugh Dickins <hughd@google.com>, Nicholas Piggin <npiggin@gmail.com>,
        Guenter Roeck <linux@roeck-us.net>, Juergen Gross <jgross@suse.com>,
        Jeremy Fitzhardinge <jeremy@goop.org>, linux-kernel@vger.kernel.org,
        linux-mm@kvack.org, kasan-dev@googlegroups.com,
        sparclinux@vger.kernel.org, xen-devel@lists.xenproject.org,
        linuxppc-dev@lists.ozlabs.org, linux-s390@vger.kernel.org
Subject: [PATCH v1 4/4] mm: Allow detection of wrong arch_enter_lazy_mmu_mode() context
Date: Mon,  7 Apr 2025 17:11:30 +0200
Message-ID: <5204eaec309f454efcb5a799c9e0ed9da1dff971.1744037648.git.agordeev@linux.ibm.com>
X-Mailer: git-send-email 2.45.2
In-Reply-To: <cover.1744037648.git.agordeev@linux.ibm.com>
References: <cover.1744037648.git.agordeev@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: wG_AoPwbLBLy8-Y75yYVC-cpQvofPbGp
X-Proofpoint-GUID: Yijp_AWT6tzwOtSLybGJbVPGYVge3z23
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1095,Hydra:6.0.680,FMLib:17.12.68.34
 definitions=2025-04-07_04,2025-04-03_03,2024-11-22_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 adultscore=0 impostorscore=0
 mlxscore=0 priorityscore=1501 phishscore=0 mlxlogscore=935 malwarescore=0
 clxscore=1015 suspectscore=0 spamscore=0 bulkscore=0 lowpriorityscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.19.0-2502280000
 definitions=main-2504070104
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="GG9/qRMT";       spf=pass
 (google.com: domain of agordeev@linux.ibm.com designates 148.163.156.1 as
 permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;       dmarc=pass
 (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
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

The lazy MMU batching may be only be entered and left under the
protection of the page table locks for all page tables which may
be modified. Yet, there were cases arch_enter_lazy_mmu_mode()
was called without the locks taken, e.g. commit b9ef323ea168
("powerpc/64s: Disable preemption in hash lazy mmu mode").

Make default arch_enter|leave|flush_lazy_mmu_mode() callbacks
complain at least in case the preemption is enabled to detect
wrong contexts.

Most platforms do not implement the callbacks, so to aovid a
performance impact allow the complaint when CONFIG_DEBUG_VM
option is enabled only.

Signed-off-by: Alexander Gordeev <agordeev@linux.ibm.com>
---
 include/linux/pgtable.h | 15 ++++++++++++---
 1 file changed, 12 insertions(+), 3 deletions(-)

diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
index e2b705c14945..959590bb66da 100644
--- a/include/linux/pgtable.h
+++ b/include/linux/pgtable.h
@@ -232,9 +232,18 @@ static inline int pmd_dirty(pmd_t pmd)
  * and the mode cannot be used in interrupt context.
  */
 #ifndef __HAVE_ARCH_ENTER_LAZY_MMU_MODE
-#define arch_enter_lazy_mmu_mode()	do {} while (0)
-#define arch_leave_lazy_mmu_mode()	do {} while (0)
-#define arch_flush_lazy_mmu_mode()	do {} while (0)
+static inline void arch_enter_lazy_mmu_mode(void)
+{
+	VM_WARN_ON(preemptible());
+}
+static inline void arch_leave_lazy_mmu_mode(void)
+{
+	VM_WARN_ON(preemptible());
+}
+static inline void arch_flush_lazy_mmu_mode(void)
+{
+	VM_WARN_ON(preemptible());
+}
 #endif
 
 #ifndef pte_batch_hint
-- 
2.45.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5204eaec309f454efcb5a799c9e0ed9da1dff971.1744037648.git.agordeev%40linux.ibm.com.
