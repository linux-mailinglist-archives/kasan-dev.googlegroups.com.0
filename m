Return-Path: <kasan-dev+bncBCM3H26GVIOBBUNFVSZQMGQEL26RZCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id E88769076EF
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 17:40:02 +0200 (CEST)
Received: by mail-pf1-x43a.google.com with SMTP id d2e1a72fcca58-70426999383sf918425b3a.0
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 08:40:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718293201; cv=pass;
        d=google.com; s=arc-20160816;
        b=ybLGl7dxFjstl1bWyOf9PwjnjMrPXvNVVqTvna9hPe8vnYbAvC+G1bjW/2cxKAjD6d
         cLy64agiHaa4GoRHoyV694e0pRW56530tZf9yB0dcsl3BLP6aUjUhBQWZ/wzhVCqZq/r
         /zM+Iz04of1DB7NkFNKCV2rTv/iD0Wt5U5Hg7+JJF+Ea6ZMN8cT3poChzSIGlZmUYjVf
         xSekWDGIhfqOO8P2jkbRXTmroIKcLUDq7L8+6qc6A7LzqQ4UMFugIHhNt1/t+C52tqYG
         B9nput/AIwRxfckHCQJQAgUdIFRVzSRfRZJBpwuaoG0DRC2B2tlcrP2CM9Gd6HmmveZL
         UAHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=gUm6UCaHunqvItjPLClHzJFsowZVho0FfEWyDytdScs=;
        fh=jZVqOS0L+Bs0c5v6EVH7v4R4VxtqGMC4WCOYk4aEh5A=;
        b=jrW6b0ojX3aU23WBdzOVFLAFN5XNPzE+L4+PtyiznD0hOyxKlvurd+DpsVJgKmk0xL
         xik5do1S7VSpfnnHqSbFdgRF1hQ8W2Q85t6dW308Jy5UhVMvsCkzg+7/Q6aYC3FrDxP0
         sP/gepIaSPjTSoMPwcZ/WxviJ1LyapnCoh2v72rmbQvPJS95pplkrXPVrBA6AspPHlE7
         f/CghFIiBp4KP+tzE03cFOFfa8A7reGNvp3w9TUE3c5+b5TeM0izqwKGaDMWd9+cEyqj
         lbtW4q5nt1xGB8WiraY1IIdricVuGngXQLpTxFCtEBIkBjji9XrAK8ph1jvqy3QDqk2x
         KpHw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=kZUSIkqS;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718293201; x=1718898001; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gUm6UCaHunqvItjPLClHzJFsowZVho0FfEWyDytdScs=;
        b=VAaYrlqu8tQsd2pezd+NuBTnDmV3e09PRkdqS4xwAfA1JBJCiQmIUqzkreVPFuHEfj
         l5mn+qbChSFIHGXukP4BQBCz+fBtTBt9gESHfyaMzdzUpc00pdOKu9tWKOTWHAHqi3eY
         vK5OXKtVuSD7hsZSroc4HXre0vQNUCBIrOGG+xJoUheT2+eG/SOZJVyH04NOfqeCO5np
         Y6f6FCZEmkf7IN3vBPzDv8PCSPm2Yb8pVcaGDDnbsN+CO/mN1H76CpLmRIBnNwJNIfxO
         EGkAIJmoDYbN2X5Q8SDoziE5M7HTEFVchdntcChoqjOTEVRioV50CSwedayHEbwq3FVI
         yFNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718293201; x=1718898001;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gUm6UCaHunqvItjPLClHzJFsowZVho0FfEWyDytdScs=;
        b=cDCJk3vogizBra9DyZBY9oUawoihL1wMKcVlXkWJqRvAnlT0ObHCM7JqK4o8PdrDe/
         yoiKQ7DQLxkl5ChR5bC8RgDg2fcIAmPmTgX1sr/H4SAQ9xWLrBxBDFdgprrZLumlbrbQ
         EcFWOniB4W+BGWjp3EeUK0h3igc2cxvL/XHacoBCdiOwMzrGjJjmnl4hyjejISI1S6P2
         L9fJzyoRU3fS4Eklwfq4/B/WPS6QHxnFEwQN/aeLwVsW4HnjhLpuYPti12OREMPiUFgG
         5qyNgokZVQULNGRJSvU96yQ79sXw+jwLwWKGsgGd+nBkixEz5CEX6teh6D4GxorIuZl3
         /DPw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXfCJXG5/LeJaVF3S0ekjilBkRlhimfLCo8XOrlmU/Z3OhBH2emIitEwG8HdnZJUj3i//Th/5Q+iXfArK6oiP+Qt6ebKWeJvg==
X-Gm-Message-State: AOJu0Yz/C9LkBY38YqyB5zie7HK9SiMHCyAGEqwwwC83oj1MP4LQLoaZ
	cvQBJOwZMiwchSPI+r0kC2nuH5zb6DMXDXpIUjDUseDSXnK0C9VR
X-Google-Smtp-Source: AGHT+IHm3nQjaccMxkYGO1N6FA/aiZ5w0lrPvdhgwB3yvOFWW8t2JLpxP23XlG3Kw5NTTMoz7GHeZg==
X-Received: by 2002:a05:6a20:3949:b0:1b6:4151:6158 with SMTP id adf61e73a8af0-1bae802b510mr217238637.47.1718293201495;
        Thu, 13 Jun 2024 08:40:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e80a:b0:1e2:306e:bcec with SMTP id
 d9443c01a7336-1f84d41d0c4ls9902665ad.0.-pod-prod-03-us; Thu, 13 Jun 2024
 08:40:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWRWZydc+GpEPCSb8iv7GmL+7BmpwE2g2twlWcJNU9HysWolPdX+cfm2mSKejs4c8ZmhOBe4/9WAU53vLLYNbkGNU1WYTbbZXA8Yw==
X-Received: by 2002:a17:903:1249:b0:1f7:1c77:b74f with SMTP id d9443c01a7336-1f8627c7cbfmr305325ad.34.1718293200262;
        Thu, 13 Jun 2024 08:40:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718293200; cv=none;
        d=google.com; s=arc-20160816;
        b=voqprNRcqb3OFjW/LbWj2dSNDeJuEd/z3pWOE/uE2ZTUg2bFVlvX0U5rsNIH7l4NmM
         4WxFUGl9AKTcNqs0q99BgRBwTTZRIx/OM6eRZIpDCRdGXUmWfLqr2LnbXQyWHn0v2ZaU
         KG8hs/I2EGruF7uYCoyCsDFpxhbbdXe9lpspoSLNaI3myywyEvqDZptE9p42SXI5C/FJ
         wI+tCJO5ej0aXENlt81dk7K3Q5dLVGFu2WB+WXO+MVQ6i6nk7thUcGcY36T2ZYrJtb9y
         Yn/QO2c5iZivqVH1etK6ANjfh8mJacz3Z+BHbCndIVFcPVTCAhXa+PZL59ODcWLDobei
         /3Fw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=aLe/3XBqno9Ykh6K8Gazkn5dKq5eSwzJESHfR5NZsd4=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=TaalEEyHl9ziKzUUM+v289NxBRzJqtQ4PQ7DDQhOP7gE+52hXKWy20ZRUuOuI5R1Ts
         AxJ4tkIfwRjajBnKxYl8mQ/ugVabKbGsKrjAWvbkmP7JV3UPCiExF702SC892Ry8hyos
         GORaPzb11iaW8ihLhg6CAsTfdXCeVTn/QtJ2T4jcUFXA1R3O81xt/4FNTiKwRq6CIlRr
         MRs9p5CYwsvaxYGv4ycPZhoKmB611G0LygsI3JIBgf2tijLBH0p+S6JzirwiAMqi0yKT
         2WttqoWfoJHnubOn+PbKyI5JswFaLFTBHpJJS709jK8lSaCbb5WSdiDvvR27jz+Ldm/D
         AePw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=kZUSIkqS;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1f855ebd9d2si576485ad.9.2024.06.13.08.40.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 08:40:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353724.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45DE7HXP011927;
	Thu, 13 Jun 2024 15:39:57 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yr28g8bve-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:57 +0000 (GMT)
Received: from m0353724.ppops.net (m0353724.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45DFdu25032626;
	Thu, 13 Jun 2024 15:39:56 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yr28g8bvb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:56 +0000 (GMT)
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45DEIs5m008716;
	Thu, 13 Jun 2024 15:39:55 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yn4b3rk1t-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:55 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45DFdo3A44302740
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 13 Jun 2024 15:39:52 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id EB6C12004D;
	Thu, 13 Jun 2024 15:39:49 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 78B9120043;
	Thu, 13 Jun 2024 15:39:49 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 13 Jun 2024 15:39:49 +0000 (GMT)
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
Subject: [PATCH v4 31/35] s390/traps: Unpoison the kernel_stack_overflow()'s pt_regs
Date: Thu, 13 Jun 2024 17:34:33 +0200
Message-ID: <20240613153924.961511-32-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240613153924.961511-1-iii@linux.ibm.com>
References: <20240613153924.961511-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: qN5TvlINAwkoyVJTUb7mish1SpksN-h9
X-Proofpoint-ORIG-GUID: Bgo41_z9p3q4U6eGSVczp70jPlI-Yan7
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-13_09,2024-06-13_02,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0 bulkscore=0
 phishscore=0 clxscore=1015 suspectscore=0 priorityscore=1501
 malwarescore=0 lowpriorityscore=0 spamscore=0 mlxscore=0 mlxlogscore=999
 adultscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406130112
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=kZUSIkqS;       spf=pass (google.com:
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

This is normally done by the generic entry code, but the
kernel_stack_overflow() flow bypasses it.

Reviewed-by: Alexander Potapenko <glider@google.com>
Acked-by: Heiko Carstens <hca@linux.ibm.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/kernel/traps.c | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/arch/s390/kernel/traps.c b/arch/s390/kernel/traps.c
index 52578b5cecbd..dde69d2a64f0 100644
--- a/arch/s390/kernel/traps.c
+++ b/arch/s390/kernel/traps.c
@@ -27,6 +27,7 @@
 #include <linux/uaccess.h>
 #include <linux/cpu.h>
 #include <linux/entry-common.h>
+#include <linux/kmsan.h>
 #include <asm/asm-extable.h>
 #include <asm/vtime.h>
 #include <asm/fpu.h>
@@ -262,6 +263,11 @@ static void monitor_event_exception(struct pt_regs *regs)
 
 void kernel_stack_overflow(struct pt_regs *regs)
 {
+	/*
+	 * Normally regs are unpoisoned by the generic entry code, but
+	 * kernel_stack_overflow() is a rare case that is called bypassing it.
+	 */
+	kmsan_unpoison_entry_regs(regs);
 	bust_spinlocks(1);
 	printk("Kernel stack overflow.\n");
 	show_regs(regs);
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240613153924.961511-32-iii%40linux.ibm.com.
