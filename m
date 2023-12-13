Return-Path: <kasan-dev+bncBCM3H26GVIOBBIUA5GVQMGQEONZARZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C563812318
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 00:37:08 +0100 (CET)
Received: by mail-oo1-xc38.google.com with SMTP id 006d021491bc7-58d76712504sf8456028eaf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 15:37:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702510627; cv=pass;
        d=google.com; s=arc-20160816;
        b=zi1vcSsI8cExHpGwGEjvN41tcNHEixQCTY2kuBbNQm2nRsT3LAuEtGbKKMLQ71Bt3i
         SrH/kFmShxi7fezF5VFAd0u08C0XrOfkbq6m4FSEW54lsyxY9JCdYSu4JE4lpF436BAK
         nCydzuMsvyBHuD9MmW42/XUWwU/gVYBtsnqlF/gk3K+i1SxVfo43Qe5vDLtrGsKU7XdB
         unV7qSwe/gmWz+WftYx5fAHqiUnIjCIEcz0MsKcw3ZrPNqM1nW3H7q/d8mOaVIiy2N4k
         YMVHSol3jxfFFHLlY7h6fBQ6S8NMsUzv0igT40VwPSi+6jRsUgXFTD0j22pcd7hhK7kv
         6fLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=VWQtZcc9pmPkTS+ewWclMJ2OLepNSFb5E3QimnVC2EI=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=t2wnnTAbjH4dg6rh0t4w/qzsmXe9rgfHIE8z5ndgBamB77RQ8C2sD3a5KGJhKvcWIU
         FDfomTIyH0p7VY5P8RTKPjIoGay2ti9CUYY+UJfEADlZB/XjZvr9QLpNQYAGtu0yYYp4
         6Vkpd+t/iUYmX1vBG2Ym4GyZGl00T53pr2PoIpP3CFbkvcZPY3ASVdOiHc3+kM7GN7s9
         e8jGP2WjUGomIMmxegggjaXa4ZZGI50bpSe3n1Bpalm2dpqQPkg0hNlf/t2fhYP9ObHC
         eMaP2y2/ut4C0QuH6UJdXBgkDRGc+VeGlUVEhl+eWj9UXzZ7ime/E0hjFw/lkWt+wa4y
         9otw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=KRFjrsCA;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702510627; x=1703115427; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VWQtZcc9pmPkTS+ewWclMJ2OLepNSFb5E3QimnVC2EI=;
        b=N9fQ1qvGX1dEeEhPU3fgzAOTME3qobv8dawA5s39D9/Yy8EDrSgoYecqPWQLH9IIej
         8Hrg8/472Dd3yaXF4qfXKyfNKePdT0Sg87XRcMVCzthoErtxKbqz0nDkPg4MaI7yIDPE
         PDKi/uUXd1GEANgU2r99lvE9e/0Je3ewEelDwK/yEt1kCSsZpeXIB66JqR4bjZxvE+gz
         u3ZzjwoUVNT9CGeEqFfocPwjBPZM+9KosmJ28DgrVjNlxXWp143D8qRdN9eKu+5c73ET
         qTXySPi1Ed+te8GH/mVRto9pfcpUwE1UHJ65+/g4WxBXvFF6YCqxLPWjRfU8jrMbs9tA
         qF8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702510627; x=1703115427;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=VWQtZcc9pmPkTS+ewWclMJ2OLepNSFb5E3QimnVC2EI=;
        b=Bgt1GygzlsJZ+OgIUACyVYrLDQ2/qKqcKOQnUw/MxoYmDyZcQCPnfN6V/0tSEI3r8w
         IRpLhcwrt5uuMfH+D3px9b4WWI/s7S4x4IRpzYJkgUbjaqqZIVVLDsu0mj0l71o1EJxY
         +cN52fO8afC88csQZ3ztHK12SCSZSOQFHR1K8cOo7Mx4v5JFccYz78V91sviPR/oHMB3
         fReh97ZgRyAVGgn+2bJeUR3896qGqURvP5XQkWIkW10LM9FlkHmjA2t7x6nJ9G7LmThh
         v8MARU4tC2XYXkaTbZ8tlNTGPDApcUQK6VRV7XmRY4a1K5QojM1+HLXMHs86azMR+AxQ
         kpYg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxCh1A7UthTW4FOp/uk4iWBuqDIFaomygVIi7vU0aJsR5S3w6Yb
	NWiOFmxxRuQzyir7UrSYtdk=
X-Google-Smtp-Source: AGHT+IEITu221L8E+d1lVcHhzVKkg9NTLxvvuWHw5wXyRQKwLAdGU/ErYwOnnwB4Kf+o4sOFBpKMRg==
X-Received: by 2002:a05:6820:294:b0:590:a09d:4e6b with SMTP id q20-20020a056820029400b00590a09d4e6bmr7681731ood.15.1702510626778;
        Wed, 13 Dec 2023 15:37:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:52ea:0:b0:677:f602:655f with SMTP id p10-20020ad452ea000000b00677f602655fls3490974qvu.0.-pod-prod-08-us;
 Wed, 13 Dec 2023 15:37:06 -0800 (PST)
X-Received: by 2002:a05:6122:2888:b0:4b2:c555:12f2 with SMTP id fl8-20020a056122288800b004b2c55512f2mr3690266vkb.17.1702510625884;
        Wed, 13 Dec 2023 15:37:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702510625; cv=none;
        d=google.com; s=arc-20160816;
        b=lhJDmo8FTm5XZbk3U8Eq3gRpYdMOq1ucUsptkbwKbOVRPGhWiIHQ93FDpdue7OmBMA
         MrBiz2r0uvGDX6ltPp4x2sLEBMvPL6i2upF8vyDFLDbWssniLZIcTxZ1LuZjhdnghmIn
         RwcDVtVH37eYrq7PO9u6hOQ1lIncuKgempuBUPZwc9kqDyGwENTmIAn7EyQVNjWygRlB
         UclVWmUlWDMLWkKPQWRa6Z4NKP73Iwt8RWhRzhYP7LXo7TAghtr5vJFZ8Milqvrzuwil
         KZ+pzacLDajP2c/PUA8p2/3I62BPfFIopvM4KAfo1in+AlwmnjJpZSISRGMNu7B5EuZ7
         mFiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ADVPDi6c9Y3U5XGJnmiIfqmOgMPyPThXfiimsaS0ZCE=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=tDrY8JCwC9TvPveVsG70uXUitOijZajt8NXaWKFLNj2pwrzVVO6v0BbENGhG8q60Jj
         GS3ap72VpAOz65Jx+k5B/iUhMA37pme7hb0/KQY2++8y6725FhqiQUkOuumMTxBnIjH3
         jxSO2p/6bomPBNN2PLONdGyIDuHjce1s0N8zu6fqDnLxvnHDPudIzJ7+iDZZHnaeyMd0
         VqFv/GkBPF/jzCxphJ5ly3FUjYDSIjy7t/s1uKi2daeDiH6mKa22Sdc5SZXv0pFqUG16
         eF9r66jjyhNZ10q5tPeNBa5FA3FO5LFpX41XWg7yumLfx2YP8g2rHf9jvy7F8OyeuhHu
         ew8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=KRFjrsCA;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id bq6-20020a056122230600b004abd0f58a5esi1650049vkb.2.2023.12.13.15.37.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 15:37:05 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353729.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDL8I7u012863;
	Wed, 13 Dec 2023 23:37:01 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyjg35xv4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:37:01 +0000
Received: from m0353729.ppops.net (m0353729.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BDNSfUs015104;
	Wed, 13 Dec 2023 23:37:00 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyjg35xug-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:37:00 +0000
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDNFEmR013937;
	Wed, 13 Dec 2023 23:36:59 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uw592c4ku-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:59 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BDNauMb45220346
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 13 Dec 2023 23:36:56 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 5792320040;
	Wed, 13 Dec 2023 23:36:56 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id E389920043;
	Wed, 13 Dec 2023 23:36:54 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.171.70.156])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 13 Dec 2023 23:36:54 +0000 (GMT)
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
Subject: [PATCH v3 30/34] s390/traps: Unpoison the kernel_stack_overflow()'s pt_regs
Date: Thu, 14 Dec 2023 00:24:50 +0100
Message-ID: <20231213233605.661251-31-iii@linux.ibm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20231213233605.661251-1-iii@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: J2H2Zg9Syo-ddfgReflDerX2XK4HaCUE
X-Proofpoint-GUID: jAIqILNw1A-DNGzWSjXXASmKCgL7b7sm
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-13_14,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015 impostorscore=0
 priorityscore=1501 suspectscore=0 spamscore=0 phishscore=0 bulkscore=0
 lowpriorityscore=0 mlxscore=0 mlxlogscore=999 adultscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2311290000
 definitions=main-2312130167
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=KRFjrsCA;       spf=pass (google.com:
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

This is normally done by the generic entry code, but the
kernel_stack_overflow() flow bypasses it.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/kernel/traps.c | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/arch/s390/kernel/traps.c b/arch/s390/kernel/traps.c
index 1d2aa448d103..f299b1203a20 100644
--- a/arch/s390/kernel/traps.c
+++ b/arch/s390/kernel/traps.c
@@ -27,6 +27,7 @@
 #include <linux/uaccess.h>
 #include <linux/cpu.h>
 #include <linux/entry-common.h>
+#include <linux/kmsan.h>
 #include <asm/asm-extable.h>
 #include <asm/fpu/api.h>
 #include <asm/vtime.h>
@@ -260,6 +261,11 @@ static void monitor_event_exception(struct pt_regs *regs)
 
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
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231213233605.661251-31-iii%40linux.ibm.com.
