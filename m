Return-Path: <kasan-dev+bncBCM3H26GVIOBBHGS6SVAMGQENUCY25Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 001347F38AC
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 23:03:09 +0100 (CET)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-35b069d2809sf23138945ab.0
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 14:03:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700604189; cv=pass;
        d=google.com; s=arc-20160816;
        b=pdMYRH/yxYcFGjPq7pzWOQaoJ3K93Cs6aYT8Iu1B+R1wSQoRnrh79bvSg7VFQnRXMp
         Ii+nQu3aXoiAdmWd72sNptKwbqTQcomqftA8vJrOfp3Pw2yGDVwTnn1zABEWCTkgL7+5
         6oYZhXo5UOi271pLxKgI1gjdihQEfYmDqrDlVc+trtoX2sJKC3i6UeWqd7v6PmhWc8xy
         vnvcsHEj8oOCyg2g6zKQqJljOpRsDYen57kgmdd9JbeDXIjnk/AkAK2WpTBABcHUsH3q
         +ELaAE+vb5LQW/Z27XUpdlVmawT3JZsyHB2LU73K7L6apZFJuFW/NoQzAtiLUuX0Yufv
         4avQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=oFDDq+tPhFfWCjZ7m9b6kpcnzCLoa/h5YbUMrGkmCRs=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=k6WjseRunMnUEr9UEC+aHGyG5q1w9IzKkPTeb+kMxBzy3Mnwl11sELTkSXe1oueF6W
         JWcQH4zry9V4dVKW+VP4Crvel7RPZX/NfEXT4wCN6rSHPfCt0e82f4vtor/XMVGwqAEI
         hMYYJOrmfuHDJCzf76HjCk54hgMrKkU1kWV1Ls/KNs4GRC7n7lMiDRB5qzvhBo9jmw/X
         TQft4WZqH5E/P4dofAguie56G+X/W3fJRCkQtYHxKK/4MD8Pahes0i4zh2m1rp8xkoUR
         e6SCcX9/SebgR1zRVLn8YsF2kE3WiXTutFzJY0PHQhFfDSFbTze0eP9xElFfHO/Nu77U
         q90Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="USgb/cGu";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700604189; x=1701208989; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=oFDDq+tPhFfWCjZ7m9b6kpcnzCLoa/h5YbUMrGkmCRs=;
        b=q3hZJAa0MmvnRyBBHx7jfQMTtzQ0kgUydfhKv+18pOI1zWKC6J/NISgUJGcDBKcaIl
         wVxD7se6lSQsnbyZMQGNuCPB17H5Mo/w3Kzm46y0wBQcXPE06kAR+xZrAN0OAESZQHd2
         Inv1IBLDQCQ3/LoQOShYVGbcEcWkF1C/H3fhY0Za5FMJDrhsUj3VC9vLwO9dQVTZ1TRT
         5otc2NLvv582rp4Kh851SBSJTNZdSZKGqdFpp38tnVEt7ceZ4sm1tgEKfeDdRSz/yo27
         PSEbx7KUqMr16rgkLlBkkSPoxaK1tIU5ZwD2tb0eg/umotRA5P0ULlbOLr62760lJML4
         NIhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700604189; x=1701208989;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=oFDDq+tPhFfWCjZ7m9b6kpcnzCLoa/h5YbUMrGkmCRs=;
        b=AocaSugAJQ1lzYF/NEG883ZA+o9EdT/Zpr4tZdcmJjitMOntz/ILl4Vr89cmyxKYMq
         zfxxsA/ABQBnqTUGwm9SgqeXgVWhRuqHri9MusRnH83+afSnNx4dsPFXundQLVswqQSV
         3OMCvlsHMpffcIb5KCsr981jwQVoBjCL7jNX6x4C8CVki+EdiKqQ35e1qX7fkDkwTql1
         ZdL6/pGgwZvunTPLAomDBa6oL4MEbof08U38sfTlaVyQiiXS80t7p1wnRLIZ5KJ4K3kB
         IkjTf4TmZgyIF5le/U6m+24y7t/Ig1B12TyBmsAYAAkbYQmDcoWZ8Ay5pxtdgamDBJ4J
         JCMQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw/2ZB7skHe2r52E6d1Lpz6PL+8QHpCtLG8l0BhGpT1+XQwyitj
	z76CL580lVs2L2ZzocEPka8=
X-Google-Smtp-Source: AGHT+IHtaVZNF44Y09CRMwfgzerjMlh6XEvIfVXI+6O7nwC5NyV6mAQoTkL9vEGJLYNEdHxgZkCSaA==
X-Received: by 2002:a92:b04:0:b0:35b:4731:15f3 with SMTP id b4-20020a920b04000000b0035b473115f3mr330170ilf.10.1700604188872;
        Tue, 21 Nov 2023 14:03:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:339c:b0:359:6bf2:7ab6 with SMTP id
 bn28-20020a056e02339c00b003596bf27ab6ls3792724ilb.2.-pod-prod-09-us; Tue, 21
 Nov 2023 14:03:08 -0800 (PST)
X-Received: by 2002:a92:a305:0:b0:35b:1134:336d with SMTP id a5-20020a92a305000000b0035b1134336dmr301791ili.7.1700604188241;
        Tue, 21 Nov 2023 14:03:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700604188; cv=none;
        d=google.com; s=arc-20160816;
        b=FAWfu5Bos57PK0OTCbBwID6gDCJ6eV6T5fQhA4U3jt9aXn6AKYsA7uOHiPDIoyLOCy
         TyCHgfXbcNCcTkNOS6Bm7Tvl0wM6NOzxH14AKFzTquMfBwksuOA3TrYifeCfup+sR3B1
         UySwvS7bu1vqnPUKWAlOpbI+t4pEyLbigzeQokVFA+U2BkE/XA69nvEx6SSlVZcwAubO
         ZxzXrEoH7ZQ9cJdhf988Sj75FGNslkmXr/KB1njM7RTO4U0OU2Dv4wMaeUFFJGkKtS3p
         LjuDQSVRanIKG/E1AY3+X5Sp+kklWCxNdCiZXqU9ei2pBV5ch6WZWTbVaiPdw0ACsXuH
         +etQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=6pHSy6ITOBZodEIKnOLq18weO5ojGJDLtwC8jf5C8h0=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=oYiVAUmcpCVRo0DU1mXmipWf15JJN+2RsWPi44O5jBvLJT/CASk1Xzy2r6gfLwJTJe
         fAqyRoNrmHZxj6+2gqbcvd002g9YG5uNeSzlK6/WwaLinSH0nfy9Fv+hMlLwdJiDEf3J
         Txnqs3skVvcF16Jwy0y1TQcik2xdvFl8BTAfPI9yqPCc9kEarYPnJDTB1cUx8txmMv8J
         5okRhTI/HplZ/ONJzFeSFx8RzFWHMrLbdH735/u+t4FWjcBNS6iJgizVJWrR+DTYeygt
         QWBQpcR8u+aMbtIYbhbgGJNLCK3dQXoBgGnFsMsuei99B0I6oWZRfjG3UVOa5BEc5xUx
         DQ1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="USgb/cGu";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id g14-20020a05663816ce00b00437bda7a9c2si748440jat.2.2023.11.21.14.03.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Nov 2023 14:03:08 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353725.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALJ7UrE028514;
	Tue, 21 Nov 2023 22:03:04 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh11we7cn-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:03:03 +0000
Received: from m0353725.ppops.net (m0353725.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3ALLeZah017347;
	Tue, 21 Nov 2023 22:03:03 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh11we7cd-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:03:03 +0000
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLnVaJ010626;
	Tue, 21 Nov 2023 22:03:02 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uf93kujvn-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:03:02 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3ALM2xbE50331948
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 21 Nov 2023 22:02:59 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 0D40F20063;
	Tue, 21 Nov 2023 22:02:59 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 96C3220067;
	Tue, 21 Nov 2023 22:02:57 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.23.98])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Tue, 21 Nov 2023 22:02:57 +0000 (GMT)
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
Subject: [PATCH v2 29/33] s390/traps: Unpoison the kernel_stack_overflow()'s pt_regs
Date: Tue, 21 Nov 2023 23:01:23 +0100
Message-ID: <20231121220155.1217090-30-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231121220155.1217090-1-iii@linux.ibm.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: urf4wyq_YMj9bTfGVt1cQOZ1POJmOTf-
X-Proofpoint-ORIG-GUID: 3zsdaRQNzKCdIMz7-it2_V5FFdGTniq-
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-21_12,2023-11-21_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 spamscore=0
 lowpriorityscore=0 bulkscore=0 impostorscore=0 suspectscore=0 adultscore=0
 malwarescore=0 priorityscore=1501 phishscore=0 clxscore=1015
 mlxlogscore=999 mlxscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311060000 definitions=main-2311210172
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="USgb/cGu";       spf=pass
 (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as
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
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231121220155.1217090-30-iii%40linux.ibm.com.
