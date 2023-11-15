Return-Path: <kasan-dev+bncBCM3H26GVIOBB6OW2SVAMGQE2CAV6FY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id BC8EF7ED239
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 21:35:06 +0100 (CET)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-670aa377deesf826496d6.3
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 12:35:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700080505; cv=pass;
        d=google.com; s=arc-20160816;
        b=x+PGlZZoDQy7VTEDxRMVAyOL/+HcdxWvm8J/lXl4qGb9ilLfBeDKwkUVYAj/NT04vG
         dIpcu/7b1e6VbwFOXKX+47Q4rDyqXGLQscKOUnW/AoMrRADuuooBjGf6CfOMadTEf3v8
         yz0Zul1aJ37dAmg50eBaG4EpLulvNcafS3YF/vY1Un6p580d6RhRPIZ/JYsdYwLpGC5C
         Gc5/GhWfdZZ99vR0KalLuIPCUwhqeaMI2yTprHfihG/1XLmX+HL9yqfk9ylN3E8D8JK7
         TxP9EW3kF6Oq+JCtdANIInpPjEN4pvKTljmHpcOyXvRxGbxRSotFPRXRhAoVF/z4QCGd
         Wf0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=BkzcO56u0VHYeCg8+rYjxLKwdRA5lfEEt5lcHNrLOXs=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=Q7bb8Ny45bfsbYk1YO8DV4pkUgol7pPBQp3dLq8yfAaGz3hjcKO5ndTPN2GedH6UhS
         gtHvdWAvZ0oO5Uq0PMSz48SowBVGMHII+Ct/Y6A/h0iD3+TWxPw3nL7E/QN1lKkqSm9y
         66U1QkOPpWZrP4cufQ8/1lQ9BDzIx+roua+PGSyuXucdl4bu6ljAxLIRbQ5aQ0JLqPm7
         a7hHB16EdGqclI42tibVcJZGZppG4ghkRpex+lKzeam9uvWA+gTYkJkcAFngvPalFKjU
         sTB/GCn3VfWNabbM6upBBk4TluBWXRmPPKsf6lvhQPm6SWs+a31MFi5L9Oi8c/lCF4Cm
         RwrA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=fX7J+qpY;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700080505; x=1700685305; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BkzcO56u0VHYeCg8+rYjxLKwdRA5lfEEt5lcHNrLOXs=;
        b=IL5dh++0Fa3nVOJO4c9HzSNIDIWbeiUL2LoLAqb1IXUGYRq2/xRyKVrVC6RU1aCK7O
         nXH7F6Hwwjz9WanRJ+ErFwXdRq9rKxTYZ2kFB0o9ZXrcJ+hgtiUXpZZtSdQDXBzt0hep
         4feiASKINZaF/i65b233Dj/V7cOQ7IFzPUU6I0nsaorBJ0sgrLOBeeJ8Et9z3qVvwYc5
         y/bLwwAuVk8Xdsg0DngzK29RKxAuHO/HV/51OcdY9Ihma5SmrsAlytCkeh9hfL03ijZh
         jAajfod7O5qACS2WBxlO847OBr8ObPOGVTENBfnx09B51OwYji8CAAp5lgk3wR3rQd94
         V8Uw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700080505; x=1700685305;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=BkzcO56u0VHYeCg8+rYjxLKwdRA5lfEEt5lcHNrLOXs=;
        b=fXpJ3XTCoSWpPDiVTEg5riKJuK+1v2s671iNHFr05CEH0FY5RwxNj5Zr395+ZaNrX0
         c5XV46kN87TwLBAykKEF2RIJVj8O1eq9yW8UhnF0slXho19FLSp09g4ePRlMvRCZGg85
         o3C07f7tPMaLmEQF7t8rXsWYMEEWoYxZpNbRIywifIebbDWNo0t7qHzqoMi6EK60ewne
         dSDA2fCGr284lrZ5kz4zRaLYoV0UtLO+tahHiyCeX1lBd681gAyqxCDukGa1aZag4idY
         Km27t6gNJJ3cnSKkJHBMFH3zq+irYKkNmtURfqoExJx4IftWRR21Z5ttwCH5fD5NM41F
         4sNQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzCn7pWug2WVeGIEk81SP6RfU5CfroQ5eluR9y5q3Nep0DV6YRi
	+aJ7nxnAhxm9VxRAP2vwdkg=
X-Google-Smtp-Source: AGHT+IH6ID5NTK3ZlwPiKK55vREaIM3U4/FTjeTFtE+YkSwS7xEBYswL79Cxk5rmwZVQMwGwqg+xOQ==
X-Received: by 2002:a05:6214:20c9:b0:66f:bbf7:dcbc with SMTP id 9-20020a05621420c900b0066fbbf7dcbcmr9120653qve.36.1700080505717;
        Wed, 15 Nov 2023 12:35:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:4429:0:b0:62f:e5ab:e5f4 with SMTP id e9-20020ad44429000000b0062fe5abe5f4ls170696qvt.0.-pod-prod-05-us;
 Wed, 15 Nov 2023 12:35:04 -0800 (PST)
X-Received: by 2002:a05:6122:3102:b0:4ab:f912:d000 with SMTP id cg2-20020a056122310200b004abf912d000mr13778948vkb.8.1700080504563;
        Wed, 15 Nov 2023 12:35:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700080504; cv=none;
        d=google.com; s=arc-20160816;
        b=ow2jbw8IUp6xpPYE7egRKswExKd0ME9LRtFgYtkbISKOiS+1OvWtFhqJWXv4H/Z6T2
         4ou6wVLHd05QKnlHqPRO8Ci0nbMPPA4Rdla6J39RFVtJGXxMaBta3dwtQ1YyfSlt1J7I
         PuIwXWFI1T+pfBFES1vQhe5p50qejpUGb4wgRc83iOy8FRtlAMhuwNUikfTfsvsHF4wW
         3/9Jjrkn9EHceFmCgZPQqhZgn+LvHzl2SCEz1Qj+IJMKoO4x7LmjdLzA97VvxHGeJ/5O
         gTjRvjM93ifNJTDQV1avqIRVCrxdmWQDLACHux+angwvtZmdzZqSQ9s7GIEsN7SQwKQQ
         wL/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=vyPRs3NEGlrSEI4OyP/kyugJK7kmBP/avTMvzRTf3tE=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=XlWY4dECK+A29U3upuFPng8HG7B5rw/vBleNBLlc5Ob1WjQbBI6enEC8hSMBfwBp7z
         jzXbh2F9NYA3Eo9LNt7dkWiJ0zEC9/+tu1xGS1Q9vcf/H+g1RwIMrreFcV3H9K1sIc3k
         Ae/IBIe2FsCDQfs61/Y8OzEVPs7nv9SJy1hBFPSa2zsv9CpvJOar+gqt7xpICM9vObk/
         6X/JMzr3fuzeve0N/jkjxkJ74u1quqriD/OQVaUX0WoSDrOj7Q31ptr4enuqogONMtYZ
         d/YJucwj1bc95mQyXrLZ+qeifgHud4kJHV9D8mVLZupgSpmZ7neGmf+sA/19g8a4GYRL
         gJKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=fX7J+qpY;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id s34-20020a056130022200b007a886d4333asi1301740uac.2.2023.11.15.12.35.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Nov 2023 12:35:04 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353723.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKFbGw004184;
	Wed, 15 Nov 2023 20:35:01 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4v30d0f-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:35:01 +0000
Received: from m0353723.ppops.net (m0353723.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3AFKQNNg002471;
	Wed, 15 Nov 2023 20:35:00 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4v30cyy-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:35:00 +0000
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKJ1Fm017525;
	Wed, 15 Nov 2023 20:34:59 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uamayj7es-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:59 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3AFKYucL4391432
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 15 Nov 2023 20:34:56 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A6F6520043;
	Wed, 15 Nov 2023 20:34:56 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 59DB820040;
	Wed, 15 Nov 2023 20:34:55 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.9.51])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 15 Nov 2023 20:34:55 +0000 (GMT)
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
Subject: [PATCH 28/32] s390/traps: Unpoison the kernel_stack_overflow()'s pt_regs
Date: Wed, 15 Nov 2023 21:31:00 +0100
Message-ID: <20231115203401.2495875-29-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231115203401.2495875-1-iii@linux.ibm.com>
References: <20231115203401.2495875-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: dnaNBt7krqikwNotd3HVlCqxFq8337Jy
X-Proofpoint-ORIG-GUID: 6zt5GNmg5wfDE8GufZyKD9mMXoFyxLx-
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-15_20,2023-11-15_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 spamscore=0 priorityscore=1501 bulkscore=0 phishscore=0 clxscore=1015
 malwarescore=0 mlxscore=0 adultscore=0 impostorscore=0 mlxlogscore=999
 suspectscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311060000 definitions=main-2311150163
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=fX7J+qpY;       spf=pass (google.com:
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

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/kernel/traps.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/arch/s390/kernel/traps.c b/arch/s390/kernel/traps.c
index 1d2aa448d103..dd7362806dbb 100644
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
@@ -260,6 +261,7 @@ static void monitor_event_exception(struct pt_regs *regs)
 
 void kernel_stack_overflow(struct pt_regs *regs)
 {
+	kmsan_unpoison_entry_regs(regs);
 	bust_spinlocks(1);
 	printk("Kernel stack overflow.\n");
 	show_regs(regs);
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231115203401.2495875-29-iii%40linux.ibm.com.
