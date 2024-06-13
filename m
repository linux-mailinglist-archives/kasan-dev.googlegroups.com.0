Return-Path: <kasan-dev+bncBCM3H26GVIOBBUVFVSZQMGQE6JW3ONI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 835AB9076F0
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 17:40:03 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-3748f11c647sf319305ab.0
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 08:40:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718293202; cv=pass;
        d=google.com; s=arc-20160816;
        b=Lsrqjc8syUIk8wxU9jLcAYqIX0tCtO0+LSlp0IzblZzyaiTDqprIw3uZdRmWT6g96h
         PJhqC6jtWyYea5kzGyUNu3SP+Nr7MaoRDnMoe3D94DbpF6gouzN6oMUz+Yd2VhA06orp
         2JIKQePFy0C9/j2y7y7XOIpXcpqMIrmsXtwDr342jje7ERIodMjjiUde6ipgfAauyCSb
         WgytdaRncgTIhUg8vmTijNFQM5mEnib9WBj3Iby4Op8iICNCuEgBF6LxSwb8lNkG+jL2
         m/mJMoekylBlzz74cKdRkbPlRf23cI5aVf5mTEXXoz+apONHA42Ush1bCw/Gld4h+I7q
         ENGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=t+YNEDs1zOSBPOi/cCr+PREZpaDDVsBgzCRVbn7i/nQ=;
        fh=AbvV4sWmynPc1GeAeT2KNGLZ/Q2NBUf4y3PQIUik8FQ=;
        b=DVvbMRXU35tiWIGRQJp+UQrHYuoL/JIGnyjEoSR+efgwaFhTKPVGbSu17+SNUuV7Zt
         bj/047T97cVCHh6RFyGQd4jNgomegVWDDShHfSZt8SU8++L69jIw88DunxGP9X1fLqHg
         DvZ8LZLQfuWZUh9xYhwAjbYVbiyTcycbaYy/f6oMXFSfOKebeXVKD/G5OovewTg9jH0e
         hM+N32npG7CnvcLQtuBR1UdOnrBGu2tqjZuQdH7XX1nrp08Q3l0chDWubRFqaJST3cuP
         4muJZQr8vv/YCsN5zdI8/1UpzWion0dRc6HgJPBsSvhZhu27nq+sieTRFlCT2CYr97Be
         iqog==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=oNvZmbF4;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718293202; x=1718898002; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=t+YNEDs1zOSBPOi/cCr+PREZpaDDVsBgzCRVbn7i/nQ=;
        b=JMUB5+IHkSzD/UvouZctIsBtQWFM9s2wao1gPbwq02cDzKoXbe5xjnp/12u1/FCX8K
         Xz/gM5Xws1qHCOAugRxehvZ1cDcgI2MM1SIhnzK3THOcGfNj27vA1w/+WeuV/2qst6+6
         mDF0Av9hL51G/e64hNQ3oK2YcrBs98TdyKXTaCaWkOGFmlx6APjkSW1AWrb6TQLWIc0z
         n47fvca0YRqlpKA//FZKHrRe8pFWpcdIMhYoF0yr5oAeiXBxinqnYO6wDMMTgpmsv9pf
         YdjOZk8N8XGV+z5K6z75An8ctPUdCCSJ24sqf821QIzBKlZbKk0LU1P43jCizAwX++fk
         1bOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718293202; x=1718898002;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=t+YNEDs1zOSBPOi/cCr+PREZpaDDVsBgzCRVbn7i/nQ=;
        b=oFqlf9YxhNWsFFIW+LJ2RyV8lhcK53Ru3tvZHIVIbAji8+qYZTX6qOx0MOxQNXNYPl
         6qHO80P5ES2FkS1+LiyCI6F6370WlmJesSGlXbzI04fI9RSjlhWlx2EYc44y0n1Yaqnl
         T/ZsxWw+ZQ5ttCN6uQPCXFegNI6asMnX7ZGoAVSOUmujNsI9t826TjQbD308aeX6W1lC
         N5pJ1JoCpc3UJbspbheS14ipRiJk09whHUR9Ow58MUMY174/0UB4/7TAOPzYcU2u1rdW
         Wz53oZgrADCbC9vjI6aGNotDukUpVq9ZO28Pqiye7uKoKXpeBrV+YL9nmFSE/Kru863t
         +TtQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXKNV6iFGmTXZ/Oq8tpHJ7lW4zkkFMyhVsB9MAYmzrk3h9cWqI9QHgkgZd0rZW05G7zYaq2kRJlsN8h1wGvbP11IVy7pdXhmw==
X-Gm-Message-State: AOJu0Yx2iR0duV3XcYvpbK7htZ7XRKR+G/ufg/MkH3NGr1BPpYRjNAc+
	V3SRoLl2aREX4b8jYOyOazmZOKh2giwF9hEsDyf7fAEoD0BWMArf
X-Google-Smtp-Source: AGHT+IEMzlBWbaBQpoYKDYCfx9i/HjbheznUc+sf1FEyWSPYEPlY96BQvgqTIQxcQ5ajs+7nxeia9w==
X-Received: by 2002:a05:6e02:308c:b0:375:cd17:219f with SMTP id e9e14a558f8ab-375d73c851bmr2459205ab.7.1718293202315;
        Thu, 13 Jun 2024 08:40:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:718f:b0:254:6df2:beae with SMTP id
 586e51a60fabf-2552b6aac4cls1146288fac.0.-pod-prod-04-us; Thu, 13 Jun 2024
 08:40:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU3dttS8CVjYxbeI0M7j8t/IfzayHLpUdpKu2qQUHUoqwNWJCEc+J5h1NTAHlRdK5m9LitHicnGGqznSAvTlBZx2VyDuXcZNyMOyA==
X-Received: by 2002:a05:6870:b489:b0:24f:ee90:4556 with SMTP id 586e51a60fabf-25514771885mr5955931fac.0.1718293201441;
        Thu, 13 Jun 2024 08:40:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718293201; cv=none;
        d=google.com; s=arc-20160816;
        b=wEo8gU0ADj10oMiyk5knLoVNCEUgWDuR5bOYizDa1iaBMaioCRHlzdC0JGDX8OLIGd
         Z8J3gq9gAw1fcuKDPVTaEmvZdjfUpprZb/2Duuryt9kXLKznk3k44CzEzkhLwZjSosJK
         rOwlTWCzl783y8pfZuYtM+1S1o3+T2hOe8djuj6hKhVwNCQ7oyi/aXei/s0q7V9ekNtU
         C8JvO9CkkrVKN0nZU+0yTg/GafkXji29Hl2yj/P9Ke0XS8V8zYbi8bWYlfLQZDX+CWyC
         qo0eoy6E9N08tIRPD0piefkjO4wM2Pu4qvqp4RCuzUQ03KdxGZQcXWwEOLgLUXPdJNaW
         /foQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=+zoFJVlk37wQaOMfwbNCgteXo249s6T95ikp3xQJB1k=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=OvTG+JbhJMTt0UxMKP51O1Pl643VXqYo5ICnpk1emKL8nKMYwSmE8112Rv6AgpffCW
         K3dH02VuJytBKJzuintIqgUxV+AzO0sAB3GtPVyHeyDDeROB/3GWyAH/lMxk+pi4kQUa
         LEs2LWXttyUHopf7bP2oFB9DTS7/k72URc2EvRKRhCoc7aWY6xWtYon5ZDlMKlY30fR1
         CpEmn/YVjQXfBeg1Kihps8ohcLSNaG66Y+RWR+qWSTZSBeF2F/XT7DrKMSeB2wD+cISb
         Mf24eXw0/rfnzJN/jRgIi38UEG5SV++/NDhe4VoNO93P1C9Am5oPmeevft7kEs9hzjhQ
         B5Lw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=oNvZmbF4;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2574b45f734si84741fac.3.2024.06.13.08.40.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 08:40:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353727.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45DFL9hI017855;
	Thu, 13 Jun 2024 15:39:56 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqy258xxr-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:56 +0000 (GMT)
Received: from m0353727.ppops.net (m0353727.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45DFdt94021165;
	Thu, 13 Jun 2024 15:39:55 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqy258xxn-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:55 +0000 (GMT)
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45DFBb7N020069;
	Thu, 13 Jun 2024 15:39:54 GMT
Received: from smtprelay07.fra02v.mail.ibm.com ([9.218.2.229])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yn34nh0d1-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:54 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay07.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45DFdmkh52494780
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 13 Jun 2024 15:39:50 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 4E2152006C;
	Thu, 13 Jun 2024 15:39:48 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id CF64920065;
	Thu, 13 Jun 2024 15:39:47 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 13 Jun 2024 15:39:47 +0000 (GMT)
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
Subject: [PATCH v4 28/35] s390/irqflags: Do not instrument arch_local_irq_*() with KMSAN
Date: Thu, 13 Jun 2024 17:34:30 +0200
Message-ID: <20240613153924.961511-29-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240613153924.961511-1-iii@linux.ibm.com>
References: <20240613153924.961511-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: 3YJV7_fgCmflF5r_am0hLna8GcLzFF1F
X-Proofpoint-GUID: _271Y5yjDhi0fa7CjP4Omqz2uyCbtCUn
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-13_09,2024-06-13_02,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 phishscore=0 spamscore=0
 suspectscore=0 mlxscore=0 malwarescore=0 adultscore=0 impostorscore=0
 mlxlogscore=999 lowpriorityscore=0 bulkscore=0 priorityscore=1501
 clxscore=1015 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406130112
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=oNvZmbF4;       spf=pass (google.com:
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

Lockdep generates the following false positives with KMSAN on s390x:

[    6.063666] DEBUG_LOCKS_WARN_ON(lockdep_hardirqs_enabled())
[         ...]
[    6.577050] Call Trace:
[    6.619637]  [<000000000690d2de>] check_flags+0x1fe/0x210
[    6.665411] ([<000000000690d2da>] check_flags+0x1fa/0x210)
[    6.707478]  [<00000000006cec1a>] lock_acquire+0x2ca/0xce0
[    6.749959]  [<00000000069820ea>] _raw_spin_lock_irqsave+0xea/0x190
[    6.794912]  [<00000000041fc988>] __stack_depot_save+0x218/0x5b0
[    6.838420]  [<000000000197affe>] __msan_poison_alloca+0xfe/0x1a0
[    6.882985]  [<0000000007c5827c>] start_kernel+0x70c/0xd50
[    6.927454]  [<0000000000100036>] startup_continue+0x36/0x40

Between trace_hardirqs_on() and `stosm __mask, 3` lockdep thinks that
interrupts are on, but on the CPU they are still off. KMSAN
instrumentation takes spinlocks, giving lockdep a chance to see and
complain about this discrepancy.

KMSAN instrumentation is inserted in order to poison the __mask
variable. Disable instrumentation in the respective functions. They are
very small and it's easy to see that no important metadata updates are
lost because of this.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/include/asm/irqflags.h | 17 ++++++++++++++---
 drivers/s390/char/sclp.c         |  2 +-
 2 files changed, 15 insertions(+), 4 deletions(-)

diff --git a/arch/s390/include/asm/irqflags.h b/arch/s390/include/asm/irqflags.h
index 02427b205c11..bcab456dfb80 100644
--- a/arch/s390/include/asm/irqflags.h
+++ b/arch/s390/include/asm/irqflags.h
@@ -37,12 +37,18 @@ static __always_inline void __arch_local_irq_ssm(unsigned long flags)
 	asm volatile("ssm   %0" : : "Q" (flags) : "memory");
 }
 
-static __always_inline unsigned long arch_local_save_flags(void)
+#ifdef CONFIG_KMSAN
+#define arch_local_irq_attributes noinline notrace __no_sanitize_memory __maybe_unused
+#else
+#define arch_local_irq_attributes __always_inline
+#endif
+
+static arch_local_irq_attributes unsigned long arch_local_save_flags(void)
 {
 	return __arch_local_irq_stnsm(0xff);
 }
 
-static __always_inline unsigned long arch_local_irq_save(void)
+static arch_local_irq_attributes unsigned long arch_local_irq_save(void)
 {
 	return __arch_local_irq_stnsm(0xfc);
 }
@@ -52,7 +58,12 @@ static __always_inline void arch_local_irq_disable(void)
 	arch_local_irq_save();
 }
 
-static __always_inline void arch_local_irq_enable(void)
+static arch_local_irq_attributes void arch_local_irq_enable_external(void)
+{
+	__arch_local_irq_stosm(0x01);
+}
+
+static arch_local_irq_attributes void arch_local_irq_enable(void)
 {
 	__arch_local_irq_stosm(0x03);
 }
diff --git a/drivers/s390/char/sclp.c b/drivers/s390/char/sclp.c
index d53ee34d398f..fb1d9949adca 100644
--- a/drivers/s390/char/sclp.c
+++ b/drivers/s390/char/sclp.c
@@ -736,7 +736,7 @@ sclp_sync_wait(void)
 	cr0_sync.val = cr0.val & ~CR0_IRQ_SUBCLASS_MASK;
 	cr0_sync.val |= 1UL << (63 - 54);
 	local_ctl_load(0, &cr0_sync);
-	__arch_local_irq_stosm(0x01);
+	arch_local_irq_enable_external();
 	/* Loop until driver state indicates finished request */
 	while (sclp_running_state != sclp_running_state_idle) {
 		/* Check for expired request timer */
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240613153924.961511-29-iii%40linux.ibm.com.
