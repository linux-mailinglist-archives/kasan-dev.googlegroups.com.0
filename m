Return-Path: <kasan-dev+bncBCM3H26GVIOBBHUA5GVQMGQEAZGOCRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3b.google.com (mail-vs1-xe3b.google.com [IPv6:2607:f8b0:4864:20::e3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 390F2812310
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 00:37:04 +0100 (CET)
Received: by mail-vs1-xe3b.google.com with SMTP id ada2fe7eead31-464752fbb15sf1846033137.2
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 15:37:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702510623; cv=pass;
        d=google.com; s=arc-20160816;
        b=uIgvFVlpgikbtw0oNN9KF7sr94toeReKePW4Y/BoAF7/Vv/VCj1WYYKMkfOD4VATHS
         Go+zLcDrV+p6VC2bzwm7bhJvyeTZ0RjCFNFS0V/1Lm0GO9TY2L5s0JLIQkaJb1HjRsQR
         C+epLXZ+G1O7vdjErMUkJ9XSBJ/Msithfo18MKF61iE1Oq/BqQHcvlSb0dXXa9IYeoup
         W5RlYSogtIIpsdM2cHG5wQ/8OPM7T1Gu8+wnOnqAwQykHBM9pPDWVPXEWvyreovPtRzD
         O7i7ztPD78i4mL/SxYf0G+ZkB6+oZxebNnF/5SPzZ5xQhM098zNDFBCyQZSH9e+0+Hx9
         dD+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=hgzLEDeuUx/e86iUhFV9DALM828MmNqIAX72Sh0rzQ0=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=FdQNb9PySny8BKCTPeg8L8lT2nEL+dG7SubMEhZHFsF76iBwfkdL+PinUubajlYzcC
         /26aHTDWXR48vYm6hNp0R8/ynKVBJGyRY093hJC13twvOELxks7FVCm4NbfroiusLuIA
         AqG30vc44VF4vtY0MR7BtU1qhuwA848XKtIjxyPDtD0FB6GEMpcChPGtlT6BfY1t36Hk
         WgULVyUkko6QcZpgAP8x498cg+S35zDOYoIFCsAC7nR2ZWeT/gJN9cL1RZLW0VSW3Nq6
         OPwAqs6TzrdOOwiDUkXB1hcLlT79QEDQUwq9pDVjuMV5QmjDuNlHhGxkgp8OSgjFEadM
         3Eww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=a+xMfSQN;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702510623; x=1703115423; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hgzLEDeuUx/e86iUhFV9DALM828MmNqIAX72Sh0rzQ0=;
        b=Ud17X41zzQfquh3VTa53P7JRwK0/OL75w1K68s6zMqsqQf70eQOWaajP/tc/MTpwU4
         VeucIfcD4AwW4aF3js9UuFNUq5Jd5It3uoH5zb5d/tQnVhgfERjKiORtMTT64cMxpjJ7
         g2CzPYpusCSD8DpJ7WNoOOPPogL2IRk1Ge3OkH2aLaXQhB16JdnKigho1i+WgZWKL7TY
         7ZnTW53vfb6ph5MZp5pZSBx2uw8br32zwvZIWVdp/m52J8t2kYcttESS25DyTV9tI6Tj
         hZOibdMK55tjjcCC8m8Q2+Sj5p68yBY+y7gDdFhlJit2CTzJRd7oly7f7MPMUuSTcOHQ
         mJaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702510623; x=1703115423;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=hgzLEDeuUx/e86iUhFV9DALM828MmNqIAX72Sh0rzQ0=;
        b=VN/tUvVGQlmbv9G8dpC+fw3SjItnpyw1GPdd/FWUKZzZWfQ+hMN5AdALmFIenW6b2X
         3BOoPQPqOxHIGbXcNNJnhcfLog7fxdcn/D9Hbmaco2d8nV8EDnmtAlNa6u9/RwS53EtV
         gqIqX4+ZoHn3mWTjONVx/ySl5Bsqo1lVaNPW7NmMtAT5MT0YV+405Jig/Xns8l6Ofcdp
         inDiBNE+pqG7cyvqSILrHXUEaoVyUUG7j5VDysLtEis5wvS3KPfg9cbrR8IzLrcSS+fh
         a2A4Hiw0K6aRLTcSRrOHa753YHeNDaZk/UYxPqjyPQMMigBNCOnUq8+i64yzJoNRqo3j
         va0Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxtJwg/UZOOnCkj1VI40froV3Q74KgKnjz8x23LX47Kbb/GgNPT
	MOatZMwMjcsfkuBPOcE2h/M=
X-Google-Smtp-Source: AGHT+IEB7ICE4hsi4Ypy6uY93ept22a3JyKztR8a5qaip1NayxlYe5Bid3uHSCR5fTq7RcuRd4xDug==
X-Received: by 2002:a05:6102:e13:b0:464:6008:72cf with SMTP id o19-20020a0561020e1300b00464600872cfmr7576138vst.20.1702510623029;
        Wed, 13 Dec 2023 15:37:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2268:b0:67a:9611:38ee with SMTP id
 gs8-20020a056214226800b0067a961138eels692168qvb.2.-pod-prod-07-us; Wed, 13
 Dec 2023 15:37:02 -0800 (PST)
X-Received: by 2002:a05:6122:200f:b0:4ab:eb8a:937f with SMTP id l15-20020a056122200f00b004abeb8a937fmr8900557vkd.15.1702510622281;
        Wed, 13 Dec 2023 15:37:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702510622; cv=none;
        d=google.com; s=arc-20160816;
        b=FjStgP8FFTleMeO40Y+MA/AKeJ2rb/cmYI8A1y2g4aKFnE4ynGxQTnU3AiUhr71jik
         sjzJNEeB93eK7N8Iw4753CZsNIoxB1iI2X77Efaqm//3CbOiEYMNpS8AnsN6aX/daFFm
         ZrWU9BMhSi4koMqzvC2goD2JVPdG9EStin2HRNrfGkZ+Xg0hUX1eaRa2JgCdp0Op1yPL
         Bh8LBDPmPyj6mlc1dHMGtW6VrFAp/H7xOGxEt0L9J5F9b8Eog4Gru4VwQj76JV2adB+F
         3ZMTeUyVSAdGMElPq7Mjf7De5uigf92Sw3mDeNmiqS5M1zM8Ca9S9vnYEd3Wud27YjEJ
         R4pg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=KKQ+/x5aBUFVSHNTE5+u0C93kqAMHLy+4zXkcQqC2PY=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=BqaWOTbPq9KoHmwfwiOTZDyYwp5RZNsiw2ZtzcFuuMgpEWWF5FxoPcy8BUQT1ayoJl
         Oo7JTPf3kRcW3OUZjQ2xkO/x1oy/zUEQ95l8PanWSJPT+phADQii32ybKe7X5JMG92xB
         CGAJUItT4aOJIX5ehaClRLCTiWlST0g7Vj2Ysh/m4pCVwRr24tZ6TYptMRanwXEK9Xz9
         0FaVNgdaXhAIIuicCLAIlgw9YfDS4iVijZB0X85RzkOhu32RP1r+aDrmvDOHHouMtgpU
         0Gns77IjNysxZRe2s4EJDt2ywfsmNbiTB1jp1WQ5HGS6KcWvoSqVMIe7G/4hMXKx/be2
         8gXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=a+xMfSQN;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id bq6-20020a056122230600b004abd0f58a5esi1650044vkb.2.2023.12.13.15.37.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 15:37:02 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353726.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDM7CtE015847;
	Wed, 13 Dec 2023 23:36:57 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyn4d1q9y-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:57 +0000
Received: from m0353726.ppops.net (m0353726.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BDNQFao006872;
	Wed, 13 Dec 2023 23:36:56 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyn4d1q98-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:56 +0000
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDLGUp7028201;
	Wed, 13 Dec 2023 23:36:55 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uw2xyvrsa-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:54 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BDNap6R27263494
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 13 Dec 2023 23:36:51 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id BA37D20040;
	Wed, 13 Dec 2023 23:36:51 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 52BFE20043;
	Wed, 13 Dec 2023 23:36:50 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.171.70.156])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 13 Dec 2023 23:36:50 +0000 (GMT)
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
Subject: [PATCH v3 27/34] s390/irqflags: Do not instrument arch_local_irq_*() with KMSAN
Date: Thu, 14 Dec 2023 00:24:47 +0100
Message-ID: <20231213233605.661251-28-iii@linux.ibm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20231213233605.661251-1-iii@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: IYnxAzNVYRzPOrpd-XtDyC5bRWSG5SiX
X-Proofpoint-GUID: xGq4qQaEqxkSC5s6qSjoXz9Vr7RdbrF2
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-13_14,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 bulkscore=0 spamscore=0
 mlxscore=0 malwarescore=0 phishscore=0 lowpriorityscore=0 mlxlogscore=999
 impostorscore=0 clxscore=1015 priorityscore=1501 adultscore=0
 suspectscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2312130167
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=a+xMfSQN;       spf=pass (google.com:
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

KMSAN generates the following false positives on s390x:

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

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/include/asm/irqflags.h | 18 +++++++++++++++---
 drivers/s390/char/sclp.c         |  2 +-
 2 files changed, 16 insertions(+), 4 deletions(-)

diff --git a/arch/s390/include/asm/irqflags.h b/arch/s390/include/asm/irqflags.h
index 02427b205c11..7353a88b2ae2 100644
--- a/arch/s390/include/asm/irqflags.h
+++ b/arch/s390/include/asm/irqflags.h
@@ -37,12 +37,19 @@ static __always_inline void __arch_local_irq_ssm(unsigned long flags)
 	asm volatile("ssm   %0" : : "Q" (flags) : "memory");
 }
 
-static __always_inline unsigned long arch_local_save_flags(void)
+#ifdef CONFIG_KMSAN
+#define ARCH_LOCAL_IRQ_ATTRIBUTES \
+	noinline notrace __no_sanitize_memory __maybe_unused
+#else
+#define ARCH_LOCAL_IRQ_ATTRIBUTES __always_inline
+#endif
+
+static ARCH_LOCAL_IRQ_ATTRIBUTES unsigned long arch_local_save_flags(void)
 {
 	return __arch_local_irq_stnsm(0xff);
 }
 
-static __always_inline unsigned long arch_local_irq_save(void)
+static ARCH_LOCAL_IRQ_ATTRIBUTES unsigned long arch_local_irq_save(void)
 {
 	return __arch_local_irq_stnsm(0xfc);
 }
@@ -52,7 +59,12 @@ static __always_inline void arch_local_irq_disable(void)
 	arch_local_irq_save();
 }
 
-static __always_inline void arch_local_irq_enable(void)
+static ARCH_LOCAL_IRQ_ATTRIBUTES void arch_local_irq_enable_external(void)
+{
+	__arch_local_irq_stosm(0x01);
+}
+
+static ARCH_LOCAL_IRQ_ATTRIBUTES void arch_local_irq_enable(void)
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
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231213233605.661251-28-iii%40linux.ibm.com.
