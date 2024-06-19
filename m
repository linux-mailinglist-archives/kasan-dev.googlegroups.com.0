Return-Path: <kasan-dev+bncBCM3H26GVIOBBM72ZOZQMGQEV3T7RUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id DD4F890F2B1
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:45:56 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-37623ddfa1fsf83285ab.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 08:45:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718811956; cv=pass;
        d=google.com; s=arc-20160816;
        b=s0kYojUwhez6kmC8vPubhJqKWkQgdEeJ1XOXPZ+42eM7TkLE/NOYy/FOadLpUfDsnr
         G9qEW9TRIr6NJ5JP0NgpJB0ld0ny7SFzUnxrNdcQbfAk2M9AxIS+Cz6okfFbxW7eXnux
         sQbHpq0RD0mQQ2XarAE65YSjPHjBl2tgK9RybF+8AQx5He3jWgsBbkopUw2/TJHHW6Pv
         CM2w0RqLSd1Vr+D9fC15g25Yf12pww6hrNpyXkRE6/3oZv9md2Qbcad/nU0RKjEdocQa
         +KpOYM5IHBmer4lFYCIrg8c9P+j2PoSYgvgLRTA7QjkiCv0uQK0ipL+qQFMwZ3D4AppA
         W65w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=r6OLN3tSqbFeo9VtPrt12Q3+9Xy0enXLgQ9WEMmNJBM=;
        fh=sFASOCjypFaDi6UQ9K/plzwWVwBHEQJrprkFcxMafk0=;
        b=HdttYzdHRAXxta8gZe/kIQSljR8BZ4ivie5Gs/ilS8LXTPZVL6/l7uCRqZemPEHznF
         wA/GQ5V5WoNPzECW6jWGhxoNgd3SnF9Mo9wpXh6yeEjpEEB+7tDNMKTgz34tDxwNV8Ew
         n022z8L+4e+Wb1Z9Y9S2q8yC1ZC4pkGGUMn4dLuXsrLMCGAV23roSRiYHUyMQ3T/+OgY
         fU72E0zHvi0kztxCqJIUZqojugNo8h/bgYrMBry5WNdlaaAFZoK40WTx/EugczcaFzYL
         AaeGGYMCszfCMTLEqunp18348OO7bC0gNFj1S92whCzoh5KWiwKDVNk7rO+QmWDdlbCx
         VUJw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=f4W6JVtH;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718811956; x=1719416756; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=r6OLN3tSqbFeo9VtPrt12Q3+9Xy0enXLgQ9WEMmNJBM=;
        b=JIUaq+JKe4Kw07nf6VWcuPFbWkTvOyXH1chAov7U4HvuwfhE11mIm76jZdRobn2Dce
         7qvg8+/ItgIcZgU6FpXIbh8VdPO8eoLi+4tYT/jj1eOJVgAwK4BoKzMwjivQ2T3IP5ea
         1CQGTi0pAaM1onGWpV/1l/g3sIhfD2+XT4Fe74HHEdMlA5zh3HGmOkHAkrAq4YrSXbVy
         wFz1frAhi5CcT4i07eYiv3ldPBuhMHn9UXK7PDxEKyIJCJs4Udr9Lfv8U3b3YX92z46d
         ThFqzB6jbqbWAuIUfTwiz3V6pjtnPffkLqb4Z0YVMeYpI9LQINAo+aYtsYsnO0mBgEnC
         1lHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718811956; x=1719416756;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=r6OLN3tSqbFeo9VtPrt12Q3+9Xy0enXLgQ9WEMmNJBM=;
        b=Aj1K8JFsffAvO/p3nfa3SewxWW1WFNI7KiXJGbvIvu64bxFEYFGJXTq7aNb6mU9bW3
         jXGBb9LbeHD+fLMOesekL+8DYoC+XG/VIgCzjCSqt8CXI+vn8E0tAwWyKS3riROmK38k
         sYRWauRh/1MUXq5L0o/MRvVxuWeJnCq5sR6ZogjadHzmspmPP7s6tTLuJjfdSh9oqdG3
         d+2XMFTuSdiA4/0zArhbwcLKh70gbjQlD42fJKdO3V+pLUBAlolKIOqb1HycJH+snRJF
         NJIv1Kt4fTQ8eGqd04POrUGWY7zUfvb3v/GF96DJQCZI/27PUQ44xrGv6R3OU2xnwTNS
         8gYg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV6Kp8b93lGcpyPNkWum2KIlvE0zjJ6knPFOtyB3a8/VJbSFlyTFhhkfSeCHVkUd2Fdehj6m/8RR2IY0Dk9z08++Q91iJJuJA==
X-Gm-Message-State: AOJu0YxtaSXF+eftJcqnbCqjQASKyjfx9QeisFq/q3kXiLcH84dSC87Y
	pV5lU67iCi9szRSRc/2BYlQPua3HGs12LgV+wWaBWDE4wQZs+Plw
X-Google-Smtp-Source: AGHT+IH4smweIlBY9L15Qi0xrHm5fKDKFYLBd/kqeNr//qxTdieBQ2VBoPtw61Yxj/bjK2SCZSqErQ==
X-Received: by 2002:a92:d98b:0:b0:376:1faa:950 with SMTP id e9e14a558f8ab-3761faa0abbmr2452885ab.16.1718811955673;
        Wed, 19 Jun 2024 08:45:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:907:0:b0:5aa:44f9:9b11 with SMTP id 006d021491bc7-5bcc3ce31d1ls6680492eaf.1.-pod-prod-05-us;
 Wed, 19 Jun 2024 08:45:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWsxShyuRXppgFYcx7DlT7Z5d06GuCi/MDONny58tdSiTpYVf/hJnxIQZy/tsu9rNkGbodwiaCZ29/OQauyMKIHvaw419lPDSjnog==
X-Received: by 2002:a05:6830:6b45:b0:6f9:a19e:7b40 with SMTP id 46e09a7af769-70075f5172bmr2834713a34.36.1718811954921;
        Wed, 19 Jun 2024 08:45:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718811954; cv=none;
        d=google.com; s=arc-20160816;
        b=BD03ub/awWIcqIzPs1/NMaU4jPPqvjGyWXiF6H8D5KV56jkgprbs+m+JG4ghVBAWOK
         oTL2P6CVoHoUPfLT/GCiY5GNwpKMxQ4/4I3TMQhm/jsjMEeWoKLJvs4pTkjxlLNIIeZB
         aVOWIQ+V8Atka6Z5SbIn561WABBRimQCk+1faRVz6mMXiJim6GZt5J66IdkF8QCJHxrq
         qdCr7Z2SWlxQ3h1HVBQCyLCxCBrFZNVhXnIRdcUdDLQcbRCgDe377mWJ7TgZjW03X6/K
         eKPw4kVovJQJn+MipMNgyeEs9eDruDfGgD7Q56buB2AYadO9Q91NK5haiaORAZmxU0Nd
         Cnyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=+zoFJVlk37wQaOMfwbNCgteXo249s6T95ikp3xQJB1k=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=IMph/QmGI8Z+458RDV+GX0YPaOtyPQ2FDJsuanWD5cBhKgX7USl1RySCNB1ZyVaG4O
         5+DBhlYCvGFHqClhYFTYPR1zAwlY2E1trn7NRxC8umzYPLpvYldypyvHMkFHdX+n+cab
         pG+HTFminlxWXATofTpuL3psEz84xcM3SqgiUgrQr7y5zcfSWrsNp2yoZLVt5zLXHxbo
         G973+OlW8CNSbxR5E8XumfXj7PKrIkVi1087CW/Ohtj3Ay3/1Ptx4jmH/F6mMmqo1IAJ
         fFmzBWs3CtJCFTxE+ioPK0MQdjx2VM3T+qZekfwj6tMKe+r7/INdLOg60uzlDMpUdFOy
         403A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=f4W6JVtH;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-6fb5afad180si556171a34.1.2024.06.19.08.45.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jun 2024 08:45:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45JFTKd2014408;
	Wed, 19 Jun 2024 15:45:52 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv20hr1fb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:51 +0000 (GMT)
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45JFjoKh009130;
	Wed, 19 Jun 2024 15:45:51 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv20hr1f8-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:50 +0000 (GMT)
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45JFhxiu023990;
	Wed, 19 Jun 2024 15:45:50 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3ysp9qdyqv-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:50 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45JFjiH211469088
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 19 Jun 2024 15:45:46 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id E9B2520063;
	Wed, 19 Jun 2024 15:45:43 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 9B67720067;
	Wed, 19 Jun 2024 15:45:43 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 19 Jun 2024 15:45:43 +0000 (GMT)
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
Subject: [PATCH v5 29/37] s390/irqflags: Do not instrument arch_local_irq_*() with KMSAN
Date: Wed, 19 Jun 2024 17:44:04 +0200
Message-ID: <20240619154530.163232-30-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240619154530.163232-1-iii@linux.ibm.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: JkoSaKFCRfRLJ8vnhBHJK2kOBJWSxeGc
X-Proofpoint-GUID: IOuM539aevafZuGj-t_FfvZHpXmybvpj
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-19_02,2024-06-19_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 spamscore=0 mlxscore=0
 phishscore=0 clxscore=1015 bulkscore=0 suspectscore=0 priorityscore=1501
 adultscore=0 lowpriorityscore=0 impostorscore=0 malwarescore=0
 mlxlogscore=999 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406190115
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=f4W6JVtH;       spf=pass (google.com:
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240619154530.163232-30-iii%40linux.ibm.com.
