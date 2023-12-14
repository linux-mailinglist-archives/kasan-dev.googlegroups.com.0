Return-Path: <kasan-dev+bncBAABBEVS5KVQMGQEFO25TVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 20DFF81272F
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 06:56:36 +0100 (CET)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-67aa0c94343sf5221936d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 21:56:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702533395; cv=pass;
        d=google.com; s=arc-20160816;
        b=ChWzpaePTT2RMEb6S4gTS8BQ5N4NK1+Cg5gAQqZRZOOtkXvxn2aXZu6GjsC2P6RjbN
         +iSIeQHlx0gxlKaKE59/Ot//ZttFXu+ssFpRh4d8GGTMYwcsVzPWrSP6A5cYqskQEPan
         FMVKsC2VgHNuHL0oRNqHcF9GbmTV0R1NffKvWx4z/kJU+gtx01IbCKF36UkFUxrtLYDH
         pPYWQaarWCKjIRLcG3PZm6qQDA/UX9Qd2MwYn9dYHT/ZwfuRA7gJjyn3xWk4tyTsp5FV
         dpW/OF9YGqlefsN72jmNIXzcT50bqqY++FEgyAtFvZ1tzoUAJvqFyEi0IwoEFyWWbbXB
         7ImA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=I+BfQSANdZH/DkaSb5s1VfxCCN92V8vy2imhbr+iMWM=;
        fh=JZjI76tHrPFh9wXiZ9caJKwSuDkcoMAMvZd7/HZf8J0=;
        b=oNOr5aCDc4b9bbyMpXO4a47bSQPK0EFpHVyGwYIwAgCNPNzpxuJ5jkzS+4Au5r41t7
         5HRxLs1lrn2m3rcktQPGZN+Qq7tPgs6Wyt020Y0yvoaQSQ95mQxoeHQ7uKuLaYxX3hg8
         CgBH59coufd4H+SSTImvlTpfPYw7AWZRdZAnOLyx0yV/7N6DPASW4bo/laWwUwx6f5pm
         ky0FnY6Gz+AF9X9mrx12PIqLdd+Oyn7jhj7TPKBLDqTQ1DbKPStBYu1D7tm1ZaOqV5sb
         lxHwqH7dYaxykTqBlaCZAH9Zi00C9+2bgS50iAkSjUXgFsT+0zcH/faRbr5JJoEcAIns
         Bqng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=HviIdLMX;
       spf=pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=nicholas@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702533395; x=1703138195; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=I+BfQSANdZH/DkaSb5s1VfxCCN92V8vy2imhbr+iMWM=;
        b=oWg/oS6F8igQz0qtlL0orsbeNeqoy94k5hD9hU2Oq4rYLq0czFhOagcbZPp8NzdFIf
         4qxhpJaCUd23qS/dgvmY4XJdNStF6e0Q4WJh6ETZyXylpCwl2jaFH86SKP+7Ipv1urSX
         7DECG1zmmTkQV36ygYI0VN+4puO9dLbMZOX0bdus4SFjCrS9OmB74RtUwSPLnoaC1dPc
         T4oJK3tAworGW2p0NCg5oUOyDWcbjFt38NksVv/1EqJZqwDQlgJn34CrZdGunRGEWP31
         6gW5XU9v2bLY0l8WFD4cJ6ePzHwSutrRqGIG0N5yD+CRgK0VifdcK2F/TJFX9kuOD+6i
         ekVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702533395; x=1703138195;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=I+BfQSANdZH/DkaSb5s1VfxCCN92V8vy2imhbr+iMWM=;
        b=JIECCnSqB7vjV/gNV5Ab+GgryANudCfuxL/PJoJwagAYmv/v/KQPXlRNNBxW4z7NOm
         sGdL46cK8ZJ/R9sZ83rSHMaOEuKf73wriMcs/TsSkRhzlY0yeuGthFDgD+M7f/NEGXvA
         1J11OZXPc7Sk1vs40E/wyoqH51msPORZdhyNgbQTJVeIHb2jlBNEvTxdpU1a+WdmnXd3
         VqjzMgnVigLmauOF1Yaay1RdjiBb2DGR56oIJCj9BWhZEU2iUejNgeS0BKBJS1jjV5SF
         rYbS7jIUXFO2WmmSyRZ4zhuUhY7Fst02oT3Xbzn85xCu+2q3H6Tlos/6UgV/psgOJkNz
         apxg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyTwx7cHf14uwccP5AKrDN04KFM2j6FNU3JJuGuD5MpAPOpNAEJ
	FogL4uKlNyRuO/qPIUPXM7I=
X-Google-Smtp-Source: AGHT+IFjJwNqiqbFsXlDStot9P4Q63Pv5zCCu6CsnxLQPyRl3LhENQ1efwpdtbnUvMxK/qv6VjQHrw==
X-Received: by 2002:a05:6214:2b0a:b0:67f:4c4:5123 with SMTP id jx10-20020a0562142b0a00b0067f04c45123mr2160791qvb.26.1702533394782;
        Wed, 13 Dec 2023 21:56:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5766:0:b0:67f:e61:7f01 with SMTP id r6-20020ad45766000000b0067f0e617f01ls35710qvx.0.-pod-prod-00-us;
 Wed, 13 Dec 2023 21:56:34 -0800 (PST)
X-Received: by 2002:a67:c019:0:b0:464:9e4e:4f01 with SMTP id v25-20020a67c019000000b004649e4e4f01mr6347824vsi.30.1702533394216;
        Wed, 13 Dec 2023 21:56:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702533394; cv=none;
        d=google.com; s=arc-20160816;
        b=cH7w37ZPLMZLpFuOvYfVkFl1JFkG49rNSEPVEpdf/VdQV7mbf331EKoEhQGDrOl1ai
         MS2zNTg5vca4WIWAdZtOq9I/bOldTH+NWbsFehpgiXFICCHZbEa//eCRKbAehQG3VqiL
         IpQ6NOfG6KLDP0NKFNM/+rfbZcEyYN786MM9TvH7f7MqkxmC7pNrtFDjaaVCj3KP54EE
         dak6lIiWi84FUOfxebQvQg+isfL00v02VFhAxOKl00E067aQ+xjCdmYbqTaIp+BEP7JJ
         f6e5MQP6tyhauyQHqpKDG7j9fKtf8RLU/1BbTkQCcl/A6SuQrGg3shN+pMbECyk+6WRc
         CZ0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=/mQKPh+Q/+oVqTYrm5JhFDCdjY5bZbTlHx3Tfk9a0cM=;
        fh=JZjI76tHrPFh9wXiZ9caJKwSuDkcoMAMvZd7/HZf8J0=;
        b=N6nBYQiGbHmI1DoAYMBurCPSBo/lhF7AQKv3IgzHrRTN1x3f7Bdu4iNM9SVGRtNrFE
         N73CKczlVKAdsonf/KMTp4OR2uvt694OIYcS+mJ0+Q+ZuRcTeR5Q84pLbgsW2aRb6NEn
         WHpARNmIo7UfxtYzZT+c+53RXMCGAzwqUQg3YdPycMIU93+TKhFEg0wMzmZUCFz4aC9m
         qA4ZA+rVwGjLAfV0DakbRmgTR0NJ+B8UvkYSIRzJBWX0AcGO9XcP6peMd5OOnEvayX7I
         xEZcz+Vz7ft2GGV6L2Oy5WRpXiPlBuZmjtVfqWSeXNV07ItBt0mXAQx9utfvLNWyE8+V
         cYgQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=HviIdLMX;
       spf=pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=nicholas@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id h37-20020a0561023da500b004649987350fsi3326250vsv.0.2023.12.13.21.56.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 21:56:34 -0800 (PST)
Received-SPF: pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353729.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BE2Uej9022139;
	Thu, 14 Dec 2023 05:56:28 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyjg3cj8s-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 05:56:27 +0000
Received: from m0353729.ppops.net (m0353729.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BE5r8A1026718;
	Thu, 14 Dec 2023 05:56:27 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyjg3cj7a-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 05:56:27 +0000
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BE5cXLZ013892;
	Thu, 14 Dec 2023 05:56:26 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uw592dwf3-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 05:56:25 +0000
Received: from smtpav03.fra02v.mail.ibm.com (smtpav03.fra02v.mail.ibm.com [10.20.54.102])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BE5uOb944237272
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 14 Dec 2023 05:56:24 GMT
Received: from smtpav03.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 2C18920040;
	Thu, 14 Dec 2023 05:56:24 +0000 (GMT)
Received: from smtpav03.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id B55CF20043;
	Thu, 14 Dec 2023 05:56:23 +0000 (GMT)
Received: from ozlabs.au.ibm.com (unknown [9.192.253.14])
	by smtpav03.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 14 Dec 2023 05:56:23 +0000 (GMT)
Received: from nicholasmvm.. (haven.au.ibm.com [9.192.254.114])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ozlabs.au.ibm.com (Postfix) with ESMTPSA id 92302606DB;
	Thu, 14 Dec 2023 16:56:19 +1100 (AEDT)
From: Nicholas Miehlbradt <nicholas@linux.ibm.com>
To: glider@google.com, elver@google.com, dvyukov@google.com,
        akpm@linux-foundation.org, mpe@ellerman.id.au, npiggin@gmail.com,
        christophe.leroy@csgroup.eu
Cc: linux-mm@kvack.org, kasan-dev@googlegroups.com, iii@linux.ibm.com,
        linuxppc-dev@lists.ozlabs.org, linux-kernel@vger.kernel.org,
        Nicholas Miehlbradt <nicholas@linux.ibm.com>
Subject: [PATCH 09/13] powerpc: Disable KMSAN checks on functions which walk the stack
Date: Thu, 14 Dec 2023 05:55:35 +0000
Message-Id: <20231214055539.9420-10-nicholas@linux.ibm.com>
X-Mailer: git-send-email 2.40.1
In-Reply-To: <20231214055539.9420-1-nicholas@linux.ibm.com>
References: <20231214055539.9420-1-nicholas@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: bbcuSHGLeoKEVuj7srCG-ZCZayTjEdOS
X-Proofpoint-GUID: KH91wVFkQGDFAZOFPfyiwzBaXkKHaRsA
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-14_02,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 clxscore=1015 impostorscore=0
 priorityscore=1501 suspectscore=0 spamscore=0 phishscore=0 bulkscore=0
 lowpriorityscore=0 mlxscore=0 mlxlogscore=999 adultscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2311290000
 definitions=main-2312140035
X-Original-Sender: nicholas@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=HviIdLMX;       spf=pass (google.com:
 domain of nicholas@linux.ibm.com designates 148.163.156.1 as permitted
 sender) smtp.mailfrom=nicholas@linux.ibm.com;       dmarc=pass (p=REJECT
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

Functions which walk the stack read parts of the stack which cannot be
instrumented by KMSAN e.g. the backchain. Disable KMSAN sanitization of
these functions to prevent false positives.

Signed-off-by: Nicholas Miehlbradt <nicholas@linux.ibm.com>
---
 arch/powerpc/kernel/process.c    |  6 +++---
 arch/powerpc/kernel/stacktrace.c | 10 ++++++----
 arch/powerpc/perf/callchain.c    |  2 +-
 3 files changed, 10 insertions(+), 8 deletions(-)

diff --git a/arch/powerpc/kernel/process.c b/arch/powerpc/kernel/process.c
index 392404688cec..3dc88143c3b2 100644
--- a/arch/powerpc/kernel/process.c
+++ b/arch/powerpc/kernel/process.c
@@ -2276,9 +2276,9 @@ static bool empty_user_regs(struct pt_regs *regs, struct task_struct *tsk)
 
 static int kstack_depth_to_print = CONFIG_PRINT_STACK_DEPTH;
 
-void __no_sanitize_address show_stack(struct task_struct *tsk,
-				      unsigned long *stack,
-				      const char *loglvl)
+void __no_sanitize_address __no_kmsan_checks show_stack(struct task_struct *tsk,
+							unsigned long *stack,
+							const char *loglvl)
 {
 	unsigned long sp, ip, lr, newsp;
 	int count = 0;
diff --git a/arch/powerpc/kernel/stacktrace.c b/arch/powerpc/kernel/stacktrace.c
index e6a958a5da27..369b8b2a1bcd 100644
--- a/arch/powerpc/kernel/stacktrace.c
+++ b/arch/powerpc/kernel/stacktrace.c
@@ -24,8 +24,9 @@
 
 #include <asm/paca.h>
 
-void __no_sanitize_address arch_stack_walk(stack_trace_consume_fn consume_entry, void *cookie,
-					   struct task_struct *task, struct pt_regs *regs)
+void __no_sanitize_address __no_kmsan_checks
+	arch_stack_walk(stack_trace_consume_fn consume_entry, void *cookie,
+			struct task_struct *task, struct pt_regs *regs)
 {
 	unsigned long sp;
 
@@ -62,8 +63,9 @@ void __no_sanitize_address arch_stack_walk(stack_trace_consume_fn consume_entry,
  *
  * If the task is not 'current', the caller *must* ensure the task is inactive.
  */
-int __no_sanitize_address arch_stack_walk_reliable(stack_trace_consume_fn consume_entry,
-						   void *cookie, struct task_struct *task)
+int __no_sanitize_address __no_kmsan_checks
+	arch_stack_walk_reliable(stack_trace_consume_fn consume_entry, void *cookie,
+				 struct task_struct *task)
 {
 	unsigned long sp;
 	unsigned long newsp;
diff --git a/arch/powerpc/perf/callchain.c b/arch/powerpc/perf/callchain.c
index 6b4434dd0ff3..c7610b38e9b8 100644
--- a/arch/powerpc/perf/callchain.c
+++ b/arch/powerpc/perf/callchain.c
@@ -40,7 +40,7 @@ static int valid_next_sp(unsigned long sp, unsigned long prev_sp)
 	return 0;
 }
 
-void __no_sanitize_address
+void __no_sanitize_address __no_kmsan_checks
 perf_callchain_kernel(struct perf_callchain_entry_ctx *entry, struct pt_regs *regs)
 {
 	unsigned long sp, next_sp;
-- 
2.40.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231214055539.9420-10-nicholas%40linux.ibm.com.
