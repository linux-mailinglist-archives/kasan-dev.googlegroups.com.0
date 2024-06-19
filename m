Return-Path: <kasan-dev+bncBCM3H26GVIOBBNP2ZOZQMGQEGJZY2YA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 17AA590F2B6
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:45:59 +0200 (CEST)
Received: by mail-oo1-xc3f.google.com with SMTP id 006d021491bc7-5ba793ceccasf6667216eaf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 08:45:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718811958; cv=pass;
        d=google.com; s=arc-20160816;
        b=NXOihotP/YdtOpE5/OxMYlhz0Neq68l9ys3LzCig0g+Krq6grjPldPDpbSDr9WUA5e
         EMR7v8df4xt56fRnVvxSCDQJdTyx3lSBPHddovqVeyqTm9s1OqPFVS25TwMJsTtXY9DH
         7ZbWc5Dxtdmh8oedqmQAnCZKCIz8G0+FaqHWri74D7sfikUE+P/Bf24gb3ADroWeSWfn
         5QyqcE9nQKeL9VJfAVPChBolYVnoPsHckWeTzIe9rrZuAoxuSC2H0Ak+o3rei5Ch5EpL
         HwreWG56sD6VNauF9eru+GE32icC4g2zRpXZib5C8m8eioHEHFCdElHWf46x+6Ka8ZJi
         8wQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=lkLa5hReWPXO5lY3LG+5mtuoLY840+0ny2cZxmZonY4=;
        fh=NN0soSCzeM4u2VYViO1MnKB5dLDKRhoZRXLEqYhA11M=;
        b=d+t8slig5gNtQr3Lmbm0zchtcRWTLOjeX/GlKj+lcOZYW/IibVXo8Iiumt2/9eDzcN
         jHXrXIUb9Mpr83nV3RtNrG1j7At6m/4cIXBoocpQ04dlLqB2UI8PgFEZn5vcF0p/ubUJ
         gixleJN3oQ2Rq75a2vP9s3VvYj6sPtxhSiMLmRwm3C5DshvlDXEdZknImIA93te9O0Oy
         shnq/kd84F3YnFvHydytx800ZOuHFN2t04IYFcbuKqeYyoSAWGuQiFsRC1m1A/YizjmJ
         YEO7wV8S3w1JjOm8YGfDyvx6PmBD8AKn7D7MF2ScrnGm9wTGMM8skSplQqDKolyQkm//
         kOUw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=DdY7fdaK;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718811958; x=1719416758; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lkLa5hReWPXO5lY3LG+5mtuoLY840+0ny2cZxmZonY4=;
        b=qqC+aGd2dBc/OqhJb10MbaFezP6SE+1+THPJqsBQxTqhuCmnkSEDIYN3cODxhnWIA5
         2H5bDZmsB8KIC4iBNrmzn3rP+vLOVbD2WnH0SA9Anm7zTzV0sVBQkg0l0INlCbcs51yP
         wVKorJtH3/+ZAXBQ0a3df/HlgVFtTOSkQrk2zYpbTsQi0YNAd2xeQYkpYTn0m3a9nvcr
         3A6IIR/jLjaAvMbA3ajDWEmdeCkFSWlezFtmAXdH88O7nmJf8poP4XwoNZDpyK1m6MGz
         03qPi0BbwUijwp/pzGaMgGGgynMOfyynmF586LlbBsckUyAK2wPWJreKkeJuF2AJnMLx
         yAOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718811958; x=1719416758;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lkLa5hReWPXO5lY3LG+5mtuoLY840+0ny2cZxmZonY4=;
        b=e/nua7ZPxzQ17vzh00f7KhQEI7i/hHdaBmxHwRWPwP+RrjSh6CT+V5WrtF2NZ/UA+2
         oahAGNMQuJiuOQG4912qXAfnVjZOnxrFed3l79pt1t6fGI6U25MIfqB+FcL2gjq9G7pl
         T95wmvRxjR/FMgXJx0tA2UlRXrMrmyRiM1rZQIOV3VOnM809zHTIX710sRjmXpXlBGsi
         mYagXN7BSFqLg8Cw9+zCIc1ebyx6z32G3uo8VRHsMPvNNdZ8G+5mtmZ4nSbodBT1wYbY
         BwIdiJJkwbH9UAkgOIzS4hKKzul4glI9aozHPdkSTShkjOSWhmOJfQIn4YRhdQOpmFX1
         SMNA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVk3Ny4EB7LceZ+o4rbWAkIzCqo+jT/ZK4kxEw5YQc27dBn3dckZmPI032nt4+7RSxco0y2zeMKig2tsr876y+EvKDpyag8Aw==
X-Gm-Message-State: AOJu0Yz26hargm2Sgc5OYHGpQ9lXeGEN9qfmG1mO2CE5Sm7EV4E2kTnK
	9Trh/sNvrc+RHvPuOr2t8nvhyEdatL1QRFHOpyC4bYa/IwuI7+Wg
X-Google-Smtp-Source: AGHT+IHMgvX30JcGyPSeu8KROFBY5H0iioZhHsPJ34bnZ0Cwt3Od0M4jkf3uTqRlq5frxlRrAlju4A==
X-Received: by 2002:a4a:6248:0:b0:5ba:2d65:3fa0 with SMTP id 006d021491bc7-5c1adbeae44mr3406619eaf.6.1718811957860;
        Wed, 19 Jun 2024 08:45:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:9284:0:b0:5bd:b810:1c82 with SMTP id 006d021491bc7-5c1bfce58cels9889eaf.0.-pod-prod-05-us;
 Wed, 19 Jun 2024 08:45:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX287TuMqmGENGDp2sEGoYFNPyiUPubzT2dkrIfK8rPtIZzvHp+5D0jaYUzFz+Bbu1+qoeLtAyuVGCG9fAMlAssuX4lMaDCvT4PAA==
X-Received: by 2002:a9d:7f98:0:b0:6f9:aa83:bb21 with SMTP id 46e09a7af769-70073a3a507mr3069886a34.12.1718811957188;
        Wed, 19 Jun 2024 08:45:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718811957; cv=none;
        d=google.com; s=arc-20160816;
        b=f89uq222BVkszr2Y/g42QOa8UcZUk3zC3DIjk1KAq3YZ/BwgIu73kAG/EGtMwElmS3
         Zw+SCXP5vf45O/d5JaggjlIGYa1oADinUSe/SLx+WFonVLljtBVc/kBVdMGpFmmF+8ME
         gOsLr/QT8OJy4ApV5rOj+rZWpZZMvr5Lkt7Zbho7b7F0stgZLipGVzmlurlJbhN2yMn3
         vIVCc0+SyEIFDe+BdTxoCWB8ScE/Vy61hUmqGP2JF1lDw+d6CxEjZMLTEALyj+7IkuqV
         BHRyCnKSkIa+eyTEhMXoDfad7uOrTyUBR38+rxY8Mqoa+ylhwpjoWHmV4ACXGhDyb+6b
         Kyaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=aLe/3XBqno9Ykh6K8Gazkn5dKq5eSwzJESHfR5NZsd4=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=C2lSMDGDhfyMlXjiPQqd3TjlyZKHpyt0yoJ++8FxcZSab3fRgWqRyUXOWIvC2NjeqV
         +qaL2wQL8BD16G6Y9Msq0pnsqruD9E7W9FXYIF6+lws/Gl03L0MU45iPz3Rjpx8GnM0s
         NKiGLckhuQ+sZB62HfXT/rbbCLxTzuRrRNaCqzowhwK8Q6pLd+KHO9vGUtXXX2pBwtZR
         g6iWHsPDUlFy0YWkdbRwHqOL/vZa13eKS9f8guyfvXUc9b4NeDl0YyGfvGcKLlfYUET+
         NgRi+g9tReOX4piP1lBIoZuHWn+G0d0nGm+dqZeFajXYm8U8sGWH+vyrYMhcXjrVhqIL
         fh1A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=DdY7fdaK;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6b2a5b57d42si5263746d6.6.2024.06.19.08.45.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jun 2024 08:45:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353727.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45JFSdmn014351;
	Wed, 19 Jun 2024 15:45:52 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv20gg1gr-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:52 +0000 (GMT)
Received: from m0353727.ppops.net (m0353727.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45JFgsTe002902;
	Wed, 19 Jun 2024 15:45:51 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv20gg1gm-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:51 +0000 (GMT)
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45JFPGhi006210;
	Wed, 19 Jun 2024 15:45:50 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3ysn9ux8ne-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:50 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45JFjjTl46072230
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 19 Jun 2024 15:45:47 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id F371420067;
	Wed, 19 Jun 2024 15:45:44 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A42EA2006E;
	Wed, 19 Jun 2024 15:45:44 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 19 Jun 2024 15:45:44 +0000 (GMT)
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
Subject: [PATCH v5 32/37] s390/traps: Unpoison the kernel_stack_overflow()'s pt_regs
Date: Wed, 19 Jun 2024 17:44:07 +0200
Message-ID: <20240619154530.163232-33-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240619154530.163232-1-iii@linux.ibm.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: v76OCW-rSK0e3OTzOrEaX6yNZpyNzUiP
X-Proofpoint-GUID: 3PULXL9LrKrVhTrKFdx-3pRbX3v6Ygw_
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-19_02,2024-06-19_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 spamscore=0 clxscore=1015
 impostorscore=0 bulkscore=0 malwarescore=0 lowpriorityscore=0 adultscore=0
 phishscore=0 suspectscore=0 mlxlogscore=999 priorityscore=1501 mlxscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.19.0-2405170001
 definitions=main-2406190115
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=DdY7fdaK;       spf=pass (google.com:
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240619154530.163232-33-iii%40linux.ibm.com.
