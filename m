Return-Path: <kasan-dev+bncBCM3H26GVIOBBUVFVSZQMGQE6JW3ONI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id AEA949076F1
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 17:40:03 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-375a26a094dsf10969455ab.0
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 08:40:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718293202; cv=pass;
        d=google.com; s=arc-20160816;
        b=RkK8zyBHPxgyz/PjY3pFjGLoiLzJusoKe9LTdw/PQwveyhMHICTMMWQvHrjBdBsIkw
         ob9i9gVeuyo2G7I9OSEV0xJI9gh9MXNgWaxgJ7GDlJonQGGpmrpj+Smprni5pHJBA2wl
         gp2ntmtAdvemiHy45jm0+9mD07z9S7gjgVRJjXVixKr9/YzF+8ART/rrznDOwhQXdznk
         gxGi0jlPRyA5y8mD3RzrHSm0toFpvWP094Y6Rcc4GmJx+xtB8dExrfe8TEaIEbcQ74pX
         cRIv57aRrFyCmP0WKuxh3aTG6rP4sGA2QcJDs3a9P1qZG3/IksRletutPtmQ1swE5rkc
         OzgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=WlKlytzvR6AiXZe3LtRZicAhiS2cjQFxR7qTG3GPzQ0=;
        fh=0iteHkpvR2U8fHtWYHmT684FZHZvSVS1IYM61Xb7E6k=;
        b=U94P5OZFHEz3wL99kaJ743MsKWoBHUiUaV/5QsTRx7tn8C3BTcDzKn21e1C+Net8dJ
         nQ9mWED7Vq/gbobDS/mKBk7XxuVpELJ0oti1TMXZYE6PigohbMNdtpBdzOqPlCaeILbx
         KN5kAHskG0vx0nXxshvzY65me2679wbIaEGg0ESjlAuKhvjLtJnTQUe6RUdOM8LsQekS
         nyU9riJYg6VCaLZSw+glxVMr+3RRGwjr5+klucQtkBf0/OFqZpl8lNLCGvbi1VyKRaz2
         Wy1kLOriXZqYv4+kmOea8AgV5An/14X9vkGQPI9NcYmziS3TDOM84MU7evAaYJAwuZ7V
         0SaA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=UNq2L3ci;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718293202; x=1718898002; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WlKlytzvR6AiXZe3LtRZicAhiS2cjQFxR7qTG3GPzQ0=;
        b=s6vRRsTVcX26f5eq7BPEq+RzIEFp802k298i2TPgP9Wa6ErZWdVOaVftaZZeKgC5go
         C3EcyXxeGAxNQqzpalN53G07zcDQKNLibIBpyeTyLJx0DSBXO+Ci0MhgZiQ/gqKhKEj0
         yv+wlDEEaFDg3bB2m16+/VIGnGGurWT09dAiKZmJwyYBpiF5kZgH26L3B4b6OXsbSw05
         XTQBbzaLe5Kj8KhH+zajzDSdkbJwD2EdJftut4iMMknvDcwFUC6LZwvm+ye2/8jD6JoD
         9043sNKhTrcubhyjj5qK7z8eBbAe/Xl2LNdTifvQZJKKUpiTjzt3b6gNEojpJ/v7xcpQ
         ixIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718293202; x=1718898002;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WlKlytzvR6AiXZe3LtRZicAhiS2cjQFxR7qTG3GPzQ0=;
        b=JmdLp/X58tA5F3gSf2S3D8JiPrvcTcE38/yBBrVz3grRn1yGzPUDOvu+zO/lq0GrC3
         E9fkPodOycyL+qgaib6Z77lyTzzIIWzfKTrzOiyUo49XUT8cqQMmiwFfmIlobMU1NKQC
         n2ZCttNB3vFHjWPeNM2KPdPnuyE8KCdEu2EisZ+qoch6dCepZdecSXBQvQe6GRacf1MQ
         Gr/HmaTGcP+vy6hergIsA+NG4pUFxmfKVSW7RXurW+lJVcsaSPYKm+oCVjwwpp1zjxmD
         TeLfa8TOmGuBVTAjN5/U4vdCHsfKJHVFvSBB5BUEIA6BHzTRYK5TajVjBwCnQ9pDryhe
         BcPQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUGoRqFhhWaas7WU9P6ncLnBjuroKfv7O2MQll3+JFKnT3+P0zU921SADLMMq9dlhYVWedMmC2xFcR6DeSvUx1s40+vmJJE/w==
X-Gm-Message-State: AOJu0Yz+j+FoYDlxy5iiCQ5ST4XxPCaPKE494v7GoCo+Ilmxd/lR6pfj
	smcF5P7PwvRvb4ifcKIHyPi+rAXssVTpBu48345cyzZlX+PXotg8
X-Google-Smtp-Source: AGHT+IEzSDW9IFRAk6ynizyjukBIZ9xOHmoRV1CRG6zO6OnDfj1d4UiMMxt/xskXSUQuqIGgybrruw==
X-Received: by 2002:a05:6e02:2192:b0:375:ab42:96d3 with SMTP id e9e14a558f8ab-375cd060933mr60912705ab.0.1718293202549;
        Thu, 13 Jun 2024 08:40:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:3a09:b0:375:a4ed:350f with SMTP id
 e9e14a558f8ab-375d5664f22ls8838995ab.1.-pod-prod-09-us; Thu, 13 Jun 2024
 08:40:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXuK5W4PWneWvkMu8ZU3cxmmbZDEilBB1QBfUuXn40SPr6RW1fexRJFQxanrG+toehGxFs4C43SdpsQeptnrR3QpidGSQcdpbTAkg==
X-Received: by 2002:a05:6602:164e:b0:7eb:6d0a:613f with SMTP id ca18e2360f4ac-7ebcd0cc570mr630357739f.11.1718293200182;
        Thu, 13 Jun 2024 08:40:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718293200; cv=none;
        d=google.com; s=arc-20160816;
        b=kg6dkylGw5+fAYFAc10xGkBI/FDYpFAql7iagzcPpFZyAdSu0cZnN4x8/Q14RkIaS3
         d0GoAUiiR2RQSlSdLJkoe6U9Gm9Z/Ork3nrDZ6E3ZmGnfkhoxDo32y+vdxMxRDEFpuGO
         aYtXT7dWPePSey4YAZoIrOrkxnJboRlGOE39B7+Koyz8UTOl3REc/+WUwfgb34zvaLAp
         6Xl0uufK3aqjaYWFE7cdJHHC5KkfYVVK/4HVeLwFPjLLCJVx7ur/1kKdHW4t09iGpdZ7
         GR/RiNWI6huHyFwYOJQGQ/s1+1NFI+iOcMODgs7LGisgTusnDc1Rs2pDIFT4tmgN3jdt
         yFew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=lwqEGphQg9/N4AE+qTFRbf/COwqV90p8RxwOJfRaDvM=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=ZEBm6rYjc7iCFkTfLIe9Nrh8WkcniN5e78s+ugFTZt3XkYB2XkwhMYvps8DUPlaulF
         ou1BqnDFKge+1PqLrial6oC/m3yzmRh45GCQ2LfwcdExJ3iHK+IUWnb501046LUxvyqG
         QZtgHHinUX6cDemXbcEisjRaywbloZwXYzIRL5p8lk/wfhBUBqm7t7vMHcZlzghjMdEe
         5B0J4VZpueBxeJFNuwsuun9cw02kSw6rNcaP4S9K/3kZZQhP9GJZFS9Y2fgKU3nlYOUE
         S84ArhWQKq5O0SUdX6bEH0f1hPJ7yAeHCRCdc5eP03t/vTUXqY+vjkAwIDDbBFRmFBH/
         qfVA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=UNq2L3ci;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4b9568bb7a7si80300173.2.2024.06.13.08.40.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 08:40:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353726.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45DDPs1w029160;
	Thu, 13 Jun 2024 15:39:56 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqq4rt37b-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:56 +0000 (GMT)
Received: from m0353726.ppops.net (m0353726.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45DFdt6d026856;
	Thu, 13 Jun 2024 15:39:55 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqq4rt377-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:55 +0000 (GMT)
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45DF54oG020086;
	Thu, 13 Jun 2024 15:39:54 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yn34nh0d0-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:53 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45DFdl5E31982318
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 13 Jun 2024 15:39:50 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id BC8BB20063;
	Thu, 13 Jun 2024 15:39:47 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 49DC72005A;
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
Subject: [PATCH v4 27/35] s390/ftrace: Unpoison ftrace_regs in kprobe_ftrace_handler()
Date: Thu, 13 Jun 2024 17:34:29 +0200
Message-ID: <20240613153924.961511-28-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240613153924.961511-1-iii@linux.ibm.com>
References: <20240613153924.961511-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: 2CzzALgI92z2xp9DoNxArLwRD-45DbUj
X-Proofpoint-GUID: vaNzi9dxYUytn-myd3xb7t8cTOvep84K
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-13_08,2024-06-13_02,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxlogscore=999 adultscore=0
 spamscore=0 mlxscore=0 priorityscore=1501 bulkscore=0 malwarescore=0
 lowpriorityscore=0 clxscore=1015 impostorscore=0 suspectscore=0
 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406130109
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=UNq2L3ci;       spf=pass (google.com:
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

s390 uses assembly code to initialize ftrace_regs and call
kprobe_ftrace_handler(). Therefore, from the KMSAN's point of view,
ftrace_regs is poisoned on kprobe_ftrace_handler() entry. This causes
KMSAN warnings when running the ftrace testsuite.

Fix by trusting the assembly code and always unpoisoning ftrace_regs in
kprobe_ftrace_handler().

Reviewed-by: Alexander Potapenko <glider@google.com>
Acked-by: Heiko Carstens <hca@linux.ibm.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/kernel/ftrace.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/arch/s390/kernel/ftrace.c b/arch/s390/kernel/ftrace.c
index ddf2ee47cb87..0bd6adc40a34 100644
--- a/arch/s390/kernel/ftrace.c
+++ b/arch/s390/kernel/ftrace.c
@@ -12,6 +12,7 @@
 #include <linux/ftrace.h>
 #include <linux/kernel.h>
 #include <linux/types.h>
+#include <linux/kmsan-checks.h>
 #include <linux/kprobes.h>
 #include <linux/execmem.h>
 #include <trace/syscall.h>
@@ -303,6 +304,7 @@ void kprobe_ftrace_handler(unsigned long ip, unsigned long parent_ip,
 	if (bit < 0)
 		return;
 
+	kmsan_unpoison_memory(fregs, sizeof(*fregs));
 	regs = ftrace_get_regs(fregs);
 	p = get_kprobe((kprobe_opcode_t *)ip);
 	if (!regs || unlikely(!p) || kprobe_disabled(p))
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240613153924.961511-28-iii%40linux.ibm.com.
