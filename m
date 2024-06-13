Return-Path: <kasan-dev+bncBCM3H26GVIOBBRVFVSZQMGQEH5RTZ6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 4263F9076D8
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 17:39:52 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-43fb02db8basf11314971cf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 08:39:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718293191; cv=pass;
        d=google.com; s=arc-20160816;
        b=GPXEkXfuKosGL3B2SItRNbyqmz38+QMlpRfoRNnMwDS7G8Rm22cr3DYHD6g+qXKooe
         WLm8+9NYUktGFEBJHzg5samzLl+N5mx7REQdCCyw9ogNIQuVA+9G3d1/+dP2CGOuSKd5
         NVukmShh4mRuO7FAa2ufNx6XfY6NSnaDyqIeumd4zl/GRWcNs+E0Cs7w8Jq1yHpIwe8+
         Omzhf1HXV9TR+cICMDGtoCf9O0mOUuUoYiuPNpeih8HwxLca8pwXaQf9ANXSQE5YY9oL
         0zXVPKRnw9GDkwsu1cwadkl+yu+kSyYf+AWR6u+9QCtxxh7a1qpAdnU4fAqBngV3MEt4
         gqkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=pvQ+Zw6Eq43ttbAztpoJ+pLTjyBTBv0RhmPC9S/VJps=;
        fh=sHqzv2Id2AfQCwIL1KnFVFi1IhrtT70SmQsV+EuNIfM=;
        b=J2jKz+XtJFdWZ2AdfCois64AUY9s1GlVJK8pS8sjYD6daxrdyvRHSt7UQVf9dwbekd
         SskpvOkOEJn50AR0ai6dMqaF85aDG1/nBSovffMUG8lrfnF9ZxFO+Fp9PejtWLrIAPSY
         wMTIB9gI/nXu1RI0gWOyXXLHxfX2tkDZZ5wHPyMK8G4Vhj9KTR2xvrjbwg725FmLWeEf
         Pxv9lMI9ZpTdWiZ8dCDPV4ywI/R6TNU1V5Q8hajanT1N33INOQJDFvP+4BkYf573iD78
         TGpRChbnfCuSLKgloIlttNzMlVzYt00yNcUvuxEClJjuk00dAfxhUQS1iKTDIgr4l6He
         LxMA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=UBQFPbWH;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718293191; x=1718897991; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pvQ+Zw6Eq43ttbAztpoJ+pLTjyBTBv0RhmPC9S/VJps=;
        b=abuOQqXAdikxgF5oXB12riNNxchK64Z3N97BrBStiEzOGlUK+2yvOibOF+KbyJXusk
         U8BpioIkrXxTR/LKwW+uyZ2G/rt8touYG3aN0PeFEUbQoD+v43uMQ4sCVnfv4NtvYSgf
         d9ftL3ZBuJMVVOpsZUytqmaUvST2/rt3nBflDRQ7dnfFGMgJPG39x5b3pUVZS5U55MHx
         KmOq+FNUdtLjBD2pvX5Enkp361/K/7Zhbkn9VTYyhmiWmNeI1GBspmAGcvMRNiCHiEzN
         HxtUgWp59kSHki43s82jZssUZZE5McNMCbTGUPhb2hpRxJU4i7gB8PQr/LWNmcq9iSID
         /Ptw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718293191; x=1718897991;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pvQ+Zw6Eq43ttbAztpoJ+pLTjyBTBv0RhmPC9S/VJps=;
        b=lfGJdAgqgSGqjsz+7pwsfRPGYmbofGdXn8Ao33qZR5bRHuC2Hdjap+Q2F5MYRdKnGW
         Jv1SsaXeSFKqc66Br00EPA0Gr+cBxmjjTxYLuQXfzfnzRXnTl5uv5n5dtZ9VOgAJHDPX
         0O3ptfrazOBrcUApBU9mBSBiiMFiKOVNWmF2vhy6Bf8Wgq8p6PYPPpPuS5tveulchIFm
         TLq80kOomWkuZWRnDQV5drisSFOFGs2Ztm5wOJV6uTFRRk12qf/leZZWboYUUaIiTc1B
         +WoWtwz8g4eiVTmOsj9QizRUrO/hDkYFF0tZa+0kDSUmge8P10DjZJefYIyPMgKMLFXP
         Mzxg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVq9vCAA+cPhyECksV3IcQyFQO5z7dDfkFnTZp3k2+qOJCcq3EkbMpp54CWo5RSr+OtLkbc3xHNemPrMbf+XmlQyznHAuld8w==
X-Gm-Message-State: AOJu0YwLw6WCxZuyvRwXpyQCg5r/cHYsT24k4pntAsvHdHX6zgsEcAiy
	5cYY7ZuqteabU/jbI6H54L3BwTdNnb1YjMdfM67MGmuU2pXzJYzt
X-Google-Smtp-Source: AGHT+IEqWWYwcy5kr7y0kywZJyCDs4EaAdgjhp9OXs1qY4Qsdn+kMwDi+70EJqTv3DAQNLdLe7wT0Q==
X-Received: by 2002:ac8:5fca:0:b0:440:f3d8:2148 with SMTP id d75a77b69052e-4415abb331dmr58939371cf.1.1718293190998;
        Thu, 13 Jun 2024 08:39:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7d10:0:b0:440:3c63:76a8 with SMTP id d75a77b69052e-44178dca6fels14755571cf.0.-pod-prod-01-us;
 Thu, 13 Jun 2024 08:39:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUAU0N1J/PNjJNYuK8yA/LihvOMceiAQKu3hxWVoBmmKrrM/xMV+xAxI4W23ZNB0fN+O6AxdgdaVii2GiMRUkLEfFCB2+4Aqbl+FQ==
X-Received: by 2002:ac8:5702:0:b0:440:1c16:547f with SMTP id d75a77b69052e-4415ac5bf22mr59700091cf.41.1718293190305;
        Thu, 13 Jun 2024 08:39:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718293190; cv=none;
        d=google.com; s=arc-20160816;
        b=yAm0RX6YXgMUOBzWZNIbrBbCgsdDnkoPXuoT4ogxycn5bI4Fu3P89UaP2Nih56q+M+
         idqVaQqFQXRYJqw44PLyuaji8xST0V3pNdum19aanZamj3Q+2elyn6Kbj5sRJnGdyajJ
         hvvGyu1rEZKePb6+3J/aD1AAaRc6om87IYVTQOxWMIoymxiZ+xTN/14iO+bGxU06ERSJ
         cAZK5+v8ZaIMuwbR2r/Zpbjb21bS8Cfix4sdiuriwwtOQ7+TxDfI5h5LcTrtfv37g9QB
         NgWwlgb8ajOx0tp/hTcPCj6Ki2mirPNIIyUBTLCYJoux76gM2fG9hxCBzblbz0+U+Bqj
         MNRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=YaTjcojmIIYPSV3AqgAoZ8tGeMyuD+KvoajbKIBgv5I=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=t9e2jryvi6KMojRjI0+kCBotKsQ2bG0Jg9vVN3EDWGSRND3PNnW6vFGAEJj5qitf/f
         tx8Jae2YZAtCtTuawv77YVWl+h9Ab3L06yw8uKf1v/AEKB+xu8+KEpeVlPte8Vez+69V
         YKFEDl26gqLkMEn47nOFD91XV7PYrn/y2ta8FXZdqem+19bkVFu9/4Uz4HmiWKilOcKP
         nJSk8FCd4jBWzusElLT4HGASNlJFfJsvNX5zHLFOFt/VIOdHH0OTH8YPKljbMDR3fLWm
         Vd9cODYMnFml0FMMlRzYps3vxZFryWv2Nl5xYexcRvh0L+tTDpdujnvtqlQndTmTffeq
         6nNA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=UBQFPbWH;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4421145ae86si588671cf.1.2024.06.13.08.39.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 08:39:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353726.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45DCR4OS031281;
	Thu, 13 Jun 2024 15:39:45 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqq4rt36v-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:45 +0000 (GMT)
Received: from m0353726.ppops.net (m0353726.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45DFdid5026772;
	Thu, 13 Jun 2024 15:39:44 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yqq4rt36q-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:44 +0000 (GMT)
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45DEqSGd027243;
	Thu, 13 Jun 2024 15:39:43 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yn211979r-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Jun 2024 15:39:43 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45DFdbRo48890310
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 13 Jun 2024 15:39:39 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 4D82F2006A;
	Thu, 13 Jun 2024 15:39:37 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id CE30720063;
	Thu, 13 Jun 2024 15:39:36 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 13 Jun 2024 15:39:36 +0000 (GMT)
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
Subject: [PATCH v4 08/35] kmsan: Remove an x86-specific #include from kmsan.h
Date: Thu, 13 Jun 2024 17:34:10 +0200
Message-ID: <20240613153924.961511-9-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240613153924.961511-1-iii@linux.ibm.com>
References: <20240613153924.961511-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: I6lUMZaRn-eKqMWngW5wl1DQIlqcnkRS
X-Proofpoint-GUID: Punmgb6NwOmY9ZII4z-shjRaLe710KO-
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
 header.i=@ibm.com header.s=pp1 header.b=UBQFPbWH;       spf=pass (google.com:
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

Replace the x86-specific asm/pgtable_64_types.h #include with the
linux/pgtable.h one, which all architectures have.

While at it, sort the headers alphabetically for the sake of
consistency with other KMSAN code.

Fixes: f80be4571b19 ("kmsan: add KMSAN runtime core")
Suggested-by: Heiko Carstens <hca@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/kmsan.h | 8 ++++----
 1 file changed, 4 insertions(+), 4 deletions(-)

diff --git a/mm/kmsan/kmsan.h b/mm/kmsan/kmsan.h
index a14744205435..adf443bcffe8 100644
--- a/mm/kmsan/kmsan.h
+++ b/mm/kmsan/kmsan.h
@@ -10,14 +10,14 @@
 #ifndef __MM_KMSAN_KMSAN_H
 #define __MM_KMSAN_KMSAN_H
 
-#include <asm/pgtable_64_types.h>
 #include <linux/irqflags.h>
+#include <linux/mm.h>
+#include <linux/nmi.h>
+#include <linux/pgtable.h>
+#include <linux/printk.h>
 #include <linux/sched.h>
 #include <linux/stackdepot.h>
 #include <linux/stacktrace.h>
-#include <linux/nmi.h>
-#include <linux/mm.h>
-#include <linux/printk.h>
 
 #define KMSAN_ALLOCA_MAGIC_ORIGIN 0xabcd0100
 #define KMSAN_CHAIN_MAGIC_ORIGIN 0xabcd0200
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240613153924.961511-9-iii%40linux.ibm.com.
