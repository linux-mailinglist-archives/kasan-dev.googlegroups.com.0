Return-Path: <kasan-dev+bncBCM3H26GVIOBB2ER2OZQMGQEO6UTMYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 1710E91176F
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:27:22 +0200 (CEST)
Received: by mail-pg1-x539.google.com with SMTP id 41be03b00d2f7-649731dd35bsf1302406a12.0
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 17:27:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718929640; cv=pass;
        d=google.com; s=arc-20160816;
        b=mS7ECwpA+uTOVijlOFtyV/Drun4mvrMTTo+aM4VAsYV2LaXxwa5/V6BJxQNLY9rdBd
         cLYL24pmTrLbmb+sZHPqY/YNzoSxJXtiDmIK11/Ksd1x/PukgLfEBR9srn0xo0yLuJeu
         HVfO6g/YbTVMkVvmOB9X7lfmMSFUb7SJmQs86IaQAy7xdhxab8XzInvwqDuOeNmFIomA
         rlXY8mvlaUfBQhenh4eAmcJ6tTSrV21AAgj750dw6UUZIw8cuan7JitGzHh/CgR98Z0k
         HExUhmOSIldR3/w5UDT7KB64YBFEb7uYO7CamV8wH+wDBo2s3Zbqjz4SRQToQueyKN2X
         Uerw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=NsBlJB3zwN0OpqGn9fuKcZSyoCdZNTFNnh0C9NvoPYM=;
        fh=oMNd3qsyTn7l2T5eTtiyAyvthutaHd1GnnY0EKkEmR0=;
        b=I5pfGDXRvEusV3RyQ2NQpZnvzqHO+IzutJQV/Qoyt60YVdDl17raG95lrsBkbF5RCw
         8pXMvDHKwZmpwwNizs4weMHKxTLbBhIJMf/iNTocVcnuD86FwsOz7aEEc/k+J8MQhAsu
         AgL6FqVVi/PTBLwaHYM0jhd1UI5akiIqGPtBSe8e2g62kgA5H8oO4Kysv/wZT1HdQ4RS
         v/v0cux3yhC4nhJHmCqgV2JWWndfZC0EeIKM8BqzRTqV6hseAIfWgC7jYFXC+8+JC7p6
         dglEm2SYxEo4SGbchhkymLVdZpmnm5ogG9WlgnLalt6xtl92/Yo+6LGur51++wJEdfIt
         1rgA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=PrZp0P9v;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718929640; x=1719534440; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NsBlJB3zwN0OpqGn9fuKcZSyoCdZNTFNnh0C9NvoPYM=;
        b=oGXdKiSBOXmQohLWV16I+dlQkfniLL3uIoR7L/tmdYHgvWTasDjkztDEzbCbHEqthY
         KdJLYIWDCnzbEcACZZMezxzeJr4ZbhiKC7P4xqoqImL/wsDMsbXJGG9RladIKI0jMwTW
         fgVi224zFP98DuvxavwQh5k+sYq/gNOh1xmS8Hugr0aR1bTjxnh40cDRBbOH8nDSS4Jl
         dveis2l7mOdqNT/xjRFWMFrJLYnGX5Tj5V3mS9igVCPUf4iHBFuLEaurUya9M17wZ9Bs
         o/lgYXuL+XXbNI2TYguVkasuykTGZzKRBC5agUZfq+F7I3Q4br3caMA611t3QyncSaFw
         monQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718929640; x=1719534440;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NsBlJB3zwN0OpqGn9fuKcZSyoCdZNTFNnh0C9NvoPYM=;
        b=cxmj92M1MvY/0W0OX+ohfRq5hMFeXMrkMESaJ1PmOKafJRkohybhYP/mzIQNdIV0Fj
         4RXbW6Vtaacsc5Sk4kdsVem4t4DRJFvHLmjmIqrp4aXleNxtJB8MVV+6hkZ5RKrXf/kb
         gsNWnJonIN4fnm9Ug7HbzpEyAKj4UIgXXckJzDOhy5HK8026WCKA7oJi5Dai5n8X/nnx
         l73yBzsP8Nbo278Q4mJeG56M6GALEh05mBtWyDY41pf4T+KD6L6h3lQUbD6T7IvCsOHn
         TN+ERaBwwmBnCG8VyYRNZP3WwAsSJPTkHL5NSNNk+FNqbza0eabYfAuQZNLnXq4dd22b
         +8Rg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXAULKVlewo6WRTcDpLXwekSvyvTUYAdGcVhitXQaptkoLY3xVcPeVQq9JfUZN4DiyLZm5NqRCTxp2eSq90AFXB9yMK5W3F6w==
X-Gm-Message-State: AOJu0Yyf2EXRau+nvSgZUC+OzWEvDC/xzKT20gIyzjJ9zaFfsYrErWjN
	D9N1xDJCm35M8Hfx43WywGsq8K0Oqq6uwBMeqTNFwW+PxeGsmNca
X-Google-Smtp-Source: AGHT+IGvfDoKbNB8NfsjjXw06AAp8I5y9ZM/GH3CPbfe9jQVs0WkdzveM3Wh4Bw5oQpVK5CEz5rzYg==
X-Received: by 2002:a05:6a20:1930:b0:1b8:831f:c684 with SMTP id adf61e73a8af0-1bcbb6ab0d0mr6582157637.53.1718929640494;
        Thu, 20 Jun 2024 17:27:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:364c:b0:2bd:e914:8fe1 with SMTP id
 98e67ed59e1d1-2c7dfbe9ed0ls826794a91.0.-pod-prod-04-us; Thu, 20 Jun 2024
 17:27:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXFqiuNhcGSbvDbroJ4vbLXlV9EAG63L9llNMZOBGjjO8GTvr8bCa9GZgH7wE72zGlSurZFqIukt1G42g8KnJrz9kQQDJhBALkQgQ==
X-Received: by 2002:a17:90a:fd98:b0:2c7:a8ca:90fb with SMTP id 98e67ed59e1d1-2c7b5c98326mr6747582a91.29.1718929638996;
        Thu, 20 Jun 2024 17:27:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718929638; cv=none;
        d=google.com; s=arc-20160816;
        b=q+Gy1rhzgZiVwuAT2MKSqLQjHUjbQJQAUMZHnYyF638bQvoLgKx5c1A/uJdbtZvgAL
         pAUXiOflh8Dm/AnDnQ8lFLY8oNjCfs0747kqJ7oQh3XNgh6LKBPNy0yZ3m8BO1GBrsUP
         KOXpSVJKqP/u2jLJCM/xonN7wZ+MiqP8L2QgUieOZh1mGtK4os7ftNiOvzeZzzzekxMO
         GikXXaX3YlKCSHbtn7Ie1xo1ccmjAihmCKNzTmLnynmL6ZYoncgZoFUI6HwMfY/Ws2Kw
         5LRiiSjO8fTvTj9DTuHQE6Pi50bX+oIsbrL8yj0T5hVfT/+K9/eTBA1KTosCYV2RKf+6
         yL/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=dJTBCTVm+DYwwDfuPqhjkMdDHVgbTJOgQUj+bRO14r8=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=lFIVKerkOADIcoRQRRjli9uWmMYc8vOCm+KL+mQTIkRtXum/eyjQvukpGjd6Qeimi6
         N27BPP5sCmcu653mcDb6xeFa30H1+fDWDYvBk8hbfhtcd9XQKdHNFNRG0ONft4dKyMIS
         9lxTlqA6d50kdmiStwSqaufj0JNI+3w8pjWDIEvPjvVNlhg2mljvGkNx3CcVDg5EqSKj
         YHAnTmdhxhgEO87f/iFQqcmvhUFYjSLxA8G2HAVByRsajam+U5kyD/XFexpJjldC3B1Y
         tLFcLX4z8b1jwp0FeNr83mD4sRayvGwQ5PIQNH5eWKfClUr+570L6GvuBOEt/Q03yPZa
         wbRA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=PrZp0P9v;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c738c1d4bbsi456206a91.1.2024.06.20.17.27.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 17:27:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353728.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45L0RD1Y009176;
	Fri, 21 Jun 2024 00:27:13 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvw8c876y-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:27:13 +0000 (GMT)
Received: from m0353728.ppops.net (m0353728.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45L0RDWT009113;
	Fri, 21 Jun 2024 00:27:13 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yvw8c876t-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:27:12 +0000 (GMT)
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45KLiBxN007687;
	Fri, 21 Jun 2024 00:27:12 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3yvrspamsp-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Fri, 21 Jun 2024 00:27:11 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45L0R6rw56885562
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 21 Jun 2024 00:27:08 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 7450120043;
	Fri, 21 Jun 2024 00:27:06 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 5446D2004B;
	Fri, 21 Jun 2024 00:27:05 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.44])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Fri, 21 Jun 2024 00:27:05 +0000 (GMT)
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
Subject: [PATCH v6 38/39] s390/kmsan: Implement the architecture-specific functions
Date: Fri, 21 Jun 2024 02:25:12 +0200
Message-ID: <20240621002616.40684-39-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240621002616.40684-1-iii@linux.ibm.com>
References: <20240621002616.40684-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: qJzneyKICj495LR47ihcGQ3AFyfHC4KA
X-Proofpoint-ORIG-GUID: DAUWdLee_Gr_anSc8J4SE-nczW9B-DNE
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-20_11,2024-06-20_04,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 adultscore=0 phishscore=0
 mlxscore=0 impostorscore=0 lowpriorityscore=0 priorityscore=1501
 bulkscore=0 suspectscore=0 mlxlogscore=926 malwarescore=0 clxscore=1015
 spamscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406210001
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=PrZp0P9v;       spf=pass (google.com:
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

arch_kmsan_get_meta_or_null() finds the lowcore shadow by querying the
prefix and calling kmsan_get_metadata() again.

kmsan_virt_addr_valid() delegates to virt_addr_valid().

Acked-by: Alexander Gordeev <agordeev@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/include/asm/kmsan.h | 59 +++++++++++++++++++++++++++++++++++
 1 file changed, 59 insertions(+)
 create mode 100644 arch/s390/include/asm/kmsan.h

diff --git a/arch/s390/include/asm/kmsan.h b/arch/s390/include/asm/kmsan.h
new file mode 100644
index 000000000000..27db65fbf3f6
--- /dev/null
+++ b/arch/s390/include/asm/kmsan.h
@@ -0,0 +1,59 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef _ASM_S390_KMSAN_H
+#define _ASM_S390_KMSAN_H
+
+#include <asm/lowcore.h>
+#include <asm/page.h>
+#include <linux/kmsan.h>
+#include <linux/mmzone.h>
+#include <linux/stddef.h>
+
+#ifndef MODULE
+
+static inline bool is_lowcore_addr(void *addr)
+{
+	return addr >= (void *)&S390_lowcore &&
+	       addr < (void *)(&S390_lowcore + 1);
+}
+
+static inline void *arch_kmsan_get_meta_or_null(void *addr, bool is_origin)
+{
+	if (is_lowcore_addr(addr)) {
+		/*
+		 * Different lowcores accessed via S390_lowcore are described
+		 * by the same struct page. Resolve the prefix manually in
+		 * order to get a distinct struct page.
+		 */
+		addr += (void *)lowcore_ptr[raw_smp_processor_id()] -
+			(void *)&S390_lowcore;
+		if (KMSAN_WARN_ON(is_lowcore_addr(addr)))
+			return NULL;
+		return kmsan_get_metadata(addr, is_origin);
+	}
+	return NULL;
+}
+
+static inline bool kmsan_virt_addr_valid(void *addr)
+{
+	bool ret;
+
+	/*
+	 * pfn_valid() relies on RCU, and may call into the scheduler on exiting
+	 * the critical section. However, this would result in recursion with
+	 * KMSAN. Therefore, disable preemption here, and re-enable preemption
+	 * below while suppressing reschedules to avoid recursion.
+	 *
+	 * Note, this sacrifices occasionally breaking scheduling guarantees.
+	 * Although, a kernel compiled with KMSAN has already given up on any
+	 * performance guarantees due to being heavily instrumented.
+	 */
+	preempt_disable();
+	ret = virt_addr_valid(addr);
+	preempt_enable_no_resched();
+
+	return ret;
+}
+
+#endif /* !MODULE */
+
+#endif /* _ASM_S390_KMSAN_H */
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240621002616.40684-39-iii%40linux.ibm.com.
