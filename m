Return-Path: <kasan-dev+bncBCM3H26GVIOBBJUA5GVQMGQEV3HYX4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A52581231D
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 00:37:11 +0100 (CET)
Received: by mail-oi1-x240.google.com with SMTP id 5614622812f47-3b9ed87a1fcsf8295890b6e.2
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 15:37:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702510630; cv=pass;
        d=google.com; s=arc-20160816;
        b=SnpZYGJtg5LLotlGQk03Sd1ZvhbQVL0fP1W1jfomWVILwK55WyR1HVGgKpUH1Yj0Ef
         UOkv+D82B9si0qrWJ2wJ1nMJomjh5iPK1cnfSh1BdXwsbU6iiuFsB9T6zzFeS4XR/Pbk
         SaoJ7pelYf1rHqEbnY7w4HkLEj629YvMFQdfYDBt+g/QVDW371Lxoo4BRCeSxiVdggl+
         DGpjIxZEBzDIcdyUH0Xb1ubKBZ2LGVFnnK1GnepYNlsCjvTQJoSApDKywqtUGWkNBv7i
         hI8KlqMBnWcD7uqzm0g4egoB0ergax6G5vY6NwoD4MQt1EBydHfu0/4u6ZY0bRcPDOdc
         fmVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=39dQSZhBqwEGS3nBTPOWjtQ/lozLeB2JwPxCoxHPqpQ=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=tGA34qqEgQWW+UYvjaHjssEp96Hx0oxqwCPJ3IltOv5U0/218pdVnTJILogs29cR1V
         maK7jKVSmjnlpsS0RH0oTTwPReWdc759J2x+N+Q/8l6uTs9NDsfVaUSEKPZG8Hyvlg8B
         Eh4miZRHDVOab2icqirz65EgGhlVyAAHyUweMLljMi4+dhybTg1AvmVo4TwHV9BbVj1P
         H835d/gPPiueoqnqp9CMB1dyqgW8u3mbD/2txAHD/oyroJDXms3994Nvj8yRQi/jwxmG
         1OMRqV9KuY4FAbZn+zw0EzybXJdOJl31SKZjHqXLAfpLkS6WWqUPQSAa677iMQAbthNN
         yEyQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=SoVtm+ks;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702510630; x=1703115430; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=39dQSZhBqwEGS3nBTPOWjtQ/lozLeB2JwPxCoxHPqpQ=;
        b=Masy9Oh7No/LwDEUbCYZnwEdPND2OV7vaBi5PwobKhJcGiAjroT1GoWlxgrLYW5NS8
         jfC8fonQT8n69MKZKgxgWGMRpLsDACbOjUckYUGCBs+5Wrc0jDIzgbhkJM+3wjAQwdr9
         MsITq6YF3kcwtFQp7OWQ9Se23unSrTrrpxyCuAM0T4cO2CDFJwQSiMY15uhXCgUqrXtZ
         e7126R1WuwyB9ppRN0INE3cp7aa9id+RMGDddpaZmh9dC5tEEzLMeuY5hLL6cQgqC0cQ
         INDQ1IidfervEa/pBQQejQMq9Gcg0alkBnRenCUmmNkJqj8Arlth5+3hxha8QCJnUBlE
         zeEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702510630; x=1703115430;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=39dQSZhBqwEGS3nBTPOWjtQ/lozLeB2JwPxCoxHPqpQ=;
        b=PO7WB6noKnQynst82H/OEaQhrL+/2iqRSAkRt3yIBvxxbUVg/6B3HOzEsmVwrPWqa4
         Y/apNRO7hLniP9/imKYSuo7fZc7YRk50e0czJOWOaM2rBm3XrP2xuN+EMUa+c+dTn4j4
         wirV5qOWI3i0KEmNaKLaDfCjD+eDuE5wNIdJGBEac3sZ6lwCZZEZ5m4FUFnILbmjKlIk
         nd7+lqxqjTkcCOcAVuO3ByBewdbaUEdX3A0Uy9i/zprJFF6pkkOa3tEeqA4pm+IB4OLv
         IytcIL40qZwoUsQfJkaJRvmJ+GJjHzuqa7aeb9NCdYw+C/OYnEZQ+j1JQ5wirEBJxPi5
         Z+eA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YykJz+LMrnf7kdsKQWkuox8ZXgEwaOcP1TrExj9vELmTmzu/7UA
	fg8vjSGK3uSaQH6gQga3pGc=
X-Google-Smtp-Source: AGHT+IG/NnYYr+FzyaRE4S9TybvUZ0ckUONOyX2TX43xovI0d9pgf32zeO2DRL34OyIXkAbo1eJa+g==
X-Received: by 2002:a05:6358:880b:b0:16d:a668:bca9 with SMTP id hv11-20020a056358880b00b0016da668bca9mr7969872rwb.11.1702510630297;
        Wed, 13 Dec 2023 15:37:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:5e08:b0:28a:fdc9:d4ee with SMTP id
 w8-20020a17090a5e0800b0028afdc9d4eels376435pjf.1.-pod-prod-02-us; Wed, 13 Dec
 2023 15:37:09 -0800 (PST)
X-Received: by 2002:a17:90a:53a3:b0:288:76d7:4237 with SMTP id y32-20020a17090a53a300b0028876d74237mr3732644pjh.92.1702510629135;
        Wed, 13 Dec 2023 15:37:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702510629; cv=none;
        d=google.com; s=arc-20160816;
        b=o4nZsgnM8M1bx2qD5ZDIlOGnlJB6lG0MLn7eYy1i9DZM0hAaP9RdOWvzqYQJl+hD5F
         JOJVtAcpUVuC9Tj4OjklYeMTEwLdx+fygKO7eDqtQeCLeGuGhqXXvJQ9HPYHydkY9fxw
         aVG3gOgfvlNHPMIsoW8scVn7hjsoJ3og9ouO9vM64iI2i89gfTDioWBzFtq8/S9ykmsJ
         CHOxiUddYFEiGHayWJmucDjlzt5lEvmMQtgp8xl1YgnH99g4CCim6nYoTKYSCo7/qQgv
         yQZTjWbSXamqC2wyRkBpuqlvkNgsUBT8l002Ugw6SVqZLAG93tUnktR4N5ID7aNe4lXi
         Kkcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=9DhmnRDZHM0G/+zJ9vPg8UIv4Wxto8sqiK6z/T5p8yA=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=U5JikUxwIhsBr4KDfdpd7D3Z7OQ4f/NX13IAZsC6wwR5hh+pyaLttmYcr0X5cPPsrZ
         oqttwGbyrMjRZ0v+LeFj7kBLumvU36rEpIJBhxhgoIkR9dK5L7m4/WS7o9dlF/UJtCJ1
         avFe2NSPY0EHCjnEZiCzVq6LeMl6yH9J2kK7wkFwSINZQWucuarCDs3B7OUYJ2IGvby3
         6WUhMxt4Y0WoEyIhjLTAVkfslVgjI/RtVzQUI+vZYVglE52f2jNW2PZvXBKlrp6VN04E
         3uUVP5DZ3DkMK1aIwXQpagPICXkhpcpH63rAfM5yeQR/spxohq2KGA8EuL4fNCoRGnbu
         0gTA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=SoVtm+ks;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id y9-20020a17090a8b0900b00285b65a9b31si275585pjn.0.2023.12.13.15.37.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 15:37:09 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353725.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDNWgUP006776;
	Wed, 13 Dec 2023 23:37:05 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uypce8257-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:37:05 +0000
Received: from m0353725.ppops.net (m0353725.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BDNaaPL017559;
	Wed, 13 Dec 2023 23:37:04 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uypce824w-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:37:04 +0000
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDL5lwv008450;
	Wed, 13 Dec 2023 23:37:03 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uw2jtmvre-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:37:03 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BDNb1fD20644524
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 13 Dec 2023 23:37:01 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id F0EE02004E;
	Wed, 13 Dec 2023 23:37:00 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 8D08420043;
	Wed, 13 Dec 2023 23:36:59 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.171.70.156])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 13 Dec 2023 23:36:59 +0000 (GMT)
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
Subject: [PATCH v3 33/34] s390: Implement the architecture-specific kmsan functions
Date: Thu, 14 Dec 2023 00:24:53 +0100
Message-ID: <20231213233605.661251-34-iii@linux.ibm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20231213233605.661251-1-iii@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: qiAanGtjw_k-Ynk9arA87Z9sLMA4H9mO
X-Proofpoint-ORIG-GUID: NB6qBGtqheS0YkDLhpLmLgpssbWag-y_
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-13_14,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 bulkscore=0 mlxlogscore=726
 lowpriorityscore=0 adultscore=0 phishscore=0 mlxscore=0 suspectscore=0
 priorityscore=1501 clxscore=1015 spamscore=0 impostorscore=0
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2312130167
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=SoVtm+ks;       spf=pass (google.com:
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

arch_kmsan_get_meta_or_null() finds the lowcore shadow by querying the
prefix and calling kmsan_get_metadata() again.

kmsan_virt_addr_valid() delegates to virt_addr_valid().

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/include/asm/kmsan.h | 43 +++++++++++++++++++++++++++++++++++
 1 file changed, 43 insertions(+)
 create mode 100644 arch/s390/include/asm/kmsan.h

diff --git a/arch/s390/include/asm/kmsan.h b/arch/s390/include/asm/kmsan.h
new file mode 100644
index 000000000000..e572686d340c
--- /dev/null
+++ b/arch/s390/include/asm/kmsan.h
@@ -0,0 +1,43 @@
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
+		if (WARN_ON_ONCE(is_lowcore_addr(addr)))
+			return NULL;
+		return kmsan_get_metadata(addr, is_origin);
+	}
+	return NULL;
+}
+
+static inline bool kmsan_virt_addr_valid(void *addr)
+{
+	return virt_addr_valid(addr);
+}
+
+#endif /* !MODULE */
+
+#endif /* _ASM_S390_KMSAN_H */
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231213233605.661251-34-iii%40linux.ibm.com.
