Return-Path: <kasan-dev+bncBCM3H26GVIOBBIOS6SVAMGQEGKAYIQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id A78547F38B0
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 23:03:14 +0100 (CET)
Received: by mail-oi1-x23c.google.com with SMTP id 5614622812f47-3b837ecd566sf861893b6e.2
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 14:03:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700604193; cv=pass;
        d=google.com; s=arc-20160816;
        b=d0PhN8YndqgMi+qDrk28e9GqmhJ0vpXtuVr/ekLiurUJ+qy1w2QpZi/7QbxgzQ8Iwa
         8Gd/qLN6GfSmslV1zywrXHyi5m8l/CZsm7muajOGQ9pI84UFKSvnR6QAi/YJnHTl3RTz
         QrMj6ZFZT+tqv4aUaHpJFBmAD1/BogHEqzZSVoAwYbDR+yGPgkd6yPbM0kWMJ/i8TPla
         p/ABufNvwOF6p1n5+AN2HfWffHeyMva5hOkFYbncduA7hIktmV5rScr0BH/fOIu2kdz2
         ERbQce5QFfZ42nGmeeVXeC0tLavo5U5+wf3AqK7eiHJoLwXNP4kyU3Nf38H2Xfi05feR
         jtUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=DUnI56OE0XvChTvHJft+VjRs/ZBEr+6/ZkvpdPfTTQE=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=e6t0H9TYUf+ep+ELwzJ9hFRbLooQgk1+J/uFe9ICqp6kgXo5DjEAUwGB0wtjzNiCfv
         BLnJ5pkpAq1Gc404cqklLoMxHIJpJ0oiIasS406kDcgeKdRy0PjS1Yq6/Dh7ca52aUeL
         Pl8d05pB9YZkWTend/vd3uJArn1875H9aUFAikBNuL3F1wCxHJiUiLmGlN9MZidI5THe
         uJglp98McSqQ+YWaf0XCUgoGqaD3lIb14JIoiXLILDGFa17mll4m+9alPLe7/K/I7jYt
         7Bdt/fykbebVJoajsD5K4dhRjlvfOK2/wF7tIpc4P8+0uF6DtRjiYPHac2D6MJr5S56q
         2c4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=l11+MRge;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700604193; x=1701208993; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DUnI56OE0XvChTvHJft+VjRs/ZBEr+6/ZkvpdPfTTQE=;
        b=hCd44gAP4132w4UPri8fYdpha3P1d45PlCa1102//ahVTUOEeO+we/91ND5bRR5s7O
         f0A12ca+mxE+y7tIdKtg9cz9ivSaLWR0x9uhXug+Zco0Ad7FZGkc8uhcnVctlmESqr20
         uxxEAwOIEVwzA/hF4D/0lZbs/FplYPTFAuxbOtK49kvQQXFeGgj0i8b5k1I1SlC2CPts
         vsYaSZziHNT+k1f8MeuX7jWxx2iYrKmbTU6EK0X3TV1tqLDcLONy96d1taTxZoD5DtKU
         EHC8Z4FJqgPaP2psKwt/dzLKFXSCWSWis/hPvX0j+1QoD9VETavp8Og71N61JRL7de29
         XAzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700604193; x=1701208993;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DUnI56OE0XvChTvHJft+VjRs/ZBEr+6/ZkvpdPfTTQE=;
        b=hCQrUzWn8LIXEle9HYnBlqM+YGAoyGkgUVhotVV1NDFOU9R8r4fOHNrWMsSdLCVng5
         4LCs2YzDNg4alN1ZQBAN3xGsGmfx99KLXD7ne09d91o/vsdMkiCQxXBv8AA6x7nNRMTZ
         BRKFCaiuc176GC87TGkyTQ87CtTPkPddHmYJ6fH+mi7to0vFL8GlzpXPQYwNqnS2Z3BE
         OzrBQ1xrclmCc6tsNSYXpmD5vWghXVtOjvkqlujqh/e2eH6WggdMMNE4wzmRsE9Nogv+
         OUFUAWIJ7tWJGf1P4n+PcCeGSfUl1xcgRkauRZkLSCL3+inJnP3vGuiu3FgeJcs/dg3O
         1oFg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw/lPGEpprVbM4bImy5FiT2EFVE6GORq3AP3GLL2zYHH9QZkNQO
	tttLmzX9hA7p/TbDjVD1k2E=
X-Google-Smtp-Source: AGHT+IGOkV5+lpRto+JT9Gw+UMTOPwSr4VdMJf5vCAxMnBe3QKdHok17E2tmzw1JLqrDep3cZgmO9g==
X-Received: by 2002:a05:6808:190b:b0:3b2:dda7:d2b8 with SMTP id bf11-20020a056808190b00b003b2dda7d2b8mr817062oib.2.1700604193495;
        Tue, 21 Nov 2023 14:03:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5ac3:0:b0:41e:8c36:f7a3 with SMTP id d3-20020ac85ac3000000b0041e8c36f7a3ls474723qtd.2.-pod-prod-03-us;
 Tue, 21 Nov 2023 14:03:12 -0800 (PST)
X-Received: by 2002:a05:620a:800d:b0:77d:619d:536c with SMTP id ee13-20020a05620a800d00b0077d619d536cmr412508qkb.25.1700604192465;
        Tue, 21 Nov 2023 14:03:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700604192; cv=none;
        d=google.com; s=arc-20160816;
        b=VsT61NdeDawiNHq2AKgd1AG6Km3dsf2wSjR8ftgcFctn9WK498Mi44VS5jXG8M9Fnv
         3+R80zdppWrXy1NltLZJSXLmnLLpG5+2HCjBT88O1p7j32KAUaAMo+6kHyNAgXym/zHR
         Xx2/7tjGdYhch/Zj5nEoDGjokF1VJ8UNtFHyjZ2hJtNN52I9yGF2TmFdyz+MixGXmCzZ
         dbhGxDfN/EBUZ7Id/bielzrts9T/f7qOfzRGEKlym2CaQDSSuG+8z53aS7ZRXCmwkzY1
         xNCBsSQEv7dVmgJiPRdL9EDdFt3vjMeK6O0I4Mcjj36pU6k3KRR7Le4y461xBkPeGenn
         E7Lw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Z9QhvajxwNq5SYGaSMflClifwELAA5o+VrikMt43NLQ=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=fbs+hsoJSDu/5TDSFABUyfYHa1uFPBLzGa+eS2RXXugBLgYNfdTDINvJ3fgI+NCTtr
         wHpo71qsVjnTG5qxRrTbythdTbMI4u6cY342at4OlWCaHZ/ANrHwgaCHk1MGYdljTOaE
         GReMGGYQmX8XmVq2DElGI6hboPWxTt9vqjlkIG/N+KuaZ9OStWppypXvvtRBMpb3LQZC
         VVCe1l0wwSBMaj+0iU5Ywff6mnqqP0X1FtF3jN+2r7gQWDXtkEjcRXAju/5Bvauc+Xcb
         FzCmC3Qyz/KAw99pByoBegbm+gdAhqqLw3lsELl7XDocytYmnECwemP40NDhYqSY9TJw
         yCpA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=l11+MRge;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id rj10-20020a05620a8fca00b0076821b38450si722750qkn.2.2023.11.21.14.03.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Nov 2023 14:03:12 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALJbuS8004668;
	Tue, 21 Nov 2023 22:03:10 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh2vcjy7n-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:03:09 +0000
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3ALKjE9N028451;
	Tue, 21 Nov 2023 22:03:08 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh2vcjy76-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:03:08 +0000
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLnVHN010621;
	Tue, 21 Nov 2023 22:03:08 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uf93kujw5-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:03:07 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3ALM348S8127018
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 21 Nov 2023 22:03:04 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id C129F2005A;
	Tue, 21 Nov 2023 22:03:04 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 5885520065;
	Tue, 21 Nov 2023 22:03:03 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.23.98])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Tue, 21 Nov 2023 22:03:03 +0000 (GMT)
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
Subject: [PATCH v2 32/33] s390: Implement the architecture-specific kmsan functions
Date: Tue, 21 Nov 2023 23:01:26 +0100
Message-ID: <20231121220155.1217090-33-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231121220155.1217090-1-iii@linux.ibm.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: IyGjYQWbcfWcSL9WVWtmI84_83T8peyH
X-Proofpoint-ORIG-GUID: NS1pbt6R8Eh77F39tcogaOWXxwBiSuqE
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-21_12,2023-11-21_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 suspectscore=0 spamscore=0
 priorityscore=1501 mlxscore=0 adultscore=0 bulkscore=0 mlxlogscore=783
 phishscore=0 clxscore=1015 malwarescore=0 lowpriorityscore=0
 impostorscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311060000 definitions=main-2311210172
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=l11+MRge;       spf=pass (google.com:
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
 arch/s390/include/asm/kmsan.h | 36 +++++++++++++++++++++++++++++++++++
 1 file changed, 36 insertions(+)
 create mode 100644 arch/s390/include/asm/kmsan.h

diff --git a/arch/s390/include/asm/kmsan.h b/arch/s390/include/asm/kmsan.h
new file mode 100644
index 000000000000..afec71e9e9ac
--- /dev/null
+++ b/arch/s390/include/asm/kmsan.h
@@ -0,0 +1,36 @@
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
+static inline void *arch_kmsan_get_meta_or_null(void *addr, bool is_origin)
+{
+	if (addr >= (void *)&S390_lowcore &&
+	    addr < (void *)(&S390_lowcore + 1)) {
+		/*
+		 * Different lowcores accessed via S390_lowcore are described
+		 * by the same struct page. Resolve the prefix manually in
+		 * order to get a distinct struct page.
+		 */
+		addr += (void *)lowcore_ptr[raw_smp_processor_id()] -
+			(void *)&S390_lowcore;
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
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231121220155.1217090-33-iii%40linux.ibm.com.
