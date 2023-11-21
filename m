Return-Path: <kasan-dev+bncBCM3H26GVIOBBEOS6SVAMGQE3UZ4YZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id AA8327F38A6
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 23:02:58 +0100 (CET)
Received: by mail-yb1-xb37.google.com with SMTP id 3f1490d57ef6-da2b87dd614sf7930389276.2
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 14:02:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700604177; cv=pass;
        d=google.com; s=arc-20160816;
        b=rRWWljzE4rNqh9HVY9HcZGD4rs0gvTNmuw98uhZ/AdNf5BZ4uwu2F3C7JIMWJdNtJm
         AUGfBYPfumI3zqx/2bCjhg9KMKiXuWw96Vu6D3GLIa0ZZj9h3eptLJug+FdoNt9LoEe6
         yWd40VNN0ERB1i43OD42Hxysx8YtTAyVE/ikngZtfLwnYcvai9L6Awbe+qpif3COCxIb
         +ThWTOOXJG7u73EAyBE7C2RpHTwBbUWEMRS1dCCPERTIyWHpc/sp7khnmDTYvwhcrUko
         CdUqaCpSp2hV6X4+UKZMIwAgBbi66OVzq5cqyC4wN+o1VFP8OfRQEo8QydIfqnWlwhZG
         ONDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=3ZpjWSENhgVY43wb9G6h4IPz6Cg9R8X7Uk3Rddv8hFI=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=X8neZPfzsGRGximUvat5WvlLQdQfX/0Q8aL/zjnBeQuTMPZY9JGpHLMHtgPZhYjVrr
         5U4e3XzV5ZBrY6mSMCmxNnOrVVQVh31ss5OF4/+vBxoLaoZVT0QeSInoiIbqHQtgdAZ0
         Hr3HM8bbic6dHNDi6+4Cp/Ujve3OSHTaafvyxkuTxTUafAEeDVc09f4pNcfngIHtgU/w
         JXI5BehNA97Ma5kOWI7wd3MqCYd6QYdAtss/NypPzKry4oSsbKgM77mk7sX+BYl0pK9W
         O9RPvwvxTfGkX3xWBpbqNO2dUW2PvyCYhD0B4EqD+kiTPWwQNxIP7WdX3snx8uibGB0U
         MgZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=IzMejt7N;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700604177; x=1701208977; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3ZpjWSENhgVY43wb9G6h4IPz6Cg9R8X7Uk3Rddv8hFI=;
        b=v2tkmmWTvQwK+LvfeXuqN9Zoc4/3A9OSoVVKGpUbiWbzIlB2Kir3KTHDrXiMRNXRa2
         KwfcLNrr9nzLxd9pzyurVnEZzmFUgwKkAGUA038wqKrgqu9lVGADtnA4extaYaFUnxrm
         v0GdAW+gD0khZzpmTRVmsH1a6Xv73vcZ+R5eGK7ImUbm30Wgu60tz5oUDNjSk3RJgtVG
         MnAbfFKEPmPNYNXsjbn30/6qU/C9nxhD6Fk9lHZCI6XC+ZSsznPSC6He3xffcyalBcXR
         DEp76q9KRWTYs0DYhYV6/FNDWfImhXyX4POyp8wgh7RJ3m/BxTJ31tyIoFa8Ow6wtWJv
         gf1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700604177; x=1701208977;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3ZpjWSENhgVY43wb9G6h4IPz6Cg9R8X7Uk3Rddv8hFI=;
        b=NQ6OU0KwqmXnGpgBqFSd7KaRSZgdOl2AP5h/8GkW6iId0kvjidUzOt70nG5wvOJ3t9
         x+Vk0LnDYJkAE6MxlqDnTHfL2lxu9VyKBkoyLtvOh5rTxMNGDW8MVLxghfcKnGSPV7pE
         SK1zrUnBVleXEa4IgoHeuZTVke8QOBWdmcTfuDFCAmC4UoAOoDSpRVMgDVXJVXAAFLNz
         jJ5xiJmSkwZ8Mk0t2mN9xdPjU1I4jHYzP2NmChNngFYW0Mg+hfXtJonW5iq3J613xuRS
         faPcV/1mbJH2j96ujOJR5s2C2aVSsoNJT9et2jIpXFKRa3A9jjfoi29I8+7V792miGlB
         MRSA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwdLL16ThpfXwoy5g/L/gFpMdJp4mwxVbKxc6WrvGStrEix7QGh
	9FQPdDRg3uwM7F8u9C1kfFE=
X-Google-Smtp-Source: AGHT+IEyUMawXcE5vO9IUOC9WjpOiliYzQFSl1di3c4PykTjanTnjqWeswoS+3QB6wvu/du7xncesA==
X-Received: by 2002:a25:2d8:0:b0:db4:1cc:3ffd with SMTP id 207-20020a2502d8000000b00db401cc3ffdmr71312ybc.52.1700604177425;
        Tue, 21 Nov 2023 14:02:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:7758:0:b0:da0:7800:8cf2 with SMTP id s85-20020a257758000000b00da078008cf2ls781750ybc.1.-pod-prod-05-us;
 Tue, 21 Nov 2023 14:02:56 -0800 (PST)
X-Received: by 2002:a25:8908:0:b0:d32:f2e7:7786 with SMTP id e8-20020a258908000000b00d32f2e77786mr286788ybl.56.1700604176556;
        Tue, 21 Nov 2023 14:02:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700604176; cv=none;
        d=google.com; s=arc-20160816;
        b=J8w+gDjLKo0waZ8ZJ7LRfPTV86elCo+ll44KLvPJTycorNJ0611gIlGvu8IvYFBZcI
         KUTcmSqC/33aoTuvm2JzlX/PgiTVVwYGM7HIstKtT2po1QWw9fJdJSZ/sSP85DVCIToQ
         farXDY3PU6Sq0CKUQU6xh2kQdx0OnKOKhqMlRU4TGikTbEk1ENw5wY3t5tTANbreMHUv
         yvsrPgUjoVEmk551zYoiCcSuQw5Ps/VYMTB0+nihajSMFGyy8ZCE1ddrF5OAqK761fei
         lMycDraa2yAFW7BbQQrU0hHfgzB9iVSdx7bg1KpYXCs7mkq9wrl6Nhff7JQytX9QAQdL
         3cWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Jw5Y1HvNWq7xyQLWYP0uulKSfMNkdY0+zz8uCuv3y/0=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=n2w88k3/V749JNzalzFq4pU8lg2gexDQ6kmPYzp9Qe2uRIUy9sA34K62hc1skzFSdQ
         tqENVo5Jgh8C3QmYH6zk623UqcTyd/tcCSgngmgkF0H1MP1yh4wXSyIh+NhgrFHvTVh2
         lteeGvmB4JB8Ir+eTA+PKWh29YqQVDfeD2f81TKB7XmpHMhV8jZQCAEEfSrtpfKSfsQw
         J8uASBEFeB5NrIEtYQEOKGzb2XNAyY9mhLKZcNgA8JtEnkGoTPnUx1fqcJPxXNqusllz
         JeBhADbXr+VyUtYsiJuL0cS5He5llD6SifHamHByFDYKs7O4TzOPYb9fF+d2kvUotsN5
         jNeA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=IzMejt7N;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id x139-20020a25e091000000b00d9caa2a9dcasi388287ybg.3.2023.11.21.14.02.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Nov 2023 14:02:56 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353726.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLfDl0025205;
	Tue, 21 Nov 2023 22:02:51 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh46a1ac9-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:51 +0000
Received: from m0353726.ppops.net (m0353726.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3ALLfLdc025865;
	Tue, 21 Nov 2023 22:02:50 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uh46a1abu-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:50 +0000
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3ALLna3m011089;
	Tue, 21 Nov 2023 22:02:49 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uf9tkbbku-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Tue, 21 Nov 2023 22:02:49 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3ALM2kHB9831118
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 21 Nov 2023 22:02:46 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id BF49A20065;
	Tue, 21 Nov 2023 22:02:46 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 526B620063;
	Tue, 21 Nov 2023 22:02:45 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.23.98])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Tue, 21 Nov 2023 22:02:45 +0000 (GMT)
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
Subject: [PATCH v2 23/33] s390/boot: Add the KMSAN runtime stub
Date: Tue, 21 Nov 2023 23:01:17 +0100
Message-ID: <20231121220155.1217090-24-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231121220155.1217090-1-iii@linux.ibm.com>
References: <20231121220155.1217090-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: qe4SXelpch00WHhO8n0hLeZh5nQleolM
X-Proofpoint-GUID: 2hpmIJbsI3XPvZcXaNBq09lhpHW9HWVv
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-21_12,2023-11-21_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 suspectscore=0 impostorscore=0 phishscore=0 priorityscore=1501 bulkscore=0
 adultscore=0 mlxscore=0 spamscore=0 mlxlogscore=999 malwarescore=0
 clxscore=1015 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311060000 definitions=main-2311210172
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=IzMejt7N;       spf=pass (google.com:
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

It should be possible to have inline functions in the s390 header
files, which call kmsan_unpoison_memory(). The problem is that these
header files might be included by the decompressor, which does not
contain KMSAN runtime, causing linker errors.

Not compiling these calls if __SANITIZE_MEMORY__ is not defined -
either by changing kmsan-checks.h or at the call sites - may cause
unintended side effects, since calling these functions from an
uninstrumented code that is linked into the kernel is valid use case.

One might want to explicitly distinguish between the kernel and the
decompressor. Checking for a decompressor-specific #define is quite
heavy-handed, and will have to be done at all call sites.

A more generic approach is to provide a dummy kmsan_unpoison_memory()
definition. This produces some runtime overhead, but only when building
with CONFIG_KMSAN. The benefit is that it does not disturb the existing
KMSAN build logic and call sites don't need to be changed.

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/boot/Makefile | 1 +
 arch/s390/boot/kmsan.c  | 6 ++++++
 2 files changed, 7 insertions(+)
 create mode 100644 arch/s390/boot/kmsan.c

diff --git a/arch/s390/boot/Makefile b/arch/s390/boot/Makefile
index fb10fcd21221..096216a72e98 100644
--- a/arch/s390/boot/Makefile
+++ b/arch/s390/boot/Makefile
@@ -44,6 +44,7 @@ obj-$(findstring y, $(CONFIG_PROTECTED_VIRTUALIZATION_GUEST) $(CONFIG_PGSTE))	+=
 obj-$(CONFIG_RANDOMIZE_BASE)	+= kaslr.o
 obj-y	+= $(if $(CONFIG_KERNEL_UNCOMPRESSED),,decompressor.o) info.o
 obj-$(CONFIG_KERNEL_ZSTD) += clz_ctz.o
+obj-$(CONFIG_KMSAN) += kmsan.o
 obj-all := $(obj-y) piggy.o syms.o
 
 targets	:= bzImage section_cmp.boot.data section_cmp.boot.preserved.data $(obj-y)
diff --git a/arch/s390/boot/kmsan.c b/arch/s390/boot/kmsan.c
new file mode 100644
index 000000000000..e7b3ac48143e
--- /dev/null
+++ b/arch/s390/boot/kmsan.c
@@ -0,0 +1,6 @@
+// SPDX-License-Identifier: GPL-2.0
+#include <linux/kmsan-checks.h>
+
+void kmsan_unpoison_memory(const void *address, size_t size)
+{
+}
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231121220155.1217090-24-iii%40linux.ibm.com.
