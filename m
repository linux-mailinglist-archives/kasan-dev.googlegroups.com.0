Return-Path: <kasan-dev+bncBCM3H26GVIOBB3MB5GVQMGQENUZXETQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1818C81234C
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 00:40:31 +0100 (CET)
Received: by mail-pf1-x43e.google.com with SMTP id d2e1a72fcca58-6cecd16a676sf7653698b3a.2
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 15:40:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702510829; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y6w9idhCua/0uL/gNLoKZqZZGADIToQYAEzIpotpgkNZRrYQpgY1z4DidUTEd5Vp/0
         QKAj3OC6DVO6wXFTWOOQ0jf1JoVeUnO5xwJEGX1+rXinEhoGk3joFqhHhldVqN64jCMo
         n0DIdsXOTTN6AwWLs57sWgQXg+PasA4t60addIsNjbLF8h0ORxykNyO8hsxeVrOt7EFl
         g0ilgA1eW2/EMcbQXOvApiQTk8Kw6DwJDYUB+9OtALmPpJQQDp4TDMHovPm0rD2Nn0XS
         EVBfc1znC3b13B4L/bhZQFOrJKy3vnGPJdSVo1avFqw9LqwJAsVFhrKTU1VXqmSLtSUd
         8sdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=kkSkKxfhBCfoYvsLTbGuN5Z3SVGuBT0HbHUinWYM5cw=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=xjFI9fq25UAIL1hCaBW8XvBuq/YOoWRDXaomIk1Ba7nB7DouoxtvdKguh8FB6JPFay
         uAkvu6vHI5vnxS/pwJr7Pa1Qi9GicMGzwkT0aHueYEl6l61ZFtiTU93dJCvjtHAyu5kV
         Zzm4+RAKCChMeMD/4zSWRPagRC5ciDiCHS7ijLpSvbz5v6BkJ8E6pqh2SHyKOLqzOlOQ
         BcFzfqIwc1s19RwOG5DtOpBgEr45dZNBrlhMsWMs8jTI0PoitmEhZ684aawlNd8VhXuN
         QudoQK1GlOl5H0nResKlXMlHSxWep0ejZtcb650ysCSoJVDBJ9gCP4SyUe88HQAyvDmT
         rIWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=E2pyhrNm;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702510829; x=1703115629; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kkSkKxfhBCfoYvsLTbGuN5Z3SVGuBT0HbHUinWYM5cw=;
        b=mtfAQHciPUflnhwpqfCzaFqbSDi4BuR5MFCjHZt52bFOZeo6gVsFDgsmc5idnjObhV
         WR4ppnc60whq/rMG8fVe3OPbge5l+s0AyW12M2kdA2oOf/BTtoUflOLgV+wnNZ2Jmo+g
         mCQu6gLDOVpg+a+cAQeAAyZpJranGotWTQGX0W+u5XBGpY7pxVCmyHbFxafoPogQueR6
         K/8I2mcvod+b1bLbdceICCeZgrorJnAQT1dM4pZcjhBPWci/KGymvn1t9U5DpgD4Un77
         pr9ptETt5jzU8Hyy4F5+J422hJJyprBc/qzE7OsQcDmG5ua4geak+q4pwJMVyVaWV7zR
         KYPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702510829; x=1703115629;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kkSkKxfhBCfoYvsLTbGuN5Z3SVGuBT0HbHUinWYM5cw=;
        b=W4mHB5QjiNogU3e09MRR7w6uinNQTUUIXfFRvDrrk4TRMKgu24Apo6h9WUrP71KuW/
         o7UbakqseY+Be3WWn5ZKyy5URxqBJzRYH8MpX2PxTBz7f1cufp3it29AdAHzobZ1mGjB
         sX1rNgavQeNf2pnArip4T88BlPSMJeLfxQCl8jlcIhQknFDq6KnPLrGNl9FBijrsVeAQ
         1tFLVHgSi7BiS0KPyuJVJXGZtTAWyBAzpfSOK9Z92i4lThgMV3auW/GaE1MxLVSPxZM4
         7zuRd6oLLdke/S8nwmHWiG4D/74QHLGToub9sDtATYTFs8SANGX7EtURz+JmmP58iebS
         PYKg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwRFzvU9KlSxcG6ldxdYGS4zc5D6Ch4s2hZ6P7op0qAbEapellv
	8bUjK481NdXhopBuZcaqrt0=
X-Google-Smtp-Source: AGHT+IFwmei4I0WxSvGjO9RZLt+HwNtaY+/36QsuLSF6JE6nqjdr/zZVLbWU32ooDVhL4X2c1jg3vA==
X-Received: by 2002:a05:6a20:3d87:b0:190:cc38:7d7c with SMTP id s7-20020a056a203d8700b00190cc387d7cmr8757534pzi.44.1702510829654;
        Wed, 13 Dec 2023 15:40:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:c8e:b0:6cb:a089:9b3 with SMTP id
 a14-20020a056a000c8e00b006cba08909b3ls2382541pfv.0.-pod-prod-08-us; Wed, 13
 Dec 2023 15:40:28 -0800 (PST)
X-Received: by 2002:a05:6a20:2451:b0:191:6d96:ffde with SMTP id t17-20020a056a20245100b001916d96ffdemr4835382pzc.24.1702510828729;
        Wed, 13 Dec 2023 15:40:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702510828; cv=none;
        d=google.com; s=arc-20160816;
        b=0BL4E2e1JRc+ARa9X//nqYzPsSxixigdTSYy/QrC7Pye3xQxvlFm2hsj5UC1+dUKNx
         RJeCHD4MlbE49flbAnF8D9ZpxpBt5lZ3LJsGCn5Pi/3Y0JqrAH/Mu5vrTCZGLskBgVB9
         H/o29miPDvPg0KH+YhZAhZA7gwoHNqPfVs+HRjKZiDiqOD3qFIIVDnHJYvRXVITa3fcJ
         jFlp6zLp37w5DJ7J3Xwn2i7w4KwlNUARztOf4UNLbTtLn/jrxMHq2ZKcFBKR+MG7KGzs
         lRh4P9PMV1OOi2mY46AmJNpA3TIzulXkdyy+fAOflxt3yOthzOn5Ld8eCCUeqeOmzwlI
         qDUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=j2GQd3hufGtxn26BXfXN2VPH4hRg4OAPUwhi4unL9oU=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=dfplMUj1kWe5TvVtuE39wdLOxhp2bntKCX1PrBm/lCJde3tppCUzc1d/n+KXAxrNY2
         pqFYt3mvax+Msk6FdZXFFYxYOSkszxQ+iVHTGLH5XwJuD98RjPJURN03omd0uwBWf7tR
         2jqRsyZQWVJRfxoZmgUYnyvqcmiZ6qelKPE8zK93JRg51Hqgdun5zzo4cVSjuOSdmGaf
         5p+G78Tlb2Tz9UDDE1Nwnv1AlyTs+uxe5A+R7so2Y3XR0lhgLYkU/H1y/BTrLnJPO1bc
         vyRB0PW+FWUPPmqzuGwBFMQYl0eyQmbJEW0Js4+eJIKCgo57PTFZQz+odL/HetPjlcnS
         7FIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=E2pyhrNm;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id x3-20020a17090a9dc300b0028b042a3f51si56248pjv.3.2023.12.13.15.40.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 15:40:28 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353722.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDLrAsR019617;
	Wed, 13 Dec 2023 23:40:23 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uymwuj5vm-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:40:23 +0000
Received: from m0353722.ppops.net (m0353722.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BDNeJQj027678;
	Wed, 13 Dec 2023 23:40:22 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uymwuj5dj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:40:22 +0000
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDMuGjx005066;
	Wed, 13 Dec 2023 23:36:45 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uw4skm9x0-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:45 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BDNagMJ15794750
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 13 Dec 2023 23:36:42 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 941F220040;
	Wed, 13 Dec 2023 23:36:42 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 2E23F20043;
	Wed, 13 Dec 2023 23:36:41 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.171.70.156])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 13 Dec 2023 23:36:41 +0000 (GMT)
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
Subject: [PATCH v3 21/34] s390/boot: Add the KMSAN runtime stub
Date: Thu, 14 Dec 2023 00:24:41 +0100
Message-ID: <20231213233605.661251-22-iii@linux.ibm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20231213233605.661251-1-iii@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: 4lAACWdvN8WbBuqQJ2B2W7oAjf4WZHdM
X-Proofpoint-ORIG-GUID: -6xNZk1Ck_XK02XybYIjXFr2nKMVO1v3
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-13_14,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 suspectscore=0 phishscore=0
 spamscore=0 malwarescore=0 mlxlogscore=999 priorityscore=1501
 impostorscore=0 adultscore=0 clxscore=1015 lowpriorityscore=0 mlxscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2312130167
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=E2pyhrNm;       spf=pass (google.com:
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

Reviewed-by: Alexander Potapenko <glider@google.com>
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
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231213233605.661251-22-iii%40linux.ibm.com.
