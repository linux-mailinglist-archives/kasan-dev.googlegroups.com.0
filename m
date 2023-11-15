Return-Path: <kasan-dev+bncBCM3H26GVIOBB36W2SVAMGQECG7UKDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 887587ED22E
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 21:34:56 +0100 (CET)
Received: by mail-oo1-xc3d.google.com with SMTP id 006d021491bc7-58a83a73ce9sf69290eaf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 12:34:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700080495; cv=pass;
        d=google.com; s=arc-20160816;
        b=BLn+pTyhG2YWFpSwynq9ouqaMjXK8lguU+lB9/tbv50kKLmA7R5ak8WVDUB2cnVc22
         VR9L68iafLXKOAbuX1l5oFdbNwtTVBzJ9Gyc0fcqIXgzuNtTNFIpBwlliXQWpf5FQ7Gr
         Veo7KRYnnyMPqKsOvMGrbCOoOyux0ONJWu7Thi3FOodyi0rPpZW1YJLDERMthuMwqW8X
         rezfVJQR9oLzAsOl/4Vr6nczmWb9pylQoc9QAFgoGY85HAK2X7ZuErgnPvOXcdLL0r4R
         sty8PK4+Vdr4BSiWMVHN2WuTGu95YO34IQeeNvxabb5g3mYGdQ0LOLj+lu9ctIS8eQgU
         E6bA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=YY3/WdxPhnR43ULhNhWXcrUV0G89cZf3XafL23PEn2Q=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=XxlEYw7tNP4i2UdKw109INWkasSfwyGYM8Odx2I3LvKCWIbW0AmuEnUpaaqrp07ePY
         8zY+ng4UgrodoH3oqR0PWBmMOEqaBRqxUPkjY0EIOgNrMzB1/njzE46xNlTi2UxDoAiB
         bsgVYLO9Pa6aVZGWfhHhiID5CqEEN09pzh0dVSBkjSlBWpR5NK4q+HWqOj7T9soYiNOs
         RYrBzt57B92kD9OgsHOdtHVAdXuZcZm9CCRh7KsR3OgIK7I9UQj4O0y3lLsUb+lQAsqC
         0e498gAe9zo6T7pUDfTw4AsbJngWGoRwK5y6kN0ho4TT2m4tno2JD3ttoeLZvlFUwU4h
         eGhA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=EXuxBFfm;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700080495; x=1700685295; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YY3/WdxPhnR43ULhNhWXcrUV0G89cZf3XafL23PEn2Q=;
        b=YfQfdjjvQ3HV41eo18z3TFLu3Utd9tLHLMTs52wo2d+rVIknC5Z/4zjKtvo3clgQ8Z
         VvThSx6Ozh/9fo2ES9nb63XI7TfREFFlxcY/CPNrtn1eW6O/ViF59NDjTAJTi3GdVU9h
         Vx2ch/jR3arpeHK66C/pyxL05/V9UK+N8DspcULDONn1Gqs+Wf/ZrlKwG7I5kpkomml+
         xoc9aGAARX4wDRLet9l2U9ZqXeW53vpk78uF0QeTQWx9vg/UJviTtCcuK7Oo04mI9lIf
         ogbWiL/Z3F9UqWTSS288jHutfx6iAEJZ3Z+b4jqiGOh4YpEmH7VtYFDbLJlNJWKjZxv8
         mMVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700080495; x=1700685295;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YY3/WdxPhnR43ULhNhWXcrUV0G89cZf3XafL23PEn2Q=;
        b=K76oNC39xZ3NUIX4dg9ev6Y2MUJLL2IV608S6k5YdqhlTMlmXtGVqvbe1hamKaSZrY
         7eK0X2U1S1i95JZQpOstgtqRXRvxK3uhBKlr9dPEDSzACZ9QxbuY/gbJe2vktkEeHeTo
         NH6mUfqT71odSlPPG5hKORa/+XwJV/fZ/8lw5lLBOKF1EvQFEyKZxQ0WbR9nLV1dItkg
         pPsHBgq3w5fQ5xKLC09mvYQhoBbCoP3jdPJKUWqQ3hmZyGu61B3MJyQV2cLSaFeqVcwB
         C+OGMWWW+ESZYd1UDM69VGY+rDmpFPC+aEEOwKuUTb6uxPeQ7I0JJHL1HNVJ9nkjvt6W
         W5PA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyWRAzOLxVaLdX6JuL203DT0BzGryES/mXWoukRjQJupRC+I81r
	aTqgsagGWks+40v1yKNMOc4=
X-Google-Smtp-Source: AGHT+IHN44DVn0mWKDK+Wev05KkRltLfNqfmsBKA/Uusvx5rvVOMaR+LCR4IPOFkysitr9KuECvnOQ==
X-Received: by 2002:a05:6358:4407:b0:16b:aac9:f995 with SMTP id z7-20020a056358440700b0016baac9f995mr7571367rwc.24.1700080495108;
        Wed, 15 Nov 2023 12:34:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:cd81:0:b0:65a:f624:1956 with SMTP id v1-20020a0ccd81000000b0065af6241956ls103315qvm.2.-pod-prod-09-us;
 Wed, 15 Nov 2023 12:34:54 -0800 (PST)
X-Received: by 2002:a1f:b297:0:b0:4ac:2561:db3a with SMTP id b145-20020a1fb297000000b004ac2561db3amr12197931vkf.3.1700080494347;
        Wed, 15 Nov 2023 12:34:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700080494; cv=none;
        d=google.com; s=arc-20160816;
        b=gfRsgvx0IjZjwqNqZhPpltzpt6MxhfXyyk2oRl95A9aReSkhS9Ry8SHcoQIjDoZVVF
         2nHoFldVU8zEanvUGFwN/xBofj8HV0lpZvcxZMeTWYd+QXwfm4/BhsaPwfqVbgEsvL60
         s8XM1V+taduecLlTOTTHg7ZMuf72VBePzvfgqIxHVZhUE10heJX+gKhhoBWJMjlovFWe
         gr146Divh24UMzKklC0pbh+VVtuP1bldOuMYAQ3I0BD86HdWa+nwBL67NEbcSaNiIV7E
         sTC4OQ1ZUcZX20YHMPp5MopFPTGYeOQgfa5CAeebpX1pjNxrExzZ5W+sDmAotqDXKjLm
         6oUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=NhhCYesztOa7Jqvt4x0Jdgg/9LLiWk0vF6FRHTpFEGQ=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=PIoWIlOvAAOrAXu7cjxMwUdCHDBQyEVxmoCZllxGbbc1mbVqD0dyWQrf7O6G/NMe0t
         EkLwjFj22Zjn5AfmJQl975MYtUkJsDIeEj9IEqIaQgrwSDvUpHzVTOyBonf450Iwt5Z4
         hCt7xVXcGCX6pThc1zw+65ceRctPT+/aumBzc7XLF86veabmpkPJqEIjql56J/2rEmIn
         IF3dgD5WCLT/kTwo2nR3FEKLV3k0OFreeXGNIKHydTuBswTKTay7rulCEZg2PRl9PZoI
         nES86s+FM4VV0Jz26khC0X8EHDFTzSKQwir6tAbfMzbBsEH6l8r15MFyaQClS6d2jMrS
         oNSA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=EXuxBFfm;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id cl14-20020a056122250e00b0049d13f0321fsi915994vkb.0.2023.11.15.12.34.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Nov 2023 12:34:54 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0356516.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKKGMt020174;
	Wed, 15 Nov 2023 20:34:51 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4xc8cef-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:50 +0000
Received: from m0356516.ppops.net (m0356516.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3AFKLkkX024302;
	Wed, 15 Nov 2023 20:34:50 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4xc8ce2-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:50 +0000
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKItQt021588;
	Wed, 15 Nov 2023 20:34:49 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uap5k9kcq-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:34:49 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3AFKYkcm23265800
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 15 Nov 2023 20:34:46 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 4F4CC20043;
	Wed, 15 Nov 2023 20:34:46 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 01BB120040;
	Wed, 15 Nov 2023 20:34:45 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.9.51])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 15 Nov 2023 20:34:44 +0000 (GMT)
From: Ilya Leoshkevich <iii@linux.ibm.com>
To: Alexander Gordeev <agordeev@linux.ibm.com>,
        Alexander Potapenko <glider@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
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
Subject: [PATCH 22/32] s390/boot: Add the KMSAN runtime stub
Date: Wed, 15 Nov 2023 21:30:54 +0100
Message-ID: <20231115203401.2495875-23-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231115203401.2495875-1-iii@linux.ibm.com>
References: <20231115203401.2495875-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: fkncNkpgvEQiGUZcGTO_3XR7T-3cRmrK
X-Proofpoint-GUID: 4uSiq2gXcSEbCiwoTCWkXAyd40BPgJJa
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-15_20,2023-11-15_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0
 malwarescore=0 phishscore=0 mlxscore=0 lowpriorityscore=0 adultscore=0
 clxscore=1015 suspectscore=0 mlxlogscore=999 spamscore=0
 priorityscore=1501 bulkscore=0 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.12.0-2311060000 definitions=main-2311150163
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=EXuxBFfm;       spf=pass (google.com:
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

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 arch/s390/boot/Makefile | 1 +
 arch/s390/boot/kmsan.c  | 6 ++++++
 2 files changed, 7 insertions(+)
 create mode 100644 arch/s390/boot/kmsan.c

diff --git a/arch/s390/boot/Makefile b/arch/s390/boot/Makefile
index 5a05c927f703..826005e2e3aa 100644
--- a/arch/s390/boot/Makefile
+++ b/arch/s390/boot/Makefile
@@ -43,6 +43,7 @@ obj-$(findstring y, $(CONFIG_PROTECTED_VIRTUALIZATION_GUEST) $(CONFIG_PGSTE))	+=
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231115203401.2495875-23-iii%40linux.ibm.com.
