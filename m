Return-Path: <kasan-dev+bncBCM3H26GVIOBBAGX2SVAMGQE6KOVXMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F9657ED23E
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 21:35:13 +0100 (CET)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-6717027ac96sf670246d6.2
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 12:35:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700080512; cv=pass;
        d=google.com; s=arc-20160816;
        b=D+xT2IWGKI9fC2sE9bAD/h3iKrwYeqSOYbIL2tsLE4hFa0hRyZB5wLctn8kW3EuZLi
         hjStPSIFAYOahGD+1FIe/qRTu6RWj1P2/+G+7P6xqZJqH8MWlmtg+E8sA3FYbhhuJNyN
         yjzJBZq9mIVjCkTQUSvXz1NpNUih0DZ+FYAkkUgPiWolrzwdoy8o1mmvpHK196nQ5Vn/
         hTEUaPNixVRVMCVQNzhEoTy0kpHmpZ6bNy7wx9Q9iSVpYeTw/v6x4erWSEWi/DO0XL/r
         7VfUV3Bz7ZioGFH2rHb7eV4YHsxQfc9fyGbqmw2PyxqYlEItCA64EBu4o/Q4N6KPaJiC
         JxJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=mGJ63Aw5ziabdTN35CR7MLRULlGDFNBoiJoFChi0Q+c=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=SlIQ4xbE8q4Mw6iOoFkc4KCH12UM0CxTKtNKLK4QiWlkRIGdGsqYopAyBfNpVC4fAc
         L86OZMeGEOktK3yL1o4Izeq/dbJ4vIwfIg32zzHAq3uoz/j8jAt7Pqr/ILi4QFeS6IJX
         KM/OsRyHUrikScUAYzJvdi2MABHyWC/T81Goog9DeqQtwiwmLBESPKdGU+3sTHXL8PmR
         NtXcjOD5zBnnqVbhApY1+rKXjdMnKmSZyPb+qAsH3hwgr+J9GbLHtqND1pUEQHi2iFKX
         z5PNeGKY76AHGTmTY0OP9sIIi8Q0kihFBxahJQiNI+j1Z3KvPqO0SS8SsMv6afGFuBvb
         mlvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="Cm7X8/vx";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700080512; x=1700685312; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mGJ63Aw5ziabdTN35CR7MLRULlGDFNBoiJoFChi0Q+c=;
        b=Y/Aa6K46Gy02m2bFuLCADgiMILtjN7FS87VowQfEMJySf1bfVWGX3m2UcBIHrJ6Nwq
         y7JzZfH/gAAn7wUDI5j2ymXssuBLLhfPLxPxD6VJoeQl98enTwOj4dBTtuqjK+3/Q206
         hI7ZxVVES3ODUkzpqX5L8U4KvsfxwxaD2GsCryG5qhfm6J1U/ICirAsb9cd1qjd69HGV
         /dL45rXHM2cNfi4kVOAQ/J7SbmBAckfEZhkAAoAB21azWzHx1K4ZV4F0CAgjxEs1Ig9X
         mlBZqB7DIvv4IJkfYspFuCqEOkvnqOLDbNn+NOxfgHGf+zd22lgDPpPdmuzIhdkW3TUB
         S/8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700080512; x=1700685312;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=mGJ63Aw5ziabdTN35CR7MLRULlGDFNBoiJoFChi0Q+c=;
        b=gzzMO+DmVqZGDdPpHBafseBO1oJDkUdDfqkfQTwmMZVnwAEoEiRFkCeYJCQrBbqc6L
         6IKAm5aav0qSc/2bvqrTljNTF+br3LeaIqW8vvopYM9yxwdcFUBhiIFkj15zIznQpvSd
         UMOH04wtAxMhehI/EZfzCCjs616bLYk6f5738AyguonIAJHgaConER4k1Vk9p62SMsNq
         dDDDjDdbNLVEJLSaWRVCGGK2mqmK/LCXlVu/agKuGvS60SR70wPReDl8BeXclpF4VuR0
         GR9Te6HuXNKbXNykiS5ig6K1WMGqL7A4M+Wpvu6HoDXnh8oHthAnS1uhg0wlVDGKOVNd
         5kdA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwH04uKV5hCGZ/W1BAGb4YSjOznMPPUAnI+FXBg6dKuJ2zqmzVX
	gTnF317Nn5dmff2jT+TOpLhQdA==
X-Google-Smtp-Source: AGHT+IGz71S3Om0ADwjLyroDNXrOTmr1n4Cp849gHeIwn4d5IzMCHXalH4bikpxuPosi/VVCCUzGow==
X-Received: by 2002:ac8:7d49:0:b0:418:1002:cfd8 with SMTP id h9-20020ac87d49000000b004181002cfd8mr7688639qtb.67.1700080512465;
        Wed, 15 Nov 2023 12:35:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7d02:0:b0:41f:157e:89e5 with SMTP id g2-20020ac87d02000000b0041f157e89e5ls186367qtb.0.-pod-prod-03-us;
 Wed, 15 Nov 2023 12:35:11 -0800 (PST)
X-Received: by 2002:ac8:4e85:0:b0:419:5b6c:be62 with SMTP id 5-20020ac84e85000000b004195b6cbe62mr8901158qtp.4.1700080511701;
        Wed, 15 Nov 2023 12:35:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700080511; cv=none;
        d=google.com; s=arc-20160816;
        b=Pw7wLz6TkpinuywQXArPPIRyum5We4u9SsrcYW14VpkkHtQBQu6dLQwLiXjxSLvN4D
         UDROrcDp2DuXR7m6r0wZEW/P3nme5g9fzfgqXWsS9IHbruZii2FWLG1ubp7CceFHFnUJ
         tfAPCDMLGaDJy01ws10rtQQ394sXCV14M5vefgmBh3tpKuKguLFYmagDKI3A7VAtg+BS
         6IVJxHDUlpAuQaEE0sMQZHVg7ZjUy0JQOx0uaYoQjWV8WtDcJGnQSUctTfhhjjY3QC1O
         6dCsWwAXELqHtsKU+Mf2wyTCkbfQnG9cuTbyTVTS5Sp9LhBpVbwa7p+oMa5S13kYzjXQ
         2opg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Z9QhvajxwNq5SYGaSMflClifwELAA5o+VrikMt43NLQ=;
        fh=Mk/+hh3KXEiY642GJit3QcoQ60j/OUZTCvigu+jTRuo=;
        b=iA9F94XXAiNanUbGHZB9bb5XzpHB/t7J13vbOUQVyi5LcvL04lejbu0dOQYAndU1SQ
         8YADLdf6Meffg7XeWj/79Hh1JF2Pr3NZFUG70ubjTQfaEB0M9rSxzGGQfB/yObUIidyf
         Td/5kMx1xPVfRiKtoFEG/w4JS7Rq0AyDgRBWaA1zdixr47xq+xUSzH8/4DpRGCCOBsZo
         Us8S7XGsVjRBRvgge38NeFdZTYBfdP8hQK110vrgaFLHhaL/qR0n2SNExAPgSN6JeTJ8
         2HqFyiZW31YmFi0gDY7phlCYNoKuzYVG8emtmDCQdziDAAaTuSbPTyNaWrfFyvPMdwzo
         Quag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="Cm7X8/vx";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id gd10-20020a05622a5c0a00b0041790471199si1554972qtb.4.2023.11.15.12.35.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Nov 2023 12:35:11 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0356517.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKGBg7020350;
	Wed, 15 Nov 2023 20:35:07 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4ch9c3f-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:35:07 +0000
Received: from m0356517.ppops.net (m0356517.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3AFKGQp8021574;
	Wed, 15 Nov 2023 20:35:06 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3ud4ch9c2w-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:35:06 +0000
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3AFKJ079014625;
	Wed, 15 Nov 2023 20:35:05 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uaneksvyw-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 15 Nov 2023 20:35:04 +0000
Received: from smtpav01.fra02v.mail.ibm.com (smtpav01.fra02v.mail.ibm.com [10.20.54.100])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3AFKZ20918350786
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 15 Nov 2023 20:35:02 GMT
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id DDD232004D;
	Wed, 15 Nov 2023 20:35:01 +0000 (GMT)
Received: from smtpav01.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 9051C20043;
	Wed, 15 Nov 2023 20:35:00 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.179.9.51])
	by smtpav01.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 15 Nov 2023 20:35:00 +0000 (GMT)
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
Subject: [PATCH 31/32] s390: Implement the architecture-specific kmsan functions
Date: Wed, 15 Nov 2023 21:31:03 +0100
Message-ID: <20231115203401.2495875-32-iii@linux.ibm.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20231115203401.2495875-1-iii@linux.ibm.com>
References: <20231115203401.2495875-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: UhAhQFn0oBvTc1Pv6N3SdNg7x4kktrNk
X-Proofpoint-ORIG-GUID: LEZ4uk_CRb6VScTTWyecjTAHWTBHOoS1
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.987,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-11-15_20,2023-11-15_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 malwarescore=0 adultscore=0
 mlxscore=0 bulkscore=0 mlxlogscore=783 lowpriorityscore=0 impostorscore=0
 priorityscore=1501 phishscore=0 spamscore=0 suspectscore=0 clxscore=1015
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2311060000
 definitions=main-2311150163
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="Cm7X8/vx";       spf=pass
 (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as
 permitted sender) smtp.mailfrom=iii@linux.ibm.com;       dmarc=pass (p=REJECT
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231115203401.2495875-32-iii%40linux.ibm.com.
