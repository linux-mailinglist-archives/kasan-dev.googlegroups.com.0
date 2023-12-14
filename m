Return-Path: <kasan-dev+bncBAABBH5S5KVQMGQERI5UKCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F503812733
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 06:56:48 +0100 (CET)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-67ab60184ebsf85663006d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 21:56:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702533407; cv=pass;
        d=google.com; s=arc-20160816;
        b=fp3MCWEyQVPDV7ymXh3OYHt2YOHIXbFYfJFHo0lHFRS1KR1N/JStzFqOqaqPilYDwN
         I8CgFgZaBirgVxc5tg4kTbnNKWKrGs9pCcH5i0J7smSChKV96NMq1nrYODX2b0Njp9Z+
         2kKO4Zy64ariEn48JxjxcWMMWtdm9oAZEHLHAO4Q/l4icoPPrcLK8mp+93nO//mut060
         /c+OjbZnRhdRr/y253Jo6tAshXkcfZUIwVEfsu8kCkdW63ykC2WKZUxRysRXYPchkUj4
         JX/AuohKZc6zO6dKO8emBaPzTILYdTG5TZMaU9E/EYpfFl1LfzvCHgZDA40BpWAGE/Fp
         Mzvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=3W1LGFGDiuW/Ap0PkqcjpR93r8/upnM1xHEkCdDi6fY=;
        fh=JZjI76tHrPFh9wXiZ9caJKwSuDkcoMAMvZd7/HZf8J0=;
        b=0Je2lE/CsYtBE6l1usQ7gfxqHL8WUVQWOYOv26QQReZnoYaktoWprpO6vPRbyjVfz0
         yxkA7TBWtWuF35NCwBXt3oLE56R7Noe2kb6tndrKM6lkOiYvCZ4wrbPLPef1B7qwZebg
         sXOzlxINcwLHwJT+rCWVxsr9IJDNEZavn9QC1g+krEcYxj5zGwgMzjtdQHoNrYA2Sasb
         GavcO14GlDKMVC4HieLS5j2edt4jzi+pvk4T7v2Kw3pxNMw3Q24YOkkWN4N1VxfWuLGZ
         mQEYKl/jDLfEMqJMB3/XIzDa/kFmAJXfuGQl0qIOd7zNcfq00Qa09f5EX0CxCsE2aD9W
         Wb9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=UYZPDBuP;
       spf=pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=nicholas@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702533407; x=1703138207; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3W1LGFGDiuW/Ap0PkqcjpR93r8/upnM1xHEkCdDi6fY=;
        b=e3BUuI1BloaxnvqugE8r7fNllmiS5iUm8cFMrlDl4iJKOfCrCkgN6yjOqe5sn2KMHw
         spB+rnEvRxlZJJV+4tTGNsl/oWB9pa3XGjxbOTiB8nApJP/cIEDVUhUNeWH3Fq96nbxk
         rJRPeZNkWNHJM15tY8atagg6xZEiXqhxPZhExl4hGvxKnwbcemjDoYxMlkLiBW7LAJdK
         /iovVMeB+VpxbmefhV/ZdtYx8lhrPnr/ATBRSvyk2S8yIIWKn5dmE2E3bjCiKhZQe+GX
         rP8vtTiWxoBb7jF2DpZIYsZBaubnpd1p14dKvPLZEYY+jsxsddovfk8RcZlN1F7S5Mlo
         yo5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702533407; x=1703138207;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3W1LGFGDiuW/Ap0PkqcjpR93r8/upnM1xHEkCdDi6fY=;
        b=VN1K/Apg5jCzVvhETQbEHe434w3VT/9ztTZnhLNJvPKDdhYEufxtnGaecHNalPSJGU
         NxU9a2NOnMbF4qT7TfpVFh6t+K7XwPjTZWPE0Hxa8J8SeRZb0IWQ77IACCsRBKXVH2PR
         HfYSqFlIq/CitqruEbwQwvr+o9b835b7wZEQRsqdjMt/aDA2SUfzTyveMYhhLQkzIHo3
         8ucOBQtyiSnfhp3ZUPaoRttPcagvg6G7rRpeKhcoGutE+b4BWRzFT/Klovf2FL2gJF2E
         clmYNG/5QCL8bMh+k/lj4lrtCzpRB6uzDqC1+ZLThMMxw1N478ryZFOPixmkSCfEEcaH
         xHHQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzLV2r4UdkTIh5fcuMbGdJCX3d7EsUijZlHVJgXcQRHsCDKXzxl
	G0NFyAgrUV8/uCNy6h6lWv3Rvw==
X-Google-Smtp-Source: AGHT+IG4Qdi4g3wilOcxQswyOfZwXmY5EqKZrA/I0j0Gw5Fu5pUaMK6Pp6yzSok2w+XoihHZ3h3zzg==
X-Received: by 2002:a05:6214:e83:b0:67f:3f8:fdf4 with SMTP id hf3-20020a0562140e8300b0067f03f8fdf4mr2023535qvb.126.1702533407245;
        Wed, 13 Dec 2023 21:56:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:cd8e:0:b0:67e:f409:fbc5 with SMTP id v14-20020a0ccd8e000000b0067ef409fbc5ls1982985qvm.0.-pod-prod-03-us;
 Wed, 13 Dec 2023 21:56:46 -0800 (PST)
X-Received: by 2002:a05:6214:260a:b0:67f:d2e:59a5 with SMTP id gu10-20020a056214260a00b0067f0d2e59a5mr176406qvb.83.1702533406523;
        Wed, 13 Dec 2023 21:56:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702533406; cv=none;
        d=google.com; s=arc-20160816;
        b=G0Y+zyJN5Wf4pZv19pQDs1snb3MEoFYTiJloaY5k4olgmyUUTTA46bObX3/2cAVntA
         J0A78mekqkCOprWy2g9aUwQ9pDoUCKyJWv0A7JkWwSBG4t+H8zFRIDTYjgcINLyXUrIN
         eUmd+TLEW6k91KZvZVI1t/ED8SiFXdJjPwy3yI5qNVQoRZ11V2mr7rmWWOTW177GSlTD
         0qnnvxtgtd/59uLVvNXLJwwe6MSzkIUNJnaozHyCebhqnx+qMVe/beMxwtXEM94RWUnO
         tx8LtJahZeXD4VvRDRQhT8nLeFkETHpD4qsVGQuWZcvJ2VvIddXCXIcQyZ+z/LCJPxmP
         id4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=d9wxIuPcEttKuooqpbXdsw1bqv2JtLrtXjyZWOljfa8=;
        fh=JZjI76tHrPFh9wXiZ9caJKwSuDkcoMAMvZd7/HZf8J0=;
        b=MvnyQvn8IzfnBAugd7/OWY8SObS20cXdIoGiYSy24ZOIjrGebahGYnL4krmwfjgUjo
         TbGlXmLYb/yKaQnrF+JZXSunrsJKFOw0GqHtb2PfaK66uLw+xrGTHzu6C6KFCt0eCfRM
         gQFcSDwCOisOuMFA71ot2yDlPei9NKx23oj3TPAxzNOm/xNUEYFXEXDf0h5nZnzWgMnU
         3ZKv1qXU61SpexcLt2wtYqVvBJI1W8/JXqfWx+6xvEstY5Pjxxf8ExWEyhH/xhxh2dFt
         v4AQEOQxvHsG8XtxSPHLz8/IH4pwfph5Sv/eBmOudnobkV/pimoKnBy2mCXqyjkQAjhm
         zO4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=UYZPDBuP;
       spf=pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=nicholas@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id o1-20020a0cecc1000000b0067a65d54666si1300265qvq.7.2023.12.13.21.56.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 21:56:46 -0800 (PST)
Received-SPF: pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0360072.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BE5Pf2V006428;
	Thu, 14 Dec 2023 05:56:40 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyp5cq854-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 05:56:39 +0000
Received: from m0360072.ppops.net (m0360072.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BE5oHZS007026;
	Thu, 14 Dec 2023 05:56:39 GMT
Received: from ppma23.wdc07v.mail.ibm.com (5d.69.3da9.ip4.static.sl-reverse.com [169.61.105.93])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyp5cq82r-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 05:56:39 +0000
Received: from pps.filterd (ppma23.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma23.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BE0fBUg014872;
	Thu, 14 Dec 2023 05:56:26 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma23.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uw42kggr5-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 05:56:26 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BE5uON922151734
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 14 Dec 2023 05:56:24 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 1B8AC20040;
	Thu, 14 Dec 2023 05:56:24 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id A9AF020043;
	Thu, 14 Dec 2023 05:56:23 +0000 (GMT)
Received: from ozlabs.au.ibm.com (unknown [9.192.253.14])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 14 Dec 2023 05:56:23 +0000 (GMT)
Received: from nicholasmvm.. (haven.au.ibm.com [9.192.254.114])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ozlabs.au.ibm.com (Postfix) with ESMTPSA id A020D606F4;
	Thu, 14 Dec 2023 16:56:19 +1100 (AEDT)
From: Nicholas Miehlbradt <nicholas@linux.ibm.com>
To: glider@google.com, elver@google.com, dvyukov@google.com,
        akpm@linux-foundation.org, mpe@ellerman.id.au, npiggin@gmail.com,
        christophe.leroy@csgroup.eu
Cc: linux-mm@kvack.org, kasan-dev@googlegroups.com, iii@linux.ibm.com,
        linuxppc-dev@lists.ozlabs.org, linux-kernel@vger.kernel.org,
        Nicholas Miehlbradt <nicholas@linux.ibm.com>
Subject: [PATCH 11/13] powerpc: Implement architecture specific KMSAN interface
Date: Thu, 14 Dec 2023 05:55:37 +0000
Message-Id: <20231214055539.9420-12-nicholas@linux.ibm.com>
X-Mailer: git-send-email 2.40.1
In-Reply-To: <20231214055539.9420-1-nicholas@linux.ibm.com>
References: <20231214055539.9420-1-nicholas@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: jSCLRD5AL1ZRUh81WentUJPts7nYAd0_
X-Proofpoint-GUID: SH2cEt_NsXZHfXK7AkjEQ-6Tk95O45Ww
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-14_02,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0 mlxscore=0
 spamscore=0 malwarescore=0 mlxlogscore=751 bulkscore=0 suspectscore=0
 phishscore=0 priorityscore=1501 adultscore=0 lowpriorityscore=0
 clxscore=1015 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2312140035
X-Original-Sender: nicholas@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=UYZPDBuP;       spf=pass (google.com:
 domain of nicholas@linux.ibm.com designates 148.163.158.5 as permitted
 sender) smtp.mailfrom=nicholas@linux.ibm.com;       dmarc=pass (p=REJECT
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

arch_kmsan_get_meta_or_null finds the metadata addresses for addresses
in the ioremap region which is mapped separately on powerpc.

kmsan_vir_addr_valid is the same as virt_addr_valid except excludes the
check that addr is less than high_memory since this function can be
called on addresses higher than this.

Signed-off-by: Nicholas Miehlbradt <nicholas@linux.ibm.com>
---
 arch/powerpc/include/asm/kmsan.h | 44 ++++++++++++++++++++++++++++++++
 1 file changed, 44 insertions(+)
 create mode 100644 arch/powerpc/include/asm/kmsan.h

diff --git a/arch/powerpc/include/asm/kmsan.h b/arch/powerpc/include/asm/kmsan.h
new file mode 100644
index 000000000000..bc84f6ff2ee9
--- /dev/null
+++ b/arch/powerpc/include/asm/kmsan.h
@@ -0,0 +1,44 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * powerpc KMSAN support.
+ *
+ */
+
+#ifndef _ASM_POWERPC_KMSAN_H
+#define _ASM_POWERPC_KMSAN_H
+
+#ifndef __ASSEMBLY__
+#ifndef MODULE
+
+#include <linux/mmzone.h>
+#include <asm/page.h>
+#include <asm/book3s/64/pgtable.h>
+
+/*
+ * Functions below are declared in the header to make sure they are inlined.
+ * They all are called from kmsan_get_metadata() for every memory access in
+ * the kernel, so speed is important here.
+ */
+
+/*
+ * No powerpc specific metadata locations
+ */
+static inline void *arch_kmsan_get_meta_or_null(void *addr, bool is_origin)
+{
+	unsigned long addr64 = (unsigned long)addr, off;
+	if (KERN_IO_START <= addr64 && addr64 < KERN_IO_END) {
+		off = addr64 - KERN_IO_START;
+		return (void *)off + (is_origin ? KERN_IO_ORIGIN_START : KERN_IO_SHADOW_START);
+	} else {
+		return 0;
+	}
+}
+
+static inline bool kmsan_virt_addr_valid(void *addr)
+{
+	return (unsigned long)addr >= PAGE_OFFSET && pfn_valid(virt_to_pfn(addr));
+}
+
+#endif /* !MODULE */
+#endif /* !__ASSEMBLY__ */
+#endif /* _ASM_POWERPC_KMSAN_H */
-- 
2.40.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231214055539.9420-12-nicholas%40linux.ibm.com.
