Return-Path: <kasan-dev+bncBCM3H26GVIOBBHMA5GVQMGQECQSLD3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id C6C3981230B
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 00:37:02 +0100 (CET)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-1fad1eeb333sf11037452fac.2
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 15:37:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702510621; cv=pass;
        d=google.com; s=arc-20160816;
        b=qDT0H9rbLiRt67z5N9aPVjIMVt8SWQlRr6bEta6uCW8TO5+kDIvapaOxirc/B/DYUr
         jYFroFkq8KABytt9bjKgh5P8t000+rsUo+zqX3ko0k9olxF526TxJgldL3nmVdwWSxa1
         3kt+KZIelCNzVKux7CONEgIQDNiqVAspEPccxlWcX0TSw1F2LHHqWWIneCHdD7ey8A4m
         07D2mf2MJAnc8GqlMh/5eEDBcFjS2xh5vvZmb3TyTAdXK9JX+s8Qm8ndOV2nBtPtzxwc
         pZq3KMimXA8fps/iKSf7ntTMYtmv69s5TSGruejft/2CSbC4F20oQ8B+YUNaR/l35uMb
         h2Cw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=3/MZll4HqRqJwHME6HlGOX9rcnqBvt0pivOBhvMWbyQ=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=rgBJc6kNO+zywGWUFsuJ7ALMytbDcvs1QX1z+r9gyh5AL5a7ZQGDm6xQ/S3cadSDJ4
         ADMfrNPJIXq2fh/DbmSt8LABzhh9zW67xaKKMK7wYBScqw0k6s/FyD+oiVJhLQZoWykq
         B1lri5MXrwMhOCg6IwSbALHea1l99ypw8uz9ThJRAggbsCTDh4MkknXdBaus0JnQL5PW
         IhP2m5K11DvmeUTUkYOg7SeLFyP62LISaJk9vrAo+IZpimRvH4n8sLLDym+90aWpQaNy
         ppGvmRrEKCLam6ELb8oeB76s9T3BQ6bh7K7mNNe066/x8H0+SXvxe3EnhGeo4hBn0B4x
         kSgw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="SK/uPMUO";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702510621; x=1703115421; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3/MZll4HqRqJwHME6HlGOX9rcnqBvt0pivOBhvMWbyQ=;
        b=HF1OS7nkP76fWJIpsWhR76LvS8+bDTPKEG4GecAi8hY62Q0TPGgdUGmybOV8BdwTqN
         lPIVESs8+aHta3r0Di1tn+PdiqWBRcGMBquoQL88OnFBxYsOPfup5kzZNf+ngInt6yOk
         zSUzVCYMTpIfgnAnJvlvwZD5EDJytkCUF6bkoACfkUFInJJVhYgyILjU7Nhg1+JUGBA6
         nlRqX8AgN7Th4WOdCbD1igxTK8pZr60MJ5BnnVgrnSdqfph7zcWqEDP0QGSmvtTk6uXa
         f/hTceypiPzTl1kdx2y4LwBhDTcFAZ2P6mlK3zoI9Fwlfwc/q/a3cnpTdTg0gNl9Wthe
         HJ0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702510621; x=1703115421;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3/MZll4HqRqJwHME6HlGOX9rcnqBvt0pivOBhvMWbyQ=;
        b=dQaLCj46d+ydT7UNGU0uAVZsaOOA0UGefIq+PiuTc5CfOz3gaJzovsmxaITR2/RQOS
         nwfyjWDg19tK8WwK1XPdemSh+eLJS3HT8kAR5lj5NS4X2qvZKuOx/z2n711HjyVSO1mS
         fsOOHngjWE79QG6GNDjiy4dJhWs7uflT1Z+eZi4eTYatqwwOV/hTzIB+GXHFqUdCSMHC
         JbsQIUDbOj0K5hvWtL39S/QaIRPE78JZo6OnIHbO+AFuUKYh+9/EHfS07p50xPLG/ImU
         9gD2nDjPuwhT0hGS9kcJua4Pvok/+hPw3nJqmLmLoS8PcWOBsc4Etc+J2LlyPe7xFCH/
         IMDQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzEocBSbOFl2mNAUlNBU5EkWFLa17ZD1F7PO4ZXQdNd0Xtj5CEl
	GdkobysZO3CajDRK0p/ooKo=
X-Google-Smtp-Source: AGHT+IHDRBW0c75h6+B6ytkMTurDLT14hReMvR7vMjFWOCrQ95YGFJkjQ9emCzOGvPijLb3p394Uxg==
X-Received: by 2002:a05:6870:6f0e:b0:1fb:75a:77a7 with SMTP id qw14-20020a0568706f0e00b001fb075a77a7mr7547821oab.88.1702510621577;
        Wed, 13 Dec 2023 15:37:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:be9a:b0:1fb:38af:b153 with SMTP id
 nx26-20020a056870be9a00b001fb38afb153ls3004958oab.0.-pod-prod-02-us; Wed, 13
 Dec 2023 15:37:01 -0800 (PST)
X-Received: by 2002:a05:6870:3854:b0:1fb:251b:6f82 with SMTP id z20-20020a056870385400b001fb251b6f82mr8613987oal.55.1702510621010;
        Wed, 13 Dec 2023 15:37:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702510620; cv=none;
        d=google.com; s=arc-20160816;
        b=GpEpENs7AthVhP5AhB5SwWXVwB4Ea3/eBhFXALn0V8ADflQFF66r9XI4ueRD+R8Pvd
         6+LGAX6xQmn0s0bjsaz10xHI2OdEfZbNLsMJJV9TRPyfP5Ie+MgJcSYDsCNFQQfSDsvI
         MUAXwKfeKbBo+Mr8kY0V0q1iFyscOqRiIq5AZ5I+W1CUlXnX5DFr1l9JtyuxqPsivo0t
         vgfTV9VOet+VVQDCTpo9ZzqIsigMZ+uSJMVw5pmMJrthnMhN1IBIz8LwtWCU4aV7SKZT
         hmXRdmQjIfoza4FJrjOCsSnl0UrfnFbmlURicxqf4X6m5eAbZsEt0oiTf5Yij40gjRQP
         Gg7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=pkyPvKTJArMXixW9BBHqQwuAqKxQXhtM/cFCkvVkAvs=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=LYco+NvmJhYb3Kl7UADGJlc26MIgfj1yxVX/mwflTSNgWzmMhGd+z7OnfUEruWusGa
         N6VVVxdBxf35grX9eOXY16UrxrSzlvsWUjH2BCGBS4TujjyzvBBQ0PeSSYks4brIGVDu
         QabaHjWGT3XpNyjiSxqcjZz1FceFkEHR7xDx6oXzBVFt6BTBVasDzIQu8GJevRRDF2G7
         ee4oN9xhRlYXiYZmie3TF+pVMO+uEgPn+Czv1zFdvY1KmN5g47qMdlFVoVVAts0ysAbv
         MrCFsNja+TKZPluvOfHPD2MEAuFXXSXABuxr44P2BEWy9lRgLIKbGqCmIp/Ggs4YZX5l
         doaA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b="SK/uPMUO";
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id he25-20020a056870799900b001fb044ebe0bsi1442943oab.0.2023.12.13.15.37.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 15:37:00 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353723.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDMS9Re010981;
	Wed, 13 Dec 2023 23:36:58 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyne6164t-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:58 +0000
Received: from m0353723.ppops.net (m0353723.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BDN8eeg015721;
	Wed, 13 Dec 2023 23:36:57 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyne615y8-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:57 +0000
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDL68jb008491;
	Wed, 13 Dec 2023 23:36:26 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uw2jtmvkc-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:26 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BDNaNFW15205024
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 13 Dec 2023 23:36:24 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id D510F2004B;
	Wed, 13 Dec 2023 23:36:23 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 6C93B20040;
	Wed, 13 Dec 2023 23:36:22 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.171.70.156])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 13 Dec 2023 23:36:22 +0000 (GMT)
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
Subject: [PATCH v3 09/34] kmsan: Expose kmsan_get_metadata()
Date: Thu, 14 Dec 2023 00:24:29 +0100
Message-ID: <20231213233605.661251-10-iii@linux.ibm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20231213233605.661251-1-iii@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: 7vjTxdvAtbwBGE_g6qvKOeyD3SR7M5Qx
X-Proofpoint-ORIG-GUID: 3_WNaL8739bQutUg911FpVkRk6xoqt1c
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-13_14,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0 phishscore=0
 clxscore=1015 malwarescore=0 mlxscore=0 spamscore=0 bulkscore=0
 mlxlogscore=852 lowpriorityscore=0 suspectscore=0 priorityscore=1501
 adultscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2312130167
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b="SK/uPMUO";       spf=pass
 (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as
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

Each s390 CPU has lowcore pages associated with it. Each CPU sees its
own lowcore at virtual address 0 through a hardware mechanism called
prefixing. Additionally, all lowcores are mapped to non-0 virtual
addresses stored in the lowcore_ptr[] array.

When lowcore is accessed through virtual address 0, one needs to
resolve metadata for lowcore_ptr[raw_smp_processor_id()].

Expose kmsan_get_metadata() to make it possible to do this from the
arch code.

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 include/linux/kmsan.h      | 9 +++++++++
 mm/kmsan/instrumentation.c | 1 +
 mm/kmsan/kmsan.h           | 1 -
 3 files changed, 10 insertions(+), 1 deletion(-)

diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
index e0c23a32cdf0..fe6c2212bdb1 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -230,6 +230,15 @@ void kmsan_handle_urb(const struct urb *urb, bool is_out);
  */
 void kmsan_unpoison_entry_regs(const struct pt_regs *regs);
 
+/**
+ * kmsan_get_metadata() - Return a pointer to KMSAN shadow or origins.
+ * @addr:      kernel address.
+ * @is_origin: whether to return origins or shadow.
+ *
+ * Return NULL if metadata cannot be found.
+ */
+void *kmsan_get_metadata(void *addr, bool is_origin);
+
 #else
 
 static inline void kmsan_init_shadow(void)
diff --git a/mm/kmsan/instrumentation.c b/mm/kmsan/instrumentation.c
index 8a1bbbc723ab..94b49fac9d8b 100644
--- a/mm/kmsan/instrumentation.c
+++ b/mm/kmsan/instrumentation.c
@@ -14,6 +14,7 @@
 
 #include "kmsan.h"
 #include <linux/gfp.h>
+#include <linux/kmsan.h>
 #include <linux/kmsan_string.h>
 #include <linux/mm.h>
 #include <linux/uaccess.h>
diff --git a/mm/kmsan/kmsan.h b/mm/kmsan/kmsan.h
index adf443bcffe8..34b83c301d57 100644
--- a/mm/kmsan/kmsan.h
+++ b/mm/kmsan/kmsan.h
@@ -66,7 +66,6 @@ struct shadow_origin_ptr {
 
 struct shadow_origin_ptr kmsan_get_shadow_origin_ptr(void *addr, u64 size,
 						     bool store);
-void *kmsan_get_metadata(void *addr, bool is_origin);
 void __init kmsan_init_alloc_meta_for_range(void *start, void *end);
 
 enum kmsan_bug_reason {
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231213233605.661251-10-iii%40linux.ibm.com.
