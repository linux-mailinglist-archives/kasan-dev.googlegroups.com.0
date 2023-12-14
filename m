Return-Path: <kasan-dev+bncBAABBEVS5KVQMGQEFO25TVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 73F06812731
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 06:56:36 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-425a8465e32sf50118941cf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 21:56:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702533395; cv=pass;
        d=google.com; s=arc-20160816;
        b=zvH2Q0SlFG1YUNnQv4tB4q3WCMfwP1TRNCNwWSjFTTH+4ZkmoBdjWQPz56I9kLd2id
         o85TR+5wkJdlMBfAo/0kZrMdslTVvVQgyoHh4GUStQXrIROfvfn0Erm1Ior/MD8DDMQ3
         2nYTaI0kNQ+6zWqb5+eQyiw/hfv01xvlMAIg9KQlhuLxr+DetcW3xFyIXtyVCwu1ocWX
         SU//6VXvdRoaNY03PeYJdEgxaWLlBhG/+GKsUFZ98Wnto7gUAPtY1iShnzSz4L4jmSPV
         4umMONnprHV815mweNCOdkUTM7IbIFALb/ONdfgsMIeFO/o+JiAr9Xfgv67wZXa7tIxk
         ndVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=2OnY2DCUKh1CVK2SaT1c2eMF5flwF3r1bqpVZRPoY4I=;
        fh=JZjI76tHrPFh9wXiZ9caJKwSuDkcoMAMvZd7/HZf8J0=;
        b=sz2RQ3y60tIJfMni9ZQQ9IbRm+jbt4SLaiWoU9J5iqRTTw/3xm/yjLf9ayNti62lqx
         uYThCc9372/NsCLPLqKrnPq/8mClO7bDOdDqqKCI1iMtlVir88epcMw9+eUmXEF+3+gc
         Xc/fDT1gf4UHqxDeJk77M2NkAheCOs1UZBio6d1e0IB4z7az/rDEj/rhEJmK5S/xoGWx
         tEAVQh3Ict82RV5trdblw4AWn+7MlEnH6Htd2mrVBOoeb8RPZEvqELpzGi6Xiu/o9iwQ
         VlK4MSWR8lSuFz0AggHJc6NfXN1FSO10yfduGKri4oqUG4cXCb3GrSCBVNd1Op6VQAn9
         zDBg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=H6Vi0Q4u;
       spf=pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=nicholas@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702533395; x=1703138195; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2OnY2DCUKh1CVK2SaT1c2eMF5flwF3r1bqpVZRPoY4I=;
        b=NeImNk2fR5EMfiUkviypcrj7YSAoA415Aqc/e060Du9Ihu4UgmWma4NnCoWk0cSu6L
         cQ2POTvvyFDChUULWejcSpcF3nDbbObUuNvd6x5FdUeSfBGI8PoLi9Qn/3UoEQ/Po7bm
         vRHmHzGzvOxOKo4PEZH8lqDTNZzkEv8wukfXIKI4L1BF98nkEtVxGBz/olWEgh253uT1
         /htj33PaLCqVu53PMfzM5Nikp57SpHN9H/gnhPm5jiaeDbBvj3CWJNHpfMn97zwO7v35
         vSQmcsCK9UdAborgXMF6/sJ5InO650F0y37q2XQ6g697pYsIpzJVTIEH66ICd6ry7pUr
         THvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702533395; x=1703138195;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=2OnY2DCUKh1CVK2SaT1c2eMF5flwF3r1bqpVZRPoY4I=;
        b=ZXeGlKeTpwH5ksUnbg5eff0v8q0em+Lb4tPAgYslJ4QHpb5PDPGoW8ZC7vGMqledWR
         8G1DPEOA2mgYBGZ4r9CspR5rCjip66JSV2WvEz9t47xh9gBZbdefXxUfZjG0zGaC1KzH
         RRPqQG8nV5JDbW743JuDCykympJONrtkWKO+7408e0+ZTaxOKPEVTyZSbX8e7IqnpDNZ
         Ib2fzXHGPxXnP1n5a3ecrHc25Qnv2YvFvVsOaqYoOqUkec1ZUodfQ1YOQIFfmCyHi6KL
         pj05XZtlN3HvFfYy50bZP84XawxJQqsOo1NOfMgu/rbKAOC3RGb8edceUpmPgeekxNVp
         558A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwBpVbMWKcjwKWZnIZv9vAC1Z/4GQsEkRmZv9OAwq1+DDBfS4TA
	CzeXsa0iL1QmSpwFh7GJKjM=
X-Google-Smtp-Source: AGHT+IEyz0fEe/p0yK6I+3ttRnY0pk6SAeTWvzGeZHFnKBUkWkGv7LooGggEyf6l0/q0htiND4XZxA==
X-Received: by 2002:ac8:5881:0:b0:41e:acf3:37f2 with SMTP id t1-20020ac85881000000b0041eacf337f2mr8404522qta.23.1702533395082;
        Wed, 13 Dec 2023 21:56:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1815:b0:423:7e09:4f05 with SMTP id
 t21-20020a05622a181500b004237e094f05ls1265311qtc.2.-pod-prod-08-us; Wed, 13
 Dec 2023 21:56:34 -0800 (PST)
X-Received: by 2002:ac8:5ac3:0:b0:424:8a:f9c5 with SMTP id d3-20020ac85ac3000000b00424008af9c5mr9621216qtd.26.1702533394458;
        Wed, 13 Dec 2023 21:56:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702533394; cv=none;
        d=google.com; s=arc-20160816;
        b=D0VU40GqfJhAS6Gvxags5xBOTfk1nPC/vRzG/NGPxnwBJFOcF6TRj1FffTlYvpRuBG
         QfrT7/e4+Us1U2zjpfdYvhK3zSdUV80ENUFPW2NpyjGd4RkBSU/BSoUCb1J3MwIlunwc
         Y4pKHxn1Glk20LyAqhTG3metIfXtcphRXMFrPhuaMUcIclEnliBhZvJbPaN4wTkss60L
         aIzMXPZa1iZEDWMDgme+rpaMI5gZ3oyC9WSzVidMITFihuk6Qvl62ivraw2W8B42mhH4
         k1EHT1SEvltdf2u84+gGdYstpMuZO5S48ihIMINrvdidKkLgl47GzdNooWy8SwtscW/1
         SXVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=JH7THuNQc9cqEmJHzHndMkqRs+bt6nd5xJ0k6Nbi28M=;
        fh=JZjI76tHrPFh9wXiZ9caJKwSuDkcoMAMvZd7/HZf8J0=;
        b=A5nN/0YVElF6qpyA0alww2RnTT4oYDKKvMs69uaSIGAaJGsZuCM+9EaF9075DjgdHn
         8h20S6yHRmRI+VBxNjrLSbbyAsUMKkTYUnLeqhsL39oi/K0Qe+PcmNko9hUovd0q1aHI
         U1XrA6SoAFHT8uABFQMMk5Ys8fNmTUU31uQ4VoS0J3yvBKtCyYxPteqAqVIWDFLIytdW
         lr1hCBeLv6mjWSdNMloVeoJsioiBCBFB5bwJmOGGxTYCcysITBcEwOlRYTgfgHcaneOC
         D6MQ0mVc7ML6kYIpHrKEu3I3j7zTOHSqyS+qiXKnbDv5olr1p7oY/gVPmr2UKkyfFQ0q
         WmBg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=H6Vi0Q4u;
       spf=pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=nicholas@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id ge19-20020a05622a5c9300b00425738e150csi2085146qtb.1.2023.12.13.21.56.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 21:56:34 -0800 (PST)
Received-SPF: pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353728.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BE5a2AN017874;
	Thu, 14 Dec 2023 05:56:28 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uypke6ev0-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 05:56:28 +0000
Received: from m0353728.ppops.net (m0353728.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BE5tX92001374;
	Thu, 14 Dec 2023 05:56:27 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uypke6eu4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 05:56:27 +0000
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BE3UgCH012585;
	Thu, 14 Dec 2023 05:56:26 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uw3jp6eg0-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 05:56:26 +0000
Received: from smtpav05.fra02v.mail.ibm.com (smtpav05.fra02v.mail.ibm.com [10.20.54.104])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BE5uOkC22151736
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 14 Dec 2023 05:56:24 GMT
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 3AD7C2004D;
	Thu, 14 Dec 2023 05:56:24 +0000 (GMT)
Received: from smtpav05.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id B30AD20040;
	Thu, 14 Dec 2023 05:56:23 +0000 (GMT)
Received: from ozlabs.au.ibm.com (unknown [9.192.253.14])
	by smtpav05.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 14 Dec 2023 05:56:23 +0000 (GMT)
Received: from nicholasmvm.. (haven.au.ibm.com [9.192.254.114])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ozlabs.au.ibm.com (Postfix) with ESMTPSA id 8B77D606E8;
	Thu, 14 Dec 2023 16:56:19 +1100 (AEDT)
From: Nicholas Miehlbradt <nicholas@linux.ibm.com>
To: glider@google.com, elver@google.com, dvyukov@google.com,
        akpm@linux-foundation.org, mpe@ellerman.id.au, npiggin@gmail.com,
        christophe.leroy@csgroup.eu
Cc: linux-mm@kvack.org, kasan-dev@googlegroups.com, iii@linux.ibm.com,
        linuxppc-dev@lists.ozlabs.org, linux-kernel@vger.kernel.org,
        Nicholas Miehlbradt <nicholas@linux.ibm.com>
Subject: [PATCH 08/13] powerpc: Unpoison pt_regs
Date: Thu, 14 Dec 2023 05:55:34 +0000
Message-Id: <20231214055539.9420-9-nicholas@linux.ibm.com>
X-Mailer: git-send-email 2.40.1
In-Reply-To: <20231214055539.9420-1-nicholas@linux.ibm.com>
References: <20231214055539.9420-1-nicholas@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: 2HFK1yGgvChNjyDg91ZhydhLex1GS7Qz
X-Proofpoint-ORIG-GUID: lBPTZrRlZWZzO3fKbGz6ydwaSFhSPO_j
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-14_02,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxscore=0 adultscore=0
 clxscore=1015 malwarescore=0 bulkscore=0 mlxlogscore=484
 priorityscore=1501 suspectscore=0 phishscore=0 lowpriorityscore=0
 impostorscore=0 spamscore=0 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.12.0-2311290000 definitions=main-2312140035
X-Original-Sender: nicholas@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=H6Vi0Q4u;       spf=pass (google.com:
 domain of nicholas@linux.ibm.com designates 148.163.156.1 as permitted
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

pt_regs is initialized ppc_save_regs which is implemented in assembly
and therefore does not mark the struct as initialized. Unpoison it so
that it will not generate false positives.

Signed-off-by: Nicholas Miehlbradt <nicholas@linux.ibm.com>
---
 arch/powerpc/include/asm/interrupt.h | 2 ++
 arch/powerpc/kernel/irq_64.c         | 2 ++
 2 files changed, 4 insertions(+)

diff --git a/arch/powerpc/include/asm/interrupt.h b/arch/powerpc/include/asm/interrupt.h
index a4196ab1d016..a9bb09633689 100644
--- a/arch/powerpc/include/asm/interrupt.h
+++ b/arch/powerpc/include/asm/interrupt.h
@@ -68,6 +68,7 @@
 
 #include <linux/context_tracking.h>
 #include <linux/hardirq.h>
+#include <linux/kmsan.h>
 #include <asm/cputime.h>
 #include <asm/firmware.h>
 #include <asm/ftrace.h>
@@ -170,6 +171,7 @@ static inline void interrupt_enter_prepare(struct pt_regs *regs)
 		__hard_RI_enable();
 	}
 	/* Enable MSR[RI] early, to support kernel SLB and hash faults */
+	kmsan_unpoison_entry_regs(regs);
 #endif
 
 	if (!arch_irq_disabled_regs(regs))
diff --git a/arch/powerpc/kernel/irq_64.c b/arch/powerpc/kernel/irq_64.c
index 938e66829eae..3d441f1b8c49 100644
--- a/arch/powerpc/kernel/irq_64.c
+++ b/arch/powerpc/kernel/irq_64.c
@@ -45,6 +45,7 @@
 #include <linux/vmalloc.h>
 #include <linux/pgtable.h>
 #include <linux/static_call.h>
+#include <linux/kmsan.h>
 
 #include <linux/uaccess.h>
 #include <asm/interrupt.h>
@@ -117,6 +118,7 @@ static __no_kcsan void __replay_soft_interrupts(void)
 	local_paca->irq_happened |= PACA_IRQ_REPLAYING;
 
 	ppc_save_regs(&regs);
+	kmsan_unpoison_entry_regs(&regs);
 	regs.softe = IRQS_ENABLED;
 	regs.msr |= MSR_EE;
 
-- 
2.40.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231214055539.9420-9-nicholas%40linux.ibm.com.
