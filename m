Return-Path: <kasan-dev+bncBAABBD5S5KVQMGQENBSZTDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E77A81272B
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 06:56:33 +0100 (CET)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-203446683cfsf672216fac.1
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 21:56:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702533392; cv=pass;
        d=google.com; s=arc-20160816;
        b=Nv3kjxw6emqTex0g/2kTwR8u0kugmg4fAeQiRcX6kTG5VY0uZm+dHhX44s4YSjWf9Y
         X4tMqF7zB48kgpsodCJVQgy5ZX36A5ndCpfalcv1ZdRdnN/ynF2hMFUMo2NundxCXM1v
         YCgM3MYuW+mMjDrmPAlJU/9+vSBN0Uz0XcvdW1QCq8n++BIlr+l2Lc3vHJbsSqqIJrdd
         dnKcXN5eQ47VBvD5iSq3aOedHR4aiUXvXY0FzfifaGATyaRqUGSDi50DuiVvRreLPTpp
         8apDniqH8kqZUv1Vt7d/jOWt4tv6EW/A8mn+83EbqHqFg1fTQtGlAO2YwnSc6V/Qtc6X
         MhLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=6jzzVtF7S0ryG2dsAlvcrOG5E3MFeLX6ZACouAWS7Qk=;
        fh=JZjI76tHrPFh9wXiZ9caJKwSuDkcoMAMvZd7/HZf8J0=;
        b=nQZ+vXW90uoiIUBpWa99iP+Thc8ABcXh6qGaCckEHu2HeDfWuwooXJNxqUYrvth6Uq
         v7af8Dba4Cq4C5NTBkkYl8qqnQSWFWS+mOlQb139O6gb38OXE151zlEac8+fXLaFkGoH
         aE+Mal/9bDjZuBWdQyaJBzUVUid9kJ9Z9EtOJbAhErvRN4fS3iqr30yN2xluj85Lusmd
         JpaEwGTN99vGpK/Yfm9MmCs6RRHrVflmWMrxAmkW5XemPly8pDKntlborAfhfdjqsKhO
         oerGBzWjD2MICS/f6XwSAKhzwlnPjePhVt9Idh0iqYtF95BuBSfWpcoMCMipWLKt7wa1
         2NnA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=ZFN6FyDA;
       spf=pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=nicholas@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702533392; x=1703138192; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6jzzVtF7S0ryG2dsAlvcrOG5E3MFeLX6ZACouAWS7Qk=;
        b=sKUoiB0/BIJ6WJaGVJF++OU4BXO11g+ucSq4Q2Iou3BfxWv2sfxWaoHVP3JPZdMzrK
         fDzlRNFRjUFpOOH5Szft4Mm2B29p4XHKyD/Ju+8ikPwCr1X2w5tmbOYXmg/KKSvU3I4N
         Wpji+FoU/XpK8VFDG91q1Zcf2l//VulAST9duqgOBmN7fX3Trr4chswumCz4mruPLNbd
         fSgllhN6m3BSMCYhRGb+UkDNBIWHaEfUdqPGslVIAAWFJwu9NqzBEL59Psd1DPqs7dDe
         nHLDAQ5geA9kAOAe/xTZFaHb782zYnGg/n55u+3fzw3pvWtj/NcBzXD6e4MW6Okcdp0F
         4jOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702533392; x=1703138192;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6jzzVtF7S0ryG2dsAlvcrOG5E3MFeLX6ZACouAWS7Qk=;
        b=n+C6TFG2b/6cu1snQjz+hCuqEVAxYyxTtby41KXaOsX4swTDgy/qBnRh8QfOWHQo06
         lBNjfXGXH8h2a9krSabYpKXX0QWOVdS9jKiLKp5c8zT3gFKvWvnnLYUICYZkZtnT5Ku0
         o/J7RUfGs1RSPfMhodH5HkNg3TDEspN2cBAZegveCT8oUKODhAbKKlbjLTS+kONgIX1d
         6VDbjWQfveczc901SgCE+LpisfOLTp2v4J8gVXlSDmPqZY2mpvJUFCAjlPviuP5gauQ/
         A5W12RK47gvjd+f7R/BG2/2DI7ND3fs0aigj+zWLLUtoU2SdWIk5lGEp0Moy90DR+cWy
         LVsQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yzh0lPVl2OYwRKqIU8lZyF929czvOk2aaxkyVGMhLatqeWPiP/g
	0b5CHn4/zNNfQwYPNQkxjj0=
X-Google-Smtp-Source: AGHT+IF+/INt2nAi39HB66T+lCEwHVtUrH99ofWWTrOGcXwbCWDc67SurMjtpA6JIugonXycXWfEsA==
X-Received: by 2002:a05:6870:d213:b0:1fb:75a:de6e with SMTP id g19-20020a056870d21300b001fb075ade6emr10731538oac.92.1702533391779;
        Wed, 13 Dec 2023 21:56:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:c45:b0:1fb:3148:c486 with SMTP id
 lf5-20020a0568700c4500b001fb3148c486ls4708382oab.2.-pod-prod-04-us; Wed, 13
 Dec 2023 21:56:31 -0800 (PST)
X-Received: by 2002:a05:6871:4e8f:b0:1fb:75a:de56 with SMTP id uk15-20020a0568714e8f00b001fb075ade56mr10509604oab.68.1702533390925;
        Wed, 13 Dec 2023 21:56:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702533390; cv=none;
        d=google.com; s=arc-20160816;
        b=rcNMQbK6F1gHQxh+g2juorvAVI662F6BctgM/mA9nNdP5fcNam8reb+WJd6a36nMVH
         lpEmjt5oB8v7NwmAzNWZFToWj4A+GYGIwg/1VPTriviFICJCWf4SGViQfmaQ7A26frFX
         XbfrRXDb0WYwPLM/h1RqX8qPWjfQYnsnSDrKz/jxbXx7qHHAdtoOSmtTWf7y7B5JqCCa
         Ok8dkuokMBMW6NF2ubKPobqfw9AIaxsoIAZoQ+Q9IQ/Rt/Qh/xGEqmpuag4ajhC+MfEY
         MT7NuySCMchNNHyLotCCWPpJHslCgY5Ss5Q948wA1YeeEChpwNIGPE+RFt54rg2gWwxe
         0UdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=sWp9Uy7BqjqTo5fm/PGTmYvFDIkuhCSMTHgBiF7av8c=;
        fh=JZjI76tHrPFh9wXiZ9caJKwSuDkcoMAMvZd7/HZf8J0=;
        b=zyKngTq9LBxC3NsPXo2c0XjzdPvSq1XiOSx/0QvlnFQWyMP90eBZJe2N51Z8zBDbgG
         Z728K7U9mFsLxFoI13oumPsRyuSzbswYrwwr9GAhV/5hejjgFKWHW8MNa9WiciTKqcKM
         Q/COhf5GfHVnTH/PGyxBAeTYHU8hj1ZYsQcvi09wtSPjcu+9CBIAf3hB3NgO4t/fo5Nr
         qdsKLni26ZT/L62sOx3xWF9wNRWcJMSCBBnzVrBRLG7qVobJUg6PP/yJCHobk1DWDNw7
         MZeYs2V6tTooQdMaiC3VJVU76Ir1bRvNhTvqH2qChy/pVCIvlg76Tr93MKm+wmjaeh5R
         72KA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=ZFN6FyDA;
       spf=pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=nicholas@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id t10-20020a9d774a000000b006da221f5f40si76906otl.0.2023.12.13.21.56.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 21:56:30 -0800 (PST)
Received-SPF: pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353723.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BE5qB70029970;
	Thu, 14 Dec 2023 05:56:25 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyuxcr247-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 05:56:25 +0000
Received: from m0353723.ppops.net (m0353723.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BE5scqm002615;
	Thu, 14 Dec 2023 05:56:24 GMT
Received: from ppma11.dal12v.mail.ibm.com (db.9e.1632.ip4.static.sl-reverse.com [50.22.158.219])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyuxcr242-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 05:56:24 +0000
Received: from pps.filterd (ppma11.dal12v.mail.ibm.com [127.0.0.1])
	by ppma11.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BE2mgWW013869;
	Thu, 14 Dec 2023 05:56:23 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma11.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uw592dwev-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 05:56:23 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BE5uMhH18285120
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 14 Dec 2023 05:56:22 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id E261520040;
	Thu, 14 Dec 2023 05:56:21 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 75D9D20049;
	Thu, 14 Dec 2023 05:56:21 +0000 (GMT)
Received: from ozlabs.au.ibm.com (unknown [9.192.253.14])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 14 Dec 2023 05:56:21 +0000 (GMT)
Received: from nicholasmvm.. (haven.au.ibm.com [9.192.254.114])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ozlabs.au.ibm.com (Postfix) with ESMTPSA id 71980605DC;
	Thu, 14 Dec 2023 16:56:19 +1100 (AEDT)
From: Nicholas Miehlbradt <nicholas@linux.ibm.com>
To: glider@google.com, elver@google.com, dvyukov@google.com,
        akpm@linux-foundation.org, mpe@ellerman.id.au, npiggin@gmail.com,
        christophe.leroy@csgroup.eu
Cc: linux-mm@kvack.org, kasan-dev@googlegroups.com, iii@linux.ibm.com,
        linuxppc-dev@lists.ozlabs.org, linux-kernel@vger.kernel.org,
        Nicholas Miehlbradt <nicholas@linux.ibm.com>
Subject: [PATCH 04/13] powerpc: Disable CONFIG_DCACHE_WORD_ACCESS when KMSAN is enabled
Date: Thu, 14 Dec 2023 05:55:30 +0000
Message-Id: <20231214055539.9420-5-nicholas@linux.ibm.com>
X-Mailer: git-send-email 2.40.1
In-Reply-To: <20231214055539.9420-1-nicholas@linux.ibm.com>
References: <20231214055539.9420-1-nicholas@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: Zsg8wvQSHNi46tVffV4C7wLdttglGSj7
X-Proofpoint-ORIG-GUID: fIizHTBc_Dr4RfFFPnPnAj4mfXHJs7tL
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-14_02,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 phishscore=0 malwarescore=0
 clxscore=1011 bulkscore=0 impostorscore=0 mlxlogscore=942
 lowpriorityscore=0 adultscore=0 suspectscore=0 priorityscore=1501
 mlxscore=0 spamscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2312140034
X-Original-Sender: nicholas@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=ZFN6FyDA;       spf=pass (google.com:
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

Word sized accesses may read uninitialized data when optimizing loads.
Disable this optimization when KMSAN is enabled to prevent false
positives.

Signed-off-by: Nicholas Miehlbradt <nicholas@linux.ibm.com>
---
 arch/powerpc/Kconfig | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/powerpc/Kconfig b/arch/powerpc/Kconfig
index 6f105ee4f3cf..e33e3250c478 100644
--- a/arch/powerpc/Kconfig
+++ b/arch/powerpc/Kconfig
@@ -182,7 +182,7 @@ config PPC
 	select BUILDTIME_TABLE_SORT
 	select CLONE_BACKWARDS
 	select CPUMASK_OFFSTACK			if NR_CPUS >= 8192
-	select DCACHE_WORD_ACCESS		if PPC64 && CPU_LITTLE_ENDIAN
+	select DCACHE_WORD_ACCESS		if PPC64 && CPU_LITTLE_ENDIAN && !KMSAN
 	select DMA_OPS_BYPASS			if PPC64
 	select DMA_OPS				if PPC64
 	select DYNAMIC_FTRACE			if FUNCTION_TRACER
-- 
2.40.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231214055539.9420-5-nicholas%40linux.ibm.com.
