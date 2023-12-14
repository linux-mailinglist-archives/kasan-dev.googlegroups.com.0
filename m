Return-Path: <kasan-dev+bncBAABBH5S5KVQMGQERI5UKCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113e.google.com (mail-yw1-x113e.google.com [IPv6:2607:f8b0:4864:20::113e])
	by mail.lfdr.de (Postfix) with ESMTPS id D71CD812735
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 06:56:48 +0100 (CET)
Received: by mail-yw1-x113e.google.com with SMTP id 00721157ae682-5ca26c07848sf89481247b3.0
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 21:56:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702533407; cv=pass;
        d=google.com; s=arc-20160816;
        b=l+/33KXPxOjNiX8B7Ms4YwTtP2CwniGt+bneg+qPDsp1OQ5/ZL9NxQyojRae6S3Xi8
         T8T9GXB1LTswctGKJKt/L1uif1YjiiheVP2jnDSbQWrfmyEA6aIFUID5RDc9jqrYADmy
         mz1vN7IMUu57ARq7HK2xSNnEl0KBTJy0r48kqTS6KI6C3tF4vCzDqxwdvDH33C9+nVS+
         yFTinYhuafEBSTvv2BQtGOexzijgbqCsOm3QmKlFskUxkDuTOSbIzm1NkUJxsrhqkLW/
         7mIroYwGLMcgauxUoGpbNWyJCGK2QJPtSmKHGPRtuPAoyZtKyVCu/3IzLhMRZX2EcXCi
         T/cw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=QjGCwJIDVFfnX3ZlkL1MQesIJl6/JewqDZkYXPfssyc=;
        fh=JZjI76tHrPFh9wXiZ9caJKwSuDkcoMAMvZd7/HZf8J0=;
        b=EhD6ZY4q0A2ycKjCWWRCHlE5QOe4P0gSsz70PySUdlZtPIYLCnK01q7S3jPDAkh3ZR
         qBYAgRVZeInl96QO3FjcjgPpZSbpEwjCLq5AF55DRtgxi7rReQkCc1Cb53B02Xn3UDMK
         GLbza7aIuXn4fMVuB42rh2bDKnoAX/FME3M7M9tqtqp5qSdNLoCGXXVLOi7Z60n1KV3K
         2eGL3UPMl4ENwXJg7hGxiAauHddBOcZhg1wjwevv6ULNo5T+J3qVCiXbyWvlb0N4ggF2
         WCju71pXX5WNj04TnVJOktxK3CsizC4K7qQFAMsPTrTfhiYw0FgDtHziEA/Z5YHzhGmD
         PYWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=B6a81kWj;
       spf=pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=nicholas@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702533407; x=1703138207; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QjGCwJIDVFfnX3ZlkL1MQesIJl6/JewqDZkYXPfssyc=;
        b=PpQkbCA/RACVIH1m5BhjUw/uzXaBtTuTbrQe71JHMt/j3qGsfn3oeeoU49fkgGrjSB
         fGZ2uDnDqYs85mXDCc3E7rmxFbVsWL8+GMXh18wA5tnQKn2QpjDWyqT5bNqOOlTUGcrO
         u/altDDKA2Da62WpB9DS/SSp2DdSa1ky4B1PGBBg2ld1FPSEsKoK247uQbRNoFmbQoxj
         1OTutqveW/NzGxjLBGot9ftIL1El3kXVH1eqlFhghIR18Skq5KwWlX/vUrq/Ymntvfsh
         AfMqfNcN70FJKuQtrRnXO5gdpKrnyvAregQRX4FxoSsAecZ9ZoldSVrNt2ByxRJ+u9YI
         l38Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702533407; x=1703138207;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QjGCwJIDVFfnX3ZlkL1MQesIJl6/JewqDZkYXPfssyc=;
        b=sRbD/CXHukSwQDrTZRZbZZjfSJm9++BriaPDthOtZzpcMi4ArPXANhjc/TPqRDIdem
         fNjsdyNwkNFLE2qnJvnu9m1rQblECCSi4I8nyVvVraAizMyV2EY06vwa6g0rG5xD8h/R
         wJIoVev4pioH1SW5EPnErw5hM8v7gKBNWRgRvaqFnAY+RrRuqbARjD2UQaguCTpxACNV
         /o7Vg4dAjLtNuZ8zu9S+kbSp9DGhY/BUp/eUlZMWfkMgobdrRJLvArq34FQPQxN9dUrh
         j8tdROunuS1qK96Wx981iF4uzKr5wL/n6CP3rtKVpcaOhnWWCTk9Y7mTos74+fKXESWr
         DK5Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YywBuC9DLBXC9Dp93uZOjB1A9KfjcUiWpDFlO3nN7pAsR++aczH
	e+/nLNjUaiVZ8CgagrcZOJs=
X-Google-Smtp-Source: AGHT+IHJLkFvpXwoT6D1850XJhgIQKOJaFayVBbqh53qzJBQfcH+Qb1gppPtktk5FuZcGR3m646snQ==
X-Received: by 2002:a81:6505:0:b0:5d3:b982:57ae with SMTP id z5-20020a816505000000b005d3b98257aemr6579520ywb.4.1702533407586;
        Wed, 13 Dec 2023 21:56:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:cf8b:0:b0:dbc:afb0:5d0 with SMTP id f133-20020a25cf8b000000b00dbcafb005d0ls211267ybg.1.-pod-prod-09-us;
 Wed, 13 Dec 2023 21:56:47 -0800 (PST)
X-Received: by 2002:a25:10d5:0:b0:dbc:dced:c022 with SMTP id 204-20020a2510d5000000b00dbcdcedc022mr974027ybq.75.1702533406783;
        Wed, 13 Dec 2023 21:56:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702533406; cv=none;
        d=google.com; s=arc-20160816;
        b=npM5TBYb1an886hFB44BED/5sz1GR+w72LK2D0qNHQNTRYyi2sSmPFmfaAut/+boas
         WwzD5mx0ZqxfJwwI0VNhr8oI7381Ch8W3Ajm5Z9c1xsqLiI6g9qZLipSNEgiH6giD02E
         K2tgwLNBdw2Tp2123HHjqwdVx1K94zhboYHyh6rMWqAdDzb7aSGqGOEgkfJMsKbOB8+U
         A4d4MohU3HLXDmzLthVfiX+4ij17AOmO1vT0NQ4/kGOFbtphC8wcpEI79oXN6yM/0q97
         JK+YuJJKMN+FoVssmk5DtIM4/GVEHKlSG7BKNK2F8UPyzZK+L3FrUtGpmAW33bHs0NqN
         2HYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=GJ3DflkJ71hJbiYLI+SB612UjG8o6wDZ5KCvtzBQhUc=;
        fh=JZjI76tHrPFh9wXiZ9caJKwSuDkcoMAMvZd7/HZf8J0=;
        b=uarERFN0bOUG9iGNoQthfjFeKUWBqvlVFcpkGTc1/dvtG3Gxx/MnRJ3VBdPiwTeRsN
         S8s24q7Po+fzSqniNDo+KcT1tLUM8NpO5WLsGEnb1hq14VuvOCQQ0ijCFYhoKpcEJ7a+
         U/tttkSPiv9shLTPoBMHu2bBFk3ZMbIc2mxlzZOLDrZbQmVA/d+LHDaTx0KHUuq5HgBi
         PFxH7OKcLuA1gJN5NRaFYf0P++g7UXZuA3wd9X3t4HFyrJ0M0XU3nUqGhb1l9OlVF0P7
         6nTCqw7gXaQhG9ZFUF75R+p3cyyZTvdyd22qeP4zzkmIh8FGbFGhQ958YfYC14D7yPtr
         N0Gg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=B6a81kWj;
       spf=pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=nicholas@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id f11-20020a25cf0b000000b00daf81fc5a57si1667024ybg.0.2023.12.13.21.56.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 21:56:46 -0800 (PST)
Received-SPF: pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0360072.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BE3EvTV002599;
	Thu, 14 Dec 2023 05:56:41 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyp5cq85g-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 05:56:40 +0000
Received: from m0360072.ppops.net (m0360072.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BE5prqX011260;
	Thu, 14 Dec 2023 05:56:40 GMT
Received: from ppma12.dal12v.mail.ibm.com (dc.9e.1632.ip4.static.sl-reverse.com [50.22.158.220])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyp5cq82p-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 05:56:39 +0000
Received: from pps.filterd (ppma12.dal12v.mail.ibm.com [127.0.0.1])
	by ppma12.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BE31fxX008585;
	Thu, 14 Dec 2023 05:56:25 GMT
Received: from smtprelay05.fra02v.mail.ibm.com ([9.218.2.225])
	by ppma12.dal12v.mail.ibm.com (PPS) with ESMTPS id 3uw2jtpnfu-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 05:56:25 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay05.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BE5uO0p8061652
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 14 Dec 2023 05:56:24 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id EC7552004B;
	Thu, 14 Dec 2023 05:56:23 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 7D77E20040;
	Thu, 14 Dec 2023 05:56:23 +0000 (GMT)
Received: from ozlabs.au.ibm.com (unknown [9.192.253.14])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 14 Dec 2023 05:56:23 +0000 (GMT)
Received: from nicholasmvm.. (haven.au.ibm.com [9.192.254.114])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ozlabs.au.ibm.com (Postfix) with ESMTPSA id 7EC8A60556;
	Thu, 14 Dec 2023 16:56:19 +1100 (AEDT)
From: Nicholas Miehlbradt <nicholas@linux.ibm.com>
To: glider@google.com, elver@google.com, dvyukov@google.com,
        akpm@linux-foundation.org, mpe@ellerman.id.au, npiggin@gmail.com,
        christophe.leroy@csgroup.eu
Cc: linux-mm@kvack.org, kasan-dev@googlegroups.com, iii@linux.ibm.com,
        linuxppc-dev@lists.ozlabs.org, linux-kernel@vger.kernel.org,
        Nicholas Miehlbradt <nicholas@linux.ibm.com>
Subject: [PATCH 06/13] powerpc/pseries/nvram: Unpoison buffer populated by rtas_call
Date: Thu, 14 Dec 2023 05:55:32 +0000
Message-Id: <20231214055539.9420-7-nicholas@linux.ibm.com>
X-Mailer: git-send-email 2.40.1
In-Reply-To: <20231214055539.9420-1-nicholas@linux.ibm.com>
References: <20231214055539.9420-1-nicholas@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: 6Qm5TuhCW2ZCW6IWoQUq-GlcW7W_bWov
X-Proofpoint-GUID: 2p1ymeKpjzD86ICS6ki9AjTIJuqVnLjL
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-14_02,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 impostorscore=0 mlxscore=0
 spamscore=0 malwarescore=0 mlxlogscore=762 bulkscore=0 suspectscore=0
 phishscore=0 priorityscore=1501 adultscore=0 lowpriorityscore=0
 clxscore=1015 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2312140035
X-Original-Sender: nicholas@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=B6a81kWj;       spf=pass (google.com:
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

rtas_call provides a buffer where the return data should be placed. Rtas
initializes the buffer which is not visible to KMSAN so unpoison it
manually.

Signed-off-by: Nicholas Miehlbradt <nicholas@linux.ibm.com>
---
 arch/powerpc/platforms/pseries/nvram.c | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/arch/powerpc/platforms/pseries/nvram.c b/arch/powerpc/platforms/pseries/nvram.c
index 8130c37962c0..21a27d459347 100644
--- a/arch/powerpc/platforms/pseries/nvram.c
+++ b/arch/powerpc/platforms/pseries/nvram.c
@@ -14,6 +14,7 @@
 #include <linux/ctype.h>
 #include <linux/uaccess.h>
 #include <linux/of.h>
+#include <linux/kmsan-checks.h>
 #include <asm/nvram.h>
 #include <asm/rtas.h>
 #include <asm/machdep.h>
@@ -41,6 +42,7 @@ static ssize_t pSeries_nvram_read(char *buf, size_t count, loff_t *index)
 	int done;
 	unsigned long flags;
 	char *p = buf;
+	size_t l;
 
 
 	if (nvram_size == 0 || nvram_fetch == RTAS_UNKNOWN_SERVICE)
@@ -53,6 +55,7 @@ static ssize_t pSeries_nvram_read(char *buf, size_t count, loff_t *index)
 	if (i + count > nvram_size)
 		count = nvram_size - i;
 
+	l = count;
 	spin_lock_irqsave(&nvram_lock, flags);
 
 	for (; count != 0; count -= len) {
@@ -73,6 +76,7 @@ static ssize_t pSeries_nvram_read(char *buf, size_t count, loff_t *index)
 	}
 
 	spin_unlock_irqrestore(&nvram_lock, flags);
+	kmsan_unpoison_memory(buf, l);
 	
 	*index = i;
 	return p - buf;
-- 
2.40.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231214055539.9420-7-nicholas%40linux.ibm.com.
