Return-Path: <kasan-dev+bncBAABBLFS5KVQMGQEJQRYNSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 15E12812737
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 06:57:02 +0100 (CET)
Received: by mail-yb1-xb3c.google.com with SMTP id 3f1490d57ef6-dbcdcc99e29sf226737276.1
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 21:57:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702533421; cv=pass;
        d=google.com; s=arc-20160816;
        b=oJEMfgvQEoqiii5an7NTlriUcWRj6W4Zo5s1GmyapyUT70NNhQSjZeC6lvxju5rlwe
         q2tR5Ip9M1R3VqLbwjrE5HC0r8R5lJdPw8NkBBe61/LsBMnfApq0xjP6L23I6NUcGlfE
         gA3u/m73Rao5UR8COT+BtSeC95QDpOA42HXwAdW6x273HP4CvVqpLwR2Al6hyCuSWZ7h
         BlUoybVSj7UxWEXosKWXq7Kyt5oi/P2nT3AA8h99RJRlaOt+0qZyu6HaWxYMGb6GW7E4
         ISmIHak9+H2xUXPfS3el4q3K6hiWK6urG2yLCh5Mf+t6GFsUwuAus9ZwHKIQKGLTPHp/
         6zGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=/DwW0NYzZclc05+vzEUTsTEpPORi1AwLC2WikM7bdV4=;
        fh=JZjI76tHrPFh9wXiZ9caJKwSuDkcoMAMvZd7/HZf8J0=;
        b=r0vdYalmzMX+Xw7oqaQX0KePu/lrGfSnsLYAoEO7wbqIW2Mq4HQIw07IVZ+XgakgBq
         TjQeMnh4n0dlzhCIWyp7qpkmFOFG9ajsXjXFQWOT13k4zWcTVNYPKhoKX2T9DuWASB75
         ZvrMq5xK5Yge/fcXh2uHQSDd0jJNbx4eS3ZEggf8HjpeHWPpWRa+8xMJ0sG7QNMA4XvA
         EI7ESCy0viMTHQEA1VK9L9s20FB5e4VdzYdk7uc+oZWbq5Td8tJK0m4eDBwlv/55+wXg
         zE9kFtj2yPAB93G8YHtcqgfRm6NXEGtwmnT6Dfwn0ZuG3nvpPhuhsfGRKU/cvTjkgHgW
         NikA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=pVMS5U4m;
       spf=pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=nicholas@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702533421; x=1703138221; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/DwW0NYzZclc05+vzEUTsTEpPORi1AwLC2WikM7bdV4=;
        b=qSr6Pj4VJ1o7d3T3d7rGI9b/jeNbFvRvtL2OZMiEihPXMgJvUs3K/9Sthjt+5FCRdU
         yJwPwpfVcwdOvle5rU6pCTA3GY1KgbGBrMogjd5U8XRth5ulQyNB6ls1UDjntZiquddq
         wbYx6YPSZDoTbW0Maek1EqIn0cwIIMAC+Bor6bPr8AQ48LLROc8il/KdhrZRapPxYwHW
         D0TDIy+EVQgAZS8UlyjxA8MvDSGpU92k5l5hJRWLVxIwBVwW3QhfgMT5kvCwOchbGrnV
         3ClYpJJSZuZ3j38xScF96bNYvfR8hdGyZJ7U5sk0DbcRgAnr0vGHgER9LHKLgQU/DZU5
         wiag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702533421; x=1703138221;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/DwW0NYzZclc05+vzEUTsTEpPORi1AwLC2WikM7bdV4=;
        b=alxt1u7mxyjOL9d7jNv4NP4bglE8OGoEgs6irKymDwcAi2LiwfUcXtI5ugJd+trEOt
         i7gPdcnko7UF0Y5dFxGw7ZmleiI6ATjszgj1TlIMcmm1nZAPzWzZDVa6Wi7mXHjNBrTd
         qSBRCoFCM0J+SgJuY6+ZBAm0nRHMj+MhYv+v24knbNivChZbU+9PiQWcFRyaHSx0upn2
         1HgzLd6sDb+vgrbLpDPbKiFXkqK48fivw6xaf2Pa64p799rCc2iAwRp7RjRApOEx9IkE
         xesWUMzyERo+N2Ml9wbAsQqkhAShrLRhFwNX9zM1CJPBjbnOQLZf0vXJMLzXfmKe+H3/
         QCIA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yywo5FC80+aoOVHn4ffoD60LYsk3jApXXgJ1ZzHFlrJtmPPDTp6
	jEITdy2LkF3ji/BTXPXBsIQ=
X-Google-Smtp-Source: AGHT+IHBkbcyuCgJt0aNwhgbJw6EqZPtS24p1hZMcqYCf6tfCBobS1JXGeS+s1bMYJaVtuFFKtiFew==
X-Received: by 2002:a25:2f50:0:b0:dbc:bf29:3193 with SMTP id v77-20020a252f50000000b00dbcbf293193mr2820677ybv.0.1702533420912;
        Wed, 13 Dec 2023 21:57:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:cf8a:0:b0:d9c:c968:ec87 with SMTP id f132-20020a25cf8a000000b00d9cc968ec87ls898117ybg.0.-pod-prod-00-us;
 Wed, 13 Dec 2023 21:57:00 -0800 (PST)
X-Received: by 2002:a25:9e06:0:b0:dbc:caf5:b351 with SMTP id m6-20020a259e06000000b00dbccaf5b351mr2132334ybq.6.1702533420101;
        Wed, 13 Dec 2023 21:57:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702533420; cv=none;
        d=google.com; s=arc-20160816;
        b=aJfP2DVsP2g+FAHWwYkupYXJ5oK2mfWSWtIQHiSP4iSajxj4Dro7PxWjRR3cpf33vV
         FoJvgrd4pDKASxo3ezUsBzDJKF6+n5eIP4rYbD1Gt4TicgjeESugUoloTLGYgCQ9tEAO
         8pn3/Akz6ZIyEhVd+p0dhMDNYsQBtL9I+Sg/nspIaIy2Isi/XTW9rImHM9wUBAbRWooQ
         zz/tp1mf12P8uK6NdPRwt7XsHgE7NRo4ZyWhi8YkMR58PXAq3mKp+Wh9JCtM+8kCX9BK
         p+HL0hunvbcAh7DO2YiupsvVk0O/H5Zu3Ewrbl8jIvoXz7frvg8ekAhbpY0l0GIQ45Nm
         l5pg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=S5PvZzwihJCEtsOMzLDq/hhL3tFxZ+GRI8sP7cCU/cE=;
        fh=JZjI76tHrPFh9wXiZ9caJKwSuDkcoMAMvZd7/HZf8J0=;
        b=hwP5OOE8+SP605H8caYJS0ido7uM7hlki47crKuOiE6DwZ6TLXHB8BRxi1f4NM8VbJ
         zMmt1dj4q+NchdXngihtFMZwvvk607yW1JLQlq9eyEqECR5mH/Tk5415rk2QnA67tYE+
         9r0jPEytLwoJqfMNCdsWZFXBzs/gWPlAERBw9vmRX3vGuajiriDa5bPms5o3BOowNaoN
         jKmk/YyCiL/Fttp3wp6kmh2wauxrjMTUymLVg21020+kdlg4H+QNfLjaPLxdNVuB84mt
         TM1LQN3t2C3z5SboHEUmwwD9T98TrqSdDf3T1BSMEtv9wapxL267w8Avx03WKZOz075B
         OBMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=pVMS5U4m;
       spf=pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=nicholas@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id p136-20020a25428e000000b00da06a7c4983si1524285yba.2.2023.12.13.21.57.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 21:57:00 -0800 (PST)
Received-SPF: pass (google.com: domain of nicholas@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353722.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BE4Whb3031214;
	Thu, 14 Dec 2023 05:56:55 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyts2hk9p-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 05:56:54 +0000
Received: from m0353722.ppops.net (m0353722.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BE5SBmS029575;
	Thu, 14 Dec 2023 05:56:54 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uyts2hk39-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 05:56:54 +0000
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BE3JYZ1028220;
	Thu, 14 Dec 2023 05:56:26 GMT
Received: from smtprelay02.fra02v.mail.ibm.com ([9.218.2.226])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uw2xyxhmk-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 14 Dec 2023 05:56:26 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay02.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BE5uOjJ22151732
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 14 Dec 2023 05:56:24 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 04D7B2004D;
	Thu, 14 Dec 2023 05:56:24 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 864E920040;
	Thu, 14 Dec 2023 05:56:23 +0000 (GMT)
Received: from ozlabs.au.ibm.com (unknown [9.192.253.14])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 14 Dec 2023 05:56:23 +0000 (GMT)
Received: from nicholasmvm.. (haven.au.ibm.com [9.192.254.114])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ozlabs.au.ibm.com (Postfix) with ESMTPSA id 77E0D605F3;
	Thu, 14 Dec 2023 16:56:19 +1100 (AEDT)
From: Nicholas Miehlbradt <nicholas@linux.ibm.com>
To: glider@google.com, elver@google.com, dvyukov@google.com,
        akpm@linux-foundation.org, mpe@ellerman.id.au, npiggin@gmail.com,
        christophe.leroy@csgroup.eu
Cc: linux-mm@kvack.org, kasan-dev@googlegroups.com, iii@linux.ibm.com,
        linuxppc-dev@lists.ozlabs.org, linux-kernel@vger.kernel.org,
        Nicholas Miehlbradt <nicholas@linux.ibm.com>
Subject: [PATCH 05/13] powerpc: Unpoison buffers populated by hcalls
Date: Thu, 14 Dec 2023 05:55:31 +0000
Message-Id: <20231214055539.9420-6-nicholas@linux.ibm.com>
X-Mailer: git-send-email 2.40.1
In-Reply-To: <20231214055539.9420-1-nicholas@linux.ibm.com>
References: <20231214055539.9420-1-nicholas@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: oohPGHWoNwWW22yXQxLqPk3YupwgWY9n
X-Proofpoint-GUID: v3dSSLQcrbP9Wpukc5CGgwUiAQvQLOIY
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-14_02,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 adultscore=0
 lowpriorityscore=0 suspectscore=0 mlxlogscore=695 malwarescore=0
 clxscore=1015 priorityscore=1501 impostorscore=0 spamscore=0 mlxscore=0
 bulkscore=0 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2312140035
X-Original-Sender: nicholas@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=pVMS5U4m;       spf=pass (google.com:
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

plpar_hcall provides to the hypervisor a buffer where return data should be
placed. The hypervisor initializes the buffers which is not visible to
KMSAN so unpoison them manually.

Signed-off-by: Nicholas Miehlbradt <nicholas@linux.ibm.com>
---
 arch/powerpc/platforms/pseries/hvconsole.c | 2 ++
 arch/powerpc/sysdev/xive/spapr.c           | 3 +++
 2 files changed, 5 insertions(+)

diff --git a/arch/powerpc/platforms/pseries/hvconsole.c b/arch/powerpc/platforms/pseries/hvconsole.c
index 1ac52963e08b..7ad66acd5db8 100644
--- a/arch/powerpc/platforms/pseries/hvconsole.c
+++ b/arch/powerpc/platforms/pseries/hvconsole.c
@@ -13,6 +13,7 @@
 #include <linux/kernel.h>
 #include <linux/export.h>
 #include <linux/errno.h>
+#include <linux/kmsan-checks.h>
 #include <asm/hvcall.h>
 #include <asm/hvconsole.h>
 #include <asm/plpar_wrappers.h>
@@ -32,6 +33,7 @@ int hvc_get_chars(uint32_t vtermno, char *buf, int count)
 	unsigned long *lbuf = (unsigned long *)buf;
 
 	ret = plpar_hcall(H_GET_TERM_CHAR, retbuf, vtermno);
+	kmsan_unpoison_memory(retbuf, sizeof(retbuf));
 	lbuf[0] = be64_to_cpu(retbuf[1]);
 	lbuf[1] = be64_to_cpu(retbuf[2]);
 
diff --git a/arch/powerpc/sysdev/xive/spapr.c b/arch/powerpc/sysdev/xive/spapr.c
index e45419264391..a9f48a336e4d 100644
--- a/arch/powerpc/sysdev/xive/spapr.c
+++ b/arch/powerpc/sysdev/xive/spapr.c
@@ -20,6 +20,7 @@
 #include <linux/mm.h>
 #include <linux/delay.h>
 #include <linux/libfdt.h>
+#include <linux/kmsan-checks.h>
 
 #include <asm/machdep.h>
 #include <asm/prom.h>
@@ -191,6 +192,8 @@ static long plpar_int_get_source_info(unsigned long flags,
 		return rc;
 	}
 
+	kmsan_unpoison_memory(retbuf, sizeof(retbuf));
+
 	*src_flags = retbuf[0];
 	*eoi_page  = retbuf[1];
 	*trig_page = retbuf[2];
-- 
2.40.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231214055539.9420-6-nicholas%40linux.ibm.com.
