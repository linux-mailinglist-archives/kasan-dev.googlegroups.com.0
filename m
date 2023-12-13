Return-Path: <kasan-dev+bncBCM3H26GVIOBBM4B5GVQMGQENPBLIIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E465812347
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 00:39:32 +0100 (CET)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-1f4ddfe6fe1sf12408117fac.1
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 15:39:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702510771; cv=pass;
        d=google.com; s=arc-20160816;
        b=LxB3U+fVVPwcz1uMATt/T3PnKi/EdU53cWUUo5AdLWW/xDauikXYuMsCEwyduDrtJk
         KAa+fA2O6O/5mkGQdk3d2OwC6fnx/VQRgmdvs0iWuB+W2Qi6eWX5uJK5K5TlYJuoXum2
         /cZWAKahtLt2JrmAGDcxyvIJ2ahV4dLuMeLQHQhVQtViJCQwipp4dZ3sUQMyU3SLTvVe
         DNT6I3N7jur2RRfq8AYsJfw9k1mDgsUXctO9/x4oSO2ToBLfmFiHVgJw1bLuzml/bq2a
         WQnEKS0LLohaT+pPsEPGjlLiC7LBaNI7pc800PTiE5OVp0alyW1qHD7xc8r4zKfd6lKt
         xL8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ferbJ4W3wyFad18KfV7SUo7oaOvfjOMkwsTcGvOpyMA=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=WHahCkjbKoq+O8uimcge76coRZ5o7lLNysmctKGDj6ndjt2ZKSCfxH396jNlU6ae8D
         gnjqq34CdQN5uqwcnFqR3U5NY6oPC/K6FtWTWpbMUoSF95WrCyOihO4/wvefN3KzLHTV
         +7bLzC3G/eLO7l+pKMFjdTZrBh7/Z8wg3x0VOlebbXWMcEulE2msgMvlrZTDcuOqGFjp
         MO/yZnh500K9F6p1j15a3AYfxqIBWawVsxswgxDvpLtrHhTrgU3xyMHs1/fYIi0HBFch
         EH/zI9b108o0+R2Jv4qcKZkUdRWQE/yBYtisa5ChVL1jGrP5tHSfq6+OAfrcBWBbm4P8
         OltQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Rss4RCOr;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702510771; x=1703115571; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ferbJ4W3wyFad18KfV7SUo7oaOvfjOMkwsTcGvOpyMA=;
        b=ayMxhntdpDKihou7ZUOyfhA4eghG7/WECuGbMGqzYwmZT8DHKVIVVEhkMzbVDaYvot
         3m7xCw5Dsi1ySXiypvzrHgBgH6DN+kG2K093jZKWLfEqWPYEuc0ZFhxzmYSsdjT/ND/t
         J1c6goU7Si3eRwROmu47DxTMqJgtfrIDirH2h+PjBoHL15h+i+ZYMV1+rMKFkmifm//A
         nWweB3fEU30wTSLeytaZRo73OzxaeWKog3hbITqf0KfJnRj0gnx/3V/dbKU6EFF6juVS
         kfPoT0FFkP1GtFgVDyoqmHzBpnde0QVKPMWjTXVALX6RqEsBcXJQk2z9A2zUdi8RJPog
         KtgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702510771; x=1703115571;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ferbJ4W3wyFad18KfV7SUo7oaOvfjOMkwsTcGvOpyMA=;
        b=dI4nHD5rsIa0x/fwV3fWRX5ZGnsijJigTp1Pvl1YffMms3PypPpEoE4aV8SP4x3GVt
         zSXqHUQ5ZHlHISwrVmMTXFM3LOc7bqywpOotWEf3LOiqx23N0vHg2u/moZZ+xeEg6RaR
         6aRjvTZVGWaltRBprSrzVExDhvekFdqH3tH5W+xEK5mCQJBZesSpp8CODlGYkUcUy/QY
         5QGcpUSXap1IkWFgzDdX4LXUXO47HFXu1YNtPIFkBEyvaTy0kIU9QvhG5pTUaxs8Bdjn
         UHpf22bzbEmWXekq0zEVmIET9UZ4/7uLTk/BS49naUdYRfZ0ntVvSXgI3kiDy563Z5Vk
         Z+MQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyJ8LVwizk243feOewJRlmBtwckHtjo6rz03Ub1YkrVu+8qZhGf
	95CAA7P8neKG0nKp31i4VOQ=
X-Google-Smtp-Source: AGHT+IHJFOIuKZEvsPfMYXkw2JL6EaNHTqFdZbqSaY4Iemcg1RmXMkmzGcUb39bD+QDwcmdgTKWDeQ==
X-Received: by 2002:a05:6871:64c7:b0:1fa:16c2:e8a0 with SMTP id rk7-20020a05687164c700b001fa16c2e8a0mr9786792oab.30.1702510771188;
        Wed, 13 Dec 2023 15:39:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:49c9:b0:203:1826:df23 with SMTP id
 ty9-20020a05687149c900b002031826df23ls1205970oab.2.-pod-prod-08-us; Wed, 13
 Dec 2023 15:39:30 -0800 (PST)
X-Received: by 2002:a05:6870:b69c:b0:203:383d:38ab with SMTP id cy28-20020a056870b69c00b00203383d38abmr993568oab.39.1702510770614;
        Wed, 13 Dec 2023 15:39:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702510770; cv=none;
        d=google.com; s=arc-20160816;
        b=DHFxn4L++nRKX6fiF8Zdr8FrNmNSc8mRZSiNMR/5alRMBwYYne9vvVzakPeX9gxww7
         H37k2b9qGWcGuce+oo4bl3n00C+YJAtQjjWqP87/3uGAbVi/Omy9veZOXU831IWwNhR6
         bS3aUWNLVbY6lanGLBCliCT1pZjQQxqnW347bDKs46gA9CfA5dhGYLeuA6Bcb4blu7EI
         VtioTqSCjjro3ydMJ6QhFIFxG/6MEzXYZh4r1FcolgmBc+F4iQbw0KzBaPC1q5hGdBgy
         UIGuXWGtw2mlgg8jqqQxtFn5hQICOVszVLsft5V7udjsUTCiiXWfptetWPtQ6PX5JsGd
         BOtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=0tC4Q68qibnNxZ7EGQhqKNfW/oX4pAJGU/AeYW+RHN4=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=KCGaEScVU6TjpLfnd+jq9cfzuksEJSQRLkrSjG2gmUefG4jiWnWEIKMKpXXTCUB8Ko
         vRwDfMNgFHBA5hmTQMxWxwSfYD8M4QKhpPZqQz2ODaXcKVdIPLTFwQo03n+gAE0+5mg2
         Z7CgSzdVMhty4MJH3xH3fRe7Fz369KjWPA+M49XB/jNCoZODYhIP1yJP4CFhkXbDKQlD
         J5o3tehNRZVXvu2kngcxahqBsrQ7WMso6B4EDK3JG85nWgyPBBoJYXIzCNrFMuA7+bXL
         yTeEea+yrIh7QK1L5q9yT+VOLk79OUafg+7hahH1fA7TvPK5hVEG9Skx1/lFmtdOqs3B
         sMrQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=Rss4RCOr;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id rh20-20020a05620a8f1400b0077f2dd797bfsi950108qkn.2.2023.12.13.15.39.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Dec 2023 15:39:30 -0800 (PST)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0360083.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDKglgr015451;
	Wed, 13 Dec 2023 23:39:26 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uykvmuvrj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:39:25 +0000
Received: from m0360083.ppops.net (m0360083.ppops.net [127.0.0.1])
	by pps.reinject (8.17.1.5/8.17.1.5) with ESMTP id 3BDMfmvh022983;
	Wed, 13 Dec 2023 23:39:24 GMT
Received: from ppma21.wdc07v.mail.ibm.com (5b.69.3da9.ip4.static.sl-reverse.com [169.61.105.91])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3uykvmuvg3-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:39:24 +0000
Received: from pps.filterd (ppma21.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma21.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 3BDM0FVa012620;
	Wed, 13 Dec 2023 23:36:20 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma21.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3uw3jp4n7t-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 13 Dec 2023 23:36:20 +0000
Received: from smtpav02.fra02v.mail.ibm.com (smtpav02.fra02v.mail.ibm.com [10.20.54.101])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 3BDNaHKZ31916778
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 13 Dec 2023 23:36:17 GMT
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id B934120043;
	Wed, 13 Dec 2023 23:36:17 +0000 (GMT)
Received: from smtpav02.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 53B7F20040;
	Wed, 13 Dec 2023 23:36:16 +0000 (GMT)
Received: from heavy.boeblingen.de.ibm.com (unknown [9.171.70.156])
	by smtpav02.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 13 Dec 2023 23:36:16 +0000 (GMT)
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
Subject: [PATCH v3 05/34] kmsan: Fix is_bad_asm_addr() on arches with overlapping address spaces
Date: Thu, 14 Dec 2023 00:24:25 +0100
Message-ID: <20231213233605.661251-6-iii@linux.ibm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20231213233605.661251-1-iii@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: 8zwUI59DJyquKUco1wEpNP13PakX9rLY
X-Proofpoint-ORIG-GUID: EAgeeP8DOV5nEsx3Wa0hsknLXVRnE7My
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.997,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2023-12-13_14,2023-12-13_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 phishscore=0 mlxscore=0 adultscore=0 spamscore=0 mlxlogscore=891
 clxscore=1015 priorityscore=1501 suspectscore=0 impostorscore=0
 malwarescore=0 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2311290000 definitions=main-2312130167
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=Rss4RCOr;       spf=pass (google.com:
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

Comparing pointers with TASK_SIZE does not make sense when kernel and
userspace overlap. Skip the comparison when this is the case.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/instrumentation.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kmsan/instrumentation.c b/mm/kmsan/instrumentation.c
index 470b0b4afcc4..8a1bbbc723ab 100644
--- a/mm/kmsan/instrumentation.c
+++ b/mm/kmsan/instrumentation.c
@@ -20,7 +20,8 @@
 
 static inline bool is_bad_asm_addr(void *addr, uintptr_t size, bool is_store)
 {
-	if ((u64)addr < TASK_SIZE)
+	if (IS_ENABLED(CONFIG_ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE) &&
+	    (u64)addr < TASK_SIZE)
 		return true;
 	if (!kmsan_get_metadata(addr, KMSAN_META_SHADOW))
 		return true;
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231213233605.661251-6-iii%40linux.ibm.com.
