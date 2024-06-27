Return-Path: <kasan-dev+bncBCM3H26GVIOBBY4D62ZQMGQEIHISCQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 272DE91AADA
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Jun 2024 17:14:45 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-37625537d64sf124959255ab.2
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Jun 2024 08:14:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719501284; cv=pass;
        d=google.com; s=arc-20160816;
        b=hwHCVRv3wS9ksMUbi+RvuynVuFqakBAXs0duVNzC0aWUD2prY849qovo0JgM6a3nSu
         p+v2Q9fG/o1DJQDpxTcHCG5K0CTuLSzblWZnWSGuTVTcg8pp41H1y6mWNWAp/N6wp2ZT
         YIFhh7QBw+Ygo92HGRxspsXmJF53GVecfmCztVxJxS6hx5ffgsQnFcCdebMvDeA6pxn4
         aM43Yg7ATIkqjl34UvNXlm5pwfZ9mQCC2cdBJHRb/2k/tEk4PJqcVURRSOXA0+E9O89Y
         XT2ILpUAGfcjzE0XMt+zOCaZP4/HqLHC1q8eHiVucw7ToPvUHNyG8w152BOZvo7/FuEG
         hcNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=/Ydzpp36BpjR+IdPzkgOh/hkWBIrm/p6uJ+8sMs4VD4=;
        fh=amihSavnjq9W84IUQCQsAOi0tS5gDufT3tmEpajopHk=;
        b=zrvdY0OkfumlYZKBU2nLehrF8YStVmKb2A2hi2rZ/CcGFMzRgsPE1s/q92CWQMPG0O
         c4N7Uy8l4nDQufAen2wb2HJj9Dl2TnSiQ0Tn59A0ADg3NCCdODA0wVdPBmUy5OqQ+DQD
         COEfvY5tmmG/Uv76lpScRvmkfuhAp04/uICsYeGuc5HBcqW4RKp2BPJFWGfWfEPLrokE
         FKQCIO4+r3cyKKt4qoejy/yMY5To76GQQrhRSm0R1DcMLu3u9b76rVxFbUMg1+hQJvHi
         tdr55PTDOpQ+ZECixWwPsCJD046RTZOlkgx5nOXFtmS6onO6+I4PDXIBUFe+9HxcKOxV
         Z/0Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=HYol0NrL;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719501284; x=1720106084; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/Ydzpp36BpjR+IdPzkgOh/hkWBIrm/p6uJ+8sMs4VD4=;
        b=t6sMQYw4YQi4SQ5zrT0sTWYh99Xte8FqHcyiG8GFDxw1+8Qz7azGfSSkksIPis2gAT
         kuWtq8DvIihaUK9BHBmrMcVmOLHiNEsTZcmCH/iOD1sD8x4IcPkn72/pJ/dWxd70OrPq
         0CRRqlhGAL1qqZm3/DzOp4zVhAEgTwIAlsFagLB0G5q5Ie/wqdS30XMHfQwB88d1T8B3
         Ewecfstlbs6daITQAAOz6xg7V59kPObJUqjUqf98EPAH+WQIxlZv4Q7msmxsyLA+YjSt
         OXAv0xnaPiOTG/+fWfETKr4qv1ntwPutbTUJvwz19+1ztTyHzBQ/4Q7snZSKFhtNCS78
         WQ/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719501284; x=1720106084;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/Ydzpp36BpjR+IdPzkgOh/hkWBIrm/p6uJ+8sMs4VD4=;
        b=LlSf/h/fbUvv2DcTqR7/tMx5VJMQwIObxbKf6mC6taLSbTcICNiS2mNP91dUYDeb76
         tbKelb59GI0dEwnHb0EY2s8pUr63LZr36UzqvnWAv1ekWayD2VIaZRKGU2m36haEGwUU
         aXG/iK1tixG9jsQ83fLip7ekW4AKcLu+nxbWlboaCWlsgIUX8I3nXOKKiftyEpmXbuIP
         keJwKHxRKddXrkrhEhU2UfVh3hOYlp79oyRYSvfM+ZGvwqBZjHXJ6L/3t4GkMGzVj0Jq
         RvobzILEA+PlKwPvPul73qLzaESPlB0nf/PfneKjpVgf4jzBmpGCFcPXX7nujBufH+NX
         QQTQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVLjeY9PYmNP68G19SfLbBLLVIbFZI2tFiXyHjD/WcMasSYbmBLEVK/o69MO1ajFcgKQ23innIgNGS1ADEwMtgdAMLh6uIinQ==
X-Gm-Message-State: AOJu0Yyu5C+Fi+ftPuDPPmucrvwfZ0qKiC1ReDPU7xfoqqhJlstw6Ihy
	x/mPSdcn0vln9iws/EILp3qQnXWQGPWBbql4V1i/hPr/1NOcqN33
X-Google-Smtp-Source: AGHT+IGOMrXQCZwCoGB5zncB85wcv5eSalhpwf5xRts5FdUgoLYafGCfiXjMMSkB3qyyzaP0D2XEGw==
X-Received: by 2002:a05:6e02:1485:b0:377:1611:1b49 with SMTP id e9e14a558f8ab-37716111c7amr100037565ab.25.1719501283696;
        Thu, 27 Jun 2024 08:14:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c543:0:b0:375:c4e6:a46e with SMTP id e9e14a558f8ab-37626ac543cls65516345ab.1.-pod-prod-07-us;
 Thu, 27 Jun 2024 08:14:42 -0700 (PDT)
X-Received: by 2002:a05:6602:6d08:b0:7eb:8c69:86d6 with SMTP id ca18e2360f4ac-7f3a75c0251mr1610265539f.14.1719501282554;
        Thu, 27 Jun 2024 08:14:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719501282; cv=none;
        d=google.com; s=arc-20160816;
        b=rrDjSBFrni/AtUPKXzhvLFUlrZCwONLEBkta0R8Bh9OOslSdLS5wut7H8Zj6C9Nsfg
         7o0bcriq38Xw5UTzG+kYiQ9uusd5D0t9zCRJNrNQg/soqaYAAvwHt2tpG8ivJP9SY+O+
         8fJahLCZPBrTKA3ewlBc7PGllkmoDGX6bW1iqVlzbKu361sm063NzdYymWK5EEwcChEl
         d7+Cid/6fG4IleTmzv7rg2e+RsvVgtRc+uWyPnQ7VREX4/Gjwz9sl+QU9hBBAriUta+j
         QjfGWayRCCApAFH7h9F1jg8kciYmUwv2RnIbZVLrZpipLFmpZTYV/+ND6hLWQwXLn0wR
         3PVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=V66HzH9oSR/SiSXR4ViDL5nQK43Lz5hHmVXw8cMBNuw=;
        fh=uWS0ctYKU363E7TZo1JbUf4LNo3jJz4pzV4p0GSEd80=;
        b=ydDJSfyd4eCfD/rfPR47ywEpmI5Dnon71lQSmErokN1bwGhVHOJXhnfxZuxyjvQlFv
         +wGW21Cc+YON4mi7u5INq7B/P1kdWLYQbwf212DeVpyx9PXKbPTs62jnpfu6DBQvCJ7Y
         AAnI4u/0gmku/fau6n81y73/APzhe+6McytxC9RQ9kPcswydcTu0L8ErqFiCiQ4teTwx
         K2i88dmIC6aVd9cI0C73FnCIhIVeGgM9XggvxccocFO9egygyP4gbmXBQ/HB4E0HNUM1
         m8+30/Ugw9+P7h/yLyqkrsFfKEPJ8/sbIE/la1BwNh12am99YIGwHnbixd04sUwW79sT
         3ZTg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=HYol0NrL;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4bb6659fec9si44866173.4.2024.06.27.08.14.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 27 Jun 2024 08:14:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0353725.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45RExQfU013827;
	Thu, 27 Jun 2024 15:14:41 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 401aagr19w-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 27 Jun 2024 15:14:41 +0000 (GMT)
Received: from m0353725.ppops.net (m0353725.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45RFEffv005834;
	Thu, 27 Jun 2024 15:14:41 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 401aagr19m-10
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 27 Jun 2024 15:14:41 +0000 (GMT)
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45REWkbs008183;
	Thu, 27 Jun 2024 14:58:03 GMT
Received: from smtprelay01.fra02v.mail.ibm.com ([9.218.2.227])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 3yx9b13fea-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 27 Jun 2024 14:58:03 +0000
Received: from smtpav07.fra02v.mail.ibm.com (smtpav07.fra02v.mail.ibm.com [10.20.54.106])
	by smtprelay01.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45REw0Ot54133066
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 27 Jun 2024 14:58:02 GMT
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id E340E2004E;
	Thu, 27 Jun 2024 14:57:59 +0000 (GMT)
Received: from smtpav07.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 5F12420043;
	Thu, 27 Jun 2024 14:57:59 +0000 (GMT)
Received: from heavy.ibm.com (unknown [9.171.10.182])
	by smtpav07.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Thu, 27 Jun 2024 14:57:59 +0000 (GMT)
From: Ilya Leoshkevich <iii@linux.ibm.com>
To: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org,
        linux-kernel@vger.kernel.org, Ilya Leoshkevich <iii@linux.ibm.com>,
        kernel test robot <lkp@intel.com>
Subject: [PATCH 2/2] kmsan: do not pass NULL pointers as 0
Date: Thu, 27 Jun 2024 16:57:47 +0200
Message-ID: <20240627145754.27333-3-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.2
In-Reply-To: <20240627145754.27333-1-iii@linux.ibm.com>
References: <20240627145754.27333-1-iii@linux.ibm.com>
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: mcPDNdB_CcP6JYr2AQf9iTbwGMyHfuTJ
X-Proofpoint-GUID: db94Zo-DaWkLUU5XH6LyXhk3sy8TGMD3
X-Proofpoint-UnRewURL: 0 URL was un-rewritten
MIME-Version: 1.0
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-27_11,2024-06-27_03,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxlogscore=968 spamscore=0
 bulkscore=0 suspectscore=0 mlxscore=0 phishscore=0 clxscore=1015
 priorityscore=1501 lowpriorityscore=0 adultscore=0 malwarescore=0
 impostorscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2406140001 definitions=main-2406270113
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=HYol0NrL;       spf=pass (google.com:
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

sparse complains about passing NULL pointers as 0.  Fix all instances.

Reported-by: kernel test robot <lkp@intel.com>
Closes: https://lore.kernel.org/oe-kbuild-all/202406272033.KejtfLkw-lkp@intel.com/
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/kmsan/hooks.c           | 15 ++++++++-------
 mm/kmsan/instrumentation.c |  4 ++--
 2 files changed, 10 insertions(+), 9 deletions(-)

diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 26d86dfdc819..3ea50f09311f 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -303,7 +303,8 @@ void kmsan_handle_urb(const struct urb *urb, bool is_out)
 	if (is_out)
 		kmsan_internal_check_memory(urb->transfer_buffer,
 					    urb->transfer_buffer_length,
-					    /*user_addr*/ 0, REASON_SUBMIT_URB);
+					    /*user_addr*/ NULL,
+					    REASON_SUBMIT_URB);
 	else
 		kmsan_internal_unpoison_memory(urb->transfer_buffer,
 					       urb->transfer_buffer_length,
@@ -316,14 +317,14 @@ static void kmsan_handle_dma_page(const void *addr, size_t size,
 {
 	switch (dir) {
 	case DMA_BIDIRECTIONAL:
-		kmsan_internal_check_memory((void *)addr, size, /*user_addr*/ 0,
-					    REASON_ANY);
+		kmsan_internal_check_memory((void *)addr, size,
+					    /*user_addr*/ NULL, REASON_ANY);
 		kmsan_internal_unpoison_memory((void *)addr, size,
 					       /*checked*/ false);
 		break;
 	case DMA_TO_DEVICE:
-		kmsan_internal_check_memory((void *)addr, size, /*user_addr*/ 0,
-					    REASON_ANY);
+		kmsan_internal_check_memory((void *)addr, size,
+					    /*user_addr*/ NULL, REASON_ANY);
 		break;
 	case DMA_FROM_DEVICE:
 		kmsan_internal_unpoison_memory((void *)addr, size,
@@ -418,8 +419,8 @@ void kmsan_check_memory(const void *addr, size_t size)
 {
 	if (!kmsan_enabled)
 		return;
-	return kmsan_internal_check_memory((void *)addr, size, /*user_addr*/ 0,
-					   REASON_ANY);
+	return kmsan_internal_check_memory((void *)addr, size,
+					   /*user_addr*/ NULL, REASON_ANY);
 }
 EXPORT_SYMBOL(kmsan_check_memory);
 
diff --git a/mm/kmsan/instrumentation.c b/mm/kmsan/instrumentation.c
index 94b49fac9d8b..02a405e55d6c 100644
--- a/mm/kmsan/instrumentation.c
+++ b/mm/kmsan/instrumentation.c
@@ -315,8 +315,8 @@ void __msan_warning(u32 origin)
 	if (!kmsan_enabled || kmsan_in_runtime())
 		return;
 	kmsan_enter_runtime();
-	kmsan_report(origin, /*address*/ 0, /*size*/ 0,
-		     /*off_first*/ 0, /*off_last*/ 0, /*user_addr*/ 0,
+	kmsan_report(origin, /*address*/ NULL, /*size*/ 0,
+		     /*off_first*/ 0, /*off_last*/ 0, /*user_addr*/ NULL,
 		     REASON_ANY);
 	kmsan_leave_runtime();
 }
-- 
2.45.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240627145754.27333-3-iii%40linux.ibm.com.
