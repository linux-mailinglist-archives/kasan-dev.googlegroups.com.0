Return-Path: <kasan-dev+bncBCVZXJXP4MDBBONORXCQMGQERJDRLGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A552B2AE58
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 18:39:23 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id 41be03b00d2f7-b471757dec5sf7885466a12.3
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 09:39:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755535161; cv=pass;
        d=google.com; s=arc-20240605;
        b=SWN/X1AXMpWfgr5O90UVjRi20YqE9FoYfF1TlFIOysOdNvxURjTbxwY49ClsBmkxGf
         /2JwMhl25fxEBT/ookLs8AEvKe3QQt0NCGbDobqXEQIIFE9L4dljc3wGQtz+D4UrcQQ8
         XU6pEFOgQ2H47ozRS1YcGaq19dOghLV+Kntw0+lA/caa61gRhKLGCfDxSYw3Xw1H+Fxv
         Z7Xnx3s3BRQ6KN9um7W5P99/5FhmuiUsN++7/05XD4GB9wvy+TgUbIsvbUN1s9oiV7rB
         RFpbAIlo1GuGV5N2IheKpRCexXeLp0BCa9cBligVHeBWdDZ8dZ4P5JC7bBpNbJKJqRSk
         Ujbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=PnllT5JLKDBDhWj1Z3f5Unw2F3WS/wo92D7Lo3c/sj4=;
        fh=i9zA6U2GZpmpBdLUHbInyUHTe8GQ+CERYAHOAg1lqkA=;
        b=DRwuuR7mN9VJ8WHKKUpsXQDOHO9XrCRuliuURkQ8S17Jy3crSTurdM6NGLU5pMncHD
         GuoTQ1pSw/NQRuc3i0l7mrLTlR/skQW5CELVweHrPTaL7els/8jEbMuM6XsKAvnwc2s2
         ha6PxHujCXgO6Ji0UikHLKWpc7/Gvf6j+yl2kOXqceJ0ee7a6qp0oKFd87oS8p/NoA1j
         6I/r1KXfSRFV9X5pFR3PqNtK5/AfLqOQvgaZGDP3zqBgvo2/yktBgRjHy0aRExxwScaH
         s9qul2raZiLnT0vCySZE9xo/16j2PITnfUrfC0OuAfQurZwfPmwJWP7WI3NSUd0QWhKz
         ZuoQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=rCfYREu5;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755535161; x=1756139961; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PnllT5JLKDBDhWj1Z3f5Unw2F3WS/wo92D7Lo3c/sj4=;
        b=SYODrl/uxkp8IXCNEUa0Pn/o7wx3GvGsL6lZz6vIkMBGS2PCS1s7sK6jjOPQ9aiEVm
         UQbSDGxCrN0YZAtE2S1AW5K6u3wI/PFfJkqf9heqwn9Qdg6QkV7lqhfr7liebjkPP1RD
         lF0sJT/uSRG55OnmsCzhAcG3SdZzuW4q8fYuvvl/oJoCy5H+ttRs680Sl16XjRgiqOTE
         D0a00zbHeGnaCIYf/2xfb9lv2LU28jQSb+EGVOVB/bltsxXGlsj80Ce9GDlxZ7S9wTlU
         25wz1XzuMnPgSAwn3ulUMs9/I4dz5Q/2m1pR3crJ5fb5yIacwBouuj1ZDPbYmG6FtPUj
         rjfQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755535161; x=1756139961;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=PnllT5JLKDBDhWj1Z3f5Unw2F3WS/wo92D7Lo3c/sj4=;
        b=OKwDSfGOQMv2oMtkvdFW68H/McwmWlG4sB4lxtsX8ANFiGD56iDIumhfyMSv4BUKGo
         0us7ogsaR43Ok4YOtvVYQLoLBrJ98za2lbyX4MHxV6b1OLG1JYVAT4FtFcSQHN2k3+Aq
         DISIxrCAnlfBbYmPqxjZZzFn5tC4iafG0pGlKA0ZRKoY/jgEEHjynHtHbfyuvn3j06Xi
         VSk+iPKGyqUmB739in2F+Dr0/it1F7JSgUT2Yd6873NYsxMOwH9wXuGDHqvkk2MH/YXC
         pCo+Iq7uxZhlx1HEtPXo7pN6TkKqhaCghlJHlAvQMk2ej+4L5gjoKEVwYd4wWJ3Pxbli
         kt+g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXYOPNAvq1pFSc/vELMjDDFbUHuJsLuETJviRmXncIQaKVN60ZyNuzbXC0OGDZjfKHK9Vy5lA==@lfdr.de
X-Gm-Message-State: AOJu0Ywyy8DC0GNU6jU5937wD4Q4xLhafy+jWRCRcR6ImXQqJI47rAsq
	4Iwh84SeGl5Ip+4816/lRaiFFZjQwZboYEyY6hyv+g5as/+ZJ/U4HOL6
X-Google-Smtp-Source: AGHT+IE9rvGPhNvdgbiuiyrk/w/CyylaXeFnI+ng3iR1BrSFB4SJIPNI6AiImsHEBz+hSDmb540M7A==
X-Received: by 2002:a17:902:e842:b0:235:ed01:18cd with SMTP id d9443c01a7336-2446d99e6acmr189324595ad.44.1755535161326;
        Mon, 18 Aug 2025 09:39:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeiTNDwGz9VHjrNB4ZyXyo7iRoacryNN2Lp0+52pUVJyg==
Received: by 2002:a17:903:2301:b0:234:d1d3:ca2 with SMTP id
 d9443c01a7336-244575a7ff7ls49252375ad.1.-pod-prod-03-us; Mon, 18 Aug 2025
 09:39:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVoWnCK73rsQP0wHQ2MBy/TaSTJLF3pMHJGV+uEK2vz1cMr4HBDNe2+SaGJNyuqwZ4fzzNuOzNt0dk=@googlegroups.com
X-Received: by 2002:a17:902:d502:b0:244:5311:8ed4 with SMTP id d9443c01a7336-2446da05d99mr170099395ad.55.1755535160039;
        Mon, 18 Aug 2025 09:39:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755535160; cv=none;
        d=google.com; s=arc-20240605;
        b=AbuprQFeMHxlUCZfctvQeKLK7YYnqJNpE1JjN7y1em3aaJC9D/EfDVgphon9QRmTMf
         QVp8r0Ryv5RwutMwtlUcI9/bKCClh/iH3KvDLx0eCvIU98Lsl9P3AlqoQhBR1uoLJlH6
         F2N5GuRjxR3LgyLPiERJAQZ4Pixz3jPYYtXz6a6XO4QRRuovtW0f7IovC7zGZKkYiWlY
         T96eYAZglBP1hYZId+d4S17CIfZqxNmTRxMdpaXqDsiQ13tcHDsV1kIUZaCw10jekpDI
         04SBV47gFccm5RpWioVyoT1oT8kkqcPRiPXiLPQqFY6SzlonOuKTEbC/tM6O1cvK8Chd
         CZAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=X5mWAYTt3pdVk9QL7e2JJSoH8wb3/z8g6wJ8lfORUIs=;
        fh=LdYAWUXcdYrCqzsb33cHKMTwCaURP2yfAndH6C0pUuE=;
        b=R7Wf0h9yeCCDBFR7Lkjo844tq7v2YSsDf1l46LF79psVYn5F7ERw6CTw/6EIHSZ/2r
         aZa0Nu6Z1veC6b2uhCSyyTAYDKDoCKPsuGJxEdraEy66Z2WE/kPTEPLmDK8WzalwVoxp
         fdZ9xQaIqHQOA1XHov8B3I57inrxPvVvsOQCv8QJjkJeHFLnd776GCLQ8dnymlpG98nq
         igzhGFjtDcxRaZaWWvsahXWEJAoeKaIEaUJ0wRsbOZ0Hk0mMynnKusJslCrD4PRA2S20
         DavVYk6mJW55sV1J3dhoghJIuubz4As76IsNpv+RtaOqhiExud67p3/O7K78mHyGEMgM
         xIcw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=rCfYREu5;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2446d52471asi3284535ad.5.2025.08.18.09.39.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 18 Aug 2025 09:39:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0360072.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57IBDGFK004808;
	Mon, 18 Aug 2025 16:39:16 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 48jhn3t382-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 18 Aug 2025 16:39:16 +0000 (GMT)
Received: from m0360072.ppops.net (m0360072.ppops.net [127.0.0.1])
	by pps.reinject (8.18.1.12/8.18.0.8) with ESMTP id 57IGdGXI014615;
	Mon, 18 Aug 2025 16:39:16 GMT
Received: from ppma22.wdc07v.mail.ibm.com (5c.69.3da9.ip4.static.sl-reverse.com [169.61.105.92])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 48jhn3t37y-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 18 Aug 2025 16:39:16 +0000 (GMT)
Received: from pps.filterd (ppma22.wdc07v.mail.ibm.com [127.0.0.1])
	by ppma22.wdc07v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 57IDjfwK001479;
	Mon, 18 Aug 2025 16:39:15 GMT
Received: from smtprelay03.fra02v.mail.ibm.com ([9.218.2.224])
	by ppma22.wdc07v.mail.ibm.com (PPS) with ESMTPS id 48k4q0pry3-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 18 Aug 2025 16:39:15 +0000
Received: from smtpav03.fra02v.mail.ibm.com (smtpav03.fra02v.mail.ibm.com [10.20.54.102])
	by smtprelay03.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 57IGdDWN59638234
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 18 Aug 2025 16:39:13 GMT
Received: from smtpav03.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 7A5E720043;
	Mon, 18 Aug 2025 16:39:13 +0000 (GMT)
Received: from smtpav03.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 6B30420040;
	Mon, 18 Aug 2025 16:39:13 +0000 (GMT)
Received: from tuxmaker.boeblingen.de.ibm.com (unknown [9.152.85.9])
	by smtpav03.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Mon, 18 Aug 2025 16:39:13 +0000 (GMT)
Received: by tuxmaker.boeblingen.de.ibm.com (Postfix, from userid 55669)
	id 41F13E0380; Mon, 18 Aug 2025 18:39:13 +0200 (CEST)
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Daniel Axtens <dja@axtens.net>,
        Mark Rutland <mark.rutland@arm.com>,
        Ryan Roberts <ryan.roberts@arm.com>
Cc: linux-mm@kvack.org, kasan-dev@googlegroups.com,
        linux-kernel@vger.kernel.org, linux-s390@vger.kernel.org
Subject: [PATCH 1/2] mm/kasan: fix vmalloc shadow memory (de-)population races
Date: Mon, 18 Aug 2025 18:39:12 +0200
Message-ID: <adb258634194593db294c0d1fb35646e894d6ead.1755528662.git.agordeev@linux.ibm.com>
X-Mailer: git-send-email 2.48.1
In-Reply-To: <cover.1755528662.git.agordeev@linux.ibm.com>
References: <cover.1755528662.git.agordeev@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-ORIG-GUID: J4hpVGuQdfh190mNZ9y0Gf73Cqn-Cb1F
X-Authority-Analysis: v=2.4 cv=L6wdQ/T8 c=1 sm=1 tr=0 ts=68a35734 cx=c_pps
 a=5BHTudwdYE3Te8bg5FgnPg==:117 a=5BHTudwdYE3Te8bg5FgnPg==:17
 a=2OwXVqhp2XgA:10 a=VnNF1IyMAAAA:8 a=dvgLwWEeUEcZKFo-wVQA:9
X-Proofpoint-GUID: oXrSUozvY-lHD9pJTMR4C4i78JDGz4zb
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODE2MDAyNyBTYWx0ZWRfX0s0pCD9PMBcw
 9xad7hv3i/i2JIneQGgCajRHsmbtUh6aA7EKw5dA7vDqDl4aRNequOMVtoYfyewAz23njA7MkYT
 V2Z5RQ3cpgQPKLF3lIFz0wAaelOynRQ2tpr7F63lBayIJjAya5hv2gS5BRCodHBVheW3IrmqnWM
 oj9OxSvZ6JcoiKC0FJIebqTen3ZJNHnxsZ+b0C2zbal1mTJzJgb7LJZUy2QPU/s5Gr0CNohWZOY
 HuvKtCPwZVCZYRbhx7o4zuBSm7m67a3Aa/ymI3NrKcR4JZ7sZuwNYWQwI0hgio75S0zM0rqj65G
 83zQFX6T3Isrg8d9s3/5jK5iR4imLOMy97gU1pGQzTri2xlKZxHcC5Do48Um7rwu6BdLX2boIRj
 RxfETVtZ
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-18_05,2025-08-14_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0
 adultscore=0 spamscore=0 clxscore=1011 phishscore=0 suspectscore=0
 malwarescore=0 priorityscore=1501 bulkscore=0 impostorscore=0
 classifier=typeunknown authscore=0 authtc= authcc= route=outbound adjust=0
 reason=mlx scancount=1 engine=8.19.0-2507300000 definitions=main-2508160027
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=rCfYREu5;       spf=pass (google.com:
 domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted
 sender) smtp.mailfrom=agordeev@linux.ibm.com;       dmarc=pass (p=REJECT
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

When vmalloc shadow memory is established the modification of the
corresponding page tables is not protected by any locks. Instead,
the locking is done per-PTE. This scheme however has defects.

kasan_populate_vmalloc_pte() - while ptep_get() read is atomic the
sequence pte_none(ptep_get()) is not. Doing that outside of the
lock might lead to a concurrent PTE update and what could be
seen as a shadow memory corruption as result.

kasan_depopulate_vmalloc_pte() - by the time a page whose address
was extracted from ptep_get() read and cached in a local variable
outside of the lock is attempted to get free, could actually be
freed already.

To avoid these put ptep_get() itself and the code that manipulates
the result of the read under lock. In addition, move freeing of the
page out of the atomic context.

Fixes: 3c5c3cfb9ef4 ("kasan: support backing vmalloc space with real shadow memory")
Signed-off-by: Alexander Gordeev <agordeev@linux.ibm.com>
---
 mm/kasan/shadow.c | 18 ++++++++----------
 1 file changed, 8 insertions(+), 10 deletions(-)

diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index d2c70cd2afb1..4d846d146d02 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -305,9 +305,6 @@ static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 	pte_t pte;
 	int index;
 
-	if (likely(!pte_none(ptep_get(ptep))))
-		return 0;
-
 	index = PFN_DOWN(addr - data->start);
 	page = data->pages[index];
 	__memset(page_to_virt(page), KASAN_VMALLOC_INVALID, PAGE_SIZE);
@@ -461,18 +458,19 @@ int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
 static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 					void *unused)
 {
-	unsigned long page;
-
-	page = (unsigned long)__va(pte_pfn(ptep_get(ptep)) << PAGE_SHIFT);
+	pte_t pte;
+	int none;
 
 	spin_lock(&init_mm.page_table_lock);
-
-	if (likely(!pte_none(ptep_get(ptep)))) {
+	pte = ptep_get(ptep);
+	none = pte_none(pte);
+	if (likely(!none))
 		pte_clear(&init_mm, addr, ptep);
-		free_page(page);
-	}
 	spin_unlock(&init_mm.page_table_lock);
 
+	if (likely(!none))
+		__free_page(pfn_to_page(pte_pfn(pte)));
+
 	return 0;
 }
 
-- 
2.48.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/adb258634194593db294c0d1fb35646e894d6ead.1755528662.git.agordeev%40linux.ibm.com.
