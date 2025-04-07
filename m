Return-Path: <kasan-dev+bncBCVZXJXP4MDBBKGWZ67QMGQEP7A3ADI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A39CA7E37F
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Apr 2025 17:11:38 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-4769273691dsf85469941cf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Apr 2025 08:11:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744038697; cv=pass;
        d=google.com; s=arc-20240605;
        b=UPzKxdYoDwr+ILF+7p335yQ2lndrBCnCrkc1/EFpu6nigMX0ZNAmbotKpMnxPFWAJa
         J7O72puCo893XUdAS0aXDyp08gY2SWfbFbgRMNafpKocVPy0Z5SlWewWEhzFu/N2Hg4/
         3+gbGl6UX0Q5/UEniSvVKORyt40rQsth2qRtPcknmN3bP/kZZNSGInjolWMP/fuyFXFu
         CGF8cxE2OGzI4OgM9IhINkkyyP06gGNGcfXLBYRsihW/MnupbmpJWN5oipgbKvvQFlyC
         QS48bRKvoBfB1nR+nY0BV482OGClCFgcrK+7HTkM18/U5zFFMN8u8jOc54FnNbb3j3K7
         c8uw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ITLNyUSPrvdpTpWus/TlYhGt80W1LsODyieYa+tiH+M=;
        fh=3WWZHYvWVy+uBA3MKngFyS+Anhu7+WWsmlQpfl4dknk=;
        b=H030PnVISrNKewatrTxdTyLtp4tNyNbndPF4k4tC557aJpNzr8oGc9SK3IV5gIlvHO
         dTdN1S68BFZv1sTPb2VNazBJenJXiX+NVQNgfAB/umuu5zIrwS+Nf7jupLqwj1gBbLcb
         Ss0tz2JwoJVK7Peco7gaTvIy7hGQ3gq2dimuI48PtelC968TFeoTtjuxtbyb3EJfWZgz
         o3BhX5nudAJcGscpY3S/DjDc4Ce28EITCeaWY2cORfScNi+1noytzQCITncHNFKhS27y
         WWf/S37RO54rFPbuoNfmNBeUyo9wU+3x6UW8hf6s9Xa/aIN+v8OQMkUT7sZhyqrC3+7I
         0ceA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=IKe6NKPK;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744038697; x=1744643497; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ITLNyUSPrvdpTpWus/TlYhGt80W1LsODyieYa+tiH+M=;
        b=I+5AWK+A2ALkuv8BV2IGS7Vkjj/dfUDCypfAjEK7nFoVqJwwecNiUxFkI+rvGn/Xh+
         OJBQOypBG1aN8s7tHwAmBakbgkK0WLup9uGIapgthtP3L9gE8ie/CXBjta6h2Iaw5Hz5
         4tYB1bI47dzehYVlHpvu7MPQ77er3/TQ5s6li8rkb90Z36S3R1GtIQRgR8ScHHspoahH
         pGmegUdt2tIZjCT5dOMoD0xJL1lWWWGCqj2TmRoNuje6nDIIhBAGSGkSz7gx3XH2CzIe
         rts8dHbiZ+2W/TnT6+6A6GaSbhssUXtFTK+41bHg9l9K47AcoSh7mXkGuEE4GAHjAVtd
         dgEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744038697; x=1744643497;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ITLNyUSPrvdpTpWus/TlYhGt80W1LsODyieYa+tiH+M=;
        b=q57QPzB+I94b0e9ndRbqAB/7DsOAPoOM2Y+hjkUS7s1YqF+C66mlNyUYGuP7ZjJNGm
         BF4FeBo7YdDJQqTcQNGP0QZ5+g72tIRMrl7gKROg7dsWFKg3ix5W1+WTIp0/EuPC4AGn
         63bLPZVhYhwlAaZUUEX/8grY/bdGglLPF1aMRuq1jlDWCQYKn146LHKrEhSQAWUVTFTW
         2XzNcAoHY1pz3Q1Y3yQQLAHG8orQK8cNP+q1sCre/dyNbIx1KvzK4KeYk9aqa0+sLXX2
         cFIrExIOs7i1w8J0REtGqxBQIWQTZqsmFqvR7WHHSdBTlMhl+ZSvNwqZUCTzUTcb2noH
         Jq9A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUOezBdq6xM4iCs26EogqnlBeSHzYcDGkc6DJXy7LfxITE0SVK+YYKLguHeoirWN8OuyB34eQ==@lfdr.de
X-Gm-Message-State: AOJu0YxNA0bznml6SMOuBpaA3gurFe+5Gl4VXrHvpv77mUts1KSGkLLT
	btszlKMGPKcnh4jjG9zmFIYNqMdF/1QsgSizWLbxG62HjPeVlxwm
X-Google-Smtp-Source: AGHT+IGtVts+IjBImZJMC8DILGLc4sfZAUok3NSm5fYRcSuEiji6LeNS3dMTvPeJo5WA+Z52pJzFXg==
X-Received: by 2002:ac8:7d05:0:b0:478:f747:1b7d with SMTP id d75a77b69052e-47925925edemr180950331cf.6.1744038696635;
        Mon, 07 Apr 2025 08:11:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJMVog43U23LgEBtW2ggFvr9gO86QKBFy5WPOe8iJ/s4Q==
Received: by 2002:ac8:1241:0:b0:476:7bbb:af0 with SMTP id d75a77b69052e-4791614a5e7ls67790971cf.0.-pod-prod-07-us;
 Mon, 07 Apr 2025 08:11:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUcXeu87aKFOURwHmS8z1PYkJitfLtQkA+vuj6iSa0zdBtFPouViqBlDR9VIkSgE+F9FuYyFs9kvyc=@googlegroups.com
X-Received: by 2002:a05:620a:438d:b0:7c5:9a4f:adf0 with SMTP id af79cd13be357-7c775a3a31bmr1783770785a.33.1744038695514;
        Mon, 07 Apr 2025 08:11:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744038695; cv=none;
        d=google.com; s=arc-20240605;
        b=gB+NVRvzHZ+vKx1Qt+fj6TFMp4jgAruw/jDwMc9O+MsHSWuHMO0/2kdMJWOx+fpr37
         jmlAvA2540Jd5YhO2Eq7fUqd5tnhvKsAAz//zGbE8ao6ZokdQHx0MJPGCeadjLUMQxdT
         4f0HAmB+zB53ndfGtKq4lIkBXScpaDa1VPvZbnCptUzG9Q8+eY1X+bYcEUR/dB0KT8kU
         pKkz+jFZOpBaUCW+WRUS0RuZ/dUTOqnc1COwNq9rRUVvsk9gh0ZTjLsurLq27kMlaotB
         GuULeEgc+fzZsAFTiF5OiN4AoMDz3pJJDss73KaD4N8oZsr5ULb2c9coM5PZMMyrWWT+
         TTDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=JAdRtQpYpJ83Wan/qay54BErF461aFj9Lbn233V6/Vo=;
        fh=LVJPJYP2Tqlg8aWQBGa6aniChm4kWZS3hY9A1BPUb/I=;
        b=evHAsDwB5+a5z1eDdntlTUtQN6VhZdiegjdh91ewXEa3cmiHwtiOO6EYie93PQIkua
         AyfE88eO/Y3HXuan1UYUPZtAiLmzq3Ukux16nsH1/BLwUU1i+ED6OyKkq1xuunRMJg5b
         phtt+vnE/6mE3kot0GR9iMbYqXLTIyGwaIWTd2PUpVBH8Ym6zGKNi6iEgbryNRsIpoSb
         usCUJWP+l6wd1yIPoz1U+gIFdRRs85QJIUPa1T/pduCqbVYVfyx6bzc1fyDdEdgBbZ7b
         SH2Z4oM7XNqUlCGljGoECOnEsnf5i7KMDrTwIxdMgtnx7ZciyCrKw5P+aynWki5qRhgt
         2AAg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=IKe6NKPK;
       spf=pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) smtp.mailfrom=agordeev@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0b-001b2d01.pphosted.com (mx0b-001b2d01.pphosted.com. [148.163.158.5])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7c76ea4ee11si42609885a.6.2025.04.07.08.11.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 07 Apr 2025 08:11:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of agordeev@linux.ibm.com designates 148.163.158.5 as permitted sender) client-ip=148.163.158.5;
Received: from pps.filterd (m0360072.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 537En0ZD029644;
	Mon, 7 Apr 2025 15:11:34 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 45uwswvt33-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 07 Apr 2025 15:11:34 +0000 (GMT)
Received: from m0360072.ppops.net (m0360072.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 537FBXTb013844;
	Mon, 7 Apr 2025 15:11:33 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 45uwswvt2v-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 07 Apr 2025 15:11:33 +0000 (GMT)
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.18.1.2/8.18.1.2) with ESMTP id 537F2iM6018432;
	Mon, 7 Apr 2025 15:11:32 GMT
Received: from smtprelay04.fra02v.mail.ibm.com ([9.218.2.228])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 45uh2ke5ug-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Mon, 07 Apr 2025 15:11:32 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay04.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 537FBVQW33751652
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 7 Apr 2025 15:11:31 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id E82452004B;
	Mon,  7 Apr 2025 15:11:30 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id D3F6E20049;
	Mon,  7 Apr 2025 15:11:30 +0000 (GMT)
Received: from tuxmaker.boeblingen.de.ibm.com (unknown [9.152.85.9])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTPS;
	Mon,  7 Apr 2025 15:11:30 +0000 (GMT)
Received: by tuxmaker.boeblingen.de.ibm.com (Postfix, from userid 55669)
	id 7F795E10FC; Mon, 07 Apr 2025 17:11:30 +0200 (CEST)
From: Alexander Gordeev <agordeev@linux.ibm.com>
To: Andrew Morton <akpm@linux-foundation.org>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Hugh Dickins <hughd@google.com>, Nicholas Piggin <npiggin@gmail.com>,
        Guenter Roeck <linux@roeck-us.net>, Juergen Gross <jgross@suse.com>,
        Jeremy Fitzhardinge <jeremy@goop.org>, linux-kernel@vger.kernel.org,
        linux-mm@kvack.org, kasan-dev@googlegroups.com,
        sparclinux@vger.kernel.org, xen-devel@lists.xenproject.org,
        linuxppc-dev@lists.ozlabs.org, linux-s390@vger.kernel.org
Subject: [PATCH v1 1/4] kasan: Avoid sleepable page allocation from atomic context
Date: Mon,  7 Apr 2025 17:11:27 +0200
Message-ID: <ad1b313b6e3e1a84d2df6f686680ad78ae99710c.1744037648.git.agordeev@linux.ibm.com>
X-Mailer: git-send-email 2.45.2
In-Reply-To: <cover.1744037648.git.agordeev@linux.ibm.com>
References: <cover.1744037648.git.agordeev@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: noh5DKX9Jwz7KQQbR0xgtrf0Cnrok7JA
X-Proofpoint-ORIG-GUID: B9e39pOuvk43sXxp1B5Vd8FFaIlzYizr
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1095,Hydra:6.0.680,FMLib:17.12.68.34
 definitions=2025-04-07_04,2025-04-03_03,2024-11-22_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 priorityscore=1501 mlxscore=0
 bulkscore=0 mlxlogscore=999 spamscore=0 adultscore=0 clxscore=1011
 phishscore=0 lowpriorityscore=0 impostorscore=0 suspectscore=0
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2502280000 definitions=main-2504070104
X-Original-Sender: agordeev@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=IKe6NKPK;       spf=pass (google.com:
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

apply_to_page_range() enters lazy MMU mode and then invokes
kasan_populate_vmalloc_pte() callback on each page table walk
iteration. The lazy MMU mode may only be entered only under
protection of the page table lock. However, the callback can
go into sleep when trying to allocate a single page.

Change __get_free_page() allocation mode from GFP_KERNEL to
GFP_ATOMIC to avoid scheduling out while in atomic context.

Signed-off-by: Alexander Gordeev <agordeev@linux.ibm.com>
---
 mm/kasan/shadow.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 88d1c9dcb507..edfa77959474 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -301,7 +301,7 @@ static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 	if (likely(!pte_none(ptep_get(ptep))))
 		return 0;
 
-	page = __get_free_page(GFP_KERNEL);
+	page = __get_free_page(GFP_ATOMIC);
 	if (!page)
 		return -ENOMEM;
 
-- 
2.45.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ad1b313b6e3e1a84d2df6f686680ad78ae99710c.1744037648.git.agordeev%40linux.ibm.com.
