Return-Path: <kasan-dev+bncBCM3H26GVIOBBMH2ZOZQMGQE2TQ7BSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id B23F790F2A8
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:45:54 +0200 (CEST)
Received: by mail-pf1-x43a.google.com with SMTP id d2e1a72fcca58-7060136ed89sf4138526b3a.3
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 08:45:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718811953; cv=pass;
        d=google.com; s=arc-20160816;
        b=WoHG86lQ/HuhcK+ZOSQ2noIlkrIGtEavkBpibjtqdB6TqIkceyoC/UvJzrJcUIOzxI
         cgSj2LwE2gDzO8W0n2lJUNItNboDf48Xb9iZmnIJTgo/Ggc7kGtVSTAOo0WlOIrwv+Pn
         DvMqhHzgdQSPeUp3WChkp7gIQDAVRo3YRchrTjOJKwSbTr3KIAfuCgduN581/TIeL3Yc
         mUPVyU+CcEipmZmfAx+93NpSI8g4f/ltoupN7tOZkwScZ1Xn8I/MLPxLMzpDul49UN59
         lE+C8LEneZuPEWA2BomHS0flCdAMyazqqLsqePV25nSsZUg1h8Atcz92Qh/V9e2dHp09
         5quA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=EyNC4rz6wpeNlNFrWg5ZNnnztV62Vvb4PJWwq+SDm74=;
        fh=VTaGpdQQvPQGwZQj+Q2nNVWcwNCytoz2nzQfIcWzDfE=;
        b=cLXoWXrEceO00MjJcDqKRdNMyU6okfa6kIpqZZ3LP/QVylixB5AOIpvWh1fmxbvLaf
         J/p0yN0NMmRVH6SvQen3U5CybcGmgBb3+AjTnmMDmj4cXVzhH2zUR77q9rRWO63H1EXj
         ihKM4yT6t4taCh0R75NprUoztYxHpmG7BorzE5V8jk/NJlJK1UNmKyZeNrBrgAQXvWC+
         VMXXnQOkXmdq/O5pRObBgW3kXE53gL+Bi+uAYWmT0zhox+o0l1TWqy1Srx3yYN6pODLs
         oZiPE/Zrm6UbEcF7Dfrz045dJcVx9kUBNyOPT0iZ9LaAa+f2fge+Cavoo5m0DCdm1VIA
         lTCw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=SynliYum;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718811953; x=1719416753; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=EyNC4rz6wpeNlNFrWg5ZNnnztV62Vvb4PJWwq+SDm74=;
        b=C+r3ivBTF3ic0HBy8m+lnErl8B/Qt7PwsTrK+KnLjYJWHylF+JZk6BD9pa4zuUnEne
         kSgQLkzav7qGHhXPCMGPwZm4MAOreH5X1LkYHqDoul/VgAdgclpyawzDCI2CdKNqKf4Q
         Rznc0IEceA5nFzf9rMJUbdCEtHLp8hDMK51jxQW6njvCcuau3xQUqAwrdSxqK5Au8bPt
         Fqv3YPeFKtM+fVT3uoHE3+hokXSyVt6hEa3rwC3Hfl6o1hwUWSNLMh03jHOZAGIkk/0F
         xv/x9Kxc16JADxKwR0cU/7jDqdY5ZSKsIJkK0DAF3Pjgtg5usImnYxDpMBSDwz6/0O2J
         55EA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718811953; x=1719416753;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=EyNC4rz6wpeNlNFrWg5ZNnnztV62Vvb4PJWwq+SDm74=;
        b=K39KI5luSWpHl8f036exJrrhvWX4sGvT4cNyrPQRADVnFvN4uAKI9Lq0Xokcq8nE5f
         isqfbQa+4EJcwpdv5wHGp6C0zV0MRxlGEf7SwOeUzXumJaAEMmD3dvZEe4qTKBN8/iUB
         yyRVLDYtXF5eNqBekw4l9u5pkMYvw5ZZ6Lh3R+fjcc7rcDyxFefcig7pSmsL51ivn4U0
         7Qnb+f5kz8YOIrGX2L/EnJgjRGrgEHi1HLL99cfxNg3h6AINHkfjeqiFyAh9steGMwvk
         7HKi2dJEN+gKguvFp9tiBSuSPFpFcZZCRp97e+pvXrEbitOGx0+fRy81NyCToVpPCjaB
         1yBw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWN0zLIHr+/LEjrsKa8ffk3lmUlX+qUHALL1y/AdygCfMqDH5kfjmQNulsV/Da9uxTeAEz6mmqeex1zpJhb/5SQYF2QIibcBQ==
X-Gm-Message-State: AOJu0YydmXDbu/XliJVXRvswEt5bdzEiqzY2gWrmwuLm+qjcL6MT5V9Z
	wygFKPYFIkV7M44m0XwNM/K3wDaK25RI75MTpHRAbaA4HvKtIIhY
X-Google-Smtp-Source: AGHT+IGTKEJeSCoB6ZaktMUJYJjV3NENiFvKSigwtdba/99a6Q77UjK35Nvq8GsnfpJxDHnv0EFruA==
X-Received: by 2002:a05:6a20:3b04:b0:1bc:a4c5:445b with SMTP id adf61e73a8af0-1bcbb40b70bmr2870668637.24.1718811953122;
        Wed, 19 Jun 2024 08:45:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1142:b0:702:6dc7:234f with SMTP id
 d2e1a72fcca58-705c94925e4ls4495245b3a.2.-pod-prod-06-us; Wed, 19 Jun 2024
 08:45:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWE+LGv0yY5NnVyEvGunDqueHt+SYMQyB8jJ+VXxorrEgGRFPDrxPuuH0VS3CgXF3QW823fYS+rnvBrkhF1x2r5VPDvZEGcD0drvA==
X-Received: by 2002:a05:6a20:b202:b0:1b8:6ed5:a70 with SMTP id adf61e73a8af0-1bcbb5d5116mr2917392637.49.1718811952038;
        Wed, 19 Jun 2024 08:45:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718811952; cv=none;
        d=google.com; s=arc-20160816;
        b=RymCaY2i8bvWCtsybJAeToDkO8xYL7vB4vV5PyPT1Xn3EmULl1HFd1Rg+zwnS41a1u
         jO4lFdxM/P8sx+FembcZQlxaesqIwlxFNWryiT+n02/XuYW5GRUlUGNngAGwXiGcWU+l
         6Xg8q8abtZPstpanu2Fuj5T4dgTaZ7MBOqA/IPI8CGueDe29w2LtFq3EiK4M0pYPupZI
         HRzpAMZQOUBTdaPWEqd9UoW56ypdOY22TXzi/VHDvcYFXs3VKC3DCcqKuFfficvzHcLN
         x1YOhJ2PVIXNPIWGzn0h6emRRCnXJo31EsXJgKFsAPv4xFqRiOOZ9oC1nAh+sFn17Vms
         3eeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=sjJ2GTGv7V5yiCtYJlQAhchvuDeCI6GGTrnLDfTIbQA=;
        fh=TQATEbdDZNcnk8L2eDP6eFL9HlexFaHIexhR1TH2IlY=;
        b=orOK3GwLzjeKD/ZbzhJjJmMhz85qZpqPzBwaOq5gdLQYyQsDiKAwJRIMVYrCk5cNHM
         SKiMPtwfhxj59atMH28rA5FaO0qYrnXD/w3OW2DhY1vkkHdarNlyS3TOibp9dAPFKIMV
         hNeJ47HdeExJGWq/Xh0Q0NwBw4UuQMksKQUhdqauC0CvcrxUhpqUcX9s6U7emeZu7dYM
         hrOFQ360DSdiLgjE1w3kX6sFO+H42xkGKU3R11nfoFjwgaKhnmJmw2A8aD5odUnaD0jl
         l4sTlvOV+nNjjibhblLtP5M5ubg5RWuM7Ie817ljvRs5rSUuhnoDEO8BZ7Nm3ZLTTOMj
         zqqg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ibm.com header.s=pp1 header.b=SynliYum;
       spf=pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) smtp.mailfrom=iii@linux.ibm.com;
       dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=ibm.com
Received: from mx0a-001b2d01.pphosted.com (mx0a-001b2d01.pphosted.com. [148.163.156.1])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-705ccbdb4d1si646029b3a.6.2024.06.19.08.45.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 19 Jun 2024 08:45:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of iii@linux.ibm.com designates 148.163.156.1 as permitted sender) client-ip=148.163.156.1;
Received: from pps.filterd (m0353729.ppops.net [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 45JFSRAB028320;
	Wed, 19 Jun 2024 15:45:47 GMT
Received: from pps.reinject (localhost [127.0.0.1])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv20g81kd-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:47 +0000 (GMT)
Received: from m0353729.ppops.net (m0353729.ppops.net [127.0.0.1])
	by pps.reinject (8.18.0.8/8.18.0.8) with ESMTP id 45JFina0020883;
	Wed, 19 Jun 2024 15:45:46 GMT
Received: from ppma13.dal12v.mail.ibm.com (dd.9e.1632.ip4.static.sl-reverse.com [50.22.158.221])
	by mx0a-001b2d01.pphosted.com (PPS) with ESMTPS id 3yv20g81k7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:46 +0000 (GMT)
Received: from pps.filterd (ppma13.dal12v.mail.ibm.com [127.0.0.1])
	by ppma13.dal12v.mail.ibm.com (8.17.1.19/8.17.1.19) with ESMTP id 45JEsEuA009411;
	Wed, 19 Jun 2024 15:45:45 GMT
Received: from smtprelay06.fra02v.mail.ibm.com ([9.218.2.230])
	by ppma13.dal12v.mail.ibm.com (PPS) with ESMTPS id 3ysqgmwmmx-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 19 Jun 2024 15:45:45 +0000
Received: from smtpav06.fra02v.mail.ibm.com (smtpav06.fra02v.mail.ibm.com [10.20.54.105])
	by smtprelay06.fra02v.mail.ibm.com (8.14.9/8.14.9/NCO v10.0) with ESMTP id 45JFjdck35258910
	(version=TLSv1/SSLv3 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Wed, 19 Jun 2024 15:45:41 GMT
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id C685620040;
	Wed, 19 Jun 2024 15:45:39 +0000 (GMT)
Received: from smtpav06.fra02v.mail.ibm.com (unknown [127.0.0.1])
	by IMSVA (Postfix) with ESMTP id 77BEE20065;
	Wed, 19 Jun 2024 15:45:39 +0000 (GMT)
Received: from black.boeblingen.de.ibm.com (unknown [9.155.200.166])
	by smtpav06.fra02v.mail.ibm.com (Postfix) with ESMTP;
	Wed, 19 Jun 2024 15:45:39 +0000 (GMT)
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
Subject: [PATCH v5 17/37] mm: slub: Disable KMSAN when checking the padding bytes
Date: Wed, 19 Jun 2024 17:43:52 +0200
Message-ID: <20240619154530.163232-18-iii@linux.ibm.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240619154530.163232-1-iii@linux.ibm.com>
References: <20240619154530.163232-1-iii@linux.ibm.com>
MIME-Version: 1.0
X-TM-AS-GCONF: 00
X-Proofpoint-GUID: CpSafJOwnnqLI12HaB96v_EEXsdBrBUE
X-Proofpoint-ORIG-GUID: 94rzP1_ZD6iOjx-buxAnf6OZgFWnBex1
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1039,Hydra:6.0.680,FMLib:17.12.28.16
 definitions=2024-06-19_02,2024-06-19_01,2024-05-17_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 bulkscore=0 suspectscore=0 malwarescore=0 spamscore=0 impostorscore=0
 phishscore=0 clxscore=1015 mlxlogscore=999 priorityscore=1501 adultscore=0
 mlxscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2405170001 definitions=main-2406190115
X-Original-Sender: iii@linux.ibm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ibm.com header.s=pp1 header.b=SynliYum;       spf=pass (google.com:
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

Even though the KMSAN warnings generated by memchr_inv() are suppressed
by metadata_access_enable(), its return value may still be poisoned.

The reason is that the last iteration of memchr_inv() returns
`*start != value ? start : NULL`, where *start is poisoned. Because of
this, somewhat counterintuitively, the shadow value computed by
visitSelectInst() is equal to `(uintptr_t)start`.

One possibility to fix this, since the intention behind guarding
memchr_inv() behind metadata_access_enable() is to touch poisoned
metadata without triggering KMSAN, is to unpoison its return value.
However, this approach is too fragile. So simply disable the KMSAN
checks in the respective functions.

Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
---
 mm/slub.c | 16 ++++++++++++----
 1 file changed, 12 insertions(+), 4 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index b050e528112c..fcd68fcea4ab 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1176,9 +1176,16 @@ static void restore_bytes(struct kmem_cache *s, char *message, u8 data,
 	memset(from, data, to - from);
 }
 
-static int check_bytes_and_report(struct kmem_cache *s, struct slab *slab,
-			u8 *object, char *what,
-			u8 *start, unsigned int value, unsigned int bytes)
+#ifdef CONFIG_KMSAN
+#define pad_check_attributes noinline __no_kmsan_checks
+#else
+#define pad_check_attributes
+#endif
+
+static pad_check_attributes int
+check_bytes_and_report(struct kmem_cache *s, struct slab *slab,
+		       u8 *object, char *what,
+		       u8 *start, unsigned int value, unsigned int bytes)
 {
 	u8 *fault;
 	u8 *end;
@@ -1270,7 +1277,8 @@ static int check_pad_bytes(struct kmem_cache *s, struct slab *slab, u8 *p)
 }
 
 /* Check the pad bytes at the end of a slab page */
-static void slab_pad_check(struct kmem_cache *s, struct slab *slab)
+static pad_check_attributes void
+slab_pad_check(struct kmem_cache *s, struct slab *slab)
 {
 	u8 *start;
 	u8 *fault;
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240619154530.163232-18-iii%40linux.ibm.com.
