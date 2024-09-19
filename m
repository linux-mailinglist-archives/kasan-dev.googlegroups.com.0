Return-Path: <kasan-dev+bncBDS6NZUJ6ILRB7NFV23QMGQEOIHT2VQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 7254797C2EF
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Sep 2024 04:57:02 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-6c366dfd540sf8111576d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Sep 2024 19:57:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726714621; cv=pass;
        d=google.com; s=arc-20240605;
        b=eS0gqEynPvNRuin9W4gWBRpkBrWzyN++XdwKf85spBwPDSp9t/+U/wJ6Y8xmjBle+x
         gWb+OuUpF9GYWcyS7N1vH30UFEPhf67U5LBI9I1auh5ByKHuW0U2NDACH5CSLL5zrExP
         0RMH/UMKDyxZxh0mU1iEkhazjSsYtx5Qnh67kILNuNE1l/YTfRsHXlGVNzA+9tqggSxY
         JRDf0wH1L4YsQMQwWxjvP1PJ1qKJ9iX/GBfWaTAuuPNvwCuz1ffKZRhrfoG30POo2Qvw
         ZYDZZY9Yb/7DAjwmAGmQpdq06F1tRKQ3W5OG3wpFVxbkysHdKXFP5x3b+pZlJWbEpKr3
         Dt6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=sJm732cF7PWvTJhYM+PGgWCxqUXV4I5uCdAa0F5eiEU=;
        fh=QcLriej5oqxfeKJXAjOOYbVNIOK+N3F9mqQ48lCP/TA=;
        b=LTyZyYc63OKJ76BFmfkyy5CkSnmWKrDxPDcCLlaSHfNKJ81iqY1GmTqRkGS8BKvn+E
         lXuI61ThQU9tooVcLzsaYDFGUGQP/WhHwtRPytgNEt+UmIgPIHmjMg2RsOnlKTKye9pd
         2XagPAPgHFHom/UI3OlJOVjb5NJgFqSS33d1/rxgyT/TNKYutG+DJ9N4qAYKpHu85Lcj
         lKUpvMIXP49sdEvoSPaxrMQCThVqxYAuhfE+osyql6OdhrSiTs3ufEl0mkauhcB9k+75
         kjLQqvFVfSuEAcLP+TaHedxjUA48TIa+eb9Www7tnYcqeBrWdU6e/cnbEObSAnfczjna
         oFtw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=NSmVjScl;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::632 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726714621; x=1727319421; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=sJm732cF7PWvTJhYM+PGgWCxqUXV4I5uCdAa0F5eiEU=;
        b=BlLtvEXPXoAlDd0phCnynPsRd0Jm+m2TvBph+3NI9a0Xmqbj98z/LsAMaUM+9eKlhx
         So3fY/eBn99WRui+OwPHP1mjilkcoTM1OCXbOB42N5MEXHT8gGpxbSGNpo7vOJdUhq26
         RljRmmFafUblQ63R+kZhHMvXMJiG5WlCfHovjTgrskoj2hcwhlCDiVORLWx8kjOwoKDr
         kHp0M03EvpW4MghMw2whZwaH6PnZ/T4S+0NYLTUcPLDNqGtE9QDMok8GyOs0RlMRLJHg
         3evYRyeF9P2mmXPd3WMH/0WFIP7vmKtmNjNICtIe4lHlgqLjPh9aDWprjFE/ktJtvO38
         NbkA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1726714621; x=1727319421; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=sJm732cF7PWvTJhYM+PGgWCxqUXV4I5uCdAa0F5eiEU=;
        b=C96yInB2kdGJFfiOSfVJoLpPDqXHU/Fzaraeg0eD2qX83QPpp5YjtScQ6lRjmDQ+VG
         uIF7dUDxrn1zeTue1uiLiAIRoeurWMylbz6G3diHdAYLPHjhkj20FhGvf6WHEH/w/gDt
         qj/D2MtNHFOxK1rgL1VSNef+AFsk+xFoFfjW3I2ke2mDb8PuRiPq8UZjkQh7DD/RUAKE
         o1WOj9tg6+fdVdHkdi10BblwX/tKr3YVfFUC2TdLopsEdGD9UxnPg8cL5izCRUMYHTXP
         H8fBOa4/5CFUK68CNQQN1L+bxfbbZLszWnKYCGKeSjfjpGUMM3QrWnCl9mtuunfvbUu1
         MAJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726714621; x=1727319421;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=sJm732cF7PWvTJhYM+PGgWCxqUXV4I5uCdAa0F5eiEU=;
        b=M7b71QI8UtU6xqzr4NPxVjRKyWCN4vLai6ZAUlpoWx4GDU4dXKZ/tG1GRsOVM6zPl8
         lp1OEml8pLerqL3ldvq54v5hU81kbwKSeS4JjFj84pnivB2I6QQ9fDHAINjUlL05o8sB
         xWP3H0xvTh1jbSrPNN4Zk5R1hRBRVgX1c81Mm05KLn4cD4HUeJ2iK2uNgOXky0yxqYsr
         U1AaStC7MAMGbED8FT45XKDxMIcA/2tDIVRq1tk8wI3hXSjktOf63oW7Mu7oqa1QFBio
         CIZNOf6Zo9b1juci+c84jTe3mACLkwyu70HkAudqch2qbjyDHRRrPKEbVHaii4YgrB7p
         REOA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVqFAewqMliF+sMjQaDnOb6wBYprzE0wVcKOPhao6DEz5XesCMZsFWYBSJdhBf/ooM5zVQHGw==@lfdr.de
X-Gm-Message-State: AOJu0YxLljYdTiqaffRX/WeTmyWt/figcbu2WR/G6080BzDKgjLRjWT3
	GLDEs5AIwkGNwqEml5MZKiwGngPTHRTfD6cj/mYBTfCVg8X0HuxH
X-Google-Smtp-Source: AGHT+IH6/bleX4Wj1ARD/RvL+94x7yIZD8if80+5oGQkHZnfa8MZ5uuo8C4pwf/922vHt5+2OfTfTg==
X-Received: by 2002:a05:6214:1749:b0:6c5:891b:15d1 with SMTP id 6a1803df08f44-6c5891b1625mr188014166d6.25.1726714621294;
        Wed, 18 Sep 2024 19:57:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5bc1:0:b0:6bf:4817:dd88 with SMTP id 6a1803df08f44-6c69bbc965cls8486686d6.1.-pod-prod-02-us;
 Wed, 18 Sep 2024 19:57:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW0bLxw9wQOEwOyEchDLuP0RynLRTw/WsEjaoHvNSxN88RMXZpwGlTi8yy9et5conmmLXZZA0TKWc8=@googlegroups.com
X-Received: by 2002:a05:6214:3c86:b0:6c4:79df:a2e1 with SMTP id 6a1803df08f44-6c57357888cmr379059196d6.23.1726714620606;
        Wed, 18 Sep 2024 19:57:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726714620; cv=none;
        d=google.com; s=arc-20240605;
        b=SptZAyNXfz7zD0MWmkHImiezrSXOUYhd5JCaxWreyzwh+hSSQ58TTZ8H5o7JvfQrFF
         8FYlfNGZq2n2du9Xq6HiEWA0P4oFL8MXg/7FKpUk+NaIK2Vx9tIZ9unMi1SaHRkhARFe
         2Fc99SPahKQ5lanC5A1SYSVUovGb7/ya5VXGeKM87nYIzCU32LnMnBzOjLPNuXjqOs9B
         wPRg+gp+/3aWy929Bm/BbeFLrzaPADJbid+7dEeMJ8ReS2rNMelN0SM0xaseRUBJGSlU
         rSTx84R3hmyXyXSAgIy/0IPp2yqL0KOF9TISIkmjZ0Dw3xcroaze2Aui0nNXkqlUnuE5
         6dxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=oTnklaF1aF0bTWeWldi91Sj9bwNgHQZw6gVAVQdUYd0=;
        fh=eXjXHZJrVgAYhIa+mSiaipStoRkeDhvPVUEFQhvPmPg=;
        b=HbX0e7Wt17TIVBOZD3mzTDQbunkbu/3HH6v5DmjNLhUE11ZYJTzLbToyZAOjOSy8OB
         GB4NqlUFBuugE6+cDYZCTBGJFtrQwXZnDqTtKNUkO+xaUGn9ZRxEKM8v3E2Sf88ao9Wn
         7t4wEGb1INBOzP0hSi0XseIKLzGFw1racqmgCRo0AcPbyGqjDpeo2S2fEIISI6sigdL0
         mwMlE9+GQvU9ULmYsE5ffCKoRX58C/VXpzN/k9DNQr2Xs+eECbqSbxaRpV7K+IBDLcIV
         EvuVzKOceA/HewgFUx9Wiv7yt5C0dc2a9oITRFxzjzeij1bht65bwvzeNcVR8ROMOidd
         qymg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=NSmVjScl;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::632 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x632.google.com (mail-pl1-x632.google.com. [2607:f8b0:4864:20::632])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6c75e5a5e29si399346d6.7.2024.09.18.19.57.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Sep 2024 19:57:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::632 as permitted sender) client-ip=2607:f8b0:4864:20::632;
Received: by mail-pl1-x632.google.com with SMTP id d9443c01a7336-1fee6435a34so4604745ad.0
        for <kasan-dev@googlegroups.com>; Wed, 18 Sep 2024 19:57:00 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVSuFStVEeL9Zjf6y/0ImU1ENVANnn/3EvGmfv6/sEoFi1PxeirXZT6VXGTwulOIheDHFV00ss6Rn0=@googlegroups.com
X-Received: by 2002:a17:903:2445:b0:205:7574:3b79 with SMTP id d9443c01a7336-2076e3622b7mr412645275ad.25.1726714619622;
        Wed, 18 Sep 2024 19:56:59 -0700 (PDT)
Received: from dw-tp.. ([171.76.85.129])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-207946d2823sm71389105ad.148.2024.09.18.19.56.54
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 Sep 2024 19:56:59 -0700 (PDT)
From: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
To: linuxppc-dev@lists.ozlabs.org
Cc: Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Hari Bathini <hbathini@linux.ibm.com>,
	"Aneesh Kumar K . V" <aneesh.kumar@kernel.org>,
	Donet Tom <donettom@linux.vnet.ibm.com>,
	Pavithra Prakash <pavrampu@linux.vnet.ibm.com>,
	Nirjhar Roy <nirjhar@linux.ibm.com>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev@googlegroups.com,
	"Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
Subject: [RFC v2 07/13] book3s64/hash: Refactor hash__kernel_map_pages() function
Date: Thu, 19 Sep 2024 08:26:05 +0530
Message-ID: <0ced93c215459479ae70dd9bbe00daa595f9aff0.1726571179.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <cover.1726571179.git.ritesh.list@gmail.com>
References: <cover.1726571179.git.ritesh.list@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=NSmVjScl;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::632
 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

This refactors hash__kernel_map_pages() function to call
hash_debug_pagealloc_map_pages(). This will come useful when we will add
kfence support.

No functionality changes in this patch.

Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
---
 arch/powerpc/mm/book3s64/hash_utils.c | 9 ++++++++-
 1 file changed, 8 insertions(+), 1 deletion(-)

diff --git a/arch/powerpc/mm/book3s64/hash_utils.c b/arch/powerpc/mm/book3s64/hash_utils.c
index 030c120d1399..da9b089c8e8b 100644
--- a/arch/powerpc/mm/book3s64/hash_utils.c
+++ b/arch/powerpc/mm/book3s64/hash_utils.c
@@ -349,7 +349,8 @@ static inline void hash_debug_pagealloc_add_slot(phys_addr_t paddr, int slot)
 		linear_map_hash_slots[paddr >> PAGE_SHIFT] = slot | 0x80;
 }
 
-int hash__kernel_map_pages(struct page *page, int numpages, int enable)
+static int hash_debug_pagealloc_map_pages(struct page *page, int numpages,
+					  int enable)
 {
 	unsigned long flags, vaddr, lmi;
 	int i;
@@ -368,6 +369,12 @@ int hash__kernel_map_pages(struct page *page, int numpages, int enable)
 	local_irq_restore(flags);
 	return 0;
 }
+
+int hash__kernel_map_pages(struct page *page, int numpages, int enable)
+{
+	return hash_debug_pagealloc_map_pages(page, numpages, enable);
+}
+
 #else /* CONFIG_DEBUG_PAGEALLOC */
 int hash__kernel_map_pages(struct page *page, int numpages,
 					 int enable)
-- 
2.46.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0ced93c215459479ae70dd9bbe00daa595f9aff0.1726571179.git.ritesh.list%40gmail.com.
