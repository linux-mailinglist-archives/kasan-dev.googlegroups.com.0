Return-Path: <kasan-dev+bncBAABBIE6TW4AMGQEHPXDY4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D354997B7C
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Oct 2024 05:50:59 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id d2e1a72fcca58-71e00c8adf9sf573363b3a.1
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Oct 2024 20:50:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728532257; cv=pass;
        d=google.com; s=arc-20240605;
        b=Rt5AcvB5j4eoR6GPIzfJI6XsSAud14F3mL2rOpJY+rvq3Jw6x2iydE6vxt7Z3333IS
         TjPWMNhesyd5ZBkNUnRZNPhTy6s1BOo8wvwplhCzFIsf9sfSs3MUGsqAn9e15fvJ1268
         rl+5Ugcxlzuz3B7SaAbl8uVmVFiStvqBO2YfOODrH4qw1bSeT3KcHG1PHHqEyUa/fXuR
         GDYBmxU3JCUQxoxybNkqPppVpVR4eCkv3/XgJEYbkjooGNR6BT9o0ubUlRf04rsSKweU
         vz1XQtQOlj5N6gWsPpOhmlF3jlFVoKPVw3tKfacubqv8J8fuIlhjc6Il+p2OQ9Zd4tet
         X2oA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=HYiIYpEcA1Z59Ezfco2HjfQH/p6ihVlfxwCjDfo5GKA=;
        fh=lMXdoMw2YsRAp0lktlQwneaidSxzn6gHt7n7okUcMtQ=;
        b=dTRLuTzbOvpj2TyfKkp5jyQvLsLgninY3xY0/CmoTDy8SgtsLo2yD5qcOGqE+mu+P5
         8l8/H5GYqmBYu6ykuu9YNMgoNNadSNijhYJixE7l3ZGsRfF2QHVk2CM1qqy8a8p1miBz
         ePV90TcHkbuiC553lu6xPoNd80b1Re8Aq4kP8FivqjegxSnpRykm69cubFEiHqXPCWHJ
         1lKPTChqfnuNiEo3pyhJ7TrN25M0OnY6S6z+vAUdaz1WhQRnDaCJAXJ7639d2yxdiSSF
         8WFpMnSskHTsI4mOj78+L+iR2jbthVrbJfhDClmjHH/H6FmaDtAzBjJvRFb+yHLNrda0
         hOlQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728532257; x=1729137057; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HYiIYpEcA1Z59Ezfco2HjfQH/p6ihVlfxwCjDfo5GKA=;
        b=ATpcw9fSEX3GTCCHRR0NnXbPIms0gAAG+s4gGi71igop5EPS5KqnV9ekN2cR2T3/ZL
         0ZHgFcpwOkYZX84iMrmJ+tVXNHPlAFslrP5Vyi7iwfpCTV6Wm49jHq3ylKkHOjemuV6k
         svtO3gNQeJQ79U/0GYtYtNBtvHhzucIH07an1F5a0BFEgLoakiMTO0vrI9XNq8SWetOo
         zg4FmiX30MerK4SzfXZXsjD8+6MU+EdppvWaQaPaYcHsY8hvGZ+JNBqymZAb8Y0XQhQq
         6t2rPGa9BzQIykOkE41PN1sKyUzrLupltYVl7wHwe2FG9tLUqoH79qHZumXDDnL+r7o4
         xi7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728532257; x=1729137057;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=HYiIYpEcA1Z59Ezfco2HjfQH/p6ihVlfxwCjDfo5GKA=;
        b=Ru313C2H/OL8zzxMFSa9m90i0ZnbivPXwzaLtRj/nzNdduOsSABb03EtEumO5/OOL4
         k0nihFIkm6JBlIyz/cFpQQsGF3hH1p30sMq4O1f7lNTbyf9vWA9lKCdD19jE4uFohJG9
         FC+v/fMtyTSdRFrCd/oqH1bztwK+HQEf4OiErXbVR1IiRwsn5w+u2YdDMnBMyz4bTHSy
         8C5HqAzLxHmFhuT3rsbJjPDvGdgDiz/8K6KH4/O1AgMYNZ7BvsK71turwKZI4qHnXUgO
         y5InSPdkaloagZHEtkES2byGP+Ef2GTLfVu7EwzvjubtKqhV7IaqJjbHhSGE1AgllzH5
         zwEA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXPHGCxaxrxPxDomd+O09Mq5dqEl6OBTr3H144y2/VE05cUnDjArb0hwBcxGqXkKkmhHi0p1A==@lfdr.de
X-Gm-Message-State: AOJu0YwjM2ON6biwBJZVJakGeXJ5doMaf4GnZYr5FQ1ISxlvigCoCuVo
	LBTnhYQov2wU/0b9NU8Spta6Mvo1cU2+l40AvDRTX9gfq3ht7S1w
X-Google-Smtp-Source: AGHT+IGwv4/FJRetBK+7SqNfOYVbt1VB/P7okDXmU6LixXzGEe6W2M8MuJ7KoM5EL9O3NchGHzCQug==
X-Received: by 2002:a17:902:e891:b0:20c:8cc4:cf1b with SMTP id d9443c01a7336-20c8cc4d243mr6248235ad.43.1728532256964;
        Wed, 09 Oct 2024 20:50:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:1908:b0:2cb:5bad:6b1a with SMTP id
 98e67ed59e1d1-2e2c81bcaf4ls384805a91.0.-pod-prod-05-us; Wed, 09 Oct 2024
 20:50:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVlABVDo3vhZ4IcV0tAeUukfAGdRVK4S8qryGDb1+WXWXrqY5u1m2xgcP8aSHueToBx17eZCv76+ng=@googlegroups.com
X-Received: by 2002:a17:90a:4b4b:b0:2e0:a77e:8305 with SMTP id 98e67ed59e1d1-2e2a25796abmr5298395a91.39.1728532255834;
        Wed, 09 Oct 2024 20:50:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728532255; cv=none;
        d=google.com; s=arc-20240605;
        b=lUIQQYuS3FiTa1wWxJ6STeis7bQMWPeCBhYGuHHdJV4ihKYxW2IQrG86PgMphCs4Ca
         Yuu8BP5f0WdEbSZiMKZdL2VSQHgL+TrZyk2iIJo7p7LIg6UuLO5c1XRCRHy61LCndb4y
         pu8fgi6l10ItprHggStNAyyDyx99qpvfsXFPlmwFi29Ch7WXf/MfDMg0BOxWWzA8zLkJ
         c2rUvoRIV7Alh60QHaWwg5Of6RRLoZqP4MmjRyYyh2hyJAcpSfRi5rpPkU5NWhYXwJpJ
         JROykIo9Ih+4Md3Rqmj/6rO4VZFtelmZ2B46VBKku0KguMOBpGKO+dbBnAbQHsdhyU17
         3ZRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=GhqZgEmhO01NNuYz9LQ6ht12zOqcVK4S3QCK4DG4Y1Y=;
        fh=W/+Rlbd92klLtgnDZozu+1Zm8L3oNk9WCo5yqUG4SDo=;
        b=Wvrn242Tiju14LA28kMw+3E8sZYs3MkwlMy9yeNKe0keuwTtSPP35nUPhr+3Vd+2W0
         8jlHvCRxmbzF7cGltmsppNZlnZ4vPg9BkAsXqY3bGPcvLkPXacPlWyjt9LNx4vmq/zvM
         qXc5SHb2RUlV4zus3wYykQnZx47nh/PewbUYzkxe6yqiUVDZZIPIdnEm2MKrbp8T++Vx
         CAxA8oQjnMC6kVHhqp6v6H4hsIps5poA66dE9zYfVic3pwzPpMHnLVz/g/gmY+U1QZGn
         Tj4edjUF1UMIcoJkuyXnQDyKZqdn4Q37mYgyO3mY94xYOCECRppXjaNI5NbFcXyHHjFo
         oWHw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
Received: from mail.loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id 98e67ed59e1d1-2e2c08ade3esi127202a91.1.2024.10.09.20.50.55
        for <kasan-dev@googlegroups.com>;
        Wed, 09 Oct 2024 20:50:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [10.2.5.213])
	by gateway (Coremail) with SMTP id _____8Bx22obTwdn37sRAA--.25594S3;
	Thu, 10 Oct 2024 11:50:51 +0800 (CST)
Received: from localhost.localdomain (unknown [10.2.5.213])
	by front1 (Coremail) with SMTP id qMiowMDx7tUZTwdnFP8hAA--.52915S6;
	Thu, 10 Oct 2024 11:50:51 +0800 (CST)
From: Bibo Mao <maobibo@loongson.cn>
To: Huacai Chen <chenhuacai@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: David Hildenbrand <david@redhat.com>,
	Barry Song <baohua@kernel.org>,
	loongarch@lists.linux.dev,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: [PATCH 4/4] LoongArch: Use atomic operation with set_pte and pte_clear function
Date: Thu, 10 Oct 2024 11:50:48 +0800
Message-Id: <20241010035048.3422527-5-maobibo@loongson.cn>
X-Mailer: git-send-email 2.39.3
In-Reply-To: <20241010035048.3422527-1-maobibo@loongson.cn>
References: <20241010035048.3422527-1-maobibo@loongson.cn>
MIME-Version: 1.0
X-CM-TRANSID: qMiowMDx7tUZTwdnFP8hAA--.52915S6
X-CM-SenderInfo: xpdruxter6z05rqj20fqof0/
X-Coremail-Antispam: 1Uk129KBjDUn29KB7ZKAUJUUUUU529EdanIXcx71UUUUU7KY7
	ZEXasCq-sGcSsGvfJ3UbIjqfuFe4nvWSU5nxnvy29KBjDU0xBIdaVrnUUvcSsGvfC2Kfnx
	nUUI43ZEXa7xR_UUUUUUUUU==
X-Original-Sender: maobibo@loongson.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as
 permitted sender) smtp.mailfrom=maobibo@loongson.cn
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

For kernel space area on LoongArch system, both two consecutive page
table entries should be enabled with PAGE_GLOBAL bit. So with function
set_pte() and pte_clear(), pte buddy entry is checked and set besides
its own pte entry. However it is not atomic operation to set both two
pte entries, there is problem with test_vmalloc test case.

With previous patch, all page table entries are set with PAGE_GLOBAL
bit at beginning. Only its own pte entry need update with function
set_pte() and pte_clear(), nothing to do with buddy pte entry.

Signed-off-by: Bibo Mao <maobibo@loongson.cn>
---
 arch/loongarch/include/asm/pgtable.h | 44 ++++++++++------------------
 1 file changed, 15 insertions(+), 29 deletions(-)

diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch/include/asm/pgtable.h
index 22e3a8f96213..4be3f0dbecda 100644
--- a/arch/loongarch/include/asm/pgtable.h
+++ b/arch/loongarch/include/asm/pgtable.h
@@ -325,40 +325,26 @@ extern void paging_init(void);
 static inline void set_pte(pte_t *ptep, pte_t pteval)
 {
 	WRITE_ONCE(*ptep, pteval);
+}
 
-	if (pte_val(pteval) & _PAGE_GLOBAL) {
-		pte_t *buddy = ptep_buddy(ptep);
-		/*
-		 * Make sure the buddy is global too (if it's !none,
-		 * it better already be global)
-		 */
-		if (pte_none(ptep_get(buddy))) {
-#ifdef CONFIG_SMP
-			/*
-			 * For SMP, multiple CPUs can race, so we need
-			 * to do this atomically.
-			 */
-			__asm__ __volatile__(
-			__AMOR "$zero, %[global], %[buddy] \n"
-			: [buddy] "+ZB" (buddy->pte)
-			: [global] "r" (_PAGE_GLOBAL)
-			: "memory");
-
-			DBAR(0b11000); /* o_wrw = 0b11000 */
-#else /* !CONFIG_SMP */
-			WRITE_ONCE(*buddy, __pte(pte_val(ptep_get(buddy)) | _PAGE_GLOBAL));
-#endif /* CONFIG_SMP */
-		}
-	}
+static inline unsigned long __ptep_get_and_clear(pte_t *ptep)
+{
+	return atomic64_fetch_and(_PAGE_GLOBAL, (atomic64_t *)&pte_val(*ptep));
 }
 
 static inline void pte_clear(struct mm_struct *mm, unsigned long addr, pte_t *ptep)
 {
-	/* Preserve global status for the pair */
-	if (pte_val(ptep_get(ptep_buddy(ptep))) & _PAGE_GLOBAL)
-		set_pte(ptep, __pte(_PAGE_GLOBAL));
-	else
-		set_pte(ptep, __pte(0));
+	__ptep_get_and_clear(ptep);
+}
+
+#define __HAVE_ARCH_PTEP_GET_AND_CLEAR
+static inline pte_t ptep_get_and_clear(struct mm_struct *mm,
+					unsigned long addr, pte_t *ptep)
+{
+	unsigned long val;
+
+	val = __ptep_get_and_clear(ptep);
+	return __pte(val);
 }
 
 #define PGD_T_LOG2	(__builtin_ffs(sizeof(pgd_t)) - 1)
-- 
2.39.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241010035048.3422527-5-maobibo%40loongson.cn.
