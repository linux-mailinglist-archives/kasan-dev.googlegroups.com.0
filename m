Return-Path: <kasan-dev+bncBAABBBVOWK4AMGQEPWL46JQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id D049699BE71
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 05:59:03 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id 3f1490d57ef6-e28edea9af6sf5104710276.3
        for <lists+kasan-dev@lfdr.de>; Sun, 13 Oct 2024 20:59:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728878342; cv=pass;
        d=google.com; s=arc-20240605;
        b=Tf6umzo1+N7/+z33h8NZcqpRNBlgIqu5iOWLOd5zuYJ+Vna5bD7lPQIRR31epvGPWu
         WoQ9rv9ypBCYNcZNuNWs2a0bbGQduK2MSynpQGqUaRliTup1Te4ILFp5l2aJXaP0eFp5
         rgX3hS2De1lPcuvJnRpY8Mn1RrpuIpoJTWYL3myVxuQqR3LvgNKligr+Hu4J/56WSBHE
         3WSF+HhHaYfwn+grW1SfD80031cW7s4IKpqZy6VbAPQfI+C7kPkiQkOqjN3HnH4EdOcN
         Z12bRhqUFNPhQ3Q+SKlRSMf9BDn+BV4epgAwOICkNX0O0dfYOqjRNSIYajYcqU9aLDuA
         Ek+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=pyOGrgjNtd1JiSRDzb9doqgCuRWPWCWgsnrwtoK9Mu4=;
        fh=yQj/czZd7GRPEA2iI4sFwaHcgFnCFuA3oTrTAgEEYo8=;
        b=izg2+OVm831+XgUA1EBjSmS4tQUJVQI0pbNL8TmN2E8xwd44dW0vpoE1FUE3SfxoC5
         MRrHm+PPuSYxGTXiDdXnVUrC8soH9GlghZZrNRTAjAkrhUeq4F7Xglr2nPSf1iQHXhbG
         s+eSZjayP/O99ZJTrcAl4vkg5dfqRwCskD3dMll0h+oKsuNWSLcdIfjhGxFp4wbVQgPV
         W+9EqysaoaoeOg2Pr7SHSDFDjEKqhqzbvkE/9ZV/I/zkbjZgQfR8tTHbartKXQcqPeB0
         BulSyZDzZFmdVNcJuEPzFX7MVVn3fBLNTVVIe7l3F1kNkXYKUsADe3XH/2ZQ+EMMXKtO
         XPmA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728878342; x=1729483142; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pyOGrgjNtd1JiSRDzb9doqgCuRWPWCWgsnrwtoK9Mu4=;
        b=VsXsSA+TveuvLc1kTwosQEBo0BdE8+eHQgr2frPSJXQIZK2vN0iitkdTOTc0wGdUrz
         xHU5wiCneimawSvtYuv4L61BJlmizhDHGO47loBor34eQbNZpKCw/fSX0BDyY8wpEOjW
         a1VfvClsiMZEwD5/7IUJeTDs/HFv8ljRzF7dk5x0Un9EsEmyYXZSoEhn+ASrqcH4uG6e
         2L4WtdgnTtS1GjjtD9aJc7SHpTXdu5qIngMfPMctSW0IGWhQzmwfiwReVlt22xKQw7W/
         kRWQHvXNayYMf0Jymt7+2xOGgwTz3ZPh790SDKyqmEhQ22hkPxHuTKCoagTIPxAk4CI1
         fqbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728878342; x=1729483142;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pyOGrgjNtd1JiSRDzb9doqgCuRWPWCWgsnrwtoK9Mu4=;
        b=COOkzEbMpoLWYOLosW7rZltziMExRZhoI7q0TOWnn7DZOR1qvYEnmq28xkFcq7xNgu
         KeKW49s3tBE8d7pkrWu1pBz/bZl0G/I0v9Nt46R68gWTiqM0fDGoa+OEbWCnxztNEZc8
         JUrOAeXx690CyegebG4R/BMKOFN5IBVpZCJdWJhutsthjnK/ukWL/2uRNH11aoCHlfG0
         taG+5blKJiqo4ixS/dNOyCj24l+2Ojc0uQ0BHxcS3A3iqf9rye2gQvglGayhg+bckMok
         OC1LUgfrbhW2BMR7/pGDW1pP4a7CjlN4ZAuWdUYD2MZ9zmimKHEJLNC0/hFOsmVbFK1N
         9Q6g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVKg86Gj+eVVLGPH/poHMcY9s+bHxxsZpD8Oyi2vcfiU4Q6j+ZgcdWJbJEWvlByDCjHMesrxw==@lfdr.de
X-Gm-Message-State: AOJu0YyWXkzWx37dklqacLia5iK8TkypK44/pJ8VNYDzg39jRzP804Mn
	XsK5/bZBuzJPnx7jROPaU+7P0U4r/tDLBCFsKOBbtLvujSaEWwiM
X-Google-Smtp-Source: AGHT+IEUprscaXz3KA3jC8li7oj8prYFlvQlIw/ISuCZYwbMHCZmIdwByi+SmH5JPPupUM8piQpZqQ==
X-Received: by 2002:a05:6902:e04:b0:e29:41af:e1a with SMTP id 3f1490d57ef6-e2941af0f22mr3025152276.4.1728878342544;
        Sun, 13 Oct 2024 20:59:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:120d:b0:e24:96b1:6ae with SMTP id
 3f1490d57ef6-e290b84cf67ls2180824276.0.-pod-prod-07-us; Sun, 13 Oct 2024
 20:59:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUsqZyFKAdKuxAGy8Td48lNCb2O3UL45PPAoI7o9eiHsWhBCMDkGTPEk+slEcRvk+akse7G5X+a77I=@googlegroups.com
X-Received: by 2002:a05:6902:100d:b0:e29:e81:fe4f with SMTP id 3f1490d57ef6-e2919fe8ad7mr7880696276.51.1728878341883;
        Sun, 13 Oct 2024 20:59:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728878341; cv=none;
        d=google.com; s=arc-20240605;
        b=RHYgWI3hml2g/GctedjNZu+gTjo4OTBLLbm9QX9Tzds19xNRSzj4zOaHZUGJrnU4Zm
         IyoQBfBvNKXgQrQ49NdBRe3qCHkFUWqKRF1H9mt+uyOGfP1UBWxf0Ip3TcdvHy1L2y1b
         cnmiJwsQy7Q3BN5XNts6/HvQ0CtgkASHZwz56V7B4MvWMmNUByrXHRlOXWvm+k75x3fX
         RTYDz7jSEgtMv359Jl9VW/p7l3bmE2CyQwaMEYfnhNWAP/gaE0skC6DqCIUZRyyuq5JC
         /Phx8JkCqHxXMTvfO96vkPpD2+p0F8DCBA+AK+CKNcww5+AkZ9j2pZVYf1WyF/ByTVnX
         zZng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=r39t5OT5vLHizTm15fY38kzPptRVLbY+MwS1wCM3o7w=;
        fh=W/+Rlbd92klLtgnDZozu+1Zm8L3oNk9WCo5yqUG4SDo=;
        b=fu3k4WPf85EqQJqoY1MfHc9BTGfAG/LHocv0LLA9z4EOQG43Z7TDGGE4ZKL0doAGAp
         r8actX158dyT+mdIsKdw+MzjXVU2e33ae3IJ8VFM3kEhfdw4sXxzMPJP6Tq0tKAdOxMR
         DYFClQu/ngM1PQIVseKSkgisiObXOr9cJLZEoU6xeeHM3kkDm9rtTpzrTieJMIcApQt3
         yOxuFv7rfNwp6VhNGSav6FZ91KAZ+zqJ+DMYEtbYRhZWoHlJ533r4fZHWbdqIqXRWxxq
         RmPZW+BDM91f1adjILFyP8aKUMGV3PczTskmM8wnCtXJf0tUWj+YxF3qZNJPmlMS5kq8
         P1rw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
Received: from mail.loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id 3f1490d57ef6-e290ede9769si476196276.1.2024.10.13.20.59.00
        for <kasan-dev@googlegroups.com>;
        Sun, 13 Oct 2024 20:59:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [10.2.5.213])
	by gateway (Coremail) with SMTP id _____8CxbWsBlwxniQIaAA--.38057S3;
	Mon, 14 Oct 2024 11:58:57 +0800 (CST)
Received: from localhost.localdomain (unknown [10.2.5.213])
	by front1 (Coremail) with SMTP id qMiowMBxXuT_lgxnc6EoAA--.1717S5;
	Mon, 14 Oct 2024 11:58:57 +0800 (CST)
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
Subject: [PATCH v2 3/3] LoongArch: Remove pte buddy set with set_pte and pte_clear function
Date: Mon, 14 Oct 2024 11:58:55 +0800
Message-Id: <20241014035855.1119220-4-maobibo@loongson.cn>
X-Mailer: git-send-email 2.39.3
In-Reply-To: <20241014035855.1119220-1-maobibo@loongson.cn>
References: <20241014035855.1119220-1-maobibo@loongson.cn>
MIME-Version: 1.0
X-CM-TRANSID: qMiowMBxXuT_lgxnc6EoAA--.1717S5
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

For kernel address space area on LoongArch system, both two consecutive
page table entries should be enabled with PAGE_GLOBAL bit. So with
function set_pte() and pte_clear(), pte buddy entry is checked and set
besides its own pte entry. However it is not atomic operation to set both
two pte entries, there is problem with test_vmalloc test case.

With previous patch, all page table entries are set with PAGE_GLOBAL
bit at beginning. Only its own pte entry need update with function
set_pte() and pte_clear(), nothing to do with pte buddy entry.

Signed-off-by: Bibo Mao <maobibo@loongson.cn>
---
 arch/loongarch/include/asm/pgtable.h | 35 ++++------------------------
 1 file changed, 5 insertions(+), 30 deletions(-)

diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch/include/asm/pgtable.h
index 22e3a8f96213..bc29c95b1710 100644
--- a/arch/loongarch/include/asm/pgtable.h
+++ b/arch/loongarch/include/asm/pgtable.h
@@ -325,40 +325,15 @@ extern void paging_init(void);
 static inline void set_pte(pte_t *ptep, pte_t pteval)
 {
 	WRITE_ONCE(*ptep, pteval);
-
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
 }
 
 static inline void pte_clear(struct mm_struct *mm, unsigned long addr, pte_t *ptep)
 {
-	/* Preserve global status for the pair */
-	if (pte_val(ptep_get(ptep_buddy(ptep))) & _PAGE_GLOBAL)
-		set_pte(ptep, __pte(_PAGE_GLOBAL));
-	else
-		set_pte(ptep, __pte(0));
+	pte_t pte;
+
+	pte = ptep_get(ptep);
+	pte_val(pte) &= _PAGE_GLOBAL;
+	set_pte(ptep, pte);
 }
 
 #define PGD_T_LOG2	(__builtin_ffs(sizeof(pgd_t)) - 1)
-- 
2.39.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241014035855.1119220-4-maobibo%40loongson.cn.
