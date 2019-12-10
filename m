Return-Path: <kasan-dev+bncBDQ27FVWWUFRB26GXTXQKGQENWSB2GI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id B2165117F1E
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Dec 2019 05:47:40 +0100 (CET)
Received: by mail-pf1-x43f.google.com with SMTP id b8sf10644630pfr.17
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Dec 2019 20:47:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575953259; cv=pass;
        d=google.com; s=arc-20160816;
        b=IdYGj3Wshhoyk3Csdww6qI3eAuI8DnenpcJQq8SyILh+KhmORl8EXx7zA8d3Qg47Wr
         PeHUrcAHm4TEA2DhtpLwSwdr21psX1THCks3zPiLkHNh2iNap370ggjLuoUq/Spf4sC+
         LaTZDdnGEhO5byQPv3hgTZ7cPPdmYoxI2LcBrmk63LsbBbyrIyMILgopPQxagTxYePom
         NrIRNSdD5eeGQUUTBBJE3rzT2GratmM9YNuKzWgAZmSqVvj0IBacTxHP2YKT4dBsLluw
         7D7KsEJtrq3ss9dx2fU7YFqvf99dDkBbCc8X420n5KaaNNb0kNgule4k0zP73qeg+A/W
         Z/0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=YjVtM1omOP0F32gOCulwVX1+auMv6Hhmf7XXdNgBbhY=;
        b=MBHC3ojpyLdB1sAovFyvpWzyqDerwyVfe6IY6vvdh4bP69D7lVaYrr0a2gr8i57kiW
         cko/XrrwYvqadsCl90DANznr70V31T607PaXn12USobciAK2FjknaVKqpIYYqfEKqr0K
         6gMm0Z/rsQmgvsmPLylyTdLmifCzGx00l6WbvvfrPqzVZyGGUcmO1X4cjr+2BszZ11su
         /5eCA0IaewLHAF6KCATq574RKMmk+uA1ktEMD1WC5m6Z7F49er8BVYwLTHjts7wJGNkL
         SCSgVRbQj4OnYfJB0ooyBuUK1TJjR7feP6z2fsSSQkxGF+mSwXKTXuXT5BTf2qrgRGo6
         EbTA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="Twub/7df";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YjVtM1omOP0F32gOCulwVX1+auMv6Hhmf7XXdNgBbhY=;
        b=Rwl6fG8+7rqomrpaKWUg+YP/02xVhwZcB6e6YM3qDmAmG9BfVI+UMFZOwISEAb5oOs
         F6dBTzuTRDNt1jL+cC0XBJTugAOWnx3O0aZBgKIRP7dwiBhu/uOHGpmltNCB195me3EM
         2hOwyRI5TnzByQKfzsd1QpFoPU67hSg22pD/g20ofBnTIKj33u8sBbWKPhoYXzW+ONol
         uMBbu9IH/ZucWb4r4AZfJ5ZgNHIqk9oj016e5H90FvZBxcqNZgyfbxNyz7sDkTpMvX5Y
         JReMyZQJgZkQLEJ0pYkbyHI6/0fwD5njErx0TFR1nPXhP91u7OC9GhKWCMJahelCx34/
         /3uw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YjVtM1omOP0F32gOCulwVX1+auMv6Hhmf7XXdNgBbhY=;
        b=HiKXromzS1THEY5oxTd4mMo/0JKyWzvynwl8xOcZBbGmcJrquMoO22Quvp2oWrKiga
         7ft4ZBvDTeDSr9FqarulDO5OastmD49wgT6rdAaIPIcysIYzvZmT+A1k/H0JpLyKT/jC
         +Jumiv2Prjrtok12YO2WeP9LEfKjW+FZDfmPlLDlDuTZ3eAVsw83zq/8nqjbi9KwrKqU
         fmVikvj3d17hwJUeTut+x2aRparuJ3DfkoBwnqzZlHkiQM+vwTqmEMlFud0OFbtwXBNY
         BNDCenQjKrr3SssGaQH0G2mTo6DH6br94d4thgKKRhM89NibGOBtFwHImuAOKbEcuPTJ
         Zh/g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXfQF9VKIrrqyJraSMRDET+chBfKfu1ghpxvz1JqXEVX6PW3Nco
	gZkZcvxaRDFNHpGJjN4rCHc=
X-Google-Smtp-Source: APXvYqwCfpv8h3lGC0fNdhtvU0xpDA2xK5J9T1MswEP4QmdzSM2j1LcxjvZjYJRqVEIsunIbaZamQg==
X-Received: by 2002:a17:902:209:: with SMTP id 9mr34037056plc.58.1575953259165;
        Mon, 09 Dec 2019 20:47:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:4948:: with SMTP id q8ls4037105pgs.12.gmail; Mon, 09 Dec
 2019 20:47:38 -0800 (PST)
X-Received: by 2002:a63:e17:: with SMTP id d23mr22754629pgl.173.1575953258800;
        Mon, 09 Dec 2019 20:47:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575953258; cv=none;
        d=google.com; s=arc-20160816;
        b=ORho6QM1aq/0GmcBqbQ5J1nXpw7njIXz+mjr16beEDy8uYXPjMe2ES2zQQ6ko/lsSq
         u7fvBgNSKBRAbV7LVAepfnlWx8gCn2AlgK16/JPX0f9tXkZqlmCjeINHduBG8rYeTjbk
         oJ8ZQ6V71ZJyhhzbgK9NXMCN3q+X4XsgnnG5SfvIfDUgc8mkiRxNUqnQdeGeexE2mGoW
         8Pja20+XKYpg2wuaiPtk0TL20EPXy83LnMIGu7JDEbXEHPM0mhWj00ybv0sr/u3xQGdv
         C3q+jiPt2JX/1XupuxsRoQ1ivIptIZcO9UxkTZe2mA/w+q/UlSyQu9LFND0acHP9ebhX
         fwZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=txq3LAFK3wOGlutPVrH/f5MoWKzx5UG/2rHrSgg8Ef0=;
        b=DRvQ5p87SECuEdoqEYl+aSQphVVMqU/JPUnVimmgB0YIMx6q1mwLIkdXvxzJbawlZE
         gSJlXmiaWHypQYDWJhEMzxGKoyy32H18h+EZbGH9nHQLQIdbl3tg56yCNAbZrwRdVuZM
         2FQiH/kjJ/3s99th9pLFnswDZP4lvKGbjAe5sifoJImK2dldEDPfWgHR1uVTh0jddmZt
         h1oGUsd5qAwNv1mcaomachIo0Kn2CRg9H9/GAMoaUWlkU5+7peKPgM6zYPUdBo3vrymO
         xrKIv6k/BrTNr4+EUk9wML1yfo888ausXVePuaJlYrot6Z0FhAH5ld1lGfE9RYr7K63P
         Bz/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="Twub/7df";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x542.google.com (mail-pg1-x542.google.com. [2607:f8b0:4864:20::542])
        by gmr-mx.google.com with ESMTPS id p5si27845pli.5.2019.12.09.20.47.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Dec 2019 20:47:38 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as permitted sender) client-ip=2607:f8b0:4864:20::542;
Received: by mail-pg1-x542.google.com with SMTP id r11so8272751pgf.1
        for <kasan-dev@googlegroups.com>; Mon, 09 Dec 2019 20:47:38 -0800 (PST)
X-Received: by 2002:aa7:8f16:: with SMTP id x22mr33786940pfr.120.1575953258528;
        Mon, 09 Dec 2019 20:47:38 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-e460-0b66-7007-c654.static.ipv6.internode.on.net. [2001:44b8:1113:6700:e460:b66:7007:c654])
        by smtp.gmail.com with ESMTPSA id c184sm1185254pfa.39.2019.12.09.20.47.35
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 09 Dec 2019 20:47:37 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	linux-s390@vger.kernel.org,
	linux-xtensa@linux-xtensa.org,
	linux-arch@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@c-s.fr,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v2 2/4] kasan: use MAX_PTRS_PER_* for early shadow
Date: Tue, 10 Dec 2019 15:47:12 +1100
Message-Id: <20191210044714.27265-3-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20191210044714.27265-1-dja@axtens.net>
References: <20191210044714.27265-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b="Twub/7df";       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

This helps with powerpc support, and should have no effect on
anything else.

Suggested-by: Christophe Leroy <christophe.leroy@c-s.fr>
Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 include/linux/kasan.h | 6 +++---
 mm/kasan/init.c       | 6 +++---
 2 files changed, 6 insertions(+), 6 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index e18fe54969e9..d2f2a4ffcb12 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -15,9 +15,9 @@ struct task_struct;
 #include <asm/pgtable.h>
 
 extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
-extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE];
-extern pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD];
-extern pud_t kasan_early_shadow_pud[PTRS_PER_PUD];
+extern pte_t kasan_early_shadow_pte[MAX_PTRS_PER_PTE];
+extern pmd_t kasan_early_shadow_pmd[MAX_PTRS_PER_PMD];
+extern pud_t kasan_early_shadow_pud[MAX_PTRS_PER_PUD];
 extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D];
 
 int kasan_populate_early_shadow(const void *shadow_start,
diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index ce45c491ebcd..8b54a96d3b3e 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -46,7 +46,7 @@ static inline bool kasan_p4d_table(pgd_t pgd)
 }
 #endif
 #if CONFIG_PGTABLE_LEVELS > 3
-pud_t kasan_early_shadow_pud[PTRS_PER_PUD] __page_aligned_bss;
+pud_t kasan_early_shadow_pud[MAX_PTRS_PER_PUD] __page_aligned_bss;
 static inline bool kasan_pud_table(p4d_t p4d)
 {
 	return p4d_page(p4d) == virt_to_page(lm_alias(kasan_early_shadow_pud));
@@ -58,7 +58,7 @@ static inline bool kasan_pud_table(p4d_t p4d)
 }
 #endif
 #if CONFIG_PGTABLE_LEVELS > 2
-pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD] __page_aligned_bss;
+pmd_t kasan_early_shadow_pmd[MAX_PTRS_PER_PMD] __page_aligned_bss;
 static inline bool kasan_pmd_table(pud_t pud)
 {
 	return pud_page(pud) == virt_to_page(lm_alias(kasan_early_shadow_pmd));
@@ -69,7 +69,7 @@ static inline bool kasan_pmd_table(pud_t pud)
 	return false;
 }
 #endif
-pte_t kasan_early_shadow_pte[PTRS_PER_PTE] __page_aligned_bss;
+pte_t kasan_early_shadow_pte[MAX_PTRS_PER_PTE] __page_aligned_bss;
 
 static inline bool kasan_pte_table(pmd_t pmd)
 {
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191210044714.27265-3-dja%40axtens.net.
