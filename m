Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBKXKY7WAKGQEC5OFN3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 879FBC2097
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Sep 2019 14:29:30 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id w10sf4448952wrl.5
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Sep 2019 05:29:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569846570; cv=pass;
        d=google.com; s=arc-20160816;
        b=e8g5R5vY+kl+E2/kZcACdPQsGwkNRPkiP2JZp0jqdwff8RpI/zg99VHWplrVIowQeJ
         08LVs2237V3B2FXv3map6QUZDK0AgR0Rh5ZN09BhEgVrSh9sjN7HCDfR9Y+haJbLX2du
         7SKC9RrwOuJdEB81NYl+aKKXccQhNDIfzwic+aCjpeyIljLQklEJhuJMVWGMFYPa8CDo
         ZZwX55DWzOJ5a+gGS5xQWukV6uH2nVB6BEcmWpeXB9lW6LKCWi4M7YwOoMc5DPc4ACbB
         +CHDmovVN503H2tUYoaib/lgLR1lSCy022BI7ny4PJgRLVDizLg2mrfWfHj++V16fDlM
         1i5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=t2deDTmY7+nhmlotjvouD3LB13bimL6+56fzYm0sB54=;
        b=X+fssoFYmz4xyjbwfbw/ZVjPcJR9VEXc2qO4VFqoHWU6wdpUUT1bvR0ZARpRih1+CW
         nb6mpOK2Ato0TEmijBp0/Qiw+w9iT5YqbJzH5/IHRwzcDLXxwlY9K2pC2kYc7/JQE/WA
         5lB+K/dnuoBv6tDeNMGcody8HswP6NrA6NhrpBkhUAYNeLyux3h9RU00lHmGfJnoUR2s
         gg1LlUZHTt7X/WO4VsXH5CCIqswEY2aLMNiSIysrhpLXAzHEhChErJ5YshMuQxujQ1Uf
         8q1eNH0IZpo2/WjjgFaoURv3FZ9KuLhtaplZ98CBZz1c/cnXaTLd+iYP9CE9ERYbzd/W
         +GMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=t2deDTmY7+nhmlotjvouD3LB13bimL6+56fzYm0sB54=;
        b=bceXbz2kq/dVbDgwEOPq4CXkxdxAzUDn02TN4gJd2okIg4aDvwLaaiqaiWl2DRhVl/
         CyVbwRWEAkQiU4zMp2vYp0gFa3F3AYTZZtBtuOif6OdsX6xlxKWcfzzf3YDdueC1lZOb
         COWoQ3MIP8mp9/Z1oBOUiRwPHH4wBgGU8jPSx4xL7TIG8kFcYDnv3kk2Drq//WEVgTRf
         R5U4kK/TR5g0gMGQbRjV7hGGP0Kd14ESFni5OMKHLd2QwxLpRFSPw+738Sn8efP1ErKC
         5nMjfGQzBtxdVql2EqGCobBWITz/hVgTmd+fiKHLp2PkD6KNsTuVpFMy++xhq7Apafdx
         rG1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=t2deDTmY7+nhmlotjvouD3LB13bimL6+56fzYm0sB54=;
        b=aOJ1DM718wf2yOKA4fBfP1SNJr1wK1KIUVUyzozRBFJwvuatpjP/zrbp4c6+lzcwij
         uslv6AX7iQFvJ+UwRnm4sauluski4A0q/7cIv0ECW5dFuwaLoIRfEyc+A//MW/Kr74EL
         Ozc2IuoTdRq6bQdpaqCjgm2mGijmM6es1dV5HhI7gpsvqzIVguNBJwvHZRnz9o9YaDpI
         4EYIrqOj52OHrxyt49zzm9DJ4V+MnOB2jvXmHZhsp6LCXlWyDIEH3wolG96+Tyf3Ol61
         j5UEdnEkVNv71N9jG9MK/GvdVb5koEKT9IROIarpVmfy5R6WIaoKiUn0brzUF2MjyfA2
         e/1g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUinX9WOaSvccCu0ASJu2EQIqpSWYa4faKbDbKZzv0F4vbGSGfx
	PVWkMHVV3iXiTA725xnF+H8=
X-Google-Smtp-Source: APXvYqzDRQ/0thZarghtvLaPjuYuT69MzsOaEqMzmQBCurKW8R6tjiNKKVQoAWXkK/87z34tSiA2zg==
X-Received: by 2002:a5d:494d:: with SMTP id r13mr10137703wrs.166.1569846570197;
        Mon, 30 Sep 2019 05:29:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:eacc:: with SMTP id o12ls2990299wrn.5.gmail; Mon, 30 Sep
 2019 05:29:29 -0700 (PDT)
X-Received: by 2002:a5d:5229:: with SMTP id i9mr13252852wra.76.1569846569685;
        Mon, 30 Sep 2019 05:29:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569846569; cv=none;
        d=google.com; s=arc-20160816;
        b=vVeyTFv32IVZQMhPXOT1TxrOwcJ2KUCe9wp+cRWKIlcHzMJu1q8m4yxgvpMKwfVryS
         G4d41q0LwVOqzpSvfwsqmL4ANt5FR3ylV04J1OwegWgfysY91Lx3++INk7OuJyGQxa/8
         BMXQ+eynTcngH8UWz5wtR7snnGM2Fvye/v/j4XZ2sVbWxVymZkOJN4r/dL3LbT5mhLsQ
         +sSwl0CkQBBuoOTeepkQWVslvaoeCGPZX7IIRaFhMS1LwPQGOHm8ew9hFuc1jZa+PnZG
         7A/bG/tuvmVevu2dd5QBTxAbTRFcNTA5gLtCftzoYaJAfFqYNja4mVBRsk1bmM7wEnKT
         jCaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=uu25XMmDRYaFACbjR1Iem7YrdP199RugQ/nKYTzB71s=;
        b=gNhx2zrJxeK4gY8N1LnByYkGhARVEtjydIM4I33ccX0/2GSqX1mhagllsrUgWN01xA
         m8w4t3qVj2FKaO3/G9BIJReBSjrVfCoQV+UIaNNMiIdbvnxgdIyQFlKVJNWVTFMjipFx
         LYAEwtkc8pL9iq7gXnfat77Gme51cEzQT3c4rZE8JRif5qwzlG4pg/VHMjVgQMAJzerD
         OjSfHNIGM2T7Vp6bhWGZOcl+THEOI8/6LDvQtEqTmmQRgnCPKy4JUgt6rxdYpa4BIGVv
         GdIbt0Z4WBRVQdfL2zpXdfh1x6TLYAyKdeKzVlwt1u1UEqJh0V484fwqJyZEU8KC2a4X
         L1IQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx1.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id n16si727994wrs.4.2019.09.30.05.29.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 30 Sep 2019 05:29:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx1.suse.de (Postfix) with ESMTP id D51D0AEF1;
	Mon, 30 Sep 2019 12:29:28 +0000 (UTC)
From: Vlastimil Babka <vbabka@suse.cz>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Qian Cai <cai@lca.pw>,
	"Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
	Matthew Wilcox <willy@infradead.org>,
	Mel Gorman <mgorman@techsingularity.net>,
	Michal Hocko <mhocko@kernel.org>,
	Vlastimil Babka <vbabka@suse.cz>,
	"Kirill A . Shutemov" <kirill@shutemov.name>
Subject: [PATCH v2 3/3] mm, page_owner: rename flag indicating that page is allocated
Date: Mon, 30 Sep 2019 14:29:16 +0200
Message-Id: <20190930122916.14969-4-vbabka@suse.cz>
X-Mailer: git-send-email 2.23.0
In-Reply-To: <20190930122916.14969-1-vbabka@suse.cz>
References: <20190930122916.14969-1-vbabka@suse.cz>
MIME-Version: 1.0
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
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

Commit 37389167a281 ("mm, page_owner: keep owner info when freeing the page")
has introduced a flag PAGE_EXT_OWNER_ACTIVE to indicate that page is tracked as
being allocated.  Kirril suggested naming it PAGE_EXT_OWNER_ALLOCATED to make it
more clear, as "active is somewhat loaded term for a page".

Suggested-by: Kirill A. Shutemov <kirill@shutemov.name>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 include/linux/page_ext.h |  2 +-
 mm/page_owner.c          | 12 ++++++------
 2 files changed, 7 insertions(+), 7 deletions(-)

diff --git a/include/linux/page_ext.h b/include/linux/page_ext.h
index 5e856512bafb..cfce186f0c4e 100644
--- a/include/linux/page_ext.h
+++ b/include/linux/page_ext.h
@@ -18,7 +18,7 @@ struct page_ext_operations {
 
 enum page_ext_flags {
 	PAGE_EXT_OWNER,
-	PAGE_EXT_OWNER_ACTIVE,
+	PAGE_EXT_OWNER_ALLOCATED,
 #if defined(CONFIG_IDLE_PAGE_TRACKING) && !defined(CONFIG_64BIT)
 	PAGE_EXT_YOUNG,
 	PAGE_EXT_IDLE,
diff --git a/mm/page_owner.c b/mm/page_owner.c
index a668a735b9b6..55f60ae2b6f8 100644
--- a/mm/page_owner.c
+++ b/mm/page_owner.c
@@ -200,7 +200,7 @@ void __reset_page_owner(struct page *page, unsigned int order)
 	if (unlikely(!page_ext))
 		return;
 	for (i = 0; i < (1 << order); i++) {
-		__clear_bit(PAGE_EXT_OWNER_ACTIVE, &page_ext->flags);
+		__clear_bit(PAGE_EXT_OWNER_ALLOCATED, &page_ext->flags);
 		if (static_branch_unlikely(&page_owner_free_stack)) {
 			page_owner_free = get_page_owner_free(page_ext);
 			page_owner_free->free_handle = handle;
@@ -223,7 +223,7 @@ static inline void __set_page_owner_handle(struct page *page,
 		page_owner->gfp_mask = gfp_mask;
 		page_owner->last_migrate_reason = -1;
 		__set_bit(PAGE_EXT_OWNER, &page_ext->flags);
-		__set_bit(PAGE_EXT_OWNER_ACTIVE, &page_ext->flags);
+		__set_bit(PAGE_EXT_OWNER_ALLOCATED, &page_ext->flags);
 
 		page_ext = page_ext_next(page_ext);
 	}
@@ -297,7 +297,7 @@ void __copy_page_owner(struct page *oldpage, struct page *newpage)
 	 * the new page, which will be freed.
 	 */
 	__set_bit(PAGE_EXT_OWNER, &new_ext->flags);
-	__set_bit(PAGE_EXT_OWNER_ACTIVE, &new_ext->flags);
+	__set_bit(PAGE_EXT_OWNER_ALLOCATED, &new_ext->flags);
 }
 
 void pagetypeinfo_showmixedcount_print(struct seq_file *m,
@@ -357,7 +357,7 @@ void pagetypeinfo_showmixedcount_print(struct seq_file *m,
 			if (unlikely(!page_ext))
 				continue;
 
-			if (!test_bit(PAGE_EXT_OWNER_ACTIVE, &page_ext->flags))
+			if (!test_bit(PAGE_EXT_OWNER_ALLOCATED, &page_ext->flags))
 				continue;
 
 			page_owner = get_page_owner(page_ext);
@@ -473,7 +473,7 @@ void __dump_page_owner(struct page *page)
 		return;
 	}
 
-	if (test_bit(PAGE_EXT_OWNER_ACTIVE, &page_ext->flags))
+	if (test_bit(PAGE_EXT_OWNER_ALLOCATED, &page_ext->flags))
 		pr_alert("page_owner tracks the page as allocated\n");
 	else
 		pr_alert("page_owner tracks the page as freed\n");
@@ -566,7 +566,7 @@ read_page_owner(struct file *file, char __user *buf, size_t count, loff_t *ppos)
 		 * Although we do have the info about past allocation of free
 		 * pages, it's not relevant for current memory usage.
 		 */
-		if (!test_bit(PAGE_EXT_OWNER_ACTIVE, &page_ext->flags))
+		if (!test_bit(PAGE_EXT_OWNER_ALLOCATED, &page_ext->flags))
 			continue;
 
 		page_owner = get_page_owner(page_ext);
-- 
2.23.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190930122916.14969-4-vbabka%40suse.cz.
