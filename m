Return-Path: <kasan-dev+bncBDWLZXP6ZEPRB3EF5TWAKGQECAYUQDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id D5DCECDE16
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Oct 2019 11:18:36 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id 5sf3254090lje.12
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Oct 2019 02:18:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570439916; cv=pass;
        d=google.com; s=arc-20160816;
        b=UfsGQVSZlCuFa2BcmZQaD5kHo1oyMYOVCYyxnqi58qhpxbeLtWl+Tqt/8CeuHimNjM
         ubCpB1YPTcn5IGoST84wWgvQuINn1N4kWJuE5Y7XYQicgnnv8E68++HaVp6NS0c/2pXS
         +ktvZlz/oh/CQVurYBE5oZTepl/b44L/w7b+4r/p8V2nuOG1bnI9YikLd+uKd3FU+W5t
         8QG2fMJX+CSjclnGIjlaSVv8TFeRTl6kA2ZyunWyVvTJlA1FoYo9Ypd/Wl6ryqg3Jtl9
         TPYpSSltMviIE65heTR1XuuQUPM8kYysDKxAqR4IRhgvnVaScIz8Inhmo3rLvrAtzaNX
         gpAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=p3dHaBsClW+WVZcgMaMqHORREncmQl5eJKqYFbX9Tc0=;
        b=Gt/DYBauIyBQYeNu15ioE4/hQ/OU3XSBXGFc7rA2+jfJJ/jwprImQEHjj3bRvYuMa8
         p5ig3x8Sd4i/dMelvJ3vsqCQaU7YwhE3ZpGKb3mfBsHUXI5/ZMZi3pO1jUo4npzIOTbT
         /UlOq862Yz6c0KCB4RxFHjSyW6PIZm8wpn9wB/6NRa54Jlk5mXEyTq6+BJdtfuJB7+jW
         Kg8R9Ugpfw2zk5kiZN2escYvWucw+Nk4iAP+oB1zGvxjKksFfk1BAIXg6Cxn8VnLCIVV
         BIqps/ZyQE5UFADbeYGZkSZ4fZqM7MzVz45xhQ/g/8utjgM+cMehsCxwnpjvi5F3P9IS
         rhwQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=p3dHaBsClW+WVZcgMaMqHORREncmQl5eJKqYFbX9Tc0=;
        b=pdMRVl5oQNowqgqE4+edeEtwWsYWKJ2jf03QXbRRluDW3i6D5r2GNlEMweXFGqqey1
         OPtd4M6TvLH4w4Zxfv9/H04MWTur+fIJFWCtlBS1fWoaHuCI4slBplfHHE0CWXc/KWXv
         THxssbWFtHI0Tjv5oUvfFY1lF9y66ouvpRxJgxgell6dqtZKgHwBo7blQK0Lle5F5uf3
         QY9GIYnZLGUpos9l/vF8GFVyzxLtjsgr3fZADFWy5o1zbATYOf8pz6gfoDPoIP9oLYw8
         R0aUNhiKeFTxBFt2lLjiyoJbLp3bpxeVhB99Z7kVbq5oxJ3BsgQHrCToY1D46VzmiqzO
         V96Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=p3dHaBsClW+WVZcgMaMqHORREncmQl5eJKqYFbX9Tc0=;
        b=RV7hW+k1NagyP1JsKIDy5E05XiYJ0AkUcAdFVpIP01S/X68ljiYcNcpDQsL7DsX3bB
         fXjJ5B5O/oYaR4fY7uBS1tXUcxXP8kirkMsWIBL0skDos7stlIpwNq50yHOqdifbnC/z
         Y5AsTtPqCAImKlBae4iEhq7SQTibqzD+3FRrFG35V3hfbt2hnBsbhmZFribG/14NcQEr
         qHH/tTbxBtrlbWMOWEJdx85FbO04Nc6TpOo+JmbA/PN5YJHc73dMLUIRdX4b3fmMIdGW
         aoFCT3CqA67lCkIiz0jzRlq5vj4sYo5z0V1kzVGhMej9fJ8nXJQWj2tjgvoJFFN9kuTn
         oHsg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWwuOts9swt404JIFn9DaNZ5ZneSW3vHQH1CdiQQ6ZzSlAD6ara
	HRpHetFKnMEXYiNJXq3F8DU=
X-Google-Smtp-Source: APXvYqwUwSxvst+C31T2HjQRUziiDXmlNM9pjo3g+TIFasLrLaOzs4WlycUJEIqnZQ+6SJiFjfs6gA==
X-Received: by 2002:a2e:89cd:: with SMTP id c13mr17638131ljk.92.1570439916444;
        Mon, 07 Oct 2019 02:18:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:428b:: with SMTP id p133ls1461182lfa.6.gmail; Mon, 07
 Oct 2019 02:18:35 -0700 (PDT)
X-Received: by 2002:ac2:5091:: with SMTP id f17mr16627538lfm.107.1570439915479;
        Mon, 07 Oct 2019 02:18:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570439915; cv=none;
        d=google.com; s=arc-20160816;
        b=W7RrP/8a81Jmj+a6dHKwxEG8SZ3t7W8ckLmhq/8lp52eKeqF/kTTQdinBtQY6zyQMd
         Vp3oGwOq0PMsw5iSprDuFro1kFq0UvePpeHkSPCRQF049B0Mwo+Pg0I2JoytW/4lY3vK
         gLOTrEo+3arE65zR5A5W6KEASsVli4fkRf/EXCpG3QUI9OwB1wN1Hl0byT/S1g76N/eE
         PLjaNcwrXtyOe2RlrN8ZRhbYXU8ds6H1eDXM1CndRj2IEpZ5Rdnd69aHiMk+nDXTGyTP
         LMypPtJWMuRFeF3SmBuc5B55X+1YLsosXDRTsMAdgvPTx0hdX2DV/8tWFRUoKnn0hx66
         VkNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=7a8xfIysDRYNjU+ddtg0u89eT0jwQZZEZ3ZFcEij0z0=;
        b=AINL5vvXvNjRMHJLNT58DFGEQrvCrigV2bOa0IzfaoEpv9H8j9GCTQl0ULitP3UQpx
         WYnbWoETFl/Z8LtIEWRnD3L1b5fCB/rc3TIpUL6pThxgGy38KqvXltsNSCUzc5yKkXjg
         QO/ZJZzsHOkTAIgZBhU43hOcSzoi6oCqqo0DnVgnIQkKln+40B/MPmqks0cEQ5UH4uBw
         QtoviKC/Siv0GsdjtNOfhK5lWvvaoDzQoszX4mHpo2LIfRk1Du7iWB9J+8XSlKc8wgyk
         gOpOn3y29BO//b/y04byJBYPNbm75nq8+qWnW4kaXFjfn0gGsX6xCjGP5cGSWbS3X27d
         4rjw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx1.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id d3si862695lfq.1.2019.10.07.02.18.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 07 Oct 2019 02:18:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx1.suse.de (Postfix) with ESMTP id 20F32AC28;
	Mon,  7 Oct 2019 09:18:34 +0000 (UTC)
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
Subject: [PATCH v3 3/3] mm, page_owner: rename flag indicating that page is allocated
Date: Mon,  7 Oct 2019 11:18:08 +0200
Message-Id: <20191007091808.7096-4-vbabka@suse.cz>
X-Mailer: git-send-email 2.23.0
In-Reply-To: <20191007091808.7096-1-vbabka@suse.cz>
References: <20191007091808.7096-1-vbabka@suse.cz>
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
being allocated.  Kirill suggested naming it PAGE_EXT_OWNER_ALLOCATED to make it
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
index de1916ac3e24..e327bcd0380e 100644
--- a/mm/page_owner.c
+++ b/mm/page_owner.c
@@ -152,7 +152,7 @@ void __reset_page_owner(struct page *page, unsigned int order)
 	if (unlikely(!page_ext))
 		return;
 	for (i = 0; i < (1 << order); i++) {
-		__clear_bit(PAGE_EXT_OWNER_ACTIVE, &page_ext->flags);
+		__clear_bit(PAGE_EXT_OWNER_ALLOCATED, &page_ext->flags);
 		page_owner = get_page_owner(page_ext);
 		page_owner->free_handle = handle;
 		page_ext = page_ext_next(page_ext);
@@ -173,7 +173,7 @@ static inline void __set_page_owner_handle(struct page *page,
 		page_owner->gfp_mask = gfp_mask;
 		page_owner->last_migrate_reason = -1;
 		__set_bit(PAGE_EXT_OWNER, &page_ext->flags);
-		__set_bit(PAGE_EXT_OWNER_ACTIVE, &page_ext->flags);
+		__set_bit(PAGE_EXT_OWNER_ALLOCATED, &page_ext->flags);
 
 		page_ext = page_ext_next(page_ext);
 	}
@@ -247,7 +247,7 @@ void __copy_page_owner(struct page *oldpage, struct page *newpage)
 	 * the new page, which will be freed.
 	 */
 	__set_bit(PAGE_EXT_OWNER, &new_ext->flags);
-	__set_bit(PAGE_EXT_OWNER_ACTIVE, &new_ext->flags);
+	__set_bit(PAGE_EXT_OWNER_ALLOCATED, &new_ext->flags);
 }
 
 void pagetypeinfo_showmixedcount_print(struct seq_file *m,
@@ -307,7 +307,7 @@ void pagetypeinfo_showmixedcount_print(struct seq_file *m,
 			if (unlikely(!page_ext))
 				continue;
 
-			if (!test_bit(PAGE_EXT_OWNER_ACTIVE, &page_ext->flags))
+			if (!test_bit(PAGE_EXT_OWNER_ALLOCATED, &page_ext->flags))
 				continue;
 
 			page_owner = get_page_owner(page_ext);
@@ -422,7 +422,7 @@ void __dump_page_owner(struct page *page)
 		return;
 	}
 
-	if (test_bit(PAGE_EXT_OWNER_ACTIVE, &page_ext->flags))
+	if (test_bit(PAGE_EXT_OWNER_ALLOCATED, &page_ext->flags))
 		pr_alert("page_owner tracks the page as allocated\n");
 	else
 		pr_alert("page_owner tracks the page as freed\n");
@@ -512,7 +512,7 @@ read_page_owner(struct file *file, char __user *buf, size_t count, loff_t *ppos)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191007091808.7096-4-vbabka%40suse.cz.
