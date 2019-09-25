Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBOPUVXWAKGQETP7BRSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id D4C32BE008
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2019 16:31:21 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id e3sf1722972ljj.16
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2019 07:31:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569421881; cv=pass;
        d=google.com; s=arc-20160816;
        b=n4IXr4TzSH3ZuttQ5Gm6QezDrFpZP5H+tk9qfrUqzI3nzr90Izd1NZgWUp3sJDMHCc
         BUsYOQKrQQzHluz8OTeuLHmSoNyMEX1JrxysNxX7VvKkEWCCpQqe7P85OcuyGIeMXlNh
         JUjSxIfUCAoY5NaKSQFzNSq/xL5jcRPb3qzIMfZjiSBMSH6HqNFYNtTRIM7gRax/Nenf
         88/HxvVYaUQ6nsfMTOWin5O2lK4qCzTBCmcmLpvvq7t+Fh2YFXNrdCCI3mNjimiDPa0A
         XMPdIZ8sr3YSyYv+hqvyLf+viCiT3VUU6WFFse5KNv0MIgZFbUCGGIsFHX/NZ3WEnxju
         40qQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=b+2Nhgv+VhlzfYQrKYemw8PG9HdJl21JE1rDBN0qNPI=;
        b=QII5UAWUeDEj98PIUQJfl71J18S28pO4dFbb0EBMhyYpuDT28VkmLoWCXX/NTbP0DQ
         kLkUkVSTv4v+MltkOraruqLciqsSKlnOir77nUKeePWq/qDy91f+PUxtV3w7TxiNnFyX
         leCGhUc1vrIpfPzmb+o9b9EhvE4lfuWxAaT3QoiDnmCPajqKjRqth2hrViZ2j4z4BBex
         sETMVfj+ngjid1UW4PAOu8Jw3fDEXr2Tf8kOTYMjx3nWPd4PswOtJGooEb7V0FozbNZH
         gn+T7DCr2R4fM1jxlLsrhXTW/a1kSL9HabraKIm2rqQ5UeenjiCO+bpLYJDF25qOQKbo
         sVtA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b+2Nhgv+VhlzfYQrKYemw8PG9HdJl21JE1rDBN0qNPI=;
        b=Xx+Hzq240VKyQ6CbnyHc/PRLqEvyKeXM29L2v8jzqA8AahzuULM/IUqTbvDVp2h8fC
         u9eZKamjgWhgbu5mgL8IJ0pkF0oMPSRptpd2o3MbD6J3QZ9W47oarFyZXuUdP7hn+VOI
         cSrPoqgr830TJDCXDWbCJpLnbVqR6HBLUowg0yDSZgHfH/Y4UX3m8L9xq9SRgfhXW4pX
         7QVpvuCKRFXt1EmVSoEeMF6zPwbeHgc2Hx/2DgDA10wNDY1b4dXhPsxyNK/Ef+Ma8RFX
         1S6Zkec42WXgH1Wk9Hri8QB0z2e0oILIbKx5efahmboKs/CmPsSbKA7QOgIsuCIms0A/
         NTZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b+2Nhgv+VhlzfYQrKYemw8PG9HdJl21JE1rDBN0qNPI=;
        b=adka35hR1O51/LjEDH69Va+OLwPHcOsbUYjqeH6tQXB33VzOOIP8mEjjKhxMEX7ETw
         PoODmMqhfGPXd84hBC+hcktE5HTvSMvVlby+NBQDyQULyu2vekG6VKAxci5WAE3O6jRJ
         O+N1QMzJ3UOaeriHJlWMtdytcoMj4b3JrhDDFZaJVGz9LWl39b32SM+Yzz6bfY8goZDS
         S2mRHD2GP63Ht6ZiG6NjNMgO+auRw1G0DADTvo6Gld4Y8N3DTm4of6rYwhBDLR5qodCF
         XOORMy1VpYTH06rXirCYG0UjpLXVFSHyEDWSVX2ASuVX6puOytSWRBl0NQtqzwWa2n8s
         HGTg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAW83VtEM6n5XFyT92N6aUZVBab+/EVgY4JTXUQeDlYhvhdiV7yN
	iK9pO9fgZ6KeOsxrUXAa70k=
X-Google-Smtp-Source: APXvYqxSHKAJhsCmJGGBS7KobM4t4hSbgDpQ91JhQImRZUb7UWe4CMBkKkURpmwMfwAU0YWAMshKFw==
X-Received: by 2002:a19:6556:: with SMTP id c22mr6306201lfj.90.1569421881463;
        Wed, 25 Sep 2019 07:31:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:559c:: with SMTP id v28ls696709lfg.10.gmail; Wed, 25 Sep
 2019 07:31:20 -0700 (PDT)
X-Received: by 2002:ac2:5203:: with SMTP id a3mr6243870lfl.151.1569421880847;
        Wed, 25 Sep 2019 07:31:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569421880; cv=none;
        d=google.com; s=arc-20160816;
        b=bbMKBXpHJKNw4QTiwBIRVzAYWZVM6amEe60X/MeH04kdWTgtDY5+hbPfVpgM/BNs0A
         /FcXjB6GtTQZh1VQwTshhkP7bn78H4fQEvSZpB6v8wcAsncbiCpMmCAnAsKNmpeLEFhW
         OEhwthGTw+CPcCTFRus4e1b9epIqkFFyYM0LVa5tMr580K9AvKChiv3NpF+HnvSm3juh
         2cEo9+400Cwx8wQO1IbI/gtl2dfpPvX7XRWWD7ZUN6U5xati3aBHJye3wB4ol95xBhMU
         crtezXDEf5DXXq/r+Qe1KxPzmn71BSOh6hRNT9VZFHFwzWxKDtf0+yjBx6D5y06HG9F8
         Xipw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=7JOt+tce8+sCCjUyiHcnZVbE/UxoVcf1EIbVfDqUa+o=;
        b=WDH4RdRwWQ/1ix91HKUCFa9rISPJDkJSkmEZjsXOZfeTNXgYgv/3Zzo9ODe64dzIAE
         /nfF6TEE7FRQRdn9K2rCq9BmpNbYe0cMmocqcHw/GL3xL5xlyDE0nTTSE4I54/pAhEf2
         YVYqgf92O7cNNjMBTHlY1wmNdeo9gq2Dwte9pWBkrBZi5LO4+n7I30w8HvmymL1lUwWu
         NnCjZkIymKTgq26I4enuql2eYSsFm1fAtPHaAhrjQB3g5BPi/hGnJ7DJEVsk5i9AgGIZ
         FCCgqkwyqQF8WMXr5fCDDLWEzLyZvBi5xpon8pzvZusg8Zup63CRjG78Ofc+SCRN7Wnl
         iPdA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx1.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id y6si314649lji.0.2019.09.25.07.31.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 25 Sep 2019 07:31:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx1.suse.de (Postfix) with ESMTP id 610D9B60E;
	Wed, 25 Sep 2019 14:31:19 +0000 (UTC)
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
Subject: [PATCH 3/3] mm, page_owner: rename flag indicating that page is allocated
Date: Wed, 25 Sep 2019 16:30:56 +0200
Message-Id: <20190925143056.25853-8-vbabka@suse.cz>
X-Mailer: git-send-email 2.23.0
In-Reply-To: <20190925143056.25853-1-vbabka@suse.cz>
References: <20190925143056.25853-1-vbabka@suse.cz>
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
being allocated.  Kirril suggested naming it PAGE_EXT_OWNER_ALLOCED to make it
more clear, as "active is somewhat loaded term for a page".

Suggested-by: Kirill A. Shutemov <kirill@shutemov.name>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 include/linux/page_ext.h |  2 +-
 mm/page_owner.c          | 12 ++++++------
 2 files changed, 7 insertions(+), 7 deletions(-)

diff --git a/include/linux/page_ext.h b/include/linux/page_ext.h
index 5e856512bafb..4ca0e176433c 100644
--- a/include/linux/page_ext.h
+++ b/include/linux/page_ext.h
@@ -18,7 +18,7 @@ struct page_ext_operations {
 
 enum page_ext_flags {
 	PAGE_EXT_OWNER,
-	PAGE_EXT_OWNER_ACTIVE,
+	PAGE_EXT_OWNER_ALLOCED,
 #if defined(CONFIG_IDLE_PAGE_TRACKING) && !defined(CONFIG_64BIT)
 	PAGE_EXT_YOUNG,
 	PAGE_EXT_IDLE,
diff --git a/mm/page_owner.c b/mm/page_owner.c
index f3aeec78822f..f16317e98fda 100644
--- a/mm/page_owner.c
+++ b/mm/page_owner.c
@@ -163,7 +163,7 @@ void __reset_page_owner(struct page *page, unsigned int order)
 	if (unlikely(!page_ext))
 		return;
 	for (i = 0; i < (1 << order); i++) {
-		__clear_bit(PAGE_EXT_OWNER_ACTIVE, &page_ext->flags);
+		__clear_bit(PAGE_EXT_OWNER_ALLOCED, &page_ext->flags);
 #ifdef CONFIG_PAGE_OWNER_FREE_STACK
 		if (static_branch_unlikely(&page_owner_free_stack)) {
 			page_owner = get_page_owner(page_ext);
@@ -188,7 +188,7 @@ static inline void __set_page_owner_handle(struct page *page,
 		page_owner->gfp_mask = gfp_mask;
 		page_owner->last_migrate_reason = -1;
 		__set_bit(PAGE_EXT_OWNER, &page_ext->flags);
-		__set_bit(PAGE_EXT_OWNER_ACTIVE, &page_ext->flags);
+		__set_bit(PAGE_EXT_OWNER_ALLOCED, &page_ext->flags);
 
 		page_ext = page_ext_next(page_ext);
 	}
@@ -262,7 +262,7 @@ void __copy_page_owner(struct page *oldpage, struct page *newpage)
 	 * the new page, which will be freed.
 	 */
 	__set_bit(PAGE_EXT_OWNER, &new_ext->flags);
-	__set_bit(PAGE_EXT_OWNER_ACTIVE, &new_ext->flags);
+	__set_bit(PAGE_EXT_OWNER_ALLOCED, &new_ext->flags);
 }
 
 void pagetypeinfo_showmixedcount_print(struct seq_file *m,
@@ -322,7 +322,7 @@ void pagetypeinfo_showmixedcount_print(struct seq_file *m,
 			if (unlikely(!page_ext))
 				continue;
 
-			if (!test_bit(PAGE_EXT_OWNER_ACTIVE, &page_ext->flags))
+			if (!test_bit(PAGE_EXT_OWNER_ALLOCED, &page_ext->flags))
 				continue;
 
 			page_owner = get_page_owner(page_ext);
@@ -437,7 +437,7 @@ void __dump_page_owner(struct page *page)
 		return;
 	}
 
-	if (test_bit(PAGE_EXT_OWNER_ACTIVE, &page_ext->flags))
+	if (test_bit(PAGE_EXT_OWNER_ALLOCED, &page_ext->flags))
 		pr_alert("page_owner tracks the page as allocated\n");
 	else
 		pr_alert("page_owner tracks the page as freed\n");
@@ -531,7 +531,7 @@ read_page_owner(struct file *file, char __user *buf, size_t count, loff_t *ppos)
 		 * Although we do have the info about past allocation of free
 		 * pages, it's not relevant for current memory usage.
 		 */
-		if (!test_bit(PAGE_EXT_OWNER_ACTIVE, &page_ext->flags))
+		if (!test_bit(PAGE_EXT_OWNER_ALLOCED, &page_ext->flags))
 			continue;
 
 		page_owner = get_page_owner(page_ext);
-- 
2.23.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190925143056.25853-8-vbabka%40suse.cz.
