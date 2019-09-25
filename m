Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBOHUVXWAKGQEAN7OIKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id C9146BE005
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2019 16:31:20 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id b6sf2487972wrx.0
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2019 07:31:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569421880; cv=pass;
        d=google.com; s=arc-20160816;
        b=l5NvWkhKdl33SbjA+Qzo9rCJdcxs4lfLxDqWZvlENo9hgkuHBSMZzUP/+e2gbw7ucR
         y2p5ePCPoOOT5wZSFJvn1o1jcHuazEKDNSnph8q1uE/vDKsGETmj3APr8nzyJKFIMSeN
         n4gTMYmeLjG74iqgkvQ4q2Iyp3f/BAZB2U7xt5utsP0G1FlWX7PPqe8D/Wn+cbx3/ZR3
         I2PYIgwhi7aSGaRTJLLylhm3ZT2E1vVcTeXGV8kDLViF6RS/+s9bcrXqxqNo5N9tcORu
         esGa+HCd+6eMYmfbikj01kZiS/UMpzFsDcsm0oNcHrVjHffUp2xWuX32IaqAb07owv2W
         qViQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=J692rHgP2/AWPcXt5DeCuIDVFHHjrtuedQ0pg1O4iE8=;
        b=bF9NUeq3hCp9PxY5WajSopcrexKLUxpC2EemQUf0RoZOgZ1rIc/yGZqjvov3Ms9lO4
         OmjPuKe5PHCeBznsDMk1PQ+HfPMyasYt4NT2eP08UeaVJ7gp6v4UrAwbLFNhjN2h039p
         mttRhICNdY0iMGL/ZEgCkD0bbir0LDXY/yPY+Rl+Gg0dnZCeKh8W3iMLSweBpAsSQ+oC
         TdS5wVGUbJjy/tPJQ5pbpu6HQKOH8YTwVFKcM0U/0NxAZX3S5WmKSaUtydL8GN7UPawp
         glY8sMBWSENZu89Y3NMVRjkSC8q7vb9IiBBHnTsZCt3+n6MpUnmV8BEc1NMoC1oVKNFG
         d8HA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=J692rHgP2/AWPcXt5DeCuIDVFHHjrtuedQ0pg1O4iE8=;
        b=VlVdHNvgkQP9YYQ4fpRqm0bGJoLe0r7InzQKhHTlvsN0S35+JxFkCBUsIayZ9in4c+
         QKv2OCApFp3z9g5s4hSYVAw0bXv13D6Ey5weN5bZ6blEhwWXzu+9zvmPsihkMkhwYGbG
         1MZlsq/LGpiZdGTI8Id1DE1keO9SWS8Vihw6Zgc5yihJw7EpbKYp13R7oaMQTsLQvAQx
         QaGM3BQu7Reb/g/rhbLKAw6Wa3MbjzYZ5lsgkb9wLu/FUrlHHDzD3nCZEwzSXO1oih7E
         Hh+tjsdL+snAxYvub5WtM1/W3l1OQgwYfkjDCJgFs3MnbXTBPME2RyxnXin/2FGfqAxH
         sNiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=J692rHgP2/AWPcXt5DeCuIDVFHHjrtuedQ0pg1O4iE8=;
        b=m9awP6Q1bcM1hXyl8JeELX/G8v4fe4mz10bhbP7ll+dNZPD/NXB9+zlHlDc02w3AeW
         HeiSDgHO6+cCzBj5F+NDCJq1LmCPzVsYcDdnI3uePPChQS0p+cXCX8X3vPoDGTWcQdsc
         Gl5yFT8qPmUmSptJny2bKchaJw6FH/8uNfJttUT/l0JL0Ry+ZKX3yJMmDzwoRv/xvXS0
         piZqLKB0VJsWdAdKGZUUwF3zi0tYEpXsdB8odIsQ/mmrgrwe4a+sgxk/hEZz4tCgo31j
         dAra6MCykr97I/eD/q9DSfwgLZygZimLmcdh0S/JwJBJaOgJdjsBA58pqZ5T/8u3fu5j
         ze3A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXA+jogZo9+hGOx4tRTEFDIUviy+t2U2HF0hr/GHrnMWrHtH+lY
	5b2LCSD6fG+4VMqZYFdu8Q0=
X-Google-Smtp-Source: APXvYqwB2jCOlhesWWJwhhzuHs3Pl5cYcBXGIk0vtwiEo6XyO6zDql8Ru5XQInV9cHKIK9N8l352nw==
X-Received: by 2002:a1c:66c2:: with SMTP id a185mr8080182wmc.2.1569421880520;
        Wed, 25 Sep 2019 07:31:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:828e:: with SMTP id 14ls2301407wrc.7.gmail; Wed, 25 Sep
 2019 07:31:19 -0700 (PDT)
X-Received: by 2002:a5d:4745:: with SMTP id o5mr9758857wrs.125.1569421879773;
        Wed, 25 Sep 2019 07:31:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569421879; cv=none;
        d=google.com; s=arc-20160816;
        b=r7sp7bx+A256S1eXFnBQuvX24MJYscHxB9oCe9fXefSeFvMeegrCMiMNC21hSQ9WDW
         FHSXlAFH6UXQnSb8poN+/kRi2MsWriHps4bQPVG9yEKgVAafO09k0AEUhGB+248l5+o5
         d+H2Zl5KAUJyCJztU8w3SLU/Ys/SfkKM9j2FwU4NnBUp3Szd7nn8SYbViiHBe9nfcwNa
         y9ZNnbEopirA5nPGnVQJyJ8h+NPapIsHWalD5LfY9AavuZGWsXEKwUURFFt2heXMgBB8
         iaTWzjd0gSHh3KqCmPX0gL3c1o4Lj85VeguGpxSdz9T1avPjZuyxs+WYJ2KmynDHGYO9
         ipow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=7JOt+tce8+sCCjUyiHcnZVbE/UxoVcf1EIbVfDqUa+o=;
        b=ocMiDbt8vvM94K+eUyaxPmxVk8sg9uizdzScYmcF//z7rO+q9nomL8wm4lW9d+MhX/
         Ddmzl3qhyjXkmCIJIytzbFaHwo/DlI3WpxBoXKx0WRLOZ6F1V8kyTGCUt17rbhkGFUav
         yLqaLcAPFah5hJUNVBrhVwYgZpfBQjZNyYh75HXwFHILaAEZtHUz9XH9dB1TjtnPmLXD
         wrkzX3Y8/cBKyUzOhiYxz84qedMgxbPG7xasbmfjoKonbUSR+Cu4jwXJiimCSpCOea4b
         3E2vE+zjib8PiU0Wfs+1KNC1LOirUYi3mv7K+e8jr0lvbsjR1zpMc2hxBJbk3Z4uw8O9
         xPHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx1.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id n16si263716wrs.4.2019.09.25.07.31.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 25 Sep 2019 07:31:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx1.suse.de (Postfix) with ESMTP id ECAC4AFC3;
	Wed, 25 Sep 2019 14:31:18 +0000 (UTC)
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
Date: Wed, 25 Sep 2019 16:30:52 +0200
Message-Id: <20190925143056.25853-4-vbabka@suse.cz>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190925143056.25853-4-vbabka%40suse.cz.
