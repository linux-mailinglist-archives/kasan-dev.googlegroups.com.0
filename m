Return-Path: <kasan-dev+bncBDX4HWEMTEBRB34LXT6QKGQEBCFC5DY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F4892B281E
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:17:19 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id 67sf4697795wra.2
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:17:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605305839; cv=pass;
        d=google.com; s=arc-20160816;
        b=ywBZm/enOUnu7TvZBG/KDxPaeBlMRM/4VMOCKsJO7fDIbeJQfffEHExvjLIijxLUIZ
         SxtJwZ4bMZf5d9RKMeO7IiuhMOHxd4br2ySU/TjvFERzazqVN706eOe4w482/QyTgrFs
         1/H7jEYEodFkBcKeBcv0M0Ehll1GR+mUq61VuZb8ZP3+D1sfMu3c5E4cH2NVgPMORxoK
         T/Fjphri8x7AVyRJ0u6bIJa/lim4ms2hlfN7frfszD/UPz+xhN3KryvQlHq429z4HRWE
         BpuSWy0B7zC+6QdQ+43gT/cxs8NW9w3CmCrDx6Afg2h7Uoop+93wOAeGAVpcEjgQcFQO
         uqsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=yV4q3xBhhNNUXCWbeb8FDob0VEfCaWkuiq5rJqvudnk=;
        b=l9JxZX19NiRWFGf8xBcZLKaXNXfe+91q02886Dz8uX/7j6UCr9f5k8gdYNpOInhE/e
         hgKCIQYLypzsoFUHq97xUqaj1rUiZo0JMSkaLtPsjES61JPhbhCWX6ZqQv8zLAY4z7zM
         IRnv0ddmfZZxBC0vBfgT4wxnuqX27MRrBQdySAGjWUf8SeHhuDBqZJBB+6/5y90xpQqz
         0/ePHsK2I1AX6RvXDyLk8uXOewKOR4MM87p0h29glISS3g2zLQqEcLLPuisqqOe0lnHE
         sKpN//C8kTq2zg3vjk2qv4j/nk6RbZdv9EbW3/xwv9VgA74YxXvKDw4aC+Y9XhchlzYO
         lCCw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MPUYatJk;
       spf=pass (google.com: domain of 37qwvxwokcbgylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=37QWvXwoKCbgYlbpcwiltjemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=yV4q3xBhhNNUXCWbeb8FDob0VEfCaWkuiq5rJqvudnk=;
        b=QE4mkxiqRwQqYDpF8vhknezJb0UzWOww/IaF8pXv4+FnU8Nfm90nhs5DEyHj83NFEz
         pItxSZyvfYrvWXK3Z+Bc/4pgsOkl5NlBQ+duCMAUC+JIQZgGb6FqOqBbeysLuR3aBDPv
         UTD8h4r52w20BBNF7NIr8VD75EzSLnlxIEEcYKB846nFZ94Q7e1CIEX3g2oF3PQJIthi
         nPnPXxJvoKjE/63k0YOZKSmu3BMLbWemDNdiCILYVww+2vYH/ShyRfEPeZdpa/YT5F+E
         H2XlNh/kUXNAa7pSvaucE/sj/FYd2hEu0q/hdGTukgkJk+emr/4sw3i252x4gzh1jVW5
         Gvqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yV4q3xBhhNNUXCWbeb8FDob0VEfCaWkuiq5rJqvudnk=;
        b=tsO03OnRuMushy7PcpxbtC98atZiOirZJZs+MXG8G5NgPcQjXA+SX2KeBTpO//s6Nq
         fp8QwOQs+x03/xJppO6qY1xMrw2VTAvPP8pYS+W45Zf9hFmMcpq/m+T62be7sk5O0VyK
         +Ar6cNxMJNXjO1ZqzE3A3HExeLhaqN2aySS3y3Vz0lio7ECSCdx4d1eeliDuZGMZ8mBG
         NztzR4mzlfXSnueb+ZZym9H/PeOTNggqCYfwxDwQUnbOVrn+SpovMuCt/G3S/KAeiUSp
         cTjOeTR9Vjti4REPvT9FF25Dg/GX/zrKjdeFjC5/5CA48ASHekCuK0aqm4ATo8Xwc6pp
         gQ9Q==
X-Gm-Message-State: AOAM533g9zJnKmRApLqwf0di7bk/f9EP/CUS7nVxxiRb46fZyoF6OLN4
	B1qdhCJIVMLcS+ui9ef8Ma0=
X-Google-Smtp-Source: ABdhPJz/WqZQ5w9dcCprWLTWk1bps3iXQ128NxwPMCJKcyMa2opNMaMIeHHiI330UBS4Lyf1/m2LmQ==
X-Received: by 2002:adf:97dd:: with SMTP id t29mr6179179wrb.185.1605305839323;
        Fri, 13 Nov 2020 14:17:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:aa87:: with SMTP id h7ls7246505wrc.2.gmail; Fri, 13 Nov
 2020 14:17:18 -0800 (PST)
X-Received: by 2002:a5d:4104:: with SMTP id l4mr6502005wrp.276.1605305838583;
        Fri, 13 Nov 2020 14:17:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605305838; cv=none;
        d=google.com; s=arc-20160816;
        b=nbom+MygU3goPfzqb1IPRZbpQDHobDl/6EtSTeAndH2ZziZSicPd7FJ+FiUqFAujtM
         F3pN1aSffSLd22Bbfz/qpROcoXVpisXebLxk6c4UnKmPFO5Vwkq6Zj+YxWR5j1NxgueO
         wktwuILY3Wlrbpplg2/XrkGsbB9lOsbHHxdP4X9t1LwIhy4KaX2dxLcGuhCYcTN449Nq
         qfeAHq+sKSrmvebMlvPMMFWX9a2bbAJoOf0W1tczq2x3QE3KbgmQoL2g6gxbOj3YsMBJ
         8kVSOXa1tOJGkMe2aUxmohiKMmyFyUj2JfKTXBHFkfrad1aUOIl75ji36I3g2VUTptTp
         kSkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=Ho6gRtmpYK99NRY0nqMDMTWGuBlu7BoOKXCHJVaPFrA=;
        b=j3oa+f/+qkC1kkeSpadKImq+D0mqTFRK2yGp+AlyOp06MJ5tgGwv9taV0lVi6iODUT
         2kbACAiFkQHOVLn5uwpoFTfU7A9642ldetbrMwifxEnG0ecBvTPiZMivTSp0qOoCbV+G
         PH/PbbA74WKY8GtNL/KP4hJEgRUmJyHAylZMsTDzdpSWk2HPXunnBUPSDBHu9YY0xFfP
         74pf6/wTmwxrSVHIXSfJGJ4ZWZ0Gsp19Sb6auHWoHUYhZP66p9O3N+SpIs/psii1qmoN
         9QSUy5SeUZcjFJARTMK9aXsB/NeQ4Q5xs20HPUovCuzxImc33LN08HgscC8fCWNHT5oq
         eqDw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MPUYatJk;
       spf=pass (google.com: domain of 37qwvxwokcbgylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=37QWvXwoKCbgYlbpcwiltjemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id j199si407347wmj.0.2020.11.13.14.17.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:17:18 -0800 (PST)
Received-SPF: pass (google.com: domain of 37qwvxwokcbgylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id n16so5508225edw.19
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:17:18 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6402:141:: with SMTP id
 s1mr4617132edu.87.1605305837947; Fri, 13 Nov 2020 14:17:17 -0800 (PST)
Date: Fri, 13 Nov 2020 23:15:54 +0100
In-Reply-To: <cover.1605305705.git.andreyknvl@google.com>
Message-Id: <18bca1ff61bf6605289e7213153b3fd5b8f81e27.1605305705.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v10 26/42] arm64: mte: Reset the page tag in page->flags
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=MPUYatJk;       spf=pass
 (google.com: domain of 37qwvxwokcbgylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=37QWvXwoKCbgYlbpcwiltjemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

From: Vincenzo Frascino <vincenzo.frascino@arm.com>

The hardware tag-based KASAN for compatibility with the other modes
stores the tag associated to a page in page->flags.
Due to this the kernel faults on access when it allocates a page with an
initial tag and the user changes the tags.

Reset the tag associated by the kernel to a page in all the meaningful
places to prevent kernel faults on access.

Note: An alternative to this approach could be to modify page_to_virt().
This though could end up being racy, in fact if a CPU checks the
PG_mte_tagged bit and decides that the page is not tagged but another
CPU maps the same with PROT_MTE and becomes tagged the subsequent kernel
access would fail.

Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
Change-Id: I8451d438bb63364de2a3e68041e3a27866921d4e
---
 arch/arm64/kernel/hibernate.c | 5 +++++
 arch/arm64/kernel/mte.c       | 9 +++++++++
 arch/arm64/mm/copypage.c      | 9 +++++++++
 arch/arm64/mm/mteswap.c       | 9 +++++++++
 4 files changed, 32 insertions(+)

diff --git a/arch/arm64/kernel/hibernate.c b/arch/arm64/kernel/hibernate.c
index 42003774d261..9c9f47e9f7f4 100644
--- a/arch/arm64/kernel/hibernate.c
+++ b/arch/arm64/kernel/hibernate.c
@@ -371,6 +371,11 @@ static void swsusp_mte_restore_tags(void)
 		unsigned long pfn = xa_state.xa_index;
 		struct page *page = pfn_to_online_page(pfn);
 
+		/*
+		 * It is not required to invoke page_kasan_tag_reset(page)
+		 * at this point since the tags stored in page->flags are
+		 * already restored.
+		 */
 		mte_restore_page_tags(page_address(page), tags);
 
 		mte_free_tag_storage(tags);
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index 8f99c65837fd..86d554ce98b6 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -34,6 +34,15 @@ static void mte_sync_page_tags(struct page *page, pte_t *ptep, bool check_swap)
 			return;
 	}
 
+	page_kasan_tag_reset(page);
+	/*
+	 * We need smp_wmb() in between setting the flags and clearing the
+	 * tags because if another thread reads page->flags and builds a
+	 * tagged address out of it, there is an actual dependency to the
+	 * memory access, but on the current thread we do not guarantee that
+	 * the new page->flags are visible before the tags were updated.
+	 */
+	smp_wmb();
 	mte_clear_page_tags(page_address(page));
 }
 
diff --git a/arch/arm64/mm/copypage.c b/arch/arm64/mm/copypage.c
index 70a71f38b6a9..b5447e53cd73 100644
--- a/arch/arm64/mm/copypage.c
+++ b/arch/arm64/mm/copypage.c
@@ -23,6 +23,15 @@ void copy_highpage(struct page *to, struct page *from)
 
 	if (system_supports_mte() && test_bit(PG_mte_tagged, &from->flags)) {
 		set_bit(PG_mte_tagged, &to->flags);
+		page_kasan_tag_reset(to);
+		/*
+		 * We need smp_wmb() in between setting the flags and clearing the
+		 * tags because if another thread reads page->flags and builds a
+		 * tagged address out of it, there is an actual dependency to the
+		 * memory access, but on the current thread we do not guarantee that
+		 * the new page->flags are visible before the tags were updated.
+		 */
+		smp_wmb();
 		mte_copy_page_tags(kto, kfrom);
 	}
 }
diff --git a/arch/arm64/mm/mteswap.c b/arch/arm64/mm/mteswap.c
index c52c1847079c..7c4ef56265ee 100644
--- a/arch/arm64/mm/mteswap.c
+++ b/arch/arm64/mm/mteswap.c
@@ -53,6 +53,15 @@ bool mte_restore_tags(swp_entry_t entry, struct page *page)
 	if (!tags)
 		return false;
 
+	page_kasan_tag_reset(page);
+	/*
+	 * We need smp_wmb() in between setting the flags and clearing the
+	 * tags because if another thread reads page->flags and builds a
+	 * tagged address out of it, there is an actual dependency to the
+	 * memory access, but on the current thread we do not guarantee that
+	 * the new page->flags are visible before the tags were updated.
+	 */
+	smp_wmb();
 	mte_restore_page_tags(page_address(page), tags);
 
 	return true;
-- 
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/18bca1ff61bf6605289e7213153b3fd5b8f81e27.1605305705.git.andreyknvl%40google.com.
