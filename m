Return-Path: <kasan-dev+bncBDX4HWEMTEBRBLXORT6QKGQE3OFMOTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 261A92A713B
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:20:15 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id dk5sf2976edb.20
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:20:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604532015; cv=pass;
        d=google.com; s=arc-20160816;
        b=c3YxUjYS52O/Ugk1GDyo7fIQX6T4N9kz/S3kBbOlslcQC/yUNjbrbUQST98Rl/4S43
         Mpgf8wsmMbs/xSIHVywgfI2o5YzoFRiOkRdZ/No8mOF0EKQ6bBrZsx5I/hMxnfdlVb3E
         umf+bibmkPWjWQZkPLtIGCweW1Xlkl2hla4M63dHPUYZagY0fw4fne5k1L65FI+HCx0F
         0QrbLkuCA2V9l2ik12iNJAheGYIlYT1oCNeAtJOJrvAsMxLk0Ys66IHxKwVJHAi4Qn8q
         aE57EXED4R9iHXNN1FHd02qHJZ7J8d4uz/nq3ReMWC2SMzhEOg9d/l5Ve8hBPhggaig9
         sJBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=fpseERdGjeqNjuHpa5Pe9dIIYsvIrGResbMQkr6VYj4=;
        b=y/U8dOaGN+KzLZarwWSVj+N8rEFJq55WX42Nm8GysWKpRdK23+Jh/hO9D9hsaYJto+
         ZZD3aMMF2l9I/P/B+UHrknSLLHR7RrVj2/FBSLzANLC8Ss5vl2JeevaZdmnC2rdkaG/q
         82TPX1LysJkABuqcblRWANwuuoMwsh0zwjx0rgy1r66xiHzGKUriuI7JHEoz5A1KyJr8
         O6StYPjga/ZyTh+nhwUY0fM5ie2+OK+z3ue2Kxji/FhWKw39YYRymvxQ+duUPHdB2xxb
         VeiAzOm1J4F27P1NMklYdtuFvBjhMwn2A6qSfhxDwGXTvuXj9SiZrIjknJ43pFyhS+sL
         xECA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uWjOaiCp;
       spf=pass (google.com: domain of 3ltejxwokcswivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3LTejXwoKCSwIVLZMgSVdTOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=fpseERdGjeqNjuHpa5Pe9dIIYsvIrGResbMQkr6VYj4=;
        b=gbBJuLdG8tiPGMqTOpcALAsLvEefSaUF5NyDT7ysaAxtJzC4bg9Q1UIoSmL57+zA3O
         WYI88fJDGgkb8tPC8XUvdjepZiHznGf8Qt3/iL/H2slCfVQqNRiG0qxT8JzTrcBGfwf5
         hKHrjc50Z04ivZBCUCCfFE0VYJMPZYZgSNbyOAyvKFgSk6qGACotRVyKCYsBoQlSH4m1
         Gfi/Uc1C1MIgtvq9zPG5ehaOKBpktv8bUv1jaJz0HbjnkDn0KMgIUlPUaPYweCY48GgA
         /59StV23Sf66iL7vTSl/qQShnsMQUEKo7rKAytG5DU43NircbpuMqKEphdX9mTXYQSDr
         Wf8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fpseERdGjeqNjuHpa5Pe9dIIYsvIrGResbMQkr6VYj4=;
        b=Wl3oR/8uEUKu2AeHSK6pHDqt3Wd8ot3+oLrWai6faWcjcqOuYtsB2prV8yWLAJKCay
         PCLqxDp0IG3a3rUaQzce+o3NiyNuPht1eYSVzBPH3HE5wUB5AeDIss4Z+IQJzXEh+RQg
         jzybhIKYfK0PMWn1qFG4n2Sd7Corrr/EA6DO4Aqyqtf91nnzzqqPa9BbEJl2CHKGWEDC
         G+oDT3xW6e0040nktMEg0Qb8es9k+r2Vnr/Etx8ydaBAdIxeUpAkUCLtBT0obNvhOaSi
         XsoJkiDtW8fCDLzjjFcKNXozgEc+TD+QVy1KH8M6mn96+1/LMT3OvRfkn9sOscNKegdJ
         MlZg==
X-Gm-Message-State: AOAM53256WjsgohsDLDDhMHRp4J4SA6yZ2g/YxzB/wpdMUYPmY8JtLv/
	bJWkmuufDfgGvNxKFrm7FSk=
X-Google-Smtp-Source: ABdhPJxa6pN9njL5tR4i0JWPfk2JhF01BcArHhUMyhZ0D8uDaMhQMPYLF9Bs63BUpUillmwxygzuGQ==
X-Received: by 2002:a17:906:c1c7:: with SMTP id bw7mr459314ejb.290.1604532014948;
        Wed, 04 Nov 2020 15:20:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:5591:: with SMTP id y17ls1781513ejp.5.gmail; Wed, 04
 Nov 2020 15:20:14 -0800 (PST)
X-Received: by 2002:a17:906:6d4:: with SMTP id v20mr460978ejb.500.1604532014030;
        Wed, 04 Nov 2020 15:20:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604532014; cv=none;
        d=google.com; s=arc-20160816;
        b=oOeEihP3z2gVJwgbAp8R7CbUIfA3wLYi6yFi5OJJCXUfTT2c5HVlMr80wAOSnU6Sbt
         ORaHNPypl1/EGBkwYvccTbRNOWUCYvt3Z0e/4g74I69hy3BCJrkvBNl9LcetzcUy4yC4
         vYTA7i5yyuRmhzNysEG33NPwVhQIx6m6/q9zdwVs81hGhPkRAebbz988wCx28otbtsgf
         aQvCxeqnQCtzNM1WMaZrodnTduVEEu6XwrMAJOLBetc4UyE9ZwkIKO75rvDS0VodkNSE
         MHjMChNiMOoVWdgKLHgkYwyV7pA4dveJu2TN1uE4C+ddr+atb09LC6Qw3hXCn1YWlIQE
         FYOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=k0rwmvWkh3wc2lbCLJgzaa11WuGN21taMrm4zUJORUQ=;
        b=Ph01lb/lv+XERGZF2I674tm9SC8k4gW3H1cFpGTAxrgOJwGOO5ad89WCiL/z+ufeCp
         NrGIWL7yVtOPWzQDQoHTi7BSj6nxI0zqRfa1ISMCkC6VVWb2KHPO9GkA6cCcTvzvVj/D
         9Nad6BHAHnvH9p76dT6p+3zSCVLzRFkMhhseNNuUW85VQ5lOnmeI3/npU8AV4Qo6FG7S
         NUZ3c3Y8MVBlBvxKSu9UI6gL1/IspaZZ9pVA0ofCB4hfD8vfPtTxiRxf+VcHLmIGismE
         CIlyVJ9HXBemwUa1L8HDvqPUFHIGNAu3kdPeWGZy+MxR7k/WlFsQF/uuwZ3jfV6xgVUC
         kAtg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uWjOaiCp;
       spf=pass (google.com: domain of 3ltejxwokcswivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3LTejXwoKCSwIVLZMgSVdTOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id g4si142271edt.2.2020.11.04.15.20.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:20:14 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ltejxwokcswivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id t11so43564wrv.10
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:20:14 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:4d05:: with SMTP id
 o5mr87270wmh.94.1604532013713; Wed, 04 Nov 2020 15:20:13 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:43 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <fc9e96c022a147120b67056525362abb43b2a0ce.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 28/43] arm64: mte: Reset the page tag in page->flags
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=uWjOaiCp;       spf=pass
 (google.com: domain of 3ltejxwokcswivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3LTejXwoKCSwIVLZMgSVdTOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--andreyknvl.bounces.google.com;
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
 arch/arm64/kernel/mte.c  | 1 +
 arch/arm64/mm/copypage.c | 1 +
 arch/arm64/mm/mteswap.c  | 1 +
 3 files changed, 3 insertions(+)

diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index 8f99c65837fd..06ba6c923ab7 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -34,6 +34,7 @@ static void mte_sync_page_tags(struct page *page, pte_t *ptep, bool check_swap)
 			return;
 	}
 
+	page_kasan_tag_reset(page);
 	mte_clear_page_tags(page_address(page));
 }
 
diff --git a/arch/arm64/mm/copypage.c b/arch/arm64/mm/copypage.c
index 70a71f38b6a9..348f4627da08 100644
--- a/arch/arm64/mm/copypage.c
+++ b/arch/arm64/mm/copypage.c
@@ -22,6 +22,7 @@ void copy_highpage(struct page *to, struct page *from)
 	copy_page(kto, kfrom);
 
 	if (system_supports_mte() && test_bit(PG_mte_tagged, &from->flags)) {
+		page_kasan_tag_reset(to);
 		set_bit(PG_mte_tagged, &to->flags);
 		mte_copy_page_tags(kto, kfrom);
 	}
diff --git a/arch/arm64/mm/mteswap.c b/arch/arm64/mm/mteswap.c
index c52c1847079c..0e7eccbe598a 100644
--- a/arch/arm64/mm/mteswap.c
+++ b/arch/arm64/mm/mteswap.c
@@ -53,6 +53,7 @@ bool mte_restore_tags(swp_entry_t entry, struct page *page)
 	if (!tags)
 		return false;
 
+	page_kasan_tag_reset(page);
 	mte_restore_page_tags(page_address(page), tags);
 
 	return true;
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fc9e96c022a147120b67056525362abb43b2a0ce.1604531793.git.andreyknvl%40google.com.
