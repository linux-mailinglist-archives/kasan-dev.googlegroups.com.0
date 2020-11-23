Return-Path: <kasan-dev+bncBDX4HWEMTEBRB6NN6D6QKGQEHW6MOBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6DE3F2C1553
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:09:29 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id u9sf106585wmb.2
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:09:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162169; cv=pass;
        d=google.com; s=arc-20160816;
        b=jrFslj8Xx+WFFbwNCojJ63FmS9jGtYo/oHMpvf1SlXJH+izV8OjaTixEa03MPrJQ9c
         0vhZZKrS/oMUxE+Hvd7mLSqkZkdbTtrC0MonDTDq2T02lbNGGoH40A8YG+NsVNYM2xRr
         h5QqZSyPDN0/WNdlG2V6nXiN1s+G7q98dU0FFHnKYAiyMrzPyEufdrn1omvYtQPHL07e
         xb2UJSPEjID0K2PXTj7/1pkZh5SOSIgnZh1HMFI1AAvEN41uQmWJQTAdPjWogrQ8MaMN
         U0JmqILWeF4mBbsP+woG/OW2FGZJ0JPEAYt7x2+gH7wF5uTYgRHZyu2y/6N+pWmZzGqN
         MvDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=kMFO5Oy0ZsxQcxZ3qbOmkBGG/U5jlYMmlDMkBBEbye4=;
        b=B3YykYtSMWRuYi5t65a9voGv6MHbYF/tERjdaiciPBLbzEYKfr+Q8MOlQyAdGASf8E
         O/h53CA7Jyt8RXkYPkgJLCTYbXjaaR1Aht0SCvfi8gc4tCxK46VlKn97EilfUitJTNvP
         YYZhzhNNLtP86b1FrbvYr53ceppfrXQb2dHbGvniV5GRefjIrGPTmbEm+0/05DEnm38m
         hCyRSmfM2DrhV+vL1RCu8tqOR1B9EseYFC8zA6Oyppf0v4S9gZe/4Xh+Pw8kC2uuen2q
         w2e8ZnIUfDY2b2k/+BaEfCBK5Zset1+fJuMS5RKMaCK57OcIUxXsn6WhIJ3wRG+b8wsK
         oolQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="QghR/2kE";
       spf=pass (google.com: domain of 3-ba8xwokcrs1e4i5pbemc7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3-Ba8XwoKCRs1E4I5PBEMC7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=kMFO5Oy0ZsxQcxZ3qbOmkBGG/U5jlYMmlDMkBBEbye4=;
        b=bU/MZI4q2gkVacWp/C9lX+/PSfgy44061/rgTzC7s0rEaw5XovaWg2ZxZilQ4aLpc+
         Gwg+4xuK0VdRx/x3J3eI1IDmsIC9TseYF8lOx3cjZfqC0nLH85RoSM5q624u7xrPxOWG
         0UiKiRbLxslYkcgLoxyhluyff3mA2nTKHWA1gbAr45p+UFc//+Uxst1BgKW16HTp1aPk
         zTZa9paCvqacIxbL1sg5lqNfRP3oP0j8Edu+U5n6JmHg2Os67rBafjK1I6yMhVQkxLmU
         /Y8DzFC6BVEzkA+dF8mAHLZP/LmOS2LGsk22h2n4TgA48CnMPhxchQJWpgGAV8tTo4HL
         ZOog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kMFO5Oy0ZsxQcxZ3qbOmkBGG/U5jlYMmlDMkBBEbye4=;
        b=G4lkBFCrZbf/AnHzABdT38JbNqkzf+DpH6QXAW87bZIp6PHpsY+ndVWto39W2SjrB1
         2/4pqSybP/Lk6YvQcn+OYjPrsVJfdTMfK5IFgIZrUY1nCK7L5nKyejCGPj4Lrg8Lwk/S
         ZjZSYjKdqGWWxXiiv97FZz/UTMo0V9ijb1mAKDWGzOWVTQjxG3py0x68RbW6QPEm/t4g
         K/Z1yQJV7ukGPcntw9FZphJ4ZmVeCdrlSN/YPjhYgbXT0fPsGL5/pJkdM6HFDkUHI7SW
         k4Ojro/DXxpxt3qkssKctVfrVIb+2DVipV2Udg1bpLm8Xg1fPbaBQzBmtqWVEOoCr/Ls
         Y3qg==
X-Gm-Message-State: AOAM530AMWHyliXt3dv++NHM7Vxc7X2njD3KQIrmGl5euVou02YKhGyk
	/6bPuua/bhxQwCKQNsNcw6A=
X-Google-Smtp-Source: ABdhPJwszkaKFcs3GPGZ6Bs6IUbIsXOHCI5/tETNF3UHvxxkTZIFAASxzqIhIBxosKjXBeUFkWYNng==
X-Received: by 2002:a5d:52c1:: with SMTP id r1mr1455547wrv.255.1606162169241;
        Mon, 23 Nov 2020 12:09:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:aa87:: with SMTP id h7ls8974877wrc.2.gmail; Mon, 23 Nov
 2020 12:09:28 -0800 (PST)
X-Received: by 2002:a5d:510d:: with SMTP id s13mr1358514wrt.380.1606162168500;
        Mon, 23 Nov 2020 12:09:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162168; cv=none;
        d=google.com; s=arc-20160816;
        b=03lMky9Xc9EWAb1uh5s3hqkwoDoE1o3K6p8qwOOvw3nOZaNZy5IGjww2tgs+j9NYFA
         96IuuJFj5gO+yB4uiBRLVC89fbxh0S4mYyeS3r6j6V4sfCsIWHIIKSHcrEn12/YBlB07
         zwCrA/Kh5fF/HYK/RT+tJ1qmDYKkbOX1Ccve7EoyVazClEzWu/x06Xn/S/dxVBF2Zv20
         XHpH+jvT9rgSqlNsAvW1xUNnP1I11EtTpxEHtBstqD9g9nZwVCSemZLWQmfcXExi1Qd3
         3z6lO1yz/7geZvYJMIrLMHgKVj4+Xinj/sOJcLdvmrTRJN2sleNnG/L94ZdCKz8yq1AN
         ZmtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=utlsD1mw0rorOhWh+9V4hpftFWJXg/4VW/2wSqx9Lr0=;
        b=XcntSfbTpWBeUgEHKF36PxkwvXaHpwRNEJOzg9a+IQ0wDI/AYg9jsd1m4Ra++ev+nA
         uslK9h5OVBGfA4i/u1yO1aomT75NCE0EU8hn+wIxswu35KNZX35NZeKxFajS55iDFX11
         XPj/82bORBc5mDh4yKkBjrYuMn2EVQ2lGLE4KnK/+Tl3l9lF+9gIea1t0EmKPOd8aZNP
         oII31UNAunHTLsRWAI4/dPJPSiPxxng2vU/y1v7pbZW+pMETG8hLk4y1vyeNcrEeapkn
         lYlWG0Yf0fM6SpXCEIUBDduPoaLUn9AKV+Mwi5EKsBTD5GperVlsHpNuNB89PbG5Wf2p
         KK/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="QghR/2kE";
       spf=pass (google.com: domain of 3-ba8xwokcrs1e4i5pbemc7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3-Ba8XwoKCRs1E4I5PBEMC7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 7si30950wmg.4.2020.11.23.12.09.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:09:28 -0800 (PST)
Received-SPF: pass (google.com: domain of 3-ba8xwokcrs1e4i5pbemc7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id a134so97128wmd.8
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:09:28 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:c84a:: with SMTP id
 c10mr612311wml.44.1606162168044; Mon, 23 Nov 2020 12:09:28 -0800 (PST)
Date: Mon, 23 Nov 2020 21:07:50 +0100
In-Reply-To: <cover.1606161801.git.andreyknvl@google.com>
Message-Id: <9073d4e973747a6f78d5bdd7ebe17f290d087096.1606161801.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606161801.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v11 26/42] arm64: mte: Reset the page tag in page->flags
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
 header.i=@google.com header.s=20161025 header.b="QghR/2kE";       spf=pass
 (google.com: domain of 3-ba8xwokcrs1e4i5pbemc7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3-Ba8XwoKCRs1E4I5PBEMC7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--andreyknvl.bounces.google.com;
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
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
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
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9073d4e973747a6f78d5bdd7ebe17f290d087096.1606161801.git.andreyknvl%40google.com.
