Return-Path: <kasan-dev+bncBDX4HWEMTEBRBV5O5T6AKGQEWLYFDWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3c.google.com (mail-vk1-xa3c.google.com [IPv6:2607:f8b0:4864:20::a3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1310729F4DF
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 20:26:16 +0100 (CET)
Received: by mail-vk1-xa3c.google.com with SMTP id j129sf1081875vkb.15
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 12:26:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603999575; cv=pass;
        d=google.com; s=arc-20160816;
        b=GkxWEsUSw6RTtoPtfjXh5uKnyroo+9JigTfdRFNlBYuC130FbtaVpm41VSilRDx/yJ
         bsh+VX1Ptu4aw/kaqcZmmB8SM6TePtH01F2FhJLsaClYr6qJzPY/lEAfX631AIJozR2X
         87sjGbb1fOeyZIpTJGRh3FZGeLP5zHU8IBYPrZjvMKyXx1QuCCzyCs1+Y8Jzra1q5RhO
         GFMOPQNeHcZVV9n2pf6Nofm5mETmT/d8Zke1MbSqw0Ck23e6+HwoLQyRcKRXYuFvWfAr
         fh7RvwqY95zv3yvaR7CL45X8c6G+p+u5zeYZZl3ba3eLn28HHP/YpPNmqJ2RBwGpd0cc
         pI1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=/OUt3P/DpnuHjyGViFfQRkdwFT5ZRkRk/3PsqbZ0erk=;
        b=J1ALzuLQO0SsyuiDPLUerTfijEZQvQHjRKNPInPrC78CUN1CGyurRckZBNMJWz0KDO
         qEjbUwTZM/7FWDmSAKo+E1i4nDYwvLxMIk2gmhiS80yyAjlMiSV7rXMvkVYIfzNYi/O/
         o/huAakt89I/CCVUvytcf3cniWjcC0U8ItbIZqYXrgL900YYPumtWYIyBWj5tvrL73Sh
         iZskBM/EU+uhoKcw2CjQEGPEgogq8z3VhJ9fDH6Da9D0nRaFrY/RDO2n1qIUSopCHe0a
         IVfgioy8MJHhPpvK3EZ2LkDZ89vook6i/uHrCNXJoH6Pq3qCdvAr2/Z7C3vaV5Cp5lJT
         WuaA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NVC+Ua+z;
       spf=pass (google.com: domain of 3vhebxwokcfmviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3VhebXwoKCfMViYmZtfiqgbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=/OUt3P/DpnuHjyGViFfQRkdwFT5ZRkRk/3PsqbZ0erk=;
        b=H0Y9yV95Zw3EiAx5OF4TnH8gZ9qxA3xp1vud7XSm+EfhjErHg75HpZKY/q4NPZBNmS
         g1I3VD7LRzkWgQ4jGxF3upIz9des+DbVi6/6ngGh/AMOFAVeIiHEoGeL/9JsIlDPHzas
         KLF5RERvOMtnGUCf1KUJuHOhsvchtOUGbx8VdnLamomrfBbxmNmXG/RDaaspXudvZi3k
         ZIAL88zxIZxlDLhfsTGThDWAOsCO64XQeDGo/eo3nSBpkhlvphzEcJrfUqH3NgLPVr4E
         TfpfMbzA5ECbgyV76bpduiqdrnXbTFUfL94YwxJFWmy2cVe14dcZqpzjIRO4JgdxQLZL
         CjPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/OUt3P/DpnuHjyGViFfQRkdwFT5ZRkRk/3PsqbZ0erk=;
        b=fjklj1IJvJZjbHX75IgemtQqLZd1N7HCUunSwcA+vrAy8cCyQaX1HcOMdenTnfmQFK
         6xQaQgtJ4srx2TEKpQHAZX4NEQMRhe2VAnMB7Yf1k+qpFPGTGhr7ryg78F3oCjyaFD2R
         upFMAx56s+xp7Q/qlYB8YVtYXOhFyl7dkv8EIQHIVRiBkgz/WCWP0W4YfvCfz1CZCHiP
         OScSvT7M8A8sc+Hzyeyl0xCwowpyjnqLqMbZcdCJuwGBi6iLIdLE+N3LIJJ3yEmvJRFF
         qtm2pLyHR3wvy4W3rJPapL0+ocyA3zd42VuJN6eJsbdxDys1BHTD+N7fXHTH0tkY4aFg
         ixDg==
X-Gm-Message-State: AOAM530Nbkw8ExBS8AeYdGhpgMAIzk/slq8fmawy6qOPd9BRr0qqaA6L
	1G6u2XcZ6hBr6enCW2Uc3jY=
X-Google-Smtp-Source: ABdhPJy5YG/CAlAtFALdbjdpUt9Hcq9QJkFp7if0THp+ZfkFLE9LNzuxYhIjgxj4OJFch42rTNKZCg==
X-Received: by 2002:a1f:3f4d:: with SMTP id m74mr4570316vka.12.1603999575146;
        Thu, 29 Oct 2020 12:26:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e210:: with SMTP id g16ls377974vsa.0.gmail; Thu, 29 Oct
 2020 12:26:14 -0700 (PDT)
X-Received: by 2002:a67:1e02:: with SMTP id e2mr5202771vse.40.1603999574674;
        Thu, 29 Oct 2020 12:26:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603999574; cv=none;
        d=google.com; s=arc-20160816;
        b=Py0jvT9lUvQ+SbUT5ABX9If+ei4ZRhEQPiI5eQgC8DAU4opSf7hS9D4J7hdDiSBVXj
         xnKRsqU0e+P3FeIhMxoWOwyD1KAai04CTY6J4OHxW+Jw3rZyqTZaRuuf83jCBxHZWIGg
         jlq8LNKCOdyd7wAz09Gx5ePdSR9pvAiMXkTKa1SCY4fRS1hE+LKtsuX/qO+uOb0xUh1I
         rnYVzHqNk+Z3KiO8R4OukhMuAXLYojvdQQm1Jg//A4vqHaTkbA2imlJv4XofN8ZwCdp/
         xkd/VS/Wj21EQdJCHrJ01Rn1Jy87aRtWltaMt0dtgDn/K0pP3AXTs4xlfg8enKJhvEcl
         b0fQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=k0rwmvWkh3wc2lbCLJgzaa11WuGN21taMrm4zUJORUQ=;
        b=IvECNiJtbeJqSqrs8FTBY/YW9lItDYaKggNzNx/nlg2F/SNWUvYldMjV7WtBVBXJ2f
         WnZ/QgJ8psHPz/4NktyOe2rDDRHSJwAyBihAARnqNo0gD54h225OVKd2+eu1tzZMp/6J
         nd6HowDf2n8DJvESqilonkV3/oqwLp+G7zN4l13Ka+l3nvkjozWV2GS9Om+pHUoRU6i8
         h4PWlc1gVfetYK+9ii+nDyU6XA5sbs15z23QfVvr/mNIy6dShWJDEJXYzJwt4zbYcTlQ
         HSaTmu1WT7rlFjAn1WleIN9NygGsFdxTvWLhuTfU1UW6ETGWe+LOxOtpeP7u6bhmZkgb
         zh9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NVC+Ua+z;
       spf=pass (google.com: domain of 3vhebxwokcfmviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3VhebXwoKCfMViYmZtfiqgbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id s3si230253uap.0.2020.10.29.12.26.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 12:26:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3vhebxwokcfmviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id x34so2389400qvx.7
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 12:26:14 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:e308:: with SMTP id
 s8mr6182701qvl.10.1603999574230; Thu, 29 Oct 2020 12:26:14 -0700 (PDT)
Date: Thu, 29 Oct 2020 20:25:24 +0100
In-Reply-To: <cover.1603999489.git.andreyknvl@google.com>
Message-Id: <d31459cf316fff73874058b8753d2385a137e956.1603999489.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603999489.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 03/40] arm64: mte: Reset the page tag in page->flags
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=NVC+Ua+z;       spf=pass
 (google.com: domain of 3vhebxwokcfmviymztfiqgbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3VhebXwoKCfMViYmZtfiqgbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--andreyknvl.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d31459cf316fff73874058b8753d2385a137e956.1603999489.git.andreyknvl%40google.com.
