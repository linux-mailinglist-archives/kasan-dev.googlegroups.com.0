Return-Path: <kasan-dev+bncBDX4HWEMTEBRB45R2GAAMGQEW5WKYPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id ED36F308CC0
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 19:50:28 +0100 (CET)
Received: by mail-oi1-x238.google.com with SMTP id b11sf4445807oib.23
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 10:50:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611946227; cv=pass;
        d=google.com; s=arc-20160816;
        b=R0uN+/O2E061JFvoWT6rfRlNrL+gSLjT1OlqY0wpLzQP9yQCYXr9pfK50yQ+kqV74e
         wrUfpGio2QBDLRh+noa18Ymf7hmbd6W3n9qSXMhx2A72uncPAQOzSzdlFBY0rpx6poIr
         oR2jGU9uREw9WuFXSv7Bt2QA1YwY7vgJudCSMHzViRIfeWuwArKCEzkGm+LQmWLjHqzA
         SsZZDXHd8KwGfIo1C6rOeC7XR7ehdHcpVUlijjIa+x9j2JyA52HHu7pbjZaOdAxCensj
         Ej23tCXEUihZDCxIH04Hyejn/6ea1YFaP2nanAC6gA9VUFz6Bo1y8AD+B/PBMJCDyGZw
         F4Lg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=ckLaaYTfGIFGnEUlxIvDHKQpW163tafV3qjRWgKoyp8=;
        b=W4ci193OJ7iNiLG1oVhPCEywhFzPJtFG1FUEiVpKAhMk3uGTIBv6cDflOX+K5RgFTs
         Mdva+0OPxZxMPBuDZOYGQg2d/e8StBvRsMzuY2ybZjs/F9ZKyTEc402dWKxcBcpDUuzg
         S3O51RLv4ybTalyB1qA0Ras2nuao8mC5Py5n4xoZ+KoVn4OaS6B4quRlZ7qmrt3NrtrD
         lIEzYFxegyauMlifmO5yV87J2M/KXOPVc6Xp1Ns0t5Vy9i/Ti8e6SXLG1Psy1q8MuE/V
         zF++1aaeBKu9XP5g8qGo1TQR5MZeu9IVKU8ojBsgFMT1REDhfxoG0TxQ6i5ZyCfVAIYY
         DgrQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=p0cuGC6u;
       spf=pass (google.com: domain of 38lguyaokcfsdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=38lgUYAoKCfsdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ckLaaYTfGIFGnEUlxIvDHKQpW163tafV3qjRWgKoyp8=;
        b=iqblgU5Xvu3uanOAv/J1SxMj5bKHiqXH8ihvOSeqewaejV0JkUNAQzlGu6D+HvXyQ+
         r8nwVXRGNWjpBDpb4h/R6a4brz/9gLpeALsHOjsgViI5WAK5/tiw0EM7d2KzcPLZkIwT
         N2pg9Vw/oKQhZL13IV0B/gj2WiQ6UWHJXVzqR0E5s5F1LwftRBNPmVOL5MiN+lckFJIz
         iMoSXjuucJmz1HxgG9i+BraFTEJQ/8Sqf9Je6iKu9Ehuk7RcXN7dk9KrsZ42zXhSTg/q
         xKvm5ohVU5wyWIeDCC/maOUonnjoHytxTVlwQKMBmUWU2rF1hSrnvhS12uUTPVPdhSDT
         KoXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ckLaaYTfGIFGnEUlxIvDHKQpW163tafV3qjRWgKoyp8=;
        b=c1lA63fpDUohUxHa7P2AFx6kluU9jQtcHz59ONN6Zz2a1FJEP2fTiG9w7t7g89Ha+4
         cPPJXNeXrAp/rQDHf5hOQJ+cHDdHrffSGq448QY1I1uClt0LqM/hlgELWGDZqWFGkbCG
         Sf9G2nGuNs7PalPQvWMI71RpGJOrZIOsPwrtCyWRZQWOaBnFFZ09XcNfO3VcaYqSSymc
         9VxrAYfn3pT1/e6Xabot9YDKxRNglElhu6uSYC9+JEId2k6ovZrt/gCAACkE09j7ClSm
         tmTj318sJfeNGRdEfh18uNfYwK3c//skQ2cZ0ch++46FVwuDjnfhPUZ23vcXFRyPtEAD
         nljQ==
X-Gm-Message-State: AOAM530F/p+sI3T9wHdj+6eK4u5JTkjMYsEyxzogdXY9o0dBDqVuxo2P
	szNn6pDory47fXDVP5338L0=
X-Google-Smtp-Source: ABdhPJx3AsOIIT7Z93bb29UQaN7i8qwdTzj7Ls4526HVgnnJoJp3EkpKQDdNr7nS7efmsl0bvdzgyw==
X-Received: by 2002:a9d:7452:: with SMTP id p18mr3783533otk.49.1611946227809;
        Fri, 29 Jan 2021 10:50:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:14a:: with SMTP id j10ls2374298otp.4.gmail; Fri, 29
 Jan 2021 10:50:27 -0800 (PST)
X-Received: by 2002:a9d:639a:: with SMTP id w26mr3670032otk.201.1611946227379;
        Fri, 29 Jan 2021 10:50:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611946227; cv=none;
        d=google.com; s=arc-20160816;
        b=vg5mouOVsha41+mvtILNDRsBxZ+uilANuyAO3zgMlQG1ERs0LQPWB76/GByHMRefBg
         FxgW7SyLzkvpRXQgOMJWz32chhHtwP8jg43E87qbHLC3Ij8284pDykcChRTJXqP4GOjr
         HWzn7tYtyNeCEo6GiawkEQr3YqE0aEOVhPQhLqtjvtTirAQDPw1ueAwSH+8Gqsa+ce10
         fsGlnhvB9kNjT1wRchEYHKGZx32feBFvMs4BvfXiiVPd+Ee90EPeqFQvWRre9O9OX77o
         pfLpA2+g/B+O0wZBrEVCXPUYJKc317YuOLHJgZmeIApdEOEoTY7Rl0wzz2tyRb7c1tb9
         8brg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=edlz3XbCYDia7c2gqKzN5FK6RAL7HO75a2b9pwPLi9o=;
        b=hSN9u02ui0RLGrz+6NvV4Ia6DupnweMh/xo4Tn7VzmSspLc8LS628+xNu0Ct6yFRmw
         lEIJa08aA9u/602Ns2Laz4MiD10XwpeSv5GrTjPIaslKEtsi0L/EgD29ygcLeG18dg0M
         Z3+Py/2w7QNvPgnNT7A8SIHHTQIZV47gFbVqZUP/2ddEgL5n8WK/QoOA64IAxLos6TWO
         s0J2bWREyVOJA9S7iDdjU9QGtHJS6EhswYNPAxjmdXhkNSsMDH0X0Ehl35gBhMciu6Y4
         WehWsBh5bS2pQXI3+fTldthE13ZKoml5t92KKSrDLPcdQm0oJ0kRzMFMjB0fvcEaGsXl
         7VPA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=p0cuGC6u;
       spf=pass (google.com: domain of 38lguyaokcfsdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=38lgUYAoKCfsdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id f197si560427oob.2.2021.01.29.10.50.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Jan 2021 10:50:27 -0800 (PST)
Received-SPF: pass (google.com: domain of 38lguyaokcfsdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id m9so7671325qka.22
        for <kasan-dev@googlegroups.com>; Fri, 29 Jan 2021 10:50:27 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:b59a:: with SMTP id
 g26mr5014944qve.26.1611946226898; Fri, 29 Jan 2021 10:50:26 -0800 (PST)
Date: Fri, 29 Jan 2021 19:50:22 +0100
Message-Id: <9dc196006921b191d25d10f6e611316db7da2efc.1611946152.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH mm] kasan: untag addresses for KFENCE
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=p0cuGC6u;       spf=pass
 (google.com: domain of 38lguyaokcfsdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=38lgUYAoKCfsdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
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

KFENCE annotations operate on untagged addresses.

Untag addresses in KASAN runtime where they might be tagged.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

This can be squashed into:

revert kasan-remove-kfence-leftovers
kfence, kasan: make KFENCE compatible with KASA

---
 mm/kasan/common.c |  2 +-
 mm/kasan/kasan.h  | 12 +++++++++---
 2 files changed, 10 insertions(+), 4 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index a390fae9d64b..fe852f3cfa42 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -416,7 +416,7 @@ static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
 	if (unlikely(object == NULL))
 		return NULL;
 
-	if (is_kfence_address(object))
+	if (is_kfence_address(kasan_reset_tag(object)))
 		return (void *)object;
 
 	redzone_start = round_up((unsigned long)(object + size),
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 11c6e3650468..4fb8106f8e31 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -320,22 +320,28 @@ static inline u8 kasan_random_tag(void) { return 0; }
 
 static inline void kasan_poison(const void *address, size_t size, u8 value)
 {
+	address = kasan_reset_tag(address);
+
 	/* Skip KFENCE memory if called explicitly outside of sl*b. */
 	if (is_kfence_address(address))
 		return;
 
-	hw_set_mem_tag_range(kasan_reset_tag(address),
+	hw_set_mem_tag_range((void *)address,
 			round_up(size, KASAN_GRANULE_SIZE), value);
 }
 
 static inline void kasan_unpoison(const void *address, size_t size)
 {
+	u8 tag = get_tag(address);
+
+	address = kasan_reset_tag(address);
+
 	/* Skip KFENCE memory if called explicitly outside of sl*b. */
 	if (is_kfence_address(address))
 		return;
 
-	hw_set_mem_tag_range(kasan_reset_tag(address),
-			round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
+	hw_set_mem_tag_range((void *)address,
+			round_up(size, KASAN_GRANULE_SIZE), tag);
 }
 
 static inline bool kasan_byte_accessible(const void *addr)
-- 
2.30.0.365.g02bc693789-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9dc196006921b191d25d10f6e611316db7da2efc.1611946152.git.andreyknvl%40google.com.
