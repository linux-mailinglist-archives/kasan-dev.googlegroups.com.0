Return-Path: <kasan-dev+bncBDX4HWEMTEBRBBUBSP6AKGQE6PVZVYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 160ED28C30A
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 22:46:00 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id w16sf4591325ply.15
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 13:46:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602535559; cv=pass;
        d=google.com; s=arc-20160816;
        b=OhG7YhFef6pdSx5VspxT2+WyMdKWmGYxzAJjTfx8iUC9Gf/y34BmmVzqSAyXVe7Hsm
         60C9Lt6bAgx/A2QY3rdmgce8G5Vs0BGPpBgkfMERAVrBeNYyQYL4lTzeuD0EWZYXUeg5
         BcFGAAbu54Auq33uZl6hbT24CIJMqTIWLDmohrK/yxjHEVELBlkMzza3U/94NkpvMpvw
         VpKSwmEgPNJVTPtvhBUhtDADetOj70B/CaZ7Y309icFqe+1R7V1iVX2KbGUwIYFXtAAe
         cL03uybyj1XqtEzuxP4xEevBPRmw92upTxT6QkFmlNgDWUWb+4ZiJuOy1pWkyCaYIOoa
         Gh0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=7xo7nuF/1L+6id4LQxtUmHv/U4j3aP3bxl34zVbgoiY=;
        b=Lkd2N6aKByTLwbkUPmIIEqCfPRsXhP7/+kr5FP8kOT6OsTbCSAOJecmcegNUeuvxxL
         H7OEQ1zndUa6b6EMsvMIVKdQHSY8ir656VOJgdjOTaC8DCusmY0pF5XEp6KMHO5AgnZ7
         c22RCgUz8RCYZR9Pr+THCW844fKEcVig2SLN2RvBCIulTpmnex/5ju/cLH6556HBImrb
         yolVCHOJz77Ipa6W0soFCCaGdAJhvukhzjdkoE5yalI1TNAyuyWU1C+lgvb4wNcDq1Qn
         4CTILohEmiHcjl8x5vJzuoeP/kPVbAP4+DiyvAJrcNUtXyZOuSBfxjz/iImD+P1PtvMD
         cHHQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sz1Ze07r;
       spf=pass (google.com: domain of 3hccexwokcrw2f5j6qcfnd8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3hcCEXwoKCRw2F5J6QCFND8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=7xo7nuF/1L+6id4LQxtUmHv/U4j3aP3bxl34zVbgoiY=;
        b=QFxx7WgjABwYlwIczF9Y+akimo9PqRw1Q30COGEd5jFDVg/bD8uNrc/z4T/m0Ru08u
         7UZXpvR6m64GUhaQm4xo2l0ftxQ6YMN+VPP2W2rSLJwPzTKqoE2jxp3MTmF1mirPISI9
         omXEoVi3dVJkTbK5+g9N7M8bVvm3gAIdFPs39n+zYPTIO9fp++0qzeVMKbNpAUy3BEcd
         r5c53vU7+SwHeseMhX92RuqwlFLnYLIIsqbPPqwPkipHQPLNKtpCFYlJRQb9Aj+C+siw
         VivA1tfAZd9Zric6tXqTuOzSZtRQvXL46wk4OTuso+Yr7HwjycGsvck1Q6Mfh9UTjWNr
         qjlw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7xo7nuF/1L+6id4LQxtUmHv/U4j3aP3bxl34zVbgoiY=;
        b=uIERHIVdUlbeYr/SIoJ6Q7L0LRD9z3hXaXM5+W2JEZ5i/GY7VGh4Zbxfhys9UKS1TM
         GKZpBHoTjxaLeCNF/H/KbaGqjx6xsVpJNpe4JWI/7Ah9c2mEiao4Mqny4Bm1nnOCgbVB
         6PGKDLDNOszQX/1VPimbGG5VvlsimDavVJwWTY2Zj4KY15LG/5QMY0Ul8BPG5Qs0IBqk
         IboUpZcXSyfw12YONosuOZ25Z6CcrTWGebUfP1igKZUBYfp6qI40UGsNclXoHAHygw8k
         KNfIuP9rX78QhBwaYszChx+ncRp/K11Bu/kzdfMvQiatE3w2NG22569Xg0BRBbTtVUtW
         VKBA==
X-Gm-Message-State: AOAM531o1LkXwt+0IBiIJC5KxvVqUeS9AGs9Ee4YJBYwPN5wKAzyR/Fh
	HeqrOUBOjW4zaDi/gUD/eIk=
X-Google-Smtp-Source: ABdhPJxLdrS/eazejwHCkn1ureF4wYjHltSyixrWebqS0JNU1jgTAwfWP/x1I/BcHgkH5xUK6Rcd4g==
X-Received: by 2002:a63:1906:: with SMTP id z6mr4848501pgl.286.1602535558832;
        Mon, 12 Oct 2020 13:45:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:123:: with SMTP id 32ls8100592plb.1.gmail; Mon, 12
 Oct 2020 13:45:58 -0700 (PDT)
X-Received: by 2002:a17:90a:6b0d:: with SMTP id v13mr22072858pjj.206.1602535558341;
        Mon, 12 Oct 2020 13:45:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602535558; cv=none;
        d=google.com; s=arc-20160816;
        b=s4k69EO+g41DAW4ubumrRniSuI0pDcAgu6HcBAcQAdL5mkYxA1VSgf/B1H4Pr5/MOh
         77lxBFjLIFPNrXM3KAc28YfgsWb4qDJ5ZZddOJmRlQsMJZL12jOKbXQw6ErU5G/UkjVE
         LhuOAOa9T4Zn0eeFTBlE4ChJbdu/HnMsXsAG3NJ5qKzCIXBDLpT8gEy0M743u+sPVjK8
         FBT8U8Ay2M6qcT05FH/U+W0FyP5De4mZuJZvyNPeN2c9RzfHZGAWD0aw7OOv72ayfkEX
         GXmZtnqU/YgaWT5c/oHrqmqa9OsN83TKiby71TWe61FshtYaTAIDq/Z18yJH7d/7JrwW
         EJ1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=uq0E0gUhwkpPRwh8MWqD4WeS1X/FQmBRJFO+B9Xt1FE=;
        b=rlyz4RuSb4N327DoImyVIcoWqjw/yFZhiKcWeNmGGxBtSf+L35kXwo7uD5L40j/yj7
         cZeczGP8dE0pgpueAKH2CDHtLPZaUEkyl04eoQqB4VYgsGYgb3NvaMqp0JJYRF9i9kXH
         Tk+gp4pbo/wdnXDP2gX01lLvVs7+A4Gy86Hq/BVjgo0tcP0Sz+r7J+btfHty2Ow5wGt4
         /h5Jw235nlnjKmiU1dfKe26og1gShf+6RZLf918RcH4winZlVTM08CzSONyAUCN7zMhp
         mT0xAP4J4kZ2nflcvEvuqrJ3nFr7AsKjVrI3vMFblGy3Y7KS5VewD+bgcUAlyfBEvQLH
         4K8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sz1Ze07r;
       spf=pass (google.com: domain of 3hccexwokcrw2f5j6qcfnd8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3hcCEXwoKCRw2F5J6QCFND8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id n8si1286429pfd.4.2020.10.12.13.45.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Oct 2020 13:45:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3hccexwokcrw2f5j6qcfnd8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id q15so13476042qkq.23
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 13:45:58 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:174f:: with SMTP id
 dc15mr25993005qvb.26.1602535557397; Mon, 12 Oct 2020 13:45:57 -0700 (PDT)
Date: Mon, 12 Oct 2020 22:44:33 +0200
In-Reply-To: <cover.1602535397.git.andreyknvl@google.com>
Message-Id: <4e28900397138acc0ea8a99cdff234ba68da518b.1602535397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602535397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH v5 27/40] kasan: kasan_non_canonical_hook only for software modes
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
 header.i=@google.com header.s=20161025 header.b=sz1Ze07r;       spf=pass
 (google.com: domain of 3hccexwokcrw2f5j6qcfnd8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3hcCEXwoKCRw2F5J6QCFND8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--andreyknvl.bounces.google.com;
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

This is a preparatory commit for the upcoming addition of a new hardware
tag-based (MTE-based) KASAN mode.

kasan_non_canonical_hook() is only applicable to KASAN modes that use
shadow memory, and won't be needed for hardware tag-based KASAN.

No functional changes for software modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: Icc9f5ef100a2e86f3a4214a0c3131a68266181b2
---
 mm/kasan/report.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 9e4d539d62f4..67aa30b45805 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -371,7 +371,8 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
 	return ret;
 }
 
-#ifdef CONFIG_KASAN_INLINE
+#if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && \
+	defined(CONFIG_KASAN_INLINE)
 /*
  * With CONFIG_KASAN_INLINE, accesses to bogus pointers (outside the high
  * canonical half of the address space) cause out-of-bounds shadow memory reads
-- 
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4e28900397138acc0ea8a99cdff234ba68da518b.1602535397.git.andreyknvl%40google.com.
