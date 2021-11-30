Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUM5TCGQMGQEULXCB6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 21F9B4632D0
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 12:45:22 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 187-20020a1c02c4000000b003335872db8dsf10296659wmc.2
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 03:45:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638272722; cv=pass;
        d=google.com; s=arc-20160816;
        b=XdhUJPL+eUDhyhLhDbbLk+V9TBkMIfh7hMpaFzgQo2uwTEAqvxe3opDaElueC6pbbc
         1cxwz5dQelIFmpLiF/NXLYcOpnqCMzHt2OTz7hCTKtbxHmRebar/yK6qP5zQdDrUnvrQ
         WFP09hhbCQaIq8638NMx91xlALh6dStq6dwSpKm7KSsMXV2+/xqK9ygRd7u5WbbTzuPc
         SdIqBueCv+WD8ecJu+ePxhpCNHbPlCpmPpdhEvFwGkSnzpf3GEur4WJ2q5o0PYf8oanf
         kHdBoXS5MzhLngKJINKfEu3kKZOpVineJ68Av3qg5Ywo11fXa75AgH2E5rxp0zCGabrW
         GsIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Uz/kPDqSiOrKMtmiixt0edz3d4L3mYNwaTNwP/yj1RY=;
        b=KKFlbhRHOvCNbJtNv3XCBHPrOkQ/0v5XIgeAY/PI/k7C1e/6ia/uga3SSXCeaoYHIS
         VqhJu3FKl5+Sy741Lt6vH/cnOHU7yDM1+6XNDKQhKuDCxlFPrq3dIdIshjbY0EhDK3TC
         Df7SWr4B7hF7dRnYK56nm3OnX7i04gF6V5Z1oEY7bQXcf1Zx0Ojx747poC7b6XNUXcjd
         Y6kzXb8QrTvUJcgpuJveqPN0d6rWhaQxOVaas43vnA3JET3ZPAePM8l65j3v3K5D3KL5
         1YzeMG0RWA1Kw09dceNvrUMkwJA8DYbjwXpQSH+WmdTOmIkhZkdoT1nsIvV6BXv121CT
         LXUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BIT8VeP6;
       spf=pass (google.com: domain of 30a6myqukczk7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=30A6mYQUKCZk7EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Uz/kPDqSiOrKMtmiixt0edz3d4L3mYNwaTNwP/yj1RY=;
        b=CaBE3MqP/OMzV5OCbrbuNOSaaTru7Zq2qkXR0MaL62QAknSLa1ftHhrvUCObLe9+ZU
         J4Sxvvtqveof0KP2Y1wOCKxMiMUENpD6Vat1DConq4pt05WA2XTnNOFIx+zbGa0HT/J+
         ML0VtQGk8skxHyCDlQ1xUz3I/rrUivvW3Smgf5CfS6gMDK3ZD7qot3uRIk550wn+w6TK
         lzomU4LvFCmx0fRAV3EIVXjQRsWM0NID4A3CtZbKE8qIxajYKuyI/cBpYVW3UQHOVwOP
         OTuXdnaElJ36UhINauEWMctSKv3rVsDAuP/uQLXPrr3O+0zY7gMGgphhCb4hCXXiEoKY
         swLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Uz/kPDqSiOrKMtmiixt0edz3d4L3mYNwaTNwP/yj1RY=;
        b=LNLCbQIVBLAVi2wq1cv/9XodpYwqwJcQWR6WZM70NIuBtHCeDQrAbyZ1SWDiBYXvdC
         qT80mbV+G8tozIVsUenhMTOlJNeDdMrIFaytQ6AuqIJ/AGFXidl9/AeCYDMGUrJxEdbT
         xUMwAacph1brZZFRJFPzSXkySM3jTPVfsj6Ujm2VACg2/o0Y1ozOU0P3DkgIyzW/RBIf
         lZIynwrep+EfuUIaGtm13sL7Ue84GhzkXlrzRTpNJzQ7YSuz9+Z8xgTja0Vl5QF2dRgE
         w6rZ3KdcdVElQMPctuezWlRaDpWZbvGS0KpEboYByEdE2v9qg/Or9bps7qmbzLhhnlQb
         yyRQ==
X-Gm-Message-State: AOAM53119Q0Utn5Mm9xEn3hJw4Wb/aMCyg+hLQ1Nf7DxsPwXjyXXct3I
	VYg8tLzRVJEoNar82eJX4to=
X-Google-Smtp-Source: ABdhPJxZG9zAL6+1EdyXA1sYwXCJ/EHomgi+YG2ssBnB3hDCmfRlspLVUL5TuCXwWOvmqGZAWVwZYg==
X-Received: by 2002:a05:600c:4149:: with SMTP id h9mr4403120wmm.100.1638272721905;
        Tue, 30 Nov 2021 03:45:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4f48:: with SMTP id m8ls115786wmq.0.experimental-gmail;
 Tue, 30 Nov 2021 03:45:20 -0800 (PST)
X-Received: by 2002:a05:600c:500d:: with SMTP id n13mr4327807wmr.174.1638272720748;
        Tue, 30 Nov 2021 03:45:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638272720; cv=none;
        d=google.com; s=arc-20160816;
        b=J0yCiqmX6yxBW5xHg7h64+CXGcWnE3Q5vryw8AKyB7c7EJO68KAi5kZpSDpk8jtSp8
         8334U00QVedPjg+vRvNwxWfouFvnYEzPFGLlmgFEzmFHL8ogdELbeASsmeWtEK4wKj0q
         YyMnjnowIeA8h902b+BxPnuTa9YGGQ3R3WwOiBJ+w7sWsc0AOK/Q6/L+YM/pu4rXaMPZ
         tPBbFhbeEPLiW4VSjjCNPSqa4bVdUgq5DykHAqJ2gpjxtglpIKtNSVxniMF0RVz4K2Ze
         WloOE6XRI8N6QpkaIbwTROZEnzXlgHiG/4VjTks16iO0+fGNLCgpD831i3JPqpxyXXVf
         oe3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=j+xGmYJ7a6naxsOgId4/Y5ehX22eJTAnRqZAmnKJeqk=;
        b=a7eJDgt6I3qxsVBBY9DZUbJaI50cYfdPyijyt2Cf0S5VAM3vcAVKVLvkKFF4+iu9yd
         N81CubZ4gYxh6921d1UUTnW247bQbg/wk7RuFlriu85GaIVlN+KdtFkWjLfrdyfQ0Ctg
         ac3eTbh7maryRkSkGFqcYrCwxc/uPNFYD3HEJFmikFZDYnAxxmcy1BPM1uWXb+HjeWK1
         BVWQL0lJSlmKQZW+PV8CbZRco8xTrGaIH6py6H7lu53sGzayrraOuNjzXEgI0vTgFDvT
         rsrzjImZJWa91e3sExdMD5x+VtRXbBt2TophSJYDTEqHtyqQ6aGSXrbbRJJBAWXtG1PF
         JXzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BIT8VeP6;
       spf=pass (google.com: domain of 30a6myqukczk7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=30A6mYQUKCZk7EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id r6si1120471wrj.2.2021.11.30.03.45.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Nov 2021 03:45:20 -0800 (PST)
Received-SPF: pass (google.com: domain of 30a6myqukczk7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id p3-20020a056000018300b00186b195d4ddso3515860wrx.15
        for <kasan-dev@googlegroups.com>; Tue, 30 Nov 2021 03:45:20 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:86b7:11e9:7797:99f0])
 (user=elver job=sendgmr) by 2002:a05:600c:1d1b:: with SMTP id
 l27mr624069wms.1.1638272720147; Tue, 30 Nov 2021 03:45:20 -0800 (PST)
Date: Tue, 30 Nov 2021 12:44:15 +0100
In-Reply-To: <20211130114433.2580590-1-elver@google.com>
Message-Id: <20211130114433.2580590-8-elver@google.com>
Mime-Version: 1.0
References: <20211130114433.2580590-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v3 07/25] kcsan: Call scoped accesses reordered in reports
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
	x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=BIT8VeP6;       spf=pass
 (google.com: domain of 30a6myqukczk7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=30A6mYQUKCZk7EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

The scoping of an access simply denotes the scope in which it may be
reordered. However, in reports, it'll be less confusing to say the
access is "reordered". This is more accurate when the race occurred.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/kcsan_test.c |  4 ++--
 kernel/kcsan/report.c     | 16 ++++++++--------
 2 files changed, 10 insertions(+), 10 deletions(-)

diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index 660729238588..6e3c2b8bc608 100644
--- a/kernel/kcsan/kcsan_test.c
+++ b/kernel/kcsan/kcsan_test.c
@@ -213,9 +213,9 @@ static bool report_matches(const struct expect_report *r)
 		const bool is_atomic = (ty & KCSAN_ACCESS_ATOMIC);
 		const bool is_scoped = (ty & KCSAN_ACCESS_SCOPED);
 		const char *const access_type_aux =
-				(is_atomic && is_scoped)	? " (marked, scoped)"
+				(is_atomic && is_scoped)	? " (marked, reordered)"
 				: (is_atomic			? " (marked)"
-				   : (is_scoped			? " (scoped)" : ""));
+				   : (is_scoped			? " (reordered)" : ""));
 
 		if (i == 1) {
 			/* Access 2 */
diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index fc15077991c4..1b0e050bdf6a 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -215,9 +215,9 @@ static const char *get_access_type(int type)
 	if (type & KCSAN_ACCESS_ASSERT) {
 		if (type & KCSAN_ACCESS_SCOPED) {
 			if (type & KCSAN_ACCESS_WRITE)
-				return "assert no accesses (scoped)";
+				return "assert no accesses (reordered)";
 			else
-				return "assert no writes (scoped)";
+				return "assert no writes (reordered)";
 		} else {
 			if (type & KCSAN_ACCESS_WRITE)
 				return "assert no accesses";
@@ -240,17 +240,17 @@ static const char *get_access_type(int type)
 	case KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC:
 		return "read-write (marked)";
 	case KCSAN_ACCESS_SCOPED:
-		return "read (scoped)";
+		return "read (reordered)";
 	case KCSAN_ACCESS_SCOPED | KCSAN_ACCESS_ATOMIC:
-		return "read (marked, scoped)";
+		return "read (marked, reordered)";
 	case KCSAN_ACCESS_SCOPED | KCSAN_ACCESS_WRITE:
-		return "write (scoped)";
+		return "write (reordered)";
 	case KCSAN_ACCESS_SCOPED | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC:
-		return "write (marked, scoped)";
+		return "write (marked, reordered)";
 	case KCSAN_ACCESS_SCOPED | KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE:
-		return "read-write (scoped)";
+		return "read-write (reordered)";
 	case KCSAN_ACCESS_SCOPED | KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC:
-		return "read-write (marked, scoped)";
+		return "read-write (marked, reordered)";
 	default:
 		BUG();
 	}
-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211130114433.2580590-8-elver%40google.com.
