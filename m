Return-Path: <kasan-dev+bncBDX4HWEMTEBRBPVAVT6QKGQEVM6DCNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id BCEDA2AE2D2
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:12:15 +0100 (CET)
Received: by mail-oi1-x23f.google.com with SMTP id t3sf55243oij.18
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:12:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046334; cv=pass;
        d=google.com; s=arc-20160816;
        b=JZ/4jL9V23E8XqqivXdusseuD394FZk3JdXO2zsRixahPacad8J0DtSps+Ry0uks0s
         kNV5sqxPD4r/+u6IdFPo53wMRMCJHi/QHmUPH055foTnQe3nRA9xF45+fB7pRubtnXrO
         IVqwAZlBx+et3uapacgU2DiocDlgVE6+U+P/T/WH7fT4wCmSVbX4Qw4dZCgRGTY/bVdj
         Pbsn/8/yuDE1tCmBBz1nMMDFlt4DvRdWUxf3sPT3LZYkYZiOBCg5DIfhIOE3+IO4Eo1d
         7vSi6O+TKEIDnyT/7QkoygsuzH0QzCE4Mpn6xmqXSt7b/LmzCf1S2sG0usQJ7mmDygCt
         8oXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=EAT2hDiok4YzQXKqL5Cun8ce9SjvqxM9p4r6g1KQ5VU=;
        b=OFXqeNzR9MHjw+z4XSZM/MX21rmN/SYrLEcIHA9nxDZ5sIyI/JzxEDrr11LT9obvro
         iunBU9IUugjo++quSLwrs8Z9j2NkyTTozKXUH6BaIl7uiOtlPZp2PiIsPP+B/+ZVXvcJ
         Vs7AQ9OVwMGLG6ME9jvYbfKvV+SR9fnuprXhKH5XIz39pebg2Jo12vZadhm52A6zptAN
         EaW8NqL0uqswYPCu9xr7Zz/eq+zJUsOIRQIiR8c7Y6O8fv7a2HadZZ4ULnxPVpjxYTsG
         JN5Bc8KkxUhHslgDWnhJ26XomqeOZ1NemBfRTwEjJY4LN+80kg8jntNSjp4wlOWyZ4Vu
         a7RA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=q4QGAbbq;
       spf=pass (google.com: domain of 3prcrxwokcq4o1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3PRCrXwoKCQ4o1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=EAT2hDiok4YzQXKqL5Cun8ce9SjvqxM9p4r6g1KQ5VU=;
        b=LJlxSOmkr/sHp1EcoU/ayRbulIUoBlrvdkugBSzxXSg9zublRcfTjapXMsipvdIjc+
         umDpaKf+LzxzRrM2rjSlBjgeArhTdYMCZ9P/6Cvzvezsz2AMJuMy5nCsg0y3Zq6mtx0c
         7qwAMOTbqdyYrms4MvywTeli7Xhrgw2aqdqKXrpePNGrA4XejBtqvJrDMVVCxzNr6rhf
         fltYDgX/q8iF/rd3tUowG6wZ0eKOQkPtt3QFxkWc4X2YSzckmSFWh1Hvgysrfm83JrSg
         uu2dnUoldoTV0qUEqBMzM1e5vvVrc+4VPaa1+dJ3sPIoLhnWOv072gxJtzMoJKCm8T4x
         WYGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EAT2hDiok4YzQXKqL5Cun8ce9SjvqxM9p4r6g1KQ5VU=;
        b=C6mGtFmfdFCeDssOCH0WVOnlR5OHjXJUKr7Kf+9WO5rhvU6FY37ZwjH7ri120aRCDY
         WkDPCSGZ0Rz53PESuLPuwgLYTxe7omUscfobL+GEBWjNJ6MnENB/Xs9DQMmbJ6DkARuo
         gQyOwril7PihwKadUoBGq9cMoSkWnMTg0S404EGZqB/uHIOLQmP611ODJwdGoLgd/h1y
         znpBA+JthI/2ThlPSJv4PpRMGTaFEBoJ+9cqseL24AKuWU4l/NQ62gZZb2Hg0OGmcf/h
         txl+rAdMVS/H9vdnpjGzKxZ5dqkc1U07oL4k/3A3PgbpNBnpSKYMXJ8rSwKcPCY/YG86
         ttYA==
X-Gm-Message-State: AOAM531KZcs7cVbV7rYP2CG9dlNV+mc+ZRdf9EY/w/WsL6TyktMsAZCE
	l3dY1po0ocLIfqLd34jYsyQ=
X-Google-Smtp-Source: ABdhPJwqzeRDxIK/8c7Y9DYwkTK1db07HEJrDP0fGEGhkzlp38bWGtTXmaJj+jtjqqv1Vk2W/lhZpA==
X-Received: by 2002:a9d:7cd6:: with SMTP id r22mr15975562otn.355.1605046334735;
        Tue, 10 Nov 2020 14:12:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7994:: with SMTP id h20ls617921otm.2.gmail; Tue, 10 Nov
 2020 14:12:14 -0800 (PST)
X-Received: by 2002:a9d:16f:: with SMTP id 102mr16506405otu.206.1605046334394;
        Tue, 10 Nov 2020 14:12:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046334; cv=none;
        d=google.com; s=arc-20160816;
        b=DdmpNNqxIzyfEdnFytc+UZr2wiQkDfYQHRd8Vu6L0hMrjonYRxOS1lwveWoTha0Vw8
         NAL+V43uFRVu2NBU57M6udg9ky/E0zJ21w4fHnMjmexACAHHhp7cyt9dMQX33c/hsjOu
         w2newEDz+TOqmclaacncBQQotTumG+J3+ixmXrlsAtiIPGtOzeBeNW7CLgn+J1NHkEGW
         NRfkvFmRjcn/bpe0fc8gItq6V7q3grp3VNnWX0XlYm5vQKFpKQ5ALuLsTkjAZbORl0JF
         VvX5ksiYsS6hNDcTynKTbo/sRCcj5L9hJtJTvA9QvPLvXsAuB0uKzI04V/wpO4u9RMLV
         IKoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=d8tQjB/ZefUWtBLBKefANqT3i+lXlksl44G7nQ4ChAg=;
        b=T4s4nuwBFGNYL24OoEz7UUe7FhYdxgX4LqfiL+vTCaReVGrNl6ckhvQ9iN9cpEdClv
         f0ZG5kyIjXMQeKxkPjNeDFgK1t59zPgS7CnCv91W9S8up3YW92h4JEblkAhsQxpa7DpO
         w3zzLEM7aEgVWdx6F8hk+JbPsfhYX6hYKnx9SqRpzyI0F1Tg3HCmKOF44lmn3DEDyy9J
         f57ldgFqwDF9RswA8ScRLOv32RNyJhmtjKWE3Zb3xnKb+y+hilzpesWStsQB/8KaIP1h
         aE28/UWkKxzcPNwlNtLIFqXWyPfldcU8pCYvwpp2AcATMELvpbEUIB1FjqPBZMReRNor
         SNAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=q4QGAbbq;
       spf=pass (google.com: domain of 3prcrxwokcq4o1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3PRCrXwoKCQ4o1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id p17si5381oot.0.2020.11.10.14.12.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:12:14 -0800 (PST)
Received-SPF: pass (google.com: domain of 3prcrxwokcq4o1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id z9so39608qvo.20
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:12:14 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:f951:: with SMTP id
 i17mr7499877qvo.22.1605046333870; Tue, 10 Nov 2020 14:12:13 -0800 (PST)
Date: Tue, 10 Nov 2020 23:10:25 +0100
In-Reply-To: <cover.1605046192.git.andreyknvl@google.com>
Message-Id: <4a7819f8942922451e8075d7003f7df357919dfc.1605046192.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v9 28/44] arm64: mte: Reset the page tag in page->flags
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
 header.i=@google.com header.s=20161025 header.b=q4QGAbbq;       spf=pass
 (google.com: domain of 3prcrxwokcq4o1r5scy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3PRCrXwoKCQ4o1r5sCy19zu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--andreyknvl.bounces.google.com;
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
 arch/arm64/mm/copypage.c      | 1 +
 arch/arm64/mm/mteswap.c       | 9 +++++++++
 4 files changed, 24 insertions(+)

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
index 8f99c65837fd..600b26d65b41 100644
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
+	 * the new new page->flags are visible before the tags were updated.
+	 */
+	smp_wmb();
 	mte_clear_page_tags(page_address(page));
 }
 
diff --git a/arch/arm64/mm/copypage.c b/arch/arm64/mm/copypage.c
index 70a71f38b6a9..f0efa4847e2f 100644
--- a/arch/arm64/mm/copypage.c
+++ b/arch/arm64/mm/copypage.c
@@ -23,6 +23,7 @@ void copy_highpage(struct page *to, struct page *from)
 
 	if (system_supports_mte() && test_bit(PG_mte_tagged, &from->flags)) {
 		set_bit(PG_mte_tagged, &to->flags);
+		page_kasan_tag_reset(to);
 		mte_copy_page_tags(kto, kfrom);
 	}
 }
diff --git a/arch/arm64/mm/mteswap.c b/arch/arm64/mm/mteswap.c
index c52c1847079c..9cc59696489c 100644
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
+	 * the new new page->flags are visible before the tags were updated.
+	 */
+	smp_wmb();
 	mte_restore_page_tags(page_address(page), tags);
 
 	return true;
-- 
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4a7819f8942922451e8075d7003f7df357919dfc.1605046192.git.andreyknvl%40google.com.
