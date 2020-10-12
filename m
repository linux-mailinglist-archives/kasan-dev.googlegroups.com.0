Return-Path: <kasan-dev+bncBDX4HWEMTEBRBTMASP6AKGQEZ67VDQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id C64D228C2DF
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 22:45:02 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id n133sf3159694lfa.19
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 13:45:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602535502; cv=pass;
        d=google.com; s=arc-20160816;
        b=oqG5ULR5SfydHN4KoqvixLv3Kml1QgZKGR73qyYISJCvEHYAKtcZe6qo1IE5C2aUx8
         +4p8sRTYKQeHkI+a3nBd+gUlb9p+WYiaYQN9+j473zvea4VrVi90U0eRutB1MxKk5OxY
         cfmeuQ92DbCgXDrB0YRMeXAjmo5dF5ZYEF79r44BmtuIAHYdM744q82J2C8FZnN33S0V
         yeU6bCIPfzIRQWIHq7RuDDtShkS4k2X4TR3vtifO7ZEKszr4M8ggarCrj/iHPQdacX5h
         +RGiAJUdNKDlND8JFD9Qh2WhLFYmBO0g7k5jn2njtzp59W8wQPNhuiqpCo/D0oDdJcRF
         39Iw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=ci0e6q/UyfBTFwJp9WLHNsmHumLjmcPZ36dV7yF14+0=;
        b=DuYOKSHhcPUKKcwGVApfQ+ronKRImDaisbJ3V4XpzUdk3Kv1dDkJ6npQeEbw+HFNsT
         NM8183HYoUDehS5CE6PT4YP0EKUTnlFzq9HXEiwH+4AWSQ9dAmv52AHEartGotXiUu4q
         6cmIf6fn9/ydlilmIQWCAEpNCeLT3ujt8ZFR3xJqG8KnFexjViJWJwnKRyFiEZZ6F4Op
         lzZjkjG0ywkjhtjAL0RS9FMfCA+wr78UjFf1f9S/t3MuFZaCpQlt/yKaSF8RaFRN2enA
         2JRD+nhGqVL17oH0EqmqqJwXic9WQdk2w8wtLkpPAUKNB/zMkdr75S/sN4feHbSMjtRS
         11Hw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iIDEyl7C;
       spf=pass (google.com: domain of 3tmcexwokceedqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3TMCEXwoKCeEDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ci0e6q/UyfBTFwJp9WLHNsmHumLjmcPZ36dV7yF14+0=;
        b=qTg4NCzhYDKzTxWhaIHcerK4LwfFViKeY5+3/ZepvEzWWZGTC2uiMHZnvVyj2iyovH
         0cDk6MUzqdiDK+1XbyD2gzpQuxwwPQB6la0eI1RVofNsuS7GaHOlJAF2fCu+sy9gKq7r
         KPZA1AQ0Ek5O1lspH8wG/lgrZZnPe1qQBPBes7Ae5fF/r1VKb1aDzaBPNYoUdbtcM1Lw
         60uC6KESIqaAVYOF11oALbJHzLjRF06quSn0l/qJ09TPnpVW9KycQyAjtKRLn+FqBWjM
         6X/JOtHN5qzex3YhhqjyWocB4JTeszDJwqIgwvgxQPvQ4hdqTpz9iGhd7mNUpoOh11Fh
         RJEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ci0e6q/UyfBTFwJp9WLHNsmHumLjmcPZ36dV7yF14+0=;
        b=Bqw7y6nVU9S/EZw35hYI6Ms8kHD52ZMNH7zJYcEHxorihkZtvKnYmGFjNKbWV6dPHK
         gFYKONqkIM3XbZrqIK1OiwDbx0O8M4gmPH2u94kJnB4QR81rUiAD1qCbLPT2STlwL+Ka
         jeZhJ+s9acpTb8sTcWxeJkisYpvJxyQTum6R0tKJbA7CxDc75W2mlcTaccpxkEJw2lL7
         RtYtj8lKGsFR8iZvojz84ZJ/Dc5Yy3RBVsK9seQ85UIfp+7FUSU70cpKgqqHNiDStU7O
         Z/o/2Pa5MtsWTXb+ezPD1DlJf+/1PrKdrM/YpVfdemEA/orGsiHhSO4Em3SZgUhEuJDq
         ERLA==
X-Gm-Message-State: AOAM5331EBdVoFV7hl6MBd0vXGgfGMI1VHmfcfeQr885VbOMkA2ImAHG
	nCfTNGlU41b2S+/5tT5mRIU=
X-Google-Smtp-Source: ABdhPJzJTy/kF262CtuRSCY8dJQEOhMCzvNSHT2PqFa5ECrvABsus2SlaYY6TiUYLEr6mD4cwaQrpA==
X-Received: by 2002:a2e:8e88:: with SMTP id z8mr4099651ljk.13.1602535502167;
        Mon, 12 Oct 2020 13:45:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:554:: with SMTP id 81ls831855lff.1.gmail; Mon, 12 Oct
 2020 13:45:01 -0700 (PDT)
X-Received: by 2002:a19:dc47:: with SMTP id f7mr9502748lfj.468.1602535501126;
        Mon, 12 Oct 2020 13:45:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602535501; cv=none;
        d=google.com; s=arc-20160816;
        b=mN+NP5J8eVWpdDKyGHtzeBXgSp4NrshHZUK0VVr/B1AyXlK8nRlZWIML9Y2B6p+JIO
         JYnBLCEk4j7OD3uDGWhL96QAddfPdOK7aO4gjDzhP6DGJtbbe6ss8t4tozSACaBb2mZ3
         yVslH+C/Kb1IE95J7av94WAJHDAKk1EoeQNAGQpE2xJLiT1bNhtT3Pddg1NLYKXrCI4B
         oeQXIg2mGh62gfNj9/7MIYeFTJ6iOG3LwIlUrfQBLUcKCwnYYhV9rRwihASdBFxg6Cl0
         7xPTXNOfg4hCizhi7PP75Gkdh2bPIDgSHWEoY/4vqQXWYEUXszUhO0473jASlGUt/6dh
         re5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=RnzGNcZZeUOChTXWjqk4hUmc/KbEjOJj4ndSgqlzHDU=;
        b=cJIwWFYOb75haMBbOAKsTXpP+u/rfjiY8X/PO71nTGEnYGXIzFbe5Eap/ALW/uJH6W
         /fQHkz68VD9X6D3jfLCm/g1a72AsJrTrhU+y62ns824eNpg1wztOxcbuEdwHHtYvIUos
         azz1ybPRNwyv4tngP+0V841xO7xEPBPnwkry2Zl5qL10oGC5szjngimAAM+R4kWZCmaq
         snW99iz5t4HL7mWKiTn5YpQHU+vCVX6+r+uEK1mJQzu2QW5Qh20HOMj0bqxRIQEoQTMN
         Qn8iXG8PJ2ZlgtRzgR8HVksTXu0sbHX+vTP21T8ZmC7C0odx7zt8IslcvrwQnYmPsB/K
         HJEA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iIDEyl7C;
       spf=pass (google.com: domain of 3tmcexwokceedqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3TMCEXwoKCeEDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id x19si537924ljh.2.2020.10.12.13.45.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Oct 2020 13:45:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3tmcexwokceedqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id n14so6296428wrp.1
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 13:45:01 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:c14f:: with SMTP id
 z15mr13021569wmi.73.1602535500490; Mon, 12 Oct 2020 13:45:00 -0700 (PDT)
Date: Mon, 12 Oct 2020 22:44:09 +0200
In-Reply-To: <cover.1602535397.git.andreyknvl@google.com>
Message-Id: <41244709e289a2467f6e5d639acf6a41a535d168.1602535397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602535397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH v5 03/40] arm64: mte: Reset the page tag in page->flags
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
 header.i=@google.com header.s=20161025 header.b=iIDEyl7C;       spf=pass
 (google.com: domain of 3tmcexwokceedqguhbnqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3TMCEXwoKCeEDQGUHbNQYOJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--andreyknvl.bounces.google.com;
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
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/41244709e289a2467f6e5d639acf6a41a535d168.1602535397.git.andreyknvl%40google.com.
