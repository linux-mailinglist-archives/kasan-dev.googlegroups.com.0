Return-Path: <kasan-dev+bncBDX4HWEMTEBRBJPORT6QKGQEF4TVTHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id B639F2A7133
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:20:05 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id y1sf22340wma.5
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:20:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604532005; cv=pass;
        d=google.com; s=arc-20160816;
        b=JuGsAVfJOYrAmS9HpefbToQBxaQWnejTPwlg+TStn7jJYmihaZu3MukbcVckPo667Q
         WZmUhyOnWZDl89Z3BWAZoGmSmXE/aU95BD9BPyV5YLLlWHeX4f0YBHmSQ7hPmy/zyAJX
         E7+D3ji3b6nnlCj6N3MA/psTeEkdl9QvjWJ8mGYL9DunNAG4QSQ+EUgvMhQii/PTZZo2
         aF5iRF7q/1YAOQNwUbztffsbdYdRwdDRvHO98Bo+9M7dcUKhBrH776DGdvPfC0raUFms
         iEy0Yss1MlIF9uxGmsZjSJlJiC/OyLbM8wEaJHL4CpkTrOWdIRMhWMWP23f0pBZQKt7k
         QMBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=ooGSTYtrrJhNBFGp953a9DcrtG0A3+VXe9Btt8KvNOw=;
        b=lAk6SW243R+D/APjVjcCbV1OmW7kA2/VUZvoMmcMA9iCgcc2h+zYoDkcBr1NUa+cr0
         1j/NvC94dIszDjzYpR1t+P8O1NKT75LC5tqEKy5I0aJHCPkACUSbYy4ii3aBAysogMo9
         pt7Tz6k3rRp0fcjgnPoXAg4/lDoljBHokk0wyQaYUnGG6w+mtT3Necptqc/RDjkTYOzP
         jSV54S7vU/6HC89mCySzo03Mkj+gwiuWSZDya69+cpg40KTIhn2XcfZegDWQSP0u7fyq
         dbPaHPEox6geKRgXi3MZ7kLsA2tDuobzRwfOdzrHiPNQ73laZE3EaRQYgjtWRgc4QSa4
         YT4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=C+OLyB6S;
       spf=pass (google.com: domain of 3jdejxwokcsm9mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3JDejXwoKCSM9MCQDXJMUKFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ooGSTYtrrJhNBFGp953a9DcrtG0A3+VXe9Btt8KvNOw=;
        b=NiQejjpfkUuDtCx3N+Fqap+TdFuC0DWhniQosxdm2sAUHPr22DRdegN2suQgPAqOdc
         gYLk/nMMvPIc5kA0Enpee7YHWx5gnNCrBROLSTTKOW9yKEP0L1RhtcKaqQDg0Fb+Ge6I
         kh70iGqAjVDCtV7vawua49d6GDRJDJoKQXqpM8ny8734cflM07nnBbVkrOfnedqfLU7g
         go6Q2pUysIKRDJYMdamSRVui1NDLyhRqd6YtmgbSvnDQtdvxVjBf+zBgi+l2oIvrnxDN
         0uHXsQRQcc/7XyYFuFiOMO4ZsH4bTVsQ6Ng4/A0Sc/lxNneuK3tuTNcQj/AMmWXNpqqw
         qKEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ooGSTYtrrJhNBFGp953a9DcrtG0A3+VXe9Btt8KvNOw=;
        b=FPcG7RM5SYU4yW6B+N0n8DZS32EjvLtv9oR1iY2+51VWeCpLbOWE06xZnlhcEhzfxB
         7qo+wDd/DnuqOrTDLWgQobmtCPYsnP4YvMTket1d5CbyfksWnB96RvmS/qnoxjMGNf8r
         IWF1L5ZNwjZAaqQHtP3wi8KEDd3hcphqC7N5ABpIsVrUmt4u7i+n0yXQikZzT5RuamAQ
         qVMWjbTDrvmQ6cGX4wIuWqi6VeAzjWp7otZPWOk6hP4ms5E1xayrwVBOuM02gqZizDH2
         rRid1Lv7t+1UdFBit/6/iO8ScCzmcNbg7aaIE04NR5SzIOajc0KpA6r3FybgiLHsmNva
         H1aA==
X-Gm-Message-State: AOAM531Rmw2OnVnjXMotr1gHiPjX92H+a3ua3Pa+MYb7g6pTutSRoZ1E
	e7f4pfsYRScxjKFlXqm9+v8=
X-Google-Smtp-Source: ABdhPJx3Umy9no1YWoX9wfEmskTb7AObVCb+GtGBcUPeL0SAKQvutwFGMe18Kq7RxVmqSe7UklKBbA==
X-Received: by 2002:a7b:cb81:: with SMTP id m1mr84381wmi.140.1604532005468;
        Wed, 04 Nov 2020 15:20:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f70d:: with SMTP id r13ls1280560wrp.1.gmail; Wed, 04 Nov
 2020 15:20:04 -0800 (PST)
X-Received: by 2002:adf:eec2:: with SMTP id a2mr410701wrp.128.1604532004609;
        Wed, 04 Nov 2020 15:20:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604532004; cv=none;
        d=google.com; s=arc-20160816;
        b=B90HEfxpaRQ/9IyaPi/02WA7WYHYDydpCwDCyvVzo4ODGaroZF2pjJoCTcRZG+jJc0
         erdzZK+dLAWsDhu0J9KbonAakbOXvmDOY+skYvN/8hCLC3nhyNOPamWApQsiQoLDwMFG
         tCqrJQWYZ5BSMIes9GIXM7b4RXE3xml+rDyNp+BGTxxPDqr+ArsafJKKt7EGyAP4XUmW
         ZXDT34Ll60Dl4o8csaUl7LaIEF512gsE1CumkYiFPeRHskiLsQmE2cKWKn1etxli8/uo
         XCuPJH5JRnJdF7Rmm6lsKGTSrsYShIU/wP8nIVU0J4ZkyQlGnlLczkjb9+S9pgd0SyLY
         Zgeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=ePhrCN9LvFC2NG8TKNxFN+Gj7X1gzwcPp9/mgeUcqHQ=;
        b=B8LBGByKyvIvvooYeEB4QLVotCMyZC+DV2N/RzF/epTONi0+xoPJ6wU6645TDZUXcd
         Ki2ThK6Hqkf/jd1T5nIUC4uFv+TCMXbz1ceZ7lzDXrlZutucDCDpP71DrbR5/CBCS2Mx
         1GS6yNdY9tpLk3AH+ka0xBrwTy7o6XIWl4TDwvc73xXKalUb3+wJh9prWN4PDTL8li3+
         wVskAkSe8tSCfjCbISzhlVMCqFcYJPxlc2fRNuS9ULqTdKXApnIUtpaHIv1gUnKoIZ1E
         z6ThbTGE5HwWjATFZeT3tuh/PBBF6/cSRjIg274yyo5eNVCjyt3j4kmmKY4891BgMmSK
         znKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=C+OLyB6S;
       spf=pass (google.com: domain of 3jdejxwokcsm9mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3JDejXwoKCSM9MCQDXJMUKFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id w6si168011wmk.2.2020.11.04.15.20.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:20:04 -0800 (PST)
Received-SPF: pass (google.com: domain of 3jdejxwokcsm9mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id b6so36551wrn.17
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:20:04 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:600c:216:: with SMTP id
 22mr50135wmi.149.1604532004186; Wed, 04 Nov 2020 15:20:04 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:39 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <c7401464c398ae353f996e2e7af5892578cfc932.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 24/43] kasan, arm64: don't allow SW_TAGS with ARM64_MTE
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
 header.i=@google.com header.s=20161025 header.b=C+OLyB6S;       spf=pass
 (google.com: domain of 3jdejxwokcsm9mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3JDejXwoKCSM9MCQDXJMUKFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--andreyknvl.bounces.google.com;
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

Software tag-based KASAN provides its own tag checking machinery that
can conflict with MTE. Don't allow enabling software tag-based KASAN
when MTE is enabled.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
---
Change-Id: Icd29bd0c6b1d3d7a0ee3d50c20490f404d34fc97
---
 arch/arm64/Kconfig | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 1d466addb078..d58b4dcc6d44 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -134,7 +134,7 @@ config ARM64
 	select HAVE_ARCH_JUMP_LABEL
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
-	select HAVE_ARCH_KASAN_SW_TAGS if HAVE_ARCH_KASAN
+	select HAVE_ARCH_KASAN_SW_TAGS if (HAVE_ARCH_KASAN && !ARM64_MTE)
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS if COMPAT
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c7401464c398ae353f996e2e7af5892578cfc932.1604531793.git.andreyknvl%40google.com.
