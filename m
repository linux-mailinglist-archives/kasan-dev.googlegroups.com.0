Return-Path: <kasan-dev+bncBDX4HWEMTEBRB3VN6D6QKGQE4YRB4NI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id A37302C154F
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:09:19 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id n8sf6911634plp.3
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:09:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162158; cv=pass;
        d=google.com; s=arc-20160816;
        b=Cjy29iB/uExlhSloii/5jI8MubLXsLwWqMvPeI1Bj/fHtgkvPbLjMl8EunMcd9SAmx
         TYGJv047PIphxpXxEKYCVWJUNCTkzPl2+1/wH7jtrMO/HnmGCR6EcCAKwp0s6Pz77EkL
         L6yrkL1NLKWToOMbJjeaCPwSj+0Rm+pRGTGXFpRKnSKXQeqIbIqI4GOLilNxqhj0v1Z1
         02OFlEYXOi8zCOvXFG8nFlCzJuZd6UXaIrz3UADPo3e9CnxIY/bsLcK7ueikepND0cft
         KRCeRIe0at5ihMu9ivMolnGR4S53VP7ZlnQSZjOVn7KTmCM7sGciQYztPjMa3j0GjGkP
         ohdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=FZrw1RFzd1r/vuM4/Yc/D9lzp0Htroi4MqKGQeetUWA=;
        b=R0JHAR99LhGgFYKaQQ36LEJo2hBYeqEYOZr0tk2PG7VF0LvuId2zfg13ASrwM3Fv3p
         99QFo7E3L3iOBMk9KfUkkh0KsKJ0vHUKq4p3n1MhLNz1qQeVio8s8qQv2eQM0QLxCKhe
         FGmJlqsI0y8XQThuOh1dftt7vVVykSBjzLlX0KLJg8fehDS0ODnLZ7hdxMjeLPMvbfMN
         3Tlxav/eUe/sXXv2ECZ1Cg+mUQJXJRZqXfCB2Yx1Z6jPOXT3kVJD2Lcn+vSbdB5x6kRJ
         II6E8Wu9aP68DgX3ZGvVXRYi5hBHlynq8UCutYQP+u5hsKNypBBiugczuGArYHDkTqt6
         BLmQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="gFQRB1/Z";
       spf=pass (google.com: domain of 37ba8xwokcq8p2s6tdz2a0v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=37Ba8XwoKCQ8p2s6tDz2A0v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=FZrw1RFzd1r/vuM4/Yc/D9lzp0Htroi4MqKGQeetUWA=;
        b=d9dvE0HSeJkH2TCxqv+cB88wxsi0lkN435EkZbIlTVMOigtPIWY7lSK6l3aDMANm+r
         7SxJmTNWC+PjoxlCAkkrncNGKXtd/j8cIlJ0mXA0zcl6wqcLdAxc6A+rzTnWdMiNsg17
         QLceFwO9dIgHqRkrA5qVz8ryldOw9d3TYKHyA6zkqoJ4NiKMJs0YRZ6YcMsMQozXVZYL
         KXrobClPjAYcrOjtploKzA6G+LvV2pBsSNy//eX6qr0UW984ZLl2L1sYBV3GDyDbS+7D
         AoyqP5GU+MeDLr7DLdXYjhbvCJaG4EfrSltCRSczcWhn1fUNoPvR70yfDdKg10gdOyC6
         BHcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FZrw1RFzd1r/vuM4/Yc/D9lzp0Htroi4MqKGQeetUWA=;
        b=tN1ziNAEJoiaNpce2SrBDGbxQyuLm9cR+UFzG9sy+VhXn6ZayKBFlGXbf1Cr/5WXhr
         yxf8Pc0ps/G9I5wQeZT0YA79p2HXyiU1vOCaGVKEDMTw3EQAPeko5bsqi5ZMMrLkWTdz
         v5HrFBwz0/jf4A2a5xiwHiZedg5MnchTQ0K/IL0I5L/tNfdq9TSI8RCLsUzeWM6Fl97f
         sDfFKwT719UjvrxoJ5B+h+ts9eFIJKCz19v9m7B7cvPp+bMey2yqjRIbHAjbF5ojtNpQ
         BEP9utndbi27DnDqSTsLc0bb2TkIKodlmVIMPDasSzFxNHVSJi8A8dao52/GoVFojkk4
         4DJA==
X-Gm-Message-State: AOAM532Mavmr/9Ch3sBbcsIDzIVhoq2pP+9m/D0/dOYqwtcDcf0LSRSE
	koDSzFiG/XFza957oMzTNGk=
X-Google-Smtp-Source: ABdhPJzDJ1zNah0dbBVYy5kiQrMSzoExcjssTtRpfguB1rGvqmbqWAGQn1yLgOM4ize9Bd5YA1frMQ==
X-Received: by 2002:a17:90a:de95:: with SMTP id n21mr704281pjv.42.1606162158445;
        Mon, 23 Nov 2020 12:09:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:bd8d:: with SMTP id q13ls6661874pls.0.gmail; Mon, 23
 Nov 2020 12:09:18 -0800 (PST)
X-Received: by 2002:a17:902:b582:b029:d6:6008:264d with SMTP id a2-20020a170902b582b02900d66008264dmr919700pls.80.1606162157885;
        Mon, 23 Nov 2020 12:09:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162157; cv=none;
        d=google.com; s=arc-20160816;
        b=PjBqEX7GWtExP0UqZTPRNkk4OsJJYj5MIhNtIEtk4ZxusV7DPrAJbP0hv81UCSDNIp
         jKRTRuPU/2MLgORcVA/lmX00yoG8hEuy32zpY7RFm91VR7aVk0YBwT9/hWkw7EnpJu3b
         5g4oPwem4c4fLfwW1ZKHtneek5HT6kuaGaa2pAa75huPt8/yKPmBh33a4jsZ2L8OJOl7
         /XsiT37qHABaGBYDxOqVFP1Yr+axeCZO4VziIsQkSLEM2MOURFZgpDuGbuPph1pjbXIs
         /3qyM6cCLTQrCEU984hSsUE/h8wdeFLKxskNbiGOJ4+uZWyK/801Ys14wl4wmdlC+c30
         38GQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=GkFr0u14154TKCLNsFsUNWuX9c3ApyttswFdMFuJ7qM=;
        b=IKAcgK20GzcAiPumzP68r78g0mzlKasX2s63Z5+TjxRvjwEkpeo8dQXWubTmfDF25r
         hkxSRt704EkjUNgeWo3faXXhu1388R5Zpc/h3xM87Y89LMbGAI4xu2tu2tPnFij9PmxP
         53hX0Qke90S+QuGpE4q1Ksv7WFszLSYWhOxuXe2nXgIbL2KzJCkAP23MNRcXW1IHB3+h
         bnZWUHR/jFENx8MNYKGJQ46rCFEBWzHykxnHuOS3YAi1v3CHxOzhfmytnd+t830vDgZE
         YhL7OrFGh0ERnWH2MvZ4y4MCbCMJHpmQzhCWa8V7loLVMOE6ww3yl/ybm03SENL3rYkR
         Q9ew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="gFQRB1/Z";
       spf=pass (google.com: domain of 37ba8xwokcq8p2s6tdz2a0v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=37Ba8XwoKCQ8p2s6tDz2A0v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id u133si907314pfc.0.2020.11.23.12.09.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:09:17 -0800 (PST)
Received-SPF: pass (google.com: domain of 37ba8xwokcq8p2s6tdz2a0v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id s128so15571998qke.0
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:09:17 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:9a9:: with SMTP id
 du9mr1076956qvb.47.1606162156981; Mon, 23 Nov 2020 12:09:16 -0800 (PST)
Date: Mon, 23 Nov 2020 21:07:46 +0100
In-Reply-To: <cover.1606161801.git.andreyknvl@google.com>
Message-Id: <0b8cd898a49ba0c9574f822c87e351ea567a80d3.1606161801.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606161801.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v11 22/42] kasan, arm64: don't allow SW_TAGS with ARM64_MTE
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
 header.i=@google.com header.s=20161025 header.b="gFQRB1/Z";       spf=pass
 (google.com: domain of 37ba8xwokcq8p2s6tdz2a0v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=37Ba8XwoKCQ8p2s6tDz2A0v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--andreyknvl.bounces.google.com;
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
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Change-Id: Icd29bd0c6b1d3d7a0ee3d50c20490f404d34fc97
---
 arch/arm64/Kconfig | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 629a293cc408..026aaa64a7e0 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -135,7 +135,7 @@ config ARM64
 	select HAVE_ARCH_JUMP_LABEL
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
-	select HAVE_ARCH_KASAN_SW_TAGS if HAVE_ARCH_KASAN
+	select HAVE_ARCH_KASAN_SW_TAGS if (HAVE_ARCH_KASAN && !ARM64_MTE)
 	select HAVE_ARCH_KFENCE
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0b8cd898a49ba0c9574f822c87e351ea567a80d3.1606161801.git.andreyknvl%40google.com.
