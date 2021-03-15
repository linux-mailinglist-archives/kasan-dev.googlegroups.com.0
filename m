Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBKV6XWBAMGQEZMQ7PCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 62BEE33B3B5
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 14:20:43 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id y16sf16008630oou.0
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 06:20:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615814442; cv=pass;
        d=google.com; s=arc-20160816;
        b=bv6PdBJSFsgPJeynSoUJSrRI/7rRpxZW8ynZkvbB4GTbQWzBFhSH5C2/KKqii65FIs
         PwDU8qxGeWBRwMV8Olcn8tqDDxXovU9eGzwTkSJEzCBqJh70w5hYkNQNQnnpWPTEzhN8
         OPJtMlSMq616GeAs6BFR6Y+Hc5ELMIgzMIA3Q8v5mXAnYNWaU6HHR1w70rd1uxiW29hB
         hUh5pnUDPa7d+WWQ+cUi5OY0Jeus3qBvT/+sPhDiqybUwRwF09/5hbawCaFZFodPGH91
         xDCasK7NaeLEoFDhuzIMbJDpYp1IE2wPvjiOUF+aoiK5hrkX+0ssfAz/3l6AUCz+EUq+
         DQ6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=BkcyozLdrD7+if/vkcFFBmQYum6r4SyeChHDddkdBbg=;
        b=PZfIHEKVMuc8NZAkXUjGhHi2BEUbQ++xdzTPD87c3PDGfJAJEOWlJqK9I7OtVA/dnl
         zaGZPB8jGI5ovGF5lz0/87Cip5OIH6rZX8o1TKYQDmyvEEB9DTeC+Y+IDHunGonppdcv
         uhdBJtM9TGKyd9k4Luv6ueRBUgW5+giY6qrYyjkA0CqFGURtPAxcV5VAWKr18zdMNMUF
         BtN0j8eo5BuCYO7BUgISqehMpMqMH8lGiP14WT89QwJi0ek+UqzW4zGHd0dcNbss+41p
         0oNbAvBa28DaLs+DeLNRSwV7bTmLNcavqyse4s2rXja12eOTLnlP8l+ZbYFDKt5jmXHk
         JI4g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BkcyozLdrD7+if/vkcFFBmQYum6r4SyeChHDddkdBbg=;
        b=V+ovs5BmfwMjEThDNg5riML0VEk3LbzrUUDOwWmUQyK3PuHPECqLf80+1ywh3k1ahB
         lJJAT+ikJc991GzJZ6LHcs7jx0/rj/LhzE6CPb1K2UDF1AT8E0A2PVFQ1JU6y/LjZVAu
         z2DDD7zI0LO0RXBclFzOjykg/dbkQ3jthtkn5lNT9TS1x5ilEM2vszemPiZY7RRnHZMi
         2df7HgQEwHywbX7Yn+P6ozuRhFLCpsUqvfDe68+0KXOyQcnXmNmlugJjJljCxZ//lJcn
         MQ/4qloulZ1BGYWBya8jHpfkEyM00buuVkeoXjC7i6uFtZn7PIbyhHJGFReqSW1BqrHV
         ikQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BkcyozLdrD7+if/vkcFFBmQYum6r4SyeChHDddkdBbg=;
        b=U2Bthtt8CMKg1V7BJ/ZorDpzCrJ2aH+HiWAYyv/984u/WRxEsARbmsCkcMJucrsrue
         reRqiIM9TZdBc3Od6CVjftcaIN0ab+F7A2/zuHsjmqWZhpH42ymRyrSr4h+IA0olrwTu
         JSoQhS/J7t2UdpQcahsGm+Kuj+1ho5R09O7YCOhp6SPfmTWX8KV6H/zTJpdyB2bOwReL
         0mSGAgjmW8iNHYhhCdXJu0iuHFZjTRkrTOa1D81gV7aiWt8uXShIKMury7L+PVSOwXdY
         uOj0E3Vk+IMLp9wLPCZRIyfcJgKPT+ziki39RhNikfW//nc4+gMWW7Wo1bzNucOck2wY
         1Fvw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5306Ww8G4ffbLF4amOpGKMGo7yRw5p2LkfwthJVG3xhr14XEp7s3
	3RIsCfrkhKzEfKw7oAaQQuQ=
X-Google-Smtp-Source: ABdhPJxLmF480xGIvM9rV5Vwz+AEKkaXrHOjf2wGLm2mWoHA171LnC0d2OFO4Drkrgcaig78yCxtKA==
X-Received: by 2002:a05:6830:1399:: with SMTP id d25mr13722007otq.249.1615814442413;
        Mon, 15 Mar 2021 06:20:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:3113:: with SMTP id b19ls2641133ots.5.gmail; Mon,
 15 Mar 2021 06:20:42 -0700 (PDT)
X-Received: by 2002:a05:6830:3497:: with SMTP id c23mr1227311otu.344.1615814442100;
        Mon, 15 Mar 2021 06:20:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615814442; cv=none;
        d=google.com; s=arc-20160816;
        b=D20QPWig8TuK7y0RFAmuDgtoVPNDokC+hZI8LosiXzEUj3DfJZJ8eRfnOtRatsj6EG
         lFtPdb+1jVp+PZJg7RbG1QVkaCiBsw5f3umhD1P5ivHvVjY2cujSoforIjGx45eoNdHK
         YDdJjttmnIyIy/4+QaIWzmBStzIQLxlKdaRlVIn8c8PhkB1caWyYfQbYy8Se5BF+EoV9
         Ic/Yv4tDLIF85cJygRigxoNeEic+5U9nMhSOgPx/buACWiR+Uoo6IfAnHG+ncozru7uY
         9/IKe5r7j4FMyCktyGw6jOKt/g/PJLEW4xET2IF5cZfg/YTEfX+c26vDW6MFaRHf9JCR
         2RpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=ZYRFPkknL+T59Geb3Do4akaxtZE+0ti5PVOWwVUJt5Q=;
        b=xKsGyU+YM7gYPjElsZph3tQXRJqM+E+ADAG+V9feixNnEl/o/xaEwbyrjo0OykXuOC
         pstToY1tSOmFISRXcZgvsljFh3jUpVKhQLENP32ogx3BNurisPBUWM4arsBc4TL3jTnJ
         f+DcEFdsGjDLvFmhKVFl1f6F13HrHoQuShVHXXxmHSUpTApk/LZMVaj9A/N7E10PZh0B
         IHre7porbiV3isZfrh7U0q6dc1ruhClObHnlIhs1oDgB3+3FV77V8DC5AkVjkPN6hoIV
         DqgMEywfAalctcCAF1iBKkEbRlhvU+ptawBi37sIO86zzltnXrcoZ2EQHM1zjDnGAzEb
         FxgA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id h5si1055214otk.1.2021.03.15.06.20.42
        for <kasan-dev@googlegroups.com>;
        Mon, 15 Mar 2021 06:20:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id D61C513A1;
	Mon, 15 Mar 2021 06:20:41 -0700 (PDT)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id F34C93F792;
	Mon, 15 Mar 2021 06:20:39 -0700 (PDT)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: [PATCH v16 6/9] arm64: mte: Conditionally compile mte_enable_kernel_*()
Date: Mon, 15 Mar 2021 13:20:16 +0000
Message-Id: <20210315132019.33202-7-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210315132019.33202-1-vincenzo.frascino@arm.com>
References: <20210315132019.33202-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Content-Type: text/plain; charset="UTF-8"
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

mte_enable_kernel_*() are not needed if KASAN_HW is disabled.

Add ash defines around the functions to conditionally compile the
functions.

Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/kernel/mte.c | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index 9362928ba0d5..50f0724c8d8f 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -26,9 +26,11 @@ u64 gcr_kernel_excl __ro_after_init;
 
 static bool report_fault_once = true;
 
+#ifdef CONFIG_KASAN_HW_TAGS
 /* Whether the MTE asynchronous mode is enabled. */
 DEFINE_STATIC_KEY_FALSE(mte_async_mode);
 EXPORT_SYMBOL_GPL(mte_async_mode);
+#endif
 
 static void mte_sync_page_tags(struct page *page, pte_t *ptep, bool check_swap)
 {
@@ -120,6 +122,7 @@ static inline void __mte_enable_kernel(const char *mode, unsigned long tcf)
 	pr_info_once("MTE: enabled in %s mode at EL1\n", mode);
 }
 
+#ifdef CONFIG_KASAN_HW_TAGS
 void mte_enable_kernel_sync(void)
 {
 	/*
@@ -147,6 +150,7 @@ void mte_enable_kernel_async(void)
 	if (!system_uses_mte_async_mode())
 		static_branch_enable(&mte_async_mode);
 }
+#endif
 
 void mte_set_report_once(bool state)
 {
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210315132019.33202-7-vincenzo.frascino%40arm.com.
