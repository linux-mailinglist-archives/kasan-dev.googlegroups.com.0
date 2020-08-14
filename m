Return-Path: <kasan-dev+bncBDX4HWEMTEBRBIUT3P4QKGQE7RNWCHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id AB28A244DCE
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 19:28:08 +0200 (CEST)
Received: by mail-yb1-xb39.google.com with SMTP id y13sf10879194ybs.0
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 10:28:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597426082; cv=pass;
        d=google.com; s=arc-20160816;
        b=I//iKYrvA8m3pEFwD1hbZB61gnOms8ocDInHpE4/N9y0euiR73hfI+M8foncSdSD4j
         I8IBPbnW3YWNTmD0Qt0gm/0GmOYwd2ru6tZabtZGxFbxVtS1ygMVOG5jauQZ2O+3BHe2
         CWf+HnovVB5LqQvgQg5UMhszvqLZLIzYQWJcCM3dds1cm7O4Z51sCQDSRnjQX3KYZIMU
         lz9KY2NxgOqOYTrcuML8sqOJfuV1iQENW6rJHvnYvmzcD1H/8dU9Dv+WBUpO5CYiatqM
         uXrNfxHskoREMoI3pzF7maa7bZIDUFpewwxZhS54vqbHcTFUNQWtTOYQIcJiTgjB/xuY
         bdzw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=XhAEVtw4bCLsiA1NiAJ9z6h/+H6na5tr9YwYVyJbahA=;
        b=PVYTgN/uuhKMphNs8UgceKguesEm8p+JrerwlSk3XgZyv+SzkVxv6TbRCh7wGw4+/n
         V9RPVYtk2Zq/iHBgrFuoeiYtDgEfjZzZGLPvHFTJub7Xo52C2HHdiAy8Z539dp0Lpeyy
         Zw9xYbRtV0epEh+fgxt2JYqal7X0IfGruL3h4llXmR3ocVaNzedTEzoxMUQGhuFXnAf/
         pCwrHjS56LwPuQKpLtR4tYn7WgAZ8KLBFxw3omkwWFOwbQ8yXb4fbqGDl04WgA+W2UeR
         Dxu5/Ch3JKdILfpCMpDUUq2vvJQ5//jJH82Um4Sqf4ns+ZHtdeiS7nTgl+0PcuaLZVSg
         Y8tw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=a+6DNaeG;
       spf=pass (google.com: domain of 3ock2xwokcraq3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3ock2XwoKCRAq3t7uE03B1w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XhAEVtw4bCLsiA1NiAJ9z6h/+H6na5tr9YwYVyJbahA=;
        b=RwxfVGwvbcD1zhf/Ux3h30Eevx2YVBvJGBpudQM2o//z1AeN+eO+IcXtapJVHlgT0U
         zC0smyzEybmLrP1csgxaWZ/lx1BoQsgSXa06P24F/thhvuZo53qv7Uhcz671XCZil7yO
         vulxPb6lQC+HbPQIK29CWavtMzIuFoBmuvWIp3mLD8Qj1xh88QzNIjLnFMoQQlwfrB15
         Ss6Ikl3y7uCyP9a9gHpglQe06AVSj2vxIoECm5DZr8QJSDDtLXpHT71mZNJkI/fAf2gr
         uw1DKuyxXap0TFCQ8bHDIsShnEOjFqVDdy61dKZyGl+xRNAYBIOU/NezF22qFIbqwt+f
         17Ag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XhAEVtw4bCLsiA1NiAJ9z6h/+H6na5tr9YwYVyJbahA=;
        b=GFocRMujpPoAzzJSJGSB9tC1EClyGRqydeuwFcng2A1HSsABmhwsob2Mw00K+Kcj1y
         yMwMGe7TcBHeCNrZ0NEjuptyqlOWlvzlqXWVTwO1cqBaH9kl5UAsU2rZJ+VC0xcvpjgV
         FbRLG3nVJ7I4yAch+fZcSq447WNvJBQxxdDvA4vPDDZDoqn0SL8vF3SKW4ew7BfuW8hm
         +jnRJ9MtUx7zrS3hDRgVwuG4e6ikumnOA2fUnyweoPasBBBJftaB0AUelF+uTJDJm8iM
         UUq1l2lBMW2R3qzUgKttLzUNjYIQltEWmVKFfahx0kqDERDUZnMjYi0uH5bNjcYvQxmh
         Gfyw==
X-Gm-Message-State: AOAM533MgnvPC6HV0PWnIpb5znGcJuN4KuxLY8X4rjaUqloDM2GcwM+5
	luNXwaNgcFN1YQzcWGcFs+w=
X-Google-Smtp-Source: ABdhPJxEFk2CTSwdHundl9fLuqZD0sdb80pHIKHVTsQfl9zL7pBSz3kPI9fqXiGkaBMA7RsBB/JTlA==
X-Received: by 2002:a25:234a:: with SMTP id j71mr5243709ybj.504.1597426082420;
        Fri, 14 Aug 2020 10:28:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:cace:: with SMTP id a197ls3963880ybg.11.gmail; Fri, 14
 Aug 2020 10:28:02 -0700 (PDT)
X-Received: by 2002:a25:4d0a:: with SMTP id a10mr5212034ybb.60.1597426082132;
        Fri, 14 Aug 2020 10:28:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597426082; cv=none;
        d=google.com; s=arc-20160816;
        b=mXil+F8whHanOO5EKzeRXuGg/7XbGyCRJJKJofczd8ENujAKlt4abG8rPWoUzxv2Nw
         Od8JPdnKLJ4P7/03WELlS8iAUavqn6AxlTg5nMK42mefVcwkjK/JQ12dle/UDGAgOK8q
         YgMlksyZvP/XQG974pPeAh7K1TSKKUtYFVhMs1VU7aSGic9qeCtRfhW0qaOCh/V/SFPZ
         EDvjfHnavfFAqoz4I5P1xZEJZwyIve/pZKabbNTTGTQpuJn7tF1RL18epzIrovfxevJf
         XqOBM8QavFUPc3+ZxY2ttZiVZW2WzVMPeQJk4MAvv0ToEcrhVDGCptAGBbYDDdShYorK
         kNGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=l6ZIwvY6syyAP67b2MO5JHAbeJPBE9lyCC+sGAziw0Y=;
        b=lQ7xCo/SjKCm7u6SGVWc3RtUt/wtsWjCXMU1x2o2ExHzXvwQ1OA8wVzubm1k+NHbf/
         HIbnYf3ed8qH+32Q46AuIqG7wL8p5QHbKvzoWVrBJMyFqRFFTfeqG9RtrFm1rq/mVYHs
         LUmm8PCxTIzkp/JGE2E3We5JJMhzWn3Y1DjRZ/JHo3hyYPEL4TWb4ptYhwWl7uZfQavb
         YziCtdCoRXTAF0xmCF+3nNE1x8VZzp98+HFlO+bCCHZeNciY3QBF6w1wSyC0FU/QPl/W
         clnJ52dMkPVaxPaqeLHWXMUIHvgN1Da0JN6Sn9nJvMhOARWKH59bWfFxIfQ2Ud6Or++G
         PrOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=a+6DNaeG;
       spf=pass (google.com: domain of 3ock2xwokcraq3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3ock2XwoKCRAq3t7uE03B1w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id i144si541274yba.4.2020.08.14.10.28.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Aug 2020 10:28:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ock2xwokcraq3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id y7so6503929qvj.11
        for <kasan-dev@googlegroups.com>; Fri, 14 Aug 2020 10:28:02 -0700 (PDT)
X-Received: by 2002:a05:6214:1841:: with SMTP id d1mr3456365qvy.135.1597426081697;
 Fri, 14 Aug 2020 10:28:01 -0700 (PDT)
Date: Fri, 14 Aug 2020 19:26:58 +0200
In-Reply-To: <cover.1597425745.git.andreyknvl@google.com>
Message-Id: <e0683edc00699fcc0fc1fbc3cb1320875ff434f2.1597425745.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.220.ged08abb693-goog
Subject: [PATCH 16/35] kasan: kasan_non_canonical_hook only for software modes
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=a+6DNaeG;       spf=pass
 (google.com: domain of 3ock2xwokcraq3t7ue03b1w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3ock2XwoKCRAq3t7uE03B1w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--andreyknvl.bounces.google.com;
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
---
 mm/kasan/report.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 8ad1ced1607d..2cce7c9beea3 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -376,7 +376,8 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
 	return ret;
 }
 
-#ifdef CONFIG_KASAN_INLINE
+#if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && \
+	defined(CONFIG_KASAN_INLINE)
 /*
  * With CONFIG_KASAN_INLINE, accesses to bogus pointers (outside the high
  * canonical half of the address space) cause out-of-bounds shadow memory reads
-- 
2.28.0.220.ged08abb693-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e0683edc00699fcc0fc1fbc3cb1320875ff434f2.1597425745.git.andreyknvl%40google.com.
