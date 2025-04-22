Return-Path: <kasan-dev+bncBC5JXFXXVEGRBPPYTPAAMGQEUM2RWCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 4FD6CA95B01
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Apr 2025 04:17:35 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-3d5da4fb5e0sf45791905ab.2
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Apr 2025 19:17:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745288254; cv=pass;
        d=google.com; s=arc-20240605;
        b=UZHmLBed+dy/FMnufj7oilSmVTilkWIsxFC1iR2f/I3OPn7fny5HJrUyPbTS7CIUXB
         p5wAA0/6/csxGsdj6tpsGVKOoXHIk2CChSzQr88dt5OJ9gTr80F07YoIRsmeTODHUOYQ
         Tzw4jovjWj+CkiKrGo2X5YGj9BxVe3yhGrbWpbgyt46KR9Gb72rx1Ct3nrQZRrg2Qzyg
         abeXT59opl03xR9fkkPYn+RkHyfYJi5yu0cuS+fEG+SN4gngw8WQ3eoPAu52GmBobD9n
         aLwmqb1bsHaXTr9Ho7MhFNFb0LlP/hR1ZVyXUsS7+esXT92TCIAFvLaAa/NPTnPL+2il
         k9hw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=bXP0gH3acUjyY+VRRIdepjuEiCbxgEwqhE+aA6Dpd94=;
        fh=fLn6f7UVMXO01gz64gruZs1eAj6Z/8oLpOH5TK6UijE=;
        b=EORKBXhcyYkiVZUB2AmEKsRNnxC+gsLJS/DthUHkbcmRzcf0vreHxJotG0awKgtTi/
         mLXAVRn/UqL/yWb4eXjVgQMoPWygujOynibVb3YmHJKYIH0eSpSCeWfkgFBJIsov841a
         OZdaPMHrPtaFE9ic9sJdEmrT9l5rX8dG30yOmgkKkaZnUQ/Px0YSIcSCba4UHjsy9Sln
         uk78JHVwTrZ5T6uTa0uWfWXPyPkjub7IknTXPEaM6Ijn5kIhaJsSPSCdSayCqfSGpWjX
         4GYHRXFLSM0FagepdnyI8CWuQV7Y2Tnr/2XaSc+sdzNDIB03f6Mw3SXq6nadNXRhX5x7
         ++Bw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=cR0MHCt+;
       spf=pass (google.com: domain of sashal@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745288254; x=1745893054; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=bXP0gH3acUjyY+VRRIdepjuEiCbxgEwqhE+aA6Dpd94=;
        b=VqbsmcxjWDz+YVXqrUjMLFXlO8rZwZZ7q08ZW036JQNtDvuKm+8NMa7vXl6xxLXbci
         MysCnNcx55xLWDX+m6n9Cgva+aveCJ36XrhUPd22wL3c9NrL6qhFH9sIz2rv71wNzc0G
         THPfA3nSWDT+BVHhW3pxbSbCUp1wQhGtgbAZklRpkxj3Pj8N3TImmikJYczwwu0DP+lR
         uTVOjAU3S26fKCMIaIe8eWYV5pV3trqMW0IbHRBzPkkfDZIMSNfN5pfURb1bBUuyzwr7
         dTLZOO9x4pfr1IPgujF3gvjxPleXqQDAU0TcAc6/7OmZulowArOfsKP7zw5/bUis64fS
         zLwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745288254; x=1745893054;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bXP0gH3acUjyY+VRRIdepjuEiCbxgEwqhE+aA6Dpd94=;
        b=ih/WZit5AE8F7SatNB6wLVlTg4ZK8HUA63zwWPmt8qrjlOJSJSEHv95mTVmITg3nHP
         WkZyli0aLdASApqUqVsOznfFNlHBZ2Mz01nYr+pAXPLPRObFPggK3bfG6GgE/5XuoNEn
         TA/R9B/2Z46RXpTyPXrGOGitsLLJalblhHVpFasd2k/Q9rWs/hhH5GJrxswbHI03qSRc
         h1YZIEcvPRisIePtx6bNxk1hSPhbiIxR990i8+CPC3Izcoay2AnN3oY5uJhlN+bDZHhZ
         Pw0H9HpAyFytBjCOvyVLXHlEoQ8JX3Zs52Q4r56Xl04gOtFdTmSCjo/7QyMLfMKSfUGK
         awiA==
X-Forwarded-Encrypted: i=2; AJvYcCV2qUy4fD3sVAr5Ozph6h4OGZMfdSYwixNFKXa9KCgf+Yqow5Y8JjffVinuUjVjjmNs4GsqWw==@lfdr.de
X-Gm-Message-State: AOJu0YyWrzmQI4VgfZIOTERumbJ211bLQxq8+YhCIGetIcil+RlijSIE
	KZGEGAbRAVMDtKv7l/c6fuCg6iC2kHJnPODH7SQ5YWBVtS4pqHQE
X-Google-Smtp-Source: AGHT+IHavmblHCKC7uWXSnTF258iypAY+ff3Uz7/Xx73WuwIR7Hoih8MLbcynfv70cfVsl9aGwE3NA==
X-Received: by 2002:a05:6e02:3102:b0:3d4:36c3:7fe3 with SMTP id e9e14a558f8ab-3d88eda0096mr126524965ab.9.1745288253700;
        Mon, 21 Apr 2025 19:17:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJCAJbsjVzXRVv5QyX20l3PHNJE+w4s1TvoHATW9DBJPg==
Received: by 2002:a05:6e02:80a:b0:3d6:d838:8f38 with SMTP id
 e9e14a558f8ab-3d81a82514cls25824095ab.1.-pod-prod-06-us; Mon, 21 Apr 2025
 19:17:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVuM+ZHa8ZWGMFByRpfYvxYFR2bRAIlTnLUJ9iH0okrVQgTaAw0Oq0uO24kbRDFcpqcXTLqaxZXkqw=@googlegroups.com
X-Received: by 2002:a05:6e02:1d8d:b0:3d8:1ed0:e167 with SMTP id e9e14a558f8ab-3d88fccbc02mr122259775ab.14.1745288252777;
        Mon, 21 Apr 2025 19:17:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745288252; cv=none;
        d=google.com; s=arc-20240605;
        b=iMq+LkKAcTAXwI6Iex7u9/oisne8VtYkuAaWeq/45o1x18KJAx/O3gNG/vNy8LDEfG
         199ohATTY5C3QVHPgxfVmYjRcboJG7nBWQvLHrzrJM5Pa83ogCgk3oHTqwI6QUgPZvCw
         LkGLeUH4WoIBWdVTZPmuFDxftGGsDVNcAV2k4XKSCmCpkVmlTYTw72Tj9fHlG4/V28MI
         H+IJ/XLpE+7vj06R62usH2xDh7ew8SnwZkk3dKrei6P1DkH7E+Pr59ho+wwYdKY+9UgM
         GibcsPM+Z/2qMKAE7sb3xW+83xn0j9P+sJ/OuR32Pew4BtBA0w0SOD+z+czTp1HqR2+E
         DnNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=JfnGb6PirAI9qCPRLsAjMCiOOhe/eKwRgKvFzKYSzZc=;
        fh=q02bgzixTNb497g9Wk7rN5TYnNlMKB/cWQBqqCg7OWQ=;
        b=V2lW0j+d2HqVodzeDa4qbhwPfSmVI6rOoI+kkW62PD6J6Iimoyt1XXCuktA/40OYFC
         ETZbN91NHJx749n++5/++gRUta1z+QkIjEYo0nCjLW5RZJBl2Kw71P3+mYiAnWT81x8h
         o4ZonHV5HVl+6WcTLLYZhwV7IxRbnTagbxVoVKcN2AFpwj6Z3WL+bl7SeeWQZZGGyNrC
         1kiD8DRRTFY9OL1ol5Q+74amf5c2oVG8tom38Bh+5zki7e46n1SztFcLFYEofBI7dulK
         TQCIx5mzU8+tUMjpS/VJpad48rH+57DhJvRAj1U6XhPlN9znKfGRQCePFY5ko7k2eiOy
         iGdg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=cR0MHCt+;
       spf=pass (google.com: domain of sashal@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3d821c61cfasi3610015ab.0.2025.04.21.19.17.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Apr 2025 19:17:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 83FEA437C2;
	Tue, 22 Apr 2025 02:17:30 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 06827C4CEEC;
	Tue, 22 Apr 2025 02:17:30 +0000 (UTC)
From: "'Sasha Levin' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Mostafa Saleh <smostafa@google.com>,
	Kees Cook <kees@kernel.org>,
	Sasha Levin <sashal@kernel.org>,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org
Subject: [PATCH AUTOSEL 6.12 17/23] ubsan: Fix panic from test_ubsan_out_of_bounds
Date: Mon, 21 Apr 2025 22:16:57 -0400
Message-Id: <20250422021703.1941244-17-sashal@kernel.org>
X-Mailer: git-send-email 2.39.5
In-Reply-To: <20250422021703.1941244-1-sashal@kernel.org>
References: <20250422021703.1941244-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-stable-base: Linux 6.12.24
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=cR0MHCt+;       spf=pass
 (google.com: domain of sashal@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Sasha Levin <sashal@kernel.org>
Reply-To: Sasha Levin <sashal@kernel.org>
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

From: Mostafa Saleh <smostafa@google.com>

[ Upstream commit 9b044614be12d78d3a93767708b8d02fb7dfa9b0 ]

Running lib_ubsan.ko on arm64 (without CONFIG_UBSAN_TRAP) panics the
kernel:

[   31.616546] Kernel panic - not syncing: stack-protector: Kernel stack is corrupted in: test_ubsan_out_of_bounds+0x158/0x158 [test_ubsan]
[   31.646817] CPU: 3 UID: 0 PID: 179 Comm: insmod Not tainted 6.15.0-rc2 #1 PREEMPT
[   31.648153] Hardware name: linux,dummy-virt (DT)
[   31.648970] Call trace:
[   31.649345]  show_stack+0x18/0x24 (C)
[   31.650960]  dump_stack_lvl+0x40/0x84
[   31.651559]  dump_stack+0x18/0x24
[   31.652264]  panic+0x138/0x3b4
[   31.652812]  __ktime_get_real_seconds+0x0/0x10
[   31.653540]  test_ubsan_load_invalid_value+0x0/0xa8 [test_ubsan]
[   31.654388]  init_module+0x24/0xff4 [test_ubsan]
[   31.655077]  do_one_initcall+0xd4/0x280
[   31.655680]  do_init_module+0x58/0x2b4

That happens because the test corrupts other data in the stack:
400:   d5384108        mrs     x8, sp_el0
404:   f9426d08        ldr     x8, [x8, #1240]
408:   f85f83a9        ldur    x9, [x29, #-8]
40c:   eb09011f        cmp     x8, x9
410:   54000301        b.ne    470 <test_ubsan_out_of_bounds+0x154>  // b.any

As there is no guarantee the compiler will order the local variables
as declared in the module:
        volatile char above[4] = { }; /* Protect surrounding memory. */
        volatile int arr[4];
        volatile char below[4] = { }; /* Protect surrounding memory. */

There is another problem where the out-of-bound index is 5 which is larger
than the extra surrounding memory for protection.

So, use a struct to enforce the ordering, and fix the index to be 4.
Also, remove some of the volatiles and rely on OPTIMIZER_HIDE_VAR()

Signed-off-by: Mostafa Saleh <smostafa@google.com>
Link: https://lore.kernel.org/r/20250415203354.4109415-1-smostafa@google.com
Signed-off-by: Kees Cook <kees@kernel.org>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 lib/test_ubsan.c | 18 +++++++++++-------
 1 file changed, 11 insertions(+), 7 deletions(-)

diff --git a/lib/test_ubsan.c b/lib/test_ubsan.c
index 5d7b10e986107..63b7566e78639 100644
--- a/lib/test_ubsan.c
+++ b/lib/test_ubsan.c
@@ -68,18 +68,22 @@ static void test_ubsan_shift_out_of_bounds(void)
 
 static void test_ubsan_out_of_bounds(void)
 {
-	volatile int i = 4, j = 5, k = -1;
-	volatile char above[4] = { }; /* Protect surrounding memory. */
-	volatile int arr[4];
-	volatile char below[4] = { }; /* Protect surrounding memory. */
+	int i = 4, j = 4, k = -1;
+	volatile struct {
+		char above[4]; /* Protect surrounding memory. */
+		int arr[4];
+		char below[4]; /* Protect surrounding memory. */
+	} data;
 
-	above[0] = below[0];
+	OPTIMIZER_HIDE_VAR(i);
+	OPTIMIZER_HIDE_VAR(j);
+	OPTIMIZER_HIDE_VAR(k);
 
 	UBSAN_TEST(CONFIG_UBSAN_BOUNDS, "above");
-	arr[j] = i;
+	data.arr[j] = i;
 
 	UBSAN_TEST(CONFIG_UBSAN_BOUNDS, "below");
-	arr[k] = i;
+	data.arr[k] = i;
 }
 
 enum ubsan_test_enum {
-- 
2.39.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250422021703.1941244-17-sashal%40kernel.org.
