Return-Path: <kasan-dev+bncBC5JXFXXVEGRBBHZTPAAMGQEU2JNYEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 618EBA95B14
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Apr 2025 04:18:46 +0200 (CEST)
Received: by mail-pg1-x53b.google.com with SMTP id 41be03b00d2f7-b115fb801bcsf1485213a12.3
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Apr 2025 19:18:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745288325; cv=pass;
        d=google.com; s=arc-20240605;
        b=bChNNaRQtgUBhHKVCupE4Q2tJwspkVVS+nEjOUT0R21CM0o504tfAy13pfiPt/YApy
         B3jppUGFnrWvorjfonIZdlNDLEDo597hG87HY81ryPDC0xz43spoYAU8KqVW7cAZv1yP
         WTlWOO7XxxL90dkc13jwLtIqdRQM/GCw0RFxILH9ah3L+T9W5KZ7Mo2+ksFAVSoTiMTe
         R/6qbVncL9P53zd4T+32iBcvUW4mJZ9ZQakPt61WtfMYJDplmixe4X65/GGhFO/Esf1s
         /M4QmJXm6wLlYWdZ5Sc3+KKjnTYf1u+8g1/VKlTM45X5qrpxh+3h9aP3gWHQXLab2yVG
         VTeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=fYRBPEzQgRScaX90facNUe9L6f3MLHxNuObEWsSfmh8=;
        fh=52Fsz9zCM8YFBd20hTcgKDhUoWirosHSpJTlszdjoM4=;
        b=iBP6XDx73Us6S0RoNraGMGwMK2m9RMr2Wt9MJVp7fHm0NTCLLBtdXz22bGzPvkbbKB
         dnjGnp/dKbvTAU86se+u4FU9GUw41QC1fD0O7YYuRk19aLsS7qY4o2qOwTgLMMy0Asle
         ipM30HjPbbxFjcYAhk9evQ7RCZCDeRIuzrEy+kaUuddxM8bX6CQ91w1Vkmhwvt1ieXCp
         COfSYed5/v1yn7LC6OJjN2bAABzTpX2NOPKGQQXdzDzL0YsUBY4TNhu9q7XwI48HPYDX
         1dc/16tzKUWSvY1zqh1sMMYNbYZK2yj5BFlqt6TM+20fEqPxevwT3WQ3UsLTX7gSEtN1
         L7pA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=N8p82v3o;
       spf=pass (google.com: domain of sashal@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745288325; x=1745893125; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=fYRBPEzQgRScaX90facNUe9L6f3MLHxNuObEWsSfmh8=;
        b=UKDzlNrCppoYv7b9MSLeiNEGcZ0YuSno0Ux9MgTEG1tcnwN+sRFyEGAJXj72uxodPG
         aiEn/mHwZS5XRBnF1IR/MdJtqwqrlPPZ8Vd0I78WvKWdWwr+V9KTEj6071GuVHUHRjJp
         N2+yk9gC1tsXwUQw5yGydqhVbtBIRalqMxa6Y+Vp3oRTxujGVB35edfc5mYXOI4Si0WG
         jRApLyJ0SGBX7n0GM8/0JfCfQ7DEs1l3uipfhWUVeY6Nn7QcRPAoJy3fCjWQ5mIWzToE
         uOwQHDGQHBhdfmCG6BW9rN6G1vY9IjnbRs70ed6MKu9BlCk8UjTm2VqW38EjinAKKbDn
         A/5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745288325; x=1745893125;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fYRBPEzQgRScaX90facNUe9L6f3MLHxNuObEWsSfmh8=;
        b=i86F2MxccOO8fF/x1Vvi0sFFfNSIel4hbZyuP/wxS+v5mdWf1fsqKDPfO4dmW6s+5q
         52UzX+GchFsnV3xX3o3n9dMpQEYxsrI0v5eyPHhCXyat1UoAOWUGGUINNhqnYf/v2Nm2
         sSfCkuQMMgU3B1xwwfBGYIJvXkOJJ5pJT00vSJ71/sUaSHPNocvJo5CzgQa540sJ9+A2
         wyLe1j99pmmMXv1IXktGZZX1GHEk4wFgBflJVxWrLQdcZ9N8eDaUBiFAT6CU4WDYFdg6
         LtcnT+D+uE/JWBgFpmr8qTMEtKHR6J54ohbM6y1ba5B6V40NPcy2BQ7TdbdZtkeHMjlj
         DS4g==
X-Forwarded-Encrypted: i=2; AJvYcCX6gJVTmmrNdEkzfOM8sE1Kkd+2unLJ2bZHI9aWzL43pBb41BRMMbg7uiZGwXgmJuwd1MYtsA==@lfdr.de
X-Gm-Message-State: AOJu0YyNkL/KfRnKn7c2EO+7WkmlXoL9pV4jvwK5v1lMSoo88edVJNBY
	22ByMMUUDGCy1hZO8cARy7tOfm1zvXgx1UhpLrHkRQUvQmN4km/J
X-Google-Smtp-Source: AGHT+IGGAmUDxf06arhXbfjHPkZ3esNU+MrQhFVZaw48OxXJ37pM9sV/o72NffjCMdnsz+WGJw70ww==
X-Received: by 2002:a17:90b:1d4f:b0:2ee:e945:5355 with SMTP id 98e67ed59e1d1-3087bb6e7a1mr18743891a91.19.1745288324677;
        Mon, 21 Apr 2025 19:18:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAIG6KSbtrDqgOCN5W1Vuezm6afVHUauuIsYNm87ehUXLA==
Received: by 2002:a17:90b:4a0e:b0:301:aec9:2622 with SMTP id
 98e67ed59e1d1-3086d9aeec6ls808114a91.0.-pod-prod-03-us; Mon, 21 Apr 2025
 19:18:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUGzc6QFkVhuJGoqtoOXg8OVievQcv/0+0zn4HGK+xOCQ9uzPLiMmofTsEYxXuYO9SD+S7poNNb3Tw=@googlegroups.com
X-Received: by 2002:a17:90b:2412:b0:309:be48:a77c with SMTP id 98e67ed59e1d1-309be48ad09mr10066983a91.18.1745288323367;
        Mon, 21 Apr 2025 19:18:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745288323; cv=none;
        d=google.com; s=arc-20240605;
        b=Qo936moc4aIghSVl6CJ/lMDIb+pg4nQxVvt+xBUujkIUsAaqfUG8wGbxyhZrB3xT/j
         N3Q1nHU78jdPUvhGNe/mnaA4CyWjgmFomY6GJBLUIZfN8gQKOH3TIU/FmuLul09tvw+x
         1cvmEMTdYTEk0mm3XQQp030GfZNlYvueLwLK57BB/YZpsD9X9FpkYZ7QyDgtwEP26+UP
         bI4ms4f74pD/PFQL48FNcFRgI39xokqEBm5DWlF1hfBuIGQR/EbRggy5FpcGu/GCh2Vu
         kZ0dAJqOSFhqOxbVyd5ohilGgu7cPywvwVHghtGiifkl+6HfiaWUbYKvhhZTuRevI3au
         s8Jg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=GEwnyhGYCWqDJJ6IA5OJEoynsCfJdXBKAHkowqX/1bE=;
        fh=q02bgzixTNb497g9Wk7rN5TYnNlMKB/cWQBqqCg7OWQ=;
        b=T0gobajH5Ovb7wTkWiZHqvi57Vvt6ihsM6a1RrxlccfMoahaUwKznTKDj+rota3BnU
         TGNJnPXKyepJItM+YImsCU2tRb0HJ7bQ0lKU/PMR74aNhf+SCX1MIWDWSuUJ1Q488U3f
         pQ+Gl2OM7gLCDRc2P5EpHM3VIpOTIoLGKDEwjMFF/xskbnSoOXSDBw04v7Kp7FHD6sur
         uZaXqRyTjYZeQPiih9QzDV9/qLvVjFskcETP3rKNYvMz+8sfykXWa/4Dis4oyh9nSQg3
         lBOAdl0TFgZ0xTRdfpAyG3wgqwlvH9uLlbF9Bc+eTYdgZQGDmXY8QOnx2X48tl/BszjS
         /dLQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=N8p82v3o;
       spf=pass (google.com: domain of sashal@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-309d343e360si35200a91.0.2025.04.21.19.18.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Apr 2025 19:18:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 86BB66116F;
	Tue, 22 Apr 2025 02:18:22 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C17A2C4CEEC;
	Tue, 22 Apr 2025 02:18:40 +0000 (UTC)
From: "'Sasha Levin' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Mostafa Saleh <smostafa@google.com>,
	Kees Cook <kees@kernel.org>,
	Sasha Levin <sashal@kernel.org>,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org
Subject: [PATCH AUTOSEL 6.1 09/12] ubsan: Fix panic from test_ubsan_out_of_bounds
Date: Mon, 21 Apr 2025 22:18:23 -0400
Message-Id: <20250422021826.1941778-9-sashal@kernel.org>
X-Mailer: git-send-email 2.39.5
In-Reply-To: <20250422021826.1941778-1-sashal@kernel.org>
References: <20250422021826.1941778-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-stable-base: Linux 6.1.134
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=N8p82v3o;       spf=pass
 (google.com: domain of sashal@kernel.org designates 172.105.4.254 as
 permitted sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass
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
index 2062be1f2e80f..f90f2b9842ec4 100644
--- a/lib/test_ubsan.c
+++ b/lib/test_ubsan.c
@@ -35,18 +35,22 @@ static void test_ubsan_shift_out_of_bounds(void)
 
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250422021826.1941778-9-sashal%40kernel.org.
