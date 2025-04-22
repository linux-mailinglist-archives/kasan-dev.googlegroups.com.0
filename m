Return-Path: <kasan-dev+bncBC5JXFXXVEGRB5PYTPAAMGQERD7FWEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 62481A95B11
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Apr 2025 04:18:31 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-2ff7f9a0b9bsf4077829a91.0
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Apr 2025 19:18:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745288310; cv=pass;
        d=google.com; s=arc-20240605;
        b=LAsiyPzDzDUmKr2tN8C4X4ovLKbvRaXb6yDKQtmpCES8a9oLwUE4GOkH+IyEr6xfTa
         /ySrvxLjjs0dlgk2rkjw+qhm8lkdQdKfyRXVPghvJeZtgWPJBb/qVULww8KNpymE2l5c
         9c8WHMxmtGEKjG3EDBkwFrPd2qLqrFisvAU2zgc94F1cek8NWKCLUsCwQYHssqs2ai7u
         03ZnQmTjrj8iSAUMmieBEfToByD7MqU7jCNDR20L2TaaaeInp4XMJYxLoxlih4951K+F
         bZG07Z4py8i+8bZRhCMvCSYwHga+7ZAuT8PWU/G+t4xMOSFC3Y4KeeKM2huKZpLNBuJs
         kYgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=49c2EGEmB/kiQrx75mJKKZsHgMrJSqEJt8TXC2Z5NgA=;
        fh=OT5N5tLvyBQhB1KrC4LHH2VJlbZPmHDMjjTF1eDklyE=;
        b=PISUcb8lQ3oooQYG1Ac2of6vLuOmkYqqhhP3/nm7vAs28QNYhTUOsQVKruVqaxsODe
         1tkId1UwjlkCPDQQnXlW2fWq0VcDaZHyqsJQfi4AgU4c3kUPL8E/7ihgodxAg+cVVdiT
         vjhDZlYn+Ay61gNQyzRrxIGxa0PXjmiXFYgKSsWQtLOEBZrNAAZmdZWqBCk9JLLhy7+H
         yvtze8kCJ6yVTes2zsnaYB89i0BSlCG2oMTEuMP+WJ4VcElDaCy2H5RAETlBinRbw3Qc
         xyhnCR3UW2t2Y6s+Lxj0o8ZsEdRksQjBRxr5K4jM67wdx4puu6u8wKpAKEmWf16Ju2Yy
         hYzw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=W7ddVIeC;
       spf=pass (google.com: domain of sashal@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745288310; x=1745893110; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=49c2EGEmB/kiQrx75mJKKZsHgMrJSqEJt8TXC2Z5NgA=;
        b=AH9JziqSlO9KHny6g9VFF/NeQWufdqBOGh4uPLAphe+lIOpshRmvOFk6j7V6XonIwq
         YrSZSlO9iKUso4xc2k2z2TWo5VCSHFlEtAtNi3nGV+n+NXsOxEi4q0WrKQzAoM0Jipiv
         Ap/dI5hQ4+CiRq8wn3KFi3D4xDxWEnHUHD5RqIebDC6W9g44kYl60ny3LbH92rlqU7wL
         rcGruB3E197QV8dQPvcdsNGsoGXaI0omgRhtWeM2XK6TK7CKOcoicm5L58ZdXzmy8s6Y
         8XOpHVn6pI92RO4gZ75CMP2YteQ0Cwr7oNZQu18Qa+1XTqovVqmnVGZIxUw90Q2z2Iql
         +CDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745288310; x=1745893110;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=49c2EGEmB/kiQrx75mJKKZsHgMrJSqEJt8TXC2Z5NgA=;
        b=dODLCAlO2XoOMz/DSF2sldLb+U4P6v3/Gr6PXFfoWkOdl3fO+Vtz+9BeA4EN7TvVCf
         SbGGOJJJgDgmWJESMo79Nch/ZfFUT6FZGSfOHmGVqMluAAhfpOSUYdSLSxRMhzkF4VgX
         j4d6lHr8OPdKJ5pm06bhFHdA4i0j0S+8yot6GW/edei9Fjk7rx6sd4T8W1N8VrFNwY1h
         3dXVcxY+FXMOGudZpsIIOm6ZxdNjYqanOf+uxMdeDEGJ0S6eP0CuRpSVJo/+Z92Bl2TS
         yUrQxug7EfVuljOntcuckzg6AF1LH+6As02Ztj1rIxDURGPEc/+IqJALWDKlCr13X6Fa
         vJuw==
X-Forwarded-Encrypted: i=2; AJvYcCXfCjZD9108img+stn6b9A3HpWufWD9i94tfA7O2PANXtdcGlNQmA84AgSQKWGdjrdXyr+crg==@lfdr.de
X-Gm-Message-State: AOJu0Yx7UUnpfn196g70ScQUzEvWmK3ygYXja5yhgrjPiGPl/U7WI+9b
	fd1ueo5KX8uMT2X2pI5q6v+YFT0+fUmE9trmlVtgs+LFv9Iql1dH
X-Google-Smtp-Source: AGHT+IEG+/QPQvXi77Yp6gf980ViDETWmph0zGgyaakIlJi5gbrBCIAPFm9kO8+al9BnQSR1O4EYcA==
X-Received: by 2002:a17:90a:fc46:b0:2fe:b907:3b05 with SMTP id 98e67ed59e1d1-3087bbb6abcmr19351815a91.29.1745288309625;
        Mon, 21 Apr 2025 19:18:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAL+OCL3udc/W7DHBoW11FcWrj/QP3Ch18FU1bQDqWroSQ==
Received: by 2002:a17:90a:ca8e:b0:2fa:5303:b1e3 with SMTP id
 98e67ed59e1d1-3086db124c0ls10324a91.1.-pod-prod-01-us; Mon, 21 Apr 2025
 19:18:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV5rVLl5w+JGXjAFGto9Kc6BbEBHvSCD6959Im6lffM5EGRzuvm8HnoDZOxcq/UU3r80l+YSkKoLX4=@googlegroups.com
X-Received: by 2002:a17:90b:280b:b0:2fe:b470:dde4 with SMTP id 98e67ed59e1d1-3087bb48e31mr25835138a91.12.1745288308258;
        Mon, 21 Apr 2025 19:18:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745288299; cv=none;
        d=google.com; s=arc-20240605;
        b=DdHN7FGWfW+ByiE2cT/PxbPOHj0OXqMGSOW8jU1XZ4exCh2zyHAen2f3iwjnrKMOE7
         /AuYyPJvCh12hy/lpZazy//IyPr7elDZGCpQGJ8eapeMYgBqGrqvM3IHJFZ4FZGiemwH
         Ivst9gLABfdKKLko5OrQ7qH9jtRx7XOx0nTWM4sObf01OCaBNOSlvKkJRpG0va/mMaw3
         cn9mysfeA0S5voDaS538dIM8FNtMgsteXy0n+mtgplI5kMUUzTEiGf196rXf+6erz2SS
         D+7VKmhacQ44+6pv0pdkjxW7GDloauXffQVtNyTxg8DxhFkDrKr6ZsNU5cAhCF+mAP9M
         y5qQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=GEwnyhGYCWqDJJ6IA5OJEoynsCfJdXBKAHkowqX/1bE=;
        fh=q02bgzixTNb497g9Wk7rN5TYnNlMKB/cWQBqqCg7OWQ=;
        b=gIVYDgt6JTlqF5C5m/kDnhm/+gZwnarbA1UFNcXVYqBe9eQvAv3K8D5YBdFeStpRww
         2CIdVYu4phXhBGA2Z5x326xGlSHLpqAlLKBpK7NxHhn51oXXHBkK6U9zgF+GKRnjNI0i
         WLskCg5juWOG1va+cC/30PA4MqugByrMhLMFdMOrSetjXKgRkn8y80+LL6nbqm8y+qdD
         ElNaPCHIUiKO4nNM8OYVy7aVEyHSwMUe8NKiRokGE7kUzClo09qDns8DhGE/OFWIqMS3
         T3nCtUPo4YFQd8YhM5FqPNWSzFY9W2Z/WXZe4vCXWFgINQjtt7uApjwSrx0eUDCn5ula
         FQfg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=W7ddVIeC;
       spf=pass (google.com: domain of sashal@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-309d34b4642si23715a91.0.2025.04.21.19.18.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Apr 2025 19:18:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 69AC44A79C;
	Tue, 22 Apr 2025 02:18:17 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E4E3DC4CEE4;
	Tue, 22 Apr 2025 02:18:17 +0000 (UTC)
From: "'Sasha Levin' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Mostafa Saleh <smostafa@google.com>,
	Kees Cook <kees@kernel.org>,
	Sasha Levin <sashal@kernel.org>,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org
Subject: [PATCH AUTOSEL 6.6 11/15] ubsan: Fix panic from test_ubsan_out_of_bounds
Date: Mon, 21 Apr 2025 22:17:55 -0400
Message-Id: <20250422021759.1941570-11-sashal@kernel.org>
X-Mailer: git-send-email 2.39.5
In-Reply-To: <20250422021759.1941570-1-sashal@kernel.org>
References: <20250422021759.1941570-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-stable-base: Linux 6.6.87
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=W7ddVIeC;       spf=pass
 (google.com: domain of sashal@kernel.org designates 172.234.252.31 as
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250422021759.1941570-11-sashal%40kernel.org.
