Return-Path: <kasan-dev+bncBC5JXFXXVEGRBDXZTPAAMGQE4Q4ZR2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4496FA95B19
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Apr 2025 04:18:56 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-3d5b38276desf79234475ab.3
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Apr 2025 19:18:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745288335; cv=pass;
        d=google.com; s=arc-20240605;
        b=GzPyV7XiwJ8jxyo2TXZEfvfT2yQAE2G+tQERuojaXrls+l9wI6n86NXNTsRXJrW90M
         dSWv+9quI9L+AU2JWGTD7iwBWQYXdRw0WgwCHLrU4Bi4guMXjhTeZkCYz0IfOmSinx2E
         zxZtfd0HHYrSmnJx3Z8+JSoJffJ4LjJH1eVpt2Dy+ROMV+cIjRV04Su6HUQvocclYAWW
         vJZasXo9eSkNAkZAQwl6vCWw2jp4fpDx7o8nrUW0ZtS1c7+Ug/xqhGFb60JUX5dlIV6S
         MMq0BLZLfA/Lk5Bv2y9R2vCtY7+bBKXZAffYZh/mlUu9jSFUm9wpvnYbPkQQim9lK6vu
         xZUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=XMY517NRwMxBQi07lvTz/X4Y7SBtT3vxnQyjF1fVPe8=;
        fh=fS7dkasrVgtrjybBqv6UzJqs0j63baDE0qO8VsiYqOo=;
        b=d6pycaJ588EYaBNYVe7BhTXTwWmLlysV0f/ZtzXAv+tylQri+re7Ts7HWCy4ZOeOEa
         Pqfx54KPSFv7EthmpLRnaokiz0gufoT/pkeN5PWQ62u81uSXlC7o1zG7lq1L92M+XDmz
         Mi1+bp1aIdAK454ytqpG0ND9FIpcV+L4j8eNbGKLX55kFTxAPk2FH59h3YCtBXy8SpGa
         IyfRQgXsgNZAJusk5zrpsHiTtUhTeXRnwIJH1Flq8caV4KHmscPN7KLo4JMp3u/uawQU
         TTmdDhLZ2MPRYo10mtadwoB0ai54G+PSUnCsnKGUou4MIvnn/JCU2u1ellivcrOw566Q
         1f5A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Pb/bTzfs";
       spf=pass (google.com: domain of sashal@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745288335; x=1745893135; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=XMY517NRwMxBQi07lvTz/X4Y7SBtT3vxnQyjF1fVPe8=;
        b=skrpfkCcRnv9y3j+iZWna/IHmXvO0nkRp+Xs/ko2ZBJQtpXOJAscLJUZMiLMWn40K5
         v3rSRYMp9reCeYcsEpgo+bKFYcg8KiyOuSXg4iEGlvBwJJ2kWs4RjM7SGaCDR6JMNRMY
         0yQ/Nc1O7hIBZDp3kL17wWsYdTGrcC0prG3x3+B9pc465TyT9bkMYluO4GqFdy1YP4Qt
         8kIkxCjmIdDnebEGvAUwM5rtpF0hNoJzcaxXnxmLfmGeM5YHgig/0Qdai8t4OdvFhifs
         g8dJu6DZAPn6IDPBVGKrvzraPNqj2o8j6zk7e9WQulWhKhECwKp/7W2Yzaq6RTjeyx/8
         4Rbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745288335; x=1745893135;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=XMY517NRwMxBQi07lvTz/X4Y7SBtT3vxnQyjF1fVPe8=;
        b=oEXAP7cQXhGziFdxtuBGrWxkmZ+yORTXw2bCAbNtLUNkcy42UTpk/HHW+Cbvz6xdSj
         qzlYaySJGBpEimiikAA0Lq7iAnr9XSdGc5v6CcV+Y81DBBJ1B1eeMcPYYAuepLD/mLnU
         4SVPMFk/m2zA3nhbT4u+XbzIyN5uDbyZulqy4xb93pUlOxU3M8wGmONigyky/X1P3DXq
         itR32z5dyUcxpE4oUmG8h2us2b9j3UKF7gKJ6vYPcFDxLRM4NSA9ECaxwlriWOOZLkDY
         N+4j00RcaqxsupnqRy6iVm2wfa0KTeeIN50MEsVZKWZDntImQ06A81R6ofcZ7A/FuNKB
         rabg==
X-Forwarded-Encrypted: i=2; AJvYcCV+dBzuee2Qzlq5+7jLr1J1bk/Fz+CCsN1mLtDsqQ9wXusW8Px1+TqIE9RLUyW6g5cEn4B94Q==@lfdr.de
X-Gm-Message-State: AOJu0YzX16aNPfHq/3sOyp2Q2FTqUlXF0unIFQqdQzDhl8jazMA6FX4M
	AZOy0mzrFLQJ818MmQT8rW+lWPF8lBh29dprp//VHuEaREJ/+Jjf
X-Google-Smtp-Source: AGHT+IHPHqb1a4b21q7onD8VOl8tcTzko188cTenm3pI4oU8Af4ylDdKpUOZwL6+3FwiUrM2x4qA1Q==
X-Received: by 2002:a05:6e02:17c6:b0:3d8:2178:5c5e with SMTP id e9e14a558f8ab-3d88ee3b7afmr119806845ab.14.1745288334879;
        Mon, 21 Apr 2025 19:18:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAIDbiaKDJ9ByeRO7lsno3yA9/nKgeCFxNNFmSM7ThFWxg==
Received: by 2002:a92:c692:0:b0:3d4:564c:718a with SMTP id e9e14a558f8ab-3d81a81012bls24754815ab.1.-pod-prod-08-us;
 Mon, 21 Apr 2025 19:18:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUIfsE7F8rFX83yhHWTJ2X+gS/Fia+gDruXrqMBuNVdkJftb1beG9KxrR1HQFu3R2xwz2TxMFsoJJ0=@googlegroups.com
X-Received: by 2002:a05:6e02:2707:b0:3d8:1cba:1854 with SMTP id e9e14a558f8ab-3d88ed6e8efmr120500725ab.1.1745288334146;
        Mon, 21 Apr 2025 19:18:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745288334; cv=none;
        d=google.com; s=arc-20240605;
        b=DzpwhgXLRlXs/I+14ALH09bS7E9Zeq3YN7PL1O2ZrIDKa1VESzqnIuVYo/xfAsY/a+
         S85p1TErlqQfefqI5vuNT9zGzljLiwhcaisAYNqHIeRs/dvjxZQUOdd0i0788WRPLAn1
         VpAlvbvPlGkVnA+SiznfcPihMI5RpE0mS8NK0TaC9pYejXxjTa8ZUQUU1b/mm1YdrmlZ
         KXsqx0pf2T5q+Y98jMdFZ+wUKz4fsJ+OeB3lZJUz4q6i6VUV9ugqKn87hLG3kGFjxW6G
         ayeY7qaoueFWTWWtXzeRxRiBb0lSpl7VMHdbC4X1XbbhDhRh1wlwLIrHFE02qIbbvx8z
         woNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=GEwnyhGYCWqDJJ6IA5OJEoynsCfJdXBKAHkowqX/1bE=;
        fh=q02bgzixTNb497g9Wk7rN5TYnNlMKB/cWQBqqCg7OWQ=;
        b=I5B7qe0638pNou2ygTvGv+CMO21dGJdpXYP0czy2UMfsrvBIR0Sq/LHQXKD+IJPrQM
         /oFco9RqrDvj7EaEOjTvdZqvQpMoF4fcwu/LmzwT7yxZlgit+6SSISOs6EnSmW4AijxJ
         /1z8YqXmD8JBfTY9VkLLTmq+VPaETGW8gxmybR/igrXzuyaWomqFt+HjSfgTTYEsAa3v
         RH5cPJTG8qwnoy6ihC6UXUnjvrD43H6/YN1XCbQjTPda6hXSSZ72NTWjjbdgu/9wSFt+
         XnSxSy8qbzDOn5pwlFs0hhZAYZZazVp4qlXs881Mn4qJNBpgi7/d4VxvIqFVM1Wr5J0R
         nR/Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Pb/bTzfs";
       spf=pass (google.com: domain of sashal@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3d821d4acedsi3583145ab.2.2025.04.21.19.18.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Apr 2025 19:18:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 1041F61362;
	Tue, 22 Apr 2025 02:18:34 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 5DAC5C4CEE4;
	Tue, 22 Apr 2025 02:18:52 +0000 (UTC)
From: "'Sasha Levin' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Mostafa Saleh <smostafa@google.com>,
	Kees Cook <kees@kernel.org>,
	Sasha Levin <sashal@kernel.org>,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org
Subject: [PATCH AUTOSEL 5.15 4/6] ubsan: Fix panic from test_ubsan_out_of_bounds
Date: Mon, 21 Apr 2025 22:18:44 -0400
Message-Id: <20250422021846.1941972-4-sashal@kernel.org>
X-Mailer: git-send-email 2.39.5
In-Reply-To: <20250422021846.1941972-1-sashal@kernel.org>
References: <20250422021846.1941972-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-stable-base: Linux 5.15.180
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="Pb/bTzfs";       spf=pass
 (google.com: domain of sashal@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250422021846.1941972-4-sashal%40kernel.org.
