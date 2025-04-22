Return-Path: <kasan-dev+bncBC5JXFXXVEGRB7PXTPAAMGQE7XZNBFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 05590A95AE9
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Apr 2025 04:16:32 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-224347aef79sf62690155ad.2
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Apr 2025 19:16:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745288190; cv=pass;
        d=google.com; s=arc-20240605;
        b=SQnunei4WNJkdSFqQdFme0rT8/u3a1zl9HpGJKr1f2cruueVLv6FKHCjaCIsOdj8El
         wowfSOb+CdokYrgmrBxPGo74QNNy9FCUImBtJF5qqFqQbDZ4xv6zhFLh+uhxZQc0Og/D
         ejFp4m8rCeeQNY1ww6R9AOwqqrInHB+QU1zDf3/F7xGq2dGxbsNMQREUiFdOeC34cknX
         Xhm4EadcbEWMTv+Fw2HZfUymYFt2e5jsgCz4BUErgXNqB/bb0RSzPTaB0v/saHuGKfch
         5HlbUuZzext5wHZxDW9ZMB1kbDKOnUeRj+UQmhjHQFlbcMAZbxxQEGl1QsVa4YqFdY7a
         hTuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=mpMj4OOlzC9EXhYusZsgKwV/NYMO7Rzvt3V5UxEzEdo=;
        fh=uWDLSlLeEsHx4GHqpIs+TTyrNdyjSDeqky2ETSLJWHI=;
        b=i8JbO2RW1vd6lmhviVXhjqL4ob8X4QjQcNRvHGnV3EuwF88eyKU1nUY9wn1tW8Vd/8
         FR/feKToLBXbJgcilMEluHhWRYWY6/MOXEV6kTLLnbYOmhU6b/LK9lK9xbWgOgemiCHa
         KX23991MJ2nq8QD2n6C2RTRvqAKJpJ6hoGdg1UmScmsW8/Zm6uUod+wDtkORuAxmIs6j
         zOwmDDYdCokz/i8SLl8wsb6k9CfF/6iNFcQeUBCP975sTmKoREk6Y+LQNUNRESk2ibKp
         Cr+KBXLAqA91ae4hhCXZZ0DxqDFIKS8p6T85OPutwh54+GPViiV4WImwBfJvyJ3/7UYH
         I+rg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ST5r1nIy;
       spf=pass (google.com: domain of sashal@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745288190; x=1745892990; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=mpMj4OOlzC9EXhYusZsgKwV/NYMO7Rzvt3V5UxEzEdo=;
        b=AtN1XtNaHvNBR1ije2fBYw7hEguHx9sVnJBhvQRug4NLQtrWYQ1xhZz8+vBSZwKsEu
         yiWNqip+ygedA5sfxNxugIRjV26B+I7StTsKHz4geamslLwTdGgp0LWnIXs65dz9Ot45
         rMIs6LlefIH+R7lh+yLliBUEOMemPGy1QYmrHW1es5cG3zRfUGB5V0Bh5j1kqjnAg++5
         W3zTkT1W/GyrlKs0qo+6LZG0ACoauCCP5f59IkWlAoBYF9HaLVVCXZsQbf3Duuvxi9ar
         P4/hmpKLIC844FU0znQL9lN01rsBS5NNa+eefzkrub0pScV7jMwaaPslLPi6NuXVeK91
         EPIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745288190; x=1745892990;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mpMj4OOlzC9EXhYusZsgKwV/NYMO7Rzvt3V5UxEzEdo=;
        b=HgsQkzQi7ncjBU7eon0UlY+86fzpJXwlqi+zgvMTjWpyvIZcSMtifBZwCr7k3nnoNc
         7VmCF0g0Xh9XipjUMUGHnkB4SclwpcLFmvZCXqWd/yU87ppvVP8aUt1tRLYyeUwNavA8
         eSIDt0y+jhv5m4nY5keTsRfKz8BFBdV+1b3pavmHCZB7X/LYkyvxSH1nEBETG33o0X7N
         lvc6vNNRLqImvVhnRe1q8it++Lk/Jhi9Wyi+tYnzJ12Ofqiiv57acuVNlHY+FLj4fVUi
         NEo0dwW/c48ejbKKT6YED+Wx3Aa7GBqaBcG8ntU/XkDd4ssdeqbAozP41wYBUMOdStQ2
         ZERg==
X-Forwarded-Encrypted: i=2; AJvYcCXjBkGE3zj4HfhTe2AhZVohvPDixDLLprBxCzS0jlS3F9G03OAcs6tkHQJ5E//umKRrT7qYOA==@lfdr.de
X-Gm-Message-State: AOJu0YxrH7f8l7+SrjflNZC2VKIUIgtyQ6wZCyPz+jTZZuPsAw0HqtSi
	rqXfUox7Eftex0JRw8/I+MK1zAfn4KLusGIyzyfcSOCZeQ+JMBzV
X-Google-Smtp-Source: AGHT+IFzUhYK1IkqVFPfAxatEE6pFesmV1gOH0D4pKH4dFB13YcCvv29djFmV6Bw4/ufh/wG0cN/7g==
X-Received: by 2002:a17:903:41c7:b0:220:faa2:c911 with SMTP id d9443c01a7336-22c535a4b39mr188111935ad.14.1745288189441;
        Mon, 21 Apr 2025 19:16:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAL++pwlTc7nDH94K73OoTIrnpfBNeMTdW3iGBJ7UK3CdQ==
Received: by 2002:a17:903:1b6e:b0:216:3440:3d18 with SMTP id
 d9443c01a7336-22c4084b196ls9581685ad.2.-pod-prod-03-us; Mon, 21 Apr 2025
 19:16:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVcFhwRcrI5wJtt1vqk+1YDFRxzd2+DNw/QPuuarR2M9inVG4c9VZ+87nioeAdttA3r1FdsqEGcU+c=@googlegroups.com
X-Received: by 2002:a17:902:fc44:b0:216:3d72:1712 with SMTP id d9443c01a7336-22c53642228mr202636595ad.48.1745288187943;
        Mon, 21 Apr 2025 19:16:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745288187; cv=none;
        d=google.com; s=arc-20240605;
        b=G1JoxyXaHWb2YQrbsqbYTqvAaChsSPegsRRHYiv+1DdE3qQpO7QzOmBDzLXZgoEbnZ
         zg6D4WQ/D8IfhcD8PCMMT5KulHq5EH58/XyFTH8QH1uB8IhubAWVA1yuWeAnjAP/Sm5b
         W0bEtKjm1vq5wK7WqWbEzFws0DSrPMjmKV55wAb0BWaAKYNM346zRgYR/pH3BxmPBF1E
         ERdSBD0XLeYNLDws4u1tHMR3O5woiJVRVcCneagKjjgb989z5tkLcK0R8qG64EjO94J+
         P9wZWHpN2iXwT7nZe1OWzWJV+VaK4cn8hgdWadmO1ryjlY+IJT1vq5pR6UKSA0G8xV/l
         Agjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=JfnGb6PirAI9qCPRLsAjMCiOOhe/eKwRgKvFzKYSzZc=;
        fh=q02bgzixTNb497g9Wk7rN5TYnNlMKB/cWQBqqCg7OWQ=;
        b=fE/lPPX1hG4110SGHMIR8XF06AWFRwwm2RPttP3Z2yhDQaAzae3Qm3JYpJ1aUCAJHw
         ZugNb4ue4Vzqoun6K0KhmaeSBwmzF9XYbhLr2UlGnS+EOI0Vt7GeO0+OUC7S6FJcv5E+
         QwS4bzxYnKpXEU1zWJxhmLIjE13Mi0deQLpf5I9GTDeVE4cvRV8tpXyNsv6Kewag9qLn
         7XOaevf376C/Z0C3vXN8a+poA2++1KQW6GwD0/yp0WRatFDPzah5l0n2250LSx8LUeFr
         0VnGICaRHWnwoTDDeGtwDeerMBxlh0OWNKB4VY4gAZ3crQvb9y8as/Q7zDNBO4umQRxG
         uqgg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ST5r1nIy;
       spf=pass (google.com: domain of sashal@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-22c50bcdc60si3592175ad.1.2025.04.21.19.16.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Apr 2025 19:16:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 34FAE5C3E40;
	Tue, 22 Apr 2025 02:14:10 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2379DC4CEE4;
	Tue, 22 Apr 2025 02:16:26 +0000 (UTC)
From: "'Sasha Levin' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Mostafa Saleh <smostafa@google.com>,
	Kees Cook <kees@kernel.org>,
	Sasha Levin <sashal@kernel.org>,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org
Subject: [PATCH AUTOSEL 6.14 20/30] ubsan: Fix panic from test_ubsan_out_of_bounds
Date: Mon, 21 Apr 2025 22:15:40 -0400
Message-Id: <20250422021550.1940809-20-sashal@kernel.org>
X-Mailer: git-send-email 2.39.5
In-Reply-To: <20250422021550.1940809-1-sashal@kernel.org>
References: <20250422021550.1940809-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-stable-base: Linux 6.14.3
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ST5r1nIy;       spf=pass
 (google.com: domain of sashal@kernel.org designates 139.178.84.217 as
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250422021550.1940809-20-sashal%40kernel.org.
