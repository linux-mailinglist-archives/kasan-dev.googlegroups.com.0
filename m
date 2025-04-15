Return-Path: <kasan-dev+bncBCVLV266TMPBBOEF7O7QMGQEJACHLRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 0EA59A8A963
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Apr 2025 22:34:02 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-43cf172ff63sf33504085e9.3
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Apr 2025 13:34:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744749241; cv=pass;
        d=google.com; s=arc-20240605;
        b=UymUiRxba4uvHgcRKJFn+WTchFgH8KzjBQ+Oh+lbRW+aoZgw/24m9JYOrY83k10CLC
         8ZUDRVe1faNggR32za5phIAEWcSmlCqshlvZfwu5AfSxrZJN4QlWDtqaI+wfrmjkczvW
         pNVl5CYglPvS0nGwZdm7twWbe04lrOa00bJXwMK/1G0c5zfZb4UYwfk5rWcnrVaUpmEv
         h9Rx9OlZ3kcakLl91o2LO+OO7HuwNUut80L1ZvQ3KFpERkipCgStuezwM6tZNZSF7m7p
         wff9iKfvhgmZimhm0Dql+ogn0eaf6Ix2U1VOMVdAVRGt5JF25zcqbBHK5zyXlqKBNLTT
         UseQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=3pKNNI4Y0AEdzD5rrBWfteWmqgOo4qYhLOcQ4pYPGOQ=;
        fh=/Kre4bT3l7Yi0JfXf1FngGsJ5DlvZ6QE/V8/2v5ikJs=;
        b=iBZYYGXM7vF/cJmV83ICvr1CX4BhdhinyPbcm7SuJHvDUkCXWu6NarO1eNg4ebGkOV
         nNpA0Fe6EVQIANTiDS5eKLDjFvdXPBGz5On3IFFnYDqeiqxCLMtFJXQ5e/WFhLOdfmht
         njIQKi9AEuzBq1bvVW6QhP3IJqYgjJYai+lt4PZ63bIaNGnLCK1e5WmRrutSHFYK0ixG
         tbjpmqjdvvy/IoBoq1y0V17cJl3KiOh6KkZXUkMJq4Rn6T7siZxJt0rsnLr4OY+eu4++
         PNWkAO/ur2D9pjkeg5iLDz1iDjMOmckh7jXpdtHnUkk+nU+SZLTK/VT3P7LqSb82dHVv
         TFcg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="FGCFq/b1";
       spf=pass (google.com: domain of 3tcl-zwgkcxwxrtxyfkflttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--smostafa.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3tcL-ZwgKCXwxrtxyfkflttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--smostafa.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744749241; x=1745354041; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3pKNNI4Y0AEdzD5rrBWfteWmqgOo4qYhLOcQ4pYPGOQ=;
        b=R9Hn6gTVI9OEweLHuJtKwPYjNuD3U3mFcql1ZIUgvOxGEVrsJPkrCCKuXvkxREbmhi
         fb/sojiaoyFmsLBhvQOvwwlOUYJTWHK0dt19e9iMR8L3OXnIqTa5k7/Z19A1jrUz1ecj
         ZpYvYEaK3t4GeQbS3oS4d6adW7EZm1aUqLN4PiQIRstOfKINfuno7YXz64I0n9HgbuRB
         i9wvi4IXuOBeFULxkD65YoDQ3bVO/J6WRijl51wVlOxZqtetT0wbqcfndv7B/GaWJvWn
         sk2cpMtoLbKnocJSsF4qvJoKZQ7ipYA6INlAi2rQyhografG8JCt53uwPAKE3OCl8FtN
         NSHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744749241; x=1745354041;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=3pKNNI4Y0AEdzD5rrBWfteWmqgOo4qYhLOcQ4pYPGOQ=;
        b=AG7phoUlX3e1W/eqEeLa8qc6DV3ecRvoqkt+I6GAJN5tlJYHoow7tuXAmTCnJ42XWo
         foJAhyOAUoXOG5Q8x45QRiLHmu2IGMLo+Mwn/la0TYOfRY3kkVf3AORsijdIG85LUHsr
         P+ZlZ2MoatZEFIxYpIkzJGceoyCn+8zJpV6Ea5VKRJ04CadDBJdU5JETa0gJwYoYJwBi
         hDKb5DVX1ETRZMMDpa8/P+FVSpmLXW+JyOSoJ2iBNk1MEQsd0gSuOBQDmVadQzUu3HWr
         6HG+sZpxDCnTe6Ug0MWy/Abt6ZDhII4hEzFtDN8J6vPPioKYH8t4JVmpyHjmivovD27y
         UnCA==
X-Forwarded-Encrypted: i=2; AJvYcCX9gbkrZigSTAuVZwCqsm/T57mDWS0XBHL90B+w6XRyK9UEMzxrStWFjICACTl6TgNLT+ikew==@lfdr.de
X-Gm-Message-State: AOJu0Yy5GNroUHTeVYvNVQUbCmuXyX9cjh+0kWK2rqqIIkHYrY3G5lZ1
	MaKWn3PHKTfIde0Imi/vyTyIR7ZxCTnn1eMDsAACbU8oG+pS+HUQ
X-Google-Smtp-Source: AGHT+IEkbyhIi2k/PiZaJOWIS4CeLt9sJlJpqKElC9C0Rt/2nbXjJ6KOoliVtMFCygcVO/xVw5nz2g==
X-Received: by 2002:a05:6000:2405:b0:39c:3475:b35a with SMTP id ffacd0b85a97d-39ee274fdaemr691171f8f.28.1744749240739;
        Tue, 15 Apr 2025 13:34:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAKWZjqAloh+sas5xGE9+xV5UYYv3BBnKMWgBAViaNQhVg==
Received: by 2002:a05:6000:2401:b0:390:dd70:6845 with SMTP id
 ffacd0b85a97d-39d8df1b5a3ls1278169f8f.0.-pod-prod-01-eu; Tue, 15 Apr 2025
 13:33:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUi2G6eTtQ/p802Goes6X56BZ0cy0BDPvI+mZVkhhXnCwBir+Je7zyAhgUpWzycplo5U8uwuu1JWmM=@googlegroups.com
X-Received: by 2002:a5d:6da6:0:b0:391:39fb:59c8 with SMTP id ffacd0b85a97d-39ee274fb02mr702283f8f.25.1744749238222;
        Tue, 15 Apr 2025 13:33:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744749238; cv=none;
        d=google.com; s=arc-20240605;
        b=ZpFwp95oK93c/8b4gKSxGjr/ahi9a3bP4wmv7vONEih0B85qoMJN+v/ypW8f7Vpz+F
         XtiDWPdfwR5ZOk9PiEhYLO3xivDNo5OxG+XzqtPTF0Bt+KRegkh0JD9qKdXQUjGQR1kP
         MrfjEnsGjr4ydjvCacZFozyVr7DvV/y0EGcG8nPbtLCeJBhikSMglZzRKw0YgMocqC9t
         orob0O3G/PmEA0z4xDAfspN1HxPhkmyUH131B4ejIcMEIuapzpOA04G0DRCnOOFjNh1r
         VEMMy1J1Gc1PARKe2bcmkFhPBw9ZRoa2124LTqUu06vfsYMou2RWfVRhXHc1p4uBBaK7
         vTJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=IEKdMkwaC8ZVuzeK27ofbBSfYgZV8m32yzn+EY7u520=;
        fh=JFeV5sAByNlRVdv8VGgVL4ykP1LbAwZ8CiqPHAL5dN4=;
        b=Ib1NNwWPQ3jmU+TP5/K0Fb36pR7FAeCyEp3pd+Y31F6lcN6e8mzqF2KJ/ZSZA0pXhM
         Md5SsuUGGFmYgzDUlcw31HLy15ipW9PcUATukDY072WH49rEMKdBPSMejnXDJun7eWAX
         YJRzIyaHAtFC9nE1RuaJBZ2gG+xg0+Ws0VtR//+qY3h3/lNuirj+QOyhzOfemcOJIw2J
         +D+1uWYB9a2yrsAf3lAXdwMvTuDPYHPJXL6Op2n5FOStlrQPSEolnXppAc9Dq8es/1S+
         5L9tqlwuHMAe6HUjlSBRdnJul8ADLpS2zIESa+scNZYa1GVac03oSXDwU6tbMhhnhvy1
         qBuQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="FGCFq/b1";
       spf=pass (google.com: domain of 3tcl-zwgkcxwxrtxyfkflttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--smostafa.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3tcL-ZwgKCXwxrtxyfkflttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--smostafa.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-44045ab6d79si1175005e9.0.2025.04.15.13.33.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Apr 2025 13:33:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3tcl-zwgkcxwxrtxyfkflttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--smostafa.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-43efa869b0aso44878335e9.3
        for <kasan-dev@googlegroups.com>; Tue, 15 Apr 2025 13:33:58 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUV08yQ8G6IQOX3alPq4I4LGpGzs6pFxiALQtgldrkEupm1kc/udZ1k+sT2CbNMNF9glVEI8gKC/84=@googlegroups.com
X-Received: from wmcn2.prod.google.com ([2002:a05:600c:c0c2:b0:43c:f7c3:c16e])
 (user=smostafa job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:600c:3ba2:b0:43d:1b95:6d0e with SMTP id 5b1f17b1804b1-4405a0a4136mr3880525e9.23.1744749237846;
 Tue, 15 Apr 2025 13:33:57 -0700 (PDT)
Date: Tue, 15 Apr 2025 20:33:54 +0000
Mime-Version: 1.0
X-Mailer: git-send-email 2.49.0.604.gff1f9ca942-goog
Message-ID: <20250415203354.4109415-1-smostafa@google.com>
Subject: [PATCH v2] lib/test_ubsan.c: Fix panic from test_ubsan_out_of_bounds
From: "'Mostafa Saleh' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-hardening@vger.kernel.org
Cc: akpm@linux-foundation.org, kees@kernel.org, elver@google.com, 
	andreyknvl@gmail.com, ryabinin.a.a@gmail.com, 
	Mostafa Saleh <smostafa@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: smostafa@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="FGCFq/b1";       spf=pass
 (google.com: domain of 3tcl-zwgkcxwxrtxyfkflttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--smostafa.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3tcL-ZwgKCXwxrtxyfkflttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--smostafa.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Mostafa Saleh <smostafa@google.com>
Reply-To: Mostafa Saleh <smostafa@google.com>
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

Running lib_ubsan.ko on arm64 (without CONFIG_UBSAN_TRAP) panics the
kernel

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

---
v2:
- Use struct instead of reading.
- remove some of the volatiles.
---
 lib/test_ubsan.c | 18 +++++++++++-------
 1 file changed, 11 insertions(+), 7 deletions(-)

diff --git a/lib/test_ubsan.c b/lib/test_ubsan.c
index 8772e5edaa4f..a4b6f52b9c57 100644
--- a/lib/test_ubsan.c
+++ b/lib/test_ubsan.c
@@ -77,18 +77,22 @@ static void test_ubsan_shift_out_of_bounds(void)
 
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
2.49.0.604.gff1f9ca942-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250415203354.4109415-1-smostafa%40google.com.
