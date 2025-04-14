Return-Path: <kasan-dev+bncBCVLV266TMPBB7P76W7QMGQE5QK2JGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D28AA88DD9
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Apr 2025 23:37:04 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-39130f02631sf1955284f8f.2
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Apr 2025 14:37:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744666624; cv=pass;
        d=google.com; s=arc-20240605;
        b=E6hY3dK5jMbkOWvcfJN6BGs94P5PjHmEe28OSu/yLM2WDUUek02evpV7ycDHsMblJx
         ogxQONdugoMoHFWyx3ky2qfrI1j1nHnzR0pKVHF0DFETqoQeEALxMyr6wRgxUEEd2dYn
         zDDf8n9SHJn503OEPwjrkHWo6kHAn2DtKFPvyBHeSUaXMAevlgrbWooRV4gqhUrCi+x7
         e7yrNb4aDm1Dabk0WSauEdPynQwEnlqGeYi5QB3TGF6Pauc3lTEjmvrKn0VIxZarKF6H
         9M/5p/II5qfs7b3Pmlc1j1qSS1YoxgOTT8YhuZ5QeFehSaftitsfmYRwEZK3FL4/HnPl
         lcbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=ykdZ81dKTTfGORTFFLG8dJ9pTSoujZsSM9VMFt7V3Og=;
        fh=34zYoZLyUld1lFaprntmv5C58j5JUTYTp6NhmGp6qrk=;
        b=Kyhlp0FYZR6goud1c9oy65D+sotI0NJk2jIQxejtbmNvVfmRFZLs9cJcxCVUC0MVWa
         DR4vGFPYaJHI9x0hLjZicnDbOhY+Z1g0ZPB+lOMJJvbvtPfMr2s6HTHgc3p2BH+x+6SU
         02kLivbu7yXCSRJoZnZT57AUq2bt18eU5nce2zaSslnmB93mBJGdeENyAnr84hG3lLjD
         DDEzZZ2IZl60rVKzvichfGU0Rcd8yQz60JDEYk7GCEhRkTCWJDwYblniZLhdqkg2YkzQ
         dAuNPlQXGncT1t064F+YAbrYE1vqDtcCl8akgEXbIrA+rjuoqYszs1G13HxkUlJTZpXr
         hsfw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=rnxjfG+8;
       spf=pass (google.com: domain of 3-3_9zwgkctgmgimnuzuaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--smostafa.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3-3_9ZwgKCTgmgimnUZUaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--smostafa.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744666624; x=1745271424; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ykdZ81dKTTfGORTFFLG8dJ9pTSoujZsSM9VMFt7V3Og=;
        b=LZeFpOtRunrPiWwqERd5WKnXUM9eUWkQciskSoSaouoHYjVBLoNkdqwBqmV8//cJoi
         /jiL1I6BhqzMp3iImVQcQZaGd2JhONDQ+JULyzg8UJeTMDdJJLTqrJSR/vbBE78f2SUT
         /rA7e3vW3ntPqak0aLINFNVDrBGNiEnQ2kDVOMs1D49wI8WzcyvgNjNKa5r6mMRBoxO/
         XH1NysEapb5JDQsIr1SjMT5fGMgcamGuP7MAA5gC7PLHNmCCwUgle/17JFQom7WYTEY9
         kqFMmhEM37p5IIY3+aXBgCTAD6usBQbDHgKljLNxHO+hcawwAv+QmJlFi1GaS3tSNIbm
         1t5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744666624; x=1745271424;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ykdZ81dKTTfGORTFFLG8dJ9pTSoujZsSM9VMFt7V3Og=;
        b=F59xkaRmj1jsGZWfImsluNl7yUSc/xXnVaXZC5F1Ne82aGoqGNTv58SIoobofDLZhB
         /gTv3N/sogVQHK5mzL8/pgjLA/JswI/Yy+LCenI7ftIqqkDkglovV/JVI4J+WVfp9eM9
         GsmP+ZrgxGZICSkzKTBBca2yjnlGSR3L0gsXOXqZFmjQTTvcsyo8VD9dvv8jA9LyLqcn
         qq7aD+sxziQ997hvvhSq9y4GmGZUB0Mx8N/vYzJNH4S7Ay+Ly/f8zlWz1w29epBFb0aT
         LzFwu25xn4pxgWt2hD4ZRJoLfHS5Tl5QLnpbF1cscd0ZYYno3adUMgD9aAIx2D5PVa7g
         uncQ==
X-Forwarded-Encrypted: i=2; AJvYcCWK/DR2wBHdjtHZPN8OScT/ixR5lRvclhjMu6Xx8TDi53DCpZxIHuabX6X8KA2ETGLegLMm9A==@lfdr.de
X-Gm-Message-State: AOJu0YyKkl5ZTYXVavgDzrNNIXZAtmIK4qA12voL8LpdiybL3by+evEU
	vBg6Vl1rDprmwmniLhm0gw5flPEWdWVhl9D6CGqT1JUCkPFPECfn
X-Google-Smtp-Source: AGHT+IFPSIMVafuNhqeNtSDuqcdMdY07qGSePOL52A+Pj8+j8N0nT5MjM7T7ifEVFUyH7wfboqL8sw==
X-Received: by 2002:a5d:6d82:0:b0:38f:2b77:a9f3 with SMTP id ffacd0b85a97d-39eaaecd9d3mr12427048f8f.43.1744666622315;
        Mon, 14 Apr 2025 14:37:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAKSPM9/Ja55GFzAml2fPnj2QlW8Z8kMJA710CuKLYoneA==
Received: by 2002:a05:6000:2909:b0:39c:13fe:1ad with SMTP id
 ffacd0b85a97d-39d8dfbc3d5ls677997f8f.1.-pod-prod-01-eu; Mon, 14 Apr 2025
 14:37:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW8RYh05djYIkASZq0O3n83ZPuKfi74oP52MijCpDCUmMxGu/s/HLy0G18VuOX8RLD8AWdXLSeIsa8=@googlegroups.com
X-Received: by 2002:a05:600c:1c2a:b0:43b:c95f:fd9 with SMTP id 5b1f17b1804b1-43f3a9258e5mr99204035e9.5.1744666619753;
        Mon, 14 Apr 2025 14:36:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744666619; cv=none;
        d=google.com; s=arc-20240605;
        b=OUpMnQwa52tbuClFokAe9ANG5zFuQro9GdWz8/fvKnS2TRglGacWZmkCn4yT6va0ZF
         vjshTUqTyVD1Vj27NYBTqAU/dfqpTCb7/I5/EIiia2rx6qPpJD2ZDrBAfTyBTSXWkOV5
         vKHjL7s7LtRPVMzdmByl3Br0Fty8SZOBtosiKJK2r8rTRtxLjr1cd9n6NXkZUyfH2I8r
         zLjF8Ca6E0jlkM5mruPY2f1T48AwYnr1Zo5KO2YF8B4mqRQSm7+9025TJ55OxgYIQHu/
         vQc1Nk0sbyzCQ/2LwTDc8JfFhg5Ew+4J73F86aMNWEHJkxtHZXsXVlVbq5urxQ8zZePO
         9zEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=jF2TNhYRLgqPg2GomnHoMsGcCSNdCtX7kL0R4HVOm0M=;
        fh=5FXmyYkjdMiwYtUKeBXU1XTCjB53rID1T91iE8OsLiY=;
        b=Ke1PS66i1uKIKTNWmoFXjobDnD5wfrffN6s+f18S6LwrnBuxeZplEFeBwm2+lihArF
         G/HFeri3wYZHgQySiF5QVQnJfagDrVYQRv8PFwBzs1D0zm/jOGAH7/6mhBwSDz0K/9yB
         OnMH4uBSZTw/VJae0pnXA5r75Ekh0NIK43DjbtmkdniAc3DJFIu6x7g7dKxvMfLp+oMF
         xkKllq8kfvEOVHL8xfvpSpo1GrFd2gqRxkviUKh1rdwrmtcpDXzbm8Fu053QDvgno/Nz
         lYpCCfUe9BX1dFIbny+BKUzwI/FRvNn9HeScYDG5R9UqvE60kOcXLYOxBofpKzToHPsI
         hBCQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=rnxjfG+8;
       spf=pass (google.com: domain of 3-3_9zwgkctgmgimnuzuaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--smostafa.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3-3_9ZwgKCTgmgimnUZUaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--smostafa.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-44034fd83d1si25355e9.1.2025.04.14.14.36.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Apr 2025 14:36:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3-3_9zwgkctgmgimnuzuaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--smostafa.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-43d209dc2d3so26892935e9.3
        for <kasan-dev@googlegroups.com>; Mon, 14 Apr 2025 14:36:59 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX0XzAcDijEBNIPh1uAJOphEM1hR91U/Px18SZGBGLUNlB958UhmOYONLIabWJNsZp0Wz/TUGEOkfw=@googlegroups.com
X-Received: from wmsp9.prod.google.com ([2002:a05:600c:1d89:b0:43d:9595:9973])
 (user=smostafa job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:600c:a04:b0:43d:42b:e186 with SMTP id 5b1f17b1804b1-43f3a93f257mr98041855e9.8.1744666619418;
 Mon, 14 Apr 2025 14:36:59 -0700 (PDT)
Date: Mon, 14 Apr 2025 21:36:48 +0000
Mime-Version: 1.0
X-Mailer: git-send-email 2.49.0.604.gff1f9ca942-goog
Message-ID: <20250414213648.2660150-1-smostafa@google.com>
Subject: [PATCH] lib/test_ubsan.c: Fix panic from test_ubsan_out_of_bounds
From: "'Mostafa Saleh' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-hardening@vger.kernel.org
Cc: akpm@linux-foundation.org, kees@kernel.org, elver@google.com, 
	andreyknvl@gmail.com, ryabinin.a.a@gmail.com, 
	Mostafa Saleh <smostafa@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: smostafa@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=rnxjfG+8;       spf=pass
 (google.com: domain of 3-3_9zwgkctgmgimnuzuaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--smostafa.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3-3_9ZwgKCTgmgimnUZUaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--smostafa.bounces.google.com;
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

So, instead of writing out-of-bound, we can read out-of-bound which
still triggers UBSAN but doesn't corrupt the stack.

Signed-off-by: Mostafa Saleh <smostafa@google.com>
---
 lib/test_ubsan.c | 11 ++++-------
 1 file changed, 4 insertions(+), 7 deletions(-)

diff --git a/lib/test_ubsan.c b/lib/test_ubsan.c
index 8772e5edaa4f..0e5c18b32b2d 100644
--- a/lib/test_ubsan.c
+++ b/lib/test_ubsan.c
@@ -77,18 +77,15 @@ static void test_ubsan_shift_out_of_bounds(void)
 
 static void test_ubsan_out_of_bounds(void)
 {
-	volatile int i = 4, j = 5, k = -1;
-	volatile char above[4] = { }; /* Protect surrounding memory. */
+	volatile int j = 5, k = -1;
+	volatile int scratch[4] = { };
 	volatile int arr[4];
-	volatile char below[4] = { }; /* Protect surrounding memory. */
-
-	above[0] = below[0];
 
 	UBSAN_TEST(CONFIG_UBSAN_BOUNDS, "above");
-	arr[j] = i;
+	scratch[1] = arr[j];
 
 	UBSAN_TEST(CONFIG_UBSAN_BOUNDS, "below");
-	arr[k] = i;
+	scratch[2] = arr[k];
 }
 
 enum ubsan_test_enum {
-- 
2.49.0.604.gff1f9ca942-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250414213648.2660150-1-smostafa%40google.com.
