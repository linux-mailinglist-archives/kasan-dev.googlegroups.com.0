Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYHT337AKGQEMDWQXWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id ED3B32DA00C
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Dec 2020 20:15:44 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id o12sf6959401wrq.13
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Dec 2020 11:15:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607973344; cv=pass;
        d=google.com; s=arc-20160816;
        b=x5gMuh6ML89cH/ZtgWmtfTBrzhW0FQQQZ+NkLWK2M1TjyewYSsnL5XiWH2+wS2EoPy
         1sJKGIHUg6BljDQnL+tMoon/nc7R1izprd6hmr5TtOdvQ2Csr47lZ+zgdNcYx3aXlX1Z
         Ns2FuoX4vR6ZJwMd9+UKGhQBqQluDtCTCBTggU6AOhuqTL5uOHE6ODt1RU5P084OBxqT
         KOo0PLhGg3oaDT0DlTujgfmTiAO+gx0eaeRsO3LDO6IutblnuOIaIfdllPniOwGFTuMg
         FTyHA1XD2qgLojKVlrCoPE4j8iZinwIh7f8GCKtYYb88mQxXXTFd//Qabfq+ZwgBZ2A4
         qPHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=345SEwZiJSE9/JM7RKRNvb4QrmqteQawZjQwhmMbFhQ=;
        b=TFX8jTkrYzcUu9mAzZGIdcIcWknVopZZ/iP6/3CEUvyBf13Xzg5xzYd6/l9GkH1eXO
         pc/j6MSWonOeFsWcIJYaBWiCyYn+KQJuMDEiP0pjh/LIbdeRxi3e0D1t7z9ddZbgS2ec
         pBE9j1Ir3UalxH7dv6NIxrNc6JOK+r2x8hqkbZ62encXHQlC2FQ8cTLKG8jlNRog/wjl
         8qxs94XDNLZ+T+ePvje7ppuVC4LMQD/w9whPUNfAqg4tBsH32R7/oLGI4+76w8UxbIKR
         ODdBIf050N+vZoPFVSPA1764kUy4HnwTLGoULcMMedzXoSgn6EZMO6vfJ1uiEMV8k1zK
         N/lQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=i11amYTd;
       spf=pass (google.com: domain of 337nxxwukcbyahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=337nXXwUKCbYahranckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=345SEwZiJSE9/JM7RKRNvb4QrmqteQawZjQwhmMbFhQ=;
        b=i0kYz9MT1UdsIo/SaohIcPVbEibH7wKVvsJtgeX3cwiEaU0WPcDA3Cn+CKD1DNF0pk
         RO+1gfwfPiijLeC6+bvMKj1UEPw4ftj+Z4HicwYE/NVPDUBLOGtC7M4bgR0yQzR76fej
         HQnWcvaa9DTMlLsG89Of81wBRt6BjLJyZtYqhKVCWRlf9h8eHRgWRQM9cxkxgOTXY+WK
         Z+0mrVK171QC6MkuiKMltFq9XXfPQU6R83Er1nU7MECtZ7P6FFCsL62izANPut5z8ZRq
         Cqv7vKy2ngmxQrqHpRhiOGyP4fLTtx1MavHX2dgmW/3QnaJalOuT4/fh3Vte+0Ql13V/
         cdqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=345SEwZiJSE9/JM7RKRNvb4QrmqteQawZjQwhmMbFhQ=;
        b=FJo8f2BCIbapI3JI8uszchDmTss2G/8x8IaeGQAc7+TzoAsC+5HwtfFtw9jUCPvjSo
         Q46ekLL0O262myhVScquCSBvPC+MCMnJQgk9V+f+pmZR0p8cETz7XuQAcvvPccQSaToV
         ye//PqfladnRbWs/6EApRa1+JcqtGJfFLVQHmRPF7uTFqwGQiPljrC73q/FHREIn6G25
         vNaggZK5JqJRe4RYd+eIrcCsMzZqgQKJPbhgjw8oEA5KDBIePerOSH3wyyjIbY9MwBLT
         jt9kPe39XNSa0sqKaP5I3v7RFaaVoBCzmKnMdIsr6lbCCct2HPjWJjy7/R6u/8z3Llf0
         vKzA==
X-Gm-Message-State: AOAM532u+IwphVA7SgCGF8tDSAvJzAvXH6ndexqbq6OzvGpOgNF8KPcY
	xc6GIQca+dcNhmrOCTaSTBI=
X-Google-Smtp-Source: ABdhPJyUNPOGudFT4jXeGn4C7U7zANm4umYyBvR+4+kv6em/lS+bQV6AJk/b9tUPjJVBWTaIu3QsuA==
X-Received: by 2002:a05:6000:1188:: with SMTP id g8mr5491282wrx.111.1607973344716;
        Mon, 14 Dec 2020 11:15:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6812:: with SMTP id w18ls2294809wru.1.gmail; Mon, 14 Dec
 2020 11:15:43 -0800 (PST)
X-Received: by 2002:a5d:51d2:: with SMTP id n18mr30950469wrv.92.1607973343710;
        Mon, 14 Dec 2020 11:15:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607973343; cv=none;
        d=google.com; s=arc-20160816;
        b=xsRHvGEbP0cz0n2NJ8T4XNR92NMQgI5zl3E5jTxzZFUx/jzhkn/tKwW1iNnCFpn7K1
         CgqW5ky1MCsmot8+/YMZKUdQuNPb9sOdgjOk7ezyuQb58yF7z8eV/xOgTYCdw2bkuiZj
         ibCd8nQprY2ZUTvUwpWdW2ja8NPO1e2a38UesockwMLqZeMGE0j0YqwMLa7fRFqvnWIY
         hjs+u6O4+SDQseuVq4r4IVdYsl2DWiimtsmNxhFH8nwFFhFfdpwE7F6jOWa2iiyF88n6
         9DDwogt+ehs3EzaJJZlOFm5pQI97Vwd24CEBC/qTT4z9BD/CjwsudTHdz8yyWHsIriM5
         Cl+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=OXWZqhdKXz2gQWFbmjoSr/aaAS/tBQHv4yy/WSCCm6Y=;
        b=hYPVC7TE/0eD6Vdnl21O+px9IlFTwvmVMaTOELFd6WTv2bxOw6xgbdNmGSH7LfeGQV
         Ybl0Qs1u1a0q2M1D14ga0jck2jJUdjJVvWOBqk9+BHZa5c6yiUB8nmHDYKM8E3/xzrHJ
         yz1YWUhyl3ox/Ojbsp9kBRg8tW6TXbxy4ZVfrAfH8BXYKpzcBXUZMCph7738Vs8PKpQZ
         N/CQxEjmz/LBZciP3nOz8v34mUhW95J2qcGMSwzdpSKn3vJxGCyjrqwTh38rh39D3nLf
         4Xx1lnMhb562Kov8LPrCbaeKDYZvpFG/VxAC5Kxksks/twQ5+oLvVZQjoEE1sVDFy6ju
         IjnA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=i11amYTd;
       spf=pass (google.com: domain of 337nxxwukcbyahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=337nXXwUKCbYahranckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id z188si267433wmc.1.2020.12.14.11.15.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Dec 2020 11:15:43 -0800 (PST)
Received-SPF: pass (google.com: domain of 337nxxwukcbyahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id a134so3841635wmd.8
        for <kasan-dev@googlegroups.com>; Mon, 14 Dec 2020 11:15:43 -0800 (PST)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a1c:2783:: with SMTP id n125mr25239565wmn.74.1607973343268;
 Mon, 14 Dec 2020 11:15:43 -0800 (PST)
Date: Mon, 14 Dec 2020 20:14:15 +0100
Message-Id: <20201214191413.3164796-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.29.2.684.gfbc64c5ab5-goog
Subject: [PATCH] lkdtm: disable KASAN for rodata.o
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, keescook@chromium.org, akpm@linux-foundation.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, arnd@arndb.de, 
	gregkh@linuxfoundation.org, andreyknvl@google.com, dvyukov@google.com, 
	clang-built-linux@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=i11amYTd;       spf=pass
 (google.com: domain of 337nxxwukcbyahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=337nXXwUKCbYahranckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Building lkdtm with KASAN and Clang 11 or later results in the following
error when attempting to load the module:

  kernel tried to execute NX-protected page - exploit attempt? (uid: 0)
  BUG: unable to handle page fault for address: ffffffffc019cd70
  #PF: supervisor instruction fetch in kernel mode
  #PF: error_code(0x0011) - permissions violation
  ...
  RIP: 0010:asan.module_ctor+0x0/0xffffffffffffa290 [lkdtm]
  ...
  Call Trace:
   do_init_module+0x17c/0x570
   load_module+0xadee/0xd0b0
   __x64_sys_finit_module+0x16c/0x1a0
   do_syscall_64+0x34/0x50
   entry_SYSCALL_64_after_hwframe+0x44/0xa9

The reason is that rodata.o generates a dummy function that lives in
.rodata to validate that .rodata can't be executed; however, Clang 11
adds KASAN globals support by generating module constructors to
initialize globals redzones. When Clang 11 adds a module constructor to
rodata.o, it is also added to .rodata: any attempt to call it on
initialization results in the above error.

Therefore, disable KASAN instrumentation for rodata.o.

Signed-off-by: Marco Elver <elver@google.com>
---
 drivers/misc/lkdtm/Makefile | 1 +
 1 file changed, 1 insertion(+)

diff --git a/drivers/misc/lkdtm/Makefile b/drivers/misc/lkdtm/Makefile
index c70b3822013f..1c4c7aca0026 100644
--- a/drivers/misc/lkdtm/Makefile
+++ b/drivers/misc/lkdtm/Makefile
@@ -11,6 +11,7 @@ lkdtm-$(CONFIG_LKDTM)		+= usercopy.o
 lkdtm-$(CONFIG_LKDTM)		+= stackleak.o
 lkdtm-$(CONFIG_LKDTM)		+= cfi.o
 
+KASAN_SANITIZE_rodata.o		:= n
 KASAN_SANITIZE_stackleak.o	:= n
 KCOV_INSTRUMENT_rodata.o	:= n
 

base-commit: 2c85ebc57b3e1817b6ce1a6b703928e113a90442
-- 
2.29.2.684.gfbc64c5ab5-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201214191413.3164796-1-elver%40google.com.
