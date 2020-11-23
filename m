Return-Path: <kasan-dev+bncBDX4HWEMTEBRBTNN6D6QKGQEILIOHBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id C09952C1543
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:08:46 +0100 (CET)
Received: by mail-qk1-x737.google.com with SMTP id p129sf120601qkc.20
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:08:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162125; cv=pass;
        d=google.com; s=arc-20160816;
        b=fhOjYrvYIWU3q6jVOyAigyQKBUB1ShTcrykKGYkN0tAhAE7EX7Yu1hKu1IcQuzmiB2
         OT45OVcWW8CtmMaXciyC+A5Qgj7fMP+67V4usPkVUaUb2TDtpJ+1eYUXcSDqBSbX/FK4
         0S4MkOcqb+5yvoKw2s9QfTkv08joZaNORpHney+lNpoVuE3e0I1EizVqA3giL1avexmI
         8e05P39xQ8m3WNt3EvfNd4GgQxikTu/bKwY2IsFbDAZS5ZqfCMwS9Tv6onGX2LzNyovk
         60Ih/Db42pMu5vZII+P2refHxqhx1cxpYfwFd6Ws1m8c+K8r+0N+Fwfr1nu46hcI5Z5B
         0p8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=KV++tmT/bEqa+4Jibuuwqh/VmhhraN15jzDvhKOUk44=;
        b=VEmis0YX7NOwkJ9g/M6avfK3HEO5y4ZANad/ls5uRM38dZCvwwvY/4CYQGA0ckpObL
         USSYYcn9PMLwMODRMKbtm01QkW6nLVQKxlVfbST4kgCOe743K1SKItBLefAGwtpM79Kg
         1jHiCHYl3+K7oBjcqjrxup7NIb8IHijO1Ekea7HXPXPC70MpY0y14NB7/X00Q4199a6a
         MnihY8CjvujwGrwdLPSYKMfvRKL1K0QaSs5blAtHchqXoxZ8rC63E9xhS1ToHd2PpvBd
         L7nkCidTTgyvla3zQieZO+8VaCJc4zJ67fyw4afS1AJ90wDWG5RFUpIJmyjol6LE5Rh9
         4JHw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uY5LZg+U;
       spf=pass (google.com: domain of 3zba8xwokce0pcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3zBa8XwoKCe0PcSgTnZckaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=KV++tmT/bEqa+4Jibuuwqh/VmhhraN15jzDvhKOUk44=;
        b=juPrgX+HZmmM5C3Av2zBe35G3YnaMQGK0ziLpPpBT+ioVUE+y5plMwn7iUwd/Nqj5x
         4XyKOiCRldo4VIBvQIbaYRzEyk9VKVpUJqQ1ud630krORGKS86T7FyCF1WMGe4qi+UtL
         05ISHNHwcBPcBWz29muXVu3EpH0KRmDayXIpuw1FesFlH6wNQ1sgcJvpDi1W6MwUYGHc
         ozETp903y9BnNfUNn3d1DQUKkJWDPme+uwhNwvxBBXOU3xdB64FzbCTjPOsBAHJ/2sZ2
         0/OklS9oXM97cU9d9u/8udsYsNxAsVSRhcC+bAiBH3+f0UZhRzFoN/1W0z7sIYBx1iRQ
         v4Sg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KV++tmT/bEqa+4Jibuuwqh/VmhhraN15jzDvhKOUk44=;
        b=WMtvxTN1f27Vh3siqnHyCbC3cd99Xs1Azu3VmScHJhXmvSP3uBqzqBYuUH3DV8MprL
         QwdWIm4Mpbbgil0V7RID4QCNWQI7e6dE2E6V4LK26QV3x4jOLu6MCMFz9N6AjRevOCRd
         QihxkwVGE3L0LS08VkXvivsVFNPiRRdId45RfyyJo9zhSBfeCTbUEADH4dE0FhrAT3Ht
         Z4cbxoeS8LLJuqGrkLhy7v/jbgiooJFq9Qs1atjaPrF97nTWNUOsnY1OtBa2Qc9xTbVo
         0MSQ2LAC10zXAm908u1dKZxc1vG/RrH5nxV/pgL14BCvhEZDKw+qlSFmji0/u2ZQ9mqe
         x4Fg==
X-Gm-Message-State: AOAM532ISXXzSb8HoOtTMngue1qA6ZgzpM1pLy6wBuhF0i83Uc1Ngg4B
	UyVmx8jQzZ49hG+xfaI2maA=
X-Google-Smtp-Source: ABdhPJz/rtJ1+r0bPo2M6fzO1QFeWcMazhmCkjZsMULtSC2d3p9DQWqb/gKFceQEVEcGDcUB/93XZw==
X-Received: by 2002:a37:c20b:: with SMTP id i11mr1309534qkm.52.1606162125564;
        Mon, 23 Nov 2020 12:08:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:7dc5:: with SMTP id y188ls7063188qkc.6.gmail; Mon, 23
 Nov 2020 12:08:45 -0800 (PST)
X-Received: by 2002:a05:620a:15ce:: with SMTP id o14mr1266121qkm.231.1606162125101;
        Mon, 23 Nov 2020 12:08:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162125; cv=none;
        d=google.com; s=arc-20160816;
        b=K8u7BwosyomCMVA0KGIb6HVnYt39BUF1PBeLw7dVLBPif+lZTmXX0KegjWiQnLvlBq
         QBirDiGWgDuipAk3HiMruzWPGHxLjF9hXR0QhvcDXPrWUms1AR1VPqvaWjRY7q0l4f7h
         dsVSy6hWhLlvM7BKPE093/NJGVlaIos2sX9IoA7Fan3dDbIA/8PpBLZtbhOG/Qcpkrmo
         sxUv198rRs2MAjs1LpTCGzOel+67aYi6OzzpSYNO27Zxn5uIZxwK0C1uJ3Kb76y4733P
         vglysctipmSjixYEHP9SFaj6sID/8aXq6mMcKT4sxnTi+Po8mBgk0WqugpeF9wsZdxSB
         7R8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=OXazw0I6oeLRK+aCYmOjFIB4MLt2eUKUeL0RxFWmIM8=;
        b=ZYDiYUWd4AImINviS6smOHAIy9uuwIw9QiT6EFXS5unuNZgG1rpeIA4fmQ4fuPZ1fZ
         C79BT00GpIzWXFJoIOJdOkRAivuMiBNj5yqCfeyyJi0i3jRrGVmXwEVcVMHKr5qgqIlU
         TulblCsJvyVwwCExzKaUCniXpHUb4YoMr8tTm4wb4JZF5BGHl0fCZdfiVFDHSVeDXQD9
         Bj/J/8ZqYsSX+0F36BWUsrXpYQPmhh3T3S2JTB0Umir47zxptb5iIedsCfDswsnBXbBP
         RBztCpwyf4VA0xQ/ot8e0V3ceunbS5W2ktrH7iVFuDurgY7N0YFSmUhr9WSUe0J5ZpTB
         mQgA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uY5LZg+U;
       spf=pass (google.com: domain of 3zba8xwokce0pcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3zBa8XwoKCe0PcSgTnZckaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id n21si759891qkh.0.2020.11.23.12.08.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:08:45 -0800 (PST)
Received-SPF: pass (google.com: domain of 3zba8xwokce0pcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id o25so15574989qkj.1
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:08:45 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:366:: with SMTP id
 t6mr1124442qvu.58.1606162124786; Mon, 23 Nov 2020 12:08:44 -0800 (PST)
Date: Mon, 23 Nov 2020 21:07:35 +0100
In-Reply-To: <cover.1606161801.git.andreyknvl@google.com>
Message-Id: <c1cc0d562608a318c607afe22db5ec2a7af72e47.1606161801.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606161801.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v11 11/42] kasan: don't duplicate config dependencies
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=uY5LZg+U;       spf=pass
 (google.com: domain of 3zba8xwokce0pcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3zBa8XwoKCe0PcSgTnZckaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--andreyknvl.bounces.google.com;
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

Both KASAN_GENERIC and KASAN_SW_TAGS have common dependencies, move
those to KASAN.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Change-Id: I77e475802e8f1750b9154fe4a6e6da4456054fcd
---
 lib/Kconfig.kasan | 8 ++------
 1 file changed, 2 insertions(+), 6 deletions(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 58dd3b86ef84..c0e9e7874122 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -24,6 +24,8 @@ menuconfig KASAN
 		   (HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS)
 	depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
 	depends on CC_HAS_WORKING_NOSANITIZE_ADDRESS
+	select CONSTRUCTORS
+	select STACKDEPOT
 	help
 	  Enables KASAN (KernelAddressSANitizer) - runtime memory debugger,
 	  designed to find out-of-bounds accesses and use-after-free bugs.
@@ -46,10 +48,7 @@ choice
 config KASAN_GENERIC
 	bool "Generic mode"
 	depends on HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC
-	depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
 	select SLUB_DEBUG if SLUB
-	select CONSTRUCTORS
-	select STACKDEPOT
 	help
 	  Enables generic KASAN mode.
 
@@ -70,10 +69,7 @@ config KASAN_GENERIC
 config KASAN_SW_TAGS
 	bool "Software tag-based mode"
 	depends on HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS
-	depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
 	select SLUB_DEBUG if SLUB
-	select CONSTRUCTORS
-	select STACKDEPOT
 	help
 	  Enables software tag-based KASAN mode.
 
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c1cc0d562608a318c607afe22db5ec2a7af72e47.1606161801.git.andreyknvl%40google.com.
