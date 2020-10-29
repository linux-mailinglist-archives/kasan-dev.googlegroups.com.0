Return-Path: <kasan-dev+bncBDX4HWEMTEBRBANP5T6AKGQEWLPNIQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3EAB229F4FB
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 20:26:58 +0100 (CET)
Received: by mail-qk1-x73b.google.com with SMTP id t70sf2308842qka.11
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 12:26:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603999617; cv=pass;
        d=google.com; s=arc-20160816;
        b=oZOGcB0YLBDKmwannl0rNEJbV6d9WBs26QmADlRqwEFnY2r2+TTCx70s+vBWcNvLw2
         O4I4yThSPvZg0UilapFhYHTXcYCecM1rFZxhhRnP/pOeSCbLfMRv9Oc79PkjgleC/Swi
         UvzVcXEP2ZBcL1hAipozgYomXTwg1NrbL+Ip+/n8tDjBSaV2bwV/cuzth281gzXilH+y
         mbTzzX9VtAEPjqS9o1cO3rRBO7fMG7c6PZeAYSjNJcRgQmCgsOUz8rerHD1qGvnRZT3U
         8NQBRP0Qv84dlW+qqMzWzjeAf/tMdrprz/fYjzq95S/FnQrW5kg79RJBWbvkhM76GQl4
         CSvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=Vaqxye0aPEnPBeS+27S7EHFqttOPTzLJuBLZtFrwoaY=;
        b=bwKxhu5jYq2Qnc5BFaW7dktz//d9PQ+CVkvYs7JUn44xJE+EDNb/QhOiIkS/L0vs2Q
         cxzjVs5Srr2iL06n7RaicAVZGJgp0PfEjihrSNKD9CuZQ0+/fF5Cg7Jmr24O22UPZpsH
         HjqLtfGhsPe3RVWjmUzWg/HymJeqXeWZNa76ikgbVOEyR58X43zj0mluHtj+mCquTri3
         vv9dlwJ6wWM8sSmycpV4TxlyNZhM+JA/Ue3TAYDII5zS5vi+pCBp8ma+7fe0CQV8RNth
         VniZYb0i4vmi1E77nNZW0CLemXKpB+L8fVkM3TEZQb15fjishSR6DQ6KZ3JGewZysoWq
         zVBA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="O/kauqeW";
       spf=pass (google.com: domain of 3gbebxwokcr85i8m9tfiqgbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3gBebXwoKCR85I8M9TFIQGBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Vaqxye0aPEnPBeS+27S7EHFqttOPTzLJuBLZtFrwoaY=;
        b=aX+Ci8MEpfCdforZnWwzLmDLpzG8w/Q6Y22RhJyoY5jjqzYvcKsKB1NRJPIOPmqIXI
         ksyA8YJvMqJ6UUwfYaKySU4mvnOb+n0t+nI/We98+r9a+/zCksiIrwNyC+CKyqSeN+29
         Glwb98SY7EYAFO/eozc7ZHScXbY4K/KG6009G0EQwVEwwM6oxYFz078y8u9X2hQV2YBD
         5GzRXegX+eW4OOmOBtOEEYbmrxfUMou7WrWlqfq9O5tanIVe+uf8fraW9vWni0GCsf+R
         h8RWB5x6+QcaGsFnS1wgSrbodJpDtNVscau2BQts9IbcXE5vg0zmUrJyeW29GxyEYUZa
         vAUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Vaqxye0aPEnPBeS+27S7EHFqttOPTzLJuBLZtFrwoaY=;
        b=IfVAy8EjAcvatP5qfnt/Rhof0V8FapICAsGh+WIAXd6OadFATzDMuRIA8ZrOqRdgp9
         nU2V1Yqf6bQGzx5+Aj6OZyZL+/wynMssOuL4vZC09+/dsRsxGZNNgQNzEhUSGs591aif
         Bk7uBVLDrb4F0QrQx+SyLJv7u6TfE04vQsA2tBVXT5KrV+U8GGhbycoCZxkbL70q/yum
         VsfITfVbxJTpc4q3tRJvPR1yb4k89r3iYS5v1iPBShsAPuZVhY0H4S7SgQSs4l7tw2qG
         TdUut4IZ7w8lFl9YArGS9Z7rSOpxRSVIRhUFpUvA+kGcKgvgHm72W1i3MR1/ejR8o+PU
         K5Jg==
X-Gm-Message-State: AOAM533sP8gOmKmyoaGm4VJmMAI6LQDwXh7kenqDwxz1knGKj1X7PkAJ
	n0EuB5oPbV207ZfIKxvt4BE=
X-Google-Smtp-Source: ABdhPJw/W4PUlJhz8zeI9iQGRFobvI0OoMzoa0DVDCAyjWt0u2Yy4xylg0b7rhfOOiz2veBBFG2YUw==
X-Received: by 2002:ae9:e314:: with SMTP id v20mr5310231qkf.93.1603999617150;
        Thu, 29 Oct 2020 12:26:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:8744:: with SMTP id j65ls1938103qkd.1.gmail; Thu, 29 Oct
 2020 12:26:56 -0700 (PDT)
X-Received: by 2002:a37:ec4:: with SMTP id 187mr5431153qko.113.1603999616658;
        Thu, 29 Oct 2020 12:26:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603999616; cv=none;
        d=google.com; s=arc-20160816;
        b=snkaIDA8XFL+1igagAchJmVdpjljU7b5csHzFHtTPmoIamPZpKrZaP5vQ2HjZkKBTR
         9FHZLSTvC8WD+I+3/4bg07QkjVQ8ViX/pu9l+D2EI9P3azdi3ml/kH12svzTgAW3MyMt
         VWvecIdw7GrbWFHXdWPIPED9xx9I+D0BSdl37Rv0BVqzQuq82bfMx9k4UDdw3m8z3gOo
         ATPodOY4IXCmuRUtBA+0p7a5s3pIL/ZUPB2sdPlqrmJ3h3i4Uux0TCrJXKPzLXDuc7Bl
         cP2CeDkUJfhpQ9EngFY89dBR8mAdTrW3az/IZswEdBXbJ6KvpwyIccYWN+BXwVhSZm+0
         Us/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=n8TE6VLWWv4zp+ZnErvJoE/L5oOe+Pde/aeeJYIsZf4=;
        b=VdoeII9yi4cdjuCPK2PWu9WhvSA9wXPIGNC/8grW0LkxhV4MBmxBgIVhCrM1N/FoH4
         PLQKQ2IkB1c02uTw9XWbzls95Oc79+IRjjuoHMjdID5PrlyZBD+d56toDdp0uZ9xfaqp
         GVY6qVGCWWqmQDNB6kLSa0WnbtiNeEMoX+lnMnYdi8UpKku8pJ+4K8jxKNpK4HiLNQV4
         XWg0adMdFVs0KOu9SWIw9qFpO+/hYt60e3eFtxmXuaRBfIHBUivQCg4laEqjVVaI7Kde
         V7kq+fVJEybon4TfEKYdfXZkNtXzBvC3qIw8dHH4u+rxPuHf5TNJ/V/XvDuo9YcYLdxi
         XESA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="O/kauqeW";
       spf=pass (google.com: domain of 3gbebxwokcr85i8m9tfiqgbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3gBebXwoKCR85I8M9TFIQGBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id g19si315632qtm.2.2020.10.29.12.26.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 12:26:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3gbebxwokcr85i8m9tfiqgbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id l47so2417073qve.1
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 12:26:56 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:9e0e:: with SMTP id
 p14mr5468422qve.25.1603999616340; Thu, 29 Oct 2020 12:26:56 -0700 (PDT)
Date: Thu, 29 Oct 2020 20:25:41 +0100
In-Reply-To: <cover.1603999489.git.andreyknvl@google.com>
Message-Id: <9f139555e8b9c10d120c3ee8da96973920476cfd.1603999489.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603999489.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 20/40] kasan: don't duplicate config dependencies
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="O/kauqeW";       spf=pass
 (google.com: domain of 3gbebxwokcr85i8m9tfiqgbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3gBebXwoKCR85I8M9TFIQGBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--andreyknvl.bounces.google.com;
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
---
Change-Id: I77e475802e8f1750b9154fe4a6e6da4456054fcd
---
 lib/Kconfig.kasan | 8 ++------
 1 file changed, 2 insertions(+), 6 deletions(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 8f0742a0f23e..ec59a0e26d09 100644
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
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9f139555e8b9c10d120c3ee8da96973920476cfd.1603999489.git.andreyknvl%40google.com.
