Return-Path: <kasan-dev+bncBDX4HWEMTEBRBPW4QD6QKGQE5JKLUVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 7CF672A2F0A
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Nov 2020 17:05:19 +0100 (CET)
Received: by mail-pg1-x540.google.com with SMTP id z31sf9509995pgk.8
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Nov 2020 08:05:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604333118; cv=pass;
        d=google.com; s=arc-20160816;
        b=Lh1DFJVcyGA8Rk/Vse7H4R31E+dZxLBR30FKWE1v7rpZvXK5upX11zJ8/12tzPAjGx
         i1TnK4RcY3Uv7FqUYfBoQPrD6qpfkM3V8sSjm5lQRFK8+mlBIdpIh2nSm1RWUhBHwplr
         02SG4b75iGX+s9FCJbsww3AZ1dAJsnVqy9olrEq3DNk89uUafz0R3Mz7kqQaXGkyjKzn
         K6Nm0BT0FEj1h/IwIiaRJ8gA5/Rj6hFZvvnoXLfkJHgwLkaBW7yJWK0zEug5VTPSmgKy
         ljZsew5XSJl8chFNuJuUeSTJ/Aj1SU+FlmHaVT/8vGeN+4/qP9q+C1oxCpPQIY4na8xb
         LrJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=dv1tod28F3AD2JC406/8gJPA+zmYrE3tvbUXHe4+1pQ=;
        b=bbNxGsccf0CxR4FXMtRt3HmioH7PY6YKDXzL/LZVq96e7gd9z09gp7x536uM5lBwvc
         Cv9JTU8gaeQcCM4qZK96YgQDvcZispGFRN75mO1pYkiTFkQezTLQF2fRB3fGx3B3sHzK
         drcWuZHbLXRmo8jY+H0DEUQ3xcDW0m3L+TMIk74R9izwQqQQy5ULqhsP6ibMQfDoRuGj
         TP2tqWcKa9b8I9wVSfjSjCIfSsB1DRKjwcYGudXqcUnmX/cXK+1Bm84VqlzmUgep/e7J
         +M4wQqZQU8lsvQTypao0zknDyBkrVfxh94Zj5cZKhN21TZPeDvV2tlF0UOAwXXpSx7Ya
         XWwg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tKz5YdB6;
       spf=pass (google.com: domain of 3pc6gxwokcr03g6k7rdgoe9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3PC6gXwoKCR03G6K7RDGOE9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=dv1tod28F3AD2JC406/8gJPA+zmYrE3tvbUXHe4+1pQ=;
        b=SI2+kSieNXPRoU6lWl1wlT5/2vPiQNOJQb30UosDjQAdZR4Fx2bH6A8/8uHE0bMlB4
         cQz0pyXcYM8ypIFc/RnboecnmvzDN29w6spTHZmN86pKlqvPnBhCKg660cpsWuJxlQU8
         0/aIPKSModnB5yNZinpQvhVJqKrj/r2R+dXILktqf7KQ++nog+uk3a3HFRVXMDUEB5Vy
         4Pr9oW80+7rEfYl177jgTSEmiQ/jg44/iYKQAOqFJqC2DYcNnfk4R0NF0Z2KSSzJbgxB
         vWEivnlLM04+gnevPcRwqlVKLsEHW7bREkcQMxaXXbHV4EHDIAYL8I+CEFl6xA1NiGkd
         XB2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dv1tod28F3AD2JC406/8gJPA+zmYrE3tvbUXHe4+1pQ=;
        b=Sa/oiOhk1TsxcfmnDCpozrR5BErm/jBUce4BwKdV1+UGpc8O7/5rTX8T0HJ4TPpcvd
         IGKhBmsoT9Xvzwd0JM5ObRlGMYMEbhUAPZvdHC7EH2PiRZqXAallqCAZHmLU1iOv3x3b
         xMdxB4UzFjyqZkKjkemlIQiWCFfH0Hj64+gAOsxK5y5ujNclztT/ukFV1VtdXO1fQeLX
         CF40faY7YM0X6flV/ETv5laaDs+zluuMXfu6XxW2CGNK2kLvxF9/29J6udULjJoU+Cxu
         YKQDziws03ssyF1QKGSJVbPxDA96NFW0AZ3jKOyw8qFErfBghJlMSsbkU5w45l3ZItpQ
         EqSQ==
X-Gm-Message-State: AOAM533bbcUdjf66Lx7WjnQlRRps5Y5J+gPVSWgsAi32KW0ftOe/m1t8
	cjpjnUneL+ZbOPOFcNkISl0=
X-Google-Smtp-Source: ABdhPJy7Au6eAgPezQC1oVVec9vK6EyvusnQQLyKdy4/Jo70nFZ3T8cpU5YOl+sE/7khfT/MLjQOXw==
X-Received: by 2002:a17:90a:5797:: with SMTP id g23mr18230512pji.184.1604333118233;
        Mon, 02 Nov 2020 08:05:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:5d03:: with SMTP id s3ls5929293pji.1.gmail; Mon, 02
 Nov 2020 08:05:17 -0800 (PST)
X-Received: by 2002:a17:902:a50f:b029:d6:da2:aaa7 with SMTP id s15-20020a170902a50fb02900d60da2aaa7mr22567691plq.42.1604333117672;
        Mon, 02 Nov 2020 08:05:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604333117; cv=none;
        d=google.com; s=arc-20160816;
        b=mtqBnBhpwiigjaOY9hxgCzEGcZg9jqiVu7uOHkBEqZoGW0rq9mcPi3L8+G+/NdSnVy
         ximhP2DQYu35J0/RbedN74o0DUZnXntGMGkcD1TbY9o9BRmPGmVKmGyDGWCxO2bYxFcP
         S/ut/5zvQDXmBzbCdW7JhpHgCS29dRGqyi/s6TKgkdUsawH3uDI9RSrFDgZrUus7gdo8
         GFpX7CEUMhVhiTxMKc+8Lnc6Kx5sxwVkiExe+X2CMt/RjxDorgLwZ8H8+31TUZgGpdEV
         U+E3ehIL7vfTOuYLv+Ee513jDxhZqAFuzJwzZGGXk6eHJ++MsSQds/b+L6kj94YlvWhW
         zlrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=n8TE6VLWWv4zp+ZnErvJoE/L5oOe+Pde/aeeJYIsZf4=;
        b=s/DLyP0zi5JNzONn3BmzLB5KM8/VU5zD52vh/CEFUpan+uXQSCuOwQ3U+nENksh9Pu
         96j9JaU4JFQK6SEzjGMmFKurQiq8mO6igapSHd7X4/8SOVC7YvB6GwKcp6TUgCHitMoE
         84xnBc6L7+oB7UrMaowK0AO8rv71+kiuQeuEfvrE1K/DmGgHgSH8RMMMEOZvUeCb02tG
         k+PYuWlJRh2QqayvWo1zy6BM9KollDlhrWOlJH1IoPz0PYtn0WdS56VWyzLL/5DEtR9U
         kwinKCSvqe4cOilii0PltlIoOmjVjt+aAnLo0OcILQxgobeT2EsfTKVpfEI9D1XQDKLY
         ENEg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tKz5YdB6;
       spf=pass (google.com: domain of 3pc6gxwokcr03g6k7rdgoe9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3PC6gXwoKCR03G6K7RDGOE9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id a22si538503pfd.0.2020.11.02.08.05.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Nov 2020 08:05:17 -0800 (PST)
Received-SPF: pass (google.com: domain of 3pc6gxwokcr03g6k7rdgoe9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id x85so9008952qka.14
        for <kasan-dev@googlegroups.com>; Mon, 02 Nov 2020 08:05:17 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:127:: with SMTP id
 w7mr7034621qvs.3.1604333116812; Mon, 02 Nov 2020 08:05:16 -0800 (PST)
Date: Mon,  2 Nov 2020 17:04:01 +0100
In-Reply-To: <cover.1604333009.git.andreyknvl@google.com>
Message-Id: <2673f10ce2a1186d88d6bda0023cc81e2564888a.1604333009.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 21/41] kasan: don't duplicate config dependencies
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
 header.i=@google.com header.s=20161025 header.b=tKz5YdB6;       spf=pass
 (google.com: domain of 3pc6gxwokcr03g6k7rdgoe9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3PC6gXwoKCR03G6K7RDGOE9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--andreyknvl.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2673f10ce2a1186d88d6bda0023cc81e2564888a.1604333009.git.andreyknvl%40google.com.
