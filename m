Return-Path: <kasan-dev+bncBAABBLVVSKWAMGQEHL4A4NA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id D91FF81BF5C
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 21:06:07 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id 4fb4d7f45d1cf-5536b82dd4bsf95242a12.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 12:06:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703189167; cv=pass;
        d=google.com; s=arc-20160816;
        b=KG5VfOUfOHEUDkIWl/yQsdsQnC780kWI7mVWFjaaSYSW45QGuGlE64uUZYLbSDZcD4
         Se/nHNeP1SH/VYqcxb5lZFytp/pI1H2wx46ohmdv8zSlCuGO84tpMF/HNxM36rDEf6A/
         4GyxfbV3e1jc938uosAj+o3i2wDmW068uSZ7KhC5V2WZGCrGyw8FcS0qzWSov3db/ARZ
         lYrzPU5D5Y35+QkxtO5MSXOUPjpy3UMBMPnm8XZJVbyhtIYaty9VwUu4zGp3pxmqDbaB
         cZXjApedHjBXOZ6pNejbuQr3aWdu4kmWVs5Y9koADoYzG/NRN7kmLzR5fqWNUSSw5Q2F
         0nfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=+sxvvOf5ifOxxIGGUe5Cx7pF6kZ5M9h6y816zedp/z0=;
        fh=GyTEpUCUNPwsl1pqA0jDPXgvja+iZTM9USlQd9sQtQg=;
        b=ePr8SitFamtNHFi9EKLA1EaoO1qffwFPgvRu373MNQCxLFW80UT2xJrzhwJghiJKZ4
         Ylk6noGuhi59Wly9e6U0hzwIxGjelZ2oQd3JRScolpfLWbXQlcewnlPz0/Xnp+8i11zf
         BG9xS5QSyFUPt/plBK8TlMXQxeT6FgiJH1iwuru7CComIjCkGRPa+qZ6PRvoYvJzWQvJ
         ApjxvjgalkjNOXl8eikPG+ZGXlW1BeTkqK3TqYx90rU+kblWDJ5i+109jautOwMBcW/9
         8oyhYzHxtufugVjfueUxBJM3z3L1HRwk8HvkMwvQDbfjNa9yt47v8YreVgI3Mwrg+ZVT
         1B2w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=UQy5FdaO;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b1 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703189167; x=1703793967; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+sxvvOf5ifOxxIGGUe5Cx7pF6kZ5M9h6y816zedp/z0=;
        b=HnQlJJXdw8JLI9Oq/PfGL7jjjv5xN7co5gey7KKviz3PFL2qibxjpF5yZunq38jGzE
         QV4yW6o0NNDucaVR9tMs6hVjehpwqnx6uWk8vjd4rb3H8W36UtuX0z065XTfbmb3PVE4
         GKETUkrXuXph+WQfAT3reJuoiF1tZNC/2QkO9ZuT9lzVS4KQ4Ab9yh43h/YjS9kj1CSL
         Y/qJPty3A6wU85o0fPmGaeQPUAXsZDeGn+OcqyvcEyfc6jsU0+iM57TL64BABU007FY5
         FjWmeant/gzfNJV0T2FCvg7zyx7ABdHRZn9nD/brYLdww/gU0trvM8nkGvNdKU/PLjbI
         bWbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703189167; x=1703793967;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+sxvvOf5ifOxxIGGUe5Cx7pF6kZ5M9h6y816zedp/z0=;
        b=YrZ7G+ws4JbEBcEP++ax7JlxGJGtGCGbYPLttIoriETuOO2ISDpBBDfjgszkArdeSA
         tw4SlT545yVr8HWPFLddhATZiVjUrOBvHtHFGgBbvoqXTeh4mSsB/Iz72Vq4FNyFvgZQ
         Zs1HHe6JEV3dtPIzfimlq5TRAj2DfCFRSsFyQz2oSwWXabaPv6SgHhr9tuKavZ81LVFX
         4puIZFdsBeTFktpNIjFcj8wr0gMgpBZaJuoqxzjeyCC9PmTCzdv7vRWyZUONvBK28XSE
         iLbMEErs3eHNuvaRrTQdTyVjRc8GDB2l/uFyX9AcNquYWQI2MgR60sMuX4Ij8XvQP/uJ
         kkQQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxfSgPp8DuHvKJAwoiWs9U4Y4aSXzYzLy2tVHth1c2qngX6ciEw
	g6GV2JdXrRk0SHtCJ9r7vMc=
X-Google-Smtp-Source: AGHT+IGK19F5NIzUTP4iQtMs1/w0brW8fkVTnzNguo651UyoP9FSIaTWtOEVK35DOHhPe4hjf5LjRw==
X-Received: by 2002:a50:ba8f:0:b0:553:46ed:3133 with SMTP id x15-20020a50ba8f000000b0055346ed3133mr185625ede.1.1703189167099;
        Thu, 21 Dec 2023 12:06:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c714:0:b0:553:366d:19ad with SMTP id i20-20020aa7c714000000b00553366d19adls570241edq.1.-pod-prod-00-eu;
 Thu, 21 Dec 2023 12:06:05 -0800 (PST)
X-Received: by 2002:a50:ed12:0:b0:553:e3cb:e64b with SMTP id j18-20020a50ed12000000b00553e3cbe64bmr1480669eds.12.1703189165484;
        Thu, 21 Dec 2023 12:06:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703189165; cv=none;
        d=google.com; s=arc-20160816;
        b=WW7jMjEjunu/w96JWaWWQat4pkqM35K6j2xZm2KY0CkB6C3Js1C/4Hh7Pzo5totVJ3
         nO2hkF4OEbW3Ad//+Dk48mvi80JUydVbnnNHgCwFDKOXDMDHWWOeYpsUvmd44Mt/8Zuk
         QKT79l7922B2RUlGuoMVXg0HZNCRofvehvhoui7QrRTYkSa3KvNQs5xJPJBO1UT7lUnC
         WpfirvTCeRBPX+hZTmj7qSegIh/55VVclaR0iwfuVfTmII8LQlf9inYDEFI05npjWDCP
         V9pnw/b3D8QadkpvqQDoLR2cS2d4tai3cBNbYuDmM6VQ9yThF5D7vl5HVmdhHH4DUX/d
         ltxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=FJl4ImE4TRrDXvrAPN+dS4cgTUzwQEr6h+ILfia+IPo=;
        fh=GyTEpUCUNPwsl1pqA0jDPXgvja+iZTM9USlQd9sQtQg=;
        b=RTgDP3LxrUkcivTCajSCJQPisRL3gl85i0W5NQbjLdxOAiU6bAE5NUlhxiGzGqeWm5
         ElVuasoINGHRRP4SnV++LeliHmc8EyO/ZRlKgBx3jcioTrZtYDb33/qahq2AXAVOa6zb
         Lbli0UynEwevjLpDB1ZIQgyTLwssIYqBJoCd/bGnwZgsz67drDqPojBN1sOKz67tWwd4
         C4BsfHN3Q8yb7wQtAZXtO28YhaKc5IAIVGe/ey+IzMHeuc8rGgFSxcf1U8tCwA/jnNKk
         dV1Np6hYVk/qxn5JcPbAi1NfW0eBPA/bjxFPYovgLt1n2rssMtk7Z+RyzAj5LJFPMDJr
         iJGg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=UQy5FdaO;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b1 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-177.mta0.migadu.com (out-177.mta0.migadu.com. [2001:41d0:1004:224b::b1])
        by gmr-mx.google.com with ESMTPS id cy13-20020a0564021c8d00b00552180ac40fsi106455edb.0.2023.12.21.12.06.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Dec 2023 12:06:05 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::b1 as permitted sender) client-ip=2001:41d0:1004:224b::b1;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 07/11] kasan: respect CONFIG_KASAN_VMALLOC for kasan_flag_vmalloc
Date: Thu, 21 Dec 2023 21:04:49 +0100
Message-Id: <3e5c933c8f6b59bd587efb05c407964be951772c.1703188911.git.andreyknvl@google.com>
In-Reply-To: <cover.1703188911.git.andreyknvl@google.com>
References: <cover.1703188911.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=UQy5FdaO;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::b1 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Never enable the kasan_flag_vmalloc static branch unless
CONFIG_KASAN_VMALLOC is enabled.

This does not fix any observable bugs (vmalloc annotations for the
HW_TAGS mode are no-op with CONFIG_KASAN_VMALLOC disabled) but rather
just cleans up the code.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/hw_tags.c | 7 +++++++
 mm/kasan/kasan.h   | 1 +
 2 files changed, 8 insertions(+)

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 06141bbc1e51..80f11a3eccd5 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -57,7 +57,11 @@ enum kasan_mode kasan_mode __ro_after_init;
 EXPORT_SYMBOL_GPL(kasan_mode);
 
 /* Whether to enable vmalloc tagging. */
+#ifdef CONFIG_KASAN_VMALLOC
 DEFINE_STATIC_KEY_TRUE(kasan_flag_vmalloc);
+#else
+DEFINE_STATIC_KEY_FALSE(kasan_flag_vmalloc);
+#endif
 
 #define PAGE_ALLOC_SAMPLE_DEFAULT	1
 #define PAGE_ALLOC_SAMPLE_ORDER_DEFAULT	3
@@ -119,6 +123,9 @@ static int __init early_kasan_flag_vmalloc(char *arg)
 	if (!arg)
 		return -EINVAL;
 
+	if (!IS_ENABLED(CONFIG_KASAN_VMALLOC))
+		return 0;
+
 	if (!strcmp(arg, "off"))
 		kasan_arg_vmalloc = KASAN_ARG_VMALLOC_OFF;
 	else if (!strcmp(arg, "on"))
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 5fbcc1b805bc..dee105ba32dd 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -49,6 +49,7 @@ DECLARE_PER_CPU(long, kasan_page_alloc_skip);
 
 static inline bool kasan_vmalloc_enabled(void)
 {
+	/* Static branch is never enabled with CONFIG_KASAN_VMALLOC disabled. */
 	return static_branch_likely(&kasan_flag_vmalloc);
 }
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3e5c933c8f6b59bd587efb05c407964be951772c.1703188911.git.andreyknvl%40google.com.
