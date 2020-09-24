Return-Path: <kasan-dev+bncBDX4HWEMTEBRBXOFWT5QKGQEIETSXLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id C18AF277BC7
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 00:51:10 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id e12sf408609pfm.0
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 15:51:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600987869; cv=pass;
        d=google.com; s=arc-20160816;
        b=CE7u6d2/Q6ENobX/cHtyGp/Kv6e6B7QQ2IvEY4XHoYl2HAzqIpUdwrzIfu95JejP79
         B3gOUxOHX/xvxiYOGGHPqWESfK/1oq0XswuMWIxIuZtem9+b8WbLF4Vsl1Sj3ZMEkiAb
         EqQtcONLdwzhA3zpg8n6nM1TeQga+FImSwc8Zl71T4Y/JdZmz99MdEwqzwFGeiHVeCnb
         Iv2q9DOQx1bQVtFkjKqA5FCMWsU20B4fEJ1n4Q/pzvVsl5p/hDkG9v6nxsyxv8nwcidA
         dF0UOAQzfR06yKMhD/XaxJUyS+Wuw1F1xFbNmO1oJ7Z6QO5Avzf8kfSrQXOVVM9TqGLO
         zCCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=OJ2swfhihBr2Ar/uuDISnYANeFWeed4AsvR3ZlK2cOI=;
        b=xBw/v2caebY9XXcUhKqeUZSKHF9xbzU8aVM8BB60oK8VPfxCcpy0sP0WgxxvMLdc9/
         e37RZ8IvMM9c5LKOf6NrXJbWbx1Wzy1vyyj/NLXU8IrKKrtrpoYD/GhIuAz+wbV8+Rm6
         lBgRWunAz6kOBkGoHit50acYCaVYE1dWebs0QuV1Riui2BdbPpfEE+MoskaPACqXZQ5Q
         PwSpLIki+WsfEeIzpOHLf8j7V7vM6FB0b/1e5IxRFbTKGlZyzJ0qSwBbM0LcPY8Fkt+t
         G7pvQ7tzLwjMT3dhhp1yik91QAIu/NpUNjSaPU+e0m9Eupid8Z+n8+whmqj13Q3XYaNE
         oEdA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Tq4lK60X;
       spf=pass (google.com: domain of 33cjtxwokcdc3g6k7rdgoe9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=33CJtXwoKCdc3G6K7RDGOE9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=OJ2swfhihBr2Ar/uuDISnYANeFWeed4AsvR3ZlK2cOI=;
        b=p0A1n0X8K78ByQPro77McRXgqm/MZOeQk2akv+1PQw1845a4iMRBfJmMzyAA5lkXWp
         3VCeaP8BjrscNnyRbg50m+0Wo/KxwHlHo+3aCp59ImNr7tIpijBjg8o3Xkc2a6rwNudt
         lzphcrhxEnwxEUsbB5B55198ORNSmJ07gwAwVAIAe/YQ6BTpdEGzZo9oYEbI76dC5jDU
         10GjwgZPmHZ0K9Pseq2163DefNFq1NCFa8GGOv2WZl1BF2Z66N16YrvL3/reDBCZxEW/
         OjJgTKs9Lo9zFELw/ARPalghH7SitiwtDYD04sQE6jvT7I9HlVYZ1xlRE643sRT1QimG
         urNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OJ2swfhihBr2Ar/uuDISnYANeFWeed4AsvR3ZlK2cOI=;
        b=H3eYGQUXeAq9OJ+LPrXrLvv8NGNMN/tLj4J45ghdxzlGba4MMG+z0HXy8oIkdRirH+
         M5799aDWihJcZQAal6fNe6G3S0xqBlHzIW1I/ZasRI6fd5uiyU/Kl84GvJTjuZvnL/qF
         janVqOfQJfqTc0sX3Fw9o7QEt1h5AV2tRf829ny6QmKbqb7YgCg6MCPYdnkoLIZyodCO
         8jLxehE7EuXlZW9wQlU3M1QCMZ/vz6KUCw9CWqhvIcaSE3bHkCYUNqRBtS6KeVMWUcCQ
         N6+Z9984F/bMu89OwxQj8q/ouh8O7+4ar4Xd6hcxROMt5Q1Ztf5FOXGQgzqgkDZi/Fyr
         ZF+g==
X-Gm-Message-State: AOAM530qrTa1RffbpgvrAl/KqxXQqSrs+dWzmA6pB1YcZOzx7ec3xURL
	3oLtoIWfLcopBHNkwTMHPSw=
X-Google-Smtp-Source: ABdhPJyVodQz+W8NTbG2lpC1Ks/hipxLU7Zcr7gaIkGrIwgWJUz/AyX0+G9sYO/tFLH9gEZjJeimrg==
X-Received: by 2002:a63:1252:: with SMTP id 18mr1093235pgs.246.1600987869509;
        Thu, 24 Sep 2020 15:51:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:551b:: with SMTP id j27ls290561pgb.2.gmail; Thu, 24 Sep
 2020 15:51:09 -0700 (PDT)
X-Received: by 2002:a65:60d0:: with SMTP id r16mr1095519pgv.348.1600987868956;
        Thu, 24 Sep 2020 15:51:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600987868; cv=none;
        d=google.com; s=arc-20160816;
        b=LH/yjKu0wqFY+XJtdGKXaDjqE8sG+CeAjzdGOi8aHgIAcAW/O1MCDHp08X6KidM52W
         iSJgGHYMBvcTDRt3kJYuhOeeNR29XctH6GNjFaf9veJbtTUF0se8aP2cjas4nqj1cHri
         DUY1OhSvtKMW2riJ4YAGNqIuo7nvAV7ttSAhtVpV+EXdsuDEdF5YAioWH7mP7o8xFWXu
         KhxDaIW6XdAYUtAl4GE5508jLxFiMvlkgZpAdMuPJtbVEJ6qNHO7XmtpFjy5R/n9O9oi
         hREruWfo2cCGIzM78RdZlPWFyb2LAyzZ8lIF+m9Yc6TQPDKkOIklzjoRAv/xX/t3XLWV
         tTgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=DufyUr3VDNtonx2hPCICVW4qjhSQO8Lbag8i7ReKhm4=;
        b=pxSu5qxpWfrzMJosPlllzlryOmK0r/rbEb5JpJbRNDz//DntHiL32EkKgG6xkAI2F3
         v2vyINUZdjFjZwhc9KYFVam9+kg92UeEWxxfjVoODX+hxk2rcQQaQODIex+APjKN8qBm
         Og4dOJ8FsHhw3t02wL7bJGdtzldcHPdv20Di3AgITzAtoKJ+nvYigVugA6+LqP+gV1H/
         aHC8/dwYnvH2LI6acJsVizerFdkc7yVd37I3YeWaGClRihoWAAS7VYnhSuR6ZzQT0qe1
         uV6stTO2YLximp0/7B+8ardxbsZXMxGYf0vdAeiBMOpp2mxiL7+HlI2mniYidbpOG9/K
         wmig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Tq4lK60X;
       spf=pass (google.com: domain of 33cjtxwokcdc3g6k7rdgoe9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=33CJtXwoKCdc3G6K7RDGOE9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id bk9si59887pjb.1.2020.09.24.15.51.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 15:51:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of 33cjtxwokcdc3g6k7rdgoe9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id m186so683470qkf.12
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 15:51:08 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:500c:: with SMTP id
 s12mr1591817qvo.7.1600987868036; Thu, 24 Sep 2020 15:51:08 -0700 (PDT)
Date: Fri, 25 Sep 2020 00:50:14 +0200
In-Reply-To: <cover.1600987622.git.andreyknvl@google.com>
Message-Id: <3ecf44f226dac37eb35409dc78568a99343fbf9e.1600987622.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 07/39] kasan: only build init.c for software modes
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Tq4lK60X;       spf=pass
 (google.com: domain of 33cjtxwokcdc3g6k7rdgoe9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=33CJtXwoKCdc3G6K7RDGOE9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--andreyknvl.bounces.google.com;
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

This is a preparatory commit for the upcoming addition of a new hardware
tag-based (MTE-based) KASAN mode.

The new mode won't be using shadow memory, so only build init.c that
contains shadow initialization code for software modes.

No functional changes for software modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
Change-Id: I8d68c47345afc1dbedadde738f34a874dcae5080
---
 mm/kasan/Makefile | 6 +++---
 mm/kasan/init.c   | 2 +-
 2 files changed, 4 insertions(+), 4 deletions(-)

diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
index 370d970e5ab5..7cf685bb51bd 100644
--- a/mm/kasan/Makefile
+++ b/mm/kasan/Makefile
@@ -29,6 +29,6 @@ CFLAGS_report.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_tags_report.o := $(CC_FLAGS_KASAN_RUNTIME)
 
-obj-$(CONFIG_KASAN) := common.o init.o report.o
-obj-$(CONFIG_KASAN_GENERIC) += generic.o generic_report.o quarantine.o
-obj-$(CONFIG_KASAN_SW_TAGS) += tags.o tags_report.o
+obj-$(CONFIG_KASAN) := common.o report.o
+obj-$(CONFIG_KASAN_GENERIC) += init.o generic.o generic_report.o quarantine.o
+obj-$(CONFIG_KASAN_SW_TAGS) += init.o tags.o tags_report.o
diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index dfddd6c39fe6..1a71eaa8c5f9 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -1,6 +1,6 @@
 // SPDX-License-Identifier: GPL-2.0
 /*
- * This file contains some kasan initialization code.
+ * This file contains KASAN shadow initialization code.
  *
  * Copyright (c) 2015 Samsung Electronics Co., Ltd.
  * Author: Andrey Ryabinin <ryabinin.a.a@gmail.com>
-- 
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3ecf44f226dac37eb35409dc78568a99343fbf9e.1600987622.git.andreyknvl%40google.com.
