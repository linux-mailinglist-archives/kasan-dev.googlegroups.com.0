Return-Path: <kasan-dev+bncBDX4HWEMTEBRB4ENY36AKGQE3MIVZLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D676295FB0
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 15:19:46 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id r4sf858078pgl.20
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 06:19:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603372785; cv=pass;
        d=google.com; s=arc-20160816;
        b=GMOLITvCmEe/BC/Y7nvOJSgvRnsYtFgXLPda57kQP7EVBI5U1w+XYaItLjNJWKIZSf
         5hNBHLKUuWvmP0TOSxkC7xxJf5uMR0/VQYAY/mapET3bx3NF6lxI0KscwKrdFdOiD8WE
         N4cChiSwunGI9zSkxYvJIRYWnfORxHcxjy/GwCnmPQjO2pm1CiChKf9QD2Cqa2Kv0d17
         72ubUDZhXUbFXu8GrqrFYxdYG+QFILZGVz1sZ8k7BHMO6+s6cv/EHuwrJ3H8td0lYrdH
         64ZU6dr3ngoHTLSwhLW/diwtjg3nzXAooPKA/0lrIqT7bZI/9I+UqLsbfntyrG1qz6sB
         E+KQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=QA+M/v+XkUef0uxHJvsx6dNIMlaRCXgfQHY7CUR/DOg=;
        b=spc9rtUFhWJHvIUXJWdb6rb9ta5i6gEzLSBQK+HpBb3mgV3c1BKeMdb1Ux7pNc/sK8
         EXRT0bkACoijFU/tLWgLRuKl581mJNBohyHllVQNB8IIw2uccESMrmOXxZd3ApsbDOb9
         kD+TaBI8jOXzCQk9rXtvr64R6Vi+X045VUGhzD8/i8XZawn46s7KisYdgtCEJX5Uuxpe
         z1XpcAjabLmCV6vWILmeg21Ong73MbE7e0ep7xSKgkVAk7Hr0X0Jm6j+5Q3y+wTIW6VN
         8+/cKXBpyIVcKtlXYgQFfPxZWdiycMZO7puBofNsmKcohIJ3AXDcRX2yz2UPmoABJ3n5
         kDfA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="A/DzVj6N";
       spf=pass (google.com: domain of 37yarxwokcuqgtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=37YaRXwoKCUQgtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=QA+M/v+XkUef0uxHJvsx6dNIMlaRCXgfQHY7CUR/DOg=;
        b=cmzf6LT9VPxA4pEGTitL9OyEdMaAMbTcrRNKLy79vGHye+EDqqN5hkxVMjka28Dulo
         F/yEXWO/Sve0yDhEp3vYtOzcz7UNznfXj17wib3ZFBBZ+OnBZuPNbuF0AI9JJZFBTTOJ
         PoG5iqSpjCDKTVndXibwTdfrkuPYecWXqSzSznlQxOdxXeANsLUXomh9ZAfT8x1qHkVa
         pcrNt9TOU8QvxkywjldHKxYXf4mRH4fghtKabaxz83oTLe4cnlmrRdSY6Ng8fhEzl0uM
         IcQCTZPrcb1QWBllAv3lEQ1s46ofW6+Qo6R9Co77YQwYa+ir8Xwl4cxgSLuGU5h5rzR6
         4uzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QA+M/v+XkUef0uxHJvsx6dNIMlaRCXgfQHY7CUR/DOg=;
        b=TDo1oo4Kc+8jmD608UZUCOMJMWu2S0B7okjcn9iay06Kiit9WRboDqVuVJdBaO4k8N
         jv+bXxUSSemYjpW0sMpsyBY2RhjHbe/kisN8pEeTWIKxUZkdx6KLpHwTudENebn+d+gm
         ckHy5fh6hXYJdSISHQigjl9RAxeh23+1UlaQv80qj8UKYRE/NelHlav4rRENLzj5e5FF
         KYoDI9I+MmQtpIZwzrm+4TqLYIWoRUIMqU+DDsjp5Kjwf2sKPUspnKiTjs28zJrg0qBX
         dJDD/+FmqAdFijbC5N80VFHM50YkQBMnZE/LWbMdzs+cO4q8K/pG+Lcq7WFTRodBoMmQ
         wSFQ==
X-Gm-Message-State: AOAM532rE2SMatjF0ygwkxoW5olE58HI1DwEd5Rf5fVWYyEGId4qc1v1
	j3Jma3WCE707hdaJTecdBFA=
X-Google-Smtp-Source: ABdhPJyKlWtIf4MG0aUANvozrxFQy5XmPVOK7Pb7Msuu6Tswi3XftaLBhBJeJ/5POfQ/JYAwnKWliQ==
X-Received: by 2002:a17:902:ec02:b029:d2:ab80:4dcc with SMTP id l2-20020a170902ec02b02900d2ab804dccmr2453603pld.64.1603372784968;
        Thu, 22 Oct 2020 06:19:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7c43:: with SMTP id x64ls752924pfc.1.gmail; Thu, 22 Oct
 2020 06:19:43 -0700 (PDT)
X-Received: by 2002:aa7:9048:0:b029:152:883a:9a94 with SMTP id n8-20020aa790480000b0290152883a9a94mr2463110pfo.24.1603372782831;
        Thu, 22 Oct 2020 06:19:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603372782; cv=none;
        d=google.com; s=arc-20160816;
        b=aWe2ecpjQVugwuIg+PqdzTP9YwJ8FSPVKV1A2Eul5Z/OuRTzQS7TWNQjtzwgds98LM
         aRyJlM/nDGSx4BREJ/eaK1tbZTYaxFxRkQQS0+SnHRlCS6vCyZ0tcdWudGs71M3rptVl
         nBXkpviG4Rx+C7/Q6RIXkuDq0pvVNLtMWiyWD+cs1mubtsa3pxzXckWPk5SReQHQGqgG
         HLwo9PxDrR7e/DMt7Doh2m5kiuatnK6UNtzx1hb2TMo4XajUtzZd5gpt4G/d/v0a8Yba
         5URxLVPFxdeS3KJVLJ9G1ZcVru38nBfiFTBkaeA26/EP+H7ncIOmRH4uH3Lvoz+LxZrj
         WAnw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=S3zpKFgl6lOQ4xschlXI9IBqFZJcfplQNQgfAvCSd9c=;
        b=foAABkxwzumpruWAazFAiKBYmMV36v3lNOBLwsbuwIP0lQ2/kmCwMufTMCeWzZWIX6
         H3qB6cuS39/vVfHWUB1xaSO3EfVq6rEMxhHe6QFSASW8MWjFt55k6aps7TM347PXc53g
         6XbueZWB3tH1oATCDbYwzOsdBnuuK3MSAYQrqiHBs0zHRXyiun7wHKBVQRJAI0ikS9rL
         hUSombkDAXX+TZ/Z291CSvp5X5q5fjv7RaAB6ai4G9elcUUNfiBBnC4FejI+8EHqVmjc
         LGBmiRlpxRUq8+QH26WvhSjv2rCCVt2wZkLv3SeqdINlRxTLfRMJAHm/3rOvVzPbHJwb
         FnPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="A/DzVj6N";
       spf=pass (google.com: domain of 37yarxwokcuqgtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=37YaRXwoKCUQgtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id d2si152403pfr.4.2020.10.22.06.19.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 06:19:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of 37yarxwokcuqgtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id d1so1016177qtq.12
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 06:19:42 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:52c6:: with SMTP id
 p6mr2361291qvs.38.1603372781851; Thu, 22 Oct 2020 06:19:41 -0700 (PDT)
Date: Thu, 22 Oct 2020 15:18:59 +0200
In-Reply-To: <cover.1603372719.git.andreyknvl@google.com>
Message-Id: <1d87f0d5a282d9e8d14d408ac6d63462129f524c.1603372719.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.0.rc1.297.gfa9743e501-goog
Subject: [PATCH RFC v2 07/21] kasan, arm64: move initialization message
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>, Kostya Serebryany <kcc@google.com>, 
	Peter Collingbourne <pcc@google.com>, Serban Constantinescu <serbanc@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="A/DzVj6N";       spf=pass
 (google.com: domain of 37yarxwokcuqgtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=37YaRXwoKCUQgtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
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

Tag-based KASAN modes are fully initialized with kasan_init_tags(),
while the generic mode only requireds kasan_init(). Move the
initialization message for tag-based modes into kasan_init_tags().

Also fix pr_fmt() usage for KASAN code: generic mode doesn't need it,
tag-based modes should use "kasan:" instead of KBUILD_MODNAME.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/Idfd1e50625ffdf42dfc3dbf7455b11bd200a0a49
---
 arch/arm64/mm/kasan_init.c | 3 +++
 mm/kasan/generic.c         | 2 --
 mm/kasan/hw_tags.c         | 4 ++++
 mm/kasan/sw_tags.c         | 4 +++-
 4 files changed, 10 insertions(+), 3 deletions(-)

diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index b6b9d55bb72e..8f17fa834b62 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -290,5 +290,8 @@ void __init kasan_init(void)
 {
 	kasan_init_shadow();
 	kasan_init_depth();
+#if defined(CONFIG_KASAN_GENERIC)
+	/* CONFIG_KASAN_SW/HW_TAGS also requires kasan_init_tags(). */
 	pr_info("KernelAddressSanitizer initialized\n");
+#endif
 }
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index de6b3f03a023..d259e4c3aefd 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -9,8 +9,6 @@
  *        Andrey Konovalov <andreyknvl@gmail.com>
  */
 
-#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
-
 #include <linux/export.h>
 #include <linux/interrupt.h>
 #include <linux/init.h>
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 0128062320d5..b372421258c8 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -6,6 +6,8 @@
  * Author: Andrey Konovalov <andreyknvl@google.com>
  */
 
+#define pr_fmt(fmt) "kasan: " fmt
+
 #include <linux/kasan.h>
 #include <linux/kernel.h>
 #include <linux/memory.h>
@@ -18,6 +20,8 @@
 void __init kasan_init_tags(void)
 {
 	init_tags(KASAN_TAG_MAX);
+
+	pr_info("KernelAddressSanitizer initialized\n");
 }
 
 void *kasan_reset_tag(const void *addr)
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index bf1422282bb5..099af6dc8f7e 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -6,7 +6,7 @@
  * Author: Andrey Konovalov <andreyknvl@google.com>
  */
 
-#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
+#define pr_fmt(fmt) "kasan: " fmt
 
 #include <linux/export.h>
 #include <linux/interrupt.h>
@@ -41,6 +41,8 @@ void __init kasan_init_tags(void)
 
 	for_each_possible_cpu(cpu)
 		per_cpu(prng_state, cpu) = (u32)get_cycles();
+
+	pr_info("KernelAddressSanitizer initialized\n");
 }
 
 /*
-- 
2.29.0.rc1.297.gfa9743e501-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1d87f0d5a282d9e8d14d408ac6d63462129f524c.1603372719.git.andreyknvl%40google.com.
