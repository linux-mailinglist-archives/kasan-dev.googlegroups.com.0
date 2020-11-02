Return-Path: <kasan-dev+bncBDX4HWEMTEBRBXO4QD6QKGQEGK4K55Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6EA5C2A2F28
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Nov 2020 17:05:50 +0100 (CET)
Received: by mail-ed1-x53c.google.com with SMTP id y99sf6031271ede.3
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Nov 2020 08:05:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604333150; cv=pass;
        d=google.com; s=arc-20160816;
        b=jLOQXNhi+B2gZeBeHkcCBytokVSTxuH0bmHXRF7oMcwfqZXWdmv2HxDtdUt4D0TJwl
         Pq56Rz2U8vSnlgceKk8ykVladxXPhlf5TbSDZNDUCMktsqAP7Hv3nQrHBuYcyObA1Ybb
         JiN6T9i5chJ9En/7oekP5WIgakYl3HxiSN8HglOrfwaBzdavYn2rDONqdpC+hPdre+Hh
         uBhx8yPczDDba/bw/a2ZSyJSFahETdhRS4qQGuuy5WKCH9Q4GsXjQhFup0FMjGCCJBr8
         5VlWtXf8KDIEa7ag0QFF+Xh769GI+jRg9FROEqjbCSNrpfR7p4fmDOZeliKMfeOYBpmX
         tFIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=rkHLeOgw5TGQjSyFv/4OeIodBxxfHieDwiE6d60Ds4A=;
        b=Lxeg1sOg/txZ4GjhpWwssqkKBMhmgeduOxuA9sj+CGIJgPHUA4PZsPEJjTi8XEH5Tn
         +XCK1/kyYQLGYBUDmhViiKxyEC8I06gzV4hgn0WQ41P2RlgCztxeRVd4Q77j3NVy6Mrc
         4Lp9zhIfCgJBay5wUpEfYIJCt9jRLWH7DEH3XI+L3NUhdKqnl9BeVVl1qlkzShGxHh82
         CmKdAT3Dl8CR3MG7IME7fHdsaYPho1ektPOLE9LYzb/gxw4EkNhoqT+JJF/kDMVWObkk
         auBPVXhNezLncS/5S43Gypak/3UBsEqpbDcuBicwdhc8n5n9ENHjKzC21JNu/qk1Jyg0
         i5UA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qPcFaq77;
       spf=pass (google.com: domain of 3xc6gxwokct0zmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3XC6gXwoKCT0Zmcqdxjmukfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=rkHLeOgw5TGQjSyFv/4OeIodBxxfHieDwiE6d60Ds4A=;
        b=PfeMAr+fMIcP1K++L0nWD/Z8JcR5qMOIbmDWjfPA669zFHr656GgSNBnsPe95hvoAG
         7E4qv5wSRldnWhlEIr6Qb8wZKZSM58PKtQbaD0TWEFcfEtt/EdVzIUOdnke7tyVIV3VY
         KfZIL1/0BQTdmhyhp7J2SqVb2P+0linwJXAfgfuggn9SVdas2K6i6wVncc9mnS0uqAin
         ihdcNb097jf9P1iED0iWJcGZph1AlkNvsMhRmBszXJT1/VZexQfD5EOVEuSSZrBRJrnm
         6iNxKXm4rSN3rUVYPHrd425BAp4q8W/S18FRlhpc/NAr65+Cehv04RB1MvbfScYRl2H8
         LewA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rkHLeOgw5TGQjSyFv/4OeIodBxxfHieDwiE6d60Ds4A=;
        b=l/gKi6fLk5Te+gq4vEll9NLH0HJ69gDE3wOffmkVL4Luj2LsFf8jZH+aqllAEtERg2
         8piYP8IyDgIJrZlPbquO/xEG+HpWIoG6HGHkjk5nhg7o7JaKas4dFO5mB4kYyws9X3iD
         gaOERu4Tl4i+e6te8m5nA3/daPkcifgcPyW1P6oRgOK645AiceW6DdxtXGdrLOghRPST
         JSTBItREeV/89CEx/fH3ehGqX26Czc50HlQU0abdNuJs16gIdnqYIUFlEOAiEQ24zMA+
         SWPM9TCJPJuLN4VmFakZNWmzgGBxI3GK47lB5GSyG5yx3wqPZZmRfojYN/qt1qkDud6g
         3iCA==
X-Gm-Message-State: AOAM532yfaBRp0LZ32GjlYFBfoILyBBM07LiUWYnrEbe0sathwi4AwTe
	Du2AyCEu2XLou3PkBYcvXR4=
X-Google-Smtp-Source: ABdhPJwcSLzYdntCNMn7n2Bka6ZY3za+2UIaxZNBrzR9g31EH2+Ubs5CoVxrdQViyNd1ImMQp8dWLQ==
X-Received: by 2002:a50:f98b:: with SMTP id q11mr3408666edn.345.1604333150186;
        Mon, 02 Nov 2020 08:05:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:1351:: with SMTP id x17ls3752878ejb.4.gmail; Mon, 02
 Nov 2020 08:05:49 -0800 (PST)
X-Received: by 2002:a17:906:8319:: with SMTP id j25mr8409388ejx.68.1604333149280;
        Mon, 02 Nov 2020 08:05:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604333149; cv=none;
        d=google.com; s=arc-20160816;
        b=U2BaCt0pvHivuqTDoOLdhoiIoHutiG/B+PujBkR91bATInzwTzaZq3ihECKYI7kVkr
         YwpOHRGMq/Eomk4fkmsC4JpSiw+2fVleV3SkOUwdUGEOD1hRl/oqM0quDcZwuUlq+DAr
         4Yjp7/lnCvEwR75tB41FrvK/88llEMZ/rjgilcRrqAYLsy5v9HK7O9eG4Ei+7YbqDgH0
         Z2e77p8fzbVLMldLSCuvyn3ITDhZe3r24yetlBYeTJMcUMax5EkzihWFWDDQnqefJ3M0
         lIgYR+xJA/cC65/7opY59TeQrFT8Fo+x+25egMExqkau6XIHNzFAZhdua4ICwdTpPL4K
         WCvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=NNmCWg3uUJkm97N9bODpJVOfWoCAwpfkACCfjKkMoC0=;
        b=c2jOUVwHe+EAb5BcOuEQ/Otz8MYAXIRUC8U4PaYYdbXjqcstePFELrPUVI/WKbFVtx
         HOzxR22KG0OLCvkZzCPAwmOAh/qaikQXg0g+GL93Pni6PSzV/Mlz8TP+Bq5Bo0ska/zq
         YgooiFEgtPjFX8/ra5LH7XPhmT2NpDj/OW15W93WkIe6dGD365jr3w4ihlQ6XcLR1Z5L
         X/rJl9ch6Zoqo1usMwUP0mUp4Su9uyrdaEOxkqTbd2V5/+qupAgmO+i4j59u3TGgafGs
         m+LDWo3/VrV/YfmWXTi00NBuNkOctL6mpqa2QMKVXp8uETfeMQLa8OEJHQMkZ6TShZUj
         YZWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qPcFaq77;
       spf=pass (google.com: domain of 3xc6gxwokct0zmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3XC6gXwoKCT0Zmcqdxjmukfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id g4si332790edt.2.2020.11.02.08.05.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Nov 2020 08:05:49 -0800 (PST)
Received-SPF: pass (google.com: domain of 3xc6gxwokct0zmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id x16so6564012wrg.7
        for <kasan-dev@googlegroups.com>; Mon, 02 Nov 2020 08:05:49 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:b0ca:: with SMTP id
 z193mr18288765wme.82.1604333148905; Mon, 02 Nov 2020 08:05:48 -0800 (PST)
Date: Mon,  2 Nov 2020 17:04:14 +0100
In-Reply-To: <cover.1604333009.git.andreyknvl@google.com>
Message-Id: <bd64e051e8e36ac25751debc071887af3d7f663f.1604333009.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 34/41] kasan, x86, s390: update undef CONFIG_KASAN
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
 header.i=@google.com header.s=20161025 header.b=qPcFaq77;       spf=pass
 (google.com: domain of 3xc6gxwokct0zmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3XC6gXwoKCT0Zmcqdxjmukfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com;
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

With the intoduction of hardware tag-based KASAN some kernel checks of
this kind:

  ifdef CONFIG_KASAN

will be updated to:

  if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)

x86 and s390 use a trick to #undef CONFIG_KASAN for some of the code
that isn't linked with KASAN runtime and shouldn't have any KASAN
annotations.

Also #undef CONFIG_KASAN_GENERIC with CONFIG_KASAN.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I2a622db0cb86a8feb60c30d8cb09190075be2a90
---
 arch/s390/boot/string.c         | 1 +
 arch/x86/boot/compressed/misc.h | 1 +
 2 files changed, 2 insertions(+)

diff --git a/arch/s390/boot/string.c b/arch/s390/boot/string.c
index b11e8108773a..faccb33b462c 100644
--- a/arch/s390/boot/string.c
+++ b/arch/s390/boot/string.c
@@ -3,6 +3,7 @@
 #include <linux/kernel.h>
 #include <linux/errno.h>
 #undef CONFIG_KASAN
+#undef CONFIG_KASAN_GENERIC
 #include "../lib/string.c"
 
 int strncmp(const char *cs, const char *ct, size_t count)
diff --git a/arch/x86/boot/compressed/misc.h b/arch/x86/boot/compressed/misc.h
index 6d31f1b4c4d1..652decd6c4fc 100644
--- a/arch/x86/boot/compressed/misc.h
+++ b/arch/x86/boot/compressed/misc.h
@@ -12,6 +12,7 @@
 #undef CONFIG_PARAVIRT_XXL
 #undef CONFIG_PARAVIRT_SPINLOCKS
 #undef CONFIG_KASAN
+#undef CONFIG_KASAN_GENERIC
 
 /* cpu_feature_enabled() cannot be used this early */
 #define USE_EARLY_PGTABLE_L5
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bd64e051e8e36ac25751debc071887af3d7f663f.1604333009.git.andreyknvl%40google.com.
