Return-Path: <kasan-dev+bncBDX4HWEMTEBRBHV5YX3AKGQE72PXRWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 511DA1E8760
	for <lists+kasan-dev@lfdr.de>; Fri, 29 May 2020 21:12:32 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id y11sf368607pfn.3
        for <lists+kasan-dev@lfdr.de>; Fri, 29 May 2020 12:12:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590779551; cv=pass;
        d=google.com; s=arc-20160816;
        b=eEWKaeY1aYBrV8AEkYWiA8snTG7SuTJwJDuA92DV130AtvBUfjuQ6DAoVkNThqCbKe
         KAUOuyEXihV/H2EK4v7VZWs3oG6RTuxn5Vf8JD8FXQ1BDUJY4xCzJ6OBpXTDtAmAw4HN
         TQTey+F7snYIsp041lC4k2PdaiLx32Os8ehCzjzPeFnu3B9kf/4tJL1JnGVysOyzYoiB
         TBwYjqg69FR5EVR+a+BYOb8NCXSUjEEBRsjAmBJ9e4V/y44Em+myUMBIyw4PV/raGK0D
         JQQcxenFShUQTWrmBGtVFXR4xDIyCmaeoactpldwDyTPpoqHs2B+c6oJm/EOLZ1CV28Z
         5cdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=tsAd5I9RpccZl6XRMv15U4C8WNWeNcdk7uHb3FAH3bI=;
        b=YHUtisOhKQnYBAmEfckw/7MLL6DPVx9yDqqhaog/WkwyCgLgT3Y5+UG8pyaVMBcNiE
         0VRESIs5i0JSZf5ie/JS1nymFY0o9RqRv8ds2Bq+JKrj13cjQXh9EaTChgYMFxhhy8C2
         pmpKVwc2wCkDsUL5aDxGPLpaGpgkoA3IrJLY0n9q2hGTLe7FX+XacJhqidYFfxTmmeoh
         A1NG2hHWxNV1d2EshrSnO8/G6yn51kHPkd5xHq2hSHFH96s47/hek1osqGmjNHJGE7NV
         JkNG4CYyxC346fBCmKGuBrFC+Qb4izPXK3zgu+Gt8WLOp9NhODeWe/XJ6+R7pB/dnXG2
         zIYg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tgFYRSTN;
       spf=pass (google.com: domain of 3nv7rxgokczw6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3nV7RXgoKCZw6J9NAUGJRHCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=tsAd5I9RpccZl6XRMv15U4C8WNWeNcdk7uHb3FAH3bI=;
        b=UUJr8nvqODrpLT/2ly4+rObYR0D/McRH70HVvzXv04YOM9N4MFUf3VqTC2vps4JAo/
         pC/3z76YZTlz+ocK6a2/jVA0Qzma9GEmx1KXlEcUkAJyQ502q7F9jzBSRwlzQbSeM95Z
         W+VOHnsqLyXVFfijUdwM3jYrvTEZPnh9MDCjS55hjd3g+/HFq8QFygrHC/JH2zSIsHRS
         /buVMwYsfquEX33erGmfB4yLa3KFHmKmOaNdRFwfvSV0UMXNwVp9gX+i/VKysbO7+Kmj
         +ukNCEGwPpv2K/rOlTWRSk8JNvPAh33WiAPazuGIVpVvGqD37asXxkwsK7DrmaVR96RT
         m8oQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tsAd5I9RpccZl6XRMv15U4C8WNWeNcdk7uHb3FAH3bI=;
        b=AHc6eQfF3hi5N4bq4bK+moMZS2w5iYEs4WBLqJ60YCg9UgYdG+OayE09JdizcQV4KK
         L47v+ZHihLt2XjIEdxOdHJdQiS9/pAvau7YbHbXX0Ponur/jVcPsyrOKSX69Ftj6AN/b
         wKUE7R38z4T7TCqHVRc3o8fG1SjLEik0P6VOiGwTDwQ5vHcjVrLJCLKWpSmM5ui8Zge4
         ZxzUen5UzZYmtkT1XwXFRgSQ3JMsl9gGaLAHuLUHTHkcfliH3lUkmM5GDp8oYMLE5HxX
         hpw36nlg3ao2zgKwittSS2wuOKWkrI64nlAmMhM94nopOf4SBjLfNEhCfbBcF/ocXGb6
         34hQ==
X-Gm-Message-State: AOAM530nseYu38oabynQ6jl5+SroCxbTVbev5gdbHVB6LbcirIWJE3Tf
	6ylcp9N0MEcLaK31VVjTeNA=
X-Google-Smtp-Source: ABdhPJyR/AOx8SYgU2sns18yB8yqCtzHRP8bO3HCGwV42B28UPgcwOJxmLZCwLAIma+fOTi1M+IhKA==
X-Received: by 2002:a62:7d4d:: with SMTP id y74mr10257257pfc.286.1590779551019;
        Fri, 29 May 2020 12:12:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:e283:: with SMTP id d3ls3271939pjz.2.gmail; Fri, 29
 May 2020 12:12:30 -0700 (PDT)
X-Received: by 2002:a17:902:b115:: with SMTP id q21mr10077480plr.182.1590779550556;
        Fri, 29 May 2020 12:12:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590779550; cv=none;
        d=google.com; s=arc-20160816;
        b=O4HGw1kHRskGe7ZSC6rVyq83lN7iND8lyoHCAArFLkNyKjaR9UILPvOtY4NHpFC8NT
         C5zd4WgPRYxlkaCoJXDipGewJeIlNrTJ5B3Z6NXmEQkSy91X3CS7WW9hJV4yUBsbRUn/
         iWXry04129Hh90BissX5xB0w7lguEiE3Q7qk6FceGISki+nTxircwy5ZLuGF5XjGzhJQ
         VZKcWcAZIR2cjRFa2adkokYuO82WkzgxAi01o5/EKim+AD6a4WTWSviVvFgyCGlKOaar
         iJR8lVToQAosx9/tWK7oyISTafQKl956HxggBxfZ0bAUBGcAo+aLsMZTegMvg/IIJ6nd
         i61A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=Moz+9hZdr2Y6CaabpiR/TuFRSQrzGhwHDxQkw4rcCBs=;
        b=EGoIoQD54DZlv7ZZJZayQUAcBypR8rKEud1P4/r0k4J3S7gxUhUrRShAhR1wwHQi4i
         m9O1CWiucMKSQzCSxUBnEY2ipRso6qxukyxsRzExy7sRGGJOxwwHbCs8ORA1yoLcpRwk
         qwjVctLI3ExnANrmJPF0u2RU/fEMyXVNuJyLXmjns0yKCHxUuFwL82mzlt0SzLC3wDuq
         eQ/ovyfit3xauFxI22NdXm05/8TRKpT9a/ZqUzN4J2LhIoxi3zfx3T12EOUevFDG15dm
         rbeTR6nFF3FpGp6aLdQvageFCpW2KY8Tu17vXILzEL/R0CjG2/YWOHvDewqxDHXr3or4
         9yfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tgFYRSTN;
       spf=pass (google.com: domain of 3nv7rxgokczw6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3nV7RXgoKCZw6J9NAUGJRHCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id a22si17399pjv.3.2020.05.29.12.12.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 May 2020 12:12:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3nv7rxgokczw6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id l6so341164qkk.14
        for <kasan-dev@googlegroups.com>; Fri, 29 May 2020 12:12:30 -0700 (PDT)
X-Received: by 2002:a0c:e4d3:: with SMTP id g19mr9444906qvm.42.1590779549611;
 Fri, 29 May 2020 12:12:29 -0700 (PDT)
Date: Fri, 29 May 2020 21:12:25 +0200
Message-Id: <c2f0c8e4048852ae014f4a391d96ca42d27e3255.1590779332.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.27.0.rc0.183.gde8f92d652-goog
Subject: [PATCH v2] kasan: fix clang compilation warning due to stack protector
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Marco Elver <elver@google.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Qian Cai <cai@lca.pw>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=tgFYRSTN;       spf=pass
 (google.com: domain of 3nv7rxgokczw6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3nV7RXgoKCZw6J9NAUGJRHCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--andreyknvl.bounces.google.com;
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

KASAN uses a single cc-option invocation to disable both conserve-stack
and stack-protector flags. The former flag is not present in Clang, which
causes cc-option to fail, and results in stack-protector being enabled.

Fix by using separate cc-option calls for each flag. Also collect all
flags in a variable to avoid calling cc-option multiple times for
different files.

Reported-by: Qian Cai <cai@lca.pw>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---

Changes v1 -> v2:
- Renamed CC_FLAGS_KASAN_CONFLICT to CC_FLAGS_KASAN_RUNTIME.

---
 mm/kasan/Makefile | 21 +++++++++++++--------
 1 file changed, 13 insertions(+), 8 deletions(-)

diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
index de3121848ddf..d532c2587731 100644
--- a/mm/kasan/Makefile
+++ b/mm/kasan/Makefile
@@ -15,14 +15,19 @@ CFLAGS_REMOVE_tags_report.o = $(CC_FLAGS_FTRACE)
 
 # Function splitter causes unnecessary splits in __asan_load1/__asan_store1
 # see: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=63533
-CFLAGS_common.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
-CFLAGS_generic.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
-CFLAGS_generic_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
-CFLAGS_init.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
-CFLAGS_quarantine.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
-CFLAGS_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
-CFLAGS_tags.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
-CFLAGS_tags_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector) -DDISABLE_BRANCH_PROFILING
+CC_FLAGS_KASAN_RUNTIME := $(call cc-option, -fno-conserve-stack)
+CC_FLAGS_KASAN_RUNTIME += $(call cc-option, -fno-stack-protector)
+# Disable branch tracing to avoid recursion.
+CC_FLAGS_KASAN_RUNTIME += -DDISABLE_BRANCH_PROFILING
+
+CFLAGS_common.o := $(CC_FLAGS_KASAN_RUNTIME)
+CFLAGS_generic.o := $(CC_FLAGS_KASAN_RUNTIME)
+CFLAGS_generic_report.o := $(CC_FLAGS_KASAN_RUNTIME)
+CFLAGS_init.o := $(CC_FLAGS_KASAN_RUNTIME)
+CFLAGS_quarantine.o := $(CC_FLAGS_KASAN_RUNTIME)
+CFLAGS_report.o := $(CC_FLAGS_KASAN_RUNTIME)
+CFLAGS_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
+CFLAGS_tags_report.o := $(CC_FLAGS_KASAN_RUNTIME)
 
 obj-$(CONFIG_KASAN) := common.o init.o report.o
 obj-$(CONFIG_KASAN_GENERIC) += generic.o generic_report.o quarantine.o
-- 
2.27.0.rc0.183.gde8f92d652-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c2f0c8e4048852ae014f4a391d96ca42d27e3255.1590779332.git.andreyknvl%40google.com.
