Return-Path: <kasan-dev+bncBDT2NE7U5UFRBU4HS34QKGQEQRF2BPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe40.google.com (mail-vs1-xe40.google.com [IPv6:2607:f8b0:4864:20::e40])
	by mail.lfdr.de (Postfix) with ESMTPS id 090352352DE
	for <lists+kasan-dev@lfdr.de>; Sat,  1 Aug 2020 17:01:41 +0200 (CEST)
Received: by mail-vs1-xe40.google.com with SMTP id v20sf606610vsi.6
        for <lists+kasan-dev@lfdr.de>; Sat, 01 Aug 2020 08:01:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596294100; cv=pass;
        d=google.com; s=arc-20160816;
        b=CqQCBOosWBS7slcIARpxU4D91yS+5Axt+0WFpjBnCwEj2zgloXo25hqQEN/Fl3O7fF
         ZNs7tinXXFBD9Ph/jEnW614MQxBdQicWH2xM62nlry9GgFajlhq7rSLOi03vtuoMatzE
         v1ya0T1Rns91MxgUBUjFdQtus3m5KKwLD6p5k6hgopzj0bVz0MW206cGI3iRrb+g0Gt7
         hyF7iqe3RICRmqnAiVBJoWfBQABJyGRmXAJwnOWzjSIJKFb4wFbriYcgVd7/7sWOeeuj
         LLitanCXugUDCu/6nFOAr3m/5hCzbQwKhMhoxG63EcYDL3OxroOr+pobqViMGGDO3gPZ
         TDUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:dkim-filter:sender:dkim-signature;
        bh=44M8QdhQlQsT0oU8uSE7ri69p/1NbNwBWKrWolyP/Fw=;
        b=awE1RnpJfU0WN9X47rLZKrtxDyrwk5zLuJpBZiBCfTxmZnUgZRoiSXQJnBOKPqDtqI
         TlzWqhF1ahlWZFG1xhMrZw+bKiwhmppmJ57x/HW+kd4hv5LqHMHXC150RdB0vHL9kGvG
         EeWFgGSZytJfZt/nOWM8MOevn3BeLyoUcKnCWtCfHDzkxEjCJbOimgMf5JQ32YrSNUCB
         ElVadi0Qi9JqXdvm8XzK6HlPQ/ZjvVt+J7G6CEBeN/XyMLAV3jx7azcFi/PicAHPyppc
         s5Nb2ABRD9/BYdIO+lliM3DNWkVL0gmQ/EdgsQUBsTRQmxymrjkVPWdlj55OJBdDRXMN
         0tDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@nifty.com header.s=dec2015msa header.b=c0JKLZBN;
       spf=softfail (google.com: domain of transitioning masahiroy@kernel.org does not designate 210.131.2.78 as permitted sender) smtp.mailfrom=masahiroy@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:dkim-filter:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=44M8QdhQlQsT0oU8uSE7ri69p/1NbNwBWKrWolyP/Fw=;
        b=coxFFj+hmurxzkwY3VTj/TYTJMcZRzL5mmngpaLgyyv+JNxOxWq3q1mIoY27AlQUZ9
         jkldvrWgB2ZBBm/IiGc3290x0+LA5lhpIQwOcjv6KihrJvEZ+4hfm4Rd+PWKvokKleT3
         Kx/hp9bIqHqqXHohEGqQw3Wr59l2UIknpo5Ixv5h97RSmoQFTVfUoe4uMFDQhl1PHtzc
         J/+/ZHzxZ+3zQc5i/oh6buJy0Nt2bYSUJOGw+7+55Ow2VbUOcIxz5Wsqi2L3ffQ4NRly
         NwCZf1SL222LZyZ/VnjD8WncC3eCey6UWURlxGyMDdMzagsFB51YLmZ+AuqKF3wrX/NC
         8lzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:dkim-filter:from:to:cc:subject:date
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=44M8QdhQlQsT0oU8uSE7ri69p/1NbNwBWKrWolyP/Fw=;
        b=ADI67kQi0E+TusgSaMu0kawo+pYB9OU4Yv/3+kOhbRF1aMg+3zhxAkPZj7XDdQ9szS
         OyZMUd0JRPg5nO+1SJPEuct6XqwDQPlbQPJOJs4+zhzYpWG+ToPFBRqiT3Gx13B4Sblf
         LvUgLpMLywmwwp3njqsiywi/D1TAIt2mnOugLESybEodZTFaQJyl5U5qfSAlY6uy2iNM
         84XHrEU0tf1XowHH0IjSEgXXbBtf9eTobMibzK4gBRU9fkMF9bmdPD6w6C8s+wFMIhal
         W7n3ec8530fqhKBN2vCg5OzIJNRAsT1fRkKdlUwG0MVic07ecouaibqoXHYZvzlYb7D1
         ku8A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533hHVZik2c6fB6sp5aVsbVUxwOPgNC9NiVJvsWpGQ9GY7eBtqjr
	KMNbKbrwCJy+Leur70DtRts=
X-Google-Smtp-Source: ABdhPJwZb/r2Ln35dZwGrWukpqKQqVyd30Bv/aCqygWcup1Q7GAy6HvPnkIlfxW1Eaqk5XYflsPVdQ==
X-Received: by 2002:a67:ffca:: with SMTP id w10mr6311108vsq.142.1596294099839;
        Sat, 01 Aug 2020 08:01:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:4d6c:: with SMTP id k44ls846085uag.2.gmail; Sat, 01 Aug
 2020 08:01:39 -0700 (PDT)
X-Received: by 2002:ab0:2bcc:: with SMTP id s12mr5808874uar.117.1596294099476;
        Sat, 01 Aug 2020 08:01:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596294099; cv=none;
        d=google.com; s=arc-20160816;
        b=jwPg0MP8RmvNIzQ7F6oDIliQT5UJdENXbRoG29dtnqxYiuGNPGPNA4MkYaIWM/o/v5
         u9h2PkiJktmSrJLgcimNiCUnvnO6u65YnU/NDZVoQGqC8/MBcUnlV7NQMe3IOMQtAThC
         p63mP+c01bonK1dnvw6EccQi5IzWy7IfdPSmJPvk0pOvWI3OL+nNWHM6qSfJKBSI3fUb
         MOMHinx8fO3XeI9pDvAk3fcSImiLBio4MfHVGxgH+naxsfsgJMhCaHCWrGNMyAJK6VfO
         ZAPWOeu5f1CHgc4YozNWug20olRm9nvF7YiQyMJRQPIbTPIgLGoRrlJ+fwnKxvDQvQsi
         7LYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature:dkim-filter;
        bh=iB+4Axh/LScTu6iv9y46G7fJslW+Ej8Wjx6mPd1aNvk=;
        b=ewRhEb8LL7Ls0YOnha7dzywevvdVydyWSV4uXmWNKjwSzc3umTOW9zq75zdlOrtn+A
         68gckD2iJ4W7wSgmLiRFgMmAhcKb1VeT9pa00xv6ALLHPfnkb04DRFo3qOoTs5Lky/el
         RSiZPWsrBIHfdKwqti9+wNCmAeqSBnOjAa6N8zd68VKDTYfHfkf6QvQUYo/A+li8L5Q+
         SBAhGSv4L8diJT66ZMBQeQaSaJaInUWzO7UlYstfbZAZxBJ7RWvr0447o7mpAO3quZyO
         MxgRkBPX909ahF9jrndpFndCjpgxf8ql4rXunpVF6p/DkP4iD3ZyrzDDGzZDcg8Ow2A+
         ouiw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@nifty.com header.s=dec2015msa header.b=c0JKLZBN;
       spf=softfail (google.com: domain of transitioning masahiroy@kernel.org does not designate 210.131.2.78 as permitted sender) smtp.mailfrom=masahiroy@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from conuserg-11.nifty.com (conuserg-11.nifty.com. [210.131.2.78])
        by gmr-mx.google.com with ESMTPS id x6si391168vko.1.2020.08.01.08.01.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 01 Aug 2020 08:01:39 -0700 (PDT)
Received-SPF: softfail (google.com: domain of transitioning masahiroy@kernel.org does not designate 210.131.2.78 as permitted sender) client-ip=210.131.2.78;
Received: from oscar.flets-west.jp (softbank126025067101.bbtec.net [126.25.67.101]) (authenticated)
	by conuserg-11.nifty.com with ESMTP id 071F0q51015446;
	Sun, 2 Aug 2020 00:00:53 +0900
DKIM-Filter: OpenDKIM Filter v2.10.3 conuserg-11.nifty.com 071F0q51015446
X-Nifty-SrcIP: [126.25.67.101]
From: Masahiro Yamada <masahiroy@kernel.org>
To: linux-kbuild@vger.kernel.org
Cc: linux-kernel@vger.kernel.org, Kees Cook <keescook@chromium.org>,
        Masahiro Yamada <masahiroy@kernel.org>,
        Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>,
        Michal Marek <michal.lkml@markovi.net>, kasan-dev@googlegroups.com
Subject: [PATCH 1/2] kbuild: include scripts/Makefile.* only when relevant CONFIG is enabled
Date: Sun,  2 Aug 2020 00:00:49 +0900
Message-Id: <20200801150050.767038-1-masahiroy@kernel.org>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
X-Original-Sender: masahiroy@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@nifty.com header.s=dec2015msa header.b=c0JKLZBN;       spf=softfail
 (google.com: domain of transitioning masahiroy@kernel.org does not designate
 210.131.2.78 as permitted sender) smtp.mailfrom=masahiroy@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

Currently, the top Makefile includes all of scripts/Makefile.<feature>
even if the associated CONFIG option is disabled.

Do not include unneeded Makefiles in order to slightly optimize the
parse stage.

Include $(include-y), and ignore $(include-).

Signed-off-by: Masahiro Yamada <masahiroy@kernel.org>
---

 Makefile               | 16 +++++++++-------
 scripts/Makefile.kcov  |  4 ----
 scripts/Makefile.kcsan |  4 ----
 scripts/Makefile.ubsan |  3 ---
 4 files changed, 9 insertions(+), 18 deletions(-)

diff --git a/Makefile b/Makefile
index ebf4d3ce492c..483456d5dd3e 100644
--- a/Makefile
+++ b/Makefile
@@ -745,9 +745,6 @@ endif
 KBUILD_CFLAGS	+= $(call cc-option,--param=allow-store-data-races=0)
 KBUILD_CFLAGS	+= $(call cc-option,-fno-allow-store-data-races)
 
-include scripts/Makefile.kcov
-include scripts/Makefile.gcc-plugins
-
 ifdef CONFIG_READABLE_ASM
 # Disable optimizations that make assembler listings hard to read.
 # reorder blocks reorders the control in the function
@@ -948,10 +945,15 @@ ifdef CONFIG_RETPOLINE
 KBUILD_CFLAGS += $(call cc-option,-fcf-protection=none)
 endif
 
-include scripts/Makefile.kasan
-include scripts/Makefile.extrawarn
-include scripts/Makefile.ubsan
-include scripts/Makefile.kcsan
+# include additional Makefiles when needed
+include-y			:= scripts/Makefile.extrawarn
+include-$(CONFIG_KASAN)		+= scripts/Makefile.kasan
+include-$(CONFIG_KCSAN)		+= scripts/Makefile.kcsan
+include-$(CONFIG_UBSAN)		+= scripts/Makefile.ubsan
+include-$(CONFIG_KCOV)		+= scripts/Makefile.kcov
+include-$(CONFIG_GCC_PLUGINS)	+= scripts/Makefile.gcc-plugins
+
+include $(addprefix $(srctree)/, $(include-y))
 
 # Add user supplied CPPFLAGS, AFLAGS and CFLAGS as the last assignments
 KBUILD_CPPFLAGS += $(KCPPFLAGS)
diff --git a/scripts/Makefile.kcov b/scripts/Makefile.kcov
index 52b113302443..67e8cfe3474b 100644
--- a/scripts/Makefile.kcov
+++ b/scripts/Makefile.kcov
@@ -1,10 +1,6 @@
 # SPDX-License-Identifier: GPL-2.0-only
-ifdef CONFIG_KCOV
-
 kcov-flags-$(CONFIG_CC_HAS_SANCOV_TRACE_PC)	+= -fsanitize-coverage=trace-pc
 kcov-flags-$(CONFIG_KCOV_ENABLE_COMPARISONS)	+= -fsanitize-coverage=trace-cmp
 kcov-flags-$(CONFIG_GCC_PLUGIN_SANCOV)		+= -fplugin=$(objtree)/scripts/gcc-plugins/sancov_plugin.so
 
 export CFLAGS_KCOV := $(kcov-flags-y)
-
-endif
diff --git a/scripts/Makefile.kcsan b/scripts/Makefile.kcsan
index bd4da1af5953..2b0743e6566e 100644
--- a/scripts/Makefile.kcsan
+++ b/scripts/Makefile.kcsan
@@ -1,6 +1,4 @@
 # SPDX-License-Identifier: GPL-2.0
-ifdef CONFIG_KCSAN
-
 # GCC and Clang accept backend options differently. Do not wrap in cc-option,
 # because Clang accepts "--param" even if it is unused.
 ifdef CONFIG_CC_IS_CLANG
@@ -15,5 +13,3 @@ CFLAGS_KCSAN := -fsanitize=thread \
 	$(call cc-option,$(call cc-param,tsan-instrument-func-entry-exit=0) -fno-optimize-sibling-calls) \
 	$(call cc-option,$(call cc-param,tsan-instrument-read-before-write=1)) \
 	$(call cc-param,tsan-distinguish-volatile=1)
-
-endif # CONFIG_KCSAN
diff --git a/scripts/Makefile.ubsan b/scripts/Makefile.ubsan
index 5b15bc425ec9..27348029b2b8 100644
--- a/scripts/Makefile.ubsan
+++ b/scripts/Makefile.ubsan
@@ -1,6 +1,4 @@
 # SPDX-License-Identifier: GPL-2.0
-ifdef CONFIG_UBSAN
-
 ifdef CONFIG_UBSAN_ALIGNMENT
       CFLAGS_UBSAN += $(call cc-option, -fsanitize=alignment)
 endif
@@ -26,4 +24,3 @@ endif
       # -fsanitize=* options makes GCC less smart than usual and
       # increase number of 'maybe-uninitialized false-positives
       CFLAGS_UBSAN += $(call cc-option, -Wno-maybe-uninitialized)
-endif
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200801150050.767038-1-masahiroy%40kernel.org.
