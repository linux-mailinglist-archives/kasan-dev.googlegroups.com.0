Return-Path: <kasan-dev+bncBDCPL7WX3MKBBBGJ3HAAMGQE6PSAGBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F5A1AA81F7
	for <lists+kasan-dev@lfdr.de>; Sat,  3 May 2025 20:46:30 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-4769a8d15afsf49796211cf.3
        for <lists+kasan-dev@lfdr.de>; Sat, 03 May 2025 11:46:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746297989; cv=pass;
        d=google.com; s=arc-20240605;
        b=F+lT9uRkbJAgn5GEbyyrVxmw2P/7Me4nSUR7dOy2EZWtJluIPe2PL1lzExsISzjo2N
         d2CZqN3bKPTtYcOjowN841T/FHUfsASTcOKy4Zz9MH42coIN7eV+ZeEO5TKTH1C5QIII
         ycSZFGTViFRql/QpVaJahq+mS84D4TQznfyaZQNojWbP39xcQObuOZ+JDs1ryp2ZbEke
         nU7yr2IY28FaJwi85vw8qOJT6q6ZfXfTR7X2/thzzBWj0rdVWZLUhHoGfm4V9X0YsKyC
         NFebisoeDhyg2LwARBjygdrXbHeSjfua08RC2cywTsG6N+znRg45uEmkhdzsUEQOEcCK
         nKdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=iZ2OpuDiSlvZvxjw6U6bHgloF/ov8oa3Y9c8iX/G+wI=;
        fh=A6A/O8EIND1HZRW7Gacyyqm/oila8+RA+Mlc3/r+Lb4=;
        b=BXOWkYmo9mJ/XTErxLAMTO4NiX06vrfU/RIXMN0tRfu9883zxYVjTgpLY0JjFzdsup
         u8zOhzwl/zlj12fVFNaVVWy8V/D4N1mvj9h/OehdEubYw7HZ6oVEk+HSiBTZ8xeoZMvf
         TS7AEGDuIL5W+n4RdlqWOj5ixM23HNrh0UkBTKXr+EChBm8rJCzt604cWNLaHbUtOyRX
         0hmny3kO7/1YzawrI/jqKnvuW5ccbTF3DxTn7vh2eF86C+jhECrgiH/18BETFl1crW4R
         R4/LyavMB/B2tO8KvZSs0TbtwfqY0TR2PNLqdrVQHmpiSEvy0nrrbom23lZ2eMaXVgCT
         Awag==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="E/5UvviY";
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746297989; x=1746902789; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=iZ2OpuDiSlvZvxjw6U6bHgloF/ov8oa3Y9c8iX/G+wI=;
        b=Bse10N7tUF4Y4G0rMFMLesAulagCekywB+kQNsc3Jq7okU+jiHwmFsyTAyGss9VU7g
         wpMwYWJSe6gqKKD7HOP19slw/TcGwY4KrclpgCRBWbjQT9H8e48lklN6UvD/kmP0V6Ov
         k/60F1hrunSKVeu8jD6Z94nwE6h2kHYSUcEAO4OrzORjvLUKzH47WTHDZ/1d8hq7gPah
         h5jU8uDl77ClelWFqqPNRItY1sDPse98D0XNWQHSzcLglXCqcO37H6ia1DvU5n5hHPzJ
         N5b8wJdSg9+IJGdmrE8S2Ze0eqynHb0DdljOfktN3YMmvRwFwOtLItcihzcdjHX/xItV
         nVBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746297989; x=1746902789;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=iZ2OpuDiSlvZvxjw6U6bHgloF/ov8oa3Y9c8iX/G+wI=;
        b=OcRsKWPwAdOi/Gn5hx1jxbj7Rn7PujCpqQB87jwxGJMY48OpGdNeWHk221l//5wX06
         /XaN2QTabiVIVf9pcFQicufjriyoW97tH/QBHfc4ZJJO8b472tpIoZSC+oXfbP4Zqc40
         jIJ24LlUEn0w5skjJd6WQndwECh85VUigNYkYnKDOZKCdAuJ+R3nYMKqNzV4TAI55MsJ
         pdTtErN3h1bSxtP/JCjSUWwqbv0yIcHhVxXXkIUM0OAYC6m27AgJR7b13rYUwTkeylQt
         3Q434L55mtV83JojLSzvBKG/DoKDqTn0/xbMxZgwnJr7emOPO+HKL+FsVSV31cu2MtL8
         q0cw==
X-Forwarded-Encrypted: i=2; AJvYcCWm8s7pRoQ8x5tvIrO0EFI92Q/0//OSZCvN4BzxtqC21r6yIt5VG9akx4TubMff5PioU6+uRw==@lfdr.de
X-Gm-Message-State: AOJu0YxOuF6XTkRZNiCwNkAmkaMMnlaTIAFMBV4fEHhFEesoQMPEhy0w
	Fseae+yefkcZL1LM3PeWlDgP4KapOa0QPOSbFvVAY1rboGHqkmn2
X-Google-Smtp-Source: AGHT+IGclskpWnIzB7ZEQdlMHu56fhc7MUUNcJ3dE52xUdjg5/U/Bt0XAewal0C1djDmP4MiSV0B1Q==
X-Received: by 2002:a05:622a:4a09:b0:476:8225:dac9 with SMTP id d75a77b69052e-48d5da48b21mr56536531cf.45.1746297988897;
        Sat, 03 May 2025 11:46:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBETmV/D0a85/Igw3YmRIDoHpRG0iaiYDS/WXano2VeeeQ==
Received: by 2002:a05:622a:1a97:b0:476:91a5:c821 with SMTP id
 d75a77b69052e-48ad8bbea81ls26685541cf.2.-pod-prod-03-us; Sat, 03 May 2025
 11:46:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWWuWH/gb62j9B9APhavUQ0AINYgy/cwzSrPDSindHDIkFls55c/uc9+C53DSd5CWh0S9thdmflZnM=@googlegroups.com
X-Received: by 2002:ac8:5d48:0:b0:48b:40a7:fee1 with SMTP id d75a77b69052e-48d5b96cbe7mr56279681cf.11.1746297987804;
        Sat, 03 May 2025 11:46:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746297987; cv=none;
        d=google.com; s=arc-20240605;
        b=I+Wo8YJ0h9fKs33I1CDfkmhecj/lNE+OAUncVODTKXP8MUxyQzIwk6qx5+erOAW0hI
         cXxFd0L1HnNPFT/aUE/aof7FJ9eyMoolHBrWKLyHb/d0tSSX2ZrMLn85EjklVx6zejDF
         PF6sRopZORT6LQa+cAaLedhuBriPYSYhWBNkRnal9GDuR+/cYa2k4fbcHoOKa06R2WbD
         GLs2/JiudoBn2sYbod1tD2WVeZ3KZuU665cOU7v8/c/zqawHJ3V2ciSWuy60c5d0VP4M
         iSmPhVGIvqifch8d6JWc/8HK/j1IkWPVBjOOmDFF8mcSxt/63f/699pMHB5kzw/oj2Gn
         dA9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=d4KrfESvuMUsyz4SWl6r3QCYAPzM0MzPQfo37dYoLZo=;
        fh=zOkMLXLBlsqDLMI+1Hafgv1XkzdBd9L/MFhYwpoF8OE=;
        b=Nu3gT8S2mYq0jRIu9owcMaLTubEdFOuD3toL9s0f4B6IP3AiwMQSDyx7J8Mc1kYuZ0
         CGcgYiS9whnM/BDYSGY6+VjBunxsJ0duWICwbUEOv9e0R9CblzO01lqJJvaTM5Fj2x8B
         6lXMu+IIqAGYwJ87qg1mSe2nQqGpwe6qA0fAaI+31NauoWC9ucfBxhoIZ9IfgsjvHiTl
         4y7HFN1QWRf7lIbsth1pvKbp29YGNIUrfZhXVkaRQRTElsKSTXe2gEXxqhy75u2T0Q4n
         lC2EGjgyfKDY7z78gZpLcDoPGJsGDLUoiqkxjuyhHvox199Bf/Y2vENG9Stby5WDuJo6
         c+/w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="E/5UvviY";
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-48b98a267c1si2324001cf.5.2025.05.03.11.46.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 03 May 2025 11:46:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 516B061126;
	Sat,  3 May 2025 18:45:57 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 80319C4AF0B;
	Sat,  3 May 2025 18:46:26 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Masahiro Yamada <masahiroy@kernel.org>
Cc: Kees Cook <kees@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Nathan Chancellor <nathan@kernel.org>,
	linux-hardening@vger.kernel.org,
	linux-kbuild@vger.kernel.org,
	Petr Pavlu <petr.pavlu@suse.com>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	Justin Stitt <justinstitt@google.com>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	llvm@lists.linux.dev
Subject: [PATCH v3 1/3] gcc-plugins: Force full rebuild when plugins change
Date: Sat,  3 May 2025 11:46:18 -0700
Message-Id: <20250503184623.2572355-1-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250503184001.make.594-kees@kernel.org>
References: <20250503184001.make.594-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=4099; i=kees@kernel.org; h=from:subject; bh=vcmcNB9M/mnVV0u1TxfACvPzuwlKwH4U0CbHSsTxvvI=; b=owGbwMvMwCVmps19z/KJym7G02pJDBliyftYMz0PPeCzUN3AeedYZIn/ro+vFtTaZi1jryxji P75JD6uo5SFQYyLQVZMkSXIzj3OxeNte7j7XEWYOaxMIEMYuDgFYCI9nQx/eAXnbl5/btvnlRlX neQ7dc5/2MPWInTRLi1CKTM3dB1fOyPDsRulL/9NuPHAXNpf6bDhB6OrK7VcI7jMZ5xn+2H9ye0 kLwA=
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="E/5UvviY";       spf=pass
 (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

There was no dependency between the plugins changing and the rest of the
kernel being built. This could cause strange behaviors as instrumentation
could vary between targets depending on when they were built.

Generate a new header file, gcc-plugins.h, any time the GCC plugins
change. Include the header file in compiler-version.h when its associated
feature name, GCC_PLUGINS, is defined. This will be picked up by fixdep
and force rebuilds where needed.

Add a generic "touch" kbuild command, which will be used again in
a following patch. Add a "normalize_path" string helper to make the
"TOUCH" output less ugly.

Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: Masahiro Yamada <masahiroy@kernel.org>
Cc: Nicolas Schier <nicolas.schier@linux.dev>
Cc: Nathan Chancellor <nathan@kernel.org>
Cc: <linux-hardening@vger.kernel.org>
Cc: <linux-kbuild@vger.kernel.org>
---
 include/linux/compiler-version.h |  4 ++++
 scripts/Makefile.gcc-plugins     |  2 +-
 scripts/Makefile.lib             | 18 ++++++++++++++++++
 scripts/gcc-plugins/Makefile     |  4 ++++
 4 files changed, 27 insertions(+), 1 deletion(-)

diff --git a/include/linux/compiler-version.h b/include/linux/compiler-version.h
index 573fa85b6c0c..74ea11563ce3 100644
--- a/include/linux/compiler-version.h
+++ b/include/linux/compiler-version.h
@@ -12,3 +12,7 @@
  * and add dependency on include/config/CC_VERSION_TEXT, which is touched
  * by Kconfig when the version string from the compiler changes.
  */
+
+#ifdef GCC_PLUGINS
+#include <generated/gcc-plugins.h>
+#endif
diff --git a/scripts/Makefile.gcc-plugins b/scripts/Makefile.gcc-plugins
index 5b8a8378ca8a..e50dc931be49 100644
--- a/scripts/Makefile.gcc-plugins
+++ b/scripts/Makefile.gcc-plugins
@@ -38,7 +38,7 @@ export DISABLE_STACKLEAK_PLUGIN
 
 # All the plugin CFLAGS are collected here in case a build target needs to
 # filter them out of the KBUILD_CFLAGS.
-GCC_PLUGINS_CFLAGS := $(strip $(addprefix -fplugin=$(objtree)/scripts/gcc-plugins/, $(gcc-plugin-y)) $(gcc-plugin-cflags-y))
+GCC_PLUGINS_CFLAGS := $(strip $(addprefix -fplugin=$(objtree)/scripts/gcc-plugins/, $(gcc-plugin-y)) $(gcc-plugin-cflags-y)) -DGCC_PLUGINS
 export GCC_PLUGINS_CFLAGS
 
 # Add the flags to the build!
diff --git a/scripts/Makefile.lib b/scripts/Makefile.lib
index 2fe73cda0bdd..6fc2a82ee3bb 100644
--- a/scripts/Makefile.lib
+++ b/scripts/Makefile.lib
@@ -296,6 +296,19 @@ $(foreach m, $1, \
 	$(addprefix $(obj)/, $(call suffix-search, $(patsubst $(obj)/%,%,$m), $2, $3))))
 endef
 
+# Remove ".." and "." from a path, without using "realpath"
+# Usage:
+#   $(call normalize_path,path/to/../file)
+define normalize_path
+$(strip $(eval elements :=) \
+$(foreach elem,$(subst /, ,$1), \
+	$(if $(filter-out .,$(elem)), \
+	     $(if $(filter ..,$(elem)), \
+		  $(eval elements := $(wordlist 2,$(words $(elements)),x $(elements))), \
+		  $(eval elements := $(elements) $(elem))))) \
+$(subst $(space),/,$(elements)))
+endef
+
 # Build commands
 # ===========================================================================
 # These are shared by some Makefile.* files.
@@ -343,6 +356,11 @@ quiet_cmd_copy = COPY    $@
 $(obj)/%: $(src)/%_shipped
 	$(call cmd,copy)
 
+# Touch a file
+# ===========================================================================
+quiet_cmd_touch = TOUCH   $(call normalize_path,$@)
+      cmd_touch = touch $@
+
 # Commands useful for building a boot image
 # ===========================================================================
 #
diff --git a/scripts/gcc-plugins/Makefile b/scripts/gcc-plugins/Makefile
index 320afd3cf8e8..05b14aba41ef 100644
--- a/scripts/gcc-plugins/Makefile
+++ b/scripts/gcc-plugins/Makefile
@@ -66,3 +66,7 @@ quiet_cmd_plugin_cxx_o_c = HOSTCXX $@
 
 $(plugin-objs): $(obj)/%.o: $(src)/%.c FORCE
 	$(call if_changed_dep,plugin_cxx_o_c)
+
+$(obj)/../../include/generated/gcc-plugins.h: $(plugin-single) $(plugin-multi) FORCE
+	$(call if_changed,touch)
+always-y += ../../include/generated/gcc-plugins.h
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250503184623.2572355-1-kees%40kernel.org.
