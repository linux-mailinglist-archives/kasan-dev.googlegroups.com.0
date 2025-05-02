Return-Path: <kasan-dev+bncBDCPL7WX3MKBBHM22XAAMGQEIRHW4IA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id C493CAA7C75
	for <lists+kasan-dev@lfdr.de>; Sat,  3 May 2025 00:54:22 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-3d90a7e86f7sf62122925ab.2
        for <lists+kasan-dev@lfdr.de>; Fri, 02 May 2025 15:54:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746226461; cv=pass;
        d=google.com; s=arc-20240605;
        b=gSLfMkIf+2S/yg6LT2XtPFGqVmYkTqRUvqoZsME2itbTxGejq5AUIytnW3X9DiHMYS
         BPeRvr+2On7w2ZLYKvSsZJlbGPhz07BZolTOJEXqjkGV0yWTSliXrgZVVB0TFWFoiCVE
         89wziwG/1Wde25jmcH6STzTalWs394pE5GapbC5Uf6gKmjl9nrkoPEv0qChjEBo1phQo
         nNPI0i7ChYTJ1qqyUc1y48va774tI/2dv7f90hOJqHqIQe2eYND/QbNZJE8sehzCMA40
         JiiyHGeTKb9O9lJXq5dzC9UDlBIxfMyG55uqpPSKcYDN9UChGnLxTLQ+5vAiB2YIQqvr
         5yrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=UKYFu/gRlf0sCPSPisDjvukXWNobeV7bgvyyw6JrRlk=;
        fh=PyZY/QdwFvmHhm5CFYCthQNk3iM6nh5BIiBk3wrC25U=;
        b=kqyXS3lhSdRs/Vm3x3SUNHCHyjNTXhwOMBdyfjSezEBha6Sy/LpSoeggxhHnDuudQz
         8qHgsWBOWYTzvb7283TfJw84XUy7SE/xGXKsnEj2rEELYm408RBcuz1GVGnVYLaeHmyv
         azzKDMoSx1qpE5/WRpPLQOm1S7PSLPH+7ARcyuqQssou8XOg4vmWFf/q9vFr1TN6mA0g
         twFlS8Og++rWQbjW/gfEBXxXIMXF8f/NZ4gC+kzo06Ob32fadKacDZDZJndZH0h0wt2B
         J8IjXB7rmlh0RlXGDVTQbEnDQllPBbUr7mQaA17W8pzCVuUfOSKWZ4VqRo8N04tv0e/0
         fjRw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="ssm7w/5O";
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746226461; x=1746831261; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=UKYFu/gRlf0sCPSPisDjvukXWNobeV7bgvyyw6JrRlk=;
        b=FclFb5erhHE5nnmoAeSKqMHg5xExXxgn0TFXhannItirlo9KgE1nnb/9Ud9oFSmvkG
         XnR/L0lCuPnKudvqJ4S/JX9BM7kIz6fwFCYGw1JvyeJAMokcj3E6kwvUu4gzN4zYM8ss
         P4xCnx8hQed+iqaKBYUIUQKukS9rCKSs1FtiY21K4lL3vSHdhXJLNam9rPMjYyK2JF/Z
         mUCjh/XxdZ+HSMKOXPG2q646APNrT1UNVlspH3ISXRwXsnRDvmCRCgyst0Dk/DENrlZr
         jAbY6Ix+EceLAW4S/v+lwIIbJUkK2uEyTftwnJvJtOHN+OlIfPG0YJGjFhkmtHysPM9T
         AShQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746226461; x=1746831261;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=UKYFu/gRlf0sCPSPisDjvukXWNobeV7bgvyyw6JrRlk=;
        b=CWwFYN9TaYhwlPbmkSxf8iiyXP8cZalFnDypCOD+aWF+fM0J63adpo0dOtqiNNty9S
         AfUoPLil4WnWsTO2KWbkCQuU3+8ld6iFVFPaeTQfmC2jOkvCkLF2v0vPR236F+UWcvCf
         iZwAic6lxXdkNUqPvAcOlladuQ4MezqcuRTFe6FhaGXpLSeKSznm95V8y7JO0Z8Kssty
         ElKCuQMiFdQjNbUFfeRQ6tUdcaoGK7p3pA+2yKUrPiY6d8VRO2o6rpeF168D7m09xQpK
         a5c8KMgl/LK4TB+qqF7C1/83vKUgl7ZKjt3Wp7e4pQjDo7VbBivt67HYrphCm5Vx0Nts
         sCSw==
X-Forwarded-Encrypted: i=2; AJvYcCUsQWYyZoMAbKokd8ZkvLYIpr6vB9QPiEyesjG5OMFx4frpL4oqlHWwDZI8chMVGzIFUm4VIA==@lfdr.de
X-Gm-Message-State: AOJu0YyiFq8dowKcq18yoDkLGQNq9LzXa8A5bWE51OgEEY3LPwFOqFtT
	WKZoemp6/jdnhKH3pa9CYyxYgc0xojx6adS6Vey42ow/8xO3mypG
X-Google-Smtp-Source: AGHT+IGI1Qs+irt/Es3UbZdm+QWknIGXuwTIwNkahYyjLIpvw7h5FjafXmpJXpRT34L3Cbte0Xne4Q==
X-Received: by 2002:a05:6e02:1f06:b0:3d0:4e0c:2c96 with SMTP id e9e14a558f8ab-3d97c1541d2mr59258835ab.2.1746226461407;
        Fri, 02 May 2025 15:54:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBEynF7Qb036OUwY53oFX9RbVVHwr6F+vYgVwcho/plECw==
Received: by 2002:a92:ca45:0:b0:3d4:564c:718a with SMTP id e9e14a558f8ab-3d96e7f3b6dls22988965ab.1.-pod-prod-08-us;
 Fri, 02 May 2025 15:54:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXvOYFUptzoPb9N0OS2MXmy59IHgjw0zGC68n62m/vDbJzeOuDwZyaxaYrKf4zBwpsms7lTn7suOYc=@googlegroups.com
X-Received: by 2002:a05:6602:3e90:b0:864:6799:6059 with SMTP id ca18e2360f4ac-8669f990d22mr672341639f.3.1746226460720;
        Fri, 02 May 2025 15:54:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746226460; cv=none;
        d=google.com; s=arc-20240605;
        b=UPGSmpmn2Pttw5pb/tNwE0PkDCOaY2PJZXt/w4HbKXs/FMVThJULh09NJVj7BhDU8O
         RgfRGDJeaIDhd/2JxEE937oj3F+lDb0Au1Q1t52YVmYvgyIAkw1qcQL0XCqhOjYtnekw
         aIAsw7JrJG6U/ipTjML+ANdixS2z1kTK/A4dzLV36IRDI1JiH6LOnEx7asWjEYzaKRIA
         sCBunG0uS060iKXIqmlFqqEK0OvFnZt6yno897vFlxtts1zbfFYUpyhQ6pqR8CEHa+W4
         dHgbzB96D5ne3IPs4vG0A6j/dSzuiSsrUkQTXuE1zH+Yp+joeEeL7GuZ5hJYRi0eZaRd
         U2xQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=jIBtEyAokjAEkZnBAUAX5LDb5f/8nH7cHbyE0gJC8u8=;
        fh=9HuoAGOkpK9C71m1ef+oZS1WAi4U+QnJVmqamFtP4H0=;
        b=g5238kzCj6RoP+x3nZFsSb1R4cF1xskhD0IQzWQdLlr12JaBjZevNpyVc5voLS5IM2
         2K2n/EunoMNJ1+xDCyJE5dBH3TMkpzoA0OkchXB9mNBzcTlez4fG5m2EN2Ojv2XdSSKH
         seSZw/XnCTELiI15GWRNjmzttCpGzREjB9hiQHbpR3iB6X1F3qLek2CCrJD6n5fVdt5G
         XYFqVsYlk+2d5wq0MeXzcD2NhGmV1o1AXXc49/DvlmwQodFJoxpxqRi6ji5Y65cOFzn5
         o8v/IKpYKefYM3QebfRY379h1jFGNWuJLKrajM9/fEaJTUuPvqe8b2lTPCdhCXeokTTi
         gZLw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="ssm7w/5O";
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-864aa407dc3si16047239f.4.2025.05.02.15.54.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 02 May 2025 15:54:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 97E534A88A;
	Fri,  2 May 2025 22:54:17 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C6EC5C4AF0C;
	Fri,  2 May 2025 22:54:19 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Masahiro Yamada <masahiroy@kernel.org>
Cc: Kees Cook <kees@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	linux-hardening@vger.kernel.org,
	linux-kbuild@vger.kernel.org,
	Petr Pavlu <petr.pavlu@suse.com>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	Justin Stitt <justinstitt@google.com>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Richard Weinberger <richard@nod.at>,
	Anton Ivanov <anton.ivanov@cambridgegreys.com>,
	Johannes Berg <johannes@sipsolutions.net>,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-um@lists.infradead.org
Subject: [PATCH v2 1/3] gcc-plugins: Force full rebuild when plugins change
Date: Fri,  2 May 2025 15:54:13 -0700
Message-Id: <20250502225416.708936-1-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250502224512.it.706-kees@kernel.org>
References: <20250502224512.it.706-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=3599; i=kees@kernel.org; h=from:subject; bh=p3LCBG41fA+N9OOg7h+A3NTLbRHrJjxplvYJ9i2fjRY=; b=owGbwMvMwCVmps19z/KJym7G02pJDBmivmJ2fLZvdZtuL3ln0FN9zyeba4Wj2k17D3nRxQXrd vdMr2PqKGVhEONikBVTZAmyc49z8XjbHu4+VxFmDisTyBAGLk4BmEjGNEaG31vtb+Y+u61978cH qSv9Qt/MA2r2XlX+dImj81RrVk9POMP/KOPbz/fsmLXErj3kugvzgqC892Eblgc1Mnx9/1GLbac cJwA=
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="ssm7w/5O";       spf=pass
 (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
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
kernel being built. Enforce this by including a synthetic header file
when using plugins, that is regenerated any time the plugins are built.

This cannot be included via '-include ...' because Makefiles use the
"filter-out" string function, which removes individual words. Removing
all instances of "-include" from the CFLAGS will cause a lot of
problems. :)

Instead, use -I to include the gcc-plugins directory, and depend on the
new -DGCC_PLUGINS_ENABLED flag to include the generated header file via
include/linux/compiler-version.h, which is already being used to control
full rebuilds. The UM build requires that the -I be explicitly added.

Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: Masahiro Yamada <masahiroy@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>
Cc: Nicolas Schier <nicolas.schier@linux.dev>
Cc: <linux-hardening@vger.kernel.org>
Cc: <linux-kbuild@vger.kernel.org>
---
 arch/um/Makefile                 | 1 +
 include/linux/compiler-version.h | 4 ++++
 scripts/Makefile.gcc-plugins     | 2 +-
 scripts/gcc-plugins/Makefile     | 8 ++++++++
 4 files changed, 14 insertions(+), 1 deletion(-)

diff --git a/arch/um/Makefile b/arch/um/Makefile
index 1d36a613aad8..8cc0f22ebefa 100644
--- a/arch/um/Makefile
+++ b/arch/um/Makefile
@@ -72,6 +72,7 @@ USER_CFLAGS = $(patsubst $(KERNEL_DEFINES),,$(patsubst -I%,,$(KBUILD_CFLAGS))) \
 		$(ARCH_INCLUDE) $(MODE_INCLUDE) $(filter -I%,$(CFLAGS)) \
 		-D_FILE_OFFSET_BITS=64 -idirafter $(srctree)/include \
 		-idirafter $(objtree)/include -D__KERNEL__ -D__UM_HOST__ \
+		-I$(objtree)/scripts/gcc-plugins \
 		-include $(srctree)/include/linux/compiler-version.h \
 		-include $(srctree)/include/linux/kconfig.h
 
diff --git a/include/linux/compiler-version.h b/include/linux/compiler-version.h
index 573fa85b6c0c..08943df04ebb 100644
--- a/include/linux/compiler-version.h
+++ b/include/linux/compiler-version.h
@@ -12,3 +12,7 @@
  * and add dependency on include/config/CC_VERSION_TEXT, which is touched
  * by Kconfig when the version string from the compiler changes.
  */
+
+#ifdef GCC_PLUGINS_ENABLED
+#include "gcc-plugins-deps.h"
+#endif
diff --git a/scripts/Makefile.gcc-plugins b/scripts/Makefile.gcc-plugins
index 5b8a8378ca8a..468bb8faa9d1 100644
--- a/scripts/Makefile.gcc-plugins
+++ b/scripts/Makefile.gcc-plugins
@@ -38,7 +38,7 @@ export DISABLE_STACKLEAK_PLUGIN
 
 # All the plugin CFLAGS are collected here in case a build target needs to
 # filter them out of the KBUILD_CFLAGS.
-GCC_PLUGINS_CFLAGS := $(strip $(addprefix -fplugin=$(objtree)/scripts/gcc-plugins/, $(gcc-plugin-y)) $(gcc-plugin-cflags-y))
+GCC_PLUGINS_CFLAGS := $(strip $(addprefix -fplugin=$(objtree)/scripts/gcc-plugins/, $(gcc-plugin-y)) $(gcc-plugin-cflags-y)) -I$(objtree)/scripts/gcc-plugins -DGCC_PLUGINS_ENABLED
 export GCC_PLUGINS_CFLAGS
 
 # Add the flags to the build!
diff --git a/scripts/gcc-plugins/Makefile b/scripts/gcc-plugins/Makefile
index 320afd3cf8e8..24671d39ec90 100644
--- a/scripts/gcc-plugins/Makefile
+++ b/scripts/gcc-plugins/Makefile
@@ -66,3 +66,11 @@ quiet_cmd_plugin_cxx_o_c = HOSTCXX $@
 
 $(plugin-objs): $(obj)/%.o: $(src)/%.c FORCE
 	$(call if_changed_dep,plugin_cxx_o_c)
+
+quiet_cmd_gcc_plugins_updated = UPDATE  $@
+      cmd_gcc_plugins_updated = echo '/* $^ */' > $(obj)/gcc-plugins-deps.h
+
+$(obj)/gcc-plugins-deps.h: $(plugin-single) $(plugin-multi) FORCE
+	$(call if_changed,gcc_plugins_updated)
+
+always-y += gcc-plugins-deps.h
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250502225416.708936-1-kees%40kernel.org.
