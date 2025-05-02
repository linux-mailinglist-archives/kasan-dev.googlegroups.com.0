Return-Path: <kasan-dev+bncBDCPL7WX3MKBBHM22XAAMGQEIRHW4IA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id D5F11AA7C78
	for <lists+kasan-dev@lfdr.de>; Sat,  3 May 2025 00:54:23 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-22406ee0243sf19060455ad.3
        for <lists+kasan-dev@lfdr.de>; Fri, 02 May 2025 15:54:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746226462; cv=pass;
        d=google.com; s=arc-20240605;
        b=eMJ2+/fzdbV4yCwYOqF0ojlPKCtMgrm2UG0Osi7NZImstsHu9TZTBAAqTuI9JeGHRL
         P+x7VYCQ34vidCH0nhPzHTP+RiYSUmrs1+cMyrrCFOsAoLosu3ZjL3N++zHLM0bMDLmg
         8lWQaU1Czh6CKzC5BgHZex1x2utGeqjOjrOc/7H6FW24OLuCpGGLtHwUTihvdPz7OCvP
         aYykO2vCWRmfP8erKsLzT4ssYI695yPh4yEF5e4CKnrKr5boSwdDkk+3A+7hCArggy5B
         WAPBxpxeYqrzSrCjUtvfPkfOAT9KOxEq5siLOGt4mQREDqHXlQwDLDmdp9is6y9f7H3h
         bx7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=AwLXWmoE5jkZSqBiHqxJhSm67nLqu9kmZ0zaGHg4iis=;
        fh=Ym4QzsuaaPKf0UeVKvVk4F1oyt70qOiCCjm9RqL/bks=;
        b=GDFCLgRqd6qipTHXCgiJ9HXVmFIaPPZncKWoBjgjtI59yfXdzDY5+cgp+eHKOjDBIk
         9NUB4NayGrt9r8gUIOTeKgBn3+J7Q+69NeOpK0KOvYydKS4VFYJuRnRrWxuCP5UpMTBf
         rhHU8RhmgygjeIE8/L5z8vDZnFbjwEox60EyUtWLvQk39J3S021egZYCy/Pi1H2VrPA8
         6txoBG7YqQm+6EdoE5hIbe3tWR6Z3c12+L2RKSYphzgMe8seTE6kmxnnBWe8X86bWYsm
         VGA+L8iK0L8rNNw2YBfNvvoAgSXVtSPNDH8/npj+WFJR2Txk/BIZeBOZ2wqYSSPXGClB
         Z2sA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="NDqh/s/n";
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746226462; x=1746831262; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=AwLXWmoE5jkZSqBiHqxJhSm67nLqu9kmZ0zaGHg4iis=;
        b=bTlALIpjG9OhAnY2Xmdrya71FY3q1yx1yxFuIjg3IaltSuTriTxwxF+3T2drVgEej1
         cDj6Snu9N2oUBmhAf5Y0TWgOBGyMDlsJa2J+QVyP89SG08ikaJAI13LPg9lC6/cEuLyS
         /CVlsiD/5tj2ToERjUpI0sHYZqjQHwFNokBtkUuGhFDLNScqA1Fj2ul7cGtiPoYXWx3g
         xiZLVtgevqH3iZ7wP5WIbsgAhKsMmVR+AMFI746RRnFKF24CcC1arsMnK4IhVxeGJBxj
         uOLeTqYVdJMs3XiUrkt97N0jQk17peHip6mBZIbYq5XFRoMMYJ2CugpgvC8ZopHRRh3L
         Ophg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746226462; x=1746831262;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AwLXWmoE5jkZSqBiHqxJhSm67nLqu9kmZ0zaGHg4iis=;
        b=kVWtHSayBrHQiyQafS7TXw0qvOIeEf/EqadiraEs1D9hKPO9Mk6fqgdJ5LtS68k+Gt
         i3CcbXOwVuBrBUTIOvE2DTjrZoIo0sVAg0aJPWQqJoY8dlUe8R9g9y2ba1y9tL3x93+W
         Z0guaQEeQTXP4vdudlx00WoTEujx6s3bWnyP1zb77wNMIein0ajPktovE8YJSBdsC80m
         h67SjCXlWnjq+TiFd8oRmKBc4lU8v00GVQiNMYqoTDlfBAtUu073cNBeW30Nyta08YPe
         yaAHwyuA+0vkczL6covy18JUCDPutO0ENJf8q85ocIxMcbcKd4qJYZVoqSb0f0UQqRc+
         2/Rg==
X-Forwarded-Encrypted: i=2; AJvYcCXhE8xBI10SgqxQd3qrH9WPMPiiING3S/G2ju/BsYF71W3W38RULO5HsCcxiCDxZ+wBYGsk6g==@lfdr.de
X-Gm-Message-State: AOJu0YzYIuBz+5uk4Mr32K8P34A19CVhT9Zz2yAJsoxPH04cd4EH3j1o
	lNlolX9Aue4NHIkS9wXSFHlZYEidNqrAyKiyOwYANutwVgqqcUi1
X-Google-Smtp-Source: AGHT+IER+VcQyInJyy8RTAvhliudl3iINmIkUphvTLj1N/zRTUddQOqop30WVyjKtcZzJ0Ur2mpgUA==
X-Received: by 2002:a17:902:e5c7:b0:223:6657:5001 with SMTP id d9443c01a7336-22e103d7483mr78109545ad.40.1746226461623;
        Fri, 02 May 2025 15:54:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBEtfxFE4/dbCSf0Bsbtk30gMCnOy123pXiFMC6PgVwiCQ==
Received: by 2002:a17:903:2305:b0:216:59e6:95c2 with SMTP id
 d9443c01a7336-22e02f0d147ls23121605ad.0.-pod-prod-04-us; Fri, 02 May 2025
 15:54:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU9w6tJBT+TCBQR8jXgx7t21C+YEaRyyV69zBu9ueqUwF/wwbH49Aw/CtOWKAPkCa/NDB/aLpItA9E=@googlegroups.com
X-Received: by 2002:a17:903:2447:b0:223:53fb:e1dd with SMTP id d9443c01a7336-22e10311d19mr62844295ad.9.1746226460291;
        Fri, 02 May 2025 15:54:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746226460; cv=none;
        d=google.com; s=arc-20240605;
        b=ICr84htgC1DreXwllDvxlRSqL6K4mZjLQ2RDXolY1HARStuXDIo7V6wh8lO+tBKWj6
         dy4BLugkl4idwqw5lhlS39gJhPQA/T3hWuNDHI/VkApIQjcMNrffh1B44tH6cWeOvKgY
         SWD9HOop782c+Q/pbQ0X0+GCqt3L4tSVmsrFKQrIRvfcJ9g0Ee7EwAc/CwSZVf/86usC
         ojqspc2y5lUUrkh0OVDqPk7ZQyArADDjdO7rXyO9GVtPCqh8WI+sL75gn+zI5pHftR+f
         JHwPqEICOT3PARm6OixuQLBJSgQvB9XiWrXziFm1zTrWuyRmIa+Jusshly+U0g/VcWQ8
         wc7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=RRnQ1suqV31gB4rMx354pNU4ez/HA2YACv6kbHtuqH4=;
        fh=1SN7+DB7TN4X7jgziTluPM2qQHB7UYj+bSBuXwPJQTQ=;
        b=arhqoCbnvPYlaNRHRxLzF293c/L+te8RZi0rxhwlL+rKINuGMvg/2d4laLOH9B9xkX
         dSNfuhQNHISTo1l596lAVm853sJtJSpfBUH4OsNbhJ479bklhpPb3zwyE5e5UiShQIiV
         kWpqJT3V5K0gP+uSXJqimzcJ3V+4LsehMFtei4jVu7kHuY9hWYMeAgHCeNdVXDWkpuxi
         MOXSZSuRjM3tzb+jNzZIKfSTc2CJecl1X8hWM/p59aGgYjyL+vj7M0bLfUUm59KCRHS8
         0Ps3S87U0wwDSDBx9ImQPD+MYdN5mpKx+iUXh4XTWJOmD2IYEd2gNedHzbUIYugRS26P
         mIlg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="NDqh/s/n";
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-30a244b5039si88513a91.0.2025.05.02.15.54.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 02 May 2025 15:54:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 754364A043;
	Fri,  2 May 2025 22:54:17 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B870EC4CEE4;
	Fri,  2 May 2025 22:54:19 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Masahiro Yamada <masahiroy@kernel.org>
Cc: Kees Cook <kees@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Petr Pavlu <petr.pavlu@suse.com>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	linux-kbuild@vger.kernel.org,
	Justin Stitt <justinstitt@google.com>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Richard Weinberger <richard@nod.at>,
	Anton Ivanov <anton.ivanov@cambridgegreys.com>,
	Johannes Berg <johannes@sipsolutions.net>,
	linux-kernel@vger.kernel.org,
	linux-hardening@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-um@lists.infradead.org
Subject: [PATCH v2 2/3] randstruct: Force full rebuild when seed changes
Date: Fri,  2 May 2025 15:54:14 -0700
Message-Id: <20250502225416.708936-2-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250502224512.it.706-kees@kernel.org>
References: <20250502224512.it.706-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=3831; i=kees@kernel.org; h=from:subject; bh=DfqvdRUqMtoPlZKLyvJpYf94EQda+fM9+VWU2/V8MOI=; b=owGbwMvMwCVmps19z/KJym7G02pJDBmivuI9R04dk2ibbdtp1zKpQ7LSSvR1fcOVTCGHVTVSs 7hClrh2lLIwiHExyIopsgTZuce5eLxtD3efqwgzh5UJZAgDF6cATGR1LsM//UwLUVHWmxW3D1qc Fs1VWStoVtv7Oe1YqM/m400zpl4NYvgf5HireJpv0ySRbQE3u5vW5VX9ulEkyZo3597GFA2nrdc 5AA==
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="NDqh/s/n";       spf=pass
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

While the randstruct GCC plugin was being rebuilt if the randstruct
seed changed, Clangs build did not notice the change. Include the hash
header directly so that it becomes a universal build dependency and full
rebuilds will happen if it changes.

Since we cannot use "-include ..." as the randstruct flags are removed
via "filter-out" (which would cause all instances of "-include" to be
removed), use the existing -DRANDSTRUCT to control the header inclusion
via include/linux/compiler-version.h. Universally add a -I for the
scripts/basic directory, where header exists. The UM build requires that
the -I be explicitly added.

Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: Masahiro Yamada <masahiroy@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>
Cc: Nicolas Schier <nicolas.schier@linux.dev>
Cc: Petr Pavlu <petr.pavlu@suse.com>
Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: <linux-kbuild@vger.kernel.org>
---
 Makefile                         |  1 +
 arch/um/Makefile                 |  1 +
 include/linux/compiler-version.h |  3 +++
 include/linux/vermagic.h         |  1 -
 scripts/basic/Makefile           | 11 ++++++-----
 5 files changed, 11 insertions(+), 6 deletions(-)

diff --git a/Makefile b/Makefile
index 5aa9ee52a765..cef652227843 100644
--- a/Makefile
+++ b/Makefile
@@ -567,6 +567,7 @@ LINUXINCLUDE    := \
 		-I$(objtree)/arch/$(SRCARCH)/include/generated \
 		-I$(srctree)/include \
 		-I$(objtree)/include \
+		-I$(objtree)/scripts/basic \
 		$(USERINCLUDE)
 
 KBUILD_AFLAGS   := -D__ASSEMBLY__ -fno-PIE
diff --git a/arch/um/Makefile b/arch/um/Makefile
index 8cc0f22ebefa..38f6024e75d7 100644
--- a/arch/um/Makefile
+++ b/arch/um/Makefile
@@ -73,6 +73,7 @@ USER_CFLAGS = $(patsubst $(KERNEL_DEFINES),,$(patsubst -I%,,$(KBUILD_CFLAGS))) \
 		-D_FILE_OFFSET_BITS=64 -idirafter $(srctree)/include \
 		-idirafter $(objtree)/include -D__KERNEL__ -D__UM_HOST__ \
 		-I$(objtree)/scripts/gcc-plugins \
+		-I$(objtree)/scripts/basic \
 		-include $(srctree)/include/linux/compiler-version.h \
 		-include $(srctree)/include/linux/kconfig.h
 
diff --git a/include/linux/compiler-version.h b/include/linux/compiler-version.h
index 08943df04ebb..05d555320a0f 100644
--- a/include/linux/compiler-version.h
+++ b/include/linux/compiler-version.h
@@ -16,3 +16,6 @@
 #ifdef GCC_PLUGINS_ENABLED
 #include "gcc-plugins-deps.h"
 #endif
+#ifdef RANDSTRUCT
+#include "randstruct_hash.h"
+#endif
diff --git a/include/linux/vermagic.h b/include/linux/vermagic.h
index 939ceabcaf06..335c360d4f9b 100644
--- a/include/linux/vermagic.h
+++ b/include/linux/vermagic.h
@@ -33,7 +33,6 @@
 #define MODULE_VERMAGIC_MODVERSIONS ""
 #endif
 #ifdef RANDSTRUCT
-#include <generated/randstruct_hash.h>
 #define MODULE_RANDSTRUCT "RANDSTRUCT_" RANDSTRUCT_HASHED_SEED
 #else
 #define MODULE_RANDSTRUCT
diff --git a/scripts/basic/Makefile b/scripts/basic/Makefile
index dd289a6725ac..31637ce4dc5c 100644
--- a/scripts/basic/Makefile
+++ b/scripts/basic/Makefile
@@ -8,9 +8,10 @@ hostprogs-always-y	+= fixdep
 # before running a Clang kernel build.
 gen-randstruct-seed	:= $(srctree)/scripts/gen-randstruct-seed.sh
 quiet_cmd_create_randstruct_seed = GENSEED $@
-cmd_create_randstruct_seed = \
-	$(CONFIG_SHELL) $(gen-randstruct-seed) \
-		$@ $(objtree)/include/generated/randstruct_hash.h
-$(obj)/randstruct.seed: $(gen-randstruct-seed) FORCE
+      cmd_create_randstruct_seed = $(CONFIG_SHELL) $(gen-randstruct-seed) \
+		$(obj)/randstruct.seed $(obj)/randstruct_hash.h
+
+$(obj)/randstruct_hash.h $(obj)/randstruct.seed: $(gen-randstruct-seed) FORCE
 	$(call if_changed,create_randstruct_seed)
-always-$(CONFIG_RANDSTRUCT) += randstruct.seed
+
+always-$(CONFIG_RANDSTRUCT) += randstruct.seed randstruct_hash.h
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250502225416.708936-2-kees%40kernel.org.
