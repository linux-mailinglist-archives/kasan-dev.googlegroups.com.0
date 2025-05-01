Return-Path: <kasan-dev+bncBDCPL7WX3MKBBD5AZ7AAMGQEDRTF2OA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1CB11AA643D
	for <lists+kasan-dev@lfdr.de>; Thu,  1 May 2025 21:48:33 +0200 (CEST)
Received: by mail-io1-xd3c.google.com with SMTP id ca18e2360f4ac-85c552b10b9sf142403239f.1
        for <lists+kasan-dev@lfdr.de>; Thu, 01 May 2025 12:48:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746128911; cv=pass;
        d=google.com; s=arc-20240605;
        b=TGMapOzsNAxhwP2TCu4m3mL3L/NhBdt833CfLmbPpczQa6UMq/g1P7N+D7MB0rZLoR
         WT5MgH553IWaizrTdR8m2peCD0gtkBmcdLqNPvN3m4ahtYNPouU+JHvGfaKPTK9HJfVn
         E766P8AySRB28pxs+cpLcRyrx/gPhpSpltFbRdaHipVsOYwlJdS84/sr5JFoLnOAsAGq
         hJe+F0JLGT88kI78FlZ8cdRTX9eJdgA4gIi3dE/8HSRphrzVn8gAMH/R2JYo7XyLx9i/
         7CIJMCl45clmZzIRNVxBj+5rCDJJPChePfFfPIuWt4eaC869tQ0n7qqCCG8xLV3iFyzw
         jdTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=3z3UPnlYiW9Pngrnty1ZHHBzvNPFgW3sc+bZf+32pRM=;
        fh=hpRPIebCuxl6DuEuvbpxgvQaUiAhTOribiiLQYkcULs=;
        b=cwSSYDDIV7s4kBNetRCN3iqn2P94Es5IN4zDS0B5enOP3ihaOadAiiYIJLm2xFXjph
         tWYPzkvUXW4Kdlaaa7BPaX6JnRXTu3fp9qq7hvMz/CEL4rBgGPE1SPiPIXXfarix8sBy
         toKiicxlt/O8prrBY7J3/zk35iAOJsISh0oTJExTDorsjScDFrcz4KsH6Sx58t7vrw5u
         red7YbfiMszd5OGZ39dFLWfaVxpa5QD8Az0o4aVIiKMooF94ZCQFZ493g3/R35COiYu/
         GHhu4Cug52pnQNgO/uJtS/2hHQwoEI0txySUlA0r3JBFMEr9UDUrwlyZXyEyCFsA2oHe
         DApg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OoaU0ply;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746128911; x=1746733711; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=3z3UPnlYiW9Pngrnty1ZHHBzvNPFgW3sc+bZf+32pRM=;
        b=dtFuXT9/vsKU6eiacGRtdl0o6ngoxKiW2QC25lFklUh9DMtfVIxId+23gkanBW8/DN
         TKzP5ABgUqTqZmwr95cJhGGVhE18DSku5J5oGTAKnHd04BVaGwp5yE/8aHwRtaQ7l5OU
         LXaypEHNWI03xb5m7LHk1G46mANQEpaKuZzwGr5NwGnYoZP3n1Z1uWABu6h/GUFnZ/Xf
         TouuBDNX+JUPpsuT+eAW8hYBc6M091LEhtZ5h4lke4IVdeWT+0/ZKlHeDJfcQbWBJatL
         tvDjzSkl5iEnYf0rzZQwwngMiZO0tjIoYFzaDncwmUFyJpB+kZB/G7uAhLCGEKYnMBwV
         MF0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746128911; x=1746733711;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3z3UPnlYiW9Pngrnty1ZHHBzvNPFgW3sc+bZf+32pRM=;
        b=jsy1r+lvhnhEPfFoZzcbTa+b8wfp4hCP+pztd5glWPUWr2/SCUCUhKkdLmC6uHpLKA
         WCVKvbL6mlh0ELYlKaccP5FZXSYhZRGwDfdWF00OTttzeQLubylDcp5FZZ5PA98Km4Zp
         yMoX3s52ra9ZHN+NsHjWUOEs4EQdIEcZ/4ZdR7Y5LXBtfWxzt5BU+/hlvCA1IqCJnlYE
         Jj0hbbLfQj9bZib9UTnlEe//UZmZ79PF1SzRCDueagfGdrihr9VwWjd9gVKSZ370/oWZ
         0wa/hdlcLJXE5HGUnDGRcCgzNHbgnzu5BqAtdU1BWolq4N37SLcm3lfdpxhkNGdYvTGn
         8pog==
X-Forwarded-Encrypted: i=2; AJvYcCVu69uSjOSnfl/ZQKeS93jkD6RBGTnEDTXUqWymr6I8TVtL1ru2WqWGCabcqzVcoUmjAyswGA==@lfdr.de
X-Gm-Message-State: AOJu0YyvOTb0NtP00eUNlCD2adyDTF7cIpvg8GPtAAY5pxvdJie5L8gw
	z7qUol7N/M5s5Kk1F69wMaGqvh6PRd7V7Eh7VwSv2I1odwaOnWBn
X-Google-Smtp-Source: AGHT+IFF0osUVZw0r0g5LkHtIXd40kV58/2IsLeb8P9qhlcxuxp5OnJ0VQodb/YX/jbX3HthohaU8Q==
X-Received: by 2002:a92:cdaf:0:b0:3cf:bc71:94f5 with SMTP id e9e14a558f8ab-3d97c253c56mr2416885ab.22.1746128911353;
        Thu, 01 May 2025 12:48:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBF0INVdbdYnmDuvypVykQAKW5hezEGjH9Rijii+cQ7+8g==
Received: by 2002:a05:6e02:16c5:b0:3d8:b690:4e94 with SMTP id
 e9e14a558f8ab-3d96e714728ls11023235ab.0.-pod-prod-09-us; Thu, 01 May 2025
 12:48:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW2UZKsTFoF9GlYBH2pW3p95B5syMlFSkfCMZ/hmD6+fkyMYBJz1l0HaafEGvEumZz7rNvqpKn/oQE=@googlegroups.com
X-Received: by 2002:a05:6e02:1a6c:b0:3d9:34c8:54ce with SMTP id e9e14a558f8ab-3d97c227475mr2544325ab.18.1746128910237;
        Thu, 01 May 2025 12:48:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746128910; cv=none;
        d=google.com; s=arc-20240605;
        b=LUHF+IPrphPJECWGUgWfIQmqw6z9yUuAypqtpYYa4jM+PDCIB1ftgqAI1dRmJepopv
         b5A+cvd2/K5y4lj4PrdcT11plYUFHinNmhhx1uS18LUJHjaIrzVClvmTqomDapGgUHpm
         BiGlpnRc54/10rfSGrEtz00EyL4DtUjF2vqWvj3/esYZxoGQKfPgyITB1EI1Gy1BvIAj
         Ca1tOh9EUmKzH32qqIooAKWL8BjdIjrpTcBwUJc+XgW+Qgnsj3ocChT/coMbaEQ9xzUO
         g9SyZTOSnOpFrrCS/DRGg57G7UTSK8f2pTLP9YrC46F8d/am+8cgaKZVZs6kVN1mxLhF
         6mLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=0S7sODCsqWH40fYAPULskA/4IVf2kN7Z+1Cc/EUU+Vo=;
        fh=yYVYSASnU4tNAYl0uvm9z05NkHHXDfA0H/kCb5r9ihM=;
        b=Oyc3Ug6CisXe+za+SPpCBaPErKOe+JwEQUCN32GrnwyRDq8Yd3txganr8W1vxJxZoT
         xVi5H5MljuXv4gP/YAcYayU6mIATBqfwkkTYtYOLmvkxFXPSbtX3NrvY6RWGpFMeWGLi
         iH6JUP4bgbCEkVsnQCkp+Z1xxskAQ+6WsCmAplwjKdDmsUYdQr3FkhnAB2Pey9R3jKb4
         NTjHHYC+z3RFhIQgrsGap6DXTebgiM8F8xwmWZLUEFvjsJDtleuioeZuZ5CCEdWQwoFs
         3W4Y37Y/XkgFo/P6fZP+wlmbUnW+ebp9FnyOzatoKKUixKxV8x6Z/Hz+LIuFMsn7zZJd
         +qjg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OoaU0ply;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4f88aa482f7si2179173.7.2025.05.01.12.48.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 May 2025 12:48:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id C6599A4BDD9;
	Thu,  1 May 2025 19:43:01 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 1646DC4CEE3;
	Thu,  1 May 2025 19:48:29 +0000 (UTC)
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
	linux-kernel@vger.kernel.org,
	linux-hardening@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: [PATCH 2/3] randstruct: Force full rebuild when seed changes
Date: Thu,  1 May 2025 12:48:17 -0700
Message-Id: <20250501194826.2947101-2-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250501193839.work.525-kees@kernel.org>
References: <20250501193839.work.525-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2614; i=kees@kernel.org; h=from:subject; bh=8LFYhUOk2+Lg4KhiXXk+lmCuulr10jRLqqlaJXRzOrE=; b=owGbwMvMwCVmps19z/KJym7G02pJDBnCFxilL1bpJjfMsursvPHsZVvOgY2/T2osYPuZcVu/O /PSkVNKHaUsDGJcDLJiiixBdu5xLh5v28Pd5yrCzGFlAhnCwMUpABN5cI/hf8CtpJVxv4zKS3pC 1uSt7nzgcupuV5KsK3NNik/hmpKEOYwMk75s22Rhal9opsopI2+uzPizQo7lAu8EFdad2Z2Pq83 YAQ==
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=OoaU0ply;       spf=pass
 (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as
 permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
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

Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: Masahiro Yamada <masahiroy@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>
Cc: Nicolas Schier <nicolas.schier@linux.dev>
Cc: Petr Pavlu <petr.pavlu@suse.com>
Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: <linux-kbuild@vger.kernel.org>
---
 include/linux/vermagic.h    |  1 -
 scripts/Makefile.randstruct |  3 ++-
 scripts/basic/Makefile      | 11 ++++++-----
 3 files changed, 8 insertions(+), 7 deletions(-)

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
diff --git a/scripts/Makefile.randstruct b/scripts/Makefile.randstruct
index 24e283e89893..ab87219c6149 100644
--- a/scripts/Makefile.randstruct
+++ b/scripts/Makefile.randstruct
@@ -12,6 +12,7 @@ randstruct-cflags-y	\
 	+= -frandomize-layout-seed-file=$(objtree)/scripts/basic/randstruct.seed
 endif
 
-export RANDSTRUCT_CFLAGS := $(randstruct-cflags-y)
+export RANDSTRUCT_CFLAGS := $(randstruct-cflags-y) \
+			    -include $(objtree)/scripts/basic/randstruct_hash.h
 
 KBUILD_CFLAGS	+= $(RANDSTRUCT_CFLAGS)
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250501194826.2947101-2-kees%40kernel.org.
