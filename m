Return-Path: <kasan-dev+bncBDCPL7WX3MKBBBGJ3HAAMGQE6PSAGBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3755DAA81F6
	for <lists+kasan-dev@lfdr.de>; Sat,  3 May 2025 20:46:30 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id 3f1490d57ef6-e73194d7744sf4576859276.0
        for <lists+kasan-dev@lfdr.de>; Sat, 03 May 2025 11:46:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746297989; cv=pass;
        d=google.com; s=arc-20240605;
        b=BJrZdBRWDTB70wDELR5kDVfpgkSgv3OCj1nQXQ+WL/6hmRHImvVd/4FEZuJ1k2xqXf
         wdtZqzG5gkdiZO16FXkDSfvCj1kFlIHr18wryDbMfxOikQW9/laSkuAMTzzgZlM/m50g
         OaLBTKSYr64qOxohxx1mwwxpZGgllNdPj78QkUrTyXZy3SutQIZrC2Qkmro7dJqFuklv
         R6a3+zGJluaCG9f9v+mJK/p7Rxw9CT6WF6+B4cJKMugnSNhc0zcHg7ykIqhkdpp7L7OL
         rGPY4bKHGXqJsNXwq3DzpLeukVtzHf8SjAmfttl1JcclV8bidOQsOGw8RZrKb1U0ZDP8
         gABw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=BjR649zgkLBRHxOEeBk78DCiDXB3/YKAbh0re6Q1fdU=;
        fh=vtSRC/F/rAClQ61WB1UUy/h2YSR34aFSRMrebO63948=;
        b=YmcyS4+pmzjbC4jBKd4yzUt3KUACmCHJfB5Z+TVofjAmANiry4QYr29wGVAqaY5kbm
         e1OUmMQK2PXYh0V9d4jxoSdZ0CUNzxIXB9WnO/6TFiBYsQPqaEJd4yF9mDUKhcQtYT+F
         A5LIr+7BoSnJuGSwBNEQWY6Fqqgtv11uOgXVFTaNCvJZJZUK1qvV/+hB1OS7qQJ09QF+
         /YhR05kfMYBppMaeFw73Vr6svVOI/cnLZN53M6esDY0WUESWXwyv/TOHraI8hV06MPRl
         cqS6M4c9eijd38bMfvicK/zOhHbcdzQxTBIKgbWoQ1J6jOrfoesRyJuQHhHcqFIsT8Kc
         3rEA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=gOIPfsz9;
       spf=pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746297989; x=1746902789; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=BjR649zgkLBRHxOEeBk78DCiDXB3/YKAbh0re6Q1fdU=;
        b=aNDF5KYJp6O0VxvNNEXbc6gFsRUJdxKbjlOIrDj0GOyH/N2YNWMYfTDiIDhdD0kEbe
         FeXopC4U5scBQtkN16sozMAU5y9AnA1cheIWDzX+MBnhPp/4aPyYmr1PZ5UfEc7mJZTj
         294zUj4aqMWXRPHFS9mVLleUEy6XcuNlePREKJ+dQ/Vli4lPINcH7R2/VrUP+ATboHPe
         b90rgZ1PBqqflEFFBtDaFVCy1K/luIzResjg+urae8aWwT9AYecvONdgHTRWWiF1Kk8B
         0LZyVRFI4togm+trmW37VBUHUhNnAlJN61I6NbGqeG0guHPK/gg55pvVP7LueFxE2lFb
         ZwKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746297989; x=1746902789;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BjR649zgkLBRHxOEeBk78DCiDXB3/YKAbh0re6Q1fdU=;
        b=fe8I62c5Hi2eRuGPLwmHQxkYOgoQXzYKAfMCJq+PGcYh3RGRcp0BZ8oegdmA9O6d2x
         xy6PjI4D5KJ5CqAx903L2/idMKYNqjkL3vUo15VHwzAwKuBpUwhlSxdqR15dVQioHYdD
         voxKl2aYqDZGYDQGU+O100iQ0+mXoKzE6fC7yo5t5SiLq0imQDB8AvMEJ36LhBP5Zu6w
         za7/AXKX5Fz/RydfgqzeDH2Z2kPxh/7QFT4hpKkFb9s4IKZF2gCDU5RJZHE7MKOe8ItZ
         zj6+zuWUtinShv0vfI4kSZDiViG+u8+tPc/Zt9GPBw5Swt3U4anx+OUHkbffS4VtsB4e
         AkZw==
X-Forwarded-Encrypted: i=2; AJvYcCXaC861q+Xfphp+OYO6JgWtmStno88mMTfuNxcOXXt2VV1YJHV8K/qxnNwtYcspWm+J/k1ilg==@lfdr.de
X-Gm-Message-State: AOJu0YzsJ+SR3pR+dLI5EopNyyURmb/aYyIHZffCzv4aTIqYO/yHUchX
	x4QZv9LQPHriDGVtjE/hS30R6JVoeMlhBdWqZBI4qHjb3a/CrO7D
X-Google-Smtp-Source: AGHT+IHnuMSE6fQ3llV8C8m4F+3hTUbPr5+i4WnFN5r4YEfzsNhj/CbYTRUJDJWtoBQ6nbj/X7nK1w==
X-Received: by 2002:a05:6902:70f:b0:e5b:4651:b5c6 with SMTP id 3f1490d57ef6-e7564d4e234mr9435657276.23.1746297988801;
        Sat, 03 May 2025 11:46:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBFW45XUkEMOZFLotGrSIc2IMkLpHFK1XCdGAf2klYX4lQ==
Received: by 2002:a25:7bc1:0:b0:e75:60d4:3256 with SMTP id 3f1490d57ef6-e7560d43324ls982194276.0.-pod-prod-00-us;
 Sat, 03 May 2025 11:46:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWCayUX4h2U++HG8UnlnsQ7OUDtdTuMveuiwDVs8qO4Ic/yOdXaBlckbczjYfUMJahsG1TM9rzBtQg=@googlegroups.com
X-Received: by 2002:a05:6902:1448:b0:e72:fcf3:9c92 with SMTP id 3f1490d57ef6-e7524a81105mr15059433276.6.1746297987672;
        Sat, 03 May 2025 11:46:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746297987; cv=none;
        d=google.com; s=arc-20240605;
        b=eSdpmBSkJD8xeDPqyVwcVk76BvX3n8pAXA38fdh4mG3YpmsTArGZ/aJgU5EA8y37LI
         b1eR6EPKSCZ6Lm1r0LHbrOIyIp+LOXHUZiPXoQHP7TY45idctlA2PWeRbZeP2uHRMLx2
         al6Duyz2PFvJBM6xgEbPIaudRz6f50MrfiRDNSTqHJ1atndeCNaWZOLGRch275aFoqHa
         bS1N9PrzpEtRTORqsZMrebZivH3ncOdypQ1WIDZgd8IcujWJ9gWW5so45i3RVjI3KTq/
         6k1YC+oOl7hpAKSgdubxqmM6wxSysmJJcKKFP/kZDBZ94ZNwomdnzOXJGYdVgtMr8UPY
         d9ww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=HqXcPWWf3zrFZlHbIEVc5mF4xzEfjxF90arpkzq7by8=;
        fh=YfDTcZX5B1ZSPOfmplXpzy0XedFwGhJ33VxL3k8t0Go=;
        b=jEItZgZ27I2mbC2HRvc+Ku5GV1vDAosA2brsogt2LdIGXIG0eVvGrWg8EV/ve0HQTD
         AG10EginocfJ3henD7Rua+Wo0i1AONcotGRXrFEXDxfJrTkn69YcoXsRZT27AA15O0oV
         fs/gv8GIBeauWWu0tj1ehLDuTSin5L2GzBke514uk4BDYEEdw+QFtwF6hmhe5f2nyOtq
         snhP6yujan+OhGhzupxKC6nvHsjtAm0DH13xzZlKmDoJYjFnX6UeCNYiOfx4I7PRqsFG
         xRs9eclq53orDzkH3XmgQezOBYKuP98zDvaZdGL3CkPoEn/oQHt9FHh24VbbNIpxw2+x
         BxAA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=gOIPfsz9;
       spf=pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e755e790366si254418276.3.2025.05.03.11.46.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 03 May 2025 11:46:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 3E5366111F;
	Sat,  3 May 2025 18:45:57 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7E60BC4CEEF;
	Sat,  3 May 2025 18:46:26 +0000 (UTC)
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
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	linux-kernel@vger.kernel.org,
	linux-hardening@vger.kernel.org,
	kasan-dev@googlegroups.com,
	llvm@lists.linux.dev
Subject: [PATCH v3 2/3] randstruct: Force full rebuild when seed changes
Date: Sat,  3 May 2025 11:46:19 -0700
Message-Id: <20250503184623.2572355-2-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250503184001.make.594-kees@kernel.org>
References: <20250503184001.make.594-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1638; i=kees@kernel.org; h=from:subject; bh=/4TdTrc4aB0kiFO9JBIxqORcQZGXnaXh7CndlvLLjw4=; b=owGbwMvMwCVmps19z/KJym7G02pJDBliyfv3J+WtzL589uiKhFWFjQuOu8ux+8/5JB98+dIOh kKRL4WfO0pYGMS4GGTFFFmC7NzjXDzetoe7z1WEmcPKBDKEgYtTACbi/pmR4Yj4wy3Pn+jVqpiI 8u5tnxmo0l9VHWgYwnHUS/Pi10eiJQw/Lvo8PqCVcGZOuLiG2bfzc6eLdL+15NuTJH6iceJDtVo GAA==
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=gOIPfsz9;       spf=pass
 (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
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

While the randstruct GCC plugin was being rebuilt if the randstruct seed
changed, Clang builds did not notice the change. This could result in
differing struct layouts in a target depending on when it was built.

Include the existing generated header file in compiler-version.h when
its associated feature name, RANDSTRUCT, is defined. This will be picked
up by fixdep and force rebuilds where needed.

Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: Masahiro Yamada <masahiroy@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>
Cc: Nicolas Schier <nicolas.schier@linux.dev>
Cc: Petr Pavlu <petr.pavlu@suse.com>
Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: <linux-kbuild@vger.kernel.org>
---
 include/linux/compiler-version.h | 3 +++
 include/linux/vermagic.h         | 1 -
 2 files changed, 3 insertions(+), 1 deletion(-)

diff --git a/include/linux/compiler-version.h b/include/linux/compiler-version.h
index 74ea11563ce3..69b29b400ce2 100644
--- a/include/linux/compiler-version.h
+++ b/include/linux/compiler-version.h
@@ -16,3 +16,6 @@
 #ifdef GCC_PLUGINS
 #include <generated/gcc-plugins.h>
 #endif
+#ifdef RANDSTRUCT
+#include <generated/randstruct_hash.h>
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
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250503184623.2572355-2-kees%40kernel.org.
