Return-Path: <kasan-dev+bncBDCPL7WX3MKBBBGJ3HAAMGQE6PSAGBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 9ACBEAA81F4
	for <lists+kasan-dev@lfdr.de>; Sat,  3 May 2025 20:46:29 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-3d8a9b1c84esf40989775ab.2
        for <lists+kasan-dev@lfdr.de>; Sat, 03 May 2025 11:46:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746297988; cv=pass;
        d=google.com; s=arc-20240605;
        b=Y+fvZsJOb3tE6udzZ9O80u1fA3I/a9PD0rKFb8kzVd9Hnh4vJbSTpqoz4z+w8hHe2Q
         iy3UrtPkmlhSsBGs0QMmMz5/xuIipIn/HeggJab2rvcY1LBXTobDPNGZqrc17tMITIuL
         K4KFxz290ZLlsZ+z9xLPLf7k7g4TIpIUTiVU89/+HPGdOUq5Mrhf2+qk5t80zlo8tPnQ
         8fkw9DnccKuAf3zRpTpIwweR2dprg50dNoGCPdTtI34atG3Mbm6RfEA230UXdL5GU8av
         R2hIIQTVlSl8jiTfMJzaUaeaLV5fAMf8lqDlqSAa7r0SyfSpiYzfku23C+nmRQtW2vf/
         5Ifw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=yejSshA0Jzk7xkR+qAkQ6ULETvU5zDiK4yWtwc54160=;
        fh=k8cMai9ywzenICw0xpNA6ETnFI3ZrZ3EGlqSaPuhJgA=;
        b=WB06nL1ouRTLPABVf8LzQ+ym2TdTWvCgoo424PcMFeVHYWTBobyS2axbSZ6aIBKE9F
         Bdn2Hb7HdFblUf70X8D3Rj6m7NsZ5Tekft9Ggw4NoXRN8tWB4A/kQEwaWRIFKEG4mOG8
         V0HxYOaD60zEOL1dPHjGiJ9oqPodiKwzggxiqrFaFJzNwsJ8Y3AuvvWLDCACVY/oKNNZ
         Z5Eq0a2aJLxNdYCLyNBZtGhlfTRdObgg147G152w6DjIhLQJRkn/g90j5/oHt/VbJhJV
         JcOhfwJEBqH21HSFcyrFZGVw68FZZS06P5MCSGw8aDNZRxHbBHdhUoIkQ0G1TwhBpMQG
         yOrQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nMyiXwu5;
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746297988; x=1746902788; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=yejSshA0Jzk7xkR+qAkQ6ULETvU5zDiK4yWtwc54160=;
        b=tSpz3yAaSiNTDSDHn8bTRSjfPDmQ7QjxlD8NL3A0N3qGK2sIQE80Mlpa3tNLsuAAGy
         yAax3sR1Uyj14bkaRJ5mVOu0HC18DMETXA+x3KIrUjR20WDpCrxStHtRIPbsSZe7HgKf
         DUabsSAWOEvR6IaKLm0GBVd/g11xQmuKWe3Sbm82Bhv20bUc5M2Vsoz+hP5rI71eGx6h
         CPlBXFG3po9Ucq73PiOPKjHh6+4Q1u8k8deoTU2TE8m80qd9rQJnUJTyRDZOySQSJ5JH
         kCRCUxrCIYGrrXplyJ2l07wAx06DZ7N4PwK24Cg+b2nOkwHXZ3G/d75VQn/hG0PvH0sC
         MzIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746297988; x=1746902788;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yejSshA0Jzk7xkR+qAkQ6ULETvU5zDiK4yWtwc54160=;
        b=makl9EfS/G2Bf5tKGyigmI3b0MdgOL1ANLONWSkGYcqBi0J+KBkROrRSlUH9LiwraB
         AataqtDTfcu0frKAjNZN8RKlRhYX3y/P1eU3EJ4sHdDHjHe8TK/LiSWKn1RcXO7p5pDk
         4tUGGPBINWG9UhRqAdfiEhixpPNaoQZ6LYldxQgYxTix73VtAI6fLUm/ytufbr2LBQbn
         XkY7qHIr3zr0ARUHM2v7sW0gnKDHQbr7njhVz4Y6pzfZ5+ramqbIQkixtPq9X4qFrCpe
         himL0uipbuAiGs6e9L1pJNk44Z2zZRJQmCQaIqt72tZua/BDTQz/++XC7dkBYwtP6AOr
         9z6Q==
X-Forwarded-Encrypted: i=2; AJvYcCUePh04h5nld4G6AgjqjAR3/nPisnqybIqE7gMhwPblPDcif+4nI12AHu3LOKQusi+Y6721jg==@lfdr.de
X-Gm-Message-State: AOJu0YyeJE8qAZg9FqatS+2ZyKZ4P2q0BqgkYz5kGzhTOz/6MxC0UEXk
	bpwpgeFQ1mHinjVe1VJv/cxIRLEzDdu83IsdsLnFajQSQyq3j2B6
X-Google-Smtp-Source: AGHT+IHD723FumZ/o7/61baOEdhVEISVlN27ivroSdu2ViqQ7WWAwupTDpfdowDLLvUpwyYUq33SNA==
X-Received: by 2002:a05:6e02:3982:b0:3d8:2032:ca67 with SMTP id e9e14a558f8ab-3da5b2733cemr17950355ab.9.1746297988256;
        Sat, 03 May 2025 11:46:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBGo38i+P09Vs5b7n+NYFTFCjVd32lnDmaXvWtWSOitX0A==
Received: by 2002:a05:6e02:16c5:b0:3d8:b690:4e94 with SMTP id
 e9e14a558f8ab-3d96e714728ls24365285ab.0.-pod-prod-09-us; Sat, 03 May 2025
 11:46:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXHI68tObsm9nJ4ozQn1fLWjKNtevVxWRtDePmPhaiyYYSot0O04Yts/TMPmOjqG3Y9UC1BM9iNVSM=@googlegroups.com
X-Received: by 2002:a05:6e02:3703:b0:3d5:8937:f419 with SMTP id e9e14a558f8ab-3da5b2a5dc5mr16130365ab.13.1746297987582;
        Sat, 03 May 2025 11:46:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746297987; cv=none;
        d=google.com; s=arc-20240605;
        b=MEjt0mQ3YdoFj+d+tbCJwyUQWyrAZOn23pStxfIuHh54Y28s5BZvxvokh7U3qY0Ryk
         7GUOUTSYCEge0JI+mABQEVofe1zGg0ZXjri8kVHdg8OI8qFgezLunpLAQu9fgszvu3o6
         mgq97XFh0vjmpvLnuzRCPoBaHj4XcxV3jF8U+5nMYFZ+4wVF15Xq6RljFZa1+nOTdAM1
         aHN9cCPsS825oiY/PWZf5ubTL2Uc6jnkvRqjgyWZIQGBP5NbNrpEwlR0oVLohiROzKAH
         dEDYwg8QE09XXAeK5ksabBRixH+Fo9oklKn+h9TRDQnVSUGxcTmsXd45PSyLi1tKwsnc
         F/jg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=68wvXYknLDViUTCnVi1/VjHGQAuvRJqyvvCNBsmkQpA=;
        fh=k4LLFD8wdh8xUrcsCJ3LuYsQ9lMJ4UqR7GkSjBA4/k8=;
        b=ENiDrPY2yFvb4ljuatGsw4PkGCCcjxVLhc3nvza8WTTyRYQCHdDUNCjr+EgoG8sFdK
         Yw6gpeqepGesXiHlUOIktHv4jRBokj/quzfs9hsol7AFcAmeQcsXBy2kWBBD31+5QrDH
         hiB56bInEb/vcsIg/O9CwLVp7EYwEURejPcpax0mRq4tutsx4dwryDlc1OP7W+Fm1cSz
         8XB+kEJfVY8I3t29pOmqkEsTef4VJBD7j4xal8GTojsdhGoa9+MgjsxuDtyeIMgdyEmG
         FbAZZ5eJ+9RyyeTJUUhne1DsPhvaqTCHU6l4va7XjGjHPtUF3jtRAlU3taqmBffBq5+Q
         Dm7Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nMyiXwu5;
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4f88aa16802si115893173.5.2025.05.03.11.46.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 03 May 2025 11:46:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 327D749E12;
	Sat,  3 May 2025 18:46:24 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7C232C4CEEE;
	Sat,  3 May 2025 18:46:26 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Masahiro Yamada <masahiroy@kernel.org>
Cc: Kees Cook <kees@kernel.org>,
	Justin Stitt <justinstitt@google.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	linux-kbuild@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org,
	Petr Pavlu <petr.pavlu@suse.com>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH v3 3/3] integer-wrap: Force full rebuild when .scl file changes
Date: Sat,  3 May 2025 11:46:20 -0700
Message-Id: <20250503184623.2572355-3-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250503184001.make.594-kees@kernel.org>
References: <20250503184001.make.594-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2674; i=kees@kernel.org; h=from:subject; bh=+tpyu2HU8spYPzq1uf4EZ3SloA5fFEfjRjUkQSozF1w=; b=owGbwMvMwCVmps19z/KJym7G02pJDBliyft7n2QtDHVZzPzT7voxVRX9o38qkjOX/vRYvIpJI GFTQFxERykLgxgXg6yYIkuQnXuci8fb9nD3uYowc1iZQIYwcHEKwETSDRj+Z68L0rBx8nkQ1vFK /Z3w59knAyKm/q25XLPDJ3Wd/pPO+4wMr37EPn6zUEbQ81Oxn66L3YPZSxqD1p88miN63FK3vj+ FDQA=
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=nMyiXwu5;       spf=pass
 (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted
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

Since the integer wrapping sanitizer's behavior depends on its associated
.scl file, we must force a full rebuild if the file changes. If not,
instrumentation may differ between targets based on when they were built.

Generate a new header file, integer-wrap.h, any time the Clang .scl
file changes. Include the header file in compiler-version.h when its
associated feature name, INTEGER_WRAP, is defined. This will be picked
up by fixdep and force rebuilds where needed.

Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: Masahiro Yamada <masahiroy@kernel.org>
Cc: Justin Stitt <justinstitt@google.com>
Cc: Nathan Chancellor <nathan@kernel.org>
Cc: Nicolas Schier <nicolas.schier@linux.dev>
Cc: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: <linux-kbuild@vger.kernel.org>
Cc: <kasan-dev@googlegroups.com>
Cc: <linux-hardening@vger.kernel.org>
---
 include/linux/compiler-version.h | 3 +++
 scripts/Makefile.ubsan           | 1 +
 scripts/basic/Makefile           | 5 +++++
 3 files changed, 9 insertions(+)

diff --git a/include/linux/compiler-version.h b/include/linux/compiler-version.h
index 69b29b400ce2..187e749f9e79 100644
--- a/include/linux/compiler-version.h
+++ b/include/linux/compiler-version.h
@@ -19,3 +19,6 @@
 #ifdef RANDSTRUCT
 #include <generated/randstruct_hash.h>
 #endif
+#ifdef INTEGER_WRAP
+#include <generated/integer-wrap.h>
+#endif
diff --git a/scripts/Makefile.ubsan b/scripts/Makefile.ubsan
index 9e35198edbf0..653f7117819c 100644
--- a/scripts/Makefile.ubsan
+++ b/scripts/Makefile.ubsan
@@ -15,6 +15,7 @@ ubsan-cflags-$(CONFIG_UBSAN_TRAP)		+= $(call cc-option,-fsanitize-trap=undefined
 export CFLAGS_UBSAN := $(ubsan-cflags-y)
 
 ubsan-integer-wrap-cflags-$(CONFIG_UBSAN_INTEGER_WRAP)     +=	\
+	-DINTEGER_WRAP						\
 	-fsanitize-undefined-ignore-overflow-pattern=all	\
 	-fsanitize=signed-integer-overflow			\
 	-fsanitize=unsigned-integer-overflow			\
diff --git a/scripts/basic/Makefile b/scripts/basic/Makefile
index dd289a6725ac..fb8e2c38fbc7 100644
--- a/scripts/basic/Makefile
+++ b/scripts/basic/Makefile
@@ -14,3 +14,8 @@ cmd_create_randstruct_seed = \
 $(obj)/randstruct.seed: $(gen-randstruct-seed) FORCE
 	$(call if_changed,create_randstruct_seed)
 always-$(CONFIG_RANDSTRUCT) += randstruct.seed
+
+# integer-wrap: if the .scl file changes, we need to do a full rebuild.
+$(obj)/../../include/generated/integer-wrap.h: $(srctree)/scripts/integer-wrap-ignore.scl FORCE
+	$(call if_changed,touch)
+always-$(CONFIG_UBSAN_INTEGER_WRAP) += ../../include/generated/integer-wrap.h
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250503184623.2572355-3-kees%40kernel.org.
