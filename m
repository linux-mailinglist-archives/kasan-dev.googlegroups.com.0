Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEPJVT3QKGQEAUEHDVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3d.google.com (mail-vs1-xe3d.google.com [IPv6:2607:f8b0:4864:20::e3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 44B9D1FEEB1
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Jun 2020 11:32:02 +0200 (CEST)
Received: by mail-vs1-xe3d.google.com with SMTP id x10sf790431vsj.22
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Jun 2020 02:32:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592472721; cv=pass;
        d=google.com; s=arc-20160816;
        b=S4wTG1prJJmR/pCK82ea1AvVwIwu6KgdVUgWS2c66SMZq18rMhGb7al5u5/NlnLkle
         rQEuosXlMS811yhnHFySN5q+hK9M5fTNYizgHLJqQdrIUSpElAmSga/6SdukR1ghy+m8
         E3vxdzCXjWUAwobQKwvKbptjw6AVAa3gQSbdwjxHHy79iDpeYI4VNE7w9bUYtf9qJpoi
         fFpSfx6BVyqWzV2oSbkJ7j4p+ypbidotJf0DYK7vMRh4TFDO8mb9qMnib3hB7bTGK4oP
         JKhvDS2fBcYFzN+OyMhNXFUUjYBpQ9eVSZWpChW0+3lI2K/JojBDTyWjxVeNr8y8jqSm
         L2iA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=jUKTuOpiNUHDH1qCCcj7gQZD4T8EgTvaesWZR05wvOI=;
        b=rawoUCj4Q/ByMSUnURy/zIvFQm+JvkOG2y/AK7c3T+Etrb5AnX5H6JL/h/Aj6VZavW
         pwIAZU7F0e4pN9JjSS2ptgmhvfIEDxH4kCV6nJ77Q9/Qa6/d3qU1SXQwNpZGJ7v1Htiz
         nVq5Ilw0R+F0kxFjLctRFe1cdUSB30aeeiX2xIowE/tBDCQ5iQWIQ7cQmQmY+gnftxPQ
         +7Ee4ymszrjR/11TRKDtLVKHTTUbXxqW7SOzUustd+ysprw7psZhe2ZXzbEPmCPrUQ01
         WTnSdQstum4VnYOzD1gSR1jjGtkCN+cTOyAPiRvUFq6K+Dt8ZkiVBCrDxPy8ppijIIOz
         L/Tw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tRJULurj;
       spf=pass (google.com: domain of 3kdtrxgukcamhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3kDTrXgUKCaMHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jUKTuOpiNUHDH1qCCcj7gQZD4T8EgTvaesWZR05wvOI=;
        b=LzeEiNM2A5/3AYQICXa+Gnnuhd5i2lf79Rd9Am+grINIktyHUUFPH6lKjjlSUMflaj
         mXZqMHKqYEjQQXEEc2snPU1O4QO6VaRSueVtq725iSh+No8x2FP5yJrGb1fVq7SWeaOP
         1FdG2UcYkW2fGsJE0JkqljlNAWr9z/BnZsyEnTQTpDpFZtkVuhNqEtLQ4Z5xNOkJWvOj
         QW5wzlQg4J4QjQIRWt0sHtyBEGl7ZUi+jw6htLTvkbNZxdKAtjD7fuTSgDgRpPK8+7YR
         BMQ2Cf4qplGWAueFX3CDi8zZ1avBCMtp8Frowg0qStSu6PDROYjcr4L84VYGsF5WEGrr
         hYvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jUKTuOpiNUHDH1qCCcj7gQZD4T8EgTvaesWZR05wvOI=;
        b=s6IW8MUTKlfWpLHh3w6js4f4AAfW1O41M+ES3ZkDGmrenTKMAsCQN6Ag0iiIJqziGd
         AO7OVyff6B0Dlnnv0tRkv3Xo0qK39C3DGKNd3tNWe87ewhPiNaGOYt3+TlXBlyD+M/GR
         lp7GTp5es8iKtQwUxOKEQguw/UKB7IafPBgV79TOj4k+5f4p6krVtAkzrIzFHUEgCF9r
         OdjwaIyYzZ6KVEpGiAA0QbDZatir3F6UJV7t/CuH/SEfqxvG2AgY+OWxgCwvDAdiGQBG
         a5wFrNMqvbLuyMfXlo3To/RG1LgX8O4t4dzVRxNu4y2SFOYwyM6PyaKKcFpompF1A/CL
         o/Kg==
X-Gm-Message-State: AOAM532zC+K54nnawwKoW7c8C/Ys1lcicWv6ZRCKbI0du7A2VYhXA+tv
	ejrUji6Dhu4pU/zZPSaUJKc=
X-Google-Smtp-Source: ABdhPJyOzE2oMVtsShDTAhYAUBxbC+ubz6JE6L46Bl4Wj8Fxl9kHQedz7P5f8GB2TeEzqBSOD0OrGg==
X-Received: by 2002:a67:c806:: with SMTP id u6mr2492037vsk.94.1592472721296;
        Thu, 18 Jun 2020 02:32:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:b6cf:: with SMTP id g198ls240122vkf.5.gmail; Thu, 18 Jun
 2020 02:32:01 -0700 (PDT)
X-Received: by 2002:a05:6122:2d6:: with SMTP id k22mr2496139vki.89.1592472720751;
        Thu, 18 Jun 2020 02:32:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592472720; cv=none;
        d=google.com; s=arc-20160816;
        b=AV7vNnuTrqfRjLKfwUdm57l36j+0p9rBP1BmRjI8i2KneD2SDgd3Jn02+yi3YqQViT
         m4+B9lkHnyTbX3+H2Eaw3NrOWdJjSKigSlDXN7HIw9SVWiOU6q7d9xoz84Tpa+ekcp+a
         ib0lOEDNBO/Q8wScS68l+ubpf1Uh3t7O4C78kOtAN+IBsxwihtXeGcDyTD6a6j7+eqkb
         Clo3NtwvMdPfRzWraejfQlmwP5geFNmiJTaFNqRx79qLNLiF7FxNCydYcCHWKe8fNLxk
         22kny7p7z/TyKWXP+s5kQGYjk736llKuAh1kaTGP0WSM0O3+MjmewdJJBezdNEJ0+O0a
         UqEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=tjAwEnOyA0tmPVPrOK6icwtI4Nv9CgkoPBXdv/shKX8=;
        b=bSgerwCNyLPyzw8HmMroaycTLvKQ9371sjm/Ky3k5HB36ewsoXyi+UkDmNwNM9bt04
         CLpOX4FwkgHgsWVJMfbQodGCWegUB/A+tHUx1S9vbyrBVuI8DpRb6F3yLGdeok7IbFV2
         bPjznlXOEw4Bt+d3XB2lbsypTC5lKwjY2SWGLr/a/rhTfB7cl0ip3+T2APSNyH4hCYS9
         QiEfa2oRtyYsSzIHaY7NpI2NLUlbvCofGIEq/9As4qlmeMGEzICNTYZ1lc7BA4cSayKi
         ikt8+9JrqDSEuYOupb07TBKrVcyMwnXHOUGXdoOO1hCTu4naOiC451DfnP1Ew1X3XWC8
         rZhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tRJULurj;
       spf=pass (google.com: domain of 3kdtrxgukcamhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3kDTrXgUKCaMHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id y7si189331vko.5.2020.06.18.02.32.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Jun 2020 02:32:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3kdtrxgukcamhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id k186so5742664yba.18
        for <kasan-dev@googlegroups.com>; Thu, 18 Jun 2020 02:32:00 -0700 (PDT)
X-Received: by 2002:a25:be02:: with SMTP id h2mr5002260ybk.315.1592472720343;
 Thu, 18 Jun 2020 02:32:00 -0700 (PDT)
Date: Thu, 18 Jun 2020 11:31:16 +0200
In-Reply-To: <20200618093118.247375-1-elver@google.com>
Message-Id: <20200618093118.247375-2-elver@google.com>
Mime-Version: 1.0
References: <20200618093118.247375-1-elver@google.com>
X-Mailer: git-send-email 2.27.0.290.gba653c62da-goog
Subject: [PATCH 1/3] kcsan: Re-add GCC as a supported compiler
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: will@kernel.org, peterz@infradead.org, bp@alien8.de, tglx@linutronix.de, 
	mingo@kernel.org, dvyukov@google.com, cai@lca.pw, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, Martin Liska <mliska@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=tRJULurj;       spf=pass
 (google.com: domain of 3kdtrxgukcamhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3kDTrXgUKCaMHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

GCC version 11 recently implemented all requirements to correctly
support KCSAN:

1. Correct no_sanitize-attribute inlining behaviour:
   https://gcc.gnu.org/git/?p=gcc.git;a=commit;h=4089df8ef4a63126b0774c39b6638845244c20d2

2. --param=tsan-distinguish-volatile
   https://gcc.gnu.org/git/?p=gcc.git;a=commit;h=ab2789ec507a94f1a75a6534bca51c7b39037ce0

3. --param=tsan-instrument-func-entry-exit
   https://gcc.gnu.org/git/?p=gcc.git;a=commit;h=06712fc68dc9843d9af7c7ac10047f49d305ad76

Therefore, we can re-enable GCC for KCSAN, and document the new compiler
requirements.

Signed-off-by: Marco Elver <elver@google.com>
Cc: Martin Liska <mliska@suse.cz>
---

For anyone interested to try it out before GCC 11 is released, I'd
recommend building a stable GCC 10 with the patches applied:

	git clone git://gcc.gnu.org/git/gcc.git && cd gcc
	git checkout -b gcc-10-for-kcsan releases/gcc-10.1.0
	git cherry-pick \
		4089df8ef4a63126b0774c39b6638845244c20d2 \
		ab2789ec507a94f1a75a6534bca51c7b39037ce0 \
		06712fc68dc9843d9af7c7ac10047f49d305ad76
	./configure --prefix <your-prefix> --enable-languages=c,c++
	make -j$(nproc) && make install
---
 Documentation/dev-tools/kcsan.rst | 3 ++-
 lib/Kconfig.kcsan                 | 3 ++-
 scripts/Makefile.kcsan            | 2 +-
 3 files changed, 5 insertions(+), 3 deletions(-)

diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
index ce4bbd918648..8fa0dd6c8614 100644
--- a/Documentation/dev-tools/kcsan.rst
+++ b/Documentation/dev-tools/kcsan.rst
@@ -8,7 +8,8 @@ approach to detect races. KCSAN's primary purpose is to detect `data races`_.
 Usage
 -----
 
-KCSAN requires Clang version 11 or later.
+KCSAN is supported by both GCC and Clang. With GCC we require version 11 or
+later, and with Clang also require version 11 or later.
 
 To enable KCSAN configure the kernel with::
 
diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index 3f3b5bca7a8f..3d282d51849b 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -4,7 +4,8 @@ config HAVE_ARCH_KCSAN
 	bool
 
 config HAVE_KCSAN_COMPILER
-	def_bool CC_IS_CLANG && $(cc-option,-fsanitize=thread -mllvm -tsan-distinguish-volatile=1)
+	def_bool (CC_IS_CLANG && $(cc-option,-fsanitize=thread -mllvm -tsan-distinguish-volatile=1)) || \
+		 (CC_IS_GCC && $(cc-option,-fsanitize=thread --param tsan-distinguish-volatile=1))
 	help
 	  For the list of compilers that support KCSAN, please see
 	  <file:Documentation/dev-tools/kcsan.rst>.
diff --git a/scripts/Makefile.kcsan b/scripts/Makefile.kcsan
index bd4da1af5953..dd66206f4578 100644
--- a/scripts/Makefile.kcsan
+++ b/scripts/Makefile.kcsan
@@ -6,7 +6,7 @@ ifdef CONFIG_KCSAN
 ifdef CONFIG_CC_IS_CLANG
 cc-param = -mllvm -$(1)
 else
-cc-param = --param -$(1)
+cc-param = --param $(1)
 endif
 
 # Keep most options here optional, to allow enabling more compilers if absence
-- 
2.27.0.290.gba653c62da-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200618093118.247375-2-elver%40google.com.
