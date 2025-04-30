Return-Path: <kasan-dev+bncBCG5FM426MMRB4VSY7AAMGQEZUCR6OI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E8B0AA44BA
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Apr 2025 10:04:04 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-43ceeaf1524sf2742245e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Apr 2025 01:04:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746000243; cv=pass;
        d=google.com; s=arc-20240605;
        b=DPw0jWH1La9fRfSmVrkx1fJtQPMrkyXWbOtJ4k0y0o/adih0sJy7FGgbcijatwpMBP
         F3ctNRQtH1pF2dVJLcz+qxNt0f1BrS2MHzbd+VA1bmEoCOTDxOc7sYS9CTg38mrmlqkO
         UKZgdusk9tZwwF62mt8avrcAc6vQodIYTMIN54tw6f9sAsX5Bd/7NfU6HczUY2+I/kY3
         EwEbTAzkVdNehSiPrXTlE0w90CXRtvU/ocUV2LfX9tR6j+do6e8r20rGxfvjFInRkTe4
         U4AyJrQMCsfVyMySwug97mYC1xA7/xhn18xoY+lxfllniJHjlkqZ83Ifk+0SI+3EbL2u
         2dtQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=9o5ForThS5qb0tZtt5p32gzIzQDHH6KHQOIB/VesDu0=;
        fh=cIF+/7WJwUN6nNzfqgTqWCskyV3zxVkrJKbAS9mR2Nc=;
        b=lMn0fjIgBzOvDmhSy946rYkka35giTA5TyY/lyznbRMOEm66kEKbg60M/TBfCkVkQW
         RmxId/iqgX5Qx8HoYhL8PnOMdyq0HKaE8YbzCn31KQvMJBmXWLlJrLdANCJdXvT2VSuG
         3W7NijoiPfi0+yrT5CAEHZ0eMUlvHbTGE97EP92ePA2EgRvbokDOA0Ps0G8/x6B8QUcG
         0OYgHQbxO2UPsA1zVW3If2wlU8L6tGl1ZicZNW7Zvkx/wj638akoSvdRtjr2l4JPPbdt
         kU8cFA4izZt21xRD/6OWLAcDgTiRzYkmroOnrfgtsCB3/ZqdPN24cLinqyIm0q4uWMFX
         pn9A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=O3Y5lSec;
       spf=pass (google.com: domain of 3b9kraakkcbaqbysuhoxbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--aliceryhl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3b9kRaAkKCbAQbYSUhoXbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--aliceryhl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746000243; x=1746605043; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9o5ForThS5qb0tZtt5p32gzIzQDHH6KHQOIB/VesDu0=;
        b=Mkr9KftlKBbsmiFBtNHIFkzPe605TkY8AUvCPkUTbiV+ccv8EjKAvgr5KVBK3Ks+l6
         l+uLiqRI4rrRezTfsk0JetOQMPQ9JXUPLCEFrPqGHhrofro4TcoulC81cEBqyaXEDlqX
         0qpYMyZedJc+Up+KGJAavFNP/qAmZRequrm47mRsIA5d8h0mh4hE+8VkYkzByxE4B0si
         Z3Z16zeCsRSdQV+OpS3G35p5ag+hapNlfQ4pSrs9k1jIdD02XqgFWLJP2+qScdUFeYCP
         9lq9/otCeumo+sNZOFmN/uVWZUvZgcdhlYyRdks0geKeOP02ziRgQ8f4e9bd40D4RbCn
         6nBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746000243; x=1746605043;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=9o5ForThS5qb0tZtt5p32gzIzQDHH6KHQOIB/VesDu0=;
        b=V/R2Eiy7tpNUyenNwJxHXgdcyBk3wTzS5BRmOwBZLvSpbWPm4YLqnddhc1ZZ2IuhLh
         GJauu2PTZktbey/Dg2h0T2pbRfJruqAr/l3x1uw3SNSW+2Xw0tZdbqkDg6aPozwkHGaJ
         MIyNyD9e5jOaDh6DS+NSL3nuI49QndYp0h/m7xQyp5WMJq6YXiisqRi0RdNJ3ivOS5Ea
         FGKIbQXegmK4kBzeakNioM3sZM06EUdomto9dC0pLUv3pP08foGvvzCRqrJ8qLdFNLJh
         Z4h5dOu330i/TIQsvKrY+csksv83L8txbDNzTmO+GKwwWm/0O0QOYHIihU6cLcixkQ0U
         qEfw==
X-Forwarded-Encrypted: i=2; AJvYcCV3G5tg/9/l3jxHvZZsXdAUUczYwHt9GrBrnVrVHz3YZmFjZ4qHC9iFvlVmUmvivrkgr+YkKA==@lfdr.de
X-Gm-Message-State: AOJu0YxVT1XYWBTfqHshpnxbgATp6sT7gvj80taymnyh+UtbTT0BBl89
	ANf7xSq2jJXjCW053Grw//3Toe7ANnhmsD7dg9kZgP2gcOTWFfM4
X-Google-Smtp-Source: AGHT+IErfbRGL7K1jsQKvzwukLeDtdT/h5hq6z8sY3iz10ZGs5/qqNRN3S7cfqRad9VcEu3+6eDEoQ==
X-Received: by 2002:a05:600c:6b67:b0:43c:f509:2bbf with SMTP id 5b1f17b1804b1-441b2404efemr13569625e9.15.1746000242901;
        Wed, 30 Apr 2025 01:04:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBGm1X5ZomVvQDgpzvU1LN3fkVolsQtnl3aipHafp75e7A==
Received: by 2002:a05:600c:4f8e:b0:43c:f636:85d0 with SMTP id
 5b1f17b1804b1-441b1dd203cls2079805e9.1.-pod-prod-00-eu; Wed, 30 Apr 2025
 01:04:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW+QQtWOaTEtOoJCR0rAhMZWZ/pe8Otte9GPVrJxx4GtY4/NoOfXXeHxYrwYIHc+VACpijTM1gHHO0=@googlegroups.com
X-Received: by 2002:a05:600c:c3d9:b0:441:b3eb:570c with SMTP id 5b1f17b1804b1-441b3eb5828mr4688475e9.6.1746000240303;
        Wed, 30 Apr 2025 01:04:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746000240; cv=none;
        d=google.com; s=arc-20240605;
        b=ajBTF4M7k3XPHV0CNsaXNfH8Nros7tdSMqcTmj5QPpbQLqwamWyYd5Jq7yKLFxBWmU
         MEJ3FtufDhcw0pOgAU/YN/UXKgVnhC75ydSC2SEjLBLwjzH+GIZjTwlyYn5sp/QD270U
         +Hl3wAptj22pHUeqDqfMswvBH6oa3xDdxB/YSW+nrkiO7o62wIKNkYMHOdvGXBPtobsE
         eUOgNHMd9BPKcajyo4CIGDzosv7ySAawhmnq0ISGCBSxVO59ig7b4zLDqoRsgUz6UqP/
         WZYFIVP+mg58NQBZ37vpS11AmClucrtIWIK0KkQXzRioa3zDMLpbV7FbiCbyhNEwWb2N
         sWZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=WpWRPKZTrgVHckN4fyywT4debJCD4sQBNo0HtHYOfx4=;
        fh=dmaRkvDcjk3+LbFugwr+4wY5bKV7TsN92iOpGf/kexs=;
        b=HsLAGCj42K8QfSXL7FQTW2dVeCycGypDPyXmw4kP1UxoQz+RuLMlL3P5DFbyA69OiW
         ovXpZu47XDK8jQLX1/+DaBRuuyHQPpmUpQ5OVqxwXe0u4TgOFjYjuehu3gjtW+QuvNsW
         1/fohLwCBt/JE0Gf1irGzCqxkLbbatAZhbAk8zHfacFiHtEuc5IR4gx6lDlw3adW9jc8
         shq/nGbcY76mXpOAgP5e92c0X/e0AX0jj/yZRhL45KLkXAYxmclAf4aqPZ8FWmAqqxd+
         5Tz9RahrW74dY75NK02gMirMr707cZWQPojxMNnySOulP4gn/M5eir5rhEja/sc6Ufz9
         ulcQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=O3Y5lSec;
       spf=pass (google.com: domain of 3b9kraakkcbaqbysuhoxbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--aliceryhl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3b9kRaAkKCbAQbYSUhoXbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--aliceryhl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-441b2aee52fsi13215e9.2.2025.04.30.01.04.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Apr 2025 01:04:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3b9kraakkcbaqbysuhoxbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--aliceryhl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-43d4d15058dso47337025e9.0
        for <kasan-dev@googlegroups.com>; Wed, 30 Apr 2025 01:04:00 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUCoEu3722VyUdAV8z2fugpzfGMmSTu/uL0BzAQjXwMGExodkjj9+pOiqSLiPOVYfr/zcnwLn+0FM4=@googlegroups.com
X-Received: from wmbeu5.prod.google.com ([2002:a05:600c:81c5:b0:43d:b30:d2df])
 (user=aliceryhl job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:600c:a4e:b0:43c:fcb1:528a with SMTP id 5b1f17b1804b1-441b1f30feemr17935465e9.6.1746000239963;
 Wed, 30 Apr 2025 01:03:59 -0700 (PDT)
Date: Wed, 30 Apr 2025 08:03:54 +0000
Mime-Version: 1.0
X-B4-Tracking: v=1; b=H4sIAGrZEWgC/6tWKk4tykwtVrJSqFYqSi3LLM7MzwNyDHUUlJIzE
 vPSU3UzU4B8JSMDI1MDE2MD3aLS4hLd7OT8Ml2zZHOTtBSDNMM0AzMloPqCotS0zAqwWdGxtbU ALAxa6FsAAAA=
X-Change-Id: 20250430-rust-kcov-6c74fd0f1f06
X-Developer-Key: i=aliceryhl@google.com; a=openpgp; fpr=49F6C1FAA74960F43A5B86A1EE7A392FDE96209F
X-Developer-Signature: v=1; a=openpgp-sha256; l=2361; i=aliceryhl@google.com;
 h=from:subject:message-id; bh=DKnudNd/9zBWW3fHL+84dgzzzUZDXPxTFrPLc0mlmb4=;
 b=owEBbQKS/ZANAwAKAQRYvu5YxjlGAcsmYgBoEdltHctz9D+GQdMdpsulmMJUFsQjQ4TdJk+NW
 R8aFYqqGmuJAjMEAAEKAB0WIQSDkqKUTWQHCvFIvbIEWL7uWMY5RgUCaBHZbQAKCRAEWL7uWMY5
 RkM8EACNQ+B2tYSbeUNKxBIjv1jFJCJsBOD4ZIW9UXYWnSamDV6d+85oW4gtrz/3sNyWC6BrxIb
 ef162AJCYx1p0heTqIwEuhhUfWddFwW8WqmZvYRMcMFm3LyVpaA9BvsXuVe4v4t5bTeaFeuPRHL
 MIczft0hFYyp0T3j2jFuSaFNIHP8CTt9FcRG2AiZeSf0klb1Kmsx9G0ZwArLD8cnVuXeKGQz+Vy
 h42QeKg6ZVhmd46p7FBUgX8RH0xbPpkELYz6YeMkHwp0jxx2zM6EoaJizuLFTE8SkPw4sLpM9XZ
 iYiwS125lIVSnSzWYRpJj0CuSdM9+QekWXREltJD5MvAeTODPdBBp6nS9z+K1A96Q85awr6jqYg
 1suryL9Pkq+gMOdf7vbQ1iB+nKo/TdTDIAyfalAtu4vo6UKyaqWR4uZ2vLzAvON7cWKO3lkowKq
 Qdw9z8eFTyKAX0a5oqadcrknlSEzZPboyuVxdAyDyiwQMG1dGcPJxeGl44z6UZF8U7xa3toy0Tc
 /jFXxkxBlC8m4pJqUK3F/Ep8vSTPQpHpM1wQWhaqg24PS8cqW6aDgRdItMy59S1zmYcVc7WQ2cu
 bDjzwYoDPQEMESBIbaTCK9GyNptDtJzA5a8oV9YxUprBaiSmLy0OGe3JxLeieWSVVZ685AqDZKR FoiAzOAkF+2jjLg==
X-Mailer: b4 0.14.2
Message-ID: <20250430-rust-kcov-v1-1-b9ae94148175@google.com>
Subject: [PATCH] kcov: rust: add flags for KCOV with Rust
From: "'Alice Ryhl' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Masahiro Yamada <masahiroy@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Miguel Ojeda <ojeda@kernel.org>
Cc: Nicolas Schier <nicolas.schier@linux.dev>, Boqun Feng <boqun.feng@gmail.com>, 
	Gary Guo <gary@garyguo.net>, 
	"=?utf-8?q?Bj=C3=B6rn_Roy_Baron?=" <bjorn3_gh@protonmail.com>, Benno Lossin <benno.lossin@proton.me>, 
	Andreas Hindborg <a.hindborg@kernel.org>, Trevor Gross <tmgross@umich.edu>, 
	Danilo Krummrich <dakr@kernel.org>, Aleksandr Nogikh <nogikh@google.com>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Bill Wendling <morbo@google.com>, 
	Justin Stitt <justinstitt@google.com>, kasan-dev@googlegroups.com, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	rust-for-linux@vger.kernel.org, llvm@lists.linux.dev, 
	Matthew Maurer <mmaurer@google.com>, Alice Ryhl <aliceryhl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: aliceryhl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=O3Y5lSec;       spf=pass
 (google.com: domain of 3b9kraakkcbaqbysuhoxbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--aliceryhl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3b9kRaAkKCbAQbYSUhoXbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--aliceryhl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Alice Ryhl <aliceryhl@google.com>
Reply-To: Alice Ryhl <aliceryhl@google.com>
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

Rust code is currently not instrumented properly when KCOV is enabled.
Thus, add the relevant flags to perform instrumentation correctly. This
is necessary for efficient fuzzing of Rust code.

The sanitizer-coverage features of LLVM have existed for long enough
that they are available on any LLVM version supported by rustc, so we do
not need any Kconfig feature detection.

The coverage level is set to 3, as that is the level needed by trace-pc.

Co-developed-by: Matthew Maurer <mmaurer@google.com>
Signed-off-by: Matthew Maurer <mmaurer@google.com>
Signed-off-by: Alice Ryhl <aliceryhl@google.com>
---
 scripts/Makefile.kcov | 6 ++++++
 scripts/Makefile.lib  | 3 +++
 2 files changed, 9 insertions(+)

diff --git a/scripts/Makefile.kcov b/scripts/Makefile.kcov
index 67e8cfe3474b7dcf7552e675cffe356788e6c3a2..ddcc3c6dc513e1988aeaf07b8efa106e8dffa640 100644
--- a/scripts/Makefile.kcov
+++ b/scripts/Makefile.kcov
@@ -3,4 +3,10 @@ kcov-flags-$(CONFIG_CC_HAS_SANCOV_TRACE_PC)	+= -fsanitize-coverage=trace-pc
 kcov-flags-$(CONFIG_KCOV_ENABLE_COMPARISONS)	+= -fsanitize-coverage=trace-cmp
 kcov-flags-$(CONFIG_GCC_PLUGIN_SANCOV)		+= -fplugin=$(objtree)/scripts/gcc-plugins/sancov_plugin.so
 
+kcov-rflags-y					+= -Cpasses=sancov-module
+kcov-rflags-y					+= -Cllvm-args=-sanitizer-coverage-level=3
+kcov-rflags-y					+= -Cllvm-args=-sanitizer-coverage-trace-pc
+kcov-rflags-$(CONFIG_KCOV_ENABLE_COMPARISONS)	+= -Cllvm-args=-sanitizer-coverage-trace-compares
+
 export CFLAGS_KCOV := $(kcov-flags-y)
+export RUSTFLAGS_KCOV := $(kcov-rflags-y)
diff --git a/scripts/Makefile.lib b/scripts/Makefile.lib
index 2fe73cda0bddb9dcf709d0a9ae541318d54754d2..520905f19a9b19631394cfb5e129effb8846d5b8 100644
--- a/scripts/Makefile.lib
+++ b/scripts/Makefile.lib
@@ -169,6 +169,9 @@ ifeq ($(CONFIG_KCOV),y)
 _c_flags += $(if $(patsubst n%,, \
 	$(KCOV_INSTRUMENT_$(target-stem).o)$(KCOV_INSTRUMENT)$(if $(is-kernel-object),$(CONFIG_KCOV_INSTRUMENT_ALL))), \
 	$(CFLAGS_KCOV))
+_rust_flags += $(if $(patsubst n%,, \
+	$(KCOV_INSTRUMENT_$(target-stem).o)$(KCOV_INSTRUMENT)$(if $(is-kernel-object),$(CONFIG_KCOV_INSTRUMENT_ALL))), \
+	$(RUSTFLAGS_KCOV))
 endif
 
 #

---
base-commit: 9c32cda43eb78f78c73aee4aa344b777714e259b
change-id: 20250430-rust-kcov-6c74fd0f1f06

Best regards,
-- 
Alice Ryhl <aliceryhl@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250430-rust-kcov-v1-1-b9ae94148175%40google.com.
