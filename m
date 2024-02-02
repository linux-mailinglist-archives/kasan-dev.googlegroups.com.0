Return-Path: <kasan-dev+bncBCF5XGNWYQBRBEMC6OWQMGQEEHWHC4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D05D846D93
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Feb 2024 11:16:50 +0100 (CET)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-42a85818c9fsf370901cf.0
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Feb 2024 02:16:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706869009; cv=pass;
        d=google.com; s=arc-20160816;
        b=I858S7mFypzATSxuH6pwkakLrHNjul1Pluy5pfwBQBcS/gufzbfncXSSxXCc+qOoPe
         8KmQRYUSIwP6pwXWOULbZWGs0TwTiakqkKd6Le0KK88wl0FOtRLb07PCxaqIfDeVVQXC
         JlfOjfwvqyq3GK+Lv06KpGMlvPvYlykpQtiNz9v8PC7pJeKDQ4CMqmnHxhy2PdheVn3T
         2aExs555Qp2O643enVNB/ET0In4pxhxr/N7J6rI3MjzZ5QawkSrELwhnn24w084n6cz0
         kwStLe39w6yFPZcTjDAA3onzGdA47GjHy348v/xf8a6irtVkJ4+5zjOlNlIzuqz8XySf
         z9Gg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=463YvHgM3h8zN/6jC8BCR6zXnoafcey6i+iIdcEJbRk=;
        fh=JDN5cHy7gaNUDiurM1K70dA6D358GZ0kl1yne+Kn7EI=;
        b=DJW/lEwnFT4R70JsMP85Kjy/n9pNMe7Z5bTj77XSMAlHetpTihhqeRuVjkR+b5ySoa
         kHssYGU8Zgha5WR6ERJEV/y+mYnohh+PQl8JRG7X/hFiWASgOm8AeC8qcSSZ4RHYU6Jh
         eE3FMCaYvum9NRKacZobE5cwgot2cfeCtaXg/IjllQw1CGQxF2E2AoEN751E52Qfbzv4
         jzFghMF3zSPE/5l8A6FnJWiylfYpAu+WE8KdLAnPuETPblfVK9SXIRb7BauR7kU0Tx1b
         YRjczdiS6ADSzv+zN87IC/eSY5xTrOVEl0us/OOIDBq5WhFyKOf+MNZi0sPSt27X9ZHT
         l8PA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=oDPZRIOf;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706869009; x=1707473809; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=463YvHgM3h8zN/6jC8BCR6zXnoafcey6i+iIdcEJbRk=;
        b=hXwvOLgHh43xw9PBpLE03V5DT2nKkUgx2wr5iCUnExbXuWwfUUCuGHtAHs8J6rxDYN
         QmmMnlfolN6dD/2wHunmVb48TPg0Uh/C+8MFQRe5e5YMddYOEPtT6PI+nl6U+8nHqQJA
         Y7xUtaHeKeT4mx+n9zfPCItbvKo7EkrHA/bGS9AJf9/qYogSbEDAYw/iK/J6DJRF8sH8
         sYwEGDk8s1ItQArfpf6dBvgF8sV+UoGBcvxXDodU177ncfz2h1UJdnGnaxKDv3cIvVkp
         FlpRyljka9PQx3ltIGtdCurnILuG4PmpJhgOJnMiYOn7XTPriwjhfeUYE1qIRDLz0H/E
         3Rnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706869009; x=1707473809;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=463YvHgM3h8zN/6jC8BCR6zXnoafcey6i+iIdcEJbRk=;
        b=mtQhzTQhxYpd62/XGiRNTWk+ziW63OyrobQfSncrKcwWZOQTafGwYHNclq6Keow/Vb
         iIwcqDPvNtt6SYH5Zd62Fs7cmNEZBHdUknpgsu2Yn5sdAbc8l+/S8eLkoWROr/WyoKxX
         EYRGYuwvvXcawmHVS1XGxFGYuHJ0GJn8HlSYd4WNyrJMzj/E1izC1M1Fvz1YawAc8civ
         q7ilbiSrVc/mlc3yXwsnZ8pK1ytm5irINvgKyiXOkQscuOVInuVFFu3KGM2B14kow68p
         FAPUWfMHJxTXOQoOW6GKxrgW16cBWPwyI+0QIgYK6KFqyzrRj817hXqRHHRig+d9CKLd
         eGUg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzwyE86YgvA42TP8kWXXHoC75cDPZRKbAAdenTGcDIajfKB97jJ
	CUHFy/TROQvhtKJILVyJwIszR/92ioa5i30Vq9w8x4vzjf7OyCSA
X-Google-Smtp-Source: AGHT+IE5nSe/uXeqmYouB4hXsf3cCnd4QdMWUAx/GcpHjnX8rWro3GTQbLtMdjXwpPanu37ZRalGUQ==
X-Received: by 2002:ac8:4e4e:0:b0:42a:db5b:c7e6 with SMTP id e14-20020ac84e4e000000b0042adb5bc7e6mr146159qtw.7.1706869009182;
        Fri, 02 Feb 2024 02:16:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:ea22:0:b0:67f:74d3:afb5 with SMTP id t2-20020a0cea22000000b0067f74d3afb5ls301652qvp.1.-pod-prod-01-us;
 Fri, 02 Feb 2024 02:16:48 -0800 (PST)
X-Received: by 2002:a05:620a:124c:b0:783:4a89:f1d9 with SMTP id a12-20020a05620a124c00b007834a89f1d9mr5359084qkl.59.1706869008296;
        Fri, 02 Feb 2024 02:16:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706869008; cv=none;
        d=google.com; s=arc-20160816;
        b=tDqyqIMFV6p5vMkuurz0n1+LeLgCydGpox9iSOcA+AI+O3mERwsmnRZCr+Ggcw61Vq
         k8vKhqWf0vO9WUUFg7CifrbW8q6X0YbmP/bm2OSNQhHyL9FUVHQdB2UFmoza+gvYExD2
         INa1A2fPOBi+66La0yD+DEAPU39sslUXG7X25ZsJGantV7CpDOppWCgVpbjl9GY2U1eH
         /ho2N3oNcxtEFP2p9ZwpDT9VhBp5gZnWdy3LgPFj7qdEmEPvbdA0TJOrrHOf3VRVogxD
         q9U93i4X4cmcnUlmROm/KO+pAil2BXjq3TW11jgWUwNf0hDkmRRHVGS3685K0sju4Sxp
         bFXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=9lpkhLqd7OEtlpbaedS5vxnqsFfxpeZmJYnh9HQNf48=;
        fh=JDN5cHy7gaNUDiurM1K70dA6D358GZ0kl1yne+Kn7EI=;
        b=K3/DW3GbTaadKl9XFnya1hZHTdxsUzlBUCbMZuwmNVO8iAdEq31QJ9vmGqN3DwypKp
         04TNbOkTw8zZSj7uahTq8LNBbdWosn660HTt/HP+8kApKySDzR6y6XBi5RqlObtH9JLm
         425V0G4ivWIBAlMnRo07PdxfviP5bqv7H7tyNh7AcqxHlGEcHLs7QAKyyvDXJGl4yhFu
         QIWUiSRqkEtOcydmDzo60Wa+zPbY+J2p+JvO9WEBn4Pp5kb1JhuO4UJosVlvpNgROeuL
         qxN1tsQV1zxFYT+7np7U8wMR1GZQ4Jxgf5zC8UnoP8Q79yXlvzdLU44i9dxU7DyMU7rh
         OG4w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=oDPZRIOf;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
X-Forwarded-Encrypted: i=0; AJvYcCWVQ8TT0aSNQlLJFmxIiUu2mbgKEv0Kv7EM45m7xixKwBBeXBij9ZnWHVvjjjBOZQJ3R78IOzhWqWo/Sb1ddHmYszL6DpMRR/5qdg==
Received: from mail-pl1-x62a.google.com (mail-pl1-x62a.google.com. [2607:f8b0:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id v28-20020a05620a0a9c00b00783f684e15bsi88840qkg.2.2024.02.02.02.16.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Feb 2024 02:16:48 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62a as permitted sender) client-ip=2607:f8b0:4864:20::62a;
Received: by mail-pl1-x62a.google.com with SMTP id d9443c01a7336-1d71cb97937so18071875ad.3
        for <kasan-dev@googlegroups.com>; Fri, 02 Feb 2024 02:16:48 -0800 (PST)
X-Received: by 2002:a17:902:ec8f:b0:1d9:7ebe:431f with SMTP id x15-20020a170902ec8f00b001d97ebe431fmr75634plg.25.1706869007422;
        Fri, 02 Feb 2024 02:16:47 -0800 (PST)
X-Forwarded-Encrypted: i=0; AJvYcCXs4G8MUacPDVffkkW3YIupLvo7fOKngXgP+Sk6+29gQMVKJs08J0+3IxTwtNEEkiZ8eGAIttWEaHeXH6T6+fNfWQ+QDHgR8QFndX1YkdshPqcHnC8ZhMEw8Y205GGD/hXZeKG9lZA4KiQhE6/y0ZGb14IngWwfwvlekaGRRjUjWt0j5zMxr8icCHSkAzObwyJrh/jcvniTLARTNzCtWdffpO6cA+p9dquKTDehLQT1ImPrwzjg6dOQIOgvEOrnwmSgHcXAhPPG9s3ww8WwNDHHhWbYEbihBm1UxI5VGCz8gxJG/LPhjIEbOa50AtDgdzpicwFKl+d/veprf2CxavchMKcf1ZFpZMPnpeQdl7uabrqw/JibLaG0sc11Qk3+f1aw2VTEFjODk3/Auveeqk+wydW8nC0nhD/Yf0OmhO3pWVWzu8PP4+241P4he/xwQLRUGB3XgKIMTvlu1GPBSADeZq15+ug6D0fQt+Rd9xziIqyoAcned2NH8sAF9kIoBbad4ycXB8VLaDO4+Flm53lBdv1eUkmjzOR9OnaWoBqBFI5sNi2Q0JvocsOdwnb+1cJGO+I34RT7e4Uv35WZCcQjH4km59aPOS+QQP0=
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id 4-20020a170902e9c400b001d94e6a7685sm1242824plk.234.2024.02.02.02.16.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 02 Feb 2024 02:16:46 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: linux-hardening@vger.kernel.org
Cc: Kees Cook <keescook@chromium.org>,
	x86@kernel.org,
	netdev@vger.kernel.org,
	linux-crypto@vger.kernel.org,
	Fangrui Song <maskray@google.com>,
	Justin Stitt <justinstitt@google.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nicolas Schier <nicolas@fjasle.eu>,
	Bill Wendling <morbo@google.com>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Jonathan Corbet <corbet@lwn.net>,
	linux-kernel@vger.kernel.org,
	linux-kbuild@vger.kernel.org,
	llvm@lists.linux.dev,
	linux-doc@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-acpi@vger.kernel.org
Subject: [PATCH v2 6/6] ubsan: Get x86_64 booting with unsigned wrap-around sanitizer
Date: Fri,  2 Feb 2024 02:16:39 -0800
Message-Id: <20240202101642.156588-6-keescook@chromium.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20240202101311.it.893-kees@kernel.org>
References: <20240202101311.it.893-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=9025; i=keescook@chromium.org;
 h=from:subject; bh=TzLGN/wZFrYl4sz0T0jyTqFgT2Lvj1xSfjBLlzj7afo=;
 b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBlvMEHyPK5ViviPn9azIBFUIYrlBFvd0kw+bqbP
 wVlizzw8PGJAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCZbzBBwAKCRCJcvTf3G3A
 Jj10EACxZp8csm9ZCk+xJiU3zMmobNiVh75p7eiqjwSp/+F5YknBmFn1AlM7gImi5vPAMhF+uJK
 S7tEGvBu0z8HJAYyprAsz8MTPA3XkwZaBvDh9ooyUaCGG4dQYhzZEamHqjAeDnajhy5ZftZymg1
 B+ufjH0oJ0ni6WwN8v+6NA2qQLUNSrjnKtiribhsUUvNU+RIbBsci8ifkfB+R/+u+pEbCf6P88A
 7+XDsZKTZQdFahZfTiTeUE/SXyL4N3tj6bSoRpsihC/55AJZVXSoatefKR16VpdBCKZKwTNweW6
 S0vj+nz1PDLZHYxiOQVF9JH1HUjMv4EXIi6sJ1rayPbtQpTapfFyPHsS/42+1og+ZkbBjhrPtgx
 V22ba3CXArD1r3+innlUCwo1gznduzvlxVifjuGsBnPTOKM9JeBPNWu75tm1vMoR65PHo4qxOG+
 O/tg1yEg6gja2mNPYPKJXZUW2S29A0iPG+8XuUSExGdu9BudGeVw18IasDUmfthZyPLWNROQGpN
 9JyUUkTnApR92NAMUzHLj3ne7upYSQJ31Ab+MogRw6at1STgZvaWFIE5e5a/XQYbuNQmITc7hVq
 6o5PuItNU7vlLrYD2InHp+9VTFqpLrw3s1toSBj+qbAQByyz+QyYIdE324S1o0WW6EeKf4cuLVm DqWvp1fbl88HqTQ==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=oDPZRIOf;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62a
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

In order to get x86_64 booting at all with the unsigned wrap-around
sanitizer, instrumentation needs to be disabled entirely for several
kernel areas that depend heavily on unsigned wrap-around. As we fine-tune
the sanitizer, we can revisit these and perform finer grain annotations.
The boot is still extremely noisy, but gets us to a common point where
we can continue experimenting with the sanitizer.

Cc: x86@kernel.org
Cc: netdev@vger.kernel.org
Cc: linux-crypto@vger.kernel.org
Signed-off-by: Kees Cook <keescook@chromium.org>
---
 arch/x86/kernel/Makefile      | 1 +
 arch/x86/kernel/apic/Makefile | 1 +
 arch/x86/mm/Makefile          | 1 +
 arch/x86/mm/pat/Makefile      | 1 +
 crypto/Makefile               | 1 +
 drivers/acpi/Makefile         | 1 +
 kernel/Makefile               | 1 +
 kernel/locking/Makefile       | 1 +
 kernel/rcu/Makefile           | 1 +
 kernel/sched/Makefile         | 1 +
 lib/Kconfig.ubsan             | 5 +++--
 lib/Makefile                  | 1 +
 lib/crypto/Makefile           | 1 +
 lib/crypto/mpi/Makefile       | 1 +
 lib/zlib_deflate/Makefile     | 1 +
 lib/zstd/Makefile             | 2 ++
 mm/Makefile                   | 1 +
 net/core/Makefile             | 1 +
 net/ipv4/Makefile             | 1 +
 19 files changed, 22 insertions(+), 2 deletions(-)

diff --git a/arch/x86/kernel/Makefile b/arch/x86/kernel/Makefile
index 0000325ab98f..de93f8b8a149 100644
--- a/arch/x86/kernel/Makefile
+++ b/arch/x86/kernel/Makefile
@@ -30,6 +30,7 @@ KASAN_SANITIZE_sev.o					:= n
 
 # With some compiler versions the generated code results in boot hangs, caused
 # by several compilation units. To be safe, disable all instrumentation.
+UBSAN_WRAP_UNSIGNED := n
 KCSAN_SANITIZE := n
 KMSAN_SANITIZE_head$(BITS).o				:= n
 KMSAN_SANITIZE_nmi.o					:= n
diff --git a/arch/x86/kernel/apic/Makefile b/arch/x86/kernel/apic/Makefile
index 3bf0487cf3b7..aa97b5830b64 100644
--- a/arch/x86/kernel/apic/Makefile
+++ b/arch/x86/kernel/apic/Makefile
@@ -6,6 +6,7 @@
 # Leads to non-deterministic coverage that is not a function of syscall inputs.
 # In particular, smp_apic_timer_interrupt() is called in random places.
 KCOV_INSTRUMENT		:= n
+UBSAN_WRAP_UNSIGNED	:= n
 
 obj-$(CONFIG_X86_LOCAL_APIC)	+= apic.o apic_common.o apic_noop.o ipi.o vector.o init.o
 obj-y				+= hw_nmi.o
diff --git a/arch/x86/mm/Makefile b/arch/x86/mm/Makefile
index c80febc44cd2..7a43466d4581 100644
--- a/arch/x86/mm/Makefile
+++ b/arch/x86/mm/Makefile
@@ -1,5 +1,6 @@
 # SPDX-License-Identifier: GPL-2.0
 # Kernel does not boot with instrumentation of tlb.c and mem_encrypt*.c
+UBSAN_WRAP_UNSIGNED := n
 KCOV_INSTRUMENT_tlb.o			:= n
 KCOV_INSTRUMENT_mem_encrypt.o		:= n
 KCOV_INSTRUMENT_mem_encrypt_amd.o	:= n
diff --git a/arch/x86/mm/pat/Makefile b/arch/x86/mm/pat/Makefile
index ea464c995161..281a5786c5ea 100644
--- a/arch/x86/mm/pat/Makefile
+++ b/arch/x86/mm/pat/Makefile
@@ -1,4 +1,5 @@
 # SPDX-License-Identifier: GPL-2.0
+UBSAN_WRAP_UNSIGNED := n
 
 obj-y				:= set_memory.o memtype.o
 
diff --git a/crypto/Makefile b/crypto/Makefile
index 408f0a1f9ab9..c7b23d99e715 100644
--- a/crypto/Makefile
+++ b/crypto/Makefile
@@ -2,6 +2,7 @@
 #
 # Cryptographic API
 #
+UBSAN_WRAP_UNSIGNED := n
 
 obj-$(CONFIG_CRYPTO) += crypto.o
 crypto-y := api.o cipher.o compress.o
diff --git a/drivers/acpi/Makefile b/drivers/acpi/Makefile
index 12ef8180d272..92a8e8563b1b 100644
--- a/drivers/acpi/Makefile
+++ b/drivers/acpi/Makefile
@@ -2,6 +2,7 @@
 #
 # Makefile for the Linux ACPI interpreter
 #
+UBSAN_WRAP_UNSIGNED := n
 
 ccflags-$(CONFIG_ACPI_DEBUG)	+= -DACPI_DEBUG_OUTPUT
 
diff --git a/kernel/Makefile b/kernel/Makefile
index ce105a5558fc..1b31aa19b4fb 100644
--- a/kernel/Makefile
+++ b/kernel/Makefile
@@ -2,6 +2,7 @@
 #
 # Makefile for the linux kernel.
 #
+UBSAN_WRAP_UNSIGNED := n
 
 obj-y     = fork.o exec_domain.o panic.o \
 	    cpu.o exit.o softirq.o resource.o \
diff --git a/kernel/locking/Makefile b/kernel/locking/Makefile
index 0db4093d17b8..dd6492509596 100644
--- a/kernel/locking/Makefile
+++ b/kernel/locking/Makefile
@@ -2,6 +2,7 @@
 # Any varying coverage in these files is non-deterministic
 # and is generally not a function of system call inputs.
 KCOV_INSTRUMENT		:= n
+UBSAN_WRAP_UNSIGNED	:= n
 
 obj-y += mutex.o semaphore.o rwsem.o percpu-rwsem.o
 
diff --git a/kernel/rcu/Makefile b/kernel/rcu/Makefile
index 0cfb009a99b9..305c13042633 100644
--- a/kernel/rcu/Makefile
+++ b/kernel/rcu/Makefile
@@ -2,6 +2,7 @@
 # Any varying coverage in these files is non-deterministic
 # and is generally not a function of system call inputs.
 KCOV_INSTRUMENT := n
+UBSAN_WRAP_UNSIGNED := n
 
 ifeq ($(CONFIG_KCSAN),y)
 KBUILD_CFLAGS += -g -fno-omit-frame-pointer
diff --git a/kernel/sched/Makefile b/kernel/sched/Makefile
index 976092b7bd45..e487b0e86c2e 100644
--- a/kernel/sched/Makefile
+++ b/kernel/sched/Makefile
@@ -7,6 +7,7 @@ ccflags-y += $(call cc-disable-warning, unused-but-set-variable)
 # These files are disabled because they produce non-interesting flaky coverage
 # that is not a function of syscall inputs. E.g. involuntary context switches.
 KCOV_INSTRUMENT := n
+UBSAN_WRAP_UNSIGNED := n
 
 # Disable KCSAN to avoid excessive noise and performance degradation. To avoid
 # false positives ensure barriers implied by sched functions are instrumented.
diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
index 0611120036eb..54981e717355 100644
--- a/lib/Kconfig.ubsan
+++ b/lib/Kconfig.ubsan
@@ -132,8 +132,9 @@ config UBSAN_UNSIGNED_WRAP
 	depends on !COMPILE_TEST
 	help
 	  This option enables -fsanitize=unsigned-integer-overflow which checks
-	  for wrap-around of any arithmetic operations with unsigned integers. This
-	  currently causes x86 to fail to boot.
+	  for wrap-around of any arithmetic operations with unsigned integers.
+	  Given the history of C and the many common code patterns involving
+	  unsigned wrap-around, this is a very noisy option right now.
 
 config UBSAN_POINTER_WRAP
 	bool "Perform checking for pointer arithmetic wrap-around"
diff --git a/lib/Makefile b/lib/Makefile
index bc36a5c167db..f68385b69247 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -2,6 +2,7 @@
 #
 # Makefile for some libs needed in the kernel.
 #
+UBSAN_WRAP_UNSIGNED := n
 
 ccflags-remove-$(CONFIG_FUNCTION_TRACER) += $(CC_FLAGS_FTRACE)
 
diff --git a/lib/crypto/Makefile b/lib/crypto/Makefile
index 8d1446c2be71..fce88a337a53 100644
--- a/lib/crypto/Makefile
+++ b/lib/crypto/Makefile
@@ -1,4 +1,5 @@
 # SPDX-License-Identifier: GPL-2.0
+UBSAN_WRAP_UNSIGNED := n
 
 obj-$(CONFIG_CRYPTO_LIB_UTILS)			+= libcryptoutils.o
 libcryptoutils-y				:= memneq.o utils.o
diff --git a/lib/crypto/mpi/Makefile b/lib/crypto/mpi/Makefile
index 6e6ef9a34fe1..ce95653915b1 100644
--- a/lib/crypto/mpi/Makefile
+++ b/lib/crypto/mpi/Makefile
@@ -2,6 +2,7 @@
 #
 # MPI multiprecision maths library (from gpg)
 #
+UBSAN_WRAP_UNSIGNED := n
 
 obj-$(CONFIG_MPILIB) = mpi.o
 
diff --git a/lib/zlib_deflate/Makefile b/lib/zlib_deflate/Makefile
index 2622e03c0b94..5d71690554bb 100644
--- a/lib/zlib_deflate/Makefile
+++ b/lib/zlib_deflate/Makefile
@@ -6,6 +6,7 @@
 # This is the compression code, see zlib_inflate for the
 # decompression code.
 #
+UBSAN_WRAP_UNSIGNED := n
 
 obj-$(CONFIG_ZLIB_DEFLATE) += zlib_deflate.o
 
diff --git a/lib/zstd/Makefile b/lib/zstd/Makefile
index 20f08c644b71..7a187cb08c1f 100644
--- a/lib/zstd/Makefile
+++ b/lib/zstd/Makefile
@@ -8,6 +8,8 @@
 # in the COPYING file in the root directory of this source tree).
 # You may select, at your option, one of the above-listed licenses.
 # ################################################################
+UBSAN_WRAP_UNSIGNED := n
+
 obj-$(CONFIG_ZSTD_COMPRESS) += zstd_compress.o
 obj-$(CONFIG_ZSTD_DECOMPRESS) += zstd_decompress.o
 obj-$(CONFIG_ZSTD_COMMON) += zstd_common.o
diff --git a/mm/Makefile b/mm/Makefile
index e4b5b75aaec9..cacbdd1a2d40 100644
--- a/mm/Makefile
+++ b/mm/Makefile
@@ -2,6 +2,7 @@
 #
 # Makefile for the linux memory manager.
 #
+UBSAN_WRAP_UNSIGNED := n
 
 KASAN_SANITIZE_slab_common.o := n
 KASAN_SANITIZE_slub.o := n
diff --git a/net/core/Makefile b/net/core/Makefile
index 821aec06abf1..501d7300da83 100644
--- a/net/core/Makefile
+++ b/net/core/Makefile
@@ -2,6 +2,7 @@
 #
 # Makefile for the Linux networking core.
 #
+UBSAN_WRAP_UNSIGNED := n
 
 obj-y := sock.o request_sock.o skbuff.o datagram.o stream.o scm.o \
 	 gen_stats.o gen_estimator.o net_namespace.o secure_seq.o \
diff --git a/net/ipv4/Makefile b/net/ipv4/Makefile
index ec36d2ec059e..c738d463bb7e 100644
--- a/net/ipv4/Makefile
+++ b/net/ipv4/Makefile
@@ -2,6 +2,7 @@
 #
 # Makefile for the Linux TCP/IP (INET) layer.
 #
+UBSAN_WRAP_UNSIGNED := n
 
 obj-y     := route.o inetpeer.o protocol.o \
 	     ip_input.o ip_fragment.o ip_forward.o ip_options.o \
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240202101642.156588-6-keescook%40chromium.org.
