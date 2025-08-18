Return-Path: <kasan-dev+bncBD4NDKWHQYDRBR7PRXCQMGQEQIYSWYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 27844B2B0F6
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 20:58:17 +0200 (CEST)
Received: by mail-yb1-xb3d.google.com with SMTP id 3f1490d57ef6-e933de385cbsf3270208276.2
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 11:58:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755543496; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZKJDL9lvC56OOtSMO8nk+LjdGZQf9xxRWPHsDJlKvgBDqtz9NCo8nTm09rpMELrCCe
         fY1Zrk/37ijd2xIP5SPR2iPygio2pWgMpZCt5evreeYBDmaS+yjoxPCVaCN/kGYP05oX
         jbpRQ7UkAcvdeSONcrj+Oll6FF0apyJAhwF7Y9nlwKmvtGkky7IBXn2KSqxiHgV+M40O
         0z0bbZ9rU5Hz2+f4fYb1MwNKdWuT8JNoGWkX9Jljk1+zK6U9dOb+KRUayyDVMtRFDgqb
         UhkL346c3DhTjCTKs24HH/fefty8B+fZDbry3138OsWMueIBO0p7fJfNgy8iQ4+Mi2zs
         B0Qg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:in-reply-to
         :references:message-id:mime-version:subject:date:from:dkim-signature;
        bh=kY+vrczgBhYJSDdszm1zFBmqALeLvQYCBMNyG9EPsUE=;
        fh=f8q00v2L/ZWPYLz1zOpp5qtkKOGsP01wPch88DuF8NU=;
        b=PeN8aoaER3I3fdsLs7byu4OpP6E6DtlpwCT3qaY89ccAUG2PnThjDbX8Rw0wGSejLL
         JIcq0z0ZsslM3vRP0JbYW6x/znnULSKZCb0+zoaOFR/GYFbJtbb3IiIjeksMQSOX5D0+
         q1KQXfG4juXWxXSOqH/luVYbMhoxbiWywES7cZ2oR4GgLtiPE8VX/0+qdoTqHPD55TZX
         +FRd/75ODlE4pP4HKQxiAPoPBq/DfnL6vZ/DSiIzesMOdg6ui8eixpopwoFsea8wx3Ry
         FucpoOtDGk7Hfw7vIKV1YnpQnLWTddYHs77E4TXuTgYbYKDqpFPBP6NBLxgCR0u4AIXu
         XY7w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=MB3X2jal;
       spf=pass (google.com: domain of nathan@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755543496; x=1756148296; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=kY+vrczgBhYJSDdszm1zFBmqALeLvQYCBMNyG9EPsUE=;
        b=ArhYPpf0H8xMW7D7w9n7XnL6Wq50tpzrUqRhxVqNI0ARGAcaydVy5hapnvYVi+pvVj
         wPF/F4003HQrRqSd4m4erjfd+RjoTjFm1HEiaKYo6lvUsj7fIQuNw4+r6j2KZNcqa8D7
         g0IFgvN/aiBW7+J664lwaJpNTCbwU16a1m1F1Kdpt59cupElprm+ljpKT5FLEQankQYA
         cMttx9hJ9s+vaeClVh/9Q0yb09Sui3HGaHJPt7oSAlUyYifltTzFcqPYnEPEOZ5XMOKX
         PdPuv7+e5CEyC3jlAtOGwzYceC6EgRe8+RmwSNs4izs/QiR5iLZPxza9GkAqZxzwEPws
         5S3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755543496; x=1756148296;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kY+vrczgBhYJSDdszm1zFBmqALeLvQYCBMNyG9EPsUE=;
        b=rwsptD/KQg1pZLqXyAVOM+YKB6mI2mWhb/puUWMoLklNSAEsJK47BUZAOxEsA23AkZ
         Bz5hxMGKYBhJFJi5bsw/8hV08ezLoIiQNEK4+BYpDgZw7M1DdeA8LmKdm/4AAreJKzU+
         S55Dlc94nsmfsmcRv4188C6q+qPL3IGPIfO/m1lwSyan+2qo0T45mIemi4zl6NUObj25
         9dGvyfXmYHF+ZdnMc2Ed1vXijtsF5E6LNKxnEL2SAsLfKv0y6X6BzwwF5WcsoqDAWZ8Q
         mBzLq8J0ElwmQGSxo2rPX9msVL/w1AGnZkj9dcF16cPXPdvsW8N9EsWZeHGUpAYNsjep
         MA7Q==
X-Forwarded-Encrypted: i=2; AJvYcCW5xB59H8NBIz7XT3Ui5vQ+wAQJHlziFLcvPOgk1TIRZvW+45Yta01dzZfAsAJzO3TwV/h64w==@lfdr.de
X-Gm-Message-State: AOJu0Yx+GydCpG+OKMNBzLdPmFIEpCyAwlT4vwarjeGan6tinHoapgz8
	IFAT4OscfSnq9rZ1r7uXjho6kOpEWU1Qvlq65Mbchg45DiXCp6+ptxMh
X-Google-Smtp-Source: AGHT+IEGxuN10YmgmR+KcxBFsrynz+YmuOXscrgFqnx8hQ62BZ3owcTbKYVvHqUDvAREs0fSC/uEYQ==
X-Received: by 2002:a05:6902:6b07:b0:e94:dac7:25a1 with SMTP id 3f1490d57ef6-e94e41db7c8mr629322276.37.1755543495646;
        Mon, 18 Aug 2025 11:58:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe2pIkElC9kuplsvDm5jENA4lJmxQHzUnOx2zS3CzFvYw==
Received: by 2002:a05:6902:6c05:b0:e93:3de3:82c9 with SMTP id
 3f1490d57ef6-e933de38778ls2210654276.0.-pod-prod-08-us; Mon, 18 Aug 2025
 11:58:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV4aqggW/5bRpVo/IP+K0YMK6K9HKDX3FiWJJZiPoB4vMSNNOxhGBhVOZueSVgjgOW78eZ5UOVPRnU=@googlegroups.com
X-Received: by 2002:a05:690c:6ac5:b0:70d:f3f9:1898 with SMTP id 00721157ae682-71f99793eafmr7492747b3.35.1755543494803;
        Mon, 18 Aug 2025 11:58:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755543494; cv=none;
        d=google.com; s=arc-20240605;
        b=NIilQqtkaXfczKFOfwXw2z7BGMVTTvbtbHnPVlqi0MDagkPRG61kxBCZiX7azegtCP
         DQLsvqC9jeTNZsMJZjxpX+UkMgj6tIaskmE15Bu90KD/m3tW/L6/CZ05Sy7YxopMpb2S
         /BlHpMLLO7co0Xh05ivbMO5Hm97y2yunZE2fK31sUFqqMtDpGddXZoIVSThLLJQqic0Z
         ZtNKsWtXrMwHFhmpZB0HAk3kLIOgYox+wzhc1yGtNvxW1UUu+ErSR72W9KFZkCumvuIm
         HAbRUfpg9t+ga3k9Od7RUDCShSHBQg1C2W73ZvfClR0sRU2ImqCIMsaL/EanRo+XxfTz
         i5JA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature;
        bh=DFJnM2Vj7wOHNkfEEUJdhYGcFU0AFWB7oploh4TTCHA=;
        fh=n8WFBAO/rQrk03iRMDGievYWTTcyvKeyafZODcrZJ/0=;
        b=PaJceUIVdz9yVyRQI8IAmPvozgZVSYuWq+qpNMiYxwXgWSCuHGiQCl5Pb462BFGFp3
         O9V3elhYgbA8uhV5aSb/NqqMZQtxWCQlh+ipiVrZS04YukZhL4gE3gKxPRqvOD5tL5s9
         KLaFDflwSLNvjL6rxZBhqoTCAR1LYaY8gAIgS2MvyZp+xxtA6SITzOA60I+JN7pv7c+H
         d0042IlX1IJ0qyRt0LrulG3LCeeO67eRA3F4pGxwxc6DgzQnW/G0qeAICdLhGebAPOwj
         jhW9AfLofKufrBW89DkHTo2wdlK2w+aoYIvxjIu7gztcwCkD92WSfkckRyDPBA9H+fOR
         qg0g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=MB3X2jal;
       spf=pass (google.com: domain of nathan@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-71f98a4cdcdsi196297b3.4.2025.08.18.11.58.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 18 Aug 2025 11:58:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id BA85E45FCB;
	Mon, 18 Aug 2025 18:58:13 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8B86DC116D0;
	Mon, 18 Aug 2025 18:58:10 +0000 (UTC)
From: "'Nathan Chancellor' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 18 Aug 2025 11:57:25 -0700
Subject: [PATCH 09/10] objtool: Drop noinstr hack for KCSAN_WEAK_MEMORY
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20250818-bump-min-llvm-ver-15-v1-9-c8b1d0f955e0@kernel.org>
References: <20250818-bump-min-llvm-ver-15-v1-0-c8b1d0f955e0@kernel.org>
In-Reply-To: <20250818-bump-min-llvm-ver-15-v1-0-c8b1d0f955e0@kernel.org>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Arnd Bergmann <arnd@arndb.de>, Kees Cook <kees@kernel.org>, 
 Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, 
 Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, 
 linux-kernel@vger.kernel.org, llvm@lists.linux.dev, patches@lists.linux.dev, 
 Nathan Chancellor <nathan@kernel.org>, Josh Poimboeuf <jpoimboe@kernel.org>, 
 Peter Zijlstra <peterz@infradead.org>, Marco Elver <elver@google.com>, 
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
X-Mailer: b4 0.15-dev
X-Developer-Signature: v=1; a=openpgp-sha256; l=2251; i=nathan@kernel.org;
 h=from:subject:message-id; bh=8nczhCzHMt2OUqv/92g+T6OrJZMdvXVJMDe6DkMp4ks=;
 b=owGbwMvMwCUmm602sfCA1DTG02pJDBmLyxfNWfcv4eSzLJNN6zb8P3FyStn3GKupuWIHXhX0r
 lpQu329Y0cpC4MYF4OsmCJL9WPV44aGc84y3jg1CWYOKxPIEAYuTgGYyCMjRobrHL5WchtvPMtY
 xt5atvnlGcO06P6WmS8rnBWvX9ujsu4ZI8P63o3WT3WW27Z4GdxwYc3+deMsV1nBsu1+3HuLS6N
 dZrMDAA==
X-Developer-Key: i=nathan@kernel.org; a=openpgp;
 fpr=2437CB76E544CB6AB3D9DFD399739260CB6CB716
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=MB3X2jal;       spf=pass
 (google.com: domain of nathan@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Nathan Chancellor <nathan@kernel.org>
Reply-To: Nathan Chancellor <nathan@kernel.org>
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

Now that the minimum supported version of LLVM for building the kernel
has been bumped to 15.0.0, __no_kcsan will always ensure that the thread
sanitizer functions are not generated, so remove the check for tsan
functions in is_profiling_func() and the always true depends and
unnecessary select lines in KCSAN_WEAK_MEMORY.

Signed-off-by: Nathan Chancellor <nathan@kernel.org>
---
Cc: Josh Poimboeuf <jpoimboe@kernel.org>
Cc: Peter Zijlstra <peterz@infradead.org>
Cc: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev@googlegroups.com
---
 lib/Kconfig.kcsan     |  6 ------
 tools/objtool/check.c | 10 ----------
 2 files changed, 16 deletions(-)

diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index 609ddfc73de5..4ce4b0c0109c 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -185,12 +185,6 @@ config KCSAN_WEAK_MEMORY
 	bool "Enable weak memory modeling to detect missing memory barriers"
 	default y
 	depends on KCSAN_STRICT
-	# We can either let objtool nop __tsan_func_{entry,exit}() and builtin
-	# atomics instrumentation in .noinstr.text, or use a compiler that can
-	# implement __no_kcsan to really remove all instrumentation.
-	depends on !ARCH_WANTS_NO_INSTR || HAVE_NOINSTR_HACK || \
-		   CC_IS_GCC || CLANG_VERSION >= 140000
-	select OBJTOOL if HAVE_NOINSTR_HACK
 	help
 	  Enable support for modeling a subset of weak memory, which allows
 	  detecting a subset of data races due to missing memory barriers.
diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index d14f20ef1db1..efa4c060ff4e 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -2453,16 +2453,6 @@ static bool is_profiling_func(const char *name)
 	if (!strncmp(name, "__sanitizer_cov_", 16))
 		return true;
 
-	/*
-	 * Some compilers currently do not remove __tsan_func_entry/exit nor
-	 * __tsan_atomic_signal_fence (used for barrier instrumentation) with
-	 * the __no_sanitize_thread attribute, remove them. Once the kernel's
-	 * minimum Clang version is 14.0, this can be removed.
-	 */
-	if (!strncmp(name, "__tsan_func_", 12) ||
-	    !strcmp(name, "__tsan_atomic_signal_fence"))
-		return true;
-
 	return false;
 }
 

-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250818-bump-min-llvm-ver-15-v1-9-c8b1d0f955e0%40kernel.org.
