Return-Path: <kasan-dev+bncBD4NDKWHQYDRBK4ZT3CQMGQEMTWRZFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id B8F8BB30820
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 23:16:28 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-4b0faa8d615sf66429631cf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 14:16:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755810987; cv=pass;
        d=google.com; s=arc-20240605;
        b=Pi63P2kiEUkuc/FSkoIy6Jl+q4pa2lQggtSPh2Xh8xQIVHHCB50amlW/hmjaNv0l/x
         Oo7RFRhypU4iDrVfoTpH7HJ/xMzIBfQtXhyu+6AXIpQKDlXasIqqUVh2jGZbiR0z8bml
         KZRwaNSsXRddCMttP4lfPPh0iPkxZGAV9seTvyr0JMMHCcaExCWL5OhhuTnsQjZ5qMpr
         vKxIt34xfF+DFwd8hI5J9yEmPMe8yjnV66rBSqfiJnJ/4k8ztgu8Vu0MtY3FbhNtgpaX
         lafEAjHK30E5POu99WohOUcy2rhdlw+5zdetD8DQFpiUHywMy0U/W/FA/7c0DxYqdYzA
         b97A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:in-reply-to
         :references:message-id:mime-version:subject:date:from:dkim-signature;
        bh=ehAwMnzuiCVWyfZpV1Ckq7SGzkMYHWN06wFSKLdWTZk=;
        fh=lPmq3405ZQK1PwQqfKV8XZXcxU23MhjQf111dyvXDoo=;
        b=Wb7qgGivCXxZUHqHt5QeynOe4yBWjEWKR9IKctbiTGWG/uUDhZa9geR4EDcUE6pqZK
         R1+EfZroOXabbOHVnpo+DZcZ1fuB8Wd/DWvXH4H0wfDIX0bAOhzysRITF0RBZcJmfdz/
         a6mvTi6cus06nvqu4Tmhd+DtYmdpgBCxJ4uEADKAGNpRql7dMLiL/C4bJ5p+pnTnGuiE
         31d4QK+hxhSSdB7MqvooI6rLzx3Kq1eoXQx+9oGQfGqSVdd/Hi4c+YOFYefcy0tKFC0T
         0EEMeHug2dZMIm5siNpsuNP1jI9genlhRmSasuumfRg0SAgM+QwQg86TOC8vSfNMpz5v
         FoUA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PyZwQa5Q;
       spf=pass (google.com: domain of nathan@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755810987; x=1756415787; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ehAwMnzuiCVWyfZpV1Ckq7SGzkMYHWN06wFSKLdWTZk=;
        b=F3JhDMR2HGM3eU6P9YklzzCIkaT5+Gtf6vfHKsha/sRW7cngvR2eRDF5+uHUeU2gyr
         m2Bylx2jAgWwgykfIAPXVp8v9VkXFkle9Kzepq2Kzl7GkmCU5JFnpcxZeiD/9FkxUDOg
         bdSBZZp7PDG0Qa+Z4nZWyrS+PRKFn5Vj5GUIa5M3eeCLDwp9PmQ4HmKHstk1Be0rDbQ8
         dQ/+0LsiGUmSduBSf664XS5s40rxGdu54LDqVqgpX/MB7t3r6g/svgq/rQ+LWTbzZCDb
         c/vm4MnC2Eraq75xhwzztdngHO51ubEpTncv5KUdCkoejSKaSP4eMZR+vi8AohU1db+W
         Cdnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755810987; x=1756415787;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ehAwMnzuiCVWyfZpV1Ckq7SGzkMYHWN06wFSKLdWTZk=;
        b=ogLdOCxWM3zeDTqwH8bDSSXnnJzF62E3LHYl/f4FbXMJ/xurucQ1jMWVd8dyZLDCXb
         CS+kmkpy7RiwYvHHnszKi23D+oz+ICS0LQDMMBW2rx7Ic5i0pg5JlaoHzv6N1jo7W1kV
         ZEeRFIEEXC7wljkPoQ2TJKcjnizQUPiZrCSmvgkf8JRGXSDXz8LLTNnOlPCZ46EQ02vZ
         MG2r7cjq+C7//RBo5cMIYRsiMYHlny4srO93pyVNCXCv3o1xIeLDxhVogqFgejfi5MMb
         tW4yAnhp5CVsd6ZV7dZMCANepUtsZ3xRUpnZwc4/hmTvuqrQ/q4PmfOI4aAXpDQWbMzL
         1Pwg==
X-Forwarded-Encrypted: i=2; AJvYcCV6mtAnAID0L0M8W8tX4cxOGap+tjHZGHLTYTL6yRZhKsb3a6TrA4LILDnPzMGDbKTDcoDWVQ==@lfdr.de
X-Gm-Message-State: AOJu0YyGk/ykZ5CZC5++s0plQmlA0WIT9ntNW2hYgcbHlIFSDzgruWEd
	PLtyS5hPi3+smTcoxm4NO3O9q0Qu41BUy8rBm4CXOxWTSihmum+/FuPY
X-Google-Smtp-Source: AGHT+IHiN8oX9Wrb+zCR4c3A/8+da0F/33vnJBl+nvxKNucqBUdduy/aOUONAKuFVBGEoYtrEkpcHg==
X-Received: by 2002:ac8:5808:0:b0:4b1:180a:ad70 with SMTP id d75a77b69052e-4b2a00f8d2dmr46633561cf.28.1755810987535;
        Thu, 21 Aug 2025 14:16:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeaFX8oR43SDBdc9oPufvpGhmhnVME5U8kW2kbsUdOInQ==
Received: by 2002:a05:622a:1355:b0:4b0:63a8:673 with SMTP id
 d75a77b69052e-4b29d8df5d0ls13167751cf.1.-pod-prod-00-us; Thu, 21 Aug 2025
 14:16:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUEDdXoplaKDQKE4s3hg9UAxzcK9K/Af2smN8VTnr6GpPWURvluMwE+FAVb/Pz2zBBKWN3FepdIzyE=@googlegroups.com
X-Received: by 2002:a05:622a:549:b0:4af:21a0:c65b with SMTP id d75a77b69052e-4b29ff900a7mr46657601cf.13.1755810986686;
        Thu, 21 Aug 2025 14:16:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755810986; cv=none;
        d=google.com; s=arc-20240605;
        b=UYhQ4iyuegh2igYaW3Awtf1bu/7/6C8mtUMjLRWXUjjk6b1MinQRTo8aqQEuodLbQk
         n2RbHw3E6ted8hJcwmwajXK5KCU0U24z5qtAqTu58K8VGz45tHi7ySumau6o1AWczHgX
         CFDDgeL8ICGSes4x4K7graTdJzg6kIek6EXHsAkALJatNkASyClNFe2PdWKh7Ydcs2QQ
         86CULMEpi8au5yJtbLUQDSJdv1apd4FomMGwRO2ieakfmEo66NBhaZFMgRG/erkPMYWl
         taEjW2AAl65k9RCjfVzMyoOzPGKOMef4sxBsdgcbLbW86f5QxNz7QCltkuR/JM5QTn7c
         BIWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature;
        bh=1iaeznBulorE9674rjS24rLAxQgD4UFu13GxdL/1/Ho=;
        fh=CgqgBZO7WaR60VKWmcWrKc4ebOfwcMU5v9RxHvXtDQo=;
        b=RV4VdbLpnjGjsiviJMqX0R6RJxf/ugn/0HS8QPvZJv1VuXTILabk/gZUBPhW4K5zQs
         R5nas0pSW4/hiMgmm7byIn0dCx0dapwngaU3TkoNJ4OxXP1TR9k29y7LAZ5sQbrn3XB/
         +R+euIVIayAnIYUaS05qE/6iJchWL8MS4qjz0EoXWwBFeWh9YeAFBpjyW3dNRn/v4Qnr
         amPQNyzKjL8MJ8c/a0eHW+9h/dnKbSMNzCwCyK1eUE2Pj9+bGn4Gtf/VEJymi5CzHlqm
         tdBqedd6rjQn4ZTzQjBDuHqKgcnm0Nr5Qr7EnIM+RHvbkkVzO1h2rf+4JSCVYpe+G4x8
         xakg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PyZwQa5Q;
       spf=pass (google.com: domain of nathan@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b11dc17f65si6175611cf.1.2025.08.21.14.16.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 14:16:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id CA2C744523;
	Thu, 21 Aug 2025 21:16:25 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 38B8FC113D0;
	Thu, 21 Aug 2025 21:16:23 +0000 (UTC)
From: "'Nathan Chancellor' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 Aug 2025 14:15:48 -0700
Subject: [PATCH v2 11/12] objtool: Drop noinstr hack for KCSAN_WEAK_MEMORY
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20250821-bump-min-llvm-ver-15-v2-11-635f3294e5f0@kernel.org>
References: <20250821-bump-min-llvm-ver-15-v2-0-635f3294e5f0@kernel.org>
In-Reply-To: <20250821-bump-min-llvm-ver-15-v2-0-635f3294e5f0@kernel.org>
To: linux-kernel@vger.kernel.org
Cc: Arnd Bergmann <arnd@arndb.de>, Kees Cook <kees@kernel.org>, 
 Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, 
 Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, 
 llvm@lists.linux.dev, patches@lists.linux.dev, 
 Marco Elver <elver@google.com>, 
 "Peter Zijlstra (Intel)" <peterz@infraded.org>, 
 Nathan Chancellor <nathan@kernel.org>, kasan-dev@googlegroups.com
X-Mailer: b4 0.15-dev
X-Developer-Signature: v=1; a=openpgp-sha256; l=2230; i=nathan@kernel.org;
 h=from:subject:message-id; bh=edt5ONquqT6iefl+nGEw5FvaJQsAKIBbDF2dxmXAwzw=;
 b=owGbwMvMwCUmm602sfCA1DTG02pJDBnLe1pKmUXsD9i/+j9z9ePwx9LqPVJZDz8/s5gtycyY9
 sm6dpp/RykLgxgXg6yYIkv1Y9XjhoZzzjLeODUJZg4rE8gQBi5OAZiIkAUjw+U4rycb7d3Y15z+
 +b26TuOmiOx51kfLJoQZbY/yWKm2k5uR4a3eX4Hb6xrrQ3ZM/LHtqZeKibheU0i5ddmN/3mGz1U
 +cwMA
X-Developer-Key: i=nathan@kernel.org; a=openpgp;
 fpr=2437CB76E544CB6AB3D9DFD399739260CB6CB716
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=PyZwQa5Q;       spf=pass
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

Acked-by: Marco Elver <elver@google.com>
Acked-by: Peter Zijlstra (Intel) <peterz@infraded.org>
Reviewed-by: Kees Cook <kees@kernel.org>
Signed-off-by: Nathan Chancellor <nathan@kernel.org>
---
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250821-bump-min-llvm-ver-15-v2-11-635f3294e5f0%40kernel.org.
