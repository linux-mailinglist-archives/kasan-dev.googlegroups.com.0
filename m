Return-Path: <kasan-dev+bncBCB33Y62S4NBBUUX57EQMGQEY3UD45A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 24E92CB831D
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Dec 2025 09:01:24 +0100 (CET)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-88041f9e686sf22558076d6.1
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Dec 2025 00:01:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765526483; cv=pass;
        d=google.com; s=arc-20240605;
        b=DVs+wrcHSlAAQ1RhzWarOJrySEJ8tOvEnZglDnWGkx/xJHg5+DwRm7nFFzHF9KOs9n
         J9RReaGI1bU3WjtFAASMAKdfDoRnmStIQDvwC+hQvW8dLP7RHbgj5H+jOsWACZ9c0sAN
         rT6SFpE4EmteEyfnabRAXn8saE08f02BpWtfMQ/md39PhSoKFnwji09+8ig4ZI/Z6c3V
         gEnT3+gK3zR7zTTES+/6e5TvzFnxiFdHv2Y5m/pCqFFTd2FHMkpnLglHTQpLqnMnUBQm
         V3kzskM2zE2tyuut8QmcvleTo773M0WScWxW6QcqHm9CIZJJXiLDjVaa0dp51U6772Jl
         W0Zg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=RuQ+z27/BH6W6qSSzVP+GIRYXMsg85c4nTBmgbg6GCw=;
        fh=0LLvhklUSL0ZNQhAvkmXUqEH3+GdrA70LCo+/vbQ0Us=;
        b=SdUW35U0nqWSs9GThM9tloHuiJQ89waeK/6s1hBgH8VK3WPI/e15fUJOnlqKqlZEZ/
         +1Y4sLF1d9zjBa7WSgjbzuM1bcPgMi0+hDtUcJrSAlk6QlDZ+8i76W9b6BcV6JTIQkOE
         UOT5EgXSw5ewMpgOwPC2p8+w/g9awASiPdjqlkuEW+AcYpMFGT8ek7e6PckyIgIcZihe
         EchyAn/y1AMSPrWAisacBRlb200qMTDtAFkNuclptnvpXkOdfof5LXG21CEe+4c8Dpto
         4BRyPcRfQtuL/JGi/DobnTscXfvflE7TczksOoQTFWTbisS4wED8Ju5sQIN2qq//DMJX
         vX0Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Wd2uhZGO;
       spf=pass (google.com: domain of mcgrof@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=mcgrof@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765526483; x=1766131283; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=RuQ+z27/BH6W6qSSzVP+GIRYXMsg85c4nTBmgbg6GCw=;
        b=TFplzgUtZGB7JaHJAW9nPdVdq+OjJ1v0K5GY96p6e8pfHYDcgfyQvNJPP9lMAdLMV6
         6Ef+mkMKvPXZXJCpLzTaQv7tODx380mk+Z1dy19D56Ii0rLSN+ikytBSkOe0qBvBC1Z/
         3POKP1imC4D0/FcyOBe/BZ+Y9uIoojijO9MtPGeSq32OnGHo/Fnm67BDtCUZnDwnOBBV
         ECsxLPpmmPf/DxIZbhU9DmjpoSrTx+F4PTuDEsu8KkfirosyfGL2/O2QxDiGoe7xE9kz
         uVv2wMx16RLCdU95hIFEl5R2Gd8hwaMdxwMAFwY7DNbqufSNSixlNU11WA3gxT1SQw4t
         nO2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765526483; x=1766131283;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=RuQ+z27/BH6W6qSSzVP+GIRYXMsg85c4nTBmgbg6GCw=;
        b=W9zlaXMZXwaLos5z8FHb0gC1h+92VEwEKeRfigeKVGjRKpfWKNO+gGoH6bVNifE9N2
         ZaMTBY+2tZf2jA/zWJ+YSY1kE6Vlu8iy8udfkU/cRHXj+1FtbOwY9i+/IbQX6aroIzMx
         ePK4KhyLKhaqWaqiOfiajuWyrB4Mr+Zu++tQ80Xqdy0b3/Wo8HxUh9HClayfgMM9W3Kv
         UHFtXf9UQiLtvno9GXHyENNt5iuTXH0VRAoO3DRXSug2x6Ruh2RbIadeYbCK5nG91g03
         8dXsjjG4XseOL2x9+0tEgY3K/Nd8Yi2djITj+NcLiPxv/x9fuDFFHGZ1a5pEl2sqRgtk
         UE7Q==
X-Forwarded-Encrypted: i=2; AJvYcCX9BP9Xk/4lMex8JMBxD1wDSsSwW9p704DEihMUUKGJ141sXAteuZ+jIvZ5FOH7nHS9Ay0SfA==@lfdr.de
X-Gm-Message-State: AOJu0YzHX16lRM+I5+k+5ejgjZHGytCjB6fcXhqDjT/TiCwofk6FMzPH
	uEfbqpqrxtJ9JWSyjdRtqYWCxW7G5c5oHOXAFc9BXHIy/nEf9QUt0V13
X-Google-Smtp-Source: AGHT+IHEzu8dqARKjhnqlfGg9hjfqTYhagUezVE+sPv+i0EY/5EKvmYJlH89Zfm7NYDXjjFM28VXFA==
X-Received: by 2002:a05:6214:14ae:b0:888:7c7e:fce1 with SMTP id 6a1803df08f44-8887e1e9bd8mr14756036d6.4.1765526482450;
        Fri, 12 Dec 2025 00:01:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYFGRmdDE/d888hqUVJw67vkzZ+U+PAh8+wdWGFhWy9RQ=="
Received: by 2002:ad4:5d6e:0:b0:880:59ee:bbc with SMTP id 6a1803df08f44-8887cd340acls9902976d6.1.-pod-prod-09-us;
 Fri, 12 Dec 2025 00:01:21 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUSi3tKeWGDjSAlno62Nu1Dv5yYsAG7/+exsr0kMzfaFYwbxf7GKgxqY4bjnBhZ/qcsHgYmY7Y7FQ0=@googlegroups.com
X-Received: by 2002:a05:6214:3008:b0:880:5d59:fddf with SMTP id 6a1803df08f44-8887e41be1bmr19942966d6.28.1765526481647;
        Fri, 12 Dec 2025 00:01:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765526481; cv=none;
        d=google.com; s=arc-20240605;
        b=Giywxpu8ka95s1SUaDEPpUNutMkfx4DGF/qPgxV22Y9p9P8E64lcuDKVUF8yii24tG
         X7vHKoFVsmV9PvEoLnBQwi8+5j9vIZtvRzyTHYwuZ7X2TpCJc5c8Iaooz4TKbkerEF2V
         1lkVy0mxTSI1k6Wg0d0EQzBZZ6rgUMR0rALx87R7jJbfXp0tIG9korSxGJNWJ0dFS21q
         Y86/fNlbD/6UkL8zVgtichWhNcJxjwU3d3kdk5w51Y+vbU54r2jeFv4WS4ejkxa8SIoj
         EMcxFIMzet/Mf+8mP6J9ogm2FHGXTl93Nh3PXslQ7bR319xs6zVdZ44MSy8XYSq3pYe9
         TJ3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Yww2ABWv2Cb1FVgDg5tCePOFsmbuV/zyC+NHtFJtQK8=;
        fh=JAFiA+8PCx/7y8dSEclZC2Ftx755pUweYGYP91aX0Ug=;
        b=LckIsvfjJiUWlXKydOBP4XUiXQD+CZMj7W+JZm0L8XQhkc2wObnThz3KmYgcXYlwq3
         Y6P2HTZRGsklLtT4+n/Y7+roSfjKKsKhAaBV/LqxNmlwCqJUBdC1KN29FQidMAz3IvoG
         Nxn8xXdPeym5Ia1hq+OVfzUxhOdN2w0FqlDqtr0ykp86Rz+Noxr1JSIkPqTtEraIZfUu
         AJ25H2MJwm85VjZYpAj/QTMMYkEsKQNJmnNTRz8gGWQWvlH7HpdVHD7Mkq/a0N0It5n4
         0QsPMNUja9vQYDJxK7ph3V41QL0p98Pn7F59+HRaV5yqQ5Tap5iqBL4LbWedJNuq0pvQ
         QQew==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Wd2uhZGO;
       spf=pass (google.com: domain of mcgrof@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=mcgrof@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-888819f5c56si186686d6.5.2025.12.12.00.01.21
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Dec 2025 00:01:21 -0800 (PST)
Received-SPF: pass (google.com: domain of mcgrof@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id DF24F60123;
	Fri, 12 Dec 2025 08:01:20 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C0E70C4CEF1;
	Fri, 12 Dec 2025 08:01:19 +0000 (UTC)
Date: Fri, 12 Dec 2025 00:01:12 -0800
From: "'Luis Chamberlain' via kasan-dev" <kasan-dev@googlegroups.com>
To: Ethan Graham <ethan.w.s.graham@gmail.com>
Cc: glider@google.com, andreyknvl@gmail.com, andy@kernel.org,
	andy.shevchenko@gmail.com, brauner@kernel.org,
	brendan.higgins@linux.dev, davem@davemloft.net, davidgow@google.com,
	dhowells@redhat.com, dvyukov@google.com, elver@google.com,
	herbert@gondor.apana.org.au, ignat@cloudflare.com, jack@suse.cz,
	jannh@google.com, johannes@sipsolutions.net,
	kasan-dev@googlegroups.com, kees@kernel.org,
	kunit-dev@googlegroups.com, linux-crypto@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, lukas@wunner.de,
	rmoar@google.com, shuah@kernel.org, sj@kernel.org,
	tarasmadan@google.com, da.gomez@kernel.org, julia.lawall@inria.fr,
	mcgrof@kernel.org
Subject: Re: [PATCH v3 00/10] KFuzzTest: a new kernel fuzzing framework
Message-ID: <aTvLyFsE55MR0kHo@bombadil.infradead.org>
References: <20251204141250.21114-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251204141250.21114-1-ethan.w.s.graham@gmail.com>
X-Original-Sender: mcgrof@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Wd2uhZGO;       spf=pass
 (google.com: domain of mcgrof@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=mcgrof@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Luis Chamberlain <mcgrof@kernel.org>
Reply-To: Luis Chamberlain <mcgrof@kernel.org>
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

On Thu, Dec 04, 2025 at 03:12:39PM +0100, Ethan Graham wrote:
> This patch series introduces KFuzzTest, a lightweight framework for
> creating in-kernel fuzz targets for internal kernel functions.

As discussed just now at LPC, I suspected we could simplify this with
Cocccinelle. The below patch applies on top of this series to prove
that and lets us scale out fuzzing targets with Coccinelle.

From 193f8364d352903f200af33131a6782be73b44c6 Mon Sep 17 00:00:00 2001
From: Luis Chamberlain <mcgrof@kernel.org>
Date: Thu, 11 Dec 2025 23:45:58 -0800
Subject: [PATCH] kfuzztest: replace manual kfuzz files with coccinelle
 generation

Replace the manually-written KFuzzTest target files with Coccinelle
semantic patches that can generate them automatically. This approach
has several advantages:

1. Reduces code duplication and boilerplate
2. Makes it easy to add new fuzz targets by just adding config entries
3. Ensures consistent code generation patterns
4. Allows regeneration when function signatures change

The Coccinelle scripts recognize common patterns:
- FUZZ_TEST_SIMPLE: For functions with (data, len) signatures
- FUZZ_TEST: For functions with string/struct inputs

Usage:
  make kfuzztest-gen  # Generate all configured targets

To add a new target, add an entry to kfuzz_targets.conf:
  FUNC:SOURCE:OUTPUT[:HEADER]

The generated files are functionally equivalent to the original
manually-written versions.

Generated-by: Claude AI
Signed-off-by: Luis Chamberlain <mcgrof@kernel.org>
---
 Makefile                                      |   6 +-
 crypto/asymmetric_keys/tests/pkcs7_kfuzz.c    |  17 -
 .../asymmetric_keys/tests/rsa_helper_kfuzz.c  |  20 -
 drivers/auxdisplay/tests/charlcd_kfuzz.c      |  22 -
 scripts/coccinelle/kfuzztest/README.rst       | 257 +++++++++++
 scripts/coccinelle/kfuzztest/gen-kfuzztest.sh | 214 +++++++++
 scripts/coccinelle/kfuzztest/kfuzz_gen.cocci  | 413 ++++++++++++++++++
 .../kfuzztest/kfuzz_simple_finder.cocci       |  96 ++++
 .../kfuzztest/kfuzz_struct_finder.cocci       |  91 ++++
 .../coccinelle/kfuzztest/kfuzz_targets.conf   |  21 +
 10 files changed, 1097 insertions(+), 60 deletions(-)
 delete mode 100644 crypto/asymmetric_keys/tests/pkcs7_kfuzz.c
 delete mode 100644 crypto/asymmetric_keys/tests/rsa_helper_kfuzz.c
 delete mode 100644 drivers/auxdisplay/tests/charlcd_kfuzz.c
 create mode 100644 scripts/coccinelle/kfuzztest/README.rst
 create mode 100755 scripts/coccinelle/kfuzztest/gen-kfuzztest.sh
 create mode 100644 scripts/coccinelle/kfuzztest/kfuzz_gen.cocci
 create mode 100644 scripts/coccinelle/kfuzztest/kfuzz_simple_finder.cocci
 create mode 100644 scripts/coccinelle/kfuzztest/kfuzz_struct_finder.cocci
 create mode 100644 scripts/coccinelle/kfuzztest/kfuzz_targets.conf

diff --git a/Makefile b/Makefile
index 2f545ec1690f..758098fb1c32 100644
--- a/Makefile
+++ b/Makefile
@@ -1723,6 +1723,7 @@ help:
 	@echo  '  includecheck    - Check for duplicate included header files'
 	@echo  '  headerdep       - Detect inclusion cycles in headers'
 	@echo  '  coccicheck      - Check with Coccinelle'
+	@echo  '  kfuzztest-gen   - Generate KFuzzTest target files using Coccinelle'
 	@echo  '  clang-analyzer  - Check with clang static analyzer'
 	@echo  '  clang-tidy      - Check with clang-tidy'
 	@echo  ''
@@ -2153,7 +2154,10 @@ versioncheck:
 coccicheck:
 	$(Q)$(BASH) $(srctree)/scripts/$@
 
-PHONY += checkstack kernelrelease kernelversion image_name
+kfuzztest-gen:
+	$(Q)$(BASH) $(srctree)/scripts/coccinelle/kfuzztest/gen-kfuzztest.sh --generate-all
+
+PHONY += checkstack kernelrelease kernelversion image_name kfuzztest-gen
 
 # UML needs a little special treatment here.  It wants to use the host
 # toolchain, so needs $(SUBARCH) passed to checkstack.pl.  Everyone
diff --git a/crypto/asymmetric_keys/tests/pkcs7_kfuzz.c b/crypto/asymmetric_keys/tests/pkcs7_kfuzz.c
deleted file mode 100644
index 345f99990653..000000000000
--- a/crypto/asymmetric_keys/tests/pkcs7_kfuzz.c
+++ /dev/null
@@ -1,17 +0,0 @@
-// SPDX-License-Identifier: GPL-2.0-or-later
-/*
- * PKCS#7 parser KFuzzTest target
- *
- * Copyright 2025 Google LLC
- */
-#include <crypto/pkcs7.h>
-#include <linux/kfuzztest.h>
-
-FUZZ_TEST_SIMPLE(test_pkcs7_parse_message)
-{
-	struct pkcs7_message *msg;
-
-	msg = pkcs7_parse_message(data, datalen);
-	if (msg && !IS_ERR(msg))
-		kfree(msg);
-}
diff --git a/crypto/asymmetric_keys/tests/rsa_helper_kfuzz.c b/crypto/asymmetric_keys/tests/rsa_helper_kfuzz.c
deleted file mode 100644
index dd434f1a21ed..000000000000
--- a/crypto/asymmetric_keys/tests/rsa_helper_kfuzz.c
+++ /dev/null
@@ -1,20 +0,0 @@
-// SPDX-License-Identifier: GPL-2.0-or-later
-/*
- * RSA key extract helper KFuzzTest targets
- *
- * Copyright 2025 Google LLC
- */
-#include <linux/kfuzztest.h>
-#include <crypto/internal/rsa.h>
-
-FUZZ_TEST_SIMPLE(test_rsa_parse_pub_key)
-{
-	struct rsa_key out;
-	rsa_parse_pub_key(&out, data, datalen);
-}
-
-FUZZ_TEST_SIMPLE(test_rsa_parse_priv_key)
-{
-	struct rsa_key out;
-	rsa_parse_priv_key(&out, data, datalen);
-}
diff --git a/drivers/auxdisplay/tests/charlcd_kfuzz.c b/drivers/auxdisplay/tests/charlcd_kfuzz.c
deleted file mode 100644
index 3adf510f4356..000000000000
--- a/drivers/auxdisplay/tests/charlcd_kfuzz.c
+++ /dev/null
@@ -1,22 +0,0 @@
-// SPDX-License-Identifier: GPL-2.0-or-later
-/*
- * charlcd KFuzzTest target
- *
- * Copyright 2025 Google LLC
- */
-#include <linux/kfuzztest.h>
-
-struct parse_xy_arg {
-	const char *s;
-};
-
-static bool parse_xy(const char *s, unsigned long *x, unsigned long *y);
-
-FUZZ_TEST(test_parse_xy, struct parse_xy_arg)
-{
-	unsigned long x, y;
-
-	KFUZZTEST_EXPECT_NOT_NULL(parse_xy_arg, s);
-	KFUZZTEST_ANNOTATE_STRING(parse_xy_arg, s);
-	parse_xy(arg->s, &x, &y);
-}
diff --git a/scripts/coccinelle/kfuzztest/README.rst b/scripts/coccinelle/kfuzztest/README.rst
new file mode 100644
index 000000000000..10d6ef0db01e
--- /dev/null
+++ b/scripts/coccinelle/kfuzztest/README.rst
@@ -0,0 +1,257 @@
+.. SPDX-License-Identifier: GPL-2.0
+
+========================================
+KFuzzTest Coccinelle Scripts
+========================================
+
+This directory contains Coccinelle semantic patch scripts for automatically
+generating KFuzzTest boilerplate code. Instead of manually writing fuzz test
+wrappers, these scripts analyze function signatures and generate appropriate
+FUZZ_TEST or FUZZ_TEST_SIMPLE code.
+
+Quick Start
+===========
+
+Generate all KFuzzTest targets defined in kfuzz_targets.conf::
+
+    make kfuzztest-gen
+
+Or use the script directly to generate a specific test::
+
+    ./scripts/coccinelle/kfuzztest/gen-kfuzztest.sh \
+        drivers/auxdisplay/charlcd.c parse_xy
+
+With a header file::
+
+    ./scripts/coccinelle/kfuzztest/gen-kfuzztest.sh \
+        crypto/asymmetric_keys/pkcs7_parser.c pkcs7_parse_message \
+        --header crypto/pkcs7.h
+
+Find candidate functions in a subsystem::
+
+    ./scripts/coccinelle/kfuzztest/gen-kfuzztest.sh \
+        --find-candidates crypto/
+
+Scripts Overview
+================
+
+kfuzz_gen.cocci
+    Unified generator that auto-detects the appropriate pattern and generates
+    FUZZ_TEST or FUZZ_TEST_SIMPLE code based on function signature.
+
+kfuzz_simple_finder.cocci
+    Finds functions suitable for FUZZ_TEST_SIMPLE (data/len patterns).
+
+kfuzz_struct_finder.cocci
+    Finds functions suitable for FUZZ_TEST (string/struct inputs).
+
+gen-kfuzztest.sh
+    Helper shell script that wraps the Coccinelle scripts with a simple CLI.
+
+kfuzz_targets.conf
+    Configuration file listing all KFuzzTest targets to generate.
+    Format: ``FUNC:SOURCE:OUTPUT[:HEADER]``
+
+Adding New KFuzzTest Targets
+============================
+
+To add a new KFuzzTest target:
+
+1. Find candidate functions::
+
+    ./scripts/coccinelle/kfuzztest/gen-kfuzztest.sh \
+        --find-candidates path/to/subsystem/
+
+2. Add an entry to ``scripts/coccinelle/kfuzztest/kfuzz_targets.conf``::
+
+    # Format: FUNC:SOURCE:OUTPUT[:HEADER]
+    my_func:path/to/source.c:path/to/tests/source_kfuzz.c:optional/header.h
+
+3. Generate the files::
+
+    make kfuzztest-gen
+
+4. Update the subsystem Makefile to build/include the generated file.
+
+Patterns Recognized
+===================
+
+FUZZ_TEST_SIMPLE Patterns
+-------------------------
+
+These patterns are recognized for simple data/length APIs:
+
+1. ``T *func(const void *data, size_t len)`` - Returns pointer (auto-freed)
+2. ``T func(T2 *out, const void *data, size_t len)`` - Output parameter
+3. ``T func(const char *data, size_t len)`` - String data
+4. ``T func(const unsigned char *data, size_t len)`` - Byte data
+
+Example input (pkcs7_parser.c)::
+
+    struct pkcs7_message *pkcs7_parse_message(const void *data, size_t datalen)
+    {
+        ...
+    }
+
+Generated code::
+
+    FUZZ_TEST_SIMPLE(test_pkcs7_parse_message)
+    {
+        struct pkcs7_message *ret;
+
+        ret = pkcs7_parse_message(data, datalen);
+        if (ret && !IS_ERR(ret))
+            kfree(ret);
+    }
+
+FUZZ_TEST Patterns
+------------------
+
+These patterns are recognized for structured input:
+
+1. ``static T func(const char *s, T2 *out1, T3 *out2)`` - String parser
+2. ``T func(const char *s, T2 *out)`` - String with output
+3. ``T func(const char *s)`` - Simple string input
+
+Example input (charlcd.c)::
+
+    static bool parse_xy(const char *s, unsigned long *x, unsigned long *y)
+    {
+        ...
+    }
+
+Generated code::
+
+    struct parse_xy_arg {
+        const char *s;
+    };
+
+    static bool parse_xy(const char *s, unsigned long *x, unsigned long *y);
+
+    FUZZ_TEST(test_parse_xy, struct parse_xy_arg)
+    {
+        unsigned long x;
+        unsigned long y;
+
+        KFUZZTEST_EXPECT_NOT_NULL(parse_xy_arg, s);
+        KFUZZTEST_ANNOTATE_STRING(parse_xy_arg, s);
+        parse_xy(arg->s, &x, &y);
+    }
+
+Direct Coccinelle Usage
+=======================
+
+You can also use the Coccinelle scripts directly with environment variables::
+
+    # Generate code for parse_xy
+    KFUZZ_FUNC=parse_xy spatch --sp-file \
+        scripts/coccinelle/kfuzztest/kfuzz_gen.cocci \
+        drivers/auxdisplay/charlcd.c
+
+    # With a header file
+    KFUZZ_FUNC=pkcs7_parse_message KFUZZ_HEADER=crypto/pkcs7.h spatch --sp-file \
+        scripts/coccinelle/kfuzztest/kfuzz_gen.cocci \
+        crypto/asymmetric_keys/pkcs7_parser.c
+
+    # Find FUZZ_TEST_SIMPLE candidates
+    spatch --sp-file scripts/coccinelle/kfuzztest/kfuzz_simple_finder.cocci \
+        --dir crypto/ -D report
+
+    # Find FUZZ_TEST candidates
+    spatch --sp-file scripts/coccinelle/kfuzztest/kfuzz_struct_finder.cocci \
+        --dir drivers/auxdisplay/ -D report
+
+Environment variables:
+
+- ``KFUZZ_FUNC`` - Required: Function name to generate test for
+- ``KFUZZ_HEADER`` - Optional: Header file to include in generated code
+
+Makefile Integration
+====================
+
+After generating a _kfuzz.c file, add it to the subsystem Makefile.
+
+Method 1: Include via CFLAGS (for static functions)
+---------------------------------------------------
+
+This method is used when the function being fuzzed is static::
+
+    ifeq ($(CONFIG_KFUZZTEST),y)
+    CFLAGS_charlcd.o += -include $(src)/tests/charlcd_kfuzz.c
+    endif
+
+Method 2: Separate object file
+------------------------------
+
+For exported/non-static functions::
+
+    obj-$(CONFIG_KFUZZTEST) += tests/pkcs7_kfuzz.o
+
+Method 3: Conditional compilation
+---------------------------------
+
+When dependencies on multiple Kconfig options are needed::
+
+    pkcs7-kfuzz-y := $(and $(CONFIG_KFUZZTEST),$(CONFIG_PKCS7_MESSAGE_PARSER))
+    obj-$(pkcs7-kfuzz-y) += tests/pkcs7_kfuzz.o
+
+Workflow Example
+================
+
+1. Find candidate functions::
+
+    ./scripts/coccinelle/kfuzztest/gen-kfuzztest.sh \
+        --find-candidates drivers/auxdisplay/
+
+   Output::
+
+    === Finding FUZZ_TEST_SIMPLE candidates ===
+    ...
+    === Finding FUZZ_TEST candidates ===
+    drivers/auxdisplay/charlcd.c:157: FUZZ_TEST candidate (string with 2 outputs): parse_xy
+    drivers/auxdisplay/charlcd.c:157: FUZZ_TEST candidate (static parser): parse_xy
+
+2. Generate fuzz test::
+
+    mkdir -p drivers/auxdisplay/tests
+    ./scripts/coccinelle/kfuzztest/gen-kfuzztest.sh \
+        drivers/auxdisplay/charlcd.c parse_xy \
+        --output drivers/auxdisplay/tests/charlcd_kfuzz.c
+
+3. Review and customize the generated code if needed.
+
+4. Update the Makefile::
+
+    ifeq ($(CONFIG_KFUZZTEST),y)
+    CFLAGS_charlcd.o += -include $(src)/tests/charlcd_kfuzz.c
+    endif
+
+5. Build and test::
+
+    make CONFIG_KFUZZTEST=y drivers/auxdisplay/
+
+Limitations
+===========
+
+- The scripts recognize common patterns but may not cover all cases
+- Complex functions with many parameters may need manual adjustment
+- Return value handling (kfree) may need customization
+- Additional annotations (KFUZZTEST_ANNOTATE_*) may need to be added manually
+  for complex relationships between fields
+
+Customization Tips
+==================
+
+The generated code is meant as a starting point. Common modifications:
+
+1. Add copyright notice and description
+2. Add additional KFUZZTEST_ANNOTATE_* macros for field relationships
+3. Customize return value handling
+4. Add error checking or logging
+
+See Also
+========
+
+- Documentation/dev-tools/kfuzztest.rst
+- include/linux/kfuzztest.h
+- samples/kfuzztest/
diff --git a/scripts/coccinelle/kfuzztest/gen-kfuzztest.sh b/scripts/coccinelle/kfuzztest/gen-kfuzztest.sh
new file mode 100755
index 000000000000..2a6ec692726c
--- /dev/null
+++ b/scripts/coccinelle/kfuzztest/gen-kfuzztest.sh
@@ -0,0 +1,214 @@
+#!/bin/bash
+# SPDX-License-Identifier: GPL-2.0
+#
+# Generate KFuzzTest boilerplate from existing kernel functions
+#
+# Usage:
+#   ./gen-kfuzztest.sh <source_file> <function_name> [options]
+#   ./gen-kfuzztest.sh --generate-all
+#
+# Examples:
+#   # Generate fuzz test for a single function
+#   ./gen-kfuzztest.sh drivers/auxdisplay/charlcd.c parse_xy
+#
+#   # Generate all configured kfuzz targets
+#   ./gen-kfuzztest.sh --generate-all
+#
+#   # Find candidate functions in a directory
+#   ./gen-kfuzztest.sh --find-candidates crypto/
+#
+
+set -e
+
+SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
+SPATCH="${SPATCH:-spatch}"
+CONFIG_FILE="${SCRIPT_DIR}/kfuzz_targets.conf"
+
+usage() {
+    cat <<EOF
+Usage: $0 <source_file> <function_name> [options]
+       $0 --generate-all
+       $0 --find-candidates <directory>
+
+Generate KFuzzTest boilerplate from existing kernel functions.
+
+Options:
+    --header <header>     Header file to include (e.g., crypto/pkcs7.h)
+    --output <file>       Output file (default: stdout)
+    --generate-all        Generate all targets from kfuzz_targets.conf
+    --find-candidates     Find candidate functions for fuzzing
+    -h, --help            Show this help
+
+Config file format (kfuzz_targets.conf):
+    FUNC:SOURCE:OUTPUT[:HEADER]
+
+Examples:
+    # Generate single fuzz test
+    $0 crypto/asymmetric_keys/pkcs7_parser.c pkcs7_parse_message \\
+        --header crypto/pkcs7.h
+
+    # Generate all configured targets
+    $0 --generate-all
+
+    # Find candidates in a subsystem
+    $0 --find-candidates crypto/
+EOF
+    exit "${1:-0}"
+}
+
+find_candidates() {
+    local dir="$1"
+    echo "=== Finding FUZZ_TEST_SIMPLE candidates ==="
+    $SPATCH --sp-file "$SCRIPT_DIR/kfuzz_simple_finder.cocci" \
+        --dir "$dir" -D report 2>/dev/null || true
+
+    echo ""
+    echo "=== Finding FUZZ_TEST candidates ==="
+    $SPATCH --sp-file "$SCRIPT_DIR/kfuzz_struct_finder.cocci" \
+        --dir "$dir" -D report 2>/dev/null || true
+}
+
+generate_single() {
+    local source="$1"
+    local func="$2"
+    local header="$3"
+    local output="$4"
+
+    export KFUZZ_FUNC="$func"
+    if [ -n "$header" ]; then
+        export KFUZZ_HEADER="$header"
+    else
+        unset KFUZZ_HEADER
+    fi
+
+    if [ -n "$output" ]; then
+        mkdir -p "$(dirname "$output")"
+        $SPATCH --sp-file "$SCRIPT_DIR/kfuzz_gen.cocci" "$source" 2>/dev/null > "$output"
+        echo "Generated: $output"
+    else
+        $SPATCH --sp-file "$SCRIPT_DIR/kfuzz_gen.cocci" "$source" 2>/dev/null
+    fi
+}
+
+# Generate only the function body (no header) for appending
+generate_body_only() {
+    local source="$1"
+    local func="$2"
+    local header="$3"
+
+    export KFUZZ_FUNC="$func"
+    [ -n "$header" ] && export KFUZZ_HEADER="$header" || unset KFUZZ_HEADER
+
+    # Generate full output and strip the header part
+    $SPATCH --sp-file "$SCRIPT_DIR/kfuzz_gen.cocci" "$source" 2>/dev/null | \
+        sed -n '/^FUZZ_TEST/,$ p'
+}
+
+generate_all() {
+    if [ ! -f "$CONFIG_FILE" ]; then
+        echo "Error: Config file not found: $CONFIG_FILE" >&2
+        exit 1
+    fi
+
+    # Track which output files we've seen to handle multiple functions per file
+    declare -A output_files
+    declare -A output_headers
+
+    while IFS=: read -r func source output header; do
+        # Skip comments and empty lines
+        [[ "$func" =~ ^#.*$ ]] && continue
+        [[ -z "$func" ]] && continue
+
+        # Trim whitespace
+        func="${func// /}"
+        source="${source// /}"
+        output="${output// /}"
+        header="${header// /}"
+
+        if [ -z "$func" ] || [ -z "$source" ] || [ -z "$output" ]; then
+            continue
+        fi
+
+        # Check if source exists
+        if [ ! -f "$source" ]; then
+            echo "Warning: Source file not found: $source" >&2
+            continue
+        fi
+
+        # If we've already started this output file, append just the function body
+        if [ -n "${output_files[$output]}" ]; then
+            echo "  Appending: $func -> $output"
+            echo "" >> "$output"
+            generate_body_only "$source" "$func" "$header" >> "$output"
+        else
+            echo "Generating: $func -> $output"
+            mkdir -p "$(dirname "$output")"
+            export KFUZZ_FUNC="$func"
+            [ -n "$header" ] && export KFUZZ_HEADER="$header" || unset KFUZZ_HEADER
+            $SPATCH --sp-file "$SCRIPT_DIR/kfuzz_gen.cocci" "$source" 2>/dev/null > "$output"
+            output_files[$output]=1
+            output_headers[$output]="$header"
+        fi
+    done < "$CONFIG_FILE"
+
+    echo ""
+    echo "All kfuzz targets generated successfully."
+}
+
+# Parse arguments
+SOURCE=""
+FUNC=""
+HEADER=""
+OUTPUT=""
+FIND_CANDIDATES=""
+GENERATE_ALL=""
+
+while [ $# -gt 0 ]; do
+    case "$1" in
+        --generate-all)
+            GENERATE_ALL=1
+            shift
+            ;;
+        --find-candidates)
+            FIND_CANDIDATES="$2"
+            shift 2
+            ;;
+        --header)
+            HEADER="$2"
+            shift 2
+            ;;
+        --output)
+            OUTPUT="$2"
+            shift 2
+            ;;
+        -h|--help)
+            usage 0
+            ;;
+        -*)
+            echo "Unknown option: $1" >&2
+            usage 1
+            ;;
+        *)
+            if [ -z "$SOURCE" ]; then
+                SOURCE="$1"
+            elif [ -z "$FUNC" ]; then
+                FUNC="$1"
+            else
+                echo "Too many arguments" >&2
+                usage 1
+            fi
+            shift
+            ;;
+    esac
+done
+
+# Execute
+if [ -n "$GENERATE_ALL" ]; then
+    generate_all
+elif [ -n "$FIND_CANDIDATES" ]; then
+    find_candidates "$FIND_CANDIDATES"
+elif [ -n "$SOURCE" ] && [ -n "$FUNC" ]; then
+    generate_single "$SOURCE" "$FUNC" "$HEADER" "$OUTPUT"
+else
+    usage 1
+fi
diff --git a/scripts/coccinelle/kfuzztest/kfuzz_gen.cocci b/scripts/coccinelle/kfuzztest/kfuzz_gen.cocci
new file mode 100644
index 000000000000..25de60d8ecdb
--- /dev/null
+++ b/scripts/coccinelle/kfuzztest/kfuzz_gen.cocci
@@ -0,0 +1,413 @@
+// SPDX-License-Identifier: GPL-2.0
+///
+/// Unified KFuzzTest generator
+///
+/// Auto-detects patterns and generates FUZZ_TEST or FUZZ_TEST_SIMPLE code.
+///
+/// Usage:
+///   KFUZZ_FUNC=parse_xy spatch --sp-file kfuzz_gen.cocci source.c
+///   KFUZZ_FUNC=parse_xy KFUZZ_HEADER=linux/foo.h spatch --sp-file kfuzz_gen.cocci source.c
+///
+/// Environment variables:
+///   KFUZZ_FUNC   - Required: The function name to generate fuzz test for
+///   KFUZZ_HEADER - Optional: Header file to include
+///
+// Confidence: High
+// Options: --no-includes
+
+virtual context
+
+// ============================================================================
+// FUZZ_TEST_SIMPLE patterns (data/len APIs)
+// ============================================================================
+
+// Pattern: T *func(const void *data, size_t len) - returns pointer (needs kfree)
+@simple_ptr_ret@
+identifier func;
+identifier data, len;
+type T;
+@@
+T *func(const void *data, size_t len)
+{ ... }
+
+// Pattern: T func(T2 *out, const void *data, size_t len) - output param
+@simple_with_out@
+identifier func;
+identifier out, data, len;
+type T1, T2;
+@@
+T1 func(T2 *out, const void *data, size_t len)
+{ ... }
+
+// Pattern: T func(T2 *out, const void *data, unsigned int len) - output param (uint variant)
+@simple_with_out_uint@
+identifier func;
+identifier out, data, len;
+type T1, T2;
+@@
+T1 func(T2 *out, const void *data, unsigned int len)
+{ ... }
+
+// Pattern: T func(const void *data, size_t len) - generic
+@simple_void_generic@
+identifier func;
+identifier data, len;
+type T;
+@@
+T func(const void *data, size_t len)
+{ ... }
+
+// Pattern: T func(const char *data, size_t len)
+@simple_char_generic@
+identifier func;
+identifier data, len;
+type T;
+@@
+T func(const char *data, size_t len)
+{ ... }
+
+// Pattern: T func(const unsigned char *data, size_t len)
+@simple_uchar_generic@
+identifier func;
+identifier data, len;
+type T;
+@@
+T func(const unsigned char *data, size_t len)
+{ ... }
+
+// ============================================================================
+// FUZZ_TEST patterns (string/struct inputs)
+// ============================================================================
+
+// Pattern: static T func(const char *s, T2 *out1, T3 *out2) - like parse_xy
+@struct_string_two_out@
+identifier func;
+identifier s, out1, out2;
+type T, T2, T3;
+@@
+static T func(const char *s, T2 *out1, T3 *out2)
+{ ... }
+
+// Pattern: T func(const char *s, T2 *out)
+@struct_string_one_out@
+identifier func;
+identifier s, out;
+type T, T2;
+@@
+T func(const char *s, T2 *out)
+{ ... }
+
+// Pattern: T func(const char *s) - simple string
+@struct_string_simple@
+identifier func;
+identifier s;
+type T;
+@@
+T func(const char *s)
+{ ... }
+
+// ============================================================================
+// Python scripts for code generation
+// ============================================================================
+
+@script:python depends on simple_ptr_ret@
+func << simple_ptr_ret.func;
+data << simple_ptr_ret.data;
+len << simple_ptr_ret.len;
+T << simple_ptr_ret.T;
+@@
+import os
+
+target = os.environ.get('KFUZZ_FUNC', '')
+header = os.environ.get('KFUZZ_HEADER', '')
+
+if target and func == target:
+    ret_type = str(T).strip()
+    testname = "test_" + func
+
+    print("// SPDX-License-Identifier: GPL-2.0-or-later")
+    print("/*")
+    print(" * %s KFuzzTest target" % func)
+    print(" *")
+    print(" * Auto-generated by kfuzz_gen.cocci")
+    print(" */")
+    if header:
+        print("#include <%s>" % header)
+    print("#include <linux/kfuzztest.h>")
+    print("")
+    print("FUZZ_TEST_SIMPLE(%s)" % testname)
+    print("{")
+    print("\t%s *ret;" % ret_type)
+    print("")
+    print("\tret = %s(data, datalen);" % func)
+    print("\tif (ret && !IS_ERR(ret))")
+    print("\t\tkfree(ret);")
+    print("}")
+
+@script:python depends on simple_with_out@
+func << simple_with_out.func;
+out << simple_with_out.out;
+data << simple_with_out.data;
+len << simple_with_out.len;
+T2 << simple_with_out.T2;
+@@
+import os
+
+target = os.environ.get('KFUZZ_FUNC', '')
+header = os.environ.get('KFUZZ_HEADER', '')
+
+if target and func == target:
+    out_type = str(T2).strip()
+    testname = "test_" + func
+
+    print("// SPDX-License-Identifier: GPL-2.0-or-later")
+    print("/*")
+    print(" * %s KFuzzTest target" % func)
+    print(" *")
+    print(" * Auto-generated by kfuzz_gen.cocci")
+    print(" */")
+    if header:
+        print("#include <%s>" % header)
+    print("#include <linux/kfuzztest.h>")
+    print("")
+    print("FUZZ_TEST_SIMPLE(%s)" % testname)
+    print("{")
+    print("\t%s %s;" % (out_type, out))
+    print("")
+    print("\t%s(&%s, data, datalen);" % (func, out))
+    print("}")
+
+@script:python depends on simple_with_out_uint@
+func << simple_with_out_uint.func;
+out << simple_with_out_uint.out;
+data << simple_with_out_uint.data;
+len << simple_with_out_uint.len;
+T2 << simple_with_out_uint.T2;
+@@
+import os
+
+target = os.environ.get('KFUZZ_FUNC', '')
+header = os.environ.get('KFUZZ_HEADER', '')
+
+if target and func == target:
+    out_type = str(T2).strip()
+    testname = "test_" + func
+
+    print("// SPDX-License-Identifier: GPL-2.0-or-later")
+    print("/*")
+    print(" * %s KFuzzTest target" % func)
+    print(" *")
+    print(" * Auto-generated by kfuzz_gen.cocci")
+    print(" */")
+    if header:
+        print("#include <%s>" % header)
+    print("#include <linux/kfuzztest.h>")
+    print("")
+    print("FUZZ_TEST_SIMPLE(%s)" % testname)
+    print("{")
+    print("\t%s %s;" % (out_type, out))
+    print("")
+    print("\t%s(&%s, data, datalen);" % (func, out))
+    print("}")
+
+@script:python depends on simple_void_generic && !simple_ptr_ret && !simple_with_out && !simple_with_out_uint@
+func << simple_void_generic.func;
+data << simple_void_generic.data;
+len << simple_void_generic.len;
+@@
+import os
+
+target = os.environ.get('KFUZZ_FUNC', '')
+header = os.environ.get('KFUZZ_HEADER', '')
+
+if target and func == target:
+    testname = "test_" + func
+
+    print("// SPDX-License-Identifier: GPL-2.0-or-later")
+    print("/*")
+    print(" * %s KFuzzTest target" % func)
+    print(" *")
+    print(" * Auto-generated by kfuzz_gen.cocci")
+    print(" */")
+    if header:
+        print("#include <%s>" % header)
+    print("#include <linux/kfuzztest.h>")
+    print("")
+    print("FUZZ_TEST_SIMPLE(%s)" % testname)
+    print("{")
+    print("\t%s(data, datalen);" % func)
+    print("}")
+
+@script:python depends on simple_char_generic && !simple_void_generic@
+func << simple_char_generic.func;
+data << simple_char_generic.data;
+len << simple_char_generic.len;
+@@
+import os
+
+target = os.environ.get('KFUZZ_FUNC', '')
+header = os.environ.get('KFUZZ_HEADER', '')
+
+if target and func == target:
+    testname = "test_" + func
+
+    print("// SPDX-License-Identifier: GPL-2.0-or-later")
+    print("/*")
+    print(" * %s KFuzzTest target" % func)
+    print(" *")
+    print(" * Auto-generated by kfuzz_gen.cocci")
+    print(" */")
+    if header:
+        print("#include <%s>" % header)
+    print("#include <linux/kfuzztest.h>")
+    print("")
+    print("FUZZ_TEST_SIMPLE(%s)" % testname)
+    print("{")
+    print("\t%s(data, datalen);" % func)
+    print("}")
+
+@script:python depends on simple_uchar_generic && !simple_char_generic && !simple_void_generic@
+func << simple_uchar_generic.func;
+@@
+import os
+
+target = os.environ.get('KFUZZ_FUNC', '')
+header = os.environ.get('KFUZZ_HEADER', '')
+
+if target and func == target:
+    testname = "test_" + func
+
+    print("// SPDX-License-Identifier: GPL-2.0-or-later")
+    print("/*")
+    print(" * %s KFuzzTest target" % func)
+    print(" *")
+    print(" * Auto-generated by kfuzz_gen.cocci")
+    print(" */")
+    if header:
+        print("#include <%s>" % header)
+    print("#include <linux/kfuzztest.h>")
+    print("")
+    print("FUZZ_TEST_SIMPLE(%s)" % testname)
+    print("{")
+    print("\t%s(data, datalen);" % func)
+    print("}")
+
+@script:python depends on struct_string_two_out@
+func << struct_string_two_out.func;
+s << struct_string_two_out.s;
+out1 << struct_string_two_out.out1;
+out2 << struct_string_two_out.out2;
+T << struct_string_two_out.T;
+T2 << struct_string_two_out.T2;
+T3 << struct_string_two_out.T3;
+@@
+import os
+
+target = os.environ.get('KFUZZ_FUNC', '')
+header = os.environ.get('KFUZZ_HEADER', '')
+
+if target and func == target:
+    testname = "test_" + func
+    argname = func + "_arg"
+    ret_type = str(T).strip()
+    out1_type = str(T2).strip()
+    out2_type = str(T3).strip()
+
+    print("// SPDX-License-Identifier: GPL-2.0-or-later")
+    print("/*")
+    print(" * %s KFuzzTest target" % func)
+    print(" *")
+    print(" * Auto-generated by kfuzz_gen.cocci")
+    print(" */")
+    if header:
+        print("#include <%s>" % header)
+    print("#include <linux/kfuzztest.h>")
+    print("")
+    print("struct %s {" % argname)
+    print("\tconst char *%s;" % s)
+    print("};")
+    print("")
+    print("static %s %s(const char *%s, %s *%s, %s *%s);" % (ret_type, func, s, out1_type, out1, out2_type, out2))
+    print("")
+    print("FUZZ_TEST(%s, struct %s)" % (testname, argname))
+    print("{")
+    print("\t%s %s;" % (out1_type, out1))
+    print("\t%s %s;" % (out2_type, out2))
+    print("")
+    print("\tKFUZZTEST_EXPECT_NOT_NULL(%s, %s);" % (argname, s))
+    print("\tKFUZZTEST_ANNOTATE_STRING(%s, %s);" % (argname, s))
+    print("\t%s(arg->%s, &%s, &%s);" % (func, s, out1, out2))
+    print("}")
+
+@script:python depends on struct_string_one_out && !struct_string_two_out@
+func << struct_string_one_out.func;
+s << struct_string_one_out.s;
+out << struct_string_one_out.out;
+T2 << struct_string_one_out.T2;
+@@
+import os
+
+target = os.environ.get('KFUZZ_FUNC', '')
+header = os.environ.get('KFUZZ_HEADER', '')
+
+if target and func == target:
+    testname = "test_" + func
+    argname = func + "_arg"
+    out_type = str(T2).strip()
+
+    print("// SPDX-License-Identifier: GPL-2.0-or-later")
+    print("/*")
+    print(" * %s KFuzzTest target" % func)
+    print(" *")
+    print(" * Auto-generated by kfuzz_gen.cocci")
+    print(" */")
+    if header:
+        print("#include <%s>" % header)
+    print("#include <linux/kfuzztest.h>")
+    print("")
+    print("struct %s {" % argname)
+    print("\tconst char *%s;" % s)
+    print("};")
+    print("")
+    print("FUZZ_TEST(%s, struct %s)" % (testname, argname))
+    print("{")
+    print("\t%s %s;" % (out_type, out))
+    print("")
+    print("\tKFUZZTEST_EXPECT_NOT_NULL(%s, %s);" % (argname, s))
+    print("\tKFUZZTEST_ANNOTATE_STRING(%s, %s);" % (argname, s))
+    print("\t%s(arg->%s, &%s);" % (func, s, out))
+    print("}")
+
+@script:python depends on struct_string_simple && !struct_string_one_out && !struct_string_two_out@
+func << struct_string_simple.func;
+s << struct_string_simple.s;
+@@
+import os
+
+target = os.environ.get('KFUZZ_FUNC', '')
+header = os.environ.get('KFUZZ_HEADER', '')
+
+if target and func == target:
+    testname = "test_" + func
+    argname = func + "_arg"
+
+    print("// SPDX-License-Identifier: GPL-2.0-or-later")
+    print("/*")
+    print(" * %s KFuzzTest target" % func)
+    print(" *")
+    print(" * Auto-generated by kfuzz_gen.cocci")
+    print(" */")
+    if header:
+        print("#include <%s>" % header)
+    print("#include <linux/kfuzztest.h>")
+    print("")
+    print("struct %s {" % argname)
+    print("\tconst char *%s;" % s)
+    print("};")
+    print("")
+    print("FUZZ_TEST(%s, struct %s)" % (testname, argname))
+    print("{")
+    print("\tKFUZZTEST_EXPECT_NOT_NULL(%s, %s);" % (argname, s))
+    print("\tKFUZZTEST_ANNOTATE_STRING(%s, %s);" % (argname, s))
+    print("\t%s(arg->%s);" % (func, s))
+    print("}")
diff --git a/scripts/coccinelle/kfuzztest/kfuzz_simple_finder.cocci b/scripts/coccinelle/kfuzztest/kfuzz_simple_finder.cocci
new file mode 100644
index 000000000000..8781ca316cf5
--- /dev/null
+++ b/scripts/coccinelle/kfuzztest/kfuzz_simple_finder.cocci
@@ -0,0 +1,96 @@
+// SPDX-License-Identifier: GPL-2.0
+///
+/// Find functions suitable for FUZZ_TEST_SIMPLE
+///
+/// This script identifies functions that take (data, len) or (out, data, len)
+/// patterns, which are common candidates for simple fuzz testing.
+///
+/// Usage:
+///   spatch --sp-file kfuzz_simple_finder.cocci --dir path/to/source -D report
+///
+// Confidence: Medium
+// Options: --no-includes --include-headers
+
+virtual context
+virtual org
+virtual report
+
+// Pattern 1: func(const void *data, size_t len)
+@r1@
+identifier func;
+identifier data, len;
+type T1;
+position p;
+@@
+T1 func@p(const void *data, size_t len, ...)
+{ ... }
+
+// Pattern 2: T *func(const void *data, size_t len) - returns pointer
+@r2@
+identifier func;
+identifier data, len;
+type T;
+position p;
+@@
+T *func@p(const void *data, size_t len, ...)
+{ ... }
+
+// Pattern 3: func(out, const void *data, size_t len)
+@r3@
+identifier func;
+identifier out, data, len;
+type T1, T2;
+position p;
+@@
+T1 func@p(T2 *out, const void *data, size_t len, ...)
+{ ... }
+
+// Pattern 4: func(const char *data, size_t len)
+@r4@
+identifier func;
+identifier data, len;
+type T1;
+position p;
+@@
+T1 func@p(const char *data, size_t len, ...)
+{ ... }
+
+// Pattern 5: unsigned char variant
+@r5@
+identifier func;
+identifier data, len;
+type T1;
+position p;
+@@
+T1 func@p(const unsigned char *data, size_t len, ...)
+{ ... }
+
+@script:python depends on r1 && report@
+func << r1.func;
+p << r1.p;
+@@
+print("%s:%s: Candidate for FUZZ_TEST_SIMPLE: %s(const void *data, size_t len)" % (p[0].file, p[0].line, func))
+
+@script:python depends on r2 && report@
+func << r2.func;
+p << r2.p;
+@@
+print("%s:%s: Candidate for FUZZ_TEST_SIMPLE (returns ptr): %s" % (p[0].file, p[0].line, func))
+
+@script:python depends on r3 && report@
+func << r3.func;
+p << r3.p;
+@@
+print("%s:%s: Candidate for FUZZ_TEST_SIMPLE (with output): %s" % (p[0].file, p[0].line, func))
+
+@script:python depends on r4 && report@
+func << r4.func;
+p << r4.p;
+@@
+print("%s:%s: Candidate for FUZZ_TEST_SIMPLE: %s(const char *data, size_t len)" % (p[0].file, p[0].line, func))
+
+@script:python depends on r5 && report@
+func << r5.func;
+p << r5.p;
+@@
+print("%s:%s: Candidate for FUZZ_TEST_SIMPLE: %s(const unsigned char *data, size_t len)" % (p[0].file, p[0].line, func))
diff --git a/scripts/coccinelle/kfuzztest/kfuzz_struct_finder.cocci b/scripts/coccinelle/kfuzztest/kfuzz_struct_finder.cocci
new file mode 100644
index 000000000000..c850f5d7b167
--- /dev/null
+++ b/scripts/coccinelle/kfuzztest/kfuzz_struct_finder.cocci
@@ -0,0 +1,91 @@
+// SPDX-License-Identifier: GPL-2.0
+///
+/// Find functions suitable for FUZZ_TEST (struct-based input)
+///
+/// This script identifies functions that take string pointers or other
+/// complex inputs that benefit from FUZZ_TEST with custom argument structs.
+///
+/// Usage:
+///   spatch --sp-file kfuzz_struct_finder.cocci --dir path/to/source -D report
+///
+// Confidence: Medium
+// Options: --no-includes --include-headers
+
+virtual context
+virtual org
+virtual report
+
+// Pattern 1: func(const char *s) - string parsing functions
+@string_input@
+identifier func;
+identifier s;
+type T;
+position p;
+@@
+T func@p(const char *s)
+{ ... }
+
+// Pattern 2: func(const char *s, out) - string with output
+@string_with_out@
+identifier func;
+identifier s, out;
+type T1, T2;
+position p;
+@@
+T1 func@p(const char *s, T2 *out)
+{ ... }
+
+// Pattern 3: func(const char *s, out1, out2) - string with two outputs
+@string_two_out@
+identifier func;
+identifier s, out1, out2;
+type T, T2, T3;
+position p;
+@@
+T func@p(const char *s, T2 *out1, T3 *out2)
+{ ... }
+
+// Pattern 4: Static internal parsers (common pattern)
+@static_parser@
+identifier func;
+identifier s;
+type T;
+position p;
+@@
+static T func@p(const char *s, ...)
+{ ... }
+
+@script:python depends on string_input && report@
+func << string_input.func;
+p << string_input.p;
+@@
+# Filter out common false positives
+skip_list = ['printk', 'pr_info', 'pr_err', 'pr_warn', 'pr_debug',
+             'dev_info', 'dev_err', 'dev_warn', 'sprintf', 'snprintf',
+             'strcmp', 'strncmp', 'strcpy', 'strncpy', 'strlen',
+             'kstrdup', 'kasprintf', '__func__', 'kfree', 'kmalloc']
+if func not in skip_list:
+    print("%s:%s: FUZZ_TEST candidate (string input): %s(const char *s)" % (p[0].file, p[0].line, func))
+
+@script:python depends on string_with_out && report@
+func << string_with_out.func;
+p << string_with_out.p;
+@@
+skip_list = ['printk', 'sprintf', 'sscanf', 'kstrtol', 'kstrtoul']
+if func not in skip_list:
+    print("%s:%s: FUZZ_TEST candidate (string with output): %s" % (p[0].file, p[0].line, func))
+
+@script:python depends on string_two_out && report@
+func << string_two_out.func;
+p << string_two_out.p;
+@@
+print("%s:%s: FUZZ_TEST candidate (string with 2 outputs): %s" % (p[0].file, p[0].line, func))
+
+@script:python depends on static_parser && report@
+func << static_parser.func;
+p << static_parser.p;
+@@
+# Static parsers are often good fuzz targets
+skip_list = ['printk', 'pr_info', 'pr_err', 'strcmp', 'strncmp']
+if func not in skip_list and 'parse' in func.lower():
+    print("%s:%s: FUZZ_TEST candidate (static parser): %s" % (p[0].file, p[0].line, func))
diff --git a/scripts/coccinelle/kfuzztest/kfuzz_targets.conf b/scripts/coccinelle/kfuzztest/kfuzz_targets.conf
new file mode 100644
index 000000000000..393285848c77
--- /dev/null
+++ b/scripts/coccinelle/kfuzztest/kfuzz_targets.conf
@@ -0,0 +1,21 @@
+# SPDX-License-Identifier: GPL-2.0
+#
+# KFuzzTest target configuration
+#
+# Format: FUNC:SOURCE:OUTPUT[:HEADER]
+#
+# FUNC   - Function name to generate fuzz test for
+# SOURCE - Source file containing the function
+# OUTPUT - Output _kfuzz.c file to generate
+# HEADER - Optional header file to include
+#
+
+# PKCS7 parser
+pkcs7_parse_message:crypto/asymmetric_keys/pkcs7_parser.c:crypto/asymmetric_keys/tests/pkcs7_kfuzz.c:crypto/pkcs7.h
+
+# RSA key helpers
+rsa_parse_pub_key:crypto/rsa_helper.c:crypto/asymmetric_keys/tests/rsa_helper_kfuzz.c:crypto/internal/rsa.h
+rsa_parse_priv_key:crypto/rsa_helper.c:crypto/asymmetric_keys/tests/rsa_helper_kfuzz.c:crypto/internal/rsa.h
+
+# charlcd parser
+parse_xy:drivers/auxdisplay/charlcd.c:drivers/auxdisplay/tests/charlcd_kfuzz.c
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aTvLyFsE55MR0kHo%40bombadil.infradead.org.
