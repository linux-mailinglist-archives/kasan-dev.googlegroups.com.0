Return-Path: <kasan-dev+bncBCJZRXGY5YJBBQEZ4KDQMGQE3HOEQXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 405413D18AC
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jul 2021 23:08:17 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id j3-20020a4a94430000b029025c2496941asf1640465ooi.10
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jul 2021 14:08:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626901696; cv=pass;
        d=google.com; s=arc-20160816;
        b=upB9UPDbHQhqlSFHdp3Q9pI9YJvEyzyi5XPen0nDLBzIft3lLL2mnVm8uCk5T8p8gD
         QVnYty2yJh/oRurX+bOSMa1Xtt7BhVaTuSHslkd/7sb5/mmPiI/D03/PnJvh4j7nBUs/
         uEG9rkooJj6z7RooiYnYEcFNLX4m/R8uWHcqfZnutXxSm3x/LxvKxwbp4FdoYngZBpZV
         2v/IQW82tixunYYCIugyfXVAPQmXt+6M8jHpKKSczBfI/7ye7DedNRJdeuKlC34iiiWD
         w9BzlcV4obYu9YWDfOSsReictFVVGAzNJNpL37hmcoyksa3hlYaK4oMDTu+tYyeT0F9O
         WG/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=T1sniXFEjJVhaLJxe/gcr9llzil1CqZzmGPi+PvdjOM=;
        b=DS3TT/spLYYhFqNKUAAjdI0JnNDZvnR9GWjMEHlnsb90AtiPwkuXQdIAQfiz9x86la
         Z9A4Zq6gS39YjCzYSJdtwRaBJfDkPyn8vEHaILyFVlwDJG0IFI0GDaWpb10fRMsY1IQU
         COyJtQHPqF1NAo2TTI7BXue+MTt3Q6Gkj6NE4V8PftGJIa0fsbOGsdWO/LaGz2oYFmg9
         qMsbQjMwJzn9C8mFTbycMLd/CTHqgtBNX7TUpwfRfSp34J9miSdgvpcF+l8d1h3DEn97
         UZdo0K0DsRJFj0A+6e5yVM2EccXmhK7ZI2I602qmYzCnFRQFcGfGyB0yJXmSvmI/oyCM
         f5bA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QPjcYR+w;
       spf=pass (google.com: domain of srs0=6g4i=mn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6g4i=MN=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=T1sniXFEjJVhaLJxe/gcr9llzil1CqZzmGPi+PvdjOM=;
        b=HIQ8Jyt9KqRiVt10963U/XoObr2MZ7spmDFNDLmbfR0nM9EVSlX2FydqzxyPEtDqRO
         zeqoTpIiqF041Sm8hDwfaU51o53uXeNwgdSjXx6jWiSQdHeru94IaWgGOrOo91dHwFRk
         w6BhnV1BR9MkXLlfNvwZHj0l+rcjwIec6lGvJv9nhZhFIa+siP6VDF7IEoF2SQuxBHQH
         mrOaUAPt/3wIXwpy1phshhukCFOsZ7NbGr/9QmGzOIDWsi/vOaLe546jgPIcJQEe2/Er
         5xBwRMguVFUMJyvS5ByAcAlSeBC3KOR2M6MmMIDkOIbsf+vWkVUIZ/voJ8oa9vJW9Mjh
         pIFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=T1sniXFEjJVhaLJxe/gcr9llzil1CqZzmGPi+PvdjOM=;
        b=JjYByee4HGGbKL11kaC6p9D/FfLPI8KoqHqAK5v325KGKd5PqyB0M6sJ+C6+e3EP1S
         iI6unKoHyV/R+MYM5DLcqko9xvJ3RfyW9hTAinRhQx2j0w0vP4+jJfYpNkeSnbzi7J+x
         s3Ni4RboetozIxQdVH4ysEmTAU/eh81WFJTTjcozk1qaSn8YiZo/HGturbPRqrgyIMHd
         oSTmrlvFQqh/Kqz6z4wwaz7WsEpUXK+Z7Az6gCkMHwOJPJuOhMrtXU3M2+A+HI3M3S7G
         xOhxJGpPC1Ic65xpscATJ2cuupTOFbc9y/O30TxVHVvgCor9i1slyIBTZNvz+/1RoLaO
         1ywQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5330bpDPQmybG/R4H7ozjVwHd5qVT/tMEVGmgTlk2m9oP8OYTE60
	Oy4lerRSsw/9jiWsgoQ6l7s=
X-Google-Smtp-Source: ABdhPJxKBJUGm40+4JLdnUe3Anl9aiul+2Afca1xEKI9dRY96k9VnY9f49qViAi+M+0HxbZFqVCogw==
X-Received: by 2002:a05:6830:1f2b:: with SMTP id e11mr27625317oth.336.1626901696079;
        Wed, 21 Jul 2021 14:08:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:f409:: with SMTP id s9ls1217499oih.5.gmail; Wed, 21 Jul
 2021 14:08:15 -0700 (PDT)
X-Received: by 2002:aca:4ccd:: with SMTP id z196mr3903264oia.126.1626901695780;
        Wed, 21 Jul 2021 14:08:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626901695; cv=none;
        d=google.com; s=arc-20160816;
        b=F8Ehwd5rXImUhLE4p2YI3nVh90veNU462o2AuPW2Om1Dcg8aX/mu/zGTibEx5n3wYa
         QUUfK+rHdNQNxi7F6jLPXewM3tXvsYlp3F//ekT5YjwdfQyRPBVYxH/2KBEwG09DmQp5
         1D8xosXYkmFwpWpokidVtFmx58IU99eNdNXjsGxH3WeUF6jKwVVT9UoQK440rp0vBeDd
         HvIzZM41RoKjFBvimZiW2RLLW6cxUBlv85mZjQXm0Yj6PWaFNHGtEwKCpdHGgU2h+p2G
         S7QfXYFzhLFGUyMODEal8ATdVcExMp/xHtB4DuKrI5LNMmr7BnjlkqZbUEi/kO5dJ9ay
         vT/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=oQfb8QCERIkjdFoTsMCaRELMtCUbDrz/AbUATTHNwk8=;
        b=BuD7k6NtBgYGs/t7Pqu/XvZ4+qsibDxJG2PGvTgHRLQGIWKBCwCizqZISe4xzM0+AW
         JRgsaP2XPk7t5gId1jbfS/FPMVqjAu31hZLWtKl8bdsmnDUV/Gw6vUFqJK7lJ+YYLnxh
         JEgf64wbHVSrBTdMTnQ3Lbggz/+Kd7qtRELp1qKkb1Hd4Rl3LItRvsEGciOTynlunRj1
         X5z4Gb4PmKlFWP7ugr+i0FEwqnpKwAVcxuhSVuSE6ZHPx3+2cfilpwJ+mI4+kiF981SN
         fLMd/HOo27CBMp8VcI01gszGuZrmLVtohrm1uFu9p7QO1LtWH8lpxM5GUwRiF6Vb8KTQ
         3LRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QPjcYR+w;
       spf=pass (google.com: domain of srs0=6g4i=mn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6g4i=MN=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id g9si1351916ots.5.2021.07.21.14.08.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 21 Jul 2021 14:08:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=6g4i=mn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 98E1D613CF;
	Wed, 21 Jul 2021 21:08:14 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 5C04D5C0A11; Wed, 21 Jul 2021 14:08:14 -0700 (PDT)
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	Mark Rutland <mark.rutland@arm.com>,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 3/8] kcsan: Introduce CONFIG_KCSAN_STRICT
Date: Wed, 21 Jul 2021 14:08:07 -0700
Message-Id: <20210721210812.844740-3-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20210721210726.GA828672@paulmck-ThinkPad-P17-Gen-1>
References: <20210721210726.GA828672@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=QPjcYR+w;       spf=pass
 (google.com: domain of srs0=6g4i=mn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6g4i=MN=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

From: Marco Elver <elver@google.com>

Add a simpler Kconfig variable to configure KCSAN's "strict" mode. This
makes it simpler in documentation or messages to suggest just a single
configuration option to select the strictest checking mode (vs.
currently having to list several options).

Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Mark Rutland <mark.rutland@arm.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 Documentation/dev-tools/kcsan.rst |  4 ++++
 lib/Kconfig.kcsan                 | 10 ++++++++++
 2 files changed, 14 insertions(+)

diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
index 6a600cf8430b1..69dc9c502ccc5 100644
--- a/Documentation/dev-tools/kcsan.rst
+++ b/Documentation/dev-tools/kcsan.rst
@@ -127,6 +127,10 @@ Kconfig options:
   causes KCSAN to not report data races due to conflicts where the only plain
   accesses are aligned writes up to word size.
 
+To use the strictest possible rules, select ``CONFIG_KCSAN_STRICT=y``, which
+configures KCSAN to follow the Linux-kernel memory consistency model (LKMM) as
+closely as possible.
+
 DebugFS interface
 ~~~~~~~~~~~~~~~~~
 
diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index 5304f211f81f1..c76fbb3ee09ec 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -183,9 +183,17 @@ config KCSAN_REPORT_RACE_UNKNOWN_ORIGIN
 	  reported if it was only possible to infer a race due to a data value
 	  change while an access is being delayed on a watchpoint.
 
+config KCSAN_STRICT
+	bool "Strict data-race checking"
+	help
+	  KCSAN will report data races with the strictest possible rules, which
+	  closely aligns with the rules defined by the Linux-kernel memory
+	  consistency model (LKMM).
+
 config KCSAN_REPORT_VALUE_CHANGE_ONLY
 	bool "Only report races where watcher observed a data value change"
 	default y
+	depends on !KCSAN_STRICT
 	help
 	  If enabled and a conflicting write is observed via a watchpoint, but
 	  the data value of the memory location was observed to remain
@@ -194,6 +202,7 @@ config KCSAN_REPORT_VALUE_CHANGE_ONLY
 config KCSAN_ASSUME_PLAIN_WRITES_ATOMIC
 	bool "Assume that plain aligned writes up to word size are atomic"
 	default y
+	depends on !KCSAN_STRICT
 	help
 	  Assume that plain aligned writes up to word size are atomic by
 	  default, and also not subject to other unsafe compiler optimizations
@@ -206,6 +215,7 @@ config KCSAN_ASSUME_PLAIN_WRITES_ATOMIC
 
 config KCSAN_IGNORE_ATOMICS
 	bool "Do not instrument marked atomic accesses"
+	depends on !KCSAN_STRICT
 	help
 	  Never instrument marked atomic accesses. This option can be used for
 	  additional filtering. Conflicting marked atomic reads and plain
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210721210812.844740-3-paulmck%40kernel.org.
