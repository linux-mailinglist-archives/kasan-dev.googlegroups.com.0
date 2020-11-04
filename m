Return-Path: <kasan-dev+bncBDX4HWEMTEBRBQXORT6QKGQEHVZ4KMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B5332A714A
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:20:35 +0100 (CET)
Received: by mail-ed1-x540.google.com with SMTP id v7sf33052edy.4
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:20:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604532034; cv=pass;
        d=google.com; s=arc-20160816;
        b=XIqDBv5nKWE58pBn9byYJ3ZNwTIlW5xeenEH6h55LT3+VG9FKr1Fh2p/2JMd29jjYz
         QEvDhlPksrT37YubpQXs755pUZpbv+o7w2um9nWd+gha+9joqB4bQi2upxjeScYNwb+O
         gGQW3g+smCEipAbxo/z5xx8iFyoTEDVHrZVx6X7pWcigX5DFmWFtHPsFiFZYfCYeh1Vq
         rbKth0iVv+50dGqq/YgGgKocL+P1JfYW/wA4pNg7GaSbsjbq7Q/bbRFOHotPVPs3thE5
         lnQo/6z9BHKCQgwPlsRJC95kUxhqr5NmQwogTtUqMJL/03eYgSNvuP8c2BI6Bv0GMhgt
         shPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=zYON3SXLZn3Axlgcu5Iw9WG+RsljWS5JvlZyzDHkzm8=;
        b=Gr8JfdfVcaxdzTmrLqyi8LBtT2L9H9xmfAg+JY4FjB7Vqjrlsm34EEetyinB7bbFiH
         Aeha/P4PxF5UpB2NAG2lj06dj3enGeSAeVLBnk+ifIFPD69HyQ8Ndl+eRh7H5fRFHRPM
         b0/S0l7AcqEjSXfwBlZtywVlU6PYBZP+OIFE3SI9xaaBl8MXR6ccDOswP0datlCSYVlY
         Q1dy9NuIK1NBeiDSWHGPK72ZyOSho8snwpDe87gzUebr3uJhToC4fGA65DXrOdJJrZEO
         qXeHeUuQlnEe1wXAYrs5RUEy9BUF5shf/PRChg5ehDX33DGtdKbZE4T1pesVlrObHC5w
         0S2w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OANIlywW;
       spf=pass (google.com: domain of 3qtejxwokcuacpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3QTejXwoKCUAcpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=zYON3SXLZn3Axlgcu5Iw9WG+RsljWS5JvlZyzDHkzm8=;
        b=duoVbcBUqmLurN1kpcv6IPRC5TwOMpEgskHRYqgB7PkvTHmUF/9fnQSLiDSoQFlk5N
         nyFVtWAEUzSFETxn3gY2OUfpoymNo/z763H8U7bLbTBbxGValyGjzhm73ThmvN6ZEd1k
         tfvm4KuTGvs65ghbTCppBhvt2C4QQ5z7xKCrrwJ7uFaeBfTOIKLEOukSsXHWsecAmpnu
         sqUcs9jKuN/AhyuZKZqiMwNWLa3UYjvPTjwbSHFcSZDKCx6cBESQpV29ZuELPnSlmMDt
         6iAuura6yABvvKRhtTxL3zGR0blVzk4wwIrQUAaxHfOhRA2pW4ij98jNLP4ZshRBln8A
         aTsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zYON3SXLZn3Axlgcu5Iw9WG+RsljWS5JvlZyzDHkzm8=;
        b=DP1+ZGMkhhyUzc0hh4x6Fq7DeZTJpEqE+VyAhkwXHLOAxqGGfuS3A+3rcl7MIkcde3
         g+mM0LxuKgSUz+hepiokCi/uny4MhCAeMDb4+t/dh2954sM6V/SwJwLo05tIRDLCNzSz
         wIRa9U/ur0lHOy4vwXary1pspneGzCUgospEWlwRSLtEG0j/ofKkiHvdogQ6Cwnv+LaV
         ZAxccmY03Ive/BUyaNCyzsf3T8neNRuCi2khIm39DSo4AaHvNed9krhg9qLuZDpkiHuq
         QLbX3PXCPBn8huJyJBeW6yJXEDaC8arMhtO5g9Hz23KxxSDsrft1TK/YZcczbOYaJTcI
         Q6PQ==
X-Gm-Message-State: AOAM5308HWq8TakRKCv6AUHR4SBf1hD0FZQGczAO7Ph4kByNkv78z7Na
	ibBtfbwlK3FY4eZ0PeEHJOM=
X-Google-Smtp-Source: ABdhPJzotyFuh2Hdi0vUmfLxUkRKA1NNzygxdXZPH7RFmQg3jio9B7K6rraEqT64CAXrFC9VEd4QTw==
X-Received: by 2002:a05:6402:1158:: with SMTP id g24mr148020edw.323.1604532034820;
        Wed, 04 Nov 2020 15:20:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:3189:: with SMTP id 9ls1771372ejy.10.gmail; Wed, 04
 Nov 2020 15:20:34 -0800 (PST)
X-Received: by 2002:a17:906:c1c7:: with SMTP id bw7mr460415ejb.290.1604532033949;
        Wed, 04 Nov 2020 15:20:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604532033; cv=none;
        d=google.com; s=arc-20160816;
        b=IlRDVd8J6b7Zn2AsNi88iZxvLEtkQU5Gnol6gIQvtXApvjL7wMx9hqEXw+flNb/XCJ
         9GlOSZT+s+PvfSBo9EPxQb8eprhb0v8KNj69y7bNrxqG3NcQTwYxV5q7ENpYIv4MLCfj
         iCsVaB8vnAnDa4Sde9zeJ9dMtpT392YWf3BXLlGHCSJWscb0eejZKh/L58E5e8X6YcLZ
         tjOh/aG7PtLVTx9LzUKRKvS2/6c3LFYcMis4MEyBgJ6u+j8eT49IjY9cm+cdTj4R5vwD
         WNnSTmzZvCjrIG9beqK2NVVBwF8phgf0lNfT80jXwZUj4ig4dg16+WZSJT58husSRrDw
         SGZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=7ejNZAMa5/1JIms2ONCukWsDh69PgCTWliqLjQNgQ+A=;
        b=oUaHk9Ist1PhRONxo44vERa0hmO18VlI30LPAft1eLoSomUtoqVnPUO4i38Y0Lo7bA
         ilcOzAnn20duvhWV6e5JDADcdhn06LFWDqRsr82rBwmFmYbguOuVaWlXDvYfm67SawI8
         TM2W40b6ZJUL/V1aZacac7RA462Wrod93wEAWqcu1ihp6gsVEDlDbDIE9rA6SyQsMSDy
         t7xsR/l4r6eF+C4c2PkLgCcDzBl3tipw2wR+T3TpTMi9l1DNZnyWU3VVHBnjmqPmZG6a
         0MfX2kES7ml3e5Y//huhxhk6lKlZZYWEBOtScMQ9CDc+YHijApkpKV8Ge7SZdcMcB0ix
         3q3g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OANIlywW;
       spf=pass (google.com: domain of 3qtejxwokcuacpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3QTejXwoKCUAcpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id u2si125041edp.5.2020.11.04.15.20.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:20:33 -0800 (PST)
Received-SPF: pass (google.com: domain of 3qtejxwokcuacpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 3so15117wms.9
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:20:33 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:600c:2252:: with SMTP id
 a18mr46162wmm.139.1604532033584; Wed, 04 Nov 2020 15:20:33 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:51 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <610e97ebe0d46531ca2c988ebb26dd04d08d96c2.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 36/43] kasan, x86, s390: update undef CONFIG_KASAN
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>, Vasily Gorbik <gor@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=OANIlywW;       spf=pass
 (google.com: domain of 3qtejxwokcuacpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3QTejXwoKCUAcpftg0mpxniqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

With the intoduction of hardware tag-based KASAN some kernel checks of
this kind:

  ifdef CONFIG_KASAN

will be updated to:

  if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)

x86 and s390 use a trick to #undef CONFIG_KASAN for some of the code
that isn't linked with KASAN runtime and shouldn't have any KASAN
annotations.

Also #undef CONFIG_KASAN_GENERIC with CONFIG_KASAN.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
Acked-by: Vasily Gorbik <gor@linux.ibm.com>
---
Change-Id: I2a622db0cb86a8feb60c30d8cb09190075be2a90
---
 arch/s390/boot/string.c         | 1 +
 arch/x86/boot/compressed/misc.h | 1 +
 2 files changed, 2 insertions(+)

diff --git a/arch/s390/boot/string.c b/arch/s390/boot/string.c
index b11e8108773a..faccb33b462c 100644
--- a/arch/s390/boot/string.c
+++ b/arch/s390/boot/string.c
@@ -3,6 +3,7 @@
 #include <linux/kernel.h>
 #include <linux/errno.h>
 #undef CONFIG_KASAN
+#undef CONFIG_KASAN_GENERIC
 #include "../lib/string.c"
 
 int strncmp(const char *cs, const char *ct, size_t count)
diff --git a/arch/x86/boot/compressed/misc.h b/arch/x86/boot/compressed/misc.h
index d9a631c5973c..901ea5ebec22 100644
--- a/arch/x86/boot/compressed/misc.h
+++ b/arch/x86/boot/compressed/misc.h
@@ -12,6 +12,7 @@
 #undef CONFIG_PARAVIRT_XXL
 #undef CONFIG_PARAVIRT_SPINLOCKS
 #undef CONFIG_KASAN
+#undef CONFIG_KASAN_GENERIC
 
 /* cpu_feature_enabled() cannot be used this early */
 #define USE_EARLY_PGTABLE_L5
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/610e97ebe0d46531ca2c988ebb26dd04d08d96c2.1604531793.git.andreyknvl%40google.com.
