Return-Path: <kasan-dev+bncBCLI747UVAFRBP5UZCMQMGQEYTLLY4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63b.google.com (mail-ej1-x63b.google.com [IPv6:2a00:1450:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A90D5EB324
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Sep 2022 23:31:44 +0200 (CEST)
Received: by mail-ej1-x63b.google.com with SMTP id qf38-20020a1709077f2600b00783ac0b15f0sf1601412ejc.8
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Sep 2022 14:31:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664227904; cv=pass;
        d=google.com; s=arc-20160816;
        b=Jsd9ZeBDTH1kbvTC6rnqpwpu56udf95XvQIG0yL9L8Em+Wxm3dJoBO4aKIoN5wEoVn
         Xl17pXZrF32Af631/y+TMnhs8CvDE4Lo895WwXKUSwRokqGtkvGdWfdTYFiP3gjLqn8U
         ScBj4xha8YNj1q9K55HfjTKhS/0uGzP20QLwPRMb0ODqF7GkyDa3FxzZTt1duSd6cmTo
         +l15k+LIFJQA0f2++5r8jFjbcK2/JAMZkKxdWK5pAKR67obgLzQqk3lpX01117QIr/oC
         PSji3dLs4+LwhjerSf1AYukN7u/wDCdB8C1zaV19M7inBsjIiDw6AnbWH5EpcpnBC1gc
         q9Og==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=ROSU/yKmsPdAa8UitL2BvbCEgrp4nVzC0cerYkzC/Fs=;
        b=LMXxuP1aFKAqh5KZ3WX1Wv/e3bD+TsmvTqld9SiMfgw/xUsHBoNEKhBzJ6PO3sRjJM
         mukQhs5InZ9bgGOQcYgSXTSJ6B2KSW/8xPF/tv6GZMLGjxx6qyEJsjPpPLubRrGTBQk9
         wypBiRV+HxlG7LIMei6sXuDcqw4Mq/OdT2wtUCRif/t8Fx3UCqpqUQzeFCZ5IA1ihIXM
         +IxTXWC0Ipn7DlgTojn5HEaKk9ilZNo04WQbRmytO/1XkjvcHGMA7qswzNC3AsSLwViK
         AAL3U2aPyXeD94YPcMkjXII+fp6jHJerLoWtUae7Lq4kiXu1U8UbeMVFdAknh87ZlM3K
         af2g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=JSF3Q0f9;
       spf=pass (google.com: domain of srs0=wzr3=z5=zx2c4.com=jason@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=WzR3=Z5=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date;
        bh=ROSU/yKmsPdAa8UitL2BvbCEgrp4nVzC0cerYkzC/Fs=;
        b=NtdpFcMZLE0eQfAE8uq6i4RIbXlo0u9ljNjyHgDO7WUNiXZ407QAhUTBg/YcyTFh8P
         azQPOyBGyKyrQeJVgfBYvO/M+EhRoT+XKEHP3POKqX8i4ZMG3BWkUX3HIQ6EhnVNMTkC
         soX41zHsFmQhj/7/Kg2PvjvSORnGHe22fo99iqmX3D2a/3aOGcoP8LHozODHVKPsVCHL
         vdyHuAVscQKNqynQMczDiCq/1FH2vr3k4S4iKSdbMNNFSGbXFjUw0UGqJD5n+2XxQPVj
         9z0Fj4e6yiVDyWFyxeHXbQHyC/pUrzGch4azA4/obAW52MyxAUXUZ7WQkX9cBMl0XYWT
         ow4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:from:to:cc
         :subject:date;
        bh=ROSU/yKmsPdAa8UitL2BvbCEgrp4nVzC0cerYkzC/Fs=;
        b=mFibHIjX+b/sN/jii7BDRr5aOjL7ivO4c62ctOhJGseFxn5sRVIE0nxXKzJibqXixf
         jdpBqOucYh6rdgn9WGnltILHGGys0dvHmeZdkJBca7G05ZC370vKsHqO0y2LD/IrJrSX
         7J2nCxEB9F0mfk17N1uANQVDLnqijBbuivyQlNg5FEK4t2n0KhOHNbWOnhawwip2EQcu
         AkvBq+xeMynPXrpjtsMi7i6dAhTcTWBHkxnQndGz8au/+9kksZD41LYXO4eWdqqnj0r9
         wnlC1Gd6rD9dFuQVuf1IwNMRkqjNAG5fwsZiahwZ9ujB5CRCvw1CHowgrV3q1+FqZm+h
         Eaow==
X-Gm-Message-State: ACrzQf1CjxM6cCy5+CXlxJe+1C3cqnw2cbup/tSHLfJRaY9cjlRRdvvy
	Z7i5BN07ToVzacDoWxyBsoY=
X-Google-Smtp-Source: AMsMyM6iF1DdEDW085xDVTVXxrJOWHnUlhjTDmauNBZehMq8uaJ7AbDI6D+Q4MfOpa8dx/1SUOecjA==
X-Received: by 2002:a17:907:ea5:b0:782:4c82:d0a2 with SMTP id ho37-20020a1709070ea500b007824c82d0a2mr20496514ejc.171.1664227903808;
        Mon, 26 Sep 2022 14:31:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:274b:b0:448:77f2:6859 with SMTP id
 z11-20020a056402274b00b0044877f26859ls823767edd.3.-pod-prod-gmail; Mon, 26
 Sep 2022 14:31:42 -0700 (PDT)
X-Received: by 2002:a05:6402:3486:b0:451:b8d3:c52c with SMTP id v6-20020a056402348600b00451b8d3c52cmr23914416edc.406.1664227902799;
        Mon, 26 Sep 2022 14:31:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664227902; cv=none;
        d=google.com; s=arc-20160816;
        b=ap18booaDQrip3+YX+r4X7zGVEvSJxkg5IxPnc73OrcqAcgQM32U0UqEcZcC1XGJp0
         nqPRZFmNS03cR6xdZenBi9VyBLcnDdP0J6lL91pR3bqF7aopPEP4TkAJRHtSpBFz9olH
         JgXmaSkk4CD65QQkloMeiJ0mW7b7/X2iAH/gNEU3vsR1/OExP6spoEZtqRuzFv4u/w+h
         T7tuU73snb4eyZrYeJqF1sZhR0CtgnSPa1nxLlfTZvjwFR8rrV7+c4ZKmSokmaOoR2jr
         dmTpQcIpor7tzAm34jUjcP84OG+pS3dITyoWl3JChEgrvyx3jd02pTR0HFVXzbFTUlo5
         Harw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=wSpLFm27xoetrBI5uTPMQazc/5C4ahgd2M/Py/ahUW8=;
        b=dy//jfsFZESilnTSkgJvdD62kQcxyECrtucLYy5m+E9jilBAp5t2BHltaaghNp+3VU
         zE5tHt5SxbHzs9hND/D0M4fZursR1LhnUA3yqtPd3MpV+1C3Agheohm5sXR1Utd+afew
         oU6hk7iWzNixVnOSsIRtveMGJex9DHSFE/MaV1N/hvpb6m2lFbLU3UCf2AT1wcL/u0YA
         ryzrjYOaSl6KWoyVyVXCOVP5EdnrjcbTBDs79vgOk+m+SdeyHbvmO/FEgn4fublcAvKT
         8hKlNqYEU+8y+HIEvZEZRktCGHXV1oIOiXjY4B13gtNbIGYwGSMBF7YPNxGPvs1lZB8A
         lH/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=JSF3Q0f9;
       spf=pass (google.com: domain of srs0=wzr3=z5=zx2c4.com=jason@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=WzR3=Z5=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id jx23-20020a170907761700b0077e2b420e6esi820898ejc.0.2022.09.26.14.31.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 26 Sep 2022 14:31:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=wzr3=z5=zx2c4.com=jason@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 5F04BB811CF;
	Mon, 26 Sep 2022 21:31:42 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 69695C433D7;
	Mon, 26 Sep 2022 21:31:40 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 01a7bf88 (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Mon, 26 Sep 2022 21:31:37 +0000 (UTC)
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com
Cc: "Jason A. Donenfeld" <Jason@zx2c4.com>,
	Kees Cook <keescook@chromium.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	stable@vger.kernel.org
Subject: [PATCH v2 1/2] random: split initialization into early step and later step
Date: Mon, 26 Sep 2022 23:31:29 +0200
Message-Id: <20220926213130.1508261-1-Jason@zx2c4.com>
MIME-Version: 1.0
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=JSF3Q0f9;       spf=pass
 (google.com: domain of srs0=wzr3=z5=zx2c4.com=jason@kernel.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=WzR3=Z5=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
X-Original-From: "Jason A. Donenfeld" <Jason@zx2c4.com>
Reply-To: "Jason A. Donenfeld" <Jason@zx2c4.com>
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

The full RNG initialization relies on some timestamps, made possible
with general functions like time_init() and timekeeping_init(). However,
these are only available rather late in initialization. Meanwhile, other
things, such as memory allocator functions, make use of the RNG much
earlier.

So split RNG initialization into two phases. We can give arch randomness
very early on, and then later, after timekeeping and such are available,
initialize the rest.

This ensures that, for example, slabs are properly randomized if RDRAND
is available. Without this, CONFIG_SLAB_FREELIST_RANDOM=y loses a degree
of its security, because its random seed is potentially deterministic,
since it hasn't yet incorporated RDRAND. It also makes it possible to
use a better seed in kfence, which currently relies on only the cycle
counter.

Another positive consequence is that on systems with RDRAND, running
with CONFIG_WARN_ALL_UNSEEDED_RANDOM=y results in no warnings at all.

Cc: Kees Cook <keescook@chromium.org>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: stable@vger.kernel.org
Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
---
 drivers/char/random.c  | 47 ++++++++++++++++++++++++------------------
 include/linux/random.h |  3 ++-
 init/main.c            | 17 +++++++--------
 3 files changed, 37 insertions(+), 30 deletions(-)

diff --git a/drivers/char/random.c b/drivers/char/random.c
index a90d96f4b3bb..1cb53495e8f7 100644
--- a/drivers/char/random.c
+++ b/drivers/char/random.c
@@ -772,18 +772,13 @@ static int random_pm_notification(struct notifier_block *nb, unsigned long actio
 static struct notifier_block pm_notifier = { .notifier_call = random_pm_notification };
 
 /*
- * The first collection of entropy occurs at system boot while interrupts
- * are still turned off. Here we push in latent entropy, RDSEED, a timestamp,
- * utsname(), and the command line. Depending on the above configuration knob,
- * RDSEED may be considered sufficient for initialization. Note that much
- * earlier setup may already have pushed entropy into the input pool by the
- * time we get here.
+ * This is called extremely early, before time keeping functionality is
+ * available, but arch randomness is. Interrupts are not yet enabled.
  */
-int __init random_init(const char *command_line)
+void __init random_init_early(const char *command_line)
 {
-	ktime_t now = ktime_get_real();
-	size_t i, longs, arch_bits;
 	unsigned long entropy[BLAKE2S_BLOCK_SIZE / sizeof(long)];
+	size_t i, longs, arch_bits;
 
 #if defined(LATENT_ENTROPY_PLUGIN)
 	static const u8 compiletime_seed[BLAKE2S_BLOCK_SIZE] __initconst __latent_entropy;
@@ -803,34 +798,46 @@ int __init random_init(const char *command_line)
 			i += longs;
 			continue;
 		}
-		entropy[0] = random_get_entropy();
-		_mix_pool_bytes(entropy, sizeof(*entropy));
 		arch_bits -= sizeof(*entropy) * 8;
 		++i;
 	}
-	_mix_pool_bytes(&now, sizeof(now));
-	_mix_pool_bytes(utsname(), sizeof(*(utsname())));
+
 	_mix_pool_bytes(command_line, strlen(command_line));
+
+	if (trust_cpu)
+		credit_init_bits(arch_bits);
+}
+
+/*
+ * This is called a little bit after the prior function, and now there is
+ * access to timestamps counters. Interrupts are not yet enabled.
+ */
+void __init random_init(void)
+{
+	unsigned long entropy = random_get_entropy();
+	ktime_t now = ktime_get_real();
+
+	_mix_pool_bytes(utsname(), sizeof(*(utsname())));
+	_mix_pool_bytes(&now, sizeof(now));
+	_mix_pool_bytes(&entropy, sizeof(entropy));
 	add_latent_entropy();
 
 	/*
-	 * If we were initialized by the bootloader before jump labels are
-	 * initialized, then we should enable the static branch here, where
+	 * If we were initialized by the cpu or bootloader before jump labels
+	 * are initialized, then we should enable the static branch here, where
 	 * it's guaranteed that jump labels have been initialized.
 	 */
 	if (!static_branch_likely(&crng_is_ready) && crng_init >= CRNG_READY)
 		crng_set_ready(NULL);
 
+	/* Reseed if already seeded by earlier phases. */
 	if (crng_ready())
 		crng_reseed();
-	else if (trust_cpu)
-		_credit_init_bits(arch_bits);
 
 	WARN_ON(register_pm_notifier(&pm_notifier));
 
-	WARN(!random_get_entropy(), "Missing cycle counter and fallback timer; RNG "
-				    "entropy collection will consequently suffer.");
-	return 0;
+	WARN(!entropy, "Missing cycle counter and fallback timer; RNG "
+		       "entropy collection will consequently suffer.");
 }
 
 /*
diff --git a/include/linux/random.h b/include/linux/random.h
index 3fec206487f6..a9e6e16f9774 100644
--- a/include/linux/random.h
+++ b/include/linux/random.h
@@ -72,7 +72,8 @@ static inline unsigned long get_random_canary(void)
 	return get_random_long() & CANARY_MASK;
 }
 
-int __init random_init(const char *command_line);
+void __init random_init_early(const char *command_line);
+void __init random_init(void);
 bool rng_is_initialized(void);
 int wait_for_random_bytes(void);
 
diff --git a/init/main.c b/init/main.c
index 1fe7942f5d4a..0866e5d0d467 100644
--- a/init/main.c
+++ b/init/main.c
@@ -976,6 +976,9 @@ asmlinkage __visible void __init __no_sanitize_address start_kernel(void)
 		parse_args("Setting extra init args", extra_init_args,
 			   NULL, 0, -1, -1, NULL, set_init_arg);
 
+	/* Architectural and non-timekeeping rng init, before allocator init */
+	random_init_early(command_line);
+
 	/*
 	 * These use large bootmem allocations and must precede
 	 * kmem_cache_init()
@@ -1035,17 +1038,13 @@ asmlinkage __visible void __init __no_sanitize_address start_kernel(void)
 	hrtimers_init();
 	softirq_init();
 	timekeeping_init();
-	kfence_init();
 	time_init();
 
-	/*
-	 * For best initial stack canary entropy, prepare it after:
-	 * - setup_arch() for any UEFI RNG entropy and boot cmdline access
-	 * - timekeeping_init() for ktime entropy used in random_init()
-	 * - time_init() for making random_get_entropy() work on some platforms
-	 * - random_init() to initialize the RNG from from early entropy sources
-	 */
-	random_init(command_line);
+	/* This must be after timekeeping is initialized */
+	random_init();
+
+	/* These make use of the fully initialized rng */
+	kfence_init();
 	boot_init_stack_canary();
 
 	perf_event_init();
-- 
2.37.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220926213130.1508261-1-Jason%40zx2c4.com.
