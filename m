Return-Path: <kasan-dev+bncBDAOJ6534YNBBGWBSS4QMGQEALCNYTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 74D319B97CB
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Nov 2024 19:40:27 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id ffacd0b85a97d-37d52ca258esf1118140f8f.3
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Nov 2024 11:40:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1730486427; cv=pass;
        d=google.com; s=arc-20240605;
        b=HuomhQ1Gog2ojepQOJmDte+lA5sbFR9LzN7YUXTQEGaPyKbPcvuK8S9zcDxoE7nraa
         yMZnGKaWNKcjhFa6IbIB+7KnFw2qeQIEMoEbzdB+533lVNxaWeuQ6sfgv0Kq/alccVNV
         RktIQV//Z3ReNUmf/29X3YmeTD+vRCt7afw+AX5feFVWqSaaKGM0IMZQ62ywlrQc9Uaf
         9DlQq18SzxrnEp7L8emlhynNYsUZ8MqijfJ2KTian8joEv0lQkx5rS9pClEBAmf8SG7n
         DPBJ/lKrxUh8VgldFhrTPKQEqteMRoUwLI0/fHA/1TInHX4USeZYoB251UjnYsESy9Wn
         iTmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=HGYxOe/9v818PoO2P6AZRXn0nATqnKfvgwwehj8Hkb0=;
        fh=ot7ztNflO8Z71gGX15bJIuHgTHLJoVmrkKUgc1c9JAw=;
        b=hxgCc/TMNM39JlLpnb7MrmMyxpMVkGouxMhVYpPe4pdH32rxF4irtLijqNMIB8c7Rx
         eNIjtN0p81iq9MsWI6pbE2v3GFMN5+/V3n4CWeufvJOSkjIG7F/cYYUbCWP+FFQmZTCP
         BH3PmrGJ1ULgMvtbzCRnGLlvdizM6+EjBvl/lU2rDHKGEzedD7WFg6wi73//Q2ddY6AE
         nHMw3hzZ4Z2kmLsqiiup1mON/msC2wrMH+y7Xybl8AdmW6wQYQlsv4qzb9FfpCUqnuEY
         iGEP9PP6wmN2ho1vTYDiJuhcVCsQsJSeJIfAiXKQ4XuJJI/Oxb0Rtaj5S3heXnNEIrpn
         UFLQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=KUkLFT22;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730486427; x=1731091227; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HGYxOe/9v818PoO2P6AZRXn0nATqnKfvgwwehj8Hkb0=;
        b=bvR2buW5J3M4rd+o9ypyjLwtJWaK/uHqBhlGZX6bbXEaUFzQJ/IaBkt2H84EkwC7M2
         mIlsIudaXXkJZbsKBweTzL0Gs6hvTBsWdZ3E28LFABCN32O0e1pAIiTgWTaG6bXh4I2H
         ejdXKk18MXt8PCWNtbK0qfnqyVAS93g2BBo6XtTYK/gUi+lbY159WbYaEHQMQF9JV4Fi
         pAju6G5bvKIk9v3TJmOBsGaC6RYAaSTKouoru3hSZ5uyVP5mT6MOydL/XVF3MI5j6EYO
         QetGlfjGGOma5kj1uYU8M7ilF6wneIN3/9783gX6szPw0AJTmAnLWgYY/sBMNfGswuXS
         6BxQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1730486427; x=1731091227; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=HGYxOe/9v818PoO2P6AZRXn0nATqnKfvgwwehj8Hkb0=;
        b=bZULQftSAFT6wQBKTtT2oNyK+IJzOT1r9s/ufqV5Ge1coDjob9nQGp8iszvhdqba3f
         djpx+q2OwmIhlHmykM3czojqe7+NhxxodDxJbtG0JPjBqnCEgDTBf687QM18TBQABRJO
         MxsIRGSpWSU1m5taLu372hzOsmVJx5Hp0ks8i9Z5lTUmdTAHTlC6ivAQ7+Aznc5wXCSD
         g1S2CTXXaYrtVuOGfrtw1dMTwZp81Ag4UklzwvGTQxpjrgJSQUTLDaIiR1oezGSItpfV
         MIbBPBi+gt4sxRXcQo8TDk9ym9eA4NR7kSC4vQZEHcU7tTZUJcbzxgQJ5ZF3VWhtPJxF
         mVmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730486427; x=1731091227;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=HGYxOe/9v818PoO2P6AZRXn0nATqnKfvgwwehj8Hkb0=;
        b=rVXKHIeQFnYLMot2i4uGPVYPppolJHV5FpD5orm45u+YwwN8XUGRmVuXRP7UGZi8iJ
         slfTOxdG+Dxkt/PA0CKSOLIkFvmcS6lI8vJQe0OSYK46iyCbRkt0libbYlgYLz4s74Vo
         ATvc7YTx42PTWgoqJmWxkcRO779juVHQVx7hEXxMexZHY/A8+8/IxEqssI7tJxdetCnR
         VJn9/hbHWzWG9iU3g3XwZr9xSXITAzKYnFyM7qb54wmX/M9NjIzxCKJ2aKkg5RH7DAai
         YFB/lTdzkFOee9MO0KA4/yRZ5aVolwzce+WNd64jEQreWO0bum8Lcit6eTvVTCgDLpae
         M1NQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV4jKtxW0a9KWsMA4WOU6eG8ECyiHcq8etptrl5UE/0CBdP6QDRw++jqD7xvaSwDyLj7vhy6w==@lfdr.de
X-Gm-Message-State: AOJu0YyE1sGH0YO0X37jPEhemh6sPEUo4dZznioPr7OAyNP//S17wtgf
	MuRL1a6+EJjayMy1DQ/PTaWmYzvnb+N+yjLgBJXMQA3H1v4e6x+/
X-Google-Smtp-Source: AGHT+IEDUdnDv6h22k0atg85tYzUG1hvVx5T0m7y+kDutROHitJ/PEEaIgRvgGnYcdcqbckfJgFhSQ==
X-Received: by 2002:a05:6000:1046:b0:37c:d537:9dc0 with SMTP id ffacd0b85a97d-381b70578bemr8379631f8f.12.1730486426605;
        Fri, 01 Nov 2024 11:40:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f58e:0:b0:368:4489:3f45 with SMTP id ffacd0b85a97d-381bea233ecls606917f8f.2.-pod-prod-01-eu;
 Fri, 01 Nov 2024 11:40:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUC3FGCjgST0G5L260BGRywS6PO0DaoN/JTUlvhbX7t+O6bppqirB5FUkPE21hPfEaEeOKjofgaOq8=@googlegroups.com
X-Received: by 2002:a05:6000:1549:b0:37d:3e8c:f708 with SMTP id ffacd0b85a97d-381b70767camr9346830f8f.20.1730486424880;
        Fri, 01 Nov 2024 11:40:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1730486424; cv=none;
        d=google.com; s=arc-20240605;
        b=FoTcgeTFN0rcde7tf+UHCuNShYgRbd+f6esN+cMDK8m0KmJghYW77T3uRNUEWJ4p+l
         hukBz0Jfivu+q5FkVJhDrCWXxofJ6UhZa11wsQvG1OrQFAiPHuAogEvjz0ExcDfOSBNN
         sNsQOIx7Troh4titOmVSCRp45up81NfAye5FsPIsr9CXAjviKxYfnXN54d/XX+z8Je7N
         3aI1zcRBIL4TWmQXysAtZgKEpO0f3CiGZLsnfpgettPhaObXI1w2M+xdjsNupS6dX07Z
         4MMa9tylASUK8zvCrel2sxjvyQ+1bSFV5VdZh1KhQbqhMpxg3lMhTTJZchDVvMxjh5zy
         3H7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=vvvOwVHZ4i14J6dT/7UuF/SG7t5JsDpEeQt8L7cE6aI=;
        fh=NSPNiue/bkIljAbheiPwfZfFAIL7d2SBKD6WUeA/EOA=;
        b=RW7jgPYu0KurMUOj4ZGOOqRzAkFZbpleJCjsQrWzuNXVyX7HJSIsF5d/x1AT9F2WNF
         5D64j5TciPq36YO66b/Uy5fQ1kO4XYrMnSCcbxyGmjqSvhbxUGHu+6f0X3g1PthRU9Zh
         eJ996lrwdCCr7X8HG4EcUqkSiBlV/lFl+9MlQR7ixMV8pJxUsqMS5oWg17C4lBj9pPwa
         0jbqbFlCmsNDVZi66WzBnpYK2CZoKrwAelRdRMHOyEcJGBHjy0RbNdPKuOHkJVFTVDD2
         Evjj2Ei1xYVuWD62obn6XHoLU/7rcbhFcMo03jIBQnEsWqgGjhIuorQI0aQ70YQPiTba
         0fNA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=KUkLFT22;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x133.google.com (mail-lf1-x133.google.com. [2a00:1450:4864:20::133])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-381c11870afsi93219f8f.5.2024.11.01.11.40.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Nov 2024 11:40:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) client-ip=2a00:1450:4864:20::133;
Received: by mail-lf1-x133.google.com with SMTP id 2adb3069b0e04-539f72c8fc1so206582e87.1
        for <kasan-dev@googlegroups.com>; Fri, 01 Nov 2024 11:40:24 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU65NV7PI18ZJVr6um/JiQSlT5ph6oFfHyj1XwjjWbeNZQylxRXsApe7v9Oie0Oy5cVngmCBFu3hWc=@googlegroups.com
X-Received: by 2002:a05:6512:a87:b0:53b:27ba:2d11 with SMTP id 2adb3069b0e04-53b7ece09bamr7284478e87.16.1730486423951;
        Fri, 01 Nov 2024 11:40:23 -0700 (PDT)
Received: from work.. (2.133.25.254.dynamic.telecom.kz. [2.133.25.254])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-53c7bc957cbsm646821e87.60.2024.11.01.11.40.21
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 01 Nov 2024 11:40:23 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: ryabinin.a.a@gmail.com,
	andreyknvl@gmail.com,
	elver@google.com
Cc: arnd@kernel.org,
	glider@google.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	akpm@linux-foundation.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	snovitoll@gmail.com
Subject: [PATCH 2/2] kasan: change kasan_atomics kunit test as KUNIT_CASE_SLOW
Date: Fri,  1 Nov 2024 23:40:11 +0500
Message-Id: <20241101184011.3369247-3-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20241101184011.3369247-1-snovitoll@gmail.com>
References: <20241101184011.3369247-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=KUkLFT22;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::133
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

During running KASAN Kunit tests with CONFIG_KASAN enabled, the
following "warning" is reported by kunit framework:

	# kasan_atomics: Test should be marked slow (runtime: 2.604703115s)

It took 2.6 seconds on my PC (Intel(R) Core(TM) i7-7700K CPU @ 4.20GHz),
apparently, due to multiple atomic checks in kasan_atomics_helper().

Let's mark it with KUNIT_CASE_SLOW which reports now as:

	# kasan_atomics.speed: slow

Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
 mm/kasan/kasan_test_c.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
index 3e495c09342e..3946fc89a979 100644
--- a/mm/kasan/kasan_test_c.c
+++ b/mm/kasan/kasan_test_c.c
@@ -2020,7 +2020,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(kasan_strings),
 	KUNIT_CASE(kasan_bitops_generic),
 	KUNIT_CASE(kasan_bitops_tags),
-	KUNIT_CASE(kasan_atomics),
+	KUNIT_CASE_SLOW(kasan_atomics),
 	KUNIT_CASE(vmalloc_helpers_tags),
 	KUNIT_CASE(vmalloc_oob),
 	KUNIT_CASE(vmap_tags),
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241101184011.3369247-3-snovitoll%40gmail.com.
