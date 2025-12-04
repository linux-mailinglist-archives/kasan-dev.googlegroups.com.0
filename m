Return-Path: <kasan-dev+bncBDP53XW3ZQCBBAFOY3EQMGQE4M6ZIVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id A2505CA3F61
	for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 15:13:21 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id ffacd0b85a97d-42e2e448d01sf1000752f8f.1
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 06:13:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764857601; cv=pass;
        d=google.com; s=arc-20240605;
        b=RuqujSqY4xgFzGc3bSz/qm4XtxSdO5YQ78LghVxvntqHFZvN1ykI8TvIOgvASYVR+G
         opl6meF7VfW8uzcoeMBrN7A3Eo2yp4LSlNMdHOoec6NoCBZHUNy2Sp3CFG37O45T0/Zp
         FREurO04fI9xgpmxYHnzPUbT7u0M44sy4/NmAWjynlXd3fG/W6lHcoErmAms3Ecpy4Vb
         of6lQc2e34x3NIJYniOBN88JvOWfpBSSGfvRb8XKxZPHM5WLzROFJ/L1/lPV2RKcRHHF
         sqUQT1C4yMKF6yUy6I5uZFqJFk1EWHu/W7d1MQ7U4c/xgBKdGG9SRi9CUtzro1aJzwac
         cYWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=ftgowfFZW8ewMDMbtMy4rC0gHPk0RNF86CvNj4h5LPw=;
        fh=hKxU0PGL+cY2hYqE0LnCwBBTfk5SQ3DXvZrZqcBexVU=;
        b=JvOrtBCR/i8vK20/borwYzcqSOFuNe1BGvt7ADhvRKeLfuRiLh3mTRvUL//Wgbtq6Z
         EJR7zweFR/NrDm7HS3MjHh/jaYtwITOFTXqSZCuCqlAWDSaE5qIyV8JjHuETmL8x5vWN
         FjOZ7MNjZO+QujYpEgGKH5RWdTdYFOdcYquZ+da9ZkD7BS/KC8XipT5mYca5OOBq4VMs
         Fc5j77QcP69NllKPOBnUJabqhOh2AuBg3FCY36ZsMEDUXynTVFVAIRX41VbQko7gvxfE
         mexII5Qlm+tecCvPEy1+cZPeR9aWXHnWBDu8e5gtPSrOhAUzasuS2J7S1+d7B+8RrNiS
         OKig==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=At0C67Lt;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764857601; x=1765462401; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ftgowfFZW8ewMDMbtMy4rC0gHPk0RNF86CvNj4h5LPw=;
        b=F5JgeE6u6qY9aPhf4zJpZpHJ1OamEkxZe6GpgB6yWoBjfRtdg1Z/mj2re7wqmsfsO2
         N34OGe8eOeutyLkJeRt+6mAYEGQmMr8q95HLw4xWgL8E/IUTmkV842qnTsKL+fZuTh8R
         D0X3QvTJXeE2KxMm6P2BCRhK6slO+ZrawMMid3/omVgNczKmw01VKaylmx2toyTIjgOm
         X1oHSadrqwT57sXII83MVeoDk80CBqMhjzTxTpM/3x7i1uMARdynJK0VgMcCnzRajL4y
         5wY15Dm9Hz/e1jvUBnM2qrbuBb9H/3kSSBediyTTptuSdrRjhtORnTjl8m/ZRube6QNv
         QfeQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1764857601; x=1765462401; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=ftgowfFZW8ewMDMbtMy4rC0gHPk0RNF86CvNj4h5LPw=;
        b=SqEaucQkIKHNGxxPaxhIgeROTU0labjMDDlbzZrMFNPH82LXuZTYTuxpM5ST+hC60t
         /BNQBEvF3tF73Fribh5J+9r229QrpJrQ+jBHVmm6QE9d+7JnRnI/RX9extc4vl5dOMCy
         PYsDOi68OFHZIeCey3rgdXg8bxJHEtYLJYFCsnbLzo1dDyOysa0i2Unmi2pMuTI7lmR7
         MUPm0bxzdf3kYl5QWyGSEhHZPG8i84MxADTp+NTL/8AG8qB3u57ojUI49BH9at5S5asq
         k3FcslYxf6BeJOS7z7aou9VnnYBe/i36ge3RcsI0UKlW1271F8WuVtNvOyJOoS1LG02l
         zbGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764857601; x=1765462401;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ftgowfFZW8ewMDMbtMy4rC0gHPk0RNF86CvNj4h5LPw=;
        b=c4CMmqdPaM+wBmRBIOVhUgvInIeAV1cMzWqdkuafvfO9I19ezZb6JAtrSOU0kS+b/8
         RWuGGaYDoouNQ/WpwAk7Clwy8+sgLQvUqCtlfUYTZfbMV1+QvL/hYTvq1Aw2BNzi27oN
         CUjId314vJe9jsEXl0pBw/dC6PusjJz9uTL4SWjE9BbjmBKIB+J/5LtOrzUjg/JJY7EC
         7CDD/5qbqOWxkyiKuUdnoEUAgiuErHblS+QiVfUTx5LIZdH1Gu8xgknT+76BcL3xCr7i
         +PJDTJP9l23RwGs4fek71s1VHUpF1bThnC2D5d9Njo0Wrga0xcEleUiVqrCqq6UTDMuD
         bEyQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWnPcIX6AYsInWzTayOZeErYeP3/0DmbO3wNBtwfzD0H0rAXWfWEDVSKmmtAuLEtYh9uMazhQ==@lfdr.de
X-Gm-Message-State: AOJu0YxlLYiig+DFIjNWRo5YCF/VZTJDUvQJU/LJOlhss8t+3aIeZIEv
	1G29Y0Ff1VwMaG27ydut0ifmKE9pw0J2AmQtxC0Pp61wZPOuNIFe93Zh
X-Google-Smtp-Source: AGHT+IFlZOBEdRzEYDX9emIFgehuwdZv4qtK0awNtXZI2LhBNW8MlcZoP3H7K3CCwIBl/mCi6/GWOg==
X-Received: by 2002:a05:6000:4305:b0:42b:40b5:e683 with SMTP id ffacd0b85a97d-42f797fe042mr3005256f8f.23.1764857600921;
        Thu, 04 Dec 2025 06:13:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZSBWAdkDxTR44w1ueoJJ/3cUyuS4cjsiLHmHTyCIPUow=="
Received: by 2002:a05:6000:3107:b0:429:bfb1:8a7f with SMTP id
 ffacd0b85a97d-42f7b2ed88dls487192f8f.2.-pod-prod-07-eu; Thu, 04 Dec 2025
 06:13:18 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU9tHxuiuqQ+1GaIvru9b8RGDk6psKukVBgjaohejM5kqtqrFvcrL1JIzARvxBodF8LtG9yeh1iQTA=@googlegroups.com
X-Received: by 2002:a05:6000:144c:b0:3e8:b4cb:c3dc with SMTP id ffacd0b85a97d-42f79514872mr3363257f8f.3.1764857598019;
        Thu, 04 Dec 2025 06:13:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764857598; cv=none;
        d=google.com; s=arc-20240605;
        b=Lu6rcX9MDYOfTM/lwMWFPOV1uC58osxkOpK5IA9hgSqyfrm7hQ1uNYFDhNIyO5GLzz
         vaTfeWhFwh6ZknBd48oaXsTlIsYDl4oCOlqZFMC754MHKUVlQdvVQEQ2c1RjxjKknuOX
         ftbVKqPT8BFp+SNudyZYQ8IpdWlIBJaEWeOESn6/oqx3bA2+yYR3A8F3MzoWCLvpbpLO
         2ba96Rs15oGY/BKSK3MBaIMGK9XiB50xpbBudlb67glX/Esnzyt4E3vmcE8ZgA1myiqZ
         HU7weIquAaS33qSreDIRZN4W6NzlLCTS9FkePM5/Mz5LmTCieJFPEbbhSr6hVLG8Pt2V
         jSBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Ekn2DBIpCkQXanmNkedEYdcryjYDg+bStsY06P8Miig=;
        fh=plOZ5MTtXb+7i+JYd11BpgfgFNbr/yyp/N9EG58dh1w=;
        b=kAGlyaOtwUvEa4osL2m2uzExnfwAg545sbP6AWvmDyYFcfxkHNxA2SLcx//kNL5u96
         dMTMfVOoWIo0Qvk3873KE/KM1SBHr9cWj4KxK1me+iKE6QLUSN6wFDW4N609TSN8myIo
         AgwsO+dYX3ooEzlMUB5ZHXrvq9UH/Lu0LthtWh/gwpc3lMfNoFPv6HCKIiJHPhHsF0Ky
         kPQhD3YaCNh7DhtA8/x1A1/gtm4vqvsHyHou7ihWj5P4WzOOhw1uZo/9jbd1JVSZa81K
         wvzzTmrbhM/cRAViyeK9mUQHeGfEw6z3s9BPcdHYCEisjteWTcLCsA6l2jiV8CDyaWzW
         BVcQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=At0C67Lt;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x433.google.com (mail-wr1-x433.google.com. [2a00:1450:4864:20::433])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-42f7d21e315si32705f8f.8.2025.12.04.06.13.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Dec 2025 06:13:18 -0800 (PST)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) client-ip=2a00:1450:4864:20::433;
Received: by mail-wr1-x433.google.com with SMTP id ffacd0b85a97d-42e2e40582eso614467f8f.1
        for <kasan-dev@googlegroups.com>; Thu, 04 Dec 2025 06:13:17 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUuog2bHApVYRrp0RimZA4XqePRJ/9yM7Dj/mIWQMFF47DZJsFDW3+VJTDvYs82S0Op5p2hWqA7SBY=@googlegroups.com
X-Gm-Gg: ASbGncuG5LSTfRzrT+5+L4fi8bq7/S1bJVNAfM9R+zH7mRQM6UQ/8zv7unkOf56CUCO
	kVBQgG6v4omxhMmEqIA2C3fHFvMHPjxbLDmdjEM8+0+LH9SslrEVMcdTtdVs1Pu1PMU6HYSFWby
	ETU3+yQqcZSbe52V+EN6rSyrbVEL57OQZP9JfyCLvtzBxfH72KpKBwrxY5krW09YwAjcLK5uOjV
	AGc28OhpTn7s/tRJ7SzAapk+XMO+yxfyYeHv9Kh11i7ukmi0s0jClFVEE+buyT0xFOzmCw9KFBG
	sM8wTHVTBEbT4+Jxv8Qy7SSYl9QhEdOJi3l2FnZNWeDHqDIvpcWaWRW+KGg6WblcD/q8psq5PI2
	426J6GwD13j3NfH+QADLdDQbb8dkYRkM3jc+u7nEPXcRyab2q4T4UTJ4OnehpOHfJqzxweOeBbd
	qcC4Inubz+/qGp1Sj1h1gRr5q+TUJjZO1w5j1Xw4qksfcA4M9hjb100cGEYBU3Z0C80g==
X-Received: by 2002:a05:6000:144c:b0:3e8:b4cb:c3dc with SMTP id ffacd0b85a97d-42f79514872mr3363210f8f.3.1764857597333;
        Thu, 04 Dec 2025 06:13:17 -0800 (PST)
Received: from ethan-tp.d.ethz.ch (2001-67c-10ec-5744-8000--626.net6.ethz.ch. [2001:67c:10ec:5744:8000::626])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-42f7cbfeae9sm3605808f8f.13.2025.12.04.06.13.16
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Dec 2025 06:13:16 -0800 (PST)
From: Ethan Graham <ethan.w.s.graham@gmail.com>
To: ethan.w.s.graham@gmail.com,
	glider@google.com
Cc: andreyknvl@gmail.com,
	andy@kernel.org,
	andy.shevchenko@gmail.com,
	brauner@kernel.org,
	brendan.higgins@linux.dev,
	davem@davemloft.net,
	davidgow@google.com,
	dhowells@redhat.com,
	dvyukov@google.com,
	elver@google.com,
	herbert@gondor.apana.org.au,
	ignat@cloudflare.com,
	jack@suse.cz,
	jannh@google.com,
	johannes@sipsolutions.net,
	kasan-dev@googlegroups.com,
	kees@kernel.org,
	kunit-dev@googlegroups.com,
	linux-crypto@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	lukas@wunner.de,
	rmoar@google.com,
	shuah@kernel.org,
	sj@kernel.org,
	tarasmadan@google.com,
	Ethan Graham <ethangraham@google.com>
Subject: [PATCH 09/10] drivers/auxdisplay: add a KFuzzTest for parse_xy()
Date: Thu,  4 Dec 2025 15:12:48 +0100
Message-ID: <20251204141250.21114-10-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20251204141250.21114-1-ethan.w.s.graham@gmail.com>
References: <20251204141250.21114-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=At0C67Lt;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

From: Ethan Graham <ethangraham@google.com>

Add a KFuzzTest fuzzer for the parse_xy() function, located in a new
file under /drivers/auxdisplay/tests.

To validate the correctness and effectiveness of this KFuzzTest target,
a bug was injected into parse_xy() like so:

drivers/auxdisplay/charlcd.c:179
- s = p;
+ s = p + 1;

Although a simple off-by-one bug, it requires a specific input sequence
in order to trigger it, thus demonstrating the power of pairing
KFuzzTest with a coverage-guided fuzzer like syzkaller.

Signed-off-by: Ethan Graham <ethangraham@google.com>
Signed-off-by: Ethan Graham <ethan.w.s.graham@gmail.com>
Acked-by: Alexander Potapenko <glider@google.com>

---
PR v3:
- Remove conditional inclusion of charlcd_kfuzz.c from charlcd.c, as
  requested by Andy Shevchenko.
- Update auxdisplay Makefile to conditionally build charlcd_kfuzz.c when
  CONFIG_KFUZZTEST=y, as suggested by Lukas Wunner and Andy Shevchenko.
- Foward declare parse_xy in charlcd_kfuzz.c.
---
---
 drivers/auxdisplay/Makefile              |  3 +++
 drivers/auxdisplay/tests/charlcd_kfuzz.c | 22 ++++++++++++++++++++++
 2 files changed, 25 insertions(+)
 create mode 100644 drivers/auxdisplay/tests/charlcd_kfuzz.c

diff --git a/drivers/auxdisplay/Makefile b/drivers/auxdisplay/Makefile
index f5c13ed1cd4f..af00b0a173de 100644
--- a/drivers/auxdisplay/Makefile
+++ b/drivers/auxdisplay/Makefile
@@ -6,6 +6,9 @@
 obj-$(CONFIG_ARM_CHARLCD)	+= arm-charlcd.o
 obj-$(CONFIG_CFAG12864B)	+= cfag12864b.o cfag12864bfb.o
 obj-$(CONFIG_CHARLCD)		+= charlcd.o
+ifeq ($(CONFIG_KFUZZTEST),y)
+CFLAGS_charlcd.o += -include $(src)/tests/charlcd_kfuzz.c
+endif
 obj-$(CONFIG_HD44780_COMMON)	+= hd44780_common.o
 obj-$(CONFIG_HD44780)		+= hd44780.o
 obj-$(CONFIG_HT16K33)		+= ht16k33.o
diff --git a/drivers/auxdisplay/tests/charlcd_kfuzz.c b/drivers/auxdisplay/tests/charlcd_kfuzz.c
new file mode 100644
index 000000000000..3adf510f4356
--- /dev/null
+++ b/drivers/auxdisplay/tests/charlcd_kfuzz.c
@@ -0,0 +1,22 @@
+// SPDX-License-Identifier: GPL-2.0-or-later
+/*
+ * charlcd KFuzzTest target
+ *
+ * Copyright 2025 Google LLC
+ */
+#include <linux/kfuzztest.h>
+
+struct parse_xy_arg {
+	const char *s;
+};
+
+static bool parse_xy(const char *s, unsigned long *x, unsigned long *y);
+
+FUZZ_TEST(test_parse_xy, struct parse_xy_arg)
+{
+	unsigned long x, y;
+
+	KFUZZTEST_EXPECT_NOT_NULL(parse_xy_arg, s);
+	KFUZZTEST_ANNOTATE_STRING(parse_xy_arg, s);
+	parse_xy(arg->s, &x, &y);
+}
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251204141250.21114-10-ethan.w.s.graham%40gmail.com.
