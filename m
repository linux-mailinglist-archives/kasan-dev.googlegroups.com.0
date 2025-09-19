Return-Path: <kasan-dev+bncBDP53XW3ZQCBBAG7WXDAMGQEGGGFOFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6290BB8A1FD
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 16:58:10 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-35f62a3c170sf14311451fa.0
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 07:58:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758293889; cv=pass;
        d=google.com; s=arc-20240605;
        b=UBeIe1F3s9VGhgfKOHxGE6M6bUYmmc1JfdDBqb/gBmd6MPqrUsmdJKD3jdWC5iQr48
         SzL1vcOQ+yB7lld/HYyIx0nSyv9hRAHC0fDgvLhyBPDwfbhSxghDyhPWXeDZYRtWIM+j
         i6cehhedxDfwmKtWZvVIVoSk6aaYMfd/vYJaqWtCn1DOchOMGEAMSbyFv6+RUp3mXAdi
         VXmzkPPgmi+amaCmt+VhkCfJV+IZdBFMpNvg4eyKgNlPR4OhHexIgYL4JaZH+q5ePUvK
         1KDdI2ZVPnrREzVB9Gv0X4kXhaMteqJjVv1IQAnRX29PmlEJZjtClhqr1lk+LOHjlE9F
         if4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=NDZl5PuQz4+c4dXGoxJacWnSL5Mt4Z+QPnAeAs7Z2XY=;
        fh=27opHWHjy8W2re2QqO9mN0LneQiaXll+h1Sdd0pz4hE=;
        b=als/WFA8SyvVc+NvzEwCjxJVQtGgqnzTV6LN1LpTJm68LOR2G8hQ9Z+Y/lNStKNl94
         sN+kihk2rSquOxhgbCfmMjx1FeBdY9W7n38CmZyfDbTvkoioR+n4VpoPZXyA6rBGZkbn
         cy5Fy5SmQ3pYFKeFncIMfsirTqnh4WIZRjOk8gARLI4uFNwQP8JatT9nFNxuM8ycvchf
         fMARdNfxeWeRVbKNlKTUZbamntc8Lp/CcIhK1/chs/HXZzCXdiecokhIjRxlWth4tGi8
         LK4rnMkB/e9X6bFFYjxk0cMy4cKKCcq3cfOveqpYtNOXT/PLomQMt2pdmjNIH6vL4lkH
         5VzA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=XrddJ9ag;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758293889; x=1758898689; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NDZl5PuQz4+c4dXGoxJacWnSL5Mt4Z+QPnAeAs7Z2XY=;
        b=xfURDrfzs73AKbP+FmfQVt5Z8+2Iple8MZCHffDIkIdDhMVH0eh3uyPKxoAd78M0su
         LbXq2go7uRtQOVxvIhlWTv7DWvhMwVhwtuGWK11uZK61YjCUDJM34FGfkfzGQcC1pOaQ
         BauXtMVAJg1urE84Afq70pxM0Qj/NEJxujpq49agvPN/alFX6HOprMD63UYY5v+sqbgW
         bLchrn70Qu9sunHOGC2iCmBbnEX0Bo63hTHnYMT0DQpJ079LmqTonsvxd/xn0B1S6vnl
         rUIYYr8eoB1tA7QJw+VCgQqtGVDIMeMHM9Q5ixHfKnxy2HnbG7BLY+Gy/KSkUXl2isCN
         RXLg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758293889; x=1758898689; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=NDZl5PuQz4+c4dXGoxJacWnSL5Mt4Z+QPnAeAs7Z2XY=;
        b=QxH3YzhZFo7X/Ssc7PwRDW5ZCOgAaP4Oa4XVa8Y2bBWFpSrRPSRaV6CsdISJ+/XV0H
         H+dJrv+07TLZCsMvCNDOW837LVjKYEQ61JTBx3Abxdk4Ng6wed9uf+5xR+sZHfwVfREx
         UTrYEqCUp6vczyWVfA90t3tCsw02QcorLhk9CkJ33sS+4R/vJcI/b1wcHROf74LNY2Tq
         P3CNjWQ++wblQ2UEVjLuO5siWhVv7bqsUKHALXR2Ljg921eZbgYc1zS57SeXSfvNS6dR
         ayjt7ixGz2SKCGL/h83OyltiS8y1na2hyYH7ZsbCGUFqtDq+vNNd+dZGQT/uD1qh5UE3
         030A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758293889; x=1758898689;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NDZl5PuQz4+c4dXGoxJacWnSL5Mt4Z+QPnAeAs7Z2XY=;
        b=sN+nYx80RlgFyS1wrRtzFbwraKoiKpMeiyOwWYYT1C5cFhtjsti91KgB+DnhbwpLV9
         aLl8p/kIsCbacvLt8iAqojINa8PgwtT8ucpl2PeKMOTp1zFxGC+9aDhoXpY4sAJnkGwB
         GGUR7CSGMFGZuSSklrhjDab2WPIsAtwHXk/SmujNy07IIY+OsN4f6/pwIKYoIURXMi9n
         UwoNPNlyzSUFHmAOABTHjIr53+6GVSvEYfrMGnhIR6kJededgtQy77IQGwrqp6/pYTq4
         byeyfMUImVm4mu5m2Ww9S7mmh3pIdLm/T0dtzzDaVzhqwlw3nsnFWXGzzOU4EIL89gUF
         RG0Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVYOyiPezOW1nZB47Vs3U/gyPAgD6yeTnpFcVUVQOAz7f92RcXCPawwNqp50qn5RmDQhcB4Gg==@lfdr.de
X-Gm-Message-State: AOJu0YwcQqXLoYftHNZFWGbhZCgkmSf5bxljTMo9i6DNP5vw6yF9FgzZ
	9bhNUHr3bhNzOPF/Oai7y9HE9ApqtusiHoIHW+9dB6IPj7gbZsZWwxz+
X-Google-Smtp-Source: AGHT+IFYvbrERI1uqE0bfLnm3Hzme4bZ6SflLD3kLAretmEtQADK16it/5FlNV0F6GpUZTyVqkq71A==
X-Received: by 2002:a05:651c:10bb:b0:361:e39a:b758 with SMTP id 38308e7fff4ca-3641612dc94mr8784691fa.5.1758293889465;
        Fri, 19 Sep 2025 07:58:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7EGQ9lEPllemzee8OAspWrUL3EUs8ELjM7TZ/npnEBAw==
Received: by 2002:a05:651c:2ce:b0:336:aebe:27fd with SMTP id
 38308e7fff4ca-361c7c6e55dls5250951fa.2.-pod-prod-09-eu; Fri, 19 Sep 2025
 07:58:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWBMYMy6AJ+0Jx5kyMJopivDLiePYdfTwndb9VNXfpccVGALQyQJebyX52WzCaqeGwFQHnl0jO3WGI=@googlegroups.com
X-Received: by 2002:a05:651c:3257:10b0:355:3e93:812 with SMTP id 38308e7fff4ca-3641612ca88mr10120381fa.8.1758293886010;
        Fri, 19 Sep 2025 07:58:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758293886; cv=none;
        d=google.com; s=arc-20240605;
        b=D97jMylMczZusn3EYiItHDzGUxPD3OH9PIDU7muf6Qeo+HhUSVdL4R13TIK4miucRW
         71f3I+mgrNxBZLBpO1KCDGz/D78W+EO/rprVFcBGlZ+2dEY5Q4W+4C7P4Sgz2ORFfWBQ
         BzcXYVbW4wIJJ1Xu7M7mhG8h68TpXmIbq+e2xW25JTZjFAeWndkv/GwFx1VcZteWkDCQ
         gG735m/kI8AMXTwWd7uKL2pQdl2LEuU36+MdNprWX+nZ1h1Gy3ooygR5q+Pyor0uBi9/
         PJj5Yg5FevzUz4OZu0PgSOv/wbj/vE7Gh/AJbdlVOPlf7ExfqD8kzJFPxzDDAM+dJErO
         ivPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=wa5F8osjsxPwGqDjaoLyZTZuU1vO95PkOFG1IS0GKrs=;
        fh=EEo5LHmMMlfXuXm+DIygCA8Z4rfjN4YdQPIrOzVSVM0=;
        b=UYhhskp9JWAeKbxzwr7B3l80bgKAq8uBT6TSyMxvENGelSgK1A/rXgwTsU5IWn2t83
         nGKnX2uMRFUlrokAkr4++YuBnuxK+GknUffSoTg3LQmIdbaLuFyE5goxCiF3cxFmQ3De
         So7Q8DND5kMxagnn4fcMPe1VFWqQ4Yx6y0nzgJOdCIhK09JATojjHfofrthaxSyL/5ME
         2mC7DnZJHGZEMSk6VAJWwD8FlLPkK3csQb9slwGDoKOk2ojtmWX30y8y2deRI3uKY+a+
         1nMxiLlwMBq2ph2L0peY6mXItptgOKwRLlIAnMnKwuBl6HwnqcwV1ciBGRwT3eWYrCyt
         +A2w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=XrddJ9ag;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x332.google.com (mail-wm1-x332.google.com. [2a00:1450:4864:20::332])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-361a7924ec9si982451fa.7.2025.09.19.07.58.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Sep 2025 07:58:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) client-ip=2a00:1450:4864:20::332;
Received: by mail-wm1-x332.google.com with SMTP id 5b1f17b1804b1-45f2313dd86so20132785e9.2
        for <kasan-dev@googlegroups.com>; Fri, 19 Sep 2025 07:58:05 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW0QAr9SUopxXD2JI1hzNVrnqVe8v5YRsHbwQvmq/Omj7ACdKfJI3xCignwyzyt3PWTxD27sFWwH08=@googlegroups.com
X-Gm-Gg: ASbGncs1xbNKQ2ahQjj3pSWL3KDmzGza0aCruTUDLZ3j7k4U2m8MQ12TubTIM+x8jYL
	dtylXZWP0ICkN62EsmtgkixuWq+gmK06+FmaHUy2xsiH1O9NtgoGSHo/RsrvEG/VaDV9Oy1/+LQ
	Y9BBIpm4pVSrRzLraapB6lnjBfL/Kc4hiSF/lvW7w8Z6ABq6Lb+bWCT84hW+W0pr7HoaKI+RI/l
	rTiHHxT4FFPZjvrtnwMAMvqstPEwmE+F19nzf8tu5e+465k61PQHb/DrHpIkIm7hZ2rhc1dGlGD
	YPDrLNsLVGRBNHSUdEgN8oVmeTEtS38OiDD5KQs6FlvZW+BUy5hThUwijqQ2I1ibGQyTMj4TY+C
	uBd7v0yPAMUmy8x9nzsM8ohBS7C7/P6BfKSE/TX+v4oT053FbdW19s7THfCXW67zwjIBClK16U2
	pDtPpTIex+nA6XlWU=
X-Received: by 2002:a05:600c:4ecb:b0:45f:2bdd:c959 with SMTP id 5b1f17b1804b1-4684c13ec45mr31051625e9.8.1758293885086;
        Fri, 19 Sep 2025 07:58:05 -0700 (PDT)
Received: from xl-nested.c.googlers.com.com (124.62.78.34.bc.googleusercontent.com. [34.78.62.124])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3ee0fbc7188sm8551386f8f.37.2025.09.19.07.58.04
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Sep 2025 07:58:04 -0700 (PDT)
From: Ethan Graham <ethan.w.s.graham@gmail.com>
To: ethangraham@google.com,
	glider@google.com
Cc: andreyknvl@gmail.com,
	andy@kernel.org,
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
	tarasmadan@google.com
Subject: [PATCH v2 08/10] drivers/auxdisplay: add a KFuzzTest for parse_xy()
Date: Fri, 19 Sep 2025 14:57:48 +0000
Message-ID: <20250919145750.3448393-9-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0.470.ga7dc726c21-goog
In-Reply-To: <20250919145750.3448393-1-ethan.w.s.graham@gmail.com>
References: <20250919145750.3448393-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=XrddJ9ag;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
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
---
 drivers/auxdisplay/charlcd.c             |  8 ++++++++
 drivers/auxdisplay/tests/charlcd_kfuzz.c | 20 ++++++++++++++++++++
 2 files changed, 28 insertions(+)
 create mode 100644 drivers/auxdisplay/tests/charlcd_kfuzz.c

diff --git a/drivers/auxdisplay/charlcd.c b/drivers/auxdisplay/charlcd.c
index 09020bb8ad15..e079b5a9c93c 100644
--- a/drivers/auxdisplay/charlcd.c
+++ b/drivers/auxdisplay/charlcd.c
@@ -682,3 +682,11 @@ EXPORT_SYMBOL_GPL(charlcd_unregister);
 
 MODULE_DESCRIPTION("Character LCD core support");
 MODULE_LICENSE("GPL");
+
+/*
+ * When CONFIG_KFUZZTEST is enabled, we include this _kfuzz.c file to ensure
+ * that KFuzzTest targets are built.
+ */
+#ifdef CONFIG_KFUZZTEST
+#include "tests/charlcd_kfuzz.c"
+#endif /* CONFIG_KFUZZTEST */
diff --git a/drivers/auxdisplay/tests/charlcd_kfuzz.c b/drivers/auxdisplay/tests/charlcd_kfuzz.c
new file mode 100644
index 000000000000..28ce7069c65c
--- /dev/null
+++ b/drivers/auxdisplay/tests/charlcd_kfuzz.c
@@ -0,0 +1,20 @@
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
+FUZZ_TEST(test_parse_xy, struct parse_xy_arg)
+{
+	unsigned long x, y;
+
+	KFUZZTEST_EXPECT_NOT_NULL(parse_xy_arg, s);
+	KFUZZTEST_ANNOTATE_STRING(parse_xy_arg, s);
+	parse_xy(arg->s, &x, &y);
+}
-- 
2.51.0.470.ga7dc726c21-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250919145750.3448393-9-ethan.w.s.graham%40gmail.com.
