Return-Path: <kasan-dev+bncBAABBUUJXKGQMGQEQGXXOYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id E895B46AADE
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:46:58 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id j193-20020a1c23ca000000b003306ae8bfb7sf6715459wmj.7
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:46:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638827218; cv=pass;
        d=google.com; s=arc-20160816;
        b=gKp/+RkDquJwnv0EuZ+QDrLekjZdT/4dnci2LumB+/i3WrRheZNTdeC6k32sNsvU/Y
         sJUGDSc1uYislme6EurlAlV9E5ttYEZs/o/IdgxUJBoTR47LD/K0r+Mf4Inm5lnLMX7x
         GhQ666qlnG9iBL+0jHxFJ6syHzVoXaSf+VZMstNWh/LU+7rghx6a/eMV3Gz7kvW8u9fY
         nYn87Q9hOHZtbJxtSJh3VY2F08XYDNNFWLF3uDkyI/ogtsQwB9jzLAzLPQ43HskAbeVY
         m0+o1qnTzrlchovYjjKs1yRI+cC+RduVhYxt6cKjfBhu93E/bcamtcY9NStLDw2L2kV8
         eVFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=iEGgjzhaElI3l+64laUJtuxSKGKI+LKhGwlrt2sWTB0=;
        b=A2LZkXptN5ayEsCJYDMxignSkcoOdHzYU/ML+2Et2479unZKyqZE36dqMtv1f2C4Bg
         h48w9Fx/8t78vQ8KEDScTJo6AqpqFeBwJTidniXfNPDMO75X8oI4SlaVBPAFXKxTeMfk
         HWMcpOl/M9rizDaAM+Vujey2V4rA1qaPPzLcaBMhHWAyulUf+epePKhC+lzKpxP3sxC0
         3sh8VFDgu85TX2TzxsixyLDb/53OqONKhOAIGzOOXznJs2bORHxTDHjcfzeS1UglLk0B
         Nl9VRfIXDFeI/HYF1bopn04AM3r58yPAFyJtq1Fg7pK/YP7QajVBIqoOnQEw/jj+pibK
         DRgQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=mAzNzcsS;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iEGgjzhaElI3l+64laUJtuxSKGKI+LKhGwlrt2sWTB0=;
        b=oAW4NTI5FZfmMSk3b51ASt7XpzFnWx2kC+hNfist4caoRdNsLX/NrTh3c7JrYCcXMR
         fHFiT142RzBXxbMtil4sZsuFBODrbkVZ5ElyQK4wG4QQ0EjPArL86F0ROPzAT549+MxU
         AY+HXwuRWP+/lhakRq//o9lkQhNw2LLEMbv8mjTSAnT63ZtkusD+6nkjUXZ2YIgY0a00
         +H3Hndaui2R9dQ7YKkHcv/cxBFvNUy+hDXWFTf5fhRBEujDGrrUhGOSAkaOI1TnCjxej
         +GULq7BxZouUI/ciNXTuBvx02UIjtQ10dIPGfFy8+4QUMxlbwVUKB9sIHoPgBHnqWv/G
         VlRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iEGgjzhaElI3l+64laUJtuxSKGKI+LKhGwlrt2sWTB0=;
        b=bjoi3BZ5CH2Mf9Y56Xq1Sme8lEx87nONDP6eS3nMM8BaGVmZi6LMHaodUJqLMYAGn/
         WN/dW6bBi4V1CSmezDh1Uv6XBalShI1xS98hAFtoFR85PB6sj9eCcJXm0dq3n/4LC2O3
         OHOchs+Ioi/GN7vltjplfcEuqlEKXMJFq9G/s+CQ7ML56msjqe7Z1me+X9g64kr2MzpX
         S9o2OAS5Tn/Ooyzo4mO3WhiCtVTweYGv0qeaxIAuD2qFggVD2e60+Xj6Ij6QqFClf9he
         CBnG1+QbIdgxCeYFfy6t2OhBtmjzmsIMTfB3uoNP/xdRRtFYDagM80wa+KYfkYeZT3ZW
         NIJw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531GYE830CueerBzdys1rhamNih5efrstCb/b5pWd+43Pn2LqND3
	2yMRpCa/Tp0dWByqMTbyIk8=
X-Google-Smtp-Source: ABdhPJxK+d8C6idiICC0zqpumbvXlH/EikJqEf5n4JfJZLM2Y2DPiklYdXpIGS6OiHk1+IwNkUhkTg==
X-Received: by 2002:a1c:4b17:: with SMTP id y23mr1509565wma.135.1638827218696;
        Mon, 06 Dec 2021 13:46:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4092:: with SMTP id o18ls1151683wrp.1.gmail; Mon, 06 Dec
 2021 13:46:58 -0800 (PST)
X-Received: by 2002:a5d:6a47:: with SMTP id t7mr47864406wrw.367.1638827218079;
        Mon, 06 Dec 2021 13:46:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638827218; cv=none;
        d=google.com; s=arc-20160816;
        b=b02TOepVFtpH7NqYd5Zot+XmoSssVvGXNKnOHJqPQjUVRA6MrYNYbE8Oj6NghBgMTj
         arQn/eD7WK/FBLOAaeIXnuvmtafL8CjzxfUmlCN/DLoLLN4lxU+lAw7JHSzB6MnEazw2
         K1U9FJshC2BMy5+txhF72hZmwFN5sOboB9VhOPWeuWHzTQJ1SlQVwK28k1a9AbKPPQDs
         FimxH+TX56y+OZA+cS+4pRsQv0Nr44dani5eEmWj4+oqJKnz/HGcjS86JCJszsNJ3JBO
         vxCx98yPfoSQlXG1Nna0kWf0itorhgdmtAdaxfEV4xrr4Ja5T4USt6OD/U2RzMoy97cz
         5j4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=H+x4/GNYyuJ4olLesp51NHArgpf+Wp1NvuW2iXEozGc=;
        b=BP3Z+tBBkmKgW66GsfM6HMufCNY4faUQ/Yhy3U5Cuxdfw77oKOoq++WYVzzQX1RDb5
         gwjTU305KTwGwHdzXhQlZWys6uG2eMw4wYneq2OebVMvirTus8l6fxe7RHmasnuW3vqV
         50FcJOqrl2RoN30gr4XsVs1FiK+WcsF6/MQZ8kmAPXz/qBm83yjR9koinrNOZMSQmGsr
         F9Y1133czNn3OO3BKtp8TmKdiaBsVxu8ifhbL7pEwV9k0mE29iGAeTQdFONQwz6y9QRr
         cScx4SGLuMfb4q0/pM3HCmWX1GEKY6FxWpjsVfvls6e1kDjA5YBLdyVhehVMio1mksVG
         QKbQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=mAzNzcsS;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id d9si521768wrf.0.2021.12.06.13.46.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 06 Dec 2021 13:46:58 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 30/34] kasan: simplify kasan_init_hw_tags
Date: Mon,  6 Dec 2021 22:44:07 +0100
Message-Id: <1de4bcc3b3f7da3574a2e8e3f6dab48f47aa03b5.1638825394.git.andreyknvl@google.com>
In-Reply-To: <cover.1638825394.git.andreyknvl@google.com>
References: <cover.1638825394.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=mAzNzcsS;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Simplify kasan_init_hw_tags():

- Remove excessive comments in kasan_arg_mode switch.
- Combine DEFAULT and ON cases in kasan_arg_stacktrace switch.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- Add this patch.
---
 mm/kasan/hw_tags.c | 12 +++---------
 1 file changed, 3 insertions(+), 9 deletions(-)

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 983ae15ed4f0..e12f2d195cc9 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -159,20 +159,15 @@ void __init kasan_init_hw_tags(void)
 
 	switch (kasan_arg_mode) {
 	case KASAN_ARG_MODE_DEFAULT:
-		/*
-		 * Default to sync mode.
-		 */
+		/* Default to sync mode. */
 		fallthrough;
 	case KASAN_ARG_MODE_SYNC:
-		/* Sync mode enabled. */
 		kasan_mode = KASAN_MODE_SYNC;
 		break;
 	case KASAN_ARG_MODE_ASYNC:
-		/* Async mode enabled. */
 		kasan_mode = KASAN_MODE_ASYNC;
 		break;
 	case KASAN_ARG_MODE_ASYMM:
-		/* Asymm mode enabled. */
 		kasan_mode = KASAN_MODE_ASYMM;
 		break;
 	}
@@ -180,14 +175,13 @@ void __init kasan_init_hw_tags(void)
 	switch (kasan_arg_stacktrace) {
 	case KASAN_ARG_STACKTRACE_DEFAULT:
 		/* Default to enabling stack trace collection. */
+		fallthrough;
+	case KASAN_ARG_STACKTRACE_ON:
 		static_branch_enable(&kasan_flag_stacktrace);
 		break;
 	case KASAN_ARG_STACKTRACE_OFF:
 		/* Do nothing, kasan_flag_stacktrace keeps its default value. */
 		break;
-	case KASAN_ARG_STACKTRACE_ON:
-		static_branch_enable(&kasan_flag_stacktrace);
-		break;
 	}
 
 	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, stacktrace=%s)\n",
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1de4bcc3b3f7da3574a2e8e3f6dab48f47aa03b5.1638825394.git.andreyknvl%40google.com.
