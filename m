Return-Path: <kasan-dev+bncBCF5XGNWYQBRBPM64DZAKGQE2752EDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc37.google.com (mail-yw1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 46364172802
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 19:49:34 +0100 (CET)
Received: by mail-yw1-xc37.google.com with SMTP id t130sf843656ywf.4
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 10:49:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582829373; cv=pass;
        d=google.com; s=arc-20160816;
        b=HNNV7ZwDt5pccX2H+zoSclvRri4BLaAcFiCVgdaHU2xxjbQDdwpf4D1lAGfpyKeAmH
         0rskabFz1zEHstONMrvAwAsUdpp6YutRqd9rI/zvJcf9gwUxSIwdshMl7j9Ot07mnjkv
         OOHEnFi8ncKmApcd7MK/725fwArDTcT9InpTQcr7nCrWkBAzCfBolKTA2UwgAufrM9SS
         XyOCrGwoGeSmOpI1an2Ps8dT2IHRyQVqjm4Lj2DCIwLoWekcWup1BImigxDRKRh7yL2q
         RlOqUNFJNAOjVcEqPigLvozvd6MMaHHl4jOK0WK0Oq+iMhmnTELOFb5MjXKA3ECCOuoB
         2YeA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=p1tNAvFfVvX/szXqARHSL9Cu1dA/n9sNGk60/WvlgkU=;
        b=mR4G0XiTfpTx3df5yTb8ETzehry7W544w4LAMRkNLlWIedryE/MqGwP6nKvIgX2YNS
         FhUnpjP5yCgcnpmh8jTgiC/g6nq4xw/GqKyk+1MqVDCdaWpq+GkpuiobiSqgCHefC7Ta
         X2sMbwtllBvLw/qxStZSNwnOsfRfVuf+LfGoUtnYxG7NrSIereQVGasq7LVWmbpQ1mjx
         ktV6TUsO9ZGY/zVVTxM46hqWP1v0ga6s/qF1X4X2pdedhVZpiudCh0fPCvi5W0VeC8cc
         sfFJwnmkxHuFCZi3B74515ka+r7GCwL9R4ICVO5mqF3gb4mjxD6ldOBomvdmV8DQ/2oQ
         KdAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=EoiJfokB;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=p1tNAvFfVvX/szXqARHSL9Cu1dA/n9sNGk60/WvlgkU=;
        b=XSehAD8kg/W6CDuRas1cYlqeZzxJ/AckIwqzAnkiJB9yCmCG4K3yOS4RbA6gIiEvxy
         dkvB5GI5qChXmODN0iUm9OZmGxEMZ70PkeGKFMouIFEBeKK1oMYg7ulU3ZlpLx385VW7
         /m9APj3JFUPvJhXA3CAulqCIDxwm1IVlM40f7DJ7fJ+4fgGnnq/ho4qXQ2QFToOk0Hip
         nQvEMeRGUUbu+qXsQ4gKa/nLvnPRnEK0eUjYgfZI4rGf+VsgbB3rIw+iOyA2Fvd2MC3f
         UFZljTDSigYqLgpITpDp22AgKJ56qdACbESRbR/Ml3TlqS+JFvOG1rYOYfjsG0/GdtW6
         wttg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=p1tNAvFfVvX/szXqARHSL9Cu1dA/n9sNGk60/WvlgkU=;
        b=qMmY409He/ETDcJ3Hunw09sgMHSp9ftcycYe7KKXM/Piy1LBb/kvRSwGaq2ufA7aRG
         Gp8lu8AKa9q5uu8h9doHlG00AlEltZllo5YmjF/zbJ9ZSGSuAl47XsXIO6AMmB/v2N3S
         Z2irUaHuxRpb5hodwYv4+Xc3Zz/6gkujwFGb4Zws+pES0X85Q6tu3QFhKjH4b4ft8/SC
         6QcZXPaW7E24H2rkwHksyFKBQ/Z/vL8bmOYNXHQAL+Y08LeyPo3MvH/sxBP0KF+rLdWH
         kbRKJe6fxWQF/FG3GUZJ4g6p/9XFhyup3NgjCwlmx4XqFLOOAYWDyksnGaFLi07BMjcY
         mPmw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV7OoO+ZLEpvErbbr9eIy+yX0PEsHSaRU4OAZYkU+zPDMR09s4v
	ml9rMbIm/Eyj4FTPIEba8K8=
X-Google-Smtp-Source: APXvYqxLuh6yV/fZUIxtxS7LgzMitHjfMLC4GSQWtFZFY+mXe4/C4FOJsC6mbqdm/uPXWjkvod5DiA==
X-Received: by 2002:a81:5e09:: with SMTP id s9mr859572ywb.348.1582829373293;
        Thu, 27 Feb 2020 10:49:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:7486:: with SMTP id p128ls79708ybc.5.gmail; Thu, 27 Feb
 2020 10:49:33 -0800 (PST)
X-Received: by 2002:a25:4147:: with SMTP id o68mr70590yba.434.1582829372986;
        Thu, 27 Feb 2020 10:49:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582829372; cv=none;
        d=google.com; s=arc-20160816;
        b=kqDkoULObNZWD/GY8XyDxv5wptQfsCAoCJGzOVTz5rDmABX/LUl0iW6MIcBhznoayJ
         CKJTlVLKpjVjmRvXXcgV47I3JJv/S8k/g6GGxKNp8GhqypuGSrpNl+DuDyaQpYc3ZKfO
         aTp+t5GWlkle+wkkiCZBfUB5nLG6ef5TPB2cjtxv+btgxTStt6q9zfvMaDdNnjj2vA5i
         1TJ2G5ELo4dlUSV9TAefucJLYWLDGqKLGw84pS0skszcnLMhunUAsjBuz8j1goQep1Bc
         j0teZEdWEFk4aMBODjum6E1byPf3jFk4/vnC0CvGzpGLg+J5rNlLeIKZ3FWGPvPnexR5
         dzEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=q9yyIQHmH5l6RRr9oXrsGBCw2p7gy7/zKkbegYq6Q+s=;
        b=lVn2567Su4/sw6XqrO3ftV4XnhuHBCl8OV2u8ugfb103iO+hqG/iaDyZkNs4f65Iq8
         KZtWoF9i2dgi7CcVnXzCVrjknYrX57QgC7GpE5Dv3/d9NU/5tNGBHjaXyEO6hgKeeYKF
         PYspYxFId2SnaMsYATamcFSLCIWFLrKUGGGiDJb14HF10DOGG/yIfAhTPmB7AYsTfcSG
         KVQsToQ81hhQnu1P9i1snPvzWXsNVT2oVRnujjY/R5v/5Upuq+BrfpjX1D7UIBm/Hxq8
         jBAo/jAvrqn1N7Fv01Z7Der7OJ7HITVnYXDSjrZVjZU9ufS7lUEg3SjOTx7BBf14moio
         wWFg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=EoiJfokB;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x442.google.com (mail-pf1-x442.google.com. [2607:f8b0:4864:20::442])
        by gmr-mx.google.com with ESMTPS id o185si15603yba.0.2020.02.27.10.49.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Feb 2020 10:49:32 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::442 as permitted sender) client-ip=2607:f8b0:4864:20::442;
Received: by mail-pf1-x442.google.com with SMTP id o24so264550pfp.13
        for <kasan-dev@googlegroups.com>; Thu, 27 Feb 2020 10:49:32 -0800 (PST)
X-Received: by 2002:a63:fc51:: with SMTP id r17mr721308pgk.292.1582829372073;
        Thu, 27 Feb 2020 10:49:32 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id d1sm7427551pgi.63.2020.02.27.10.49.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 27 Feb 2020 10:49:31 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Kees Cook <keescook@chromium.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Elena Petrova <lenaptr@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	kernel-hardening@lists.openwall.com,
	syzkaller@googlegroups.com
Subject: [PATCH v4 6/6] ubsan: Include bug type in report header
Date: Thu, 27 Feb 2020 10:49:21 -0800
Message-Id: <20200227184921.30215-7-keescook@chromium.org>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20200227184921.30215-1-keescook@chromium.org>
References: <20200227184921.30215-1-keescook@chromium.org>
MIME-Version: 1.0
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=EoiJfokB;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::442
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

When syzbot tries to figure out how to deduplicate bug reports, it
prefers seeing a hint about a specific bug type (we can do better than
just "UBSAN"). This lifts the handler reason into the UBSAN report line
that includes the file path that tripped a check. Unfortunately, UBSAN
does not provide function names.

Suggested-by: Dmitry Vyukov <dvyukov@google.com>
Link: https://lore.kernel.org/lkml/CACT4Y+bsLJ-wFx_TaXqax3JByUOWB3uk787LsyMVcfW6JzzGvg@mail.gmail.com
Signed-off-by: Kees Cook <keescook@chromium.org>
---
 lib/ubsan.c | 36 +++++++++++++++---------------------
 1 file changed, 15 insertions(+), 21 deletions(-)

diff --git a/lib/ubsan.c b/lib/ubsan.c
index 429663eef6a7..057d5375bfc6 100644
--- a/lib/ubsan.c
+++ b/lib/ubsan.c
@@ -45,13 +45,6 @@ static bool was_reported(struct source_location *location)
 	return test_and_set_bit(REPORTED_BIT, &location->reported);
 }
 
-static void print_source_location(const char *prefix,
-				struct source_location *loc)
-{
-	pr_err("%s %s:%d:%d\n", prefix, loc->file_name,
-		loc->line & LINE_MASK, loc->column & COLUMN_MASK);
-}
-
 static bool suppress_report(struct source_location *loc)
 {
 	return current->in_ubsan || was_reported(loc);
@@ -140,13 +133,14 @@ static void val_to_string(char *str, size_t size, struct type_descriptor *type,
 	}
 }
 
-static void ubsan_prologue(struct source_location *location)
+static void ubsan_prologue(struct source_location *loc, const char *reason)
 {
 	current->in_ubsan++;
 
 	pr_err("========================================"
 		"========================================\n");
-	print_source_location("UBSAN: Undefined behaviour in", location);
+	pr_err("UBSAN: %s in %s:%d:%d\n", reason, loc->file_name,
+		loc->line & LINE_MASK, loc->column & COLUMN_MASK);
 }
 
 static void ubsan_epilogue(void)
@@ -180,12 +174,12 @@ static void handle_overflow(struct overflow_data *data, void *lhs,
 	if (suppress_report(&data->location))
 		return;
 
-	ubsan_prologue(&data->location);
+	ubsan_prologue(&data->location, type_is_signed(type) ?
+			"signed integer overflow" :
+			"unsigned integer overflow");
 
 	val_to_string(lhs_val_str, sizeof(lhs_val_str), type, lhs);
 	val_to_string(rhs_val_str, sizeof(rhs_val_str), type, rhs);
-	pr_err("%s integer overflow:\n",
-		type_is_signed(type) ? "signed" : "unsigned");
 	pr_err("%s %c %s cannot be represented in type %s\n",
 		lhs_val_str,
 		op,
@@ -225,7 +219,7 @@ void __ubsan_handle_negate_overflow(struct overflow_data *data,
 	if (suppress_report(&data->location))
 		return;
 
-	ubsan_prologue(&data->location);
+	ubsan_prologue(&data->location, "negation overflow");
 
 	val_to_string(old_val_str, sizeof(old_val_str), data->type, old_val);
 
@@ -245,7 +239,7 @@ void __ubsan_handle_divrem_overflow(struct overflow_data *data,
 	if (suppress_report(&data->location))
 		return;
 
-	ubsan_prologue(&data->location);
+	ubsan_prologue(&data->location, "division overflow");
 
 	val_to_string(rhs_val_str, sizeof(rhs_val_str), data->type, rhs);
 
@@ -264,7 +258,7 @@ static void handle_null_ptr_deref(struct type_mismatch_data_common *data)
 	if (suppress_report(data->location))
 		return;
 
-	ubsan_prologue(data->location);
+	ubsan_prologue(data->location, "NULL pointer dereference");
 
 	pr_err("%s null pointer of type %s\n",
 		type_check_kinds[data->type_check_kind],
@@ -279,7 +273,7 @@ static void handle_misaligned_access(struct type_mismatch_data_common *data,
 	if (suppress_report(data->location))
 		return;
 
-	ubsan_prologue(data->location);
+	ubsan_prologue(data->location, "misaligned access");
 
 	pr_err("%s misaligned address %p for type %s\n",
 		type_check_kinds[data->type_check_kind],
@@ -295,7 +289,7 @@ static void handle_object_size_mismatch(struct type_mismatch_data_common *data,
 	if (suppress_report(data->location))
 		return;
 
-	ubsan_prologue(data->location);
+	ubsan_prologue(data->location, "object size mismatch");
 	pr_err("%s address %p with insufficient space\n",
 		type_check_kinds[data->type_check_kind],
 		(void *) ptr);
@@ -354,7 +348,7 @@ void __ubsan_handle_out_of_bounds(struct out_of_bounds_data *data, void *index)
 	if (suppress_report(&data->location))
 		return;
 
-	ubsan_prologue(&data->location);
+	ubsan_prologue(&data->location, "array index out of bounds");
 
 	val_to_string(index_str, sizeof(index_str), data->index_type, index);
 	pr_err("index %s is out of range for type %s\n", index_str,
@@ -375,7 +369,7 @@ void __ubsan_handle_shift_out_of_bounds(struct shift_out_of_bounds_data *data,
 	if (suppress_report(&data->location))
 		goto out;
 
-	ubsan_prologue(&data->location);
+	ubsan_prologue(&data->location, "shift out of bounds");
 
 	val_to_string(rhs_str, sizeof(rhs_str), rhs_type, rhs);
 	val_to_string(lhs_str, sizeof(lhs_str), lhs_type, lhs);
@@ -407,7 +401,7 @@ EXPORT_SYMBOL(__ubsan_handle_shift_out_of_bounds);
 
 void __ubsan_handle_builtin_unreachable(struct unreachable_data *data)
 {
-	ubsan_prologue(&data->location);
+	ubsan_prologue(&data->location, "unreachable");
 	pr_err("calling __builtin_unreachable()\n");
 	ubsan_epilogue();
 	panic("can't return from __builtin_unreachable()");
@@ -422,7 +416,7 @@ void __ubsan_handle_load_invalid_value(struct invalid_value_data *data,
 	if (suppress_report(&data->location))
 		return;
 
-	ubsan_prologue(&data->location);
+	ubsan_prologue(&data->location, "invalid load");
 
 	val_to_string(val_str, sizeof(val_str), data->type, val);
 
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200227184921.30215-7-keescook%40chromium.org.
