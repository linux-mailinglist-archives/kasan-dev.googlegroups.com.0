Return-Path: <kasan-dev+bncBCF5XGNWYQBRBSPW73YAKGQE3NRPR2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id ADC8C13D175
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 02:24:26 +0100 (CET)
Received: by mail-il1-x140.google.com with SMTP id u14sf14796537ilq.15
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 17:24:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579137865; cv=pass;
        d=google.com; s=arc-20160816;
        b=jkA0xRb3AaCoimB1P2fZnilbkDKssp5yOVNrOSVnQuw7cBgg4Cys7hffe2/BqiJwmi
         CTiOo6HUXOsLhpSz9dsKB8h3/VeWVGhqnUk87ribkdJQoqUnT2SxHi/20RspEYSu80fW
         gzyIZqqiLu/mEZ+EiW3i9BKE3a+XGxdBy4lqRbb4eRJvhCqbJJMRnav7JHG1XDE4mq7F
         uzOcfSpiaj4TNSvHrLy0hAX9b/MFPcmuX//Zicc/b1RNkMu8YZm01hCL1C20f8jMBk/g
         fwUVQSqBCq4Xdvv0FMgU4JIwcw0agP75+9ekJ0+ummM+oXNWsaO+b+wBS0uvpHd1y9bs
         RmHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=rfOmzgCJdBagP+2oFpfzFqr/EMAcplleNNgL39aWNvs=;
        b=vYztsFMzQ9NQv1aDetADQ/RmdIcevszFMmij0gf49XlAYBTs/l5gw4w2JRb1CkNE/i
         +WgRDPkllXeqXyx02aD06XuYEkr2xWX9NDNCKl2V5SMMPZfMsAx6qLbZWdHaKA0l5Crm
         rD8BKp4abNgU0F7+CmLWXMR01iNDnIeJvXwuICzWfu57nz6XUnL9AXCW+ceFtUSV/zUA
         xMwTsq2N1AZUMvLbDeMwyvwMMd0t7vnyzu7S84vN2KwA7LoqQtq/UEho2VtChICAQieT
         1e6ACjuyngJ8K938fScEj2yEevDXwZ29S2mYIz5yPytNMmp1SAnnB3anxSymvG/yJRnr
         LTNQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=B7I20849;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rfOmzgCJdBagP+2oFpfzFqr/EMAcplleNNgL39aWNvs=;
        b=ltoNdZLCyMW77ZxknPNR3DbD/h8kdefy4Oa+pKRG2MwcolFive/IuVclg5iDTKrgrC
         gYIDZWeQdVurKpjzp7aWjvyObEoxC+Fh3rs7qg/pjDeeRW7kNyhD6U9u3U0oDw4LMuVX
         GeMIBX80vLXOvrJmtBHb3jBo2QcW7Nz9lDUxYWG/p0oioz4wJjvhjueetx8QvrQcO0E5
         2YRjopGPgjJ7PcPanZf30ems4MQfP7yX7osUB5rdfRsQRyrTPe6RBT9L6P86Fm0Dr/TU
         1YjaPrtgJM4mV21ncS42djKamvwyMVcoIdpX4ii3+NassJrOTjVAM8l9RVPT6ZpDotsI
         G5+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rfOmzgCJdBagP+2oFpfzFqr/EMAcplleNNgL39aWNvs=;
        b=c9tLj+SDEc5NhFfBcDVyo07jhxVxOOD9mkx5ZhPndQQP41pSqcRa70PTZ2FFoR4mZy
         UcPsrEAIC0DRdgKpcGfKf0JZH5EXKVpNY678Y5bJT5ivTaTO+UFjEqgXv4HMcktVWgWv
         e+PAD4Ha4ZqWtEcJCWggwGs1tUlV+BooGEJpcF36PpJBxk6WpVfIOFcaqx82j9Ci1aIv
         f20DHHhRvMw+qCpG8Xcor7bFOxdws2vKX6UTZ9wgnxxWx/Qy2FW0MYilqit1krV6AwNd
         fBQS6VKhFpe1rEdd+SzH4zrn9rQZZGCt/fggOOdjIVEqDrC9/NEDSiMKvxuT+HI0oukS
         Xgvw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAW55uNP0cuiE4OYTxFkqXR64s4GRdHBqOCGa16BOtXeD619INLD
	ycxKWskuI9xeDs8JnOc4k1U=
X-Google-Smtp-Source: APXvYqxcIFJ9OnHBaKAxpYszUuvx6RyWXJkIwSDfZ2a1OA9PMr6KIdOi9Abq3VFG2oA8euQEUpJqvw==
X-Received: by 2002:a6b:8f0c:: with SMTP id r12mr25345886iod.233.1579137865600;
        Wed, 15 Jan 2020 17:24:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:b657:: with SMTP id s84ls3702368ili.3.gmail; Wed, 15 Jan
 2020 17:24:25 -0800 (PST)
X-Received: by 2002:a92:af8e:: with SMTP id v14mr1305383ill.150.1579137865269;
        Wed, 15 Jan 2020 17:24:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579137865; cv=none;
        d=google.com; s=arc-20160816;
        b=h3ufiEA20rVkcGr5Tn7vbzrliK06g8U4IGzLkRT29Ng2p6a4m1jcDkgkJWlcZoClR6
         DhqIXMTShqI/uhydh4ZyxGPplxHPwEfT7UR0NjwhaWBjQGFbTd/AquEK+SDnanT0VYqx
         nnvbrYFdqsG9btGQl4JwZEzTXCRfsJQl6iW4wRJ6KHYR+fmC+Vj21PmrHiYt0O8iZ/gD
         8sV9l4IASVgK+XltvKPleRxucQqTTImRPILhNEdFSWA0dEe2NoQstEYTttVZB8UvrD6Z
         Ego3HKMzfWjotGBhYoW36toZl1zPJG83lWZqaoGmWoW95SotcKGiSY70qTYPA+B1s5Kl
         2bsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=q9yyIQHmH5l6RRr9oXrsGBCw2p7gy7/zKkbegYq6Q+s=;
        b=E3B6SpFVLYFkkg9xpapqtqTeys4wsg+BIWBNZW0q7xLT7ReO18kuCBjl6Txb3rjEXk
         HW7Ecv3LH4aRCMIGC6+NoryvoW2HZb4WV8r51KbnPC6BXf3WhZaOBFPrIGJq1En++fLm
         66JmQVmzF9pIsvOye4/GNmlo7oXPBLD2KAz36uRnTL+9JkfSqLGyUeOcSW/PedJwyGfe
         ztlGCIe+9EoqnhyTBcrrZPxKFnEBHM/ti+4x5tRyGStBfnMOF/gOp3+IlhjxZK7UhuBw
         m8N2KCM7FwXDVxmN/MavXI9qx6fX0Ru8Fq0CoUxPzgHP/DYnMI16L1sB1JRM4y2tx8ge
         RZxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=B7I20849;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pg1-x542.google.com (mail-pg1-x542.google.com. [2607:f8b0:4864:20::542])
        by gmr-mx.google.com with ESMTPS id v82si965129ili.0.2020.01.15.17.24.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Jan 2020 17:24:25 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::542 as permitted sender) client-ip=2607:f8b0:4864:20::542;
Received: by mail-pg1-x542.google.com with SMTP id l24so9051900pgk.2
        for <kasan-dev@googlegroups.com>; Wed, 15 Jan 2020 17:24:25 -0800 (PST)
X-Received: by 2002:a63:e0f:: with SMTP id d15mr36134094pgl.255.1579137864589;
        Wed, 15 Jan 2020 17:24:24 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id bo19sm150751pjb.25.2020.01.15.17.24.21
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 15 Jan 2020 17:24:23 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Kees Cook <keescook@chromium.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Elena Petrova <lenaptr@google.com>,
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
Subject: [PATCH v3 6/6] ubsan: Include bug type in report header
Date: Wed, 15 Jan 2020 17:23:21 -0800
Message-Id: <20200116012321.26254-7-keescook@chromium.org>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20200116012321.26254-1-keescook@chromium.org>
References: <20200116012321.26254-1-keescook@chromium.org>
MIME-Version: 1.0
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=B7I20849;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::542
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200116012321.26254-7-keescook%40chromium.org.
