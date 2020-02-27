Return-Path: <kasan-dev+bncBCF5XGNWYQBRBAVU4DZAKGQESXAQF4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A0BE1728AF
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 20:35:31 +0100 (CET)
Received: by mail-ot1-x33d.google.com with SMTP id 4sf300937otd.17
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 11:35:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582832130; cv=pass;
        d=google.com; s=arc-20160816;
        b=vLzHvGz5q4j9U2g7oyQLxpmawWuhzU1WQQWS4ybjkJjAfBIZ+GonYXyk2+Evw5jycN
         BsgxgfCtBZIY/i0mZ1l+1FI+ycD7+oR6TpeDtchyK6P4YmLjdLgkyFr5WkOSxeGWlYSd
         SGHjBML2l8qASpi/XZAIXrZ+zk4Mq8B9BPw1KLSj5CyRKpKATA4ABIMlDRwZ5TBTsLYL
         wAQKyhMnw6EPoOqOVuP4MZBVukOSNDk627CNDBI2pLL6ZGz9uZ0DGBiHsWvWMAAVFq9d
         HsfoytM1oYLywa4EcUOkde2wMXTTdtSIE5S7H+XhwWsIHgHJkkWjKBgcQnSjf0KD/Me5
         Q+ew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=G+wdBzetYDIbcuxdXmd7nhbf2pav6A6L4MoiEB5R4MI=;
        b=lpLRChDRxebOT6WrDE2NKNFfWqBUKeU/5wZt9J9H2lwmUa8qUFBV1lkLXKIIaSMSOh
         uwczivdNN893tgh3R7VCJqZ0vHFRZobaJssoAqymNW7VoTzsNGc6wndIHPLH2QRYVA6P
         T9BU3yn9+ghzXarndXPOrpAQPaFFDbIvk6aXrjlB3gDttQcVc2UPKawl4hdFEcuZlQYP
         ++u9OrXuqaLUWnvI3YcXQZsmGBzqcXyuPQDFP1WyEepiu9+jcYpajmxPYUMuznU3LZya
         UQ8mwgOdbn1Brm1brZPmyFIVSWvMF8TRV8fvxIckOTag9SfzawQbVmBcQ64OjDZosamF
         uhaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=RHZfJ6Zj;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=G+wdBzetYDIbcuxdXmd7nhbf2pav6A6L4MoiEB5R4MI=;
        b=E9WIdqxuw/D07eE0yGmuzB9yNEHzNbJkcH0FEFRDwvDaCMVUABpR0tSPaRW+M8BR9C
         YlUpQYCyQHyShiLHBeCHh2GR4GP17CS/CLIINWA21DUapxWHnL+Wz49aZTS02INnm5Bc
         84QYBKpx7V8f1nOief8CslecMGfFdHPUg7+h7m8iNNiXc7S6ChFZlzTu/ALtkMmO0934
         ABWv9F2hXMvi2K8UJQ3OZW02ybBNqGBI4r10uFrW9Fqbh2GpLXo9U2JcmmgXaRAyIgeb
         lnsp4urL4PtyAYNmq6jU/nVas25W7R7d3mjjZLc3mxf5OypBf/8dWoW2OP3nFZFiEbZX
         6RJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=G+wdBzetYDIbcuxdXmd7nhbf2pav6A6L4MoiEB5R4MI=;
        b=q25oU9/EF/IX6xeIf0Lbs3yua0iFG4PD076eX++HtRG7nLI6SyHWQ7me3i96KT0Cal
         KRAXmD2cxxMz8lWp/84lZEDer3tJ41U89CG+sdqFqz5u4NdeTnHPWpp+WUEitct0OHwg
         1ZaATLOJUxTHFRL9gjqKgOcXGR6gwkybIlfwH66vvFEGXlce6vnK3Ada8sr/6ymcSGIf
         RPc5kgfaPIFg3W/RnTPgia/B9vwVVX/s+cE/Tsd3S7M2h9OUjDYFINJotY4qidWMVy0p
         7/su2ZCJL/3QvAMgEkUN0Rl7wRlZsrRDemUIn6YF7UiD21I0Szjjodquv8zgIm7H9GHI
         shLg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXy7lANP0BzM892fzoLtRywyvxG0SwBntWYek83Fh26S6clYD8Y
	+/WMr/QKqkyjX82i4IR6PGc=
X-Google-Smtp-Source: APXvYqym9WzuW9DXEfqXaN16JzT1L61pnZFXmqx78Fy4QuyUhyuYPCRF+fsTV/HIc6PaEIXKO/P20w==
X-Received: by 2002:a54:4816:: with SMTP id j22mr433948oij.179.1582832130429;
        Thu, 27 Feb 2020 11:35:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:649:: with SMTP id z9ls268966oih.3.gmail; Thu, 27
 Feb 2020 11:35:30 -0800 (PST)
X-Received: by 2002:aca:c515:: with SMTP id v21mr531465oif.60.1582832130139;
        Thu, 27 Feb 2020 11:35:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582832130; cv=none;
        d=google.com; s=arc-20160816;
        b=pRIis91W9jx9LcQbeKni924aNGmEeDEj4qxlxarFX0+u+z8B3mGFJD9yXc1GqcKhGN
         BBQD3T1Fy3s0OIjMLEWcillDH7/epXsJ1fbOEwwfxYNwu+pkrXLQwx9r8aZErIqH8X+G
         Zwl541x5+STMpWlCISmg2XdsmUWzg4Kufi+ygZqxNCKpXWpjFyZ7/jGhdV5MshAtnv6I
         903cgIUOL3Y1EuX18ETuPNRDuMOxP92MoEGE0Z3q+wcp6NRfPDghm8dA1VjjHWnGKwTx
         88v/v3rsuTih7tN/EmqvffkYRrnkULzggTw2h+083gHp4bcWkCXVBId4aI4QlYswKKJK
         5Htw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=jDKV/BVhQvBMwfS/RHWg5/AFVijLTVXYoYGSEirzUqw=;
        b=TxWoDZ5UMf+Hbfy+hPU7F9crY1BGoYJDxvWY7O7DHY5iS6iGT0Eqznt2Wi86LFiC0E
         VKz05nE6+v0URJPmPkb1aFMd37V1ARjIBMyjNUnG79PU9T/qaMACOFDcbBK0+vGZpLi+
         A4OrgTMh8vVom9F8UwcAsSGc+m4a8fAYyHl3S9wT5+rCJk58i2G/sOcvL0oPIxiaODfB
         HOqGsPs4K+hC14rym11Jm7IpcWpVslMpg9Gv91WodPGH5NhZDTkyQREnfg+imHHT9WOL
         66EXiSsdxCB+yi6GzO4TayFYt0oaOuST4Xnhn4OP3x5MJuwaUaskwlPpSBXfg8XPpkEu
         4o9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=RHZfJ6Zj;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x442.google.com (mail-pf1-x442.google.com. [2607:f8b0:4864:20::442])
        by gmr-mx.google.com with ESMTPS id z12si47274oid.0.2020.02.27.11.35.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Feb 2020 11:35:30 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::442 as permitted sender) client-ip=2607:f8b0:4864:20::442;
Received: by mail-pf1-x442.google.com with SMTP id y5so335334pfb.11
        for <kasan-dev@googlegroups.com>; Thu, 27 Feb 2020 11:35:30 -0800 (PST)
X-Received: by 2002:a62:e80a:: with SMTP id c10mr518798pfi.129.1582832129371;
        Thu, 27 Feb 2020 11:35:29 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id o6sm8598900pfg.180.2020.02.27.11.35.22
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 27 Feb 2020 11:35:27 -0800 (PST)
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
Subject: [PATCH v5 6/6] ubsan: Include bug type in report header
Date: Thu, 27 Feb 2020 11:35:16 -0800
Message-Id: <20200227193516.32566-7-keescook@chromium.org>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20200227193516.32566-1-keescook@chromium.org>
References: <20200227193516.32566-1-keescook@chromium.org>
MIME-Version: 1.0
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=RHZfJ6Zj;       spf=pass
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
index 429663eef6a7..f8c0ccf35f29 100644
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
+			"signed-integer-overflow" :
+			"unsigned-integer-overflow");
 
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
+	ubsan_prologue(&data->location, "negation-overflow");
 
 	val_to_string(old_val_str, sizeof(old_val_str), data->type, old_val);
 
@@ -245,7 +239,7 @@ void __ubsan_handle_divrem_overflow(struct overflow_data *data,
 	if (suppress_report(&data->location))
 		return;
 
-	ubsan_prologue(&data->location);
+	ubsan_prologue(&data->location, "division-overflow");
 
 	val_to_string(rhs_val_str, sizeof(rhs_val_str), data->type, rhs);
 
@@ -264,7 +258,7 @@ static void handle_null_ptr_deref(struct type_mismatch_data_common *data)
 	if (suppress_report(data->location))
 		return;
 
-	ubsan_prologue(data->location);
+	ubsan_prologue(data->location, "null-ptr-deref");
 
 	pr_err("%s null pointer of type %s\n",
 		type_check_kinds[data->type_check_kind],
@@ -279,7 +273,7 @@ static void handle_misaligned_access(struct type_mismatch_data_common *data,
 	if (suppress_report(data->location))
 		return;
 
-	ubsan_prologue(data->location);
+	ubsan_prologue(data->location, "misaligned-access");
 
 	pr_err("%s misaligned address %p for type %s\n",
 		type_check_kinds[data->type_check_kind],
@@ -295,7 +289,7 @@ static void handle_object_size_mismatch(struct type_mismatch_data_common *data,
 	if (suppress_report(data->location))
 		return;
 
-	ubsan_prologue(data->location);
+	ubsan_prologue(data->location, "object-size-mismatch");
 	pr_err("%s address %p with insufficient space\n",
 		type_check_kinds[data->type_check_kind],
 		(void *) ptr);
@@ -354,7 +348,7 @@ void __ubsan_handle_out_of_bounds(struct out_of_bounds_data *data, void *index)
 	if (suppress_report(&data->location))
 		return;
 
-	ubsan_prologue(&data->location);
+	ubsan_prologue(&data->location, "array-index-out-of-bounds");
 
 	val_to_string(index_str, sizeof(index_str), data->index_type, index);
 	pr_err("index %s is out of range for type %s\n", index_str,
@@ -375,7 +369,7 @@ void __ubsan_handle_shift_out_of_bounds(struct shift_out_of_bounds_data *data,
 	if (suppress_report(&data->location))
 		goto out;
 
-	ubsan_prologue(&data->location);
+	ubsan_prologue(&data->location, "shift-out-of-bounds");
 
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
+	ubsan_prologue(&data->location, "invalid-load");
 
 	val_to_string(val_str, sizeof(val_str), data->type, val);
 
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200227193516.32566-7-keescook%40chromium.org.
