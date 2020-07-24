Return-Path: <kasan-dev+bncBC7OBJGL2MHBBC4O5L4AKGQENUELGEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id EDC0622BE69
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Jul 2020 09:00:28 +0200 (CEST)
Received: by mail-oo1-xc3d.google.com with SMTP id n23sf47516oon.8
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Jul 2020 00:00:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595574027; cv=pass;
        d=google.com; s=arc-20160816;
        b=fj6weNMmXnTn/xKlI6N1lB6FcXAMRyLF9ocd30hDudpUz5nAeWfDzUP8dSKrUx3Js6
         eOnlyWV47DvefkJ1etKwaismIeEvLsHSmvYRkaWnuybEyPozzklkALJS0ztrZ9jZIwux
         ugq4JnQ0PoqaUQ2+bZ/ped+jqNxAuONv53jFueRgHuvuJtV2jvY92Wm8TH8VKcztPX81
         tHamYHBydNqSWzLhYbWSLJhHMtomXAQyTLQ/URnJKUzDmJkEHy97f+3N8tAG2iT3JHCD
         7zB5YSfa7TkYUtGID7gNHKvX2R7DQ8OHqTYGh2Q8lN8FRvcbTWz10ybU+hT2im2TtQIL
         08aA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=6KZugDFEDaHLnnWbRZEI4N4L7KPQOR1ptO79gydox1c=;
        b=MnG65zistxhWPSufkbbz/HAPqWOXClYlx/Iq7ElB38CnKItjBRxMFzcoschBCbQPDQ
         3uZ1/WhubZOrpYAGxW+lMtslh4VJGZaLmFEZck1/W5odW2gcYQMvO9olqyRDCn2ot2bs
         B3NujuqFGJtCEjPJpv1nDqkuehKFnJbSi0pmfXWui+5ZBiTxske6eF7Vv8LeOat8dHN/
         OhyWhP2Cpyw98lfomNkfJOHNmNc8tY5j2WOY6mVwDKjd5oPJL/jkgaupgTVzzy8PiHAs
         45wHDXKZapXKvCQCxtvG0j5bF811YHFLLRQ4/UMLxOZJrLK7HPKvEE9tvFQgQgOOngVX
         YFmw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=czFkbnvr;
       spf=pass (google.com: domain of 3cocaxwukcyejq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3CocaXwUKCYEjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6KZugDFEDaHLnnWbRZEI4N4L7KPQOR1ptO79gydox1c=;
        b=fKDjnnt+/46Tk+Eh1SzRjSSPrY8qcwtu0YmScsdE6iBspPig1AQp3eCBx/KjnAGwpU
         MgO8p2xnFbdVDiVvlHrEKtcX0n9B0dXfhyHLt+lhf88GWlVACP8W08Y7QlGN/qT3PF7A
         dsiUdTu1WzkxJPt53RniUOSPBvmq9PIWUvn6hxfVv/UgdniEL0ZVMV4p2+E3ihX0A5nO
         CUmcz/eZT03LKN8JCKApBiGD4XAxgQtY1v0oI8Xe9glTSpfDCSBv6JjXEeAWbTfzvCdj
         LPCzf3GNR0tQjiOHPxzgS2DuJ7xrkDOfxY6wb2EUXcMVfe/Kqshz8PJgbEMhxkYsIWbB
         +MvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6KZugDFEDaHLnnWbRZEI4N4L7KPQOR1ptO79gydox1c=;
        b=guRToZMYoVrYplbIrLJFLI55X0kTRNlDc3O9IdB8VqtXIBzFuXTBR9AQ7dLiLmOVFv
         30mcmYIg7EC4odcnnBatiO5bIxi3xKZk5AtvtWLan04yd1Zd2ACUO02Y1goZ49LAOD+a
         yoyp+mq1wTCLVcTab8Ni3P6ynVFdYDYKNi1kSAKN2cLUeYox0klBdEb++PcKYuC0RLqy
         zR51DDjovlNt/IVt+CsgpwZMBsKInCp3O4zjiV1cuLtBqNE3f6PgEiCjeOq77uLk/TIS
         sLhtgB3vWVvEpvK1SDTcazVn/GEANsv8i+ci+Urdje305FAHoi6FvN7SLjFQNn0hwAJX
         sbaQ==
X-Gm-Message-State: AOAM533lgjwgxvZHhYMmhR7RoK4Y2NMz/HQ7dA5d1aJEA3ht3j0VN9Bx
	PVzgwdl+wcMbz4DK+x7h9fk=
X-Google-Smtp-Source: ABdhPJzZYQNg6YHyczF8KyDHDCLjvQyQzKJ8cJ9b5XJ1VML4MZiKTPS1a8UoAALvx3HBVLtXdJ7QMg==
X-Received: by 2002:aca:cc8e:: with SMTP id c136mr6955858oig.128.1595574027550;
        Fri, 24 Jul 2020 00:00:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:620c:: with SMTP id x12ls243965ooc.6.gmail; Fri, 24 Jul
 2020 00:00:27 -0700 (PDT)
X-Received: by 2002:a4a:e8da:: with SMTP id h26mr8053579ooe.59.1595574027248;
        Fri, 24 Jul 2020 00:00:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595574027; cv=none;
        d=google.com; s=arc-20160816;
        b=eFoRnHcjl0Otraa9yvuEgzMGFy01+EmRE9FBxGdmTLJSjS4k2nIJwiLVYvDep1iCqD
         eWo1k6w2AM6o9pdsUqXnIUKdgwKq9nDhFSwAV6sPRxQiTgM8lezwvTxZpnaOfvEYnA8M
         MbNlyUtGwH83zgt16GK8L+B2wuoMMg/hHoJhNc3LfMCagLMcIC6c3R4nH92Rykm3wF4n
         XIeNY4W4+DmgkMK2a146QpKG9nU4DM46u0Zv155ItJC7bHsBL10Zf6fkaMPNF3zqQ8Du
         J9tiW1HZZo0Azfcq5SgKvlfM1kQfQRXfDU+QCKCVwMlc0rYt1WneQRfqQk0LiwxJvyhA
         C5qw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=0nD1NJT1E7A4DlzwAlOASLTDllp8VUp9XPKXYyHjpfM=;
        b=MgOaC12/jLB9vfmcUqUxI6GlByCDSRUZ63OemSjNqtpcKzmaOdUHT1paNhH6mtWND5
         VltVYhV3dKTwjwN9o6IQb1tbqa+9/Xjq33k0eXG6YtzOTBAl18SM5M4p50P3Yk/+kCC8
         Bc+dL3upJ25jnozMgkBFHpVdG0QBX9kOiM+j9VUSqUMVk0NFimYF6mcWBj0a5CgxMuGD
         4QQXKE/AOBofHBu9rh8MHie6YpXlFyTzeZTKvc9kzBYLinpqcKv+IClFSQxgkZMx6589
         8ivk8Hl69DXL3M0nJkZgNeO/Np2FmjrBGOJVFe82704LvY2tT1bZrqJN1IrHqm6/5li4
         1PmQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=czFkbnvr;
       spf=pass (google.com: domain of 3cocaxwukcyejq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3CocaXwUKCYEjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id n26si486596otk.5.2020.07.24.00.00.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 Jul 2020 00:00:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3cocaxwukcyejq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id x184so9377497ybx.10
        for <kasan-dev@googlegroups.com>; Fri, 24 Jul 2020 00:00:27 -0700 (PDT)
X-Received: by 2002:a25:9c06:: with SMTP id c6mr12958040ybo.403.1595574026740;
 Fri, 24 Jul 2020 00:00:26 -0700 (PDT)
Date: Fri, 24 Jul 2020 09:00:02 +0200
In-Reply-To: <20200724070008.1389205-1-elver@google.com>
Message-Id: <20200724070008.1389205-3-elver@google.com>
Mime-Version: 1.0
References: <20200724070008.1389205-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.rc0.142.g3c755180ce-goog
Subject: [PATCH v2 2/8] objtool, kcsan: Add __tsan_read_write to uaccess whitelist
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: will@kernel.org, peterz@infradead.org, arnd@arndb.de, mark.rutland@arm.com, 
	dvyukov@google.com, glider@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-arch@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=czFkbnvr;       spf=pass
 (google.com: domain of 3cocaxwukcyejq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3CocaXwUKCYEjq0jwlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Adds the new __tsan_read_write compound instrumentation to objtool's
uaccess whitelist.

Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 tools/objtool/check.c | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index 63d8b630c67a..38d82e705c93 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -528,6 +528,11 @@ static const char *uaccess_safe_builtin[] = {
 	"__tsan_write4",
 	"__tsan_write8",
 	"__tsan_write16",
+	"__tsan_read_write1",
+	"__tsan_read_write2",
+	"__tsan_read_write4",
+	"__tsan_read_write8",
+	"__tsan_read_write16",
 	"__tsan_atomic8_load",
 	"__tsan_atomic16_load",
 	"__tsan_atomic32_load",
-- 
2.28.0.rc0.142.g3c755180ce-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200724070008.1389205-3-elver%40google.com.
