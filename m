Return-Path: <kasan-dev+bncBCF5XGNWYQBRBSHW73YAKGQEWLMGXZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 7868413D174
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 02:24:25 +0100 (CET)
Received: by mail-io1-xd37.google.com with SMTP id x10sf11627096iob.2
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 17:24:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579137864; cv=pass;
        d=google.com; s=arc-20160816;
        b=Un6AeW2vznCbCplyZA0XkgLKSV/7QQ7wP06g1FxRO1x3n8SSH+PFiOZvQZqpYFK8iD
         gBT5a8eowQ3FOgdjJmhUhz5V8SVGoqmdk8ixY5UUYJ/HBjtzF8E3frQe/c5XlpDdTdCN
         qY7iXWe2jayc/yqf2BgJAZBTf+8bHQrJagDaeDYWFqGns7Sqgm9XsPmSvVj4VbndqYqh
         /HbxYAbTcu3BOEl2UxMfCwk7tiFbmk4poCblJ4DCfA1+FDHmomtXCXyhXoOkqZ3VbGbI
         4V31GDp+z2alNYEwPFfOVJMhTPtqjZ7WzfiiAch2QRyVxwN5cfhgQXnYW4Sgc9zGVOw7
         8o4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=EreGCOtcv7A4MNjFZxNyFP5B5Kr9vkRC88y7g1Eoubk=;
        b=lOH23W+L9F4NwbOjxIfpMYUbIpmRk0fcSysulLOtS9Ixt5akfWZYVpx9gHq4NFWvXJ
         6QwEmTPbJ4RlNRH8tJgsF6WEX6MFT6Gdz+UwEQhTGG4uJkG48wbmuE/mVbB1JiVwSt2M
         1zTxq8hVllFksQC82u9j8r2VS01Qa6vNRdEBxotzdjzjaymBK9zuPk6OVIKT/tVSqXP8
         RKvu6oruiAHeD9C3q+CSrCvW76HNJ1mhq/j0NYJQHnrVhxUm8XyG4sHvPo0w4ylUA/Ba
         hV0EtCLaIEC56RFGjTmi2Mv4oowlpEeIxMZXa5bqiSRopLkxbXnOE7YxZU5Sm6Xagn5Q
         PUfw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=SJwnin5n;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EreGCOtcv7A4MNjFZxNyFP5B5Kr9vkRC88y7g1Eoubk=;
        b=mbhbc1GnTi/lURv5jbhBaoANahE9um/FIroBRL0I3MbO/vd4vn04rGSdH4tWWYjr5k
         l8c+ZYHlEL3I8EIqgby55GwdZrs4mLbhOk/XQH9r3dNTQSX0KH1lDVQqNO6qhbYo5WOB
         tyuahF5t1hjifLVDSkNYMGbSD7R5892v+cnJ0nhT6GsKTNvl9NajQSe+7ZL7SCl35hhN
         f9MQ4NFZMJCw9q3rAWF/p+O1tNdeLjo8bcA9ZvW5YocuOdBHH0udi+ifxqZ4b/0ABIBT
         zhdLQUMulqmaUqyV6FlqrtfRPXbgtpcn1dUI6ECWyxfTni9Gwrsk3XgoWzT69PbJRnow
         ITWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EreGCOtcv7A4MNjFZxNyFP5B5Kr9vkRC88y7g1Eoubk=;
        b=JZ4kjqPnW1v5YRplvJfdcrQY/GC+/2EUHp47bs5q0VvlfKibfbEYxOYaF3ipe2slp0
         doS9AlgeqeSe1+QsXTUPTVBt3Ka6aPCCiZDoKms9Jza6lNjrD+TTbr0i6FFfO5usRkld
         PCt8z+k9YwHugnhLR5u+ffiK/E7eZ7Il5XmSq6wb2wXmC+/RgmRdU3qcztO05rrumBSj
         aHrHyr1J8EzIX84gGMORRANc+Y9zOOwrgRGKxEszkqL0PS3vhVTE/MTdgoQ6e5jtHeFt
         9OJTi8PPrsMOdZvXxUeSvjxkYZyDpJCE2Ak9k99VfkUdRrvTwCmizB0KDa+1fMckFm7P
         X33A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWFZRGK0MDUpZ8DAoK45Ohlb7vb1aKQiz98vTJMAV+lhy6TiNvd
	W7TVNCFCsvAUa+vn6nvSmwE=
X-Google-Smtp-Source: APXvYqygDV1VdIl5EFh1gupcxGUtPNbZmLkFl+ecS8rF9AKAhUd9/scYUuFDa5cU2errvQR8+GT8sg==
X-Received: by 2002:a6b:7e44:: with SMTP id k4mr2053041ioq.23.1579137864299;
        Wed, 15 Jan 2020 17:24:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d3c9:: with SMTP id c9ls3697054ilh.1.gmail; Wed, 15 Jan
 2020 17:24:24 -0800 (PST)
X-Received: by 2002:a92:5a16:: with SMTP id o22mr1307425ilb.152.1579137863953;
        Wed, 15 Jan 2020 17:24:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579137863; cv=none;
        d=google.com; s=arc-20160816;
        b=x2HXlnbdxtc6AHeszqByOga/JxcqWtf8UyCmbcHyAs0hDf/tuPW9gkvX/fyThRStMS
         MFzSX0GFTvjs1NaXL35AUV59N1QsewCa80lZPemCDtjfBTXwDcJhemiPwvcxitVEdge2
         QWWlGljKwJJ5HhLG4TlKRAivvqAo440LQ6Gu4VQYPwW+UzAJemW6Bto21/Xn3txuVvSJ
         ayfFErl2v45cG8CCTB/fTgma7F9m6vNpO8hQa4yBEuGSDaiYiiA96/LMLsw0ym7CRzqZ
         3kmd+mbXsX7srVlnRRLwgm55dp07JGA/GunCUtcyknqfkz1fP+7ulAOppOyp4FjlY58z
         Obzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=46Z0N6nNFPIgM2OuwNgkHRjYe659IsqNoWw8FG0hdrY=;
        b=xB+fQF5Zn5mVp+vKmDwzT6lFItZusG/vjuTydcfW6lk8QORRcpUij7Y6TwrTlg76Z2
         G4mR6yuAxuiut+SNmdMH2N7ubnfSnnEZAzCgwIQaMi2AB0FqwX91r2A3i6i5e/6UR1SX
         RII5FCu7cHAhKwfGsXdLwZvrjPqMOaF8vN4gfeJSFX1A+dngxINZaChPa2E61PvCaDlt
         +vkzBWX35J3zCJTrR6x/OLHMJhz9cA/O61hemH9sTyaIS730XzWO7rQQ0kdFDCh8aHTm
         GG520oyZCw0V0urFZFmGqP8J7s5ba7EtDRv/fRbfj40E+eN27edWTBRyblB/UAl7NPQU
         ooBw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=SJwnin5n;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x442.google.com (mail-pf1-x442.google.com. [2607:f8b0:4864:20::442])
        by gmr-mx.google.com with ESMTPS id k9si927780ili.4.2020.01.15.17.24.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Jan 2020 17:24:23 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::442 as permitted sender) client-ip=2607:f8b0:4864:20::442;
Received: by mail-pf1-x442.google.com with SMTP id 62so2732139pfu.11
        for <kasan-dev@googlegroups.com>; Wed, 15 Jan 2020 17:24:23 -0800 (PST)
X-Received: by 2002:aa7:9816:: with SMTP id e22mr35105862pfl.229.1579137863425;
        Wed, 15 Jan 2020 17:24:23 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id d20sm1058272pjs.2.2020.01.15.17.24.18
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 15 Jan 2020 17:24:18 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Kees Cook <keescook@chromium.org>,
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
Subject: [PATCH v3 4/6] ubsan: Check panic_on_warn
Date: Wed, 15 Jan 2020 17:23:19 -0800
Message-Id: <20200116012321.26254-5-keescook@chromium.org>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20200116012321.26254-1-keescook@chromium.org>
References: <20200116012321.26254-1-keescook@chromium.org>
MIME-Version: 1.0
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=SJwnin5n;       spf=pass
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

Syzkaller expects kernel warnings to panic when the panic_on_warn
sysctl is set. More work is needed here to have UBSan reuse the WARN
infrastructure, but for now, just check the flag manually.

Link: https://lore.kernel.org/lkml/CACT4Y+bsLJ-wFx_TaXqax3JByUOWB3uk787LsyMVcfW6JzzGvg@mail.gmail.com
Signed-off-by: Kees Cook <keescook@chromium.org>
---
 lib/ubsan.c | 11 +++++++++++
 1 file changed, 11 insertions(+)

diff --git a/lib/ubsan.c b/lib/ubsan.c
index 7b9b58aee72c..429663eef6a7 100644
--- a/lib/ubsan.c
+++ b/lib/ubsan.c
@@ -156,6 +156,17 @@ static void ubsan_epilogue(void)
 		"========================================\n");
 
 	current->in_ubsan--;
+
+	if (panic_on_warn) {
+		/*
+		 * This thread may hit another WARN() in the panic path.
+		 * Resetting this prevents additional WARN() from panicking the
+		 * system on this thread.  Other threads are blocked by the
+		 * panic_mutex in panic().
+		 */
+		panic_on_warn = 0;
+		panic("panic_on_warn set ...\n");
+	}
 }
 
 static void handle_overflow(struct overflow_data *data, void *lhs,
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200116012321.26254-5-keescook%40chromium.org.
