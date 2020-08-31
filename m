Return-Path: <kasan-dev+bncBAABBX75WT5AKGQEECDD7KQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id CCBA325809C
	for <lists+kasan-dev@lfdr.de>; Mon, 31 Aug 2020 20:18:08 +0200 (CEST)
Received: by mail-ot1-x338.google.com with SMTP id b62sf185211otc.8
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Aug 2020 11:18:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598897887; cv=pass;
        d=google.com; s=arc-20160816;
        b=sa8Mv6Pjg6O72gUZWGMsdnzCyHFn0CYPhV2DWpb6H2VXDNM2fO2GdsjzwptE2EReOw
         OxNi6wXDvp3MQ85/qr/z/tFQ39qIc0l2ioj0NFie5XzprpczZlxuhW42pPUzkR5Hwx0F
         Yo2Lz1ikBw556eb18NA1nSAKCxO+Lnta57aN6iWR5JYoKKLyeS3FlD/lOlL3vnG3uhlN
         FWnAKvZe2ohBF10K3CtDnnmfx13KVbiRxrUo9wZ7Hsuk7wdvDSzlfrekr7Bp4svYuf6O
         y7FI6cccopA3zxQ3oPfIbwJenHZBMY8bemc22unVrLqxEzH8DPRL5gznrbfKr36Qfxry
         bGxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=Z5PuJIwNHoUhEYL3CQZcgiIDwi+qTtH/n4bYlKMmWZA=;
        b=c6kLSXswrwtk4vqOmUA/d0jE1A++PqF49zmKAp1v0kF5dPLHvAZnMUJrc1NwVxegnE
         2nUeRXuaSzUmfpIFGKjwvMn6b7ZVqgWyNwHeAVa1ZIkE/CrnfE+4QnJhl9v9XWpU4xbR
         lBGJL9dXPYL/M0Nmu2CbFAbFlTcUX1hZqmMxs26RXRQiPGjck93gD1Zx3CUqihqJVZn4
         QlLoUokYjP3GvtQzKXNrCg55wxV23hIC5t23GSzFbpRLeSgWOj5FyGivzMdM2NsSMKKj
         lIGMk+TJv7z6mM8+QjB9V7kwNCNrs227LkEOU06Vb81jEtdT+XroixJTidEZxq2NDNNM
         FewA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=UUxcBKpP;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z5PuJIwNHoUhEYL3CQZcgiIDwi+qTtH/n4bYlKMmWZA=;
        b=ssEs2ZsFejJxTchMgGDLxqOvVatyGr9MMscqLDWbAGYQW1tumWXV6/9d+1H+ppFW4s
         9dJDhv30K7ZC3g1aEFuIkULIzlI45hLK7yPGtsONgRrcb7aty5Vf+Gutcsil8qpwYxXr
         Y3w+3083zd0TSzp2RKKlaZS+01eL1zzuK8rp87BikR7nvvW0nFrU011Vuv0N8ckgRrkD
         49FOVQvEd4Z4hwZ0nW3eCE943gZxtbEDeTKsOnZOK5vBQbMV9TXA2kBgPtEBq1SY5I/V
         NKWHEdw4D187R2gA85D/R49pLUvvuSuVlJjIsvlqfsDmunmYPPaBtzIRd9dgPnGhmruy
         zf5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z5PuJIwNHoUhEYL3CQZcgiIDwi+qTtH/n4bYlKMmWZA=;
        b=Cqhqj7VJ2Wa6/uu2mXFzqU8wd5b/HgDghzY5rYvMnPzvwe10m6ccrftOg6d2JTukDx
         iFJEsbQgSbADAz5bOn5tJbaNtH1abbgFiKdjvVhMQ3Ms+U2XW0kRLmGT+VPBdCPBTrsC
         xPvLylfgxdXHrOjnIN+8GCeAATI3tXJHBfcrlFJdCJI2rb3y/vLFivrG94I8+dp+fXW0
         HkRW57uqXc0dLwkMq5M6DYUxatco3ufMwGNRSwDOQk0qA81dwJluz/G/NnhSL+vn7/xP
         YscJa0nbvbfPRmgkEOVWQpTttNNCb97kXxOVtpo1UAySwAcuIb6PnTikgAkSk49jA/zC
         evHw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531F3un6DZJoLgSwEwXzSyZZBoLdk0eQgR7ys7hzBD0YtRuDqvFv
	8DISNuQWSK4WvDt6kX6faNE=
X-Google-Smtp-Source: ABdhPJwb5p1tEtKeeilJ9Emk7UqJhF8Et1vNr1UMOArXKrLL4vAriY/++kLkzENBmEkotmpat/6qXw==
X-Received: by 2002:aca:1c03:: with SMTP id c3mr368051oic.46.1598897887671;
        Mon, 31 Aug 2020 11:18:07 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:7cb:: with SMTP id f11ls448814oij.9.gmail; Mon, 31
 Aug 2020 11:18:07 -0700 (PDT)
X-Received: by 2002:aca:1711:: with SMTP id j17mr388923oii.152.1598897887406;
        Mon, 31 Aug 2020 11:18:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598897887; cv=none;
        d=google.com; s=arc-20160816;
        b=MFlHqCRrnSP+6geOA2qCVqJo19xShWyfQklPRSba32Qz6UpG3pz+/Bd0JuW/ogcKir
         jDTm3BM61u2XDWnxN1U04KfNO1cF0iQXs73gkp1yh1rzr9aMvdEnAK2lkSO/kZBJyfDz
         4luMG4jbBBmM0eYxhJFnhOUs5vzD88fJbUrnFop12ZXGnEz/jYl6dmJz6AoLmreyZ5ux
         AfgU4b3QHhssXo1Zxbr70EtHHxnWrHZEixH5Bqy6ynBqxKW9ALikd2eMrD5GUPb5NgkD
         mYyb+KRbw8XL2szqE6hfgHjoQtFAumxATPXUlQyZ207wh3m5c7E4HIY3Y/NhawYqnkKt
         V+zA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=E5lBzBHsuOYbJtw7AbBXHvP0oRuyq+KE3ruzJxRvLKI=;
        b=LDJhykQ8mC2wOUFpuEZ7As7pb294Qcz2gnjxdqekgIrbyI2d5r/hcCwDJTzttU0c05
         /H/7aKpiRwSGaECYoQZ9o++ViXLYUUqJAhc0qDDWKU2EXMjRJRWNyp+lTdYuz7DAN0eJ
         r4fqG9LhB9SbwUdpz+Rd2fj8FnvYDkVmc2pMSwyb2n05A4imDxKWSw3vmZ14xB/qlEsj
         oBdY3ROPffXdfqKQSP1M9KtffPz5p0AFPuDwpUhpsNYYJ7qGVjxjPmi6pvQ+O1D4BBop
         AyVSC1su5VekcY1BWXRI6KehYrqkOaHNO+8cluQXbPJvgRnh4/MK5AZXij0L63UIQ2//
         L6Gw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=UUxcBKpP;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id d11si563574oti.2.2020.08.31.11.18.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 31 Aug 2020 11:18:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [50.45.173.55])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 7A8DC20E65;
	Mon, 31 Aug 2020 18:18:06 +0000 (UTC)
From: paulmck@kernel.org
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	"Paul E . McKenney" <paulmck@kernel.org>,
	Josh Poimboeuf <jpoimboe@redhat.com>,
	Peter Zijlstra <peterz@infradead.org>
Subject: [PATCH kcsan 02/19] objtool: Add atomic builtin TSAN instrumentation to uaccess whitelist
Date: Mon, 31 Aug 2020 11:17:48 -0700
Message-Id: <20200831181805.1833-2-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200831181715.GA1530@paulmck-ThinkPad-P72>
References: <20200831181715.GA1530@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=UUxcBKpP;       spf=pass
 (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

From: Marco Elver <elver@google.com>

Adds the new TSAN functions that may be emitted for atomic builtins to
objtool's uaccess whitelist.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
Cc: Josh Poimboeuf <jpoimboe@redhat.com>
Cc: Peter Zijlstra <peterz@infradead.org>
---
 tools/objtool/check.c | 50 ++++++++++++++++++++++++++++++++++++++++++++++++++
 1 file changed, 50 insertions(+)

diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index e034a8f..7546a9d 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -528,6 +528,56 @@ static const char *uaccess_safe_builtin[] = {
 	"__tsan_write4",
 	"__tsan_write8",
 	"__tsan_write16",
+	"__tsan_atomic8_load",
+	"__tsan_atomic16_load",
+	"__tsan_atomic32_load",
+	"__tsan_atomic64_load",
+	"__tsan_atomic8_store",
+	"__tsan_atomic16_store",
+	"__tsan_atomic32_store",
+	"__tsan_atomic64_store",
+	"__tsan_atomic8_exchange",
+	"__tsan_atomic16_exchange",
+	"__tsan_atomic32_exchange",
+	"__tsan_atomic64_exchange",
+	"__tsan_atomic8_fetch_add",
+	"__tsan_atomic16_fetch_add",
+	"__tsan_atomic32_fetch_add",
+	"__tsan_atomic64_fetch_add",
+	"__tsan_atomic8_fetch_sub",
+	"__tsan_atomic16_fetch_sub",
+	"__tsan_atomic32_fetch_sub",
+	"__tsan_atomic64_fetch_sub",
+	"__tsan_atomic8_fetch_and",
+	"__tsan_atomic16_fetch_and",
+	"__tsan_atomic32_fetch_and",
+	"__tsan_atomic64_fetch_and",
+	"__tsan_atomic8_fetch_or",
+	"__tsan_atomic16_fetch_or",
+	"__tsan_atomic32_fetch_or",
+	"__tsan_atomic64_fetch_or",
+	"__tsan_atomic8_fetch_xor",
+	"__tsan_atomic16_fetch_xor",
+	"__tsan_atomic32_fetch_xor",
+	"__tsan_atomic64_fetch_xor",
+	"__tsan_atomic8_fetch_nand",
+	"__tsan_atomic16_fetch_nand",
+	"__tsan_atomic32_fetch_nand",
+	"__tsan_atomic64_fetch_nand",
+	"__tsan_atomic8_compare_exchange_strong",
+	"__tsan_atomic16_compare_exchange_strong",
+	"__tsan_atomic32_compare_exchange_strong",
+	"__tsan_atomic64_compare_exchange_strong",
+	"__tsan_atomic8_compare_exchange_weak",
+	"__tsan_atomic16_compare_exchange_weak",
+	"__tsan_atomic32_compare_exchange_weak",
+	"__tsan_atomic64_compare_exchange_weak",
+	"__tsan_atomic8_compare_exchange_val",
+	"__tsan_atomic16_compare_exchange_val",
+	"__tsan_atomic32_compare_exchange_val",
+	"__tsan_atomic64_compare_exchange_val",
+	"__tsan_atomic_thread_fence",
+	"__tsan_atomic_signal_fence",
 	/* KCOV */
 	"write_comp_data",
 	"check_kcov_mode",
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200831181805.1833-2-paulmck%40kernel.org.
