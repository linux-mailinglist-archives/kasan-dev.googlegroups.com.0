Return-Path: <kasan-dev+bncBAABBOVGTLZQKGQE3MZ5EVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B92917E7CE
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Mar 2020 20:04:27 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id q7sf7432632qtp.16
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Mar 2020 12:04:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583780666; cv=pass;
        d=google.com; s=arc-20160816;
        b=NjdiAuPLWzqc2f9V0xqpOgjtWEuH3PSdHYHizDNtI+sBZMGC7il+MKxRD/3pTnvKZC
         Yi7x8B8rHqOputI2QAjB8yJ58qvAllZdABzwS7d0I8r0TxFgR2ROkNyQaeN6qNhmo76b
         0UXkrRnAizXTuSFJLRyBdOA6+YGHr/suU95KEfxSJ7ivyCj57rdV6EYxJ4gHwOk2Bhbv
         GsKcxkIFP7SoKtnnAcpp6fg4q8gOAmjisWBKgn+hfKbMfBtU6go3qdmfdnzRuzrQrQFO
         EMlaThMeEv9Q1/JtOhQLZygAOr1+at8csoCKbLLW+3PNIFAI63nciaLF7LBXUwFTTyGf
         +vEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=MKI3TMil273DfkRTZZudS2V/A3VgGxi/t7grz/eDFwg=;
        b=BC4NcaOgsaQSTd0yRB9HbRhpuqLCeEaSWZgwAQUe3/Mutc4LAUlW8dAgFygX21PXs8
         KyTaTRMpKZb5sG8t77m/jWKWDf4X6VwS660BUDVg7IuYeQoJrxywHxxXOz6TemSF+aFT
         2TcG8YE0SyIVPpO/tI6YQ0Fzxcr9mnDnThdmg9WMl4YP+/0Qhhmfxj3Pc91h8kJOZypZ
         T3wSlDYqgvis10L9uPCev6/7JriIRjhP7ksswR7wxrysZorsQstZaxNHywPvhiXtJxs6
         UbWdJCAh2ZkYG7ikzdN+MsDgygYBM+OHNUvEC9AOhpudePSIWOM4bUNAC66UeCh6dL2Q
         Jctw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=hIvCA7JD;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MKI3TMil273DfkRTZZudS2V/A3VgGxi/t7grz/eDFwg=;
        b=ZagbT+ZBnwQKp+duyNRkrDJQ25oaTtBtF+c7s5aYWA2k91YpjLZ46ekas6Dbscxx6b
         qb4D6zFqmLolAQ8N/ChtCWvfg5+aGbYpeHeYKKJ49bA7TLsixv31xwo0wB2gt4nOdCbk
         6WwjnIC9gJ/xd6umlIcMGvBOAUEAxuk4pSTdw8fq53/utWxnS3ZaYobNouJIYUnnBcR2
         0MLdIZKVFACqcFbb8VuR8muIB+Zl439FlbClR0NIJhOeEu3H3YBNoEVnLThj1U+IGAHk
         xeR1czcYD4zRc4lTwbOgMzFmnqCOZZe7pPu3oYwQY2mdryGqbtS1k5dbv+sGkg2kjikH
         hFTQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MKI3TMil273DfkRTZZudS2V/A3VgGxi/t7grz/eDFwg=;
        b=DQdtPoQZDhRY9esuSorJUSDmiRIUxWJDNGRZ1RrIkyRbNbyoLqhu2CcZaXwdgjSsPj
         KTDiLzVUprzE4o+zT0+0uR3buMHeiL+YX0XUmqYKV/Y3+PBjWvvAE4WkujdshNydOpZt
         DGAYeIZ9k38HEwiFdqpwixd6bDn79JpIhRZCdNT4fGEDOtjpvEBMO2j784fZrlLtpoP6
         aIrnhUDuo0ZG+JhCSolwdNt0xgQMv92d9EGh3y+86PdafQoPu7cUm/FNj1ZsxucvhXe+
         5rBH52AOPxmcqN8vZ5QMCWKOEtG64SLrLYqcCLRxlvNY84oxw75eADsq5WPjhVmSCv4R
         C9cA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ1NDx94mz7ye+bIixDDrlLNH5CtQAm46nR4i4oTHg3rOoAxfsXL
	SFqindfGGguhDCsCX+YcL6M=
X-Google-Smtp-Source: ADFU+vsYF2hCGHJWiji94xcSEnryEN5Yx8+4p5QDmHsVR+zh2G08iQA/AXlcvrTw66WCiPxKR8I44Q==
X-Received: by 2002:a0c:e58e:: with SMTP id t14mr15385532qvm.131.1583780666161;
        Mon, 09 Mar 2020 12:04:26 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:6542:: with SMTP id z63ls2190441qkb.3.gmail; Mon, 09 Mar
 2020 12:04:25 -0700 (PDT)
X-Received: by 2002:a37:496:: with SMTP id 144mr2833839qke.403.1583780665850;
        Mon, 09 Mar 2020 12:04:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583780665; cv=none;
        d=google.com; s=arc-20160816;
        b=01lfXfw7qsdkwXwbmKBvqMJk6s8zi1j//8CtA0cjrU+1EH7y0O+C0nj238WY8/kJX4
         IxSGVOKolQ7iUFx7A/KVMW9Qx+ouCdnA7jMvhfLRpw8I1xdpTSY7UyX+ErGD7buonBgD
         EcPpGG8q9VMfgZFkqKQz4Hwut2v0MHsgOS6948a4Te5A+4GvtYNK7QX2UAFJQYb/ERux
         IbLOZTXxDI6SfuYZnsgWSIxlfU3dErhrgYhOc0gpbKjmSyOwhlohQLgRDwGDv2/EmVl5
         teI+PM5kNXmuL0zFZj/t7zgef37SudHDe1bX3l8hymtpU9AZeJZOhuATZ7EH1zQa+6/F
         kL9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=iWjMAFNzF6h0jAva2BT/l+NY/b/4sxIeSiuhpKm5knQ=;
        b=FzeDUN4QCX/E1w1afXxolkbGxehxl308kv31NTKekU1IC7yRCRrYvavfJpyRBpQedH
         NyswwGfv589wBPSJloUm7dBFD9+7Vvab4qYlJEvVmqWHbtytN+tqvdzL0HR1C9FNzK0g
         6BCltQfwxQPT1Xqzg9jco1tjI+Vi7wd3Vm7YH2i4a43xhmKP8/sIPdde4cuP90ZzJyFl
         MKJKWiYhHkb/vMa/nOjdWPAPvWAdSKd1Cs/CZF22enrbgW2+e6XnM3F3698gUSLIpPXJ
         V5L94m+o8S/lRqSSpFwMMcY7wPOXORZfEtM9I0hg572gkX4Q2J4ps7lCaRmH0U3ZZf0T
         Z0wg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=hIvCA7JD;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id w53si592945qtb.4.2020.03.09.12.04.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Mar 2020 12:04:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id D19F924658;
	Mon,  9 Mar 2020 19:04:24 +0000 (UTC)
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
	"Paul E. McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 11/32] kcsan: Add docbook header for data_race()
Date: Mon,  9 Mar 2020 12:03:59 -0700
Message-Id: <20200309190420.6100-11-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200309190359.GA5822@paulmck-ThinkPad-P72>
References: <20200309190359.GA5822@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=hIvCA7JD;       spf=pass
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

From: "Paul E. McKenney" <paulmck@kernel.org>

Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
Cc: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
---
 include/linux/compiler.h | 14 ++++++++------
 1 file changed, 8 insertions(+), 6 deletions(-)

diff --git a/include/linux/compiler.h b/include/linux/compiler.h
index 8c0beb1..c1bdf37 100644
--- a/include/linux/compiler.h
+++ b/include/linux/compiler.h
@@ -315,13 +315,15 @@ unsigned long read_word_at_a_time(const void *addr)
 
 #include <linux/kcsan.h>
 
-/*
- * data_race(): macro to document that accesses in an expression may conflict with
- * other concurrent accesses resulting in data races, but the resulting
- * behaviour is deemed safe regardless.
+/**
+ * data_race - mark an expression as containing intentional data races
+ *
+ * This data_race() macro is useful for situations in which data races
+ * should be forgiven.  One example is diagnostic code that accesses
+ * shared variables but is not a part of the core synchronization design.
  *
- * This macro *does not* affect normal code generation, but is a hint to tooling
- * that data races here should be ignored.
+ * This macro *does not* affect normal code generation, but is a hint
+ * to tooling that data races here are to be ignored.
  */
 #define data_race(expr)                                                        \
 	({                                                                     \
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200309190420.6100-11-paulmck%40kernel.org.
