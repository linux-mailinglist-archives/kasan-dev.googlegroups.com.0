Return-Path: <kasan-dev+bncBAABBYP5WT5AKGQEET3LPCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0CCF42580A5
	for <lists+kasan-dev@lfdr.de>; Mon, 31 Aug 2020 20:18:10 +0200 (CEST)
Received: by mail-io1-xd3a.google.com with SMTP id k133sf4649078iof.16
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Aug 2020 11:18:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598897889; cv=pass;
        d=google.com; s=arc-20160816;
        b=zrgySAg6ZdbbYQ1FoWyyCbelKUvD01fHzU3V+NTYXL7mB2OiyGUKbeJeyPnvuPgmrN
         v2GZpM0hWtyV0OSgn9PUAEEcWqZPhlpfDMqBgODefuYH2Hhcbh1enOIe6Bqhu+72B0PD
         MSJHLu6YavH+yIAozkwYxZT5rwxnNJcDjYXMvOaJdXhpod9jplbyR5ZTLxsIaUom1AYv
         UpM7O9DD8lQ8BUBKm7pk7QgWgHf/19XhuJLyrAY+KV3DB6BbTMyrrnRHpWNBZ3Ytj2hO
         IwSNWJiBVqM12Ep363Ujj3HYnDbb/anc3U95fm7J0RPAWCxQkoeSJ0bl1c7MCz0NlR1R
         NkJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=Gq3GjxtfOqHc5CMW7qPTF7tCzK+Q8GX9OQsLeDPvb0A=;
        b=Cq5JjJR+JbSI8LHkiU/2BvFZhtYBc4GZsflRbfHcNlY732gkmeV7Zlv7eUw7vbMche
         OtEbJOHutc9TW1ABGJZ9IsCFd7Ocauphi8y8Z4fPkNylrQ6pGmggEDS0o0KvU2M2vHWg
         tncNp5zaVlQphc9hRAgX/9OvLUhgn3hLFQ/S1rMeYPG3IbdMUkdbRiCconvmZyEtwhUD
         boeySZzqriSZ2DZ1PPeEL+SGj/zhfFhmLMmng5QZ+DlMS4BzeVe0KjXbT+/D4/wifLLj
         rot5fELjHeN5TF+HFLq2OGxC/2UYSwx1owaeFUvpEMkG0i61MqhBMdr39u8UCAabz76C
         qo5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=DxSc8+pg;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Gq3GjxtfOqHc5CMW7qPTF7tCzK+Q8GX9OQsLeDPvb0A=;
        b=nfQ6sFnzvxZQlT40fj7Ih/8VP+QHOf9PTyBybK6IGnhoKNvY6Ct9976/3cd0KPK4ox
         sDKpiZPBlNOi3h27VuStXqkCqqK6Sp7epu7qc/U4uNbCWSgfnmP/WfdQgM6zRym3dZJq
         OfUoe5iMmGLx+d6ruw7oXVf/W16VyO8AotGizryo9yxwAxE6BsIxgK5A0XfQbRJTpH73
         x6/mjendIpRnJ/cLFXxuqP42upqs3b8rIUeGVsu8xTg+ixw500DDLA4rk2OiFfgy1nl+
         dDq6dlZ7M86NZnBS7lCwpWAf1h+lce+wQuaj0IoTen6gbyVdQ3HusXPDc6W27tWscWLc
         I01g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Gq3GjxtfOqHc5CMW7qPTF7tCzK+Q8GX9OQsLeDPvb0A=;
        b=CW14Tc7u2LwkYdbMrySPCw/Xy72SN+Golwi8ectiU3AOtoduQ1bMKOYrUz0zzMyBi9
         7i6iiYmWEYZLHz4SeOpnQ9X6DPvKprrC9czgRyXEUFt57ZXlNa1oBr8m6p91Qe7Xe1TI
         HSOplmzIocJs2v84xNdyEEnLGsgPMFqH2w4XaaNTJMhPrFP862uZa26GcY0Wh5ifx+pF
         sN5Fu9T2OYCvfVdoJBFt/OSZ75qEQkXHpPbGYybzsWrzIr0Gz8QGz06W4JB6IKubFKWG
         sx5IV97IS86UoyS3QXWsiXcRky1jWtf7BpCbWx4sb3hwj5SDzwRA7+4Favo2gKvoBADD
         8wyg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533tvoCB5gFBdFZ3m5irBOoctFniJ8xDvaqFo7w3J9pgnof+9+6K
	HsmC98ujpj/FoKEoZTC0wx8=
X-Google-Smtp-Source: ABdhPJzGHMMW5VNwg4XNgsiTynlELZ1OTdsUyytLO0OCT7e1NuO5Mn1cGBSgepHPFC3qSJpfvOOUvw==
X-Received: by 2002:a05:6e02:dc5:: with SMTP id l5mr2525371ilj.112.1598897889078;
        Mon, 31 Aug 2020 11:18:09 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:b603:: with SMTP id h3ls423582jam.4.gmail; Mon, 31 Aug
 2020 11:18:08 -0700 (PDT)
X-Received: by 2002:a05:6638:1501:: with SMTP id b1mr2296051jat.93.1598897888841;
        Mon, 31 Aug 2020 11:18:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598897888; cv=none;
        d=google.com; s=arc-20160816;
        b=QihnSoolZrErn7eTEv34PzSp015EuyKVKxx9bhCzItB4iZk+X4etEhB2FrDsNDyOqZ
         aNvcgvoxjCn6sew3sYT0axEDuoOp2qsRvAh4h5iv/Oul49pz9LYb8tc4Jvm1VYCQizBQ
         gdfG+y+Dne2x4mqEGqqOsbYHM6bQY6fghsSyvynVNKPmCuTcLWNX7j4tejVruaIo6XFT
         EglpIJesc0n4jM6wjKgul17+fH4t1tP9kMyqhvmNpKxkrrmU3zQWFmof2XYnKdEdpr3r
         5evX1RvlNFMZwFPkuPA6JW1eCDWfd/a+hl7kw7hMen8ChYjZ0F3+oCUFn0WInD08JA8U
         tbWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=2s63zwzbUPiHzApYJJBP2c2g007qIThmgZjojQduUY4=;
        b=nwG3JWCQDgkAfqMuJp0DIrDaYexORbLGNfU6r+RhQO8wmIR0HwVWwxpol6ZTulNRTu
         4C+KLoqye29eBN2zFOousNlPA+v8Ct6+jmDmV9jVd90YloPFGbUXfwMyXAojfjUH4qKN
         V0WnKVNJl0kZJCCInnlT2yDMKwqu0q6rFlKtdq6t1fact30SSM0fwcJ/JA6E8LUiN4ec
         TUE6qJz6DXRp2E7euewtv3pLd8LwV+35LoQKJWHJ89V91+jWH3kGqq7PUzatI8W6tgnR
         jdRasE+ehsYiPI2vEBN/GpHp48Yg9HtLOXD5jfIkSIv/myxm+8+bi0bR2hDEMZdbORzF
         orlw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=DxSc8+pg;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y21si540299ior.2.2020.08.31.11.18.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 31 Aug 2020 11:18:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [50.45.173.55])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 23683215A4;
	Mon, 31 Aug 2020 18:18:08 +0000 (UTC)
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
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 12/19] kcsan: Simplify debugfs counter to name mapping
Date: Mon, 31 Aug 2020 11:17:58 -0700
Message-Id: <20200831181805.1833-12-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200831181715.GA1530@paulmck-ThinkPad-P72>
References: <20200831181715.GA1530@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=DxSc8+pg;       spf=pass
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

Simplify counter ID to name mapping by using an array with designated
inits. This way, we can turn a run-time BUG() into a compile-time static
assertion failure if a counter name is missing.

No functional change intended.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/debugfs.c | 33 +++++++++++++--------------------
 1 file changed, 13 insertions(+), 20 deletions(-)

diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
index 023e49c..3a9566a 100644
--- a/kernel/kcsan/debugfs.c
+++ b/kernel/kcsan/debugfs.c
@@ -19,6 +19,18 @@
  * Statistics counters.
  */
 static atomic_long_t counters[KCSAN_COUNTER_COUNT];
+static const char *const counter_names[] = {
+	[KCSAN_COUNTER_USED_WATCHPOINTS]		= "used_watchpoints",
+	[KCSAN_COUNTER_SETUP_WATCHPOINTS]		= "setup_watchpoints",
+	[KCSAN_COUNTER_DATA_RACES]			= "data_races",
+	[KCSAN_COUNTER_ASSERT_FAILURES]			= "assert_failures",
+	[KCSAN_COUNTER_NO_CAPACITY]			= "no_capacity",
+	[KCSAN_COUNTER_REPORT_RACES]			= "report_races",
+	[KCSAN_COUNTER_RACES_UNKNOWN_ORIGIN]		= "races_unknown_origin",
+	[KCSAN_COUNTER_UNENCODABLE_ACCESSES]		= "unencodable_accesses",
+	[KCSAN_COUNTER_ENCODING_FALSE_POSITIVES]	= "encoding_false_positives",
+};
+static_assert(ARRAY_SIZE(counter_names) == KCSAN_COUNTER_COUNT);
 
 /*
  * Addresses for filtering functions from reporting. This list can be used as a
@@ -39,24 +51,6 @@ static struct {
 };
 static DEFINE_SPINLOCK(report_filterlist_lock);
 
-static const char *counter_to_name(enum kcsan_counter_id id)
-{
-	switch (id) {
-	case KCSAN_COUNTER_USED_WATCHPOINTS:		return "used_watchpoints";
-	case KCSAN_COUNTER_SETUP_WATCHPOINTS:		return "setup_watchpoints";
-	case KCSAN_COUNTER_DATA_RACES:			return "data_races";
-	case KCSAN_COUNTER_ASSERT_FAILURES:		return "assert_failures";
-	case KCSAN_COUNTER_NO_CAPACITY:			return "no_capacity";
-	case KCSAN_COUNTER_REPORT_RACES:		return "report_races";
-	case KCSAN_COUNTER_RACES_UNKNOWN_ORIGIN:	return "races_unknown_origin";
-	case KCSAN_COUNTER_UNENCODABLE_ACCESSES:	return "unencodable_accesses";
-	case KCSAN_COUNTER_ENCODING_FALSE_POSITIVES:	return "encoding_false_positives";
-	case KCSAN_COUNTER_COUNT:
-		BUG();
-	}
-	return NULL;
-}
-
 void kcsan_counter_inc(enum kcsan_counter_id id)
 {
 	atomic_long_inc(&counters[id]);
@@ -271,8 +265,7 @@ static int show_info(struct seq_file *file, void *v)
 	/* show stats */
 	seq_printf(file, "enabled: %i\n", READ_ONCE(kcsan_enabled));
 	for (i = 0; i < KCSAN_COUNTER_COUNT; ++i)
-		seq_printf(file, "%s: %ld\n", counter_to_name(i),
-			   atomic_long_read(&counters[i]));
+		seq_printf(file, "%s: %ld\n", counter_names[i], atomic_long_read(&counters[i]));
 
 	/* show filter functions, and filter type */
 	spin_lock_irqsave(&report_filterlist_lock, flags);
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200831181805.1833-12-paulmck%40kernel.org.
