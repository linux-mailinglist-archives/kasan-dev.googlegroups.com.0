Return-Path: <kasan-dev+bncBAABBYH5WT5AKGQEXAV6IBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id A42902580A0
	for <lists+kasan-dev@lfdr.de>; Mon, 31 Aug 2020 20:18:09 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id a14sf9944205ybm.13
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Aug 2020 11:18:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598897888; cv=pass;
        d=google.com; s=arc-20160816;
        b=OAigSThDN8gTSBj7Oyn+ksk48pstauarlZlyqoVwHeb1q47Bq4wBKtXMH8vTlb+XmM
         HRR1C1pQT1fRjnWcF2FBsOqwr2fZ7DpbUQQzcw7EUldFRiesuwQGw/Jcp2wgLY6MxYfU
         5sDe1nUl7HtQEjAl2MxMmWqh9UVApOOLNAC9qfeChbIwwiBg9Xw9MYm0CN/tOXSxn/Fl
         mVUPu3n56FVmo098sBX7iw2rgh66MLrS6mQHTjvcnaRXtNGxSIt17O8ES9sXLZWCpx9R
         o8CLr0JKuys2wU9Pa/WvW+xSKTn9snJUXUaHc+2ty1hNCAdR1RxjoQVFJovn84uL2/CD
         Yxww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=ucECDZvTcnO//toV3xjNFhalBJfoMZvEjo2tfSye+mk=;
        b=lSBjjBB81VJRReCgMuwxxIVjmQnHo13IaOdiSjXyXa3wvHQ6A0K6t3WtL/DzqoiFOK
         T8Y0M2VnShXuR7zIKSIfqj2aSw7MwTLRYFzClP8y/5uTgLtK0P89RrqVhvrdNI2YAqTp
         s7aL/hV3/ksVljolppHqHFoV5pC+c/Y7VlH5WMCii9y8bvcTEZc/GK8zM+v4GEJq95qt
         r1b+6ePa+j0nlk9v6oQ98BC8I3eTg6woJ+bLqOPmU3JsdX6lICgXgOyz7QS2/gxBmiLF
         hLFo1lqMQivIpq6wsvl3oB+1y1Tw4AP/moP4t5b0+f3/OPUdkICpYZPelQxK5DXCdsr+
         UNbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=yovMFVrO;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ucECDZvTcnO//toV3xjNFhalBJfoMZvEjo2tfSye+mk=;
        b=YSyYTjegYCgp7S6xDvtvvI5l7CSLgyR8J+VyuY9Ba7Za3o0Hb/n2x9mnF086//sfyv
         VOQd9QYKGaf3dJWZ7w6+g4kHhhyiRCmKuV+lGKSvIwaPkSaxk0MwyESl2wAURYv9cRpq
         3qI3wjnsoJD0B4x0PaVl2QmEFVZ7sMkyfWRV0cTZaJZB7EQw7uzq+K1Ue67SfA6Du0/h
         XXG3BkOAsC+f2JQPqxzEl4CHFwwoIyaHUANngIHGF2k5H0Uh/4tAz7ZutgtVyd0j8cAZ
         /zNT4amRBv7AgOR1A4uKML4Kk219TBozqaYVxfHSiozMVzJ5wfNncuxYqJJfgY1fYce8
         /Oig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ucECDZvTcnO//toV3xjNFhalBJfoMZvEjo2tfSye+mk=;
        b=BpbSkT1z0btEHnr17/0vRlA8cDccTpsbIELgZK9km3n3ThHZrLL7VMYtF9k20ppMr2
         Kj6+N8NSAIq2EVIiHKcEH1DIOVYx9aOMjc2Y5a76NfnEOjqPwaRwzpLoRG7L4iJq+sOe
         LpVGeroQ44H6kAc1iNkovLCoM3b7rp3bAmv5rPyH341qt4mNNIcJmB4Bsyz+xSPMvv8f
         D38+tQHMCZK6fiH/HSxtFr+ZvNdxXSI4XoaulMuykNB43/GsazUnvP61VZg57jeQ8ro8
         XMB4vdl9znivywEhEBVMMt55KvjTo+VOjqoB+flblikaK0syNhxZ/pPDEh2gTdBqhrM5
         vTAQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533AvnVQMGDyt/CEEfcgf4SQeUlFEfyKwpVpLSOOh1yE9FdYQ0sZ
	KowCazjux2SOFBsENX8LVB4=
X-Google-Smtp-Source: ABdhPJw5op0Fwgbisai1HCA8619tUAFdYzv8Jgw8HeQRfEWCtzf35jZ5l2PtZ6Z3KB2Js+u47TZ8ZQ==
X-Received: by 2002:a5b:403:: with SMTP id m3mr4049461ybp.514.1598897888535;
        Mon, 31 Aug 2020 11:18:08 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:b612:: with SMTP id r18ls3214423ybj.10.gmail; Mon, 31
 Aug 2020 11:18:08 -0700 (PDT)
X-Received: by 2002:a25:4ed6:: with SMTP id c205mr4120334ybb.279.1598897888195;
        Mon, 31 Aug 2020 11:18:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598897888; cv=none;
        d=google.com; s=arc-20160816;
        b=G9Ws9eIekqeHL7Olc1aY4wVK2u+vjNeCaa0qcR1zNaeLqf9NaTmV6Ysa3urcYkx9nS
         eTcN19ohlDCswRJ/6Rb0mr8ZotYHy4zN9GmV1E8QaVxo31fTz9KVND00YGU4vi05vQTy
         k3+IXVlk5IFPTaZ11DSIlhEan+J4ciWN8wok3257Md3OCgOAI82tIWPPkJiOSG9DlbhD
         JJ4sAJh2USOKPuYIZzZYF2xY5dTtw0IGvXIpt3xk7f5UwDap8yYkz6CrZN6qdzutCMKg
         6Aycgkliu3JEl5oQosqrQoaeiFue24CKh6c34lgpAFlOfQQN4uPnnq5dj8P+XkrA/e69
         w15Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=UoRE0fkcejE9udJT2YvhQLoqV+rFVnh5EqPNuD/lSNQ=;
        b=qIYOCQ457JaCnKu/hbLbWOHXGrMIcniQ9vigw9qathPzSpGDeGQNipO2xsTI7xuTVe
         GKFKCG2qR5g2DZTU8gQ306qsmUTAWXIHBzdUD8YxDeEzjrvABqE3/7gquN5WU3nyEpoC
         Q/eudukB/Fp8hj7INPZQs7/BiM89EQnt05w23zjAStQMqgPpHEOazs4lw+9nwuwbMm4K
         FKXGuJe5Nenm8eI4bFXMz1IjfDCFfA5dKF0NcBmJw1Mm4hX1GtIFk/m0tDz7e5jJkvI6
         +jMAVyDmsUxhp8sH8GwYeBC9Ejb06Sly2b/QMUv2T6+GJzXGbc8MoKSnOm6S2oSBwhiG
         G3Yg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=yovMFVrO;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id m193si568341ybf.1.2020.08.31.11.18.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 31 Aug 2020 11:18:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [50.45.173.55])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 4D5DE214D8;
	Mon, 31 Aug 2020 18:18:07 +0000 (UTC)
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
Subject: [PATCH kcsan 07/19] kcsan: Add missing CONFIG_KCSAN_IGNORE_ATOMICS checks
Date: Mon, 31 Aug 2020 11:17:53 -0700
Message-Id: <20200831181805.1833-7-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200831181715.GA1530@paulmck-ThinkPad-P72>
References: <20200831181715.GA1530@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=yovMFVrO;       spf=pass
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

Add missing CONFIG_KCSAN_IGNORE_ATOMICS checks for the builtin atomics
instrumentation.

Acked-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/core.c | 30 ++++++++++++++++++++++--------
 1 file changed, 22 insertions(+), 8 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 95a364e..99e5044 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -914,14 +914,19 @@ EXPORT_SYMBOL(__tsan_init);
 	u##bits __tsan_atomic##bits##_load(const u##bits *ptr, int memorder);                      \
 	u##bits __tsan_atomic##bits##_load(const u##bits *ptr, int memorder)                       \
 	{                                                                                          \
-		check_access(ptr, bits / BITS_PER_BYTE, KCSAN_ACCESS_ATOMIC);                      \
+		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
+			check_access(ptr, bits / BITS_PER_BYTE, KCSAN_ACCESS_ATOMIC);              \
+		}                                                                                  \
 		return __atomic_load_n(ptr, memorder);                                             \
 	}                                                                                          \
 	EXPORT_SYMBOL(__tsan_atomic##bits##_load);                                                 \
 	void __tsan_atomic##bits##_store(u##bits *ptr, u##bits v, int memorder);                   \
 	void __tsan_atomic##bits##_store(u##bits *ptr, u##bits v, int memorder)                    \
 	{                                                                                          \
-		check_access(ptr, bits / BITS_PER_BYTE, KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC); \
+		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
+			check_access(ptr, bits / BITS_PER_BYTE,                                    \
+				     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC);                    \
+		}                                                                                  \
 		__atomic_store_n(ptr, v, memorder);                                                \
 	}                                                                                          \
 	EXPORT_SYMBOL(__tsan_atomic##bits##_store)
@@ -930,8 +935,11 @@ EXPORT_SYMBOL(__tsan_init);
 	u##bits __tsan_atomic##bits##_##op(u##bits *ptr, u##bits v, int memorder);                 \
 	u##bits __tsan_atomic##bits##_##op(u##bits *ptr, u##bits v, int memorder)                  \
 	{                                                                                          \
-		check_access(ptr, bits / BITS_PER_BYTE,                                            \
-			     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC);    \
+		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
+			check_access(ptr, bits / BITS_PER_BYTE,                                    \
+				     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
+					     KCSAN_ACCESS_ATOMIC);                                 \
+		}                                                                                  \
 		return __atomic_##op##suffix(ptr, v, memorder);                                    \
 	}                                                                                          \
 	EXPORT_SYMBOL(__tsan_atomic##bits##_##op)
@@ -959,8 +967,11 @@ EXPORT_SYMBOL(__tsan_init);
 	int __tsan_atomic##bits##_compare_exchange_##strength(u##bits *ptr, u##bits *exp,          \
 							      u##bits val, int mo, int fail_mo)    \
 	{                                                                                          \
-		check_access(ptr, bits / BITS_PER_BYTE,                                            \
-			     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC);    \
+		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
+			check_access(ptr, bits / BITS_PER_BYTE,                                    \
+				     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
+					     KCSAN_ACCESS_ATOMIC);                                 \
+		}                                                                                  \
 		return __atomic_compare_exchange_n(ptr, exp, val, weak, mo, fail_mo);              \
 	}                                                                                          \
 	EXPORT_SYMBOL(__tsan_atomic##bits##_compare_exchange_##strength)
@@ -971,8 +982,11 @@ EXPORT_SYMBOL(__tsan_init);
 	u##bits __tsan_atomic##bits##_compare_exchange_val(u##bits *ptr, u##bits exp, u##bits val, \
 							   int mo, int fail_mo)                    \
 	{                                                                                          \
-		check_access(ptr, bits / BITS_PER_BYTE,                                            \
-			     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC);    \
+		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
+			check_access(ptr, bits / BITS_PER_BYTE,                                    \
+				     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
+					     KCSAN_ACCESS_ATOMIC);                                 \
+		}                                                                                  \
 		__atomic_compare_exchange_n(ptr, &exp, val, 0, mo, fail_mo);                       \
 		return exp;                                                                        \
 	}                                                                                          \
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200831181805.1833-7-paulmck%40kernel.org.
