Return-Path: <kasan-dev+bncBCS4VDMYRUNBB75J4SGQMGQE3NDIFKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E22B474D93
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 23:04:48 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id b3-20020a2ebc03000000b0021ffe75b14csf5981355ljf.5
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 14:04:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639519487; cv=pass;
        d=google.com; s=arc-20160816;
        b=GfwnYIkZ+aao+zqhiv0eGu9+d6g+c99zc7ZQvNHO8M5/C2XbZibBV5bGOLlMV9c9kP
         PfBLsO+ocrKfYABhVOY1WRCuEszwsv3f+ppOjrjogNPI5W0+Etzy9t4qdv+ix5zFX4vl
         1q7MpwfU2TkBrsrpSK493N9ffjdieVAMV1zmUsRChfmpnQ6peCBSC0JQt8jJ1J6ImlPy
         lGeU2zuo4ou0neM8EmkJeC3337VgKOqnnRZuXjDcf5PPDvNqigf3aJIQqY3ztcHu/VUj
         elw+R4z5TE5+zf5NRH5W43T0l3p/OgMm724UstLkUm5tv/iDIhtpVBEeMuJCSygyOWTT
         nlBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=R/DdZonmh08Fd+UjBQ2wWwHZZ2OgPzcCtHbmy8PDxNA=;
        b=ZqZZ+Mtmhkv6R3YoqMzmENfqx4f+x58MIaG77FM0Ic++rrUjVaJWcisZKT9FWSw7bI
         gHvQOkufnK9noBpLfp/xgZXk1bfy6WdBpqqtOG6NBpWR5Z/f+gsKkNL97k4xZjW432QA
         bY7T+z5vc+TtpngIdRw+DMwmj2uQJE9lkJgbdaUHe9cmoyKKHgpi47QcpzKbJp1J+V2a
         8M3G7hWjH0OoBDacxmGQzTIDppo0/2P9zRS3Ig3TovXJn97N9HH0/QBETL/ci1pGX0Ib
         EsKGRTnTeOvRPL2Quq9T2dJ36x/hlky92S7H62pAjeXka6x6E7DpkLAPfADWm0vVUDmZ
         9rYw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QoCIj1bZ;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R/DdZonmh08Fd+UjBQ2wWwHZZ2OgPzcCtHbmy8PDxNA=;
        b=mX6toy9hkmwfjI8bmHj+xZK3mcK7PEmR8tVmrbe7csBq/1cEmEv8JjpzuGzM9KXgY0
         TlKnaslDBVzXxxqryrKb21nifoOXAKH98Z2rOCk7nCB8ch9JlfgzJLNpBM6U+Y01RNBX
         OzChtjX69LUNhM1h9HeFH9E1RCqV9tWQRzgcb987HQfJQ9zqXnsZL1ut/HzqpA0GJL63
         rIKcMNyytG5naapl/ERSILWNBo6qWicfZRGe3uSUP6CBVFZ+MsP4YfQZ4obJc2R8VO0j
         EyCRNAl/HwbdmVqCgq7BQ3tRDxhgeLSfLiQ3WS2k4ilXB0JS5tsEqL7AHQmPtz2dW+2U
         TIcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R/DdZonmh08Fd+UjBQ2wWwHZZ2OgPzcCtHbmy8PDxNA=;
        b=tm/AClSZx9+8g9H5wpXSmwU4/iDFae79AS9XrNmcikTfL/yji9rl/c0wmgy0UdyzcS
         A6SZtb9YlEK4uPr5xuypu25jNAnmbsxakiEyQj+6pld2BZAjlKITiqS1q/vi9C3Wko7w
         LnWOYKOI6eGICCriLkT+iVq/EuvNXREZo3Ic/isLCWiazf6+KSOF5qkAHfFtu93Oykw4
         VWlIPrpLE5+e6x7y/DAK/KS1dn2Z4mol3db2ywpqfT+wxJ54YC5Ixq1wjW1tnaR5I5g6
         dzqQugG45aLsnhfRlujNtNVlECTF8a0Fxu86avlHvYwhxX48wVmEXGMfwb1LAG7C+CEC
         mYzw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531/2N8G6M1Gb6iAkzRPtSELymrb1+2bDtD27ECYkImXWcsbBSme
	FqAGcXQ/cOaMaIgX6pqhzOQ=
X-Google-Smtp-Source: ABdhPJyoJOKpv+HLQmAKiDTLcjgExmkVy1QU/rgsELNLS+q+SpS6p43kKbt0y48LeiGlNa5v1lvZLA==
X-Received: by 2002:a05:6512:3f27:: with SMTP id y39mr7132724lfa.675.1639519487705;
        Tue, 14 Dec 2021 14:04:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:234c:: with SMTP id p12ls100630lfu.0.gmail; Tue, 14
 Dec 2021 14:04:46 -0800 (PST)
X-Received: by 2002:a05:6512:16a1:: with SMTP id bu33mr7199818lfb.129.1639519486582;
        Tue, 14 Dec 2021 14:04:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639519486; cv=none;
        d=google.com; s=arc-20160816;
        b=jhn4jUjHAxp8D7Aa6wK7zBEHm12xHoxuZeA4vN2ifCAePxzE/JVrntbtzxawaGNOpz
         D3KwD/ArzNnldpF51qjwaRr2+19utnKwn1dz+F0daTF6mLKWzOTbMzBhgqiAGVAHv9Gb
         5f0I9+/il41uTlpxYjLso+2a+AgTsoTnq8wBbCDuQI9O3DiZRO+ckp7sr8QWKfbX/Au0
         Ozi8myfgoPactjlKnikrbWbU2eSzCwmJIz+jQtSWqO7G1vb52R0YT7OtBjF/7tK/iIfV
         u7Se0TKEEceYgHBMMpWxKYqaw8uYrdutC8DXMJAz4ZiPNCVbx2Cum1tB5yK7IG3Qwwvt
         zPuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=lgg3Mb6GYJCWBp/gg1bstIbwy0JjGZc8WrY4YxVax2I=;
        b=TemJ2btKJ1E9dbEus3CrekxUFVp6WEqh5VG4wFzZmu+ZY2kJ8c6uHp4HrmhqD6uHAS
         sThlykojm6GB4VO28oC84FA69P+TOoxqk04mKFnEeGio98aAidbpUw0dvup2cMxZYczt
         SCP22XE8KGqWSWvMJ3i+FfJTjnjmFkrwNEDuu9ANG1inam8jHBlN5RSGOt73A15KYSAU
         YwWchFywCDF0MfiDASuyhwi5aBvKAzeS5NU1Rg/EPstbEkLVE/uXbhffkRKxdRwvDBQ7
         ftq4legbEXrFLjSfX5R1G72hYY8oP1bu7GhjpAClD+9vSsQdohpOlOypNTH6rpgSJate
         MkaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QoCIj1bZ;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id e15si5195ljg.0.2021.12.14.14.04.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Dec 2021 14:04:46 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 67BA161766;
	Tue, 14 Dec 2021 22:04:44 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3B019C34638;
	Tue, 14 Dec 2021 22:04:42 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 886E05C1F98; Tue, 14 Dec 2021 14:04:41 -0800 (PST)
From: "Paul E. McKenney" <paulmck@kernel.org>
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
Subject: [PATCH kcsan 24/29] compiler_attributes.h: Add __disable_sanitizer_instrumentation
Date: Tue, 14 Dec 2021 14:04:34 -0800
Message-Id: <20211214220439.2236564-24-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
References: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=QoCIj1bZ;       spf=pass
 (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

From: Alexander Potapenko <glider@google.com>

The new attribute maps to
__attribute__((disable_sanitizer_instrumentation)), which will be
supported by Clang >= 14.0. Future support in GCC is also possible.

This attribute disables compiler instrumentation for kernel sanitizer
tools, making it easier to implement noinstr. It is different from the
existing __no_sanitize* attributes, which may still allow certain types
of instrumentation to prevent false positives.

Signed-off-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 include/linux/compiler_attributes.h | 18 ++++++++++++++++++
 1 file changed, 18 insertions(+)

diff --git a/include/linux/compiler_attributes.h b/include/linux/compiler_attributes.h
index b9121afd87331..37e2600202216 100644
--- a/include/linux/compiler_attributes.h
+++ b/include/linux/compiler_attributes.h
@@ -308,6 +308,24 @@
 # define __compiletime_warning(msg)
 #endif
 
+/*
+ * Optional: only supported since clang >= 14.0
+ *
+ * clang: https://clang.llvm.org/docs/AttributeReference.html#disable-sanitizer-instrumentation
+ *
+ * disable_sanitizer_instrumentation is not always similar to
+ * no_sanitize((<sanitizer-name>)): the latter may still let specific sanitizers
+ * insert code into functions to prevent false positives. Unlike that,
+ * disable_sanitizer_instrumentation prevents all kinds of instrumentation to
+ * functions with the attribute.
+ */
+#if __has_attribute(disable_sanitizer_instrumentation)
+# define __disable_sanitizer_instrumentation \
+	 __attribute__((disable_sanitizer_instrumentation))
+#else
+# define __disable_sanitizer_instrumentation
+#endif
+
 /*
  *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html#index-weak-function-attribute
  *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Variable-Attributes.html#index-weak-variable-attribute
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211214220439.2236564-24-paulmck%40kernel.org.
