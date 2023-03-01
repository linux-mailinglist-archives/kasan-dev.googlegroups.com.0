Return-Path: <kasan-dev+bncBCCMH5WKTMGRBMWH7WPQMGQEAVKBO3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 48F7D6A6E99
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Mar 2023 15:39:47 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id b30-20020a05651c0b1e00b002959c2fb94fsf4155673ljr.20
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Mar 2023 06:39:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677681586; cv=pass;
        d=google.com; s=arc-20160816;
        b=RBg9+92PGP5J+2tr7O6D7o1/VYrw7k6e12SDCcmAa6M7riOhLGqSQ/3ELsVJ1HzbQv
         PZIyFxkOviO2JhfVyGuJl0ILe/GxsQd/O2sSeI4zPVcVZsl6Wa3cYtR1x+I5R+W0n2DX
         p1oqeKjUze4j4ZIeHY6JEUXeUzD64i/RbSDNJibQQbx8JnmEbiri9x46inCGZS2kjwDO
         KWj9OKVxLLpJkeDKfO7S5/GFh2iJicNwwSlp5OJ7NLTGKFYbotfaqNNXlmqZ9l3GbR3h
         EqtK4hxvieENeafbfkDjcFuIJX/mlyyEtUOCw/nYGn5BdJIQbJCsFN3LDvhO6Im/uLYk
         uIDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=yGZP7QkooCYJHOW/OcWZv777DIkUxmnR0lEPQiWVFQ4=;
        b=WwLa9LvnMRHAuT5fykJ/mKcz682n9YAOxeSyP1ptfqYA0XwEAhrfW48mdQUvS43srb
         00ppA7K5NaTFsUpTLI58DPA9p773xc2C31lpJShV/acblCQ5Oz67OKWgpjGRJlSj4gYZ
         jY8BPjkyhvbPx6yHxL4tXSCWzyYCYyBnwhfmNnm/92CwZF4FjotuNr1gtMxNu5G7sDVC
         z/o7fu6AGIqHhqCmIEsAvm4qGF/Wu7sX4szxkyUaFUwvLFYG5HNJNwwMOXepYri6TwwU
         YdlyXkiplHtU5mEFRVhoBjHGJef2V2PCMe7NS0URVN2hpxbmPUAcpQ2pSzpjcrHUfv/I
         EnTQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=cATkgsuo;
       spf=pass (google.com: domain of 3swp_ywykczwche9anckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3sWP_YwYKCZwCHE9ANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=yGZP7QkooCYJHOW/OcWZv777DIkUxmnR0lEPQiWVFQ4=;
        b=qKLexVDB4qtPXLCVQG3k4Sv8c+nOnPPFQ7F105M3i+vcREJaR9PO055J0SHlW1zUoc
         /WK0iZqua9T81Fu4G8cCGIDrxi89Wc9aOTtymWrfhrkP8wG0msXyhGYDWyyLLe6knKPn
         OdyDj7UBHlf9iICFwhIdmk+VvZCJx8vMe4BwSJesZSti+QYiFjVr/nWMzoIU+O/Wk/nK
         0k3epWG49FqQ1IIiNitvCHxz+SZZnoFrUppb46tm8p4RbXehQn9UUiBJLrzkqfsn10FE
         4G56O9Cx8DYDr6aJ3PMqUW2sWG1V3lPQe86JPb3J7apqMS3FJuAgf0GtrAyYn1DFa4ZQ
         hooQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=yGZP7QkooCYJHOW/OcWZv777DIkUxmnR0lEPQiWVFQ4=;
        b=jXeQmdduK+NC8KFA1/U1CkMgzeBunaY/5NlTVATWjOh58vOLzbmPhmeyFOP/NLP5Yh
         GLCjDnjEQx/4BuACQtACWJLFIzDUj19EKD9rqdqLLooekMCDPWkN12OLVFe0SOUV+2i5
         IFI4fFMGsYctLYLQ5+IdTZbN5OCfPtaPCRBM8jrSjRWKlW0qbdmWpp5wd2f+u1qlQBHm
         DtzUSFOysB7c0M1RfVN3072OBKVT1KCO36GT9nXqY0157DMFZiSvzIARLg1jtWKpPR0q
         IrwakIhanzmQAl0y5ba/FHyQN9q3raemLU1e3m5s39OHSJs+VqUFf86/2LhlBggC3Agn
         y8YA==
X-Gm-Message-State: AO0yUKU7I2Xw059bQO4TGJGQJarkdLWZYgUOINqaYICcbGIHt22LeB78
	uK/cGE6o9Nx+CT/UpOlVMHU=
X-Google-Smtp-Source: AK7set9d4BT/yhAmpa4Q0+NXduOyIzYvbhCl9ACVaSkFXza7RJFrrVbQqhzQWllUxKT0AN2zCkWW/w==
X-Received: by 2002:a05:6512:4020:b0:4dd:a379:f24c with SMTP id br32-20020a056512402000b004dda379f24cmr7772867lfb.6.1677681586800;
        Wed, 01 Mar 2023 06:39:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3055:b0:4db:5081:6ce7 with SMTP id
 b21-20020a056512305500b004db50816ce7ls286452lfb.1.-pod-prod-gmail; Wed, 01
 Mar 2023 06:39:45 -0800 (PST)
X-Received: by 2002:ac2:5544:0:b0:4dd:a788:7783 with SMTP id l4-20020ac25544000000b004dda7887783mr1537795lfk.61.1677681585397;
        Wed, 01 Mar 2023 06:39:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677681585; cv=none;
        d=google.com; s=arc-20160816;
        b=i6YcO64Q/7H76XwipLJHMllpfd1cUel4ztTIk0QBaV/JrPR3tZkyCjW3yj8GiJwqvz
         Kkeix871huQnyJEkGH4R2HNq4vlVC57fPA3sK7AIYdgaE6B4H8g5/roesAHpoXSVIk8X
         GrE+Gbxs3c0QucmbUU5KyCHcifhXw+K7WvsyICRG0NG5CI3OTo1/FSicOxbrO1m3Uy/g
         ycihtksLSan+XRW3viQjDNczsUDD2YNp6IpMva5z3FH9u0ITuxziBsPggTyYs/CbPjmf
         U0DfPo8jEZ1digtKg8hVAANwA3inruCKFCVhD2rZw536c9FMCcsdqaJ8Z9oouYrn5CBl
         Jldw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=nI6aPFa9WKtq8ZRbJBabpyygWI3BetO7s5boeToCFf4=;
        b=BAj2sJss6PtLncQCCPvlMUWKPGxL5DgQFLFeiQMA75P3ZDS7G8cnMm/fbtutZkdMtA
         BFufFt3Q43u6EQI+RI6dAsf5if+TVnViPF8QcNpbH9VDaP/03c5U2SAdj5A2in3El+p8
         lHq22ut4U1fnOnCOqzFpl6MIsPlr/mYlGMH0Zqsdrw20d2gWnH/eJ/7AiJu24izMD8Qu
         X49fYY+1k3kfna/hq02R+L+cBIiQJmgzyCtEEnKgWlOx7+IWAcLKxjb9mTRaIZMiKoXN
         RlWIOWE7u4FLeHWL/UXKVgAOmkINcT1jQDpEkRDIX48fCbXrZjc88AuhBJml4xg3sZZa
         wLig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=cATkgsuo;
       spf=pass (google.com: domain of 3swp_ywykczwche9anckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3sWP_YwYKCZwCHE9ANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id e19-20020ac25473000000b004dcbff74a12si579505lfn.8.2023.03.01.06.39.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 01 Mar 2023 06:39:45 -0800 (PST)
Received-SPF: pass (google.com: domain of 3swp_ywykczwche9anckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id cf11-20020a0564020b8b00b0049ec3a108beso19363161edb.7
        for <kasan-dev@googlegroups.com>; Wed, 01 Mar 2023 06:39:45 -0800 (PST)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:3c31:b0cf:1498:e916])
 (user=glider job=sendgmr) by 2002:a17:906:ce59:b0:888:b471:8e18 with SMTP id
 se25-20020a170906ce5900b00888b4718e18mr3181793ejb.8.1677681585154; Wed, 01
 Mar 2023 06:39:45 -0800 (PST)
Date: Wed,  1 Mar 2023 15:39:33 +0100
In-Reply-To: <20230301143933.2374658-1-glider@google.com>
Mime-Version: 1.0
References: <20230301143933.2374658-1-glider@google.com>
X-Mailer: git-send-email 2.39.2.722.g9855ee24e9-goog
Message-ID: <20230301143933.2374658-4-glider@google.com>
Subject: [PATCH 4/4] kmsan: add memsetXX tests
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, tglx@linutronix.de, 
	mingo@redhat.com, bp@alien8.de, x86@kernel.org, dave.hansen@linux.intel.com, 
	hpa@zytor.com, akpm@linux-foundation.org, elver@google.com, 
	dvyukov@google.com, nathan@kernel.org, ndesaulniers@google.com, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=cATkgsuo;       spf=pass
 (google.com: domain of 3swp_ywykczwche9anckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3sWP_YwYKCZwCHE9ANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

Add tests ensuring that memset16()/memset32()/memset64() are
instrumented by KMSAN and correctly initialize the memory.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
 mm/kmsan/kmsan_test.c | 22 ++++++++++++++++++++++
 1 file changed, 22 insertions(+)

diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
index cc98a3f4e0899..e450a000441fb 100644
--- a/mm/kmsan/kmsan_test.c
+++ b/mm/kmsan/kmsan_test.c
@@ -503,6 +503,25 @@ static void test_memcpy_aligned_to_unaligned2(struct kunit *test)
 	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
 }
 
+/* Generate test cases for memset16(), memset32(), memset64(). */
+#define DEFINE_TEST_MEMSETXX(size, var_ty)                                  \
+	static void test_memset##size(struct kunit *test)                   \
+	{                                                                   \
+		EXPECTATION_NO_REPORT(expect);                              \
+		volatile var_ty uninit;                                     \
+                                                                            \
+		kunit_info(test,                                            \
+			   "memset" #size "() should initialize memory\n"); \
+		DO_NOT_OPTIMIZE(uninit);                                    \
+		memset##size((var_ty *)&uninit, 0, 1);                      \
+		kmsan_check_memory((void *)&uninit, sizeof(uninit));        \
+		KUNIT_EXPECT_TRUE(test, report_matches(&expect));           \
+	}
+
+DEFINE_TEST_MEMSETXX(16, uint16_t)
+DEFINE_TEST_MEMSETXX(32, uint32_t)
+DEFINE_TEST_MEMSETXX(64, uint64_t)
+
 static noinline void fibonacci(int *array, int size, int start)
 {
 	if (start < 2 || (start == size))
@@ -549,6 +568,9 @@ static struct kunit_case kmsan_test_cases[] = {
 	KUNIT_CASE(test_memcpy_aligned_to_aligned),
 	KUNIT_CASE(test_memcpy_aligned_to_unaligned),
 	KUNIT_CASE(test_memcpy_aligned_to_unaligned2),
+	KUNIT_CASE(test_memset16),
+	KUNIT_CASE(test_memset32),
+	KUNIT_CASE(test_memset64),
 	KUNIT_CASE(test_long_origin_chain),
 	{},
 };
-- 
2.39.2.722.g9855ee24e9-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230301143933.2374658-4-glider%40google.com.
