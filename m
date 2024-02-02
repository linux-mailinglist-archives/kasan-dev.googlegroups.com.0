Return-Path: <kasan-dev+bncBAABBDNG6OWQMGQEIOBHUEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 253CB846EFC
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Feb 2024 12:33:35 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-5101e12059asf1778745e87.0
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Feb 2024 03:33:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706873614; cv=pass;
        d=google.com; s=arc-20160816;
        b=fvK68EZS6dyfRhD+3KZ0hvmq6Eoqi4Sz+wr4YjlIN4d3lx/mhTIS3EbqHzKyS6i6k7
         2uDR7GTlKTRzazp/K/iJvETVwhoYIZIlqsTgQTkHQcxoGX+fyrL5/nSWfAUDN8Mm/eQW
         iTqduas755q3FgLdbL981EJvreNKU0/1CXl8hCugb17QpaWZ/DDrAR7ng+zNT/danq8c
         UvZRtiWAoZyI1OifqPT/+EntXdZNBRA8t91W8l6PlzBf4p0kO9QeWO6cUKRjEBQEFlju
         KuZPXART3arbihfAOpt+6H9uBf2bi77npNp2KDw+g4QA+0koPSX2RE09DQUL7RIbkk47
         AZgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:sender:dkim-signature;
        bh=pp1l6FE3N3ruOMxoUwtr9mBJ+It0nK/NLJArAQX83fI=;
        fh=evqNWWC5lqW2AYVLR4jUy1h92C6w5SG2uB80oSgcBVA=;
        b=peLIuiQN0WUyiYBoSLKFysfqnTzsV4jDd/jOO/yrlswnNo0uNLNQZZLKwPI8hRv/1s
         x31vrHKfuMaySqkHizHA5ZXqFz46yDjKAW4t/to/HjdcXTFxgO2ZDnbt/Zj5Lrn5fYlx
         m1nvZ5C75UzrJJXA37SQrg1Kb4mFRsRdxRkWMWA1lyRXGQTJlLczLoJ4qixA49rOVuH9
         zMQ2bH1JKW8+NedXKQXUO/bA8gk/jtGaA2oPgo37Kphvs3w/04C/d4jHx/z5iUZ2OBhP
         S4tM7UmXtekWMkMfnVmcmTBxsvjcrAJrhNadxo7XFEI24Sh/R5jB1M3wFx/BHYxqR6EH
         T/Mw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@tum.de header.s=tu-postout21 header.b="LH/t7DFy";
       spf=pass (google.com: domain of paul.heidekrueger@tum.de designates 2001:4ca0:0:103::81bb:ff8a as permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tum.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706873614; x=1707478414; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pp1l6FE3N3ruOMxoUwtr9mBJ+It0nK/NLJArAQX83fI=;
        b=Zysfw12wGTnhH+yE3o8ji8FlZD7tO55lkdCTC6HPUD019WvykRHq47gPbbRNLMSoJR
         ggfo9vZiqBKsPnz6EG0GtNZg+U9MuEYytEdu2HeZvnoVGsz/QxywheKiz53VWenUFzft
         oKPVQUydu8Z+7U0m0O24SnocTDqNBTE487t/ZzNvCMY1RjPARJcHCBR/RTxR9mchfk9N
         65MqqpNTdu3iW9IJaUFYZKGTai7raSj4Iv5nfofcXbC3873jOhK3NQTO//lv0OTS8lRn
         3m/aFWtg5u84eXMuwL+ezEyfuyRj+bHvpr5C/ptQMg89Voy2y4EU4hsco2MKOZc+a6mq
         WF5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706873614; x=1707478414;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=pp1l6FE3N3ruOMxoUwtr9mBJ+It0nK/NLJArAQX83fI=;
        b=erXzEj0QIJbdP4tLpF1qdYt/RKzXz9pRfv/cSY0dFSzvPtYyLeqg6WxYy0tjUmP5P8
         wgsViQHdprGcGJv86VWcmIudpbF8Za87w7THBJzW+q4AkQcYsdN/ZPXTqiNx1kXRq/n0
         /mcNjX0jWdt31cQRlfMaicY6DkZb6QAkeFr77BR86BzhnELTDUOgoplUSQnfE8y6bJuY
         NhE7NGPBk6uCdLtcvcfeUyhuH5YN4DR/5Mp621aKmZEpCtYdWAQCDZpz2hx3haW/xggk
         mT3RXp1IE0fW0XIaQx/ALvjTh4nFN1i3X7FjoCl1mPVdn/OuouDOxINXOmWguXRf8Thx
         4mFg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Ywu6+xLUTrDJfgsTq1a4vUyAeLz4Ht4QnhN9JO+B9XLx71BZsnh
	VvYx8iTfzMyn8KxjxkdF2H3Tv+ctb5NPmMF4Zfjtkz/CVV9l19Tj
X-Google-Smtp-Source: AGHT+IGgwbugcjUAToWZJvuv1DdjyY/u1hSqGENOr5rV2BjvW43IyXPLWM7iOPRb5fVbMa3vHwRo5Q==
X-Received: by 2002:a05:6512:481e:b0:511:2a1f:64f8 with SMTP id eo30-20020a056512481e00b005112a1f64f8mr1140513lfb.38.1706873613772;
        Fri, 02 Feb 2024 03:33:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e28:b0:511:3a75:9f31 with SMTP id
 i40-20020a0565123e2800b005113a759f31ls136362lfv.0.-pod-prod-04-eu; Fri, 02
 Feb 2024 03:33:32 -0800 (PST)
X-Received: by 2002:a19:e054:0:b0:511:1531:76aa with SMTP id g20-20020a19e054000000b00511153176aamr1172650lfj.64.1706873612113;
        Fri, 02 Feb 2024 03:33:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706873612; cv=none;
        d=google.com; s=arc-20160816;
        b=obvFYBGrCN/K3zbkyT6XBdqbI3R4ehZpk9oJiTxTze174lKJyqvajOL+0QbrHJly53
         t/cS7LuBAvzMIF+DrezeV5FWwaE17W3NId5h8sm6a0xfpng8+DgZz9LjHectZWZviNOJ
         laRAIDgG7KXgh4qn+ZM7PV9wfJxTLmKrR08+qKHclPFLc1mnUPwc6C094rhNxeoHXGvN
         gc2D538MutiJSk+ECCXKcsd3Lzhcj/svpqOOpF3kQTJO8q4pJbZlxT6WsyBdVsmJODZs
         /460zgQzyZvFN+18Va/gizaR5WVD9P5JyrhYONo+uL+quaH93t3Nd15zHsCcNJXfZIUV
         OO/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=CFqy2ux5XUG9htHw0BliWENPoh369TclIQ8YDIpQUic=;
        fh=evqNWWC5lqW2AYVLR4jUy1h92C6w5SG2uB80oSgcBVA=;
        b=K+uwy0SSbGinZmqabsJOSBQIE8H8yNj2VgkQXdo6M159vHxUJjJK1g3UNBTWln31Cj
         /z3wjMrs+gzuxRVa6/TXjUvillsW514QEmlQwqqYIXjHJE/cEG5Vfafsi1N8zr4TXS/4
         pProiu4K7QdtCd85QXMLCD17Ud80RCaMCRgFAwhtbPaIy0W6RbicDyVmhv30VLkXmAXE
         BYkdh7vcx7N7iix8MnHB4w9DCoEX/13q62oXVvKua1DMM5WdpfbarFxRuKmfh5afS/bR
         0eYERiUcIithm+kkGS2JX1Ah3wkK7kmDaHJxSGGWxgXZNH94uZspMwPLCZWjZB8Ldjuw
         7sgQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@tum.de header.s=tu-postout21 header.b="LH/t7DFy";
       spf=pass (google.com: domain of paul.heidekrueger@tum.de designates 2001:4ca0:0:103::81bb:ff8a as permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tum.de
X-Forwarded-Encrypted: i=0; AJvYcCXXNnfx0hbUsMr0WQNYXJG1jrT3DqW6QoZinkM3DvqXLfCtuyhMO5JYs5x11HGncIkJF9NVxDB0aTBo0fyIXpUfMkZkIceN6adJNQ==
Received: from postout2.mail.lrz.de (postout2.mail.lrz.de. [2001:4ca0:0:103::81bb:ff8a])
        by gmr-mx.google.com with ESMTPS id az2-20020a05600c600200b0040eb6ce3dbbsi46669wmb.0.2024.02.02.03.33.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 02 Feb 2024 03:33:32 -0800 (PST)
Received-SPF: pass (google.com: domain of paul.heidekrueger@tum.de designates 2001:4ca0:0:103::81bb:ff8a as permitted sender) client-ip=2001:4ca0:0:103::81bb:ff8a;
Received: from lxmhs52.srv.lrz.de (localhost [127.0.0.1])
	by postout2.mail.lrz.de (Postfix) with ESMTP id 4TRDDW1kRjzyYQ;
	Fri,  2 Feb 2024 12:33:31 +0100 (CET)
X-Virus-Scanned: by amavisd-new at lrz.de in lxmhs52.srv.lrz.de
X-Spam-Flag: NO
X-Spam-Score: -2.881
X-Spam-Level: 
X-Spam-Status: No, score=-2.881 tagged_above=-999 required=5
	tests=[ALL_TRUSTED=-1, BAYES_00=-1.9, DMARC_ADKIM_RELAXED=0.001,
	DMARC_ASPF_RELAXED=0.001, DMARC_POLICY_NONE=0.001,
	LRZ_CT_PLAIN_UTF8=0.001, LRZ_DATE_TZ_0000=0.001, LRZ_DMARC_FAIL=0.001,
	LRZ_DMARC_FAIL_NONE=0.001, LRZ_DMARC_POLICY=0.001,
	LRZ_DMARC_TUM_FAIL=0.001, LRZ_DMARC_TUM_REJECT=3.5,
	LRZ_DMARC_TUM_REJECT_PO=-3.5, LRZ_ENVFROM_FROM_MATCH=0.001,
	LRZ_ENVFROM_TUM_S=0.001, LRZ_FROM_ENVFROM_ALIGNED_STRICT=0.001,
	LRZ_FROM_HAS_A=0.001, LRZ_FROM_HAS_AAAA=0.001,
	LRZ_FROM_HAS_MDOM=0.001, LRZ_FROM_HAS_MX=0.001,
	LRZ_FROM_HOSTED_DOMAIN=0.001, LRZ_FROM_NAME_IN_ADDR=0.001,
	LRZ_FROM_PHRASE=0.001, LRZ_FROM_TUM_S=0.001, LRZ_HAS_CT=0.001,
	LRZ_HAS_IN_REPLY_TO=0.001, LRZ_HAS_MIME_VERSION=0.001,
	LRZ_HAS_SPF=0.001, LRZ_HAS_URL_HTTP=0.001, LRZ_TO_SHORT=0.001,
	LRZ_URL_HTTP_SINGLE=0.001, LRZ_URL_PLAIN_SINGLE=0.001,
	LRZ_URL_SINGLE_UTF8=0.001, T_SCC_BODY_TEXT_LINE=-0.01]
	autolearn=no autolearn_force=no
Received: from postout2.mail.lrz.de ([127.0.0.1])
	by lxmhs52.srv.lrz.de (lxmhs52.srv.lrz.de [127.0.0.1]) (amavisd-new, port 20024)
	with LMTP id 1ecYqzhVSBKZ; Fri,  2 Feb 2024 12:33:29 +0100 (CET)
Received: from sienna.fritz.box (ppp-93-104-92-119.dynamic.mnet-online.de [93.104.92.119])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by postout2.mail.lrz.de (Postfix) with ESMTPSA id 4TRDDQ4z8xzyYX;
	Fri,  2 Feb 2024 12:33:26 +0100 (CET)
From: =?UTF-8?q?Paul=20Heidekr=C3=BCger?= <paul.heidekrueger@tum.de>
To: elver@google.com
Cc: akpm@linux-foundation.org,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	glider@google.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	paul.heidekrueger@tum.de,
	ryabinin.a.a@gmail.com,
	vincenzo.frascino@arm.com
Subject: [PATCH] kasan: add atomic tests
Date: Fri,  2 Feb 2024 11:32:59 +0000
Message-Id: <20240202113259.3045705-1-paul.heidekrueger@tum.de>
X-Mailer: git-send-email 2.40.1
In-Reply-To: <CANpmjNP033FCJUb_nzTMJZnvXQj8esFBv_tg5-rtNtVUsGLB_A@mail.gmail.com>
References: <CANpmjNP033FCJUb_nzTMJZnvXQj8esFBv_tg5-rtNtVUsGLB_A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: paul.heidekrueger@tum.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@tum.de header.s=tu-postout21 header.b="LH/t7DFy";       spf=pass
 (google.com: domain of paul.heidekrueger@tum.de designates
 2001:4ca0:0:103::81bb:ff8a as permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tum.de
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

Test that KASan can detect some unsafe atomic accesses.

As discussed in the linked thread below, these tests attempt to cover
the most common uses of atomics and, therefore, aren't exhaustive.

CC: Marco Elver <elver@google.com>
CC: Andrey Konovalov <andreyknvl@gmail.com>
Link: https://lore.kernel.org/all/20240131210041.686657-1-paul.heidekrueger=
@tum.de/T/#u
Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D214055
Signed-off-by: Paul Heidekr=C3=BCger <paul.heidekrueger@tum.de>
---
Changes PATCH RFC v2 -> PATCH v1:
* Remove casts to void*
* Remove i_safe variable
* Add atomic_long_* test cases
* Carry over comment from kasan_bitops_tags()

Changes PATCH RFC v1 -> PATCH RFC v2:
* Adjust size of allocations to make kasan_atomics() work with all KASan mo=
des
* Remove comments and move tests closer to the bitops tests
* For functions taking two addresses as an input, test each address in a se=
parate function call.
* Rename variables for clarity
* Add tests for READ_ONCE(), WRITE_ONCE(), smp_load_acquire() and smp_store=
_release()

 mm/kasan/kasan_test.c | 79 +++++++++++++++++++++++++++++++++++++++++++
 1 file changed, 79 insertions(+)

diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index 8281eb42464b..4ef2280c322c 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -1150,6 +1150,84 @@ static void kasan_bitops_tags(struct kunit *test)
 	kfree(bits);
 }
=20
+static void kasan_atomics_helper(struct kunit *test, void *unsafe, void *s=
afe)
+{
+	int *i_unsafe =3D (int *)unsafe;
+
+	KUNIT_EXPECT_KASAN_FAIL(test, READ_ONCE(*i_unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, WRITE_ONCE(*i_unsafe, 42));
+	KUNIT_EXPECT_KASAN_FAIL(test, smp_load_acquire(i_unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, smp_store_release(i_unsafe, 42));
+
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_read(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_set(unsafe, 42));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_add(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_sub(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_and(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_andnot(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_or(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_xor(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_xchg(unsafe, 42));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_cmpxchg(unsafe, 21, 42));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_try_cmpxchg(unsafe, safe, 42));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_try_cmpxchg(safe, unsafe, 42));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_sub_and_test(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_and_test(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_and_test(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_add_negative(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_add_unless(unsafe, 21, 42));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_not_zero(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_unless_negative(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_unless_positive(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_if_positive(unsafe));
+
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_read(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_set(unsafe, 42));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_sub(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_and(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_andnot(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_or(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_xor(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_xchg(unsafe, 42));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_cmpxchg(unsafe, 21, 42));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_try_cmpxchg(unsafe, safe, 42));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_try_cmpxchg(safe, unsafe, 42));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_sub_and_test(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_and_test(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_and_test(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add_negative(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add_unless(unsafe, 21, 42));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_not_zero(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_unless_negative(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_unless_positive(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_if_positive(unsafe));
+}
+
+static void kasan_atomics(struct kunit *test)
+{
+	void *a1, *a2;
+
+	/*
+	 * Just as with kasan_bitops_tags(), we allocate 48 bytes of memory such
+	 * that the following 16 bytes will make up the redzone.
+	 */
+	a1 =3D kzalloc(48, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, a1);
+	a2 =3D kzalloc(sizeof(int), GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, a1);
+
+	/* Use atomics to access the redzone. */
+	kasan_atomics_helper(test, a1 + 48, a2);
+
+	kfree(a1);
+	kfree(a2);
+}
+
 static void kmalloc_double_kzfree(struct kunit *test)
 {
 	char *ptr;
@@ -1553,6 +1631,7 @@ static struct kunit_case kasan_kunit_test_cases[] =3D=
 {
 	KUNIT_CASE(kasan_strings),
 	KUNIT_CASE(kasan_bitops_generic),
 	KUNIT_CASE(kasan_bitops_tags),
+	KUNIT_CASE(kasan_atomics),
 	KUNIT_CASE(kmalloc_double_kzfree),
 	KUNIT_CASE(rcu_uaf),
 	KUNIT_CASE(workqueue_uaf),
--=20
2.40.1

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20240202113259.3045705-1-paul.heidekrueger%40tum.de.
