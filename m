Return-Path: <kasan-dev+bncBCUJ7YGL3QFBB3FQ5KLQMGQEAYK6KDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 89571593604
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Aug 2022 21:03:10 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id h12-20020a170902f54c00b0016f8858ce9bsf5304849plf.9
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Aug 2022 12:03:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660590189; cv=pass;
        d=google.com; s=arc-20160816;
        b=y6Kcajol1ijJh8GwyMBOvKeX6Q5RHdyLnvkqEplT8K4gk23S9VayjJGgfOWYARn3tB
         ry11ZaEkOIUx2zI5jHAlFLCs+GKHlYmGdlfwZX/RHzj04C2gx3itc+yzNPu3WchLISmZ
         DNMOGQvhQ4PrWMW3E3QG4MROgqIfiIQ4dg4EkH87cCwzfvUIAkdCCUBb9inajZrPga4z
         faBrNbJ8B4gScwXyR4zCszS5XNbWQ1SfEm0OXU8yFtNDmsZN/HEXGohzmUBLR6Soe6LB
         C45L8TdtMq+d+g520Ex1LO+9mABFrBvQK4Ai/G90OqvuvXgpe+0yE84PUBpnb0mI6vyB
         NE7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:message-id:date:subject:cc:to:from:sender
         :dkim-signature;
        bh=4v2KQ46UhjwYluKi2NcBGrFNhIqjia+VIh7aCo0Hoco=;
        b=HvxGV9B8TlG+lm7MiQnuf2RH9oZd7cTj7IZnMO7SHFh+/JwDUs6ipu2aTJzZ5p5sYL
         OXcmEejqO7YFqjQr+Ot4sAYOa686minWlG/dLxDrmDw02op3qp1GFLE2Fzt/Fyzuqy6r
         o8oDyI2P3lYxyV6Bj1xQA53qQJe2++qeQrLnH3ALNXJZid+qz0lbNfyfc5ShwGmpqsF/
         hJU1o2DeQYYdR8V5R4fp0F4IlnUqYO9NMoGtHJcbG1/t6k1r9lfxbrxmQwjuvT0FBNU1
         nltIWzjCsCtwP47q3qLrBhmQTd4LRAGtY8r7RvSUTeXAYwuMtNkiw8R/YrutmY0ZECK4
         g3XA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=nnJPVBeZ;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:from:to:cc;
        bh=4v2KQ46UhjwYluKi2NcBGrFNhIqjia+VIh7aCo0Hoco=;
        b=M3nJMXIZA9UzeaDaD29YAWUFQo5BPGHoHq+ihO0MDjCDqvTYWvJuYZWq5cK9WqTylL
         MIbKaLkoRizcYSpLAsXFS93EIvyCOd3WzOQAqhxzquorLc1YWpuuXpu+61u+eaLrrdRa
         poMzjAgmiU4w7RD2RkQPCCWfmpPPprlKwsXAhJie/I9VEC4ctH3q5M2m4TU/qRD0YuHN
         HL5PNc/jOIPXFeqds96yO08f7VU/EaYm3vZAInpMFlAolmvpVf8WH3fd09m9fQth2l9k
         6nROBgFhmIFd0YDc5sM05ru8BAZbZX18B2A9yo9vpCSY8yGseDML93o4KYPiLkbHwhkU
         znxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:message-id:date:subject:cc:to
         :from:x-gm-message-state:sender:from:to:cc;
        bh=4v2KQ46UhjwYluKi2NcBGrFNhIqjia+VIh7aCo0Hoco=;
        b=A0UtqivM033jNd6eKp4RuLGzrsg/fQyIG9kzI9+3yHoDD2tDtqO9Pr6Xg3AxVE/MC6
         uGIOkmi+tIcccWe1FOuHgYbSCw8DC4CECikvWIhUYKmAbui7VfVcZk6x0+JEzou9bfqa
         XLymb6AioqG5kDgVmEL7jZZdFFHnTkLLDjk+o89vHEfA9pYz47XVF5Kag2eLeBY/q7yD
         IfuG7WF3RG7lv42QL9xpsbaLxRIuILNse5/RsVXPucZUBJB5CPEzLPc9knTQEKcyeBIQ
         0QNqxDJaBxirNM9Wh/O2PUYZ//gu/eeK5YxmID8KRgp4FRt/fxtwvK32KtorLiRhjgiF
         DyrQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo23llEPMYGqYl+SsyobzGkRoVhzYUNuiKciRYor5rAbh0Fqj0/o
	q6PpxyfPIBdTemMzmtf2SiQ=
X-Google-Smtp-Source: AA6agR5DEhZOiClPHIci65QHAQX6b/wLJ7CVOzjamAQLgDOTHMkZFehrZq5eCFenw6DYmI2UfqSwGw==
X-Received: by 2002:a17:902:7448:b0:16e:e3f8:7683 with SMTP id e8-20020a170902744800b0016ee3f87683mr18400597plt.74.1660590188584;
        Mon, 15 Aug 2022 12:03:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9557:0:b0:52c:879b:42bb with SMTP id w23-20020aa79557000000b0052c879b42bbls5268895pfq.7.-pod-prod-gmail;
 Mon, 15 Aug 2022 12:03:07 -0700 (PDT)
X-Received: by 2002:a63:d617:0:b0:422:4d27:5817 with SMTP id q23-20020a63d617000000b004224d275817mr13760930pgg.412.1660590187816;
        Mon, 15 Aug 2022 12:03:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660590187; cv=none;
        d=google.com; s=arc-20160816;
        b=OQAsdsxgpkGYsx13n/OEP/Kp6jfvYTsgwYJJdZ3yg1fDFLE9zoyDyUbjiSaA6mhg5U
         T9MrJbh7nXBDYkx1bg/7AVX0f+u4lBT0TXy/wO4rDd/7W2BDXh9p5RtISQ/nUVshnBBG
         9T+5SMMqC8ejstl3rr7LwtjewmARPEMMxDZ4fWbQ0fKvyDuNANLMwHFYWIlqVJ6Vkeqc
         HK4sB4P0W6HjduTrj1AD2xnajOkKIURdPYYrF2MBcPVhcoOnpwih9zXcVU3DtT28YCiK
         JFNUarxea0ZbX3sJNAuJIo6SEq/DFzbrd54FhLpBKfJbb9KGb/QhoriR8qYGoaiQu7yB
         i3Zg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=NbVc0Vo1sLqcgfTOm2iqMSV26EFs3rA276g9CXnCZk0=;
        b=yRcoKTCL9ipvfBPEZsKuTaHaXLn1CNSVSPk/DJtv1Uj1qR6plpqPosTWlTCzunPqsN
         jOeFM4YVSJ7FdQHcSx7kL3EFEgZ1HnKBqQZYx3HsWNrJ10dhCXr/CF0KCsQH6meyCXzZ
         chiUJTIeJ/TUuQiAJDsWkYbvk7D74+t7svUGvr7FKZqNr2eX70208LRS1tMpPhRqBhnP
         NOqdUz4APPUAWqn9k0A566Z2Oqk993ceLGl8g9CV8pudYaLs5AVqcGxTarXBEwWj81WY
         Qc8QVMyGQFBwCbEhBV6K3w4hn7asAq1nKAaxsKOHM6MBUz/jnsC41GA/AgyD7YD3iuLz
         FvEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=nnJPVBeZ;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id qe17-20020a17090b4f9100b001f29166eab0si357741pjb.0.2022.08.15.12.03.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Aug 2022 12:03:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 581F3612A3;
	Mon, 15 Aug 2022 19:03:07 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id DB140C433C1;
	Mon, 15 Aug 2022 19:03:05 +0000 (UTC)
From: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
To: linux-kernel@vger.kernel.org
Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	stable@vger.kernel.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	Kees Cook <keescook@chromium.org>,
	Sasha Levin <sashal@kernel.org>
Subject: [PATCH 5.18 0180/1095] kasan: test: Silence GCC 12 warnings
Date: Mon, 15 Aug 2022 19:52:59 +0200
Message-Id: <20220815180437.088934858@linuxfoundation.org>
X-Mailer: git-send-email 2.37.2
In-Reply-To: <20220815180429.240518113@linuxfoundation.org>
References: <20220815180429.240518113@linuxfoundation.org>
User-Agent: quilt/0.67
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=nnJPVBeZ;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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

From: Kees Cook <keescook@chromium.org>

[ Upstream commit aaf50b1969d7933a51ea421b11432a7fb90974e3 ]

GCC 12 continues to get smarter about array accesses. The KASAN tests
are expecting to explicitly test out-of-bounds conditions at run-time,
so hide the variable from GCC, to avoid warnings like:

../lib/test_kasan.c: In function 'ksize_uaf':
../lib/test_kasan.c:790:61: warning: array subscript 120 is outside array bounds of 'void[120]' [-Warray-bounds]
  790 |         KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
      |                                       ~~~~~~~~~~~~~~~~~~~~~~^~~~~~
../lib/test_kasan.c:97:9: note: in definition of macro 'KUNIT_EXPECT_KASAN_FAIL'
   97 |         expression; \
      |         ^~~~~~~~~~

Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: kasan-dev@googlegroups.com
Signed-off-by: Kees Cook <keescook@chromium.org>
Link: https://lore.kernel.org/r/20220608214024.1068451-1-keescook@chromium.org
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 lib/test_kasan.c | 10 ++++++++++
 1 file changed, 10 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index ad880231dfa8..630e0c31d7c2 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -131,6 +131,7 @@ static void kmalloc_oob_right(struct kunit *test)
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	/*
 	 * An unaligned access past the requested kmalloc size.
 	 * Only generic KASAN can precisely detect these.
@@ -159,6 +160,7 @@ static void kmalloc_oob_left(struct kunit *test)
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	KUNIT_EXPECT_KASAN_FAIL(test, *ptr = *(ptr - 1));
 	kfree(ptr);
 }
@@ -171,6 +173,7 @@ static void kmalloc_node_oob_right(struct kunit *test)
 	ptr = kmalloc_node(size, GFP_KERNEL, 0);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = ptr[size]);
 	kfree(ptr);
 }
@@ -191,6 +194,7 @@ static void kmalloc_pagealloc_oob_right(struct kunit *test)
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size + OOB_TAG_OFF] = 0);
 
 	kfree(ptr);
@@ -271,6 +275,7 @@ static void kmalloc_large_oob_right(struct kunit *test)
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 0);
 	kfree(ptr);
 }
@@ -410,6 +415,8 @@ static void kmalloc_oob_16(struct kunit *test)
 	ptr2 = kmalloc(sizeof(*ptr2), GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
 
+	OPTIMIZER_HIDE_VAR(ptr1);
+	OPTIMIZER_HIDE_VAR(ptr2);
 	KUNIT_EXPECT_KASAN_FAIL(test, *ptr1 = *ptr2);
 	kfree(ptr1);
 	kfree(ptr2);
@@ -756,6 +763,8 @@ static void ksize_unpoisons_memory(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 	real_size = ksize(ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
+
 	/* This access shouldn't trigger a KASAN report. */
 	ptr[size] = 'x';
 
@@ -778,6 +787,7 @@ static void ksize_uaf(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 	kfree(ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	KUNIT_EXPECT_KASAN_FAIL(test, ksize(ptr));
 	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
 	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
-- 
2.35.1



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220815180437.088934858%40linuxfoundation.org.
