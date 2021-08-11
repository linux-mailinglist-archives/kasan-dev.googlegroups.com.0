Return-Path: <kasan-dev+bncBAABBRWG2CEAMGQETMKZV2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 3FCEC3E989D
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Aug 2021 21:21:43 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id y206-20020a1c7dd70000b02902e6a442ea44sf1962442wmc.9
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Aug 2021 12:21:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628709703; cv=pass;
        d=google.com; s=arc-20160816;
        b=NAdPD7doBR2qn0yAbAMtLVm0mF5KyFlQH+PRuoS1I+RqwfzgwAxL+4GfF3AZFNR7HL
         L37ftxSHGfxPdfUAiECQZ5K6fUKIBaLP7wzKwdiW5HYHOsU01iM2gD2OreQAWPwiKzK/
         QHJcHuOPknH6ypJDHcxN7Hq4PJmYAry+rTwvxYRW6aF5ongFnti8hauRHBe9NeGT22I3
         wK8TDqVQntD3awGgUSQo7+IN8cn/OjilyhbMsLp9IrH/ECjPw41WfgTLTepa2INcO0yn
         NJQyj0RldG8lR0lElFOkcZTFlYxh12slrNOAb9+r0WhrOfcx4FGNmmgpf7vlpeH1lekC
         7TbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=DNeuNTkR9xmiRyPV6wrdrXj1gRNmVPJ34LN5B3kH95s=;
        b=mOexMPVPCXATswmkJUmw+nzWJ89+H1ICtNiUULrxAF2Rv69ibu7DLs8DK736TMub3m
         bfx0vuxfs92oROLmeHzmrKhACaG/INIc02vWPI8LVRmceRUnUUm9Pnri7D+/lc2vYfeW
         MOkGpvuQedYSJBwaamdJexKbYq8s+KM9XhbJ5RlynW7kBQhYF8tunCk7iCkiivTW7Afb
         13gawBIUgUzr7kiAVhffdDvp/rxHZKSRR4itjD9y5yDcLHFyzlryCHiISggXv+yeIL+E
         8vNBIj7WbJh13zQcqqK3d7iZEpuKRrq8QUR9IRvMH8jtY/85oIJyAeHyEG04gGvkARw/
         XOXg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=flF8MnPS;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DNeuNTkR9xmiRyPV6wrdrXj1gRNmVPJ34LN5B3kH95s=;
        b=aeOsDTg4tHbIjkuZrNT0TZ+FGslX3tKSWm9yTDWreAKPK+McbnW+Yn1TfKZIKr9Ll0
         rLfYwNkp8TJwPC/dXmqpnMIXa7YBKW70elx22rtBGm91K8wls6F2Cu5dPtQdBlamupxv
         BFMId0bGunQTuTgdHPaEd4emHSsSkf528i9u1YhUdjH7HWRI+rE9Nd4IVSB+H5RB9HDB
         u49Yi4I5xVUrSdBlOzdqWka3x1wUDATLqkjYbO0EsI1SyhF9lnPZJExwl8oGSSTIEsDd
         9PQj80POaHDIDf/L/T8F1GDLA4EX7BPzbF25wa7j/qBGkhVORkCY5xX5HUU/vVnEyybE
         nqsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DNeuNTkR9xmiRyPV6wrdrXj1gRNmVPJ34LN5B3kH95s=;
        b=uK87ZYEYCqnf86U+xoZF3k56BfAg9+IRzT4jDIX6e84UYZ3Cw08oRCKqLes0FG1rnc
         n9igDtFzc7EgaUsxfwDI2gUbYM7Bu9nCKh2SCYItPRhIbZWhSmTsDq+YhvY2BNQKLlHy
         L019AP3hPKDGKGtHdf3nNcQz3kkoxXZ25vogkbeMu9hHVd1PcuTN8zgbRl4TCgMfYN1T
         ByuyezDLQF8u/KdkDJAnlm/EVAYvqS2N/gj4HYiZivuVTsqRtrn2VdwEmx2dzhwJ3QG0
         DHGm7D35s4rM6nwPVtp6GGxQcONIicWwgl3nvm9d92CYafzhJ0QKr/ZU5vfz3sVOD7pC
         Rl/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5334PqHnWlIiZAtGaezwDKKe021d0y4+9bTLlwx/FUnUoiQdEsfi
	QeUbvwEujbWD7HPpR38WYo4=
X-Google-Smtp-Source: ABdhPJy2HuRVRUWbn3A2nPVl9wA23Gw3LlGoZQgKSDhe5UVlEa4kCi8J+CgMj3ueOHYdJOycben9eg==
X-Received: by 2002:a5d:640d:: with SMTP id z13mr22064wru.145.1628709702973;
        Wed, 11 Aug 2021 12:21:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a191:: with SMTP id u17ls884280wru.3.gmail; Wed, 11 Aug
 2021 12:21:42 -0700 (PDT)
X-Received: by 2002:a05:6000:1152:: with SMTP id d18mr8398wrx.303.1628709702201;
        Wed, 11 Aug 2021 12:21:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628709702; cv=none;
        d=google.com; s=arc-20160816;
        b=QYpZRRhGMuYm+j3StpZo8Ai3EvowdKPursyCH03xnGGA7uv3iQ6n7eN5t38CbL22Yc
         DDiYAFlAS2L7PxSx2XBBrYp4ybg1i2mjV2g9ZdWnrt6I1qZsOInlJTBGHchO/atx3nxY
         wc39Q6Lsov0BEK5KpPtwlufM64c33dmR99KVIPsaoHWNiS6wmg33cXup+fsd1lF9rtm2
         vCrddHz1U6ccxg+it0YV0bHWxu3jH5wCvV3XP80Cp584pHlozLfb1FyU51RNG6Nil7Ck
         pH8mp1PPcxDY4NJopEVoEzTPGOX2DezQNkukC4PDUOhD5DSWROlWgFLluPemwZ01rl5D
         ntlw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=67kYwukmo7Ml3X3ud3b8IvQ8hH4hhd8RmqNx/G1meFc=;
        b=poL1jlJPaNwJ79jqHY/EqpaJtdijmzgajh6Fy5FeRck9Qff/qcrmyNrOCz9HJfQ8DM
         aXj79mLH2G5Xi3MTcgbfgqFRN8j1gW0/zREKF0MR2AxN91ti2LeDuujXq6fsj47LejcC
         b2l5L+ENMAsokIzn3RQdvQScDjXKwKEkNs2wJF7DL4sAxwKWi3OsV+RdcbEmEdtVWhVE
         q7B8lM3zaEZrGqspYAb7iccLisPcMNzclj2pQId6C3zy5pi6JtOJep5AdzM6JKaj8rPn
         L+o8tnmegez2jAYKADWJEtFfDaT1OQnN/F9oECZee5vvfVf1oKdwaIOmlCXGXAvF9Hti
         bL5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=flF8MnPS;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id s130si55062wme.0.2021.08.11.12.21.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 11 Aug 2021 12:21:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH 2/8] kasan: test: avoid writing invalid memory
Date: Wed, 11 Aug 2021 21:21:18 +0200
Message-Id: <c3cd2a383e757e27dd9131635fc7d09a48a49cf9.1628709663.git.andreyknvl@gmail.com>
In-Reply-To: <cover.1628709663.git.andreyknvl@gmail.com>
References: <cover.1628709663.git.andreyknvl@gmail.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=flF8MnPS;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@gmail.com>

Multiple KASAN tests do writes past the allocated objects or writes to
freed memory. Turn these writes into reads to avoid corrupting memory.
Otherwise, these tests might lead to crashes with the HW_TAGS mode, as it
neither uses quarantine nor redzones.

Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
---
 lib/test_kasan.c | 14 +++++++-------
 1 file changed, 7 insertions(+), 7 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 1bc3cdd2957f..c82a82eb5393 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -167,7 +167,7 @@ static void kmalloc_node_oob_right(struct kunit *test)
 	ptr = kmalloc_node(size, GFP_KERNEL, 0);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 0);
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = ptr[size]);
 	kfree(ptr);
 }
 
@@ -203,7 +203,7 @@ static void kmalloc_pagealloc_uaf(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 	kfree(ptr);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = 0);
+	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
 }
 
 static void kmalloc_pagealloc_invalid_free(struct kunit *test)
@@ -237,7 +237,7 @@ static void pagealloc_oob_right(struct kunit *test)
 	ptr = page_address(pages);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 0);
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = ptr[size]);
 	free_pages((unsigned long)ptr, order);
 }
 
@@ -252,7 +252,7 @@ static void pagealloc_uaf(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 	free_pages((unsigned long)ptr, order);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = 0);
+	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
 }
 
 static void kmalloc_large_oob_right(struct kunit *test)
@@ -514,7 +514,7 @@ static void kmalloc_uaf(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
 	kfree(ptr);
-	KUNIT_EXPECT_KASAN_FAIL(test, *(ptr + 8) = 'x');
+	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[8]);
 }
 
 static void kmalloc_uaf_memset(struct kunit *test)
@@ -553,7 +553,7 @@ static void kmalloc_uaf2(struct kunit *test)
 		goto again;
 	}
 
-	KUNIT_EXPECT_KASAN_FAIL(test, ptr1[40] = 'x');
+	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr1)[40]);
 	KUNIT_EXPECT_PTR_NE(test, ptr1, ptr2);
 
 	kfree(ptr2);
@@ -700,7 +700,7 @@ static void ksize_unpoisons_memory(struct kunit *test)
 	ptr[size] = 'x';
 
 	/* This one must. */
-	KUNIT_EXPECT_KASAN_FAIL(test, ptr[real_size] = 'y');
+	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[real_size]);
 
 	kfree(ptr);
 }
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c3cd2a383e757e27dd9131635fc7d09a48a49cf9.1628709663.git.andreyknvl%40gmail.com.
