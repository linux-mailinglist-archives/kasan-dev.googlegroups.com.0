Return-Path: <kasan-dev+bncBAABBXVWT2KQMGQEGAKQ5AQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63d.google.com (mail-ej1-x63d.google.com [IPv6:2a00:1450:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id EE356549ECD
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 22:17:34 +0200 (CEST)
Received: by mail-ej1-x63d.google.com with SMTP id h16-20020a1709070b1000b00713a3941a27sf2080570ejl.0
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 13:17:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655151454; cv=pass;
        d=google.com; s=arc-20160816;
        b=bjwWF6c3B3ACWzs6fk8i6bHNXwoESmkm3XYlV4XJ9dgPX1OyAT4g2LjrkSF9XkCFR8
         1qqX6dMAH2FuKXzbNJ2bK6p2V9JLjL+DXrf/R6PTNJyI6TAvp37XNu38Vk2HmW2a/L3F
         grMoxTTj/aMeQLHZyjNJTGEJF9XEIWTGYV/oTb4eng9DYZPDm2SOZPdwxRKZzEwiXkrb
         aAKRBK5nPEcYgCSZ+WjFFmlGFB4c6DjmkhZpOyM1lb1ULgIdnqf/mxGCMUxz1rWGUB6b
         DyXj98m5t2qxS1XBJ14VxU2/imm9c+rjVDSfCv+GCqepyjAsDpjKjm6UylPg2arja89A
         YqPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=WhLM1Bim/4mPygYNM4KU6NnkTfHFkXwzytH7C5VDPhQ=;
        b=WOUSQpF4XfWdOSUwQfMFcVwKLa0wfc/hgxPPTwOdP0PpGBD7BdpPo0E6j137pkuJC+
         qJ7zzRGkSiTvYux7znDmLoxFKSNgxu6NyId7wRbq5sbjdAzY1ItNkoQJ56SY77SvU3ph
         aG0iOIb+fY8S82uaSi40xU9DMesg9nn34m39MWJtyA21Tys6LpM2pBHnDl8GSk6YD1i4
         5l1w+nLnLg1tXFBBg5xsLHFYTbDqyL8/5qGPCeHY7ZLzy2iXDi2+4CBwx/poyLyxnAW9
         v6u+wKze/FYBowNsEd0zbwRtdyWzY9lDqOUfKWMVgH84h2VU0z/8wD5JoS4hbTSsbP+0
         zPgQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=gY7JQXEB;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WhLM1Bim/4mPygYNM4KU6NnkTfHFkXwzytH7C5VDPhQ=;
        b=XKt5lapWSUEoN9sHxFQ71HxhiNFGrQYH5+p5u+85eQ4LVcXIW+BqZKPOTq51wUkeIz
         ubEh17ZwDyMsQAkb7sLymSw364Euhm92oDerq5X41Xz2irUb7u0zdmvAPvHhWR2ZyOTW
         sJBW/id9DyNKuOH41x5wTAZZzQQE1xp6XCoveMR2iWxSAKLtNjcgqmHSGhuoBSTO4PSB
         bdZ2s/xNqKV4rzxB48mCvqTmdoqPXguWuH+wNLTqFfkGmchQL/OaZ5w14BSqzslDi24F
         7aAEolz0TK5tEKd3tcCfq2/Jqc6VbEdW5/1TPUrciSKwYc70CPCtjn8dMl4N3NhtdkD5
         MryQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WhLM1Bim/4mPygYNM4KU6NnkTfHFkXwzytH7C5VDPhQ=;
        b=hUqnY3heCwX6GdZgKdRrhH7Um2f/WlmcnjhQKbpnqKKgKtb0f0g8oINJ4mHrxI/xKx
         klNbFFSZPYdvSx2LXolS1baF5ka3sjOQ5Z9vBjxzbqh4F3bzh3qGYA2ozCFrGsiynUhD
         Gf+q3qgAu/Q8vA/am09xPc1eaH/L+Clip7ZapTweTpUwlMVVp6ATdd9Ou34PGut1USUB
         IYXpfyZBSVniwQy78kPIju5mxPzDEm3ghZxC2gS/DV4ScbiBUa2JdNbmn5yBAdaF/7RJ
         6DD9TQFffDw7gvHKMdkFFg9SJ1G/UEUj+cTbb3QNdCPtUe0zNovKqtShY+3MzbqCi24x
         IP+A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531wwdJmavQHyGAjP1UhpuC9exUmif+LHSmSECMbk/EQoexd4Y/J
	tC7iMr8bZD/qiIo577h7/fk=
X-Google-Smtp-Source: ABdhPJx/eQtzlZL6lRY1t6Ng8RJm9WRBw5oNbbDVX7W0Ud4oTkE+GSCaUQ/LZedGa5Ed7g6UaX+TyQ==
X-Received: by 2002:a17:906:586:b0:70d:9052:fdf0 with SMTP id 6-20020a170906058600b0070d9052fdf0mr1198331ejn.633.1655151454694;
        Mon, 13 Jun 2022 13:17:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:97c4:b0:711:d2c2:9fa4 with SMTP id
 js4-20020a17090797c400b00711d2c29fa4ls144311ejc.9.gmail; Mon, 13 Jun 2022
 13:17:34 -0700 (PDT)
X-Received: by 2002:a17:907:7747:b0:6f3:ead4:abcb with SMTP id kx7-20020a170907774700b006f3ead4abcbmr1293916ejc.296.1655151454021;
        Mon, 13 Jun 2022 13:17:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655151454; cv=none;
        d=google.com; s=arc-20160816;
        b=ZpyZIqHAbDjPgOdl/iVuFbJFh1Pxh/CI6/+my3ZLDtVvA4bgIiWzu9V5NVNEKdQAZH
         VzzxvdRdi/KJkEc1Vne1yuljn4P3jbMNoWPP7jIVcv4Qr5Gsjjcet+nvw7LlEggc7oUt
         3qwUW1lT3v7kSv0gOFaik/sBIKfD83oiooOwkrjRljaDYVn3kaCZISmQl54sEayGAjV1
         z104JfXJGWy1luToyYaXP2RQgx/GaIMMKNkoAeIzOAQ2x/iReLRtFeEtd6Jt0a/Ki/wn
         c6ML+tusI5wJb6AK+Q778ZacKMlyR7V/m1Rt2rTEP8aLRmo1GXBLTT3hu4WH8AfLTAby
         AcBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=gFl1aLadfWJPQ+Xg4RcAPABChePIqsdWPpe8i7e+EqU=;
        b=ID2D8XT3z+TSZaW2701p02CDJqpwzndccLlDNS6jzGIXdSqjpCe5icj+N3Ga3SX5ir
         bAgUUgBBfBiA2lv4o8j4bDsLbiS8g+L5WXE/+YEWL0RssvwMXRhX1MiLProTz3fXZYnA
         FTAT8vFrrL+67bkgRPzshyyAbNxxpsXqPoU+QFCRkos9P6tnJ9fzpbaUZ9/hPXnAIwbf
         iuTnD4ujQPzeJAMgdvuxOtMh1yqgnppsP2aSR/gPcbkLeJM14yLUdhHCYApFaCar0XNj
         cVUifa0uTymuATt5Fs81wSUtTUHaYGJnUqcCbLVOQsfiXUwLq4hz4K5QekbUxHai5c9N
         IuAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=gY7JQXEB;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id g22-20020a056402321600b0042b8a96e45asi258499eda.1.2022.06.13.13.17.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Jun 2022 13:17:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 13/32] kasan: drop CONFIG_KASAN_GENERIC check from kasan_init_cache_meta
Date: Mon, 13 Jun 2022 22:14:04 +0200
Message-Id: <d9a5f3886e8cce132121fe3a4ed2379a2fc1d1c2.1655150842.git.andreyknvl@google.com>
In-Reply-To: <cover.1655150842.git.andreyknvl@google.com>
References: <cover.1655150842.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=gY7JQXEB;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

As kasan_init_cache_meta() is only defined for the Generic mode, it does
not require the CONFIG_KASAN_GENERIC check.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/generic.c | 6 ------
 1 file changed, 6 deletions(-)

diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 73aea784040a..5125fad76f70 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -367,12 +367,6 @@ void kasan_init_cache_meta(struct kmem_cache *cache, unsigned int *size)
 		/* Continue, since free meta might still fit. */
 	}
 
-	/* Only the generic mode uses free meta or flexible redzones. */
-	if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
-		cache->kasan_info.free_meta_offset = KASAN_NO_FREE_META;
-		return;
-	}
-
 	/*
 	 * Add free meta into redzone when it's not possible to store
 	 * it in the object. This is the case when:
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d9a5f3886e8cce132121fe3a4ed2379a2fc1d1c2.1655150842.git.andreyknvl%40google.com.
