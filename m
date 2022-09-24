Return-Path: <kasan-dev+bncBAABBPGOXWMQMGQEZQEN7JI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63d.google.com (mail-ej1-x63d.google.com [IPv6:2a00:1450:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id A084B5E8F9D
	for <lists+kasan-dev@lfdr.de>; Sat, 24 Sep 2022 22:23:25 +0200 (CEST)
Received: by mail-ej1-x63d.google.com with SMTP id jg16-20020a170907971000b00782d87ab6e5sf852788ejc.0
        for <lists+kasan-dev@lfdr.de>; Sat, 24 Sep 2022 13:23:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664051005; cv=pass;
        d=google.com; s=arc-20160816;
        b=EyM2prwAmHlB/eBKkVIT8+6MykFMun5U9zhI1Hy3wD0k0BJl3J1DIAS0ebLcfsB94G
         COAu1/L2N0YNmeWqBh+VCwmDgUcz06fWHNwkv/ToZOAyOgdnoPpodaorfJjCPDmiwwBJ
         rGkEQajjrACIA2fybBPwS3cUpfPuxIscP1Sr6+UrsXGf2AUwt2bPwTCoxe9+Py8goZJJ
         w7qZlEbVhbPA6Es8XjZsKWkuXqdw93fzzi/GdkJiZfdmOp374mluHXFfNDaChb8956in
         VWp4Jb6FG9iPyCyb0UanDhFhUC9AV2aBbryf4dhIT7PiTaA3dqTSc915jyayLe60OhaX
         jMJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=Zuw0Rd1GrLiO6i1ac6wkgzvY9F7TvSQD7OIryQBJEqs=;
        b=L3o0Og1h0bDksNWd/Grls310wuY7udBKqvtx66RharGL0nFItevQqUpK/NaEstaxTx
         6zGQsEHI7KsokFDdt+jL593/Ulx/3gzstSXZeWLTkzOLsONjeuRd1ec1lIdm7Z5a/9JD
         7cW1Yh+bt1p1CHH026aeJ1WJn68MRvtSj4ocaCwPc03US2iy0eT07NSTcs0sI/XvxOW9
         QHzfF8Obvf08MtjDGEfngzq0n5w08Q8HJP4DUnlB2Umfs7kNsNU81ogXvkdPxZTriIt4
         Xr0wbyCe0Fdgg4vWzu5g0w0EF4wb+Lx1oVverjFA8IK7khknfHAoBOkiWN2xt1G1NJMN
         SCiw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="K5b/cTkQ";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date;
        bh=Zuw0Rd1GrLiO6i1ac6wkgzvY9F7TvSQD7OIryQBJEqs=;
        b=YF/QdoQpT8D1XCafykk35rtvb1FCfToLtMPqYZkdFU7UrVovPgVG4euxQm2wvRr9Eh
         aZflY/9IFZ5SKVDnC7aeizdid4jZa5XIebqDoBg9U+87LwsS/h7IcAt7E/BZ5Yw89OgP
         DWqQOKMX46FuuXoB7F/8sYLLiql7DT3a5g89ytX9oQB/p7+gvRsWHdkdfHWLwTCEMbk4
         WiHAQ6mLOdM4NaGC0BJHuqbziuesrfhalLPzpGid/VAw4i3ieizjVXQRztyWDQUn7gmd
         o4a5hTNw4LjZgYoo3d9F9abeeP1vQQEwrk+O3kw71kct32TEj4gPC5wq0yYTrBcBAZ9j
         lvGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date;
        bh=Zuw0Rd1GrLiO6i1ac6wkgzvY9F7TvSQD7OIryQBJEqs=;
        b=0ifbSy+WhO4ZtfSBfGQ0uDTyuAk9H64guMHdh5PQEhJwTjnf9c6wJGRIXN2N99RCu3
         3oy2sqSIOSdCiLZ1qLfj+3KK+NB4VoPG1dCupfPVQP6/xPQGsgPqTUAfnJcQak2bbsEV
         scyL1xbE+4UvGWx7T795A5XpzX9QJUOYJXYKUoXwqiYBlPYwF8ibqEJLPEaID3GzNgsG
         PVmm5Ze3hILALAl3OTlB/1zG1hIeTzjU7Vw/P7bhI2Zd/KxENtrXwmwwbvyFwU76mq8L
         o/GSGZaC73UfRYh9ULRPMG35Lka3nkJgHUx67faXGOQ+EqnUs5CRfhTSN70y03loUID1
         t+sw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2DgnsMT1TJmsyU9YF75w0bzkM6y7qU0IfxPnXt1M1AqH5HXS8M
	R1ZPwizYPcvy1G2zNOoPKAw=
X-Google-Smtp-Source: AMsMyM7Jbgmoil7acTCLh8j1hhYi5Z8hxYJaeZWzmxZ/DkjG3XeVYcpfo9sibsM718UQiwDxtMgxfg==
X-Received: by 2002:a17:907:96ab:b0:782:2f88:cf29 with SMTP id hd43-20020a17090796ab00b007822f88cf29mr12403447ejc.72.1664051005165;
        Sat, 24 Sep 2022 13:23:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:35c5:b0:447:ec6e:2ee with SMTP id
 z5-20020a05640235c500b00447ec6e02eels10452205edc.0.-pod-prod-gmail; Sat, 24
 Sep 2022 13:23:24 -0700 (PDT)
X-Received: by 2002:a05:6402:1941:b0:457:138:1e88 with SMTP id f1-20020a056402194100b0045701381e88mr3669925edz.394.1664051004375;
        Sat, 24 Sep 2022 13:23:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664051004; cv=none;
        d=google.com; s=arc-20160816;
        b=CRb2GUOPkjxhJLQQrgoOa0d2lBtiqbPun85iALhciXz/80WhDtHPpYUA1qyOIyiit+
         LSV8f8sC5USrGWP26MoVQlt/tS+Eg/yHi0XEV2w+omgG/VXTVuU/so7LiHhcCJGCFWJU
         gh1rZ5bp03QUuw9vBJ4ZRNbImyVfhyoKNdTnH/QSJm1iY5IoF8DetnSl2MdOh9d1b3en
         vr/+8e5OkwqtqcLCRjsCSD7khLs23QsrNYurVSOfyuqEnOl4tdMYu+UiLcdyfP7e/+gu
         yt6csk4yh5qIc4EdGnFkrHr+wTEDzPKlPGqeLYRKjAJOFAQpvw3nJftD/PPTpqmfBWwt
         BO4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=nC3nuVqN+jtEUN74Nl68oDoRxZZaXpDu+Kubg+3Y4uE=;
        b=cRxs0cctE5WppbWti7cl9eytX0HmUGtLPSmXJdI0iGnTmueqQtYXZH7Z2u8QEGC+sU
         JfWQpqWK262o6k3tmqTFj8aX7aioTAiAShYKrU1oQtisZR7zHD5grev3c6YAZy8L9ru/
         5Pm4GZcAHgKQh1wuxGW14IL1RPLHbJs9gDmuvLERyOP/sj8P8/MBUlmQ92Ojudtncv4I
         lhMWSyfHwqdp+wzmTB/Mwc9CTNSNB99iwZ7kI9HZT8j5WQCaCcYsAlEFDt477SuJVGL1
         CsI++nQeGWoKHIpae/Jl6fncf/64vqzHknxTy98VLqY7W9VEKqWxWVC2SzqU+qrX7cVg
         Mt9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="K5b/cTkQ";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id o7-20020a056402038700b00450f1234f2csi482906edv.0.2022.09.24.13.23.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 24 Sep 2022 13:23:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Kees Cook <keescook@chromium.org>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>,
	kernel test robot <lkp@intel.com>
Subject: [PATCH mm v2] kasan: fix array-bounds warnings in tests
Date: Sat, 24 Sep 2022 22:23:21 +0200
Message-Id: <9c0210393a8da6fb6887a111a986eb50dfc1b895.1664050880.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="K5b/cTkQ";       spf=pass
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

GCC's -Warray-bounds option detects out-of-bounds accesses to
statically-sized allocations in krealloc out-of-bounds tests.

Use OPTIMIZER_HIDE_VAR to suppress the warning.

Also change kmalloc_memmove_invalid_size to use OPTIMIZER_HIDE_VAR
instead of a volatile variable.

Reported-by: kernel test robot <lkp@intel.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- Hide ptr2 instead of size1 and size2 to be consistent with other
  uses of OPTIMIZER_HIDE_VAR in KASAN tests.
---
 mm/kasan/kasan_test.c | 7 ++++++-
 1 file changed, 6 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index 71cb402c404f..dbb0a672380f 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -333,6 +333,8 @@ static void krealloc_more_oob_helper(struct kunit *test,
 	ptr2 = krealloc(ptr1, size2, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
 
+	OPTIMIZER_HIDE_VAR(ptr2);
+
 	/* All offsets up to size2 must be accessible. */
 	ptr2[size1 - 1] = 'x';
 	ptr2[size1] = 'x';
@@ -365,6 +367,8 @@ static void krealloc_less_oob_helper(struct kunit *test,
 	ptr2 = krealloc(ptr1, size2, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
 
+	OPTIMIZER_HIDE_VAR(ptr2);
+
 	/* Must be accessible for all modes. */
 	ptr2[size2 - 1] = 'x';
 
@@ -578,13 +582,14 @@ static void kmalloc_memmove_invalid_size(struct kunit *test)
 {
 	char *ptr;
 	size_t size = 64;
-	volatile size_t invalid_size = size;
+	size_t invalid_size = size;
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
 	memset((char *)ptr, 0, 64);
 	OPTIMIZER_HIDE_VAR(ptr);
+	OPTIMIZER_HIDE_VAR(invalid_size);
 	KUNIT_EXPECT_KASAN_FAIL(test,
 		memmove((char *)ptr, (char *)ptr + 4, invalid_size));
 	kfree(ptr);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9c0210393a8da6fb6887a111a986eb50dfc1b895.1664050880.git.andreyknvl%40google.com.
