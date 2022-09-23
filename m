Return-Path: <kasan-dev+bncBCF5XGNWYQBRB5FNXCMQMGQEUOGA3HI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7200A5E8382
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Sep 2022 22:28:37 +0200 (CEST)
Received: by mail-qk1-x73f.google.com with SMTP id bp17-20020a05620a459100b006ce7f4bb0b7sf816937qkb.5
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Sep 2022 13:28:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663964916; cv=pass;
        d=google.com; s=arc-20160816;
        b=b0YRzph6TdnNpT+qw/JQiQJwRALNpCsY9LMzn3Fx4ZhT4gBPojC9nNLkltGCFp8viT
         +kaW4rrwfOhd+cduVMjZA8Lh5YTCuNQMxU+RL+KsqDM6QHhHXG5XGqMmBq3cqxsvNNYD
         t4ZZR9Ys951hZtHoPB9xF0N9HUBupJokx29F74tJobUqvh5CCKWReYyn0gwOK3xGdY9Z
         kDQfLgTmETaK3NUComLUoAvpHMg87cQNhRfs9cjMP1BrZT9KEXORdVPDaaAfEQlkH/iC
         cUquKc7uumGHc0wmiqaGQ6s+Tt8M7V1J1JRsTJqJztL9pSND8WS38JK5ESEduXWiSoSw
         Op5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=whKVBm2Ww1zUls6mzsg0tzR0OZ2gdNLU0o3ZAi5QQns=;
        b=LxhE16EH8LYWbMtDxiSPudUrzQ06zZCg4KwWVbCsNLmRWhYqEUg22Bs1t43X5jiTOs
         RQV+0X+EIUV/mKhu9qXk4C7+yfg/aY1YU8zd2rQpZqTn2x9BDyMXYWn33/OLca8nEkSc
         ArJ+A+4iTbz3H1lVXrA1noH5+VLqDPXWb0NIsNFGE3dNdjSgfceuknLpYvuNVnIyz8Zp
         iOJslxj63DNBaRDbfBUBoqv4yf3Gyu5OSOYT5YP9DhZTXBjUw6Ua4Jd/Le6BRcBgjsww
         9hjbCJCPvHB6F1TuVXi+mNdCLyxDgFwp0xnzsw57vwpxhLo6V5HHWJlQYnm0+sEig9Hk
         z4+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Q4rh+gml;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=whKVBm2Ww1zUls6mzsg0tzR0OZ2gdNLU0o3ZAi5QQns=;
        b=sas/qJg/6U7A2TEg5MNCeAZvGcCjFXr8KB256fUnmZIgM9RC0m66NxabPAxH9BTEF3
         IJXHManpyU+oNsX0e0jRzJvxe7f9HGS7/zII32pkMQLz2tSDJkm1pe5Q8wPJM9uCqhwA
         zoMziXu9CElXpfkCl/9T35kTTwnGca6atq2rPsZPAqTsazC0ULAsyTRiPdiHhhFL8zVV
         Q/Qn5BzZUz9wysAxPkjRV2Vh/1ZoMyjs+RE8l+L/I1u3f0nwWk2SN/f/xD+6WZFwwioe
         wMh0VTTdf3gDVY/JvYKRdpXliL3SWAdlF8id6Yd1XEKrRHEKQet68+tSoKrt5iGziFyO
         zRJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=whKVBm2Ww1zUls6mzsg0tzR0OZ2gdNLU0o3ZAi5QQns=;
        b=ESxaz+8UkSeK3+/IHCJqnVQQqz7nVPu3c8aZviwd6mTguXjeHdcjzg7YlYoraCk7mI
         e58MZ0MNk1guBhizM80ihwPDwvMHX1M2rrlaFrAL5Cho2guldE3t50rgsp+ALZGXg5z3
         CXXQ+tBzdX/sPGiMxgj32xLJ36XhHzf4NTFx8ot+RX91S/XadEnQrrSh9qdwZZIHyMvw
         GzMUc6FWI+xxqIN0waxnsN5AcqVHWZqrlMqGYXH93x2C5W9WvgiVXdCW7CTtgmB0lwyQ
         kfCllFZjvnP4UMoE0OBZKwYXTTsAU5Mzz66iXPkrWnobC4X1svvh/Tdbw19KDS3AqZsi
         sR/w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf13WJIMa8uABqtpd8Qv4Cyk5AjcBzh2DeYb1NddTaRc2JNh/eaz
	dHYY4t8cv9bGAyPV9LMxWII=
X-Google-Smtp-Source: AMsMyM4aYKwUjdGM+zEWLYchEvnbIrhuyKEUSUYxjMOAZsmFRdbhCcnBIArVXVVCnZWezBQQpu1v3g==
X-Received: by 2002:a37:557:0:b0:6cb:d766:ba14 with SMTP id 84-20020a370557000000b006cbd766ba14mr7095428qkf.3.1663964916193;
        Fri, 23 Sep 2022 13:28:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5781:0:b0:344:94bf:7994 with SMTP id v1-20020ac85781000000b0034494bf7994ls12332818qta.0.-pod-prod-gmail;
 Fri, 23 Sep 2022 13:28:35 -0700 (PDT)
X-Received: by 2002:ac8:574d:0:b0:35c:e350:243b with SMTP id 13-20020ac8574d000000b0035ce350243bmr8833701qtx.292.1663964915647;
        Fri, 23 Sep 2022 13:28:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663964915; cv=none;
        d=google.com; s=arc-20160816;
        b=C4+6rWgyveyQOWfrGthg1bSGXB4odt86gGOLkUk8BAaZ2cp3DI+B//A6q6ly+dWg9o
         cawg16AnttjaEDk8yByp/wOusV/RdBupWyH3VYDJb0ySZZ2pvhaEGX4mIf8UK/OJLMIg
         c5m5ZLjukU/X/gFBlMx21YZi8Dtr2LC1poew0zki2mK3dFn6WeW9NIodBWs6cpFB304O
         4/DpefLS4LnzSsp4c6d6qf7B6MACigZu5y9UckumfhhUEL24NZZp8Mnh44XIa3I1d8Ei
         d6oxgDadHigt0iLplXhQYw1bMyTxo0vxslfV2qbFZuEdQ1tYD9LEIhgRBuL0qecvlhzt
         P+fg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=z4tB+xVARH2BbBzGKcf3E9OvsPG9MUKkIVIFYw9OFoE=;
        b=QwWBoRL91I9tZ8gvY37pN/TjG2oBfINzDijwUiDQ2X5rpL5e6fm3E5iAhGJvHs8poM
         pYjcQ4X1BTnMYoIv13ePVE4fpbtOD0TMGx8y2wvf0Z2IJerqE34IFkQANGud7dpKlOcD
         5o4DRv9sHBMGMc1qxXj5/0Qbgjp87J9IqqPSfk2YWpTIPVeCr9ihxR2yi7ckJtGBK3hv
         0ZwjmMq9ZPLIyx7bdrdNZ5pV0PH7RpXYpUM7VsbPYpgQLvXOERAS7VY+8BU9pM9QWCa+
         mrifyKfJlXoVmT/dN81BEl3fnx9jAtNb2Cp9bmQoq5nGXIgugjtMvBdedl7dtEVvrl/v
         GrVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Q4rh+gml;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pj1-x1030.google.com (mail-pj1-x1030.google.com. [2607:f8b0:4864:20::1030])
        by gmr-mx.google.com with ESMTPS id r17-20020ac85e91000000b0035c9fda218dsi448892qtx.2.2022.09.23.13.28.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 23 Sep 2022 13:28:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1030 as permitted sender) client-ip=2607:f8b0:4864:20::1030;
Received: by mail-pj1-x1030.google.com with SMTP id a5-20020a17090aa50500b002008eeb040eso8353512pjq.1
        for <kasan-dev@googlegroups.com>; Fri, 23 Sep 2022 13:28:35 -0700 (PDT)
X-Received: by 2002:a17:90b:4b46:b0:202:7a55:5588 with SMTP id mi6-20020a17090b4b4600b002027a555588mr11300183pjb.55.1663964915056;
        Fri, 23 Sep 2022 13:28:35 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id o5-20020a170902d4c500b00176b66954a6sm6438596plg.121.2022.09.23.13.28.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 23 Sep 2022 13:28:32 -0700 (PDT)
From: Kees Cook <keescook@chromium.org>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Kees Cook <keescook@chromium.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	"Ruhl, Michael J" <michael.j.ruhl@intel.com>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	"David S. Miller" <davem@davemloft.net>,
	Eric Dumazet <edumazet@google.com>,
	Jakub Kicinski <kuba@kernel.org>,
	Paolo Abeni <pabeni@redhat.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Alex Elder <elder@kernel.org>,
	Josef Bacik <josef@toxicpanda.com>,
	David Sterba <dsterba@suse.com>,
	Sumit Semwal <sumit.semwal@linaro.org>,
	=?UTF-8?q?Christian=20K=C3=B6nig?= <christian.koenig@amd.com>,
	Jesse Brandeburg <jesse.brandeburg@intel.com>,
	Daniel Micay <danielmicay@gmail.com>,
	Yonghong Song <yhs@fb.com>,
	Marco Elver <elver@google.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	linux-kernel@vger.kernel.org,
	netdev@vger.kernel.org,
	linux-btrfs@vger.kernel.org,
	linux-media@vger.kernel.org,
	dri-devel@lists.freedesktop.org,
	linaro-mm-sig@lists.linaro.org,
	linux-fsdevel@vger.kernel.org,
	intel-wired-lan@lists.osuosl.org,
	dev@openvswitch.org,
	x86@kernel.org,
	llvm@lists.linux.dev,
	linux-hardening@vger.kernel.org
Subject: [PATCH v2 14/16] kasan: Remove ksize()-related tests
Date: Fri, 23 Sep 2022 13:28:20 -0700
Message-Id: <20220923202822.2667581-15-keescook@chromium.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20220923202822.2667581-1-keescook@chromium.org>
References: <20220923202822.2667581-1-keescook@chromium.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=3002; h=from:subject; bh=nsR089jDUY/rZ3RkLnBCmN0cxhulkR1WvQxc2IILkdA=; b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBjLhbmz8DrfaIQlG3nQhgCokX0k1pjcPoiZW0Jauf3 tW1sqtCJAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCYy4W5gAKCRCJcvTf3G3AJhLbEA CE0iCQD7eLDXpM8ch5Nl2WFXcHp3LHX4r5WZApWbPThez4fy3zQ6oNOuYG3svqE9Ty3HRWiGtAuj1z 52ieVU1DgCeOcKoR+WWmyjUwvEKyYiR5nSddmdky8FqqpEzQC4EtPsNCfpE7C5WkkbCFT2YOnKkP+I c+XG3sdrbNkpYqdfxTpOaqfpmDejGo/bN62+BnL1P/oGYvKbQbJwTsGZSFgCcDiGxIx4MUs8kdvOoE f3E1N/A5SnQc82KMjdHOBvqyr5/nmPWBXDf9PlAi8EX9EOeSdWA63gqrcMmtWF7k53AM8y3nnA1WjF ArSY9BsRELGcOYhJ3ZLW3AkptdWRSxpYNY4+Bez24YkZOCmYJtf8k9uUGxCocTzQbk81lJAneIcRM6 CmmNxTps7Rcdxo//FEpitZVXcFDFcuKqMUFVXOtgkBr5VTyqhFW3U3sns9A/xdIvuzU1nLW21+Z/gs rX/cfIV7h8BHZawSfOBQwanV/aeRIHMA3P7DqC6Wryes8omgf/NBRyzIEWcXGOjM+KfNjcPoqUYaPn VmEXb44aYqHppQofZHS2SZ2s3815KS6eI25k+LJIkeIBCtJfER9/IiKu4geqN/K/Fc2osV+7bYCzqb C4y72qoT68wn68L1UOdkRy8UoFwG12ut8cp2hnf2M1C3fLZUVpj8BctMNe3A==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=Q4rh+gml;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1030
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

In preparation for no longer unpoisoning in ksize(), remove the behavioral
self-tests for ksize().

Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com
Cc: linux-mm@kvack.org
Signed-off-by: Kees Cook <keescook@chromium.org>
---
 lib/test_kasan.c  | 42 ------------------------------------------
 mm/kasan/shadow.c |  4 +---
 2 files changed, 1 insertion(+), 45 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 58c1b01ccfe2..bdd0ced8f8d7 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -753,46 +753,6 @@ static void kasan_global_oob_left(struct kunit *test)
 	KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
 }
 
-/* Check that ksize() makes the whole object accessible. */
-static void ksize_unpoisons_memory(struct kunit *test)
-{
-	char *ptr;
-	size_t size = 123, real_size;
-
-	ptr = kmalloc(size, GFP_KERNEL);
-	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
-	real_size = ksize(ptr);
-
-	OPTIMIZER_HIDE_VAR(ptr);
-
-	/* This access shouldn't trigger a KASAN report. */
-	ptr[size] = 'x';
-
-	/* This one must. */
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[real_size]);
-
-	kfree(ptr);
-}
-
-/*
- * Check that a use-after-free is detected by ksize() and via normal accesses
- * after it.
- */
-static void ksize_uaf(struct kunit *test)
-{
-	char *ptr;
-	int size = 128 - KASAN_GRANULE_SIZE;
-
-	ptr = kmalloc(size, GFP_KERNEL);
-	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
-	kfree(ptr);
-
-	OPTIMIZER_HIDE_VAR(ptr);
-	KUNIT_EXPECT_KASAN_FAIL(test, ksize(ptr));
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
-	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
-}
-
 static void kasan_stack_oob(struct kunit *test)
 {
 	char stack_array[10];
@@ -1392,8 +1352,6 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(kasan_stack_oob),
 	KUNIT_CASE(kasan_alloca_oob_left),
 	KUNIT_CASE(kasan_alloca_oob_right),
-	KUNIT_CASE(ksize_unpoisons_memory),
-	KUNIT_CASE(ksize_uaf),
 	KUNIT_CASE(kmem_cache_double_free),
 	KUNIT_CASE(kmem_cache_invalid_free),
 	KUNIT_CASE(kmem_cache_double_destroy),
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 0e3648b603a6..0895c73e9b69 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -124,9 +124,7 @@ void kasan_unpoison(const void *addr, size_t size, bool init)
 	addr = kasan_reset_tag(addr);
 
 	/*
-	 * Skip KFENCE memory if called explicitly outside of sl*b. Also note
-	 * that calls to ksize(), where size is not a multiple of machine-word
-	 * size, would otherwise poison the invalid portion of the word.
+	 * Skip KFENCE memory if called explicitly outside of sl*b.
 	 */
 	if (is_kfence_address(addr))
 		return;
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220923202822.2667581-15-keescook%40chromium.org.
