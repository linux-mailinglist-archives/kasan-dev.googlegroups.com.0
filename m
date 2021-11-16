Return-Path: <kasan-dev+bncBCF5XGNWYQBRBK74ZOGAMGQEPHYGPFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 81E12451F96
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 01:41:16 +0100 (CET)
Received: by mail-oi1-x237.google.com with SMTP id y20-20020acaaf14000000b002a817a23a1esf12534347oie.23
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Nov 2021 16:41:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637023275; cv=pass;
        d=google.com; s=arc-20160816;
        b=xTDGlOk3s9tMzcrPq3CURVW3kh9RoZzJ22FoV+9lBT8jzNPaibNSe3N9Y0r8w+6Q9O
         bKrZJ4d8sr2S96XEVb54zFFzF/2g8WH4kkdEuVNHFhqo+EM/pDio3vi00zP9uX2GLIZr
         Mk/OstZLiEZSCrLmnwzSJySahBAd8polBDKWgU5ag3T59EN794tQk2jINDJdRwDKTwIP
         IfdMk5PgGxn6/rfCQ++UK8XR7OfCh2SV8mI1owFNPGDpPNjk7VwR/PXQ43E6O22RVloQ
         FRcD2X8mQ4MtpEQ+flyYuHyYx32tw/GKyGuA39RhtY6fnlG0W12m5eLDdJ565+tPMYo0
         0hTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=Cr5yFAzc6jRQCoClqcJ+khhVvs0xhjTQN/lltdsQsXo=;
        b=wJLMXWL30kxQ96ngD0kes1UI/TxHkuK6nLrCVmoU51E43zng6LE/c2oiwBZHGk+d5I
         FF4CVZU2IdIkOkCwf9hFCVtFdA7uOj0jrpfrD1ftRtm81XDDURqOjmqXfu5WHoMHUAjm
         e8D4psCuJX+CbTmYbaXpLuTkA5IZZWj5kIndRPickj/1JngnsXVyKaYzHd0XzCteyiOs
         yz0T/aXJGBo0G8yCT6ewr5OUfcBAtjzeGtV+rxzXEUVSmMQBVGYeWhYEdpqZMtkeaxIA
         ErnDrZSLYBqc+wX7sT0izbs3+PQnxV5BHOrptIupvi02GBUJTYtYE3iXr0RPV29WhwaI
         H8BQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=eRJXSwOu;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Cr5yFAzc6jRQCoClqcJ+khhVvs0xhjTQN/lltdsQsXo=;
        b=WsCTVOk3TNUBin0TUoVWXgluRXNn+mCd/Sg+sfU1QXoSNgdCgX1lyUhOroIJniTinH
         ERfuAP0IwNOg2tLV+eZCMlnYyhfTlwMRclMzTzvY6N5v054Af7Ki79cD9v4ddi/TS34R
         LluZMOsDvsO+7iFi6fjWzm5ECZTuXMSMfRJHmtqVY6tOi8K4WXllVi64Qy5szvbhM0LF
         8L8PGrF/26hkUiG/yUaHpAJbtqe55sVof10jZOa825uIOtDhutgEaiNGwJYGUZque0ip
         gQMd/ffbFGa7Fgz7nZO15j7MrjXxCzkpW2AHY6NwWNOO+9YOhtNVJOvO6ivy/m7UoBRB
         6BMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Cr5yFAzc6jRQCoClqcJ+khhVvs0xhjTQN/lltdsQsXo=;
        b=hDoPxd6nd2canA2gIFsxSpikWio0RuuHRYKuEOAI4KWQBl2tBFzV75+Ccwfk4eq/ni
         3jCTBTxy1zkXktN2IrMyjp6hodfWSrKUJQaRxyPmwqr4pCI3aPW792Zkn6VLgy65+A9U
         pOPlI+y0rZNpKCjvMN/YJ+NwoXXFpFgnz9l7Obuq9Fnn5VQ9f89ZaOgsr9Pw2A351+yW
         wgQa06WXvLz2VKjwkfsvhZkHrOsBKKHduSi1v8wcVOM5NmW+TNMvFaLnbblhotxfBCfO
         blZO0Q+xu7KGh3kTY41cyftI6B3e0tBYd7NRfitcIMNMI7Ogp1C/8UI0b1uch6xxksb/
         oMtw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533RG1Tm0/XEAJ/tNZxSWYcKOdQ4VfwllomAg8npPvMpHid8+cxC
	WrND3ncKZ05EX3uzUtKnBKk=
X-Google-Smtp-Source: ABdhPJwza3E0+Uj7vpoX+vuTizba58xSznUX5YtnXQWJuIJgTebD9kSaaBHrNGQXoQUscptF5MCDGw==
X-Received: by 2002:a9d:37e3:: with SMTP id x90mr2633388otb.11.1637023275065;
        Mon, 15 Nov 2021 16:41:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:4599:: with SMTP id x25ls5397678ote.9.gmail; Mon, 15 Nov
 2021 16:41:14 -0800 (PST)
X-Received: by 2002:a05:6830:2681:: with SMTP id l1mr2677993otu.378.1637023274668;
        Mon, 15 Nov 2021 16:41:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637023274; cv=none;
        d=google.com; s=arc-20160816;
        b=LtAaTrJ/xL8GjPJrRgyi9VdWLEhaintZQ224GXBv/0Erj9vxotSouQrzKVgYOzD0j6
         tNkktzHuo5TXnTxgFR747ox6DUVIPXXgJUMJxCDQx5jfhcqzKkM9iJtccMQmZfis51W5
         eB2PMqRM9dPu2ZyYztbaGAZzvbjkjDP/ehrWUkmlt6nN9Z9qLanCOcIQpXl2nspegmz2
         R+RDJ7srzAKFh98+5clsiAO5Zf1+jx+VKd/GbfR00OSbVpNkEscKdLWMBkiu3fi4U7RM
         MQNiYgZeGgZBjQ/ywgUr+ttKnmPWLOeJVJ3x/Ep6ACbUxadMZ1ehITzwUx7v8E+nQA97
         DWSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=gYCggQgM7Hv14HFSqESLBpo6cv4sDLeY3VVnNudB4CE=;
        b=EsEs2gBREri5D4iJD9apNhIvj2DmaqOWuauPLx1QdkRWGh+LBDEYTj5/H4pMReeKVy
         kSlrOm5q7E+LxGKjFN/pNnnwsea2JDSf39OTEjyvo29JYHVtJ/L3PAm9ChUGQtllrkGr
         dKNcv5Ph4saDTVYXE+cJHarPPwtRlRi2GM9WwEfu5LFYL9UJgTiRbF5mnMBwEDYbSV4e
         UGFYWWUM0wFzmharoQSVR0+Zt/PxvWYHVWzCRLnw+s3u0CSXNnbuCY04c/rz+iAY5Hr6
         IcDtsJ8bQWVErVOgyYE8AQmDxbg5JMvuu7rhJtafXnfSfuEPn2cMCw8hhQgOqj15ACZZ
         r3Eg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=eRJXSwOu;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x42d.google.com (mail-pf1-x42d.google.com. [2607:f8b0:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id i6si1252871oot.0.2021.11.15.16.41.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Nov 2021 16:41:14 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42d as permitted sender) client-ip=2607:f8b0:4864:20::42d;
Received: by mail-pf1-x42d.google.com with SMTP id n26so11895869pff.3
        for <kasan-dev@googlegroups.com>; Mon, 15 Nov 2021 16:41:14 -0800 (PST)
X-Received: by 2002:a63:7c1:: with SMTP id 184mr2174203pgh.11.1637023274056;
        Mon, 15 Nov 2021 16:41:14 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id oj11sm425461pjb.46.2021.11.15.16.41.13
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Nov 2021 16:41:13 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Marco Elver <elver@google.com>
Cc: Kees Cook <keescook@chromium.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-kernel@vger.kernel.org,
	linux-hardening@vger.kernel.org
Subject: [PATCH] kasan: test: Silence intentional read overflow warnings
Date: Mon, 15 Nov 2021 16:41:11 -0800
Message-Id: <20211116004111.3171781-1-keescook@chromium.org>
X-Mailer: git-send-email 2.30.2
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2821; h=from:subject; bh=oTw/CUC/KuutWYAe3WotO4gW4yWeVdWkH/bgioWASI8=; b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBhkv4mvd6GwHkIJO9fQ+xSGSSiPaJlNQ06IPenoXOv PUPzH+CJAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCYZL+JgAKCRCJcvTf3G3AJr0PEA CV/Dk3AykdjYzMT0aiqyOW5Nc7joC2ew50WxzpazdoT7QhDPrULZLvH7Xp0Olo6DNG7ZKXmWpE+Dk7 6Z5ooMF4qbGtRfw5ZaCrXpbLUgui8PNcq3VuUlEbxErmVpa6avJ5EjI9pmIeEB+RRh/xgFIJbc9Jeu tGpc4LeJODoXjW1y3Ym5/gGMRaxa6hCroQ0yy77OYuzX4KpDa6xnQXffCPtBIet0iutZSAyYx+GeHT XDJdHFJXTN3YZCocJ72P8R/JLjyz0pJY2viN9h8vhRjang9udr8hDWsFyzIGoUd5spNqkXcx1PXSIn fXd/1jvrHIbk3scnUgh26kVjOlctTdQsQf8Y1hTUY5vz94JAtXX77qXwuOlqGlur+p2LSvDK7JkdD/ EsIh7siCd/xkuJ0VFU2T5lPcnryuKmr+u1WRuhyvDygJjxdifEXULYhwTEWQ9/H9l6zEvY787VqUy4 xFd/y5SlOTjLq9W31bhhGg8gyO3hgey6RKVGD/LhMH4AOUG6Y3iKutGUiCbHAF5PNz0IvEPVn+E92x w/Q+pxpTavHYQX3yJvux0YN/SWYfGQV73NuGjHgtD0XegV6dZcBDtZ3I211VRGZfsJieB1JtGLGYrr g+G7KkkHqVeJrrtahW8NsTmzi7pPr+R6+3tdVzEbRgRpAI+S95yUW99j5nMA==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=eRJXSwOu;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42d
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

As done in commit d73dad4eb5ad ("kasan: test: bypass __alloc_size checks")
for __write_overflow warnings, also silence some more cases that trip
the __read_overflow warnings seen in 5.16-rc1[1]:

In file included from /kisskb/src/include/linux/string.h:253,
                 from /kisskb/src/include/linux/bitmap.h:10,
                 from /kisskb/src/include/linux/cpumask.h:12,
                 from /kisskb/src/include/linux/mm_types_task.h:14,
                 from /kisskb/src/include/linux/mm_types.h:5,
                 from /kisskb/src/include/linux/page-flags.h:13,
                 from /kisskb/src/arch/arm64/include/asm/mte.h:14,
                 from /kisskb/src/arch/arm64/include/asm/pgtable.h:12,
                 from /kisskb/src/include/linux/pgtable.h:6,
                 from /kisskb/src/include/linux/kasan.h:29,
                 from /kisskb/src/lib/test_kasan.c:10:
In function 'memcmp',
    inlined from 'kasan_memcmp' at /kisskb/src/lib/test_kasan.c:897:2:
/kisskb/src/include/linux/fortify-string.h:263:25: error: call to '__read_overflow' declared with attribute error: detected read beyond size of object (1st parameter)
  263 |                         __read_overflow();
      |                         ^~~~~~~~~~~~~~~~~
In function 'memchr',
    inlined from 'kasan_memchr' at /kisskb/src/lib/test_kasan.c:872:2:
/kisskb/src/include/linux/fortify-string.h:277:17: error: call to '__read_overflow' declared with attribute error: detected read beyond size of object (1st parameter)
  277 |                 __read_overflow();
      |                 ^~~~~~~~~~~~~~~~~

[1] http://kisskb.ellerman.id.au/kisskb/buildresult/14660585/log/

Cc: Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev@googlegroups.com
Fixes: d73dad4eb5ad ("kasan: test: bypass __alloc_size checks")
Signed-off-by: Kees Cook <keescook@chromium.org>
---
 lib/test_kasan.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 67ed689a0b1b..0643573f8686 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -869,6 +869,7 @@ static void kasan_memchr(struct kunit *test)
 	ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(size);
 	KUNIT_EXPECT_KASAN_FAIL(test,
 		kasan_ptr_result = memchr(ptr, '1', size + 1));
 
@@ -894,6 +895,7 @@ static void kasan_memcmp(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 	memset(arr, 0, sizeof(arr));
 
+	OPTIMIZER_HIDE_VAR(size);
 	KUNIT_EXPECT_KASAN_FAIL(test,
 		kasan_int_result = memcmp(ptr, arr, size+1));
 	kfree(ptr);
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211116004111.3171781-1-keescook%40chromium.org.
