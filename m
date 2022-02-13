Return-Path: <kasan-dev+bncBCF5XGNWYQBRBRE5UWIAMGQEEK5UMWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6BB6D4B3CDD
	for <lists+kasan-dev@lfdr.de>; Sun, 13 Feb 2022 19:32:37 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id x6-20020a923006000000b002bea39c3974sf7779836ile.12
        for <lists+kasan-dev@lfdr.de>; Sun, 13 Feb 2022 10:32:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644777156; cv=pass;
        d=google.com; s=arc-20160816;
        b=S/f7ksge3q8nr6m4YECg1q4xD0cgvDgV/idStWtbi8Ss79kPI5cvDjva+Mv3WI9tWw
         07UlVOWm/azaer/nyzSugpnlqqh8KJQ8H5ggWowBcRrmrg9zmgtzUdQfsG4GqsGG3v3d
         oiUkziSx+Lq68xUhlSSAitxwI93/k/jF+fJhQyEQz+27rIodSZyqyikY5hCvrHrxg2hX
         B4/m5GSr77+aCshf0qlztbDk9oA5z1lLqUNstR9XuqGrBL/p9n8Y4QZkfvjbAobACsT6
         p9mWGcFABGo+UzUHxlLamOge1f3UcJtIaxdcnbDenRxXub2dGH9Ysu/VWThxHqFhIe6P
         I/Ug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=PyYnN5jn07XdPwVxEFbRRcnbulJnmRYmgVWfVUxvN8k=;
        b=rtwk72jkaGMEBOkoWNact8j+KdrVG+TpN4+fHjJpRkCdUrZLqInze0DDg4kcRuaY60
         FOdiGWBywCFnJe81Dl4cOQ2BNi7dS5B+mYd2NB4cjr/A4sgAh9U/RSlSlnZh6OuFmED8
         Prc8/J2kE/MkRDkcnwIZlMSQrrfuyOG2F+V7Kqg1wxan491Gz4Tjy3biLB+keiuO5Cnc
         2EF2Lx5k76qsfN6co9NESadBXztj8dsARAXYfODbmXzUti0hTABeiKJOXlek4zWhpu7g
         3MgLq7YXJambzI6ECjntFVFMnZeursrtfBDMCBm55ak02nVTe97rp3q6WIosm+Ml0q5q
         pUWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=GAsZqZDa;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PyYnN5jn07XdPwVxEFbRRcnbulJnmRYmgVWfVUxvN8k=;
        b=HjYgzBFiztQUu8W1P6l/fhS2Mrv7U8Hgj40lYdR0A8klo1X1kbbz8XkazfZ7gYUnnn
         wKXd6NdcFmjW3Wf0fInJFEzweXOhF/0Pj/VmHEw4CNLASXT3CbEd4N5K+Uh0T3d5irJY
         Eg2jYFwKj92qUSXsXV48ONLECfAuAAHzMUefmwdsHHQxK8h0+jx1WKy8ROkqkRgobDMj
         HuY2noSTwIpV0U3gqS2ThkQEvaVzDfXz6JDHhx1yUmyJQ2nzeBPHzOmTyuyxhY8+3lbA
         nq2XK+OwJULaDPcLuPM0M+csBvgJHk6gLiOPLVeLP0UHDgleWtHv4G+kl166JOOJbY/v
         jLQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=PyYnN5jn07XdPwVxEFbRRcnbulJnmRYmgVWfVUxvN8k=;
        b=Ttdl0O+TX3eNfjF1mYT9fij/JOjEBEDKahHcOKYeoK3WlExApsWeoFDw++lzE83iun
         9d3b7XvCcxcuHWa+juvGBp1/od2S6b1VNZr34ygdFxIU/pkrAZ5s/+Fw+HEXZuIU0oLb
         /rlhA3cdphvDu1a4TPjLewJaxpd8hQbwvudbnFPeZZy8huLdMyZLwNmx7m3bgLf8UqBh
         A2kWWqHb+Ji5LH75RrUEdRxXHMijtaU2Y0OMBbRVx3MPCTFd4pHpd3qxKQKigDdm5S86
         kqUOnBhNNV0bcdtjg0eCizq5kCvjs64V3nKOnDguEGFzkg1QjKAdEIDWTnc91kMnaQmO
         vaNg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Vha3L1X/bzrWO5XQRfqXwrL3pKvryhuTekdECc45C8HKp27h8
	O6MuE9uFtu06xNDbQaURtrA=
X-Google-Smtp-Source: ABdhPJwltwh0tQ56+ds+X054MwM5L+KhSmM0tM6U+MxlTKzxleuF8OvbvhgJXIattHihJh48sKeL9A==
X-Received: by 2002:a05:6e02:12c8:: with SMTP id i8mr5753584ilm.279.1644777156192;
        Sun, 13 Feb 2022 10:32:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:2614:: with SMTP id m20ls2432917jat.1.gmail; Sun,
 13 Feb 2022 10:32:35 -0800 (PST)
X-Received: by 2002:a05:6638:606:: with SMTP id g6mr2907964jar.20.1644777155769;
        Sun, 13 Feb 2022 10:32:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644777155; cv=none;
        d=google.com; s=arc-20160816;
        b=Tir0uzRxGHVJpL10blQwOrSrPFyM0jszGgXcuinlyzkV4GrKr0NF9t6S2kNbDcl+d7
         rgTYXRr5zdpN68I7JOn2SHPlBfuEJKXEgFduGV0ALPAwQmx1on5RsRf9bVm9HePEdalO
         OLUF+jfTzISIEu8o812nppF9Ku+hUuBiwLUD8qMBvMGK4PjqEMi/hKGlC6DdlBzaumGy
         jB9ukGq6viXBCifhT/crB7x6FtO1W7dTRO2U3qqdG76EIrSbiLm9iXnFEh1YODShMV8J
         b93hrQiJcqshLNxIh4UQ7jStAhSJTUcL+6YCysPbj8rzty1g9EOG5NAVw8A1VidKNhzJ
         zgFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=GbN1m5GjdzaYtEly7rnCE3vNXf0FkYK/naaa45R/epk=;
        b=j8lv7ivlTpX2e2I+ojdk1iikWOnkXPq4sYzezMVfvHHABVdev6qbKFuGH0PWMkgbPw
         aTLf0mEtUKHCVtQ+Wmz0o+Lvw+b7zHDEy2I0OqOw7/nHD5vCW45KKqJdYoArdekcr1gf
         8Hf4RvZtKUqJm7awXqO7S10iw8YJbahd03h32obezb1iwsfZW2qBQJQcArM90ETDSSnd
         tvpdfELM63VVQf8Y37pU5H/eLYod6VGyrrWrY2BalL+dcIrr9Z8gEQX/kBMqwX0ph0xK
         uya7xzVIRFUe6RZuulcrVmvNp60R97moKt+7OIo2TbI670KhWfaNHKCnCr9wiBS1y/IE
         lK1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=GAsZqZDa;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pj1-x102a.google.com (mail-pj1-x102a.google.com. [2607:f8b0:4864:20::102a])
        by gmr-mx.google.com with ESMTPS id u13si2931923jad.2.2022.02.13.10.32.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 13 Feb 2022 10:32:35 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::102a as permitted sender) client-ip=2607:f8b0:4864:20::102a;
Received: by mail-pj1-x102a.google.com with SMTP id r64-20020a17090a43c600b001b8854e682eso13717137pjg.0
        for <kasan-dev@googlegroups.com>; Sun, 13 Feb 2022 10:32:35 -0800 (PST)
X-Received: by 2002:a17:90a:c7cf:: with SMTP id gf15mr10802631pjb.83.1644777155479;
        Sun, 13 Feb 2022 10:32:35 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id j2sm33728429pfc.209.2022.02.13.10.32.35
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 13 Feb 2022 10:32:35 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Kees Cook <keescook@chromium.org>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-hardening@vger.kernel.org
Subject: [PATCH] kasan: test: Silence allocation warnings from GCC 12
Date: Sun, 13 Feb 2022 10:32:32 -0800
Message-Id: <20220213183232.4038718-1-keescook@chromium.org>
X-Mailer: git-send-email 2.30.2
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2824; h=from:subject; bh=9u7Cd7ajn+8VmlBggVW9I93wUx5ifwsTV6OZFwgwhrM=; b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBiCU6/gcktGKuswV/wNYH+QUBfdaSH8kMaFAvY83FQ ph5DlX+JAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCYglOvwAKCRCJcvTf3G3AJv+tD/ 0f4VQg7uhKWf8BVJWIrY90fqUSCg1jxlya8ImO4GTv7SnS2huBhD3gvcwvxMtKTBTaR66ijo2duyI7 6i/R4ysAKYnFzcVGZVlIwztISpnXG2aCDszH6/9vxsKZT0WArlKqRIqbQjeykzbCCaR8bxpEBAFin2 htLRBbiZeIK/7ITXcNa2EBwmcB3UjN+XLGKaARJgehBunT+W6VFR2H5xM0R3mLvM6vCCQtJ6VFienm PPMNaXG8ai3zXd5d4rN9qbWH9ie3xPjVRze8vKTKPzk16+A5EHP2to7DOWORwlSLLUi/SOcRDknkSw tQxGILWKjx7bLbEwtignkRLipkgt0twRlTP7p73Ss7JM55Kw08KlQRjE+S4aQyc/9tgwBwU5aYuExW 2At+7hE9R/6vEZ/gi1tKolhnItAeh/yHgR/vvCPmSfeaUjKrtDSQ6tkzpjEUPvwXWFIKA42c6xlQSL brzc35QiULxWnwydILbzuOvAUvNR1a4kqISFIADBcXJYELaLqe32E/Be3zIfR5DfTy9aQXQNJvIuR9 x1DBYfSET2fDsWASvaZqIfGYI5m7BqKiYDP9Y9E8r4O86SOvtvkfp81wVCamYcKvyx40Kp6SYdiLCd IWUuwzekAYY0r1WDsvsd3cBgfsOm+QaXU9FsSlbr7ofiVKO7H5ShRQwDBdOQ==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=GAsZqZDa;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::102a
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

GCC 12 is able to see more problems with allocation sizes at compile
time, so these must be silenced so the runtime checks will still be
available. Use OPTIMIZER_HIDE_VAR() to silence the new warnings:

lib/test_kasan.c: In function 'ksize_uaf':
lib/test_kasan.c:781:61: warning: array subscript 120 is outside array bounds of 'void[120]' [-Warray-bounds]
  781 |         KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
      |                                       ~~~~~~~~~~~~~~~~~~~~~~^~~~~~
lib/test_kasan.c:96:9: note: in definition of macro 'KUNIT_EXPECT_KASAN_FAIL'
   96 |         expression;                                                     \
      |         ^~~~~~~~~~
In function 'kmalloc',
    inlined from 'ksize_uaf' at lib/test_kasan.c:775:8:
./include/linux/slab.h:581:24: note: at offset 120 into object of size 120 allocated by 'kmem_cache_alloc_trace'
  581 |                 return kmem_cache_alloc_trace(
      |                        ^~~~~~~~~~~~~~~~~~~~~~~
  582 |                                 kmalloc_caches[kmalloc_type(flags)][index],
      |                                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  583 |                                 flags, size);
      |                                 ~~~~~~~~~~~~

Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev@googlegroups.com
Signed-off-by: Kees Cook <keescook@chromium.org>
---
 lib/test_kasan.c | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 26a5c9007653..a19b3d608e3e 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -124,6 +124,7 @@ static void kmalloc_oob_right(struct kunit *test)
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+	OPTIMIZER_HIDE_VAR(ptr);
 
 	/*
 	 * An unaligned access past the requested kmalloc size.
@@ -185,6 +186,7 @@ static void kmalloc_pagealloc_oob_right(struct kunit *test)
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size + OOB_TAG_OFF] = 0);
 
 	kfree(ptr);
@@ -265,6 +267,7 @@ static void kmalloc_large_oob_right(struct kunit *test)
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 0);
 	kfree(ptr);
 }
@@ -748,6 +751,7 @@ static void ksize_unpoisons_memory(struct kunit *test)
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+	OPTIMIZER_HIDE_VAR(ptr);
 	real_size = ksize(ptr);
 
 	/* This access shouldn't trigger a KASAN report. */
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220213183232.4038718-1-keescook%40chromium.org.
