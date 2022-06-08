Return-Path: <kasan-dev+bncBCF5XGNWYQBRBS5OQSKQMGQEIPCSSFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113e.google.com (mail-yw1-x113e.google.com [IPv6:2607:f8b0:4864:20::113e])
	by mail.lfdr.de (Postfix) with ESMTPS id F16A9543EB6
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Jun 2022 23:40:28 +0200 (CEST)
Received: by mail-yw1-x113e.google.com with SMTP id 00721157ae682-30c99cb3d4dsf185240927b3.6
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Jun 2022 14:40:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654724427; cv=pass;
        d=google.com; s=arc-20160816;
        b=PYziUyqq1yO+0ZCQlMexDWfPJOR5V2BYvuH3LGIyUAPdAEMKpZa8fvOcW1mQ8/+hyp
         vCTBCIZaTd1xHSg84omMSRpFLwB98o0wrpVKPTj75s+4LECMuYP2aK94cjZs8gXnvLbR
         sw7pf5DRkkEUI7FpaQXuKLmEuIbzq6oJ9gn9dtfBJfnYH6sk0q/Q6EtR61fysrAMPQUW
         dUwBovV6AU/fS/Uur6b+1nOUj3/C9YrfF6jWmbHl53PpQQJzOwY8A/RcL1wd3moRMWVe
         V5XM5b3nUM+mmY8J0zSe4qAiU7b7gaBzIrvyifUcz5XpKIlARroG4IPHQisKrLGIvzNU
         KwLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=SS7QO9EFr1ZELtD0vOylMTDJUTHRFNN4pWIHvdMR92g=;
        b=pBrp9z3Gk5qkyOUfdtYQOhZqW+jjZRB4Ef7/h7ybpYSDvEhvG9vJwD9yzETt6qCSdc
         rqIU6bqJrJ917cJ5R1miKskjrrhJLcExRAsbwbPXY+CMlVVV5siBazk13qY79/7OK59a
         V9jZjjYigdRuohhMPKrsrnZpCkKEW7xBqPlIoryBwgnDqJzpR61DuQup3VYFJ2EClpCe
         Pb9+N2MzFuvGcSbiz6US7KISlQSPornuAxA5m4VQxDUjkJaonaRX6phWIir7mXmW28rG
         k6+mtEslzAGACK9UyYtvJbBZpY39CNVHXuuRTogq1x5POfv5SmYJnt0orXX0dQU9U2G+
         wVVQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=iOX8V1rv;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::632 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SS7QO9EFr1ZELtD0vOylMTDJUTHRFNN4pWIHvdMR92g=;
        b=DY/pNHpHa+bzlMAaRHLjIc/xZEE0S6/5ZaGyZReyU7VnVll2CwRrxEPPEjUYKfg9Uz
         r4TrOV85aflIf58M5gGGRGqStrLYMi0IoCjaBlMMQ/3T/10WLMVkmVRIqzoTRaEJvYtb
         Z7+UPIcpt56sSzHusSQPdzxuJFRhFBByFuxkcEoL52DyA76bHN0KXLCPErPHmLLAhEhe
         ziHgXfldalH+IJTtJnTsn/+CSXNTreFpiNSxXcM6FuNVkFxHCFTMeTnkn/oo3j4lk1o7
         tlN83Us2s5zZtm/6k2StuiW6/fC/xwxQ3gxrkaZuMKCATQDM3GqW645iA2bKRIWts7Q2
         9/mg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=SS7QO9EFr1ZELtD0vOylMTDJUTHRFNN4pWIHvdMR92g=;
        b=NJQrzDE+BCdbvQKj88VlsArIrUY3thYm/X3+ch0Ax31dy594YwjmXG/MVXmC6zRKOG
         U949aenUZUMdpdz0h0kFNUmyVSdnNHgmhLGsFHksCAP9Tn3IV1CfRK4C+AQTwSlrFoYU
         5o7EkTpmCBDBenclWs4zOoaUJQuVpgJZVawWXIICxy2Ty00MHEbuJhCmRAuf3GMt7yfw
         HlvfMG8WIeYfh70gSYc54LbQXPTsmrE9cICfpUK/CqKgm3Q8DsfubMDQ9dYUZLvzZm5S
         o+wwcrmLGWTr5fqMEpN6VvHuquhKyD5YspJqBtCkrv3vONgo58xvjzclupuBiRJRWJD8
         /wcw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5319THG3KJ/F8naGk8WA1PhNJRCpmZ1V/1yhyARCF3gtocq9Kjyy
	tV3l+Ijpr7jdhv0SwlNqOIg=
X-Google-Smtp-Source: ABdhPJw6a77wANit7XWS8e2MnlmIhuol8bcrm/8afIOMIXUfMLD81CE9kZeOa5SDWjun1T91XGw6zw==
X-Received: by 2002:a05:6902:c9:b0:641:1998:9764 with SMTP id i9-20020a05690200c900b0064119989764mr36504043ybs.427.1654724427486;
        Wed, 08 Jun 2022 14:40:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:134c:0:b0:30d:8627:7e66 with SMTP id 73-20020a81134c000000b0030d86277e66ls1964611ywt.10.gmail;
 Wed, 08 Jun 2022 14:40:27 -0700 (PDT)
X-Received: by 2002:a81:3d41:0:b0:313:e95:d777 with SMTP id k62-20020a813d41000000b003130e95d777mr13515584ywa.98.1654724426912;
        Wed, 08 Jun 2022 14:40:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654724426; cv=none;
        d=google.com; s=arc-20160816;
        b=uJGo8VAHEQ+ydqWVdwX/oZLTgjGEQpHuwpTosRP+pI689C91uWiVwyssxX6I3M3brt
         uztoaoXZH6PEbt5oOkTKe20px5UE+32FXmEw8YbNaT7iP0oeKaKB1iI0+72jFNQYXyrj
         iO8hGEblmGyJ96BQKsob9mEmEUjXjqLpfHX1kppVRiQw4GEeHX6lUrfNvk+2f09ChQ4a
         Z0b30ttHsVJfl+lNgVM8DyZ2lQRF1xuOWsFVrchtMC2ncQgWjRzCX9X7fclw1gi2uA+Q
         2PQvQ3X1/29ExqJC/RFFja4ratAim73J4dTt2d/4BpaNEDcVl/X8oVFbCB6HqgH02Cbs
         U6Hw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=ZBKWev1Rs6wuYROdIel8IsWvzj2P6ShAsqmcV/ovcGg=;
        b=Azh87bmvvpFwbuc3xaaTZsOTjUtR3nM5SSIDVmZ51sToVIFVP6ZFxza8ySEDJegj+J
         0HCMTkc8F7uNumFVrwDwL/cdd99YJJUIkeYRD/zHUFmGqMfUbjAsnmXTHOrBD1JJ+CkS
         R3OlzkehL7PE+yewsXYAqUVom1SdcAp9Dhqv4VwxnfflybCbDDapnAXNOMufyn3OKioU
         NTapIAyqW+cxQNlPh2E3ATfyzMcyBm7A0MOUXyYSsyFpIxJkbc26FkVf7du6xTdEa8DV
         eKEpLrlm1ChIUAgTEV1nUJtR0I1pJyUe47FmGN9hPrg+IfYxVJLY1axTzTiP0H2I6II3
         3BvA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=iOX8V1rv;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::632 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x632.google.com (mail-pl1-x632.google.com. [2607:f8b0:4864:20::632])
        by gmr-mx.google.com with ESMTPS id d7-20020a813607000000b0030ceb73fd6asi1168243ywa.4.2022.06.08.14.40.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 Jun 2022 14:40:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::632 as permitted sender) client-ip=2607:f8b0:4864:20::632;
Received: by mail-pl1-x632.google.com with SMTP id o6so13687133plg.2
        for <kasan-dev@googlegroups.com>; Wed, 08 Jun 2022 14:40:26 -0700 (PDT)
X-Received: by 2002:a17:902:e34b:b0:166:342f:82c6 with SMTP id p11-20020a170902e34b00b00166342f82c6mr35312017plc.29.1654724426139;
        Wed, 08 Jun 2022 14:40:26 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id y17-20020a1709027c9100b0016223b5d228sm15176202pll.288.2022.06.08.14.40.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 08 Jun 2022 14:40:25 -0700 (PDT)
From: Kees Cook <keescook@chromium.org>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Kees Cook <keescook@chromium.org>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-hardening@vger.kernel.org
Subject: [PATCH] kasan: test: Silence GCC 12 warnings
Date: Wed,  8 Jun 2022 14:40:24 -0700
Message-Id: <20220608214024.1068451-1-keescook@chromium.org>
X-Mailer: git-send-email 2.32.0
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=3431; h=from:subject; bh=f4bWuW0f1isrySVA800mMFtNGe6OzsYc2hHoaLhCD+0=; b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBioRdHHwaRwKKbpz1nkt1hw65Ms2PiFAooSZ7/hdvb /x/msieJAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCYqEXRwAKCRCJcvTf3G3AJm3yD/ wIJi5uSdbwIZpiSkKpBCwp+MzcWNoQclJTycpr4NCLKbPlepOG19bev3lzzPoAyBLUMRPvono2ZUn7 Z84NKF4HKmEHVEQpOyp3SaZ4LhWCgOeFSF5pNEngCqJNz6YJbITJf0NhsoDEpCuHeCc5kGd9XTXZpJ UU+djeG3geRtSbx2jnO6ralgR89jo02fozbjwp5ej+yVaJ2USgQ+Us1CvwufWlFSPUJbpXOcNTN21O V+Nw1zDXkv1aSORCghOHNQyREFiz466+WssNBEnq5TbsqU9TOM4VfqjRaV8Li70nxGMpXZKplxT7SD 3EXDu8JkTlX/lFQKxpdR7tBjC9+S7K988kneNgVXd1lp8hCuP1fTUNyg7KVAX+6H/Mc3iwQxsmgHMB NFC11iiiI36dIUST4xXEi+4GX2gb6FHTggQG+YIesttUPFDZH9tUbfIinkBW29tLMajecRRDA3EgPB m96Xy2mMe2qPAR1FZJxRNklTHMHZSmD2i96CJw1UsZWv9hC4NUniNGAlB7VzPkuPRK/LqLyiXvl6DU kNkrZGm1juLpUEVWVBsjMUElWb2kt0z+BHUSz/LaDv7Y3cYmXLvV9uHEDwUPKrInYZXulBc2BRwBho y4y/ZKxM8vqXVmqyAo0HoYQOzzC1qKXhumZTYLIF4SOur39wGcNJzUWy7Zcw==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=iOX8V1rv;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::632
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
---
 lib/test_kasan.c | 10 ++++++++++
 1 file changed, 10 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index c233b1a4e984..58c1b01ccfe2 100644
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
2.32.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220608214024.1068451-1-keescook%40chromium.org.
