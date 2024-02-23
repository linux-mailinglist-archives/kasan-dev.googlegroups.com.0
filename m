Return-Path: <kasan-dev+bncBC65ZG75XIPRBQWJ4KXAMGQEEMKWSCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id B4A62861373
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Feb 2024 14:59:32 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-512d6a5c0f0sf312117e87.1
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Feb 2024 05:59:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708696772; cv=pass;
        d=google.com; s=arc-20160816;
        b=WlP2HuNvVBkpv9jr8S78jsdv2QNNvWe07JOUfCEGCX27J4dRJQvuDVKs6+gUWLzsRG
         menKCIgaZ4eKUCA66a8zjxsmeMbiyDRcoLYhEQ9N9rxRTTaoUvxGmF8wjbyqLTl6zCyq
         WLs5ykAdokPv0YA+5oopOubH0IBON07BVNEHGXNzU0kN1/wHm+FA0qf4oAuQJCPlIcky
         +6tpwejV88VBBAy4mT7mG4JhLz4hOZkFJ1SLcW60wUw3r8IYGMMIQZPkod0MQ7Vbc7iZ
         4JeK5/Av5npv5jscUyxqy92VCRR9XzuH3kmm2Wp+sqW+UdZZyzmhOH6KQof9WYDqTDin
         sg5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=iSg/iO5WN1uQo12irDCuOe/EswX2y1tRyB0OE59Pxyc=;
        fh=mZBFTdU1xAnX1sn2l6jkWXwQS6OvTuw9rbsl67V327o=;
        b=Zx6nZgx+TO3VSP9wbhhCpca34CrvqacH8iHyuD48UGWc5fhYYZWJE1vX8Tgl73HHMe
         /dQ2w1/r2XJmkhfb3kab4RQpPAEDHBKJNqjvN0E0bAPoEOX6SjkrHkcW1Ir4GzJSEWgp
         RNoktHFSCWXJHoa3Eipgs2ESp1ksSISQvZ5WlgFggAQx4b1kTO31xKYpFJO5Qfu2glE9
         22c+3EZIeTc3uCC6vXJ8G7LWSo23L2wFBt1RjmBqf5PKdAZxyewpRrKM0wGDgfoUlr74
         entPG4bxePawTL4nKkT4glSNDNzxIR2bpC/05UY9P8XDpXqjy8G6NKRMab6nSPR1Swn5
         y8Nw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=xFkUMGc0;
       spf=pass (google.com: domain of dan.carpenter@linaro.org designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=dan.carpenter@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708696772; x=1709301572; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-disposition:mime-version:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=iSg/iO5WN1uQo12irDCuOe/EswX2y1tRyB0OE59Pxyc=;
        b=v0xALR+F08pxWf+VZfeKtmFGhjLTzO7axTNzqofrgFvIy2/W7h8ZkAkerF4raQtnDX
         A6c91Gd4VQ8541gOd8GtljU6+jfoMh3pcHPxueCDc7+nqtlsnuKSIGi88U9oEo7mRKCE
         23yzF282zd0bk92qOiKetC5oPsFnFEcOamtsKD2LDQVQqO7qeK1O3U2Vv3jajegzAGVG
         Lh+dIGe4D2cgSCP+Dm32/YNMAzt7+MBWBrIjeioIiPchNc9bhM/0iLjvzcm9PKlBo/vl
         noYFDSb84ZFadME2u9G8z0JWN2pWYMCptGBwWHUDmL5L1KE2HmMAOVNICzkDkNMfnTOA
         /irQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708696772; x=1709301572;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=iSg/iO5WN1uQo12irDCuOe/EswX2y1tRyB0OE59Pxyc=;
        b=HLGPa/4s03jEPkXChe1Iz2nuZFuqIBHTSICQI8wHID+j8YWb7y7fVKoX/NtkkLsoeO
         sJ5gdQowd2hT6TpsuS/Vzvbkmvq1XKx/E+DvuvafJkA49wmw4poIyMY3D72OCsd9Xd2J
         Tc34F3HmiYROSL1WYjM5vwBa1AaMfRl2CoRRy2ut3uPFmICsxyTh1ax2btpO944MDVwc
         Jcjqi6ShbLr+TR/hp+/TKDuvnwH5bBmT5iGKmUF6HddV4mcRRnhHOIEnUziv0SzHuAaK
         bl0xYg/1E02fmC0hV80/FDeWi7WUypa3c3HdVWjPnHzuDBJiPHIW10T7fwC8kdqCihUl
         Ij/w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV6X29LyhYOMyXvL88p15E8SXEfcupJuh7aqCq5NhtslQ51gy2Dt+U+VG2SB1mWkzM5n95KsOVfnmJ8Ubaj/EU7yN663nEBBw==
X-Gm-Message-State: AOJu0YxoJg7O9KpVcMqYlPh5OwE38yRoyTwvGNqkDMIzLnKGZELndIKN
	2cy+hXv2T23iPuHMrvo5urFYiVEOPa5ugKxYeV4KDBgM0ZXfWF+U
X-Google-Smtp-Source: AGHT+IH6LLOiLX02bL1DsSyqTwbUtyVO7hBRVLx4FJTuMAzbA/WaEVYVbV8ju0QAzyIQogHo5Qu0Mw==
X-Received: by 2002:ac2:4d01:0:b0:512:ec53:9519 with SMTP id r1-20020ac24d01000000b00512ec539519mr506211lfi.35.1708696770732;
        Fri, 23 Feb 2024 05:59:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:3218:b0:563:7dc3:bec8 with SMTP id
 g24-20020a056402321800b005637dc3bec8ls309493eda.2.-pod-prod-08-eu; Fri, 23
 Feb 2024 05:59:29 -0800 (PST)
X-Received: by 2002:a05:6402:1acf:b0:564:b823:a78 with SMTP id ba15-20020a0564021acf00b00564b8230a78mr1423826edb.37.1708696768846;
        Fri, 23 Feb 2024 05:59:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708696768; cv=none;
        d=google.com; s=arc-20160816;
        b=oNgAbD4FOiWAq4bFEGyVy+ccPG8e43defxWt1EpgyUexoaQa4q4SCUPBtqPWTG0fqo
         OIA534qx+/v4HKFGu2LV0LJLS4/d3qP3e2EpITWESyPmSVY+K/6xewpivi/0kgpPB0wS
         4OZy9bcQxUKAhr0gUEsPqI1kFJbfx3ah+KK5GLELIXiXkOod4O7WWU4L0JkdfHsRxPow
         j5zFnKcV3DZAIlaF3OSYAkQxH24g+7hWWQTst8JeDtdPtfrlxgtq7UrXjY6wHC1W2A5L
         uti/d4/vVAUKyokRq5l66WuFgFAwicZCrVNg/7eUVVjotEeI2ONIbjgMZokkAFskogpC
         a/xg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:mime-version:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=jjgxYquA5yg3thtLQosh0fBZBhvAc6n9mvaIrU2SLwQ=;
        fh=xfbwRLICyICepMAHo+YYCAmzmU8O9w0A8MMTNdBUFdI=;
        b=wbdCeu+gKesFXeyp/XvnIdDqWT4zK78R1eqgijWuARFOJospZH1W0pdd2rQMKVMHQc
         kB+1jRQyq5jLrHiMcjI/+Z1W81prB19mo/S7oFtz/ERpPpmS0lJDZcC0dyDm/ksq31uU
         /Sc18mfsqRM8dgraFDwx2U/iH4w3MPRDV/I+/lA1V7wxPFq6Xpx8l/86QRTVk4/z5iBC
         zqVMiJyjCAhMv/7Kh4GQqLGfXWTg1fyJbng5e42OepR8xdwICjfXGDxpcTNdELoqpmtm
         8jgxZELMpHv2mO6pceq/cRthRLC0zGfcH0agcJa0ToPkzXzMeXuQm8YoK75cfUHYC19l
         JfGw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=xFkUMGc0;
       spf=pass (google.com: domain of dan.carpenter@linaro.org designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=dan.carpenter@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-wr1-x42c.google.com (mail-wr1-x42c.google.com. [2a00:1450:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id m20-20020a50d7d4000000b00563fcbe92aasi1006608edj.0.2024.02.23.05.59.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 23 Feb 2024 05:59:28 -0800 (PST)
Received-SPF: pass (google.com: domain of dan.carpenter@linaro.org designates 2a00:1450:4864:20::42c as permitted sender) client-ip=2a00:1450:4864:20::42c;
Received: by mail-wr1-x42c.google.com with SMTP id ffacd0b85a97d-33aeb088324so253490f8f.2
        for <kasan-dev@googlegroups.com>; Fri, 23 Feb 2024 05:59:28 -0800 (PST)
X-Received: by 2002:a5d:5244:0:b0:33d:3553:d395 with SMTP id k4-20020a5d5244000000b0033d3553d395mr1607850wrc.15.1708696768466;
        Fri, 23 Feb 2024 05:59:28 -0800 (PST)
Received: from localhost ([102.222.70.76])
        by smtp.gmail.com with ESMTPSA id bw26-20020a0560001f9a00b0033dabeacab2sm2282733wrb.39.2024.02.23.05.59.27
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 23 Feb 2024 05:59:28 -0800 (PST)
Date: Fri, 23 Feb 2024 16:59:24 +0300
From: Dan Carpenter <dan.carpenter@linaro.org>
To: elver@google.com
Cc: kasan-dev@googlegroups.com
Subject: [bug report] kfence: add test suite
Message-ID: <1605a86c-103e-4e93-a8ed-c9731c573fcc@moroto.mountain>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: dan.carpenter@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=xFkUMGc0;       spf=pass
 (google.com: domain of dan.carpenter@linaro.org designates
 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=dan.carpenter@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

Hello Marco Elver,

The patch bc8fbc5f305a: "kfence: add test suite" from Feb 25, 2021
(linux-next), leads to the following Smatch static checker warning:

	mm/kfence/kfence_test.c:673 test_memcache_typesafe_by_rcu()
	warn: sleeping in atomic context

mm/kfence/kfence_test.c
    656 static void test_memcache_typesafe_by_rcu(struct kunit *test)
    657 {
    658         const size_t size = 32;
    659         struct expect_report expect = {
    660                 .type = KFENCE_ERROR_UAF,
    661                 .fn = test_memcache_typesafe_by_rcu,
    662                 .is_write = false,
    663         };
    664 
    665         setup_test_cache(test, size, SLAB_TYPESAFE_BY_RCU, NULL);
    666         KUNIT_EXPECT_TRUE(test, test_cache); /* Want memcache. */
    667 
    668         expect.addr = test_alloc(test, size, GFP_KERNEL, ALLOCATE_ANY);
    669         *expect.addr = 42;
    670 
    671         rcu_read_lock();

Preempt disabled.

    672         test_free(expect.addr);
--> 673         KUNIT_EXPECT_EQ(test, *expect.addr, (char)42);

You can't call KUNIT_EXPECT_EQ() under rcu_read_lock because the failure
path does some sleeping allocations to log the errors.

    674         /*
    675          * Up to this point, memory should not have been freed yet, and
    676          * therefore there should be no KFENCE report from the above access.
    677          */
    678         rcu_read_unlock();
    679 
    680         /* Above access to @expect.addr should not have generated a report! */
    681         KUNIT_EXPECT_FALSE(test, report_available());
    682 
    683         /* Only after rcu_barrier() is the memory guaranteed to be freed. */
    684         rcu_barrier();
    685 
    686         /* Expect use-after-free. */
    687         KUNIT_EXPECT_EQ(test, *expect.addr, (char)42);
    688         KUNIT_EXPECT_TRUE(test, report_matches(&expect));
    689 }

regards,
dan carpenter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1605a86c-103e-4e93-a8ed-c9731c573fcc%40moroto.mountain.
