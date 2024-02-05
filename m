Return-Path: <kasan-dev+bncBAABBHHXQGXAMGQEN7ASVMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 64DC88493B1
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Feb 2024 07:09:34 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-59a25e89211sf4508528eaf.3
        for <lists+kasan-dev@lfdr.de>; Sun, 04 Feb 2024 22:09:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707113373; cv=pass;
        d=google.com; s=arc-20160816;
        b=fETTCSkpxeIAIb0YtUCKeHlEQjgH0JyvBKDj2KrdmhcNv1wcc99Qqp6Ot7HPIfFWrk
         tz6jvo5uz5BlNtPu/+uZZb1ax7vin15TBiORVGoQ4D8XXhrsgsXzm33CNpShQv2YhTMH
         PjPz5eKSRdyp5uVkbY2MLtBCko/DFbD78WbAfWiaoVy3X+xq5m01jepB1HxfbhcJI5N5
         2Nb63xEZRiHyj1r3tIGnTkBhBFAZUz+sb/xTVclz5CNgJmsiKY7IcNd9St1Utv05W4s4
         QqHYbSomZGmRkhjBQoKjOmA8j3Z4CFfWMzAzvGycfshhpUqGLkcsmN0+hup/SC7M9gEl
         S1Hw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=oib2HYofJwAA4260nQdHSgNZkh+3/Sr2vH1DtimYmqU=;
        fh=0KRQjzbHBaKQUWW2QN6sdkLPD8j+RSKb6Fp4CX9F69Y=;
        b=Kpc3eFG3cQ2lW5lRNY4/WrPnT2nuo0TvEPjMxHKLfhg4yJc9nH32Uk+McUW55YAiUV
         X1IPiuX1IxYrncH4s+8udQ7LHaBtdW3ekgmFzGVHt4OXJyhVzOZwWowOAaM7T8a6+kJJ
         zwKOy68GQRpQfpapsjIG0Epw/Sd0aL+beZ+/s+X0cYOKFhlUXgADLNKJ6qh8kj/F3ip/
         GOBuC9/TwNMZsRvj1I1EG1v/mAvrErbVQYLYKbI9BjkqfF7Cw3YZpVsw+vJCpkG/6OuP
         WXbJdZe3byf5JtkZsqPUppryokcdC89tYxc98it1izC+8OiEC4ni11KAJhGz7v3e+SRG
         6r0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707113373; x=1707718173; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=oib2HYofJwAA4260nQdHSgNZkh+3/Sr2vH1DtimYmqU=;
        b=SdLK/5FFofQZ7jkuisux0nLt5s5iOgKKud5xUjapvrwWpsPKsEfC3by+7uTawMU7Dd
         KECU/lFMYVmHBe05J4TZo9qtvNii7CapcVpErEdKYB99MBTyzc6pWG4TGOnqa7y3sAWI
         0OkZ+XPlW/Kuxiqte2pgoDNNyy6dS7ptVf9moQiSKtQsN39ZQtudbSDPO3Nf8K+W5Tcm
         t4zPdFadFC8WlB/2qDVUHrY/wUeM7p6hSmCv9QQXmXQY+ZqXK0HYUQW24CQM4flqDcwc
         YwZFRzhNA3xicXMJaW8xzknCHq0MUFFeK4PoMwby8qOXwtlgmi9IHSUFZM0fcYy6IjtU
         53wQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707113373; x=1707718173;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=oib2HYofJwAA4260nQdHSgNZkh+3/Sr2vH1DtimYmqU=;
        b=LJVw14nLxMxrOIG+dttIeI4ukdDlHQY/ISfQafo6ri5DSSlwcMbAg4EI53hNTZT4t3
         WPqT/ImuWdJg8B2ywAXVSGlwGB8ILFD+e4LzdA0int7/qPJwcmm4QAGiAlyba9lyzSR0
         8jXncqzmTJqqLfPpiIWXBrT/yQErLkrsp9NOZfyQIkfLyzGtEyZHgUPyam5OSMF4creP
         /bNwLurIbJrbLcHVtx7+d+/de+F3YdGqY3VwL4Tb622YeQ2To+EBRVcdUtTBscKRGsTh
         lfTdpKF+6W1VUFAa1CdJ6wgZgYQuTHy100TK4XR01JMX68EkAFPLcCNQvUlB1foUpBDp
         lQ2Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyeBYXNplgsaADt46rHEtCvgB4M2l1gbDpCHAXBVo3+sBf+eVkk
	PEE1zMLqD5xCP1Uw+DgOAh5sn7Q+vwU+qFlx20C5I7f4UHZ5h63e
X-Google-Smtp-Source: AGHT+IFaByVeG1RjDagurRgNdim0kkVgnT9WCe5ctvo2g36aCknXeuRGET2f2E7c03UE/hVHVH5fhg==
X-Received: by 2002:a4a:e6d3:0:b0:59a:3ad:4feb with SMTP id v19-20020a4ae6d3000000b0059a03ad4febmr13420033oot.2.1707113372994;
        Sun, 04 Feb 2024 22:09:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:5548:0:b0:59a:49cc:2998 with SMTP id e69-20020a4a5548000000b0059a49cc2998ls885542oob.1.-pod-prod-07-us;
 Sun, 04 Feb 2024 22:09:32 -0800 (PST)
X-Received: by 2002:a4a:d5d2:0:b0:59c:9164:f1aa with SMTP id a18-20020a4ad5d2000000b0059c9164f1aamr8303076oot.0.1707113370982;
        Sun, 04 Feb 2024 22:09:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707113370; cv=none;
        d=google.com; s=arc-20160816;
        b=If6Tam2QM0ZbY86W6sa0qgkGfA62lNMXt20Zj4cMRP2YP0nw/v/bzG5tFvGAuRY3Ak
         shI0IxIL1KPYvdUd1Hgnmc7BxWsf2jE30ZKDjvcmpjlel3Cb5ZyQr9QfBjzOcc/K0Qnl
         rquaeN6jPZ8Lcd9NQOVl+vg9WQ/kiRZc9tFnLC6v1TnVlGnl9yg+YogtsHvZ/uSVmtfy
         PHGgbR1GxhPUg7ALd+2RGR9lS4DqAYdFhuYUb6hd5DnBUicuarwE3uUX8Ctprjj7KWhx
         xLE84GpkmdJeSdi3QPBAdqbdGGT9gbmxHwtpWwMKMUPIIzRYtYUzrbHCio2Ua+71OTj1
         Jxqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=3wbIYeOJe/Z2Xp7ZpOCGvu3U9PRSd955H5wVCPXFKyo=;
        fh=0KRQjzbHBaKQUWW2QN6sdkLPD8j+RSKb6Fp4CX9F69Y=;
        b=SruVFO+2FyHSiZ4bt7oHjYW4GhCg+P93EDLxj88HVYGlo01FCHlmKqPhOukZ0Froq0
         3gt5f/oe2DvbE7Q6eI1EMMwFRaJnrOjXIE9SyfCf1Ont4BFTLx3U7f/O3FI6TbXEfTS7
         MAGBV+c5Xy4vE0aTiWRMm5senLmIOd9AVUn3ZUyK0imLdNlpuAjYEEdMdmkp6hMR+OXG
         5wl0OmuaWeBVFsAdU2RUk8cVF/DOQTx+AjPAhNaYH0iljR7in3nmUxDT5LvnyQjgcc06
         wLlrAwAXafXgHMwKyQLUOjSCp2aX4ySqbqzk4QW/mCAFbNesS7Ltng2iHjbV3ONfagZe
         5DRg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
Received: from mail.loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id f139-20020a4a5891000000b0059a92c49ed7si934070oob.2.2024.02.04.22.09.29
        for <kasan-dev@googlegroups.com>;
        Sun, 04 Feb 2024 22:09:30 -0800 (PST)
Received-SPF: pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [113.200.148.30])
	by gateway (Coremail) with SMTP id _____8BxVfGYe8Bl7ckKAA--.30922S3;
	Mon, 05 Feb 2024 14:09:28 +0800 (CST)
Received: from linux.localdomain (unknown [113.200.148.30])
	by localhost.localdomain (Coremail) with SMTP id AQAAf8AxHs+Ve8BluusvAA--.49177S4;
	Mon, 05 Feb 2024 14:09:27 +0800 (CST)
From: Tiezhu Yang <yangtiezhu@loongson.cn>
To: Andrew Morton <akpm@linux-foundation.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>
Cc: kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH 2/2] kasan: Rename test_kasan_module_init to kasan_test_module_init
Date: Mon,  5 Feb 2024 14:09:22 +0800
Message-ID: <20240205060925.15594-3-yangtiezhu@loongson.cn>
X-Mailer: git-send-email 2.42.0
In-Reply-To: <20240205060925.15594-1-yangtiezhu@loongson.cn>
References: <20240205060925.15594-1-yangtiezhu@loongson.cn>
MIME-Version: 1.0
X-CM-TRANSID: AQAAf8AxHs+Ve8BluusvAA--.49177S4
X-CM-SenderInfo: p1dqw3xlh2x3gn0dqz5rrqw2lrqou0/
X-Coremail-Antispam: 1Uk129KBj9xXoWrZF45Cry3Jr18uw1DJryxWFX_yoWkGFXEqw
	4UXrZ5G34aqanYkr47uw1fXrs7ua1xCrs8ArWxGFy5Zwn3KwsxZr40qr9rJw4rCr43ArWf
	trWDZr1Yqr12kosvyTuYvTs0mTUanT9S1TB71UUUUUUqnTZGkaVYY2UrUUUUj1kv1TuYvT
	s0mT0YCTnIWjqI5I8CrVACY4xI64kE6c02F40Ex7xfYxn0WfASr-VFAUDa7-sFnT9fnUUI
	cSsGvfJTRUUUb7AYFVCjjxCrM7AC8VAFwI0_Jr0_Gr1l1xkIjI8I6I8E6xAIw20EY4v20x
	vaj40_Wr0E3s1l1IIY67AEw4v_JF0_JFyl8cAvFVAK0II2c7xJM28CjxkF64kEwVA0rcxS
	w2x7M28EF7xvwVC0I7IYx2IY67AKxVW8JVW5JwA2z4x0Y4vE2Ix0cI8IcVCY1x0267AKxV
	W8JVWxJwA2z4x0Y4vEx4A2jsIE14v26F4j6r4UJwA2z4x0Y4vEx4A2jsIEc7CjxVAFwI0_
	Gr1j6F4UJwAS0I0E0xvYzxvE52x082IY62kv0487Mc804VCY07AIYIkI8VC2zVCFFI0UMc
	02F40EFcxC0VAKzVAqx4xG6I80ewAv7VC0I7IYx2IY67AKxVWUtVWrXwAv7VC2z280aVAF
	wI0_Gr0_Cr1lOx8S6xCaFVCjc4AY6r1j6r4UM4x0Y48IcxkI7VAKI48JMxAIw28IcxkI7V
	AKI48JMxC20s026xCaFVCjc4AY6r1j6r4UMI8I3I0E5I8CrVAFwI0_Jr0_Jr4lx2IqxVCj
	r7xvwVAFwI0_JrI_JrWlx4CE17CEb7AF67AKxVWUtVW8ZwCIc40Y0x0EwIxGrwCI42IY6x
	IIjxv20xvE14v26r1I6r4UMIIF0xvE2Ix0cI8IcVCY1x0267AKxVW8JVWxJwCI42IY6xAI
	w20EY4v20xvaj40_Jr0_JF4lIxAIcVC2z280aVAFwI0_Jr0_Gr1lIxAIcVC2z280aVCY1x
	0267AKxVW8JVW8JrUvcSsGvfC2KfnxnUUI43ZEXa7IU8gAw7UUUUU==
X-Original-Sender: yangtiezhu@loongson.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as
 permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
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

After commit f7e01ab828fd ("kasan: move tests to mm/kasan/"),
the test module file is renamed from lib/test_kasan_module.c
to mm/kasan/kasan_test_module.c, in order to keep consistent,
rename test_kasan_module_init to kasan_test_module_init.

Signed-off-by: Tiezhu Yang <yangtiezhu@loongson.cn>
---
 mm/kasan/kasan_test_module.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/kasan_test_module.c b/mm/kasan/kasan_test_module.c
index 8b7b3ea2c74e..27ec22767e42 100644
--- a/mm/kasan/kasan_test_module.c
+++ b/mm/kasan/kasan_test_module.c
@@ -62,7 +62,7 @@ static noinline void __init copy_user_test(void)
 	kfree(kmem);
 }
 
-static int __init test_kasan_module_init(void)
+static int __init kasan_test_module_init(void)
 {
 	/*
 	 * Temporarily enable multi-shot mode. Otherwise, KASAN would only
@@ -77,5 +77,5 @@ static int __init test_kasan_module_init(void)
 	return -EAGAIN;
 }
 
-module_init(test_kasan_module_init);
+module_init(kasan_test_module_init);
 MODULE_LICENSE("GPL");
-- 
2.42.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240205060925.15594-3-yangtiezhu%40loongson.cn.
