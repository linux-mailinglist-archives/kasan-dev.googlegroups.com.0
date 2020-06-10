Return-Path: <kasan-dev+bncBDE6RCFOWIARB24QQP3QKGQECXOFLCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id AF0B81F53CC
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Jun 2020 13:47:55 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id c4sf411876wmd.0
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Jun 2020 04:47:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591789675; cv=pass;
        d=google.com; s=arc-20160816;
        b=QRjBt+92XlNve1y2d0QglOkSCtffyeOTjSDlOuqr+2nyTm6eWaROjeF8G889YJvggS
         WOlTgFv5ZDUawtxTUThjndWw8GLLagzaaowFon87YzLc4WQWwJFrK+9ncVYavQVd/8Z6
         +XiMsmAXgr6OjzfFpW4Ey6+iW6aUPHi/IfOWIQDNnumERrE9y8/KTmq1y6Lm0KU/NnTX
         EyaI97Jtzmwf1xP6wruwGOX9+C1qaDCk5uyGZtS5O8aL8CDbwKt9mi83AxrWdfGOdTZA
         vj9h6rHGeRMc5qCici86sliP9g/AZdttMOlyFrlmXDXOeZebNRFQvcdAhWuKJLhhp5IW
         ofgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=yHrvn6u/bNly28l69GcK3AgkUFQ3o7JC+pLOGKMzieI=;
        b=ueH90WI7hH2ksBkT2Tg77EltBs1xJGKTNLWi3c/cbjh/aPaINR9QACYcAYhHu74qxp
         pgrTxtMM4baOK814IxfteeuhVwhKxLNwLHnSqYdmJXWB7Cm8Nc9ZRZ8/1e/uC+OJdReg
         czipIwh7bV+eg6bS+V+9WWUHOv1mPhj9f72afdbKwt06wUaer6ENtgor6yYa/mBUvJWc
         34qgOTqOeJtntsBslNTqL/XTRQftKMKuz46oAt5pTU/Ay1gdFpnVrbSKJdG0c+G9+SSy
         kxBNN3Cl8GPnk8CCw41d0CvrseOMDEUjv2y4tMUCj4N/APq//BCfccwOsY2LeC1eaNgS
         ZfOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=bLYH45Vm;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::22d as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yHrvn6u/bNly28l69GcK3AgkUFQ3o7JC+pLOGKMzieI=;
        b=ai0DVbqR8Yxt2o7Rd55s4zvqa6D9CtROqaF19CIoaKhSwbXiLoERur3E1UMPM2NEkq
         u9f3o1SP/Z2EAfataO0AYKJQProiE8QRCIjHVeVopf35tJ6oaqsOLbH8CabVHK///SDv
         //HV6Swyi5sfr1RlbLTqqYJgwXD+Zk2djjtjawTyFpU9wtFMo8JLU/EwGFAfDIejPiu9
         pvDXlBTm/zra2sFNjp/a0Mw8n85oLo5zwaz0fVL2t1ud9C/o4ByQdbeYZ9v5xuq9Ttiz
         QrsI57n9pwV2ALrCb6zOG6K/Sp2GPL4rvsKgkPU2Ad9uHclraI4tdkO2T7SX6EbYU891
         N6NA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yHrvn6u/bNly28l69GcK3AgkUFQ3o7JC+pLOGKMzieI=;
        b=J+WdXCc0spaHjc+NfmsVdhjDPPXIugvroq7hwdiwdcBUR4q11fEOdbUpRnpmup6aO9
         DEtZ2EQyKGTH1dNziBjJtAKi4nViKKVyPQnCFeI17vao2HR32UQ4Gdpr0VSq/s8vQGxK
         x2st+5SB+PlgRXCMHG2HtG2fLdbEhliIEIy1ensMv2lb4E4l8d7SdE3eOIKSG5qp1Qkf
         6own8iW+2q0FlfNMZSm/cgih/Sa7RBh8oDxj2tX8AwCQvt+orxPTr4LRSBc5xEMWXq7k
         EKhRN7+0WeijyZcTzD+IF7uI7Q7X7UYqvrxg55lVuZF3KmYlPlVi5liwjCZk8n0fQDp6
         3JhQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533w6Z4q9UPoBui/3oGwCD7xJzwgASsIWVQ+aSuZR9nr/OElPHUz
	Jpy4xwapXcOmfiNJrN+ofZc=
X-Google-Smtp-Source: ABdhPJzbPn9BNbM26zEBTSXtwltaFzwMKu/Z73dM6BD+7EGtcEg6I5836lr9ZwTwCii9Gt/7hOr3Mg==
X-Received: by 2002:adf:8b55:: with SMTP id v21mr3395466wra.187.1591789675370;
        Wed, 10 Jun 2020 04:47:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1d84:: with SMTP id d126ls1074103wmd.1.gmail; Wed, 10
 Jun 2020 04:47:54 -0700 (PDT)
X-Received: by 2002:a5d:4e03:: with SMTP id p3mr3330654wrt.350.1591789674895;
        Wed, 10 Jun 2020 04:47:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591789674; cv=none;
        d=google.com; s=arc-20160816;
        b=e9Jhz/vCBO+3h8nSvsiexjc397fiCzMZKhaiFqSv7K4h9W/ygOLxo4BqLCTpam9tXD
         XS6SVxFTioxk+oOQhYosmFdoRY40FQT7k84TViQXv8RH8G2b808kkQRvTvMZnh0CZ2D+
         nCQTqe7p7XN1luaY2db2kFwQ0U5FUQNUBFkOEtaI4opIvTAE16gstJurMh5nCP+lhQEX
         n6FFGmsNIszk9hOug/J6Ych/pO10uv3CFlzGenDQi1V9t4vKwEkQ5++014o31L4gzZc6
         A9HmHEZO535J7SBq/50wM9CT5rAVttjZlFIoaesGADeO3aZvQn+i1XTMzJSuOMtn3LU4
         ByJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Yus+/lD4OuvMldxAEiN7jOisiD2+C+JAIcpjZmzcBIU=;
        b=xFpYJfG9TA7lq2Y/v6LXPsJrEf3XWnYlN2XWa1eokShZX2qgSVjqotU1d0PRR9wv0P
         jBViaBuV+6GhSud6KtGxbnnBoq2OSXOLj9O16eLicm2W7nIyxTfA+QRg0F3/w0QUoOY4
         QJvhHh9JK7HxK4pDQUiWFDBXbGmGGXPkpGjdoo1gRHnUSn6B68v27gB0225u9zzuta3W
         3PKOoBCl8gc6nw4DzcPH3b0IbmTsb3aObuNG/xxOIvSVqiHKqSpdqffbi93SZxehmA2A
         N6XimRtKCtJUDy5fAOThMRWyDki1jLrwSL5vbWv+wO4CGsiDa0Qju1PzFuFAhBczsWgU
         jWdQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=bLYH45Vm;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::22d as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x22d.google.com (mail-lj1-x22d.google.com. [2a00:1450:4864:20::22d])
        by gmr-mx.google.com with ESMTPS id f16si313068wrq.5.2020.06.10.04.47.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 10 Jun 2020 04:47:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::22d as permitted sender) client-ip=2a00:1450:4864:20::22d;
Received: by mail-lj1-x22d.google.com with SMTP id a9so2071930ljn.6
        for <kasan-dev@googlegroups.com>; Wed, 10 Jun 2020 04:47:54 -0700 (PDT)
X-Received: by 2002:a2e:a40f:: with SMTP id p15mr1696360ljn.286.1591789674600;
 Wed, 10 Jun 2020 04:47:54 -0700 (PDT)
MIME-Version: 1.0
References: <CA+dZkamtaXi8yr=khO+E9SKe9QBR-Z0e0kdH4DzhQdzo8o-+Eg@mail.gmail.com>
 <CACT4Y+YS5b2PokFVvw69Mfo-jjE13jGAqYmtEJQa7tVHm=CjgQ@mail.gmail.com>
 <CACRpkdZzj6MRJk3sFN+ihw8ZksZ-WF=CJNsxuazkAYPmd=Ki_Q@mail.gmail.com>
 <CA+dZkanvC+RU0DjiCz=4e+Zhy+mEux-NHX5VO5YUCkhowN4Z_g@mail.gmail.com>
 <CACRpkdZv_6RN2vt5paCDx2g9DWsKT6LZTw1+jrLZNqVrLvKQWA@mail.gmail.com>
 <CA+dZka=1cE1Zt71bH1K7ZZz0dPfB5pW11CJgzRiOwyxqnNOSJg@mail.gmail.com>
 <CAG_fn=WM-JNOsBXHkVEtuWzk_UZATuRVUsEins2O5sxf0tYg4Q@mail.gmail.com>
 <CA+dZkako-AaeWJ71eHHLnJVWxbCUWkrc7b9sSWZPUSLL-ty=-w@mail.gmail.com>
 <CA+dZkakg-PpowaqknoKcoy3RDWSNbEAqSVm01SOOYDxZKV-WOA@mail.gmail.com>
 <CACRpkdY9pbM--gBU2F_3Q=AdB1Fsx4vHzc5O-3Fq0M105SQWLg@mail.gmail.com>
 <CA+dZkann4Z1TavtJ+iq9oBrAiAaohZfke8aoyhcqvs_CYSuirA@mail.gmail.com>
 <CAG_fn=XjmgyxDANUN0a8kY2CuucQ2gHFfQqsk6TF_XpiqWGCgw@mail.gmail.com>
 <CA+dZkakFEJZLtfe7L2oN4w4O=T+x1L2WxZyKtSyofs8m3wLEzw@mail.gmail.com>
 <CAAeHK+xA6NaC0d36OtAhMgbA=sCvKHa1bN-a4zQZkzLh+EMGDQ@mail.gmail.com>
 <CA+dZkakGP0O_H2x0z+z_xojtDHR59jKqb1M97KvO7yjzxsC5+g@mail.gmail.com>
 <87lfl2tk2p.fsf@dja-thinkpad.axtens.net> <CA+dZkamULgVfngAu7rW3rPEeQxXXURy3r49UaTaPL+ok+-aNcg@mail.gmail.com>
In-Reply-To: <CA+dZkamULgVfngAu7rW3rPEeQxXXURy3r49UaTaPL+ok+-aNcg@mail.gmail.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Wed, 10 Jun 2020 13:47:42 +0200
Message-ID: <CACRpkdYC_PeXKUhg9yAAh9JPTMPfff4e_57S6EcREnTHDvtjSg@mail.gmail.com>
Subject: Re: Need help in porting KASAN for 32 bit ARM on 5.4 kernel
To: Raju Sana <venkat.rajuece@gmail.com>
Cc: Daniel Axtens <dja@axtens.net>, vrsana@codeaurora.org, 
	Andrey Konovalov <andreyknvl@google.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Abbott Liu <liuwenliang@huawei.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=bLYH45Vm;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::22d as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
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

On Sun, Jun 7, 2020 at 9:09 PM Raju Sana <venkat.rajuece@gmail.com> wrote:

> Another observation while debugging  STACK  size is very high I see a a frame of
> around 2000 in  number (not sure if its due to recursive calls or  due to  disabled
> FRAME_WARN inside kernel when KASAN is enabled which I did.)

As Andrey K explains the stack usage is severely increased when using KASan.
This is why we increase the stack order depth in the patch:

+#ifdef CONFIG_KASAN
+#define THREAD_SIZE_ORDER      2
+#else
 #define THREAD_SIZE_ORDER      1
+#endif

I haven't had any problems with it, I think this accounts for the problem
of increased stack usage. I have run into OOM on very small memories
(64MB) but that is the worst that ever happened.

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdYC_PeXKUhg9yAAh9JPTMPfff4e_57S6EcREnTHDvtjSg%40mail.gmail.com.
