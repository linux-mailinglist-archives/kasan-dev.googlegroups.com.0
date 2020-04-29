Return-Path: <kasan-dev+bncBDQ27FVWWUFRB4GNUX2QKGQE3MATZPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 370A31BDAC9
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Apr 2020 13:37:22 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id d4sf2247472qva.16
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Apr 2020 04:37:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588160241; cv=pass;
        d=google.com; s=arc-20160816;
        b=ihj9idHrf73elQKZjNjOBrHUt9qKOK2tzl+NpzhJu/3YqItqTIFBfwhNxMPML4123i
         VpGLFmAXjV491ccgyafcF5MFRx/F2sAdhZbqdauV3cBW7qT6uu1uWqZ+OpBUpvO7+L9o
         2IsDWLwRZLTgnBfzGpLN2Y69WZHF6GGmwo1oUFAKkJRJjTxUG87fxHsmLUei/kQs2ZhL
         RmYLmr4PKRTqmjiy42MUIXTEE0pY83Jbs6dP5D7xWySZWOdOm1ip8s4Yj48V0StqpciS
         kjJCGR9zI0oBpa9X8g9USsdfTl2DcqFxfInh8nv5su9+AXqUvWqXlFbrA+vl14xH57fw
         JRug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=M0Rfkmw0jrSAp/J0nDD5plcR4U/hn9anup1RoXVDgZI=;
        b=xRRgWFXwNcH7g7R9v4h5ZVKoFphrOeGpPOJUTHpBIngZ1cMF30beSAvdzfQtukubo3
         9gQ+s8b20bevY28pd/DXX5CHUHBVeuS9uiCeh8u3h4bAwo7s1I9n3a3m1kfMbehMXaIp
         mA9lZFpR6A64lTTC2e/MPKl7D7WGlFCSY1+IVmTAYnNl8kcRgmAURUNpHNtRSYNsLPDY
         atpxopFgH3Z0RNYdyuEDDnR0+vR6w3ii6BSG4Mcq0UGxHBneVqlP/E7FXgLlSOYiKPYr
         PIfhMMMzmoaB9Wd097ixaDtjakZki/pmFwu6EwLH/wrqkUWSEncwKJvq7QmWl1RaEwdy
         Hpgw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=HNsIW1kl;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=M0Rfkmw0jrSAp/J0nDD5plcR4U/hn9anup1RoXVDgZI=;
        b=jee81PJVedFAD5sgIdMBIXR56B4BirU0PA/FXG5KlG4tsJz0iqChDsSXUlP5ertgmu
         FgGe1BQ4l5MWi1ruRo7CpWUNDnEJS4y/4hpmdcczLprufNE0AszBAiVKE/1fHY4W6Sgc
         Bippt+0OCPhLmgNYgHE3CKk7JWIhl3DlG3VRxj23RJgyIaJFVr7yZA3UBS2Li5s3nZNt
         PFUdqSoeI1ZvbWXv3SmbaIAutTZsV71xmQrr9WLhIHv9Miee3CTElD3HWUjHS3pe7L9p
         r6vlNtqiWeyE0E9CJwogE5PGQFpaKTHrGBcyoAPuI9gCrUk+zMLsDbdFv18UVnfno5EY
         k1kA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=M0Rfkmw0jrSAp/J0nDD5plcR4U/hn9anup1RoXVDgZI=;
        b=JcUZ8ztkk6DIBMTd76E7hvksy9WTXZkmbTCzG7yL5O/5TnNLTXcvCBQqAmjaTYqL6N
         JEjuymEQsFAhTBeyVvg3zgF7wvh1CqRmCnWHgrwHTzKb6wjg7nR3+Zfz4kz2OCRb8tnV
         lj24DKTXKnqcCoPlE05If97+Tp9nupuAP4SJukqRhTY1sw5UNiP25Hggw7rhMQf0REpk
         1EByL804R1wGnTvA0g3c8xmxX7lIJBIYeBWGxBuuStSaWbLCsdNUkp1VvL7lbBIYHgby
         pFejazsTQgzr91MxF6CxnDeiovwD9IrMGKpivHbUk6U6zA4LgEeyiRyTXdzpu2bVuT5b
         XtZg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0Puawt4CyK2dXCbDfTUPzDbFBNgxEEh0mTtSwA97lUGlrLpIcFBmf
	AYP9AYWm7lo0SWms3vytd6Y=
X-Google-Smtp-Source: APiQypJCST/QqRmDbyzSefOU+paV85bm8GkLeGoXBVd5MCpKzK9Msk7KTIL2iOHY6B391PUtzvtaSg==
X-Received: by 2002:aed:2558:: with SMTP id w24mr34808678qtc.29.1588160240957;
        Wed, 29 Apr 2020 04:37:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:2e8:: with SMTP id a8ls14894103qko.3.gmail; Wed, 29
 Apr 2020 04:37:20 -0700 (PDT)
X-Received: by 2002:a37:9a43:: with SMTP id c64mr24115514qke.466.1588160240623;
        Wed, 29 Apr 2020 04:37:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588160240; cv=none;
        d=google.com; s=arc-20160816;
        b=A8h7ll7tsOsCTRAR0v0ZWDzHf7wmILZ4x3UWLxfQhvbmZUm5CMUmNQpGqM/7KbmpFa
         s5dXbZX0uEx97dAhXCfJ+1Zp3YvCPktjcKa/5h3cJf076O0kBo7qhQ6Z/g4h0Zvlc4Dr
         B24xyfn66pAJRIe1NHxHSPn7EGBhVSD4iRH/Fori7LgHI6sRH7hFvflFIunGDdb6qyCL
         /a6PM0kXBYJJvHXwZH08WjVJYFmPTHKDjo/Zk3Q2jp0XgDTiJTqu0P+jbe1Qh5WS2pKc
         Tfcyhfhg6skXqtHyYj+gUwoFriG13DdVbjeJ5HJkweF07uLQnv9c+1gcA+2JwFk0Irw6
         uocw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=EfTYCtmxBJqTUoGYDRmYu/ZuGf0n4eZeFXlQQGMb68Q=;
        b=GTbM2d7x/+CwTZJ6oM4SOv06G3Ql7GzL+/qZjgCxZ12AnxiZUlY5YyxdsF02SD21FK
         KNLW5YhdGKKY9QvAsuMmTMT6F7RTUE4NCUVyuCHhkWrwJTxuwHWnC6OfODBPGU4BLxqZ
         qyget7qHnRUgJVEfzc7wurTsjWyrGgvPG5ji5r8Jc+dExRueIfr+kKJeR4xDlCER3A+y
         PV6ZQOYowyAzZ9JAAkNqNmVvd/KNcZuirwONRsAZVITVlNpnn52JILoI2j6yXYQKsQAr
         4K1QCtTbpTlDCVjnqAWiTFZ1Tw1fEpNj9HKoZrz647TiIny/gdoj0AFjRFNI7zfzPvPA
         5pKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=HNsIW1kl;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id j11si492365qkl.6.2020.04.29.04.37.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 29 Apr 2020 04:37:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id 145so941767pfw.13
        for <kasan-dev@googlegroups.com>; Wed, 29 Apr 2020 04:37:20 -0700 (PDT)
X-Received: by 2002:a62:75d1:: with SMTP id q200mr33635426pfc.238.1588160239605;
        Wed, 29 Apr 2020 04:37:19 -0700 (PDT)
Received: from localhost (2001-44b8-1113-6700-6017-7a81-3587-7e42.static.ipv6.internode.on.net. [2001:44b8:1113:6700:6017:7a81:3587:7e42])
        by smtp.gmail.com with ESMTPSA id n69sm4599277pjc.8.2020.04.29.04.37.17
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Apr 2020 04:37:18 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Zheng Bin <zhengbin13@huawei.com>, aryabinin@virtuozzo.com, glider@google.com, dvyukov@google.com, kasan-dev@googlegroups.com
Cc: zhengbin13@huawei.com
Subject: Re: [PATCH] lib/test_kasan.c: make symbol 'kasan_int_result','kasan_ptr_result' static
In-Reply-To: <20200429014710.45582-1-zhengbin13@huawei.com>
References: <20200429014710.45582-1-zhengbin13@huawei.com>
Date: Wed, 29 Apr 2020 21:37:14 +1000
Message-ID: <87wo5ysetx.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=HNsIW1kl;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Hi Zheng,

Thanks for picking up on this.

> lib/test_kasan.c:31:5: warning: symbol 'kasan_int_result' was not declared. Should it be static?
> lib/test_kasan.c:32:6: warning: symbol 'kasan_ptr_result' was not declared. Should it be static?

I didn't mark these as static because:

/*
 * We assign some test results to these globals to make sure the tests
 * are not eliminated as dead code.
 */

I'm a bit worried that if the variables are marked static, then the
compiler knows that nothing outside the file uses these variables. Then,
because nothing in the file reads the value of these variables, that the
compiler might be able to eliminate the writes to the variables.

See https://lore.kernel.org/linux-mm/20200424145521.8203-1-dja@axtens.net/
for the detailed explanation, it's fairly intricate.

Are you able to check that your change doesn't lead to the elimination
of anything assigned to kasan_int_result/kasan_ptr_result? Maybe you
could use the 'used' attribute as well as static to prevent the
variables being eliminated?

Regards,
Daniel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87wo5ysetx.fsf%40dja-thinkpad.axtens.net.
