Return-Path: <kasan-dev+bncBCAP7WGUVIKBBM4EWSVQMGQECIU5ONA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id D06ED802872
	for <lists+kasan-dev@lfdr.de>; Sun,  3 Dec 2023 23:33:25 +0100 (CET)
Received: by mail-oo1-xc38.google.com with SMTP id 006d021491bc7-58dc2d926e7sf5471109eaf.0
        for <lists+kasan-dev@lfdr.de>; Sun, 03 Dec 2023 14:33:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701642804; cv=pass;
        d=google.com; s=arc-20160816;
        b=NkdfpGxTCGIb766Fvw32XwjkQebar/xpEGSiy/LM97RVmHq+w2S4m5oGiw8Yx9medg
         c7WROyOezFT4c0G6g1BZQG6OGc2RYSrKoJmF3aNkMl8w1KwNVCTN4nhALn+Rl2vI2FcO
         xbM6wy2couPnwPPlTGmXe/KgqO+RGMz/fIYILlmFqRYNeRjPlw6xOs1Ei+Yw/XysyPTn
         eIPQbdqq7NliEqAK7Sd3gr8Tqquxk6RNw7pxdGcWiTinpkIKCEoRaDS+7woN4/Son0mg
         HsbETuXhBI+i1quVGKL2M4/bFM2g5xfyyn4NYCRIq/kq2CNdXUSE68WAteEsaJb/+ofL
         Pg4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:cc:references:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=eyIyeBU9v4vn92LMqvOmVqYcKboJi7UdHwyt0e+EW+Y=;
        fh=iONX4EgxVUl8AUsvjKDlswL102JSBisx8m4gcplemwk=;
        b=VXrQ3Og+WApui3aHhTodWeTUqbVA9g3v2IlAzVHC2wTWNxHYkvauFfHnjDV/Kt8v/x
         l1DJ9h7xGxRii0pMrIAmCDZrYYg6igXXf7ZzqdR9OJsGWAPU0V2ciUddpiXS7ucYT3F3
         JZPalfLvcDF7cgZq4Ysje0WUYkgJK10vE/gRbdggD1z2jYQ7FxJUks25G4NpcNzVM+n2
         ZCf83k5AlXXTzxYzvOlmZICQ4dIHVkIfVXZsUtUyhaKVYI7SZaMI8VRftsUE7SSP698e
         qwtvF52ocJFfj7SZjjKOvbEOcb/5o5J4xgOAvyYNsvst9+EzlMerWt3NyHYSYQvvPFw2
         4+tQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701642804; x=1702247604; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:cc:references:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=eyIyeBU9v4vn92LMqvOmVqYcKboJi7UdHwyt0e+EW+Y=;
        b=lDIJ65yLzC23kx6ulEiBpuVJhRfSsBrmi8XqqvzsVBk7WlGT2Y2B8Jrb3Lp3sRuBFH
         UoWDBT33It0X9KBknmmp6MzELnGeH9AxVSA+cfMt7Ti1RwkO1B21ylUg15N7OTnH2Jjt
         hfZM+AoWZxgbbggzQI/BEOgyNkWX3iQEwL0eA8XP50fZo14cqzD/FiG9PX4/FGUv2iho
         kY3vsVetpm6ZcaqdmgCJ/oqD/z7mkYHVsJZuysOmdT17F9MED1k+okkc+GXDQZqY8GS9
         vc0HaSagynK17+BQ9H85cVZW4WBhE9R5IP2q+ZEhrAd5PFujjG4+2ACO0xeCVPGUh3dl
         6zJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701642804; x=1702247604;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:cc:references:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=eyIyeBU9v4vn92LMqvOmVqYcKboJi7UdHwyt0e+EW+Y=;
        b=wueyAlBL30v0vYCeBUVeW/zCbHqxr1LMRC/2di5urhLAjmFTv3BQJVcYe1lpHLd1W8
         Yxsv4ifYOKQfTfMWeGP6znZE3L+eQ/Ym4U+iJw+jpgKgv5Y2HMWnRVsoimD7r3HkPJxQ
         1nuMBN3apz3FYojMdZWtfRpaCL4KSpntE2Ahg8SP7/QLvFVxI2BzTbKkW7Hck/LUl4Hk
         XAPH7uUVFFT+434Tt3TtpyVRn9E/Gvd0tIm+1JVU5UvsQ3mEe8ng7URvoOyVRblInH3p
         xu+l5XhPMow0KbhNwI8utoJg7UcG0ark3fvVY7IBCb1XHlZAnKj81Cf9vvmmIAwvcaEY
         dP/w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwqLwAI5jS0LkQRUe+gHk0I55vDGwGGMWg/RYtLw/UZYgt2kmxl
	DL4tQMEzeIfQQoGMwzaYD34=
X-Google-Smtp-Source: AGHT+IEzKVNPLjjjxMUUfdKJjUwVERegemSM4K4S+eY5bc2rSYqcl/dlj9XuHLoQqlilCgTwsgHS8Q==
X-Received: by 2002:a05:6820:2c98:b0:58e:1c48:1ede with SMTP id dx24-20020a0568202c9800b0058e1c481edemr1412702oob.16.1701642803848;
        Sun, 03 Dec 2023 14:33:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:a345:0:b0:58e:2e05:d95f with SMTP id u5-20020a4aa345000000b0058e2e05d95fls1330007ool.1.-pod-prod-02-us;
 Sun, 03 Dec 2023 14:33:23 -0800 (PST)
X-Received: by 2002:a9d:619a:0:b0:6d8:8067:daf9 with SMTP id g26-20020a9d619a000000b006d88067daf9mr758706otk.4.1701642803160;
        Sun, 03 Dec 2023 14:33:23 -0800 (PST)
Received: by 2002:a05:6808:2182:b0:3b2:e349:d5c2 with SMTP id 5614622812f47-3b8a8292eabmsb6e;
        Sun, 3 Dec 2023 05:17:38 -0800 (PST)
X-Received: by 2002:a05:6a00:1c88:b0:6ce:2732:277 with SMTP id y8-20020a056a001c8800b006ce27320277mr651624pfw.38.1701609457792;
        Sun, 03 Dec 2023 05:17:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701609457; cv=none;
        d=google.com; s=arc-20160816;
        b=EEo3Z6Lwo+qghpsjbEhNb9TatHRlI20eCvfnPqT79WqWFNTnfF1/rWYXmK3KZS7Foz
         x8e/GSWsjILSqZZxUUXvqWochqIuvI7BhpKT3xFeYLd9sHKGrIBH/2Te+g1Cbs1ENTQi
         jONtdmQEd0CFJIdtktd0YmsBWvMBoJngmRkLme3jAnfPJBI1BMV7pd9lqgqyZ0YSaIaj
         RfAKCx9LNBLqINV5mEdnGZunpiaGh0LNlqmT4J/2vWxquwHOraTsxht7J+w1L+EvWLGQ
         u8mTrsjcgFpRG3HgWsl4sFFSyWyKGdwkPDbyvqqb0M9p2tgTHCHmKmHtXsVca3TaOCr3
         fBxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:cc:references:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=IF9x/2vET7H34gWiQo4C9nkHVzCwSKcs+yfdih/G+44=;
        fh=iONX4EgxVUl8AUsvjKDlswL102JSBisx8m4gcplemwk=;
        b=mrLrRo/h/ViBAgEmnMdTHVADDN+W186q1GJ2me5ClnkZCvIhUQ9gICLQJlCuN9jwPi
         edIfznkMO7py4SsB5UphMX8KdkxlYFQmDK9S46Sg6SAw8obC2ZktjjELOwJ9W98OOGeB
         kHJTAK6Ob1TkY5w1iqR+H7dF0c1vdZpxzT3LW49lzDa7iRvInQw3RbtN/mrPvxNtc9tp
         LgXn3/ez/h8xx71KMsiAJwE7/0fp6MR+xzc/JR9z/wIMNiLKuNFRrru7IFRvTrpqiyIL
         8il3M7GIaUqZD+aRo9Z/3/AZSqnH4oy4S6muHkLXzbM4hrZcSJFJ+K6xExtGEv39VomP
         69wA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id hj20-20020a056a00871400b006ce43f6e146si52087pfb.5.2023.12.03.05.17.37
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 03 Dec 2023 05:17:37 -0800 (PST)
Received-SPF: none (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) client-ip=202.181.97.72;
Received: from fsav415.sakura.ne.jp (fsav415.sakura.ne.jp [133.242.250.114])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id 3B3DHTpg021425;
	Sun, 3 Dec 2023 22:17:29 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Received: from www262.sakura.ne.jp (202.181.97.72)
 by fsav415.sakura.ne.jp (F-Secure/fsigk_smtp/550/fsav415.sakura.ne.jp);
 Sun, 03 Dec 2023 22:17:29 +0900 (JST)
X-Virus-Status: clean(F-Secure/fsigk_smtp/550/fsav415.sakura.ne.jp)
Received: from [192.168.1.6] (M106072142033.v4.enabler.ne.jp [106.72.142.33])
	(authenticated bits=0)
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTPSA id 3B3DHTER021421
	(version=TLSv1.2 cipher=AES256-GCM-SHA384 bits=256 verify=NO);
	Sun, 3 Dec 2023 22:17:29 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Message-ID: <0c079048-79ef-4e50-8fe2-a9626e40b363@I-love.SAKURA.ne.jp>
Date: Sun, 3 Dec 2023 22:17:25 +0900
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [syzbot] [kernel?] possible deadlock in stack_depot_put
Content-Language: en-US
To: syzbot <syzbot+186b55175d8360728234@syzkaller.appspotmail.com>,
        Andrey Konovalov <andreyknvl@google.com>,
        syzkaller-bugs <syzkaller-bugs@googlegroups.com>
References: <000000000000784b1c060b0074a2@google.com>
Cc: "kasan-dev@googlegroups.com >> kasan-dev" <kasan-dev@googlegroups.com>
From: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
In-Reply-To: <000000000000784b1c060b0074a2@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: penguin-kernel@i-love.sakura.ne.jp
X-Original-Authentication-Results: gmr-mx.google.com;       spf=none
 (google.com: i-love.sakura.ne.jp does not designate permitted sender hosts) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

On 2023/11/26 6:07, syzbot wrote:
> refcount_t: underflow; use-after-free.

#syz set subsystems: kasan

By the way, shouldn't pool_rwlock section be guarded by printk_deferred_enter() ?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0c079048-79ef-4e50-8fe2-a9626e40b363%40I-love.SAKURA.ne.jp.
