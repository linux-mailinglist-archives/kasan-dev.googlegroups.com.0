Return-Path: <kasan-dev+bncBCH67JWTV4DBBTXHZTXAKGQEFUQROVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id DABA9100FC1
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 01:14:06 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id k15sf17245902wrp.22
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Nov 2019 16:14:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574122446; cv=pass;
        d=google.com; s=arc-20160816;
        b=QKssotyPh/qJyBdmSUH8TCv707SUTohWa7nqVHaNY5/pDdssWlmhubWlmgZ3GY9NC9
         G/RFwrRDgWFrN+F1NMPQTKSVztYoGSSXiJU6WnFKqlZzL+SaHhHavCUYqRwYCECaQ4Bh
         rnmml5fDnEIHjuRse2qfbJzYr5BQNzEulheOWQ9ogwhxQbEceQJXELe8Skyh2njEE6vn
         5sUqeFH1IAIBG8TIlR7LDF57MUQxQS2uECXLVt27yuh75yuCXgGiyD42M4Y0YzYBYm+v
         E3duBDmGpzh9rB/HAKNHe+CzPftZSopNdlhNGMVaOsoUhimfW4XvfD8yprfjp0bi3osY
         55Zw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:openpgp:from
         :references:cc:to:subject:sender:dkim-signature:dkim-signature;
        bh=R0kKBjIwJlCSW6hsyEtzwN/2ouNp9NYefQwc1eEIK30=;
        b=aKNRM7thJOP7DGlBfEo/GX00H2ErHNfBJuQX4c3U7kdd46sTmp/w/7aO6EM/hMEkSE
         Cf4Fh54BKSGoMLeOBJWbzliNckz7tKHgUsptWYbRQs6KHgXXUwzm+imbNVWJPxOsB8Av
         SdYIApDSHZNSaR4x5XtAcwF18Z8nTp3xAXOWch4gb06JLj8zltNhxVaF5uTP0lTZIfIP
         VdnR1SkK+JM4gqWfFjsOQjcicJZUnIhWdaEhvOccvvZD0GomSfKnRbzj0Lnqju9sKd6g
         QYgh4g4042QpwkTSGct/r0InpPCUF9M2ROOksl1y8kBt17P2Iu/E36W4j1KVb72df51g
         nghA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=hrf+XtvF;
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::542 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:openpgp:autocrypt:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R0kKBjIwJlCSW6hsyEtzwN/2ouNp9NYefQwc1eEIK30=;
        b=YaSfpL2i+5i0aiAxPS3weqkuMNPNgdt6G4LzvubZgGz5HgiqtW9qUxeGnJvn8rXqRS
         SFLWXiHyAL3hKc6JlHOx2ZABJJlz2SAG8+b0tozhTlZYRUgpcDo/O25hm3wdWJmA8dEC
         k34YB9fuTckj9spAlyG7DbLc9xSztrnmwjhg6fREvPGCBZ1GNeTfE13IedGjYSgSXzvF
         vXdSeaCpoXPrvN2wcKtr+zc5Y1s46ar31hG9QohhtaQqSgG9kvuHW/gzlNQIv3zJB7dS
         3VfYznQ4gt3AzPMT0vEiAk6jy0jRsdHZR6XKBxf8t/tP2K3EvbVwkg8uyugPJK1HUkTX
         jg1Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=subject:to:cc:references:from:openpgp:autocrypt:message-id:date
         :user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R0kKBjIwJlCSW6hsyEtzwN/2ouNp9NYefQwc1eEIK30=;
        b=XoA0jgvhqYP5fhI+9il29rHQX/8xDzg9GMOiCdBJSDZdKFE/xIqBTooG5NT4l8kFQJ
         OvZRIYyJ4qdBb5RbdG7PhWn4kt0MY60/A29Lc6KQHNuuqxB4pqMvndWiZIKmmxR9y71O
         yj86LiFIxq9rwLiFN1Ewba69ha7fAFlK81SRWXINuHEr1EXsgRwLp3FxET5E0QY6lKVQ
         OYqvEstcnLxUAnjvFAyy6qq02Ny3j5viU6VtsZWTkjz8Tqrb1sDJ747mRDd1wMokjI7D
         Y5V1IFfOaaiugT88VS9nwZVp3ljF7bJtdOaTW2Lbwwn+FIXOOU22nm/8Q1V75tM8apL4
         h6/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:openpgp
         :autocrypt:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R0kKBjIwJlCSW6hsyEtzwN/2ouNp9NYefQwc1eEIK30=;
        b=dC8biVIzymHnJstqaXw4UZneq1DwdVc+CPHpQs42usIw5+cWgLyBz+kQlIwNU10fTX
         L9Dt8lW7uMgqhbEUp0TATXhVnqQCzjTegmwuSuei58oEjb0BCogAjP7maGYJ0T+JDFKw
         nduz7uHVbKbLNyVm744sKCL7YXBqEDxEWV1CtQBUI4MUwdWrbWNu1HFhIiCS7sqG/MD0
         W564ejGVaaGVOgmNoMxMlfEZr73wUhKiIMdqMobfggWP8YP1fo9BhUONCFXGQdJ4DSQB
         +OeB2tHKPbp1RKL0G7bLotnfagyRj8jeo0UGVlxyst5kcAqZqs+GOiZ2oC/RGyPppkiB
         tJUw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX9qD5yM2IfAnj8ybg8d0pKuxqGLDBqo1z/r3l7Kn8tWqLKFZdb
	TJD3a0v9amtn060ZQ4Lq6cg=
X-Google-Smtp-Source: APXvYqw5Z3bwYY9LC7AzBWgN/e00aOL2Eg5tCYllFnwcAkM2HS4cJbudmXfShgVfQbI6LDj41VLdwA==
X-Received: by 2002:a5d:574d:: with SMTP id q13mr36424876wrw.263.1574122446437;
        Mon, 18 Nov 2019 16:14:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:387:: with SMTP id 129ls4369542wmd.3.canary-gmail; Mon,
 18 Nov 2019 16:14:05 -0800 (PST)
X-Received: by 2002:a7b:c24b:: with SMTP id b11mr2304206wmj.125.1574122445695;
        Mon, 18 Nov 2019 16:14:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574122445; cv=none;
        d=google.com; s=arc-20160816;
        b=ILQ9sTqyQ+okBYFck6UCU6+dOjyekJv33ZR+bqHJBvAHUKuBfxT+14ieOelHyLBLZv
         SUM249sizSDjkU3fz0vJg++ARbgyqfiOmbgy/pExBsQ//sKgelgh3B0QEdLZZNP2deOq
         l4tQNKd923d1fk/t2OTNodsZgMqw9QOmCIH0rsS420p6jiUmv96yDejqCe9idOTz7i1Y
         NyGkuAGi8gnoSsDzXyEFzEPrzL67YfmyLHACnbleoAysC0+eiq7+f2vmkkXYz0UgN3E4
         Z7skZGbdusHWhx7fV/pzxaVnSWpGZZx4J5JpwCgqL/dLa8Brp5HItea7ZAO6j829if1S
         uDCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:openpgp:from:references:cc:to
         :subject:dkim-signature;
        bh=KvzBw5GEm6IKy7UcTEcP5CcHIg0pP5+1eixVP7EiPts=;
        b=HK0Oo7sItC0+PQmuy4TiVkeEWGQEPLo4GFdWDzadaX2F9sshEzhyyLR0JW0mgMSIBl
         uzvCZ/clr3wI8L2LQPP2zBSUiMYGVUdTBsf0Q2HvV3fWkZIFfz75ZGXrUjaJDbqn/RVe
         /y4gDO1qx3E6BugCBC4ohpX+2JU3SOP16pyPosUPs00FeANXs8rlg8t3uynynpVg/Ogy
         YTFEVJcSoG8ZAFmHX85logoWwIrhtnwUIF6+sb/DTNua13axmYPSH9JiJs/zSdx+P2gZ
         qrk+0bIauJC7JgWdy5Ls5+kxHJJu7tNPsPTbE2wX7r8W3IFyxhDnM0a4VxljKksOqeqj
         W4Zw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=hrf+XtvF;
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::542 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x542.google.com (mail-ed1-x542.google.com. [2a00:1450:4864:20::542])
        by gmr-mx.google.com with ESMTPS id r11si1127912wrl.3.2019.11.18.16.14.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 18 Nov 2019 16:14:05 -0800 (PST)
Received-SPF: pass (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::542 as permitted sender) client-ip=2a00:1450:4864:20::542;
Received: by mail-ed1-x542.google.com with SMTP id b5so15453158eds.12
        for <kasan-dev@googlegroups.com>; Mon, 18 Nov 2019 16:14:05 -0800 (PST)
X-Received: by 2002:a17:906:5c06:: with SMTP id e6mr27480410ejq.195.1574122445324;
        Mon, 18 Nov 2019 16:14:05 -0800 (PST)
Received: from [10.67.50.53] ([192.19.223.252])
        by smtp.googlemail.com with ESMTPSA id r9sm1113964edw.11.2019.11.18.16.13.57
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 18 Nov 2019 16:14:04 -0800 (PST)
Subject: Re: [PATCH v6 0/6] KASan for arm
To: Marco Felsch <m.felsch@pengutronix.de>,
 Florian Fainelli <f.fainelli@gmail.com>
Cc: mark.rutland@arm.com, alexandre.belloni@bootlin.com, mhocko@suse.com,
 julien.thierry@arm.com, catalin.marinas@arm.com, christoffer.dall@arm.com,
 dhowells@redhat.com, yamada.masahiro@socionext.com, ryabinin.a.a@gmail.com,
 glider@google.com, kvmarm@lists.cs.columbia.edu, corbet@lwn.net,
 liuwenliang@huawei.com, daniel.lezcano@linaro.org, linux@armlinux.org.uk,
 kasan-dev@googlegroups.com, geert@linux-m68k.org, dvyukov@google.com,
 bcm-kernel-feedback-list@broadcom.com, drjones@redhat.com,
 vladimir.murzin@arm.com, keescook@chromium.org, arnd@arndb.de,
 marc.zyngier@arm.com, andre.przywara@arm.com, pombredanne@nexb.com,
 jinb.park7@gmail.com, tglx@linutronix.de, kernel@pengutronix.de,
 linux-arm-kernel@lists.infradead.org, nico@fluxnic.net,
 gregkh@linuxfoundation.org, ard.biesheuvel@linaro.org,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, rob@landley.net,
 philip@cog.systems, akpm@linux-foundation.org, thgarnie@google.com,
 kirill.shutemov@linux.intel.com
References: <20190617221134.9930-1-f.fainelli@gmail.com>
 <20191114181243.q37rxoo3seds6oxy@pengutronix.de>
 <7322163f-e08e-a6b7-b143-e9d59917ee5b@gmail.com>
 <20191115070842.2x7psp243nfo76co@pengutronix.de>
 <20191115114416.ba6lmwb7q4gmepzc@pengutronix.de>
From: Florian Fainelli <f.fainelli@gmail.com>
Openpgp: preference=signencrypt
Autocrypt: addr=f.fainelli@gmail.com; prefer-encrypt=mutual; keydata=
 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
 M5kY0ACeNhCZJvZ5g4C2Lc9fcTHu8jxmEkI=
Message-ID: <60bda4a9-f4f8-3641-2612-17fab3173b29@gmail.com>
Date: Mon, 18 Nov 2019 16:13:55 -0800
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.9.0
MIME-Version: 1.0
In-Reply-To: <20191115114416.ba6lmwb7q4gmepzc@pengutronix.de>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: f.fainelli@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=hrf+XtvF;       spf=pass
 (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::542
 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On 11/15/19 3:44 AM, Marco Felsch wrote:
> 
> With your v7 it is working on my imx6 but unfortunately I can't run my
> gstreamer testcase. My CPU load goes to 100% after starting gstreamer
> and nothing happens.. But the test_kasan module works =) So I decided to
> check a imx6quadplus but this target did not boot.. I used another
> toolchain for the imx6quadplus gcc-9 instead of gcc-8. So it seems that
> something went wrong during compilation. Because you didn't changed
> something within the logic.
> 
> I wonder why we must not define the CONFIG_KASAN_SHADOW_OFFSET for arm.

That is was oversight. I have pushed updates to the branch here:

https://github.com/ffainelli/linux/pull/new/kasan-v7

which defines CONFIG_KASAN_SHADOW_OFFSET from the PAGE_OFFSET value
directly, and recalculate KASAN_SHADOW_START/END accordingly using the
same formula as ARM64.

can you try them out? If that still does not work, can you detail the
imx6qdp memory layout a little more? Any chance of running a kernel with
DEBUG_LL/EARLYPRINTK turned on so we can see where the problem could be?
-- 
Florian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/60bda4a9-f4f8-3641-2612-17fab3173b29%40gmail.com.
