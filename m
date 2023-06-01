Return-Path: <kasan-dev+bncBDEKVJM7XAHRBC5V4ORQMGQE7A7WINQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 6AA0A71F11A
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Jun 2023 19:51:09 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-2af17f626e3sf10244771fa.0
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Jun 2023 10:51:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1685641868; cv=pass;
        d=google.com; s=arc-20160816;
        b=RtojZfodIQ+qAKd+FBxKHnBHSJdFd9vjT7JUVYeUFwFNySV2MV/igKOubzkYR9pPQH
         fvSE4yiTOmAcOFeaAHKik3gBZTsjr/OFE8EzTb3rCw3C7/06q5qGWGIg0ma6zsEe2xCe
         NqZQngyWx6Cw5QRN9NoNbRgsM5lX8Ms2kEhBm1MDAF93fDbdSED6XR8mJII7FaqwhV5A
         lleeoQkfWHEm654RveYAM001Sh7PHMKgSoDfqZ06R3UHPIVEpw4CrwOjwi3ZpU0IbnDL
         qD/R+RcbNeZCMc8aSGDyuU3zFXA8gSTfQPoY4fCXr7nRAcQLRBiyWyq9E7rQpU6ggCzi
         gjdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:cc:to:from:date:references
         :in-reply-to:message-id:mime-version:user-agent:feedback-id:sender
         :dkim-signature;
        bh=tgP7rouXeqsYdZQQdsqcAeCKL3pzcAZIEkAPvk5JfvE=;
        b=lze7zMjBXM1MUihvjB9bmd7DjhzRSF778ezelNPZnKWsLnXfvku7XrswoQfYHDNg4L
         sjGME8It4wRPyitoOBFcMahjDrRO3aI/B3adsCZB+4PJVr3F2XwFEIXUnzdgthQBHqa1
         Q4zGFdHSXa1yla9s6XUXnihzUvuUizNQWxly2DpEXvc0f43aMmwElHdInzqtFrY9l3u9
         juWluki+vRruVKpW52hRMAuDr7fGcffevxB2rK+7rPyw0HY1pHrinxJOdRAhIuVniSrN
         /DH1YQNOYS7uhMamcMGqo7Prol5enbwmnRLmMvfVsViOYtgMpzQmgJxTapm/gchOQyO0
         7Sng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@arndb.de header.s=fm3 header.b=YsbtSfmN;
       dkim=pass header.i=@messagingengine.com header.s=fm1 header.b=x278PMWM;
       spf=pass (google.com: domain of arnd@arndb.de designates 64.147.123.21 as permitted sender) smtp.mailfrom=arnd@arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1685641868; x=1688233868;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:subject:cc:to:from:date:references:in-reply-to
         :message-id:mime-version:user-agent:feedback-id:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tgP7rouXeqsYdZQQdsqcAeCKL3pzcAZIEkAPvk5JfvE=;
        b=GYKSuQVs2PJyG4PrnneCsOIhFXzv8eJaHJrshwOp+lg9JJF+jU3AlXRHF6SXBJElxF
         hV4J5tOV2DtSAmLBkLeRNNV1F0AkRzDXa5nP+hSHXD7HCTa5F6fNi43+7xlkkdPNOBuC
         90yC3B5N/nNbDtNzcI+MU7jpNfOGbFCGdbTXkB85ZiYCo57fQxqrNLCZjntArh/bzA/F
         q5UPyUvKaB84UsJwUKy+RQ6X45k7gAiiyPZ9wXg1tlKR4O+Skw9cCCdGImvQDmL4aul/
         IA3aYRBxedXgCjJunwkPKpaZe1SkMmnM5FJNIiVWvywmJX5eUQZ6sQeXXvo7oLjkucjp
         fyLw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1685641868; x=1688233868;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:subject:cc:to
         :from:date:references:in-reply-to:message-id:mime-version:user-agent
         :feedback-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tgP7rouXeqsYdZQQdsqcAeCKL3pzcAZIEkAPvk5JfvE=;
        b=HHM52FB3tEDbid6B7H/vFTMLwDKPSuhNZbUsd2wq6CcOXlTgRhlS9bQjBo1pzHPcgQ
         7FVwP01sO5v8ld+KrkbJggxcHlAwYTYYEI+n04VC0ZV+1i36FY/A+lliUqMxunVx9SXw
         vlFdmL5hVgiJ/obJKPoXA1WHXIjhuHGHMxL9eHDqwnrbb2zpa+eL5VhiM6aKetnXyAah
         SE0ZQjwA8tk2O1pf0Z6sIoUsN6gCBcRIeB8zDEAh4PoWY4RY32jZi2AE7c/vOPrO6pCD
         UytBTSjEgRjauPHmDrAfKlEF6bUOUBPZZTZuLk2IWEbHnlKnpWUlG8J/Q3aYAocc8HAT
         8fDQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDxls9122LVzcaGuS3jLpue9aqrDyyzoIsfCVLklvPqd9PbiP3AN
	Nkf8tGJVE5/GAsb1twCRYhE=
X-Google-Smtp-Source: ACHHUZ5qG366NBhjy9TvrwHDxhKJVPR7sULOlv76yI4gqITj7e+M+7SVyWSZ2ClicUC7dt6NmsgCHg==
X-Received: by 2002:a2e:330f:0:b0:2a8:adf6:b0e2 with SMTP id d15-20020a2e330f000000b002a8adf6b0e2mr143636ljc.13.1685641867922;
        Thu, 01 Jun 2023 10:51:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a593:0:b0:2ad:a1ce:ff1b with SMTP id m19-20020a2ea593000000b002ada1ceff1bls317119ljp.0.-pod-prod-02-eu;
 Thu, 01 Jun 2023 10:51:06 -0700 (PDT)
X-Received: by 2002:ac2:442a:0:b0:4f6:db0:f162 with SMTP id w10-20020ac2442a000000b004f60db0f162mr121644lfl.63.1685641866503;
        Thu, 01 Jun 2023 10:51:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1685641866; cv=none;
        d=google.com; s=arc-20160816;
        b=e3M6qyQqJh0Xp3buSzzoDFS2kfMu8ZLUmFNozFnthJhs0Qn4rf3ptLUjp5rZKxfZDc
         EOBSaV4PMxSQ6Hajfgn/w+OakCogye53GdAQx3tHNlSHQfqEha+K02jrR+CoYsh0gfD8
         I4BVPFsU95/qWuXpHRdCvehw4wJe+4TGV59n4vKuODlr+JBnEhqJY2XyZKgURk42uoRh
         YbKOuKXc7nfqGCxLcNcZRVYT72M/BQTAMAnlrHtUtFN8nI/2YZLzNpd1wu09c7UFC1m/
         lC6pREHLghqDmM5+/pkRaM830D/JsvzcDAWMOHhnAl/GtIQbYTA3jRnhK6cm7b+5qdQ9
         Fuqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:cc:to:from:date:references:in-reply-to:message-id
         :mime-version:user-agent:feedback-id:dkim-signature:dkim-signature;
        bh=rIkHOu2cJZ+vhgMgLgXQFIzSc/FfETBAe+GmKBqE/d8=;
        b=HBSHszFdiQWNACZ391dgBJbamawBPGuNhgrdC0+KCYJ7qnHJSCTHmW+rK+nsVNccqE
         1Be61BKYCgDRqt9hb0OfYqQxpopEXXjZX/W6UQJBsr+OaDLbrPPe79J5MeHBlUQp5XYO
         ZvEtPc6OFMTLfePnT+GTk/dQ966PT8O+4vN69N/6MsXntS4VA8uVFMHzmskfz/H4edOv
         DsTO4116iFZdqlbAUtnV9UbhjTBG6n5V/TKrBA5QmH5/CcSeKBuHcISlA4HH7nKH4zNb
         JDkJfP8QMJn778dC1nWhuuJoyH4QRL+WgyGKQbofateD8sokQQWFZ/BB34bZPY2AVqOH
         +h5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@arndb.de header.s=fm3 header.b=YsbtSfmN;
       dkim=pass header.i=@messagingengine.com header.s=fm1 header.b=x278PMWM;
       spf=pass (google.com: domain of arnd@arndb.de designates 64.147.123.21 as permitted sender) smtp.mailfrom=arnd@arndb.de
Received: from wout5-smtp.messagingengine.com (wout5-smtp.messagingengine.com. [64.147.123.21])
        by gmr-mx.google.com with ESMTPS id c42-20020a05651223aa00b004f60948e9fasi149671lfv.3.2023.06.01.10.51.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Jun 2023 10:51:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@arndb.de designates 64.147.123.21 as permitted sender) client-ip=64.147.123.21;
Received: from compute6.internal (compute6.nyi.internal [10.202.2.47])
	by mailout.west.internal (Postfix) with ESMTP id 5FF8832006F5;
	Thu,  1 Jun 2023 13:51:02 -0400 (EDT)
Received: from imap51 ([10.202.2.101])
  by compute6.internal (MEProxy); Thu, 01 Jun 2023 13:51:04 -0400
X-ME-Sender: <xms:hNp4ZEB47iSnUPOggsaPyqB3htwwzNbBYiP2c2CDEU-GAelh2g8d0g>
    <xme:hNp4ZGjPiJzGYKEOKXF8ZVG6qJObsay-XWlXTArfI2edvCGmlHvO6H8hcnSw2yE8S
    M_zWTR4S9o1_3Selek>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgedvhedrfeeluddguddukecutefuodetggdotefrod
    ftvfcurfhrohhfihhlvgemucfhrghsthforghilhdpqfgfvfdpuffrtefokffrpgfnqfgh
    necuuegrihhlohhuthemuceftddtnecusecvtfgvtghiphhivghnthhsucdlqddutddtmd
    enucfjughrpefofgggkfgjfhffhffvvefutgesthdtredtreertdenucfhrhhomhepfdet
    rhhnugcuuegvrhhgmhgrnhhnfdcuoegrrhhnugesrghrnhgusgdruggvqeenucggtffrrg
    htthgvrhhnpeeigfeiieeiheejjeeiudekleevvddvffetieehteeikeeigeeiffdttdef
    tdeggfenucffohhmrghinhepghhnuhdrohhrghenucevlhhushhtvghrufhiiigvpedtne
    curfgrrhgrmhepmhgrihhlfhhrohhmpegrrhhnugesrghrnhgusgdruggv
X-ME-Proxy: <xmx:hNp4ZHkX2OtLDMVwiM9pUSRildLjmx7b470Z9Ca5GPuJafo5YZtD1A>
    <xmx:hNp4ZKwgiGYOpOdmKAbTAywxVof93l8RU1AQtJKMm8M8XxQ-KJalsw>
    <xmx:hNp4ZJQ1JHiPxb1I71yRvpM9eN-KRrOUQGwapN-tDspykREevQDiyg>
    <xmx:hdp4ZICyxJxKWz4v3ZWf754mlZqb1XGQlvWDQ_AdPqLkWWJ3D8psOg>
Feedback-ID: i56a14606:Fastmail
Received: by mailuser.nyi.internal (Postfix, from userid 501)
	id 38825B60086; Thu,  1 Jun 2023 13:51:00 -0400 (EDT)
X-Mailer: MessagingEngine.com Webmail Interface
User-Agent: Cyrus-JMAP/3.9.0-alpha0-447-ge2460e13b3-fm-20230525.001-ge2460e13
Mime-Version: 1.0
Message-Id: <f6fcae8a-9b50-48e4-84e9-c37613226c63@app.fastmail.com>
In-Reply-To: <202306010909.89C4BED@keescook>
References: <20230601151832.3632525-1-arnd@kernel.org>
 <202306010909.89C4BED@keescook>
Date: Thu, 01 Jun 2023 19:50:38 +0200
From: "Arnd Bergmann" <arnd@arndb.de>
To: "Kees Cook" <keescook@chromium.org>, "Arnd Bergmann" <arnd@kernel.org>
Cc: kasan-dev@googlegroups.com, "Andrey Ryabinin" <ryabinin.a.a@gmail.com>,
 "Alexander Potapenko" <glider@google.com>,
 "Andrey Konovalov" <andreyknvl@gmail.com>,
 "Dmitry Vyukov" <dvyukov@google.com>,
 "Vincenzo Frascino" <vincenzo.frascino@arm.com>,
 "Marco Elver" <elver@google.com>, linux-media@vger.kernel.org,
 linux-crypto@vger.kernel.org, "Herbert Xu" <herbert@gondor.apana.org.au>,
 "Ard Biesheuvel" <ardb@kernel.org>,
 "Mauro Carvalho Chehab" <mchehab@kernel.org>,
 "Dan Carpenter" <dan.carpenter@linaro.org>,
 "Matthias Brugger" <matthias.bgg@gmail.com>,
 "AngeloGioacchino Del Regno" <angelogioacchino.delregno@collabora.com>,
 "Nathan Chancellor" <nathan@kernel.org>,
 "Nick Desaulniers" <ndesaulniers@google.com>, "Tom Rix" <trix@redhat.com>,
 "Josh Poimboeuf" <jpoimboe@kernel.org>, linux-kernel@vger.kernel.org,
 linux-arm-kernel@lists.infradead.org, linux-mediatek@lists.infradead.org,
 llvm@lists.linux.dev
Subject: Re: [PATCH] [RFC] ubsan: disallow bounds checking with gcov on broken gcc
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arndb.de header.s=fm3 header.b=YsbtSfmN;       dkim=pass
 header.i=@messagingengine.com header.s=fm1 header.b=x278PMWM;       spf=pass
 (google.com: domain of arnd@arndb.de designates 64.147.123.21 as permitted
 sender) smtp.mailfrom=arnd@arndb.de
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

On Thu, Jun 1, 2023, at 18:14, Kees Cook wrote:
> On Thu, Jun 01, 2023 at 05:18:11PM +0200, Arnd Bergmann wrote:
>
> I think more production systems will have CONFIG_UBSAN_BOUNDS enabled
> (e.g. Ubuntu has had it enabled for more than a year now) than GCOV,
> so I'd prefer we maintain all*config coverage for the more commonly
> used config.

Fair enough, I can send that as v2, but let's see what the others
think first.

>>  config CC_HAS_UBSAN_BOUNDS_STRICT
>>  	def_bool $(cc-option,-fsanitize=bounds-strict)
>> +	# work around https://gcc.gnu.org/bugzilla/show_bug.cgi?id=110074
>> +	depends on GCC_VERSION > 140000 || !GCOV_PROFILE_ALL
>>  	help
>>  	  The -fsanitize=bounds-strict option is only available on GCC,
>>  	  but uses the more strict handling of arrays that includes knowledge
>
> Alternatively, how about falling back to -fsanitize=bounds instead, as
> that (which has less coverage) wasn't triggering the stack frame
> warnings?
>
> i.e. fall back through these:
> 	-fsanitize=array-bounds (Clang)
> 	-fsanitize=bounds-strict (!GCOV || bug fixed in GCC)
> 	-fsanitize=bounds

From what I can tell, -fsanitize=bounds has the same problem
as -fsanitize=bounds-strict, so that would not help.

     Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f6fcae8a-9b50-48e4-84e9-c37613226c63%40app.fastmail.com.
