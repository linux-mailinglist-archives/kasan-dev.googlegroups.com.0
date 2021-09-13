Return-Path: <kasan-dev+bncBDQ2FCEAWYLRBNFE72EQMGQE2KK5TNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 85474409BA8
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Sep 2021 20:02:30 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id x20-20020a056830245400b005390988b0c9sf8089310otr.20
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Sep 2021 11:02:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631556149; cv=pass;
        d=google.com; s=arc-20160816;
        b=c0hRUFTFQOr9NbI8d9ivkiJHqgnT8SPGis/fHLdet+wTGnQdN44bxJi7jduXgmHADW
         wOdYfEEsHFwMZFz7UdncSuPVJ5W9u4YZUyhwHTSfsq/FlsFLmxy/uEjwLJxVQiKr4EPi
         hpdFu5Yh4z9hnMPsVM+B0Z1wxP4/Jz1ZlZcC69e4iwV72tKFCkpCgayNxKtTWfBIom8B
         gCxTbkp+qFzIyGUtoUqqm6sK8g/eNXoVqXCZ761qtfwedsUtg2ajIhsZwV0rSBmNaXD8
         Es2PzmgYhHT259oNn9HhnkQcgYrib71HcqwwP3RrHi1v7gomgAF3A/+8NgQ5x03p5nb4
         L1BQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=3pi2bD+iI2nKIJOqxhz0kFFMp5ks0Bmv+ks2e2A1HSQ=;
        b=XhUIkLCFTM0PoRw4b35v02SPMBAA7G4NLa0I7zPq3l3G59rM/f+/erRxOLlqDOYRCG
         DgokQnA34p4T6oItANMYEtlQRJPDp3pqrD/j4MtsqCqUsXZdTBCa5dwbvMV3mZQ4CbTz
         OQUoFhgNvk0AvgzJrI4zdkLryIm2BlUvcnrG5x0hA63GtSXDxT5gCk5p0e8UpyncA+SN
         XYZowsOqd7EuYj5OgYkyEmgyoIsTV1L+F+wNW4GQc+TF6g2X4KRZEaefwYDBPXjGMoXo
         IOvspIc0imCU233SsfE1k4E+z/uimFKrhHEzmYTvqMoDriwqBISew/DHIrvuo9TF90Xy
         IP5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=DK2QdqG7;
       spf=pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=htejun@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3pi2bD+iI2nKIJOqxhz0kFFMp5ks0Bmv+ks2e2A1HSQ=;
        b=YgvH25UaseBwZkWM1j/fr7yTONRZZ0S2ymwyj47/N+5vUkuQnJ6ymaN/x6CAs5H57o
         lEldraEgROjRM5BfgRpCRDvSMYxiS/bjdTs3F/Dxs2Lz97qlxxWKOKhxuP4yER6W5CTd
         FRTc0PJSnUylt9ewsQxjpd26c9QhbEERMuOq2liJRQh3acKM7NBQ9WILz0+HHjUDNG1A
         ysbGXj/48z5TGKHYd7VjwXtfo8h2rj4wgM9kMkizYJ/lt8gevaeE/lJ3Um8Xyd5UlYis
         FI7Hw9TcVCzRqEzxCpOWBM5PXcasv9o/s5eS2Sfl0uloHmf4AqgoUB46le/S1Kfxpsxy
         REww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:sender:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3pi2bD+iI2nKIJOqxhz0kFFMp5ks0Bmv+ks2e2A1HSQ=;
        b=pzcE3nWdeSoM2R9aSqYsvbYCMcAb490wHX+SqnNMwZGbjHbwjqX6NjVAgSkz+NH34G
         KE1Z+wxldlEpbBi1F6n0hAKSvpoP9K/1XdyRYV4UUZKzOxJyB4MiiiSxxSaavcBF8AuC
         358KD4zPckatBh97L6TrT07ea88hqlhzsF141a1f3dzTBxlYuOKjrZTg02oaOWAHEwC5
         uj2kEqEdDsqM8VwLfVc2YOOHg0A1ki4yG3+Nj3sbQF/D0QTJdqVOO8VikBwndsNprwci
         9dd7utAry+jdQeBbD/98pkXsH3AwqwYY57WE/wFEvSUVsOv1TRfvpUrrE4RnD7ZnvbFs
         tW/g==
X-Gm-Message-State: AOAM532oIohmCyckqFe+LMVyud0u+jwRhbfT6B7z3Lm/bp71vd94ssbX
	a+HAqZWqR+06qHslCPGKmrI=
X-Google-Smtp-Source: ABdhPJyHDK3u5gqJoOsUphm/YJ2tQImUN86K1k+WgpQr/xdLBcUc9jAyJWarwo9eSgjp8hF9mepEKw==
X-Received: by 2002:a4a:d108:: with SMTP id k8mr10359811oor.90.1631556148432;
        Mon, 13 Sep 2021 11:02:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:66c4:: with SMTP id t4ls2133630otm.5.gmail; Mon, 13 Sep
 2021 11:02:28 -0700 (PDT)
X-Received: by 2002:a9d:7e88:: with SMTP id m8mr11283997otp.81.1631556148066;
        Mon, 13 Sep 2021 11:02:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631556148; cv=none;
        d=google.com; s=arc-20160816;
        b=Jmfl9Me18xFZn3kA4HMcK2degHRzf65PPFQwBPpajFQ3ZudYFv+KCAJl8fyYW5QOOm
         XL6NFiHiNn1kfpvgLG8aGLVinPdVIlWX5HmFqZ3HGjw46Qg0UtXRKJE9/vppq1bL0bNz
         Gl9o8rSo+C1uiy9e3WanLrKfAM4Mh6xboxpNb2EoPC1u9d+DjxKYX+j1JovV3kg3/4Mz
         ZFH4R4jl8BZB44U4SGNFMxkDM/6HLfF62PKwqOScK/vkH1Pu9wgJmP+jsh+5qhth7ixx
         qt6TLQPiLFIT270pTKH3KGFj2m4VGv+hok76g8vLlIQgRUU5SOwGgCeXH4t7lt0DDQQ0
         LP+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=cYi40BkhVJV1s9UwCAK3qxpR0NPFRGQvgiD+V+l72EI=;
        b=GMnT2ZixkXtsxbmkg3kkzsis1+LgQiwZ/z93a0XNRglLKWxgyauja6pm68YvCWiafH
         H2fCDVhOumSgJrvOK5AjJ4lDLsz+UqQIW9fzpyMB4c5CpDsP+j1VWIsysa6nqpRk2QUr
         vAGuLRXqaIwBjUEy3kHek3YXcpRpL4sb2uls9beEUEI8qDHpR9Zgybl+wPtMpC8VJV9F
         i36qUmX4ol7BhCuTPqQTBBEQT9+3NsndMl35CIroa8tnzjgQbAYtRvVQ5Ol4xsa582QE
         7MGVwz8RZ7WGtsuDGEhHZWlehn0iHHx/n1BryUCNrKjJhFkmA6d1wznMMiamlPHg0ibd
         Riwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=DK2QdqG7;
       spf=pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=htejun@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-pg1-x536.google.com (mail-pg1-x536.google.com. [2607:f8b0:4864:20::536])
        by gmr-mx.google.com with ESMTPS id bf14si635522oib.0.2021.09.13.11.02.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Sep 2021 11:02:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::536 as permitted sender) client-ip=2607:f8b0:4864:20::536;
Received: by mail-pg1-x536.google.com with SMTP id w8so10176874pgf.5
        for <kasan-dev@googlegroups.com>; Mon, 13 Sep 2021 11:02:28 -0700 (PDT)
X-Received: by 2002:a63:1259:: with SMTP id 25mr12268930pgs.48.1631556147639;
        Mon, 13 Sep 2021 11:02:27 -0700 (PDT)
Received: from localhost (2603-800c-1a02-1bae-e24f-43ff-fee6-449f.res6.spectrum.com. [2603:800c:1a02:1bae:e24f:43ff:fee6:449f])
        by smtp.gmail.com with ESMTPSA id r2sm9321578pgn.8.2021.09.13.11.02.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Sep 2021 11:02:26 -0700 (PDT)
Sender: Tejun Heo <htejun@gmail.com>
Date: Mon, 13 Sep 2021 08:02:24 -1000
From: Tejun Heo <tj@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Shuah Khan <skhan@linuxfoundation.org>,
	Lai Jiangshan <jiangshanlai@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Walter Wu <walter-zh.wu@mediatek.com>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	Thomas Gleixner <tglx@linutronix.de>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vijayanand Jitta <vjitta@codeaurora.org>,
	Vinayak Menon <vinmenon@codeaurora.org>,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, Aleksandr Nogikh <nogikh@google.com>,
	Taras Madan <tarasmadan@google.com>
Subject: Re: [PATCH v2 6/6] workqueue, kasan: avoid alloc_pages() when
 recording stack
Message-ID: <YT+SMKI1SW3FOACn@slm.duckdns.org>
References: <20210913112609.2651084-1-elver@google.com>
 <20210913112609.2651084-7-elver@google.com>
 <YT+EStsWldSp76HX@slm.duckdns.org>
 <CANpmjNPA9qW8i=gHvrdMRag0kOrOJR-zCZe6tpucOB4XN8dfWQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNPA9qW8i=gHvrdMRag0kOrOJR-zCZe6tpucOB4XN8dfWQ@mail.gmail.com>
X-Original-Sender: tj@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=DK2QdqG7;       spf=pass
 (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::536 as
 permitted sender) smtp.mailfrom=htejun@gmail.com;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Mon, Sep 13, 2021 at 07:58:39PM +0200, Marco Elver wrote:
> > Please feel free to route with the rest of series or if you want me to take
> > these through the wq tree, please let me know.
> 
> Usually KASAN & stackdepot patches go via the -mm tree. I hope the
> 1-line change to workqueue won't conflict with other changes pending
> in the wq tree. Unless you or Andrew tells us otherwise, I assume
> these will at some point appear in -mm.

That part is really unlikely to cause conflicts and -mm sits on top of all
other trees anyway, so it should be completely fine.

Thanks.

-- 
tejun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YT%2BSMKI1SW3FOACn%40slm.duckdns.org.
