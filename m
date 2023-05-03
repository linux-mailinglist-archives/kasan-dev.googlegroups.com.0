Return-Path: <kasan-dev+bncBCLL3W4IUEDRBV7NZCRAMGQEZW7R7FA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 57C616F5618
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 12:26:32 +0200 (CEST)
Received: by mail-ed1-x53d.google.com with SMTP id 4fb4d7f45d1cf-50bcaec14c2sf2353573a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 03:26:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683109592; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ej+ircwPn+579+8R20Z6OrZolPamJglJQrVadX6K2UJ4b+egrQMNjSB984BMzeh7+V
         AnGzbHnz5kc4zLM1EX86RDW6pnSVMqD/y91hxAFt59Px2cQmbwCjTO+fxNtlfFIDdhpL
         nv7CdXXYyv+KQV9jdBSkiCzW/7itMlgOh0du2Opzu4NotFMnAnCfIxGrRWqRNDxsleae
         PVxND+dUbrb1sOQRCaS6AQ0YOdwoug0i6DPzn8UVjQ7wxJlnaz5yquEb8raaLIVVjVAn
         KvNsyoQELFB3WSBTYoS2YJBF2EkxfXVFjAE/q/lWwhR7eZT+Mwy/IxagRZBDKl1eDIKw
         Ucug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:subject:cc:to:from
         :date:sender:dkim-signature;
        bh=ZYKv5EwRqEP3hoAB0rynLb574dLw7fd6/eWw5SXPJfQ=;
        b=y7FQbLk55oztMtp0ZxHX2ONZEbA0IG2RTTDWqzd5XCZlwr09v9gPVS8V1+ljN9G5Y/
         85vBXTsammCYwT05wj2GImFQ4+lPI9J41NT6U8DnRXUvMWtAiChji2DkwM6A/t5LpbKs
         fZWxVEBL/Tw7fIJfJniAFmfX9mCf9XJCDVgVZ5BGBJ7ZpTMX/xXa4oQCBHxxUnJMflMH
         zN8AD1EXwuayRbdlDLIt0cHx+jrR6hq0zu8jJfG0IS8CAUJwe1zlyALgMSGUVhcT5PlR
         KQu0MCSQWiXJR/CS5EiR+uyZhmNSQlPgwdbTouid+edWC7rBXBlqBjkd3i2H5jWftc4w
         71MQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@tesarici.cz header.s=mail header.b=RY1nRufp;
       spf=pass (google.com: domain of petr@tesarici.cz designates 77.93.223.253 as permitted sender) smtp.mailfrom=petr@tesarici.cz;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tesarici.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683109592; x=1685701592;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ZYKv5EwRqEP3hoAB0rynLb574dLw7fd6/eWw5SXPJfQ=;
        b=EtW2UO+y20a6amKxdRQl74l2jz9oLt67nZ4+6QDhbHNfeW/ljxeRwO99p6W+9met3I
         DvxxyA0e3DUgyiKHsYsYlg1lEzr2c30RifemUn4GD1FjI+70QAgDlfLhwdLZjpWRUgj9
         s2SckrUqbeGEr8cy3XgqdKXJLsAXE5pQA79+A0PM1iFLjQad+/jinOHlBRcWp4HotrJR
         qlbBwdXL3RdukBwy6bCsgkBDo+DCVLkAS4lA2TFIqTixKQhW2Ek5ZSjiRIfF4cwZ6rpP
         UYdsmHjbIb/P0JJ3roN8GRBymvzLZ1pCP2BuOpOufZr1bcDQXp/6T9L/afX/Eedmqnla
         fTYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683109592; x=1685701592;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ZYKv5EwRqEP3hoAB0rynLb574dLw7fd6/eWw5SXPJfQ=;
        b=Iq2kqVDVrNMUBVfTIcbpT1QlPdSWjkDLo5J5stX1DPjWL1tgKvMu+RUnJZ5DzFHon1
         V/wFjCUnHfpuFSkQMLx3qIPvUWdARWOoaxkv71EInkuxFlmhr/xRXxV4ZIcA8xkDFjbe
         W2dIKKHERdKUFbfrD2g3wWbdWuGPGqifx1amqykjVbLEZvahiu5cyj8Xs/c6aULUKsHT
         kIfffYCqqo/5nsxAuiLoEBgoaM1iBRq8BB2YUG+KRaKzlc761g1obH6Ma9GF4m5RSX0H
         DaqgceQhExZDredsAFXIiolzMfWg2oBQz4+0X6veC6ewaVMpjlFVeZfXP58rNadYaQ6W
         YhfQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDw/5jtuLmXmsUkFpcyB0keGmffq6iIdZ75XVMKrZrB/3yzAwrt2
	XTTvimyzQ0AsB2sugTvrxMY=
X-Google-Smtp-Source: ACHHUZ6Fw5473fuhL4pH5Dpk+frHB1zGL+/rAw2pLMJq9eojnUmdT0iNiWk0I8h4U9zQBizCMvipyg==
X-Received: by 2002:a50:d59a:0:b0:4fa:71a2:982b with SMTP id v26-20020a50d59a000000b004fa71a2982bmr641521edi.0.1683109591847;
        Wed, 03 May 2023 03:26:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:35c7:b0:50b:c404:41f5 with SMTP id
 z7-20020a05640235c700b0050bc40441f5ls7413948edc.0.-pod-prod-gmail; Wed, 03
 May 2023 03:26:30 -0700 (PDT)
X-Received: by 2002:a05:6402:614:b0:504:7fdc:2682 with SMTP id n20-20020a056402061400b005047fdc2682mr11498735edv.35.1683109590621;
        Wed, 03 May 2023 03:26:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683109590; cv=none;
        d=google.com; s=arc-20160816;
        b=gkNT/bhKtcIYdsufurvvDP23vlOQKsxL5NcvYnLXB0HaUktkU+S4amWc5dxrJ3qh4p
         OS5M6J8HsfFoctZY6eKGbFpYV8K6BD2LQu/xTznmhRnZBlTlO2JeCmjLPbT466CeeqXe
         /pz4UNfwhxClqGNTn4I4cw9DSHOCikFBcOa0o3O1sUv3yihzgEjZljADMfuh2Rcqynzv
         bIHswVSAdoH2gDGNokTmCjzNCyQNftusgVMyf0ysqSw2eojH6FoXBKSpseUUOSxXDNhn
         UlSzjWjeM9i5psodEhWuF0W1bRp9iY7CDJklRDAXqxFDabvyPe2wMiThpui4X2wNCmBk
         PHfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=9W2wun4Zj44NWzwdlLkMFEunLnmomS6UpnHu7fqlUvw=;
        b=ul2rLjDjWiLnE9haBA4jlxdVqW2EevVTvXRNFRPUY/FeC5v5941c/dE381jaPEINsW
         4mvh07hBHOmI7nCIUQxMhdT8OAHNd1Shm4VNLhw+3H6a/Rrgwad0R3py+tYxcNx6oRge
         Jah6vheeC8z+wHFXSe9rAzKrV2uFUeiWLLQ+lCm4J3qphGmu14TbgmN8vbeJhU7X9Hwo
         BzHlCR85Nd1ZOCu2oPBo0S1Y8mXko+KVzpdkxAx4FVNb+By989mdNlyV5Un0md5WK2JY
         pIhgKMSr5EYrGWFbfkOA94d4i2/d/3eRZZG4s++ZYZXPll2Eo/1Ew5sLha3RShf4187x
         iH1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@tesarici.cz header.s=mail header.b=RY1nRufp;
       spf=pass (google.com: domain of petr@tesarici.cz designates 77.93.223.253 as permitted sender) smtp.mailfrom=petr@tesarici.cz;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tesarici.cz
Received: from bee.tesarici.cz (bee.tesarici.cz. [77.93.223.253])
        by gmr-mx.google.com with ESMTPS id g34-20020a056402322200b00506956b72a8si68403eda.2.2023.05.03.03.26.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 May 2023 03:26:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of petr@tesarici.cz designates 77.93.223.253 as permitted sender) client-ip=77.93.223.253;
Received: from meshulam.tesarici.cz (dynamic-2a00-1028-83b8-1e7a-4427-cc85-6706-c595.ipv6.o2.cz [IPv6:2a00:1028:83b8:1e7a:4427:cc85:6706:c595])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by bee.tesarici.cz (Postfix) with ESMTPSA id D9EB814F410;
	Wed,  3 May 2023 12:26:28 +0200 (CEST)
Date: Wed, 3 May 2023 12:26:27 +0200
From: Petr =?UTF-8?B?VGVzYcWZw61r?= <petr@tesarici.cz>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Michal Hocko <mhocko@suse.com>, Suren Baghdasaryan <surenb@google.com>,
 akpm@linux-foundation.org, vbabka@suse.cz, hannes@cmpxchg.org,
 roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
 willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net,
 void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com,
 ldufour@linux.ibm.com, catalin.marinas@arm.com, will@kernel.org,
 arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev,
 rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
 yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
 hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
 ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com,
 ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
 rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
 vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
 iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
 elver@google.com, dvyukov@google.com, shakeelb@google.com,
 songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
 minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 iommu@lists.linux.dev, linux-arch@vger.kernel.org,
 linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
 linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
 cgroups@vger.kernel.org
Subject: Re: [PATCH 00/40] Memory allocation profiling
Message-ID: <20230503122627.594ac4d9@meshulam.tesarici.cz>
In-Reply-To: <ZFIv+30UH7+ySCZr@moria.home.lan>
References: <20230501165450.15352-1-surenb@google.com>
	<ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
	<ZFIOfb6/jHwLqg6M@moria.home.lan>
	<ZFISlX+mSx4QJDK6@dhcp22.suse.cz>
	<20230503115051.30b8a97f@meshulam.tesarici.cz>
	<ZFIv+30UH7+ySCZr@moria.home.lan>
X-Mailer: Claws Mail 4.1.1 (GTK 3.24.37; x86_64-suse-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: petr@tesarici.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@tesarici.cz header.s=mail header.b=RY1nRufp;       spf=pass
 (google.com: domain of petr@tesarici.cz designates 77.93.223.253 as permitted
 sender) smtp.mailfrom=petr@tesarici.cz;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=tesarici.cz
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

On Wed, 3 May 2023 05:57:15 -0400
Kent Overstreet <kent.overstreet@linux.dev> wrote:

> On Wed, May 03, 2023 at 11:50:51AM +0200, Petr Tesa=C5=99=C3=ADk wrote:
> > If anyone ever wants to use this code tagging framework for something
> > else, they will also have to convert relevant functions to macros,
> > slowly changing the kernel to a minefield where local identifiers,
> > struct, union and enum tags, field names and labels must avoid name
> > conflict with a tagged function. For now, I have to remember that
> > alloc_pages is forbidden, but the list may grow. =20
>=20
> Also, since you're not actually a kernel contributor yet...

I see, I've been around only since 2007...

https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?=
id=3D2a97468024fb5b6eccee2a67a7796485c829343a

Petr T

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20230503122627.594ac4d9%40meshulam.tesarici.cz.
