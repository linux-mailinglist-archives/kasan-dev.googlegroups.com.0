Return-Path: <kasan-dev+bncBCS2NBWRUIFBBUWG4SRAMGQERAHIRPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 55F8A6FB50F
	for <lists+kasan-dev@lfdr.de>; Mon,  8 May 2023 18:29:07 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-30629b36d9bsf1765330f8f.0
        for <lists+kasan-dev@lfdr.de>; Mon, 08 May 2023 09:29:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683563347; cv=pass;
        d=google.com; s=arc-20160816;
        b=H7utNcrfpDps+aa3CGxKZ9z2SHoT9tvWUS7gbP1sZ1I49Co4lm+AXy/yHmy4w9/H15
         AVyOUuxOpFGr9g/8+EZVugpEM4xOa4eBqpf6t6Wo3vluyT6WG4JSqKlkLgMqV1Eg2We5
         VH9aLvZQKWuEd14mQqQSYInomWWY/Ji4sxTYD5Y3mqthisd31XgM6JzGY9Z5KAkBsXKN
         5rfrcemeC0bLj8gX8ZkhSixDRVxqh7yiZDQ9FRlQI1bufrDwo2rnr1wqpl6QoY80273d
         yKd7+JRHPGhNIZdOCvcpiiMGZH/PaWG0KuCDIix5bqmmGZxo01XdEPnmaoI+sBsIbJPX
         WKow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=PYoUKl7r8NwdT9shLQBSbRam2hBap35CD3Bt8W50U9M=;
        b=F+G4UAz0OIOxsUStUj+fh/81s/GNri91dl1cSoqG+hYjySQu1lRVNFQN7pJ16r8A94
         eVdanz+rvIp2WTgocXv4d5Ppbp687PQ1C/HA3K2NKvWXN8MkkW42jSt7UCMpH/ZhBOLW
         1bEJppdeo7MesNCeVgbmCR1+WJrWE9PsriYo2VY8+/YIpHNtwsyZ9KjzyC7RxY7zpHVH
         nwmsdmKbY5U9n/fBwTd4C3vdoqMIH3FOEjqibatCfml0sq3zuEQOZjTO7nujN2H/zk/f
         gI9I1pz7HXQnHbGAgLwhQeN3AG9W3OSoeBu6xmX+MAUh7nohwJooLBT/CitQPy+Yaz81
         ukBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ppCSykAa;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.53 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683563347; x=1686155347;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=PYoUKl7r8NwdT9shLQBSbRam2hBap35CD3Bt8W50U9M=;
        b=i+6zOnSndmK5tGMx5lOUEJzrRWuBZTBgA33C7d9IUhP/2hkKjt6Ahej5SxOkSBr/37
         5nc5SYtH93YjHSVN47AAlIrBlSfirN+EzmKdakBtWqLt2yrtOgjFVRrP64C3bZnIkm1s
         ARbBr6tJMSAQjdz3C78ssuX7FjixaUTOkvZ8vLvDe99INF/lMrm2GUgmUHmuSll5DrWo
         YDSmvV5Rj/dFpSNP1hn/so6q3o8jI8XzDyUKac4n1Yg2P7RRq/ckJw2NPa4RVcjCmf/o
         0Y35LujnLcgLC5OkxvbpBhG2bSKJ4anACehXiWzASy/rg4Bcijxdf9A2VRIKirMrj+b3
         fqeg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683563347; x=1686155347;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PYoUKl7r8NwdT9shLQBSbRam2hBap35CD3Bt8W50U9M=;
        b=OonCQ7TJgHn4sNA0d9hQdJjKbiaRshfv0Pk4fne6Cp6UZoiqYWOa8Yv/z5lIXuAok5
         othkF/ORq4KYDyh6WLQrlxYcAOWxRM7TCphWAUxkBzZM70w3IIrJnN0KPkK5LF54p6to
         74XsNSTEhzrH/GXEjLyydkfDijdHEBqVS56+KKFwmk9l/UFaHbv83VspxyKinB/fVSh+
         5KARc5BTQr8TVZSDow1rzOrrGRbZdUqCYN8UNq725bzbiP4gJFZCWNCwerxMWyTLL6Mm
         N/8HpD3qDzaiY8aNJat+KuVFTUN3B4tslsjTpjqzFYGg2DalUXoZrV/OX2CDELnPZsmO
         +XHA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDwu6y3wNYh5tKG8pcVSLq3/NKzDeKn80d7dBo6/mS6RTsibFw63
	1Ju5iq2MBcT5t/MLeGFxFBI=
X-Google-Smtp-Source: ACHHUZ7IMNcnPjMQZB43LSVCgOad63xvo3n7bfFyk0pApxKPR2yK1mVeQrUU9TFfJC4Fu6ijRFegEA==
X-Received: by 2002:a5d:4d92:0:b0:2ef:b5a2:50cb with SMTP id b18-20020a5d4d92000000b002efb5a250cbmr1726605wru.0.1683563346561;
        Mon, 08 May 2023 09:29:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5e93:0:b0:2f4:1b04:ed8f with SMTP id ck19-20020a5d5e93000000b002f41b04ed8fls1562257wrb.1.-pod-prod-gmail;
 Mon, 08 May 2023 09:29:05 -0700 (PDT)
X-Received: by 2002:adf:f30b:0:b0:2cd:bc79:5432 with SMTP id i11-20020adff30b000000b002cdbc795432mr8152304wro.25.1683563345342;
        Mon, 08 May 2023 09:29:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683563345; cv=none;
        d=google.com; s=arc-20160816;
        b=wipFBK6HI3iKcxigxqEYZl1Od7QX9HQw3elUuhWlctW3ogAefnER0wPbDxSMlI97Qd
         75ke8XgwGibnrCgduIvti79UywJYihRtp5DsDfRDy00TK6NQm8pph/hbGnz9VKmT4Sh6
         KKij9QruP4EC11zNBJoTdFikQ64cogEp0tdKQL8+0fPVbCzZOrlFfd+YE8tgvOppImn3
         iT6rJmCC05NIap87UAodzcuRSj91hWY+3b4Lngf3DY/KVgl7O7Hc2l9eXGVOA93RenJx
         Pmi+monbxKjazbzCX+/FmgSCYlqVJuD8r+6ZPDU7+ygh328DNUqYC6L1OfjNiZoDG1CM
         +6UQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from
         :dkim-signature:date;
        bh=btuWTLCDIU3N1awwn4zUt1YF71kJtC5z8SNVVUAIbyo=;
        b=vSgkCwfQ3bx4/ekF5ZC3YiuLT3qKHA2zo5O6v9DyZNzAyv0Dj6JXvRChPKI74khKZR
         sJGIgTL7VO01x0Bo1PmvFnw2UjthHOsrhO6x5w8hG5cZKg/7hxR2iti0OAxuhT0rbR4p
         sHvnU7NsxHvrglPU/VdCZoN83CGwMD8e5AWh4j+UpdkEAj2roB3V5eSurgST7gLNkRzB
         AqnWN3S93hrQSuoGyj7ybR86m349N7M/HKvpYJVTcQEl42s2PulA/QafAz3E8TtEeJfm
         e+J8bOp3g+ZozdFpRRJTcFXzJaV8hcPrzYmOn1qy9d42HwGKt4/WuQjMtYM2I2fzz2tc
         rs1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ppCSykAa;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.53 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-53.mta0.migadu.com (out-53.mta0.migadu.com. [91.218.175.53])
        by gmr-mx.google.com with ESMTPS id l11-20020a05600c1d0b00b003f4272db66dsi135736wms.1.2023.05.08.09.29.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 May 2023 09:29:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.53 as permitted sender) client-ip=91.218.175.53;
Date: Mon, 8 May 2023 12:28:52 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Petr =?utf-8?B?VGVzYcWZw61r?= <petr@tesarici.cz>
Cc: Michal Hocko <mhocko@suse.com>, Suren Baghdasaryan <surenb@google.com>,
	akpm@linux-foundation.org, vbabka@suse.cz, hannes@cmpxchg.org,
	roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
	willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net,
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com,
	ldufour@linux.ibm.com, catalin.marinas@arm.com, will@kernel.org,
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
	masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org,
	tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org,
	paulmck@kernel.org, pasha.tatashin@soleen.com,
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
	ndesaulniers@google.com, gregkh@linuxfoundation.org,
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org,
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
	glider@google.com, elver@google.com, dvyukov@google.com,
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com,
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
	kernel-team@android.com, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	linux-mm@kvack.org, linux-modules@vger.kernel.org,
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH 00/40] Memory allocation profiling
Message-ID: <ZFkjRBCExpXfI+O5@moria.home.lan>
References: <20230501165450.15352-1-surenb@google.com>
 <ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
 <CAJuCfpHxbYFxDENYFfnggh1D8ot4s493PQX0C7kD-JLvixC-Vg@mail.gmail.com>
 <ZFN1yswCd9wRgYPR@dhcp22.suse.cz>
 <ZFfd99w9vFTftB8D@moria.home.lan>
 <20230508175206.7dc3f87c@meshulam.tesarici.cz>
 <ZFkb1p80vq19rieI@moria.home.lan>
 <20230508180913.6a018b21@meshulam.tesarici.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20230508180913.6a018b21@meshulam.tesarici.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ppCSykAa;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.53 as
 permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Mon, May 08, 2023 at 06:09:13PM +0200, Petr Tesa=C5=99=C3=ADk wrote:
> Sure, although AFAIK the index does not cover all possible config
> options (so non-x86 arch code is often forgotten). However, that's the
> less important part.
>=20
> What do you do if you need to hook something that does conflict with an
> existing identifier?

As already happens in this patchset, rename the other identifier.

But this is C, we avoid these kinds of conflicts already because the
language has no namespacing - it's going to be a pretty rare situtaion
going forward. Most of the hooking that will be done is done with this
patchset, and there was only one identifier that needed to be renamed.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZFkjRBCExpXfI%2BO5%40moria.home.lan.
