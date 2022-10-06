Return-Path: <kasan-dev+bncBCLI747UVAFRB5XN7OMQMGQELXTXLTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 49BB75F6ACB
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 17:40:39 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id h23-20020a05651c125700b0026e01b79d34sf884478ljh.13
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Oct 2022 08:40:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665070838; cv=pass;
        d=google.com; s=arc-20160816;
        b=SZicQJhVN/xPjSKZLJQE8/dzuacabpYDwwXAzE1QDu3IxRocZd3TMMELT1Aj27YCXL
         Q+KZ9+Bsgj8W6mepWDEdp1OlIbmd+S8N/1lbgUGO7/z3wyKf9vKwSLTPCXUk6J/LXQ5G
         HdAKq3u3Ut15v2qJJReQDkhoMiecAfO42xMxQwqtKuF47Wgr2D3bYI5ZtAR9htOyXpXO
         SBebD9CbnJ4jwa5ByLDGyWaSn8z8X333JUwaVkJwd+gT9JTnG0JzE4gu3sBs6hlaa/17
         T0KV3ID1/08Amu69Lqjqc6HpAXs3LxboQ4SR5LS+ysyNB4Pb+4APkMZGEYgTgTHJwyXK
         au0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=Knt1qJ2o1PNIf17KAAw8EfohdXOXaB1yNJpdI790xTM=;
        b=eJGoAVUaqtm+lLoGfGUNlWjKQT9uhXmnmNCtcJlcrfwvKC2j7jCp5yFs1kaOLO0Xha
         /ET6LC2qPlHk0W57wUjPR7bMyLa2Fxyg1OlN8dn4RaFnyk6bsw2tZFGnrVq3rDY05sf0
         Mcd//WB4gNnt6ouAnAp5etJoTmFqkyH3gXPAKnDzZPXSZpEmjbB1KuWhtcNgktZ8VEoC
         sT/SoPCkYf8DBI++DF0lxQQmk3uWkahvhLcE0pfe+Nmu1Pt2j2bIrZoGSEPLycABb66t
         hya0jmElQadFF7g3DCGA3RxIzdJ/BTxbs37tbn22R3u5oY+1p+v6AzEQIjxiym6waP5+
         4m/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=kBRHEGDV;
       spf=pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=tIOp=2H=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=Knt1qJ2o1PNIf17KAAw8EfohdXOXaB1yNJpdI790xTM=;
        b=DycpTjVSdGxfrP9F5sCy8bI8ecDaUbdAFsGAH3iOAt0k3r7pFSmXFw+WJHE+mf3tfB
         D/6btHeVAf/mzb+Uu/BPw3waU4STDtgXcjjF4PLYpYrNECmgJIUsbbWciJ792+Lqb6gY
         QXcBM7wolvlscqpfVA7Cnms9YDLXEPPQCv8r2UJ6VRuCLkHZJuHPQfenQZaf3vFlFq+R
         K/vmAHi0gv/s/xs8cZ2JJl+s+hOaiwwUB7r6Y5s2KANrPAVOZeKqpWsKTR21dRf6tfiY
         p2OESgkZkBRltY5jXkk/ar/Dsk5r0fPayaDXEx23qOuGCWqXwRiuHmrhTywcpaK8T7AA
         NY0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Knt1qJ2o1PNIf17KAAw8EfohdXOXaB1yNJpdI790xTM=;
        b=tJvvSwVK4Wohg5cxQnljVqzTE6TjiQKag49NwCklyA7I5aaq3JIBEWbWthmHIQ7j+g
         mqnCN3JckK0MFbF1WURcnNW8bwUB5NPUZRfPKm6UQ9Ebqb6c7Q7XMochJMU2ghRegLfw
         TbzWBY6n4Tl8Wtj77ZKfRsDWdt5nUaVQX+PwiJWgwRsZ1pSVC7QRpiH9HkSaGqqk2v9Q
         4R0iYMukEzwUdRd0n2R2aK3VusFMrepGsmcaxmGHsR6UK5vNRVnZDUXHmAI4fwVeV3fo
         q/mJgEmgzlPOWEgkz3KfXHOhiM0NXDK8pHHniU0s/CCfG4lJG/FyIUHDgQCCFQbw40cP
         DZjw==
X-Gm-Message-State: ACrzQf0WmFuTjPdYTllVgRhSt2xhs8mfybJ9CK557HuI5PKdd4bgOur7
	QZFI0WbkfSvwFmdcxSsqBac=
X-Google-Smtp-Source: AMsMyM6rYCTE8GKezzNpiebJeBHMwVvXDAqeeye1ocBSUFbbZG06DVUWQtEen4yrWtmCSTJdcM7Y2w==
X-Received: by 2002:a05:6512:401b:b0:4a2:4f6d:721e with SMTP id br27-20020a056512401b00b004a24f6d721emr215186lfb.393.1665070838597;
        Thu, 06 Oct 2022 08:40:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3a5:b0:49a:b814:856d with SMTP id
 v5-20020a05651203a500b0049ab814856dls1627316lfp.1.-pod-prod-gmail; Thu, 06
 Oct 2022 08:40:37 -0700 (PDT)
X-Received: by 2002:a05:6512:1699:b0:4a2:1924:af2a with SMTP id bu25-20020a056512169900b004a21924af2amr202820lfb.491.1665070837435;
        Thu, 06 Oct 2022 08:40:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665070837; cv=none;
        d=google.com; s=arc-20160816;
        b=kojFDGq8u81DLjnkLAGn9tLotlsrEmOSYlqaGk9BC+cW8rbknIXOeASvefyuL1uHjA
         Dbz5Ep12CXjAqbHQJchPNENvekwan6DvvIziXmanFNrVaN9Yk2iWxaM7aHaoleXohtuT
         93yE8ma+L9sksiO6hpjMsyfsm9cbS1bB+fz6lk9Tx6ttlJoTcBzBW0rgyjcL1N2jIBXV
         Gphyqa0EFhGUlG62eN4G9JycHVs9FnguOqyoAe7lemMD6hYfOzgRA4IFOwwB4VR/ITqC
         H6zTQWdH1yDoUrk5bRH4m0kW4od3Rkq3toKnlE9flO6pcIOKhciMIoJZU1pe2d20r4An
         Fb/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=UErKVaJQCmz0JpPdH7ldbL7h3QJYSFC93QhEFTHl6oU=;
        b=u/0MoxIF1QANny4jauGTvBFa16WXrYoR8AW9N4o667L5fxvdnIWc680n1CgGS134n9
         GbsD2aSiHT2ip5t+dPZKrn+W7pI9VCbdbFjupy7wuK41OWTNMXS973Mi3tPLaVIBPqk6
         +AvE3FvTON1v2q81qvVsn3jtwLTjm8d8UQLOlGnBoZrvSD2jh3po2S4/IsQuS/DezrVp
         bpaAKrEo1xWt/g1SfItDKjdogBXKQBG5rbL0/K6Zs94s6NUtY3Qmqx1DxJ9oJLvGUZ9s
         J2jBKq44uLnO8AbbsSHzHyOl7RUvKCc0fYsd7VmKFSNmTRtl6ich0HWzQ2o4ODu/WjWW
         OYmQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=kBRHEGDV;
       spf=pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=tIOp=2H=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id m11-20020a05651202eb00b004a225e3ed13si49574lfq.13.2022.10.06.08.40.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 06 Oct 2022 08:40:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id C4379B8210E;
	Thu,  6 Oct 2022 15:40:36 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 1CD3CC433C1;
	Thu,  6 Oct 2022 15:40:31 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 477cd97a (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Thu, 6 Oct 2022 15:40:29 +0000 (UTC)
Date: Thu, 6 Oct 2022 09:40:24 -0600
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org, patches@lists.linux.dev
Cc: Andreas Noever <andreas.noever@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	Borislav Petkov <bp@alien8.de>,
	Christoph =?utf-8?Q?B=C3=B6hmwalder?= <christoph.boehmwalder@linbit.com>,
	Christoph Hellwig <hch@lst.de>,
	Daniel Borkmann <daniel@iogearbox.net>,
	Dave Airlie <airlied@redhat.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	"David S . Miller" <davem@davemloft.net>,
	Eric Dumazet <edumazet@google.com>, Florian Westphal <fw@strlen.de>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	"H . Peter Anvin" <hpa@zytor.com>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Hugh Dickins <hughd@google.com>, Jakub Kicinski <kuba@kernel.org>,
	"James E . J . Bottomley" <jejb@linux.ibm.com>,
	Jan Kara <jack@suse.com>, Jason Gunthorpe <jgg@ziepe.ca>,
	Jens Axboe <axboe@kernel.dk>,
	Johannes Berg <johannes@sipsolutions.net>,
	Jonathan Corbet <corbet@lwn.net>,
	Jozsef Kadlecsik <kadlec@netfilter.org>,
	KP Singh <kpsingh@kernel.org>, Kees Cook <keescook@chromium.org>,
	Marco Elver <elver@google.com>,
	Mauro Carvalho Chehab <mchehab@kernel.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Pablo Neira Ayuso <pablo@netfilter.org>,
	Paolo Abeni <pabeni@redhat.com>, Theodore Ts'o <tytso@mit.edu>,
	Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
	Ulf Hansson <ulf.hansson@linaro.org>,
	Vignesh Raghavendra <vigneshr@ti.com>,
	Yury Norov <yury.norov@gmail.com>, dri-devel@lists.freedesktop.org,
	kasan-dev@googlegroups.com, kernel-janitors@vger.kernel.org,
	linux-block@vger.kernel.org, linux-crypto@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	linux-media@vger.kernel.org, linux-mm@kvack.org,
	linux-mmc@vger.kernel.org, linux-mtd@lists.infradead.org,
	linux-nvme@lists.infradead.org, linux-rdma@vger.kernel.org,
	linux-usb@vger.kernel.org, linux-wireless@vger.kernel.org,
	netdev@vger.kernel.org
Subject: Re: [PATCH v2 0/5] treewide cleanup of random integer usage
Message-ID: <Yz726M8q7RTNFKXb@zx2c4.com>
References: <20221006132510.23374-1-Jason@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20221006132510.23374-1-Jason@zx2c4.com>
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=kBRHEGDV;       spf=pass
 (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates
 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=tIOp=2H=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
X-Original-From: "Jason A. Donenfeld" <Jason@zx2c4.com>
Reply-To: "Jason A. Donenfeld" <Jason@zx2c4.com>
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

FYI, v3, which I'll wait a bit before posting, will also take care of
get_random_int().

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yz726M8q7RTNFKXb%40zx2c4.com.
