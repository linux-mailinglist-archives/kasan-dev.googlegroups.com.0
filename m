Return-Path: <kasan-dev+bncBCLI747UVAFRBK5R7OMQMGQEIMVJPVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D0335F682B
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 15:31:24 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id a13-20020a2ebe8d000000b0026bfc93da46sf744464ljr.16
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Oct 2022 06:31:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665063083; cv=pass;
        d=google.com; s=arc-20160816;
        b=vwyal151h+tI99kjMPuKBOhohBcRW369g7qEdSGTGQRTH2ocGn7c0irEi1mOkaHZX8
         /Mg7x2xiDgWXuup+iP4a0WRgMCIP51aUSq1Z6r5I0f793a0XUmT66pY+q4rjMOYq3Ivw
         qrj0ZKDwJNR1jxsGyl45CKqLgASp9ibqKmYH0vUVpaXRwJQWGjmmYwAPDwNudtD21hNG
         X8vRvAa6MaWO3zRdTxLjb3Ryr8hHoazKJKAmdXg6hxqTRlbf76RJLtBHlOU26faBI9ti
         jntl2PFkK19AAmeazq5er7/zHaR1M2lGkoIqmHpYax1hQh5R/YY85SjcW6Yw5AayqE9m
         YBVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=NpcdCN/SHoYmatFMv7FyZ0cf2iOrN6viriqLzAnU/mo=;
        b=dkVqt54a2sTiclvAc0WKCd78bxq2A3G/VO1CdAQT9Pso90wOmsxvwU7FN5vs2Jt7zb
         DTMx3jHJo7us+GwlQKNSZFqKuWDgY/fn848a3jESfu9nMXC1NnMNLXoqtZLJTJCWAh16
         2hT03v6oOtTr7A3b6bMo9t3zRGXT3ch1wCZod4v3kXKVICzhjrMB26Iov/O/3a8PK+hj
         fpqCoabT0tiOB3gPdPpkQGmt+74gUBg2vE6fj5aalz+UUY41m7OkicxcpfMdGoBeU1o/
         8VqiF7RDWVDprVCYmucopiseUULeOG6GRa8RetAPb+RFsT7JQewfylZRxgluEshg2wxB
         tF4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=paDfDcvH;
       spf=pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=tIOp=2H=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=NpcdCN/SHoYmatFMv7FyZ0cf2iOrN6viriqLzAnU/mo=;
        b=gckxGxq8hngedqghiertBHZjTDyMoqXIqpp8K8V+hPjkM+WjNJHQQu+s0cdd+m5HQt
         qFn9WfQJS1/51e23IQ2viv5fD3rkP05xpzNC8XsTaS1dSx5QvASVaaFUk+AaDy8/hOcD
         tQMHQTFpXAJpSWOZ9WWyCulDWoWwWtWHD1GaI3LTuEQNqVBPPWbTxpEQEw66OdYptL2/
         HQTuk/+HLV5ME+lF1tUWkSxsBsouAAwfean2Emr7BzPP7Q4JtpRa7XtWwYwGJOkhYGFm
         GdvafFxNZROwkNOPX1svUOQHQdgN++/KsGs0UbP+UaCxmU8uiGXwoLKXBxowXiUwGHr3
         5M1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=NpcdCN/SHoYmatFMv7FyZ0cf2iOrN6viriqLzAnU/mo=;
        b=3emjnMEngZINa+ngMGt4WXN/nHtr060apCpKd9jNTnhXRuiZQfPpPYVoCEnVfweRrs
         7+Kgl7PS7Sk8jeYbjFTvOkUhjIznw06n9jASHwgoER3GzAtQ8Cp9F/kl4ftc/lwXTCP9
         spGDfaITsgyre4MdRzQQ0KI2Lz1uMFzCtJtpmMSHZxPHbHqGAUB/b2j2iX8DWM31upJj
         Tm79OY0yACvxAyaThAPQSwpxICafHfEzt9HRV830nnbQSCEd6fPD9RjE2KhEMt+d9Yvz
         LRhvyCqQKXuFDPsitUG6tsx81OKZFxNB66PpHXrJIs8Ewhx1uDZcliiqp+vopv4Mv/SL
         S9bA==
X-Gm-Message-State: ACrzQf33IiLpVE6aRZPcJBOH9St6Z6j/V8jHa8kx3eLGwiUbOgnPGFZ1
	eZ4KrCZj3ZXOQRCZGuDJ+MM=
X-Google-Smtp-Source: AMsMyM6tzpfYwl6oPtDmYonF03JX00fqwghblB2dlSK0+StIcag/aEZy/Q9p5md1mj8O6Nh3nKrrqg==
X-Received: by 2002:a2e:8541:0:b0:261:b44b:1a8b with SMTP id u1-20020a2e8541000000b00261b44b1a8bmr1909675ljj.46.1665063083686;
        Thu, 06 Oct 2022 06:31:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3a5:b0:49a:b814:856d with SMTP id
 v5-20020a05651203a500b0049ab814856dls1302712lfp.1.-pod-prod-gmail; Thu, 06
 Oct 2022 06:31:22 -0700 (PDT)
X-Received: by 2002:ac2:4e71:0:b0:4a0:7191:762e with SMTP id y17-20020ac24e71000000b004a07191762emr1730983lfs.361.1665063082496;
        Thu, 06 Oct 2022 06:31:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665063082; cv=none;
        d=google.com; s=arc-20160816;
        b=V3zOXrSfxnZ/+yqhn+UI0aO3WKtxiX/H364EvukM5OZwF3lWkLGCdWKntNvmWvwoi1
         3wiyLvAqwKyQVao20nv92FNuyUEVgLgTigpBGyassD47e+Z7zEE4nTtlb9Z1Qlehic4M
         va5QVY7oIpazdXFy7bSgGPnQ02rBgb58/kvxIC6bmi/+DsuvDnHPms8ucRrSByrUkorP
         9bEkI2sGVcdudzRCe3TX0zOMnLwXCNbhxP1n4BnMrVMNuEE9a3CPmZSWclBV+Uyci16k
         8+0IRd7Ga+aWDhxczjo2GD66Rao/JFU3rQtqQy1COIaojtxFkd4HOspD1smlcidlVx/F
         ReZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=19y9yEzpIVCdXeybhvKA7dJEvUCmehig1gThjjfIZlg=;
        b=SdoDZ1NGuVFJDUBspnkXy9SF/3hQYb2MrVj2CK+vuZsIKqYeEFOXET0dA4kPgPXUrG
         1qaDdeAVyFPNB80fqTA2VIMrc08ZR/UoJ5MwQKHn/d5FvctW5I/nABsAexm+0JSHKz69
         2wikW+hIHsEJlZLjVV420YhHB/OpYlVedvHeX7S2WtiLE892q/WCd1zQ3WiVlnuzdNWe
         MKHevhfJpdjtory4jeLpV1bh11l8OeysMb29sZYtSp4gd9KRtJOLjsdDWU0519yJoGX2
         WI2Jw7aAk/6LRjKKH4qfbJtvRLAP/AT/OOL4wCaVR7MmVX0urLt8vvWaSrvHnzcVyrXh
         5N6A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=paDfDcvH;
       spf=pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=tIOp=2H=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id z4-20020a05651c11c400b0026bf7cf2a41si618047ljo.2.2022.10.06.06.31.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 06 Oct 2022 06:31:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id D596EB820C1
	for <kasan-dev@googlegroups.com>; Thu,  6 Oct 2022 13:31:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4D2DCC433D7
	for <kasan-dev@googlegroups.com>; Thu,  6 Oct 2022 13:31:21 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 274a3fd4 (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO)
	for <kasan-dev@googlegroups.com>;
	Thu, 6 Oct 2022 13:31:17 +0000 (UTC)
Received: by mail-yw1-f182.google.com with SMTP id 00721157ae682-3321c2a8d4cso17715487b3.5
        for <kasan-dev@googlegroups.com>; Thu, 06 Oct 2022 06:31:17 -0700 (PDT)
X-Received: by 2002:ab0:70b9:0:b0:3d7:84d8:35ae with SMTP id
 q25-20020ab070b9000000b003d784d835aemr2699257ual.24.1665063063460; Thu, 06
 Oct 2022 06:31:03 -0700 (PDT)
MIME-Version: 1.0
References: <20221006132510.23374-1-Jason@zx2c4.com>
In-Reply-To: <20221006132510.23374-1-Jason@zx2c4.com>
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 6 Oct 2022 07:30:52 -0600
X-Gmail-Original-Message-ID: <CAHmME9pXuGKNsm3cCOMLSOMJoX2XJnHffpiF_rr32mW2ozShhw@mail.gmail.com>
Message-ID: <CAHmME9pXuGKNsm3cCOMLSOMJoX2XJnHffpiF_rr32mW2ozShhw@mail.gmail.com>
Subject: Re: [PATCH v2 0/5] treewide cleanup of random integer usage
To: linux-kernel@vger.kernel.org, patches@lists.linux.dev
Cc: Andreas Noever <andreas.noever@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>, Borislav Petkov <bp@alien8.de>, 
	=?UTF-8?Q?Christoph_B=C3=B6hmwalder?= <christoph.boehmwalder@linbit.com>, 
	Christoph Hellwig <hch@lst.de>, Daniel Borkmann <daniel@iogearbox.net>, Dave Airlie <airlied@redhat.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, "David S . Miller" <davem@davemloft.net>, 
	Eric Dumazet <edumazet@google.com>, Florian Westphal <fw@strlen.de>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, "H . Peter Anvin" <hpa@zytor.com>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Hugh Dickins <hughd@google.com>, 
	Jakub Kicinski <kuba@kernel.org>, "James E . J . Bottomley" <jejb@linux.ibm.com>, Jan Kara <jack@suse.com>, 
	Jason Gunthorpe <jgg@ziepe.ca>, Jens Axboe <axboe@kernel.dk>, 
	Johannes Berg <johannes@sipsolutions.net>, Jonathan Corbet <corbet@lwn.net>, 
	Jozsef Kadlecsik <kadlec@netfilter.org>, KP Singh <kpsingh@kernel.org>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mauro Carvalho Chehab <mchehab@kernel.org>, Michael Ellerman <mpe@ellerman.id.au>, 
	Pablo Neira Ayuso <pablo@netfilter.org>, Paolo Abeni <pabeni@redhat.com>, "Theodore Ts'o" <tytso@mit.edu>, 
	Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>, Ulf Hansson <ulf.hansson@linaro.org>, 
	Vignesh Raghavendra <vigneshr@ti.com>, Yury Norov <yury.norov@gmail.com>, dri-devel@lists.freedesktop.org, 
	kasan-dev@googlegroups.com, kernel-janitors@vger.kernel.org, 
	linux-block@vger.kernel.org, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-fsdevel@vger.kernel.org, 
	linux-media@vger.kernel.org, linux-mm@kvack.org, linux-mmc@vger.kernel.org, 
	linux-mtd@lists.infradead.org, linux-nvme@lists.infradead.org, 
	linux-rdma@vger.kernel.org, linux-usb@vger.kernel.org, 
	linux-wireless@vger.kernel.org, netdev@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=paDfDcvH;       spf=pass
 (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=tIOp=2H=zx2c4.com=Jason@kernel.org";
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

On Thu, Oct 6, 2022 at 7:25 AM Jason A. Donenfeld <Jason@zx2c4.com> wrote:
> This is a five part treewide cleanup of random integer handling.
> [...]
> Please take a look!

I should add that this patchset probably appears bigger than it
already is, due in part to that wall of motivational text. Keep in
mind, though, that the whole thing is only "305 insertions(+), 342
deletions(-)", so it should be conventionally reviewable.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHmME9pXuGKNsm3cCOMLSOMJoX2XJnHffpiF_rr32mW2ozShhw%40mail.gmail.com.
