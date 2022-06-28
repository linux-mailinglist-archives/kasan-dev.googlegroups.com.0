Return-Path: <kasan-dev+bncBDPYNU65Q4NRBNU35SKQMGQEOTJDCJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id E8D6255E542
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 16:18:30 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id p6-20020a05600c358600b003a0483b3c2esf3801866wmq.3
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 07:18:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656425910; cv=pass;
        d=google.com; s=arc-20160816;
        b=BJGWXZiLkMW327XbMgiFYWInlCLkMy9PCnwa8/VAjjQTawnhV0AFm8u4LDQZ9TzMFv
         eszBGOCnifWU8b1D/dfxzh9d2vGk/DVid2W2TJ4H4NcrrssLo95pi7a5tNK8KrZo3Ggr
         X7XOeMR08wcs5fZWKH7gTV5ur2ei2sOrZa6CJcAKEZJf4VjrctMNeby9s5nqv40GOkRQ
         RQDnH6isq36s2ClQuho8R6La47Euljaf7CJQPT+MD84Lc44QBEnxNEnU9cJctPEX8HEO
         H+4NsGFRBDs0NpEuVXIWD0PFPtFqjzuvYQuyHssK7fARGoRMtnqYejKx2I2hkiAou2/b
         euHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=iBNkOmV0xxkVmKo3IMlXhEhp8slpmU/onODoTxl+d9A=;
        b=k5YX7DgDpvhbd8s+KfH51Timg2vIUFS2ZnSzs3OhslpiAheHwj5B6h8K+330j93VKr
         Rn7J9kDIO7F6lYg7urJqL9BnercpaRKbjpGrC16i4llB26wN2i6oCjOpT1CuIBD4RORY
         rYhjjHt5GrxJYnPuEf2PinhlaKGbCp/zv/QjjQDFRswGlPMZ/083UR33jqHnkHYrZTnV
         YZdw0KLLpg26/znbfm0KqLRAeHbRFnaECMR0jKHNliAten9qEtMd8TXyz0P0qs65xYwM
         QDgTJ23mhIjLY5dQLVj1PRhUgwOQgMZJyqcgPc/n+vB2S/QB3KfcUZCSV/ngbKVWgfvj
         9m+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=LKmDxdei;
       spf=pass (google.com: domain of gustavoars@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=gustavoars@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iBNkOmV0xxkVmKo3IMlXhEhp8slpmU/onODoTxl+d9A=;
        b=YsQpOzuQzEU8YNFzFT+Uah824CG+72oAKjTy5sM8lmzLCkKuze8PkzLK8BZNx6ksoY
         vmTNFN0980YSScTavgcDYrVuEctqTkG3h9WmSiSif8+XCHTTPhSAvBNkXsLngEDRkaUD
         E2Y4nd+Jezn1YZKPW3GGRdDxUfSzxjRqCOpSudO+F5D7gN14bmguMrEQ3IVx/sYfz8O0
         jofM1gXbtofFTl4dyYsLzT0y7AGr9Vk3Gimq2/wnE9YoAFJ/09SRFsFmn/eq0t5s7rHg
         q5gtI903sDIvSLMZpQsnCUPoyqIiK/24VaJfMUnH15lD/ijcNiCQOCxmiiOPI7xcupxT
         Xzjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iBNkOmV0xxkVmKo3IMlXhEhp8slpmU/onODoTxl+d9A=;
        b=h2J1HvNijZYj3xt6LxUsd+1g5qEsm8/U5zCBxHTHF/FidWv541knkZA+pIxWQBejK1
         09tlF6UEykHTTCRYR2nsxDsaD52/lAoLGz7vm7yVC0khxVXFD32Elthabg0GYlaDzbe3
         op4tCWdxRSpVtTYVtvh8J/zxEE00NM7FpTQCL0+ltjARKY9SQ4UQbRUj2mXAa0qeiCGt
         Z7cnqdcwIEZpJRcuV4fh7t3ysfXC8iQnFUOwOI5FdqkfqAKmvGRWcG58vwcQa44nqzds
         RRe0qJ48GxDoHGxpFRkh4I3ktmuG+4dhO3Omz4cG4kt5OjJTH6Gq08Jf2oc+NB8gvoW1
         qSeA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora8oT42xNMlnAUV0oFVocnD+ujz9WaYLM51u0MUCQCO+oq3hhGqH
	7sYUXtcehDif209SuT4/Ge8=
X-Google-Smtp-Source: AGRyM1sga4WdO+hK+MADVSbhgRsp/am7//uyA+Kum21hlo5/W7U5CNR38lOYXZx73Wx3SD+7mSfSMQ==
X-Received: by 2002:a5d:6d8f:0:b0:21b:dbb5:fe0e with SMTP id l15-20020a5d6d8f000000b0021bdbb5fe0emr10671169wrs.500.1656425910526;
        Tue, 28 Jun 2022 07:18:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:eb04:0:b0:21b:b3cc:1640 with SMTP id s4-20020adfeb04000000b0021bb3cc1640ls18486485wrn.1.gmail;
 Tue, 28 Jun 2022 07:18:29 -0700 (PDT)
X-Received: by 2002:a5d:598c:0:b0:218:3fe6:40bd with SMTP id n12-20020a5d598c000000b002183fe640bdmr19195663wri.373.1656425909583;
        Tue, 28 Jun 2022 07:18:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656425909; cv=none;
        d=google.com; s=arc-20160816;
        b=WlGUGhrsFdmRaPFFU3JiswNzMJQZhRBFoS+cWmaHRuuVGt6fNXcmp6yHSZYEEce9XZ
         sl3BuUQn11QxxB80zFg9KZ1+WWjVF6QoegrZGtfvkXpGCATlkqN43aR2wlvIuDi5e8wh
         ba/LjRspak+WM437sh0Ob6383GN2Fmc+kJJFwW5OPfpt7MI4OBreoW5U6Dl1u+RYlkAN
         dMBvzyChPnMCj5LdIk0HmR6B/maHoFaEG950grmgpsZdjD3yX8Nuq0sZOCYANG+eVZXa
         /GrkfNvkiIGFumOS2NLgFpyjxTiGRivZy6s5y0oAC+AnxkrDUmYWNAjFflBKNdb22g+l
         gt2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=h9liMSSgApbUjsLt5jfOEZYU3mzJi6+bkb3BBQ9Dqgg=;
        b=IL5CENMescSbz41SCdwHQagZB3CVk5MzOvOI9PpEKn80XrRNzh0/pcknsckCwG6ht7
         DXCchhJQvCmc3KJCaEYDszot1iCwHXyw71G1d9DUpmeHmUq5DHPLr1oc6VzZk1gxeW14
         935Vmrbmp4BVEw+tyCVaoc86TSWxjVubakohCxlzYuLmofpce8JdEFixTPr7jb/e4nH4
         HDU/vkIRah+uyOOOd41asebAKkklXVJZiAg6fexq5TXuA4+lpJ42EEZL0qzEookSejSE
         RaQto8Jk8x7w0gbv/HAw9BOB3bY6rjw6Jp7duUUhqRGIfRk/ffRWyzEbNcCZ+fJ/5X0x
         SaIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=LKmDxdei;
       spf=pass (google.com: domain of gustavoars@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=gustavoars@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id i17-20020a7bc951000000b0039c903985c6si754300wml.2.2022.06.28.07.18.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 28 Jun 2022 07:18:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of gustavoars@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 48579B81E3B;
	Tue, 28 Jun 2022 14:18:29 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4B5F2C341C6;
	Tue, 28 Jun 2022 14:18:25 +0000 (UTC)
Date: Tue, 28 Jun 2022 16:18:23 +0200
From: "Gustavo A. R. Silva" <gustavoars@kernel.org>
To: Stephen Hemminger <stephen@networkplumber.org>
Cc: Kees Cook <keescook@chromium.org>, linux-kernel@vger.kernel.org,
	x86@kernel.org, dm-devel@redhat.com,
	linux-m68k@lists.linux-m68k.org, linux-mips@vger.kernel.org,
	linux-s390@vger.kernel.org, kvm@vger.kernel.org,
	intel-gfx@lists.freedesktop.org, dri-devel@lists.freedesktop.org,
	netdev@vger.kernel.org, bpf@vger.kernel.org,
	linux-btrfs@vger.kernel.org, linux-can@vger.kernel.org,
	linux-fsdevel@vger.kernel.org,
	linux1394-devel@lists.sourceforge.net, io-uring@vger.kernel.org,
	lvs-devel@vger.kernel.org, linux-mtd@lists.infradead.org,
	kasan-dev@googlegroups.com, linux-mmc@vger.kernel.org,
	nvdimm@lists.linux.dev, netfilter-devel@vger.kernel.org,
	coreteam@netfilter.org, linux-perf-users@vger.kernel.org,
	linux-raid@vger.kernel.org, linux-sctp@vger.kernel.org,
	linux-stm32@st-md-mailman.stormreply.com,
	linux-arm-kernel@lists.infradead.org, linux-scsi@vger.kernel.org,
	target-devel@vger.kernel.org, linux-usb@vger.kernel.org,
	virtualization@lists.linux-foundation.org,
	v9fs-developer@lists.sourceforge.net, linux-rdma@vger.kernel.org,
	alsa-devel@alsa-project.org, linux-hardening@vger.kernel.org
Subject: Re: [PATCH][next] treewide: uapi: Replace zero-length arrays with
 flexible-array members
Message-ID: <20220628141823.GB25163@embeddedor>
References: <20220627180432.GA136081@embeddedor>
 <20220627125343.44e24c41@hermes.local>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20220627125343.44e24c41@hermes.local>
X-Original-Sender: gustavoars@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=LKmDxdei;       spf=pass
 (google.com: domain of gustavoars@kernel.org designates 2604:1380:4601:e00::1
 as permitted sender) smtp.mailfrom=gustavoars@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Mon, Jun 27, 2022 at 12:53:43PM -0700, Stephen Hemminger wrote:
> Thanks this fixes warning with gcc-12 in iproute2.
> In function =E2=80=98xfrm_algo_parse=E2=80=99,
>     inlined from =E2=80=98xfrm_state_modify.constprop=E2=80=99 at xfrm_st=
ate.c:573:5:
> xfrm_state.c:162:32: warning: writing 1 byte into a region of size 0 [-Ws=
tringop-overflow=3D]
>   162 |                         buf[j] =3D val;
>       |                         ~~~~~~~^~~~~

Great! This gives me hope. :)

Thanks
--
Gustavo

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20220628141823.GB25163%40embeddedor.
