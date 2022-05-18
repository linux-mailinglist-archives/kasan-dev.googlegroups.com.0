Return-Path: <kasan-dev+bncBAABBMPKSSKAMGQEC5IWKAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3972452C1B7
	for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 20:04:34 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id g2-20020a0565123b8200b004725c7af360sf1374040lfv.19
        for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 11:04:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652897073; cv=pass;
        d=google.com; s=arc-20160816;
        b=i+DrhvYK6PxR2Ae71jkoeVxTStSjPP0uv9Xi7h6m5KtRTMlOL4cmHFpOjvsgYDQ+eG
         XJX713fDAazJJSsxlncpW51ALwTVV8DM15LwB6ssztXUsKu1xVwbxHTFLoYtHCnn3btR
         ka5sPYz80ELTmBFt6mCtfUyicQ1migpQlX0iZt5VCT6FpNL4Wm0S+AAEzjIyKPZUJPog
         j5ZlCAZcrOYhCypRpyGl8/Ir2b3tRqrKIU69QB/ts5IZoBr5rpcwwF9NWr3tlo8WnCCJ
         +8xnwxaSIoDXuO6VOciDl5j82AKxe1f4SZjzaG6vmTUdAR/b07B49MK39bXm3+Ij+Fn/
         u6Ow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=LD6O4QqDOUOxIl7YnGPzhhKQ+qjENZeAnzs6yXJ+TbM=;
        b=mGq7C3JO6HNU5vCHdmMdi1B08kYI5bRfh7HqshnW9U/QoI949XY0zx4P5xJtFTNSGy
         NTNofGOIGJSY7RPfGtA4jiCVCSyv4yQ73ldmZWatyG/rsY3zQhOsq5UaQCjdTtB0pBH0
         HdfcyurAL0icxPhYcoEZTXgi1ncaFqUcCBN2nEY4MMZzrBhM2vindwb0mSFGprc2INdC
         g6NnTNDJgyB7j9SWnN92hgs5FQRC5XEXOOICGsyV4CNro+1eOD53XEzkrtsCzYRp/Hsw
         UIQ0+KMP/K1iXYmOdYBWMJSgjhfUdvNqoJuKtgL6I17fZCrNLih5Df1hkymxUGoYf/hp
         XEOA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=aRY8v8BQ;
       spf=pass (google.com: domain of jpoimboe@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=jpoimboe@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=LD6O4QqDOUOxIl7YnGPzhhKQ+qjENZeAnzs6yXJ+TbM=;
        b=Yolv9sfSJNgE5eSf/C2DxoFrNjjWPlrjlI6rA9l26GyNtxN4AKsTeqqBIsqMHFwmOj
         GmXmqHjN/OwBVyjXb982YCO+clNMBbqQnqgKzg24U0ruVFX5h/xhSk+cssvowevK/tzi
         XXpmrd5JrX242H7AX5vrVG9hjUukLIsEoJSXUqKYDDalftkk1CKa5NVawpx4YFPaL23l
         nDU5fkw1NJElcTLsIho+aOKWKkBG7xzUom0YakwZBdnXYgk+9nN5tdqsa3N/hRo64n8+
         iIPSosTvS9Bv2sSaguR90HO9ElCcqwYamjKv/scEfhh8PEsCDtZIwsiEdCjR4lwTugIV
         awrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=LD6O4QqDOUOxIl7YnGPzhhKQ+qjENZeAnzs6yXJ+TbM=;
        b=jQW6ZxtjPjAcu9TSlGCoz7ub/DRvcBd9dYs+mWAejXWa9FQ7BsARNE6qtdr4AxK9DD
         2847PdWv41weCiHNsO0XGMpOg5e9dVnapO9jAXtXo2kw9EhyGQjuasgq6WIsCba0jNXg
         xlB7kkZgPrEKCskKOlL3oJRzq8Mj0CBLJtdKkRoijqHqkb7zOSCiIuQNUkCm+5wCKUhI
         6AtPBKVs730F7FLxbfVPojfxlHxiiCFGvNyxUPcYVf2LAsSs9IWZxuuJ5jELcAAuzWrf
         /RU2SK5qthgIBcHNkK/t9evf8rvsg0shGV2GjhIEw7Ol9TsZpSFl/eoyt7wc5VciDUh9
         rqkg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5332KMK0CVfswg4URZjUlSq45Y7gXjmtJ7CX931MyFc5OocvSGAO
	hucxV48H/KZLob6QTAQDzUk=
X-Google-Smtp-Source: ABdhPJyyoiDSnC1n2f/WaLDJl3nBJN4VtxhIrfE2aON72h1/FIZPdjEDaQ8/okO1TQeHyaqERJaPXg==
X-Received: by 2002:a05:6512:2312:b0:472:5de2:ddf0 with SMTP id o18-20020a056512231200b004725de2ddf0mr481527lfu.134.1652897073467;
        Wed, 18 May 2022 11:04:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:210e:b0:250:5bd1:6dab with SMTP id
 a14-20020a05651c210e00b002505bd16dabls81372ljq.6.gmail; Wed, 18 May 2022
 11:04:32 -0700 (PDT)
X-Received: by 2002:a05:651c:542:b0:24f:51da:6d8b with SMTP id q2-20020a05651c054200b0024f51da6d8bmr348585ljp.181.1652897072581;
        Wed, 18 May 2022 11:04:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652897072; cv=none;
        d=google.com; s=arc-20160816;
        b=wICyshRHST6Fa8pyef7IsA92Y9BQgCVZS6Rb0W724AmoCN32QUrhk58sRjSeYhKXGX
         RlE1kUQbEIlsvUYIM16KC03/gBSCoBKXGKTDKrqTBr1xr3VQTY/9YPjVz1CmJMQ1/ToT
         g1T1LDbAnV9Qs3L6uH4Md3Uql83O/aML40/2lz1VQ7mcZ9DWVH2rgbscwN8OmzZbO1m+
         rOTSqUC1jNp78FGfeDpvQHZZiwFE6LIk1luiL98TccQymUkoCncW9/oqAZVrexIElq3D
         UoiX8TMK19ZRgigQBYktBn85QzIuPSERzCRsJ++ipqAr8MgFMuYDqBLNoGperyCgBpjn
         yRtQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=j4NYBIJ7hPaBQPWRUlhiZtptdk3k6Y0xddcRShIJCVg=;
        b=Dl3Mrk1vqe8n4VrCm/bcHsz7NPfxPIBW+NuME/9Ch5CXx+mYZMX/PoMIdEHj1tnor1
         SCdHoq3xBkrCPlaKhOp6wbNijgWGUnGFvGL7+ppcXTY8249AneTJ/Ws49m2hNqCD5ZVh
         WBaQpoRM06rZtfMVnTNly2mi3KZ7dSMVsI40RbrpiLViSoA3QcGrTxprYtrsCVK95ZPw
         QcCXTCL380dbt8Z4xD4vLNeNf7RoDsVF5A6WhHKav/H6EJ9nEuLaX1k2tP+3ndTWecev
         EMoCGncOc8ux5V/G8YewF7ibqx4q3fKSTnAg0+zwB9W8XLf/tevQfrOl5koNsuFFjL6i
         5+zQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=aRY8v8BQ;
       spf=pass (google.com: domain of jpoimboe@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=jpoimboe@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id i25-20020a2e8659000000b0024c7f087105si141167ljj.8.2022.05.18.11.04.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 18 May 2022 11:04:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of jpoimboe@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 15FB0B82180;
	Wed, 18 May 2022 18:04:32 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 72E90C385A9;
	Wed, 18 May 2022 18:04:30 +0000 (UTC)
Date: Wed, 18 May 2022 11:04:28 -0700
From: Josh Poimboeuf <jpoimboe@kernel.org>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>, llvm@lists.linux.dev,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: objtool "no non-local symbols" error with tip of tree LLVM
Message-ID: <20220518180428.6yxf6tcqvzdvtfxb@treble>
References: <YoK4U9RgQ9N+HhXJ@dev-arch.thelio-3990X>
 <20220516214005.GQ76023@worktop.programming.kicks-ass.net>
 <YoPAZ6JfsF0LrQNc@hirez.programming.kicks-ass.net>
 <YoPCTEYjoPqE4ZxB@hirez.programming.kicks-ass.net>
 <20220518012429.4zqzarvwsraxivux@treble>
 <YoSEXii2v0ob/8db@hirez.programming.kicks-ass.net>
 <20220518161725.2bkzavre2bg4xu72@treble>
 <20220518172513.GH10117@worktop.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220518172513.GH10117@worktop.programming.kicks-ass.net>
X-Original-Sender: jpoimboe@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=aRY8v8BQ;       spf=pass
 (google.com: domain of jpoimboe@kernel.org designates 145.40.68.75 as
 permitted sender) smtp.mailfrom=jpoimboe@kernel.org;       dmarc=pass (p=NONE
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

On Wed, May 18, 2022 at 07:25:13PM +0200, Peter Zijlstra wrote:
> So while writing the global symbol can always use the new data section,
> writing the new symbol can need arbitrary iteration of the data blocks.
> 
> Something somewhat similar is when there's no global symbols, then the
> new symbol needs to go in the new data block instead of the old.
> 
> So it all became a tangled mess and I ended up with the one generic
> function that could do it all (which is both simpler and less code than
> trying to deal with all the weird cases).

Makes sense, and matches my post-bike-ride insights.  Thanks :-)

-- 
Josh

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220518180428.6yxf6tcqvzdvtfxb%40treble.
