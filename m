Return-Path: <kasan-dev+bncBDV37XP3XYDRB6VC6DXAKGQE3UJCF7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id B9EDF1092ED
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Nov 2019 18:38:02 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id 2sf58319wmd.3
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Nov 2019 09:38:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574703482; cv=pass;
        d=google.com; s=arc-20160816;
        b=JGbPwOHvZHbb6+XfKPqndGqpzZr24bTvcDHc8/NNMVt89u0TW+7pW9vHHxRPcSuyeH
         khx8Lot1DyB05RmrClIQj+2V75ijzNYupwfQRXLxxXhDnW1DJto3EvKooMgdHA3/a7FU
         vBswL+TA2z3j+KLCqNRRg44cLpPSgZCKWfeYXJxIPUhsPbVnp1lyKCE9S7v2kf/Y6bNn
         XoD7XKX2m8omWExPyzno3Xlk4wd+Je+niFljTgnYXFN9+cuzwh30oBnSuqlGmt0vmSAs
         9M+7RwKgkEEDTrsUmc7Wlrch/uk3nQXVqpvlyOzgKRN+sF1lCAM7Q5xRqpxcO2Lrq7CG
         niog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=0q2nAG/av8VN4yJWtcYrvLbcoWjgJD7eJR15Scsy1mM=;
        b=OQdgf3ey6vxtRS86CHgeSc4vGZOjwXvicJ/u1FMju280VTBBd+B376OkmTMrYD/yDy
         a2MkCaTzeMNN49U7pARI1/zc882NQCA+NMhDewTILLZhvhoXgzBUawOjbkzNrYe6bg4O
         sV7B25wvr7Ie7txOiuWlHkl/fXU7EWbDH7/XvZb//eX8EYnhZc7C2ywnXDE5lG5XTPhN
         LuUwoFWvmRh9ids8mg4NGqQ90Wd1L53SJMmSLMviMQykeH1fRP/fFMWyI7UQLOsRLBoi
         TelbEmlYncUoaMChaO49nBQX4PJEXOtjRjzVhkXb6ti3R9IGkOeIXRtVqYyc2swQGqZc
         nu/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0q2nAG/av8VN4yJWtcYrvLbcoWjgJD7eJR15Scsy1mM=;
        b=coxipDYU1lj2MCXwBAwkEiZsFnWZ8hIlPFypT3TOiV3JiycjbCgnLX7hB2Znqx4Yhe
         xTjAbURmPRQUjp8m+qmpDtjM7rvayVOrryiwTxVw+dMzLPvsBpY+/VRMgSXylr3fLYM9
         aFOjgXuerR69+2oJfRvvUm9ykiINx0ZoY4FFY3/Rk7aCHAXOC5z583l7/ouheShQbiGN
         q2fzWvtMd0H0oZNnOkTnw2UrUvFqkc0TLJTrxvXMd3SXWRoXBgPJCe0djQ+mqHgmGuKe
         heTTFOAdCcAZnothi7I+1yizEw1jY82g9xX3AA0zE9DpKnfMhOktivkedvc7IyCkb+/f
         qGBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=0q2nAG/av8VN4yJWtcYrvLbcoWjgJD7eJR15Scsy1mM=;
        b=UopGXNFdVAZP5O4Z5TK85oavqqjhb6vJxIDQPtP0vAAz5kgQ3vtNvbpYkPd6NdGSmS
         6CL23ZwQ5sZOGDQVIjMmpxZp2gvBeqWojLqSNz5ZPAyoMMV3O+Gyug71Jf3kCfIQJAqu
         TKM07yBnM+kvL/LYG2LBeHBLGIV8r8dpjKAcjhUaVmHxPO0vO+7TIKTvbFrSkBANzv5r
         SxoUBBMns1az5eamFdrVL8S6kTrK0mySpc6+mqiYgNVIAmsbwVNlzfjaRg9At2d/FZm6
         zy+LjASoTfFAcjpyOGPiQrOmyLn41QKeaVWboQ2WoCthRaKBr2N1u9uKgABmOnk9/sPm
         TOVQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVhejGeEmFQTerKgs+8by60OFcxcDwuG5fGjnZSOl4TzAmoRDh/
	C/+nsdlk8w7b3HmegbSn4Us=
X-Google-Smtp-Source: APXvYqz9fi6kQm+1gEchmVbbbUCrOGgCAhMJUafR+cJOCx7OSS1P8i6ZoGCBuDRm5pCSAeLe3Lo10Q==
X-Received: by 2002:a7b:c347:: with SMTP id l7mr52922wmj.48.1574703482396;
        Mon, 25 Nov 2019 09:38:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1b0b:: with SMTP id b11ls8739wmb.3.gmail; Mon, 25 Nov
 2019 09:38:01 -0800 (PST)
X-Received: by 2002:a7b:c95a:: with SMTP id i26mr11550wml.41.1574703481658;
        Mon, 25 Nov 2019 09:38:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574703481; cv=none;
        d=google.com; s=arc-20160816;
        b=yuXeL/21tr8g4v2DL7c027QURNEKnhEJwT8oDHiDR5iPIyM/9l1YI54URfiSoUBnaK
         xv3vR2DLSAHcjRV0x3UQSCB/FYU7bkNkbrKAfNiWVyy6W3YaaysYAlXNj5iY/ItjE/QC
         S/fDwTcVaYZcslmty5Hn5CrvK1J1HGiUO6nF6GkngFbWkFFCQ8Y/nG/u2IcIAjmuG17V
         UHvvOP37eDMMUHZgWuboyUSJ0BhHa56/TwgOF68FrkGatQY2e2k7QnyngAEvxpJd4q20
         Bir9BlJ0kjjEINFASrgWLTBPE2xh/3R+PbYH2mCT9XSoXutZ98SY3jq/3wLb+waEw/om
         6rMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=u4uYpXeUY9JSXEQwoz5yxP4Eh6c4EYuR/T39pmMgA+4=;
        b=t6xeTJ9k7t3jXIW/MIeSyXJJhxg5YP+JhWkSqsryXttBOQxTie8/dUYvzPVYJZrWKy
         RyWP+f9VgBA3QgUUbShW73547p5Y9n59oZ4nFMZ09zZyWpUE7cmnpa41MwOM5fLYFQUA
         dDL3zAgGXLtweIH2CCwaHt4KXUFBHBgkumg72BaBr1a5/wykrg/68CauIv9/Xz8MOj+i
         990TDBQocO4pQ9SDXBDhVIt5Pmg44+V2o7TOt1X0ewTHhE565aVG7uMuVZ3HtlKti2aF
         ecrHF4CFh9gxEoxZWqiPlJ0UVmN/LJzZBOXnJc4ybda23uNGlLnJ/YwCSisFOQ/SoDQJ
         qq4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id x2si354192wrv.1.2019.11.25.09.38.01
        for <kasan-dev@googlegroups.com>;
        Mon, 25 Nov 2019 09:38:01 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id E134731B;
	Mon, 25 Nov 2019 09:38:00 -0800 (PST)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 75FDE3F68E;
	Mon, 25 Nov 2019 09:37:59 -0800 (PST)
Date: Mon, 25 Nov 2019 17:37:57 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: will@kernel.org, peterz@infradead.org, boqun.feng@gmail.com,
	arnd@arndb.de, dvyukov@google.com, linux-kernel@vger.kernel.org,
	linux-arch@vger.kernel.org, kasan-dev@googlegroups.com,
	paulmck@kernel.org, Randy Dunlap <rdunlap@infradead.org>
Subject: Re: [PATCH 1/2] asm-generic/atomic: Prefer __always_inline for
 wrappers
Message-ID: <20191125173756.GF32635@lakrids.cambridge.arm.com>
References: <20191122154221.247680-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191122154221.247680-1-elver@google.com>
User-Agent: Mutt/1.11.1+11 (2f07cb52) (2018-12-01)
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

On Fri, Nov 22, 2019 at 04:42:20PM +0100, Marco Elver wrote:
> Prefer __always_inline for atomic wrappers. When building for size
> (CC_OPTIMIZE_FOR_SIZE), some compilers appear to be less inclined to
> inline even relatively small static inline functions that are assumed to
> be inlinable such as atomic ops. This can cause problems, for example in
> UACCESS regions.

From looking at the link below, the problem is tat objtool isn't happy
about non-whiteliested calls within UACCESS regions.

Is that a problem here? are the kasan/kcsan calls whitelisted?

> By using __always_inline, we let the real implementation and not the
> wrapper determine the final inlining preference.

That sounds reasonable to me, assuming that doesn't end up significantly
bloating the kernel text. What impact does this have on code size?

> This came up when addressing UACCESS warnings with CC_OPTIMIZE_FOR_SIZE
> in the KCSAN runtime:
> http://lkml.kernel.org/r/58708908-84a0-0a81-a836-ad97e33dbb62@infradead.org
> 
> Reported-by: Randy Dunlap <rdunlap@infradead.org>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  include/asm-generic/atomic-instrumented.h | 334 +++++++++++-----------
>  include/asm-generic/atomic-long.h         | 330 ++++++++++-----------
>  scripts/atomic/gen-atomic-instrumented.sh |   6 +-
>  scripts/atomic/gen-atomic-long.sh         |   2 +-
>  4 files changed, 336 insertions(+), 336 deletions(-)

Do we need to do similar for gen-atomic-fallback.sh and the fallbacks
defined in scripts/atomic/fallbacks/ ?

[...]

> diff --git a/scripts/atomic/gen-atomic-instrumented.sh b/scripts/atomic/gen-atomic-instrumented.sh
> index 8b8b2a6f8d68..68532d4f36ca 100755
> --- a/scripts/atomic/gen-atomic-instrumented.sh
> +++ b/scripts/atomic/gen-atomic-instrumented.sh
> @@ -84,7 +84,7 @@ gen_proto_order_variant()
>  	[ ! -z "${guard}" ] && printf "#if ${guard}\n"
>  
>  cat <<EOF
> -static inline ${ret}
> +static __always_inline ${ret}

We should add an include of <linux/compiler.h> to the preamble if we're
explicitly using __always_inline.

> diff --git a/scripts/atomic/gen-atomic-long.sh b/scripts/atomic/gen-atomic-long.sh
> index c240a7231b2e..4036d2dd22e9 100755
> --- a/scripts/atomic/gen-atomic-long.sh
> +++ b/scripts/atomic/gen-atomic-long.sh
> @@ -46,7 +46,7 @@ gen_proto_order_variant()
>  	local retstmt="$(gen_ret_stmt "${meta}")"
>  
>  cat <<EOF
> -static inline ${ret}
> +static __always_inline ${ret}

Likewise here

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191125173756.GF32635%40lakrids.cambridge.arm.com.
