Return-Path: <kasan-dev+bncBAABBY5Z3X6AKGQEXQLKXWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa40.google.com (mail-vk1-xa40.google.com [IPv6:2607:f8b0:4864:20::a40])
	by mail.lfdr.de (Postfix) with ESMTPS id F0CC5299A8C
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 00:33:56 +0100 (CET)
Received: by mail-vk1-xa40.google.com with SMTP id g80sf4267301vkg.19
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Oct 2020 16:33:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603755236; cv=pass;
        d=google.com; s=arc-20160816;
        b=b9NDovEyiEd5Fd0Hk5g8OrlU5NeHdbcEk39WfFUc7Ls0CVRifYi5ngANRf7RCeCyED
         Bxu5M06JDlNGOA0CXYogsLklBSA9DE87DGA2DfHga/jh5Ou0Tc7rr8m10UYIXsdf6aiN
         LAfoF1fcsF8SbfCsk3yhpbXww2PweuImK7Bt+pbYb2tbtSUDr6304JHZrXq9WghfwFa+
         OT8RBVAiCqjesje7ckudFvahuB3kBvDpmTluff85X6VzzhN+jMehkQXV+iUNjMnZm+s8
         lQ5e8v9hB8+K5xjsrrQDWAelSBEC5HHUaFv2+1Z5TndKJVh9T/Zb5tgPkWy5qZ5vrceQ
         8J9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=ZGmOA0ImgON86/yaeWRWD3yyGkTirfEn4THZS95KXqI=;
        b=XGOBcop80LZALYpY3STq3iAlp/ETpFYa3Ba5po3b4A3MFBxpflSAYC7T8uH0sJDtNM
         75gvlGtb0QdN1RxMfuoajhqr25lRx0lA68Q3lL+zyYixz1ViNuRusyM0B5aLFf0Uyr7q
         mnpn5lubNQn42lpPi6VH3QjBjIaUCGSIuoo5t9jj0//dxKVXQMa7RzNBhx0V+a/vm26R
         PaoELe6R9txwBMgOt06z3+INvlBaHMhaNBEElTL2BDYPyYOV24I31/AkJv2ZkpDfBGD2
         e+xsRSxs6lxxTptd3pswTRoArWfSZ9gzHg63rPaTy4BsXIP/nlhnbNY/FOfgecO4KWdI
         8ArQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=yr68WEil;
       spf=pass (google.com: domain of srs0=pox6=eb=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Pox6=EB=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZGmOA0ImgON86/yaeWRWD3yyGkTirfEn4THZS95KXqI=;
        b=gKf+rC+Lhqq1PsECIFmWnkOjKvy2g1/CYiMxW6vyyYqtZVKy7WxxsCpEvu1A8sZH+B
         rA2GTUg7/rFoBn2uuOjAuvvBm6hA18Y+cw9sSo5U1sozQYIhysoyt3wOG+unob2P+w7w
         RV7Xgf/6FdtHhSJuN4UXo177wJhU4jXs28xIJ6zhB/+zmWRsBw2fj8JPmRxpMxHaB06R
         YY/DxUGZT+6o/MhA29O0Xh5h3LQru8on5GY5sJBY3zPT0mPbicfTrD0FprSD0r0ziPux
         bpygbMXzePmcarIPZqT2z1hA3qodTdAn2zTyxs7eQkqqexrwlf8JmyDFwamV/6qQUak2
         m3+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZGmOA0ImgON86/yaeWRWD3yyGkTirfEn4THZS95KXqI=;
        b=U++F4Vgbd9Sw+6LZfIjeYesAaeHz7TNZHm9rusGHa5MQKPDvo5SHLlC9iisw2ApALM
         ImwhdgUGE9GiCvPW6VPbbmJS0Pabxpl5iEBN2lAxLdLjhU4vNr1U0Ss9ky4Ewr+jRJX8
         aJLnGcU6nj4knWmTym++Rh2JMtdyeOJ/A8xqzj+d3XovdDz/ZQybMv3/cHqF2L7z1LKj
         7/Z/VaICIs+Fzq+7MYN/rbL/hCDXSdogutneihQ7N9SA3SuzRVEugSkKeybl3lYa5IaX
         uF5ZbG2FHApbtHYEABt6mEEAMKVAt4XtLceIK+hcM2TvH1FAx2+gvlNxI1xNczjM7q9T
         b/pA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530CTXvPFFBCgvvHzAX5DU5BwgpUASkYBtprTqicsMJ16UtU/qqj
	MX9I5ooF5cqdrxZD4sxxr3I=
X-Google-Smtp-Source: ABdhPJxhozB2DNnD3EgVaZ9RGwtIIiONKRQMjnA+KTlp6NLrdDhHHm9q+39NHyt/Jtd/5w6zkM0LqQ==
X-Received: by 2002:a1f:2817:: with SMTP id o23mr157320vko.2.1603755236045;
        Mon, 26 Oct 2020 16:33:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:5adb:: with SMTP id x27ls681362uae.1.gmail; Mon, 26 Oct
 2020 16:33:55 -0700 (PDT)
X-Received: by 2002:a9f:3661:: with SMTP id s30mr22907507uad.73.1603755235594;
        Mon, 26 Oct 2020 16:33:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603755235; cv=none;
        d=google.com; s=arc-20160816;
        b=M6kcHYAhYxSVpV4g4/uAd4/T5itZwzKzuC7SthFG/18p+ceI14bbDp0ngjP//MOsnU
         sT2sk73HP6WOFX3bCRc8y8jfiNZcTjKroYUe0qx+s0KLtJma2VMOSLhLJ5Pv98pyER+z
         jfevO6ZWqSUx6IsjoUE0vB+U9lvrNa2mbEOq7KC7MnIhtr9++hu5CU8An/NM1aOQ6JNw
         PCR1GWdLWVx1ANsgbzYRCW4R6ftw73xhVBuYHefIpoAyfkAXjs75WfZseWMV4gS6Mb7w
         pJnbSgRvNivR6eWpOFlsjS/EJMTbCr41U7ciOCj0TFFwIDYf5q4QtqEiepzRwkf8HmAf
         w7TA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=SssQjffg/hvN2tNuKtodd/OHk+oDy2UwNBWdXZxhgwA=;
        b=UnF653lzUzGcmK+UyvPt2/2Q/mcVAriCda3q78TwgS7AoEyVYbl3xr8KemHbzGDjXb
         lOOFmsowlkWvO44uS/zfhI4xzla3xKT4sraxNccDJ6XPP7NgYYTCNy2x2l4utsoEcsf5
         5GbZ2/mA83eTxfmyAjJ2NggjwvWrcVUwSegw42fVkomIdve7NWzZC7zvXMnwfmIl1S0j
         4uF64E+/V/q851oH2HntuxXZRNfWUCFoTtzfLLbe6JcI9faDwgfRfALvPbCcW1GTxrso
         qYtUl+SqkTc99ys4SrkzDPAQhteG4joDob2doFd8vWzJ+e312aazQo9YKfoKnQk3GFxs
         oSeA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=yr68WEil;
       spf=pass (google.com: domain of srs0=pox6=eb=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Pox6=EB=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id b16si804472vkn.5.2020.10.26.16.33.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 26 Oct 2020 16:33:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=pox6=eb=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-104-11.bvtn.or.frontiernet.net [50.39.104.11])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 770AB207F7;
	Mon, 26 Oct 2020 23:33:54 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 41A9135226C8; Mon, 26 Oct 2020 16:33:54 -0700 (PDT)
Date: Mon, 26 Oct 2020 16:33:54 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: mark.rutland@arm.com, dvyukov@google.com, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH] kcsan: Fix encoding masks and regain address bit
Message-ID: <20201026233354.GV3249@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20201023121224.3630272-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201023121224.3630272-1-elver@google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=yr68WEil;       spf=pass
 (google.com: domain of srs0=pox6=eb=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Pox6=EB=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Fri, Oct 23, 2020 at 02:12:24PM +0200, Marco Elver wrote:
> The watchpoint encoding masks for size and address were off-by-one bit
> each, with the size mask using 1 unnecessary bit and the address mask
> missing 1 bit. However, due to the way the size is shifted into the
> encoded watchpoint, we were effectively wasting and never using the
> extra bit.
> 
> For example, on x86 with PAGE_SIZE==4K, we have 1 bit for the is-write
> bit, 14 bits for the size bits, and then 49 bits left for the address.
> Prior to this fix we would end up with this usage:
> 
> 	[ write<1> | size<14> | wasted<1> | address<48> ]
> 
> Fix it by subtracting 1 bit from the GENMASK() end and start ranges of
> size and address respectively. The added static_assert()s verify that
> the masks are as expected. With the fixed version, we get the expected
> usage:
> 
> 	[ write<1> | size<14> |             address<49> ]
> 
> Functionally no change is expected, since that extra address bit is
> insignificant for enabled architectures.
> 
> Signed-off-by: Marco Elver <elver@google.com>

Queued and pushed, thank you!!!

							Thanx, Paul

> ---
>  kernel/kcsan/encoding.h | 14 ++++++--------
>  1 file changed, 6 insertions(+), 8 deletions(-)
> 
> diff --git a/kernel/kcsan/encoding.h b/kernel/kcsan/encoding.h
> index 64b3c0f2a685..fc5154dd2475 100644
> --- a/kernel/kcsan/encoding.h
> +++ b/kernel/kcsan/encoding.h
> @@ -37,14 +37,12 @@
>   */
>  #define WATCHPOINT_ADDR_BITS (BITS_PER_LONG-1 - WATCHPOINT_SIZE_BITS)
>  
> -/*
> - * Masks to set/retrieve the encoded data.
> - */
> -#define WATCHPOINT_WRITE_MASK BIT(BITS_PER_LONG-1)
> -#define WATCHPOINT_SIZE_MASK                                                   \
> -	GENMASK(BITS_PER_LONG-2, BITS_PER_LONG-2 - WATCHPOINT_SIZE_BITS)
> -#define WATCHPOINT_ADDR_MASK                                                   \
> -	GENMASK(BITS_PER_LONG-3 - WATCHPOINT_SIZE_BITS, 0)
> +/* Bitmasks for the encoded watchpoint access information. */
> +#define WATCHPOINT_WRITE_MASK	BIT(BITS_PER_LONG-1)
> +#define WATCHPOINT_SIZE_MASK	GENMASK(BITS_PER_LONG-2, BITS_PER_LONG-1 - WATCHPOINT_SIZE_BITS)
> +#define WATCHPOINT_ADDR_MASK	GENMASK(BITS_PER_LONG-2 - WATCHPOINT_SIZE_BITS, 0)
> +static_assert(WATCHPOINT_ADDR_MASK == (1UL << WATCHPOINT_ADDR_BITS) - 1);
> +static_assert((WATCHPOINT_WRITE_MASK ^ WATCHPOINT_SIZE_MASK ^ WATCHPOINT_ADDR_MASK) == ~0UL);
>  
>  static inline bool check_encodable(unsigned long addr, size_t size)
>  {
> -- 
> 2.29.0.rc1.297.gfa9743e501-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201026233354.GV3249%40paulmck-ThinkPad-P72.
