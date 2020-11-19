Return-Path: <kasan-dev+bncBAABB4GQ3P6QKGQE6PESQSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x937.google.com (mail-ua1-x937.google.com [IPv6:2607:f8b0:4864:20::937])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BAE42B9D18
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Nov 2020 22:49:37 +0100 (CET)
Received: by mail-ua1-x937.google.com with SMTP id v17sf796045uam.23
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Nov 2020 13:49:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605822576; cv=pass;
        d=google.com; s=arc-20160816;
        b=gs1kjo49PDD8q3VIuckEmXFefY5CPWWnpYjgUnmmi171xpN+cfDa11F3PMlu06eOBf
         q8Bv4efQYmH8yS4VPlAMhd0/joSdSSYdnASptSxW/k2TH/1eOlJ5xqYOJ1QfBvKwcfbd
         cTEuvBFgZBXVyRIq24+bBiSGjTJpZy3/cqCk5lunWhREICjFadsHp4udj1lX/LMer6pj
         LG6IYcv7XPBhheSU4Mtaf83wA3k5zPfA7bge2r5P0UebVXJNZzUdoCpWtjIhh3QfZHlp
         inXINV3apmpcxtroFGeUWkRnuijZgU8LeVC6EETsxc5hmaU0v26GA8V1Z25YwCEJ3va5
         4dtA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=6N8Qy27kvy9yz1UzBYQS6a+tDM2RtEcsxq4sPwvdH7Y=;
        b=OLaHb+C0AWSvNQj85m2gdV1YszH6WSj3msrZBAKFUq6vnyxvgzJO+LjW1Pz4Gn7yH7
         h2z6tRBXjTN+eNgCgDdsJF0peXUwCP9x3UPxJt2nnf2kS/ZjTP5AgmLPnIkvNNL2U68K
         hRxKLUnyQHOeIMULvxztBnU6ThzK97Tjk7no9N/Be0wvQNtfytykt8unlpRwdHN2OMwQ
         +LPhu94TvfSJaaz1CBD9zgDWVjt1Sed5zywszHMzLRe22EoYGZyYfewp1i1YqYSaRugw
         rqZbkJw4ALU4mm+EjS3fU7CuG4bn9gaj14HjZP6QnRr0jbkBib+k9qYl2p/GjKcN7kHK
         Ekdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="GLC/r4pk";
       spf=pass (google.com: domain of srs0=8ov6=ez=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=8Ov6=EZ=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6N8Qy27kvy9yz1UzBYQS6a+tDM2RtEcsxq4sPwvdH7Y=;
        b=c2CYW3YonabINtr1pr/kPWsy9vy9/e7wM1z51eL58knEdgQM5cz4Dr8vNIq1jO83Yf
         f8G/WCozBBomGEujNhZEJgZUsZvtV/fHTXI1ILYFws8KBqod5Y8SR6VTI4lBccn3P+Ot
         9IJCHOwPUU0tq6AmPvR2gDEqorqkeTC/xw+emOhvjsZpIFCaI4u/IgaYL2V6r4+nVL7S
         u+p7YG7bS89CvVOdEH7TeR7+H0Fo3oh91cP6bn9vAzpY2hoW2y+Y9FC9vuroDNTX2wBt
         +LB+kaFxyr9/F8gfUk62ps1i7TH8MeN8pKZTxLw9T9Gh2yAyOSdM0BUWzEpmTAadE+3u
         oOgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6N8Qy27kvy9yz1UzBYQS6a+tDM2RtEcsxq4sPwvdH7Y=;
        b=MepTF+D+Ppe+93U0n88WMEZVGimeBYSm+R8AylxRrtmTgK0RmGFDOEd3vVgbCnPgfl
         ZOor1oHa1PnQ56in4TY9Asy40EwapaYK7c5Dm19cP/h5MD0F1sV0zmnCqqvBtb+jOrdi
         KSQFftsVybGAoYsGL3w0GKJX0kdmb7QazQLpHvrvszbjxep0b0SxBmQgGDkD/G03E3qR
         8LKZCKCO2dfyMpBJAYdF/6mLSuYW3/IlyRzNS1Yc6YkZ0FpQmbruxoPGZraVk9Sf1H0n
         pM8BbJq/j0p0J9X8gscKWxUgCPPY6ydde2+EHys2foWloUyUFKOPE1U+my5UabTzx7GL
         Bybw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532x1/KULVEd3i/CAsuqpUKcXWcYwByhBNAO2PoWzOOleShxF3I1
	rjGLmkF3YJ56Vb/MxRkrs00=
X-Google-Smtp-Source: ABdhPJz5wB6Ad1PkZCfyu3vozH2OtO+299zZRiv41m1EUcBc5ZXkYrQvWU4uW4PiTxaXGCpOEuo+0w==
X-Received: by 2002:a1f:2817:: with SMTP id o23mr10583165vko.2.1605822576281;
        Thu, 19 Nov 2020 13:49:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:fe43:: with SMTP id l64ls290404vki.6.gmail; Thu, 19 Nov
 2020 13:49:35 -0800 (PST)
X-Received: by 2002:a1f:3257:: with SMTP id y84mr10347851vky.8.1605822575810;
        Thu, 19 Nov 2020 13:49:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605822575; cv=none;
        d=google.com; s=arc-20160816;
        b=JnMgn/J8S2xs5uIZx7L4arHNyOhG349DXzxZNPreJOEtvfYclsdsyHZmuRsmN1gWrc
         PW/D82PWaMCCkxJintEPEZgyPZpfmD7g4qDNaBTTNRzz8a2z6nihIxo+9lH+15YUwT5N
         WBoDcycDFIQY6GogmWSkcPUpfqD4e5x85ulcRQcbX/dxI75G2qNJ7L5515lOmRDttZZz
         hcxDtTPLVfaIRwEpA4uM3zldclvgAPyWN/cVMDJAqavHAsWXsJyeM6IVgtxTIYjkdiSR
         fJwpGYZecZG/6PTNK/dBwybanS0uhUV723vtEfToLeAfpfuxNu2/TJ/WGdxX9gDUpi6s
         4MjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=zPoaUmhviZW+SAz8eVYYYyn+bF9rRXQTMGeLRCxNeLg=;
        b=z7SSzy1ZmYZ61Ocd1ha4TZ7+WMAAS6tAvbZoD8CRrG1to4nG3zaqO6qfUoN+A08F7U
         UthSnlgqxQbKnbaNKdTwRNG/nDBy4QIEt+HryPlaL1L6Y6jI5mKdEk4zQ2x22qI2DL3g
         9rqADbPwBkhd6MSD0JYJeW0/I1yQSczl0r00L7XPvYSYpVNgp9XqLaKG4Yo7gPgLB1Vc
         sd9pnYKKKefxs+bTUdPcaQ9E48MNxbBmADHsYcp3i21+dqZX5e2rOSOh2HEsUo6/cwB7
         JjGoAX59td2cy6c7MYhQx1n30gemmUy8aKneGCPZjHDqvZV7lt2F+ilBDolbydmCwbd3
         hl9A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="GLC/r4pk";
       spf=pass (google.com: domain of srs0=8ov6=ez=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=8Ov6=EZ=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id c124si113392vkb.4.2020.11.19.13.49.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 19 Nov 2020 13:49:35 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=8ov6=ez=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-104-11.bvtn.or.frontiernet.net [50.39.104.11])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 7E76122202;
	Thu, 19 Nov 2020 21:49:34 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 18BE135225D3; Thu, 19 Nov 2020 13:49:34 -0800 (PST)
Date: Thu, 19 Nov 2020 13:49:34 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: qiang.zhang@windriver.com
Cc: josh@joshtriplett.org, rostedt@goodmis.org, joel@joelfernandes.org,
	rcu@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, urezki@gmail.com
Subject: Re: [PATCH] rcu: kasan: record and print kvfree_call_rcu call stack
Message-ID: <20201119214934.GC1437@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20201118035309.19144-1-qiang.zhang@windriver.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201118035309.19144-1-qiang.zhang@windriver.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b="GLC/r4pk";       spf=pass
 (google.com: domain of srs0=8ov6=ez=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=8Ov6=EZ=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Wed, Nov 18, 2020 at 11:53:09AM +0800, qiang.zhang@windriver.com wrote:
> From: Zqiang <qiang.zhang@windriver.com>
> 
> Add kasan_record_aux_stack function for kvfree_call_rcu function to
> record call stacks.
> 
> Signed-off-by: Zqiang <qiang.zhang@windriver.com>

Thank you, but this does not apply on the "dev" branch of the -rcu tree.
See file:///home/git/kernel.org/rcutodo.html for more info.

Adding others on CC who might have feedback on the general approach.

							Thanx, Paul

> ---
>  kernel/rcu/tree.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
> 
> diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
> index da3414522285..a252b2f0208d 100644
> --- a/kernel/rcu/tree.c
> +++ b/kernel/rcu/tree.c
> @@ -3506,7 +3506,7 @@ void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
>  		success = true;
>  		goto unlock_return;
>  	}
> -
> +	kasan_record_aux_stack(ptr);
>  	success = kvfree_call_rcu_add_ptr_to_bulk(krcp, ptr);
>  	if (!success) {
>  		run_page_cache_worker(krcp);
> -- 
> 2.17.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201119214934.GC1437%40paulmck-ThinkPad-P72.
