Return-Path: <kasan-dev+bncBAABBKOE77ZAKGQEGSYNSPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3a.google.com (mail-yw1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id B3F9E17967C
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Mar 2020 18:15:22 +0100 (CET)
Received: by mail-yw1-xc3a.google.com with SMTP id w185sf3354111ywa.22
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Mar 2020 09:15:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583342121; cv=pass;
        d=google.com; s=arc-20160816;
        b=kh3wErR8A5O1ACWacIGdLFTxuQt6jo9NLGm91+1GjgsR320yA/ldKZSsJA/PmrTt5h
         Mnhq8A3DsgohP4bYlNz15a9u6eha80iIZi/MfpPEufyAeSMFSMlpfq3euUA+09cvILLc
         xHesVdzZUzdHnzFanHdxXvh/eh3yjruOS2kOy7jetEEXdDxCJcNRbPJk+AGODZz2Eo7y
         g6moWFumnNF7zIDWtjZZAyfClD3QfTjReb9SzDE5KsYWJABpfNekhwB1eI994VtvUpdz
         ucdtxlRyqb77ZmufcwgSEme/9YFIVs2L5UE5EmfgYUc0o7vgdgnjSFHSPdhC3BxQNxho
         cKQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=UdQ29Y3FITdqBE531blrJEbJvwC1z8Ud2MozlrkDQ8A=;
        b=rgkIfZ/q1bpPhf2s9Ivr8V9ptNeb2Izi2S5sgFH1vVIo1+g24qiLkaYraA+rjeQ4Kp
         5HUEJLRRYEiFHhbH/NAyPI4xaXUKGTQvgAnK35pB8RvopL26+0P14UyK1ei0FzX/HKTy
         RK4E3gqJ/6RRJU7Iuor593JZudbEHcOUxeOkYxaAMJzgcwJuPpB5fRjrsvT0AHfRLoxJ
         Jk6n19J7GIMFYVTrLC55MoD+MMjxcTckxxqu7RihMi7jakuAvXKcxg686wvinrvwWXnn
         FVbPmEuTTC3gaDGgkCmzWMCporSO1u+UBEvgvo+aLGIfD5xdw8lWFNzA0FQYi+wTE+/l
         L6gg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=xDxCJ2bv;
       spf=pass (google.com: domain of srs0=usjb=4v=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=UsJb=4V=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UdQ29Y3FITdqBE531blrJEbJvwC1z8Ud2MozlrkDQ8A=;
        b=WTQdPf18RGGJ/z/MuUcFSiji2MKyZl9Ht5rezEOkxEc1L9g6zccf7Xm1s9A7LZfIwr
         OAveJuCmqmUGAj6b83/8X4axna1eZfxYUmO7NTfnvCNcXaKgFwgzBmgrYfqDoO97DAyc
         2ag62RGBdHAXDEIlIycr5o6UwwVaJ8DD+bzqMedqDB94rAzlOxcOF7GbboB3XpJz6Pz+
         Lu+nOSjEeQLHhQeekFfnCvPl3D9uOb3JK9/UCeVOQNfrno/SfgLSlGiaZoivRGO5CKJ8
         zDFVX6bkqzrxfnvBn71J/L8YLN6w0k7lR4X/kAEUf/z3T887g8IGq3OqO/90AvZLwHCL
         xMNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UdQ29Y3FITdqBE531blrJEbJvwC1z8Ud2MozlrkDQ8A=;
        b=U+8dhTDxnFRMWHh7Owy+xV8Kcj3xwb/D/TXWIQ7NN3vMQNrNdY9WmKyqLOhHCj+wM5
         XSd1qBW3tA+ZU3LDS96TLURJ7jvdYmC49aEG5pYhvNYZlRlm/meCXiiC3e/Rfr9jrg3d
         SuyMlu3aAxYexkUWLEEG/C8RpV5GUuunBm09+09DTvRawhno5pKh/Rh+PGF8VLZCA/v9
         vm3SqkyQ9tFFU7Q5B35nfa97y3J7ErORaStXKuO8URxW4Qf/eYi4ueDRiYlTN3fkRduA
         pHTFVLJcgqQLwVvzZ/UgA35jyCxsgCLGCXfZKNFHm++ltFPESdwjC2QFM0sMPwR5u/2i
         Vsfw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ0eRpaKLbrsf1nnrMgsFrqbwdJUbz7VyA+/lpgXzMYAIyyWQiln
	p1yUJqTMl4jpiBATGnMitnQ=
X-Google-Smtp-Source: ADFU+vvN2bDqS2wR89JKLao/YwKc4eIsLjnKM4LD8o208FaNUjxZo48jpFpI2pBL0pN13DoLFZD2bg==
X-Received: by 2002:a25:6a45:: with SMTP id f66mr3425739ybc.63.1583342121390;
        Wed, 04 Mar 2020 09:15:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:d8d3:: with SMTP id a202ls603807ywe.6.gmail; Wed, 04 Mar
 2020 09:15:21 -0800 (PST)
X-Received: by 2002:a81:a115:: with SMTP id y21mr4131872ywg.47.1583342121036;
        Wed, 04 Mar 2020 09:15:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583342121; cv=none;
        d=google.com; s=arc-20160816;
        b=HT2UI1tW7MkedH6SKUTXEkB59uk+SBPBY9hiPXpaOXs3wPmQyFhzaY6ubVXmXk0LIt
         Ts8qeS9dQ80UOYsZV9L4ryfa1j6WwpOoWkhESYzFyeytcGVx4Ycj3e54oNRZ9JPeAX+D
         M8sgnA15l3+C60ndI29j5D+VpfH4+at1q4sTDT+XBj+qxZmlrBpwASkbUkMg82dtvoDf
         B9uU76FVidOG9aoEROYmfs5HlWg1BvZqUVrGc7otuMzqDpAYWqOfL06TqRdv/+OZGUuQ
         vKsIlp5+gADpWefXfG5cQefaH847VpP21m7uZ1S1cPYNEFPxtL3mrXnWBV/UL5/d9Tbd
         u5Vg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=14bbCC6sh2T2skx+BHNLh6iVePbX59fZCtHGJxnfEf8=;
        b=H3ooPbYKYKZQmt3CaRsbwKsyAdTRZGYqqqPDSLQeZ0VG5pQnWxn0ofHXs88sge/WXy
         wZJx09TSJjXfsqr3KY3h0O3lUSoQNMocU9iXCnzcvjS0LSS3VzrzJWJwEZHA9ftnUsLm
         Lz2htRvG/g142URtCbahHyEu63kjTxLMfsjwFa5HvnRidbzwYApVMPvESMzXliDmPSCc
         2sAj5mfxyi8dp6KxRzM3Tm6XU2En6imBUlNCm6xb1eeCg17A9Tq6rSaFmlPEFa2TbWve
         4+Su9dITPYXG4W1rVfj6LR4Uo1tcIrHOm/G3iImRhCzc6RlFR4MNFdkGHN+JpXg9hkav
         qzbw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=xDxCJ2bv;
       spf=pass (google.com: domain of srs0=usjb=4v=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=UsJb=4V=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id s8si164497ybi.5.2020.03.04.09.15.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 04 Mar 2020 09:15:20 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=usjb=4v=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 0C9A320717;
	Wed,  4 Mar 2020 17:15:20 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id D9A4F3522731; Wed,  4 Mar 2020 09:15:19 -0800 (PST)
Date: Wed, 4 Mar 2020 09:15:19 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: andreyknvl@google.com, glider@google.com, dvyukov@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	corbet@lwn.net, linux-doc@vger.kernel.org,
	Qiujun Huang <hqjagain@gmail.com>,
	Nick Desaulniers <ndesaulniers@google.com>
Subject: Re: [PATCH 1/3] kcsan: Fix a typo in a comment
Message-ID: <20200304171519.GB2935@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200304162541.46663-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200304162541.46663-1-elver@google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=xDxCJ2bv;       spf=pass
 (google.com: domain of srs0=usjb=4v=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=UsJb=4V=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Wed, Mar 04, 2020 at 05:25:39PM +0100, Marco Elver wrote:
> From: Qiujun Huang <hqjagain@gmail.com>
> 
> s/slots slots/slots/
> 
> Signed-off-by: Qiujun Huang <hqjagain@gmail.com>
> Reviewed-by: Nick Desaulniers <ndesaulniers@google.com>
> [elver: commit message]
> Signed-off-by: Marco Elver <elver@google.com>

Applied for review and testing, thank you!

							Thanx, Paul

> ---
>  kernel/kcsan/core.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
> 
> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> index eb30ecdc8c009..ee8200835b607 100644
> --- a/kernel/kcsan/core.c
> +++ b/kernel/kcsan/core.c
> @@ -45,7 +45,7 @@ static DEFINE_PER_CPU(struct kcsan_ctx, kcsan_cpu_ctx) = {
>  };
>  
>  /*
> - * Helper macros to index into adjacent slots slots, starting from address slot
> + * Helper macros to index into adjacent slots, starting from address slot
>   * itself, followed by the right and left slots.
>   *
>   * The purpose is 2-fold:
> -- 
> 2.25.0.265.gbab2e86ba0-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200304171519.GB2935%40paulmck-ThinkPad-P72.
