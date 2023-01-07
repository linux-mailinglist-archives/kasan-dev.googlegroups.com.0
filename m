Return-Path: <kasan-dev+bncBD7LZ45K3ECBBMEY4WOQMGQECSP4IWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id E9B3E660DF7
	for <lists+kasan-dev@lfdr.de>; Sat,  7 Jan 2023 11:40:48 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id p34-20020a05600c1da200b003d990064285sf4088015wms.8
        for <lists+kasan-dev@lfdr.de>; Sat, 07 Jan 2023 02:40:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673088048; cv=pass;
        d=google.com; s=arc-20160816;
        b=fT6RAgY8OD2VNZnEw215yO2RohqB3gTnOIXtelg1BXMG+dRGxDzvDDUqwyuW2dysDg
         N5qc+0D63myjiwg4kbUGwKSoVoJTFwZ2mXKuc24Sgbia5ZIofEAZyVVsfIb+I2nSt3qv
         dUE4Zrtx5/SF94jw1y6cslPeL3rb8H8aYrbQA9U48smlNq+t4mIwXJgO+yTZXKcviBOL
         VNMQqMb6EJB/NbQsl7VPfF6D4HHHvbgmy7La8stC4oA7kjYcaGDsWpKTT0vCC349+SQd
         8Rc+E7G9wIsBKfU3GRTmHkFbcNGZ7dKWcM1olMd+TPDzB4rh05JnmQ2WKzO2FdHRIklw
         +fBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=vUFXX8N5W+ebzEgFwcv0jL2hzyc2YycljA1nXVts9zM=;
        b=A3v8uYST3kXiOzYNpx65WZED7UFMSEWTO836yXfMBl/j7J8+5yUwRwjUZugwWdJwsZ
         4uao767kMqpPXDVe+m3bodaMrgYnaRuBOVo8ztJM1DmbU5WimOcT7+TkvDhqqiLkmoqj
         um4HPNbjFDvJmzQ7iVMRGp2PLwtQEdMEnGwN6cOwyiFlHHAH/k4wWPzaby4bFycX58x2
         CxUlKElxSn6ph/KixntFf1Cbf1EzUbV7HNnE3H6aMYP2+vrTBFyUew89eAq0JY0aJqtm
         AuQ2FZX9/ZWpUYj2xL+IZpSj+5a/Gva8/f+rc3oXa1MdrO5ogURG0j7UtMG+del2pbGj
         sJ1Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ZLxygyA9;
       spf=pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vUFXX8N5W+ebzEgFwcv0jL2hzyc2YycljA1nXVts9zM=;
        b=kocVuQofrAoAXf8aKAwwP/3goFhWqiM8mdEhlBEn09ho3g92KjUq3JM9KP5QUC5Ftz
         F43EaSfojPuLDGNnE1kHEwbPjaalSAaAirIM3odSXHZLrLbKTKSXHefo3mVB8DDxiS4c
         HXK6u5g3jZspOhDI5QjsAGuEhzrC4jl/yYdEwXGvMjiF2cGRwdUCWEKca0tyu+hOq/rC
         30WJsylNlRuiV0hXI0Q1iMZ2XaXq9M/PUDiIw/gN+t2icwTKBrdiBwsQZRhhUSk+/bhN
         c3yP60vFZVfrWKAvxDZIbdBwQFaSsMoL8FFUEARYishYpuDj6W5nehZreZ//Uysx96se
         HalQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vUFXX8N5W+ebzEgFwcv0jL2hzyc2YycljA1nXVts9zM=;
        b=0OhdU42FXm9U62s2pUiiuYNdRw2f02vAF37aTwXPfz1ab5LKWZ/gp7y1jsNCqVEUuf
         POUtdyp8Ikh0PvS4kHh1u8NbCZMs2yGkf9NloSJY54n+0XBX0h9f5S2jAhsvn1sKbZUA
         Ttdt21cPKuYvjF8HijMhfCNqXUc88BYzewc6F2VHAEp5myfhviPW2N8EZ6KZrJoM1C1y
         tXombyJn6A+PQgs1jS+54fhwz0nTe0UrDJGb8cL/Lxys4K3eYmRGBx9sNoH64FBO4gy9
         qtTiQTxtAmCIK4uEckwydI/uR8f/AmjiurkdLc4g7Uvsdl63NuYRQq/FpwLSN+kv+mW8
         KrDQ==
X-Gm-Message-State: AFqh2krdNzrGRAHB6M/FjXfSOaxRB9iUoORGOq8py51OVC56o6fctYCw
	7y5tZUtDQmJRneOoG9wwBXU=
X-Google-Smtp-Source: AMrXdXvQ1xgFEUByVlV9LLtES837BTN5m3rNXO3faQbG8DkMfXyRunve/sVyLtw5pFVDCxory7sfSQ==
X-Received: by 2002:a05:600c:283:b0:3d2:1798:8223 with SMTP id 3-20020a05600c028300b003d217988223mr4198697wmk.49.1673088048381;
        Sat, 07 Jan 2023 02:40:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:250:b0:269:604b:a0dd with SMTP id
 m16-20020a056000025000b00269604ba0ddls2094626wrz.0.-pod-prod-gmail; Sat, 07
 Jan 2023 02:40:46 -0800 (PST)
X-Received: by 2002:a5d:6a43:0:b0:242:13bf:29de with SMTP id t3-20020a5d6a43000000b0024213bf29demr36014852wrw.52.1673088046823;
        Sat, 07 Jan 2023 02:40:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673088046; cv=none;
        d=google.com; s=arc-20160816;
        b=TdSxIJOjTVne69UR2dS5FcyrXOk7gVQKmDZbABXv9mIhiO38DIVCJl0VaA+wJ/Huzs
         Zq5kPgolNYe72pD7JPX7+5oyxl95Cmk3HTSUFQpVmcRMWJqT9aC5Dog+ds0kiidV0v0z
         c4SpnzCyIxYNYnrUpAOU5AP6p6fgZuNJHwWelL9AzOon49DFpSkdNBXOnOhXj9n4WCyz
         vzyjkk8zHzOyoJYKMoBXgUJ9Zi/X5uEym9coSak/n1kko599sFGoE9n8OyJwcvlCxPY+
         AhT8NC7LPZ0JubF5BIM4IoD2KVzzDW6wzyyV384BMGZm/TprK6cnA3RFd0CrWIaCQHG/
         EUWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=Q7wsnRffu5O2RWgyv3GZ3K8cLeYYuVq6dZD0H2Sa32E=;
        b=UiF38/n1zsdDifYsqtW+S83czkTJbThHs5NXiqrb7ZjmilH40IJWaKJ9ocg+PKFB/w
         E06D+5jaESt59AP23m8p3ksAR/Cvul6egGz6Gs/W2tTYo5DszLZBhR4KQ4Cwpix6cj5b
         aJsyCs7LbUjoL0dYN8/NQ6fNAsyWfnx3aqN/eITkVe3gaPsEHnJ0fvALOSrurRPv+ekf
         md1wz3JfMXU7uOcqNLF1CBSXRIhMA+iGE0AZ3ESJoERl0YFO8r3nq8nOY9IQo1IEKjpP
         N+Xq/HkWVzppbEhdHzZHv/cxMqhFd8fQ5xLTJ1txVS7lJNtHlXK8haD7iE6ftYZ8HFZF
         H37Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ZLxygyA9;
       spf=pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-wm1-x32d.google.com (mail-wm1-x32d.google.com. [2a00:1450:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id v5-20020a5d59c5000000b00236e8baff63si134726wry.0.2023.01.07.02.40.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 07 Jan 2023 02:40:46 -0800 (PST)
Received-SPF: pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::32d as permitted sender) client-ip=2a00:1450:4864:20::32d;
Received: by mail-wm1-x32d.google.com with SMTP id z8-20020a05600c220800b003d33b0bda11so4871049wml.0
        for <kasan-dev@googlegroups.com>; Sat, 07 Jan 2023 02:40:46 -0800 (PST)
X-Received: by 2002:a05:600c:2d07:b0:3d3:5841:e8b4 with SMTP id x7-20020a05600c2d0700b003d35841e8b4mr40607615wmf.35.1673088046544;
        Sat, 07 Jan 2023 02:40:46 -0800 (PST)
Received: from gmail.com (1F2EF507.nat.pool.telekom.hu. [31.46.245.7])
        by smtp.gmail.com with ESMTPSA id l11-20020a05600c1d0b00b003d01b84e9b2sm5377974wms.27.2023.01.07.02.40.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 07 Jan 2023 02:40:43 -0800 (PST)
Sender: Ingo Molnar <mingo.kernel.org@gmail.com>
Date: Sat, 7 Jan 2023 11:40:42 +0100
From: Ingo Molnar <mingo@kernel.org>
To: Liam Ni <zhiguangni01@gmail.com>
Cc: x86@kernel.org, linux-kernel@vger.kernel.org,
	linux-arch@vger.kernel.org, linux-efi@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-mm@kvack.org, kvm@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH] x86/boot: Check if the input parameter (buffer) of the
 function is a null pointer
Message-ID: <Y7lMKhXSQvwvLq7L@gmail.com>
References: <20221206125929.12237-1-zhiguangni01@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20221206125929.12237-1-zhiguangni01@gmail.com>
X-Original-Sender: mingo@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=ZLxygyA9;       spf=pass
 (google.com: domain of mingo.kernel.org@gmail.com designates
 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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


* Liam Ni <zhiguangni01@gmail.com> wrote:

> If the variable buffer is a null pointer, it may cause the kernel to crash.
> 
> Signed-off-by: Liam Ni <zhiguangni01@gmail.com>
> ---
>  arch/x86/boot/cmdline.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
> 
> diff --git a/arch/x86/boot/cmdline.c b/arch/x86/boot/cmdline.c
> index 21d56ae83cdf..d0809f66054c 100644
> --- a/arch/x86/boot/cmdline.c
> +++ b/arch/x86/boot/cmdline.c
> @@ -39,7 +39,7 @@ int __cmdline_find_option(unsigned long cmdline_ptr, const char *option, char *b
>  		st_bufcpy	/* Copying this to buffer */
>  	} state = st_wordstart;
>  
> -	if (!cmdline_ptr)
> +	if (!cmdline_ptr || buffer == NULL)
>  		return -1;      /* No command line */

Can this ever happen?

Thanks,

	Ingo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y7lMKhXSQvwvLq7L%40gmail.com.
