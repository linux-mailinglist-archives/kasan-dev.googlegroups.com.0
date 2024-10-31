Return-Path: <kasan-dev+bncBCKLNNXAXYFBBEXARS4QMGQE747JLEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id D7B539B7541
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Oct 2024 08:21:56 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-2fb5035169dsf4753301fa.3
        for <lists+kasan-dev@lfdr.de>; Thu, 31 Oct 2024 00:21:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1730359316; cv=pass;
        d=google.com; s=arc-20240605;
        b=Nxq18zK3u/6VkC8Kk5WXxBsxrz3VyTYcZcjLQULlrXfxeW08tCKYdtWeDNDQLasRW9
         77efi8gpNG19Jlvvw3YnTVEyU+06hJBSz27IXLCPIHBeESWNKY1dhx12aRo03QjdUVw7
         mQuw0yECKMMGJlTzCqPZr2Mlv5hkWXAJvJscDFSG+XjX4jrNdXDMnBKowppPu11Bfyim
         1sns8m65h48k0AL3B450yA/M6QvC3syuDgMjph779Cd5z6PC5+8lASuvOQTySzn5WoMK
         2pib9tsH1RJQOv+G+0wsw7e4A46E166Ni51qDF4VANZ77bmBJ1jwi2RIsK0z4pOQKxzW
         q46w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=N0aPXG8D88L6FqfByO4kxT/cHS1X8hNUo3iRY/j1pvA=;
        fh=6dl6HTgQOCBAOdJsnfG8JuAA1FRGOq+NUkGNBeFFjR0=;
        b=UFNpHCQsE7aC6z34W2wslGFpsCxKsDKzZTcksI2lUFl6j21nK9lPrk0L/+JnYD69C6
         IGtOd17zE7VScDLp3bCw7uLyD2YP65gql60hyMKKEKWdxmBUauxbEhXB/0S3Qior3N/p
         lYepN0ZFoK/TrA5Em30Y9nLrwB5BPqLrvFVKkw8FljpE86wDOzCbJdXtB8WFaC8eetGB
         b3AxyJwKuMSqj49NVnslI/ejyEHh1Br/iu2hGHIKoJZpyEQvy6vAsrg6Y7ccT4hWvBHn
         15BjWKvvU5F+Z+QmCNOW6SbhHK+iGgbXmJQIHYdVeYA9prK+GRCdMPRiQPecADGJwGMF
         2hJQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=OOfWBcjg;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730359316; x=1730964116; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=N0aPXG8D88L6FqfByO4kxT/cHS1X8hNUo3iRY/j1pvA=;
        b=c/t0t7lVWuQjNcOaO6TAdOzdtxG/XiuY03zAoez76mQaI2gjwVY44Wq6+aoXT6MYNP
         ek2ccCJ+NLbcukffBoNvVJwTrob5Kx5xT+jx12+KVFI/x9TjV2EK1h0qKmKuoLZvYqv9
         mv1BHCfclbv+hs9sT4oJGXK6vX8gU8QHQpMA1aWgKtFSy+Eza9WnYOhJ7tKe3eh3yoVX
         2i/WSkX5JL7anmD2Bus2Ar+EvpjAPJa46DCeVt9z1Bsi2GkLXylGyFFaK6vdr92LLuu0
         vwu1onsVk2gSaBKK7+M1uFIpGAP7SWPFY86lxaldSOO+atabIQz0hRriuEoeeeKyHxoQ
         WPfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730359316; x=1730964116;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=N0aPXG8D88L6FqfByO4kxT/cHS1X8hNUo3iRY/j1pvA=;
        b=l6X3fuxsBbYB378zHDf8fFy8C055sY8g9CN4FvLl/0q/KuNnJwdOskP7v3QxK147yu
         J3e3ondP3bREXdMHt1TX9YtYf9DNzIMWqyzcj8ih/FNGyJag+sWg15kVdvmDw1lHLTDV
         OBlm9TCobbZUV+3FYMPIOTta2tKs2OGDElUF4fZd8mQU9VDOFVqex7iyDwD9XMpssq+A
         OOHEczTHmKlG1nIG2LAZ7k8O2hjxKGYYFQxhA/32U7zjqGfR2+ZAfpw8UFxk9cWLQDil
         IG225ovXJ4DYXEaQ7e6ODIsS+tCDBiQOk3LITCllQEwv6eGMsKvfRsOcGxTmU4L7mUEH
         AaoQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW9uGnrIpXs/T9cdaP1XMQ+QzoN/ZFMjncvC+QB5ZeGOX27FxGzchMNrtdKt6NSToZWPHm92Q==@lfdr.de
X-Gm-Message-State: AOJu0YwxgeEWcKLMBlj3mZFW7ht/nH/hY0C7wcnAyoGNoAWH4xJwFQd1
	vHIjaGkXhgc4Zek1n+jYPp+bftedVGNK+2H1syw5YUuYXzk0qEVe
X-Google-Smtp-Source: AGHT+IEyM82yUoySHZYvtJjTKxheR23KW0UOVy0Tbve7/A4IKFAW32AhiV260fmwxFZNFGa+cvlefg==
X-Received: by 2002:a05:6512:33cf:b0:533:c9d:a01f with SMTP id 2adb3069b0e04-53b348ba0bemr12599410e87.4.1730359315170;
        Thu, 31 Oct 2024 00:21:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:ea8:b0:53c:75d1:4f2c with SMTP id
 2adb3069b0e04-53c794ff760ls365809e87.1.-pod-prod-05-eu; Thu, 31 Oct 2024
 00:21:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW9uhazql6g7jFyfA0ikGbe72Yj+7gSfR6eAojC7UO0Wp759h8tymt/SFyzmCVyXvskyEAoWVDBWL8=@googlegroups.com
X-Received: by 2002:a05:600c:4f4a:b0:431:4b88:d407 with SMTP id 5b1f17b1804b1-4319ac6f874mr200862225e9.5.1730359301916;
        Thu, 31 Oct 2024 00:21:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1730359301; cv=none;
        d=google.com; s=arc-20240605;
        b=MTkpMJ4AqI8vdkE5uZF21xHs7nXRlW09eOuXTHkUQWhW1sj7FnEsB6W856nEKAmgok
         oI5uCAPFvg9JO7Ypgq68fKqXJh7oj4Z6ganO8s0abypwjEDfJFTmMDKkd73x3eZVPV7O
         qGR/YMh5H3Up8miAKqtQFkEUom8GpPsUvlteXN929cM9SfcoCJbpOLwxke82NWgQG9Bz
         Ncsyiyk5UwogoGnF81yat6oVrq/bp/eluALUQS4OMFG4eWs4RpL+G0kq5+aabQ8P9ohY
         Obm5YM63bJoqWqToAP8AJGMU6KfOonyjR3OFxuqB0rIYXKiS8/FlNw2x+1MiETD38scE
         BT0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:dkim-signature:date;
        bh=o4se6XKAoDumSaMJxQiVaipt/NAGA0v3RVpl95g5pxQ=;
        fh=hcxBbb0HWrOLE6CPJY1SKA8TEksAYHP8jVS8YPmtJf0=;
        b=BVipj/bzDfLE2gYYfO4dL349SeqwaMXJBmwaV3yKCRkEHFGG0S2wZlkbewGyF0mJSy
         V98hXGWrx+wx9E/8GhbmjM0MEFwWr4sthUyA2vMH/KshFXsLrAwUxC0o/QpwKq1PB2B/
         DJeOuPXfjkXvUcQFdLfDl4uiGSOhngX+bSY8pzm4+Wrf+mAX3vArY21Sw0ES3w4zcWrk
         R9HG1FxEfQUon3Uy6IasEZxUtSgVDOWT0pC83qUG8ftbR1TpzPOIHlCnuUksAO0uOCa0
         rztzEE8kUhZO7wrqyc4IEplHi5s2YDmIZkrkug92A7mbh+xvrxWNAeim8jr63CEoEB/Y
         Iqyg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=OOfWBcjg;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-431b43ab705si1364025e9.0.2024.10.31.00.21.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 31 Oct 2024 00:21:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
Date: Thu, 31 Oct 2024 08:21:36 +0100
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Marco Elver <elver@google.com>, Vlastimil Babka <vbabka@suse.cz>,
	linux-next@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	sfr@canb.auug.org.au, longman@redhat.com, boqun.feng@gmail.com,
	cl@linux.com, penberg@kernel.org, rientjes@google.com,
	iamjoonsoo.kim@lge.com, akpm@linux-foundation.org
Subject: Re: [BUG] -next lockdep invalid wait context
Message-ID: <20241031072136.JxDEfP5V@linutronix.de>
References: <41619255-cdc2-4573-a360-7794fc3614f7@paulmck-laptop>
 <e06d69c9-f067-45c6-b604-fd340c3bd612@suse.cz>
 <ZyK0YPgtWExT4deh@elver.google.com>
 <66a745bb-d381-471c-aeee-3800a504f87d@paulmck-laptop>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <66a745bb-d381-471c-aeee-3800a504f87d@paulmck-laptop>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=OOfWBcjg;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e;       spf=pass (google.com:
 domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender)
 smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

On 2024-10-30 16:10:58 [-0700], Paul E. McKenney wrote:
> 
> So I need to avoid calling kfree() within an smp_call_function() handler?

Yes. No kmalloc()/ kfree() in IRQ context.

> 							Thanx, Paul

Sebastian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241031072136.JxDEfP5V%40linutronix.de.
