Return-Path: <kasan-dev+bncBDQ2FCEAWYLRBTEI72EQMGQES4ZVV6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id F0817409A45
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Sep 2021 19:03:10 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id bh9-20020a170902a98900b0013af7fdcba9sf3524466plb.6
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Sep 2021 10:03:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631552589; cv=pass;
        d=google.com; s=arc-20160816;
        b=Zx956sowNr4A5xAk0VzJJq3Ktr2IlGbFbD2LKrXwDPGePptUQotAs5tFdTlxqmiTT/
         D1w3SSM+jZk06JZNCuHN09rxIlykdXze2cxBxZueFhsZZYwH0UwXZz0n477IG8bhZOcx
         B/jQBDjhozmdfp7+vxBCg9raautoPySukZHdidpSEGeCOCcaDlVHGukiDxJFwdA8jAS0
         iEtyv9cOz6lkItAK3XaT2pOLVdTnY93enuOa/CviwZolx2HhQm26jRzpN9GzgFBRUbyG
         KiLwFLhXdE7a/xsGRKzFmz6uuOdc5zOeUBgoMn+P+pj5LytIW6MIhfcP/nDCwVDfc2qT
         Uf0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=yVRZCyDM8mo134DE3RU4dYtFKsURyVFYopjcgaqRE6I=;
        b=TYTV91kxWlIjAL60ggYrlwtncvNo11KGLeuBfZ7dmvjK+lvQyVsXRLuxzIiZTNIvZH
         dx1hf5/RZE4cZV4SlM6Lj8+UDIAazHvZM2qyKMhQYsVC9PrkvfupDd3u1frw/m7oQSni
         kqbPV/0tC57MKTz8RhaEthYu1+GaVd4zFBGAmWWppc90HZuxBiyZfnyCSDZ3FNJJqm55
         C76Fubw+6qAWaqIdk6v5NoQ4Ggy5B+nBBLidIbziwqsbPIBqsWWHa97Td49Gn5QFsFpa
         ZmSYFr6VpYXEIuCT9hvbGJ4WFviYpVjGnmXbaBVL0m0TufjjW3jgSxIbnbMMfn3IJBic
         m1mA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=jH+jgXCD;
       spf=pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=htejun@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yVRZCyDM8mo134DE3RU4dYtFKsURyVFYopjcgaqRE6I=;
        b=hdL8UAgThUSKWS/FNZoHUav24JmztH4lxbbJ4P2+4SvUp8R4Iw/r+DBiOKEjXqXd9T
         aGbM3WfVxssY1qebY1tJpDI2xY4AmOuB0IjFqqIxin8IcebhxHS6sE0xf3jQtzmJe1wY
         222bQEP74+PCuwIwwnGaRJ1lSkQG1gkQSYB+AZcB6BhgJaGbZezk9EHBAt+UdmS21eHB
         YJDFiWKHZuX+hF5zXynubzgmyMTFVn9wmpATsxwK0KzicU+qYYlx5IQZyNeoRw0Z0OPR
         uhX3K+uL+YFU9B0n4XyQgyzRWJCEQyshqXh97q4pkAUWvXGIf/uXFmSmk/L+/8SKFBRp
         Ri6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:sender:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=yVRZCyDM8mo134DE3RU4dYtFKsURyVFYopjcgaqRE6I=;
        b=rXVmm5kFX+N3AYV36XXBU1kx5daTbgV9eUAdsxpoDlwomzdqVrK7alof6kOgPxQkBp
         c5+iYi3ykcgUqml39fiOUs241iXHewzwBMEGzioxpMCDjDF4RoT/eXyzqKtKPT8YiN1b
         8Qeh3tAtevZEpwDkvXd0pbwTxbr40Dr1i5sveRrTBhYitKbRV840T3NbnzWQKZLj3YiK
         iNwUWsEEL0KJAl+K94jVbdh46YZRYIt2huncuhZm+PjMzB605jUy3WXcVftbqVRnJka5
         mqIzCyvvNKq8Oj/0qcikzopSZGgCFOkl3QN60OGDCXQULUudc2ugizF17NIACJh7zXr6
         W/Vw==
X-Gm-Message-State: AOAM531NukwjVxLv9x1PhDVhQDzX7v1+zdkdz2wetst59wCgUBqBMfCx
	sZ95EcOUYQyARvL74O9z3ig=
X-Google-Smtp-Source: ABdhPJzbdPge4FpxkF6cPCf5wYNPIVP7C5dpdTvGHj6F+oO/4C9j389AQC6R1rC7i7Yw90viKp4K2Q==
X-Received: by 2002:a17:90b:194c:: with SMTP id nk12mr535778pjb.50.1631552589166;
        Mon, 13 Sep 2021 10:03:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:2c01:: with SMTP id m1ls3915424pjd.2.gmail; Mon, 13
 Sep 2021 10:03:08 -0700 (PDT)
X-Received: by 2002:a17:902:aa88:b0:13a:95d:d059 with SMTP id d8-20020a170902aa8800b0013a095dd059mr11390909plr.65.1631552588399;
        Mon, 13 Sep 2021 10:03:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631552588; cv=none;
        d=google.com; s=arc-20160816;
        b=FbV72L+PCI3Ak90kc4NdNNofJazNKsZBPG1Ph82YUb3PjNyer1BTsoMbOmtJOrn8CP
         6c2U9wrzsJCnJDI8nRQCEX19FpjhTFkkRYwV/qAbQxMXfMrvdfXcioS2prIg8O4LUeNr
         8iJVyb2mUKYMJ74Mlvo16XLkZPqmRETVVlIjFUpXD3iuuk9nDYUyWIJRlcN6k/Q/JrA3
         pwtaHfiGXDGgxcRM4/gd6krQGbChcsrEdHGe97Uf6Ko9zugPJBjDkFpxNwT0lb2PAJUr
         vwb6trzXQ2wqf1c96TbAs4GKvBQ2M083DYRx7WjQ+A2FzswU/4jNUAxI82Kt+KyNg4ey
         BNbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=frWu/JoUaXMXlQeR23mYrB0fgcNWVG++fwwYDmdHa4w=;
        b=AVLys6s6of5irZ5eqGD+1WWs4EW1UJHmnT1NVPXoNiQB7n1ZN9hsjXd/IXj0j63IYU
         1JFvyLKDOq+eI+vgTLJfvC29wrg7ODLIZQvaZ2AwpluH6uyaJNJFzq9RPf7CziKHuuYR
         sByHl9JIeVM5E/O/pnnmNOhPMkCgv5JNkjj9F7G9xdxbnrH0hwjeZVF77Ibm5YYwaI3y
         uTRiJHv8FIqFj9sfzVqmzjNd04uJgeaK1ANirqOo9qCDF0QHNVxb7Trff9b5n0OCJKys
         xZMLj5vQsH4kEOxPZprUzSkirJmGhFIW54+jt2QRtWBfemelhv7cSipNkJFtJ8KWcyWv
         GPKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=jH+jgXCD;
       spf=pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=htejun@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-pg1-x534.google.com (mail-pg1-x534.google.com. [2607:f8b0:4864:20::534])
        by gmr-mx.google.com with ESMTPS id o5si576670pgv.1.2021.09.13.10.03.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Sep 2021 10:03:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::534 as permitted sender) client-ip=2607:f8b0:4864:20::534;
Received: by mail-pg1-x534.google.com with SMTP id u18so10092126pgf.0
        for <kasan-dev@googlegroups.com>; Mon, 13 Sep 2021 10:03:08 -0700 (PDT)
X-Received: by 2002:a63:9a19:: with SMTP id o25mr12129014pge.61.1631552587899;
        Mon, 13 Sep 2021 10:03:07 -0700 (PDT)
Received: from localhost (2603-800c-1a02-1bae-e24f-43ff-fee6-449f.res6.spectrum.com. [2603:800c:1a02:1bae:e24f:43ff:fee6:449f])
        by smtp.gmail.com with ESMTPSA id q5sm4512106pjd.30.2021.09.13.10.03.07
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Sep 2021 10:03:07 -0700 (PDT)
Sender: Tejun Heo <htejun@gmail.com>
Date: Mon, 13 Sep 2021 07:03:06 -1000
From: Tejun Heo <tj@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Shuah Khan <skhan@linuxfoundation.org>,
	Lai Jiangshan <jiangshanlai@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Walter Wu <walter-zh.wu@mediatek.com>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	Thomas Gleixner <tglx@linutronix.de>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vijayanand Jitta <vjitta@codeaurora.org>,
	Vinayak Menon <vinmenon@codeaurora.org>,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, Aleksandr Nogikh <nogikh@google.com>,
	Taras Madan <tarasmadan@google.com>
Subject: Re: [PATCH v2 6/6] workqueue, kasan: avoid alloc_pages() when
 recording stack
Message-ID: <YT+EStsWldSp76HX@slm.duckdns.org>
References: <20210913112609.2651084-1-elver@google.com>
 <20210913112609.2651084-7-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210913112609.2651084-7-elver@google.com>
X-Original-Sender: tj@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=jH+jgXCD;       spf=pass
 (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::534 as
 permitted sender) smtp.mailfrom=htejun@gmail.com;       dmarc=fail (p=NONE
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

On Mon, Sep 13, 2021 at 01:26:09PM +0200, Marco Elver wrote:
> While there is an increased risk of failing to insert the stack trace,
> this is typically unlikely, especially if the same insertion had already
> succeeded previously (stack depot hit). For frequent calls from the same
> location, it therefore becomes extremely unlikely that
> kasan_record_aux_stack_noalloc() fails.
> 
> Link: https://lkml.kernel.org/r/20210902200134.25603-1-skhan@linuxfoundation.org
> Reported-by: Shuah Khan <skhan@linuxfoundation.org>
> Signed-off-by: Marco Elver <elver@google.com>
> Tested-by: Shuah Khan <skhan@linuxfoundation.org>
> Acked-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>

Acked-by: Tejun Heo <tj@kernel.org>

Please feel free to route with the rest of series or if you want me to take
these through the wq tree, please let me know.

Thanks.

-- 
tejun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YT%2BEStsWldSp76HX%40slm.duckdns.org.
