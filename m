Return-Path: <kasan-dev+bncBDAZZCVNSYPBBANGSH2AKGQE6W6OKXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 836A719A770
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Apr 2020 10:38:26 +0200 (CEST)
Received: by mail-vk1-xa3f.google.com with SMTP id r201sf7875424vkf.5
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Apr 2020 01:38:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585730305; cv=pass;
        d=google.com; s=arc-20160816;
        b=NxIJtV/eTJRLDCELTALG0w9gQDduHPsJYQvAjPxIac2qXqmlgv3b42/7UP1vYCiwlG
         wy3Jxogk37zb+YRo2VFGCsLyN/fJ29ELqvKKeHz9TPfITU7gpR3jLZAYQaQvfxIjIm3l
         FpusqrK01IiA8v4omfrHUmsFNAS0Lj5O3ooRASQ0dsRnoqRCtuFgTeYA2V+tS7RXtGcg
         cuAzY5tHqSbg+qbHL2GM6bvCAXV6bBzW1bAMlhne4NDX7cU5EQmrf38EZU4WaJ0tTlSs
         DQmX2qeX/LWXWCxatd/4doryO4ZpUnKDrDvymLBvjpd1yKVegk7kccHzaGQR4Xm/NjQV
         2IEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=kceRjACHyCodKNUQUbZ0Yxx9cFFxMeKbOkvUZ6lModA=;
        b=ZyIWZS3tRwW6vcFbpS1U6G9GvcijQ8PMVC9zT7wgd2L5tl642WZ9AN+9o07vp7Ypt8
         UGpij8MYu1HgylYmYxPPoZXM89Fw5fVRvAeG5ZmNWLYLtm16oM4fC453cIVouLBHcOze
         fvbLrUiDbDKS8glUx+l6O8Fs/fPZLiNRUUr3MfNGTlNlivvY4XG7nW0lQxD6HnGSgfTW
         fOuRJpOc41gDAlUdm0QwxOrC/6f4GpMxPDMhHbPI9rB+LVdOv/qfNqUcYv7P6oxQKhyw
         hGBLG9ZjV3StmNzAixKKKIibdVpeSUNw9BWemootvMfASgLYmHCHFeolyUN+sX8Hvm0e
         CKRg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=J2s9ykdX;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=kceRjACHyCodKNUQUbZ0Yxx9cFFxMeKbOkvUZ6lModA=;
        b=aIRMgGk8UJg8hotwBdHL5F/+LdmxU1PUZB+7Kiz6J/rPiTp7+hdXsjXgCqp9C7yp7r
         kooCFA9ORH+gN70v6xWeOvdn9K6ar57omI9v64DLcybgL+KUm/JAAtrgqEfYz9uHbTwY
         r+yq2JZaWhFDUkBXnO4/9gmXj8Doz+Gsr5bVu5tqbAmuozy6wbLOXetXNo6Xc0TtI3Rn
         ez4aFq70m9dDE7DI0CjaqS2Wl0QBaDNf5L//TFJqInzPEfs7vRg3U07/kWZUa93MtwzD
         P7Dut6g6rJoRE97XYSQJwJuelN7XcKB1zk7bpSLxGHt7Qoh+UjnZq7lWe9uszd3bFEyj
         wcBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=kceRjACHyCodKNUQUbZ0Yxx9cFFxMeKbOkvUZ6lModA=;
        b=rI6sm15h7hjNrFvffP+57sIWZGuRT29CbJBMoVRX7ENjwTB/AdlRssOOBjZPKvGPFX
         6+yaQ5lwEFUR/6e0KVeYdtDmLT2wuyMfxJMzcow5SjylJaZCJsnRwpD2B+/k04g5Y/2M
         ronXEEoi3JU/yoO0dtTGx44M9/NdszFULzd/BcSnNlUIXjTbU65OdZO11v2moRsdo59p
         dCEOh34VcLGnsjFiTNsuzbtG5xX+yJfGYW05oEM6AqghEPWFnJWHbnD2IL2Id1uWuHHT
         qiSMqSIt6t3Zwqjbahk14igR9A4e48XsBUNObGip1jcom8ZP5tG8NNf8it5BKtUKLURu
         YXzg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuZr1mgA3JntHGsoDB2etWR/yCxkb+kps8Uj7UvJj7VlQ/MpmMa+
	gsILToqRZDJne9kAlVg94MY=
X-Google-Smtp-Source: APiQypLSGTG5MoevYqicq0S8d/Lx4HQGwPesOA/a3HUVp+e27t05J5kdJBQjHNJFy2Hzvk4KOi8nlw==
X-Received: by 2002:a1f:4ac6:: with SMTP id x189mr14585624vka.50.1585730305529;
        Wed, 01 Apr 2020 01:38:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:684c:: with SMTP id d73ls3182248vsc.7.gmail; Wed, 01 Apr
 2020 01:38:25 -0700 (PDT)
X-Received: by 2002:a67:5c7:: with SMTP id 190mr16179260vsf.97.1585730305043;
        Wed, 01 Apr 2020 01:38:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585730305; cv=none;
        d=google.com; s=arc-20160816;
        b=EjSFlsiiB2nHqus6Yihs7j9XhnJNuTKlCkXXiMzfzGzSo2oAINtCU/JPa/04uw15bI
         m2JjKoUOknJnqnqtPoCmtL2eq9qjEMs3CVr004ueh6aO/0MOQalOJIlWu6B0hET8SrBw
         ZgkyTy1/SKzOiSk5RNF+gty2hWa+W8WauNG1HcEE3pvCbKtY5y3HA1El9vWi3EptAKz6
         y7sVGZAA3GDFwT5d/Gzc2hi22pUPMdheI8LI8p4rVznLkOumhIOwaxoOiGOygNQi+U4R
         TM3Msmik+msNF6AAQoEclyMLwb6a3SjQGZ7ui3Rto4rk+6O3PmMYuxfuhzCyNbHZNirC
         FLew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Iq34dYwT2pFM9ChNu170uX954yMTayyUFQS9IB63uVc=;
        b=buXutrVdPacCSUVvELFL4wW5p2rP3tSx9VZ9LEWnSJOb1a9ErafQjLBwNP9W2WijyP
         nP/5OFmBIg0WPRW3RoTgBEsvIu172VwaQBsoZHTYEkZsG0tTmKXT3TWCcy2TjkAJoLQ7
         NZ9b7+hBJWBhdH4FTLgG9PZi1KkIFyAFDGHsMtqMzjHOnX0FArzpt6wbwTuKxq8Ai+FN
         n2lsxhq9XL0YD88ZNsbXotJwd7qcgCljtURkr9mcgmd/oRHkNoq/2iHQDbDF2+OUlcRE
         IK83Ifwr5mE54YRpc973rB//zkWz8lTA0tCWze0vtrA94WCQGHlqrrOVUb33rqXkxUqi
         KEPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=J2s9ykdX;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id h6si114172vko.4.2020.04.01.01.38.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 01 Apr 2020 01:38:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from willie-the-truck (236.31.169.217.in-addr.arpa [217.169.31.236])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 75CF82073B;
	Wed,  1 Apr 2020 08:38:22 +0000 (UTC)
Date: Wed, 1 Apr 2020 09:38:19 +0100
From: Will Deacon <will@kernel.org>
To: Marco Elver <elver@google.com>
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com,
	andreyknvl@google.com, cai@lca.pw, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 2/2] kcsan: Change data_race() to no longer require
 marking racing accesses
Message-ID: <20200401083818.GA16446@willie-the-truck>
References: <20200331193233.15180-1-elver@google.com>
 <20200331193233.15180-2-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200331193233.15180-2-elver@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=J2s9ykdX;       spf=pass
 (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Tue, Mar 31, 2020 at 09:32:33PM +0200, Marco Elver wrote:
> Thus far, accesses marked with data_race() would still require the
> racing access to be marked in some way (be it with READ_ONCE(),
> WRITE_ONCE(), or data_race() itself), as otherwise KCSAN would still
> report a data race.  This requirement, however, seems to be unintuitive,
> and some valid use-cases demand *not* marking other accesses, as it
> might hide more serious bugs (e.g. diagnostic reads).
> 
> Therefore, this commit changes data_race() to no longer require marking
> racing accesses (although it's still recommended if possible).
> 
> The alternative would have been introducing another variant of
> data_race(), however, since usage of data_race() already needs to be
> carefully reasoned about, distinguishing between these cases likely adds
> more complexity in the wrong place.

Just a thought, but perhaps worth extending scripts/checkpatch.pl to
check for use of data_race() without a comment? We already have that for
memory barriers, so should be easy enough to extend with any luck.

> Link: https://lkml.kernel.org/r/20200331131002.GA30975@willie-the-truck
> Signed-off-by: Marco Elver <elver@google.com>
> Cc: Paul E. McKenney <paulmck@kernel.org>
> Cc: Will Deacon <will@kernel.org>
> Cc: Qian Cai <cai@lca.pw>
> ---
>  include/linux/compiler.h | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
> 
> diff --git a/include/linux/compiler.h b/include/linux/compiler.h
> index f504edebd5d7..1729bd17e9b7 100644
> --- a/include/linux/compiler.h
> +++ b/include/linux/compiler.h
> @@ -326,9 +326,9 @@ unsigned long read_word_at_a_time(const void *addr)
>  #define data_race(expr)                                                        \
>  	({                                                                     \
>  		typeof(({ expr; })) __val;                                     \
> -		kcsan_nestable_atomic_begin();                                 \
> +		kcsan_disable_current();                                       \
>  		__val = ({ expr; });                                           \
> -		kcsan_nestable_atomic_end();                                   \
> +		kcsan_enable_current();                                        \
>  		__val;                                                         \
>  	})
>  #else

Acked-by: Will Deacon <will@kernel.org>

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200401083818.GA16446%40willie-the-truck.
