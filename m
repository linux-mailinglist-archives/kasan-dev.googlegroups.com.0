Return-Path: <kasan-dev+bncBDQ2L75W5QGBBR4T4CYAMGQEINOZUVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C93F8A1943
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Apr 2024 18:03:21 +0200 (CEST)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-22edee26782sf14439fac.3
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Apr 2024 09:03:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712851399; cv=pass;
        d=google.com; s=arc-20160816;
        b=yXH8t7USZlYwoSrVExzzoL3hE6G49z6/MpmHZtyfbVcHphOUa7gzrvvMe5/+ADsd7C
         uvnXVRx2hf4hPr8QNHb7RmaXeuvJ7hBiHUsEPDUjaz36fM+XPci1Vuep1fTwwFf+x7gU
         sv3xAWVvVUL/CsiAFLm2g/2aPF6QsuLGIE0lW49ixbsYi4x/zg25pNZoEi5Z1ofJMYZR
         qU5UEyKp1ZIOh7V2accGz76tO5Ox81HgDpeX+YiWSRZMvI5Na4T9CL6Pv3i2lTq4etVx
         vg8Fu6K0uRcDxNffVT30kXgUcUgDBKTpVsCO/7PsYhfn0CosgVQWM6/WW6+cdF9cIUOi
         Mumg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ZpVxFhdmaq4koOppVUakyiRWC46IMICvk/kXUjn+3kU=;
        fh=Bz5YnsOS9Y+Hno9VYJ7sEXDGQQWZ2ZWAJIVPv6vdl7E=;
        b=DgOk42HaWl9nWNJg15UJsZac8HySRp9OmvRl6EVDUtXvwYS1b35vYEBaHozJu/y9Yf
         V3sozdJHsiaU6cwJmzj2sjzxezUrOyBdm1ZxdE98LFdn3+gNcmUkIEEf5OQ/4JO5E0bm
         AEkIm4R7yH/yfDyEtVJ6NPXEZMDkEQ0FCkX6VKdZxFAcAfqvHNLmrJcDx0W4nbfymTf+
         5olmq9HDiZB/TrAetM6XH7tIYSNIFkZ5+yZ94r0gOHkg5tonZpu5kKDGwxhJ3ZagIYhQ
         mZsDCWJX1Ywl3RRn//Rjl8EIxzPHib5Oerp8o8AUI3aXUVu7v8t3dsqpkooicsHURQv/
         J1Qw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JFKAUFGr;
       spf=pass (google.com: domain of broonie@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=broonie@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712851399; x=1713456199; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ZpVxFhdmaq4koOppVUakyiRWC46IMICvk/kXUjn+3kU=;
        b=GrHxJS3QKNfzBrxtAH7NLOHn70OJZ33SvSOKIbJUNI7SisGs12zyspxdUaytFOxSQP
         ezOWQuPWJ6LWmC+ghHx1HJofuaUXRiGkrWxgoDawGLO2ll7kvKWi3kNPaxE+Mkurxg2J
         lT+3HA7DdHFkaVxyNai0DvNNAXytyMRNqXu4veT6rT/EIC7Xwq4DcZ6y8tEHBMxxVpef
         uqmIvWiRo1D1CfDhBwKQHcqBpOKVOqzou7njWnjZdd1TEyULg2Qpmkht2mbF2JueKztE
         ctAlfcKirCxtr1BWFnW+DnVq1O2bhAvhjorGgN2GNuAVfpVq43dvdxq8+C1zRxBP8n2g
         2zcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712851399; x=1713456199;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ZpVxFhdmaq4koOppVUakyiRWC46IMICvk/kXUjn+3kU=;
        b=j5LR+R+MK4c8Pdi6+iilXFkaODdCmgnC7mErCnYEhiVXHC2y3qNbUJqk7xcysMlWxe
         LJQEcBVuIhWHkZ5eW+UCE3X72X7DOTlRTUc7h8/eXkTDDH0PHrnYAWfeWan0GYEHWYND
         wm5pakh84ZGonsYSJajKy3UzxMtSVe5d8/4fS6WN7GxNkzvbiK+QnApZSqJ9LC4WEw3L
         fw7UJT+b0whOj5ldFwWQ/nxQQYDP5WEy7qGy8reJjAsQ8/n9IipS0B0GelYG56/ej/CG
         ScFPgNxxUxRh8VL9Md75B/cAf2DdI1XtnUp+5v+DzHOX41vGXkHTIbUTIzs+4H6xSyOh
         rEuQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU0NVI+au56QSLdL5aGI5E27SdDmyIwv9NqnABYkdPZ4nykm78g7oXkB8lM/x5NOJ6NuIOka2dsh7Gng4jS4rX2/qa4EK/6Mw==
X-Gm-Message-State: AOJu0YxOsu9F7LRovyd+YnnT0WAFcqtCQs+HLY0rcu8gRKUD3QPfB4IR
	fZm0y3Dr/ZFeCtiFhxnNnGTw3VY6OD50hatNSVpgGloX0XIN2tgH
X-Google-Smtp-Source: AGHT+IF92tVnGEf5i5uPpTXtEp5mCtdDxw3zkIQn6UWmKf5s/3Zus1URXrmn5zZHLdTCuaeSD/BF0w==
X-Received: by 2002:a05:6870:c0cc:b0:222:a91a:63cd with SMTP id e12-20020a056870c0cc00b00222a91a63cdmr6716234oad.45.1712851399338;
        Thu, 11 Apr 2024 09:03:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:f809:b0:22f:4b4:f2de with SMTP id
 fr9-20020a056870f80900b0022f04b4f2dels60767oab.2.-pod-prod-06-us; Thu, 11 Apr
 2024 09:03:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUEVci3K8h0FT4gaiHLMQ+QePK4VQ9sGAh8/lPlIfQVva0aGrbgnfreb+zTAzWKGkBlAdhTmxdeMuPvuL+b740I/P5iobYpf7UYOQ==
X-Received: by 2002:a05:6870:e0c9:b0:22e:8907:e7bf with SMTP id a9-20020a056870e0c900b0022e8907e7bfmr6831143oab.40.1712851397683;
        Thu, 11 Apr 2024 09:03:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712851397; cv=none;
        d=google.com; s=arc-20160816;
        b=sXAiZFn6j4OKauk+C1OhzJ+wMHxKjLauhox7C0+7weqok3OfRXOROWRUOP8QcVYCqm
         NC1268HgEfM4lWsLGGiKcL2FBJqSU/zp37Jok6GEQjiOW9Q3w5aEC7/XHdz4+lR+p/V/
         jkLvsyBmeHcRutabEAxkY42LKQrmjB0TtcuHf+WhIUUG/cD+g6Jnqjl/yuG9SZuKb34G
         D20QNEzoEyup6ZdbpiUX+Li09AweQ7F7sdyRsycGqMWf6OHi7X6ovnOfjC9yI1EpN7J8
         zgXXUnzHFVQttu0dCQ0/7ykqNBilVTCmg34ki0umWFWV/b3DL/rJQgzhBXnYPGSqC6Et
         PzOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=1Hnq/ZAc7nWl6n4a+MUkmaPzOHmN8ZMKpbljmDPzbqY=;
        fh=fmJAQNqzv5Vyv75RDDlN7CK/avNDzxUCRrx53jU3DTg=;
        b=mC+ZHTAER8U/CQY1PxVn6JCyCt164rb79L5h5vht9loSrR8amQPDD4JFf7C7fKLSvM
         l78jmLpWx51To7uFdPrx7fJt9HZ8uvB8Prijtn/GRQZ7iT3k9ifAlVDUniXx+F1gqXov
         7lF0wCp4kL1JhcOrB8bxwsSMnz9NGfO5gk+CkZWuY6qbW9taAnhyU2sL2qOpcEnQ7wEJ
         +mkq1tDmxJcGQIxPK8Bw2Hw1nRhtzYvdv5Bb6wjgwTkjQFGXsH3UD3vjRYlVLQybzgtb
         FuPARhUYvc8antMC+eBW59Ralkwr74S12x2bOcHbQKXWcd4YtUGYe2WJygIHNhqTJ5uI
         Smfw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JFKAUFGr;
       spf=pass (google.com: domain of broonie@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=broonie@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id lq11-20020a0568708dcb00b0022ef31f7182si230133oab.2.2024.04.11.09.03.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Apr 2024 09:03:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of broonie@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 72BFF6208B;
	Thu, 11 Apr 2024 16:03:17 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D6AE8C2BBFC;
	Thu, 11 Apr 2024 16:03:13 +0000 (UTC)
Date: Thu, 11 Apr 2024 17:03:10 +0100
From: Mark Brown <broonie@kernel.org>
To: Oleg Nesterov <oleg@redhat.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, John Stultz <jstultz@google.com>,
	Marco Elver <elver@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	"Eric W. Biederman" <ebiederm@xmission.com>,
	linux-kernel@vger.kernel.org, linux-kselftest@vger.kernel.org,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	Edward Liaw <edliaw@google.com>,
	Carlos Llamas <cmllamas@google.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Subject: Re: [PATCH] selftests/timers/posix_timers: reimplement
 check_timer_distribution()
Message-ID: <280faf88-9bcd-4f0d-b02a-eb72cbefbb3e@sirena.org.uk>
References: <CANDhNCoGRnXLYRzQWpy2ZzsuAXeraqT4R13tHXmiUtGzZRD3gA@mail.gmail.com>
 <87o7aqb6uw.ffs@tglx>
 <CANDhNCreA6nJp4ZUhgcxNB5Zye1aySDoU99+_GDS57HAF4jZ_Q@mail.gmail.com>
 <87frw2axv0.ffs@tglx>
 <20240404145408.GD7153@redhat.com>
 <87le5t9f14.ffs@tglx>
 <20240406150950.GA3060@redhat.com>
 <f0523b3a-ea08-4615-b0fb-5b504a2d39df@sirena.org.uk>
 <87il0o0yrc.ffs@tglx>
 <20240411155053.GD5494@redhat.com>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="6X+i8LxTiBMSWKj7"
Content-Disposition: inline
In-Reply-To: <20240411155053.GD5494@redhat.com>
X-Cookie: How come we never talk anymore?
X-Original-Sender: broonie@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=JFKAUFGr;       spf=pass
 (google.com: domain of broonie@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=broonie@kernel.org;       dmarc=pass
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


--6X+i8LxTiBMSWKj7
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

On Thu, Apr 11, 2024 at 05:50:53PM +0200, Oleg Nesterov wrote:
> On 04/11, Thomas Gleixner wrote:

> > Grrr. Let me stare at this.

> Damn ;)

> Can't we just turn ksft_min_kernel_version() into

> 	static inline int ksft_min_kernel_version(unsigned int min_major,
> 						  unsigned int min_minor)
> 	{
> 	#ifdef NOLIBC
> 		return -1;
> 	#else

That'd probably work well enough here.  I think it's reasonable for
someone who wants to build a test that uses ksft_min_kernel_version()
with nolibc to figure out how to implement it, right now it's not
actually getting used with nolibc and just happens to be seen due to
being in the same header.

> Not sure what should check_timer_distribution() do in this case, to me
> ksft_test_result_fail() is fine.

I'd go with skip but yeah.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/280faf88-9bcd-4f0d-b02a-eb72cbefbb3e%40sirena.org.uk.

--6X+i8LxTiBMSWKj7
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iQEzBAABCgAdFiEEreZoqmdXGLWf4p/qJNaLcl1Uh9AFAmYYCb4ACgkQJNaLcl1U
h9Corgf+If9pRewR2Sf7yuBxPHFwhekXG3uOsPuQGQrq/fl0/zgB+V1ToPn9FsrD
+INicy+H4EAfPy4Zr1aWOSJc9O9fsavsvYg59sfnRmYiwSHjQEbIj0ZUSVzEpCRH
39YNs2AEF8MtR0530GNjsDJqYFGdGj/ZCkcgaAHLrvkTWe97LPNaFDhxRfvR6HJz
Y9Dub0bcfCQUt9bg2zGOMzgdll5TF6h2TApiEeedMpS0qO6/uvDH8Ws1gnVlH2dV
HNW/grfhC5too7+GFpDDnBDaWaWD3vWDwuVDcGIWm1Nm9e8Yi1pwjXiGXSRMsBID
8MBmTlnBXsIEKJEnVpTu9zVw9Fg1Sw==
=G3lU
-----END PGP SIGNATURE-----

--6X+i8LxTiBMSWKj7--
