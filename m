Return-Path: <kasan-dev+bncBDQ2L75W5QGBBIVV36YAMGQENJPXBPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 25FE08A14D3
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Apr 2024 14:42:12 +0200 (CEST)
Received: by mail-pg1-x53b.google.com with SMTP id 41be03b00d2f7-5c65e666609sf7099696a12.1
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Apr 2024 05:42:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712839330; cv=pass;
        d=google.com; s=arc-20160816;
        b=C2mersFWZMziHiwgGGdUGhiStRIGCeFsHgoPNAhcS49i8MWReXMxpg2+yjnJVXiA/4
         ZCjAqUTkN/umZl4ZkZKjGvUyfLagI+LJATOKPkhCHSnF/9+FiE61I/Tl2Tiq6TB5IgMf
         kij3EOaWtus4Lup7+5mL5oRSNkmkRQW5mgnP1FpAbk38XVIKQpAbRxKocEkdtXIimtSe
         G2U5e5Y4IxSCyrxw95cvylKusvkkzWKpsMmMpq7BwUeEZD6/YUlMX3O5Rg5zWTtdb5i4
         614m4s1vPv7+fGzHi65eSo5bRajvblOTxoKQpivIpNFkKHmaImTP76ZwqEJoRBR4qx/v
         m+Kg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=3IHt6HkBoNUEdndFiF2P5Zl4opH5X4sgopPAYnXwSlU=;
        fh=i8LJwiqsPBu9LTJ/cc6wbakugjAPO9526SFLrpzDDZI=;
        b=ir59sJq0KfYJzCUpAYuhyfdeSon5bTAV8EXYWOkUzI7StguuTwwFHXgjvWN0Vnr178
         YpUAkFC3jQnKKTemVYZeFBTCEdyJU9o9N/DUEBfg5jDLQdQnRGr5jYwaoLkRsHVcs5dy
         raGXzU/SDjb/iyRROQlZyk1sa4+MssFwocaSZRUdMxXblmjqoy/0X5PhO/JfcA4W+QkG
         KSgc1rY1+urljjjTTiEWrYCTXDMdZehQM6O5MKVb8d18sNYII8LeAi2CcUTcgUXiwEkK
         Yq+J6oBVLXOS4cZPZKYnv3LL+GIpdCAELvpXxs3bwNT5KfQvfGdn8MDR6Jiw9DCjP4rz
         IOvA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VRFRu4LM;
       spf=pass (google.com: domain of broonie@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=broonie@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712839330; x=1713444130; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3IHt6HkBoNUEdndFiF2P5Zl4opH5X4sgopPAYnXwSlU=;
        b=sjUxtBHdve2WJftU9sFggHOjkZfKP3I4o+yYa5DYEWcf+BnXkRUbnvrLU7e+Pd2SSh
         onAe7uu2tr2sYX/wt9tY2VKw6A8boipSGaYTLHizQlBGsP9zgsROCqS3WWcBm8bVr6RQ
         1Z4UKTGOk1Ug5DX+/g+u4CVz+NRGfHMNOohn+hfyf0TdTfE26bVkP7W1fXTEudk15twV
         rFR0FZJrCZAAOl2Z0PnpY63Rb9RcFw+zHbbWF7ufI4tp69gpLUGWmRWyAnQ6ZwS0sy9m
         DDYICaNHgyayA5U5I8wfhsslNABbcIXznaNIyPJS4gWhigwqPmB4bYDD8xD+cklJsFYt
         kAaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712839330; x=1713444130;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3IHt6HkBoNUEdndFiF2P5Zl4opH5X4sgopPAYnXwSlU=;
        b=ICJeD/c6i1r3IwzY6jI3ojMj0XEcvjmex7cMCee2ZGhsFhU0e5eyfmA7c2jWzYOEQ1
         e/jIGjOyt0aWYF0WG+9KYaUpXH8GD8ze4jLDuHE3clOPNUG7Z4rALX/BaQs/unhJpJBN
         enq8dUvosv9ckTEItsSoU3yqs3C/C4WsmhHZ6piOqLwr2vffybnlIjevz+Y72ZmVhXDh
         wAJ7f/ji5I9kPjmCOrPQwy/lHXIiV9A7cuzT1T93tv74k7bdHG5jiAe7G0EEsatGh4D0
         qf2M7+VWZos0FdoGl3er5V3aUXTa3ixHa+XyncFHREJraloBso/YOqSzZUuxQyjjB69F
         zCUg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWVfvVRfap7/lFBicqPfnfKyb5eGbXC8Kr7/FX02y6bdW7D+vBOxPy8C0FHcE9d/bTFDjmrKxcnshYrp67DhjCuAKcEue0JvQ==
X-Gm-Message-State: AOJu0YzWqv1HpSXJE6OjC/twE8kvtbUAXlRsHmHmKyKZXWFJitNFfd/v
	iFj1a/Au2c2UgzdQ4uBdzk5MsbYEzBLFn1GuC3gBb+SWyanx8nh/
X-Google-Smtp-Source: AGHT+IGSPYplIZ3PCPo9qp8X/kmQTtP2FULjXzZHwL3ZMH+AW2/xYFS5+XT+oce/jQ5HnmDLDVXVdw==
X-Received: by 2002:a05:6a20:550a:b0:1a7:4f8b:6438 with SMTP id ko10-20020a056a20550a00b001a74f8b6438mr5425454pzb.34.1712839330309;
        Thu, 11 Apr 2024 05:42:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1399:b0:6ea:e009:181e with SMTP id
 t25-20020a056a00139900b006eae009181els654651pfg.2.-pod-prod-03-us; Thu, 11
 Apr 2024 05:42:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVmMsZefdc0liuSKIjsw1jA3g+05uK1/c5WhafcKmTLTZC+UNsdeH/cTyWjZjJI40obKksNG1hwFw9h3wnJNKNPEq61kvYR75OXKw==
X-Received: by 2002:a05:6a00:1892:b0:6ec:ffe8:af92 with SMTP id x18-20020a056a00189200b006ecffe8af92mr6742382pfh.5.1712839328931;
        Thu, 11 Apr 2024 05:42:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712839328; cv=none;
        d=google.com; s=arc-20160816;
        b=IVbiaGmF5MMpE0Rq5fdKoFnFLAN9qzuECwiFpU8h+mQ54vMnNuEErv6i+abKyqhah1
         RBR7fYKpgSrMqdgPZJN3lqeWxjeFb8+a5JeMCInEkOOTwajKEJeMDHS0BT4NFqZiHmeS
         Ipda8Qybt31wWYien4VulYHvGxo62sxytqLrZvBhH66joZfG5oXiUjYH9u3PCkFRe7n3
         r+IUUz63DFgTidtuzI1Br1t1Kazb4m24Avfi3VwQmn0SdiHMCXeMFLSNNxeDdTPxWwkQ
         xFt9UPHNqQ3MTEhSP3jNfp8qUO/PMZDGrQq96Plbipwc/PKIpPr77bQ0wY/sTNzc4Y6Z
         B4tA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=BeD2tLXhJDCp8Hd+iLB4/ol9hRgR96ICz3aVnm76G4E=;
        fh=fmJAQNqzv5Vyv75RDDlN7CK/avNDzxUCRrx53jU3DTg=;
        b=JNiD7ZpIxvM6n6z0ffeFCzLTivGnb/j2feleEizxJDLTWaDK6unqLHUqlVSNPF/l7j
         4swHMeQCfcRGKkfzl1SqC/1n56zy0arNXn62BOQuLc7JE6+DdJ9yN73Rp+G+q8fEcKBd
         9MvdSCoD7EszWjkx10IlnD0F6J8AfZ8S1wYcpvFBd4pLE0Hn2Pyko8NlIHVv9cXMzaKQ
         oKxyt84YyFYr2Z6+oP/XFDZqwmTH1igeqSHg5ZCrAtynGpd74hdwfta2jzi6zBJwCyWg
         J4wDjVfQ36xHoQfBsh7RupSKNL5fbiAgm4Fo2lL9+s7swW+3JAye7jKfkp2jy3jPrEDM
         0Sgw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VRFRu4LM;
       spf=pass (google.com: domain of broonie@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=broonie@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id n4-20020a632704000000b005dc13d8277dsi91553pgn.2.2024.04.11.05.42.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Apr 2024 05:42:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of broonie@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id F3AC9CE2983;
	Thu, 11 Apr 2024 12:42:06 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B9039C433C7;
	Thu, 11 Apr 2024 12:42:02 +0000 (UTC)
Date: Thu, 11 Apr 2024 13:41:59 +0100
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
Message-ID: <a9a4a964-6f0c-43a5-9fa8-10926d74fbf1@sirena.org.uk>
References: <87sf02bgez.ffs@tglx>
 <87r0fmbe65.ffs@tglx>
 <CANDhNCoGRnXLYRzQWpy2ZzsuAXeraqT4R13tHXmiUtGzZRD3gA@mail.gmail.com>
 <87o7aqb6uw.ffs@tglx>
 <CANDhNCreA6nJp4ZUhgcxNB5Zye1aySDoU99+_GDS57HAF4jZ_Q@mail.gmail.com>
 <87frw2axv0.ffs@tglx>
 <20240404145408.GD7153@redhat.com>
 <87le5t9f14.ffs@tglx>
 <20240406150950.GA3060@redhat.com>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="dyKDlGTPSGYPjOVd"
Content-Disposition: inline
In-Reply-To: <20240406150950.GA3060@redhat.com>
X-Cookie: Elliptic paraboloids for sale.
X-Original-Sender: broonie@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=VRFRu4LM;       spf=pass
 (google.com: domain of broonie@kernel.org designates 145.40.73.55 as
 permitted sender) smtp.mailfrom=broonie@kernel.org;       dmarc=pass (p=NONE
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


--dyKDlGTPSGYPjOVd
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

On Sat, Apr 06, 2024 at 05:09:51PM +0200, Oleg Nesterov wrote:
> Thomas says:
> 
> 	The signal distribution test has a tendency to hang for a long
> 	time as the signal delivery is not really evenly distributed. In
> 	fact it might never be distributed across all threads ever in
> 	the way it is written.
> 
> To me even the
> 
> 	This primarily tests that the kernel does not favour any one.
> 
> comment doesn't look right. The kernel does favour a thread which hits
> the timer interrupt when CLOCK_PROCESS_CPUTIME_ID expires.
> 
> The new version simply checks that the group leader sleeping in join()
> never receives SIGALRM, cpu_timer_fire() should always send the signal
> to the thread which burns cpu.
> 
> Without the commit bcb7ee79029d ("posix-timers: Prefer delivery of signals
> to the current thread") the test-case fails immediately, the very 1st tick
> wakes the leader up. Otherwise it quickly succeeds after 100 ticks.

This has landed in -next and is causing warning spam throughout
kselftest when built with clang:

/home/broonie/git/bisect/tools/testing/selftests/kselftest.h:435:6: warning: variable 'major' is used uninitialized whenever '||' condition is true [-Wsometimes-uninitialized]
        if (uname(&info) || sscanf(info.release, "%u.%u.", &major, &minor) != 2)
            ^~~~~~~~~~~~
/home/broonie/git/bisect/tools/testing/selftests/kselftest.h:438:9: note: uninitialized use occurs here
        return major > min_major || (major == min_major && minor >= min_minor);
               ^~~~~
/home/broonie/git/bisect/tools/testing/selftests/kselftest.h:435:6: note: remove the '||' if its condition is always false
        if (uname(&info) || sscanf(info.release, "%u.%u.", &major, &minor) != 2)
            ^~~~~~~~~~~~~~~
/home/broonie/git/bisect/tools/testing/selftests/kselftest.h:432:20: note: initialize the variable 'major' to silence this warning
        unsigned int major, minor;
                          ^
                           = 0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a9a4a964-6f0c-43a5-9fa8-10926d74fbf1%40sirena.org.uk.

--dyKDlGTPSGYPjOVd
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iQEzBAABCgAdFiEEreZoqmdXGLWf4p/qJNaLcl1Uh9AFAmYX2pcACgkQJNaLcl1U
h9BWSAf8Ce2hIytHCkF6x1UmNuIwLSR+DyWc98yv65Jm8C0/yq8fOxHApvkBkoJD
TPfPTSw/my83GMGiSkXAyoMcRuK6C5MS6Nnr74SPv8y6sweoXDEr2lQ8MSr3m08e
HSE21HDCyG/zXhs00vukeR55ffNA7VGDB3BFoogyVDtILTpYgjz5xoJeFCyRQ6Kn
P/QpL4Ig57dAWqYfCk3ya6OFpwNN2GFeBV6OL8Lmxa4EXXHqJY0S9Zkn8Rg9oISf
qisPgNrW2RZ9xGHlRKAw4/g2Rqu5NHSUXQ3zhf7nK3m34MU2CccG2400FyF/X9u3
JO2v7g6vTGB3SDPcCJhahFtF76LMgA==
=8Eym
-----END PGP SIGNATURE-----

--dyKDlGTPSGYPjOVd--
