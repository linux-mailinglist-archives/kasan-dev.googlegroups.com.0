Return-Path: <kasan-dev+bncBAABBN56UP5QKGQEDNO7IQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A08A2730AD
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Sep 2020 19:13:28 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id z75sf7159386ooa.21
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Sep 2020 10:13:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600708407; cv=pass;
        d=google.com; s=arc-20160816;
        b=JGjpjsW+1kcJ+7nA+/8p8F8nIzDyejzqyeo2Lamujh9m0nJLbB2fevW4Ev9ljEWh50
         oIUZymtzL5s4s/hRlOo7vbe4NirFPgMmD7/7rJWQzXOB4JfWTk3TS/tXgiuhK/OQQYSD
         2cAnWwKVPgTyHUDGY8gJM8y59Gp7mS4+Y0MgrQTYqJIfvHXfZ/b0sUc4knre/Jo0ydEc
         oUgYPuwVBCrKIsWiU1dcwgor3v/lZKPQH/kAmopGSt6m0FOTTKr/1OeXnAPZi9d0vMHF
         Za4iIukuOjAeUFnUAVIZlAJRqG6wbVFX37ACAS4rqFrwXN+4T8jzBo1ASmypLFq6c6p3
         JVYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=QnOZ06m+HSf9zF2uC6S6n7WLilhNhlV/jmV72ySH5dM=;
        b=sQ/VNqayeh5MlRWjQhYAZ/oXFTLP63QIDmLcEz+vFxR+oLg2+HySfdKbdwmsnDUDnT
         mhlh3U/WqEamwLY8cUkIuFc6xGlprBBzkXF8lUz7vnOF7Kxo87Rg2uPnLcFhbuYEUuiW
         eNQf0BXfC6S2GvpkLOv1c/UpdVuMQAR0HAQRu4qHhQ8WemFtCKupbJPPtyeUb6A+sruR
         8ivPup4x+Xif9VyJFzZX1eI4MByBqUUM3L3MtVPxc9gsxk4JG6VGGMhD7n9TL+J9iFS+
         d2WyazgkzOTH4sdrPRinL0d2IX6Zhr6EA07VuIRcrNyPRM8NKb1sM3QgCVh9mF6zrvFb
         73Cw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=1ijNGgPZ;
       spf=pass (google.com: domain of srs0=dqke=c6=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=dqke=C6=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QnOZ06m+HSf9zF2uC6S6n7WLilhNhlV/jmV72ySH5dM=;
        b=WVE+2p7nAJw6Sc7Xkpx/OE7dNQoj2ZSYSgJxyr8OoFwQy+6H3RyKk2ByIkMY9MMlhz
         zezoU36EVb0nDkE+h3Yloebcw0WKNQpbbvAH0jPUaXY1tHrBqkFWEhuWHY4v0uuBXQNt
         D/VeibaK5tbHkT4D6KhVmF0Y+YkoT8RJPhbi5yiOt1prTJp5V58kD0ufx19hSmRtWUxe
         Tc6wWAM7tY9bbCSAJVwLiJkItmDxnUgRMC2+DzwzwvKYLM5sZUai4NJ2caZiy5ukv5TY
         lrZbH4cK8VUrPbRH/P99XTcGTx0G7GW9UcuAZMlPoChRMjgwhBvfGGMpDSjUZ7ikvHMZ
         cQCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QnOZ06m+HSf9zF2uC6S6n7WLilhNhlV/jmV72ySH5dM=;
        b=QG//+kVlUYOVzrdnA03fGQF/McFvQeo+3/6J9Ca9Ce2UnURJBRQxjdhJsf0fKygClF
         WyNqNaUxizCduUD+buLxRwzbPpjOfxV1S9eYMwWj/pK6coCFGnoGVJplcAef6V5gSEr2
         a22dkuSO+Szk6KxT2D+7V+OeX2QBdhnYsdHqehnk5QZepsRE1fvmdqu5t9IgxcW8SL5P
         SAz1UE3RFmqoBuSDmCfXxyOD3iSJm4GtapEu5OZftxdk5hU7Us64uLn0cNyP8rCzy+pd
         z5NUo+yZvzg2PDS34pVhNfFzTS1bnyDLcxTWXPUReSTwtodngtR7LZqT3KlQwdvxmSyY
         ESdQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533oehRGlUNd8z95Vg2lJwVTuKCbnDMwXumn7sxr5GK57GWQ2gid
	bB3JUW77j0vmlvjp/kpjcHE=
X-Google-Smtp-Source: ABdhPJwLm1eYH7qBD5Dl/PezOVXc8TFOujsSWNmP+ni2fKew/SaZymo0mUXyRSpVpbuPtW4SM/YLzg==
X-Received: by 2002:a54:408d:: with SMTP id i13mr241121oii.156.1600708407200;
        Mon, 21 Sep 2020 10:13:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7ad8:: with SMTP id m24ls3046683otn.8.gmail; Mon, 21 Sep
 2020 10:13:26 -0700 (PDT)
X-Received: by 2002:a9d:7dd8:: with SMTP id k24mr356769otn.160.1600708406854;
        Mon, 21 Sep 2020 10:13:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600708406; cv=none;
        d=google.com; s=arc-20160816;
        b=sE6dGOkDvdKpHCBvEdO7kVxWIHNvCzr++CtfLgJEmGJK/bC7aT24LXzY+52XgCYvZ3
         5ZgBQhwbctOBFms7EWLMXYAGIbLQPaSLEf4laWfsjnQbd1DhWWLHlvu0hzCpMPptEkB0
         ReeL4JuE4t0dxAC9SHA98DYWCz+G/muh63dfXyl+yXud75pa/oNTsK3tBTZEsHnHrZ6r
         U3Q/IAvQ3YBxubkZHbKOAJibxuuwhKZmlHpBOq6rzpevdUdbXtjThX8eSWYbBaR43NxG
         T0Pi2mRew5FSIUrAheFPgEqVd5PLCNALFTHzUBrEfbKThuHNsZHsC2P31LcbRA7XIOyJ
         553Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=pR+KXBQDolnTwvcjsxqeGpHvkdNbMhlvFuzpuFiWQqQ=;
        b=O+lWn4umfFUWumuSFPZHunCFOtDoGmgZlX3Ak5Kbx2mqmnAyKtyZMBimvXiXfQkuBO
         95ASMmnaPjKApTE3IqsrWNBznsLw0Q6gK9Zozps6cBMA54fYUq5u4/r53N2+oXwCHeo/
         hkauimCoGaJbrfGezmGX+NSPqt9/xI4PzUQQ8unGR5Yj6sD1niRpXmhpNki7qfYelP6s
         UnWYRW51BhMZA2OvIuIROPl/ZIUMl/8SZNHVyziaQcCMuuOO4QrsT1T3uI/L+3MUGoEU
         N94WKTF3MGnP2cDEi4XxtJ8HnGu/VA7Q+w4oJCtr/I5f8Z4s3OOQqwteIVmlcGDPnrv7
         IcEQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=1ijNGgPZ;
       spf=pass (google.com: domain of srs0=dqke=c6=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=dqke=C6=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id o22si726411otk.2.2020.09.21.10.13.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 21 Sep 2020 10:13:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=dqke=c6=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [50.45.173.55])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 1305520758;
	Mon, 21 Sep 2020 17:13:26 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id D2C8D352303A; Mon, 21 Sep 2020 10:13:25 -0700 (PDT)
Date: Mon, 21 Sep 2020 10:13:25 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: akpm@linux-foundation.org, glider@google.com, hpa@zytor.com,
	andreyknvl@google.com, aryabinin@virtuozzo.com, luto@kernel.org,
	bp@alien8.de, catalin.marinas@arm.com, cl@linux.com,
	dave.hansen@linux.intel.com, rientjes@google.com,
	dvyukov@google.com, edumazet@google.com, gregkh@linuxfoundation.org,
	hdanton@sina.com, mingo@redhat.com, jannh@google.com,
	Jonathan.Cameron@huawei.com, corbet@lwn.net, iamjoonsoo.kim@lge.com,
	keescook@chromium.org, mark.rutland@arm.com, penberg@kernel.org,
	peterz@infradead.org, sjpark@amazon.com, tglx@linutronix.de,
	vbabka@suse.cz, will@kernel.org, x86@kernel.org,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org
Subject: Re: [PATCH v3 10/10] kfence: add test suite
Message-ID: <20200921171325.GE29330@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200921132611.1700350-1-elver@google.com>
 <20200921132611.1700350-11-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200921132611.1700350-11-elver@google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=1ijNGgPZ;       spf=pass
 (google.com: domain of srs0=dqke=c6=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=dqke=C6=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Mon, Sep 21, 2020 at 03:26:11PM +0200, Marco Elver wrote:
> Add KFENCE test suite, testing various error detection scenarios. Makes
> use of KUnit for test organization. Since KFENCE's interface to obtain
> error reports is via the console, the test verifies that KFENCE outputs
> expected reports to the console.
> 
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> Co-developed-by: Alexander Potapenko <glider@google.com>
> Signed-off-by: Alexander Potapenko <glider@google.com>
> Signed-off-by: Marco Elver <elver@google.com>

[ . . . ]

> +/* Test SLAB_TYPESAFE_BY_RCU works. */
> +static void test_memcache_typesafe_by_rcu(struct kunit *test)
> +{
> +	const size_t size = 32;
> +	struct expect_report expect = {
> +		.type = KFENCE_ERROR_UAF,
> +		.fn = test_memcache_typesafe_by_rcu,
> +	};
> +
> +	setup_test_cache(test, size, SLAB_TYPESAFE_BY_RCU, NULL);
> +	KUNIT_EXPECT_TRUE(test, test_cache); /* Want memcache. */
> +
> +	expect.addr = test_alloc(test, size, GFP_KERNEL, ALLOCATE_ANY);
> +	*expect.addr = 42;
> +
> +	rcu_read_lock();
> +	test_free(expect.addr);
> +	KUNIT_EXPECT_EQ(test, *expect.addr, (char)42);
> +	rcu_read_unlock();

It won't happen very often, but memory really could be freed at this point,
especially in CONFIG_RCU_STRICT_GRACE_PERIOD=y kernels ...

> +	/* No reports yet, memory should not have been freed on access. */
> +	KUNIT_EXPECT_FALSE(test, report_available());

... so the above statement needs to go before the rcu_read_unlock().

> +	rcu_barrier(); /* Wait for free to happen. */

But you are quite right that the memory is not -guaranteed- to be freed
until we get here.

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200921171325.GE29330%40paulmck-ThinkPad-P72.
