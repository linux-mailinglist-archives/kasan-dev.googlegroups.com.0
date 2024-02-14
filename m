Return-Path: <kasan-dev+bncBCS2NBWRUIFBBSNLWOXAMGQEWTKB76I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id E9763854C0E
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 16:01:30 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-5119f6dca82sf1421062e87.0
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 07:01:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707922890; cv=pass;
        d=google.com; s=arc-20160816;
        b=hZrguhcL/ysKlWXUBnxwenfIs4fPDVseBIN1SkLrEwUjUkHJMMUx6mgE8iWaFecbph
         k0lAmFHKijsBwbMEJKmVM9gnfu3CDvg0x7G+q6vmsnwQGf8bz+dXuTaKBsgDZDmuSXlO
         7VI/wHdw2GURCJcEbDq4akiXRJEmG8zblWEr3RXpLXn0zTCvhGAVuHDWbnJybl4agmMP
         7O/r5QpFF/qwtVdqnMgRpFACkt57TL0YS11M2tamGExva4WDoasGlgFnr21yaCauU+I3
         VV4Sjb/avol8jZnvW8QGpSdbMYegasdThHgRvTNVSshIlfHbuul6pjqVkbk8CXdO3W5m
         RtUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=b5uF1PtEG6etNLEvosgAX7X9xQqJcqKlB6jxjy6lWhs=;
        fh=zzEsDoo1TiGOoL8wZYWgk6jHuIvaRhtifyEiC32V+24=;
        b=Ki0ILU8NeMBRff3orIMXU+XwUdJyP9Bo8v1YwipJIdjibi11wKS/wy4GPdt68xUrsR
         XAElgwh0c4wsDKzME30oyljLuZXgYXE8iK2kWW7gfNaeMLjlrykeI1fK/C28z74g0Ysz
         vGEFS8ZBP5OEE33mV8EEI/IQXgODg+acTyGBRZ5K2qyAtNcCWlMyTl2nrx06qUzWUgap
         Kx2R4xtuEXuFUT5hkHz1XDYVvZXGwmsKgC/bMC0jyZK8L0N1opp4Y/LdKbngzKgkuwNb
         wrYXnjOu91I2hc3VP/It9X2zLI2zxbywK7HCfMmWOo+bMb2Wm0ZJpUyWSxZs/8hvO0Ny
         aw+w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ntCXoZ0V;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.182 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707922890; x=1708527690; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=b5uF1PtEG6etNLEvosgAX7X9xQqJcqKlB6jxjy6lWhs=;
        b=V8mIqxBgn2Puk1J0eZyPDC9c2WtgMXVHgiMT9aBhj0hUnSBblfvCfcH+U8041xnxoN
         5Xz8KpvK8F67QF2WBjuafJlDY2ov3toIXZGxUUZn3tMdaquU8eDT3o7n106iOq9NgsxE
         D+b1gMf4Dx8dQRtq0AlgtW94/H4Np1WlqvvuMkzA4hvN1ljqbCxrZ6agH5noj4+jxbyt
         d1lueUxXdTP9bnbs4bPc/hy9HQWW/rUgYq2SmGrr3x+Y2WdLaYAh35tc7rLzc9btbwfa
         KvefsMyLmmken41HGOv16zQp8U+FK01rd0cJybHi52mccXwFIzImp3ttn4OCCxoRWyPK
         72gw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707922890; x=1708527690;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=b5uF1PtEG6etNLEvosgAX7X9xQqJcqKlB6jxjy6lWhs=;
        b=PGLtz6EFyHW2x24rKoeTP06NXZ3MMcliNGLpnEdhio4uuBRkPTkJ6f98U6pGD7WPQ2
         35Bwcfrfqgc6q7yeFe8mDHO5+96vaKKxbFi8/kMtvD68aJ0GkDiAAYj7xhndKr4wuQEg
         uMXHW6VO/sgJ0ufvXnF+F1pN8CLXTyHDDWRJvEpwMCl6WMxakW2Oq6ROyyjX0eH5PL6U
         +1puM6MHJbXCAwCJDFrOYuwAZ8EhODDAD2trfEdI1LP1d+I0yTfj+7tuz2zzh4CcXzwC
         9E1MMbSSsXB3SlMEK/cjQ3LmxlY/LC1X9AtzPsuLTb0ml+jjg851aVe9g4Y6+IsIpGDl
         Rw3Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXljUapqVwlddUT6HDvlA0rvtw+D0GcQyiQgbur7zbHYfIRzCk+kdj7RFoaHlDslzrUK7SygzW0NpunPTYsY9dJLrep4OL25g==
X-Gm-Message-State: AOJu0YwMms5tiR9PCWww+JSYX6Kg7ft342egXf3cZcVQSN6HZ2vT6/NB
	t9CSm7FxVJebhs3rzLCQr36SQUHH19juYvg1ZnjTr0cR7V03dkMf
X-Google-Smtp-Source: AGHT+IHtYsGVA+nnyW/cfbG1a6Lj3skTf8RdSUlkBBfKME1Ig538T6QxqdSF9z3H9UdbeB79uukKEA==
X-Received: by 2002:a05:6512:4027:b0:511:ac21:57d2 with SMTP id br39-20020a056512402700b00511ac2157d2mr1362620lfb.0.1707922889710;
        Wed, 14 Feb 2024 07:01:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1385:b0:511:528a:c0d6 with SMTP id
 fc5-20020a056512138500b00511528ac0d6ls270990lfb.0.-pod-prod-09-eu; Wed, 14
 Feb 2024 07:01:27 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVirxK9/vmjvMrEJNqrUByNYz4AWlYZ7BXBjO6f02DtxvLdVB/XWHlvVzS8aUftTxbwJ0jObDSLrG3onHBDJl5ZMLs8DxysC6IUPw==
X-Received: by 2002:a05:6512:2253:b0:511:a4c4:b2c9 with SMTP id i19-20020a056512225300b00511a4c4b2c9mr2387920lfu.26.1707922887492;
        Wed, 14 Feb 2024 07:01:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707922887; cv=none;
        d=google.com; s=arc-20160816;
        b=C6l60ZjZZM/lqkM47UP4sYHo/8lcwtIVJ4NsstAplElEK7Ze6p63X3g/M/tMj86ZHY
         6N93UhjwRSnizWdIssKBaPXxKCbabS29Qp+Xb3e5GMNEBvYmncWOkkEdYyo4b81Q4yk5
         caC+M5A3VY6Xc0yUm8/BXH0YYXD9rzjnviHs6oorPkG4pQ4e9gi8vSSDZQw2bS58a3HM
         ybA9RAyZ4WqwOMbPweXu6wF3Dq1CeTYcHktJTUfQtXQA00+rYJ9M7t5sV1a3trsK04V8
         JaFmJgDFOiMdg9qnte3wPjOR470mQdiOYSgsJqawc7BnMWw+ECVS5bYt8zzOEBKacgTT
         WgTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=t/AETcYHznmpv4/j2syV358dOWN8/yUI1GROKTci8BI=;
        fh=6NJXVWCr3/Qa2IBmOZVsPPQQ2JQLGpobT/L+zYMaNtI=;
        b=OINiSkdB1Vo5fKnHj7WhUz/M8dIJ/QuuNX89TNm2Ue+WpAbAgtw013DFpYMOXAzjeD
         9D8i8EVT1yhHDkNq9WS3TRX2Zeh6hUssiCNPfhrjf/Jwj6piAsSH7F4rQcmK0Yhhgy0f
         l/6yRVlPXmqHbjEgYDWQVJwIPuBlgTphEdQFKAPwvA/w+99eS4YK4FaQT664mg4EUiVT
         lkIFwAkDH6ICm4NfB2Fy38wXxRpqpjMise4mvYXHHvD3k6rxq9tlYTg3qj0GGJAaNrc7
         M7SL4v+Uh1I8SkSCCvwGBhaXUkcRmPq7M31nC9RF1xIg6mkj4zKxMVq6F6Ncv8UcjmQ1
         D53A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ntCXoZ0V;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.182 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
X-Forwarded-Encrypted: i=1; AJvYcCV2AbdFdfg5GDCs0ra2ZRblowq/v4ZiOfz/7oFeGzLWXn/WVg6qKHXK5aGYg0zpt5bvKL7abG8UfbYi15SXcvSqlOAkQK2EioM+sA==
Received: from out-182.mta0.migadu.com (out-182.mta0.migadu.com. [91.218.175.182])
        by gmr-mx.google.com with ESMTPS id k41-20020a0565123da900b00511495618fdsi600885lfv.7.2024.02.14.07.01.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Feb 2024 07:01:27 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.182 as permitted sender) client-ip=91.218.175.182;
Date: Wed, 14 Feb 2024 10:01:14 -0500
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Michal Hocko <mhocko@suse.com>
Cc: Johannes Weiner <hannes@cmpxchg.org>, 
	Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org, vbabka@suse.cz, 
	roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net, willy@infradead.org, 
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, 
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org, 
	peterx@redhat.com, david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, 
	masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, hughd@google.com, 
	andreyknvl@gmail.com, keescook@chromium.org, ndesaulniers@google.com, 
	vvvvvv@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, 
	cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, minchan@google.com, 
	kaleshsingh@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, linux-modules@vger.kernel.org, 
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v3 00/35] Memory allocation profiling
Message-ID: <ifz44lao4dbvvpzt7zha3ho7xnddcdxgp4fkeacqleu5lo43bn@f3dbrmcuticz>
References: <20240212213922.783301-1-surenb@google.com>
 <20240214062020.GA989328@cmpxchg.org>
 <ZczSSZOWMlqfvDg8@tiehlicka>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZczSSZOWMlqfvDg8@tiehlicka>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ntCXoZ0V;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.182 as
 permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Wed, Feb 14, 2024 at 03:46:33PM +0100, Michal Hocko wrote:
> On Wed 14-02-24 01:20:20, Johannes Weiner wrote:
> [...]
> > I agree we should discuss how the annotations are implemented on a
> > technical basis, but my take is that we need something like this.
> 
> I do not think there is any disagreement on usefulness of a better
> memory allocation tracking. At least for me the primary problem is the
> implementation. At LFSMM last year we have heard that existing tracing
> infrastructure hasn't really been explored much. Cover letter doesn't
> really talk much about those alternatives so it is really hard to
> evaluate whether the proposed solution is indeed our best way to
> approach this.

Michal, we covered this before.

To do this with tracing you'd have to build up data structures
separately, in userspace, that would mirror the allocator's data
structures; you would have to track every single allocation so that you
could match up the free event to the place it was allocated.

Even if it could be built, which I doubt, it'd be completely non viable
because the performance would be terrible.

Like I said, we covered all this before; if you're going to spend so
much time on these threads you really should be making a better attempt
at keeping up with what's been talked about.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ifz44lao4dbvvpzt7zha3ho7xnddcdxgp4fkeacqleu5lo43bn%40f3dbrmcuticz.
