Return-Path: <kasan-dev+bncBDBK55H2UQKRBEFAXSMAMGQEWQBBUFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 094415A77A3
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 09:38:57 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id h16-20020adfaa90000000b00226e36cc014sf751051wrc.8
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 00:38:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661931536; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vl7w2bvRzBtKo3MXJSEbmfVwXxU6tib9vMJ6sxzPxVAE3AtO5yNP0lOwrVBffJiVUT
         sDkrD+vvXbrxp4AzTVnmD9COQJ8Lu5MdAVFAdAsLwYPXGtnG+UWlgPZ2bDGTer6ZyK7b
         rQjZMEO9evz2K+ir8abdkP9kYEoe/eU+6RIJD5nv5BTz8cbatMQQsYAI12KukG5nAkNR
         KUou7ZM733v/NWod1MZXLnpj7VpJx+GoWjQvNyse7u+lRA74PxFjuvdHyhZDSPbLx/SI
         bUu464WIGdQShsonkisLZ3nm1j6OtKmDUiMuJLYaM/82lUbxY5PjiRrxeRqe8CGxyZ9E
         HOgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=7FDt5028wCQu3ds8kpcsvFh97IjVhtgOuKJF5X+gP4s=;
        b=wY6OwQ+f2Vy6kHwZ8QVBrT5dQkS/MNnBDklu2HlMJSTctQRpCkdlkSNRpWykTFDqWW
         hzGhxteiaEhMuRsVQ7vEuEL1d6j2kqt3J0ZFTBIN/byBqdil9l4f5QOMFSmGIM6bbcTS
         YHc6OQqO5Akf43w03TJpTcwbdt4+nCxsmSlTg0hSO0SeZCV+Fm066zGRqwUZD1xV42d3
         Ke1vrI3UZwCoifTBVIIoPcOZUBWzDVFbkHp5e3AL0NsILrenQGLEy6JbGQ32N9tq/W60
         puNEnIDqzRx6RNIL13eqU8vXLaj08kj5yb9sJltHqz/n+vrkMEx5Tb73SzkoerDOG7T0
         bsVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=OachOLS7;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc;
        bh=7FDt5028wCQu3ds8kpcsvFh97IjVhtgOuKJF5X+gP4s=;
        b=K/V9K7PJfbVz7DUVitRtKJkSOhuPi1hMTN/bye02aV84orhfOwu2zymR4xvQGYP6Fy
         gk08dOrneHgKiB4vlcy00oK4E6NMhiG2J54Auc8y+CJmTR6I+rYUASA5Jvj4e53JGjKO
         Pib/8ofx+o7nydverPO5JzqlfclDthW0OMbQoQr4RbXYlBbBpDkFSkx8VHaSHYlsrCAn
         4BxkLQtyGUxz2ctSUPz9buBPt6BWPU0W0wcA1JRKayE+NoVivCpzjrX2sHahR5uuaBGX
         DxzN8X8twEgf4bLSVsFwoBDFwGh0ocsnU+I3WJBojD226ql8xBcN4jI021XVNrAXjpsJ
         gFEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc;
        bh=7FDt5028wCQu3ds8kpcsvFh97IjVhtgOuKJF5X+gP4s=;
        b=BZP7WEYyI+Fqqznb43m/qe1Wp4BcPNi1KqDVCuVrGb8AX1AJ3ZYUOg89NJBF+7Syxm
         wW4Zr5FsBTd+aczvLtk7TXBSvMCVsKDB82bi/gbLbhWCad6FwdZ4cj8mPR5H2XdPfuDb
         1ZYyxQBOzlylo8yEnhQyBfOioWlz0bpmtDQ1CVTBBOkzdcYXLknMezvUlg5EZQEOfrRy
         stOs4xYeK4l4yyO4UfUe7GEtib8HuxY3xA8fYjkuVjWLzgf60Y/tVIm8wL4VI3TriQqo
         9m00FW6VhCaWOIu/nMXIzsktUMhWAfjYQ1SlxxqVXxCWy56cT6vsECJasCbIwiLhraiP
         Tcwg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1HA/q3Q2btm6sy1QEigRGAfmGnuROF7hJJ4BBd68CRCrifOoNF
	D/WnxF4i6byt0FxerqeZ2vI=
X-Google-Smtp-Source: AA6agR7yyNEmGmsMiRouBiSwkcgR0v6cX5joc/Y7pSqTilxnirO31+1ELkSGS5vtDvFFCFvBqXn9Yw==
X-Received: by 2002:a05:600c:29ca:b0:3a6:75fe:82af with SMTP id s10-20020a05600c29ca00b003a675fe82afmr1106605wmd.3.1661931536783;
        Wed, 31 Aug 2022 00:38:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4848:0:b0:225:58db:7886 with SMTP id n8-20020a5d4848000000b0022558db7886ls9726785wrs.1.-pod-prod-gmail;
 Wed, 31 Aug 2022 00:38:55 -0700 (PDT)
X-Received: by 2002:a05:6000:1d8d:b0:226:dabd:596d with SMTP id bk13-20020a0560001d8d00b00226dabd596dmr7990358wrb.174.1661931535555;
        Wed, 31 Aug 2022 00:38:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661931535; cv=none;
        d=google.com; s=arc-20160816;
        b=htc/fPjqC5Od33nA52mpO9u2VxzHs1k2zfvHZw999TaQkDhmOVJGVzAPDZLmyivB+O
         wi9Ao5z9Xj8o+hza6UVA7b2OV0wSMKaOV8kHLt0qP+qoLk9qTGBKJM2FfVdHZMdz2RuB
         YPJbcP+uo23vlyisRaGMP15+YKscIS1R2oOcksecdQMUxQXzvG//xLfJQS7E7qTF+NmW
         r7DC/y5nKiJ25U7ZRmVyS2m7qw2fp8LXztohpvGhyhgsHrJEoOr5KAef1CdZpW6DcElq
         j82FgW/rPNJJy8RJoiSKUXAW7BxKs3zDv0XVFNFxLvJFDRbh3QihvO6jw7XahMZsNAsS
         uaUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=gDCNZ3f2D6OuuyZZIQqudj53nBzwis7zfrQMn3P2Fjk=;
        b=yUjaNGEzaZc0B3O6O48VrN+xKMoSV/45XJZT6WQCqdt+6vCk4BunfVliGmDC1Ircd/
         osfRPUNdgLh35sONbGYguS+UpuYUsRiQrIdIoF6gYqXtSVF321fmqeg6N2NgV+oMPm0A
         5HWYwr/HsOiLl5XLD//9Dmj+rlJybtleIS4F1M24v0qcc1H9WPmEx0xoB8VkpsJOijY9
         7tnQBFHSAAH396BmZTqrvqjYEuiLx0uhYqjCPbV8oGh8yg03d2RVHm1bF7Y0WmOU8sVS
         9FBboLj5rT5kcDZoFSU9YAoDBpqktZD9rjh00pFFXT9LiDK7ikQ55lgc8fvbCzVDIyYv
         7ZjA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=OachOLS7;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id l3-20020a1ced03000000b003a5582cf0f0si104420wmh.0.2022.08.31.00.38.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 31 Aug 2022 00:38:55 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oTIIy-004tbB-R2; Wed, 31 Aug 2022 07:38:32 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 8A485300413;
	Wed, 31 Aug 2022 09:38:27 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 66CD32B843CC0; Wed, 31 Aug 2022 09:38:27 +0200 (CEST)
Date: Wed, 31 Aug 2022 09:38:27 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
	liam.howlett@oracle.com, void@manifault.com, juri.lelli@redhat.com,
	ldufour@linux.ibm.com, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, changbin.du@intel.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, arnd@arndb.de, jbaron@akamai.com,
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
	kernel-team@android.com, linux-mm@kvack.org, iommu@lists.linux.dev,
	kasan-dev@googlegroups.com, io-uring@vger.kernel.org,
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org,
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
Message-ID: <Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
References: <20220830214919.53220-1-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220830214919.53220-1-surenb@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=OachOLS7;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Tue, Aug 30, 2022 at 02:48:49PM -0700, Suren Baghdasaryan wrote:
> ===========================
> Code tagging framework
> ===========================
> Code tag is a structure identifying a specific location in the source code
> which is generated at compile time and can be embedded in an application-
> specific structure. Several applications of code tagging are included in
> this RFC, such as memory allocation tracking, dynamic fault injection,
> latency tracking and improved error code reporting.
> Basically, it takes the old trick of "define a special elf section for
> objects of a given type so that we can iterate over them at runtime" and
> creates a proper library for it.

I might be super dense this morning, but what!? I've skimmed through the
set and I don't think I get it.

What does this provide that ftrace/kprobes don't already allow?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yw8P8xZ4zqu121xL%40hirez.programming.kicks-ass.net.
