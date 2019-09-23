Return-Path: <kasan-dev+bncBC6LHPWNU4DBBH4VUHWAKGQEGRODDBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id AE276BAD4F
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Sep 2019 06:31:29 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id q127sf9397313pfc.17
        for <lists+kasan-dev@lfdr.de>; Sun, 22 Sep 2019 21:31:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569213088; cv=pass;
        d=google.com; s=arc-20160816;
        b=IXWh89eUE5n/fy5KZvJk3YPszc3TA8voDZmzx14CQHvqYv8qf8IG8mN6BILzlBLYED
         PLwqlfdLnDZOBdrQHAtc7ogAdf/oB6mOFN8FAzDrIPLkuG99EH9kY2M1nXxjudw8pJ5W
         6liWcgz+4OE+Mybj90G3QVzaRz4Jlj2eMAqZFilLbXXRaBkz/Vstr+p6GtV3ywdgk5fm
         v+WrATkXkQzCXdzRjUdbdHqfGSGnSgbVywtbJFDvRCSkngVCvH2GCALG4UKoBCm5oifT
         nWD/Q2jXBZPRSHrWWE7+oSAvERzTaI0ycR0LiQoYRvGI7Nfxtl37FvbGC1xiQZeXj+Af
         +s3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature:dkim-signature;
        bh=KnEDziCwsp6+g+HaMzQyW17+goWhQGK2Kg1J2Rio04w=;
        b=AWc7tyzZoXsgYW/somnS0vgsglgCnaYpY6HujaAPs6xsl7SCvNpXs4hTFM++qjfxQe
         mjg99nJll4a/h/L8eqnbID4zJPPFzYYrlGf31yadPn402HcgCUL3NUVEAoDDtDOsBUb8
         rcS1jSrA3tegz3VJnIUIdWC1oBSo4C4jxeVu1aKaofKwqugrkIsI+GMgGCQuJ9qYFpR2
         1PHEhiiDKEjzztKc9Pu/NZHgikGT2hvMqGvXiXV5bNZX6TENRoZlTxOvb2TpQftP4HhM
         yZkKaN9g7DuZw+I2bFF/BU5bEPhe60xPQ/sWfyUBRzTviAbaLcbvU22H0w0n3BU4Wv83
         ZDyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=kp6S8U50;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KnEDziCwsp6+g+HaMzQyW17+goWhQGK2Kg1J2Rio04w=;
        b=l/oja3XkCKYMs2ZYFua2z3ykPnedcdrUbdYiUhLHDcEXahcc4XlLrFngEGCXQ+rfFa
         R18X2Ej77S9o7QUB5meMgq+U2/Ddgki27Nb3kdCWiWJ15QR8l4LtbGJj+7axEF2r3d/n
         re5mMiQbjSD3ZOPpC7Ql9n0BjPliWvdFghNrVzZFf6RtF577PmQ4azEeQbbNBn1t+MnB
         HrI0qNW+TxzgKmnfUQ28XVUZFka1w9ZCSIPeZtsDC8HFEe+hhqpFrgH+D3Y4xvAZcEIU
         Onxiku4f8ExY0+TvqDeret7ZSyPrqwP0VeOPFHk+ZC3FfuTzDHfpewq6VggCviXSQpTx
         cbVw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KnEDziCwsp6+g+HaMzQyW17+goWhQGK2Kg1J2Rio04w=;
        b=iTHIUESe0eYf8PPjLKGWbk1wTc3LnnpvjUJOf/wJMCekktOBxnRjwFbNKQtGvWW80P
         b/AVBcEWrtyjjj4DjtggkOLvqd8kj/RbnH9CfSgZjgibEx595WGwrrGRNJoBKuVFtn/o
         2vyc771s5WvJ49KDvo2EnmSNhOzvy9Ca95gVVmWcKC17ySB5i1Nr4fZjwTWrpOmpiWe8
         ybf3HAqmEH2KbaFKzzQw+KL5fwSwSZYDwACQPNl0WcbgBgcR5tdAV4bcBYniQTMRwbgm
         7yp8pDvzFEK08ohiZvuZUFPjrAsQ+j1b3+pfCCXn8lItavzujUx87HNCrKI26PBwqRC8
         wVcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=KnEDziCwsp6+g+HaMzQyW17+goWhQGK2Kg1J2Rio04w=;
        b=kvkextDzv+gWfJ2oHGF61TgutHWyro7wkOC2e07gBAVU0a66T35h8etGFDD4y/rvrJ
         s7PogBRB4TxTmJMrtOwxYyTgz8P/3ZwV7jAHmh+os7asczHJQsbrJ7oStR3LMsQyt4AR
         QHIUMt7mHBiJJZqv2vbxtk0rgG6QtDk6ww0FSN3v+2440ACWmeoiTkJ/yZnrSW/P9KeW
         UVblG4h+PR9pJVvuC0yc7juw9+bTlJc7RIMhu5GBR2e+qyFrPC9oQkeMp8g1ODbQmndI
         YfGz73Oyg+2odVraJcnVnEcVSa5RLhHW5gQgYvxjAJg4PJdJnXbqTfS4n68hGE000uQD
         s0mw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWrLI+O0QxND7LmjvecRrllD/NA/EspA0gWg4SDXWOVmiFJvaYl
	S7snwzfMJ+Di/xP7juCCocc=
X-Google-Smtp-Source: APXvYqw8oLSWZWrTO1IvXWZZNfwOwNssH1BLROfRojGEjb2FefdlQ3esw2l8ssOmt1jWjSNG8QKN3g==
X-Received: by 2002:a62:1890:: with SMTP id 138mr32189079pfy.161.1569213087941;
        Sun, 22 Sep 2019 21:31:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:bd03:: with SMTP id a3ls3143736pff.10.gmail; Sun, 22 Sep
 2019 21:31:26 -0700 (PDT)
X-Received: by 2002:a63:5652:: with SMTP id g18mr24383441pgm.393.1569213086000;
        Sun, 22 Sep 2019 21:31:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569213085; cv=none;
        d=google.com; s=arc-20160816;
        b=Ui1YVEAKr2x6pg9yc2IHGO8Oc/+1lbv/reQ0/46vcwoYgiXZHXeQ7tC93srvOknVKc
         ABlSvQUxrUIyN8bSx/blgmts+89JFccoN75ke+5vUni0u/SMb5GB0GBnvuX4P4wK6v8w
         FM4K7nC2/M3tLhhGblCEUMGnLpI2/4HjZ9hl7hlShonwiaZB4T006W4eUlNIDY2Hv6n8
         F1isem9IalxERCkL72f7AiHc83Tez0vQWXLId7c8nj8m700RmiwBs/XMsE8AXzdpoiNw
         jcclAHdiexBDNMK4jTKZt86gHK5+eRtdFuKD68WjB19F/MLMQqrJ+sRQ/x5NxFNP16Gt
         morA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=4QM9p6JUL1H2+7ufpY9lHAHlLiqvaNnzuQlbpSFc8tM=;
        b=xNmY0wVBe9FyPvMab2mzZGb80AvukZO8UltlBSuo6FESvKeS24VyvR4gMlklQVRHQo
         6NXp41okMWgFIsDyjJih2jfz2Px1TzN3pORrrp8/FEMFHWySZxmUQpSz3J93FUTNamjt
         j8Wmvp47RDsTo4E554bl5T7aeBrg+hUy3RMR/lZ1Dbng4e7NBrUD+Bi5L51ykZXU4yUC
         KiIKQafind/UlxsHAsuK3nV5lpv9AToAHpCKFLSeZpOTbQxZ+jl1UPqMN56Ai8kpfYzn
         6yN8BiVFMHNsGv18wSlvH5rJ5sT5N69ktKHoYje4rddCnbyt1FJjEyLFSIhizkt043J5
         NMpg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=kp6S8U50;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id br8si1750822pjb.3.2019.09.22.21.31.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 22 Sep 2019 21:31:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id 201so13943907qkd.13
        for <kasan-dev@googlegroups.com>; Sun, 22 Sep 2019 21:31:25 -0700 (PDT)
X-Received: by 2002:a37:7041:: with SMTP id l62mr15740747qkc.7.1569213085158;
        Sun, 22 Sep 2019 21:31:25 -0700 (PDT)
Received: from auth2-smtp.messagingengine.com (auth2-smtp.messagingengine.com. [66.111.4.228])
        by smtp.gmail.com with ESMTPSA id k54sm5680914qtf.28.2019.09.22.21.31.23
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 22 Sep 2019 21:31:23 -0700 (PDT)
Received: from compute6.internal (compute6.nyi.internal [10.202.2.46])
	by mailauth.nyi.internal (Postfix) with ESMTP id 4D4CE220AA;
	Mon, 23 Sep 2019 00:31:22 -0400 (EDT)
Received: from mailfrontend2 ([10.202.2.163])
  by compute6.internal (MEProxy); Mon, 23 Sep 2019 00:31:22 -0400
X-ME-Sender: <xms:mUqIXZLWXcLOHduDT8srUfss5BIJ4xJj5zU3TD0he-1DWmuMFpAGzA>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgedufedrvdejgdekiecutefuodetggdotefrodftvf
    curfhrohhfihhlvgemucfhrghsthforghilhdpqfgfvfdpuffrtefokffrpgfnqfghnecu
    uegrihhlohhuthemuceftddtnecusecvtfgvtghiphhivghnthhsucdlqddutddtmdenuc
    fjughrpeffhffvuffkfhggtggujggfsehgtderredtredvnecuhfhrohhmpeeuohhquhhn
    ucfhvghnghcuoegsohhquhhnrdhfvghnghesghhmrghilhdrtghomheqnecuffhomhgrih
    hnpehgihhthhhusgdrtghomhdpuhhsvghnihigrdhorhhgpdhlfihnrdhnvghtnecukfhp
    peeghedrfedvrdduvdekrddutdelnecurfgrrhgrmhepmhgrihhlfhhrohhmpegsohhquh
    hnodhmvghsmhhtphgruhhthhhpvghrshhonhgrlhhithihqdeiledvgeehtdeigedqudej
    jeekheehhedvqdgsohhquhhnrdhfvghngheppehgmhgrihhlrdgtohhmsehfihigmhgvrd
    hnrghmvgenucevlhhushhtvghrufhiiigvpedt
X-ME-Proxy: <xmx:mUqIXejTuUx4gqDmyOeK0FASaV1GS4t5wADakmISS3IQ6hdC7VWssw>
    <xmx:mUqIXaPnYPna0kbUzHdqHX4j-38-ubG2XEEbnCJ91cyqQVRi9eRpuw>
    <xmx:mUqIXZ6Q214evmbHeUFLX5FUhsX4IxzFdaWJtZlxaguljMHpvYz1ug>
    <xmx:mkqIXSgHFWi-oMaQFgvYOJAhhqaBn4sxV3ZEza_A-wcU2aiiSWcp3hf_iKE>
Received: from localhost (unknown [45.32.128.109])
	by mail.messagingengine.com (Postfix) with ESMTPA id 20A73D6005E;
	Mon, 23 Sep 2019 00:31:21 -0400 (EDT)
Date: Mon, 23 Sep 2019 12:31:13 +0800
From: Boqun Feng <boqun.feng@gmail.com>
To: Will Deacon <will@kernel.org>
Cc: Marco Elver <elver@google.com>, kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>, paulmck@linux.ibm.com,
	Paul Turner <pjt@google.com>, Daniel Axtens <dja@axtens.net>,
	Anatol Pomazau <anatol@google.com>,
	Andrea Parri <parri.andrea@gmail.com>, stern@rowland.harvard.edu,
	akiyks@gmail.com, npiggin@gmail.com, dlustig@nvidia.com,
	j.alglave@ucl.ac.uk, luc.maranget@inria.fr
Subject: Re: Kernel Concurrency Sanitizer (KCSAN)
Message-ID: <20190923043113.GA1080@tardis>
References: <CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com>
 <20190920155420.rxiflqdrpzinncpy@willie-the-truck>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha256;
	protocol="application/pgp-signature"; boundary="RnlQjJ0d97Da+TV1"
Content-Disposition: inline
In-Reply-To: <20190920155420.rxiflqdrpzinncpy@willie-the-truck>
User-Agent: Mutt/1.12.1 (2019-06-15)
X-Original-Sender: boqun.feng@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=kp6S8U50;       spf=pass
 (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::743
 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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


--RnlQjJ0d97Da+TV1
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

On Fri, Sep 20, 2019 at 04:54:21PM +0100, Will Deacon wrote:
> Hi Marco,
> 
> On Fri, Sep 20, 2019 at 04:18:57PM +0200, Marco Elver wrote:
> > We would like to share a new data-race detector for the Linux kernel:
> > Kernel Concurrency Sanitizer (KCSAN) --
> > https://github.com/google/ktsan/wiki/KCSAN  (Details:
> > https://github.com/google/ktsan/blob/kcsan/Documentation/dev-tools/kcsan.rst)
> > 
> > To those of you who we mentioned at LPC that we're working on a
> > watchpoint-based KTSAN inspired by DataCollider [1], this is it (we
> > renamed it to KCSAN to avoid confusion with KTSAN).
> > [1] http://usenix.org/legacy/events/osdi10/tech/full_papers/Erickson.pdf
> 
> Oh, spiffy!
> 
> > In the coming weeks we're planning to:
> > * Set up a syzkaller instance.
> > * Share the dashboard so that you can see the races that are found.
> > * Attempt to send fixes for some races upstream (if you find that the
> > kcsan-with-fixes branch contains an important fix, please feel free to
> > point it out and we'll prioritize that).
> 
> Curious: do you take into account things like alignment and/or access size
> when looking at READ_ONCE/WRITE_ONCE? Perhaps you could initially prune
> naturally aligned accesses for which __native_word() is true?
> 
> > There are a few open questions:
> > * The big one: most of the reported races are due to unmarked
> > accesses; prioritization or pruning of races to focus initial efforts
> > to fix races might be required. Comments on how best to proceed are
> > welcome. We're aware that these are issues that have recently received
> > attention in the context of the LKMM
> > (https://lwn.net/Articles/793253/).
> 
> This one is tricky. What I think we need to avoid is an onslaught of
> patches adding READ_ONCE/WRITE_ONCE without a concrete analysis of the
> code being modified. My worry is that Joe Developer is eager to get their
> first patch into the kernel, so runs this tool and starts spamming
> maintainers with these things to the point that they start ignoring KCSAN
> reports altogether because of the time they take up.
> 
> I suppose one thing we could do is to require each new READ_ONCE/WRITE_ONCE
> to have a comment describing the racy access, a bit like we do for memory
> barriers. Another possibility would be to use atomic_t more widely if
> there is genuine concurrency involved.
> 

Instead of commenting READ_ONCE/WRITE_ONCE()s, how about adding
anotations for data fields/variables that might be accessed without
holding a lock? Because if all accesses to a variable are protected by
proper locks, we mostly don't need to worry about data races caused by
not using READ_ONCE/WRITE_ONCE(). Bad things happen when we write to a
variable using locks but read it outside a lock critical section for
better performance, for example, rcu_node::qsmask. I'm thinking so maybe
we can introduce a new annotation similar to __rcu, maybe call it
__lockfree ;-) as follow:

	struct rcu_node {
		...
		unsigned long __lockfree qsmask;
		...
	}

, and __lockfree indicates that by design the maintainer of this data
structure or variable believe there will be accesses outside lock
critical sections. Note that not all accesses to __lockfree field, need
to be READ_ONCE/WRITE_ONCE(), if the developer manages to build a
complex but working wake/wait state machine so that it could not be
accessed in the same time, READ_ONCE()/WRITE_ONCE() is not needed.

If we have such an annotation, I think it won't be hard for configuring
KCSAN to only examine accesses to variables with this annotation. Also 
this annotation could help other checkers in the future.

If KCSAN (at the least the upstream version) only check accesses with
such an anotation, "spamming with KCSAN warnings/fixes" will be the
choice of each maintainer ;-) 

Thoughts?

Regards,
Boqun

> > * How/when to upstream KCSAN?
> 
> Start by posting the patches :)
> 
> Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190923043113.GA1080%40tardis.

--RnlQjJ0d97Da+TV1
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iQEzBAABCAAdFiEEj5IosQTPz8XU1wRHSXnow7UH+rgFAl2ISo4ACgkQSXnow7UH
+rgHOwf7BLuk59YmfLvND3YZHNAzLM2LGXuNIuOZcWlnUL1nI092bou02ChdTEPo
2VRQ41P95dAA6mGX5oIhExPy8KQ+vCMqnNV8ZMT3L134cqiLU6C+UZIp/9GSFub/
0c9cvLyiwQo98gVIarEb/HWk5lSye1hlOPgSud3NpE4A11QFWAzRs4LkcVlFnh3g
ATihIRCxLr0gPOsi9YQI2mBJjCi9yId+VzTFNbGhKfQVwAMUHZMVbRg15Q/OYe8g
1/c449UasaAZ64z/zlHZisjkD4RCUztekNPdFL1R7zrsaAJtpC5xsPncC6Q8EXL+
+6FT4rcFYJy4vRHy9MFnh/AxSEsXyA==
=B1n/
-----END PGP SIGNATURE-----

--RnlQjJ0d97Da+TV1--
