Return-Path: <kasan-dev+bncBAABBUPBSHZAKGQEMWKEYCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E4D815B2E3
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2020 22:40:34 +0100 (CET)
Received: by mail-qv1-xf3f.google.com with SMTP id n11sf2233074qvp.15
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2020 13:40:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581543633; cv=pass;
        d=google.com; s=arc-20160816;
        b=V2UQJN4+NvI8RATHjOKQcJhY3tgECnSBWpbG9RUUZXuYd9QopOoB1lh7Du3NCKQCzv
         HncHm4UMzejjJ8bFLWEde1arE1vG2ubhTxY7U5J0hLdQ1UWTiXB7JqBSbPzYGrakHpls
         s/1Dqrjh+jk7wzNrwvOo7E6NNtv2ODYQny9bn0jFnh03K8JTNc26qGk59WItZhpebfBi
         BEQwr83ax7idCUDl3N4Ek34e7YySCXHUAkD+Q2IO0A7EY6yliXaf4rGDbl4gh9cOzdc+
         ufOxNSQKzAyvYo9cJFlmpg7va/uBv8jdn6KXVxUbItnMr3U9keN8ge7ncYyqUh/KctPv
         ZbNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=INqz1rQ5mwp/ZkBnWSYSb7hk2qFJKoAAy22ImgTQJtQ=;
        b=PIdWjaFxVKCBprDBgzLZp8x08l2vH+pE9i1Tz5j23e1miPcNH2qD0F4Pqpqio2NeVj
         oQP3OSUyBKBKmxwZszX4kMsAeWXf219m9dNoCglJPKtFMtxTzThshTjb+FljvvB0P5j9
         zccQkW96JO3erycJdFug5FFjGlEQMYOevs5VxD12gXyb22VEO4ea5qEfALVLSF0aSCuz
         d4rCDKsxoym42W7qbEtn1OGRyCbhyG7UmKT6OWb5mufZT1rU0VmuJZPVqYguHr/5QfnB
         rgFMWozgDS8fmcvwSapwK19kRgees5fw0R9cdtM15EO63FKo0tiLXGsgcqjmnugV8806
         Nljg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="Ti//QRKW";
       spf=pass (google.com: domain of srs0=uvu3=4a=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=uvu3=4A=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results
         :content-transfer-encoding:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=INqz1rQ5mwp/ZkBnWSYSb7hk2qFJKoAAy22ImgTQJtQ=;
        b=TawT83c17p8msirktEIp4tdUlM9dwU08LXWdBgxBLwV+32F6FIN2ec4nvamvbgxJJ3
         1pb8NEf/LLPi7hTcUvdCEqnDoTKccfVg2ffwNNg2pUFpghjdCj9XQTKr1UDHdVWAU5wo
         hZy5f57TOSL7PUOJSp5foNcG9Ve++c3sTDeFx+RObPIDMbLpNKxlcrzJ0ZhhSX9fe6zw
         vUwmI6dIK9lDHbnHqMPH1fAekK8otjHyOYQ2wRSzcB03U7Z/iLvPv0i89cvi79hRrLjg
         azKUUgrUF7X+64OVsoaRPkTZGGd4cEEXPSPsj0mOWH+2RvmMxUhCZRVb1HTlx4zQt2MB
         XTDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :content-transfer-encoding:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=INqz1rQ5mwp/ZkBnWSYSb7hk2qFJKoAAy22ImgTQJtQ=;
        b=Sha5vGuQVhEOAZhMMauQsIvF+1V2ISSoz8GROvByGgBB3FOV7CKZOqC/l9tYwCnSpQ
         s7tybDx4p0DNT8Qb9tHDmFSsw5YZ7/uhaE1EYN66+hTlYxJgPlchHDJRGuLOLLKcpQUW
         ilN8Mx4gajQUPtDSYemr6Nvbs5UfWkgnyoPuoejRMJI/QMAaJtLc5MPukeUAh3yGcCTF
         0KcYyoPrwAoHtzAT2/+OxYOY9/Al5Cu8E4RYNSyWkeAcJr3bxfZI0D2pcFS17x3FxZR8
         o9F41S13q8V+rZWDogXbHtrL38jfd4SsfM6n9xqbV0S1/Os+Sa6+VS8WTuwdSy3yJn8D
         +ZDA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVMk5WOFcim+z515ED9qfzGDSQU1caRoXc2XiRd55EB1dNs8ODz
	xhRMDprK8cTeItT6nP0QGKo=
X-Google-Smtp-Source: APXvYqw52orCUYsLIZQE1RQt4J++guiZp7LCdlKytwajfZzXHNlW71s4C8AAC8x/ceSeV84jIEKs9Q==
X-Received: by 2002:ac8:7152:: with SMTP id h18mr8933124qtp.349.1581543633097;
        Wed, 12 Feb 2020 13:40:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:52b:: with SMTP id h11ls2651387qkh.5.gmail; Wed, 12
 Feb 2020 13:40:32 -0800 (PST)
X-Received: by 2002:a05:620a:1464:: with SMTP id j4mr9279280qkl.29.1581543632804;
        Wed, 12 Feb 2020 13:40:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581543632; cv=none;
        d=google.com; s=arc-20160816;
        b=VNWioKOSy6I8jnIql6YJYBZXHg/ntzerVZqV5hBCb35uL4biVdK1LyYyLbDmBNTw0y
         i3CmD8A+JMlBE4SaA4rCSmFsZjGZVQSll8dlA6Exm9zUOwBJhRb0VBrRisVvvsVbqNTt
         ksjtkRYBuG0LcgPS4RmbINUgrWhtXRlOP/iufNHFh3uM5MAZQ+dIbwS6MQn9dxxA2cHv
         GDC0ImNvcga/1tJBwB/X8qBP5tDZe1didEMAFBAzjkge9z3+5N3CBYsXMONQt79FIQ/E
         OyFeGxWsTMHhyRRRgoDGM0jNncGx5ZhOkOzsQrcYXyrj4e85f8EHCFq3QpiMJaCz4hw6
         K/Yg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=sEHJH4LDAvVSZuH1y3jT9rqeYNfnqRbXzsy7NmvSaI4=;
        b=Uiz4B270XJxdQK3X5KZnP0/mdRof20eJTHk+vplkpnIHUcbgSO3XHgdZQE0e7VjGaW
         L9VWb2IhIaYBVs9gwF2Od85GyjKcjVzotRHTscG4TX161zqZYNtTx2mlenEmYd129GMQ
         RGI7LaQqcotDdgjWrU06a7SdQTOfzIVWDzdJF894+NS2dlaQ/9STy0ppM+ee14BZF/MG
         JZVIvT7wYIfGTy1j90gOvKP3v2L5uuF6JOzynOfz1gMD1exPRzNA4xNIIjYUuD8H2h5h
         NUUuDJl48G5MgUzmuEqY+gv+wXoW0NApn6FnBBOdeUGR99ozr38xfI8lpUfpG8xYWKeS
         0i5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="Ti//QRKW";
       spf=pass (google.com: domain of srs0=uvu3=4a=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=uvu3=4A=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id o21si14742qtb.3.2020.02.12.13.40.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 12 Feb 2020 13:40:32 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=uvu3=4a=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [62.84.152.189])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 9B1512173E;
	Wed, 12 Feb 2020 21:40:31 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id F19FD3522725; Wed, 12 Feb 2020 13:40:29 -0800 (PST)
Date: Wed, 12 Feb 2020 13:40:29 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Qian Cai <cai@lca.pw>
Cc: Marco Elver <elver@google.com>, John Hubbard <jhubbard@nvidia.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	David Hildenbrand <david@redhat.com>, Jan Kara <jack@suse.cz>
Subject: Re: [PATCH v2 5/5] kcsan: Introduce ASSERT_EXCLUSIVE_BITS(var, mask)
Message-ID: <20200212214029.GS2935@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <CANpmjNOWzWB2GgJiZx7c96qoy-e+BDFUx9zYr+1hZS1SUS7LBQ@mail.gmail.com>
 <ED2B665D-CF42-45BD-B476-523E3549F127@lca.pw>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ED2B665D-CF42-45BD-B476-523E3549F127@lca.pw>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b="Ti//QRKW";       spf=pass
 (google.com: domain of srs0=uvu3=4a=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=uvu3=4A=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Content-Transfer-Encoding: quoted-printable
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

On Wed, Feb 12, 2020 at 07:30:16AM -0500, Qian Cai wrote:
>=20
>=20
> > On Feb 12, 2020, at 5:57 AM, Marco Elver <elver@google.com> wrote:
> >=20
> > KCSAN is currently in -rcu (kcsan branch has the latest version),
> > -tip, and -next.
>=20
> It would like be nice to at least have this patchset can be applied again=
st the linux-next, so I can try it a spin.
>=20
> Maybe a better question to Paul if he could push all the latest kcsan cod=
e base to linux-next soon since we are now past the merging window. I also =
noticed some data races in rcu but only found out some of them had already =
been fixed in rcu tree but not in linux-next.

I have pushed all that I have queued other than the last set of five,
which I will do tomorrow (Prague time) if testing goes well.

Could you please check the -rcu "dev" branch to see if I am missing any
of the KCSAN patches?

							Thanx, Paul

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20200212214029.GS2935%40paulmck-ThinkPad-P72.
