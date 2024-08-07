Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBGMOZ62QMGQEAVD35OI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id D0CAE94B052
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Aug 2024 21:12:26 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-2f0276170f9sf1233481fa.2
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Aug 2024 12:12:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723057946; cv=pass;
        d=google.com; s=arc-20160816;
        b=wYFL6dyvETss8Z1qlBBzs7pXzUXce8wSG4h49mIPRWIu7xR2jnWkHQoygxu+yLVGTG
         3hfYw5kvSzeKLKtiYluLY77DztTqtSSSFC/6dqUquTRS4MjBfngYp4mmDJ3Re+ZTooll
         b0uRATJCtUZKQw5wasckdReS4QKkYvYJOoMWmy9nFs7OtMyJamsVGbgD6cXkz8AdKinI
         anb9oLOqmNt2EJ/51c+IlMP6hhRWA49tp6BzqN7Z0ddkpZbHAPI1El2Il2tsqxNCvNAy
         yomQGI79uX7tl+rAuuKt5QLHyDkXwaQ1ibNQ5mUmPgXI77nLjZ3VUpVQlJ+QPveuzjce
         IREA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Nh9Zusb+sBaQXkBeBvkYNs0qOUuw33TVCC184YyHC6I=;
        fh=ixjMuRuNsdCPjN0Ryg1dsxNKQaV7RTMjrnD9Vjaq5nY=;
        b=A5gLSyA/ivWKG9GxPmtq8PUtzbaQ0m8EUAIZy+byMDrAopvkY42veKzItvVtEep0TH
         E1oDCcNFUusjZ8x3l6D69We0LkAdyuYpZ7B+YoWoz7lwjuqRJcdF5g//BDG+qQB5Nzhz
         8XOH23v2xpZkRt56U1P1207/FS05yAl+dnkxGne4Y9ARcDoshj6TcFPDMzd0rXItoarn
         KBYOhywzO8LQ9rFQDaoIBXA1xK0sXw5yq7lFiyJ30J16QqZd6CV+Q8OagznY4IwQZgJA
         AwF2QJ4GvuCzxjCcWQVDfYPqnbsDonf3psIS/NFnzveNrXJpAUDtbgfeL2hKHBAC1RKV
         1RWA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=foMn71gR;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723057946; x=1723662746; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Nh9Zusb+sBaQXkBeBvkYNs0qOUuw33TVCC184YyHC6I=;
        b=a4d6R20oSh4kZtRg8qszzZFO8UXlT/GNQTwXwjljSnK4HbAMvlNb6cvU+XomFQDcQh
         poiihVLeRTGebt8hqJnONxth5r935wHoc8DjGXLOTGgelwgTjdRDjMgJzOnWP03uV8/7
         P3ypPYTJokzUzu4r1qbogw8lBZ84Jumzd4c1jy2QP7Ekf7kQWCUaAANuKHOIj7w0n2uX
         VztdM/L3bPPxzN9gGFZwXVY+AODW05HdSp2KkurxJt3FkJrTaqLGSf4jptWLJlPUvtZt
         98zYGvcRP3vKDk7kwV5w2iaKtYKLeLzzznnbPuzkonRHygnMMYgYUwCW7Ob5M8CBNW2z
         1naA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723057946; x=1723662746;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Nh9Zusb+sBaQXkBeBvkYNs0qOUuw33TVCC184YyHC6I=;
        b=G02spF+c0OKJAMqjYY82EnLMARmCdAQvd8dZ5iyEZBcmpWAbvaXXV4rgUkDyHzZyAR
         86buSUG7iuZWBnYu8zrw3O7FnLvzZhsSI1wOgwFxAWXe69E8OoMTpQJq+OHWRUUdrVY7
         BSjwt1NyG2qatq5zjfy+bh4DpOQk7qEP0GeO/qKfcjMVyc1edrP4BK0ljnvBa2Hu9TIB
         /yoDOqbErln/B2kBMTgxYZDUeXv6NTSJ8z744prWy/C6uCQRJoqqFIz0P5K1loO1i/45
         5ZVPhi9ES5ipFNg1Nylx+gekMN2AuqR+wdsH9R8C6trCBsOHeelKV9sWAtX2V2JyotzT
         fUog==
X-Forwarded-Encrypted: i=2; AJvYcCUXcD1YFCS3TP5SoVh5vFTpgBnL8Bhod6Hp0+lhNcLPfSraWE+bxrjqtDT1uyDQOG1mUaGpJQ==@lfdr.de
X-Gm-Message-State: AOJu0YyvvHfKEPcWOxrW3SholvmBN1bwkosWpKrzp7XcvNoGh1JSgJcL
	GwnqMojFoDxwqxoOiFW6Mnq9UrGG6VwhQl3cu7O+VOWZCL3GRfue
X-Google-Smtp-Source: AGHT+IH4/7tJOFTpVul9M3oguXsb0OR7vbSm6F/3JedKFOgPL7ThgoHxUThhY9WUYap5TX+mzvPHQA==
X-Received: by 2002:a2e:b1c8:0:b0:2f1:5561:4b66 with SMTP id 38308e7fff4ca-2f15ab52fd4mr123326981fa.44.1723057945426;
        Wed, 07 Aug 2024 12:12:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:2a82:0:b0:2ec:5941:b0cb with SMTP id 38308e7fff4ca-2f19bc58509ls576351fa.1.-pod-prod-04-eu;
 Wed, 07 Aug 2024 12:12:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVSmzYkucuIS+tWz1cHVvTUc47Oau0iaoNWaGrWybfUA39092Q9hCLrfuA3yZiezdgpBbF08Fyy49s=@googlegroups.com
X-Received: by 2002:a2e:b6ca:0:b0:2ef:185d:e3e2 with SMTP id 38308e7fff4ca-2f15ab236d8mr127163741fa.36.1723057943031;
        Wed, 07 Aug 2024 12:12:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723057943; cv=none;
        d=google.com; s=arc-20160816;
        b=UVXhokQe79jypVcA3SOizlUhWGPV2ZyghT4WpY2P/c2GteE5toQWunOQnbk3ZrztlW
         jbNytYSBTelM5ZXVdt+SetCVqhnPkx7irAPqK1220+SEUbQb9J9cpasz1sZi6LKgK+lX
         S73cJUaFpIW5WXb8N9OwQbc1Gh81ulhsk/ql3gq36NKpQh2cLj1xnHJsERqMxCawGBIO
         5cPnTwzpA0Q+DyladIGMdJLGP1Eb+MEYFC5yS/Rz/gDbAgNEgLUjGhYEQ/nw3n+HJOl3
         c8becL0C2zW66+6s0sbwWZFqMcZXhve6juDm8y8muK8deHHKFGYAXIZ7rcrmjEs1GR3R
         YKiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Kdol11eQXlFr/aoPc6yojOHFiXqRC3vd03C+IkTOtL8=;
        fh=evKCwjrumy4flvK2j0jOfRqiGVnNNsQVWHn8t147C5w=;
        b=AqzfHFo//2sJhutyvDXmZI/dvIMpQaGrDnF3aHF+4dAO78MoftdOLsggBHTdmrxMgS
         m6AzsAXgUmXdnDat3HYFhVyYTC8gXj2Ec8rGugQXkrlhTwV5ZAseeBDbqQo8IjF7AuKJ
         E+RodBuwGFovFeHhizGQDrbET+WFK0q14thM92Gza02dN+mHz7hj9YxgPOFodpXPffjA
         SFyle4TlDVwFZ2atQ2ZLlBVyO6/ynp3/L7B+QoJCT+vuvvCdoYij6DYN5XhDRRRVLzpf
         dbo4uNhTnph4YPrQ67QS/dsp80PdxvEjbo4vL+9pgL2J3TaK+Y0v2XA8DkWd9o6Kyt33
         kKbQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=foMn71gR;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x532.google.com (mail-ed1-x532.google.com. [2a00:1450:4864:20::532])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-429057ea2f7si1072295e9.1.2024.08.07.12.12.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 Aug 2024 12:12:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::532 as permitted sender) client-ip=2a00:1450:4864:20::532;
Received: by mail-ed1-x532.google.com with SMTP id 4fb4d7f45d1cf-5a28b61b880so97a12.1
        for <kasan-dev@googlegroups.com>; Wed, 07 Aug 2024 12:12:22 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUrteSqvfmHSFayYiH8l9I8HuA5R/G2Xkec/RDxCLM/e2WeBA2VodWN/UTy797Qn9GjZx9LWbkJSWs=@googlegroups.com
X-Received: by 2002:a05:6402:2686:b0:5b4:df4a:48bb with SMTP id
 4fb4d7f45d1cf-5bbafe5dd90mr36209a12.0.1723057941805; Wed, 07 Aug 2024
 12:12:21 -0700 (PDT)
MIME-Version: 1.0
References: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz> <20240807-b4-slab-kfree_rcu-destroy-v2-2-ea79102f428c@suse.cz>
In-Reply-To: <20240807-b4-slab-kfree_rcu-destroy-v2-2-ea79102f428c@suse.cz>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 7 Aug 2024 21:11:45 +0200
Message-ID: <CAG48ez1nuA5bwDUWpwOoMdVqdjhgSKMc+mtFwuH6pbbz51CA_Q@mail.gmail.com>
Subject: Re: [PATCH v2 2/7] mm, slab: unlink slabinfo, sysfs and debugfs immediately
To: Vlastimil Babka <vbabka@suse.cz>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Joel Fernandes <joel@joelfernandes.org>, 
	Josh Triplett <josh@joshtriplett.org>, Boqun Feng <boqun.feng@gmail.com>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Lai Jiangshan <jiangshanlai@gmail.com>, 
	Zqiang <qiang.zhang1211@gmail.com>, Julia Lawall <Julia.Lawall@inria.fr>, 
	Jakub Kicinski <kuba@kernel.org>, "Jason A. Donenfeld" <Jason@zx2c4.com>, 
	"Uladzislau Rezki (Sony)" <urezki@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, rcu@vger.kernel.org, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, Mateusz Guzik <mjguzik@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=foMn71gR;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::532 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Wed, Aug 7, 2024 at 12:31=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
> kmem_cache_destroy() includes removing the associated sysfs and debugfs
> directories, and the cache from the list of caches that appears in
> /proc/slabinfo. Currently this might not happen immediately when:
>
> - the cache is SLAB_TYPESAFE_BY_RCU and the cleanup is delayed,
>   including the directores removal
> - __kmem_cache_shutdown() fails due to outstanding objects - the
>   directories remain indefinitely
>
> When a cache is recreated with the same name, such as due to module
> unload followed by a load, the directories will fail to be recreated for
> the new instance of the cache due to the old directories being present.
> The cache will also appear twice in /proc/slabinfo.
>
> While we want to convert the SLAB_TYPESAFE_BY_RCU cleanup to be
> synchronous again, the second point remains. So let's fix this first and
> have the directories and slabinfo removed immediately in
> kmem_cache_destroy() and regardless of __kmem_cache_shutdown() success.
>
> This should not make debugging harder if __kmem_cache_shutdown() fails,
> because a detailed report of outstanding objects is printed into dmesg
> already due to the failure.

Reading this sentence made be curious what __kmem_cache_shutdown()
actually does - and I think technically, it prints a report of only
the outstanding objects *on the first NUMA node with outstanding
objects*? __kmem_cache_shutdown() bails immediately after seeing one
node with outstanding objects.

That's not really relevant to this series though, just a random observation=
.

> Also simplify kmem_cache_release() sysfs handling by using
> __is_defined(SLAB_SUPPORTS_SYSFS).
>
> Note the resulting code in kmem_cache_destroy() is a bit ugly but will
> be further simplified - this is in order to make small bisectable steps.
>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Reviewed-by: Jann Horn <jannh@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG48ez1nuA5bwDUWpwOoMdVqdjhgSKMc%2BmtFwuH6pbbz51CA_Q%40mail.gmai=
l.com.
