Return-Path: <kasan-dev+bncBCT4XGV33UIBBKHA3K2QMGQE464FXDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id A543F94D959
	for <lists+kasan-dev@lfdr.de>; Sat, 10 Aug 2024 02:11:22 +0200 (CEST)
Received: by mail-oo1-xc3b.google.com with SMTP id 006d021491bc7-5d5ba2d8d5dsf2618735eaf.2
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Aug 2024 17:11:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723248681; cv=pass;
        d=google.com; s=arc-20160816;
        b=yzKYJIbsYW9x4JKnT0tChZohToVX0TpFBzHzIEmyZbX1SP/okJwhQNmWUSoDFutvyN
         gKyhyQkCfEY3cUW2e1p+h6XT3Sr2IqbyUEY0k+IVrdIg+3PnJ+rCu1qee8zw9uYH43xJ
         YqXw9uc7IWY3aXdZ9Me4kMwGEiGuBJY9JvyTtZ/DdDQSw303eqjlut7XSTSw8xxpMihQ
         qO82mWPIH5vgNdqGKCVWswRb2Iv6nlglsYRuIY1GEzsKp+3BhEqYyN2e2VezRBVeHqs9
         g9/8ul7owhLPYw6j/rOq36KEbjp4W/3wR466gsx57Cq8PIpLaW8byhFDn4Ar9WZzyCRE
         Yg1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:subject:cc:to:from
         :date:sender:dkim-signature;
        bh=LHB/QAiu+c406jwtCtMA/nOtnNTs/AYgM+9CBIfDzVs=;
        fh=g+jEEWASi10NzmSdeB6IQaYZz0/2d5UyXXIIUro0e5U=;
        b=M10Gq9wqHqjWYi+Cxrtgujq8WCZLK0xRrZq0KzpxYWEg7UGHWoTEu89p44H2sZheeG
         bAvXA62G0mqUndLQDIWr2VNH7DgVkpphTihzgfUCU190RIgyOw7dRfdPIF25WESgq7Nt
         QvPXlgESJGX6sgw2UL3o8HFerVgrP0Bjb+1nh8qbtVQHKreBEl6Gq9HZIbAPT6fDseHc
         mXeph8JUd6X3SP8ksb0q4rd5cxOpP1+jIHcCziN8/NzzKOt/XLndzBh7teVMfU2j3L6N
         JUbamFitt3okwkHfJFCYVopzMjje3LuS/bZ0SFpqKrEbksF+XwXWvumaTWrcBJoKbmQA
         s1lQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=XxoyP0t1;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723248681; x=1723853481; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LHB/QAiu+c406jwtCtMA/nOtnNTs/AYgM+9CBIfDzVs=;
        b=ptHdlfRJhsLCng7lj+cOvtg+mfsgGhEaOHWKKhsZWqognAwUuurBQCoS0jxiRZIHn8
         CtMXFCu4tkhlYFCgbbpqjSMQZFZZZS1crj5XxlQdha4N4sHY/WVQfRAPyzrKFtVr8MCt
         YxtRQmasEbOfc+thrHVJuGy81IGIXcUik9hN5u45jwdCkdzgAAOr8y4Tt/MzXmoLNSgv
         +5HTgan9/b4Y8HQsdYXEpLNsPGRM/kwMQfz03CyLMcMLtN7GIfkre/CcmGaCJG8RkUNw
         QeG6kVckAiQ2VGRhXdHsekfsOKs93/WQHgyslTDAeETfG2dNdbNN9xfFc2uhuXMiRtp/
         zsSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723248681; x=1723853481;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=LHB/QAiu+c406jwtCtMA/nOtnNTs/AYgM+9CBIfDzVs=;
        b=sSJsbBN4dGmOwWy0FyPaqJGCY3/rPgDUSnU6D1+VATq3lSfDUW8Wm9aqMVXnXJ+3mA
         v2a69PrfP1aMZQppk3M1mA30nc4BN6K1OgV7LQHjBSK3Xad+U5WiO+sQOFK8S2yIvDJH
         UlTvIsAMFYW6GrJI6AiUsBrQOhtqD+kJuT6U9wcctRYC1bud3QkGuAstl+EOiH5Zh8vr
         kvqHDuP5isj2sjUm3uno5VgEn1OeB+tDjVXfTMqkAq45DuwL696dXioO9TVaqzaQAMBz
         KM4hfugWQwpf0zDqb9jQTpJ9uQJouKbIozFfRHRO6MwqqB2Avs6JvWWpi5aaqz0NCv1v
         tHFg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUdZM/KWHX4lNDAf1sVvnK9kLpJFKcKmHUTJThPW3BmvmgBWgiDG2DePZCzMxiK9uwnHqWXB2U1w5W2nU51xBc7F2YnrpzeJA==
X-Gm-Message-State: AOJu0YycJBdkwFTsQhMyEGCtefeaCpUtUrJEjzQoQpTy5sz2pMUbfrS5
	rDy3YXsqB41KBWdi2foUuG+6zj7UV1tqAYD/z9b5kgFSOYfmPSmL
X-Google-Smtp-Source: AGHT+IE+TNV9o+esnumOS7Y/DxvNv3tTa6TC2pj4qVp3w7ZZxtGvTS5pJ/K1Y5AqO8iB20vJCvhPww==
X-Received: by 2002:a05:6820:50d:b0:5c4:27f0:ae with SMTP id 006d021491bc7-5d867c81ac8mr4304211eaf.1.1723248681029;
        Fri, 09 Aug 2024 17:11:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:d683:0:b0:5aa:44f9:9b11 with SMTP id 006d021491bc7-5d8512b31d7ls2936504eaf.1.-pod-prod-05-us;
 Fri, 09 Aug 2024 17:11:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVCOQz6FWZDXrE734AwNNorWNyzN1cDhLyutlzBV2jJGyWIelxCbCam8OoxfD7nopwyRoRTzDBXgD/gH9nnwpSpznEsvEMjPoURsA==
X-Received: by 2002:a05:6808:159f:b0:3d9:3649:906f with SMTP id 5614622812f47-3dc416e0b38mr3639697b6e.37.1723248680307;
        Fri, 09 Aug 2024 17:11:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723248680; cv=none;
        d=google.com; s=arc-20160816;
        b=llOMjvsIslUT2qJoxtGN+clOQd5W2CqfNf4RqBoPBpSCF42iM1cwWIQvnCn4A4e5Uw
         oxk7KhydA45O2hMR+gumCv0hP88M2Df77fmyW1lkDFWtVInXxu8gW9u8+Ct2T8ryjai4
         cx8oH3O9MUfXRIrNKjjDpeEaMvtb89RZEOkJ6aeKYaS6JvjjoCoVPkbPYcQvAq5ZUg6A
         cohsHMxjr9cbEYWsCOQyB1ouufvc7p0+nCMup/iKYmhGfNnY03qj9m5evG07FTaBI0P2
         h7LXjAZaHvUySD9CTdJsECsfr1aGspUGkeJo9PzrZnR5/VnPpEZTZRGBPG0rpmE6gaRO
         OzNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=gGrgLfj7j52qHubff1W163mXs/lmaeZML/S3gpt64wU=;
        fh=nsjmLT1OLCumvzps10bmAkfgxVlpbSiJAcnuS31zlqM=;
        b=ZI7TGy+s8exOXsmuiShfl5lOsdyElaXbS/ZdkW7dJillTizzakp1c0LXDYjpH1z/YN
         ++5XbW4z1IuGjFDSrYscrIE9Y6Rg9y89ksCdCa23rvWvld+zn3/2jwBM8Yx2k977KgQy
         4UVaUHm72gA6faWEjpDq9rx/0D3s+h23c+4ecfZHCv1awn5ns15E22cYxt1buCVfiPDb
         a5p/f1UvUwai/fNqJ5t+SGifcy94PfAWJgqwH6E0gAb5sEnXmvKMWHs+JjN38Qqlj4qD
         Irav4gAUnd1RmMZ9EIfj33vuF9ZsnW6nlfuIY0s9YRHzZJiyiEYolhRmRu3z27qmnH4C
         kl2A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=XxoyP0t1;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3dd060bbaa5si15933b6e.3.2024.08.09.17.11.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 09 Aug 2024 17:11:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 5AC26CE17DF;
	Sat, 10 Aug 2024 00:11:17 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id AF830C32782;
	Sat, 10 Aug 2024 00:11:15 +0000 (UTC)
Date: Fri, 9 Aug 2024 17:11:15 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Jann Horn <jannh@google.com>, "Paul E. McKenney" <paulmck@kernel.org>,
 Joel Fernandes <joel@joelfernandes.org>, Josh Triplett
 <josh@joshtriplett.org>, Boqun Feng <boqun.feng@gmail.com>, Christoph
 Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Stephen
 Rothwell <sfr@canb.auug.org.au>, Steven Rostedt <rostedt@goodmis.org>,
 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Lai Jiangshan
 <jiangshanlai@gmail.com>, Zqiang <qiang.zhang1211@gmail.com>, Julia Lawall
 <Julia.Lawall@inria.fr>, Jakub Kicinski <kuba@kernel.org>,
 "Jason A. Donenfeld" <Jason@zx2c4.com>, "Uladzislau Rezki (Sony)"
 <urezki@gmail.com>, Roman Gushchin <roman.gushchin@linux.dev>, Hyeonggon
 Yoo <42.hyeyoo@gmail.com>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, rcu@vger.kernel.org, Alexander Potapenko
 <glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, kasan-dev@googlegroups.com, Mateusz Guzik
 <mjguzik@gmail.com>
Subject: Re: [-next conflict imminent] Re: [PATCH v2 0/7] mm, slub: handle
 pending kfree_rcu() in kmem_cache_destroy()
Message-Id: <20240809171115.9e5faf65d43143efb57a7c96@linux-foundation.org>
In-Reply-To: <e7f58926-80a7-4dcc-9a6a-21c42d664d4a@suse.cz>
References: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz>
	<54d62d5a-16e3-4ea9-83c6-8801ee99855e@suse.cz>
	<CAG48ez3Y7NbEGV0JzGvWjQtBwjrO3BNTEZZLNc3_T09zvp8T-g@mail.gmail.com>
	<e7f58926-80a7-4dcc-9a6a-21c42d664d4a@suse.cz>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=XxoyP0t1;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Fri, 9 Aug 2024 17:14:40 +0200 Vlastimil Babka <vbabka@suse.cz> wrote:

> On 8/9/24 17:12, Jann Horn wrote:
> > On Fri, Aug 9, 2024 at 5:02=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz>=
 wrote:
> >> On 8/7/24 12:31, Vlastimil Babka wrote:
> >> > Also in git:
> >> > https://git.kernel.org/vbabka/l/slab-kfree_rcu-destroy-v2r2
> >>
> >> I've added this to slab/for-next, there will be some conflicts and her=
e's my
> >> resulting git show or the merge commit I tried over today's next.
> >>
> >> It might look a bit different with tomorrow's next as mm will have v7 =
of the
> >> conflicting series from Jann:
> >>
> >> https://lore.kernel.org/all/1ca6275f-a2fc-4bad-81dc-6257d4f8d750@suse.=
cz/
> >>
> >> (also I did resolve it in the way I suggested to move Jann's block bef=
ore
> >> taking slab_mutex() but unless that happens in mm-unstable it would pr=
obably be more
> >> correct to keep where he did)
> >=20
> > Regarding my conflicting patch: Do you want me to send a v8 of that
> > one now to move things around in my patch as you suggested? Or should
> > we do that in the slab tree after the conflict has been resolved in
> > Linus' tree, or something like that?
> > I'm not sure which way of doing this would minimize work for maintainer=
s...
>=20
> I guess it would be easiest to send a -fix to Andrew as it's rather minor
> change. Thanks!

That's quite a large conflict.  How about we carry Jann's patchset in
the slab tree?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20240809171115.9e5faf65d43143efb57a7c96%40linux-foundation.org.
