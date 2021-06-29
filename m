Return-Path: <kasan-dev+bncBD63B2HX4EPBBA4P5SDAMGQEW7BQFEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 51B6E3B717F
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Jun 2021 13:44:04 +0200 (CEST)
Received: by mail-oi1-x238.google.com with SMTP id n84-20020acaef570000b029022053bcedd7sf10697564oih.17
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Jun 2021 04:44:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624967043; cv=pass;
        d=google.com; s=arc-20160816;
        b=oHYZIqduZakYV4Cqfmv/shCl1PgX6tl2YOqkVszLsvV8FaJpb9veKG7glgcs2JrhBD
         3Pw+VKzrfb/WFkGcXdTCjeT9bzV3VbBO4socIRYUoTq5e77mA2hHBi8ECfj7y24GJ9fY
         pENI2pQjbkdVDkSXZb/vq+Oh0YqAI8s7jcstmsJ1xwgClrQ4J37tv29iWgyjImNy8GRV
         /CheF8uB0r+6zOhCNDCOx9g5y6i+M2/u6bMTJDaJJmqofyrR0bxbGYPhKotMO/Dogf5x
         x27t+NnfaMienn+dheyj6HzGsCPLZRJ5pY90L4S/tZ+VC60gQKkQcBwHQiO+v/0eyJgJ
         hKgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=B3pnAAhGwYsG8cE+1mmhva4e1yby4SySz6QQxWoD8Ow=;
        b=fFTbY+kiM0Odt+2dyUE6X0lSJksj2RZ6cKYOX94XoTtdkBbUekqIB1LVEHLZnJaSsV
         H5fN94vVhzYds2VmtZbFsCNGqt8y/LHn6rOyhemuNvc5+nuR667JE0GxeEPTz+bb8kER
         Ng84AhADAAH0JzkwYxP5WfiTkFg8Ke9DCE9OJLpmIl0DL85agEWG2tKsJHwFqQI0ZE1Q
         zJqWknN12tUc0FF43Grnlst3ngc2J8vkZgleqcrY50w1c/R+7yaJGDi2GF3BsgU0YAI+
         I6rm2CUIIAL4/ivxkqjDWKr2Ja9uM1m+/86iR6kQrobGRRD+vZ5N+Z+805URtz15N97U
         gIlw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=NZ5JqNRi;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=B3pnAAhGwYsG8cE+1mmhva4e1yby4SySz6QQxWoD8Ow=;
        b=akGqykJXHokjQuIC4DnteZecz1N907LtS+TMgvNW6ah9jQWISX03OlNHSx04kuJE8M
         id8453mxJKU3fRg9z7ltzsLkSP0v/lN6aOlbEBF8pq3Iw9pqJKiIKYsgsIRf1Bl/Inus
         g5sD/9tMxdAKzqqDVEWtGNrIdiXl0Z/4HKiEtrisOvWCXpMf+2EbaxraOrpP5jtyp9K1
         Xq/y1yTdY2uWr5AKzeuUzK4cJUAOXXQCTSYkmy5sgOJFEv7fKROHCCF5xu0VZrNWGQbA
         gcPP8KZE+ximSbYlnsV/+kknlExjRy3d3Q6C7ucXnejnBGQPKD25yVIP76n2Vkl3Z1JN
         QuFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:x-spam-checked-in-group
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=B3pnAAhGwYsG8cE+1mmhva4e1yby4SySz6QQxWoD8Ow=;
        b=XX1rOX1DgT3/Spz+4O2Zo9dAAVb6rvL8coQ1EWfLU83BqfFEOF0uH4t7L/7GHkolSd
         jarJBEx6j8WYEdYOEo+085PRHtQds5QOT0ZMPldfDPLEpwdrdydr4OEt7c9bLEYpcC/B
         +BdyhLJiraUq+tWW6OIF8bM72Wq+CPMR3cBzucngCAjpvCpuzVKDwgP3SnA50D6dPONQ
         uF/bxmZjlu0+9xg7gbunLcvUpBK0uUUr3j8/o9X8BgO9rQ4+ywt8jhqrdzpTrMa+eYjX
         OfO9ZfvpdOZJlsq6hcNaAvKTwqz26kTHjZkP/b3XmG6q6mGJl9wEG03+lHcmdmnlgiCf
         M+aQ==
X-Gm-Message-State: AOAM533TLkWZ7AAoVkbpqtvZ/mNUsgO11b5LbuLdiV63er5K0gGYCKgD
	C9iWvW6AwO5pMyf/qU6SjLc=
X-Google-Smtp-Source: ABdhPJzIaYFaWrSNNULHs2ZqfOn9ZEm/ozLaf/+bK8IBBn514h63Muwr9Zcz5eqyJO9tMrcjJJHZJg==
X-Received: by 2002:a05:6830:1b6b:: with SMTP id d11mr4002295ote.86.1624967043341;
        Tue, 29 Jun 2021 04:44:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6e08:: with SMTP id e8ls3607546otr.7.gmail; Tue, 29 Jun
 2021 04:44:03 -0700 (PDT)
X-Received: by 2002:a9d:3aa:: with SMTP id f39mr3917272otf.57.1624967042996;
        Tue, 29 Jun 2021 04:44:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624967042; cv=none;
        d=google.com; s=arc-20160816;
        b=iTAJTFciJdzxk9CJfEwhsWzaw3c2RTx6oiZsqCgNnKZk29WAay6kF9vQ1CopFOqUAi
         s1LJsxRQ88JSYvU+g2gG01YmQnvfp6b8tljePFydASLpLZsyU5sMLtyPXCzXm0HC1Ozu
         T65ejPgRD9bkbo192Tq8Ss3rEwR2VrbdMagditSINPlfh0msjoZ2pJcnOlUx0XVVsn4V
         o0LyC8AncQgp8ho8kzma42GXjLrOJhBKLm0N7mJUAJzU1uTcMNe5EGJfkyhSCJ/0oVf2
         sNVc+ecnracpDu9eNJsRztrH5bBPa4o80zLXcFc+5qKLyVPGxawZ/xrndbbGzh8cMqQv
         0CGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=I7XeIXrLjB5/JjIKlsp0QxTc+g0l4DypC97xhNvEgKY=;
        b=aenTGid6pXAaVbrLLLP5a1acUup//TAmd7V3pFvuq5Aic5N9MdJa1V+4nmliddioy0
         utuoCivga0/q4EoKcYv28/Wv1d1OxGyGJ0zGhJpZKC9CK2fwDfjWztrz6PHL+qQ4peaH
         dZnDL9XCpD2rhhzr3l2nOz/Ro946aE0zR3pLJ2h2vuUsQHOZAAY3jLLwgLLAlMg9Pqxk
         LNQ7H9DczobOgDIErZyM95v26Y0t5QxoprTfenZ+yj04e8PFsyCQh+pzXYqofVPV74eM
         jo8GMofScO3NpXzIvrgzuW4h7XmJyNsDQRmHi04/ID9tcpSmOLQoZxuPQU/Jf6483+aA
         OQ7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=NZ5JqNRi;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
Received: from mail-pl1-x630.google.com (mail-pl1-x630.google.com. [2607:f8b0:4864:20::630])
        by gmr-mx.google.com with ESMTPS id c22si1320601oiy.1.2021.06.29.04.44.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Jun 2021 04:44:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::630 as permitted sender) client-ip=2607:f8b0:4864:20::630;
Received: by mail-pl1-x630.google.com with SMTP id b1so4248461pls.5
        for <kasan-dev@googlegroups.com>; Tue, 29 Jun 2021 04:44:02 -0700 (PDT)
X-Received: by 2002:a17:902:b203:b029:127:16e0:286a with SMTP id t3-20020a170902b203b029012716e0286amr27673929plr.0.1624967042328;
        Tue, 29 Jun 2021 04:44:02 -0700 (PDT)
Received: from cork (dyndsl-085-016-196-171.ewe-ip-backbone.de. [85.16.196.171])
        by smtp.gmail.com with ESMTPSA id l10sm3049080pjk.15.2021.06.29.04.43.58
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Jun 2021 04:44:01 -0700 (PDT)
Date: Tue, 29 Jun 2021 04:43:55 -0700
From: =?UTF-8?B?J0rDtnJuIEVuZ2VsJyB2aWEga2FzYW4tZGV2?= <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Alexander Potapenko <glider@google.com>
Subject: Re: GWP-ASAN
Message-ID: <YNsHe2okf7S6Jma3@cork>
References: <20201014113724.GD3567119@cork>
 <CACT4Y+Z=zNsJ6uOTiLr6Vpwq-ARewwptvyWUEkBgC1UOdt=EnA@mail.gmail.com>
 <CANpmjNPy3aJak_XqYeGq11gkTLFTQyuXTGR8q8cYuHA-tHSDRg@mail.gmail.com>
 <YNnynlQRxr9D3NJJ@cork>
 <YNoK3gss3nFxbpjB@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <YNoK3gss3nFxbpjB@elver.google.com>
X-Original-Sender: joern@purestorage.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@purestorage.com header.s=google header.b=NZ5JqNRi;       spf=pass
 (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::630
 as permitted sender) smtp.mailfrom=joern@purestorage.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
X-Original-From: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
Reply-To: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
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

On Mon, Jun 28, 2021 at 07:46:06PM +0200, Marco Elver wrote:
> On Mon, Jun 28, 2021 at 09:02AM -0700, 'J=C3=B6rn Engel' via kasan-dev wr=
ote:
> > We found another bug via kfence.  This one is a bit annoying, the objec=
t
> > in question is refcounted and it appears we got the refcount wrong and
> > freed it too early.  So kfence removed one layer of the onion, but ther=
e
> > is more to be done before we have a fix.
>=20
> Nice.

Even better, after some more staring I managed to understand the bug.
Very roughly, ACA would get ignored when deciding whether to destroy a
session.  With commands in ACA state, they could complete and reference
the session after it had been freed.

Another bug we wouldn't have found in a decade by conventional means.

> > What would have been useful in the investigation would be a timestamp
> > when the object was freed.  With that we could sift through the logfile
> > and check if we get interesting loglines around that time.  In fact,
> > both time and CPU would be useful details to get.  Probably more useful
> > than the PID, at least in this particular case.
> >=20
> > Does that sound like a reasonable thing?  Has it maybe already been
> > done?
>=20
> How about the below?

Looks good.  I'm semi-busy travelling, so I only gave it a quick check.

J=C3=B6rn

--
It does not require a majority to prevail, but rather an irate,
tireless minority keen to set brush fires in people's minds.
-- Samuel Adams

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/YNsHe2okf7S6Jma3%40cork.
