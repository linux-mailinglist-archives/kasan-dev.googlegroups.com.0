Return-Path: <kasan-dev+bncBCQ6FHMJVICRBHHWR3XAKGQETOVWKAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F644F27AF
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Nov 2019 07:35:10 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id f6sf1510713ilg.5
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Nov 2019 22:35:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573108509; cv=pass;
        d=google.com; s=arc-20160816;
        b=iJ25/35LppqzjUMGW5ZM5f5MS7JjpYIJ4peWKhNQ1CX4T/k5kxOGoebAFB3gIa3BwV
         hRJaVeHt0JuEi/ZljxXav+OChv34JCEp+Dd4OksL+E9aMSqyYEu3WRp1kzgjIgc7xhrS
         l6aQi+XwbsdtKA+mLFpEZm+/hgvqLP49Jh6mh33kzyrVUAGeib5GTZE+tifevd+oMrZh
         SU0ETw7Gubk6kaEx5IzPeXqNun+YfGMDiqFpi2qtI71Z/SUGnrRiqYG//8O/ME8+RdOC
         Hfo1H29rsDR6ZJMq6X0mq5WxjV6AEz7Hlx0OipdH7oRQr9Q9Of7YMPr7ImvQtNOw3CV6
         TRuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=g82rxy0niwaVveF2S8W9/6TTXzBgrJWLiT3KUJndaks=;
        b=t2Bru4R59Te3LKiMaAa5UTefzVFnxW8CBMCuab0RLczSE1qp+QbzXR2xM9WNzyj7mI
         m/HPhOgq0T8PvE4enGj05fccuX3s07GaPY4WHi908d4rBZTPB/9kmTKgFJC2BdQsxFar
         icE7N/oakJ2hpD+KqSRZaN8XmjJZW5SaRHZUZn8j/K70R+JqHJ3lEIyvxSLCn1qaqtzc
         Uh0kocsaUdSaIgD7sosjU3H9S7/OQMGq21vXHmPqdgyiRlLhgrTx9URpHpP6nQJ3H4Tp
         iuY4AyF/IqOJrvtYhcYLiTrbgn/fGD/nogTw3MoKCImOx3tpPht53kEmpduw/XsJeikl
         r+gQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canb.auug.org.au header.s=201702 header.b=l5EM9iXC;
       spf=pass (google.com: domain of sfr@canb.auug.org.au designates 203.11.71.1 as permitted sender) smtp.mailfrom=sfr@canb.auug.org.au
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=g82rxy0niwaVveF2S8W9/6TTXzBgrJWLiT3KUJndaks=;
        b=BqFAG4qNwijulkZAPPTzYVqLmKwVBY2uQop0lmDBfffyqMEjE2jxP2f9yNFlHx+2W9
         bsqfOIpSuc4sWetlJpTF61GgWo8Un1desjwhahWDYi7oUN+E1NMkAIx6Ni18Q3zDLH0U
         oiK4oRfopr38sNQZXgT2T//po3RhpaqqLwp0QTICX+4hQ/8v/xhRKVWm8e0Hi9s6pWiJ
         JkKtq0dv3IUMVTlkFjaiURNjlT3eyc8D1OD+eLNIe5Bc7GGImYu2mIjEtJ8dURcWze4P
         PT0PpuyKi5j5lkeVwzMkdj9Y4H+1ad9WcC6kkpRTvc/T+vSykp1DI6dNaFNRg9IGIbet
         p1xw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=g82rxy0niwaVveF2S8W9/6TTXzBgrJWLiT3KUJndaks=;
        b=TQ7ITzEZuLNgY+DeJddYv3WPjdkqGKMlAvo4PGRE9Fcn+tzB/SsMJLbr1UypKbnYig
         ZbKnu/HJkWRxD236IFmphoGImnSCajKQ+eHULzZ0ZqTdO1QE68judNKHq7PT7adh/BVF
         9rG3MibHrdddQWifzUZE31PsRD/LarqjrsBQTy2oK51/UF+5PIMUDQSYCtMz6NQ/WmH3
         4aIblNue086UxP/sRoCSPuV9g4ZCqqQCJq4jpCSN8b7oKZPWFnZwOFdT8N7PGCfX9apk
         I4cqIbQT6N1kkOgGJIbsDcOkj9TaaU9m9QmY/1g2O0yeYX1ZFepETamcbIM34ETX2J9d
         PsCQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVprtzM2nzvbQ/aayhmMb9oDMBcg6xxN33M8IacEGZOVDr3Rpjt
	QMSf6HkXua/QXjfydq+ofmY=
X-Google-Smtp-Source: APXvYqxUt1yvD0iBZKgsAL66hu71agljPeqBwQvMmG5s8GWp+1zKW7TVJ1ekBOiCN0gnM8wZjXYavQ==
X-Received: by 2002:a02:1788:: with SMTP id 130mr2303616jah.82.1573108508785;
        Wed, 06 Nov 2019 22:35:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:37cd:: with SMTP id r196ls403714jar.8.gmail; Wed, 06 Nov
 2019 22:35:08 -0800 (PST)
X-Received: by 2002:a02:a09:: with SMTP id 9mr2443339jaw.84.1573108508105;
        Wed, 06 Nov 2019 22:35:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573108508; cv=none;
        d=google.com; s=arc-20160816;
        b=MN8GtrGOy4tnl900aTm8vxSvLpo+XEi0JIemMnxxU/OBF5fV1el3vQi4aVFL1FgfeN
         ziEuTyxMYWSrzsJHgvA0eyxUDOIx6l7gv9MuckKSGByPTVsLJch5G1bZwUmLU5RwwRUL
         mgUnCS7OVGv08vWoM8DpiRCYZY/o5Ufv7QktM5npsG/7ZS7P3WK862NH9ClwsMfLPUtq
         rgnkAjfbXKttMb6EpQP3yYzJKArWS/usSmJDeC3LVUvLH91yLEuzTcCIDPGn5maUdwTA
         XBrq37ZkAb3IYs4OJCqi/lt86Y1TyvYY7tR7lfF224XnIW3JMXbUY//FIJOOYCQljxNd
         8Cww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:subject:cc:to:from
         :date:dkim-signature;
        bh=lpPQpfn7Cw8YS1TocSuox9N/4jbiZLX9RTirfzk76pE=;
        b=S1VUgrdmfMPBPffgslp0gRQn2YIGB13y/YJ3LaUIyXdE0TbFZakKgSkWR4+BYSC9sB
         Z4zSQIUZ+LrXPc8+3FKj9jTszJ6maAx0sfBBel7svIAqSbUH+jx1+Ca+jNaJIhtycCl+
         bVvRXbQDGEjLzx+t7xaTVkisix4KMTSnftk9nEY+cn2F1GBW80oKu+SIXZfbEZIbMyGL
         cLsNrgp+o1L3Y8YpNsY1CMVE2j7vj6xpIEWFJC1Uxqd/bwmkRi1pGw8dNl2NqgYbXXyj
         vbieYOqaifE1gTZAuOyJtNDdDNRTMRcYDKf7/YIk/99qGLECGBOu8QdwklBt3y9lwts6
         Ww5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canb.auug.org.au header.s=201702 header.b=l5EM9iXC;
       spf=pass (google.com: domain of sfr@canb.auug.org.au designates 203.11.71.1 as permitted sender) smtp.mailfrom=sfr@canb.auug.org.au
Received: from ozlabs.org (bilbo.ozlabs.org. [203.11.71.1])
        by gmr-mx.google.com with ESMTPS id k11si62193ilg.4.2019.11.06.22.35.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Nov 2019 22:35:06 -0800 (PST)
Received-SPF: pass (google.com: domain of sfr@canb.auug.org.au designates 203.11.71.1 as permitted sender) client-ip=203.11.71.1;
Received: from authenticated.ozlabs.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by mail.ozlabs.org (Postfix) with ESMTPSA id 477ttV3Hh4zB3tP;
	Thu,  7 Nov 2019 17:34:58 +1100 (AEDT)
Date: Thu, 7 Nov 2019 17:34:51 +1100
From: Stephen Rothwell <sfr@canb.auug.org.au>
To: Michael Ellerman <mpe@ellerman.id.au>
Cc: linux-next@vger.kernel.org, christophe.leroy@c-s.fr,
 linux-s390@vger.kernel.org, linux-arch@vger.kernel.org, x86@kernel.org,
 linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com, Daniel Axtens
 <dja@axtens.net>
Subject: Re: Please add powerpc topic/kasan-bitops branch to linux-next
Message-ID: <20191107173451.6be74953@canb.auug.org.au>
In-Reply-To: <87r22k5nrz.fsf@mpe.ellerman.id.au>
References: <87r22k5nrz.fsf@mpe.ellerman.id.au>
MIME-Version: 1.0
Content-Type: multipart/signed; boundary="Sig_/QLj.mRHKb6JGbFGyiT8jLoU";
 protocol="application/pgp-signature"; micalg=pgp-sha256
X-Original-Sender: sfr@canb.auug.org.au
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canb.auug.org.au header.s=201702 header.b=l5EM9iXC;       spf=pass
 (google.com: domain of sfr@canb.auug.org.au designates 203.11.71.1 as
 permitted sender) smtp.mailfrom=sfr@canb.auug.org.au
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

--Sig_/QLj.mRHKb6JGbFGyiT8jLoU
Content-Type: text/plain; charset="UTF-8"

Hi Michael,

On Thu, 07 Nov 2019 15:11:12 +1100 Michael Ellerman <mpe@ellerman.id.au> wrote:
>
> Can you please add the topic/kasan-bitops tree of the powerpc repository
> to linux-next.
> 
> powerpc         git     git://git.kernel.org/pub/scm/linux/kernel/git/powerpc/linux.git#topic/kasan-bitops
> 
> See:
>   https://git.kernel.org/pub/scm/linux/kernel/git/powerpc/linux.git/log/?h=topic/kasan-bitops
> 
> This will be a (hopefully) short lived branch to carry some cross
> architecture KASAN related patches for v5.5.

Added from today.

Thanks for adding your subsystem tree as a participant of linux-next.  As
you may know, this is not a judgement of your code.  The purpose of
linux-next is for integration testing and to lower the impact of
conflicts between subsystems in the next merge window. 

You will need to ensure that the patches/commits in your tree/series have
been:
     * submitted under GPL v2 (or later) and include the Contributor's
        Signed-off-by,
     * posted to the relevant mailing list,
     * reviewed by you (or another maintainer of your subsystem tree),
     * successfully unit tested, and 
     * destined for the current or next Linux merge window.

Basically, this should be just what you would send to Linus (or ask him
to fetch).  It is allowed to be rebased if you deem it necessary.

-- 
Cheers,
Stephen Rothwell 
sfr@canb.auug.org.au

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191107173451.6be74953%40canb.auug.org.au.

--Sig_/QLj.mRHKb6JGbFGyiT8jLoU
Content-Type: application/pgp-signature
Content-Description: OpenPGP digital signature

-----BEGIN PGP SIGNATURE-----

iQEzBAEBCAAdFiEENIC96giZ81tWdLgKAVBC80lX0GwFAl3DuwsACgkQAVBC80lX
0Gx+nQf+Kb9/DdUAxGd+w9sWu1q0Z+Hiq9qD8vwzOM0/tFtNdMhWLOJRM0idUy9Q
NHHN0yi54olE5bolHbOqmXXITBE+Dy7RyRUchaPSMkUgAAI8n+iteHy4/ZakmJr+
6lYeGHjGzM9+9q5eYl6yD7hj6cAAyI4wBUu0fMYBcuWix/xOImWZAe/6iGRhgRLf
UAzDGUbnyqpox0S0v10SJjbTkGXyuvaxzs27pGUBZbRODNPbZYEX7hpo5TnQxzBq
ZMkJaRdxAKi0szigouKz9d75XPKNmc4zz5tY9gCShmBlE6bjJHzVF0ntNGrge78W
mMgfvcvatGMcL/fbSn8nu3+vqMnFpg==
=XNA5
-----END PGP SIGNATURE-----

--Sig_/QLj.mRHKb6JGbFGyiT8jLoU--
