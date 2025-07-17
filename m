Return-Path: <kasan-dev+bncBDCPL7WX3MKBBYMV43BQMGQEDZ6SN4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id D2879B09867
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Jul 2025 01:44:35 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-23692793178sf10870815ad.0
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 16:44:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752795874; cv=pass;
        d=google.com; s=arc-20240605;
        b=RZ001sCQXuqr3/MoKhbGMKcXg/xRPMx4hGoNloyAYiZS/QRj/zgisxMooH3a0bG31n
         s6TuvEFlRs5czD7+Me4QIBqWHKZkSNbAQZfteMvObgrCSg9qbmI1Wlla0MCwhktw2PlE
         DqwbsAzFGXegA6WE2ssfpt9pUV8YQHQNuO2rwgeUyQ660anmADK7YRPT5IdB02pcRYFa
         jshZF3VVotGN15g6BYAFOVSaLSKEMwzjGgZctcg56VeH5OrAb35o2oRYhGYYPgLeCxrc
         RY3bFoTb8nUeGzNLMY6/gEvNf3GL2geN1WT1gVPUsxx5Uc4rV6Vq4kja1qsHW52MgiLx
         uieQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=D11xI+X1GNfsCrZHrQ7n+6XEv2traYOYKZmOU+nl2ag=;
        fh=qRlXKtM2ISs3YIzZIENyHU7BRGaICMhwJskFqn+Oe2Y=;
        b=fpbXJRpWPsH3IAaZwyNvjtDkiNfESpHWcr4+L6Ty27iQH3FE+IRNMz069KlbTCEeCf
         pHy3Y+/TRb0yfZz1duHPp9PhpHcZlOQFkpcJlRx7tuXp1nDB9T6HUvwvXISnsiRLJnbq
         o0d75aOlZC+jEuRy6kaiMcl0jNGxCwtCsTrapvJppqmpIPus+XXS8FcC8zSbOtorXP10
         Sv36v0yUsWLpn5T1S77CQh1cg7H2bJaxktc+291v2s/VgjDUqnPluwniWwigjJl1vTMA
         kWatRvxA8VctMjiwLkdosX5oduax8nHEaEceZ0VUpYOD14vkiE/atewO+4/dMA9w45ed
         Xx3w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SzfaH+Fh;
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752795874; x=1753400674; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=D11xI+X1GNfsCrZHrQ7n+6XEv2traYOYKZmOU+nl2ag=;
        b=wSZIWFeJRgH6lOwtx62bzv6UqNsNbKOoxDwT4kXvx8uLbaTmDz/NVxKI83gW2AUlvh
         XWajFXpAAsu6IM++sey7qAiOzcq7/cvkbfPL+akJcFxBZ8SXRgq9zyeOggomzIMXYEeL
         FPRZgY9l6VTGW9Su54w+Xt/6ynhosSJl1p0pBMHmL2LbY+Ify2pUjOtR7MKw7n5GotZb
         HlCwJSHd2tZfuFw5wPhGSOo4Zai9qzNqXXKoOtoihqoc6/BhgDD8rd0TNh4skPrQGiBb
         cX/SculODjO53+D6wxoxROyl/85ujQSIOtEDn8nVHcTkEf8YQcbp2dnsLiZQiRD0cgqr
         kfeg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752795874; x=1753400674;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=D11xI+X1GNfsCrZHrQ7n+6XEv2traYOYKZmOU+nl2ag=;
        b=MNlT4rSRcGHXblTU+24CaFw5MCvFJXvZrT0MJUFNBvzkBVrW/3R7Tb8GqLCtmXZCGf
         80MTw9DwdJp9fRv6XuIYbz8QI/ORlsf0WVtBb5CoZg2PS0YMmLfd4MJWmFJtVBkGbrnD
         gaJ2zZOnc2XZkgmbDj+f11KKCRlC5cuhyObDuvYEmYOcoucB6ZKDCtbT6Cm0Mu0P7Hzw
         vda3g7aEWBJRVILnmnDs1tCfibextzsQ3j+uAXYvNlG5P7yJCQ7NDjOInyFqYMiGqYJ2
         JrwSxpxo2FYfMI11RMoLj0oYGaWc0xT654xLE4xBYvjfNBwmO0Zeu9b8h3jtZOaYoCmH
         s5fQ==
X-Forwarded-Encrypted: i=2; AJvYcCXngAzfNtGVCxAqYk4Rytq2ME7mnf4w2fcFyBrpm+ssvE/DxvJuqp8c1oBkbEuNxv82PLvSLg==@lfdr.de
X-Gm-Message-State: AOJu0YxHhzh3D557gpC5BgwZV3ywuQ09O2O/ofxaATnYRTHw5dPWCixD
	aVUX1vrzbLjgneoPrRQaXB1O4ZLobH90njor8I9F07x2BOquc28hR9Tc
X-Google-Smtp-Source: AGHT+IFikCmpuVsWSCluTH1QLwRu7Ci0NcpgaUUtVr1Lu8C4c2ZL3t1on8EQJSdcLhj0u2s1iZVjag==
X-Received: by 2002:a17:903:84c:b0:23e:3c33:6be8 with SMTP id d9443c01a7336-23e3c336f4bmr5439265ad.8.1752795874054;
        Thu, 17 Jul 2025 16:44:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeYNyLzCGOd/dj+7W0/H4mi75rWAF10QQkomETimN61jQ==
Received: by 2002:a17:90b:3641:b0:31c:b5c8:53e2 with SMTP id
 98e67ed59e1d1-31cb5c8599els695298a91.1.-pod-prod-04-us; Thu, 17 Jul 2025
 16:44:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVR0WN9fxfh/wKUvqCTC9jRF+iwCWuV8zl2ykNS4ENn0IfuYVLbmntmd8/wnoXq19M6sNZZTPcu0Bs=@googlegroups.com
X-Received: by 2002:a17:90b:6ce:b0:311:b5ac:6f6b with SMTP id 98e67ed59e1d1-31cc253d5c7mr1227289a91.9.1752795872712;
        Thu, 17 Jul 2025 16:44:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752795872; cv=none;
        d=google.com; s=arc-20240605;
        b=T8Umo83fe7LtO8T4D9noeQWGgVslTXhsBjZ1sS3aYf/QzVOjMj3nXXtei64ZyPCnAN
         2dx504ar2NvcRaL9QAa2hirW6oGroTNr1drqTHZOsVs7qk1qZ/CrFI4ZUdojdEVosbd9
         gGZEV25GslPttIsKusSGEvrsgHk0oRzeHmip1ny7w4VF1NZcziAr5g9Ug9RjHKrmyZ6k
         JT1pwrrG96blqKA/mrnp3AtW5okdEHkERJ9MAjbFWX/mV2Bn7Z4imutf8WpXqLx7G/Gu
         zhv95Y4HnR5ZNiTUeU3h4xD50HhlaeGzvccRBEbWNVbug5Qmzm13oxYn/VjKEzBeaSSU
         +WeA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=VjgPfxy/JZnEml13t3c0HaQUwX1qYUBpOmj6F5DrhUM=;
        fh=W2GuqOSQkMx7SRa4fFRDCZUcYkGdl5ZdziUMbW4+5lA=;
        b=Tl3g+yGhRdowuJgz+EUe7GqIFMOrdVgBuSOiKFZgbWMN+wT/RuArae9zBYl40K6H+N
         r2RYC0m5YX3/8bP0gi0vuICT3jQ5ipRY1oFExwtZ/XY9h/dXA/FY2xxhtWqrGe4d86NX
         TBYtnXEJtCDTM9rHbTJAm+aTNyahCYx3bX0M9dWxgePy7Coy3rfIr8Pr/3+v42Lx87H2
         4QUDHOu8vTzYNKSfy4lMzhfd5rLsxznHurLJgeuCvHvbW922PECX5rtqeQur+BFSumKW
         QNsNyP+3eMs9AWz7Z+OyVqtf1whu6hixvjhXEeZgyDmsu2iAW/GmBmw1JZe7hBW340g4
         1K8Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SzfaH+Fh;
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-31cc3e35411si9279a91.1.2025.07.17.16.44.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Jul 2025 16:44:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 6D81344846;
	Thu, 17 Jul 2025 23:44:32 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 48199C4CEE3;
	Thu, 17 Jul 2025 23:44:32 +0000 (UTC)
Date: Thu, 17 Jul 2025 16:44:31 -0700
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Martin Uecker <ma.uecker@gmail.com>
Cc: Linus Torvalds <torvalds@linux-foundation.org>,
	David Laight <david.laight.linux@gmail.com>,
	Alejandro Colomar <alx@kernel.org>, linux-mm@kvack.org,
	linux-hardening@vger.kernel.org,
	Christopher Bazley <chris.bazley.wg14@gmail.com>,
	shadow <~hallyn/shadow@lists.sr.ht>, linux-kernel@vger.kernel.org,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Harry Yoo <harry.yoo@oracle.com>,
	Andrew Clayton <andrew@digital-domain.net>,
	Rasmus Villemoes <linux@rasmusvillemoes.dk>,
	Michal Hocko <mhocko@suse.com>, Al Viro <viro@zeniv.linux.org.uk>,
	Sam James <sam@gentoo.org>, Andrew Pinski <pinskia@gmail.com>
Subject: Re: [RFC v5 6/7] sprintf: Add [v]sprintf_array()
Message-ID: <202507171640.F649D58897@keescook>
References: <cover.1751823326.git.alx@kernel.org>
 <cover.1752182685.git.alx@kernel.org>
 <04c1e026a67f1609167e834471d0f2fe977d9cb0.1752182685.git.alx@kernel.org>
 <CAHk-=wiNJQ6dVU8t7oM0sFpSqxyK8JZQXV5NGx7h+AE0PY4kag@mail.gmail.com>
 <28c8689c7976b4755c0b5c2937326b0a3627ebf6.camel@gmail.com>
 <20250711184541.68d770b9@pumpkin>
 <CAHk-=wjC0pAFfMBHKtCLOAcUvLs30PpjKoMfN9aP1-YwD0MZ5Q@mail.gmail.com>
 <202507142211.F1E0730A@keescook>
 <d43ebab47ee70cd11bddf78c424ec341b4c797cf.camel@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <d43ebab47ee70cd11bddf78c424ec341b4c797cf.camel@gmail.com>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=SzfaH+Fh;       spf=pass
 (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

On Tue, Jul 15, 2025 at 08:24:29AM +0200, Martin Uecker wrote:
> Am Montag, dem 14.07.2025 um 22:19 -0700 schrieb Kees Cook:
> > On Fri, Jul 11, 2025 at 10:58:56AM -0700, Linus Torvalds wrote:
> > >         struct seq_buf s;
> > >         seq_buf_init(&s, buf, szie);
> >=20
> > And because some folks didn't like this "declaration that requires a
> > function call", we even added:
> >=20
> > 	DECLARE_SEQ_BUF(s, 32);
> >=20
> > to do it in 1 line. :P
> >=20
> > I would love to see more string handling replaced with seq_buf.
>=20
> Why not have?
>=20
> struct seq_buf s =3D SEQ_BUF(32);
>=20
>=20
> So the kernel has safe abstractions, there are just not used enough.

Yeah, that should be fine. The trouble is encapsulating the actual
buffer itself. But things like spinlocks need initialization too, so
it's not too unusual to need a constructor for things living in a
struct.

If the struct had DECLARE which created 2 variables, then an INIT could
just reuse the special name...

> The string builder is for safely construcing new strings, the
> string view is for safely accessing parts of existing strings.

seq_buf doesn't currently have a "view" API, just a "make sure the
result is NUL terminated, please enjoy this char *"

> Also what I found really convenient and useful in this context
> was to have an accessor macro that expose the=C2=A0 buffer as a=C2=A0
> regular array cast to the correct size:
>=20
>  *( (char(*)[(x)->N]) (x)->data )
>=20
> (put into statement expressions to avoid double evaluation)
>=20
> instead of simply returning a char*

Yeah, I took a look through your proposed C string library routines. I
think it would be pretty nice, but it does feel like it has to go
through a lot of hoops when C should have something native. Though to
be clear, I'm not saying seq_buf is the answer. :)

--=20
Kees Cook

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
02507171640.F649D58897%40keescook.
