Return-Path: <kasan-dev+bncBAABBYO5YDBQMGQENSVYQ5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 7AEC7B00DAE
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 23:21:39 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id d9443c01a7336-2349fe994a9sf12527025ad.1
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 14:21:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752182498; cv=pass;
        d=google.com; s=arc-20240605;
        b=QOSLGCdbyGb1pU3PWAaunILO1cIS/2X0lVBpnmX7FnuO8pfvIME9z0FR4UmhZsQ84y
         wCHd/FiTW4NAiG2ORsQgAI3KuGehXKI8Y8xUCW9jrBJ2Ff0Z8tb2LsOCMlPB4zcIxmUK
         EuypSvttqKdoBAD+pm2qfsRvTR7mZH2ZpRzaD2wBX9ndj62tarhE36AE6mJqJbjANHeN
         bOTgZKDyIp5r78VXDrYXIgvXnT6xj0NIo6Y2I3Jb0wsy0+LdjM5eAX3ta+COgYHxgbXU
         D+w8dc47VPJPxEJfSvk9Kfywk9geNlbBStlQRUXJGkcm8+PFf3wOixUGjbv5RRyDQAxo
         49tQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=YkFWAAECsFO01GEj55Pi+6rf5oQ93lXkQLFM+ISSLTo=;
        fh=AhoOyBe6pNdHp+leJA+Mb2JKIj8DUN2jK24iwk35H+8=;
        b=gifTgQlgMzMkIYXuMdIgZMOGNvAF6lCmPXlAHK4mOiXDyJYyn9HT6/lDZ9XrD5Wuvt
         v6b76T2CEyC+3BhRS+A5YReB+pYJhAIboi57U2i6QL2uJ0TeJEhKSRvEwqLlth08usiB
         mLfqmo40MFpZObXc1aWkS1hKZo/ufGdvrR8HbNhDMMbf7NypD3ZZKNkaz1bpk7jeOVzr
         SoajQMaRYtOMeiHf5v1dS2tPqxE5D7PmMXag1BAM3bAF49B04sNd/wPO56Fa4UTrDNcU
         Pus2RipfEcFQTbHWcxUSJpHg4Id1OFevsJVz9U1qy6eFuEeZXYleFBqJDuDDHoAnnw6D
         N3Iw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=gj450Crq;
       spf=pass (google.com: domain of alx@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752182498; x=1752787298; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=YkFWAAECsFO01GEj55Pi+6rf5oQ93lXkQLFM+ISSLTo=;
        b=nnHOVQ7X3TtWLYskeENiNt3Fva+CB+VW48xlCvHf/gBLCv6wVS0qRrdcFPkEp72mgL
         3g9CZcfIIchRWqF5e3PSc9nYwzy2OlyQNETZRx2iwxMkHGksShU3hQz7g2vSTbf6Ud6d
         vyZXJ+WsBAq4xeDZQ4w1J+61jj6ySLFJ8hHSlCC/fnO2j5rGZCJ2kpzLkiR2sLLLgZyG
         NlzFKTnd17DEijHF1+KsewZvg7rDsrmn/ElT8Vam0W29vU/mzpkVOllCFrhhWvICUvpw
         VOmZT9V3mrwzGmg5ZrVBILYTnIPV8ZVQQNKF1bzE9AXAaWeUB2UqnwkELluo+0VWQgls
         B96A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752182498; x=1752787298;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YkFWAAECsFO01GEj55Pi+6rf5oQ93lXkQLFM+ISSLTo=;
        b=b1Vak56ktmXE5I+faLGOSsfbg+/5FQhAR1HNShmeU2mcwtEkhbaDFIUFc3aYJPBjGY
         LHoLeMQ09r0OfqEB7VYfFMThipwEqM26D5vHwzsqK8s2avpiBn1x2KMqrsx3dNxEKCLF
         bKEVwcnETkClJ02azWvCOEZCfF3jTQNCh02yUs+1aDHc1fMus+Wnd9mQ7+cNhNTFxYEe
         Inf74nZ2/WmA4WIPu5aWODYFKXvZcp1I07dTHkv8tovZfI4p7s8SxG/Luod90vWJuF6y
         aRDmp63/1wlzya3WbIO6iYNJ5TYk0cz2yIgiFVhtIx5ongto087HlLJGhLLV2crnBXKr
         Ixpg==
X-Forwarded-Encrypted: i=2; AJvYcCWVIzYu1kz5HqP0aBJZGWVGeCck9HjNkRSheMHzNjj6fewnfotHDqSYbEDfYw+dDr7rg3rNjw==@lfdr.de
X-Gm-Message-State: AOJu0Yyc03IWJF8VHU7G6+ze/8eBuXOeD6g4Lla1C1TTkQYO4N/ohO+H
	vYoR5XtZzXz99WQHm2HS8mtgyECAP2Y17mVXyQcR6weHl5P3ESCDN25T
X-Google-Smtp-Source: AGHT+IGqLrNZNrg2nGdOsyQ1fav2+0BwFwrUofZdrp3YrJv78A3ZAXP9t0A+KiCKn/sVwD4OWfjgKw==
X-Received: by 2002:a17:902:e80c:b0:234:cb4a:bc1b with SMTP id d9443c01a7336-23dee3af512mr7756865ad.49.1752182497767;
        Thu, 10 Jul 2025 14:21:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfXW6wrlHVZ3HpMpa/MsHO0sw6fl8aoxwSo7QpOsi8Lbw==
Received: by 2002:a17:903:2a87:b0:234:9ef7:61a6 with SMTP id
 d9443c01a7336-23de2e1b376ls15233705ad.2.-pod-prod-09-us; Thu, 10 Jul 2025
 14:21:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVhL816LckokeMdwXxwfZymLsB4GneTiGwAoHpndLg131G5RSzusRyAzPe0jxCD53kTUCb5dkV1p/s=@googlegroups.com
X-Received: by 2002:a17:903:1a0b:b0:23d:ed96:e2b6 with SMTP id d9443c01a7336-23dee2a09c6mr9036005ad.44.1752182496576;
        Thu, 10 Jul 2025 14:21:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752182496; cv=none;
        d=google.com; s=arc-20240605;
        b=L81tYYBBw8fHznCL6PFaDW3xvER8s0/B0G4Vvr9BQSK4FntPtZGzqAUx5Upf0zwv9f
         NeQIvs4Y6uJT0uVauHmYQrK/f3p5kgM4nULakRbEbvNwcew4bdKkxQSwGSQzqt/JT3V+
         jCo/vkOQbWEVXCQp/lpNjt+Y7Dlq1NxqNyo7tfwRL1mUeTTYOQuFS866G2rGjooIDQ4O
         gvUcX1OgiKtI01pSLn1L/g5aRyfjolSq6mgk3yyFgwdZNbxOuA0s7ZAbe2N3Z67D5+fk
         GwrXV8Bb3eCsN36mBPd0+oDTk8h4DjQmZn4L60H6aiyLzKA+4qauWhu/RhAy7JIQi4Fp
         uINQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=6YIeQpInIwQz2Nd/h4h5EwwajbyybB+Kp1ssJRPsM4Q=;
        fh=27HATg/3q9XP1Ib0lz1m3MmiSlFXVfpHfl9a0h/+uVM=;
        b=YEXfhcnhNB5cTwkM7+vrqxno0aLmCCyMrpDW19ldGFrBzS2y2V5YJTSHcNlGK0JahT
         v+YAJdKrf0YVcZnnBWJiwk1Tx3DVb7Zex7GxcMSLpaxGdIuipGmMKrKinWz8Zp7YJiyc
         VvFPHpGjfPAHOgdHG6jH+FTvvEibjGUah7zoyiVN3j4x//4iteWtr+2sqsFLfrNiPKYq
         JmA2QC/7+ZDxmIi/c8st29aK02h4kAEdwPtcq4jcfqYsoyElwOPpndQCRKGqIxMCPemY
         1mOzOmNsT91OkHC1MNuRoBAtWmZjIF2hw5bxt8MOzHkLcU9VlF4eJseqI6NbwxrQ9FPo
         nAZA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=gj450Crq;
       spf=pass (google.com: domain of alx@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-23de43302d2si1064285ad.9.2025.07.10.14.21.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Jul 2025 14:21:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 5087B61148;
	Thu, 10 Jul 2025 21:21:35 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 213A6C4CEED;
	Thu, 10 Jul 2025 21:21:30 +0000 (UTC)
Date: Thu, 10 Jul 2025 23:21:28 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: linux-mm@kvack.org, linux-hardening@vger.kernel.org, 
	Kees Cook <kees@kernel.org>, Christopher Bazley <chris.bazley.wg14@gmail.com>, 
	shadow <~hallyn/shadow@lists.sr.ht>, linux-kernel@vger.kernel.org, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Rasmus Villemoes <linux@rasmusvillemoes.dk>, 
	Michal Hocko <mhocko@suse.com>, Al Viro <viro@zeniv.linux.org.uk>
Subject: Re: [RFC v4 6/7] sprintf: Add [V]SPRINTF_END()
Message-ID: <yxa4mb4tq4uamjc5atvhfefvxyu6fl6e6peuozd5j5cemaqd2t@pfwybj4oyscs>
References: <cover.1751823326.git.alx@kernel.org>
 <cover.1752113247.git.alx@kernel.org>
 <0314948eb22524d8938fab645052840eb0c20cfa.1752113247.git.alx@kernel.org>
 <CAHk-=wiYistgF+BBeHY_Q58-7-MZLHsvtKybrwtiF97w+aU-UQ@mail.gmail.com>
 <svune35mcrnaiuoz4xtzegnghojmphxulpb2jdgczy3tcqaijb@dskdebhbhtrq>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="7rucxqy6jxtw6lim"
Content-Disposition: inline
In-Reply-To: <svune35mcrnaiuoz4xtzegnghojmphxulpb2jdgczy3tcqaijb@dskdebhbhtrq>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=gj450Crq;       spf=pass
 (google.com: domain of alx@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=alx@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Alejandro Colomar <alx@kernel.org>
Reply-To: Alejandro Colomar <alx@kernel.org>
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


--7rucxqy6jxtw6lim
Content-Type: text/plain; protected-headers=v1; charset="UTF-8"
Content-Disposition: inline
From: Alejandro Colomar <alx@kernel.org>
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: linux-mm@kvack.org, linux-hardening@vger.kernel.org, 
	Kees Cook <kees@kernel.org>, Christopher Bazley <chris.bazley.wg14@gmail.com>, 
	shadow <~hallyn/shadow@lists.sr.ht>, linux-kernel@vger.kernel.org, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Rasmus Villemoes <linux@rasmusvillemoes.dk>, 
	Michal Hocko <mhocko@suse.com>, Al Viro <viro@zeniv.linux.org.uk>
Subject: Re: [RFC v4 6/7] sprintf: Add [V]SPRINTF_END()
References: <cover.1751823326.git.alx@kernel.org>
 <cover.1752113247.git.alx@kernel.org>
 <0314948eb22524d8938fab645052840eb0c20cfa.1752113247.git.alx@kernel.org>
 <CAHk-=wiYistgF+BBeHY_Q58-7-MZLHsvtKybrwtiF97w+aU-UQ@mail.gmail.com>
 <svune35mcrnaiuoz4xtzegnghojmphxulpb2jdgczy3tcqaijb@dskdebhbhtrq>
MIME-Version: 1.0
In-Reply-To: <svune35mcrnaiuoz4xtzegnghojmphxulpb2jdgczy3tcqaijb@dskdebhbhtrq>

Hi Linus,

On Thu, Jul 10, 2025 at 08:30:59PM +0200, Alejandro Colomar wrote:
> > IOW, why isn't this just
> > 
> >   #define sprintf_array(a,...) snprintf(a, ARRAY_SIZE(a), __VA_ARGS__)
> 
> Agree.  This is a better name for the kernel.

Oops, I misread.  I thought you were implementing it as

	#define sprintf_array(a, ...)  sprintf_end(a, ENDOF(a), __VA_ARGS__)

So, I prefer my implementation because it returns NULL on truncation.
Compare usage:

	if (linus_sprintf_array(a, "foo") >= ARRAY_SIZE(a))
		goto fail;

	if (alex_sprintf_array(a, "foo") == NULL)
		goto fail;

Another approach would be to have

	if (third_sprintf_array(a, "foo") < 0)  // -E2BIG
		goto fail;

Which was my first approach, but since we have sprintf_end(), let's just
reuse it.


Cheers,
Alex

-- 
<https://www.alejandro-colomar.es/>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/yxa4mb4tq4uamjc5atvhfefvxyu6fl6e6peuozd5j5cemaqd2t%40pfwybj4oyscs.

--7rucxqy6jxtw6lim
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iQIzBAABCgAdFiEES7Jt9u9GbmlWADAi64mZXMKQwqkFAmhwLtMACgkQ64mZXMKQ
wqlldw/9G3vuwHK1ltksLTZk/bAMY1df2lNT+Tnvbn1O60dXRLNSLE1uslMMtt5m
Ch9ME1lm4Z3rjU+EvgVg+CTTUXjmwPBMwC54IX4d55SJPLERcYcjrftC7AkDiaqA
+lHnVLrZzGgcdypVU7sADXi4efbbA2ju7Z9vpmvAivQr8bpP49dsahV/DjjVGOqT
t9ZPfx6FbbGkGbceyVrYVVGdPt+2xRQ1lWAmmNxHvw2s4FPsbX3qTjFzCi3py3jr
YfMncGwTyfeaivqCtayzi4w32hYDAsP6zigcf3ZPv2coww51DP1dnvY8c6CqabF4
SBTYZPtTfbByr/COPxdNvJKqszwUKnuMpbLK0nSXe+zKUJsNGeQfFbg8SWG/AK+P
miRh99ztSOhn13wqYqkJZEpVhPfjDgurEYVN1DeOMMLkvjEThtTF5A5gQebKAe0a
nVxc+0UBwZyJflXngUvrwazrM+20tt+YK992Mgus+1tOcdF3RpphzR6umUkiv6de
pesBSrzjVFdb81e1slMHaPpuouaIcTGHh+wuDSamjx/7Tfi/dUpz1ifa19UdUeWR
4LJMN2FPIW+41OM8WwAppQXwehXlE2gKssUEa6tln4k8Pi/dn6ZZTxh25TPYI0Lc
1O7lU+hNeS52MnpJRCpZpRhhZB0CAfGIFVBGT2EKIFdHWTbT1ho=
=0kpp
-----END PGP SIGNATURE-----

--7rucxqy6jxtw6lim--
