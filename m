Return-Path: <kasan-dev+bncBAABBSOGYXBQMGQEBNKFBUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 50473B02460
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Jul 2025 21:17:31 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-4a7bba869dbsf52596721cf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Jul 2025 12:17:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752261450; cv=pass;
        d=google.com; s=arc-20240605;
        b=H4GB8PZPdx9jTxu6er+7Wy0ICEK4/wp4tY6Pp14uoJQnjScjc+GLytMMgs8psu/oo8
         g0icxhBd8tJ1Vopqj0rjJTbO2kdJmkOMJWxYzKuPjVcDMVI3kCNbCLzbQ+a55jdxnZIQ
         KyaG2ia2UbjvhcNGQcnC8f7cxvSsBSk6dpkUEsbcL71VrY9YbCGZJ8pjVSvMfXNTuPRC
         jcp4Mb9JPKTHCLpyQqqkSOWjuSwAaGh2+xJEBoFUOPUlK/7xARCpVilPmbYejBhxQzts
         mw7uwOdEFhSLuDtDTJaSb+EzHBxaL0gPrs0JW1pEzW8S8kEucvYYQyWzJMK/xR2FZGfN
         ICOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=vn8em3VJBBaPMcap6igR99u2Udl+Yo45lTJI8XRfp70=;
        fh=ZHQr4hk+VsHG24xFsqQEICHyvf8p80sMhfKSbafZAOY=;
        b=dDhD6zSl45sdLsIhgEzpZT2evtdaqs8Ls6ewIY5ms/5gl/CEhcTkgwNKZzO1KVyWxv
         qvBk+4BZTPO8J/t+w1AFKkXAuqJkb2wMFU6w4T2YoY8vFY8OsAJmm1uC+DOOROx+2TAX
         UJHLjI9xlzryP7D2sn9NmxhmbCk9jlbKjh8VRA2d7+hUhUStnnJz+wYhNoK5b1A5UHAr
         kQ93tjbQ9MCyu3w5oUMNdz7fG0VqqLDsmHddq9k2+yKbU/j7rQdpeE67vHHmHZzL0ycy
         kTq5nJ5HJppmb8wWrNefO28JgI5NcgyYBy6WU+XFRAP/7gaGP5TksW02v8Ur+EvdPNLJ
         IaNQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VqcQoHXn;
       spf=pass (google.com: domain of alx@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752261450; x=1752866250; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=vn8em3VJBBaPMcap6igR99u2Udl+Yo45lTJI8XRfp70=;
        b=U0Zmfo1TE0iMRsdX8PlER+hVniPZY6DeXW9KCZogxFBWUZbBQqFaNxA/7bhNbEBSG0
         AntN5qR/pX+077JTUDezPuFNVmb6LfEvP6OD4RSrMT18PJ1vYdulomk/GAL6v3cJ6D37
         wU+hBKOAHQymIvwj3cYGwibne7be1uFo074kbvIT2C1q+FUG+57J8X9cChNrEJmcCnrj
         MbcTMKdF4k2iW7XEErJFrWlZihnTTMWKOavYQiKi9rEsxFvtlVWVnhPQf5U9sBvKojUK
         OMCWR15B/R7AjepFXIvVlAWl5oggtAaA4bxsYmwxhNKQtXI/wUCCf30MlfLliU2zZBAY
         sdhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752261450; x=1752866250;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vn8em3VJBBaPMcap6igR99u2Udl+Yo45lTJI8XRfp70=;
        b=okkCYukfh+SMHXZI5hTAx2xwmgfjBl5am2genTBjmuZUJNpoVwqzJwKGjeyNosrEgh
         W9R89iId2T1Uaq/eSDgP5UJ5Xq1ZYPrCzjdgaS1Ob1zjYQNh/wFYQUnO/YH6n5cK2B7B
         w02zbUz27hIUyqzF3wS9HqDWoVjv5s91BMSOuyEVj8uTKm54/6p5ooyDOFSXXdvaz3Fg
         Jfb0emVEvSdHf/MovK0r92RQQzmEBYzzPcKH8FAkGvDc6zLZgSySXDjCY4rTG+b47eh3
         PCb5/lk8Sq7l+TCMrTBnUG1GrNdytIkFuAPy2+UgjufhxoDnn8qX722Msu1dKcsp+Jnp
         7Ksg==
X-Forwarded-Encrypted: i=2; AJvYcCWCnLLJpEd01Nw4ZXYYVb+NPLrf+5/RqvS1TDDXzCAr6XxXSRfo2ks/gwlLi70JM/1VqjBR7Q==@lfdr.de
X-Gm-Message-State: AOJu0Yzeh8Hwe+QLMChX+azUvjH42B/M78L8LUvwF5tCTxoAqbJsrWcj
	/drrj7WpF2tGWgslGoTiB5Bz5AXYp7t0u8jLnm2W6KhNTqkJRoKUtqkf
X-Google-Smtp-Source: AGHT+IE4hCBqq2+8vak4C1vZpcwhoSE2XICbCU0N/Z2OcDHdCz0KMgqdkp5zslWLb0Y5+peDlO7sJA==
X-Received: by 2002:ac8:584e:0:b0:4ab:3fda:ccad with SMTP id d75a77b69052e-4ab3fdaccc9mr26696051cf.8.1752261449771;
        Fri, 11 Jul 2025 12:17:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZenIUTuWZlHiR2y+xILD5kv5Bev4V0WHrIJN0Rkv9EcJQ==
Received: by 2002:a05:622a:2c5:b0:476:9c9c:1a5d with SMTP id
 d75a77b69052e-4a9e9ebaeb9ls33909121cf.2.-pod-prod-05-us; Fri, 11 Jul 2025
 12:17:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUg+Kq2X98cLKoIKm4u3ro6TJZOa07Glpd/17yh1H94hDSR2/pbA1oM7lmi6SNPk7rKCRDJEaGEOXE=@googlegroups.com
X-Received: by 2002:a05:622a:900b:b0:4aa:d487:594b with SMTP id d75a77b69052e-4aad4876a0fmr51451931cf.35.1752261448885;
        Fri, 11 Jul 2025 12:17:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752261448; cv=none;
        d=google.com; s=arc-20240605;
        b=A9W0Eo4iqbxPhRrPlZznzPIBfCS/w1KMu14TqSg6y+Ovi3EVLxcYdCACiDsIcXKn93
         3MxBYlDd+bsSBMHmh3C/0NP4tIBtGSqm78xCY50CyjKwGrJ1tcIsgqgQKwvb6i5+0ytu
         ROW9GHfkhav6sSYM60m+Jnze4O+/UCMIsrTnVTZ/K+S4OdiyhfgJgcZxTGx3McYfV/It
         obQVUC0E/SRIsdMOZWu8H4JMj7BV8UfS+5WQ/tJQrhjTx0ai4Bo+Mwr5TAcwUAEWrhoW
         JFztPMt+D/mDVtufbSm8lEzQ4GjcMSoHcZBw4X/8/6kST0CG0/ext16tPoYgxnI74A34
         kneg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=4Sue4U5h07UOwUTxFMzgE6eTiGZQCUp/7S+alX1FYF0=;
        fh=2OGjSb/oY7qaqI+h0DEYF1US8wtZ6PYcMwUX6GL7UKE=;
        b=JFXEZ6BV5NvBaulyAKM8ikYUwNVVNigiePzMmkCeZFDDXXocOz4882XnkBN64rADxW
         /LoAW6tDx4bBD27Cd9/Jp/26lOQlmUcdFgpUj2krVdY21B5lbDYPmafBdDxy7alJQDMH
         7Tj+VA9GmDUsMmGkwZjd6EsvJbjdB9Kn6tAzlf/FGAIHG1rk25VMn2AjP5CYJn5NJzjT
         Y1dODqO76nyAutrEKIJgQVkeInecZdhegxIesa39NvFqwFd/oNgDN0GOZR3sDzSQfT+U
         DvjUUJkoIJRP59lQ6XdtLhtez5rR8CKHmcZterxDmkosgWSpmvsw6riB9hOx49GeoYhG
         Iuvw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VqcQoHXn;
       spf=pass (google.com: domain of alx@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4a9edf3ea9fsi1247331cf.5.2025.07.11.12.17.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Jul 2025 12:17:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 580FF5C5D56;
	Fri, 11 Jul 2025 19:17:28 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 34C1DC4CEED;
	Fri, 11 Jul 2025 19:17:23 +0000 (UTC)
Date: Fri, 11 Jul 2025 21:17:20 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Laight <david.laight.linux@gmail.com>
Cc: Linus Torvalds <torvalds@linux-foundation.org>, linux-mm@kvack.org, 
	linux-hardening@vger.kernel.org, Kees Cook <kees@kernel.org>, 
	Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Rasmus Villemoes <linux@rasmusvillemoes.dk>, 
	Michal Hocko <mhocko@suse.com>, Al Viro <viro@zeniv.linux.org.uk>, 
	Martin Uecker <uecker@tugraz.at>, Sam James <sam@gentoo.org>, Andrew Pinski <pinskia@gmail.com>
Subject: Re: [RFC v5 6/7] sprintf: Add [v]sprintf_array()
Message-ID: <uipobgcwwyzsq5dtq3wf6haoae7zgwjfefokbwx5nx6wfx5uq2@vgpl36ryhkel>
References: <cover.1751823326.git.alx@kernel.org>
 <cover.1752182685.git.alx@kernel.org>
 <04c1e026a67f1609167e834471d0f2fe977d9cb0.1752182685.git.alx@kernel.org>
 <CAHk-=wiNJQ6dVU8t7oM0sFpSqxyK8JZQXV5NGx7h+AE0PY4kag@mail.gmail.com>
 <krmt6a25gio6ing5mgahl72nvw36jc7u3zyyb5dzbk4nfjnuy4@fex2h7lqmfwt>
 <20250711184343.5eabd457@pumpkin>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="744n7ojxglqyswg3"
Content-Disposition: inline
In-Reply-To: <20250711184343.5eabd457@pumpkin>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=VqcQoHXn;       spf=pass
 (google.com: domain of alx@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=alx@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
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


--744n7ojxglqyswg3
Content-Type: text/plain; protected-headers=v1; charset="UTF-8"
Content-Disposition: inline
From: Alejandro Colomar <alx@kernel.org>
To: David Laight <david.laight.linux@gmail.com>
Cc: Linus Torvalds <torvalds@linux-foundation.org>, linux-mm@kvack.org, 
	linux-hardening@vger.kernel.org, Kees Cook <kees@kernel.org>, 
	Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Rasmus Villemoes <linux@rasmusvillemoes.dk>, 
	Michal Hocko <mhocko@suse.com>, Al Viro <viro@zeniv.linux.org.uk>, 
	Martin Uecker <uecker@tugraz.at>, Sam James <sam@gentoo.org>, Andrew Pinski <pinskia@gmail.com>
Subject: Re: [RFC v5 6/7] sprintf: Add [v]sprintf_array()
References: <cover.1751823326.git.alx@kernel.org>
 <cover.1752182685.git.alx@kernel.org>
 <04c1e026a67f1609167e834471d0f2fe977d9cb0.1752182685.git.alx@kernel.org>
 <CAHk-=wiNJQ6dVU8t7oM0sFpSqxyK8JZQXV5NGx7h+AE0PY4kag@mail.gmail.com>
 <krmt6a25gio6ing5mgahl72nvw36jc7u3zyyb5dzbk4nfjnuy4@fex2h7lqmfwt>
 <20250711184343.5eabd457@pumpkin>
MIME-Version: 1.0
In-Reply-To: <20250711184343.5eabd457@pumpkin>

Hi David,

On Fri, Jul 11, 2025 at 06:43:43PM +0100, David Laight wrote:
> On Fri, 11 Jul 2025 01:23:49 +0200
> Alejandro Colomar <alx@kernel.org> wrote:
> 
> > Hi Linus,
> > 
> > [I'll reply to both of your emails at once]
> > 
> > On Thu, Jul 10, 2025 at 02:58:24PM -0700, Linus Torvalds wrote:
> > > You took my suggestion, and then you messed it up.
> > > 
> > > Your version of sprintf_array() is broken. It evaluates 'a' twice.
> > > Because unlike ARRAY_SIZE(), your broken ENDOF() macro evaluates the
> > > argument.  
> > 
> > An array has no issue being evaluated twice (unless it's a VLA).  On the
> > other hand, I agree it's better to not do that in the first place.
> > My bad for forgetting about it.  Sorry.
> 
> Or a function that returns an array...

Actually, I was forgetting that the array could be gotten from a pointer
to array:

	int (*ap)[42] = ...;

	ENDOF(ap++);  // Evaluates ap++

Anyway, fixed in v6.


Cheers,
Alex

-- 
<https://www.alejandro-colomar.es/>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/uipobgcwwyzsq5dtq3wf6haoae7zgwjfefokbwx5nx6wfx5uq2%40vgpl36ryhkel.

--744n7ojxglqyswg3
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iQIzBAABCgAdFiEES7Jt9u9GbmlWADAi64mZXMKQwqkFAmhxYzoACgkQ64mZXMKQ
wqkjfQ/7B1Jy0fUNlWDy/S4747BI6FB8QvtJDXSmUh+9JUnYeA3/UC+7bZqstMwk
GNhbO5oX4r84xDPdJIpjEtKv7qkA9VkBWVG13PS6irDPYfqXblRyzEV6U9bissR2
Qc+WUC7mmpZvUXCjQXyVTsw4SHsfot41d2A+45wpof5Nc3lZXgzQD4Z56iH9PV6Z
/iyu8MGKu+eiso+/DaPStdC7xXj3acrjZK2L+JUuVmq28TBJnRcl6cUsvZITFg69
rq/XCYTJGjMEa9tLrn51Q2/TNTV+okSrLJl+0txHm1vCsVZ9L+GJ8VTIMkhAZft6
m3nYday4EgSz7QXrXYvj/LcpVfwrMRosgiEfHY4zL/7V55sObXyhrukHIpyaUfxu
q9E2T9FertPMmgKdNSadfJSht+uoRR8evxf8Xtry13aUqi7E3tIGL8/tCymdZAPq
6nANf7I8A8m/FBAMVtyg0mZS233L0oRG4hhWcG+umzzH6wwX9fDdNpB4X0FQMRJG
32U3uJbXK6GKcKU+igB9QpTW1DZlqXIGpT3rfLMweKoXOtfyNzZs51g7DMzVoYWh
Gl2Y0AO/rvYjwKhQydwVxukWpdtqJ9j3wiegSl2EKQx+4nZH0z7eKiRvOaG1N0TO
wEFZe8rebmqPxSLrJX6mKcTvOfvU4+5y/tStHrgRZ2ONh5BiGsg=
=Ka9G
-----END PGP SIGNATURE-----

--744n7ojxglqyswg3--
