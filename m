Return-Path: <kasan-dev+bncBAABBZUNYDBQMGQEQEFUCQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 73A5EB00B6F
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 20:31:12 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-235eefe6a8fsf11018855ad.1
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 11:31:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752172263; cv=pass;
        d=google.com; s=arc-20240605;
        b=ck7UO3iDbQt4Gs2WThv+sC3TR/YntbzaC91azjZOV2JoOVDzkQKX4GiWiPb5IYnSeh
         pnSdRaxo1vzkzUAGMCfWidrgyrKyx7t0yz0zxDh6B5voUjW5J1Sq2SlDL4+DJQRSmrN4
         ujSISqNr8idSsIEcsD7yb6SHVEP3/c2PLjSs5DwHZ9xduka08ztysQL5VvrE2qcN31d7
         RR0wM3GsOmXWonn0lc+UTHzGCbBW5Z8jpAmXB+Etuq2h3+dqxq5FmTp8xFLV0NtTsXag
         tSdIp54OAnyYGp1U0N7J35UuHgN8/UuKgmW6DdVzLthB8hxzBnuv/pWoxclzKPJAbMlK
         T4tg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=L7reXMGsOfOgoamXhdyeqV0Mc4yvG2ZgIUI1qKUqrno=;
        fh=NVYL8VOmZ5CggeiLuqVTLwN/3L7WZQ0KSkfd5oHSEi0=;
        b=b6ESBQ+wUp8NzLpniVLyBowwjV0vXsuTlaBijxzco67M1UYKuTR2Js3HRZ/S5Sur5J
         3C14LM6q0SgrQpq1sjilED+b/QZA0yG7dMvJ7LEkxF/xkz+RJWwwdAecoAFQ2cftDt5G
         F6b6gH8ZxSNigqLypTaonvJt52YM/qG4fxBHtFNIgXr6lcqchV2iv5lGV9Z4sqhZJwkn
         9vqt3S2JmruSPMNV/7NTSpH7+JHrlrH/+YEx10DdB4Xjw4yXBzRixoseltHauEdh6v85
         95n6GQaQvsHz+f6oEBpqR4u98G/6IQsNKJPzDZdO+70cRTzfRhn9iYVi2+75V/LcNp/V
         3Svg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=pMXbP2GH;
       spf=pass (google.com: domain of alx@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752172263; x=1752777063; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=L7reXMGsOfOgoamXhdyeqV0Mc4yvG2ZgIUI1qKUqrno=;
        b=S0m8Kva5s1fuw3l/3Ouhww7JQD5HZqPd8+VJvS/sJoTyfD48dVlBMI4Sf6cP1lk11c
         2UCNBdDQolODWUGpHPEJpuWMb1b2dhdkz4REueZ+VuQoMMvNVVsDix3hNyysyGAbGkp3
         x/q3FAJz+IfziHiHb8+gKYw5mq+ST4yehQZPZCMfMeZETIcg3ujoDYPk3StD6yHb8Kl9
         +nxO4z1yy3lgP45hmFnDfB5nzdm8cCSAhkZcnfMPnqYqUqqdqXG7Ty7TuFj/1YFZNoit
         ZEEHAQ8dTqVP7/OdmzdTlNBx0QRYo6wi2akQ/OS4DGso6iYX/GKMF5fKdrlaxHNb5Tc6
         taTQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752172263; x=1752777063;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=L7reXMGsOfOgoamXhdyeqV0Mc4yvG2ZgIUI1qKUqrno=;
        b=L1v14D+GG5+IvDafOi4Wwc66ZJmuob2JG8LOzW4jDXDWPoBypIvNXqUAAHSuIsy8Hy
         Myyh27Z3BAMSeQqvpVwFdeIDcUDFqLm7J//BuWR0NW3ZjMhfcAsmmAA0eRO5j9bbyMtB
         65gzR1AcCeZO2euHn2ZKDgvm4Swlcdd2rCV/0o1O7z51I9qytK3xYGJNMKVk9BdmwXH5
         8GhJ5Sxgo8UL2Yhl3iiTDr0ZZCYn12L5FworhBytWhlUyHeIYsNTk+VM44m5TZYzWAyJ
         769hq+cXOFD0JZNT41Jcm1VI/dH+t2wwbLHkXsuS83yaHWMfoF/mn/ruTeIdZdXQjnKX
         5yrg==
X-Forwarded-Encrypted: i=2; AJvYcCX4d9niF7D74yWwojp3tUFzyArq57bQT98NFM9yFRSR+vtFj67K70WaircTcOQ/YzfmybTMcA==@lfdr.de
X-Gm-Message-State: AOJu0YyRBB1ezqZ4dlXud6IEC0ELxnRPMTcbEShUNCWKOJLTnO7oEzUE
	rFsY9fqvCAU3sc/897pqFSeFy9QEc6U1dzJhgZtL6ZDg/k4BkOdRVpXW
X-Google-Smtp-Source: AGHT+IEwgCkUwoitAd1bkrpwt9uLsRhThn829nhohL7J+CYdFLvF7GRbNGziDBKG2NclIAVF6K4EjQ==
X-Received: by 2002:a17:902:e54f:b0:234:c65f:6c0c with SMTP id d9443c01a7336-23dede45f81mr3774745ad.15.1752172262351;
        Thu, 10 Jul 2025 11:31:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdd1Ilbi7mI00Llb1FwxvXDa/YQSL6QcwaDs56tkg7tJw==
Received: by 2002:a17:903:2055:b0:234:9fce:56ab with SMTP id
 d9443c01a7336-23de2dfc22dls7431915ad.1.-pod-prod-04-us; Thu, 10 Jul 2025
 11:31:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVaBLe7l7sJjB4FfhdR56Xk02plL+3URgG1btBv7Wx1rAXKiUJ5K0K9fBTLqlKNPn0/vPThM6Gxq2w=@googlegroups.com
X-Received: by 2002:a17:903:90e:b0:234:d7c5:a0f6 with SMTP id d9443c01a7336-23dede860c0mr3152025ad.31.1752172260671;
        Thu, 10 Jul 2025 11:31:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752172260; cv=none;
        d=google.com; s=arc-20240605;
        b=dR/wBcoP0pDwci0ssrSwQszltYCtNpAKNBeNFlCTavfGif0ws+m4Un3lxhypZZUPbc
         nGhQ1aWqeWWulLkfhyIJHdIpZAidZ/v1kBXpm61HndHi7KirN6Cgk5OTeu9zUcDChLdP
         4u0bqZ2TAKqbUK+O8d7dbuywT9uc0XWdIx68a2212FKwhKjAkofqaDUCQbHtzLkR0dYa
         VXr1jelaf9R6o3VNlPTRRwssrpZD2NVgdapUD9TrXW0vqH2OpkbvKuCZv6nASsKblYN4
         AkPUKaGZhmKsmlxz8JrIhBtksLvEKbD7KQyKH+nliXYZNNUwMIUxQpUpAhzNxC3ZTJD0
         3NgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=lyRdOARNiPxKcJ9Sgw+OlpMDBnmziLhWvxyx39eyrL0=;
        fh=27HATg/3q9XP1Ib0lz1m3MmiSlFXVfpHfl9a0h/+uVM=;
        b=TY45R4396ImyPzqPzBgYVxESCk7S4BmWce5SFvfoah8nbm9Za3aAXN0Q3+xvO5wOMS
         xZtZxkNJznutCSxke0LSEIgRpRoAZdJuf85fYeht3lLZH/uPhq3Hbq4SwzLur57TIEKM
         +QKum3qdN0s1Fe5m9J0clGCE+A/Xsc/0XvUWgwSij0wPwo8yAv4c7iP/3o8PpPhZxgTQ
         GcgMl8/F25JX7Ka3lbx2CAGLbajuj5PwxsdMkrI4r7mCxlSiSTkhb+cz8X5IDX6nRC3w
         oWWaNllhXzfax+JdX2l4zQjlwm32pv4ikegp60q8Cpd1y0ewqYL5EK03wQVcexhhec6B
         Vb5g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=pMXbP2GH;
       spf=pass (google.com: domain of alx@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-23de43411desi908565ad.11.2025.07.10.11.31.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Jul 2025 11:31:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id B337F5C6CCA;
	Thu, 10 Jul 2025 18:30:59 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6C7FEC4CEE3;
	Thu, 10 Jul 2025 18:30:55 +0000 (UTC)
Date: Thu, 10 Jul 2025 20:30:52 +0200
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
Message-ID: <svune35mcrnaiuoz4xtzegnghojmphxulpb2jdgczy3tcqaijb@dskdebhbhtrq>
References: <cover.1751823326.git.alx@kernel.org>
 <cover.1752113247.git.alx@kernel.org>
 <0314948eb22524d8938fab645052840eb0c20cfa.1752113247.git.alx@kernel.org>
 <CAHk-=wiYistgF+BBeHY_Q58-7-MZLHsvtKybrwtiF97w+aU-UQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="fodiyed7jhvlrxi3"
Content-Disposition: inline
In-Reply-To: <CAHk-=wiYistgF+BBeHY_Q58-7-MZLHsvtKybrwtiF97w+aU-UQ@mail.gmail.com>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=pMXbP2GH;       spf=pass
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


--fodiyed7jhvlrxi3
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
MIME-Version: 1.0
In-Reply-To: <CAHk-=wiYistgF+BBeHY_Q58-7-MZLHsvtKybrwtiF97w+aU-UQ@mail.gmail.com>

Hi Linus,

On Thu, Jul 10, 2025 at 08:52:13AM -0700, Linus Torvalds wrote:
> On Wed, 9 Jul 2025 at 19:49, Alejandro Colomar <alx@kernel.org> wrote:
> >
> > +#define SPRINTF_END(a, fmt, ...)  sprintf_end(a, ENDOF(a), fmt, ##__VA_ARGS__)
> > +#define VSPRINTF_END(a, fmt, ap)  vsprintf_end(a, ENDOF(a), fmt, ap)
> 
> So I like vsprintf_end() more as a name ("like more" not being "I love
> it", but at least it makes me think it's a bit more self-explanatory).

:-)

> But I don't love screaming macros. They historically scream because
> they are unsafe, but they shouldn't be unsafe in the first place.
> 
> And I don't think those [V]SPRINTF_END() and ENDOF() macros are unsafe
> - they use our ARRAY_SIZE() macro which does not evaluate the
> argument, only the type, and is safe to use.

Yup, it's safe to use.

> So honestly, this interface looks easy to use, but the screaming must stop.
> 
> And none of this has *anything* to do with "end" in this form anyway.

That same thing happened through my head while doing it, but I didn't
think of a better name.

In shadow, we have many interfaces for which we have an uppercase macro
version of many functions that gets array sizes and other extra safety
measures where we can.  (So there, the uppercase versions are indeed
extra safety, instead of the historical "there be dragons".  I use the
uppercase to mean "this does some magic to be safer".)

> IOW, why isn't this just
> 
>   #define sprintf_array(a,...) snprintf(a, ARRAY_SIZE(a), __VA_ARGS__)

Agree.  This is a better name for the kernel.

> which is simpler and more direct, doesn't use the "end" version that
> is pointless (it's _literally_ about the size of the array, so
> 'snprintf' is the right thing to use),

I disagree with snprintf(3), but not because of the input, but rather
because of the output.  I think an API similar to strscpy() would be
better, so it can return an error code for truncation.  In fact, up to
v2, I had a stprintf() (T for truncation) that did exactly that.
However, I found out I could do the same with sprintf_end(), which would
mean one less function to grok, which is why I dropped that part.

I'll use your suggested name, as I like it.  Expect v5 in a few minutes.

> doesn't scream, and has a
> rather self-explanatory name.
> 
> Naming matters.

+1


Have a lovely day!
Alex

> 
>                 Linus

-- 
<https://www.alejandro-colomar.es/>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/svune35mcrnaiuoz4xtzegnghojmphxulpb2jdgczy3tcqaijb%40dskdebhbhtrq.

--fodiyed7jhvlrxi3
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iQIzBAABCgAdFiEES7Jt9u9GbmlWADAi64mZXMKQwqkFAmhwBtYACgkQ64mZXMKQ
wqmOQA//bIEhEXLVgwS7mz/jBLQAGT4v53a5yhA1vSbBvckl7+P/z4tYOhS7drGu
KipZBsVxwdBQhN097m1zOT1T1T9q4vbqFOVX1uNVL7Q2R/0WyYC5APIKDHO1ijNF
uXc0HmMSM7Lm0CrY0nvPsI6ZGVagYdXm7QuQ9+GfBc2NAoiJU9fGRPBOjzllradR
3ALXe1Y5c2lgE4sEPPHmAAQNK7LGIX17yx/+YlMDtbZ9/F8fYQrIyW6nkWLgoid9
BmaQ1be4FK7NNbemif5QzHXxaLiwe3OgJrEsgEEAB7cmAvSc+bTloPpFv7UErAsq
BRAv7ivc/Saq5S7779xS5e4GDq8MjdCG2qSMvMnUtfAuhNB90zarK5cXAdCPKvAB
oD+7JptOjM1LHBvjK+Y7ZUIZ1JzP2/4NFtam9ioZUE+Drb5iLSGdwTYjOHzfF+Pi
FLmGbNNQzBMl1b8kjXnOxvmMfYeYM39/eNWUxYXxrhfZGIiRnIdh3ezJreD8t5Rp
AvqHuTbMKRbZmExHJ5sQFJ+MYH1/dOwkgpXvmhFnO78EgLJQSbW05CdDnGvlCNpj
NvcOhy5N+fVmC64ytcS/ALIWJk6XG/Tadns1r2Dn44oDlm1po+tt5k5nT81+cL9t
8gyc+6tp4He6Q4/zznnOCaQytRCja4eJcji3hvW3q2loFPWpzTw=
=kDfd
-----END PGP SIGNATURE-----

--fodiyed7jhvlrxi3--
