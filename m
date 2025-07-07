Return-Path: <kasan-dev+bncBAABBQG4WDBQMGQE4N46HJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 0A2A0AFBC88
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jul 2025 22:29:55 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-311ef4fb5eesf3127078a91.1
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jul 2025 13:29:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751920193; cv=pass;
        d=google.com; s=arc-20240605;
        b=T/Cmp8gHBL+ylS5o5H2HlNBI0iwb9sRmLyRpTt6Im1VZ3DnoonFR1lYTUYqnbQKYQs
         ht+bLsZ+plUZ5d/NG+BUoXX7uPeRtWi0lppoaXa1hftsoOxL7aUblz9ssVCEXWx8MgxU
         3KS5b+OEWIJQobvOZhuT2vT5n+5h9ROZNiSof4hvaWSHzcMjNEi/ATHhxVyaJju/SGD4
         TcE53LAfheNPc3r40iSymNHtboIYxaUVeC9hPA5LcvXo9rWNCnRBPbFLDOQ5ityI1fYp
         XdD0eUJ2B0QDN0uotg2Pg0qHctU+aXsGC9kivS/ZhbiM7SoH0pydiomNUow7/HUFxaJc
         AgGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=6iY2O1+iCVH1JnicCbqSdxRHYqazlOg3BSfLrQdJZPA=;
        fh=kz2ZI6O4HrMKKRDLG3YF24ZEP1vtIvhFqtOEA7qPvPc=;
        b=Cvu85EeD+uc/DpVGiO51CCIZrTsQ9cDnZKIereXJeA5LP+hLg7cgS8KGQUmspwahRG
         xkwjk4AXfPLzM+iw9zPdXGacC1IQdE84sta3LV3gaBqB+nnyh3CSB9BRZHCnOr4NNLe1
         3lhhoamtLNkK6OHrNxYr8g7iw3Kl5ZogwathIg9+mAQyLZDjIeKYqQ1GR9lXUmencqv4
         abIu5JPQxi4Jt+k1qkVN5ykKbmfPdRPdN5Zmjl3GFhUkGE44Z7+QTtuQA4iXnvVCMHX2
         LeuK0o6ubk9rhtqZZ8s47OzHZnHsNJbQYEwhyNYCyuE8b6cuS2vimeoTvpB1OSCx2Aq7
         MFSg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=LoB2iX7G;
       spf=pass (google.com: domain of alx@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751920193; x=1752524993; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=6iY2O1+iCVH1JnicCbqSdxRHYqazlOg3BSfLrQdJZPA=;
        b=eZ2WGMZL0YombLvTvCKi0MnSCWJraXa23NIygt1YfVPKUuteANIh1+Zu+ZyxKOOC3F
         i04qFD/+A6CpaQTchqQ1Kfdya7SEUo8fDfUkbXedhZTEiccFknboyCxvo2yrqaK3kEUu
         6xA0GLxsp0YM0StLnhV+L+uZXfhgPro7o5/KTCVU6TfBNzyfwuclk79SqNFTYcRSr7I1
         3LNEtND50+YhBRU3++u4HGE2Baa8tZIiUeWU1mbkxufSntFTiNggvycLyoJjP///iyq5
         ZfL2LY0smBOxM7AdjEPXqyRd4YDI9Ztc+1l4FZigwsiU5eFx7i0/+5BNXLkaelzadMZ4
         3H9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751920193; x=1752524993;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6iY2O1+iCVH1JnicCbqSdxRHYqazlOg3BSfLrQdJZPA=;
        b=k2gGm/Ud6bFG8LIQy+SNw+0WTML4VRCzP37y8HDm8GUACI8apZblEitnJkp4JQrdBI
         exVdYYU7okqzsHOLom/Ph4Irsv6Q4FOp4IbBtFrb7rktzOkcK5X0V2y9oIlJN03uWm7J
         EeurDvEcYA/P95yllkHXL4hDanyTX+xCBcoVYfqotgT/NPUIVtx0FNVOfmFK7RQGdaxx
         CWytcCU6HneaBpUzeo6RAioR+2SO0ddCvcygzLQbpEWEKp41qhs1/7ctan96kh4t7BUw
         mMOAEOlXlCB2eMsloLp8JpKWl+wA69tNrsstd/kK9nGmGb7dyT46c1JGcfUihU080SZ1
         6bUg==
X-Forwarded-Encrypted: i=2; AJvYcCUjmpHLqxUuv8XhZWDdrCP5/DyjfObJOwBS3DIABuytJnNJpKDUOoDZ+bXracx/N9jl6Vf5wQ==@lfdr.de
X-Gm-Message-State: AOJu0YzOxER0eAmKHcujsmSASLUhqiupFHc+lQ7O7aQ2goZGGUHyqAQq
	hx9KNHCq9m8kH4UZWl0Y1eHpC3c7GtjKc4I+hWs8DfrNnF4nsaDSHcA0
X-Google-Smtp-Source: AGHT+IG+KZsM4tjRxxZPxG+jZ6FsGdKtTViXglYg7EAGJ9k5CIg9rGsIJXBnFN/xPMriSgjOaTUqmQ==
X-Received: by 2002:a17:90b:4acc:b0:315:9624:37db with SMTP id 98e67ed59e1d1-31c22920815mr61398a91.3.1751920192959;
        Mon, 07 Jul 2025 13:29:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeTxTmvGrHkxeFOQz4sSLNGzJwJQZGx6iUEcepVmcGTSA==
Received: by 2002:a17:90b:3d0c:b0:310:af10:d180 with SMTP id
 98e67ed59e1d1-31ab049234dls1728635a91.1.-pod-prod-00-us; Mon, 07 Jul 2025
 13:29:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVpl5mHpPDQnC19UIoATdPpJo6j441dbwSkpeJ5blT4T7Ncc2p0l7GNv/CI/HKJ9GlfWoHjAQmzo6o=@googlegroups.com
X-Received: by 2002:a17:90b:5350:b0:311:83d3:fd9c with SMTP id 98e67ed59e1d1-31c224f347dmr225712a91.0.1751920190727;
        Mon, 07 Jul 2025 13:29:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751920190; cv=none;
        d=google.com; s=arc-20240605;
        b=g4dBdT7cZoguLC2UMX/WGqTZIyzwYfQE+bpe4UA2lxHArIhIj/9m+euV9KulBZx5jh
         ymt5eG3j2noctohzy1PSnp3D1asFvbKhOpC3i0sLLHPYa4MDvHBPJTSVeYcSc337Tx0E
         xTUtkQ55SSrCQ6paeCpSiR7xb6E1EduX/nj95LZe1+fh+zb8/EZQK6cRUVKkJKEJpjXf
         Kd+Y3+CceLQHCKUw6xiLMslp/gsB+3xa5P1txJxUR2zBcgUa4Ogr+SPcV5unjosUsCfw
         32u8QdlQVi25PEIF5tG4TmXTJSKdYu/1WpumIUrMUczZekEigAAXbOeZfRg73DKNcbxa
         6IsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=E9XVJnkm9rNvuY7wlcSvsZbkTX8oHoDg8FF51VrLuO8=;
        fh=ZEmjEA+beua0ACHfvGG6b46BenHjaWFbMeK4riMguPk=;
        b=dBP7qJRutb8iHyNBB4dH0eDAOhtLf+TZHbhGDnYj0m1DI4gSEPeQLag6b51NWZYFI5
         hevtlQtL2obmGiXuNT3NCMgQwyRGY/UYwXHVA5em0Y2TiDF90j6gnxUj0ag4lL0y3kRC
         89V8b8YoRCUkCJM2oNCQSpoxg2HbbWBm8qvyoWRkZY1v/WmG0XWRGZmazhlVwN+vPrsG
         WOYK/MUgioIQnBMf2NPGb5/FTk1Rcc6BoD4ROMi4n7BZakQC02/pYLwQJJUyTO3ooE3h
         1ec6revoqlRGKRPR5RwArP/DE2/76E+QYVq5fPpexzjygmauGCO/s0AnDKje3dmO/2Bf
         /Taw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=LoB2iX7G;
       spf=pass (google.com: domain of alx@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-31c21e00224si9773a91.2.2025.07.07.13.29.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Jul 2025 13:29:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id CEA5C6111F;
	Mon,  7 Jul 2025 20:29:49 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 678F2C4CEE3;
	Mon,  7 Jul 2025 20:29:45 +0000 (UTC)
Date: Mon, 7 Jul 2025 22:29:40 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: linux-mm@kvack.org, linux-hardening@vger.kernel.org, 
	Kees Cook <kees@kernel.org>, Christopher Bazley <chris.bazley.wg14@gmail.com>, 
	shadow <~hallyn/shadow@lists.sr.ht>, linux-kernel@vger.kernel.org, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Sven Schnelle <svens@linux.ibm.com>, 
	Heiko Carstens <hca@linux.ibm.com>, Tvrtko Ursulin <tvrtko.ursulin@igalia.com>, 
	"Huang, Ying" <ying.huang@intel.com>, Lee Schermerhorn <lee.schermerhorn@hp.com>, 
	Christophe JAILLET <christophe.jaillet@wanadoo.fr>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, Chao Yu <chao.yu@oppo.com>
Subject: Re: [RFC v3 3/7] mm: Use seprintf() instead of less ergonomic APIs
Message-ID: <ugf4pu7qrojegz7arkcpa4cyde6hoyh73h66oc4f6ncc7jg23t@bklkbbotyzvp>
References: <cover.1751862634.git.alx@kernel.org>
 <033bf00f1fcf808245ae150346019aa7b997ea11.1751862634.git.alx@kernel.org>
 <CAHk-=wh9Pqz07ne9iSt1_v0c14rkOGvF9AbEkaq1KnFhQD1SSA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="hm3euuqedab7podc"
Content-Disposition: inline
In-Reply-To: <CAHk-=wh9Pqz07ne9iSt1_v0c14rkOGvF9AbEkaq1KnFhQD1SSA@mail.gmail.com>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=LoB2iX7G;       spf=pass
 (google.com: domain of alx@kernel.org designates 172.105.4.254 as permitted
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


--hm3euuqedab7podc
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
	Andrew Clayton <andrew@digital-domain.net>, Sven Schnelle <svens@linux.ibm.com>, 
	Heiko Carstens <hca@linux.ibm.com>, Tvrtko Ursulin <tvrtko.ursulin@igalia.com>, 
	"Huang, Ying" <ying.huang@intel.com>, Lee Schermerhorn <lee.schermerhorn@hp.com>, 
	Christophe JAILLET <christophe.jaillet@wanadoo.fr>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, Chao Yu <chao.yu@oppo.com>
Subject: Re: [RFC v3 3/7] mm: Use seprintf() instead of less ergonomic APIs
References: <cover.1751862634.git.alx@kernel.org>
 <033bf00f1fcf808245ae150346019aa7b997ea11.1751862634.git.alx@kernel.org>
 <CAHk-=wh9Pqz07ne9iSt1_v0c14rkOGvF9AbEkaq1KnFhQD1SSA@mail.gmail.com>
MIME-Version: 1.0
In-Reply-To: <CAHk-=wh9Pqz07ne9iSt1_v0c14rkOGvF9AbEkaq1KnFhQD1SSA@mail.gmail.com>

Hi Linus,

On Mon, Jul 07, 2025 at 12:17:11PM -0700, Linus Torvalds wrote:
> On Sun, 6 Jul 2025 at 22:06, Alejandro Colomar <alx@kernel.org> wrote:
> >
> > -       p += snprintf(p, ID_STR_LENGTH - (p - name), "%07u", s->size);
> > +       p = seprintf(p, e, "%07u", s->size);
> 
> I am *really* not a fan of introducing yet another random non-standard
> string function.

I am in the C Committee, and have proposed this API for standardization.
I have a feeling that the committee might be open to it.

> This 'seprintf' thing really seems to be a completely made-up thing.
> Let's not go there. It just adds more confusion - it may be a simpler
> interface, but it's another cogniitive load thing,

I understand the part of your concern that relates to
<https://xkcd.com/927/>.

However, I've shown how in mm/, I got rid of most snprintf() and
scnprintf() calls.  I could even get rid of the remaining snprintf()
ones; I didn't do it to avoid churn, but they're just 3, so I could do
it, as a way to remove all uses of snprintf(3).

I also got rid of all scnprintf() uses except for 2.  Not because those
two cannot be removed, but because the code was scary enough that I
didn't dare touch it.  I'd like someone to read it and confirm that it
can be replaced.

> and honestly, that
> "beginning and end" interface is not great.

Just look at the diffs.  It is great, in terms of writing less code.

In some cases, it makes sense to pass a size.  Those cases are when you
don't want to chain several calls.  That's the case of stprintf(), and
it's wrapper STPRINTF(), which calls ARRAY_SIZE() internally.

But most of the time you want to chain calls, and 'end' beats 'size'
there.

> I think we'd be better off with real "character buffer" interfaces,
> and they should be *named* that way, not be yet another "random
> character added to the printf family".

You might want to do that, but I doubt it's an easy change.  On the
other hand, this change is trivial, and can be done incrementally,
without needing to modify the buffer since its inception.

And you can come back later to wrap this in some API that does what you
want.  Nothing stops you from doing that.

But this fixes several cases of UB in a few files that I've looked at,
with minimal diffs.

> The whole "add a random character" thing is a disease. But at least
> with printf/fprintf/vprintf/vsnprintf/etc, it's a _standard_ disease,
> so people hopefully know about it.

seprint(2) was implemented in Plan9 many decades ago.  It's not
standard, because somehow Plan9 has been ignored by history, but the
name has a long history.

<https://plan9.io/magic/man2html/2/print>

Plus, I'm making seprintf() standard (if I can convince the committee).

Yesterday night, I presented the proposal to the committee, informally
(via email).  You can read a copy here:
<https://lore.kernel.org/linux-hardening/cover.1751747518.git.alx@kernel.org/T/#m9311035d60b4595db62273844d16671601e77a50>

I'll present it formally in a month, since I have a batch of proposals
for the committee in the works.


Have a lovely day!
Alex

> So I really *really* don't like things like seprintf(). It just makes me go WTF?
> 
> Interfaces that have worked for us are things like "seq_printf()", which
> 
>  (a) has sane naming, not "add random characters"
> 
>  (b) has real abstractions (in that case 'struct seq_file') rather
> than adding random extra arguments to the argument list.
> 
> and we do have something like that in 'struct seq_buf'.  I'm not
> convinced that's the optimal interface, but I think it's *better*.
> Because it does both encapsulate a proper "this is my buffer" type,
> and has a proper "this is a buffer operation" function name.
> 
> So I'd *much* rather people would try to convert their uses to things
> like that, than add random letter combinations.
> 
>              Linus

-- 
<https://www.alejandro-colomar.es/>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ugf4pu7qrojegz7arkcpa4cyde6hoyh73h66oc4f6ncc7jg23t%40bklkbbotyzvp.

--hm3euuqedab7podc
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iQIzBAABCgAdFiEES7Jt9u9GbmlWADAi64mZXMKQwqkFAmhsLi0ACgkQ64mZXMKQ
wqmzHhAAiWAsGEbvSPpIRKjHFLRmZ1qgrHgSd2MJ5KPyYritnzqRD0gE1mRApWtk
kfVZhvAa0ud09ds81/+KW/SAYw5VsHdJuyDpLxfNNaP0sKJRuTUgHPmjqBsj3N3F
4MtyXQ1P6YjydvSUQ200zKyXaPBsPTqJEz2M+gXxNgghYp07sEYcEEKKV1X1j6vK
atcQsESKA+/+V9kPiHFgGQsaX7/e/nvSVpao5gnZ8oIxsqDN/zPosSks7wxBptyJ
FSMMer6X3IUsh7innNWu4QSPXObRGS5BJol6Ev1d5IKvXTkmxipe4vXWO7OQ9Un4
LNBAqD8+SQWbqHFHjEH1VUqr9wzJNFnJrjGUsz+kwtV4dHtbATi/7peYZA7Ht0CA
arhageKLWRn2JUM5beeIug/CJHZ150+m/M1Dc0Ec6K9rxJUj10sP/t09WIljrJzF
4D8lBcrZVMjz+NkOWQNn55ZN9VU7r/6y57Dv090D0ysBmmE2fG7GzGbJJMYqEGrb
nXAFN1giVxeg2t/tlbzAGJ09EZkxinK0EHEzY/4bgT5gDw/tMMBqsX4qTp7qa9Va
JzUTGvdbS5I1Px04zRDJrOvNyx5vyFRj+ZROPop/tO3Jucf1BWE2sxBezKoCK1zl
3NiRecJc2x2mDZnh2mDRcMuEMkprSbFB/5KS56i0ayITLsqauSk=
=E6l+
-----END PGP SIGNATURE-----

--hm3euuqedab7podc--
