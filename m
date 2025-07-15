Return-Path: <kasan-dev+bncBAABBZ7427BQMGQEYRZMHJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D922B05269
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Jul 2025 09:08:25 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-3e055be2288sf53683265ab.3
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Jul 2025 00:08:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752563304; cv=pass;
        d=google.com; s=arc-20240605;
        b=lw4eb3iZ9G6NvqdQMct+b86ZvQJIKoYJWGavkOMm0OrUtKQXPM4eoGp0JtmnEGuVYV
         X1Pf45E8GdOZpw3OeKQVE4QumG5WH/DQMk7rYjd7qX/onEyRClmdku+R2B5LTrfZrrG7
         9cAxdgLL6SbJT6wulf4al4hmTXUvPzyRxkcOku/JAisU+RBUNFDvuNq3kKRKOfuayAMt
         dmZi1GVcTN/IcUrQ74f9h6BjKUWFBpT737xzUFQtOYTIyQxhlas9/zFihrqvshXLeZHt
         EtMEXE9Swq9xxgrEDkx0rQnwfZ0EjMPdyMCZjnq7Wj7B2Fi0maLt20A44CqTg6vkRRIP
         /kqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=1nRg/9c6y+F4w+BQ+TqWvahZWyBQkR9bxD0rGv1LzPI=;
        fh=KAK+EYu0/wh8r3TtkggOMtJ/HrZlnLyok58jQH2sXNM=;
        b=C7KBPKYtJe3za7swZ0koVetYiVwQAsUg8Y6vhX+1iSmDMjwYK+rXaPSlGphSrjesoC
         lmQaXJdqfxphE8e2IntTFp+M+v8z3Q+/E1zDmAjrLshBqJnioz47UFSC1XAn05WqxuIe
         fBEvOjV2LUGfLMfVVg7EUeRHLzVVkvYttIKpW1vk5gowy5ReIhdZBmiiKK9nZ6lk3/9R
         NbkuLTyfEJD2tYwbcPegRKqtYOKDK64ewjj8LqyKaOvQeR3CegrDx8gmQGtuT8hOLFpm
         IFRczQ8xf6yIUT/sPktelci0BrYYwTC7dW75OqDSL4M2iQ4xe5xjLS3djifCdG1Yd/bm
         twsg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=TP0IAAkR;
       spf=pass (google.com: domain of alx@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752563304; x=1753168104; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=1nRg/9c6y+F4w+BQ+TqWvahZWyBQkR9bxD0rGv1LzPI=;
        b=g+gbQEQ2scq4mQcSwxts6kFEI2j6z+xZrlMXtda8RImQPnvnnp8e8j/camf2NTCYH2
         8rHIuBWYKPyywXYWzpfxqQFMGGa0+TxvG8tzogbF25Qtk6mlmnVUChhLFXLDpXjE/prg
         IZmGDBY0ec6oPV7iYszmMKrBgnYP87zY0DxwyOAvQGydCQRxJos5W0Ybt3l2tQR3vdZZ
         nILLYNACkISFLTVy74+MaTjyVpeEzhayxxPLWHYHMlxgaiQ66u+flf9XsLnRFHO3AUcy
         bNsLiqV2BY93oxQdRJNjlyaNlYhO6YSQHhSi4uBgxCsOHFztzdEtbDrEJrwVTqfEUCwc
         cvEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752563304; x=1753168104;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1nRg/9c6y+F4w+BQ+TqWvahZWyBQkR9bxD0rGv1LzPI=;
        b=Gi1NB40LiG0BdZXLguMIVuISuiP05tjaqi+ejl4v4rkcQhYghin1fNRu5nCaGir00T
         PBMxb3p069GuN80DgjIDvC5lEV7YjYXxsAWLxRZO4WA4pb2yJsIcSc1T0lo1hSm74kuJ
         9c3xCpHO9a+HiIwVRKdrpJFvOJjM5YGd086IM1zzZ6vXy9xRaiBkAaWZiFmxGFCvxAKL
         oyhG0PCo2CBWLC0icRH0dfNmjLkd87nNKA6HxHRD9J598jZHb/8iOIAFcLrGwIbffi56
         ATyO9fyxF2WQRuIA5naZYYYiahstaMenX52Pyzpb+zem6bBFfT+D7IrolcXMwa7KP6JB
         scKw==
X-Forwarded-Encrypted: i=2; AJvYcCV3UlqUozYwfilgFp7436C2K/O8earwppq42VkGh0ZkYSzLn/mu17NqtG+sOj6giubp5fWX/w==@lfdr.de
X-Gm-Message-State: AOJu0YzN4za/gCG7DX8ziCs9vmW3XTJ8TRvsDZxPHrCy9KCv1N2iGyqJ
	QP4aIRxHtMIt0NvhM07HY6okyppCpF1SBcELn+H4834SGBsBk4vHPdCA
X-Google-Smtp-Source: AGHT+IF4/BLUh5TaL67gdFvQMs7FU1Jsl5EyYx1SPMgyL6Fb7fwzhNG7muZHQMn2+JS2AKCQ8/KwEA==
X-Received: by 2002:a92:ca4f:0:b0:3dd:f4d5:1c1a with SMTP id e9e14a558f8ab-3e25429f85emr147293955ab.17.1752563303912;
        Tue, 15 Jul 2025 00:08:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe5Zj934j3W4AGliuspaESD5OrpYDVv6aJ41uK/Ydvg+w==
Received: by 2002:a05:6e02:481b:b0:3dd:bf83:da96 with SMTP id
 e9e14a558f8ab-3e24411b6b2ls39816525ab.2.-pod-prod-09-us; Tue, 15 Jul 2025
 00:08:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUQibxqJ64bHLqSToKBqCsdt45CkiwE7NPgtSZ8nVLJEvM4KGfJoTaIhvf86MmATdsQTbeqjFYMyhw=@googlegroups.com
X-Received: by 2002:a05:6602:26c5:b0:861:7237:9021 with SMTP id ca18e2360f4ac-879787d4d9emr1652844139f.3.1752563302961;
        Tue, 15 Jul 2025 00:08:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752563302; cv=none;
        d=google.com; s=arc-20240605;
        b=aC+5Bzu8YFGlvWyWt49ziiAW62+1eyqOCjy5aFjb/mJP4wXSPLbWWfTtkTN1CW9Pt3
         NfQ1qxGB/4ueiDzch+9RJWt39V9jcqhVvbj2LxQ9ZkyekUfeM+D2RxNBL0EpEix/PtZx
         /596MOjujuJADKNyGWSiieOoIqDT6sRblt+IAQTb+fhPSyvEGFRRIeAn2KOYjTJhNRdB
         YrcsQa4D5Y7bOlKnjtm/tiRTO93uZkhgRgTjshaRb2f7xyk/halX3a2vhn8Y8JqH3naS
         oiGcEsxe4s1Gv/vPUZQMIiqzeZmYybQKv97qB5gcvt/3rV/aD8M45cBrEcaT4Q/FbJDC
         APug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=wgOy1FmSDbs+GUCR+IA9ljOb//Y1Ab7h6QXhOcw1yfU=;
        fh=cmp4Fc4FmjixHz6c78+txVwv/pt5TTtyGPnBpLg+W2Y=;
        b=YnL+MSWtvmJ3kaQg+OP02Cxvw1qzzdTZsA+TaSrpIt6R71ic5uHXgezO2PDZhAmNed
         7PHu5Qc8JaLv9OqISQ8NtglHtOZUg2sHiazioVe2CMDx3aYeZfHLP99a86l7ujzaCcdR
         eK234df1Ghc3ziyE4YbZUWRLfG3vy4hicGja7VNMBebB5dbwSLHLlRbMldkVum6kzbjg
         ZGCFbbFT5hFwj5LWmXKwQejnxaDLNjnCRXDiv4NU0au6WqjaTvbhZvQZ0lA7JeErcuME
         DfyX+k7P5c43xca3BNqoxWdclU2+nbusabUFffO3Cm8pQPvXhBBeVKDRWk9z6x0plzZx
         OGfQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=TP0IAAkR;
       spf=pass (google.com: domain of alx@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-505562d346dsi410245173.0.2025.07.15.00.08.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 15 Jul 2025 00:08:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 068BB436A4;
	Tue, 15 Jul 2025 07:08:22 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D79EBC4CEE3;
	Tue, 15 Jul 2025 07:08:16 +0000 (UTC)
Date: Tue, 15 Jul 2025 09:08:14 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kees Cook <kees@kernel.org>
Cc: Linus Torvalds <torvalds@linux-foundation.org>, 
	David Laight <david.laight.linux@gmail.com>, Martin Uecker <ma.uecker@gmail.com>, linux-mm@kvack.org, 
	linux-hardening@vger.kernel.org, Christopher Bazley <chris.bazley.wg14@gmail.com>, 
	shadow <~hallyn/shadow@lists.sr.ht>, linux-kernel@vger.kernel.org, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Rasmus Villemoes <linux@rasmusvillemoes.dk>, 
	Michal Hocko <mhocko@suse.com>, Al Viro <viro@zeniv.linux.org.uk>, Sam James <sam@gentoo.org>, 
	Andrew Pinski <pinskia@gmail.com>
Subject: Re: [RFC v5 6/7] sprintf: Add [v]sprintf_array()
Message-ID: <3o3ra7vjn44iey2dosunsm3wa4kagfeas2o4yzsl34girgn2eb@6rnktm2dmwul>
References: <cover.1751823326.git.alx@kernel.org>
 <cover.1752182685.git.alx@kernel.org>
 <04c1e026a67f1609167e834471d0f2fe977d9cb0.1752182685.git.alx@kernel.org>
 <CAHk-=wiNJQ6dVU8t7oM0sFpSqxyK8JZQXV5NGx7h+AE0PY4kag@mail.gmail.com>
 <28c8689c7976b4755c0b5c2937326b0a3627ebf6.camel@gmail.com>
 <20250711184541.68d770b9@pumpkin>
 <CAHk-=wjC0pAFfMBHKtCLOAcUvLs30PpjKoMfN9aP1-YwD0MZ5Q@mail.gmail.com>
 <202507142211.F1E0730A@keescook>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="42cidsdllbjeiguv"
Content-Disposition: inline
In-Reply-To: <202507142211.F1E0730A@keescook>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=TP0IAAkR;       spf=pass
 (google.com: domain of alx@kernel.org designates 172.234.252.31 as permitted
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


--42cidsdllbjeiguv
Content-Type: text/plain; protected-headers=v1; charset="UTF-8"
Content-Disposition: inline
From: Alejandro Colomar <alx@kernel.org>
To: Kees Cook <kees@kernel.org>
Cc: Linus Torvalds <torvalds@linux-foundation.org>, 
	David Laight <david.laight.linux@gmail.com>, Martin Uecker <ma.uecker@gmail.com>, linux-mm@kvack.org, 
	linux-hardening@vger.kernel.org, Christopher Bazley <chris.bazley.wg14@gmail.com>, 
	shadow <~hallyn/shadow@lists.sr.ht>, linux-kernel@vger.kernel.org, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Rasmus Villemoes <linux@rasmusvillemoes.dk>, 
	Michal Hocko <mhocko@suse.com>, Al Viro <viro@zeniv.linux.org.uk>, Sam James <sam@gentoo.org>, 
	Andrew Pinski <pinskia@gmail.com>
Subject: Re: [RFC v5 6/7] sprintf: Add [v]sprintf_array()
References: <cover.1751823326.git.alx@kernel.org>
 <cover.1752182685.git.alx@kernel.org>
 <04c1e026a67f1609167e834471d0f2fe977d9cb0.1752182685.git.alx@kernel.org>
 <CAHk-=wiNJQ6dVU8t7oM0sFpSqxyK8JZQXV5NGx7h+AE0PY4kag@mail.gmail.com>
 <28c8689c7976b4755c0b5c2937326b0a3627ebf6.camel@gmail.com>
 <20250711184541.68d770b9@pumpkin>
 <CAHk-=wjC0pAFfMBHKtCLOAcUvLs30PpjKoMfN9aP1-YwD0MZ5Q@mail.gmail.com>
 <202507142211.F1E0730A@keescook>
MIME-Version: 1.0
In-Reply-To: <202507142211.F1E0730A@keescook>

Hi Kees,

On Mon, Jul 14, 2025 at 10:19:39PM -0700, Kees Cook wrote:
> On Fri, Jul 11, 2025 at 10:58:56AM -0700, Linus Torvalds wrote:
> >         struct seq_buf s;
> >         seq_buf_init(&s, buf, szie);
> 
> And because some folks didn't like this "declaration that requires a
> function call", we even added:
> 
> 	DECLARE_SEQ_BUF(s, 32);
> 
> to do it in 1 line. :P
> 
> I would love to see more string handling replaced with seq_buf.

The thing is, it's not as easy as the fixes I'm proposing, and
sprintf_end() solves a lot of UB in a minimal diff that you can dumbly
apply.

And transitioning from sprintf_end() to seq_buf will still be a
possibility --probably even easier, because the code is simpler than
with s[c]nprintf()--.

Another thing, and this is my opinion, is that I'm not fond of APIs that
keep an internal state.  With sprintf_end(), the state is minimal and
external: the state is the 'p' pointer to where you're going to write.
That way, the programmer knows exactly where the writes occur, and can
reason about it without having to read the implementation and keep a
model of the state in its head.  With a struct-based approach, you hide
the state inside the structure, which means it's not so easy to reason
about how an action will affect the string, at first glance; you need an
expert in the API to know how to use it.

With sprintf_end(), either one is stupid/careless enough to get the
parameters wrong, or the function necessarily works well, *and is simple
to fully understand*.  And considering that we have ENDOF(), it's hard
to understand how one could get it wrong:

	p = buf;
	e = ENDOF(buf);
	p = sprintf_end(p, e, ...);
	p = sprintf_end(p, e, ...);
	p = sprintf_end(p, e, ...);
	p = sprintf_end(p, e, ...);

Admittedly, ENDOF() doesn't compile if buf is not an array, so in those
cases, there's a chance of a paranoic programmer slapping a -1 just in
case, but that doesn't hurt:

	p = buf;
	e = buf + size;  // Someone might accidentally -1 that?

I'm working on extending the _Countof() operator so that it can be
applied to array parameters to functions, so that it can be used to
count arrays that are not arrays:

	void
	f(size_t n, char buf[n])
	{
		p = buf;
		e = buf + _Countof(buf);  // _Countof(buf) will evaluate to n.
		...
	}

Which will significantly enhance the usability of sprintf_end().  I want
to implement this for GCC next year (there are a few things that need to
be improved first to be able to do that), and also propose it for
standardization.

For a similar comparison of stateful vs stateless functions, there are
strtok(3) and strsep(3), which apart from minor differences (strtok(3)
collapses adjacent delimiters) are more or less the same.  But I'd use
strsep(3) over strtok(3), even if just because strtok(3) keeps an
internal state, so I always need to be very careful of reading the
documentation to remind myself of what happens to the state after each
call.  strsep(3) is dead simple: you call it, and it updates the pointer
you passed; nothing is kept secretly from the programmer.


Have a lovely day!
Alex

-- 
<https://www.alejandro-colomar.es/>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3o3ra7vjn44iey2dosunsm3wa4kagfeas2o4yzsl34girgn2eb%406rnktm2dmwul.

--42cidsdllbjeiguv
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iQIzBAABCgAdFiEES7Jt9u9GbmlWADAi64mZXMKQwqkFAmh1/lcACgkQ64mZXMKQ
wqkuig//S3hiwlkmTsz7a0bec7iYCPTHlJQErIaH1hA0PDwadlm0Uld/f8mbbM7o
Ps84e7sweLABRiI8zlkgBCM4sK3SY+wyoKz7d9vasg5XiyIVVAPxE3PaArxdTYz5
0eEJpu96pwyMyMk5efylDBnL7q7C2orgiimax53nITbsbQs3gx5rrT1eAFjQ18fk
SWYjiO4LTE+vn/XWYSm/RJQpTRkss67jMrxNTg534J8NG3WRAK4q4ytJPxd3cCrB
1EQs5McuvHSVYcRCqdSfW4BK4EF1gQwwfBGh6VEX/t+i7K4tufhSeaQUGU1x4xmx
ERW0AWe80VDMCyz1hmZkyEj/4r4nXn1hZ8Tjg/bvUK5WDICFKfaTGgd4EbQ4yyuY
+GGOGLpHF/LzIQfGsAMLhv6QCgRd29bT3EHlCSdqpQYYDcBvCY/yCzS19q9C/5r+
kZBJGn0g+hStrC1CjItE8yrviowVmopVLsx5d3cEnjdK1FqZX8OgfWjNdDR6d0dl
Ypk3D6e857x/WBd2p19r6k+Qda0Mw0KDLz/qZ0aoEjGoyBj2s86Ipi3aA54MqJyV
YV/c78fOIDQB4PC+AfsvQ9xYO8Ij264dGBnHJunjZGsL1pTwVSlOnjdVw6gVsr8p
bUsCwLZLs4q1EEFG4RELMcCvjXBoziYheUg2rvW5+lkV/ZPVryI=
=tD+S
-----END PGP SIGNATURE-----

--42cidsdllbjeiguv--
