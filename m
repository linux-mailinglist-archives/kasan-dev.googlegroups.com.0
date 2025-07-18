Return-Path: <kasan-dev+bncBAABBPFX43BQMGQEB32IGFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 81F23B09903
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Jul 2025 02:56:30 +0200 (CEST)
Received: by mail-io1-xd37.google.com with SMTP id ca18e2360f4ac-879c1688420sf251230239f.0
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 17:56:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752800189; cv=pass;
        d=google.com; s=arc-20240605;
        b=AfQ2N2FKvnspu+1OpReBRuXGzD81Mm3RdV8gOo0I208OyY9N77OiZyT4eJtoXCMLff
         LG/ji/j8+B3eSJrE1SEb/l8VwamvZOaLyqd09LZuXT+SgPQmneObp3ATaslXYdYDtGlw
         Mi/ilRIK3RAi9W8pesWV/Qs6DnY4hsnwzsudp3NhQrU7Uat8aCIee06VmD2jcAfHfErH
         99YzTi/wG8aKaft31K3Ca5LMv5gf69z9lH85cNo4GI5KhxZEpRwE4ecXqiVeHFIfoJVK
         SoYHrBe0ftyoQJoLy2ZOsJlu7Mby0bwz49j2W7xXQO8FZ3MDcwYNTqvJEZrfIYisqA1e
         5dhQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=D5mAlcylcX5djys9CcARzrwS50MWsPMElBpPxZvK1s4=;
        fh=0NdjeQApFkeeSxT3rj4eiSZoFFtgL9m4Qix+TfABpRs=;
        b=WKXgRaBDSJ+wvFKdcI+aIjbTQePAVJvOWXyk8TBpKfMjKiolsb/w4NsvT6O4CKFPDk
         9EoMcUQzXfqdibG/Jhm7Ht795k0umDtG5nguzd8WT1xGPmwakE/e0Gx5CNemJ8KNBWPF
         HLS13lJSqhMqKQmELuXu3ktQdNH+UmrmpySNOHu6yZs9v6SLwGElFMe5T4iDXGxe/Cmy
         uAdAiZBZkdxDi8PyaUUXtu6Ibhv8XEs62bioxqu7KbFhZn7CPao8/QeV0vyvx/oHpuGw
         VTAIyNoKw4LOijXp0o34Z9gvXZyel+vrCNoG+OxrWgVCtaO6w1+gvDbiaL3I/hvEebmb
         kz3A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ZcIWXRcn;
       spf=pass (google.com: domain of alx@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752800189; x=1753404989; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=D5mAlcylcX5djys9CcARzrwS50MWsPMElBpPxZvK1s4=;
        b=GbJG2fYWUaFPi56qsKMaNRYdIefVZPVjjAOY8bB8I/i0ge8etID3khaj3WMWPMTmYT
         ZQh4loJB+EfANiIi7Ztm8mq+jczJxIP+hbZrU3CJg+I+219UIPxVuWLwkIjWvpl6WzEQ
         jXi1G7vMDJ5Z5IDfvaEUae39IJAk6ZXHoIUvzA5QjPlw0mE3zO1nR8EgG3IMtG66eqWX
         HGdzIBfUYPIGNIwURNXRcQouWVbReotIF3dZZ1I1u4LLu0D5oEbLa1fxNSE3cKj/imG+
         RXPFm8lfy8Op+z7kHdePm07aVs1gwTsI5LDksSAABCRe/rrdL7QWggQaZbzik9nGb1BJ
         YzHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752800189; x=1753404989;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=D5mAlcylcX5djys9CcARzrwS50MWsPMElBpPxZvK1s4=;
        b=s9pH6945n18v1VBFKh3nUMZSRTwOBeF0W7YbV8tHEJDrFt06VVX8zH3XrAG5nP16G0
         /0fsWnsUY+DWIhdkBaGQy+w7UVD/1iIu4UBqRxGSOWbeei5vHarHtXDRWlq089cNhJDM
         Vj9pKtF8VLM4sxlfh5p2B4AA3nbe7n3l5O5E935XqYOUSqMbNRGAm9XE6ewcOrLsaf9H
         5iIGX63DDyei6Jlx/LsXRtQ7H6YHRhhDlRysHznK64EpWRfCI/VxAtA8O4qpyyaVQLbq
         OeWmn4bwJN7R99u3VhFesqMshi1WkFSC6wbCapg9/+jZxrV/AXE++abUpfz+JVzqq6Gv
         EG2Q==
X-Forwarded-Encrypted: i=2; AJvYcCU3gNoQDEXDIu0mDoJhKYXFdyeOe46e9w5HtGfGCISXgTj+CWXnvp7akjPzoI7qlLimrqE/9Q==@lfdr.de
X-Gm-Message-State: AOJu0YwReFoUTKAgm9l+Sy4qIPcgFP8JxQtQ54gmNpNA/2VVqfz5OFb1
	iB5W28t+Rbys+eYD5RgNsZpj/nhuvPzojiYEvQqxiPmACydZpBjoTCUK
X-Google-Smtp-Source: AGHT+IFoKO+YH94apiT9enLn4qRGiBo1tb486xb5vDKtK6MCiFKA2gO58jaEOcE0x9nPR/AUXRlQ1Q==
X-Received: by 2002:a05:6e02:3047:b0:3e2:77d9:f8fc with SMTP id e9e14a558f8ab-3e28bdfb160mr56025845ab.10.1752800188841;
        Thu, 17 Jul 2025 17:56:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd3L2W8jXL6GXeuPq9sS3h2nYqYv50pWmUu/uUAxZgvPg==
Received: by 2002:a05:6e02:1a83:b0:3e2:5a85:8182 with SMTP id
 e9e14a558f8ab-3e2818750dbls10000315ab.0.-pod-prod-00-us-canary; Thu, 17 Jul
 2025 17:56:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXc5lHRtD7Z6T6VNd4dpOJq7bMbrPfDye8Be2KUU4j1GZDYcki82W0GnLb6QeD1fEDM23Dp/MmeDbs=@googlegroups.com
X-Received: by 2002:a05:6e02:380d:b0:3e1:25b6:2a9a with SMTP id e9e14a558f8ab-3e295a1c481mr19960085ab.6.1752800187602;
        Thu, 17 Jul 2025 17:56:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752800187; cv=none;
        d=google.com; s=arc-20240605;
        b=QoLu42OoH2y9FfxL/naQBnMIEJqWgChj/QGFrhV4YJuaNe2sRMuDIJ4NUUXXsw0qLL
         3viq/+mFVJJLTqNOv3AuYXPm+iwaC5bozUJw+PuysCD4EqCGnNxP2QCnM4U0T7aem81i
         /xjxke89UhE4M4X8XOHcxWGi/b2BnF3lwzoCK2bYtcLp9uuCanzd5cL39F4J5Q/KusNX
         Jo2kkbut3kOLbYBsgc7Alzi3oka0aBiTnhgns05zzl1mVNRKZBy4deYUQLHr8F1vEm7G
         fsGNRFjVAa7Jco8uK2FfJWWAMM8/YlX3xEFeqagtIFgPERx4IgJJSg9P8iAMoVkwbQHx
         v7yg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=IILpd21Q8TYRGD7EQ676jjJfPfW+3gwlEDD+U7WON4U=;
        fh=+hijkY4EbnFXO9rqlwhUFqvsDuDAlPj76UEgw2SxaRo=;
        b=TNjUZKXAxBmnpH3H5KkkfCd9ivdUHu6a4DnQG20I+2gVSD9r3dBO/XbuD2RcAfiOdT
         lxNd99slC1L1hWoBu98EkZa7ycenr7WCM0Xv9iIf1m7+GVWIxKQzkYO/pkemK5Jb3fb/
         h2Iva4ndzkZke5ngscdBQc0itMLALjuDC4H3EB4fvUEb9I9+aHOITcy6HQwP2/316yC/
         QsU4HHTYUBUmKw+CY0Gbb9xM0ihfnpiEE3UKEGlAUpWRdJ0wgyruOafLxh5c78nIROiy
         Vw/7L49f7/v9Duojj1sSzujkLSut5ehGnDYzsKlxAZGPQXFpIrnDIQwl/RRDT7WoBrLT
         WJvQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ZcIWXRcn;
       spf=pass (google.com: domain of alx@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3e2982e803asi156145ab.4.2025.07.17.17.56.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Jul 2025 17:56:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id C6E3843261;
	Fri, 18 Jul 2025 00:56:26 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 23233C4CEE3;
	Fri, 18 Jul 2025 00:56:21 +0000 (UTC)
Date: Fri, 18 Jul 2025 02:56:19 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kees Cook <kees@kernel.org>, 
	Linus Torvalds <torvalds@linux-foundation.org>
Cc: David Laight <david.laight.linux@gmail.com>, 
	Martin Uecker <ma.uecker@gmail.com>, linux-mm@kvack.org, linux-hardening@vger.kernel.org, 
	Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Rasmus Villemoes <linux@rasmusvillemoes.dk>, 
	Michal Hocko <mhocko@suse.com>, Al Viro <viro@zeniv.linux.org.uk>, Sam James <sam@gentoo.org>, 
	Andrew Pinski <pinskia@gmail.com>
Subject: Re: [RFC v5 6/7] sprintf: Add [v]sprintf_array()
Message-ID: <p2gl2w7gntydz4lpoyrazha2hqswwoggykdxo2un7us5wsc3lp@ij5my4epi3ot>
References: <cover.1751823326.git.alx@kernel.org>
 <cover.1752182685.git.alx@kernel.org>
 <04c1e026a67f1609167e834471d0f2fe977d9cb0.1752182685.git.alx@kernel.org>
 <CAHk-=wiNJQ6dVU8t7oM0sFpSqxyK8JZQXV5NGx7h+AE0PY4kag@mail.gmail.com>
 <28c8689c7976b4755c0b5c2937326b0a3627ebf6.camel@gmail.com>
 <20250711184541.68d770b9@pumpkin>
 <CAHk-=wjC0pAFfMBHKtCLOAcUvLs30PpjKoMfN9aP1-YwD0MZ5Q@mail.gmail.com>
 <202507142211.F1E0730A@keescook>
 <3o3ra7vjn44iey2dosunsm3wa4kagfeas2o4yzsl34girgn2eb@6rnktm2dmwul>
 <202507171644.7FB3379@keescook>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="k63pphsxoo2hl7dh"
Content-Disposition: inline
In-Reply-To: <202507171644.7FB3379@keescook>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ZcIWXRcn;       spf=pass
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


--k63pphsxoo2hl7dh
Content-Type: text/plain; protected-headers=v1; charset="UTF-8"
Content-Disposition: inline
From: Alejandro Colomar <alx@kernel.org>
To: Kees Cook <kees@kernel.org>, 
	Linus Torvalds <torvalds@linux-foundation.org>
Cc: David Laight <david.laight.linux@gmail.com>, 
	Martin Uecker <ma.uecker@gmail.com>, linux-mm@kvack.org, linux-hardening@vger.kernel.org, 
	Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
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
 <3o3ra7vjn44iey2dosunsm3wa4kagfeas2o4yzsl34girgn2eb@6rnktm2dmwul>
 <202507171644.7FB3379@keescook>
MIME-Version: 1.0
In-Reply-To: <202507171644.7FB3379@keescook>

Hi Kees,

On Thu, Jul 17, 2025 at 04:47:04PM -0700, Kees Cook wrote:
> On Tue, Jul 15, 2025 at 09:08:14AM +0200, Alejandro Colomar wrote:
> > Hi Kees,
> > 
> > On Mon, Jul 14, 2025 at 10:19:39PM -0700, Kees Cook wrote:
> > > On Fri, Jul 11, 2025 at 10:58:56AM -0700, Linus Torvalds wrote:
> > > >         struct seq_buf s;
> > > >         seq_buf_init(&s, buf, szie);
> > > 
> > > And because some folks didn't like this "declaration that requires a
> > > function call", we even added:
> > > 
> > > 	DECLARE_SEQ_BUF(s, 32);
> > > 
> > > to do it in 1 line. :P
> > > 
> > > I would love to see more string handling replaced with seq_buf.
> > 
> > The thing is, it's not as easy as the fixes I'm proposing, and
> > sprintf_end() solves a lot of UB in a minimal diff that you can dumbly
> > apply.
> 
> Note that I'm not arguing against your idea -- I just think it's not
> going to be likely to end up in Linux soon given Linus's objections.

It would be interesting to hear if Linus holds his objections on v6.

> My
> perspective is mainly one of pragmatic damage control: what *can* we do
> in Linux that would make things better? Currently, seq_buf is better
> than raw C strings...

TBH, I'm not fully convinced.  While it may look simpler at first
glance, I'm worried that it might bite in the details.  I default to not
trusting APIs that hide the complexity in hidden state.  On the other
hand, I agree that almost anything is safer than snprintf(3).

But one good thing of snprintf(3) is that it's simple, and thus
relatively obvious to see that it's wrong, so it's easy to fix (it's
easy to transition from snprintf(3) to sprintf_end()).  So, maybe
keeping it bogus until it's replaced by sprintf_end() is a better
approach than using seq_buf.  (Unless the current code is found
exploitable, but I assume not.)


Have a lovely night!
Alex

-- 
<https://www.alejandro-colomar.es/>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/p2gl2w7gntydz4lpoyrazha2hqswwoggykdxo2un7us5wsc3lp%40ij5my4epi3ot.

--k63pphsxoo2hl7dh
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iQIzBAABCgAdFiEES7Jt9u9GbmlWADAi64mZXMKQwqkFAmh5m60ACgkQ64mZXMKQ
wqkLwBAAhgrJrpnkhBACfYY0eDqJcZh5qz8L/7W6xPGCf46NZSmjG/xJiYD2Ystf
j2+6m1UM6ynUzTMKK0hUo2nMhmBqqd3mmgFpTgWO6iwOt+Am5C7+RuLtBhCNrAh+
kYBPjichLntIH4Di6kHYlGevuH2NCR5zh5ImDK/fbBl56V6p0YTJCFGKqqWeiKo6
UI/SXQgqL1leL6clVP18x0WTaPfslnoZ9SlbGT2FpVIkhs/fLzcfJm+sXDQTzGff
1ccwyUPLGSJoiAD8jlrAxPson+KND8FtjU582aK/JwX05VVZSPzcKJLHm3Vu36j0
ye+DL97kD00ebWjS+w2u9F2Xfl5mc1cNqGJUHhmaK2jJV1JTlus1HhWgQp9rNe/K
49FWUIhnfqG2rz1kFzpGyTJY0zEXRmctcmm35K+qiGKnFHpO3DikvtBbgTPlOO2/
+8ODvnlfr0ffTLHZ3Zh0x+vvKqCXm/OI7Wm9H3utA9X3GvSeDIYHfYjtTuJFyO8F
Hw82ItMzcbi9h2mOgUQtVliLtxskzOxt+1jN+QgUfcRRQbV4K21MTQ/HzBioIKk1
JUQZbyYIaXqS1RsJ308A4fuDA+XR5zah2Zn7WiIbVmnU7/xt72UQ3Jrq/jr3f0aW
pXJ8aI2ggPuQXwUaF1pN3yHwlAXdAVziskVxXFiOXPTp7WXtC/c=
=mSgQ
-----END PGP SIGNATURE-----

--k63pphsxoo2hl7dh--
