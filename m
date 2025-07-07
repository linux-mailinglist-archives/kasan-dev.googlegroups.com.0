Return-Path: <kasan-dev+bncBAABBDNOVXBQMGQEFPSDWLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id B7FABAFAAC4
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jul 2025 07:11:43 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id 41be03b00d2f7-b115fb801bcsf3736718a12.3
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Jul 2025 22:11:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751865102; cv=pass;
        d=google.com; s=arc-20240605;
        b=dNB7DPqZKkWmJMBL7DIWWWEo3Bp7KA4wRSH6qtnBJLi3MjuuJfcMeGbYGAV21/0Ep/
         uttQKsc+XWaGTtP+dpAF6F+d8EpL3d0WZavDeWFe2W4pNfTW5MafFohoWSMCpM6lzgn6
         5915PnTbtjGpc5LH9mYqHlrYoVZb0fqKo76ko5yp1SCLmG+vlJZh5C43J1DQBuccnL4o
         l9Pafuc1xM9om7QogKitW6GOVNlZtFIW4Sl0hky4xhzDS/IUgGTAIpdHd9UE+B6mesnh
         ZjJIvBfBreZ95dvo/+jmF/GjzRdKhNqRJMEwEIL7KwzXnQImWB0y2PUg+7cHqG9HCeeg
         GyLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=3cCat4Y58uJa22mqGAc6M9HuLlsy9DzecdfL00r3rnA=;
        fh=jj/1OXUV3nJAq0JHg3L3F11u3YyTw+xVKwoMhG2Cx5I=;
        b=UBdCLwihboE68AnA1+ffIiLSyyvv7045Nr38Uy7bxcF1RrU8QZ0luglT94vB5jzNZW
         VycU8EsrOLJIFRB+FN8EuQBKBvaCNRSqxvL0B1jUAVWSDdxMS4Twh/1m/+ntREOKR5ZA
         Cr9y5Zxr96BL5JFo6sNxExWiQm1kSkvhFM5lRcEF2IGHxo4vkt/7m+GYW8WowbdcLOuz
         cCP7wopUQZv9ncQnluYj647NPDAIOc6CbDxpKlMmOzTAn3ehilU1+wmllYXi8FE27I0I
         afv6Ct7jz64apC+V51aRkKmJWz4nvtqh86EYWpoXokIpQX8UKHCgl/2NbTZ2pNN9u9+E
         pZTQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mIhU3eks;
       spf=pass (google.com: domain of alx@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751865102; x=1752469902; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=3cCat4Y58uJa22mqGAc6M9HuLlsy9DzecdfL00r3rnA=;
        b=wsXw8aO5/yrUoiXSZYc0BUKEp545RefUlC00/WMeYkas0acX03+Q7rWFZoKcv+jm+6
         BMhP9ciNfqwfFo24E1gWi9ylpQ707XMZd7TC23ZcsUiB7Sqo0bmHBLGsLwyncdgwTrs4
         t81ExGDnkKYMBHOyp0zNLLyCh3ATCIuiv/pR7LE1XEJOwMBTh6/ezu+8j2b4N+xeBBrr
         ER89TQyHDCgEw7DHPtC5C0x1i3KDxSrwClMQYGfHYWLQRSVxLuyCM/JCLHXFfLaji1nA
         YjGlKji0CqNiIXHh55YUgRzVj4NnR9XB41JZi/YwihUfhuNcR+exXMRWFJZkF+hSorXr
         GLTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751865102; x=1752469902;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3cCat4Y58uJa22mqGAc6M9HuLlsy9DzecdfL00r3rnA=;
        b=cRBmHJ4pwTxyFMoTa2qGiiYE377WHMKjAOSAHykiBNXsXcUFDUdAzbiBlBgKCzsNXI
         vkR96JH0Ehckr8+CXrQPr9/+N1F4qAUIkpH2pC9cRjvquQxJXnu4ulgqCa/fssEhBGUF
         4lmBou88vDs4HxI3MCBZfIHE0GEFc6xrdJD5GFDZ2SEh4rAarkvDsWE1u2LXZr3fSd2t
         wWeiiI3d4gaqBCou1BhzDDOb2DKTrJ4cjT9y/9wdQq0eZ1f8IzutAMI4DQhdTYcyz7JB
         12538YkiZNrDTkqJqTNQ0eErxRFMh2WI2C5eaAYQ45Qi+589+EDopyq9WD1qjcZHYRlL
         gnhg==
X-Forwarded-Encrypted: i=2; AJvYcCVMt1aScDqMzfxEsPZjPPmCHym1UBdMgGrTYcnLSb6yd+3z3aFzozJtN1yFdLOLXLYcekpKXQ==@lfdr.de
X-Gm-Message-State: AOJu0YwOzLjODdvmtS2W6dXm7YFIlFzxWnhdPzs0Lm/5GxXeNaauvWuR
	osRaVd7bJ+JiY383Uv1QzF+OMA7Aftf+O7gEYmrYxk9Utf03usdwMz0Y
X-Google-Smtp-Source: AGHT+IHFCZA42mmF9rMoFbYzBMLJN9M0SWt+aEAakOtZzk6fRnvkWfQALqYI5QseMJv2hAPDZyYsug==
X-Received: by 2002:a17:90b:528a:b0:311:df4b:4b81 with SMTP id 98e67ed59e1d1-31aba8d2928mr8500841a91.25.1751865101904;
        Sun, 06 Jul 2025 22:11:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZewuSYBdt+daRq1lEzQ0+aSNieH5KyWddpsAUdOJexFzg==
Received: by 2002:a17:90b:2283:b0:31a:94dc:73e8 with SMTP id
 98e67ed59e1d1-31ab035ae59ls2248368a91.1.-pod-prod-03-us; Sun, 06 Jul 2025
 22:11:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVxTD0WvX770Qs6FdZEB9kTvS9rknyI0rDcFB/Ok7MH93Z1jc4YDYZj7XCRr9TWdUwZpmwfquwGMDE=@googlegroups.com
X-Received: by 2002:a17:90b:3fcc:b0:313:1e60:584d with SMTP id 98e67ed59e1d1-31aba8449dcmr12365425a91.11.1751865100735;
        Sun, 06 Jul 2025 22:11:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751865100; cv=none;
        d=google.com; s=arc-20240605;
        b=kAfEVxgDHoIfWsOxxfclg2bcEpUxZ9UB8K7ysKslWq4mIfHENTA4ycra9nfGMlAm6c
         tmsi1+YLme0AJU4G0Wyf4d3LTzRVY2FV5IGNItuFL6SZx5jPKfWlOZKD1W5uWtIGoqCu
         Fm/7EK/WYW12JvZlHxoEfrEfBJEeyiFrOViAdNfAoZIflrWTgQIRC2F0bYim5ipU+Vje
         qij2ObnWfCylkGKyLKB/ydYeCEnAn59FvRtiphF6p8oGIWt8ShvhGoL3eEcD6+O3SykA
         eQwpzTAkr2AkT9DF2DWKrQoHNSSSn3nQwC83VSbypyUbj5kZ/N1FAEJZQU2DLoXk5tyt
         ypog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=7jIJW515gzjzho8lEaiEGu7jRz5B3BP2+Rdmn/GpoT4=;
        fh=uiJxyLDnnDuYp+6fhppTcm8+kNBrxhADxzWEE6Bv3/4=;
        b=JvgzMrtMEQOAO5hkIbeGZY9b5P+AFNVmHorVmGoSdFV8EGtR+ccyDE6hFRW5tIipiR
         /7W1/tIUH27WCl9xXFK1dQ9B3LUUS1lR7Oa0seLbOF79n2TM9kADSNdp7Z3OEkE4F3Ui
         I2STDBwl687iotK+1DEpvJEzP4ICIWyTT5GncD/rk2a8ovk73I492VCTov0hRvcJ/lqv
         Hle03VSNOpkrrl6kt1Fd0z60RJf+QF/j+qLQI0dD8qAh5UwjCjlx7df7sNRactmQVNTw
         LwJgXxU7u+mEZGIOjxVBuSJqP57vFiHQtaeK2XI4YiFzWGWg4D6PM5FmY6dbJ3EAjD63
         JXyg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mIhU3eks;
       spf=pass (google.com: domain of alx@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-31a80814906si812141a91.1.2025.07.06.22.11.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 06 Jul 2025 22:11:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id C48D1A529B8;
	Mon,  7 Jul 2025 05:11:39 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7FFD5C4CEE3;
	Mon,  7 Jul 2025 05:11:38 +0000 (UTC)
Date: Mon, 7 Jul 2025 07:11:37 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org, linux-hardening@vger.kernel.org
Cc: Kees Cook <kees@kernel.org>, 
	Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>
Subject: Re: [RFC v3 0/7] Add and use seprintf() instead of less ergonomic
 APIs
Message-ID: <vg7cczocbx7okwrvgik6wysiduiw7aesntkqzlklrlkacyvz5u@psb3mh2pyiwz>
References: <cover.1751747518.git.alx@kernel.org>
 <cover.1751862634.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="mmmwfwiqbayszx3n"
Content-Disposition: inline
In-Reply-To: <cover.1751862634.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=mIhU3eks;       spf=pass
 (google.com: domain of alx@kernel.org designates 147.75.193.91 as permitted
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


--mmmwfwiqbayszx3n
Content-Type: text/plain; protected-headers=v1; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
From: Alejandro Colomar <alx@kernel.org>
To: linux-mm@kvack.org, linux-hardening@vger.kernel.org
Cc: Kees Cook <kees@kernel.org>, 
	Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>
Subject: Re: [RFC v3 0/7] Add and use seprintf() instead of less ergonomic
 APIs
References: <cover.1751747518.git.alx@kernel.org>
 <cover.1751862634.git.alx@kernel.org>
MIME-Version: 1.0
In-Reply-To: <cover.1751862634.git.alx@kernel.org>

On Mon, Jul 07, 2025 at 07:06:06AM +0200, Alejandro Colomar wrote:
> I've written an analysis of snprintf(3), why it's dangerous, and how
> these APIs address that, and will present it as a proposal for
> standardization of these APIs in ISO C2y.  I'll send that as a reply to
> this message in a moment, as I believe it will be interesting for
> linux-hardening@.

Hi,

Here is the proposal for ISO C2y (see below).  I'll also send it to the
C Committee for discussion.=20


Have a lovely night!
Alex

---
Name
	alx-0049r1 - add seprintf()

Principles
	-  Codify existing practice to address evident deficiencies.
	-  Enable secure programming

Category
	Standardize existing libc APIs

Author
	Alejandro Colomar <alx@kernel.org>

	Cc: Christopher Bazley <chris.bazley.wg14@gmail.com>

History
	<https://www.alejandro-colomar.es/src/alx/alx/wg14/alx-0049.git/>

	r0 (2025-07-06):
	-  Initial draft.

	r1 (2025-07-06):
	-  wfix.
	-  tfix.
	-  Expand on the off-by-one bugs.
	-  Note that ignoring truncation is not valid most of the time.

Rationale
	snprintf(3) is very difficult to chain for writing parts of a
	string in separate calls, such as in a loop.

	Let's start from the obvious sprintf(3) code (sprintf(3) will
	not prevent overflow, but let's take it as a baseline from which
	programmers start thinking):

		p =3D buf;
		for (...)
			p +=3D sprintf(p, ...);

	Then, programmers will start thinking about preventing buffer
	overflows.  Programmers sometimes will naively add some buffer
	size information and use snprintf(3):

		p =3D buf;
		size =3D countof(buf);
		for (...)
			p +=3D snprintf(p, size - (p - buf), ...);

		if (p >=3D buf + size)  // or worse, (p > buf + size - 1)
			goto fail;

	(Except for minor differences, this kind of code can be found
	 everywhere.  Here are a couple of examples:
	 <https://elixir.bootlin.com/linux/v6.14/source/mm/slub.c#L7231>
	 <https://elixir.bootlin.com/linux/v6.14/source/mm/mempolicy.c#L3369>.)

	This has several issues, starting with the difficulty of getting
	the second argument right.  Sometimes, programmers will be too
	confused, and slap a -1 there just to be safe.

		p =3D buf;
		size =3D countof(buf);
		for (...)
			p +=3D snprintf(p, size - (p - buf) - 1, ...);

		if (p >=3D buf + size -1)
			goto fail;

	(Except for minor differences, this kind of code can be found
	 everywhere.  Here are a couple of examples:
	 <https://elixir.bootlin.com/linux/v6.14/source/mm/kfence/kfence_test.c#L1=
13>
	 <https://elixir.bootlin.com/linux/v6.14/source/mm/kmsan/kmsan_test.c#L108=
>.)

	Programmers will sometimes hold a pointer to one past the last
	element in the array.  This is a wise choice, as that pointer is
	constant throughout the lifetime of the object.  Then,
	programmers might end up with something like this:

		p =3D buf;
		e =3D buf + countof(buf);
		for (...)
			p +=3D snprintf(p, e - p, ...);

		if (p >=3D end)
			goto fail;

	This is certainly much cleaner.  Now a programmer might focus on
	the fact that this can overflow the pointer.  An easy approach
	would be to make sure that the function never returns more than
	the remaining size.  That is, one could implement something like
	this scnprintf() --name chosen to match the Linux kernel API of
	the same name--.  For the sake of simplicity, let's ignore
	multiple evaluation of arguments.

		#define scnprintf(s, size, ...)                 \
		({                                              \
			int len_;                               \
			len_ =3D snprintf(s, size, __VA_ARGS__);  \
			if (len_ =3D=3D -1)                         \
				len_ =3D 0;                       \
			if (len_ >=3D size)                       \
				len_ =3D size - 1;                \
		                                                \
			len_;                                   \
		})

		p =3D buf;
		e =3D buf + countof(buf);
		for (...)
			p +=3D scnprintf(p, e - p, ...);

	(Except for minor differences, this kind of code can be found
	 everywhere.  Here's an example:
	 <https://elixir.bootlin.com/linux/v6.14/source/mm/kfence/kfence_test.c#L1=
31>.)

	Now the programmer got rid of pointer overflow.  However, they
	now have silent truncation that cannot be detected.  In some
	cases this may seem good enough.  However, often it's not.  And
	anyway, some code remains using snprintf(3) to be able to detect
	truncation.

	Moreover, this kind of code ignores the fact that vsnprintf(3)
	can fail internally, in which case there's not even a truncated
	string.  In the kernel, they're fine, because their internal
	vsnprintf() doesn't seem to ever fail, so they can always rely
	on the truncated string.  This is not reliable in projects that
	rely on the libc vsnprintf(3).

	For the code that needs to detect truncation, a programmer might
	choose a different path.  It would keep using snprintf(3), but
	would use a temporary length variable instead of the pointer.

		p =3D buf;
		e =3D buf + countof(buf);
		for (...) {
			len =3D snprintf(p, e - p, ...);
			if (len =3D=3D -1)
				goto fail;
			if (len >=3D e - p)
				goto fail;
			p +=3D len;
		}

	This is naturally error-prone.  A colleague of mine --which is an
	excellent programmer, to be clear--, had a bug even after
	knowing about it and having tried to fix it.  That shows how
	hard it is to write this correctly:
	<https://github.com/nginx/unit/pull/734#discussion_r1043963527>

	In a similar fashion, the strlcpy(3) manual page from OpenBSD
	documents a similar issue when chaining calls to strlcpy(3)
	--which was designed with semantics equivalent to snprintf(3),
	except for not formatting the string--:

	|	     char *dir, *file, pname[MAXPATHLEN];
	|	     size_t n;
	|
	|	     ...
	|
	|	     n =3D strlcpy(pname, dir, sizeof(pname));
	|	     if (n >=3D sizeof(pname))
	|		     goto toolong;
	|	     if (strlcpy(pname + n, file, sizeof(pname) - n) >=3D sizeof(pname) =
- n)
	|		     goto toolong;
	|
	|       However, one may question the validity of such optimiza=E2=80=90
	|       tions, as they defeat the whole purpose of strlcpy() and
	|       strlcat().  As a matter of fact, the  first  version  of
	|       this manual page got it wrong.

	Finally, a programmer might realize that while this is error-
	prone, this is indeed the right thing to do.  There's no way to
	avoid it.  One could then think of encapsulating this into an
	API that at least would make it easy to write.  Then, one might
	wonder what the right parameters are for such an API.  The only
	immutable thing in the loop is 'e'.  And apart from that, one
	needs to know where to write, which is 'p'.  Let's start with
	those, and try to keep all the other information (size, len)
	without escaping the API.  Again, let's ignore multiple-
	evaluation issues in this macro for the sake of simplicity.

		#define foo(p, e, ...)                                \
		({                                                    \
			int  len_ =3D snprintf(p, e - p, __VA_ARGS__);  \
			if (len_ =3D=3D -1)                               \
				p =3D NULL;                             \
			else if (len_ >=3D e - p)                       \
				p =3D NULL;                             \
			else                                          \
				p +=3D len_;                            \
			p;
		})

		p =3D buf;
		e =3D buf + countof(buf);
		for (...) {
			p =3D foo(p, e, ...);
			if (p =3D=3D NULL)
				goto fail;
		}

	We've advanced a lot.  We got rid of the buffer overflow; we
	also got rid of the error-prone code at call site.  However, one
	might think that checking for truncation after every call is
	cumbersome.  Indeed, it is possible to slightly tweak the
	internals of foo() to propagate errors from previous calls.

		#define seprintf(p, e, ...)                           \
		({                                                    \
			if (p !=3D NULL) {                              \
				int  len_;                            \
		                                                      \
				len_ =3D snprintf(p, e - p, __VA_ARGS__); \
				if (len_ =3D=3D -1)                       \
					p =3D NULL;                     \
				else if (len_ >=3D e - p)               \
					p =3D NULL;                     \
				else                                  \
					p +=3D len_;                    \
			}                                             \
			p;                                            \
		})

		p =3D buf;
		e =3D buf + countof(buf);
		for (...)
			p =3D seprintf(p, e, ...);

		if (p =3D=3D NULL)
			goto fail;

	By propagating an input null pointer directly to the output of
	the API, which I've called seprintf() --the 'e' refers to the
	'end' pointer, which is the key in this API--, we've allowed
	ignoring null pointers until after the very last call.  If we
	compare our resulting code to the sprintf(3)-based baseline, we
	got --perhaps unsurprisingly-- something quite close to it:

		p =3D buf;
		for (...)
			p +=3D sprintf(p, ...);

	vs

		p =3D buf;
		e =3D buf + countof(buf);
		for (...)
			p =3D seprintf(p, e, ...);

		if (p =3D=3D NULL)
			goto fail;

	And the seprintf() version is safe against both truncation and
	buffer overflow.

	Some important details of the API are:

	-  When 'p' is NULL, the API must preserve errno.  This is
	   important to be able to determine the cause of the error
	   after all the chained calls, even when the error occurred in
	   some call in the middle of the chain.

	-  When truncation occurs, a distinct errno value must be used,
	   to signal the programmer that at least the string is reliable
	   to be used as a null-terminated string.  The error code
	   chosen is E2BIG, for compatibility with strscpy(), a Linux
	   kernel internal API with which this API shares many features
	   in common.

	-  When a hard error (an internal snprintf(3) error) occurs, an
	   error code different than E2BIG must be used.  It is
	   important to set errno, because if an implementation would
	   chose to return NULL without setting errno, an old value of
	   E2BIG could lead the programmer to believe the string was
	   successfully written (and truncated), and read it with
	   nefast consequences.

Prior art
	This API is implemented in the shadow-utils project.

	Plan9 designed something quite close, which they call
	seprint(2).  The parameters are the same --the right choice--,
	but they got the semantics for corner cases wrong.  Ironically,
	the existing Plan9 code I've seen seems to expect the semantics
	that I chose, regardless of the actual semantics of the Plan9
	API.  This is --I suspect--, because my semantics are actually
	the intuitive semantics that one would naively guess of an API
	with these parameters and return value.

	I've implemented this API for the Linux kernel, and found and
	fixed an amazing amount of bugs and other questionable code in
	just the first handful of files that I inspected.
	<https://lore.kernel.org/linux-hardening/cover.1751747518.git.alx@kernel.o=
rg/T/#t>
	<https://lore.kernel.org/linux-hardening/cover.1751823326.git.alx@kernel.o=
rg/T/#t>

Future directions
	The 'e =3D buf + _Countof(buf)' construct is something I've found
	to be quite common.  It would be interesting to have an
	_Endof operator that would return a pointer to one past the last
	element of an array.  It would require an array operand, just
	like _Countof.  If an _Endof operator is deemed too cumbersome
	for implementation, an endof() standard macro that expands to
	the obvious implementation with _Countof could be okay.

	This operator (or operator-like macro) would prevent off-by-one
	bugs when calculating the end sentinel value, such as those
	shown above (with links to Linux kernel real bugs).

Proposed wording
	Based on N3550.

    7.24.6  Input/output <stdio.h> :: Formatted input/output functions
	## New section after 7.24.6.6 ("The snprintf function"):

	+7.24.6.6+1  The <b>seprintf</b> function
	+
	+Synopsis
	+1	#include <stdio.h>
	+	char *seprintf(char *restrict p, const char end[0], const char *restrict=
 format, ...);
	+
	+Description
	+2	The <b>$0</b> function
	+	is equivalent to <b>fprintf</b>,
	+	except that the output is written into an array
	+	(specified by argument <tt>p</tt>)
	+	rather than a stream.
	+	If <tt>p</tt> is a null pointer,
	+	nothing is written,
	+	and the function returns a null pointer.
	+	Otherwise,
	+	<tt>end</tt> shall compare greater than <tt>p</tt>;
	+	the function writes at most
	+	<tt>end - p - 1</tt> non-null characters,
	+	the remaining output characters are discarded,
	+	and a null character is written
	+	at the end of the characters
	+	actually written to the array.
	+	If copying takes place between objects that overlap,
	+	the behavior is undefined.
	+
	+Returns
	+3	The <b>$0</b> function returns
	+	a pointer to the terminating null character
	+	if the output was written
	+	without discarding any characters.
	+
	+4
	+	If <tt>p</tt> is a null pointer,
	+	a null pointer is returned,
	+	and <b>errno</b> is not modified.
	+
	+5
	+	If any characters are discarded,
	+	a null pointer is returned,
	+	and the value of the macro <b>E2BIG</b>
	+	is stored in <b>errno</b>.
	+
	+6
	+	If an error occurred,
	+	a null pointer is returned,
	+	and an implementation-defined non-zero value
	+	is stored in <b>errno</b>.

	## New section after 7.24.6.13 ("The vsnprintf function"):

	+7.24.6.13+1  The <b>vseprintf</b> function
	+
	+Synopsis
	+1	#include <stdio.h>
	+	char *vseprintf(char *restrict p, const char end[0], const char *restric=
t format, va_list arg);
	+
	+Description
	+2	The <b>$0</b> function
	+	is equivalent to
	+	<b>seprintf</b>,
	+	with the varying argument list replaced by <tt>arg</tt>.
	+
	+3
	+	The <tt>va_list</tt> argument to this function
	+	shall have been initialized by the <b>va_start</b> macro
	+	(and possibly subsequent <b>va_arg</b> invocations).
	+	This function does not invoke the <b>va_end</b> macro.343)

    7.33.2  Formatted wide character input/output functions
	## New section after 7.33.2.4 ("The swprintf function"):

	+7.33.2.4+1  The <b>sewprintf</b> function
	+
	+Synopsis
	+1	#include <wchar.h>
	+	wchar_t *sewprintf(wchar_t *restrict p, const wchar_t end[0], const wcha=
r_t *restrict format, ...);
	+
	+Description
	+2	The <b>$0</b> function
	+	is equivalent to
	+	<b>seprintf</b>,
	+	except that it handles wide strings.

	## New section after 7.33.2.8 ("The vswprintf function"):

	+7.33.2.8+1  The <b>vsewprintf</b> function
	+
	+Synopsis
	+1	#include <wchar.h>
	+	wchar_t *vsewprintf(wchar_t *restrict p, const wchar_t end[0], const wch=
ar_t *restrict format, va_list arg);
	+
	+Description
	+2	The <b>$0</b> function
	+	is equivalent to
	+	<b>sewprintf</b>,
	+	with the varying argument list replaced by <tt>arg</tt>.
	+
	+3
	+	The <tt>va_list</tt> argument to this function
	+	shall have been initialized by the <b>va_start</b> macro
	+	(and possibly subsequent <b>va_arg</b> invocations).
	+	This function does not invoke the <b>va_end</b> macro.407)

--=20
<https://www.alejandro-colomar.es/>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/v=
g7cczocbx7okwrvgik6wysiduiw7aesntkqzlklrlkacyvz5u%40psb3mh2pyiwz.

--mmmwfwiqbayszx3n
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iQIzBAABCgAdFiEES7Jt9u9GbmlWADAi64mZXMKQwqkFAmhrVwgACgkQ64mZXMKQ
wqmc8hAAjqafnpn73MMIHqLNTRMr8vTQficAqAVGQiMMJFKI8nUO7mcy7OcpzhO/
EKXSdqJj+W5vpStlJ6iyc2CN6CWXPtMrGWS4YN0nS5YsfWxizwjPHUn4/wwF0H/Q
/COwaBNK99JOv8iXdkt8pfBmHCKplMkjIhdQsD2LC/N3di0JjY7Os/5+MXqTbaEJ
PXr44ALp5nKMpfZD2rqshLUSGuCd3esIq0a4UJX1/QuLfmxvUvKFSQCd7A+D9qwd
E8WPkRcAv2deFdLWZbmCw7mMqMFU7uBTnTbzKlIz787HUpJdo/ajZ5/x1rKSPm5Q
BTNbFUel4C+wB1NBMUGBC890FmimtOlcknepJNFZa1I+BWCVnvElI7dVPEH3BhTb
YIEJQ6gZkb4SLqiSlC1kcIicu3H1zoE/WUycoB3dTaZ7j5miQ3k38QnF8yqMbrtK
J7eVMRXWiAD/cU2d7GlDBU9pvC/2BAHFTj2TaXHEui4dAjc7v9C/VKM8FG6MNw3Z
S5ChjOOLB+NCnuo/YjINqQkRYFpTeBf73/fdb0I+hQSpq1I9p2XLTuhCCSqHEA5l
x5EDin7AMYMkV3dyhmQejOtLQ/y9fD21W4+6PRY8IqsvyQRmRAZxBDjK/WNG5z0T
3oMQ5d2Y68lwXeQfx/7KsTh+fQ7YnWrm385qvByOlxU/+fYArzk=
=Wn/n
-----END PGP SIGNATURE-----

--mmmwfwiqbayszx3n--
