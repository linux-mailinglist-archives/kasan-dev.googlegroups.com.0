Return-Path: <kasan-dev+bncBAABBDUXYHBQMGQE5YBF6OQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id AEE6DB00F99
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Jul 2025 01:23:59 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id 3f1490d57ef6-e840e706230sf1845186276.3
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 16:23:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752189838; cv=pass;
        d=google.com; s=arc-20240605;
        b=lYltE9Yt8CcUUPDBZSTWlaNKaxRiaIHCnKHGBsaZnvcwjZ/chfeMEoZHV/CXU1FJst
         ZB9LhjNql26Yovu7CfzKwXIQzK8TtIKlqrnrfZ0bmtNH7WUDWWKLWPVsUkUzVbYWa00+
         Q0gCm70i7+K+AoedqixWK0FCsftc9Tp/v8DhT4dWXmXVJsagr6vCd9LYcR8cd0ATRlh0
         8DDSJJXm/NTnbm4HOxa7apW+u2p3Sor6OpZELHBS7kGippxlSI+/tXLQZ3xiQ/0hRnmA
         ktD2azVTssVENUhjjhMHVw3RgpBSYofZ80rwhaVD+8clXkJi9jXofMyBA3ck7aJYW2ju
         5CCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=B1R54teoY2BgwZWNV1Vqt2atfSzE6qEfL3I3+9WDpyw=;
        fh=8a/ZfPbbTf5yijrr55nYfeUaE0AzxMcJ4L5qz322bDw=;
        b=dT8yN109m9+YRxJp/yp8K8z8XYAsRx+mfKAxFl0kcsO8d6xv4RZ/D8Y5NTlEWZmcKc
         /H5+PTSe7E2JitCfCWkX9N/7RiVkHr83+ffBCHuAjA3qdj9FILIqIVnJ+ERp0v7FeFyk
         Z1Gh/0mP8dD1B0rzdGaXjH3M1De4+BCeQbXEMMPR6RXtrgV4Li5UmY3DXREChgsVLCL0
         a59vJridIRBwjxgppeAM+lILTHjp+NIwgLphFOXoBUpOtWSSm5TQQTFSe11Hwc5+ixpj
         VDleoPkuVfZoVyUdJHLqFBtEhdTvNT/k3a0s538eFt5jVLQ8miWPQ7SgDyYchwMirFcG
         wTqw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IFnRv05a;
       spf=pass (google.com: domain of alx@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752189838; x=1752794638; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=B1R54teoY2BgwZWNV1Vqt2atfSzE6qEfL3I3+9WDpyw=;
        b=GwDXx3iOH331eY1kOpgTEOXrMP1LTUjtL8SCHki7HNyLdon7xC298TZk5biFPBvsnp
         H3JaTQVJrKvqzxcIMQEzo9tZDGHQ2OR2h3wP2kzl1QTw1AuC5he27xgrCEUPE/8lbFie
         bHwxMprB+EwqrauiERrUOLvY2IfweXO+0Nw0CCfZlZq9/vT9PDa7o2+28s5wS3hzBDz9
         vL7jau+pzkiS0uDfJMh3XamlfWQsv7KzleS7p7AEs9j7sBsq2510+YhnhX21/zbe7poK
         91QDb9NSLh91nw+EjK0F2cR7RbW8c85Ch41Rz50VDU28xf+OCZOfJHpqTMZihmbtZ/Mk
         GnAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752189838; x=1752794638;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=B1R54teoY2BgwZWNV1Vqt2atfSzE6qEfL3I3+9WDpyw=;
        b=FZ1dtOq5iJcO6e0imIuujdk92zJCRMQkNHr0yeqPQaLPKjz77iiRo4LQkkOkVvm8t/
         zJly9k+n7qvH7zYNdXT/efe2tvLim9hrP6XuGPYrp6CjRwXRVteS5xFPxDeI+UKXlise
         thCSnihy4L2j2KwBrNeKnx0BE3vINF8+SH89lQjgqBJRQ4dUoRCYAKfcgyQwX+Bt57qZ
         yCMJdMmrFrua0j3tpyxishUadgQf/Q1yWoTyp4eF2JjcXv59u9Ijzw4jS0JxaSCWbMYS
         rVl2Z5bQ2IghbkVNa6uwa2OnNB4iWb4vnQmuMobTAm8/2KWxmoDM4ZP5vjERDgggR4Zr
         qAGQ==
X-Forwarded-Encrypted: i=2; AJvYcCWgWKOIWtErCbY9KuUCkVS+SXodNQw91SY9HF952+oqwOG2QFso639ma/eAIZq7isvcZ/oXvA==@lfdr.de
X-Gm-Message-State: AOJu0YxUKLADLhl4UOM+CMS5P4YDrNqRLBdkcLxikqfO1J7C0Xc2Stel
	TWI3GnNJzCHvx5UWmvV4EBdU3yXkalGbJUwpfjE/ml2oYcE1OGFDdbnB
X-Google-Smtp-Source: AGHT+IEAf5Pe58ECU1viWEbfXRHhf1S04nzoyfCjQmLInz9v2CnLtUU+405t+t0ElbxbcCe5qXJlkg==
X-Received: by 2002:a05:6902:120d:b0:e84:ce8:135b with SMTP id 3f1490d57ef6-e8b85c5792bmr1171733276.44.1752189838352;
        Thu, 10 Jul 2025 16:23:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcn8rZMQh//Kq08ZpnqQsRiSmfb3FkIQt7SsKWK7ZasEA==
Received: by 2002:a25:c1c5:0:b0:e82:307f:5561 with SMTP id 3f1490d57ef6-e8b7795f27bls1544774276.2.-pod-prod-06-us;
 Thu, 10 Jul 2025 16:23:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXf4CnWk57+s0BaMD3E4LcSr6yEhZIpUJ8SGx6bZ+f0ugFJna6yQxlBa/UndfFJOdbVbTJCYgSzf9A=@googlegroups.com
X-Received: by 2002:a05:690c:398:b0:714:429:edc5 with SMTP id 00721157ae682-717d5b8019cmr22152277b3.4.1752189837331;
        Thu, 10 Jul 2025 16:23:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752189837; cv=none;
        d=google.com; s=arc-20240605;
        b=C6N/hh4cT9fbpS7tLO0RxDB8DCh7znD+B0n9Dz+Sj038NlzHyiFbDw4R7ixWsBP236
         WyOLzwjxmAnRkmeYaMKEim2Dl5vlXRN5SofvQpsHwnFlQi+CinyrbPLfbnx93grdf/zm
         ujrtf2cGtYLpsyoKf/LY1jcXl8VWOe5kqsCsp4oKV5NOKd0Z+x38U3xQo90NxOewgp/m
         n8cifyYIZO4kL8xiHqDyULhL3SffknU+4P0XIO2GHWs/tzAO1eypzDVr+OXjRcuv27A+
         EIHM9aVVoSBrtrpZrdXXWNI4XyyiuqHJBsnRfQFtlKSTAwc+6bqttgTqF3frv7J9Yqz+
         FOVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Cup3PyNK537Lv9LxdLhG/3+z3/ESd/NGq9+Im3jxqns=;
        fh=zUc2rdoSbCbn7clUWHxfTk4+JRSRpIJzJWpzDhccr1w=;
        b=Txaag8tzsefGT35xHU/LvjU9Z4dvGonwkt7vcM/Oc7SNx0+bQx41VJsJda7em2zePD
         ahr0CAMoTFuPilKl78cAA+pbRuQDixbTdVmfRORC5R5eXEogyIXHJjJ8vDS/as7Ru1nn
         Cvqyp8zU5YmfePsFa4s1QjDwNvSAseIsDTCBWFSxDrGR0tVQ1uxNVvzs+QGOoLqglM6q
         6jo/gp13R/MiB6EHbWqfE3LSq/9mFsZ/oKj4wUKPNKa/pDwUM1o8nbxkOxEQeWuqkd8x
         0VF/S1FndEfuHdbIhsYbiXfGG3mCDMVa3BEd+TK6F01KywYii9kGlwEswzQn9z8oGCtu
         nxsQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IFnRv05a;
       spf=pass (google.com: domain of alx@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-717c59f4198si1364347b3.0.2025.07.10.16.23.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Jul 2025 16:23:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 5BB0946E60;
	Thu, 10 Jul 2025 23:23:56 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C565FC4CEE3;
	Thu, 10 Jul 2025 23:23:51 +0000 (UTC)
Date: Fri, 11 Jul 2025 01:23:49 +0200
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
	Michal Hocko <mhocko@suse.com>, Al Viro <viro@zeniv.linux.org.uk>, 
	Martin Uecker <uecker@tugraz.at>, Sam James <sam@gentoo.org>, Andrew Pinski <pinskia@gmail.com>
Subject: Re: [RFC v5 6/7] sprintf: Add [v]sprintf_array()
Message-ID: <krmt6a25gio6ing5mgahl72nvw36jc7u3zyyb5dzbk4nfjnuy4@fex2h7lqmfwt>
References: <cover.1751823326.git.alx@kernel.org>
 <cover.1752182685.git.alx@kernel.org>
 <04c1e026a67f1609167e834471d0f2fe977d9cb0.1752182685.git.alx@kernel.org>
 <CAHk-=wiNJQ6dVU8t7oM0sFpSqxyK8JZQXV5NGx7h+AE0PY4kag@mail.gmail.com>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="lpnpaylljl22ydn2"
Content-Disposition: inline
In-Reply-To: <CAHk-=wiNJQ6dVU8t7oM0sFpSqxyK8JZQXV5NGx7h+AE0PY4kag@mail.gmail.com>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=IFnRv05a;       spf=pass
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


--lpnpaylljl22ydn2
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
	Michal Hocko <mhocko@suse.com>, Al Viro <viro@zeniv.linux.org.uk>, 
	Martin Uecker <uecker@tugraz.at>, Sam James <sam@gentoo.org>, Andrew Pinski <pinskia@gmail.com>
Subject: Re: [RFC v5 6/7] sprintf: Add [v]sprintf_array()
References: <cover.1751823326.git.alx@kernel.org>
 <cover.1752182685.git.alx@kernel.org>
 <04c1e026a67f1609167e834471d0f2fe977d9cb0.1752182685.git.alx@kernel.org>
 <CAHk-=wiNJQ6dVU8t7oM0sFpSqxyK8JZQXV5NGx7h+AE0PY4kag@mail.gmail.com>
MIME-Version: 1.0
In-Reply-To: <CAHk-=wiNJQ6dVU8t7oM0sFpSqxyK8JZQXV5NGx7h+AE0PY4kag@mail.gmail.com>

Hi Linus,

[I'll reply to both of your emails at once]

On Thu, Jul 10, 2025 at 02:58:24PM -0700, Linus Torvalds wrote:
> You took my suggestion, and then you messed it up.
> 
> Your version of sprintf_array() is broken. It evaluates 'a' twice.
> Because unlike ARRAY_SIZE(), your broken ENDOF() macro evaluates the
> argument.

An array has no issue being evaluated twice (unless it's a VLA).  On the
other hand, I agree it's better to not do that in the first place.
My bad for forgetting about it.  Sorry.

On Thu, Jul 10, 2025 at 03:08:29PM -0700, Linus Torvalds wrote:
> If you want to return an error on truncation, do it right.  Not by
> returning NULL, but by actually returning an error.

Okay.

> For example, in the kernel, we finally fixed 'strcpy()'. After about a
> million different versions of 'copy a string' where every single
> version was complete garbage, we ended up with 'strscpy()'. Yeah, the
> name isn't lovely, but the *use* of it is:

I have implemented the same thing in shadow, called strtcpy() (T for
truncation).  (With the difference that we read the string twice, since
we don't care about threads.)

I also plan to propose standardization of that one in ISO C.

>  - it returns the length of the result for people who want it - which
> is by far the most common thing people want

Agree.

>  - it returns an actual honest-to-goodness error code if something
> overflowed, instead of the absoilutely horrible "source length" of the
> string that strlcpy() does and which is fundamentally broken (because
> it requires that you walk *past* the end of the source,
> Christ-on-a-stick what a broken interface)

Agree.

>  - it can take an array as an argument (without the need for another
> name - see my earlier argument about not making up new names by just
> having generics)

We can't make the same thing with sprintf() variants because they're
variadic, so you can't count the number of arguments.  And since the
'end' argument is of the same type as the formatted string, we can't
do it with _Generic reliably either.

> Now, it has nasty naming (exactly the kind of 'add random character'
> naming that I was arguing against), and that comes from so many
> different broken versions until we hit on something that works.
> 
> strncpy is horrible garbage. strlcpy is even worse. strscpy actually
> works and so far hasn't caused issues (there's a 'pad' version for the
> very rare situation where you want 'strncpy-like' padding, but it
> still guarantees NUL-termination, and still has a good return value).

Agree.

> Let's agree to *not* make horrible garbage when making up new versions
> of sprintf.

Agree.  I indeed introduced the mistake accidentally in v4, after you
complained of having too many functions, as I was introducing not one
but two APIs: seprintf() and stprintf(), where seprintf() is what now
we're calling sprintf_end(), and stprintf() we could call it
sprintf_trunc().  So I did the mistake by trying to reduce the number of
functions to just one, which is wrong.

So, maybe I should go back to those functions, and just give them good
names.

What do you think of the following?

	#define sprintf_array(a, ...)  sprintf_trunc(a, ARRAY_SIZE(a), __VA_ARGS__)
	#define vsprintf_array(a, ap)  vsprintf_trunc(a, ARRAY_SIZE(a), ap)

	char *sprintf_end(char *p, const char end[0], const char *fmt, ...);
	char *vsprintf_end(char *p, const char end[0], const char *fmt, va_list args);
	int sprintf_trunc(char *buf, size_t size, const char *fmt, ...);
	int vsprintf_trunc(char *buf, size_t size, const char *fmt, va_list args);

	char *sprintf_end(char *p, const char end[0], const char *fmt, ...)
	{
		va_list args;

		va_start(args, fmt);
		p = vseprintf(p, end, fmt, args);
		va_end(args);

		return p;
	}

	char *vsprintf_end(char *p, const char end[0], const char *fmt, va_list args)
	{
		int len;

		if (unlikely(p == NULL))
			return NULL;

		len = vsprintf_trunc(p, end - p, fmt, args);
		if (unlikely(len < 0))
			return NULL;

		return p + len;
	}

	int sprintf_trunc(char *buf, size_t size, const char *fmt, ...)
	{
		va_list args;
		int len;

		va_start(args, fmt);
		len = vstprintf(buf, size, fmt, args);
		va_end(args);

		return len;
	}

	int vsprintf_trunc(char *buf, size_t size, const char *fmt, va_list args)
	{
		int len;

		if (WARN_ON_ONCE(size == 0 || size > INT_MAX))
			return -EOVERFLOW;

		len = vsnprintf(buf, size, fmt, args);
		if (unlikely(len >= size))
			return -E2BIG;

		return len;
	}

sprintf_trunc() is like strscpy(), but with a formatted string.  It
could replace uses of s[c]nprintf() where there's a single call (no
chained calls).

sprintf_array() is like the 2-argument version of strscpy().  It could
replace s[c]nprintf() calls where there's no chained calls, where the
input is an array.

sprintf_end() would replace the chained calls.

Does this sound good to you?


Cheers,
Alex

-- 
<https://www.alejandro-colomar.es/>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/krmt6a25gio6ing5mgahl72nvw36jc7u3zyyb5dzbk4nfjnuy4%40fex2h7lqmfwt.

--lpnpaylljl22ydn2
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iQIzBAABCgAdFiEES7Jt9u9GbmlWADAi64mZXMKQwqkFAmhwS38ACgkQ64mZXMKQ
wqmhJhAAhZBNcIE/LkNJtDs9GNCCyYFQN+O55h5xwKBvOeNPeOX9QO202kKaYgsO
+BNzl6ccOtttWGx1ReDyi4BrB78LZGtm17mfXSb+kDpeThSMOc4uBdVepQ3CpXwg
p4fdLPwNMWp3kRyN0Y4t8+w4mejmpSKQtwoY/Es/IKp6h8ol+ivkM0V46NviK//I
fqvkaLIeMoiM2fks1mvdELYGBdTtSTjI3iFd5gP8Gk+oxIS6csyjE1MCQbUBcAp1
VNaVVTRNstB34zYgQ6LhL2TzZySl7h1QK4Vd1yN8h8gRSg0TM3U3dWQ0ThcvjnDo
cmoo8L3vj+Ya/hirwJ4h3MR0mSRKgDqvFSXC+p1/tI3xZCZZIFuuALQ2OLIl9gD2
yibSSV6NCBLueGs/UrUIT0Z7d/adiroKW9CRmsMdmLQSsIUDRNlARo2vndL9wU7S
wjBHqh/feWZ9R/1DNQfPgOuqMaqGBqm8wh2eyp828bIgAu+YV75apRZ1Q5kWJTwx
IydZHSnOViZbfo7sDxBG6s6APp2eJJN7+RZpL1doZctkneboKN2L7EYg2ZJErmgO
oYOCbbyGkRqWkedbQ0zOJL7tanUA0zT9OPLABVV/hY6QngajyUeix4pP+ve76aJH
fggtgH9SFW1uhmA7dCnBF1SABfPMrgFB+71kzC6wI+BBgGleLKs=
=hhWT
-----END PGP SIGNATURE-----

--lpnpaylljl22ydn2--
