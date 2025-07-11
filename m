Return-Path: <kasan-dev+bncBAABBLVRYHBQMGQEDKVTLQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 5622DB0101C
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Jul 2025 02:20:00 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-2f3bc8c5573sf1794806fac.2
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 17:20:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752193199; cv=pass;
        d=google.com; s=arc-20240605;
        b=eEKEFkEqjmmebQTjj+XhhHAjAERuKGVMglxgBzINS2IJKhMqek3zMZJC5mXzUUqKI5
         aTmQbt2EdeKGgz3eYexgoxR8Oi0kuDGh0TBkor17d4aAKDt8M17aRAsYv/9UMODBqMiv
         Z+7mIngYT9FIgKCHvSC6BXmT9Jvo4xXSfYFbQx0oBHlHRx4Q+6vMXScBNkpavPVdupav
         vVcU30rLtupkZu0AROGwLdk+Y7Hpy1kUi+1xs/BtuYwwMII366cR8/0KmT/lvmVCPhfq
         skgWePXiYOcK9tU4c64O1AyJrk3dEJCUz8JO56VkcbtC1NhfXhmCz6jI6VhraEOwI91o
         WUtg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=bi/Mf1dWU7uP+LT8rddpDMYcfqPOjRNwHNEL6rUBN7o=;
        fh=EHNkBNcMduxA1yah6ziEQABXtzCpe6h8NxjpG14pqQs=;
        b=XMKTbg1YIDo+/ZHFhBXYt3iJjMQXaiuxgN/IM6TzcR539kSbef/4VoJa04VIBXfgIG
         CwT4n+ZAaqVchi+qzKnQMCOFo65o7CKCFxbc+YMxRkGLfNvEMIad0T9QD5S6bTLhoprI
         7h9+xQTlzgY50pghNL/rDxoo2bS3CTeVI9ZBDbuM079H9pxOqUI40KDxQDi6L9K5G1LN
         TlB/4krIejKC4jClIrZDiQ51QYHao40GqOvgA7b2ZnqpaBWu8O1eOtVREpf7u1gNfNQe
         qo6h5r6bGMdyCEA4VBU/Y6sf19tIoFKaKxg5Nsvk7fvekT72+RirlwN80KH+CWW4zNrs
         c0GA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Weh/yhwS";
       spf=pass (google.com: domain of alx@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752193199; x=1752797999; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=bi/Mf1dWU7uP+LT8rddpDMYcfqPOjRNwHNEL6rUBN7o=;
        b=uDNKk+Saeo8M/AZmkI2nOV2FZGYRdKfOFwWyHvKP/tmipTiruWhOgrJX3mZGy+vZlG
         Toc+GAoY9tZwDjio9YQh1UwLL57Rf6Di+aMI6xRtvXtaWqpENix2nKNiYZb2ohpvjCD9
         wek1ewYCmP83EzNIeNjE1UyiTf+BVpRD+jVfr4dcBrngkfrNjxWzEN4fzRZ3IZJ+UrYo
         fpwJD3+K3ksgN3hG34feRmkrJvH+/SsqTB14rgcVFO8RMIR0HjsAlRRGLBowTzVveCRz
         uE4Hms/or//3JjLb9zjqK7huIAzAzwsrVQV7IKJ3em+TOz7Y9+SMqTKZDDBwi9x6qAwx
         i6sg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752193199; x=1752797999;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bi/Mf1dWU7uP+LT8rddpDMYcfqPOjRNwHNEL6rUBN7o=;
        b=oKdnl+B2ZrtgdjE5cnEvN1i2EicxumzxsqrkD0moAf5l1f/lDKFROqqr+8+PgY1xxY
         IwTxDqVCjwxY0yL0IPdh92m0EusVtS/b+ycpImkWepksz3GaSMiDp7RFEOVD1TjBcL3N
         OO+wjQhn4JxBJGFVybbBdde5k7CGZTqfT9szG4ZNBO6ZdoZDAHilzgyMGsYQkjsQieFb
         tv9Xqbpb1cTdJbnbdcFn9JI02gAIqLr08TKi5Jb1s59fruyaRUBR6MYhc5ylIKe4V97l
         OvC791BeFBxuWE8Fvr42DV/ZkpFxnoZWFJKyQf5iAZdGTZQzCZzA9v9kVYVqLHh0TGQe
         c2Ng==
X-Forwarded-Encrypted: i=2; AJvYcCXQgTixXk/C5qUUvgkNyWazNfPpmrw5WUVFzwUEa2hsfFDAWdEK6DhXTgzHGur2PtykXCTDSQ==@lfdr.de
X-Gm-Message-State: AOJu0YxW4yi9BEgXG6in7WpcHhiYhrNfYAxJJdfh//RVJPxOWpJEIQKN
	ZAhWg2oh89TZ7sj2EgFF72TwFtYR3fnThRJMGIWDU7E2fItVfxWOTYw9
X-Google-Smtp-Source: AGHT+IFeDthvZ3iPfEMe9ksUEplEU6+p7hZDyqXZwBGZsTghAT31Dc+Sabtd1dweD9l0yzgXG1D1pw==
X-Received: by 2002:a05:6871:6aa:b0:2e8:ec55:aafc with SMTP id 586e51a60fabf-2ff269fb9c0mr929105fac.37.1752193198933;
        Thu, 10 Jul 2025 17:19:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfrXWe5cR01sdEG8z3SPltz0nlhFrxTev3O425ZB6A+IQ==
Received: by 2002:a05:6870:e6c9:b0:2ec:f2fe:213c with SMTP id
 586e51a60fabf-2ff0bd2fba4ls898618fac.2.-pod-prod-05-us; Thu, 10 Jul 2025
 17:19:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXIRm5pLh2LCNI5Zo21wYzfMKNhyLVsEtoKwaiPhJCjJKaALQMPjTyWC0ILPVxO7K5jarwjr2fJMG8=@googlegroups.com
X-Received: by 2002:a05:6870:a450:b0:2f7:840d:3e7 with SMTP id 586e51a60fabf-2ff267aae51mr979420fac.13.1752193198177;
        Thu, 10 Jul 2025 17:19:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752193198; cv=none;
        d=google.com; s=arc-20240605;
        b=e+IopByDj/WZTOlmBYE+GwfeT+i/ZtTjVy2fDz9xScbSwuJTB2rnuDdEuo/a/YWoJc
         +ClJNRmQ0fQSsQWbW3Et+k5UcZgjMErNPMamPAgcwvqF0d5phiIjgy2gy75sgR1cXts1
         o8YffHo3iUuowGbRHkUPW592FJTWPIXvwdalSccFdylyZ9oki/Iq+Vd55g5JS9fgu20J
         ZHj4vO97G5UxmcMmD/DUscsZRIZP6AQ4cOh3mXr6yfO/IELr00XSWs57Ijq92Sh/4Nqa
         1L+6Uy9c/+YrZJZdMu+d4lWATwsxOoHEvW43VX/Sn8uvJEQHW44ZPJGD/5V/vULnE2VT
         bo2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=7anj020mL6gxQRjluBn5RQ282qTmpp0hZCMqhCUti+I=;
        fh=zUc2rdoSbCbn7clUWHxfTk4+JRSRpIJzJWpzDhccr1w=;
        b=Fn4jSWWJF9FXUg6EPM+35WeNYtMBedrmawu45kZW9JS5zU/wd17QLl6NVQQmrLbFZu
         yj2I78SMK6sYqse2XbpC+mBrcU7e8/ppNH3TVERUDdbC8cAPCsyt2omw5y9fKc6k5aWg
         b1CmJaFQdeR/rfuLIL65WcHb5zb1phYBxwhpDE7GiY/ONlqezzFXe/G0NHbqkJM4QDhj
         J8bSeDZHioWHZjv9N4p3iGoZksDTh5YsEKrnLJXTQTO1MVErxSAPluoYXJainabD65TR
         7yoVaKzZ4SCMsIR9l2ohxbpFgwLMVfai/onuBK/IZvxvPX3wAkUdP8kON/K4S4yIa+O2
         uulg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="Weh/yhwS";
       spf=pass (google.com: domain of alx@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2ff116fafc8si178746fac.5.2025.07.10.17.19.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Jul 2025 17:19:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 48307614A6;
	Fri, 11 Jul 2025 00:19:57 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 26BA0C4CEE3;
	Fri, 11 Jul 2025 00:19:51 +0000 (UTC)
Date: Fri, 11 Jul 2025 02:19:49 +0200
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
Message-ID: <z275r52gltcgv6gbixfdwj7z6ocn6qa26v5lif3h7n5otapiq2@37bsjlraqalo>
References: <cover.1751823326.git.alx@kernel.org>
 <cover.1752182685.git.alx@kernel.org>
 <04c1e026a67f1609167e834471d0f2fe977d9cb0.1752182685.git.alx@kernel.org>
 <CAHk-=wiNJQ6dVU8t7oM0sFpSqxyK8JZQXV5NGx7h+AE0PY4kag@mail.gmail.com>
 <krmt6a25gio6ing5mgahl72nvw36jc7u3zyyb5dzbk4nfjnuy4@fex2h7lqmfwt>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="wxhooa7cq2eiokbj"
Content-Disposition: inline
In-Reply-To: <krmt6a25gio6ing5mgahl72nvw36jc7u3zyyb5dzbk4nfjnuy4@fex2h7lqmfwt>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="Weh/yhwS";       spf=pass
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


--wxhooa7cq2eiokbj
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
 <krmt6a25gio6ing5mgahl72nvw36jc7u3zyyb5dzbk4nfjnuy4@fex2h7lqmfwt>
MIME-Version: 1.0
In-Reply-To: <krmt6a25gio6ing5mgahl72nvw36jc7u3zyyb5dzbk4nfjnuy4@fex2h7lqmfwt>

On Fri, Jul 11, 2025 at 01:23:56AM +0200, Alejandro Colomar wrote:
> Hi Linus,
> 
> [I'll reply to both of your emails at once]
> 
> On Thu, Jul 10, 2025 at 02:58:24PM -0700, Linus Torvalds wrote:
> > You took my suggestion, and then you messed it up.
> > 
> > Your version of sprintf_array() is broken. It evaluates 'a' twice.
> > Because unlike ARRAY_SIZE(), your broken ENDOF() macro evaluates the
> > argument.
> 
> An array has no issue being evaluated twice (unless it's a VLA).  On the
> other hand, I agree it's better to not do that in the first place.
> My bad for forgetting about it.  Sorry.
> 
> On Thu, Jul 10, 2025 at 03:08:29PM -0700, Linus Torvalds wrote:
> > If you want to return an error on truncation, do it right.  Not by
> > returning NULL, but by actually returning an error.
> 
> Okay.
> 
> > For example, in the kernel, we finally fixed 'strcpy()'. After about a
> > million different versions of 'copy a string' where every single
> > version was complete garbage, we ended up with 'strscpy()'. Yeah, the
> > name isn't lovely, but the *use* of it is:
> 
> I have implemented the same thing in shadow, called strtcpy() (T for
> truncation).  (With the difference that we read the string twice, since
> we don't care about threads.)
> 
> I also plan to propose standardization of that one in ISO C.
> 
> >  - it returns the length of the result for people who want it - which
> > is by far the most common thing people want
> 
> Agree.
> 
> >  - it returns an actual honest-to-goodness error code if something
> > overflowed, instead of the absoilutely horrible "source length" of the
> > string that strlcpy() does and which is fundamentally broken (because
> > it requires that you walk *past* the end of the source,
> > Christ-on-a-stick what a broken interface)
> 
> Agree.
> 
> >  - it can take an array as an argument (without the need for another
> > name - see my earlier argument about not making up new names by just
> > having generics)
> 
> We can't make the same thing with sprintf() variants because they're
> variadic, so you can't count the number of arguments.  And since the
> 'end' argument is of the same type as the formatted string, we can't
> do it with _Generic reliably either.
> 
> > Now, it has nasty naming (exactly the kind of 'add random character'
> > naming that I was arguing against), and that comes from so many
> > different broken versions until we hit on something that works.
> > 
> > strncpy is horrible garbage. strlcpy is even worse. strscpy actually
> > works and so far hasn't caused issues (there's a 'pad' version for the
> > very rare situation where you want 'strncpy-like' padding, but it
> > still guarantees NUL-termination, and still has a good return value).
> 
> Agree.
> 
> > Let's agree to *not* make horrible garbage when making up new versions
> > of sprintf.
> 
> Agree.  I indeed introduced the mistake accidentally in v4, after you
> complained of having too many functions, as I was introducing not one
> but two APIs: seprintf() and stprintf(), where seprintf() is what now
> we're calling sprintf_end(), and stprintf() we could call it
> sprintf_trunc().  So I did the mistake by trying to reduce the number of
> functions to just one, which is wrong.
> 
> So, maybe I should go back to those functions, and just give them good
> names.
> 
> What do you think of the following?
> 
> 	#define sprintf_array(a, ...)  sprintf_trunc(a, ARRAY_SIZE(a), __VA_ARGS__)
> 	#define vsprintf_array(a, ap)  vsprintf_trunc(a, ARRAY_SIZE(a), ap)

Typo: forgot the fmt argument.

> 
> 	char *sprintf_end(char *p, const char end[0], const char *fmt, ...);
> 	char *vsprintf_end(char *p, const char end[0], const char *fmt, va_list args);
> 	int sprintf_trunc(char *buf, size_t size, const char *fmt, ...);
> 	int vsprintf_trunc(char *buf, size_t size, const char *fmt, va_list args);
> 
> 	char *sprintf_end(char *p, const char end[0], const char *fmt, ...)
> 	{
> 		va_list args;
> 
> 		va_start(args, fmt);
> 		p = vseprintf(p, end, fmt, args);
> 		va_end(args);
> 
> 		return p;
> 	}
> 
> 	char *vsprintf_end(char *p, const char end[0], const char *fmt, va_list args)
> 	{
> 		int len;
> 
> 		if (unlikely(p == NULL))
> 			return NULL;
> 
> 		len = vsprintf_trunc(p, end - p, fmt, args);
> 		if (unlikely(len < 0))
> 			return NULL;
> 
> 		return p + len;
> 	}
> 
> 	int sprintf_trunc(char *buf, size_t size, const char *fmt, ...)
> 	{
> 		va_list args;
> 		int len;
> 
> 		va_start(args, fmt);
> 		len = vstprintf(buf, size, fmt, args);
> 		va_end(args);
> 
> 		return len;
> 	}
> 
> 	int vsprintf_trunc(char *buf, size_t size, const char *fmt, va_list args)
> 	{
> 		int len;
> 
> 		if (WARN_ON_ONCE(size == 0 || size > INT_MAX))
> 			return -EOVERFLOW;
> 
> 		len = vsnprintf(buf, size, fmt, args);
> 		if (unlikely(len >= size))
> 			return -E2BIG;
> 
> 		return len;
> 	}
> 
> sprintf_trunc() is like strscpy(), but with a formatted string.  It
> could replace uses of s[c]nprintf() where there's a single call (no
> chained calls).
> 
> sprintf_array() is like the 2-argument version of strscpy().  It could
> replace s[c]nprintf() calls where there's no chained calls, where the
> input is an array.
> 
> sprintf_end() would replace the chained calls.
> 
> Does this sound good to you?
> 
> 
> Cheers,
> Alex
> 
> -- 
> <https://www.alejandro-colomar.es/>



-- 
<https://www.alejandro-colomar.es/>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/z275r52gltcgv6gbixfdwj7z6ocn6qa26v5lif3h7n5otapiq2%4037bsjlraqalo.

--wxhooa7cq2eiokbj
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iQIzBAABCgAdFiEES7Jt9u9GbmlWADAi64mZXMKQwqkFAmhwWKUACgkQ64mZXMKQ
wqlpAw//RdeLKJ5j+1r2HH8/miXwNO+Td73GjSPzQwmr0qv5WC6xsxijQKo0TqcZ
hCbrsLeLZwNnEOqaOpGJzyUyROAoqpFDN6WsPa2N4ZvZdPoktE2PwkUzTcCscJG7
H/cZigcGgcQn2vNWM6RvGPCYrATCt7ijFBiuWsw42ojhDyLsF5WrmuzyD7z+zCOr
/QuqtAH3pcX8lyyQQbKDqJKwoUDg0LR6jwnqYLuHPALsFH3h3NKKYanRGUqM5if3
FfN9XQu+YGRAAIl0LNPD97im7wi0EVdt0VmnmVB8B0SuS2aBE6tEyQoP90lSkY5h
X37I7y7fyevgIl/nfsOaWWe6kYSbFqI2gIRh4YE0pN0eaYwyiclf7L+GHu8ZyZs+
ABUSDY9H7UThNDDC9mgZE4Cs9qTeCgAU0TllLqcrxVI15JsTriRIayp7dmCCZx4y
eZg9sizGjpd6/X/s7F8w6yAWEvfVxt8Vcfm/064Z1/UtvkK/pRA04324lPZbVxVK
l79tjbCwzIyfvtyhTPlCvCCOl5vSKGrsiTgxQDd0rGsMxj7bsmfehMAbvHIwYhGu
dB2Mgil21Ce0I38Vx0oGdlaOQtXGSl1OCDttCcD+kkxjqfY0nJTX6psFr9DIQzhe
BSdqZU3Kd2uKHWLPmxH0xAy7EzJ9iuECkOnGL3J9SKg8VLiWCg0=
=KM9i
-----END PGP SIGNATURE-----

--wxhooa7cq2eiokbj--
