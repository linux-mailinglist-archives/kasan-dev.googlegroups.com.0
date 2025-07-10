Return-Path: <kasan-dev+bncBAABBREXYHBQMGQEJIWJCKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 17428B00F9B
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Jul 2025 01:24:54 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-4a7bba869dbsf33222001cf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 16:24:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752189893; cv=pass;
        d=google.com; s=arc-20240605;
        b=hPtxwrXBdE9OYH6G5ubdmusvWzBcblXOz98yI8B9YwhHoPYMrvV2GRwJDyldLlI4Or
         Lls5bJOupODGIs2A96iFHOJXe/mUIJs/fPiFULn3DdCNBxTlfzJzDGG3OKN0tho0NS/5
         t0Bdbh4HOf1tUL7VGiiZoeXNEY1XiPlrmW0YBZ+GWfGe246bHYRNQv0056rjtHD8eU7x
         oE0nMUB59WXgGMFTg4irorXC/AZAXcxeVmd7ZDAkC4j8IfftOSNzysKFmgMUeIzZG6WW
         KJ6gFfDeG1/jmUj4eh5PuVDGl+79DeW3YNMi1eMxruMr8QdyAGz2+bOh1TtojKc1Must
         9HWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=8tbw04P9W+VF+08AC0A/WFJhBAGKeSWQtsdK5OH7z2c=;
        fh=Cp0akRI2mhtPUXCicP+KdDBnq2RKQdIRZ7VtUlOvekw=;
        b=WE1UkunItPB0uiDKw8ShqNGRADhYqKi4/3Eh52Ce/0OmkX0FElPNJKKTu19Dber2OQ
         vs9KFlKD/FjLFKrkT28aqWy/Txq07xBn6wubqp2n3tgHEPoDqkRiyRAf1Va+y8+iZn6a
         9zRJuG51PhHyfPvAXDKvODQfZ63WJug9VlEKGGrPPHq8WQNsL5pGZDsZyECA6smK79AA
         sFh7K7ng996Mlh0IMSJUfYLZwED2xI+TIep0kjEWS3OTSjprHfPcJYifwfcjyQtTtt5C
         AAkQWrb7gkmePff+/lC7Fym0SpA6wwgPDrh30IWk2bZhQVjvYI6pUIutuTZ+RPuedUS7
         RV2w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=oEw4YreP;
       spf=pass (google.com: domain of alx@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752189893; x=1752794693; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=8tbw04P9W+VF+08AC0A/WFJhBAGKeSWQtsdK5OH7z2c=;
        b=gtG3JPH0cU+rmmKcSxcwerX7eDJ+DWPCwulH/2zwrsvw7Q2HJ0Bx+APxX/W7BvmAx3
         c80OCH6p3bQWAiXPbrKjqP/FH2kFxKhOcgfRauNH/aD8Xt2P0EetSKJ4LkB0YoW/HjRI
         77d/TZ9GEe+KHms87B01MKjhdd1o0TCcH/LdEDXlev1YiHB54K/3xYh0whcMQiWh0Utf
         L6nnObXdt5aePcdhUocbCL0U0oUk6iwOVEQ14WtB2sSe6rjN45A0I5bCwt45Q8xsnvRM
         vGnDc67umdI/X6N7dMkVrpoxNDNdEw/99p3W8OqtzqVfSpmf5TSivVVJUz3/LJd1n703
         8MUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752189893; x=1752794693;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8tbw04P9W+VF+08AC0A/WFJhBAGKeSWQtsdK5OH7z2c=;
        b=t/kyR+zGy6WopH9yCppNCjpIPGB1M2LwkZ2V3CDXa3PCQXQvY4eX8yPTd1Gvsycono
         bERskJ+7K+qI+EZPUtFBQy3Be1+4Wt/ir1gpyPJORBDmVPvNcQSJelPoTfNoq9ctkfwQ
         PjEDMeY60fxLbiFL7FB65K/x8l1Gp3DTH6MO2b+qU++kbu4iC/sT6E/v57P8+NiFkh0c
         JkqvBNfZxQ6OmcWGjAkI4HImed7lkMa3CTRggTkF0hqanYo4J8iJ5YF4Jhf6w85XT13i
         QSincR1jitEx4hXc4G+cfBZ15ixvADvcswESENU1DHRrh8nAXhDM3LSaMsJ6ympn90Sn
         JgcQ==
X-Forwarded-Encrypted: i=2; AJvYcCVzOj+vkURxkC9TGzgbGt0z3j7JqSJij2TxMFdaTeimI9FkuFMGvaRfiX92/vEu+uQPXN9SuQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz6YPVkGgdY3610iyhNxU1rITGkupawqpo5cRPBoSs4lbFN9eo3
	x2yjDLGBEURIdXtoqoCdH3aTYF8p0mZngQcS1esotwr1GrzJQx2gkw/P
X-Google-Smtp-Source: AGHT+IEcet1tCdEt3rQULiH2Ae4AFh7z3svu+C/dmFio5ywShJ8KK7QJuHwLkjNjzkeCQmT6Tei6Wg==
X-Received: by 2002:a05:622a:5b87:b0:4a9:a2b7:bb3f with SMTP id d75a77b69052e-4a9fb5b0d4fmr15961251cf.0.1752189892743;
        Thu, 10 Jul 2025 16:24:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfJAm1YFCBqfYTx9Phk6k7laeOBY/bkLGrCfh6IKEFOSA==
Received: by 2002:ac8:59cf:0:b0:476:6bc3:c758 with SMTP id d75a77b69052e-4a9e9c30a0dls22916311cf.0.-pod-prod-05-us;
 Thu, 10 Jul 2025 16:24:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUj/5Z72B5Qt3BSmCGmHKVukq8Kd6xku7ol2xzNGcanoy2vTTR0E4UlWmtXL65jCVS0s/b9ti1jOGk=@googlegroups.com
X-Received: by 2002:a05:6122:1d4b:b0:52f:47de:3700 with SMTP id 71dfb90a1353d-535f472fffcmr725051e0c.5.1752189891931;
        Thu, 10 Jul 2025 16:24:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752189891; cv=none;
        d=google.com; s=arc-20240605;
        b=Uao9lz9HJTIbWYSJp8UlG+X1j/PZ05mExu+Tk57xwXkYVFd9mRqg0RtEXeI9+vJ0hJ
         QvNgXtcXF0HgVukuGz9JTY7TeaFoBli+j5y6oT326FqnIwwRjP3QaNwj8AVEksC382Nc
         RgU+ILkfkBOK2SOd7AQq6P8NIPv/TBb4is/QNtkM+GvIT0W+14g1BOXh+zfxnu4v43S0
         BVy5jzsKrLc8R1uxOfi19UVsHsvFCUgFkNdjvNq1aOIOVPcQdfmvmtHWKSku9gPPUxfT
         4KwuIavScVpsZNULMA/aHFeb+IitVeb2K0fnSwUxsZAGpJa7+sS8UwjlUqJ6s6iSZY4F
         n74g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=8Tm3ntCa/cpDFLceDFpG/gbGsJihNni0whe6V+msW3M=;
        fh=zUc2rdoSbCbn7clUWHxfTk4+JRSRpIJzJWpzDhccr1w=;
        b=cVrCDX8MquRj+22KT6SjVOP2Ve5tipI+SgSIMkm66l+K0pyfmRTqf0wv0WYls87+MR
         M9Eqoou+t++qs1paOJ2W0SuEmBGvZMJvNj9dTKWlab0CdKF6NsGIWkDYPY+msGaDiga+
         a8WQp34lwv564bdciz9f0FIhm7Yn/95OfTDpKL/JuDEiKFpzap32mmsxqlUULK4DNaQp
         2Q3zulA0ZAwCCXWH5JTU6MK1xixPODu/gWgCLTJepYMbT0kJbaAd+956Kn/jkHYjo+xJ
         9dYX2t3dO8HWpJ85F07K7yjJLR0DQhoyw06BIZLqK2gUoY9svw8LIIU6IR22ShIh+MTE
         NXTg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=oEw4YreP;
       spf=pass (google.com: domain of alx@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-535e71f458dsi130885e0c.1.2025.07.10.16.24.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Jul 2025 16:24:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 7B0D5A53812;
	Thu, 10 Jul 2025 23:24:51 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id AD578C4CEE3;
	Thu, 10 Jul 2025 23:24:46 +0000 (UTC)
Date: Fri, 11 Jul 2025 01:24:44 +0200
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
Message-ID: <vgqpplbhg6krsufibrhe4n5agnh7vcrdsmoqd225guiakr3ojs@2dltrftpb3p2>
References: <cover.1751823326.git.alx@kernel.org>
 <cover.1752182685.git.alx@kernel.org>
 <04c1e026a67f1609167e834471d0f2fe977d9cb0.1752182685.git.alx@kernel.org>
 <CAHk-=wiNJQ6dVU8t7oM0sFpSqxyK8JZQXV5NGx7h+AE0PY4kag@mail.gmail.com>
 <krmt6a25gio6ing5mgahl72nvw36jc7u3zyyb5dzbk4nfjnuy4@fex2h7lqmfwt>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="6edp5zcpae764526"
Content-Disposition: inline
In-Reply-To: <krmt6a25gio6ing5mgahl72nvw36jc7u3zyyb5dzbk4nfjnuy4@fex2h7lqmfwt>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=oEw4YreP;       spf=pass
 (google.com: domain of alx@kernel.org designates 2604:1380:45d1:ec00::3 as
 permitted sender) smtp.mailfrom=alx@kernel.org;       dmarc=pass
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


--6edp5zcpae764526
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

Typo here.  It's vsprintf_end().

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

Typo here.  It's vsprintf_trunc().

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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/vgqpplbhg6krsufibrhe4n5agnh7vcrdsmoqd225guiakr3ojs%402dltrftpb3p2.

--6edp5zcpae764526
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iQIzBAABCgAdFiEES7Jt9u9GbmlWADAi64mZXMKQwqkFAmhwS7wACgkQ64mZXMKQ
wqlOQxAAqQqG5Z7+Xh1jkMiJqhKKnJ4dTK0nc7NVJNqdOHZBJCjt7CCvZulq+QO5
TAKjjj5aaK3ZA+XB42UNR6cya6aL88fDOr4d6srebkLTkGoEXnjBN/VWardd8z2d
Iq8z4UsaxfDDA8OQVz2lbcnFxA2KSszs9SwsP0mZZXjCZSdrIKqguPaexaJ1ZSkC
IML9PzRqUqm9KbJn9qroGTx5DWRg2hf/q+T6PxCjzU+DDQL7mh1+XHgL3EXL1s4Y
9+DnXRe+s9VJ8A/TcAwlbdZO99Cp4YpnNJP+m8y0wOJpOgIwlk51hbGGZ2U+jIU9
nISZk+EZTERJLqU06PVPp3wVyWhxTqVIcbxhQTGKGumltTWaHu2i2yI/RkoMLL/c
FRm8AnuO4X874TUc9JJTCq9ycz0BAv8YRmbNDmZoVcm8XhBzKVPo03h1LOm/kTnq
+seYP9mJz6BiFwSXok60CZrsflPlaob3z3tFnMgwG/7qXwMnS6gW3FDRMFMuPVCf
7vmiDiXMOf0sjwYzM0AYDqqWaGDloWBxU0KwUH0e9+Tp/mDxJbaCxr/1G7fyX3QL
QtRd6yUURufITU56DsxEJYx9PkDdheYm9JI91ZFHEajSrR0FzQd+SwcNivSk6q8p
fYtGfPwriq8GxHRzTxeYlCWcy2YKIhb63RLIRNuIgcDyDZ+EKhc=
=icSd
-----END PGP SIGNATURE-----

--6edp5zcpae764526--
