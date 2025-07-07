Return-Path: <kasan-dev+bncBAABBWOBV7BQMGQE4UAYECY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 706C0AFB6A2
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jul 2025 16:59:39 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-4a9c7f2f4basf8460821cf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jul 2025 07:59:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751900378; cv=pass;
        d=google.com; s=arc-20240605;
        b=KTmCYpnySJwZ0HuOU2hTUTXkO3bVKCrjGZyCeyHDz48mCysFBemcHIE2LM+Hb/DBqu
         MGL2JKtwkPT5EgofokoMg3r5+ui//nMPb5zrwtwIu/dRmSs6y6Wn0NYnrAbOYzSNrxkc
         bX72lGVx5tZ5/Oi+FrKo7qcK6fwnn9S3IbKdqC/q1nL2Qi/4oYVSjFaQS8wUWvpJDPLl
         Y6aoOAVf+QKL4zjeuIiXeoQ4ZkdLVA5zrEDA2yqWMvBikpqG7NOngNmN8dPyt+PhN/IX
         umFIbSpkfFCY12lAiOhgb0VwvvQkuO0YT53wnI9cj8jvRUbo3863lLULNdupb3atTgWT
         YKJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=yN7LWDEKNtabgA3xHqU2wv0mpMzHA1A9RbeUNqpSBb8=;
        fh=uNlBk4Tdk08yX59vE1rt3D7Xa122Kzdg00vf6a6IRWo=;
        b=H4U4HqnEkOK1NIRtLjUfPmibmDvDq+jOsavcbdpntIlwDOPUKjGYa/Vx8xEzX+DXlc
         00hWQq9CVHIpEdd1VGHAjY7pPuj2CcZqsTDpPpHij6T6hvm8Gjz+Rp1TujqM4vRaM2nN
         Fi1LR7C3F47W4wmxrEce+BYl1B1P84XlLN4GqClxxsKMcGSuw32EA9xlcIzuMM69vsaS
         crf0NSd+iSp4jb0iak2wCaHpfSHnyYd+t37IohEXF18CuIFKNNigflM6tAkcpwpee1WR
         v18q6j2XjyanVoO8TlO/s0Ki/PB/Ujt6eXMRVHOOj3D6fjdRfcOXLHCCRCd+jrRRmcXA
         0gTA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AvUGVCWn;
       spf=pass (google.com: domain of alx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751900378; x=1752505178; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=yN7LWDEKNtabgA3xHqU2wv0mpMzHA1A9RbeUNqpSBb8=;
        b=UpByfkrS6dz+x2VPpREO7KOoKNg9dnansDjTq1m0co9A6/MoMLZLUAT6LUMRfci0vy
         bapsMiimnQr5+FHARAHSzjZm5/3H49vDbrcZ+wnA6MT37sVKnJobf/uRk+4u3D6fr/1h
         JEN4I00XJ5a0KnhLsd+hFgNNwSWU5nWa87YSqPowMqlUNbhfnSTGMzPd1SxY3Yc7fYQt
         D9roOVzqr2R7ynLjDcgURemdycmWhat3GytC1g0BS4/zcowvClNm6I+Tjo6s/nDDKqfk
         i/7U8eCGycdEUeyG58VQhmnuwI2QddwQ6Ua8U2kMthE7wqh4EJmlMCUhiSc19YJIyx4Q
         O4jA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751900378; x=1752505178;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=yN7LWDEKNtabgA3xHqU2wv0mpMzHA1A9RbeUNqpSBb8=;
        b=gH9nq0kqBBx/j9bxt8jDYMHAjLrUnnmWNjlXKUFrIEwF4KYsh1DGNX7aBSYUMPcwlN
         /oKh9x9aXbCBB3lL6hjiBS6Xj+LmRzws5sbJqXkJhgHRX/Tgo9a4NUqo8Tyv6dHsyarJ
         Zl90gG6Tny6Y7zflxsqsx9szcdmgfF56O40MvUTX5qwwMen+QZPxHn3yL2j0QpJ90xfO
         F6FEdzaC62NSdZLOB+5H1WLfjJ25vo0H/AoRS0LluekUzf/slJ8K26qUYusRCgYcMwY6
         n1FRiSSr4zCHuChZ2A4qqDT/T20AgHCS7Cj46iD8XlyWSBpbUAD1KkVY7OtRkSgJrdbk
         3+rw==
X-Forwarded-Encrypted: i=2; AJvYcCVdEcedIVk3QsjKXDnZqTaLTmmSjumcEinZBpWg8t73Gz8llpPLHnCv79i83Bi1tfuTZSWjBQ==@lfdr.de
X-Gm-Message-State: AOJu0YxdOi8U9KWjAxywkIK/9CaW7Fc2a+myB1EXxVLpchTRpXVnL8hH
	2RnnSCtsg/8HgJF8OSkm3Yb1YF93BfeZOxhCj1UHYLd0On3xmJtuY14A
X-Google-Smtp-Source: AGHT+IEmKQGyPcFbKJ5Za7MMXbvB+bS+WBX7Vat3ctZwvf5i+h4iaReQ/j8ULpLJ+rFvAig351eWPw==
X-Received: by 2002:a05:622a:546:b0:494:9d6b:620f with SMTP id d75a77b69052e-4a995791273mr224006151cf.14.1751900377961;
        Mon, 07 Jul 2025 07:59:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfkH7VQwI7eDmh3+FKBdbXITaKdFkh7m98GOCoxSAlGrg==
Received: by 2002:a05:622a:580e:b0:4a9:71c1:b74 with SMTP id
 d75a77b69052e-4a99be5d282ls46930131cf.2.-pod-prod-00-us; Mon, 07 Jul 2025
 07:59:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV5WbDbNa/UAuNoINtnEDsKJVl6ARREJY5JT/sAlwj+vVgmL5XAhoODg6Rzg1OTo5DvcBm9XiChmoI=@googlegroups.com
X-Received: by 2002:a05:620a:4044:b0:7d3:a4fa:ee06 with SMTP id af79cd13be357-7d5dc6e82b7mr1890297085a.29.1751900377002;
        Mon, 07 Jul 2025 07:59:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751900376; cv=none;
        d=google.com; s=arc-20240605;
        b=c5FX9/b2dysUnXIb1Kg8vcVxuDbJBYWNqTqedzQU8h50LSPxTpDroZTivTdV3YoANZ
         lKOmvFApm0nPIsJRLD42vJSIo7OgV/EZhdtw8p5rPIbCV9u67QqK2Q0jknmtJZl5Wc88
         68PYh3nm+/daDbYx1ON4iMqAVp5lt5OTDM/xm+YlePEpVslDhwMR1KGxFvFN7BG1Ndi8
         fZcErBEbA5gcVuhUJXe9ERQxk6bHQF25KPaYdzG9zdxxx6hea/j7X+xncdz6n4k6xCxJ
         UrVj1aYoZtVXCi1qvLRd7o60uSfIfmnpLDkH0LUaBkK1zIbJ+vlikfuz8mCVzlrGxByq
         6/kA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Ua/pU1asxZEC1SDx4TLmGsItVvCbIim55tXRb/bEicI=;
        fh=Gc/mDhvsY7x4KaCM6O5RoH+iuauY5fHr03AGMmMUQVM=;
        b=V7FTxOlODMPS/YUjh9r7uId+YiG0UPei1qJD10K1L3K8HXJ+Vi92RgjOovVnYqJi5U
         +6TIehRP9xddzEi9AVhCu6yZqHyAwRvwEt/7rumjefCofajryHB4WuSK536zUkcfDyM4
         3MPp8gjeOPMh26THsPKYreKJ/M6xb2/k+Jw+RG8aF2Ig6raUoDz0QKfCspPYvw0Knld1
         s79NidznL32j7+wtaC/k8ccBQd2EijKnGdhVBuxrsk82KFmQ8xj+VW3PUUjpzfA/1Bu5
         HKb642WXdnaHszuKFFqfptlNfpGxwuRRH8qjhyZwYEDMVj3l+HPNbrAOCzBSebQc3Iqt
         NsaQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AvUGVCWn;
       spf=pass (google.com: domain of alx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-702c4d292ffsi3619756d6.8.2025.07.07.07.59.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Jul 2025 07:59:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id D69ED45221;
	Mon,  7 Jul 2025 14:59:35 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4A9B6C4AF0B;
	Mon,  7 Jul 2025 14:59:34 +0000 (UTC)
Date: Mon, 7 Jul 2025 16:59:32 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alexander Potapenko <glider@google.com>
Cc: linux-mm@kvack.org, linux-hardening@vger.kernel.org, 
	Kees Cook <kees@kernel.org>, Christopher Bazley <chris.bazley.wg14@gmail.com>, 
	shadow <~hallyn/shadow@lists.sr.ht>, linux-kernel@vger.kernel.org, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>
Subject: Re: [RFC v1 1/3] vsprintf: Add [v]seprintf(), [v]stprintf()
Message-ID: <a3f7i56s5fmg2kcc2j2yledsyxfgepvf62jquqhjzckvg2ojwp@nokqxjgqpman>
References: <cover.1751747518.git.alx@kernel.org>
 <2d20eaf1752efefcc23d0e7c5c2311dd5ae252af.1751747518.git.alx@kernel.org>
 <CAG_fn=UG3O-3_ik0TY_kstxzMVh4Z9noTP1cYfAiWvCnaXQ-6A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="ltlrnmdc5i3ybtlp"
Content-Disposition: inline
In-Reply-To: <CAG_fn=UG3O-3_ik0TY_kstxzMVh4Z9noTP1cYfAiWvCnaXQ-6A@mail.gmail.com>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=AvUGVCWn;       spf=pass
 (google.com: domain of alx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
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


--ltlrnmdc5i3ybtlp
Content-Type: text/plain; protected-headers=v1; charset="UTF-8"
Content-Disposition: inline
From: Alejandro Colomar <alx@kernel.org>
To: Alexander Potapenko <glider@google.com>
Cc: linux-mm@kvack.org, linux-hardening@vger.kernel.org, 
	Kees Cook <kees@kernel.org>, Christopher Bazley <chris.bazley.wg14@gmail.com>, 
	shadow <~hallyn/shadow@lists.sr.ht>, linux-kernel@vger.kernel.org, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>
Subject: Re: [RFC v1 1/3] vsprintf: Add [v]seprintf(), [v]stprintf()
References: <cover.1751747518.git.alx@kernel.org>
 <2d20eaf1752efefcc23d0e7c5c2311dd5ae252af.1751747518.git.alx@kernel.org>
 <CAG_fn=UG3O-3_ik0TY_kstxzMVh4Z9noTP1cYfAiWvCnaXQ-6A@mail.gmail.com>
MIME-Version: 1.0
In-Reply-To: <CAG_fn=UG3O-3_ik0TY_kstxzMVh4Z9noTP1cYfAiWvCnaXQ-6A@mail.gmail.com>

Hi Alexander,

On Mon, Jul 07, 2025 at 11:47:43AM +0200, Alexander Potapenko wrote:
> > +/**
> > + * vseprintf - Format a string and place it in a buffer
> > + * @p: The buffer to place the result into
> > + * @end: A pointer to one past the last character in the buffer
> > + * @fmt: The format string to use
> > + * @args: Arguments for the format string
> > + *
> > + * The return value is a pointer to the trailing '\0'.
> > + * If @p is NULL, the function returns NULL.
> > + * If the string is truncated, the function returns NULL.
> > + *
> > + * If you're not already dealing with a va_list consider using seprintf().
> > + *
> > + * See the vsnprintf() documentation for format string extensions over C99.
> > + */
> > +char *vseprintf(char *p, const char end[0], const char *fmt, va_list args)
> > +{
> > +       int len;
> > +
> > +       if (unlikely(p == NULL))
> > +               return NULL;
> > +
> > +       len = vstprintf(p, end - p, fmt, args);
> 
> It's easy to imagine a situation in which `end` is calculated from the
> user input and may overflow.
> Maybe we can add a check for `end > p` to be on the safe side?

That would technically be already UB at the moment you hold the 'end'
pointer, so the verification should in theory happen much earlier.

However, if we've arrived here with an overflown 'end', the safety is in
vsnprintf(), which has

        /* Reject out-of-range values early.  Large positive sizes are
           used for unknown buffer sizes. */
        if (WARN_ON_ONCE(size > INT_MAX))
                return 0;

The sequence is:

-  vseprintf() calls vstprintf() where end-p => size.
-  vstprintf() calls vsnprintf() with size.
-  vsnprintf() would return 0, and the contents of the string are
   undefined, as we haven't written anything.  It's not even truncated.

Which, indeed, doesn't sound like a safety.  We've reported a successful
copy of 0 bytes, but we actually failed.

Which BTW is a reminder that this implementation of vsnprintf() seems
dangerous to me, and not conforming to the standard vsnprintf(3).

Maybe we should do the check in vstprintf() and report an error as
-E2BIG (which is later translated into NULL by vseprintf()).  This is
what sized_strscpy() does, so sounds reasonable.  I'll add this test.

Thanks!


Have a lovely day!
Alex

-- 
<https://www.alejandro-colomar.es/>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a3f7i56s5fmg2kcc2j2yledsyxfgepvf62jquqhjzckvg2ojwp%40nokqxjgqpman.

--ltlrnmdc5i3ybtlp
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iQIzBAABCgAdFiEES7Jt9u9GbmlWADAi64mZXMKQwqkFAmhr4M4ACgkQ64mZXMKQ
wqmu/w//WwZs9mMUUpehQAZpcLdKgHxOjWIoVERVVix9JXaMkRjvecmLbMcM09Gq
VaIcLpSsccjhDCyz1HKOgvnjIXR/s7bDsy13cjIDwQ7LA8dcT15srw5TAFJhdIlB
LgXQLbewhPidtpcqQBlZavyw2bhL6qhr/1RsI9vaRv6+fpz/TunEP6No1PogIwHB
jTtats/jSKw+PwMukd2a7ZAuBsuopcP+vehDSgr5C+L6v2bG7adoFaiyZT6w3zLS
Tp21Q1bZpQGtD2O6dHWcyn+mrr6i5XP/jKT9r0KQP/HEa28uHSEm/R4oi2RDtr7G
PgJokX5UT8Jfj1YOOebpi0gp30hHEpyWNDPIoLxTqxRYhUja4yJQr//qrSxI++ec
ZXEr4WNNMFDBiVLSfzan8TSJqxEL2KuexQbk89WfPdUw0xEV5bXbIRdIJAjoEM9o
ZWpD61Fsk5vhiB++H4vHK7xVKvlbbdydWGr4/gEhw2Fb6TTUeR7yw24aBXjUSvWh
TyDvLRfKpEy5GDmpzt3goQddiF3T4yP8mrcRXvvnJkyOyqJBX0TsMyLh32zTYoF/
GvrcWFlZvMYB6HuW470wsTDDmQR4NfMdvlD5S/8gBOsIdmjLOMhyViZgYDsb5S5G
xkvPd/+crvso450yOEVkbQMRMgQnx2IexlfON3fHYrQZ2EuSNi4=
=2l/v
-----END PGP SIGNATURE-----

--ltlrnmdc5i3ybtlp--
