Return-Path: <kasan-dev+bncBAABBZEHWXBQMGQEEK4D7XY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 30E20AFD05F
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Jul 2025 18:14:30 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-315b60c19d4sf3589274a91.0
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Jul 2025 09:14:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751991268; cv=pass;
        d=google.com; s=arc-20240605;
        b=DV6UBonYbhSpZFxZ31eRk5ESj+apVINsXOLQ/YXnLuaSOSPfILEfTi+bnCbr6JBIAl
         9emRRUlgg3uzL62aRCqgfW55MI2kDmlvvw6dv5WoDvhA3XJhbaaq2jIK6W4gqAYw2txd
         CfSrnxqtMxSksVAqcsT5XiOKu5ApYFZ6GYtHDmuDlYTqO/2VCUh2cYY9rno2wRPkdPOJ
         BbRa7aNbbGti9pCBr8DIZlkLsSTy6Pf55DmGLkMhiTJvQGtE8b8N2Ev0VCDpi+Ax/sKn
         E6agr0SLC7WoLmaKkQASTAxCJdo+sZ+FDkD2HzF0zljBVEe3ZqNltqv7UK07DUqMMz9r
         a8uA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=upipTSVgiLg6M03/9BFoiERiAGPBsxqibrGxOMlNYaA=;
        fh=a2Yb/B9pKY03M9j+4QAY1GgweThIlPjOV0WGl2L6RJI=;
        b=UEqey79fXzCXLoooLePBNcJ5fbzm7Pu9rWeYhXpfYn07wK5fozdhoYoyFrgPCeahHE
         BiRlTt88pNtUQ5o2kCT0bU0zb4f4WvJK83OEokvaeP2ZcwjdVH01eXr8saam55MvSRcn
         EAJjotikqIuttn9YBz7Vgh4iGkQV2GDqPTZuDB+iXgNPPlsDnv6FPUz3S6iTiaLT8YP8
         VM46UF+QnHgfY1FCaxWIqXX8NIP3gYyj+cE2zm4lBHXzD5Xaqe2XWLtmkX5s71YV9fHS
         8P+rh7Ayqkp/ik+oCdomzNHJG30176eW+y1342P6a79UTiRBHAUiPKBfkK2JhUC4zyen
         WMAw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Q48En5Xx;
       spf=pass (google.com: domain of alx@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751991268; x=1752596068; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=upipTSVgiLg6M03/9BFoiERiAGPBsxqibrGxOMlNYaA=;
        b=kmrLog6pCYggjLm/Jm3qR+umTLwn9Mnytbl3Nb5PjJDowjG8XM8pVJzqRMMxLpsLr1
         45JdoYTsZ0kni7H/0jgelh3zChLr2QdIYfQv2c0h7JpkgidN60JyVCyJPEDnyEx2Of9G
         hchOy5e/nb8NhKDTlBdScoFaVYQxmiZPGs9m7Skjb/CZaO8tgDK2bJ/H7Kkk34x+0VC/
         ejRuF3tGoB10aD2jXxEUxcMivxZm5T/kswnkxzyZbnOrxIR67k809imlF8L0vDkcOwae
         uPXYeOYEJSQRLlu1jR4zg//YDn7rLidVFqm0jrMT0x4TWjU2/+UKOwmABOsvVwoRuZ7a
         dewA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751991268; x=1752596068;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=upipTSVgiLg6M03/9BFoiERiAGPBsxqibrGxOMlNYaA=;
        b=qsBPi8959Su4InZLlitnZK3Ioiktgyb5lCREg5fNMxd+waheTRL5H95MoYviVDpZAX
         Xr+jespIiV+/HmEaUdWuEZIhF1f/rvuEyOnF2phTZEyrs/fs6qJi4ETEA8A6c1jGCSjg
         kgWXmTJLy7pAxuI3iMkIOZk3vHMDVA/o66AbMf3gUDJv5oWgAbjAydYf0we9Evw151C/
         cjedVnMVQv7DVX7dFhWCngsw2w66JK8xW8KAyC2SQIRTIMLE1Wb9e+kxWegHyYNO1FLz
         TYXYOXjicsNL2X0P123SPCnpyLpMHj7BGEscqPwW5EbrqiigCpe+XGWZ/VVM5H8P4Ot6
         COcA==
X-Forwarded-Encrypted: i=2; AJvYcCVxlVZDhtXah9tB4ThzgKHYBqXVRBTa1uNr+PcFr9UXouaBuIGLgUJ5bUq1fstekAbOS7uqFQ==@lfdr.de
X-Gm-Message-State: AOJu0YwrlfQhA/zuxmi+cUXNl+EGIaR6lCSCLxIeuuyWiRxgUnsjFu8G
	cH5NVr9e7N0zlaiIN0kr+JEE7d2qO6GQn52qhGr4XIFBlxZyjg7iR0Dy
X-Google-Smtp-Source: AGHT+IFOD0/YN3blVjY2yiivCCrkeRP9hVBfXOneyrd3n7g1HaOx0IcFzmwyxuj+kn80tjyP4DNUHg==
X-Received: by 2002:a17:90b:5744:b0:313:2e69:8002 with SMTP id 98e67ed59e1d1-31aac4bae02mr21954006a91.20.1751991268315;
        Tue, 08 Jul 2025 09:14:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdefumFXtQyv7rizp8TktzX5MebRcyHiJahJgKDCfJoOg==
Received: by 2002:a17:90b:50c3:b0:311:b6ba:c5da with SMTP id
 98e67ed59e1d1-31ab03359cfls3794204a91.1.-pod-prod-05-us; Tue, 08 Jul 2025
 09:14:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU25n6ZnUt8MDJb1iQXVVorUWn2vTgLA/3vAmY3T0VFO4ayNukAUS94VInNHOJbBWkrQ3tFTTRUaCQ=@googlegroups.com
X-Received: by 2002:a17:90b:1e10:b0:312:e445:fdd9 with SMTP id 98e67ed59e1d1-31aac44b747mr26005570a91.10.1751991267144;
        Tue, 08 Jul 2025 09:14:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751991267; cv=none;
        d=google.com; s=arc-20240605;
        b=bgT7O1ebrK4fbCckND0nnTEB9mvXaSnjKN2Dt8kRHY7TURY0fZ3YNTXcILqB12IVDT
         SaZlalcHP2u7NSGLocsyq89pkn0WqK3gY2mmEYLcAm11SWCS2ASAbObNyci0Lf9xuhVI
         mjVU/F1Kw6UX4TF5ltg1PLpBzbOB7My09otMGk65MPsPH5fPoYdQAv9pGBIf6qddaS7J
         8CSnWrqZLuJDx96RJQQQLfYHSGRFH3d2Vy7g206AJcIsZxWM00OYvfERhJpEgS78bjne
         ctW+a9fa6IJc1JgjCL7hUGo1YmUscSjqRttXX0tATtVjImCV83ZEtQzTYXab2l69xfQw
         pQ7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=LWFZZbbE5Kesn1qqHv/z8/iOC50rgh4eT/OcY8Gk3pw=;
        fh=dyVddJ4ioll5zQWyJsUIfnKP91wTBJRhYoGWALTgmks=;
        b=cSRPpWggMF+/u1btRM+Db29JL3KUXHftvD+WQ2WZJl2WUaWJx9dN6shXsihbrO4w8w
         43K9RU48TkfF3WCzO7p1ZNrO54XV+URHd9JL4e4TXEXBG2aAFDpiK/NLmj5mm6CSZyKE
         6hWPYhHPLLs8z2gAI7tGDZ7AM6ZNe29+s7BtG3iCaMdMwLDfghbqkGxBF5KsifFTn5um
         LpHfkrYajAVa4Uu0/RF2jvYCKr3GQY6qIZ6YjSWWYmoGUkCpDz+Omm6GE8ovjfYIQAak
         ipQTpKmVE9guo4B29cGc1B1jPFXvDeqh3vSSDtC08Sdd4cTtrmmwtW7cXsMJ49LJYVJq
         fXFg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Q48En5Xx;
       spf=pass (google.com: domain of alx@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-31c22003493si142679a91.1.2025.07.08.09.14.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 08 Jul 2025 09:14:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 72DFF5C58DA;
	Tue,  8 Jul 2025 16:14:26 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E4ED1C4CEED;
	Tue,  8 Jul 2025 16:14:21 +0000 (UTC)
Date: Tue, 8 Jul 2025 18:14:19 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: Rasmus Villemoes <linux@rasmusvillemoes.dk>
Cc: linux-mm@kvack.org, linux-hardening@vger.kernel.org, 
	Kees Cook <kees@kernel.org>, Christopher Bazley <chris.bazley.wg14@gmail.com>, 
	shadow <~hallyn/shadow@lists.sr.ht>, linux-kernel@vger.kernel.org, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>
Subject: Re: [RFC v1 0/3] Add and use seprintf() instead of less ergonomic
 APIs
Message-ID: <xmrrnnvhipkhfs6xk743nczeuze6hegjihtdhdcougkuzsnv73@qgmtmjntsd7r>
References: <cover.1751747518.git.alx@kernel.org>
 <87a55fw5aq.fsf@prevas.dk>
 <ez7yty6w7pe5pfzd64mhr3yfitvcurzsivjibeabnkg457xu7x@tkompzcytwcj>
 <871pqqx035.fsf@prevas.dk>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="uc53hol6uccylkwy"
Content-Disposition: inline
In-Reply-To: <871pqqx035.fsf@prevas.dk>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Q48En5Xx;       spf=pass
 (google.com: domain of alx@kernel.org designates 2604:1380:4641:c500::1 as
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


--uc53hol6uccylkwy
Content-Type: text/plain; protected-headers=v1; charset="UTF-8"
Content-Disposition: inline
From: Alejandro Colomar <alx@kernel.org>
To: Rasmus Villemoes <linux@rasmusvillemoes.dk>
Cc: linux-mm@kvack.org, linux-hardening@vger.kernel.org, 
	Kees Cook <kees@kernel.org>, Christopher Bazley <chris.bazley.wg14@gmail.com>, 
	shadow <~hallyn/shadow@lists.sr.ht>, linux-kernel@vger.kernel.org, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>
Subject: Re: [RFC v1 0/3] Add and use seprintf() instead of less ergonomic
 APIs
References: <cover.1751747518.git.alx@kernel.org>
 <87a55fw5aq.fsf@prevas.dk>
 <ez7yty6w7pe5pfzd64mhr3yfitvcurzsivjibeabnkg457xu7x@tkompzcytwcj>
 <871pqqx035.fsf@prevas.dk>
MIME-Version: 1.0
In-Reply-To: <871pqqx035.fsf@prevas.dk>

Hi Rasmus,

On Tue, Jul 08, 2025 at 03:51:10PM +0200, Rasmus Villemoes wrote:
> > However, there's the early return due to size>INT_MAX || size==0,
> > which
> 
> First of all, there's no early return for size==0, that's absolutely
> supported and the standard way for the caller to figure out how much to
> allocate before redoing the formatting - as userspace asprintf() and
> kernel kasprintf() does. And one of the primary reasons for me to write
> the kernel's printf test suite in the first place, as a number of the %p
> extensions weren't conforming to that requirement.

Yup, sorry, I was talking from memory, and forgot about the size==0.
I've introduced the check of size==0 for seprintf(), but snprintf(3) is
okay with it.  My bad.  The issue with INT_MAX holds.

> > results in no string at all, and there's not an error code for this.
> > A user might think that the string is reliable after a vsprintf(3) call,
> > as it returned 0 --as if it had written ""--, but it didn't write
> > anything.
> 
> No, because when passed invalid/bogus input we cannot trust that we can
> write anything at all to the buffer. We don't return a negative value,
> true, but it's not exactly silent - there's a WARN_ON to help find such
> bogus callers.

Yup, I know.  It's silent to the caller, I meant.

> So no, there's "no string at all", but nothing vsnprint() could do in
> that situation could help - there's a bug in the caller, we point it out
> loudly. Returning -Ewhatever would not remove that bug and would only
> make a difference if the caller checked for that.
> 
> We don't want to force everybody to check the return value of snprintf()
> for errors, and having an interface that says "you have to check for
> errors if your code might be buggy", well...
> 
> In fact, returning -Ewhatever is more likely to make the problem worse;
> the caller mismanages buffer/size computations, so probably he's likely
> to just be adding the return value to some size_t or char* variable,
> making a subsequent use of that variable point to some completely
> out-of-bounds memory.

That's why seprintf() controls that addition, and gives a pointer
directly to the user, which doesn't need to add anything.  I think this
is easier to handle.  There, I can report NULL for bad input, instead of
adding 0.


Have a lovely day!
Alex

> 
> Rasmus

-- 
<https://www.alejandro-colomar.es/>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/xmrrnnvhipkhfs6xk743nczeuze6hegjihtdhdcougkuzsnv73%40qgmtmjntsd7r.

--uc53hol6uccylkwy
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iQIzBAABCgAdFiEES7Jt9u9GbmlWADAi64mZXMKQwqkFAmhtQ9UACgkQ64mZXMKQ
wqmXexAAoMKhj1wyGjvhsWQvcONm/dFCQQmigbvdvZel7D+KJfQQSiN8AHuDL0WI
+NP0JRsmbOqvnvrc8RW6w4rtmWyoRpsyJjCOCneNiw35EWmUcBbJTCXfD/A8TF9B
Idf453FE2u5B4QWJ+7X2s9ee4rxKiL3MzF4iEpZ/afDa7DA4FSYBuK7bv16YfTn5
KssCG9JEH91cMLqjOuv7YgnVrHfYburjuKt9GzK5QyLinlzNvBDYl+OHRPG4OOWb
1arsLTPccpfnM0CCu2iLaCWfTDEz5W8n4ml2kwmctACzzEFUOXVm8CjC4CiRLzBu
STVoHGKKn8S5KdjUxx7VdkgJmO+2a3L+J4Yq6/xP3ywlMEfXeZi3iEP/7AcBaqSo
5PR/LMx113ftA9M4/KMesyL4aB7U0EME2a0lLspvtSU64puOLa9eAcq71FcuxdQH
DWRLjkLrck7s39Kwrzk/JsQO0OuAmwTqs0zV2M6aBRUCBnjfyRDrqY+PDQ1C+47z
F+g8xt57alY6tN/tJFWAymozBl+6UMmI+4O8z4gL0Urso2juh1YWuH4XD5sN69iT
V5ft+sw2G9VPd5T1OZYIrB8ySSgZLl3mKs0AfZr99XJsU/onPVL27ZLDfSTkEFKm
NEDOPx1Ojv8NIDyKXUYid1NaofXjKbWfKF7lKsGtLanOdGYLJbU=
=sxYf
-----END PGP SIGNATURE-----

--uc53hol6uccylkwy--
