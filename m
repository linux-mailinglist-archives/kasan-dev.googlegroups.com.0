Return-Path: <kasan-dev+bncBAABBXOIYXBQMGQE2EPUD2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 19425B02478
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Jul 2025 21:22:07 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-2f3b9f04303sf1011563fac.0
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Jul 2025 12:22:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752261726; cv=pass;
        d=google.com; s=arc-20240605;
        b=EmNYV/lYfQ/e5y636kvgCP+7xjbBgw8qdk8YBWEcz6tHxmM0wVo6zp7I+ID94daG3v
         GVkLQVvdD4+OE9u2EsG6aJdNCYv3nA3/qQXlkeK0NQFmaHUtYB87fNgSNXokXRJmmIOe
         dHS/MbqFdVhqCAlcTN7/E9zkmUWHADPiquVae8Yvv7QG8OpuiLFwSpTrWiWS5CCvA111
         f9Is6RhVw0PmHhHSDCnBcB9meS8YQ+Zox5yxnj1dTfgfiA1ifRAvVHbHoXZcr5ePnXTg
         SheHQlRAIaeBeKCbzN5S01bEkpJ1QXHmtf1DcSHIGYWefNJPL21O0sEG2f4bfKNi5c1k
         vMvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=cdFBGfAhEhTutQnoxSaChpD2a+hR1qAoCjdLG4JYB4A=;
        fh=FzxDEat/Den5ePbx2m+gJmqhd41wMHvaaCiGAV+nHVo=;
        b=gGAvXTqc9pIJpfdE6IdsDFHn57mPFBQnUGY+Op7/8mseb7Sy2f56EXlxPeiGlgq+qH
         fO+91LmTjjPnjABxbx8MKvHFLGRvwEz8JrdfWPN9HO+6JGCP1Tv+pwBKx4wxw7By5zzK
         r9AyN+xdWqNDnH2IoAgba8qYcCATSAGXTWiP0gICMhTYol33XQkg/h3fuTL5WnBqh4U0
         vLwjhFbNpKiIe6mYlyeD4JtVN4BALgJW2QyT198jpwWCFsZ4DqYY5nvPJ5ljMnxFahDt
         pCJjEfpQFIMxqYwdgL2HFziUH6vdWdXgG81kehJ7eMqiKia280hd0Ssk+28sFMafRUyK
         0pDg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Lcx+bn6N;
       spf=pass (google.com: domain of alx@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752261726; x=1752866526; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=cdFBGfAhEhTutQnoxSaChpD2a+hR1qAoCjdLG4JYB4A=;
        b=m6EraT34am3k0M5Pu7WcImcTFl6qI2DaPKjjR+gsBKeHJzIY+wyHaJLocPpBIrPOj+
         84QGu9nwRL5kVdzqi8Vmxs4bModGMnPTad3KQ1za0HUR08vd71yAqjyK+36xL3DsjClU
         dJvqm+YU3YsgZXvSYS1w1k/vtxZG+1j7qv9zVRjIqmBMnNhvlGIgkq+sy3sosxC/AaE2
         9xyEGhtw/wxIAEk1ucXnxS3vOdZU66qTlMJbDBtYD3lbIvdZXKC2qp51IPIH15mBJkxM
         I4PILqN8ZtpukAmlfYNlebiVHtzlfct+ho+IbyoU+ZZ/jvPQVEp9F4mrwyM+uh1fBKBu
         S6xw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752261726; x=1752866526;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=cdFBGfAhEhTutQnoxSaChpD2a+hR1qAoCjdLG4JYB4A=;
        b=Wf2PWtDWfH8+xDIyMOs11ywi/UvkngKiCaDsCUxq9ht42CUx+41RxkJ0lEYz8lYa47
         xSabxky7+EbEMFIMDwpANl4blTo5Oap4+UGUgdLXxlwj/ITn5pA4hJGrlKbc6iiBUqaj
         mBfsngRYDsxiBfM2hN/AWrGcc0mClzL31O9h1cyOrtkiF4WHuzmkjyFISSgnTWhKzFC9
         yip4/fsqeTMMkCbcqx5qAGh7I3aKzspsN1VuCvLL/MtN6ZQN830Fw23Mp1kPGr3UlAU4
         GApg5aoFSdiCnk6FJhAVSukWbx3vhOLOZ9xG6ntnkMN0nSHxuGPZqLJ1UgCwehbVfHsn
         X9zA==
X-Forwarded-Encrypted: i=2; AJvYcCWG56BZWgKUScljlM+tZu1y354iw9P8lA9HJAzyIhYeK9au+jLX95jgqS0i7tWYINNiQzsBGQ==@lfdr.de
X-Gm-Message-State: AOJu0YzfnqhteXXnfm92DYsZdWmmG3YAI/Vm+qMLWNSaBDR6n9++htu1
	fAsrzGQ8OGSBq2qyK+uGnBMrdsRiRVkc0cfoCyvi/9x/zUmGc57wadnO
X-Google-Smtp-Source: AGHT+IHKv6IXfqMyvg2lEYvAZJ414rL8vz/RzXlY5DIHg0UBFS1yskrQMvnPdKjouWd+hFhEZkGuAw==
X-Received: by 2002:a05:6871:7b02:b0:2c2:30e9:b15f with SMTP id 586e51a60fabf-2ff26a255aamr3547700fac.20.1752261725726;
        Fri, 11 Jul 2025 12:22:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeHICn1ONHoE4h9JKFge2GuqYwyiaD5WUGraz5Grzh27Q==
Received: by 2002:a05:6870:37d2:b0:2d5:b2c1:db0b with SMTP id
 586e51a60fabf-2ff0c94e9c8ls937102fac.2.-pod-prod-06-us; Fri, 11 Jul 2025
 12:22:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUxuk0/KR5+LP+C9Xi4Z88eRNSWJ2DmxpAhQ+/nicb1F1G+ny0QC2GBspUO8ciIG7mRTwiWoKtjlqI=@googlegroups.com
X-Received: by 2002:a05:6871:5293:b0:2ef:14cc:caa8 with SMTP id 586e51a60fabf-2ff2683c72bmr3428309fac.3.1752261724804;
        Fri, 11 Jul 2025 12:22:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752261724; cv=none;
        d=google.com; s=arc-20240605;
        b=i+gglWff9GwD2neOtfzsOj7+KK3yIEhS5z372ME0mZMp4pUgZqMe//vVKZi1bIywEm
         6GVX8Qs3w9xX/02gZxSj0ts6TWhYA0v0Jb2dnREcvvAdRO8HgRQ/uIk0P4x4xlVOzjhu
         EXW53TWf22+1wz0xDF0jkxGZ+TtUTowDRoBWI92aOZIL0iljVxIfqryJ+7MsFycWVreh
         y95tMsUs3dOoqVTLJAME5t/8c0n8rs7BUGnkbnU2cmfP/VCP0gEcz6SNa/t1IU8Cn8/5
         gbPzIVDLDQ37BAVPw9LrpMcvYSF+g3UffAKDRC+W6zb67TV+SdL6ufsRA/VOZ6RpO75j
         3nUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=1kpsaSG3yQHxnE3KhywpzjrmaxDbT7HL8ur2ohsCViI=;
        fh=2OGjSb/oY7qaqI+h0DEYF1US8wtZ6PYcMwUX6GL7UKE=;
        b=Y388JP4Ett59HKhqhqY2w2ZiuEqEAN/Ea/c+GjJQpZBZSR5qFGlygbW+0Im+zDW0SS
         8RV3uv0ptTvkAySgJpFlvOuZGHWFRSsUlAg/OJkZ35JB4MsulHaOoFHTHL/WPnXJTdUt
         lStRpynttgd+mRrnBiiuwjToW47rPIqqR4sU5Is3uV/Jm7+7zxFOcHHZJU8t5jyHt0eU
         lzmPjVIQbDYdvv5YNu8q5Uvp7ZT6j9Cg3ZBViKFGznEhJe5us5dx7lXcalDeU2gCoKzl
         JpvZH8xaMdFcVcmc/mFvtLbo2iFwcbTGRID2CV/g3CwWRbFGZPltdUMCgTLQmeCZX9O8
         fI0g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Lcx+bn6N;
       spf=pass (google.com: domain of alx@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-73cf10745f6si201865a34.2.2025.07.11.12.22.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Jul 2025 12:22:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id D35B761425;
	Fri, 11 Jul 2025 19:22:03 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D9CE8C4CEED;
	Fri, 11 Jul 2025 19:21:58 +0000 (UTC)
Date: Fri, 11 Jul 2025 21:21:56 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Laight <david.laight.linux@gmail.com>
Cc: Linus Torvalds <torvalds@linux-foundation.org>, linux-mm@kvack.org, 
	linux-hardening@vger.kernel.org, Kees Cook <kees@kernel.org>, 
	Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Rasmus Villemoes <linux@rasmusvillemoes.dk>, 
	Michal Hocko <mhocko@suse.com>, Al Viro <viro@zeniv.linux.org.uk>, 
	Martin Uecker <uecker@tugraz.at>, Sam James <sam@gentoo.org>, Andrew Pinski <pinskia@gmail.com>
Subject: Re: [RFC v5 6/7] sprintf: Add [v]sprintf_array()
Message-ID: <327bas45h6nu7jsrod2qnekijq4xrztddzb4wbl7avkquwvwrs@xpwtrozq5o6z>
References: <cover.1751823326.git.alx@kernel.org>
 <cover.1752182685.git.alx@kernel.org>
 <04c1e026a67f1609167e834471d0f2fe977d9cb0.1752182685.git.alx@kernel.org>
 <CAHk-=wiNJQ6dVU8t7oM0sFpSqxyK8JZQXV5NGx7h+AE0PY4kag@mail.gmail.com>
 <krmt6a25gio6ing5mgahl72nvw36jc7u3zyyb5dzbk4nfjnuy4@fex2h7lqmfwt>
 <20250711184343.5eabd457@pumpkin>
 <uipobgcwwyzsq5dtq3wf6haoae7zgwjfefokbwx5nx6wfx5uq2@vgpl36ryhkel>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="c5hzqt4435udh3dp"
Content-Disposition: inline
In-Reply-To: <uipobgcwwyzsq5dtq3wf6haoae7zgwjfefokbwx5nx6wfx5uq2@vgpl36ryhkel>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Lcx+bn6N;       spf=pass
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


--c5hzqt4435udh3dp
Content-Type: text/plain; protected-headers=v1; charset="UTF-8"
Content-Disposition: inline
From: Alejandro Colomar <alx@kernel.org>
To: David Laight <david.laight.linux@gmail.com>
Cc: Linus Torvalds <torvalds@linux-foundation.org>, linux-mm@kvack.org, 
	linux-hardening@vger.kernel.org, Kees Cook <kees@kernel.org>, 
	Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
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
 <20250711184343.5eabd457@pumpkin>
 <uipobgcwwyzsq5dtq3wf6haoae7zgwjfefokbwx5nx6wfx5uq2@vgpl36ryhkel>
MIME-Version: 1.0
In-Reply-To: <uipobgcwwyzsq5dtq3wf6haoae7zgwjfefokbwx5nx6wfx5uq2@vgpl36ryhkel>

On Fri, Jul 11, 2025 at 09:17:28PM +0200, Alejandro Colomar wrote:
> Hi David,
> 
> On Fri, Jul 11, 2025 at 06:43:43PM +0100, David Laight wrote:
> > On Fri, 11 Jul 2025 01:23:49 +0200
> > Alejandro Colomar <alx@kernel.org> wrote:
> > 
> > > Hi Linus,
> > > 
> > > [I'll reply to both of your emails at once]
> > > 
> > > On Thu, Jul 10, 2025 at 02:58:24PM -0700, Linus Torvalds wrote:
> > > > You took my suggestion, and then you messed it up.
> > > > 
> > > > Your version of sprintf_array() is broken. It evaluates 'a' twice.
> > > > Because unlike ARRAY_SIZE(), your broken ENDOF() macro evaluates the
> > > > argument.  
> > > 
> > > An array has no issue being evaluated twice (unless it's a VLA).  On the
> > > other hand, I agree it's better to not do that in the first place.
> > > My bad for forgetting about it.  Sorry.
> > 
> > Or a function that returns an array...
> 
> Actually, I was forgetting that the array could be gotten from a pointer
> to array:
> 
> 	int (*ap)[42] = ...;
> 
> 	ENDOF(ap++);  // Evaluates ap++

D'oh!  That should have been ENDOF(*ap++).

> Anyway, fixed in v6.
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/327bas45h6nu7jsrod2qnekijq4xrztddzb4wbl7avkquwvwrs%40xpwtrozq5o6z.

--c5hzqt4435udh3dp
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iQIzBAABCgAdFiEES7Jt9u9GbmlWADAi64mZXMKQwqkFAmhxZFQACgkQ64mZXMKQ
wqnkGBAAjriK3UgFz2uAsA2nQ5DSYgg16hTsoy9M6VaKntUP8JFaRNe4TB4xm5UA
/BrfAEO0CKqsO3bz9YLPzmvUlTTwoCDA05ywKnX19tG+DW5Ir0Dar9yqjqid5i8T
GuC7z6Y7xujsmcqTBb/6xu7o9g7Ac6dMrRdfSBDlWuIhRtczjpJTzazu6+ONmcdM
twvcEs4qftRs5JNls9bfCQfrkemdDR4SKNEQdlwk6tRRBnQgEMUlqfxMxuXNelvX
FmKgytE3bSPjRiZRi3zLIBcs7n3XgLMCdzF8UGIbtVq724Gr2CQ7sr/apwbrjGbp
Nj16mXhdDg5kroRpnOnQ0rT5nP7PzXpcK1IeAlUCozPilCrZ9K0esN7COdzdJBEx
03r9f22R0Z4PXCbwMmQ12gCbNbMzFiLH5urJe1N14vBGHdx5TihXP0PuUlmKNm4e
yaCqb2qwCQKvInTgogO9xnhU5DwPAso8h6gBAidNmUYW5nLL1EHoHWexH0rYC0BB
44yFitPtS7ig1l6XY9I4bIewN7WI6YKLz7ywe57y1cbC5uiTcRXY8U3K/dNmztHn
OW60sRMFBdaKWAYfSUMHMIvQwGNPp9LZGrDMLZYsSr4mg7A2/ZjXOevL8MK9AhrL
2oWZjrjrAa+ZT3srhAcQwpZUYRoonAVTgzi6rHWaUa/Vnm1MrTM=
=OO/t
-----END PGP SIGNATURE-----

--c5hzqt4435udh3dp--
