Return-Path: <kasan-dev+bncBAABBYUFWTBQMGQE5PYTBBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id C953CAFC9B4
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Jul 2025 13:37:07 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id 3f1490d57ef6-e819f79d125sf4968549276.3
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Jul 2025 04:37:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751974626; cv=pass;
        d=google.com; s=arc-20240605;
        b=iiL1bmDQZzQcw95ExXeGIWcTWBrEMLDCQMhXzOXPDu/dmwDOM5bVmEOQcPsgX1fckt
         navkzVRz/Mok99Ak8DnLgVAXmTMd3s8V+vgv8oOBGU4e5fkB4yhbsF9IrVz+PcTVn6Sx
         UQBGgDwvTNtcjChjts1naYHSPzqdXla/wZT6KhDZys5HYY5YqKL14aeJOALVcUKx6lAP
         UTatVlu+IQB3tZyORNC/YsikzdGX12rf86HacHUUTszEW8syPBkuMFnSuNX32H1tO64D
         oE/m78HEIDzHSfUbS+Pv5ng0iE+RMnOtMURQvpzVxKBuk1pQU/Q7FBqVvefv+3UVo0aw
         QD1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=yAcYZqFOaQbBfOaHDfrZpYglqgsW/LIMNJCdZfrnGDw=;
        fh=PaEAiLjhUNRAgXu2ugBwKVYhAiO7eDcfaUmyaZ+csqY=;
        b=IFvKrsYSs3ZaYw2lZrrEcwLIAN4bdN1gbMHNY0E1WvVcX1+6NUx8uWNYvlxxgMvwb9
         i7IDNm6NbSVQgvd7vwZCnmkiXMBYNYqt2mLxIXwyPiS6h/cRD5nkFN7iRJ9/J/LeR0xO
         0pbGtQVtQ1025+XDv0+0QVpZB1U3eKvudmxxZH9klPg3xv1Eb4KfDpATA6uzyH/0rWbD
         NixxMOztljuCmSUs2wNDlOpoNP/gazktiRQXq5RLQ0aCXb2nLZhmRcAZFXGOFtRq1Pqr
         CYjDIkwjhXnfGDUfXmYDSygZrWcbksKPzp4Hy2WoFnsIpVfqn9zLyfggxQYuycOC3UOT
         U2Fw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Kqh+LDrT;
       spf=pass (google.com: domain of alx@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751974626; x=1752579426; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=yAcYZqFOaQbBfOaHDfrZpYglqgsW/LIMNJCdZfrnGDw=;
        b=wC6X1Ky0JLX0mVgZTp0H3ghZtJcGb7/EqwGnsVtTMnk6sZfKSyz4jFan1JgkKrtoxm
         Wx/oysZzhYIrZZtL8J80dybsHuzAHKS5mDT2Tp6SyL36c7DP618IXdzqWiKZo5aMFmJl
         vu8RVN44V7eSdKvj9TgIn4c4mbz8TZfcxuh4G2TleFmo6M0jIZf5nVS6PZS4PdsfGXVT
         0raFCjK1jhaH+lsXabFpVXebHIwuPllEr+Q+VWwPOQiuuXoL6vQv1QT7WxLvO0LKVJZe
         IyvIxgd4xss9qveQZPz2rCUWoLjYVRqUbYK9nRyFiYNH7tpXQ/Od1lRacOmvnY2j/6Qu
         NNYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751974626; x=1752579426;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=yAcYZqFOaQbBfOaHDfrZpYglqgsW/LIMNJCdZfrnGDw=;
        b=wnWdtJawYwW4OY29DNJsr2ZiRqmmztdRV9mMJzIG/HuBoIB/7bli+v6Y7pschZTUoH
         BrOfWn9AGzQRvFCvWbWGLqPJmAdOwrsNqx7N7/DQz4CLNDw7o10UZMJ5+i9tvm2Dm81N
         kqC+mr0lEXqeudepz09Iql5XwczfgN19b80Jb5RvIn8fbz3dVBvLl0Pw3QRIaKS51Edh
         h/cjUP1W4cUOFGkxrDsQDtJqdmWtwwP4KY1S4yZjEIOTi7qiynhZfvXb3fgbybhI4hiZ
         Tq9SI3Y6CXNJ4I6CO992SVe5cvej272JgfDXAP73JxKCQTD2D3gHXQo/lc6PeOzZH0q0
         6c4w==
X-Forwarded-Encrypted: i=2; AJvYcCWYlQxJL91Bl742RBmTl0Mmp7x2sxm+FnRXQSWSQQJP/OACELs9dv3dkMsW8FgCUW7bFIoxOg==@lfdr.de
X-Gm-Message-State: AOJu0YzfskSmeSnq6hZ8WnxIzXFty4El+8smsGXv0XHPknxQOTW/9LLW
	OtECZL01XQ00wh/hHBMD+aLOxHtAwQQj1Boia0nNqxxiHlBKxDrRD86/
X-Google-Smtp-Source: AGHT+IGW3Urj7LboWh98m3LFKOWxkFCJFgv5TcFmfNLR8zo5W7iUFOb0ZBDzyc6AMPZukzfoY7a0Lg==
X-Received: by 2002:a05:6902:1144:b0:e81:eb4b:f1fe with SMTP id 3f1490d57ef6-e8b629f5d18mr2974763276.9.1751974626283;
        Tue, 08 Jul 2025 04:37:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZew/Ohi1Gx3NicfF3MqB8hCGfdipOBIh6AYh20Sxv3TxA==
Received: by 2002:a05:6902:4282:b0:e7d:8991:61bf with SMTP id
 3f1490d57ef6-e89a3870a21ls4131477276.1.-pod-prod-01-us; Tue, 08 Jul 2025
 04:37:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWlNYXq7O3vQ2FO+I051HYdzpQPcLQAydCDYxT4OYfiWmGMamRVVfDljh+wxwb1oQFt6Jbu7aXq534=@googlegroups.com
X-Received: by 2002:a05:690c:311:b0:70e:779:7e6a with SMTP id 00721157ae682-717a0405bbdmr32080857b3.22.1751974624529;
        Tue, 08 Jul 2025 04:37:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751974624; cv=none;
        d=google.com; s=arc-20240605;
        b=bgK4EbiaPYBL279icWgQ7q3T9Bkry12DqXTpUloDGCsydcJ8ffqjowrWX10ocUQnzV
         RZe8Rm6Mr29xTfQHhokr3Fv0NpoHmr4/YDluADDa1zlcff58cSxQk/To9YXYTuzEQyF4
         qmCqhCe9tk4Q+WegHYXS37HRDhivxMBwNDUEqzG79lkjN3pSz4/QH3Y5u0S2lnhvXbE3
         kIIjym46qqsto9c88k9h6A2xlybwKB8BCE10H33vTFvdqsxAP2Pb/oSGLsDBkPnx/DN5
         9BbjkYnyroKzIhpYK4b5/exNuAJmk4J2oqetNJ44Y1U4jDO1vyuwCI5AqlXShYqJuEC1
         afug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=knexG6brHCg3eooqX8hX2Ylbvf2JPs1FcC/C1VzNkJQ=;
        fh=dyVddJ4ioll5zQWyJsUIfnKP91wTBJRhYoGWALTgmks=;
        b=ewOrySL1wOqzL2euNDsQhZ5x/rblYtJKsXwYzq0DLrpDpOy/X0zFD8jjGriqlaPflt
         Z6qe6Kxr27feGQZJn4YX20JcBMT0m7yVFphSi2yuu3XHmupub6G/pwFoTJuogfecoo6S
         X8deI4NtsDfUoAnufggO2CmxufW10gixi+kSA2s6mlqUubx9gsT3q7cP1WvX9T7i3WaS
         Hkz5ZleAH7D/ldyIDTMbMTMXyHsVKlAkm7r6HSfVsaLhUA4bjyD8LPqcgvsZ12Uo+i7f
         EZakzIdVNjA8uuD8KDNRyLmCmKabm10gQJGy9JGSbKMKcDUSw4dUwLBn//7MwYgxanzN
         FJXw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Kqh+LDrT;
       spf=pass (google.com: domain of alx@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-71665753a1bsi2796517b3.1.2025.07.08.04.37.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 08 Jul 2025 04:37:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 30A4AA532E5;
	Tue,  8 Jul 2025 11:37:04 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3D0B9C4CEED;
	Tue,  8 Jul 2025 11:37:00 +0000 (UTC)
Date: Tue, 8 Jul 2025 13:36:57 +0200
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
Message-ID: <ez7yty6w7pe5pfzd64mhr3yfitvcurzsivjibeabnkg457xu7x@tkompzcytwcj>
References: <cover.1751747518.git.alx@kernel.org>
 <87a55fw5aq.fsf@prevas.dk>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="yu7ixni4xjxoijgm"
Content-Disposition: inline
In-Reply-To: <87a55fw5aq.fsf@prevas.dk>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Kqh+LDrT;       spf=pass
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


--yu7ixni4xjxoijgm
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
MIME-Version: 1.0
In-Reply-To: <87a55fw5aq.fsf@prevas.dk>

Hi Rasmus,

On Tue, Jul 08, 2025 at 08:43:57AM +0200, Rasmus Villemoes wrote:
> On Sat, Jul 05 2025, Alejandro Colomar <alx@kernel.org> wrote:
> 
> > On top of that, I have a question about the functions I'm adding,
> > and the existing kernel snprintf(3): The standard snprintf(3)
> > can fail (return -1), but the kernel one doesn't seem to return <0 ever.
> > Should I assume that snprintf(3) doesn't fail here?
> 
> Yes. Just because the standard says it may return an error, as a QoI
> thing the kernel's implementation never fails. That also means that we
> do not ever do memory allocation or similar in the guts of vsnsprintf
> (that would anyway be a mine field of locking bugs).

All of that sounds reasonable.

> If we hit some invalid or unsupported format specifier (i.e. a bug in
> the caller), we return early, but still report what we wrote until
> hitting that.

However, there's the early return due to size>INT_MAX || size==0, which
results in no string at all, and there's not an error code for this.
A user might think that the string is reliable after a vsprintf(3) call,
as it returned 0 --as if it had written ""--, but it didn't write
anything.

I would have returned -EOVERFLOW in that case.

I think something similar is true of strscpy(): it returns -E2BIG on
size==0 || size>INT_MAX but it should be a different error code, as
there's no string at all.

I'll propose something very close to strscpy() for standardization, but
the behavior for size==0 will either be undefined, or errno will be
EOVERFLOW.


Have a lovely day!
Alex

-- 
<https://www.alejandro-colomar.es/>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ez7yty6w7pe5pfzd64mhr3yfitvcurzsivjibeabnkg457xu7x%40tkompzcytwcj.

--yu7ixni4xjxoijgm
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iQIzBAABCgAdFiEES7Jt9u9GbmlWADAi64mZXMKQwqkFAmhtAtIACgkQ64mZXMKQ
wqmtvxAAmdw883CZToXhH1TBnZ2W4hbKBzvMaF3mq84wKNfBB/CyJKTfWfVNRW9k
yAG58nel0gHuklLCVK2BMCuG7JfNXNIKdUG7bQTGEr8t//QYcx4haFut+xlfph/M
R+lwiw1q4yy3Q/0q97e2WJ/c4eBbWo5D0A6Ggy1bbYYsVY7AagO1ZHnglzVIHf4j
95IiyR5BFCEtVjmaU8gEACNQIVeC6OnpSw385YlumOiXFX+KFBsiipbew0kXre8M
tv+hyM2u3MR7YSWoMsyAheqSZBKz+puMVS4BGhwg8aAdsRSMoUbTRiszW5GJgSmN
iHxFecIMKkyN3pdKm1Ca4MBbBTe7iYQuALQq0I0bZiP/qhkQMFbxSn0ldBL/tsAU
qkB36CF/S784nfKJ4wDKy1UFUQZBdgMVDLuRH/VWxahijzBhsBF/qnIDdmqEEP3q
un7+CRbi8WkPanq8lVYiiixE/BmOrw95LcrYIycQfwxjShQizzDLCSVXA6NN+lVu
Qae7GlLpZ2vmw+vX50Jq76DzpwspOsIbzpypuXy/Y4f36UBeoqfzI/XtUIZ9CNmS
B0bDgV1z094QTghOi7pZSaWqK8FFpb6lUd0a9fRAKihqEoPPj+Xgg1fagOULkLiO
gor9ti3mUbSyRbeVwQAp/kVVMIrnDZSPtFp945FmBvVVjR7XerI=
=UstB
-----END PGP SIGNATURE-----

--yu7ixni4xjxoijgm--
