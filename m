Return-Path: <kasan-dev+bncBAABBKHXWDBQMGQELB5R3LY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id ABC5CAFBD79
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jul 2025 23:27:06 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id d2e1a72fcca58-74d15d90cdbsf1006483b3a.0
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jul 2025 14:27:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751923625; cv=pass;
        d=google.com; s=arc-20240605;
        b=Kp50l4FM1k+dlIZf7sPw7N00HmBl72duIblZ/2KNYua1aJkKUDXvzWApLCq3/1iA0Z
         ugY0Kd/LVBL+VbEe0vA3qNJGE1pbja9Gj+3dWkH9N69NhN8Q+D6W+XAUWY/Jhbn/TWzD
         rdq7xr4rfX19SBewRavjwvQlSuM7oXiu/aoLpoGDyBcUDuI2/IMyyxYDCiHc6nsVdROz
         2faCGrTqDpiJ/PDJqyjdltikiE5t3h+AWD3hOs8nacxtqVmLTaQ9ogaBXQ/MqZedZAvT
         DMueZrzNnOY5ShqKXvakYdjOPpDKcpzIpV28yNWyLG8KIapk3gbIA2OOX2bm/OTJFqfu
         2SWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=t3/awEwZxycGylPIloNP5kzZezMuIZULioelAysB0eM=;
        fh=UBBjss6YTtzyE0enfyynUfoXWJH07dstQc007D94Z2w=;
        b=QUm28j6bWBbWRzsgVzgeMK9G9+g/PR4sDKwWXIxde8/a4WqnijIthhfoOHMlYgXVhv
         pI64Fr5YoeItnwqwobcBxzgRM3gXz5eHBjz/0+9ai9rumvlBzcpSUbH2nNOT0VYI7G6v
         EO53S68ivjOUcskc8CPQOXxHEBXUbhrbO1X3/p67003edhe1l6ccakMslN/hEoQSyfVb
         EWjz1uWVrngdNqMwxh7xZgD5eM5RnW4/C2MEoV7cPuLsysLrXH1eBqnPHZqxHBbR6ls8
         ATcsmA/L/oC6yINulCRUE+426y+mYvGiLy3X3M8F+zoiqIqBi3BWfdJsfyV3blBMoZcG
         iu9Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=TPeaJUeW;
       spf=pass (google.com: domain of alx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751923625; x=1752528425; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=t3/awEwZxycGylPIloNP5kzZezMuIZULioelAysB0eM=;
        b=buIqcckv9SfQ4XNQfyRRWCoLnxOcYvXM+0dBHZWhBGuaeVqSCNo0shZI51ivXB30mw
         SfTIjME0ATswfcXXupfQPMoOxpgvSHXSKd/O3xj8ccJTMVB5+X92rC4f6eYS+Io3E2gK
         pGZRuxKHbQn4JjMCeHnJpCrzcsakdIzvwvOjdPfBlLbxp7e4vlw8ecERC9wW16dINRrh
         H36OXEObLnIW0T2Ohy3i2azBx4kMRy2l6Zni4Ufo/nV0OD93aUsGmtMZdFpzZ7NI/EOp
         I7+ZdMkgIsPS6Y+q7hY8VQQgi9UE9Vy63sCReO7Ij4YCNzE2RD59BQmri1W7yb4761oq
         9R3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751923625; x=1752528425;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=t3/awEwZxycGylPIloNP5kzZezMuIZULioelAysB0eM=;
        b=VFOMLJn7KZL1NDD/6/lkJ6sP24qdHyqlep6hgxF6kU7bl/WLt546mzKVB2Kx5i/r2N
         OYr2I39ybHfLkCu/ZIYltGOHykfi5mEDrQAijU8SNjrrWNPC17s/WueLz9nJFDK/C7tO
         nhop8EhXw9Ra+01I85zSZs7UT0CVdbd1wHgPFXRjIw+w/bDSKlBpUWGC2juGkbED3CZ5
         52FYhWnxjgLK8e3E76OYUXa4lkM4u0MMq1V0fl0K8rDnqVY3XMRS/WWMdvHO7TkdO/md
         o/mKEm2goh2sSezdwfaneOiyT8PFQX7vQTDQLNBiS2TgEl1Rx47VSyue5LKO9/vIC882
         pFdg==
X-Forwarded-Encrypted: i=2; AJvYcCUdOVai4DxHZNVDGYkbRx16fiHRWjLGiDwxEYOuDxb3ZdG1FV6g543x4rvC/wd6ho09XjVikw==@lfdr.de
X-Gm-Message-State: AOJu0YzRBbM/ntn7X2eFTcDjkizKGJg/9HQPmBqla0L9e/sp5685XCwE
	Jk1NqIujudh+AGkHaopNye9qU9yxfaLT7yeMB9FHai3zMb1MArx1d2sm
X-Google-Smtp-Source: AGHT+IGvoO+bCQJJpTc/LswLBLvppkAHUZ9zpxAwZKYJY+fp3pCybuwv7s2BLz4XbXnNZvHeLPOEXA==
X-Received: by 2002:a05:6a00:368f:b0:742:a77b:8bc with SMTP id d2e1a72fcca58-74ce880fec1mr18486964b3a.2.1751923624996;
        Mon, 07 Jul 2025 14:27:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdPDb6GlAKKrd0iAJf3rk/LjpBrpV8DySQpKm8g0m4+Tg==
Received: by 2002:a05:6a00:39a1:b0:748:33e8:bde4 with SMTP id
 d2e1a72fcca58-74ceb5f3c5als2729704b3a.0.-pod-prod-07-us; Mon, 07 Jul 2025
 14:27:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUcOkjy3zEm+A5KewKLoFO625SFzMcSzvTbmafl2q5A/CWP+p7YX5lqSZYjn4TqTCYxJENl0Xio+VA=@googlegroups.com
X-Received: by 2002:a05:6a21:3a85:b0:204:4573:d855 with SMTP id adf61e73a8af0-226092b0ea7mr19868632637.9.1751923623778;
        Mon, 07 Jul 2025 14:27:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751923623; cv=none;
        d=google.com; s=arc-20240605;
        b=ErM46KqC8to5miBRtikFW7i0o/HljEyulC4O5BcvEMT85dsrrPDFHvmFvWDrxo4q8R
         xApnn4D/zN2UIeWERhCDHSfddpSmvu0LdNzzzlHMAWRX7FjAXJLex9fVnBT7wn4EWR9R
         AYOEPs5W7yZO9r4TSs/fFIR6wG4kN7NzNChIW7AfY23axzX1t6Y+srH6KFn8eI6Y36lL
         P2RivjQA8Q4ParjJoVFDXU2YKuSvnVzYFHhpxepzSFvoVXWXfEE3b6wrNjIY2HuNFH7P
         TS6uu9dNY6Fc07kzR5fbHQW5aB9/aphgwe6ExFm4cBCqBoZX3KEQoP7AcYieUUw9uyZ7
         NJ0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=9vG17PwzVFEg+u68Dkxrzb8VDpEz6W3xL8I8qWDaP2g=;
        fh=ZEmjEA+beua0ACHfvGG6b46BenHjaWFbMeK4riMguPk=;
        b=UXYCb8kNHaRLEYxHWmWnqR/e6WxgD7mEIHczc1QbKCxHOsUirIoBOTlUaadrTni9Rv
         vPnWXSqkVFZTOXuIUInQ9xcJExFmI3gslj7zJ4083ZTHoJm9WIhz8oW4GmHcryxgosIi
         iBFUQuGHGzzc83YPU2/y1VJeHtPbUed3+WVoci5d7tOLtAotTs8ABsq/FiR7TBCkEQHq
         beBK9uqxASebWtcruHRjrqOIDpdmXxfj9acKw9uC+GaIl02m7NIciQOI2W9lizpuxhVr
         haLhqm+IPhgmoiyFA7uTklFcXUBmSjb+urPB6JZ3D7VqgAWgL5l7Atw3RGBqID7YiTbW
         AXKw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=TPeaJUeW;
       spf=pass (google.com: domain of alx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-74ce2b05021si324476b3a.0.2025.07.07.14.27.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Jul 2025 14:27:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 6765D44CD4;
	Mon,  7 Jul 2025 21:27:03 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 5FF7FC4CEE3;
	Mon,  7 Jul 2025 21:26:58 +0000 (UTC)
Date: Mon, 7 Jul 2025 23:26:49 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: linux-mm@kvack.org, linux-hardening@vger.kernel.org, 
	Kees Cook <kees@kernel.org>, Christopher Bazley <chris.bazley.wg14@gmail.com>, 
	shadow <~hallyn/shadow@lists.sr.ht>, linux-kernel@vger.kernel.org, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Sven Schnelle <svens@linux.ibm.com>, 
	Heiko Carstens <hca@linux.ibm.com>, Tvrtko Ursulin <tvrtko.ursulin@igalia.com>, 
	"Huang, Ying" <ying.huang@intel.com>, Lee Schermerhorn <lee.schermerhorn@hp.com>, 
	Christophe JAILLET <christophe.jaillet@wanadoo.fr>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, Chao Yu <chao.yu@oppo.com>
Subject: Re: [RFC v3 3/7] mm: Use seprintf() instead of less ergonomic APIs
Message-ID: <r43lulact3247k23clhbqnp3ms75vykf7yxa526agenq2b4osk@q6qp7hk7efo2>
References: <cover.1751862634.git.alx@kernel.org>
 <033bf00f1fcf808245ae150346019aa7b997ea11.1751862634.git.alx@kernel.org>
 <CAHk-=wh9Pqz07ne9iSt1_v0c14rkOGvF9AbEkaq1KnFhQD1SSA@mail.gmail.com>
 <ugf4pu7qrojegz7arkcpa4cyde6hoyh73h66oc4f6ncc7jg23t@bklkbbotyzvp>
 <CAHk-=whQ_0qFvg3cugt84+iKXi_eebNGY4so+PSnyyVNGVde1A@mail.gmail.com>
 <gjxc2cxjlsnccopdghektco2oulmhyhonigy7lwsaqqcbn62wj@wa3tidbvpyvk>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="4tam3kmtkoib67ue"
Content-Disposition: inline
In-Reply-To: <gjxc2cxjlsnccopdghektco2oulmhyhonigy7lwsaqqcbn62wj@wa3tidbvpyvk>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=TPeaJUeW;       spf=pass
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


--4tam3kmtkoib67ue
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
	Andrew Clayton <andrew@digital-domain.net>, Sven Schnelle <svens@linux.ibm.com>, 
	Heiko Carstens <hca@linux.ibm.com>, Tvrtko Ursulin <tvrtko.ursulin@igalia.com>, 
	"Huang, Ying" <ying.huang@intel.com>, Lee Schermerhorn <lee.schermerhorn@hp.com>, 
	Christophe JAILLET <christophe.jaillet@wanadoo.fr>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, Chao Yu <chao.yu@oppo.com>
Subject: Re: [RFC v3 3/7] mm: Use seprintf() instead of less ergonomic APIs
References: <cover.1751862634.git.alx@kernel.org>
 <033bf00f1fcf808245ae150346019aa7b997ea11.1751862634.git.alx@kernel.org>
 <CAHk-=wh9Pqz07ne9iSt1_v0c14rkOGvF9AbEkaq1KnFhQD1SSA@mail.gmail.com>
 <ugf4pu7qrojegz7arkcpa4cyde6hoyh73h66oc4f6ncc7jg23t@bklkbbotyzvp>
 <CAHk-=whQ_0qFvg3cugt84+iKXi_eebNGY4so+PSnyyVNGVde1A@mail.gmail.com>
 <gjxc2cxjlsnccopdghektco2oulmhyhonigy7lwsaqqcbn62wj@wa3tidbvpyvk>
MIME-Version: 1.0
In-Reply-To: <gjxc2cxjlsnccopdghektco2oulmhyhonigy7lwsaqqcbn62wj@wa3tidbvpyvk>

On Mon, Jul 07, 2025 at 11:06:06PM +0200, Alejandro Colomar wrote:
> > I stand by my "let's not add random letters to existing functions that
> > are already too confusing".

If the name is your main concern, we can discuss a more explicit name in
the kernel.

I still plan to propose it as seprintf() for standardization, and for
libc, but if that reads as a letter soup to you, I guess we can call it
sprintf_end() or whatever, for the kernel.

Does that sound reasonable enough?  What do you think about the diff
itself ignoring the function name?


Cheers,
Alex

-- 
<https://www.alejandro-colomar.es/>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/r43lulact3247k23clhbqnp3ms75vykf7yxa526agenq2b4osk%40q6qp7hk7efo2.

--4tam3kmtkoib67ue
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iQIzBAABCgAdFiEES7Jt9u9GbmlWADAi64mZXMKQwqkFAmhsO5kACgkQ64mZXMKQ
wqmfxA//c8S1dBGM6C2xdsVSN9VQGixTM+3FYuFDeOMfw3aJA3T74AUqgcqoNktT
PdHNMk63xbAZwzFx3VVNdNVOtUMBuW70OfoOSFzVMwYYxrnVSoZUE95diweHAPvi
hnPR6uvqM4TDiSpC4nI21I/fAuyQ9SI/E5eeUd23yDzAUHeXkNPCSnvAeiHSmZA0
aaFn53PZV9aljWxzwWXI4ybptt+Zl3Y34ic70IFJ2SmBmzigJ3FOnH4LtOf5JvMl
0zpzJkcUc9ZnhLfPt23qm3hoFzO7QSBNFMqzSdYby45I9ggRgE8Q3CNnvJZswzQ3
bqEzuO/xHpKWU/Ost/Di26ckySPVv9LZcMhLThNlXD/iG4HuHeElInBham9vBsS7
96xpy569tpZT6MJtOPpnZ1S/CKpUbsqCg5Bk0WHCyMLxU3c9RK21BPCkKArtMo0U
loc1IW75iUG3Hyegg2vdalX4synsd1OyKZU6saIyP85Nga+gQ1Ou8gLJngq2Q8JR
dZHpILVaJ4avAIjHrcwWnh3IBmQMphV29hLFxJmPM8fPpPHsfNODJLbrjgPP7ydR
MhHsaP545Yx2j1a3X/CWNFNVYv7S31p9QDz694HMPU0Gdik0LYChP6iEgWexlqsF
p23zq/kpLmR3XELdUin0C1ijMXokwxgG49UWy9nSlnW1S/GnPBk=
=WSVf
-----END PGP SIGNATURE-----

--4tam3kmtkoib67ue--
