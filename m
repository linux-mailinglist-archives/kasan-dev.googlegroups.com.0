Return-Path: <kasan-dev+bncBAABBSFOWDBQMGQE5DGBIRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id DB3AEAFBB2B
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jul 2025 20:51:53 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-6fb4eed1914sf79025656d6.0
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jul 2025 11:51:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751914312; cv=pass;
        d=google.com; s=arc-20240605;
        b=X0CB+X8LMjuogspqnpzJdzxT5xGbfxVkw0sy4rixZbLgXd2FoXaG9eBfCZDj/X8lIs
         MSwrdk4PQ8Y8LuFRR86fO+hvBl6UDGAgVBH89V3A9qxt7/bjcg5FBVoGpnENu2AriqMf
         P35OEL0CJ6OJZiXB/MjjV4fGGGWFPw+cnx/lIgPuogXvX52iSe/9R2+6jZCnEMHvKHa3
         a8bxdPu/xcYJbqPH9Wpm0I1meOL2anYApDJrxFEauj5oCcg7zjm11Bfi8kWaXhZzpbaT
         CsbWF7S2CkceQ7wBmMH4bPBanaK1GCGOL2pNbv6hWHgzL7o9KqTumfJ2EIAUhwP1zVzb
         2yBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=AVr74B7e8iJ2QElU0+BMQ8tzS+s5NsTvURg1MI7njhM=;
        fh=eE82AKSmBK8MaekLOTG4LlTUjkjpjEdnMIMZkvB4i0E=;
        b=k5x9B4UtrE+sGRmMzx2se/M6eLHqSt9s6BsAHHNL5QmWIoghzeOO/sWOU6HJCA44HU
         RkhPmI87O4Z8UYwkNPpuLSPy5Yds7+Fb8t3FFS/1Kp28Y/pnhDeTpWZtYtbBMEiF281W
         +FvfNLtBWoSSoFU6Klqd/NJM94QooC7RXLKynLwsR2u0E8wABfHA83UuJIGvRlhhE+sv
         77EpcmNI6TjfUmmkcFAGeUoH83hn/rsA8lSN1eFviqmyDlk68d+AeqeMCvM3NMFqA8Lh
         ABurNeTpaDH8ziujBl6WSS2cZJE8KGboM/9J2NZir2lBAqcuzf2Cmg32Rc2IJuE7X7Oc
         JF6w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=TTLwsxqI;
       spf=pass (google.com: domain of alx@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751914312; x=1752519112; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=AVr74B7e8iJ2QElU0+BMQ8tzS+s5NsTvURg1MI7njhM=;
        b=mVMVns5zcVRRXmIjXhiumps5dJwKtd/vAK6s4p/9QKRUS4Yvxi8nmSTC5fsmKJieuC
         rUu6W+6cpVLm7Ofs9w2BuYhhvJ+otQtixoPXQZucPZFTMYPrRDa0km7BUjE0qDxXWq2y
         +ZGTjV3GOuEGC8shXMGWrHx4U81SHne7e+B53cowhN7Y2gvxrQhIhDr1Hi/mUTJh56Y2
         pR4tjBvhPR2zd0bswJ7QzNncAaTLxb/PdgXetLBqkqac4vohAqpBUfFV442gtOg4mTIP
         urbuP2L5WRkdFG4qAVG+xxDfTPhG8BuZ7qcxeIPWpOHyqKC+YP0GIMzC4S8DRI7qqD6o
         DBpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751914312; x=1752519112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AVr74B7e8iJ2QElU0+BMQ8tzS+s5NsTvURg1MI7njhM=;
        b=M41t4HxwKgJlBhO2Pq859GGyynpl6AdLSf2W+9naNRP4nQ9OR2O3nUHA48AcmMlvOu
         mw8UtTTB9Hx1/FJNu8FZTsrXS93nb32sXxDmps8CotF1Zydg4nvvjmFHuqNV65tzUerm
         v8ZVcFY17hWgc4y8WC9Kz7wJIlHRygi0LrzzC4wMETR5ZXNC/UoG3/dZrm7zFJO+J1J0
         AgVP6ZcbpP7Ct4PujyMghDEbZo3hLAW0rSepAy8j3KzeQa3CYDITOwDfBkTWISGrU9Rw
         nXx+njl9GTYBLl7iRPa1FHS8+PXAMJjIBO+ErCjGtlYsQ3VAQ/sNYwa1W9tsDWhB1d6g
         mZbw==
X-Forwarded-Encrypted: i=2; AJvYcCViothY3NoN1+qheiIxljIZ8KdYbl8LIi76PFPjsaOYFKe0gwh6RZpyDaAgcmkqfsG7xfNTlw==@lfdr.de
X-Gm-Message-State: AOJu0YxmZ1uifBWbnhDKtbFUWiIRDx0mm/XXzAl2y0x5wAamwXoM9qH2
	pQIRa++py1+Hixpxqm56dFBILeb+Z7XAjIF8PyIEGWr26KMVLQPLUrV5
X-Google-Smtp-Source: AGHT+IENjlmTrVi0pnS5QpvLSyWv/C6xJMOC42ne4mIBfxDtBnwBx76sOtTYad01Tdsudnk/3QD+PQ==
X-Received: by 2002:a05:6214:2405:b0:702:f45c:e535 with SMTP id 6a1803df08f44-702f45ce5b9mr85244806d6.42.1751914312484;
        Mon, 07 Jul 2025 11:51:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeq8HcVW5UukHMUO8sSwynX2fTeyZuF64yJ1L1tCNUvZQ==
Received: by 2002:ad4:5aa8:0:b0:6f8:b50c:910 with SMTP id 6a1803df08f44-702c9d44941ls48995086d6.2.-pod-prod-09-us;
 Mon, 07 Jul 2025 11:51:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUqfzPP9Yzy1cSlMf31VPSA9Uz+JORPPFQhT91vdn7u0ai1+o1Irq60JpwEPLtXQDKrGAOmnB1jZ+Y=@googlegroups.com
X-Received: by 2002:a05:6214:5406:b0:6fa:d8bb:294c with SMTP id 6a1803df08f44-702c8b7e048mr245757106d6.14.1751914311452;
        Mon, 07 Jul 2025 11:51:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751914311; cv=none;
        d=google.com; s=arc-20240605;
        b=Dna3Yy2q+PG/wCmyHKC9ivedlK0fswWsMyZsYudgOXjr5pk5cAgIssZzPUwBY9bcuS
         +cEIAIxFlZy3iKydbIGLKubv4wtENjk2XmHa+whyGWE2JzKGfXH2e2oFo2W6KZ195XGR
         j+96FOd4eprDurEspICMpriomB7kEVStiAK6Fvq+zjW0gOe9kTBWW8j+JO+PCQWXtfFM
         XeO70JDt2fQ2un4AIRQc/l3pS1bQHOYbpjmeOAQjiY+FcBCI3z8bDzyLoR5tz3VDG5JT
         NTJnXNpXR0NmYMr+wdPwgv5R7iXtdypjnhHg45tuX1QDwt2gBPEjpwo2HQxhUIgR9qAC
         C8kw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=4drFWszOgT5mKQvTeLRTeOBeTllmRsH9F96hokWD8LE=;
        fh=ZFmqDGIg7cn7OadhPwrJaXrZ3b0GVPkdcyJRWc1zL1w=;
        b=QOeUFl3RU5qI0/fjTLFgkBtOFMrKVqXIQPF7M1I787xytcQvqAPvqtqJATwmDXiDEG
         o5cCGcKynD9QNBn+O2KXpcLA1ly+5YJqlmmPm5O/LHXt6rhbTpNgm9RHWzqTZuaFwlbE
         ZTDUb9Iyt2QMC0+HbeYScS5DOiRSbor2Ck/xCwxnx5Sller4WVViBR9tfgBpyF6bVYpZ
         E5/yuUAbrrbkJVDGHbkcPWpltWZalk6rJUuhXvDhmsy5a/50WZ/0U87UXbDDijFhf53p
         rvNfOxFIkDBSX4KvHc0yHoCGBRSWmZowOaQR4RgaidQ453q5sWF/lq7Jfk77UThbZXix
         LFeQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=TTLwsxqI;
       spf=pass (google.com: domain of alx@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-702c4d1a451si4117726d6.6.2025.07.07.11.51.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Jul 2025 11:51:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 7EF4F61454;
	Mon,  7 Jul 2025 18:51:50 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7461CC4CEE3;
	Mon,  7 Jul 2025 18:51:45 +0000 (UTC)
Date: Mon, 7 Jul 2025 20:51:37 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: linux-mm@kvack.org, linux-hardening@vger.kernel.org, 
	Kees Cook <kees@kernel.org>, Christopher Bazley <chris.bazley.wg14@gmail.com>, 
	shadow <~hallyn/shadow@lists.sr.ht>, linux-kernel@vger.kernel.org, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Sven Schnelle <svens@linux.ibm.com>, 
	Heiko Carstens <hca@linux.ibm.com>, Tvrtko Ursulin <tvrtko.ursulin@igalia.com>, 
	"Huang, Ying" <ying.huang@intel.com>, Lee Schermerhorn <lee.schermerhorn@hp.com>, 
	Linus Torvalds <torvalds@linux-foundation.org>, Christophe JAILLET <christophe.jaillet@wanadoo.fr>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Chao Yu <chao.yu@oppo.com>
Subject: Re: [RFC v3 3/7] mm: Use seprintf() instead of less ergonomic APIs
Message-ID: <gvckzzomd7x3cxd7fxb37b6zn4uowjubpyrnvj7ptzz3mr3zq2@xovzgew63mxr>
References: <cover.1751862634.git.alx@kernel.org>
 <033bf00f1fcf808245ae150346019aa7b997ea11.1751862634.git.alx@kernel.org>
 <CANpmjNMPWWdushTvUqYJzqQJz4SJLgPggH9cs4KPob_9=1T-nw@mail.gmail.com>
 <kicfhrecpahv5kkawnnazsuterxjoqscwf3rb4u6in5gig2bq6@jbt6dwnzs67r>
 <CANpmjNNXyyfmYFPYm2LCF_+vdPtWED3xj5gOJPQazpGhBizk5w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="zymvzrfpwpjx3twc"
Content-Disposition: inline
In-Reply-To: <CANpmjNNXyyfmYFPYm2LCF_+vdPtWED3xj5gOJPQazpGhBizk5w@mail.gmail.com>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=TTLwsxqI;       spf=pass
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


--zymvzrfpwpjx3twc
Content-Type: text/plain; protected-headers=v1; charset="UTF-8"
Content-Disposition: inline
From: Alejandro Colomar <alx@kernel.org>
To: Marco Elver <elver@google.com>
Cc: linux-mm@kvack.org, linux-hardening@vger.kernel.org, 
	Kees Cook <kees@kernel.org>, Christopher Bazley <chris.bazley.wg14@gmail.com>, 
	shadow <~hallyn/shadow@lists.sr.ht>, linux-kernel@vger.kernel.org, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Sven Schnelle <svens@linux.ibm.com>, 
	Heiko Carstens <hca@linux.ibm.com>, Tvrtko Ursulin <tvrtko.ursulin@igalia.com>, 
	"Huang, Ying" <ying.huang@intel.com>, Lee Schermerhorn <lee.schermerhorn@hp.com>, 
	Linus Torvalds <torvalds@linux-foundation.org>, Christophe JAILLET <christophe.jaillet@wanadoo.fr>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Chao Yu <chao.yu@oppo.com>
Subject: Re: [RFC v3 3/7] mm: Use seprintf() instead of less ergonomic APIs
References: <cover.1751862634.git.alx@kernel.org>
 <033bf00f1fcf808245ae150346019aa7b997ea11.1751862634.git.alx@kernel.org>
 <CANpmjNMPWWdushTvUqYJzqQJz4SJLgPggH9cs4KPob_9=1T-nw@mail.gmail.com>
 <kicfhrecpahv5kkawnnazsuterxjoqscwf3rb4u6in5gig2bq6@jbt6dwnzs67r>
 <CANpmjNNXyyfmYFPYm2LCF_+vdPtWED3xj5gOJPQazpGhBizk5w@mail.gmail.com>
MIME-Version: 1.0
In-Reply-To: <CANpmjNNXyyfmYFPYm2LCF_+vdPtWED3xj5gOJPQazpGhBizk5w@mail.gmail.com>

Hi Marco,

On Mon, Jul 07, 2025 at 04:58:53PM +0200, Marco Elver wrote:
> Feel free to make it warning-free, I guess that's useful.

Thanks!

> > > Did you run the tests? Do they pass?
> >
> > I don't know how to run them.  I've only built the kernel.  If you point
> > me to instructions on how to run them, I'll do so.  Thanks!
> 
> Should just be CONFIG_KFENCE_KUNIT_TEST=y -- then boot kernel and
> check that the test reports "ok".

Hmmm, I can't see the results.  Did I miss anything?

	alx@debian:~$ uname -a
	Linux debian 6.15.0-seprintf-mm+ #5 SMP PREEMPT_DYNAMIC Mon Jul  7 19:16:40 CEST 2025 x86_64 GNU/Linux
	alx@debian:~$ cat /boot/config-6.15.0-seprintf-mm+ | grep KFENCE
	CONFIG_HAVE_ARCH_KFENCE=y
	CONFIG_KFENCE=y
	CONFIG_KFENCE_SAMPLE_INTERVAL=0
	CONFIG_KFENCE_NUM_OBJECTS=255
	# CONFIG_KFENCE_DEFERRABLE is not set
	# CONFIG_KFENCE_STATIC_KEYS is not set
	CONFIG_KFENCE_STRESS_TEST_FAULTS=0
	CONFIG_KFENCE_KUNIT_TEST=y
	alx@debian:~$ sudo dmesg | grep -i kfence
	alx@debian:~$ 

I see a lot of new stuff in dmesg, but nothing with 'kfence' in it.


Cheers,
Alex

-- 
<https://www.alejandro-colomar.es/>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/gvckzzomd7x3cxd7fxb37b6zn4uowjubpyrnvj7ptzz3mr3zq2%40xovzgew63mxr.

--zymvzrfpwpjx3twc
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iQIzBAABCgAdFiEES7Jt9u9GbmlWADAi64mZXMKQwqkFAmhsFzIACgkQ64mZXMKQ
wqm7pBAAp0OWYMffe4VFeySMyLKfBxSElLM0oKkc8hXHHJmYhodncUpDMxt6a6W0
v3YW6LRCH20Pc1pEj4acCR5smdKJ3vXplvkoHKfKeCRlDL2nWTPG6ped6udUMbxp
i9dz4jMwv+XNZccdN03NF5u+o0f4VF0KQOntx0wcGlqg1yvWlp2yg29oTJ5J/fim
pZV/5L1lggzVnkHCze1+kXY4q6ZKko/olwgOhs4NXOQwVC5oxjBI7BUQX9e61Cca
EJ8EVgQLDyzx9O4UhpXmztx+6fzdJLewN2RVfVScnMHF3wLniIa9ZyiwKZHpeeP+
1a3qfy3o/gO0G/KLHpB4RQEdS61jzZxtYgbMYTqxID6QT2j3fTmCpS+nySEtQ8DR
A86GlXYQlt/6HCp3K6ixmMOiTf7YOuFJkapw1T2zM1YZHMa3euxwEdLYwG+hiri1
ZIt5AQP4CGpy90d5PTzZFGxqOdHELjws+oiU3zFXPDN/p2AepkOtSDU75ohaq6Kh
PaK4Fu0ixILfKDRAhOKBDqcwz8eVzWEgAHV/PzksR/+nYBqUj8I3lPqLpu2eQTkV
a/cHEPj7iu8nV0vdlO8CXzH5C9IM41eLSBGf3i7Hl+TWrRXSCq3pJMDp6rWM/52m
R+nNX4VzpE4SfBI9jemyj2HoT7dA6uyaXQV2a2PrNS+XMnbkXOI=
=h4vO
-----END PGP SIGNATURE-----

--zymvzrfpwpjx3twc--
