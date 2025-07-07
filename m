Return-Path: <kasan-dev+bncBAABBU7HWDBQMGQEGWLE6VA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id A0664AFBCDE
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jul 2025 22:53:41 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id d2e1a72fcca58-74913385dd8sf5049228b3a.0
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jul 2025 13:53:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751921619; cv=pass;
        d=google.com; s=arc-20240605;
        b=bT/PQXlvSP+/7dZIwYPb3CdywhZdA6LsuYKRXOICrnuMLBQdcnLEIx6dEBNiYORZlp
         h9KNvBe7+w5A30GjHxRyjhpQYAD5PAaK3lKlJHki6izOjATusw2k/qcW/cYrLnLZuMAA
         oj5i+jCwmNh68zjQHGO+U3G5nilb9Uu7km4b0Jc4WuHsXsX+AZL7JYgxzvWUo45PBaDo
         vtAqAIZzHdWCWU7CoGbXngBuTeYntSmzOqcPv/NgYIG8UkFQ6LDNVqQuwmgVI2Z6/BLE
         Fvo1WN2H7wetvQ7zFBEY5IBEPGcjJgJgwACd3xxcqtgrfmM0XUL9SC7ttlt6+pOBly9m
         CSeA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=r8AYwhWpGiieJ48vhaVtQd4DI6x4kCytYNn3N5Dw7X4=;
        fh=YVXFjYxVEBHw+j25RAoC4wnQvFDkwen0yvh0svxo1/o=;
        b=dxYSiQUC1KfTkCHsrWHDuyo+WwCAHeLp8eM46cNi82yScWGBWtYfvqxUfDPFxq4FMa
         Is/FyJzW+rKBxqT+ju4GODqPNlGa3w5TdNw1nMin+POzQgdLBVRPseLDaXXISuxKJMQ8
         RYUYtNy3vtI9X/PdiBOxzXrKlAJlF/Q2W/vzgkV22PWpynKmmyK9NYFSoQUN8BZjOlEU
         ujKq1BBfK9gpfMlmR2NLrxYJakJTnYgpr16xX+Z6Q63TZhq9O1kZ8HZCTuZR9etzpK48
         3KiMFrI7TSxiC9J26Vf5x/XRRUx07AePoGoO9EFnctqXNSSdDbrhdZ5x6tLjdSjH6eJw
         3txg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PUJz70kr;
       spf=pass (google.com: domain of alx@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751921619; x=1752526419; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=r8AYwhWpGiieJ48vhaVtQd4DI6x4kCytYNn3N5Dw7X4=;
        b=wGd4e9iTvrkwEKDix9GaOYrAHyylUj+RLw9c2ADkInPO96rZlt8dQC6owEmkb2S4ui
         V37SUzTVnXEjDAjstxsi2jpLOpL3pwRl87YiJhreCaxn+0egZnmfAgwB3HejTvnTXq0z
         9RIqgERatbtrArfqagOBElyoTHGldli3lP38I1OLB026jqdY7IZBvWRSxWTrXkctaJ6B
         vL4Ypo3Hzho6EI9ue7Nd6/wdUStj2HP/cAP4NUYAJpqJevnJrnLT6cS6rWnA3u5yoDG2
         XXyJdKMi5qPcsRRvdJtBWLfVvgZ7W7AIpzrcnsAwB6xbeef6v+Hr8KtT/t3uQoNJaY9D
         VsNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751921619; x=1752526419;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=r8AYwhWpGiieJ48vhaVtQd4DI6x4kCytYNn3N5Dw7X4=;
        b=UW+bmV1kAWmckT8Mdi1MlYRdNe3+UQkWEgV+YtCcJQmeQf/vqwuADj6/I1wNPQJG6c
         VOdxJ/dZmHAyHMCd7SM8qQluwPYRlMikjATip7qCrwxPT5ZLRZFZvTukKTkMwqPgJ7EF
         5Fd04clgOnSdSy4G2rF2aBB1ne8Ci+fMEiSuba5p4nx/PXa7S6NUxB+ZrcCh4f31ZZD7
         q3RMw8lvFIf8Xm53ddGn/hh7qwUz0ZkSn0jWZbDJNB3BmBZWq15vaRGDGSJvEpxFe0ZU
         j5vYQzQ/JYxmG+RJ2YgLsxVvHW/cbeLwEoNEgFw7TeMG1k85XS+7pb+a1y4GnpSWZOMz
         ElxQ==
X-Forwarded-Encrypted: i=2; AJvYcCVUX5PieGNretjESZKXeIlBM2c3nb9bTHlsClnb0ubIbjkLmOA6aJQgpJ5A8s9wXLVJ4ePUVA==@lfdr.de
X-Gm-Message-State: AOJu0YyOzTCOE8KGWLzktRbD76uqcEUyUrQyhRj+FhC/50aOUnt4Kg9Y
	pnGxtW0QIUV7vKgaMM2WMsSROdarnbf7w5gH70abl0pi1MZ93bUyrpNo
X-Google-Smtp-Source: AGHT+IEXdvlY8pOyCwurUC7ZuZbEx5tJtXXg21Gly/njNh7VY70rBpylSSya+gDrLwiO9iqGZ+qXQA==
X-Received: by 2002:a05:6a00:130f:b0:748:2f4e:ab4e with SMTP id d2e1a72fcca58-74ce66697a2mr19642386b3a.11.1751921619350;
        Mon, 07 Jul 2025 13:53:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZehRt1nSItneCMaJILRl4HvTD53+XGuvIf3DVepDlRMGA==
Received: by 2002:a05:6a00:3a15:b0:730:7e1b:db16 with SMTP id
 d2e1a72fcca58-74ceb9cda5cls3197305b3a.1.-pod-prod-06-us; Mon, 07 Jul 2025
 13:53:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWuk1vgWa4VE7O3aUqzW7HlXCYU0zGH1TErBTJbtGsGKZmgH1Gepiv+uxZKcDx15qAYKuvZ3ZVCNz8=@googlegroups.com
X-Received: by 2002:a05:6a00:4808:b0:74d:2312:ca7e with SMTP id d2e1a72fcca58-74d2312cc18mr1034834b3a.24.1751921617971;
        Mon, 07 Jul 2025 13:53:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751921617; cv=none;
        d=google.com; s=arc-20240605;
        b=E+RlY9awEyZRjr8u0A/hCQRf6Yv/MfvEEOjQkNMr6OXpFUoq/mwmSDVZrR+RREfvyX
         SdBQkTMZ1wUdyB/fnF2f2knvICsHp9hkGb961DIsyWLi36L6/tWlb1dcyY8c6PzxtmK2
         yE7u4HgrM39iyPiN54D6kFTHtyl9kokOxYqfuH4wfOY7w0pplkJIkxH3l7HBUN4Lo0pI
         jTfWokbJHD8PMqyd2JflzWzuQFv5GhAVOWfYolRLaW18THnScuN7bZPjD9s7v7k+QlNo
         bkY+R1fe999vYFq2SW6TwVi5eH7OWhU3iUF3D5vCTTVt8cf6e5OqZrcPS1t7dSOBrKk+
         5Bzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=BTNKP2LOva/Dahf0Ork9MJGMn/uawc7iGFzQVbaz6Cg=;
        fh=ZFmqDGIg7cn7OadhPwrJaXrZ3b0GVPkdcyJRWc1zL1w=;
        b=HyedAErjMAGgSyCrhSegDRc6apeROdA7fWkTsSxHMn+hb0rRPkL4bJ1VTIXEC7Q8kh
         fnP1TaMxLnR20X09/vL7JxfPW5HqSrcWTx+AsWmO+gDk9n9f4xE5xwlcfBBiupiGHtbi
         IB/bjXQcrhqmEHi4YEMt7J+LunKj0WkH4zF4i2YwOSsttF64P6BQ0DVEwrpbhNNPkrlY
         9kt0/CsRjnk41Svqs9H0zIrzzEPUNVPqasuBXRDT1AW2NwSOM9QwPtJ/UGssiycCmbCZ
         mfrNtEwEf1j5tPCPI8DScSKQ5yljPAKJ1IbFoHo3KNajMxH0ZOpKkf5lUmd4wbw+aiVB
         Tfcg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PUJz70kr;
       spf=pass (google.com: domain of alx@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-74ce32e29b0si78308b3a.1.2025.07.07.13.53.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Jul 2025 13:53:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 196085C06EF;
	Mon,  7 Jul 2025 20:53:37 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9460EC4CEE3;
	Mon,  7 Jul 2025 20:53:33 +0000 (UTC)
Date: Mon, 7 Jul 2025 22:53:26 +0200
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
Message-ID: <t3wv6hlt7quhab7qqvxbx6zn4rh2oo6466urtu6tmnix63ju7v@hiwhnb5l4twf>
References: <cover.1751862634.git.alx@kernel.org>
 <033bf00f1fcf808245ae150346019aa7b997ea11.1751862634.git.alx@kernel.org>
 <CANpmjNMPWWdushTvUqYJzqQJz4SJLgPggH9cs4KPob_9=1T-nw@mail.gmail.com>
 <kicfhrecpahv5kkawnnazsuterxjoqscwf3rb4u6in5gig2bq6@jbt6dwnzs67r>
 <CANpmjNNXyyfmYFPYm2LCF_+vdPtWED3xj5gOJPQazpGhBizk5w@mail.gmail.com>
 <gvckzzomd7x3cxd7fxb37b6zn4uowjubpyrnvj7ptzz3mr3zq2@xovzgew63mxr>
 <CANpmjNO0_RAMgZJktaempOm-KdY6Q0iJYFz=YEibvBgh7hNPwg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha512;
	protocol="application/pgp-signature"; boundary="v74lbtuwitce4ome"
Content-Disposition: inline
In-Reply-To: <CANpmjNO0_RAMgZJktaempOm-KdY6Q0iJYFz=YEibvBgh7hNPwg@mail.gmail.com>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=PUJz70kr;       spf=pass
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


--v74lbtuwitce4ome
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
 <gvckzzomd7x3cxd7fxb37b6zn4uowjubpyrnvj7ptzz3mr3zq2@xovzgew63mxr>
 <CANpmjNO0_RAMgZJktaempOm-KdY6Q0iJYFz=YEibvBgh7hNPwg@mail.gmail.com>
MIME-Version: 1.0
In-Reply-To: <CANpmjNO0_RAMgZJktaempOm-KdY6Q0iJYFz=YEibvBgh7hNPwg@mail.gmail.com>

Hi Marco,

On Mon, Jul 07, 2025 at 09:08:29PM +0200, Marco Elver wrote:
> > > > > Did you run the tests? Do they pass?
> > > >
> > > > I don't know how to run them.  I've only built the kernel.  If you point
> > > > me to instructions on how to run them, I'll do so.  Thanks!
> > >
> > > Should just be CONFIG_KFENCE_KUNIT_TEST=y -- then boot kernel and
> > > check that the test reports "ok".
> >
> > Hmmm, I can't see the results.  Did I miss anything?
> >
> >         alx@debian:~$ uname -a
> >         Linux debian 6.15.0-seprintf-mm+ #5 SMP PREEMPT_DYNAMIC Mon Jul  7 19:16:40 CEST 2025 x86_64 GNU/Linux
> >         alx@debian:~$ cat /boot/config-6.15.0-seprintf-mm+ | grep KFENCE
> >         CONFIG_HAVE_ARCH_KFENCE=y
> >         CONFIG_KFENCE=y
> >         CONFIG_KFENCE_SAMPLE_INTERVAL=0
> 
>                      ^^ This means KFENCE is off.
> 
> Not sure why it's 0 (distro default config?), but if you switch it to
> something like:

Yup, Debian default config plus what you told me.  :)

> 
>   CONFIG_KFENCE_SAMPLE_INTERVAL=10

Thanks!  Now I see the tests.

I see no regressions.  I've tested both v6.15 and my branch, and see no
differences:


This was generated with the kernel built from my branch:

	$ sudo dmesg | grep -inC2 kfence | sed 's/^....//' > tmp/log_after

This was generated with a v6.15 kernel with the same exact config:

	$ sudo dmesg | grep -inC2 kfence | sed 's/^....//' > tmp/log_before

And here's a diff, ignoring some numbers that were easy to filter out:

	$ diff -U999 \
		<(cat tmp/log_before \
			| sed 's/0x[0-9a-f]*/0x????/g' \
			| sed 's/[[:digit:]]\.[[:digit:]]\+/?.?/g' \
			| sed 's/#[[:digit:]]\+/#???/g') \
		<(cat tmp/log_after \
			| sed 's/0x[0-9a-f]*/0x????/g' \
			| sed 's/[[:digit:]]\.[[:digit:]]\+/?.?/g' \
			| sed 's/#[[:digit:]]\+/#???/g');
	--- /dev/fd/63	2025-07-07 22:47:37.395608776 +0200
	+++ /dev/fd/62	2025-07-07 22:47:37.395608776 +0200
	@@ -1,303 +1,303 @@
	 [    ?.?] NR_IRQS: 524544, nr_irqs: 1096, preallocated irqs: 16
	 [    ?.?] rcu: srcu_init: Setting srcu_struct sizes based on contention.
	 [    ?.?] kfence: initialized - using 2097152 bytes for 255 objects at 0x????(____ptrval____)-0x????(____ptrval____)
	 [    ?.?] Console: colour dummy device 80x????
	 [    ?.?] printk: legacy console [tty0] enabled
	 --
	 [    ?.?] ok 7 sysctl_test
	 [    ?.?]     KTAP version 1
	 [    ?.?]     # Subtest: kfence
	 [    ?.?]     1..27
	 [    ?.?]     # test_out_of_bounds_read: test_alloc: size=32, gfp=cc0, policy=left, cache=0
	 [    ?.?] ==================================================================
	 [    ?.?] BUG: KFENCE: out-of-bounds read in test_out_of_bounds_read+0x????/0x????
	 
	 [    ?.?] Out-of-bounds read at 0x???? (1B left of kfence-#???):
	 [    ?.?]  test_out_of_bounds_read+0x????/0x????
	 [    ?.?]  kunit_try_run_case+0x????/0x????
	 --
	 [    ?.?]  ret_from_fork_asm+0x????/0x????
	 
	 [    ?.?] kfence-#???: 0x????-0x????, size=32, cache=kmalloc-32
	 
	-[    ?.?] allocated by task 281 on cpu 6 at ?.?s (?.?s ago):
	+[    ?.?] allocated by task 286 on cpu 8 at ?.?s (?.?s ago):
	 --
	 [    ?.?]     # test_out_of_bounds_read: test_alloc: size=32, gfp=cc0, policy=right, cache=0
	 [    ?.?] ==================================================================
	 [    ?.?] BUG: KFENCE: out-of-bounds read in test_out_of_bounds_read.cold+0x????/0x????
	 
	 [    ?.?] Out-of-bounds read at 0x???? (32B right of kfence-#???):
	 [    ?.?]  test_out_of_bounds_read.cold+0x????/0x????
	 [    ?.?]  kunit_try_run_case+0x????/0x????
	 --
	 [    ?.?]  ret_from_fork_asm+0x????/0x????
	 
	 [    ?.?] kfence-#???: 0x????-0x????, size=32, cache=kmalloc-32
	 
	-[    ?.?] allocated by task 281 on cpu 6 at ?.?s (?.?s ago):
	+[    ?.?] allocated by task 286 on cpu 11 at ?.?s (?.?s ago):
	 --
	 [    ?.?]     # test_out_of_bounds_read-memcache: test_alloc: size=32, gfp=cc0, policy=left, cache=1
	 -[    ?.?] ==================================================================
	 :[    ?.?] BUG: KFENCE: out-of-bounds read in test_out_of_bounds_read+0x????/0x????
	 -
	 :[    ?.?] Out-of-bounds read at 0x???? (1B left of kfence-#???):
	 -[    ?.?]  test_out_of_bounds_read+0x????/0x????
	 -[    ?.?]  kunit_try_run_case+0x????/0x????
	 --
	 -[    ?.?]  ret_from_fork_asm+0x????/0x????
	 -
	 :[    ?.?] kfence-#???: 0x????-0x????, size=32, cache=test
	 -
	--[    ?.?] allocated by task 284 on cpu 6 at ?.?s (?.?s ago):
	+-[    ?.?] allocated by task 289 on cpu 8 at ?.?s (?.?s ago):
	 --
	 -[    ?.?]     # test_out_of_bounds_read-memcache: test_alloc: size=32, gfp=cc0, policy=right, cache=1
	 -[    ?.?] ==================================================================
	 :[    ?.?] BUG: KFENCE: out-of-bounds read in test_out_of_bounds_read.cold+0x????/0x????
	 -
	 :[    ?.?] Out-of-bounds read at 0x???? (32B right of kfence-#???):
	 -[    ?.?]  test_out_of_bounds_read.cold+0x????/0x????
	 -[    ?.?]  kunit_try_run_case+0x????/0x????
	 --
	 -[    ?.?]  ret_from_fork_asm+0x????/0x????
	 -
	 :[    ?.?] kfence-#???: 0x????-0x????, size=32, cache=test
	 -
	--[    ?.?] allocated by task 284 on cpu 6 at ?.?s (?.?s ago):
	+-[    ?.?] allocated by task 289 on cpu 8 at ?.?s (?.?s ago):
	 --
	 -[    ?.?]     # test_out_of_bounds_write: test_alloc: size=32, gfp=cc0, policy=left, cache=0
	 -[    ?.?] ==================================================================
	 :[    ?.?] BUG: KFENCE: out-of-bounds write in test_out_of_bounds_write+0x????/0x????
	 -
	 :[    ?.?] Out-of-bounds write at 0x???? (1B left of kfence-#???):
	 -[    ?.?]  test_out_of_bounds_write+0x????/0x????
	 -[    ?.?]  kunit_try_run_case+0x????/0x????
	 --
	 -[    ?.?]  ret_from_fork_asm+0x????/0x????
	 -
	 :[    ?.?] kfence-#???: 0x????-0x????, size=32, cache=kmalloc-32
	 -
	--[    ?.?] allocated by task 288 on cpu 6 at ?.?s (?.?s ago):
	+-[    ?.?] allocated by task 291 on cpu 6 at ?.?s (?.?s ago):
	 --
	--[    ?.?]     # test_out_of_bounds_write-memcache: test_alloc: size=32, gfp=cc0, policy=left, cache=1
	 -[    ?.?] ==================================================================
	+-[    ?.?] clocksource: tsc: mask: 0x???? max_cycles: 0x????, max_idle_ns: 881590599626 ns
	 :[    ?.?] BUG: KFENCE: out-of-bounds write in test_out_of_bounds_write+0x????/0x????
	 -
	 :[    ?.?] Out-of-bounds write at 0x???? (1B left of kfence-#???):
	 -[    ?.?]  test_out_of_bounds_write+0x????/0x????
	 -[    ?.?]  kunit_try_run_case+0x????/0x????
	 --
	 -[    ?.?]  ret_from_fork_asm+0x????/0x????
	 -
	 :[    ?.?] kfence-#???: 0x????-0x????, size=32, cache=test
	 -
	--[    ?.?] allocated by task 290 on cpu 6 at ?.?s (?.?s ago):
	+-[    ?.?] allocated by task 293 on cpu 10 at ?.?s (?.?s ago):
	 --
	 -[    ?.?]     # test_use_after_free_read: test_alloc: size=32, gfp=cc0, policy=any, cache=0
	 -[    ?.?] ==================================================================
	 :[    ?.?] BUG: KFENCE: use-after-free read in test_use_after_free_read+0x????/0x????
	 -
	 :[    ?.?] Use-after-free read at 0x???? (in kfence-#???):
	 -[    ?.?]  test_use_after_free_read+0x????/0x????
	 -[    ?.?]  kunit_try_run_case+0x????/0x????
	 --
	 -[    ?.?]  ret_from_fork_asm+0x????/0x????
	 -
	 :[    ?.?] kfence-#???: 0x????-0x????, size=32, cache=kmalloc-32
	 -
	--[    ?.?] allocated by task 292 on cpu 6 at ?.?s (?.?s ago):
	+-[    ?.?] allocated by task 296 on cpu 10 at ?.?s (?.?s ago):
	 --
	 -[    ?.?]     # test_use_after_free_read-memcache: test_alloc: size=32, gfp=cc0, policy=any, cache=1
	 -[    ?.?] ==================================================================
	 :[    ?.?] BUG: KFENCE: use-after-free read in test_use_after_free_read+0x????/0x????
	 -
	 :[    ?.?] Use-after-free read at 0x???? (in kfence-#???):
	 -[    ?.?]  test_use_after_free_read+0x????/0x????
	 -[    ?.?]  kunit_try_run_case+0x????/0x????
	 --
	 -[    ?.?]  ret_from_fork_asm+0x????/0x????
	 -
	 :[    ?.?] kfence-#???: 0x????-0x????, size=32, cache=test
	 -
	--[    ?.?] allocated by task 294 on cpu 6 at ?.?s (?.?s ago):
	+-[    ?.?] allocated by task 298 on cpu 10 at ?.?s (?.?s ago):
	 --
	 -[    ?.?]     # test_double_free: test_alloc: size=32, gfp=cc0, policy=any, cache=0
	 -[    ?.?] ==================================================================
	 :[    ?.?] BUG: KFENCE: invalid free in test_double_free+0x????/0x????
	 -
	 :[    ?.?] Invalid free of 0x???? (in kfence-#???):
	 -[    ?.?]  test_double_free+0x????/0x????
	 -[    ?.?]  kunit_try_run_case+0x????/0x????
	 --
	 -[    ?.?]  ret_from_fork_asm+0x????/0x????
	 -
	 :[    ?.?] kfence-#???: 0x????-0x????, size=32, cache=kmalloc-32
	 -
	--[    ?.?] allocated by task 300 on cpu 6 at ?.?s (?.?s ago):
	+-[    ?.?] allocated by task 304 on cpu 6 at ?.?s (?.?s ago):
	 --
	 -[    ?.?]     # test_double_free-memcache: test_alloc: size=32, gfp=cc0, policy=any, cache=1
	 -[    ?.?] ==================================================================
	 :[    ?.?] BUG: KFENCE: invalid free in test_double_free+0x????/0x????
	 -
	 :[    ?.?] Invalid free of 0x???? (in kfence-#???):
	 -[    ?.?]  test_double_free+0x????/0x????
	 -[    ?.?]  kunit_try_run_case+0x????/0x????
	 --
	 -[    ?.?]  ret_from_fork_asm+0x????/0x????
	 -
	 :[    ?.?] kfence-#???: 0x????-0x????, size=32, cache=test
	 -
	--[    ?.?] allocated by task 302 on cpu 6 at ?.?s (?.?s ago):
	+-[    ?.?] allocated by task 306 on cpu 8 at ?.?s (?.?s ago):
	 --
	 -[    ?.?]     # test_invalid_addr_free: test_alloc: size=32, gfp=cc0, policy=any, cache=0
	 -[    ?.?] ==================================================================
	 :[    ?.?] BUG: KFENCE: invalid free in test_invalid_addr_free+0x????/0x????
	 -
	 :[    ?.?] Invalid free of 0x???? (in kfence-#???):
	 -[    ?.?]  test_invalid_addr_free+0x????/0x????
	 -[    ?.?]  kunit_try_run_case+0x????/0x????
	 --
	 -[    ?.?]  ret_from_fork_asm+0x????/0x????
	 -
	 :[    ?.?] kfence-#???: 0x????-0x????, size=32, cache=kmalloc-32
	 -
	--[    ?.?] allocated by task 304 on cpu 6 at ?.?s (?.?s ago):
	+-[    ?.?] allocated by task 308 on cpu 8 at ?.?s (?.?s ago):
	 --
	 -[    ?.?]     # test_invalid_addr_free-memcache: test_alloc: size=32, gfp=cc0, policy=any, cache=1
	 -[    ?.?] ==================================================================
	 :[    ?.?] BUG: KFENCE: invalid free in test_invalid_addr_free+0x????/0x????
	 -
	 :[    ?.?] Invalid free of 0x???? (in kfence-#???):
	 -[    ?.?]  test_invalid_addr_free+0x????/0x????
	 -[    ?.?]  kunit_try_run_case+0x????/0x????
	 --
	 -[    ?.?]  ret_from_fork_asm+0x????/0x????
	 -
	 :[    ?.?] kfence-#???: 0x????-0x????, size=32, cache=test
	 -
	--[    ?.?] allocated by task 306 on cpu 6 at ?.?s (?.?s ago):
	+-[    ?.?] allocated by task 310 on cpu 8 at ?.?s (?.?s ago):
	 --
	 -[    ?.?]     # test_corruption: test_alloc: size=32, gfp=cc0, policy=left, cache=0
	 -[    ?.?] ==================================================================
	 :[    ?.?] BUG: KFENCE: memory corruption in test_corruption+0x????/0x????
	 -
	 :[    ?.?] Corrupted memory at 0x???? [ ! . . . . . . . . . . . . . . . ] (in kfence-#???):
	 -[    ?.?]  test_corruption+0x????/0x????
	 -[    ?.?]  kunit_try_run_case+0x????/0x????
	 --
	 -[    ?.?]  ret_from_fork_asm+0x????/0x????
	 -
	 :[    ?.?] kfence-#???: 0x????-0x????, size=32, cache=kmalloc-32
	 -
	--[    ?.?] allocated by task 308 on cpu 6 at ?.?s (?.?s ago):
	+-[    ?.?] allocated by task 312 on cpu 6 at ?.?s (?.?s ago):
	 --
	 -[    ?.?]     # test_corruption: test_alloc: size=32, gfp=cc0, policy=right, cache=0
	 -[    ?.?] ==================================================================
	 :[    ?.?] BUG: KFENCE: memory corruption in test_corruption+0x????/0x????
	 -
	 :[    ?.?] Corrupted memory at 0x???? [ ! ] (in kfence-#???):
	 -[    ?.?]  test_corruption+0x????/0x????
	 -[    ?.?]  kunit_try_run_case+0x????/0x????
	 --
	 -[    ?.?]  ret_from_fork_asm+0x????/0x????
	 -
	 :[    ?.?] kfence-#???: 0x????-0x????, size=32, cache=kmalloc-32
	 -
	--[    ?.?] allocated by task 308 on cpu 6 at ?.?s (?.?s ago):
	+-[    ?.?] allocated by task 312 on cpu 6 at ?.?s (?.?s ago):
	 --
	 -[    ?.?]     # test_corruption-memcache: test_alloc: size=32, gfp=cc0, policy=left, cache=1
	 -[    ?.?] ==================================================================
	 :[    ?.?] BUG: KFENCE: memory corruption in test_corruption+0x????/0x????
	 -
	 :[    ?.?] Corrupted memory at 0x???? [ ! . . . . . . . . . . . . . . . ] (in kfence-#???):
	 -[    ?.?]  test_corruption+0x????/0x????
	 -[    ?.?]  kunit_try_run_case+0x????/0x????
	 --
	 -[    ?.?]  ret_from_fork_asm+0x????/0x????
	 -
	 :[    ?.?] kfence-#???: 0x????-0x????, size=32, cache=test
	 -
	--[    ?.?] allocated by task 310 on cpu 6 at ?.?s (?.?s ago):
	+-[    ?.?] allocated by task 314 on cpu 6 at ?.?s (?.?s ago):
	 --
	 -[    ?.?]     # test_corruption-memcache: test_alloc: size=32, gfp=cc0, policy=right, cache=1
	 -[    ?.?] ==================================================================
	 :[    ?.?] BUG: KFENCE: memory corruption in test_corruption+0x????/0x????
	 -
	 :[    ?.?] Corrupted memory at 0x???? [ ! ] (in kfence-#???):
	 -[    ?.?]  test_corruption+0x????/0x????
	 -[    ?.?]  kunit_try_run_case+0x????/0x????
	 --
	 -[    ?.?]  ret_from_fork_asm+0x????/0x????
	 -
	 :[    ?.?] kfence-#???: 0x????-0x????, size=32, cache=test
	 -
	--[    ?.?] allocated by task 310 on cpu 6 at ?.?s (?.?s ago):
	+-[    ?.?] allocated by task 314 on cpu 6 at ?.?s (?.?s ago):
	 --
	 -[    ?.?]     # test_kmalloc_aligned_oob_read: test_alloc: size=73, gfp=cc0, policy=right, cache=0
	 -[    ?.?] ==================================================================
	 :[    ?.?] BUG: KFENCE: out-of-bounds read in test_kmalloc_aligned_oob_read+0x????/0x????
	 -
	 :[    ?.?] Out-of-bounds read at 0x???? (105B right of kfence-#???):
	 -[    ?.?]  test_kmalloc_aligned_oob_read+0x????/0x????
	 -[    ?.?]  kunit_try_run_case+0x????/0x????
	 --
	 -[    ?.?]  ret_from_fork_asm+0x????/0x????
	 -
	 :[    ?.?] kfence-#???: 0x????-0x????, size=73, cache=kmalloc-96
	 -
	--[    ?.?] allocated by task 320 on cpu 10 at ?.?s (?.?s ago):
	+-[    ?.?] allocated by task 326 on cpu 6 at ?.?s (?.?s ago):
	 --
	 -[    ?.?]     # test_kmalloc_aligned_oob_write: test_alloc: size=73, gfp=cc0, policy=right, cache=0
	 -[    ?.?] ==================================================================
	 :[    ?.?] BUG: KFENCE: memory corruption in test_kmalloc_aligned_oob_write+0x????/0x????
	 -
	 :[    ?.?] Corrupted memory at 0x???? [ ! . . . . . . . . . . . . . . . ] (in kfence-#???):
	 -[    ?.?]  test_kmalloc_aligned_oob_write+0x????/0x????
	 -[    ?.?]  kunit_try_run_case+0x????/0x????
	 --
	 -[    ?.?]  ret_from_fork_asm+0x????/0x????
	 -
	 :[    ?.?] kfence-#???: 0x????-0x????, size=73, cache=kmalloc-96
	 -
	--[    ?.?] allocated by task 326 on cpu 8 at ?.?s (?.?s ago):
	+-[    ?.?] allocated by task 328 on cpu 4 at ?.?s (?.?s ago):
	 --
	 -[    ?.?]     ok 22 test_memcache_ctor
	 -[    ?.?] ==================================================================
	 :[    ?.?] BUG: KFENCE: invalid read in test_invalid_access+0x????/0x????
	 -
	 -[    ?.?] Invalid read at 0x????:
	 --
	 -[    ?.?]     # test_memcache_typesafe_by_rcu: test_alloc: size=32, gfp=cc0, policy=any, cache=1
	 -[    ?.?] ==================================================================
	 :[    ?.?] BUG: KFENCE: use-after-free read in test_memcache_typesafe_by_rcu.cold+0x????/0x????
	 -
	 :[    ?.?] Use-after-free read at 0x???? (in kfence-#???):
	 -[    ?.?]  test_memcache_typesafe_by_rcu.cold+0x????/0x????
	 -[    ?.?]  kunit_try_run_case+0x????/0x????
	 --
	 -[    ?.?]  ret_from_fork_asm+0x????/0x????
	 -
	 :[    ?.?] kfence-#???: 0x????-0x????, size=32, cache=test
	 -
	--[    ?.?] allocated by task 336 on cpu 6 at ?.?s (?.?s ago):
	+-[    ?.?] allocated by task 338 on cpu 10 at ?.?s (?.?s ago):
	 --
	 -[    ?.?]     # test_krealloc: test_alloc: size=32, gfp=cc0, policy=any, cache=0
	 -[    ?.?] ==================================================================
	 :[    ?.?] BUG: KFENCE: use-after-free read in test_krealloc+0x????/0x????
	 -
	 :[    ?.?] Use-after-free read at 0x???? (in kfence-#???):
	 -[    ?.?]  test_krealloc+0x????/0x????
	 -[    ?.?]  kunit_try_run_case+0x????/0x????
	 --
	 -[    ?.?]  ret_from_fork_asm+0x????/0x????
	 -
	 :[    ?.?] kfence-#???: 0x????-0x????, size=32, cache=kmalloc-32
	 -
	--[    ?.?] allocated by task 338 on cpu 4 at ?.?s (?.?s ago):
	+-[    ?.?] allocated by task 340 on cpu 6 at ?.?s (?.?s ago):
	 --
	 -[    ?.?]     # test_memcache_alloc_bulk: setup_test_cache: size=32, ctor=0x????
	 -[    ?.?]     ok 27 test_memcache_alloc_bulk
	 :[    ?.?] # kfence: pass:25 fail:0 skip:2 total:27
	 -[    ?.?] # Totals: pass:25 fail:0 skip:2 total:27
	 :[    ?.?] ok 8 kfence
	 -[    ?.?]     KTAP version 1
	 -[    ?.?]     # Subtest: damon

If you'd like me to grep for something more specific, please let me
know.


Cheers,
Alex

-- 
<https://www.alejandro-colomar.es/>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/t3wv6hlt7quhab7qqvxbx6zn4rh2oo6466urtu6tmnix63ju7v%40hiwhnb5l4twf.

--v74lbtuwitce4ome
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iQIzBAABCgAdFiEES7Jt9u9GbmlWADAi64mZXMKQwqkFAmhsM78ACgkQ64mZXMKQ
wqkNcw//cAOxiIsGa8kbXMBkXN7Ook5P9u2Zs0cUjCYoHn9AIRtW+hYf1lDdnNav
BahwpujFq2zGzRyI1s959gqIYMg6K4bcKTE4INHACBnjgjMpRlHJy80VmHF2teO0
wRIrPP+kH8fp005+LI5DjXLKwT6f8y6n0qGCfvQ9TRXkzrUSs8k0RKnhfW36sSff
OVOARSwCyWLTgW0fXraBYwON/iFLjqYaMtqQrJ98XD1kzuOd8mIySqvFeDT7rZIN
ysSww7O/EkPOGx6eWNpFHdhsW97XfYMsfMjULq3bJ2k6qxEryGG3f2Tz02d3VtYN
Li7+VnK17YTfCtUIvztGRuhXWibtoqEcHt2bkmw1pHU2CTErtQi0c5+eeQ3T67dU
1ypdyvk0q9xBxr77E031Po0VyXtRIhkEFwtAKsLU2zL7ebF9m0kj1tMqYGeS6UfO
8G7ljq4NsBLX75+50dJGzbeRYdcxrMmbCNgAijuH5tN834b4BY5lw2mAuMeYUKg0
58N4TGr/2jZ224zRFArUB7rlnfqnDUs/G4Qb6qM2VQJ0m5viWQ5QEJRvYQSr6TDh
HYvlfve6M4tKrCmCKq6bc5Mpv13I3oGzushJn7gb8dFGkbTBe44youIcBMojljcz
QJWkCtjVuSEA9icPljo1VU9boyGgmnPnf7gznVm1eCmLgpBRbQ0=
=wycf
-----END PGP SIGNATURE-----

--v74lbtuwitce4ome--
