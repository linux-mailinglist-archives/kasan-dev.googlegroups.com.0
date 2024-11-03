Return-Path: <kasan-dev+bncBC6LHPWNU4DBBDO7TO4QMGQE2B7BKLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id 94AC39BA3C6
	for <lists+kasan-dev@lfdr.de>; Sun,  3 Nov 2024 04:35:43 +0100 (CET)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-2883d08e5f8sf2925522fac.1
        for <lists+kasan-dev@lfdr.de>; Sat, 02 Nov 2024 20:35:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1730604942; cv=pass;
        d=google.com; s=arc-20240605;
        b=LJ3fF4dH6+zmCksjFWBxvf4UlJK3Hjb+3iAjdH2ouRqq8zo+rsKYoXjh9ngCV4/kqm
         g4layp0P01JQIjJ20XfGkqvMYk6xsfCB1X3Xqr7KUK+s8P+pwenIS9ONO6+xH1rbm5oQ
         nZnkjAcuOHOd41k04zMOsvtWWUOTeKOUb6K8Xr0YSaCDpKGAN8F/r6tMAzUbYk2Ky7CE
         DXR8z9TRKVFICrNW0BHuLs6vvK7Eg7hVVqRVsYBwKP9U6J8nRzWf+qjlgf0i4nEQeXcM
         1FlaKMkXPhvmDlZYJBTBDVZ6YZezATqUWkYG5nwX+amuNAabT4yhAIq8+q6H+YegfLGu
         r3eg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :feedback-id:sender:dkim-signature:dkim-signature;
        bh=SL4sLZEdk9EYR8LCUYvT/xb3nv53QOZUQzwN+ZfKiuU=;
        fh=CbgutRGM92fQ/e5kKtskXLEN9znWK9EowkGlvZNujVk=;
        b=DA+QUTsvJscsSGqEYUZS4+W6O1tlVPtghN3y+4QxIW61acI/urnI2pYkHTa3BaRbLm
         dz2KmM0x7pONeEv/Zj1UtaM/pU3snajdiyasoa111n/2S9wzG9IjCgwyZVv9bkmW4AwE
         f27Fa5aCaQGUwKM5ejjrrqEQ1IB2xNFiTDBH98DN6meH0wQdqxweqSv4Xxa70rN37j7N
         6udrWEvFxd2EiHptUShpaYXXxRpdLPwWa0JZNRdUVXdBUy75jtNRbdLaXuqweLQmnYa+
         i1oBfgEBFoDn6N+9aQ+NQEvPMOTqa8CSGM+92p75zUFSr1Redb/4XohGa+5DzGUEsL+A
         6rRQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=KQPC353q;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730604942; x=1731209742; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:feedback-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=SL4sLZEdk9EYR8LCUYvT/xb3nv53QOZUQzwN+ZfKiuU=;
        b=WrxgiMSqoL2P5RDax5I3AmYdVgzZU7TxMCDmbBkK+SPkVJWDgse6q/Y7f6D0RGYVq+
         JcbaNarS0OOy1EBgs8uANi5jpCWeWGYJlmwJyzKLEA8vnG8zVvnPI0F/toCEbeKnaFp6
         rawc6te2anBY/e6hTO/80wb8QjollhZ9xFbzqDCd9CbPrvAmmVkavs7biTKedXqkbDOf
         aGBBU9cuiUE+hgnOidcBQFUVUDCXidZvRId/LMMva8mJfv1ExQO/QdrQYPVH2UcbokfQ
         FMjEURWIs4snbVaI7xtALzs2aWgQWARmJ3NI85LdMjI6T6ASjONvevYHayPtbnJFj6i3
         4YDQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1730604942; x=1731209742; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:feedback-id:from:to
         :cc:subject:date:message-id:reply-to;
        bh=SL4sLZEdk9EYR8LCUYvT/xb3nv53QOZUQzwN+ZfKiuU=;
        b=Fg1iBWcWSn2B/x6VCFRIgPzS4DqFB3YxeUMckFzHmZrWO+I1wheAuVH7nvPWkhTWu2
         EMFO0NwXeVu0o7BH5fsbZpNVQNnVpNPtv84o8Jj4PWWLbMRO9/yuio3ttHjbjOA82WNj
         YYazvXIzW1DknsxGOgjwB46elCZf5y8Dl/Gn3K0mkZpXD5htT8/YP1z9RjDT04o5diJ3
         OKyDc7bVtgIBZYGooeuTd1gJYgII1hZ+sILWeQmMTuV9aqPmSOWbQv6QJCqi8KRYGGf7
         6QSQoJ6jdkjfqBWJii2Sxlz2LGjtC87riU7JKSIye6+PRubdAPavEoB9ueprcH+6OlDf
         vw4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730604942; x=1731209742;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:feedback-id:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=SL4sLZEdk9EYR8LCUYvT/xb3nv53QOZUQzwN+ZfKiuU=;
        b=h+CUKk2zn5+IabaRrJqonY3yHzjjz4Q4i0xCYRVzDOwSjP7plmZr22NwCaYcoaQ+Ho
         QPDNW3n2Xvllrni2jQej/GbzVK9k7t/huQ9OFrjK6Bxeu8qgFQ7xH/vLt5X5DGVAmhl5
         QPzna4cmzPWW1M6qna5AdT3TJvWNvFlqafu27PBGpwycGRXLrRXFV6kmoesie46I7HBA
         QdlDEL4S7vz0EJvUKB2eUCtRaaLJElnvo7URss7ffMdwD6tYbIvZUM0gNqIatrkg/TFS
         UtdzwgH0CeKpzgC5+gal3hH1Y+uFhZOnzf/SEhdm4i1LlR2r4XqYfIhV2KCSFKZBTse1
         4HuA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWdpbM4YUQ7PlRPufqkZoqQJg/0F+JuEcHhCwL+AG9KKEh+ACZQFNGFfjrCod2pwSBD4QH7uw==@lfdr.de
X-Gm-Message-State: AOJu0YwXaS/OHaFaIjMJ7rMtZeKtd2ASXc4r/01rKFb5Cm0pYRyULlcO
	2jHAU0SZ5P8GxkcOpQT+B2I7He18TjBM9Xhg6f6FpFdqAoAXPiaB
X-Google-Smtp-Source: AGHT+IEcWFSv5UBVrgySv7/UFOUNVIP5kun/7UF25nk/pIuLssoqKGFb5PiItSiDxzJAkkm3SRu/kQ==
X-Received: by 2002:a05:6870:fbaa:b0:277:f09f:9eb7 with SMTP id 586e51a60fabf-2949cfda7bbmr5188104fac.7.1730604941806;
        Sat, 02 Nov 2024 20:35:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:1689:b0:289:3280:70fd with SMTP id
 586e51a60fabf-294827fceafls2408fac.2.-pod-prod-00-us; Sat, 02 Nov 2024
 20:35:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUEOiLGbKWiG+qAV1ggys+CNZgWe4T+sbqHY1j1FZOX2aoyw+6CfptygsZCkOVXN/bw4kDqWuh00h4=@googlegroups.com
X-Received: by 2002:a05:6870:781a:b0:265:b32b:c465 with SMTP id 586e51a60fabf-2949cff585cmr5277368fac.9.1730604940859;
        Sat, 02 Nov 2024 20:35:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1730604940; cv=none;
        d=google.com; s=arc-20240605;
        b=hyOdmsclx3WMk7b+GUofrvaE6/VN6X573OC6GAnbk8Uxbii1a100ADWNgVa6R4EDC7
         6JhtBmrF3MgVdAvw16l4oD8zw9C7ZIvEvR8SJLP6bQlUOLIaheOFXDXf++gISCBVkwQp
         SPaUvtxovCDlOCKia7g3wrmP/LAcMBBwZBdOBdRxBTus+yRfAkD+HWjrypW2wf4sYgbA
         wisECOtCgUixkroLiXsLSACieSevhAGLl7MlEkIYCAha5TxizXt3lcfjPxj9KYZiS6br
         jwLa1dfmDZa2gON1bpFHXSibhDOLrlUWpHDNicNB6MOmfAlw03VOI7/dHJ/EwRf8q1D2
         0kGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:feedback-id:dkim-signature;
        bh=7Urc9Z86LcjyqhCcm6H0VVQdu+SdtQEzmvHdA+i0O10=;
        fh=q8xkXcbPj82Qfxg9I/o70ab+B4PMe6sSMIno7/BNO6s=;
        b=LC1UxK10sG7aof2q/MVAPPVhi367n5B+ZqV53LfS/NiJFOA1v2/sLC2Zgj6AcCZ9+V
         6t7pI9Fdp7NLCuND/Yyr7oHM+S7buoeI/Nje6n1psJDnrSHuPqrYsboIppBCPn4IH0hT
         vrA/lKrNIu2DZJK+9S0wGvT7Pg++uZDCer61gkVCFH2Z5oRz7lIm0l6X6stgCVLWHRxe
         QzyxxI2F0tFnzJTW19/UrLTYDCliOOngW3vA2PXWlCsckSXGbDzfUCXU8LWYtXDZupp4
         XDVOB6rrI8hFNAIlwC+zUWD0OpX3ehnOC7RBiqULAJjPUHX9iBdMi26k56YkKbsUX8Fm
         8gkg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=KQPC353q;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf33.google.com (mail-qv1-xf33.google.com. [2607:f8b0:4864:20::f33])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7189ccf7dc6si258529a34.5.2024.11.02.20.35.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 02 Nov 2024 20:35:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::f33 as permitted sender) client-ip=2607:f8b0:4864:20::f33;
Received: by mail-qv1-xf33.google.com with SMTP id 6a1803df08f44-6cbd57cc35bso36217416d6.1
        for <kasan-dev@googlegroups.com>; Sat, 02 Nov 2024 20:35:40 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX9mP4ezIYK1G4GNwYRk7y/h2OXqXKxI8PeAM5xVGSzUpdt7yBQuGpiyuLpXT8E3hFqCMg2VDvCmKM=@googlegroups.com
X-Received: by 2002:a05:6214:5d0e:b0:6d1:9f1b:b669 with SMTP id 6a1803df08f44-6d3542eddbbmr200542976d6.15.1730604939972;
        Sat, 02 Nov 2024 20:35:39 -0700 (PDT)
Received: from fauth-a2-smtp.messagingengine.com (fauth-a2-smtp.messagingengine.com. [103.168.172.201])
        by smtp.gmail.com with ESMTPSA id af79cd13be357-7b2f3a718bbsm309375385a.87.2024.11.02.20.35.38
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 02 Nov 2024 20:35:39 -0700 (PDT)
Received: from phl-compute-03.internal (phl-compute-03.phl.internal [10.202.2.43])
	by mailfauth.phl.internal (Postfix) with ESMTP id 89A4F1200076;
	Sat,  2 Nov 2024 23:35:38 -0400 (EDT)
Received: from phl-mailfrontend-02 ([10.202.2.163])
  by phl-compute-03.internal (MEProxy); Sat, 02 Nov 2024 23:35:38 -0400
X-ME-Sender: <xms:iu8mZ9g9xRAqgpSsuv468xIJ18NCxzL5b6y2mLAeCASem1XW6oZEvA>
    <xme:iu8mZyCBofRgAjDFqnIdvWgwDOLWr8q1TJKTkNntMuO6Rz421sRc1cJjrtTxyZpdK
    F6VeRxhHtLSoXfBzw>
X-ME-Received: <xmr:iu8mZ9ESpwMuCl-pTWTfpIAjWjHl5PzKT0TnWmdNt3_7yz1UzzRSaeOU7hs>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgeeftddrvdelvddgheekucetufdoteggodetrfdotf
    fvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdggtfgfnhhsuhgsshgtrhhisggvpdfu
    rfetoffkrfgpnffqhgenuceurghilhhouhhtmecufedttdenucesvcftvggtihhpihgvnh
    htshculddquddttddmnecujfgurhepfffhvfevuffkfhggtggujgesthdtredttddtvden
    ucfhrhhomhepuehoqhhunhcuhfgvnhhguceosghoqhhunhdrfhgvnhhgsehgmhgrihhlrd
    gtohhmqeenucggtffrrghtthgvrhhnpefhtedvgfdtueekvdekieetieetjeeihedvteeh
    uddujedvkedtkeefgedvvdehtdenucffohhmrghinhepkhgvrhhnvghlrdhorhhgnecuve
    hluhhsthgvrhfuihiivgeptdenucfrrghrrghmpehmrghilhhfrhhomhepsghoqhhunhdo
    mhgvshhmthhprghuthhhphgvrhhsohhnrghlihhthidqieelvdeghedtieegqddujeejke
    ehheehvddqsghoqhhunhdrfhgvnhhgpeepghhmrghilhdrtghomhesfhhigihmvgdrnhgr
    mhgvpdhnsggprhgtphhtthhopedukedpmhhouggvpehsmhhtphhouhhtpdhrtghpthhtoh
    epphgruhhlmhgtkheskhgvrhhnvghlrdhorhhgpdhrtghpthhtohepsghighgvrghshies
    lhhinhhuthhrohhnihigrdguvgdprhgtphhtthhopehvsggrsghkrgesshhushgvrdgtii
    dprhgtphhtthhopegvlhhvvghrsehgohhoghhlvgdrtghomhdprhgtphhtthhopehlihhn
    uhigqdhnvgigthesvhhgvghrrdhkvghrnhgvlhdrohhrghdprhgtphhtthhopehlihhnuh
    igqdhkvghrnhgvlhesvhhgvghrrdhkvghrnhgvlhdrohhrghdprhgtphhtthhopehkrghs
    rghnqdguvghvsehgohhoghhlvghgrhhouhhpshdrtghomhdprhgtphhtthhopehlihhnuh
    igqdhmmheskhhvrggtkhdrohhrghdprhgtphhtthhopehsfhhrsegtrghnsgdrrghuuhhg
    rdhorhhgrdgruh
X-ME-Proxy: <xmx:iu8mZyQ1moQKIgbQ5C7gBiQUMnsFQjOHesl3UO3wY02XC8g7xxxk0A>
    <xmx:iu8mZ6y82nLjVDUhjZjyoVrhkf_8ZVHbfL0lpUtQHFer8UTchH6fPw>
    <xmx:iu8mZ455GwRqIxBQlyCoTo9iVl2kjeDonsPd0hBGe3_LMmoaQYz4wg>
    <xmx:iu8mZ_zmbRQkGqS8hxvRnfLnU4jUeoU1M-MF3u4SVsW_6yH7ZMQJzg>
    <xmx:iu8mZyiOUvEEIEqpkifvVtnQalduFxGP0MgorsiFo2_fLE7n8y_nqzZ3>
Feedback-ID: iad51458e:Fastmail
Received: by mail.messagingengine.com (Postfix) with ESMTPA; Sat,
 2 Nov 2024 23:35:37 -0400 (EDT)
Date: Sat, 2 Nov 2024 20:35:36 -0700
From: Boqun Feng <boqun.feng@gmail.com>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	Vlastimil Babka <vbabka@suse.cz>, Marco Elver <elver@google.com>,
	linux-next@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	sfr@canb.auug.org.au, longman@redhat.com, cl@linux.com,
	penberg@kernel.org, rientjes@google.com, iamjoonsoo.kim@lge.com,
	akpm@linux-foundation.org, Thomas Gleixner <tglx@linutronix.de>,
	Peter Zijlstra <peterz@infradead.org>
Subject: Re: [PATCH] scftorture: Use workqueue to free scf_check
Message-ID: <ZybviLZqjw_VYg8A@Boquns-Mac-mini.local>
References: <ZyUxBr5Umbc9odcH@boqun-archlinux>
 <20241101195438.1658633-1-boqun.feng@gmail.com>
 <37c2ad76-37d1-44da-9532-65d67e849bba@paulmck-laptop>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <37c2ad76-37d1-44da-9532-65d67e849bba@paulmck-laptop>
X-Original-Sender: boqun.feng@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=KQPC353q;       spf=pass
 (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::f33
 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Fri, Nov 01, 2024 at 04:35:28PM -0700, Paul E. McKenney wrote:
> On Fri, Nov 01, 2024 at 12:54:38PM -0700, Boqun Feng wrote:
> > Paul reported an invalid wait context issue in scftorture catched by
> > lockdep, and the cause of the issue is because scf_handler() may call
> > kfree() to free the struct scf_check:
> > 
> > 	static void scf_handler(void *scfc_in)
> >         {
> >         [...]
> >                 } else {
> >                         kfree(scfcp);
> >                 }
> >         }
> > 
> > (call chain anlysis from Marco Elver)
> > 
> > This is problematic because smp_call_function() uses non-threaded
> > interrupt and kfree() may acquire a local_lock which is a sleepable lock
> > on RT.
> > 
> > The general rule is: do not alloc or free memory in non-threaded
> > interrupt conntexts.
> > 
> > A quick fix is to use workqueue to defer the kfree(). However, this is
> > OK only because scftorture is test code. In general the users of
> > interrupts should avoid giving interrupt handlers the ownership of
> > objects, that is, users should handle the lifetime of objects outside
> > and interrupt handlers should only hold references to objects.
> > 
> > Reported-by: "Paul E. McKenney" <paulmck@kernel.org>
> > Link: https://lore.kernel.org/lkml/41619255-cdc2-4573-a360-7794fc3614f7@paulmck-laptop/
> > Signed-off-by: Boqun Feng <boqun.feng@gmail.com>
> 
> Thank you!
> 
> I was worried that putting each kfree() into a separate workqueue handler
> would result in freeing not keeping up with allocation for asynchronous
> testing (for example, scftorture.weight_single=1), but it seems to be
> doing fine in early testing.
> 

I shared the same worry, so it's why I added the comments before
queue_work() saying it's only OK because it's test code, it's certainly
not something recommended for general use.

But glad it turns out OK so far for scftorture ;-)

Regards,
Boqun

> So I have queued this in my -rcu tree for review and further testing.
> 
> 							Thanx, Paul
> 
> > ---
> >  kernel/scftorture.c | 14 +++++++++++++-
> >  1 file changed, 13 insertions(+), 1 deletion(-)
> > 
> > diff --git a/kernel/scftorture.c b/kernel/scftorture.c
> > index 44e83a646264..ab6dcc7c0116 100644
> > --- a/kernel/scftorture.c
> > +++ b/kernel/scftorture.c
> > @@ -127,6 +127,7 @@ static unsigned long scf_sel_totweight;
> >  
> >  // Communicate between caller and handler.
> >  struct scf_check {
> > +	struct work_struct work;
> >  	bool scfc_in;
> >  	bool scfc_out;
> >  	int scfc_cpu; // -1 for not _single().
> > @@ -252,6 +253,13 @@ static struct scf_selector *scf_sel_rand(struct torture_random_state *trsp)
> >  	return &scf_sel_array[0];
> >  }
> >  
> > +static void kfree_scf_check_work(struct work_struct *w)
> > +{
> > +	struct scf_check *scfcp = container_of(w, struct scf_check, work);
> > +
> > +	kfree(scfcp);
> > +}
> > +
> >  // Update statistics and occasionally burn up mass quantities of CPU time,
> >  // if told to do so via scftorture.longwait.  Otherwise, occasionally burn
> >  // a little bit.
> > @@ -296,7 +304,10 @@ static void scf_handler(void *scfc_in)
> >  		if (scfcp->scfc_rpc)
> >  			complete(&scfcp->scfc_completion);
> >  	} else {
> > -		kfree(scfcp);
> > +		// Cannot call kfree() directly, pass it to workqueue. It's OK
> > +		// only because this is test code, avoid this in real world
> > +		// usage.
> > +		queue_work(system_wq, &scfcp->work);
> >  	}
> >  }
> >  
> > @@ -335,6 +346,7 @@ static void scftorture_invoke_one(struct scf_statistics *scfp, struct torture_ra
> >  			scfcp->scfc_wait = scfsp->scfs_wait;
> >  			scfcp->scfc_out = false;
> >  			scfcp->scfc_rpc = false;
> > +			INIT_WORK(&scfcp->work, kfree_scf_check_work);
> >  		}
> >  	}
> >  	switch (scfsp->scfs_prim) {
> > -- 
> > 2.45.2
> > 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ZybviLZqjw_VYg8A%40Boquns-Mac-mini.local.
