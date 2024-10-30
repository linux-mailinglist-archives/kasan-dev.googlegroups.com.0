Return-Path: <kasan-dev+bncBC6LHPWNU4DBB7PWRK4QMGQETE3WOSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id B76E89B7039
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Oct 2024 00:04:32 +0100 (CET)
Received: by mail-pf1-x43f.google.com with SMTP id d2e1a72fcca58-71ec3392c25sf387516b3a.1
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Oct 2024 16:04:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1730329470; cv=pass;
        d=google.com; s=arc-20240605;
        b=W3wOjRnk4wl5IdiuWEfabZ4P/Z0OrTwWX89nmq94aF0+5PgyUSkdbLZaTmzjxhQD0I
         zv/Djw/5ec0ToJPwPHNJgmixRtBsOrFGCDZPjlLOVKu9TP6yszVv7o9cjiBLSRvT3+nR
         DdXDewVxiMB4xO6ZLEotkxnFsO5Ogjcdy9h9R70Mw5nZ+f04NqQxm6iK/2ZMO7ZHGph6
         Sw/1lekmUJHyjED1Ei2rT7x/XejUmbLy8OBoOmdrgngFsCP4ZiAORMWtbfXWnrpxZCmC
         nEy6MeAX5XtCioe/hmog9Fgcy9zMlsO7dXLFDBkg5IyhYnXbLfVh4caQFsS24eVHrWTy
         NbNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :feedback-id:sender:dkim-signature:dkim-signature;
        bh=A9wQ6LDp+CWMAk2feswSZVnWyUf99DzVoFw/asH8D0w=;
        fh=SWTtw0FrEp676Es7uKny/iS86KMI5nCqXL8dL867JK8=;
        b=Lydo6esVRWbttPkzSJr+fWZDNKa+w/YDG3nrcQVq8zbRy/sjNJEPo7K6qhug0tUwFK
         y7+KJIry0kHnL7eWXnmNreKZCQMadsfRHrLjp4oxvqd+/jfVUIkYiu/2p1tUpGI3Sl6J
         g09QPz4ka5Bj6KGDq28eRyrbAt04ogYTrtdUVMwFxOHeSfIamNjGaMWmcfZeo+AHxrv4
         heUcpAvxPqIG1oILd8UXFz1a+x7bZC6C/T2Yn8GscVjW3xRxiuZboe2xG7z1ywRc+WH+
         VpIngPk5C/dxwaRpkzVxHtkzS7SAXUG+mSIB/Q/TH7jpBcbE7gOYx4LOzmEyfEuOEAqu
         QGGQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Lql1SEAG;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::82a as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730329470; x=1730934270; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:feedback-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=A9wQ6LDp+CWMAk2feswSZVnWyUf99DzVoFw/asH8D0w=;
        b=JhLXfcPc9Lpv5li4xIhRXOj61TYmy/x1TL5HN0U2PY/gDn8U79o90/Rvfv/NzRJDS8
         IX5ok74+U/DiaJ4ekuT9h0Gim8F5gLVqTMkfk2WCJds3w2MHgdvc91eZuue9ha+KzOY4
         39cRPrSW/GJzLvj3q7eP3bqvAVBXMEWLUVBp/uzNZbe7iG2mHvtjJbhKVdb+zU8r0nwk
         UxHk+hFaXKffQPchb2v4+s8mbLKFPz84uwKXIGQLbyBGsGxlv0yq+227vdTJOLm98IXJ
         GfPVx2i/Yll6kghDnlDtoaK9le/QPuAG3VX7MPKsvncdBF3cySs1WAUBAI0zaKfKdsSd
         0ing==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1730329470; x=1730934270; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:feedback-id:from:to
         :cc:subject:date:message-id:reply-to;
        bh=A9wQ6LDp+CWMAk2feswSZVnWyUf99DzVoFw/asH8D0w=;
        b=m2sRDwHY5UVn2K7qFzAMfCKzqNClf5eIhnzbhhdgVr7h3SVyCJv9BfiDpnEib8SIVm
         zTF5veahxEBjOJDA8vj1chh+iXDIyoN90FMP8HdpiMqRZqwO02IybX6H++QO0WutGd82
         oDwQJJWavmDGAIdSTrAmuYKRVhRK6OL+UBQcgbtrcI8F2oJ+4bDTAGH/TAWA2twodqWb
         X5ARegkEnBNEUYQEYL47uaoEm6FdQdCbbGQtpR5Ui8FRBmDzXiyQMRnksI7hCyP4JURs
         0MzwwboMfYYgAikBm0tJfbaKOuyTG/DTrMKplAAe9jyIG0zwmlYBhIRBc2FhIjq/bM1s
         Ai+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730329470; x=1730934270;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:feedback-id:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=A9wQ6LDp+CWMAk2feswSZVnWyUf99DzVoFw/asH8D0w=;
        b=EDNvTZ2vmwveVjajkVnPaA++W3VX7lYbhb7sef/jNp9zPXr1JsRJ+hWLje3moo0t81
         6xSyGrKghxQ9OooLqIy3DCpGLd8bT1GX5NJlPpsh8zX8S6SEjYPTIxD8bNRbSstGeYZI
         LM++MLZ6uh5Ot4gKyHC2msYjJlaA3ticD8slVh6NZZHLlX9U28wqTN+GjQfxJt5nU/mP
         c3ggQQEyuLLuBUHd7lh15PlKwr/WC6cBW/dzLsPEAKYOgrwEIRIm1oPwuia5HKQXy6vc
         ZME/KPwErTCtqOdXLtutarvyfKK6BpCpbQSj9Y4wml1Z8kHlRqlsRLUF+G/AKGVwL8/b
         pMrA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUi6huOcnlrXX5XIIOQ6WWJYp+s+XXHHJW8ZmFjBiU62gzycGrJffR87ngMgBU4Jn3EYp/ecw==@lfdr.de
X-Gm-Message-State: AOJu0YyG5S9ZZCkbadIN+3iIpl+3mjuAN0044yZhRghHgJtRLeKEC9Qf
	d/keJOtaXB44MXJDGsO4sjLQPks1Ks7u41EI7lLH+xCqMBSBfqSj
X-Google-Smtp-Source: AGHT+IH7yvsbKZV0SdkZ8sNnMa07vz+X7oW27FwI2l5A4STw2qHQbY7GwVWXyPW+sWxQDRqkvWzsGg==
X-Received: by 2002:a05:6a21:a34c:b0:1d9:221c:6605 with SMTP id adf61e73a8af0-1d9a84233femr23782636637.29.1730329470221;
        Wed, 30 Oct 2024 16:04:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:14d1:b0:71e:6edf:b2a2 with SMTP id
 d2e1a72fcca58-720ba10a6c1ls325647b3a.0.-pod-prod-04-us; Wed, 30 Oct 2024
 16:04:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU3VvpdOhBAiNB2TYh64tdoWMOTh224pATFFrZHdSGHnGjsaHkM6dGUHvdos6aN1bTK35080MrZyCg=@googlegroups.com
X-Received: by 2002:a05:6a20:431f:b0:1db:8958:5e6d with SMTP id adf61e73a8af0-1db89585f99mr3270372637.20.1730329468710;
        Wed, 30 Oct 2024 16:04:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1730329468; cv=none;
        d=google.com; s=arc-20240605;
        b=LWyXqgTuYnac3rCkf0iZx8qXj0Afnz4lWlbTELkSMjbrnYXMPDwx+q/obU0J1LTlet
         d3vAt2zXIZUjOOrVqZij2ZGobDiUeF6qCVd0GffMEqXtXYXupMW/1hj5bgUbo8Vv6By+
         EgcH9SktcMJHTZb1FnSoRUZcbzodmnAj1w5sg/8882n+tlNzBAJS/p07naLJZfjrCGjA
         /faxfxbKkusHa04aFk+5opHHtWNhIChMYjjleFur5IpUBUT29MzVTB42RhdjjkNcdUkD
         Y4DOTQ+hYQkooz2TxsxFMRabHusG+f30NAwOQ8EPfON/SbTbFlZBwW+pmsASA3BNPyO0
         WCAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:feedback-id:dkim-signature;
        bh=PLJJBAKyQj+SNUNmxz2AeNTsEKRK6TwiIX+0O6pGNdQ=;
        fh=+81a1Mt5zqSv2KE4dj9G5XUPHugkM/3ut+lDC6uUPtU=;
        b=eQ2wF66KvLGjQ1AlQ2d6XSwGnp6OVNZYtSSfDyeUKqVdvTN8js6yciY0GPEMEDqCrK
         jGsVIhsKoi2WdCTG14QZwLxg0RShjMSWFZSVWzD+/z/+XK3UzAJS82g0LenHyjMToI7S
         yOkrcncd4kQTv8WwEmAg8XVzfqxtTaT+O8uMIEtti7nfjozDOyUCu9BliBtX9i6b/RCl
         D9w2hZ2j2XugJ9S4ghHbIoiqtIfuPwy580uFBn9AxojyhL1kWwc/Ntcz0gr8Jnp6piz3
         KfHoLeSD5IwoPqZomm02HKJA0/j7E0lGyX2PH+jGPCpoI75uhvofcKARmQ+3fywv7V5g
         3m2A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Lql1SEAG;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::82a as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x82a.google.com (mail-qt1-x82a.google.com. [2607:f8b0:4864:20::82a])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-7ee45297844si10547a12.1.2024.10.30.16.04.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Oct 2024 16:04:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::82a as permitted sender) client-ip=2607:f8b0:4864:20::82a;
Received: by mail-qt1-x82a.google.com with SMTP id d75a77b69052e-460c1ba306bso2610591cf.2
        for <kasan-dev@googlegroups.com>; Wed, 30 Oct 2024 16:04:28 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVlgZ85lAMEsEGhDzM6S0M84YH1SSR32p3L+GOWujkMb2EQNeGajC+sLAHKcVExsudxZvHmEbvSsKE=@googlegroups.com
X-Received: by 2002:a05:622a:58e:b0:461:148b:1884 with SMTP id d75a77b69052e-4613bfd0547mr250096891cf.11.1730329467740;
        Wed, 30 Oct 2024 16:04:27 -0700 (PDT)
Received: from fauth-a2-smtp.messagingengine.com (fauth-a2-smtp.messagingengine.com. [103.168.172.201])
        by smtp.gmail.com with ESMTPSA id d75a77b69052e-462ad19b328sm1220441cf.85.2024.10.30.16.04.26
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 30 Oct 2024 16:04:27 -0700 (PDT)
Received: from phl-compute-03.internal (phl-compute-03.phl.internal [10.202.2.43])
	by mailfauth.phl.internal (Postfix) with ESMTP id 72ED31200066;
	Wed, 30 Oct 2024 19:04:26 -0400 (EDT)
Received: from phl-mailfrontend-01 ([10.202.2.162])
  by phl-compute-03.internal (MEProxy); Wed, 30 Oct 2024 19:04:26 -0400
X-ME-Sender: <xms:ersiZx38nY2ghCYzRWWqgHa3CxJ8ukzFhWb1D2-I3W9RVVnspMWbTA>
    <xme:ersiZ4GCeBW-Vulbkr8qDM4UuWiVjCkdHBJgw-YzMszDOxocMSwKSjbIGM4CeEbqe
    H4eTna0cpq3SrGjwQ>
X-ME-Received: <xmr:ersiZx7P240Dmw5DHoWeDSgttVlOUid3ijnFMigJvHgOZEtIaJqieE4bzM0>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgeeftddrvdekgedgtdehucetufdoteggodetrfdotf
    fvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdggtfgfnhhsuhgsshgtrhhisggvpdfu
    rfetoffkrfgpnffqhgenuceurghilhhouhhtmecufedttdenucesvcftvggtihhpihgvnh
    htshculddquddttddmnecujfgurhepfffhvfevuffkfhggtggujgesthdtredttddtvden
    ucfhrhhomhepuehoqhhunhcuhfgvnhhguceosghoqhhunhdrfhgvnhhgsehgmhgrihhlrd
    gtohhmqeenucggtffrrghtthgvrhhnpeevgfejgfevfeevteegffdvhedtgfekvefgledv
    teffgeffveeiuedvieethfdugeenucffohhmrghinhepqhgvmhhurdhorhhgnecuvehluh
    hsthgvrhfuihiivgeptdenucfrrghrrghmpehmrghilhhfrhhomhepsghoqhhunhdomhgv
    shhmthhprghuthhhphgvrhhsohhnrghlihhthidqieelvdeghedtieegqddujeejkeehhe
    ehvddqsghoqhhunhdrfhgvnhhgpeepghhmrghilhdrtghomhesfhhigihmvgdrnhgrmhgv
    pdhnsggprhgtphhtthhopeduiedpmhhouggvpehsmhhtphhouhhtpdhrtghpthhtohepvg
    hlvhgvrhesghhoohhglhgvrdgtohhmpdhrtghpthhtohepvhgsrggskhgrsehsuhhsvgdr
    tgiipdhrtghpthhtohepphgruhhlmhgtkheskhgvrhhnvghlrdhorhhgpdhrtghpthhtoh
    eplhhinhhugidqnhgvgihtsehvghgvrhdrkhgvrhhnvghlrdhorhhgpdhrtghpthhtohep
    lhhinhhugidqkhgvrhhnvghlsehvghgvrhdrkhgvrhhnvghlrdhorhhgpdhrtghpthhtoh
    epkhgrshgrnhdquggvvhesghhoohhglhgvghhrohhuphhsrdgtohhmpdhrtghpthhtohep
    lhhinhhugidqmhhmsehkvhgrtghkrdhorhhgpdhrtghpthhtohepshhfrhestggrnhgsrd
    gruhhughdrohhrghdrrghupdhrtghpthhtohepsghighgvrghshieslhhinhhuthhrohhn
    ihigrdguvg
X-ME-Proxy: <xmx:ersiZ-2PNxt_8g4rxZhOfvGOkxDK_WrYHRcmNR_UcN51kjb6QqwqfQ>
    <xmx:ersiZ0H6tvJbvOp1Yq0VQ58WZoMXNeRa8YXDYiiDy1xBICrXxzWIkg>
    <xmx:ersiZ_-PkU9APVb4QIEFu-fjasOuj7NDUjW8bHId8-blUvHHtXUIAw>
    <xmx:ersiZxn7CvyI9URkKz8eoySlJ3n1HKFwvXMaND_xGj2HdiVA7_HLpg>
    <xmx:ersiZ4EsAmAZcD4QUT5YWF0wJIVnUb3L4DRyUgVUBYXId3xVFlLfY0hZ>
Feedback-ID: iad51458e:Fastmail
Received: by mail.messagingengine.com (Postfix) with ESMTPA; Wed,
 30 Oct 2024 19:04:25 -0400 (EDT)
Date: Wed, 30 Oct 2024 16:04:24 -0700
From: Boqun Feng <boqun.feng@gmail.com>
To: Marco Elver <elver@google.com>
Cc: Vlastimil Babka <vbabka@suse.cz>, paulmck@kernel.org,
	linux-next@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	sfr@canb.auug.org.au, bigeasy@linutronix.de, longman@redhat.com,
	cl@linux.com, penberg@kernel.org, rientjes@google.com,
	iamjoonsoo.kim@lge.com, akpm@linux-foundation.org
Subject: Re: [BUG] -next lockdep invalid wait context
Message-ID: <ZyK7eGSWfEYzio_u@Boquns-Mac-mini.local>
References: <41619255-cdc2-4573-a360-7794fc3614f7@paulmck-laptop>
 <e06d69c9-f067-45c6-b604-fd340c3bd612@suse.cz>
 <ZyK0YPgtWExT4deh@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZyK0YPgtWExT4deh@elver.google.com>
X-Original-Sender: boqun.feng@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Lql1SEAG;       spf=pass
 (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::82a
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

On Wed, Oct 30, 2024 at 11:34:08PM +0100, Marco Elver wrote:
> On Wed, Oct 30, 2024 at 10:48PM +0100, Vlastimil Babka wrote:
> > On 10/30/24 22:05, Paul E. McKenney wrote:
> > > Hello!
> > 
> > Hi!
> > 
> > > The next-20241030 release gets the splat shown below when running
> > > scftorture in a preemptible kernel.  This bisects to this commit:
> > > 
> > > 560af5dc839e ("lockdep: Enable PROVE_RAW_LOCK_NESTING with PROVE_LOCKING")
> > > 
> > > Except that all this is doing is enabling lockdep to find the problem.
> > > 
> > > The obvious way to fix this is to make the kmem_cache structure's
> > > cpu_slab field's ->lock be a raw spinlock, but this might not be what
> > > we want for real-time response.
> > 
> > But it's a local_lock, not spinlock and it's doing local_lock_irqsave(). I'm
> > confused what's happening here, the code has been like this for years now.
> > 
> > > This can be reproduced deterministically as follows:
> > > 
> > > tools/testing/selftests/rcutorture/bin/kvm.sh --torture scf --allcpus --duration 2 --configs PREEMPT --kconfig CONFIG_NR_CPUS=64 --memory 7G --trust-make --kasan --bootargs "scftorture.nthreads=64 torture.disable_onoff_at_boot csdlock_debug=1"
> > > 
> > > I doubt that the number of CPUs or amount of memory makes any difference,
> > > but that is what I used.
> > > 
> > > Thoughts?
> > > 
> > > 							Thanx, Paul
> > > 
> > > ------------------------------------------------------------------------
> > > 
> > > [   35.659746] =============================
> > > [   35.659746] [ BUG: Invalid wait context ]
> > > [   35.659746] 6.12.0-rc5-next-20241029 #57233 Not tainted
> > > [   35.659746] -----------------------------
> > > [   35.659746] swapper/37/0 is trying to lock:
> > > [   35.659746] ffff8881ff4bf2f0 (&c->lock){....}-{3:3}, at: put_cpu_partial+0x49/0x1b0
> > > [   35.659746] other info that might help us debug this:
> > > [   35.659746] context-{2:2}
> > > [   35.659746] no locks held by swapper/37/0.
> > > [   35.659746] stack backtrace:
> > > [   35.659746] CPU: 37 UID: 0 PID: 0 Comm: swapper/37 Not tainted 6.12.0-rc5-next-20241029 #57233
> > > [   35.659746] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS rel-1.14.0-0-g155821a1990b-prebuilt.qemu.org 04/01/2014
> > > [   35.659746] Call Trace:
> > > [   35.659746]  <IRQ>
> > > [   35.659746]  dump_stack_lvl+0x68/0xa0
> > > [   35.659746]  __lock_acquire+0x8fd/0x3b90
> > > [   35.659746]  ? start_secondary+0x113/0x210
> > > [   35.659746]  ? __pfx___lock_acquire+0x10/0x10
> > > [   35.659746]  ? __pfx___lock_acquire+0x10/0x10
> > > [   35.659746]  ? __pfx___lock_acquire+0x10/0x10
> > > [   35.659746]  ? __pfx___lock_acquire+0x10/0x10
> > > [   35.659746]  lock_acquire+0x19b/0x520
> > > [   35.659746]  ? put_cpu_partial+0x49/0x1b0
> > > [   35.659746]  ? __pfx_lock_acquire+0x10/0x10
> > > [   35.659746]  ? __pfx_lock_release+0x10/0x10
> > > [   35.659746]  ? lock_release+0x20f/0x6f0
> > > [   35.659746]  ? __pfx_lock_release+0x10/0x10
> > > [   35.659746]  ? lock_release+0x20f/0x6f0
> > > [   35.659746]  ? kasan_save_track+0x14/0x30
> > > [   35.659746]  put_cpu_partial+0x52/0x1b0
> > > [   35.659746]  ? put_cpu_partial+0x49/0x1b0
> > > [   35.659746]  ? __pfx_scf_handler_1+0x10/0x10
> > > [   35.659746]  __flush_smp_call_function_queue+0x2d2/0x600
> > 
> > How did we even get to put_cpu_partial directly from flushing smp calls?
> > SLUB doesn't use them, it uses queue_work_on)_ for flushing and that
> > flushing doesn't involve put_cpu_partial() AFAIK.
> > 
> > I think only slab allocation or free can lead to put_cpu_partial() that
> > would mean the backtrace is missing something. And that somebody does a slab
> > alloc/free from a smp callback, which I'd then assume isn't allowed?
> 

I think in this particular case, it is queuing a callback for
smp_call_function_single() which doesn't have an interrupt handle
thread AKAICT, that means the callback will be executed in non-threaded
hardirq context, and that makes locks must be taken with real interrupt
disabled.

Using irq_work might be fine, because it has a handler thread (but the
torture is for s(mp) c(all) f(unction), so replacing with irq_work is
not really fixing it ;-)).

Regards,
Boqun

> Tail-call optimization is hiding the caller. Compiling with
> -fno-optimize-sibling-calls exposes the caller. This gives the full
> picture:
> 
> [   40.321505] =============================
> [   40.322711] [ BUG: Invalid wait context ]
> [   40.323927] 6.12.0-rc5-next-20241030-dirty #4 Not tainted
> [   40.325502] -----------------------------
> [   40.326653] cpuhp/47/253 is trying to lock:
> [   40.327869] ffff8881ff9bf2f0 (&c->lock){....}-{3:3}, at: put_cpu_partial+0x48/0x1a0
> [   40.330081] other info that might help us debug this:
> [   40.331540] context-{2:2}
> [   40.332305] 3 locks held by cpuhp/47/253:
> [   40.333468]  #0: ffffffffae6e6910 (cpu_hotplug_lock){++++}-{0:0}, at: cpuhp_thread_fun+0xe0/0x590
> [   40.336048]  #1: ffffffffae6e9060 (cpuhp_state-down){+.+.}-{0:0}, at: cpuhp_thread_fun+0xe0/0x590
> [   40.338607]  #2: ffff8881002a6948 (&root->kernfs_rwsem){++++}-{4:4}, at: kernfs_remove_by_name_ns+0x78/0x100
> [   40.341454] stack backtrace:
> [   40.342291] CPU: 47 UID: 0 PID: 253 Comm: cpuhp/47 Not tainted 6.12.0-rc5-next-20241030-dirty #4
> [   40.344807] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.16.3-debian-1.16.3-2 04/01/2014
> [   40.347482] Call Trace:
> [   40.348199]  <IRQ>
> [   40.348827]  dump_stack_lvl+0x6b/0xa0
> [   40.349899]  dump_stack+0x10/0x20
> [   40.350850]  __lock_acquire+0x900/0x4010
> [   40.360290]  lock_acquire+0x191/0x4f0
> [   40.364850]  put_cpu_partial+0x51/0x1a0
> [   40.368341]  scf_handler+0x1bd/0x290
> [   40.370590]  scf_handler_1+0x4e/0xb0
> [   40.371630]  __flush_smp_call_function_queue+0x2dd/0x600
> [   40.373142]  generic_smp_call_function_single_interrupt+0xe/0x20
> [   40.374801]  __sysvec_call_function_single+0x50/0x280
> [   40.376214]  sysvec_call_function_single+0x6c/0x80
> [   40.377543]  </IRQ>
> [   40.378142]  <TASK>
> 
> And scf_handler does indeed tail-call kfree:
> 
> 	static void scf_handler(void *scfc_in)
> 	{
> 	[...]
> 		} else {
> 			kfree(scfcp);
> 		}
> 	}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ZyK7eGSWfEYzio_u%40Boquns-Mac-mini.local.
