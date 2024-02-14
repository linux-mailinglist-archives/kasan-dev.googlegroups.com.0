Return-Path: <kasan-dev+bncBC7OD3FKWUERBNMXWSXAMGQEPNLHCNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 485A78552A9
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 19:51:34 +0100 (CET)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-68efdf7e047sf1538236d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 10:51:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707936693; cv=pass;
        d=google.com; s=arc-20160816;
        b=aFw37XByRkjeM3g/fpfssF0mqrT79inAWZgmDyCA2k14tPpZBo3zeWzxaabkufUSDY
         Zdh4Kyd6XF3qFld6xQB5pzRfYM6jYiswV2G+I0o28ovrG0eY55ks3Qw/Bo6B6sFPGg8J
         OXWrPOIFApel/4JxhMIY6jCEzXVnLlAtvR+Y4K0UGYcR4sxiCTPIi2Zj8aEi5RVS75Mi
         TEye+3dWW2q5VskS8eOGIw2QbXW3iycJ9/OhylCpz/I95lC2ewZxIm/AnmuwORsTNq8G
         1kBVfPHaIc9oz4HfXEjFzoGvlB/Z5Nc45VxDPFq/LtEONnai9scVZuD7ZUTGjI4JQYR0
         kulQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=gDTllBoEW6X83pX/p+utgZZ+nt+91dfm1eN5cHkZfLI=;
        fh=hQGK6DevIT+aeqAWz2Cg+kCrdnITQM9zP0UscFzXvEw=;
        b=z+rP1i8VzKuZVejOEjnlC7Wq2TO1B9lOKx2DeMZfEz0H4jvwXl6zGhR1fMkj8GN2ba
         3vhouxZHK20FDcWzwxKMRsxSDsBEMbtBJrIsazAg/3+anq4b/w6iYFf1aBh2XXJifrkJ
         9/zNZhNCmWnQc5boHVrPTzw5S/eyJQWUSYF+NGehCNhIowmPDYM2HDnpp7Z95zol48O0
         Ap8qnAdncJDCcvKqoC5GltMNK/06J4+NNL1TXaUJ6IUtb/Pv4evjdxTe+F6Fhqn2IWYG
         t47L2gvj5PBRelVBGvcxdpWLnCQa4Jjej9Oihzh0/EZoaoy/dFj5HE0xfcUH+0SbHG3B
         UUXw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=3zETmSda;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707936693; x=1708541493; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gDTllBoEW6X83pX/p+utgZZ+nt+91dfm1eN5cHkZfLI=;
        b=sL+GxuWnVdQlSXuEeq/kv8dKtHlHGEF9e8VPXy3U004wF9X9PAqqBKU1jkWDI8cz7o
         yKHA6sPzkVKRKJxf9reCD0DwXSzG2KDJaHHOBmEP692lI1osFAHiJ0+WXSrI86LkKSTM
         Rn4P8EY+eSXfQW0g3CIQbGFVk1izS8fC3sgKI1R7IH7WNTUjLO9M2kQ790s7Z4J/HwIS
         3rTBm1TEnzdfkGFl8BlX5FXy16HNp19w4KP8d5S5fMc0pYot2fQQzsgFAT2BVboNCWCY
         DiIVKg3Lv8fC/UFr1A2BmbefOJsvrF9HHFrKyYELimys0OSJV+5fnxyn76YKmaKC3u2b
         0xng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707936693; x=1708541493;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=gDTllBoEW6X83pX/p+utgZZ+nt+91dfm1eN5cHkZfLI=;
        b=P5qlOIcWW+mqmSW4wRtDj0pfWb9a8qlyk/3I/nnV7e0OLlj/pCZXyc7r/SVKlikVCr
         0sw9nKomMZIDSSzHTVGn3vkIny9xx5dERNSs2E74p/VZShnYcOSfUsNZYANZ/RvQBMBs
         sZBKLvbC4oe15GDb1c0jBbqp0XDdimUH3LeHtIwVr1CA2RkBMZN4v7cMH5GH2kn9s8j4
         CQgVb1uqfn9+fKPkv22BNn2u1EC35Zth1tD8INilNCd0urQsngWj4LOkQk4BjRIO7md4
         QJOU9SURlVmhZp+2zQyqF0nHMs9bDhRNBSsPK+YRxm2iSwcxSM/Nm36xIYqjwhQ1iQv3
         k/Xg==
X-Forwarded-Encrypted: i=2; AJvYcCWiTr3t+Q9S7arlQbXFIKrPGFNwfBELQlgRLB4W3kYv12wwDTInbzt2c1xkf7QBOFLmcRBUS56z3dwWxPaliRznxC9Cq/CKQg==
X-Gm-Message-State: AOJu0Yzs35B3j37x0Wij3MfV+rrB3VCyR0jdc/Nz4+6Ayyokno7IFMXi
	KUiFK3gTchQM/hkEoT+VlCE4bYnAmbLFg1ZPrcVjiKwqa2qX8TXy
X-Google-Smtp-Source: AGHT+IG7cJw0nTJr9tDxqon6IsWbNEm+8cAgwq1J7QDQamRge2TZb7c/2RofP4xAYDYe/GZQ48w9OA==
X-Received: by 2002:a05:6214:ca4:b0:68f:258:c7d8 with SMTP id s4-20020a0562140ca400b0068f0258c7d8mr3014112qvs.19.1707936693157;
        Wed, 14 Feb 2024 10:51:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:5087:b0:68c:3663:a1f6 with SMTP id
 kk7-20020a056214508700b0068c3663a1f6ls2646963qvb.1.-pod-prod-07-us; Wed, 14
 Feb 2024 10:51:32 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU1amvy0UDKo52AwqgXLgIdDcS31prCYDQq2Am6fZrXE/kE+GrVGLpoqex/pacGUfw3AfVrfCe1eOwKI4xjeBXMoHn6s+VyPYYqtw==
X-Received: by 2002:ad4:5be2:0:b0:686:2ff1:8e46 with SMTP id k2-20020ad45be2000000b006862ff18e46mr3680751qvc.13.1707936692293;
        Wed, 14 Feb 2024 10:51:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707936692; cv=none;
        d=google.com; s=arc-20160816;
        b=qZSkayMgOO6UMbqHUulM2ZVgzuqpixzAvn50jU/p4waXWSnw3B6iCgW81lH3RKfkGi
         XDAFo4pUCZcme3woO7J1m8Sk7ExZWg39qT/bnMWBaFY9k7SlymWN2IeZ3GI9Kn9fuiIN
         2bnDXmFSyPOQHEAlxOd+4+540aIYoqHKXukv+/aZgkJgHOr340OwpJ55qWFVikhl1o0Z
         vp6Wzdshc51nxRqDoUbLejVit5Htm1IjQ2g/rh9G9fpa9LOLvMKYErYIDlZNVBR0lKFM
         2RbLco/qvi+xK7j3UDf5CStr9RbAI+6pf6NwKFSkFh8Tuh9oG7Wj3rmzliOlGrOwVsOv
         ZKKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Z3dYemjv+ptpRw8TmiD3eBcby1+9nhEoYONXK3+Hucc=;
        fh=5eugPaUpKrkT/lBqVg+kBXQ1JOwgrU1/ossDYefRxEw=;
        b=ZrjW6frLFvaya9ZUmqC3/19ZPeubM32TEaAmm7/PcTBQCeqkd76hPpw8un/oGH6RSt
         rTjbK0lUcHAbNN3Jz3G/PUoHd3nwTRrGcDUACRpbBa7hXxUcnANI2qVAE5lignG1lO9u
         xFFCXu8SIR5ZPN6LPWCpkvtsy7KT3NHMcNufYa+VnulzotfQgdBhbjXkjo+MlBz99EDn
         sewq7+2JUGkjVuwjv6JoQ1q5hJBYuYABWvm8EH2l4ZBDLyA9GD1zhRaH1rgUPdg0Fs4U
         iPMDT9iJDNQe9XCp6+nQaBFQ0LSTW4fmTaj1QffVqyc6dYjv90TqBJGm6wmJ2h2FHUSY
         beXA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=3zETmSda;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCX4O2PZcb/KWVvbOOymY+dsU13WYRJLv8/uu60HMzrqTCgbO2/exuIfOUBGyBJjLbU+F04TPVk6dokPEd2sic2tGCc0EprC7pkJ5w==
Received: from mail-yb1-xb2c.google.com (mail-yb1-xb2c.google.com. [2607:f8b0:4864:20::b2c])
        by gmr-mx.google.com with ESMTPS id w12-20020a0ce10c000000b0068efb69f5easi185014qvk.3.2024.02.14.10.51.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Feb 2024 10:51:32 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) client-ip=2607:f8b0:4864:20::b2c;
Received: by mail-yb1-xb2c.google.com with SMTP id 3f1490d57ef6-dc74435c428so5655893276.2
        for <kasan-dev@googlegroups.com>; Wed, 14 Feb 2024 10:51:32 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWSiIVxuOKSDm7etvzk6uviNf6eLKFDMlmJoVt8mCtuZJvh7TPnYqsVYwRQPDv4yGv5E/fhNLTTHL9gzBAdNQa+yIiR0yK3ZS3hmQ==
X-Received: by 2002:a25:a02a:0:b0:dc2:2b0d:613e with SMTP id
 x39-20020a25a02a000000b00dc22b0d613emr2929866ybh.10.1707936691500; Wed, 14
 Feb 2024 10:51:31 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <Zc0KEfoCVvP1kWvA@black.fi.intel.com>
In-Reply-To: <Zc0KEfoCVvP1kWvA@black.fi.intel.com>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 14 Feb 2024 10:51:16 -0800
Message-ID: <CAJuCfpHEbeF2Pve462nSqcEja_ygWGvbJqzkc+NGZefRxJ6VUw@mail.gmail.com>
Subject: Re: [PATCH v3 00/35] Memory allocation profiling
To: Andy Shevchenko <andy@black.fi.intel.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=3zETmSda;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as
 permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

On Wed, Feb 14, 2024 at 10:44=E2=80=AFAM Andy Shevchenko
<andy@black.fi.intel.com> wrote:
>
> On Mon, Feb 12, 2024 at 01:38:46PM -0800, Suren Baghdasaryan wrote:
> > Memory allocation, v3 and final:
>
> Would be nice to have --base added to cover letter. The very first patch
> can't be applied on today's Linux Next.

Sorry about that. It as based on Linus` ToT at the time of posting
(7521f258ea30 Merge tag 'mm-hotfixes-stable-2024-02-10-11-16' of
git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm). I also applied
it to mm-unstable with only one trivial merge conflict in one of the
patches.

>
> --
> With Best Regards,
> Andy Shevchenko
>
>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpHEbeF2Pve462nSqcEja_ygWGvbJqzkc%2BNGZefRxJ6VUw%40mail.gmai=
l.com.
