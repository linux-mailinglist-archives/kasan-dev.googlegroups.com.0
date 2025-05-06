Return-Path: <kasan-dev+bncBAABBVPN4XAAMGQECNV56NI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 4BF0AAAADBB
	for <lists+kasan-dev@lfdr.de>; Tue,  6 May 2025 04:41:27 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-3d970d75b64sf60198545ab.3
        for <lists+kasan-dev@lfdr.de>; Mon, 05 May 2025 19:41:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746499286; cv=pass;
        d=google.com; s=arc-20240605;
        b=XO2XoxGvTZw6E3pm28XpmnFpdap2wY54fGQIpcIr7CUxoqmrRezLlSojnOUDAvoJ69
         ubIvmrqsUXW5L8xP4uwKX78u8oOW+H2BlTATFH+j9wlCatgne/VDFEKNmH0L5qHAQVVP
         H6eX2XBV8+id7t4ljXHApZo/NviscoLqqf63li2W/1QRq3MY4Z4KHEbv/+0/oDaH1RVF
         fkGQNIVE+LNLi7GLp4AV7X+8PAJgNcWTvenphdNE0D5FfNHpKMFvKwNX/PlHX9q0BNCw
         4aNIbIrYc+MDYlcShBKuKiE74Hm+sQfbz8Q9gs+axKi+vfvEHwcH39IQuuBusajgJtZm
         9vwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:feedback-id
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=IC2vIm9htlEQUbJ/hm8AwUcCl0Q2LWHU8bERA9TZLqA=;
        fh=zOOyWrqMgXOL6cSFdSJQPlsUUo7BxOLZV4/xZoNy05k=;
        b=MzQkMZxGGQrcjg4nwJZND6/37P2m6+hmdLHkJ8n/0+yry/cWbg7xbN9vobVQJ9ZN0c
         SOB3BOldkrvd3oAVdtOzyJZzpdaMXXV7dFiDzP/eJjqgeAGj66rcDaN6yZnHYvZFuqBg
         sUuMegsTLM55tn3loevJRSXn38O0B01ldOWJQ2B1E7i96eGwRExQOjRFOzJbY7DHP8ZP
         HtC+znGbY3bZlCkACw0b2O62EdKKUNH44UvQScvKVmgeG80QnJSX0fXA1Riwvesg3pTY
         ljY7+j8Pg9kuXPq1TBt8ZUSN7njsCMDksxfYab+ot9Hca7kNPY9SIfqIlkdl7FGWQSXp
         5cvg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@uniontech.com header.s=onoh2408 header.b=CTw4vjs7;
       spf=pass (google.com: domain of chenlinxuan@uniontech.com designates 54.243.244.52 as permitted sender) smtp.mailfrom=chenlinxuan@uniontech.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=uniontech.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746499286; x=1747104086; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:feedback-id:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=IC2vIm9htlEQUbJ/hm8AwUcCl0Q2LWHU8bERA9TZLqA=;
        b=RiTXX0v8vmEOfyDtNcS1mLmgL80jwlJEsWWzw8eo+2V/IDjrUWeQg1HyB75ygQZGCQ
         k5woMMFyjqnjIl0chA6td/Cjlp1VQeBDjIhezaR8Z7pU0JQmSQmnFKxtHoR/6FgH0MTt
         4jIjtbU6YwidYZ0vl/crxpdXcGbB8Zf9YIYGHmvQ+jDWyx5UnBfG6sU8uk+NzgErlGEM
         G1ysZyJxjAbBRVqqXRRcmRzXYXyTc275MPMWg4ddPDX2DydqmjarozIR+YMxHB2kCCOI
         pvBVvn/BuSdnW1vXmIeY0AxKC6hGMADML+jmNCDEETorlPh5BjolQ1lxgflUuQaD4YOW
         p/mA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746499286; x=1747104086;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:feedback-id
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=IC2vIm9htlEQUbJ/hm8AwUcCl0Q2LWHU8bERA9TZLqA=;
        b=vmYL18SlR3kJ33MEtrjUHoBXM1gYcrQfse8/HU5X2QFN6oTR5Qr385DDYbNrioDbRL
         m8IW6hh+YBDCL2cS5HVLS43NCzyWkTxOCwSV0tDARhAJhAhwo3fshkRP/Eahio+tnPDh
         xTTztxgMAz1j0isT2Xm/DF6+qs0NV1IpUi8/DkmQAzUsXBJBt5IC9O6jUg/NO3o29+Hh
         156QCBQr/+FUbjZ9ZgCd4RfaaqVaYZv9UigbvAAETAG9kbbO5y2SCAP2yzhW2ROZJz36
         q3HZFpu6Wb173S9jsWNonhNbVUFAOSSokBv1G5Wm6icmx2C2IJlmEbaBVWXcaJngVw1z
         rsHA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVmhDNMxh9RCUeUeXgryKXQ8A29GB6LrfcZkkR9VedfiG0saPkle8efAVukS6ceBC+r/cifnQ==@lfdr.de
X-Gm-Message-State: AOJu0YzsTmh+8RUfDEITXo0XVF77M6pkYzA+aCuBo5OcEgRP4NrJks2x
	Ynj7YwZYQPeT8tndcAocwjGf34sIN3hG9jLLSnRgz5hLhvHAmnvp
X-Google-Smtp-Source: AGHT+IH27m6JAm/7nf6JfzuudWkjadPtTTUbntkK1Z/czUzyP3y4b0fIMtuW5t5NmmZmShKosy/lLA==
X-Received: by 2002:a05:6e02:3786:b0:3d5:d6ad:286a with SMTP id e9e14a558f8ab-3da6ce5e264mr13681935ab.13.1746499285984;
        Mon, 05 May 2025 19:41:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBFKatyeo+JcjoEq9U6tmpes+HmlUgvYUe2ZTWD0z4i8yQ==
Received: by 2002:a05:6e02:198f:b0:3d8:1622:6006 with SMTP id
 e9e14a558f8ab-3d96e708599ls23542205ab.0.-pod-prod-03-us; Mon, 05 May 2025
 19:41:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXlcvaVlHVonVvI4IoWK75xG+VXuoRUE/irjW9GCLhiTg8mUn+y/T72fsBXNSXkCea1/dbh/F/uslc=@googlegroups.com
X-Received: by 2002:a05:6e02:b4c:b0:3d3:fbae:3978 with SMTP id e9e14a558f8ab-3da6ce54c74mr14015025ab.9.1746499285418;
        Mon, 05 May 2025 19:41:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746499285; cv=none;
        d=google.com; s=arc-20240605;
        b=eqGw6mKNU03Hq5QOFPf+pXUXdkaHv/fTWrRHWmNDrpccxrHM2uAPJ170LyxLk65pV2
         ebzwAuCJOiVeopoJnxXazFSIRydR8jwaKEZLvWIdszUKUll1bA6zF0vJCmZ/cSHuqLon
         eLpR5dT6RsqKR6IQss1tDH/Ztfk/ehLXO4Icagb/oj7002pUF9VuzFm8LS4sMxGTXvdD
         ln8YsZ7WDlv4yFEn7Cby75UEJMgfCCR3B4XrzeAEJ1+pjbfUJlWgnZGFHBULH8SaUqlw
         0WeOgrsjEZcwNE93E9z9FrQeTeG23IXRjLGgoGMtcqiLSwRg8BEwd6uodq6xE96iH4bF
         VYzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=feedback-id:content-transfer-encoding:cc:to:subject:message-id:date
         :from:in-reply-to:references:mime-version:dkim-signature;
        bh=dDn4W5v9t6AyHBHxLWO7FuLjj98KbpZnLxWf1Zria3s=;
        fh=oH5s7IOsr7e1QuXh4XVUp4ZF30KW6j6bZIB0twkK6f8=;
        b=V//T7Q9Ik6UsFOzScEeS/tZ3kjk/sn4Mn+LAD+kvKZNEagFOnR3MyZJcDVgRlCD/a0
         K5npVXut8Krdp3qRSlxxWfuD3ZoYuZ80lbLaheR8Ka9akDH3BaRRWM0W5mtzai4P9Q87
         GoNLQlsHlTK3rbDgiqGjE5Wnq01IvmEL9J/q+3Yl6KaRu4iBTD8+fS41GcdBkiZ77GTD
         DWdSkWEf+7we8Nq4TntUKepjjTsxw1YCzEVMOGv6QlFEcUeb/ekz5W+aPAhfkNbR0q1u
         iO/9LMTxrseFMiYEU2ZYs+aGPY8aTQObdycxL2ciKFlSRjMUuYyHBkskXnSP4FhIFS5+
         nQYg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@uniontech.com header.s=onoh2408 header.b=CTw4vjs7;
       spf=pass (google.com: domain of chenlinxuan@uniontech.com designates 54.243.244.52 as permitted sender) smtp.mailfrom=chenlinxuan@uniontech.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=uniontech.com
Received: from smtpbguseast3.qq.com (smtpbguseast3.qq.com. [54.243.244.52])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3d975e6eef9si990865ab.2.2025.05.05.19.41.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 05 May 2025 19:41:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenlinxuan@uniontech.com designates 54.243.244.52 as permitted sender) client-ip=54.243.244.52;
X-QQ-mid: esmtpgz11t1746499273tf8af5d33
X-QQ-Originating-IP: 8lGnvXPDGj+LObl89uND17rbtYMae/UMoOpM0lAdy0w=
Received: from mail-yb1-f179.google.com ( [209.85.219.179])
	by bizesmtp.qq.com (ESMTP) with SMTP id 0
	for <kasan-dev@googlegroups.com>; Tue, 06 May 2025 10:41:11 +0800 (CST)
X-QQ-SSF: 0000000000000000000000000000000
X-QQ-GoodBg: 0
X-BIZMAIL-ID: 2464262057826349361
Received: by mail-yb1-f179.google.com with SMTP id 3f1490d57ef6-e733b858574so4734524276.2
        for <kasan-dev@googlegroups.com>; Mon, 05 May 2025 19:41:12 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXx2CplI0AxGw6Ko3MqncTUEU5eTyg6uFn1imS2UZHgUKgAGMS3/pl9AE25bCh3SVraT5wSApepHGA=@googlegroups.com
X-Received: by 2002:a05:6902:1ac5:b0:e6d:f3ca:3e15 with SMTP id
 3f1490d57ef6-e75c08b698bmr1960395276.3.1746499270786; Mon, 05 May 2025
 19:41:10 -0700 (PDT)
MIME-Version: 1.0
References: <20250429-noautoinline-v3-0-4c49f28ea5b5@uniontech.com>
 <20250429123504.GA13093@lst.de> <D9KW1QQR88EY.2TOSTVYZZH5KN@google.com>
 <20250501150229.GU4439@noisy.programming.kicks-ass.net> <D9KXE2YX8R2M.3L7Q6NVIXKPE9@google.com>
 <08163d8b-4056-4b84-82a1-3dd553ee6468@acm.org>
In-Reply-To: <08163d8b-4056-4b84-82a1-3dd553ee6468@acm.org>
From: Chen Linxuan <chenlinxuan@uniontech.com>
Date: Tue, 6 May 2025 10:40:59 +0800
X-Gmail-Original-Message-ID: <973B455678FC1BDD+CAC1kPDM2pUEwFRiUZFHKq_7sYpjARkFczJnp_FRu+r9-xYdgKg@mail.gmail.com>
X-Gm-Features: ATxdqUHhA0M6lhr1xavQzClQ8qzartLkG1qHh9aYbVlX-6LFgZ39KxjHPoTQnkI
Message-ID: <CAC1kPDM2pUEwFRiUZFHKq_7sYpjARkFczJnp_FRu+r9-xYdgKg@mail.gmail.com>
Subject: Re: [PATCH RFC v3 0/8] kernel-hacking: introduce CONFIG_NO_AUTO_INLINE
To: Bart Van Assche <bvanassche@acm.org>
Cc: Brendan Jackman <jackmanb@google.com>, Peter Zijlstra <peterz@infradead.org>, 
	Christoph Hellwig <hch@lst.de>, chenlinxuan@uniontech.com, Keith Busch <kbusch@kernel.org>, 
	Jens Axboe <axboe@kernel.dk>, Sagi Grimberg <sagi@grimberg.me>, 
	Andrew Morton <akpm@linux-foundation.org>, Yishai Hadas <yishaih@nvidia.com>, 
	Jason Gunthorpe <jgg@ziepe.ca>, Shameer Kolothum <shameerali.kolothum.thodi@huawei.com>, 
	Kevin Tian <kevin.tian@intel.com>, Alex Williamson <alex.williamson@redhat.com>, 
	Peter Huewe <peterhuewe@gmx.de>, Jarkko Sakkinen <jarkko@kernel.org>, 
	Masahiro Yamada <masahiroy@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Nicolas Schier <nicolas.schier@linux.dev>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Bill Wendling <morbo@google.com>, 
	Justin Stitt <justinstitt@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>, 
	Johannes Weiner <hannes@cmpxchg.org>, Zi Yan <ziy@nvidia.com>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Juergen Gross <jgross@suse.com>, 
	Boris Ostrovsky <boris.ostrovsky@oracle.com>, Thomas Gleixner <tglx@linutronix.de>, 
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, linux-nvme@lists.infradead.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, kvm@vger.kernel.org, 
	virtualization@lists.linux.dev, linux-integrity@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, llvm@lists.linux.dev, 
	Winston Wen <wentao@uniontech.com>, kasan-dev@googlegroups.com, 
	xen-devel@lists.xenproject.org, Changbin Du <changbin.du@intel.com>, 
	Linus Torvalds <torvalds@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-QQ-SENDSIZE: 520
Feedback-ID: esmtpgz:uniontech.com:qybglogicsvrgz:qybglogicsvrgz5a-1
X-QQ-XMAILINFO: NrxvMG+AXCyEr8nOWJPdkODDPPLOnJbJuqMVTHQbub7tfNFLOkSiFjzh
	+cDe9rdFONZv5R1+62VoEy9wy8/o3yGIkEPS+k9Bv82BdOEB2PbrLKBs2wOyFfUt/9NEfV6
	Rvz7CfNdYjXSmDDFJuM2W38Kj7ja22GFDNg6yeqfFyQlLpQf7XtGqeQbTnHPELVdofgc5Ml
	lLcym09H4f6OsGb6TZJEC8YchCHLAil5Yr30jfexMUhYCtyv0t9EHaSmKIWP7K5B+TX06BD
	gJ2zey0LriZrV928xeWANJxzeeapSk43Az6F/FcCb3ajsNIdVexFJPYqaSx6AHpGagPkdLN
	3/B0BDfmQLzDmIUUT2owNGrmGwoP1uakjE+9bnVO6/4HQl7yvjQtfu3TUkzWOcZ/narnCRn
	6fUOJ8tmUH/5r/ci+fawAEYTTjRvgX/0R19WUv82ub3UeF3k/CChWM/B8q7V+f0RpDkUhTZ
	xFYlhsxVdtFVMXOtNSwFrwE/3JIzPketwPVs7pglxQkvEw0CHTQZPridD7cajRRQvixc2or
	wd7IOlzC1tXEFOk54j0oZzobqNP8DzFwf7DczZHggjdo+sp/d+7h3XrXJb/MSoUBd5oOu4K
	AS+xDlhX+L7k5+9PmQfeWGR0aOImUUUHEqC4RDxry0E/OU8G9j421PFw7RbXJjO/mfdDjJ/
	ILfMGXT787RDrfIKVxXkeIz2urNBjZut98t0vHLwSZ/ylnDTZddsi8Ct2cbdATmhkGwTOu4
	QX2kGFMs1xPGU+sa9ZnFTiNUnl+JOKqIBEHDHwXoUDoy16R9w1IX3nUUBW6NCW+ILtUDPZ+
	SvU5e9UU5SGAD3nKi6j0tGM0/TiLm77gXXyNjQTPdFx9K/pwo7mIbdlIAXa2t1J1L5Aj8bu
	t59w4vU2kCrXM8rLC+g/lr//N+ykYBph65/wYm10v/6zerV7roCFrjphFHxQPZzMyAGlLR1
	wNdeojAWLt5b42zbCnZfJEoU/1Iwj9SGhE80eaaWyEN7JQQlmdAAqvYvAS6V1w9i6kwqzQS
	QTzMCedGo64Su0wT5WvEgNUwJ+oYL8DGbGZesqzntciZ8v6rT4CFVE5fcgErELQcfbLDfjP
	Q==
X-QQ-XMRINFO: Mp0Kj//9VHAxr69bL5MkOOs=
X-QQ-RECHKSPAM: 0
X-Original-Sender: chenlinxuan@uniontech.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@uniontech.com header.s=onoh2408 header.b=CTw4vjs7;       spf=pass
 (google.com: domain of chenlinxuan@uniontech.com designates 54.243.244.52 as
 permitted sender) smtp.mailfrom=chenlinxuan@uniontech.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=uniontech.com
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

On Sun, May 4, 2025 at 3:14=E2=80=AFAM Bart Van Assche <bvanassche@acm.org>=
 wrote:

> If this is for test builds only, has it been consider to add
> -fno-inline-functions as a local change in the top-level Makefile?

The issue here is that the current kernel cannot be compiled when
these compiler options that reduce inlining behavior are added.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AC1kPDM2pUEwFRiUZFHKq_7sYpjARkFczJnp_FRu%2Br9-xYdgKg%40mail.gmail.com.
