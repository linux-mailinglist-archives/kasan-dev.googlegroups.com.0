Return-Path: <kasan-dev+bncBDEZDPVRZMARBBMZRTDAMGQEYJHVIUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 20F81B53AC4
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Sep 2025 19:53:11 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-721094e78e5sf10673966d6.1
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Sep 2025 10:53:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757613190; cv=pass;
        d=google.com; s=arc-20240605;
        b=hyVJpZSI+/g32Grm+iEAYXvIlvNRy9uLmjbZKNjTPwRJ+K4Mm3lnv+OdmlEFkUD2Ep
         hpxJvU6rzkGHAbCX3/kEsv+fIub6kOPwFc/jW4dNiWkIKmRVT+I86cHpS5k0oT3Tg6GJ
         DukQl4UQFjS4aj0xWq1xgE6v2gBt7OaEn+19gHHWSb/dt5SYlJ8rWk5Hac83Y6z+nIB4
         Om/weEyAgIfXnVChtT+CuAxzlHEahWHCkEomhJkqDM1sscUoOLrw82AsaDC1vbSa/I6L
         BRzI9/XUpLrusW9XwPuoHZzg2KarLaBaDKeNWLxL009wpTm2rmJxoieIwko03g6xmTDX
         2rgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=42avIuNiGvo3vGBi4Z0kGmH4fJbAM5RTnkFh2AqN4aM=;
        fh=WczkOn3Gjfyj3rAXlVrSkHmT9BJjCnkR7tuSuFF0cvY=;
        b=Z6+w3+PGVU6HUW7Lz2DhSaMJ/D5JLGS5MJ6VKpV7qUL73iI7fUalBd9a1QQbohaa70
         VPIjWUhn8SA3f9sOOds9g9aAziYSA6yopuzqqvJyLqXKYHjyoQppbKeUn34lUcBRW+p/
         S4LgP5T02h00CJUybxhRYWGvitYyWUwLg3gjmrH3dV9xaZxIRnMAZok4C4nVtlc0sCNP
         /+1peg2UYw8cYjhXIve461xpWuOW6K3RmYvP8ZDEZWzpiTvFY8YZ99rQqRvBF1ukFs7E
         ZIYqNwFfYT+b5mFGiW2Ju76fZlgXXnpSqhf07TzsopWYFemwu5lL2oIAwuv2fe2N4VpA
         mPBg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Bkf3Wnkq;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757613190; x=1758217990; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=42avIuNiGvo3vGBi4Z0kGmH4fJbAM5RTnkFh2AqN4aM=;
        b=ZCevkPg69rgpG5qjPqNjDRw4XZ2hT2helU1yd57VZldBN7LN8DPsh3OI1I8PhObW2S
         LTY4FNRnVh8cPiNI1wZQiMqmeE5xI2FhGYm7I1gxE8srg+NbuXjaRigd7goHp/IPLUOu
         IhrXxLwaGPkoqVVcuAjt763wkEG6y8mSzMCX7D32IO9HL/0UYaKbH+UztOzBm01BbNOa
         8XKUAUL3BU2t6U61/cwMUiUIEdtjjAGlhLiSdvUKdsrNJZAS1CccTPxnVqJZGxsTHKj4
         IoEJmPYrAoYbvKlfZufdCpi40QITejBn+UFoSskepalbEhLkpu2ABoHrUeadN5M5Z36E
         r5YA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757613190; x=1758217990;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=42avIuNiGvo3vGBi4Z0kGmH4fJbAM5RTnkFh2AqN4aM=;
        b=FZtN1iLLFLi+cBzXg1u0LPGRhPCPks8+6BP92Sr3pajJrXWGLjR/dbNmbCWO9H9zHv
         BBEnR/pam1jfxfs56k7H3BmfzCcE7icsaFVKKDL8zbY+T0Djnau3UYJBhZ9k7/2KGp9Y
         RyomS1TXZLLmx/RhRFPaLtgwyC/IAagdws6Laz7Agrb3ptVgo9UQxUjCazmA2GLsWOjj
         Aj98bH4ztIa4ds2c2uLD98IAFWZs+pc95uHEaAKoaGgTaCXNmcGNDBQOLnO1INu5SPWl
         ZgUBT1crOm1qE31Z88ga2HxqVJp+mK7po8Mawk9+xcSzwtCYK83Artow50m+6XEAyz2u
         Lnsw==
X-Forwarded-Encrypted: i=2; AJvYcCWgEgqUIWGpqavu0MCDPP8dGKkbYsTCDJt9pWDg/T6nqTaoVB9x2tWjg+xH9lu8yFWhc9XUOg==@lfdr.de
X-Gm-Message-State: AOJu0YzF63OZgOFIcvHI4rHbiPkOENQ1Ahze8gwuXJ8e/Lirby6SI7nX
	IssRp8cgbzXqMVI7y4X5JYk1b6tckHMeeq8S3r6mDYFQMLtG7T1B7dNp
X-Google-Smtp-Source: AGHT+IEg7cxet3NigL44GJSPM8QqnF1bCplq8yUBe8SDnI4C0+eagW66k+VkHvokxEZLJ7KKXzh5Fw==
X-Received: by 2002:a05:6214:ccd:b0:72a:3858:74b6 with SMTP id 6a1803df08f44-767c65803fdmr2616136d6.66.1757613189663;
        Thu, 11 Sep 2025 10:53:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5hCJ75k5+zumwBJTYZSF1NwEWX2nTZDE35LC6hrs7DCg==
Received: by 2002:a05:6214:268b:b0:70b:acc1:ba4f with SMTP id
 6a1803df08f44-762e3265b34ls15252696d6.1.-pod-prod-08-us; Thu, 11 Sep 2025
 10:53:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVCCWfkFS3ul2P9TZOCcdVejTiSh2rux1xEefKLHk1pysJwns1ce+MSUoxzT8Xw3N5jseYvNNJWz6E=@googlegroups.com
X-Received: by 2002:a05:6214:1d24:b0:72a:f29e:72c5 with SMTP id 6a1803df08f44-767bc9e39e7mr3656326d6.24.1757613187563;
        Thu, 11 Sep 2025 10:53:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757613187; cv=none;
        d=google.com; s=arc-20240605;
        b=BcL/EdRwn8FYG/0agPjPsGcPi4GiXQgDpLTNhysiFrYQdNGciqvsmUtPopPtDG/vW1
         GmCMqw+dOGFViYibaNljYaSvI+ig9rie11eyr+FOVKdKSptBrilG0M9r3p41LE2UPVcB
         vV4KMkEA1fMvw7+cpDfaI0eP0zP3Bxj5rvmq+uM8KqHiw/I4O9X+XjIbxApCYL5rJExd
         nsut4oXy0vzlFA2QiNbInJVmwi+Ha1rVviPUCHZQ8pHsGw9OY8a15qHNMdLaQ6E8Ji3Z
         vx95G5Xm0B9/91+sF/WvYEbQMzqJIxU/HrHrUpicieCxxyJray/icnP2WFoPFZp+ckVr
         Zc8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=Dtns83FC3YsvcEfVkCRkQi8rN9yb9Edlp++8Gk32kgE=;
        fh=vHgtsy43R8RJtzyTW4VMnFfccRlknnLvBvTjgt3SY6o=;
        b=GEIcj16DJ1yNi0K4WvhrqaNEFaVHiESN4Xdn6SDEmby89Pv6+TToHFLNebDo/1kXm8
         DtETXv2gpIL7yimfI+52xCFpLjBZYK04/jW/I6FbnJRXtWzON+tPGWyB10EU83T6Wzsm
         0Eapg2cAkE+G8yKNlTRyhxWxqalbqgappBUS+vVsrhI6gG/fc+Z93G6w+myQbBoESBBW
         AuJrvguzUkojG/9whiQgNbHtKV+N8FbGLocRzz90sDdBjXJOOysTdop4y6pWYfdR4R5F
         UmIT5Dq3Z1Fdukswo40s4rVQC/grmjvI6ndk49Fsf7S1Kl5LoXSs+0iWaHt10s6ikjbw
         rQGA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Bkf3Wnkq;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-763bad40f92si766446d6.5.2025.09.11.10.53.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Sep 2025 10:53:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiggers@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id ACBF6436CF;
	Thu, 11 Sep 2025 17:53:06 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 520F5C4CEF0;
	Thu, 11 Sep 2025 17:53:06 +0000 (UTC)
Date: Thu, 11 Sep 2025 10:51:45 -0700
From: "'Eric Biggers' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>, kasan-dev@googlegroups.com,
	Dmitry Vyukov <dvyukov@google.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, linux-crypto@vger.kernel.org,
	stable@vger.kernel.org
Subject: Re: [PATCH] kmsan: Fix out-of-bounds access to shadow memory
Message-ID: <20250911175145.GA1376@sol>
References: <20250829164500.324329-1-ebiggers@kernel.org>
 <20250910194921.GA3153735@google.com>
 <CAG_fn=W_7o6ANs94GwoYjyjvY5kSFYHB6DwfE+oXM7TP1eP5dw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAG_fn=W_7o6ANs94GwoYjyjvY5kSFYHB6DwfE+oXM7TP1eP5dw@mail.gmail.com>
X-Original-Sender: ebiggers@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Bkf3Wnkq;       spf=pass
 (google.com: domain of ebiggers@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Eric Biggers <ebiggers@kernel.org>
Reply-To: Eric Biggers <ebiggers@kernel.org>
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

On Thu, Sep 11, 2025 at 11:09:17AM +0200, Alexander Potapenko wrote:
> On Wed, Sep 10, 2025 at 9:49=E2=80=AFPM Eric Biggers <ebiggers@kernel.org=
> wrote:
> >
> > On Fri, Aug 29, 2025 at 09:45:00AM -0700, Eric Biggers wrote:
> > > Running sha224_kunit on a KMSAN-enabled kernel results in a crash in
> > > kmsan_internal_set_shadow_origin():
> > >
> > >     BUG: unable to handle page fault for address: ffffbc3840291000
> > >     #PF: supervisor read access in kernel mode
> > >     #PF: error_code(0x0000) - not-present page
> > >     PGD 1810067 P4D 1810067 PUD 192d067 PMD 3c17067 PTE 0
> > >     Oops: 0000 [#1] SMP NOPTI
> > >     CPU: 0 UID: 0 PID: 81 Comm: kunit_try_catch Tainted: G           =
      N  6.17.0-rc3 #10 PREEMPT(voluntary)
> > >     Tainted: [N]=3DTEST
> > >     Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1=
.17.0-0-gb52ca86e094d-prebuilt.qemu.org 04/01/2014
> > >     RIP: 0010:kmsan_internal_set_shadow_origin+0x91/0x100
> > >     [...]
> > >     Call Trace:
> > >     <TASK>
> > >     __msan_memset+0xee/0x1a0
> > >     sha224_final+0x9e/0x350
> > >     test_hash_buffer_overruns+0x46f/0x5f0
> > >     ? kmsan_get_shadow_origin_ptr+0x46/0xa0
> > >     ? __pfx_test_hash_buffer_overruns+0x10/0x10
> > >     kunit_try_run_case+0x198/0xa00
> >
> > Any thoughts on this patch from the KMSAN folks?  I'd love to add
> > CONFIG_KMSAN=3Dy to my crypto subsystem testing, but unfortunately the
> > kernel crashes due to this bug :-(
> >
> > - Eric
>=20
> Sorry, I was out in August and missed this email when digging through my =
inbox.
>=20
> Curiously, I couldn't find any relevant crashes on the KMSAN syzbot
> instance, but the issue is legit.
> Thank you so much for fixing this!
>=20
> Any chance you can add a test case for it to mm/kmsan/kmsan_test.c?

Unfortunately most of the KMSAN test cases already fail on upstream,
which makes it difficult to develop new ones:

[    1.322395] KTAP version 1
[    1.322899] 1..1
[    1.323644]     KTAP version 1
[    1.324142]     # Subtest: kmsan
[    1.324650]     # module: kmsan_test
[    1.324667]     1..24
[    1.325990]     # test_uninit_kmalloc: uninitialized kmalloc test (UMR r=
eport)
[    1.327078] *ptr is true
[    1.327525]     # test_uninit_kmalloc: EXPECTATION FAILED at mm/kmsan/km=
san_test.c:173
                   Expected report_matches(&expect) to be true, but is fals=
e
[    1.330117]     not ok 1 test_uninit_kmalloc
[    1.330474]     # test_init_kmalloc: initialized kmalloc test (no report=
s)
[    1.332129] *ptr is false
[    1.333384]     ok 2 test_init_kmalloc
[    1.333729]     # test_init_kzalloc: initialized kzalloc test (no report=
s)
[    1.335285] *ptr is false
[    1.339418]     ok 3 test_init_kzalloc
[    1.339791]     # test_uninit_stack_var: uninitialized stack variable (U=
MR report)
[    1.341484] cond is false
[    1.341927]     # test_uninit_stack_var: EXPECTATION FAILED at mm/kmsan/=
kmsan_test.c:211
                   Expected report_matches(&expect) to be true, but is fals=
e
[    1.344844]     not ok 4 test_uninit_stack_var
[    1.345262]     # test_init_stack_var: initialized stack variable (no re=
ports)
[    1.347083] cond is true
[    1.347847]     ok 5 test_init_stack_var
[    1.348145]     # test_params: uninit passed through a function paramete=
r (UMR report)
[    1.349926] arg1 is false
[    1.350338] arg2 is false
[    1.350746] arg is false
[    1.351154] arg1 is false
[    1.351561] arg2 is true
[    1.351987]     # test_params: EXPECTATION FAILED at mm/kmsan/kmsan_test=
.c:262
                   Expected report_matches(&expect) to be true, but is fals=
e
[    1.354751]     not ok 6 test_params
[    1.355229]     # test_uninit_multiple_params: uninitialized local passe=
d to fn (UMR report)
[    1.357056] signed_sum3(a, b, c) is true
[    1.357677]     # test_uninit_multiple_params: EXPECTATION FAILED at mm/=
kmsan/kmsan_test.c:282
                   Expected report_matches(&expect) to be true, but is fals=
e
[    1.360393]     not ok 7 test_uninit_multiple_params
[    1.360676]     # test_uninit_kmsan_check_memory: kmsan_check_memory() c=
alled on uninit local (UMR report)
[    1.362916]     # test_uninit_kmsan_check_memory: EXPECTATION FAILED at =
mm/kmsan/kmsan_test.c:309
                   Expected report_matches(&expect) to be true, but is fals=
e
[    1.365946]     not ok 8 test_uninit_kmsan_check_memory
[    1.366415]     # test_init_kmsan_vmap_vunmap: pages initialized via vma=
p (no reports)
[    1.368805]     ok 9 test_init_kmsan_vmap_vunmap
[    1.369223]     # test_init_vmalloc: vmalloc buffer can be initialized (=
no reports)
[    1.371106] buf[0] is true
[    1.371937]     ok 10 test_init_vmalloc
[    1.372396]     # test_uaf: use-after-free in kmalloc-ed buffer (UMR rep=
ort)
[    1.374021] value is true
[    1.374463]     # test_uaf: EXPECTATION FAILED at mm/kmsan/kmsan_test.c:=
378
                   Expected report_matches(&expect) to be true, but is fals=
e
[    1.376867]     not ok 11 test_uaf
[    1.377229]     # test_percpu_propagate: uninit local stored to per_cpu =
memory (UMR report)
[    1.378951] check is false
[    1.379432]     # test_percpu_propagate: EXPECTATION FAILED at mm/kmsan/=
kmsan_test.c:396
                   Expected report_matches(&expect) to be true, but is fals=
e
[    1.382201]     not ok 12 test_percpu_propagate
[    1.382625]     # test_printk: uninit local passed to pr_info() (UMR rep=
ort)
[    1.384329] ffffc900002bfcd4 contains 0
[    1.384933]     # test_printk: EXPECTATION FAILED at mm/kmsan/kmsan_test=
.c:418
                   Expected report_matches(&expect) to be true, but is fals=
e
[    1.387474]     not ok 13 test_printk
[    1.387824]     # test_init_memcpy: memcpy()ing aligned initialized src =
to aligned dst (no reports)
[    1.390061]     ok 14 test_init_memcpy
[    1.390327]     # test_memcpy_aligned_to_aligned: memcpy()ing aligned un=
init src to aligned dst (UMR report)
[    1.392359]     # test_memcpy_aligned_to_aligned: EXPECTATION FAILED at =
mm/kmsan/kmsan_test.c:459
                   Expected report_matches(&expect) to be true, but is fals=
e
[    1.395181]     not ok 15 test_memcpy_aligned_to_aligned
[    1.395467]     # test_memcpy_aligned_to_unaligned: memcpy()ing aligned =
uninit src to unaligned dst (UMR report)
[    1.397845]     # test_memcpy_aligned_to_unaligned: EXPECTATION FAILED a=
t mm/kmsan/kmsan_test.c:483
                   Expected report_matches(&expect) to be true, but is fals=
e
[    1.400221]     # test_memcpy_aligned_to_unaligned: EXPECTATION FAILED a=
t mm/kmsan/kmsan_test.c:486
                   Expected report_matches(&expect) to be true, but is fals=
e
[    1.403059]     not ok 16 test_memcpy_aligned_to_unaligned
[    1.403437]     # test_memcpy_initialized_gap: unaligned 4-byte initiali=
zed value gets a nonzero origin after memcpy() - (2 UMR reports)
[    1.406077]     # test_memcpy_initialized_gap: EXPECTATION FAILED at mm/=
kmsan/kmsan_test.c:532
                   Expected report_matches(&expect) to be true, but is fals=
e
[    1.408340]     # test_memcpy_initialized_gap: EXPECTATION FAILED at mm/=
kmsan/kmsan_test.c:538
                   Expected report_matches(&expect) to be true, but is fals=
e
[    1.411063]     not ok 17 test_memcpy_initialized_gap
[    1.411338]     # test_memset16: memset16() should initialize memory
[    1.413393]     ok 18 test_memset16
[    1.413651]     # test_memset32: memset32() should initialize memory
[    1.415427]     ok 19 test_memset32
[    1.415739]     # test_memset64: memset64() should initialize memory
[    1.417513]     ok 20 test_memset64
[    1.417783]     # test_long_origin_chain: origin chain exceeding KMSAN_M=
AX_ORIGIN_DEPTH (UMR report)
[    1.419805]     # test_long_origin_chain: EXPECTATION FAILED at mm/kmsan=
/kmsan_test.c:584
                   Expected report_matches(&expect) to be true, but is fals=
e
[    1.422415]     not ok 21 test_long_origin_chain
[    1.422752]     # test_stackdepot_roundtrip: testing stackdepot roundtri=
p (no reports)
[    1.424598]  kunit_try_run_case+0x19d/0xa50
[    1.425243]  kunit_generic_run_threadfn_adapter+0x62/0xe0
[    1.426252]  kthread+0x8cd/0xb40
[    1.426747]  ret_from_fork+0x189/0x2b0
[    1.427320]  ret_from_fork_asm+0x1a/0x30
[    1.428245]     ok 22 test_stackdepot_roundtrip
[    1.428519]     # test_unpoison_memory: unpoisoning via the instrumentat=
ion vs. kmsan_unpoison_memory() (2 UMR reports)
[    1.430771] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D
[    1.431682] BUG: KMSAN: uninit-value in test_unpoison_memory+0x146/0x3e0
[    1.432705]  test_unpoison_memory+0x146/0x3e0
[    1.433356]  kunit_try_run_case+0x19d/0xa50
[    1.433979]  kunit_generic_run_threadfn_adapter+0x62/0xe0
[    1.434773]  kthread+0x8cd/0xb40
[    1.435263]  ret_from_fork+0x189/0x2b0
[    1.435846]  ret_from_fork_asm+0x1a/0x30

[    1.436692] Local variable a created at:
[    1.437270]  test_unpoison_memory+0x41/0x3e0
[    1.437903]  kunit_try_run_case+0x19d/0xa50

[    1.438766] Bytes 0-2 of 3 are uninitialized
[    1.439433] Memory access of size 3 starts at ffffc90000347cd5

[    1.440517] CPU: 3 UID: 0 PID: 99 Comm: kunit_try_catch Tainted: G      =
           N  6.17.0-rc5-00110-ge59a039119c3 #3 PREEMPT(none)=20
[    1.442247] Tainted: [N]=3DTEST
[    1.442725] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS =
rel-1.17.0-0-gb52ca86e094d-prebuilt.qemu.org 04/01/2014
[    1.444376] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D
[    1.445263] Disabling lock debugging due to kernel taint
[    1.446103] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D
[    1.447007] BUG: KMSAN: uninit-value in test_unpoison_memory+0x23f/0x3e0
[    1.447996]  test_unpoison_memory+0x23f/0x3e0
[    1.448650]  kunit_try_run_case+0x19d/0xa50
[    1.449319]  kunit_generic_run_threadfn_adapter+0x62/0xe0
[    1.450122]  kthread+0x8cd/0xb40
[    1.450611]  ret_from_fork+0x189/0x2b0
[    1.451181]  ret_from_fork_asm+0x1a/0x30

[    1.452010] Local variable b created at:
[    1.452894]  test_unpoison_memory+0x56/0x3e0
[    1.453537]  kunit_try_run_case+0x19d/0xa50

[    1.454407] Bytes 0-2 of 3 are uninitialized
[    1.455043] Memory access of size 3 starts at ffffc90000347cd1

[    1.456182] CPU: 3 UID: 0 PID: 99 Comm: kunit_try_catch Tainted: G    B =
           N  6.17.0-rc5-00110-ge59a039119c3 #3 PREEMPT(none)=20
[    1.457925] Tainted: [B]=3DBAD_PAGE, [N]=3DTEST
[    1.458545] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS =
rel-1.17.0-0-gb52ca86e094d-prebuilt.qemu.org 04/01/2014
[    1.460239] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D
[    1.461617]     ok 23 test_unpoison_memory
[    1.462056]     # test_copy_from_kernel_nofault: testing copy_from_kerne=
l_nofault with uninitialized memory
[    1.464122] ret is false
[    1.464538]     # test_copy_from_kernel_nofault: EXPECTATION FAILED at m=
m/kmsan/kmsan_test.c:656
                   Expected report_matches(&expect) to be true, but is fals=
e
[    1.467250]     not ok 24 test_copy_from_kernel_nofault
[    1.482563] # kmsan: pass:11 fail:13 skip:0 total:24
[    1.483790] # Totals: pass:11 fail:13 skip:0 total:24
[    1.484532] not ok 1 kmsan

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250911175145.GA1376%40sol.
