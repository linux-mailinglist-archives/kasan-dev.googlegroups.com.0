Return-Path: <kasan-dev+bncBDW2JDUY5AORBOPLVCXQMGQE7K5ICYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id D03648759BB
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Mar 2024 22:46:34 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id 4fb4d7f45d1cf-565862d2fdfsf3693a12.0
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Mar 2024 13:46:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709847994; cv=pass;
        d=google.com; s=arc-20160816;
        b=uDb8keyVvoxdLBE059Lug2DC3IG3vCgN2/5ilEC3vBiQhT4BrULSdBHDJF66rrm2ys
         d5AeZYJup39ntr+vXPGXL66ZKaQ8LPB+M9zU0Egb8/0BeLfJmpRCcYnORUaF92PsG6YG
         fU3FRDS1SvV6diYgLM8u7mSe5hm92yX+2WwGU9sKcGKFSbUfvl5yjiJqe/AinsOZLA2B
         +cxotnX+Ys/+Nxv4qA8bxgnCNydP/T9U8f0JALPM5g9CbwJw0Hl0m1l0RikcnhVBpHF+
         4mBNQeCrVuaF7JR8heftc1MCWqXeSRvObUbXDXe5FnZMuSn89A4It1MF+JoetZhP3A6x
         m6sg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=Y+4OADQ3j5kL2xxkNhzmT6aPyVPFFxJWmql9gdl6tMU=;
        fh=qi6/xhNATsNfGg0atB020yrLbDHXh0K8ksBXgGnL8nM=;
        b=UG7dMc/5A2JMrLeHTZix9u8Pe+50i8OU4YMs+HZpzfVW3M4a1b0NOIg5EHNCTRUn7A
         tcZr3JhAxRSyXsa0JQYJ7OvuQaUR4lb6wjsRJXbW4804CtM45U2kb5GOhOO+9Wu9tTZ3
         FEuZXRs1lulbPCZ+3T8IvlmtyOxVOHhf2qH4UQc6rE3dQiWJoxs4CdyQPD52+D+uqmj2
         HuPXznV/MKjbIzx9CnOD/drvWU7RN60AynwWI/WQEsr9kiJRxBSj3SqLMyxF/ZvtDAIA
         4qblyROsq/htBk3zdC6GDDxc8LOBjvVNpKb+7aKJ/5xdiVeZytcf+ySc4f+wiLBsq2QM
         3j8w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=VR8ZQGnW;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709847994; x=1710452794; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Y+4OADQ3j5kL2xxkNhzmT6aPyVPFFxJWmql9gdl6tMU=;
        b=dU9qCYMnlB7gLo3L5xuDzo/8pr/t+ktOyc8/HRS8icUn2yD5T7L3ZX4y48vouepqAR
         gMhPQMMFQfoupzLFfhtpFW70PCl7jqn9Z53qRvQLUyN9WnwSLLp7+HhO7aiYCFxMKtyj
         iD+l6xu1UrNSx7uWJTETyZxv//FqR6S/Fen1oaoAG3i9I//2Lb9wZJz7x5WaBIRSFVzj
         6oVufxK50XrdAPOCQThawj+YqdPL4RMmBhKzc7+JmK0ElNMVKlN+lO7+uJPMGJ2XiMP0
         LSrxlcVrau3Anet5vX8Z/X7i1OzziUQdJAHE5tjso1y4jhC2wqxRWFPhGvIuh64xfVN/
         ZGyw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1709847994; x=1710452794; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Y+4OADQ3j5kL2xxkNhzmT6aPyVPFFxJWmql9gdl6tMU=;
        b=WfEzPjhsSzisuquzt5Z84KizINMXvSswcOsDQaEal/TUpfniBGQQ/Qq8VXgGyo7Flq
         QmaUmsL9hr+iyP2aXKL0SXomXQiffXy5dwS+Sw16z9DU32GZmjjqnEQf0yH21MllOaRE
         vrAg+miBWGmxLBVFK9lXl4mLPiVMO23aHO1oxJbe/cGn3WCPPEzZE8dDuZVL8RHGpGuJ
         PgF6++Qqk5p4fgxXr/pM7wmuBSRevLDsEANMgF8jrpSSEv1PuIRkr4ptANEDxdI7Vbvg
         iWx1H6W2K4x0WN3QV2UWJIx5M6q6tHuryW4YERgq0r17UzFIFbsygyldoZ219W3dkrNi
         yP2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709847994; x=1710452794;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Y+4OADQ3j5kL2xxkNhzmT6aPyVPFFxJWmql9gdl6tMU=;
        b=mBUxGmlnDlW0GqWPOZl3ntzJuRHj3qYsmFKc4xxH/IgWZpsGh9xGwkpKBcwiEt4uUN
         5Hktre3ZKmw3yHAi0CDRNz1UISgZFRN32iQ/w+FqnRupRwkTmxeFm7TVgecGv3eKRrEA
         4hTvubRu1XnJYRgL+M3/HcjZQ4hnfFlhOox7S2j72t4K8QIMbETFOj7TSTWSY/mjCA8l
         oJczSGdcYsYK00toPFWBK0Z1hyzuWm8/5l2HmjAa2vR5T3mqAmueksuR3slW+uEizuK/
         CtK7hmWFa7CrBWQKf3SrrsyKXrpl7NFtEHeZO/NWASxrFx6MWE8RAnQ5+W1DE58XWNzc
         FQUw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW0lIdgdnqxcRI8mqUp6Sqzb1H4pT2Le+UR0K/byOK/hTiHdQKyGijfyS1tUE83g/fZjdQnsdT0mR+xk33qPg3WAIF9PgXPKg==
X-Gm-Message-State: AOJu0YwM5SXvtR/6DGakfqAbda1sKYMwQKE917erfwupXUENoeUz2tZj
	I/1LP51u8Fcn+TjjAH2eP9wAEdGyGRbCRs4Iffv9AP+Dtk7l9ZBm
X-Google-Smtp-Source: AGHT+IFhqNYLnQF6FR65/n/wclamSK2kZJfCLPk6QEdqUE/D2WCoh26br1dPfsIFJkZY7yAW/wKAyA==
X-Received: by 2002:a50:ee90:0:b0:565:ad42:b97d with SMTP id f16-20020a50ee90000000b00565ad42b97dmr335447edr.0.1709847993951;
        Thu, 07 Mar 2024 13:46:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:3227:b0:567:bb66:cd3d with SMTP id
 g39-20020a056402322700b00567bb66cd3dls814185eda.2.-pod-prod-00-eu; Thu, 07
 Mar 2024 13:46:32 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWd8YyyXSmha3HBk5KidBc8ZPhARyaUtlQhZ3bPOEXxvlj++B2YacW0GCmZgm4Dk52+nJDmbIEgFDG9HgwEPSrHZ0UOEb3JafBtAw==
X-Received: by 2002:a50:cd8a:0:b0:566:fb8d:ed8f with SMTP id p10-20020a50cd8a000000b00566fb8ded8fmr1077622edi.14.1709847991830;
        Thu, 07 Mar 2024 13:46:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709847991; cv=none;
        d=google.com; s=arc-20160816;
        b=DfcLLXDpWLj+O1nGJtWx2Rtk+PApUk9crrY6/FOk+4a0mIghmH2a48EERlu56SZufo
         KEi7XT4b32eeOlhW9b2/sXQywdkwXzBJmbsfEnAOShDJ7zUt2w2D++0K+QIL3Yx72Pdw
         96mhBUaIbKPhGDovQcXall78KbkqwryJM0tJ7YrcF3JvHjbIFFvMsvdgBl7N6O1Q15ff
         djrg7wVOM3Xb7Inp69TZRfher3VTGBJuHdR/129/pAL/32x8lHH+FDFCFMtk4T7jXJ9e
         V0wJFwWe0adhFaeRduPaXuYTWO/AcGyeLykDH8Ua6TB6m7PbKKpRW8QbNxU9nsGexzvf
         GLTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=WAcLRny2X5cFvZL5LMWeuUAc4ddAe5gJN8/CLeYQB1Q=;
        fh=ZcXqed9tPMgcqAMsTTAIFqKzjySotSLGLnurG2XHq0o=;
        b=kxudQbde6QQ7AGsf8MLp01EQeMvOuGIOc6CtHpFOD5izG8/5UY8djlbFxImTs4bCrX
         xrPVOB7pxl8AfrC4xwscUHiwRyT1H6e2dp6K51QteQJfN3/zXgMjbC2e3sbsXdZXhxwi
         +OcWoQ9D+maZ8WJSoQbGAu1s5psZ+CWC8Lt+WBoJWB1ojH03NIC399+i+AWmFZT92QPQ
         nzhYKQYurrBFmd+1Lurmt3DwRyfxn7K8cATLqCrxYu9w51DGVYJdAUoGC9ruQE795wi4
         48wt1HnNRy96lMsWXOmOs5mChwCClzwxI5r+CPdzyP+yU3BPMC5Rj3jdEGYpPUD4zAiB
         +MjA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=VR8ZQGnW;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wm1-x329.google.com (mail-wm1-x329.google.com. [2a00:1450:4864:20::329])
        by gmr-mx.google.com with ESMTPS id dz13-20020a0564021d4d00b0056818e13141si32920edb.4.2024.03.07.13.46.31
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 Mar 2024 13:46:31 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) client-ip=2a00:1450:4864:20::329;
Received: by mail-wm1-x329.google.com with SMTP id 5b1f17b1804b1-41312232c7aso6094885e9.0;
        Thu, 07 Mar 2024 13:46:31 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUZc3DXbQdQcOKLlCwZB03jmuZAWnriHMlaH52rboaSJpGQ5sjuIHLHpWQw3jbsvhU1QeVlUu2zv+mAhBHZYs/PZfuS5hsUpK7dKgZaY5ouJddAEkV2TaoiGSI6jSJ2h303yK+IyP0=
X-Received: by 2002:a5d:63ce:0:b0:33e:7337:93b3 with SMTP id
 c14-20020a5d63ce000000b0033e733793b3mr1184609wrw.25.1709847991062; Thu, 07
 Mar 2024 13:46:31 -0800 (PST)
MIME-Version: 1.0
References: <20240307135130.14919-1-npache@redhat.com>
In-Reply-To: <20240307135130.14919-1-npache@redhat.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 7 Mar 2024 22:46:20 +0100
Message-ID: <CA+fCnZe+W+Umcc59=N5b2brN966qdUjb6vo=LjptJ=FdDPiCwg@mail.gmail.com>
Subject: Re: [BUG REPORT] Multiple KASAN kunit test failures
To: Nico Pache <npache@redhat.com>
Cc: walter-zh.wu@mediatek.com, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=VR8ZQGnW;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::329
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Hi Nico,

This might be related to
https://twitter.com/andreyknvl/status/1632436931345670144.

Do you observe these failures on latest upstream (with the same
.config and toolchain)?

If so, please share the .config and the compiler version that you use.

If not, you can try bisecting to find out the guilty commit, and
perhaps a fix will become apparent after that.

Thank you!

On Thu, Mar 7, 2024 at 2:51=E2=80=AFPM Nico Pache <npache@redhat.com> wrote=
:
>
> Hi,
>
> A number of KASAN KUnit tests have been failing on the upstream rhel/fedo=
ra
> kernels.
>
> cki-project data warehouse : https://datawarehouse.cki-project.org/issue/=
1972
>
> The kmalloc_oob_in_memset* tests are failing and the
> kmalloc_memmove_negative_size is panicing.
>
> Arches: X86_64, ARM64, S390x, ppc64le
> First Appeared: ~6.3.rc5
>
> Failing Tests:
>  - kmalloc_oob_in_memset
>  - kmalloc_oob_memset_2
>  - kmalloc_oob_memset_4
>  - kmalloc_oob_memset_8
>  - kmalloc_oob_memset_16
>  - kmalloc_memmove_negative_size (PANIC)
>
> trace:
>      # kmalloc_oob_in_memset: EXPECTATION FAILED at mm/kasan/kasan_test.c=
:565
>      KASAN failure expected in "memset(ptr, 0, size + KASAN_GRANULE_SIZE)=
", but none occurred
>      not ok 17 kmalloc_oob_in_memset
>      # kmalloc_oob_memset_2: EXPECTATION FAILED at mm/kasan/kasan_test.c:=
495
>      KASAN failure expected in "memset(ptr + size - 1, 0, memset_size)", =
but none occurred
>      not ok 18 kmalloc_oob_memset_2
>      # kmalloc_oob_memset_4: EXPECTATION FAILED at mm/kasan/kasan_test.c:=
513
>      KASAN failure expected in "memset(ptr + size - 3, 0, memset_size)", =
but none occurred
>      not ok 19 kmalloc_oob_memset_4
>      # kmalloc_oob_memset_8: EXPECTATION FAILED at mm/kasan/kasan_test.c:=
531
>      KASAN failure expected in "memset(ptr + size - 7, 0, memset_size)", =
but none occurred
>      not ok 20 kmalloc_oob_memset_8
>      # kmalloc_oob_memset_16: EXPECTATION FAILED at mm/kasan/kasan_test.c=
:549
>      KASAN failure expected in "memset(ptr + size - 15, 0, memset_size)",=
 but none occurred
>      not ok 21 kmalloc_oob_memset_16
>  BUG: unable to handle page fault for address: ffff888109480000
>  #PF: supervisor write access in kernel mode
>  #PF: error_code(0x0003) - permissions violation
>  PGD 13dc01067 P4D 13dc01067 PUD 100276063 PMD 104440063 PTE 800000010948=
0021
>  Oops: 0003 [#1] PREEMPT SMP KASAN PTI
>  CPU: 0 PID: 216780 Comm: kunit_try_catch Tainted: G    B   W  OE  X N---=
----  ---  6.8.0-0.rc7.57.test.eln.x86_64+debug #1
>  Hardware name: Red Hat KVM, BIOS 1.15.0-2.module+el8.6.0+14757+c25ee005 =
04/01/2014
>  RIP: 0010:memmove+0x28/0x1b0
>  Code: 90 90 f3 0f 1e fa 48 89 f8 48 39 fe 7d 0f 49 89 f0 49 01 d0 49 39 =
f8 0f 8f b5 00 00 00 48 83 fa 20 0f 82 01 01 00 00 48 89 d1 <f3> a4 c3 cc c=
c cc cc 48 81 fa a8 02 00 00 72 05 40 38 fe 74 43 48
>  RSP: 0018:ffffc9000160fd50 EFLAGS: 00010286
>  RAX: ffff888109448500 RBX: ffff888109448500 RCX: fffffffffffc84fe
>  RDX: fffffffffffffffe RSI: ffff888109480004 RDI: ffff888109480000
>  RBP: 1ffff920002c1fab R08: 0000000000000000 R09: 0000000000000000
>  R10: ffff888109448500 R11: ffffffff9a1d1bb4 R12: ffffc900019c7610
>  R13: fffffffffffffffe R14: ffff888060919000 R15: ffffc9000160fe48
>  FS:  0000000000000000(0000) GS:ffff888111e00000(0000) knlGS:000000000000=
0000
>  CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
>  CR2: ffff888109480000 CR3: 000000013b120004 CR4: 0000000000770ef0
>  DR0: 0000000000430c70 DR1: 0000000000000000 DR2: 0000000000000000
>  DR3: 0000000000000000 DR6: 00000000ffff0ff0 DR7: 0000000000000600
>  PKRU: 55555554
>  Call Trace:
>   <TASK>
>   ? __die+0x23/0x70
>   ? page_fault_oops+0x136/0x250
>   ? __pfx_page_fault_oops+0x10/0x10
>   ? memmove+0x28/0x1b0
>   ? exc_page_fault+0xf9/0x100
>   ? asm_exc_page_fault+0x26/0x30
>   ? kasan_save_track+0x14/0x30
>   ? memmove+0x28/0x1b0
>   kmalloc_memmove_negative_size+0xdf/0x200 [kasan_test]
>   ? __pfx_kmalloc_memmove_negative_size+0x10/0x10 [kasan_test]
>   ? kvm_clock_get_cycles+0x18/0x30
>   ? ktime_get_ts64+0xce/0x280
>   kunit_try_run_case+0x1b1/0x490 [kunit]
>   ? do_raw_spin_trylock+0xb4/0x180
>   ? __pfx_kunit_try_run_case+0x10/0x10 [kunit]
>   ? trace_irq_enable.constprop.0+0x13d/0x180
>   ? __pfx_kunit_generic_run_threadfn_adapter+0x10/0x10 [kunit]
>   ? __pfx_kunit_try_run_case+0x10/0x10 [kunit]
>   kunit_generic_run_threadfn_adapter+0x4e/0xa0 [kunit]
>   kthread+0x2f2/0x3c0
>   ? trace_irq_enable.constprop.0+0x13d/0x180
>   ? __pfx_kthread+0x10/0x10
>   ret_from_fork+0x31/0x70
>   ? __pfx_kthread+0x10/0x10
>   ret_from_fork_asm+0x1b/0x30
>   </TASK>
>   ...
> --
> 2.44.0
>
> --
> You received this message because you are subscribed to the Google Groups=
 "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgi=
d/kasan-dev/20240307135130.14919-1-npache%40redhat.com.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZe%2BW%2BUmcc59%3DN5b2brN966qdUjb6vo%3DLjptJ%3DFdDPiCwg%4=
0mail.gmail.com.
