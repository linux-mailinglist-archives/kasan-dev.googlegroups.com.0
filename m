Return-Path: <kasan-dev+bncBDW2JDUY5AORBKHSY3EQMGQERGBAKCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5CAA1CA48CD
	for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 17:39:06 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id 4fb4d7f45d1cf-6460725c6a9sf1248147a12.3
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 08:39:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764866346; cv=pass;
        d=google.com; s=arc-20240605;
        b=UiYdVcRP4W55Ov3RxcS95D43lu5kc/B12G0srLHfhhG6tEA0cfc4RFI0y/hwspagl7
         5401uqSKtJIobGu1Zc3/K93YZbD9LdLDpcT5aHzu5oVvK/qZhyPzQnmNIM0sI3ryUjmb
         KymONIJkUvVM+NOFWIapdH7TakzbrmrFEgPSRPsSY0fvWFWNImbERfO59paGwvAi4hoA
         1s3wZ7/7UnsWtn9cUuYo+Ixnb5OUHZKzxL/Ur8dwqVOOcbvm0MuIVGDXiMXvB92jmOEl
         F6v+2CVckYZyOSL++4i7B/3d0eDDualUPPl2zQdPkwN+7BnMLFiTncR53tchpBdneYj7
         /7iw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=FYwRWg3vpU9cMdTLwzYqR0m+5Xo95f3L5bDHqUvZrxo=;
        fh=a89qUOkSsBjflSr9yoUvfHsmdWCA7SZ7kPlTPN8QCMg=;
        b=lpXe3nhCJndXqPsuFyP2+cjHdQozeiHGTuA1KY6QrjSB74ANx7Q0xLaAsW0Xp+N0sY
         szD76l5fdhF64QtS1kayF3IyfT1h/jmWLM+8odl7r1XPJortl1P9K0++p8n1ejCwshJI
         ojdHK1DGul4fOVL8ZNYVtrQvxTppjZB9h51fuYx6uJmgVGcGbDU6fbGd125OOyuOf+6z
         PT/47RqDBA8r9XN9Avca5488kQI6mC3d7QYLdwUzoAQKjfLbPxLuzRhIMkk+g0NPDOXQ
         HT7EOz2ib2aYWlqZ+RnY5CXfSkn2qgXMFijY0TY5vcnf8d85ZWuP9IQS0iXVGCAqHmfL
         lKvQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=XwsjN3aX;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764866346; x=1765471146; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=FYwRWg3vpU9cMdTLwzYqR0m+5Xo95f3L5bDHqUvZrxo=;
        b=UZEbf8Q1ESz3UipS1ExJJWCRxvkO4pTQOvH4+AcGGZw0BZpR5y0S5O3CsvvCXf8QFX
         ESfVAHALagZYcRPpDWC8WtQjIp0wl7LMfENkS801hmw97RofoPhKvglcDTdLvDNpRyUX
         nyMsat2j34neZJzi+Y9d3k+V+/Np8WgWEPdBF3HbTyX4Dgm29l65BE1c9NVPeW3rowPJ
         UWMrrv2/1vcCanT8C2RlepEaEEZZPeiL1xJmhAU/6Sv87PLC+uLvOvgJveeS39dzFdj8
         TkimmFn529JfqaVCXQmAUb1dI5IJ1g2GzCNXlcAJhrvx6BAMXUNFWkJ/qbRLoImodreB
         Ex4Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1764866346; x=1765471146; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=FYwRWg3vpU9cMdTLwzYqR0m+5Xo95f3L5bDHqUvZrxo=;
        b=g5IQsv7mqMe+da2JPHZxybfXmHYsSzy89+sVEyUIE8IPgHBTE0QPs4lzoimRFkgdv3
         AxPvvdIACao/gGVoWBFipFoCv/f+FcUOFRzHNiRNYPYkeWnk2KzgCmq1uZWt/nRrEA7k
         r1lF5+7yt+wq4h/Cakfq1BWKe3MUvCreyOneIABKXImEyioKYs8oKinEw6Vd1EOtVYng
         wyMV19FKENfqSQIZHdPDvjyE0hXk1qDF0XkJHUEFGpF8HczAFH9iE74sPs99jSbSqEc0
         uYDLD8cAOuClpVR6HJWq9ANXgzo8CB8q8uP4aqs0unMjtAQWGr8NzUAPbidcuIL0PoMq
         vuDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764866346; x=1765471146;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FYwRWg3vpU9cMdTLwzYqR0m+5Xo95f3L5bDHqUvZrxo=;
        b=fJGUSArziiUejklJYEmwPS8FtUkxaiG8Dn8EGpvr43bIJX1fz+Z/9T8tgzN/KpW30U
         YyWqgGuY9CwXSQpbAeMsNVSkoSxSand9Dnqrba5sQnQmZqeclKtqeEZUkt3jHVgfuU98
         nJt2/7j6yYa8MXz2/M9DEpDwIK6xlC29rsw00aa98FCpFPHSkQEG9SLXzvPjWIi3RkH9
         WtNG9vhPk6oUKzp+0f96m/VtNkvee/WioSi3M7iH3zyh9GZarfqSV6nboBnCj5iyJe59
         c2qs6A0beBvMc9AihnrkcJ/eua/8CS1HwBOhRuPI4HzXpJmE2Bp7ulfketsnNdFtreVd
         1A4g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX/xxYlHv+ZbAYBIH9ZpKmKcQQMn0LoZhsBTkQ1QhoYsHb05/rCSzueRiqh9bVe1CJGqZVh6Q==@lfdr.de
X-Gm-Message-State: AOJu0YxC4Lpn2j2BiM58FbjAEy/fEkC3snIv8EcZLe9OWNECS6naUC90
	5Sc9RXVwZ0u3BEalZWcjOmSywtP3iEXQs0Vklh/R6rHfPrmBVPtIRIcr
X-Google-Smtp-Source: AGHT+IHjc45OnM+2KllxnjvNrYUJHKcwldodiV4idJ65y/0f7PwnHxjRnAAe8OD9D4sWX51IbI/rYg==
X-Received: by 2002:a05:6402:84e:b0:640:9d56:50a7 with SMTP id 4fb4d7f45d1cf-6479c3f6527mr5238090a12.9.1764866345693;
        Thu, 04 Dec 2025 08:39:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Z7yG1fkWIJDPS/NLkftfi8W/iMdvnfaIqmW/XW/0yB8Q=="
Received: by 2002:a05:6402:1ec7:b0:647:9380:1e4c with SMTP id
 4fb4d7f45d1cf-647ad2ee0b2ls1322424a12.0.-pod-prod-01-eu; Thu, 04 Dec 2025
 08:39:03 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVQsHCdlhk513m8xMF6I0IfLKgA7Gn2jwGh35ywAQz4U2YJJbsBiQUyMXITZf9h4jyCyx9W2PTdBZ8=@googlegroups.com
X-Received: by 2002:a17:906:7952:b0:b73:5e4d:fac4 with SMTP id a640c23a62f3a-b79dbe49137mr786103266b.7.1764866342968;
        Thu, 04 Dec 2025 08:39:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764866342; cv=none;
        d=google.com; s=arc-20240605;
        b=EPAqX0ErQHywzhd/2SCcL5uKHs+mZo0TASn+7xL+uP81Xmkjs0vVtUL/fiSCvfCe/K
         /h4Uan6k5Po/rFsmTIGFryoVJpyVeUcw9IpG875bu62zKU3LwTDf81Wwd6W7VhUnnc4/
         DubytnV/8j2hrh34zf99BEdBMsFb3agZq5JdembL0WBD/12em86hQ6NM6S8isN9wU4PT
         79YDzNsssMOK2dPB5ddOG44m3aXIDbh1VGhAj5hvaX2F9KLHfbFHkO29FlRua+uABl54
         SljdQ9sibTt+koXIDzVYvRKPqF0RXfhCYSqcC7eRjz5xVsFH76yHDnZdlGjDMPxM3ZOj
         PWpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=rUx19gRPJQTm4oWcB8wA8j6Dup+z8ZZpv7z/N3R45CY=;
        fh=qoBe1l8LxVuIf71/XtgPVcpM4ZLdbkJyfxoGJWanLi8=;
        b=jcbmikOzu5yRC8a4E7Ey9X6S7wwnTfFIrtTd4pymb1co0DSxbDyQg6cNraZPFuH3HW
         tDNRy8kcAOI2NEdqPhElfcFgeiw2mxeywcDq30/ZVmTReddFZjwuVpGbuTQ/dBTKfXBT
         ZYrMHERThIVg9ULTkSZ3hZfdDcdGf5PQ39BkyKgi3l36JFD9RTqQw8Gdf0DGj6lFHwN/
         PLBR1RxjmTm6IFmTS1HzWU5lXdxBolGl2SAUT9GTzNZGKm44fpvdPFT9qmRhv7HOCJPL
         73jBL5Y8898uGctDJ/dQBKk4M8tLG6k8ASZ7aCVZDlxIVOfuPdkpOOzWUNCKcvqEFhGj
         mCZQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=XwsjN3aX;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x329.google.com (mail-wm1-x329.google.com. [2a00:1450:4864:20::329])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b79f496b628si3777266b.3.2025.12.04.08.39.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Dec 2025 08:39:02 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) client-ip=2a00:1450:4864:20::329;
Received: by mail-wm1-x329.google.com with SMTP id 5b1f17b1804b1-47796a837c7so9729495e9.0
        for <kasan-dev@googlegroups.com>; Thu, 04 Dec 2025 08:39:02 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWq/VRuJoLNoVhuy7y9WedbNugzrUPoKt8F/CJbbh74AVXfZ3KgtfpA3QTOFCjGy+C5bDSlOthQ3TU=@googlegroups.com
X-Gm-Gg: ASbGncvVaE28N7espmGjX6LJE7oyrvFykx4K09UfsrLW8tBH/euFTLlyHJfSm4GzyeY
	ZHfK8FKG+/dSGBEuy+2r8F67n7K0lDhztnsarmj/+jeMLupvdTo9IRLAyXGo0DuqzSCwwvj/bW+
	iqpJ3PnHH4DLvGTSHPC38fhb+lwgybipVPOFDD+hZyo9b4Udk14WGC46VBdGzMc6wKf2bKHPmo0
	wLcGQuEOeOvw2RCxj5EQEQVHKAx+HJbrfvMcDS9zgCHO5g1ToOEOqdlEIBV068r0LVpj+dGUlAD
	nBi1IYfYuFGBPiLR43bmOAlv8qDm
X-Received: by 2002:a5d:64c5:0:b0:42b:383d:9c8e with SMTP id
 ffacd0b85a97d-42f731c2e72mr7003661f8f.41.1764866342105; Thu, 04 Dec 2025
 08:39:02 -0800 (PST)
MIME-Version: 1.0
References: <20251128033320.1349620-1-bhe@redhat.com>
In-Reply-To: <20251128033320.1349620-1-bhe@redhat.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 4 Dec 2025 17:38:49 +0100
X-Gm-Features: AWmQ_bmhKUWGLOGRduhfezxTuPYTkb1LvtYgmV18KfelSCQT0T4sQ7pI9eJTnYc
Message-ID: <CA+fCnZcVV5=AJUNfy6G2T-UZCbAL=7NivmWkBr6LMSnzzTZ8Kg@mail.gmail.com>
Subject: Re: [PATCH v4 00/12] mm/kasan: make kasan=on|off work for all three modes
To: Baoquan He <bhe@redhat.com>
Cc: linux-mm@kvack.org, ryabinin.a.a@gmail.com, glider@google.com, 
	dvyukov@google.com, vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	kexec@lists.infradead.org, elver@google.com, sj@kernel.org, 
	lorenzo.stoakes@oracle.com, snovitoll@gmail.com, christophe.leroy@csgroup.eu
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=XwsjN3aX;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::329
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Fri, Nov 28, 2025 at 4:33=E2=80=AFAM Baoquan He <bhe@redhat.com> wrote:
>
> Currently only hw_tags mode of kasan can be enabled or disabled with
> kernel parameter kasan=3Don|off for built kernel. For kasan generic and
> sw_tags mode, there's no way to disable them once kernel is built.
>
> This is not convenient sometime, e.g in system kdump is configured.
> When the 1st kernel has KASAN enabled and crash triggered to switch to
> kdump kernel, the generic or sw_tags mode will cost much extra memory
> while in fact it's meaningless to have kasan in kdump kernel
>
> There are two parts of big amount of memory requiring for kasan enabed
> kernel. One is the direct memory mapping shadow of kasan, which is 1/8
> of system RAM in generic mode and 1/16 of system RAM in sw_tags mode;
> the other is the shadow meomry for vmalloc which causes big meomry
> usage in kdump kernel because of lazy vmap freeing. By introducing
> "kasan=3Doff|on", if we specify 'kasan=3Doff', the former is avoided by s=
kipping
> the kasan_init(), and the latter is avoided by not building the vmalloc
> shadow for vmalloc.
>
> So this patchset moves the kasan=3Don|off out of hw_tags scope and into
> common code to make it visible in generic and sw_tags mode too. Then we
> can add kasan=3Doff in kdump kernel to reduce the unneeded meomry cost fo=
r
> kasan.
>
> Testing:
> =3D=3D=3D=3D=3D=3D=3D=3D
> - Testing on x86_64 and arm64 for generic mode passed when kasan=3Don or
>   kasan=3Doff.
>
> - Testing on arm64 with sw_tags mode passed when kasan=3Doff is set. But
>   when I tried to test sw_tags on arm64, the system bootup failed. It's
>   not introduced by my patchset, the original code has the bug. I have
>   reported it to upstream.
>   - System is broken in KASAN sw_tags mode during bootup
>     - https://lore.kernel.org/all/aSXKqJTkZPNskFop@MiWiFi-R3L-srv/T/#u

This will hopefully be fixed soon, so you'll be able to test.

>
> - Haven't found hardware to test hw_tags. If anybody has the system,
>   please help take a test.

You don't need hardware to run the HW_TAGS mode, just pass -machine
virt,mte=3Don to QEMU.

I also wonder if we should keep this kasan=3Doff functionality
conservative and limit it to x86 and arm64 (since these are the only
two tested architectures).

>
> Changelog:
> =3D=3D=3D=3D
> v3->v4:
> - Rebase code to the latest linux-next/master to make the whole patchset
>   set on top of
>   [PATCH 0/2] kasan: cleanups for kasan_enabled() checks
>   [PATCH v6 0/2] kasan: unify kasan_enabled() and remove arch-specific im=
plementations

Note that are also:

[PATCH 1/2] kasan: remove __kasan_save_free_info wrapper
[PATCH 2/2] kasan: cleanup of kasan_enabled() checks

But I don't know if there will be any conflicts with these.

>
> v2->v3:
> - Fix a building error on UML ARCH when CONFIG_KASAN is not set. The
>   change of fixing is appended into patch patch 11. This is reported
>   by LKP, thanks to them.
>
> v1->v2:
> - Add __ro_after_init for kasan_arg_disabled, and remove redundant blank
>   lines in mm/kasan/common.c. Thanks to Marco.
> - Fix a code bug in <linux/kasan-enabled.h> when CONFIG_KASAN is unset,
>   this is found out by SeongJae and Lorenzo, and also reported by LKP
>   report, thanks to them.
> - Add a missing kasan_enabled() checking in kasan_report(). This will
>   cause below KASAN report info even though kasan=3Doff is set:
>      =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>      BUG: KASAN: stack-out-of-bounds in tick_program_event+0x130/0x150
>      Read of size 4 at addr ffff00005f747778 by task swapper/0/1
>
>      CPU: 0 UID: 0 PID: 1 Comm: swapper/0 Not tainted 6.16.0+ #8 PREEMPT(=
voluntary)
>      Hardware name: GIGABYTE R272-P30-JG/MP32-AR0-JG, BIOS F31n (SCP: 2.1=
0.20220810) 09/30/2022
>      Call trace:
>       show_stack+0x30/0x90 (C)
>       dump_stack_lvl+0x7c/0xa0
>       print_address_description.constprop.0+0x90/0x310
>       print_report+0x104/0x1f0
>       kasan_report+0xc8/0x110
>       __asan_report_load4_noabort+0x20/0x30
>       tick_program_event+0x130/0x150
>       ......snip...
>      =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>
> - Add jump_label_init() calling before kasan_init() in setup_arch() in th=
ese
>   architectures: xtensa, arm. Because they currenly rely on
>   jump_label_init() in main() which is a little late. Then the early stat=
ic
>   key kasan_flag_enabled in kasan_init() won't work.
>
> - In UML architecture, change to enable kasan_flag_enabled in arch_mm_pre=
init()
>   because kasan_init() is enabled before main(), there's no chance to ope=
rate
>   on static key in kasan_init().
>
> Baoquan He (12):
>   mm/kasan: add conditional checks in functions to return directly if
>     kasan is disabled
>   mm/kasan: move kasan=3D code to common place
>   mm/kasan/sw_tags: don't initialize kasan if it's disabled
>   arch/arm: don't initialize kasan if it's disabled
>   arch/arm64: don't initialize kasan if it's disabled
>   arch/loongarch: don't initialize kasan if it's disabled
>   arch/powerpc: don't initialize kasan if it's disabled
>   arch/riscv: don't initialize kasan if it's disabled
>   arch/x86: don't initialize kasan if it's disabled
>   arch/xtensa: don't initialize kasan if it's disabled
>   arch/um: don't initialize kasan if it's disabled
>   mm/kasan: make kasan=3Don|off take effect for all three modes
>
>  arch/arm/kernel/setup.c                |  6 ++++++
>  arch/arm/mm/kasan_init.c               |  2 ++
>  arch/arm64/mm/kasan_init.c             |  6 ++++++
>  arch/loongarch/mm/kasan_init.c         |  2 ++
>  arch/powerpc/mm/kasan/init_32.c        |  5 ++++-
>  arch/powerpc/mm/kasan/init_book3e_64.c |  3 +++
>  arch/powerpc/mm/kasan/init_book3s_64.c |  3 +++
>  arch/riscv/mm/kasan_init.c             |  3 +++
>  arch/um/kernel/mem.c                   |  5 ++++-
>  arch/x86/mm/kasan_init_64.c            |  3 +++
>  arch/xtensa/kernel/setup.c             |  1 +
>  arch/xtensa/mm/kasan_init.c            |  3 +++
>  include/linux/kasan-enabled.h          |  6 ++++--
>  mm/kasan/common.c                      | 20 ++++++++++++++++--
>  mm/kasan/generic.c                     | 17 ++++++++++++++--
>  mm/kasan/hw_tags.c                     | 28 ++------------------------
>  mm/kasan/init.c                        |  6 ++++++
>  mm/kasan/quarantine.c                  |  3 +++
>  mm/kasan/report.c                      |  4 +++-
>  mm/kasan/shadow.c                      | 11 +++++++++-
>  mm/kasan/sw_tags.c                     |  6 ++++++
>  21 files changed, 107 insertions(+), 36 deletions(-)

One part that's still missing is a Documentation change.


>
> --
> 2.41.0
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZcVV5%3DAJUNfy6G2T-UZCbAL%3D7NivmWkBr6LMSnzzTZ8Kg%40mail.gmail.com.
