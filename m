Return-Path: <kasan-dev+bncBD4O7ZP764ERBJODVL7AKGQEUOTY4AI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7833D2CF5DC
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Dec 2020 21:52:54 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id cu18sf5777696qvb.17
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Dec 2020 12:52:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607115173; cv=pass;
        d=google.com; s=arc-20160816;
        b=qY9AlYisdPU3REv8er56RFeITtcXLsPlwqJwg+cxl4vw51n30ZjrrpkSANooac4Sdp
         fQ7fWpu0o1uobMWfgUnZm3Rh/ceuF+nssozbBgBdSkIGjYmlMzAyl0RZGQDCYXD1EDYg
         BiB8mKvCk6Poa5Us9Ter2/xaWTvo4ycTKFGNV2Tflu1U6aYMmKtfdM7cwANSchTe4Ka6
         uW06P/hJmOkCO3MnnIRBx3Apf/mGjvzpcP8bndwLcelAFfGCjQPinlNL4m4DPxrq7xXN
         6OoKnIJwkLN3OqhERnugeUD3pZnAI7wIiUhnaXOuYMUt4rzFswxPhwC13C02HKwWaN9d
         D2HQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:user-agent:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=IZY8lUQA5AxE9qW5C8c5XjxLlAa4TJ4RVzGlWe6vYKk=;
        b=KWaaYz/BRkPkkS+pYjY/3a+mgTT+qrIl2uV0Uc0Dx01yLWufQu1ZN5pT8laQvIZQwt
         V4oOhbOX3Hwa4EXSWdqxFyTrajXfHa2u6hJb5RaDw/P2H9JitcyoYiOaOtUnWmIIUZtw
         e+Hm/kFHWVZvV8lVd0qnKCg6dv7SEfo8Q1CvBcBqf/SB3/rUuvF7iUEdiNsrH2G+EFZL
         yDlZjixCjL/3x9j0YKODr7oUkXM0osrJU5OOMqZgo9VNQ1cKm4Kd94MLkRN991PTsmDy
         zJBKfaNxQvJ6daJXFzSkrC+2PSuFEE4Nhr3MhYjMgzOu4jVijUTqbjbbQ67h1VGL1Wqr
         dHnw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rajagiritech-edu-in.20150623.gappssmtp.com header.s=20150623 header.b=p+ejBgzw;
       spf=neutral (google.com: 2607:f8b0:4864:20::543 is neither permitted nor denied by best guess record for domain of jeffrin@rajagiritech.edu.in) smtp.mailfrom=jeffrin@rajagiritech.edu.in
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=IZY8lUQA5AxE9qW5C8c5XjxLlAa4TJ4RVzGlWe6vYKk=;
        b=GoYZt4nQx0KpT+xRVbUE/pjGg71HOWTFM2s5SXBXqWJPne6Jahy8u+yCLZ3sJ7zb5J
         efcztaZwd7lZiAf0VvCk16dBVnqNDT0a9jBPdW+EjV2txXfjeegZSvGSh4GVxFkiCkAY
         90YNPj3Xd7BtgEL8Alv1d96d5Ri1Nw6s8fzKZtTCORUBBudfO1WpulLjZivW2kWkkF/6
         PDeCIyv309jUw+PZRqOQiEsqaQ2+e9Zj9IDcXScG/DnHh0P2rfK4qa9IqHhYOuSYvSD5
         wDMHXy7sefU94k4aq/zWG2gfYlAqv+lCz39wLR+BWGCw4At1ZJvRNI84MDxOji0RgqVy
         tlLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IZY8lUQA5AxE9qW5C8c5XjxLlAa4TJ4RVzGlWe6vYKk=;
        b=ppySEuexIJE4V0L4C+tVD58Kg5vers106Etkay+JkaV5BlM6WIrYnc8Z0CcgBcmpNB
         3+wrAE9cD+eEutGrlgCJc7KubZJS9dhNafJC0Nro85Zv/uzyexGBRPwKFeqnenUqJWdG
         7voJQzX4nPENAW8qKkke5gwEMzlWBZ9Ny+vkDiXudN+50g3C/ueo8wzvUQOfPJVTZMXc
         Wo0SaAdcHglF3cLPrEEidlA5Uxyl56EnTMK1Fqa/CBYz+SnAs9iosWXK/7vrMFpefmkT
         y8YkCsW0uepjVE95/Je8QAGvRFOyDSzenhb9vEYrOnDA9KVwv9FTqZ2xd83nJHGh6qZs
         FHLw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532KH7dep3A1vgTm20mqFAqyAPte8VdbURm79l4xRj2mL6Bt99rq
	Vm4pDomuspUvdCOOO48dHiY=
X-Google-Smtp-Source: ABdhPJzdtlUAGoqvrr1rtrf0bzvHmA53Yw8mh61w018cO7ZaePyS0qnxUFInkdVxhQ6LO4U2zpXmVQ==
X-Received: by 2002:a37:a9ca:: with SMTP id s193mr10956306qke.313.1607115173252;
        Fri, 04 Dec 2020 12:52:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4e29:: with SMTP id d9ls3764150qtw.10.gmail; Fri, 04 Dec
 2020 12:52:52 -0800 (PST)
X-Received: by 2002:ac8:bc7:: with SMTP id p7mr11371659qti.91.1607115172786;
        Fri, 04 Dec 2020 12:52:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607115172; cv=none;
        d=google.com; s=arc-20160816;
        b=g+fVHQX0eImezs8mvziRv2EJsI3J5osWQNkCKef63dLZHC4J6iSj0VZ6xfdbljLfUJ
         Plpm8uCd73pMkAZOmBlUS9mM/3Ip5+skSNft6Bw3hF+bNhiM6nXB8G2BCFT1+qFFj1Wu
         naNeG/RzEr2op8jvqQSO1SWb3+FOm+/nEwnHgcdTPkyaxYyMgEzvfmCbsFcNcV5LZYAP
         ZXIXkimOPsqE5cdqlqUblNE01S8tXJI6CNk07hKOIJohkTgAw+mklmWI2p9TYKh9xIgB
         uogELR/gpZ1kjCSMtujbCI8yiK8Czd31KwkGtN27+HMvpbjldB2nD5tAnWS9gkbK/pO7
         3KmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=mEQ3gaJd3KfpSvV/0MrjNCIinjXitvVhyYq2m08x7tc=;
        b=bTFW9vQlX6PlfXDP1z8mSOhf+kKPpe2RIriPDysnqRK8PivaT/CInew/ANzG9/mCnK
         UnPaZDD4t4G9LVjwkZskLMcobHI7C6WoMxOGvKYXteTvhqvymRmsfwlqDZzwnxsJ9LRu
         muE/dx4w+XyWLdLLMK8oGn3wufXCpBPBOpVj+2Z5tFUx4MSaP15ehVWvOP6klSrR8U8G
         pmFZ3APBzJFZcyS59dUUyFZy2/8wAFnS5NupGhVbZVT7ZPqzRy/Sib/+7jcGECUmW5Yw
         wB80yivxg3lyJEn9A4TKbzC0+cEy6kjb91nm+cD6JexDwZctCUcm2nPubEt5QbheV+Ni
         bgDg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rajagiritech-edu-in.20150623.gappssmtp.com header.s=20150623 header.b=p+ejBgzw;
       spf=neutral (google.com: 2607:f8b0:4864:20::543 is neither permitted nor denied by best guess record for domain of jeffrin@rajagiritech.edu.in) smtp.mailfrom=jeffrin@rajagiritech.edu.in
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id f21si426626qtx.5.2020.12.04.12.52.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Dec 2020 12:52:52 -0800 (PST)
Received-SPF: neutral (google.com: 2607:f8b0:4864:20::543 is neither permitted nor denied by best guess record for domain of jeffrin@rajagiritech.edu.in) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id n10so4257041pgv.8
        for <kasan-dev@googlegroups.com>; Fri, 04 Dec 2020 12:52:52 -0800 (PST)
X-Received: by 2002:a62:2ac2:0:b029:18c:25ff:d68 with SMTP id q185-20020a622ac20000b029018c25ff0d68mr5581084pfq.64.1607115171887;
        Fri, 04 Dec 2020 12:52:51 -0800 (PST)
Received: from [192.168.1.9] ([122.164.27.91])
        by smtp.gmail.com with ESMTPSA id o132sm5861837pfg.100.2020.12.04.12.52.49
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 04 Dec 2020 12:52:51 -0800 (PST)
Message-ID: <b5bd7b0924bd239eb8d6557e10eead8bb2b939a5.camel@rajagiritech.edu.in>
Subject: Re: BUG: KASAN lib/test_kasan.c
From: Jeffrin Jose T <jeffrin@rajagiritech.edu.in>
To: Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	 <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev
	 <kasan-dev@googlegroups.com>, lkml <linux-kernel@vger.kernel.org>
Date: Sat, 05 Dec 2020 02:22:47 +0530
In-Reply-To: <CANpmjNMCiCf9w34duqGpQ90=qB4QGnRR8Xny+wOVf=2WG=JVoA@mail.gmail.com>
References: <dc46ab93e6b08fa6168591c7f6345b9dc91a81bb.camel@rajagiritech.edu.in>
	 <CANpmjNMCiCf9w34duqGpQ90=qB4QGnRR8Xny+wOVf=2WG=JVoA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.38.1-2
MIME-Version: 1.0
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jeffrin@rajagiritech.edu.in
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rajagiritech-edu-in.20150623.gappssmtp.com header.s=20150623
 header.b=p+ejBgzw;       spf=neutral (google.com: 2607:f8b0:4864:20::543 is
 neither permitted nor denied by best guess record for domain of
 jeffrin@rajagiritech.edu.in) smtp.mailfrom=jeffrin@rajagiritech.edu.in
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

On Fri, 2020-12-04 at 21:29 +0100, Marco Elver wrote:
> On Fri, 4 Dec 2020 at 19:56, Jeffrin Jose T
> <jeffrin@rajagiritech.edu.in> wrote:
> > hello,
> >=20
> > =C2=A0detected=C2=A0=C2=A0 KASAN=C2=A0=C2=A0 BUG
> >=20
> > [ related information ]
> >=20
> > -------------------x-------------------x------------------------>
> > [=C2=A0=C2=A0 43.616259] BUG: KASAN: vmalloc-out-of-bounds in
> > vmalloc_oob+0x146/0x2c0
> >=20
> > (gdb) l *vmalloc_oob+0x146/0x2c0
> > 0xffffffff81b8b0b0 is in vmalloc_oob (lib/test_kasan.c:764).
>=20
> This is the KASAN test. It's a feature, not a bug. ;-)
>=20
> > 759=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 kfree_sensitive(ptr);
> > 760=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 KUNIT_EXPECT_KASAN_FAIL(test,
> > kfree_sensitive(ptr));
> > 761=C2=A0=C2=A0=C2=A0=C2=A0 }
> > 762
> > 763=C2=A0=C2=A0=C2=A0=C2=A0 static void vmalloc_oob(struct kunit *test)
> > 764=C2=A0=C2=A0=C2=A0=C2=A0 {
> > 765=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 void *area;
> > 766
> > 767=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 if (!IS_ENABLED(CONFIG_KASAN_VMALLOC)) {
> > 768=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 kunit_info(test, "CO=
NFIG_KASAN_VMALLOC is
> > not
> > enabled.");
> > (gdb) l *vmalloc_oob+0x146
> > 0xffffffff81b8b1f6 is in vmalloc_oob (lib/test_kasan.c:779).
> > 774=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 * The MMU will catch that and crash us.
> > 775=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 */
> > 776=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 area =3D vmalloc(3000);
> > 777=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 KUNIT_ASSERT_NOT_ERR_OR_NULL(test, area);
> > 778
> > 779=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char
> > *)area)[3100]);
> > 780=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 vfree(area);
> > 781=C2=A0=C2=A0=C2=A0=C2=A0 }
> > 782
> > 783=C2=A0=C2=A0=C2=A0=C2=A0 static struct kunit_case kasan_kunit_test_c=
ases[] =3D {
> > ----------------x-----------------------------x--------------------
> > >
> >=20
> > Reported by: Jeffrin Jose T <jeffrin@rajagiritech.edu.in>
>=20
> Which CI system is reporting these?
>=20
> If you look, this is the KASAN test, and the report is very much
> intended since it's testing KASAN. Please blacklist the KASAN test
> (and any other tests testing debugging tools).
>=20
> Thanks,
> -- Marco

gdb session was started by me.  (gdb ./vmlinux)

portion from dmesg output is as follows
--------------------x------------------------x-------------------------
-->
[   43.616259] BUG: KASAN: vmalloc-out-of-bounds in
vmalloc_oob+0x146/0x2c0
[   43.630470] Read of size 1 at addr ffffc9000006ec1c by task
kunit_try_catch/193

[   43.659055] CPU: 2 PID: 193 Comm: kunit_try_catch Tainted: G    B =20
5.10.0-rc6+ #10
[   43.659070] Hardware name: ASUSTeK COMPUTER INC. VivoBook 15_ASUS
Laptop X507UAR/X507UAR, BIOS X507UAR.203 05/31/2018
[   43.659080] Call Trace:
[   43.659105]  dump_stack+0x119/0x179
[   43.659131]  print_address_description.constprop.0+0x1c/0x210
[   43.659163]  ? vmalloc_oob+0x146/0x2c0
[   43.659185]  kasan_report.cold+0x1f/0x37
[   43.659210]  ? vmalloc_oob+0x146/0x2c0
[   43.659234]  vmalloc_oob+0x146/0x2c0
[   43.659259]  ? kasan_global_oob+0x280/0x280
[   43.659287]  ? kunit_fail_assert_format+0xa0/0xa0
[   43.659313]  ? lock_release+0xb2/0x730
[   43.659334]  ? __kthread_parkme+0xa1/0x120
[   43.659356]  ? lock_acquired+0xb4/0x5b0
[   43.659379]  ? lock_downgrade+0x3d0/0x3d0
[   43.659403]  ? lock_contended+0x6e0/0x6e0
[   43.659423]  ? do_raw_spin_lock+0x1b0/0x1b0
[   43.659447]  ? io_schedule_timeout+0xb0/0xb0
[   43.659467]  ? static_obj+0x31/0x80
[   43.659492]  ? lockdep_hardirqs_on_prepare+0xe/0x240
[   43.659517]  ? memcg_accounted_kmem_cache+0x1b0/0x1b0
[   43.659542]  kunit_try_run_case+0xa6/0x150
[   43.659567]  ? kunit_catch_run_case+0x170/0x170
[   43.659591]  ? kunit_try_catch_throw+0x40/0x40
[   43.659617]  kunit_generic_run_threadfn_adapter+0x2e/0x50
[   43.659637]  kthread+0x232/0x260
[   43.659659]  ? __kthread_bind_mask+0x90/0x90
[   43.659684]  ret_from_fork+0x22/0x30


[   43.686511] Memory state around the buggy address:
[   43.700445]  ffffc9000006eb00: 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00
[   43.714559]  ffffc9000006eb80: 00 00 00 00 00 00 00 f8 f8 f8 f8 f8
f8 f8 f8 f8
[   43.728725] >ffffc9000006ec00: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8
f8 f8 f8 f8
[   43.742808]                             ^
[   43.757156]  ffffc9000006ec80: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8
f8 f8 f8 f8
[   43.771845]  ffffc9000006ed00: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8
f8 f8 f8 f8
[   43.785957]
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D

-------------------x-----------------------------x---------------------
---------->


--=20
software engineer
rajagiri school of engineering and technology - autonomous


--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/b5bd7b0924bd239eb8d6557e10eead8bb2b939a5.camel%40rajagiritech.edu=
.in.
