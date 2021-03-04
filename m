Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHEKQOBAMGQEPLWIEFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3c.google.com (mail-vk1-xa3c.google.com [IPv6:2607:f8b0:4864:20::a3c])
	by mail.lfdr.de (Postfix) with ESMTPS id DEA7A32D1CD
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Mar 2021 12:31:41 +0100 (CET)
Received: by mail-vk1-xa3c.google.com with SMTP id k21sf7527058vke.3
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Mar 2021 03:31:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614857501; cv=pass;
        d=google.com; s=arc-20160816;
        b=Tnha1PAaQgBRQgvqk2RQILtCCcZxrjnIoRT0CrPE0pTBRvbrnHf84asDdmdSLsQPum
         8a7P+O2U9ArcaoZH/c93yw+uDWcBKsThI/OXsTiXe3LiBDog6sgZJdaIM4iukA7ainN3
         4VfxHVWx66H71YnGmxbCPPVsaGoyVOQVwVMUH1rfHyVoK1RblD9ucN/ujbO0eoZCku3D
         NnTgiAF6jpkzmZoDZiyc1g5FspU7I9myuZHGRQUV0FcPYQ/a4aWyjhPJuq0/DFS3YKBD
         Zq1SO+c2tMbYs6KG6D2NTgS5ERZfMwxIM/VsAxNGcvKRw3ZDVTPMCkpKbSH2q1nkMgCE
         v1yQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=y/ceorpu3MgGm4csWaDcZvrXjVMGthEIF935vam0Vz8=;
        b=BsosrHFLihjqC1wdJPe19xVvrPE0NrTWvnzUxpepqPQuPmyASUlgc3qb5RleW9Vuvj
         /oLAScjP7wEajqRb3d6WwyyCsyVH+NgAz9TmL7fma56gF2g2BLI5XLZBOcsVkLZ54DCh
         53ZNu8uHk9fb7TjTLrqV/ptRe65OtIuPPSoOGqnoAz8GV/pnPaj82f/sK0DW5drWOt4t
         RoeCofCeEWv8ZXMBRu0nVXek5IZnwENsSQdOo94W96bF6cUOJ3SfmA0f9dwsxTlNFSSq
         DgUo23L5DOfsIkoafEPFz1xuDt7EM50zrtD38eehZUUyq9ePH9Jg+khmq6icZG1/PkGP
         M1yQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FvLMEup3;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::230 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=y/ceorpu3MgGm4csWaDcZvrXjVMGthEIF935vam0Vz8=;
        b=XcLvweU9GV2sK092Knz4XwEg1TexkKxxzZHibrSOIglynRoblssShw7Gd0DkYt7/g9
         Rh75MsfKlz1ul9oRUv8LL/IhK+F+A5dfGWEq7VLT9K++L5KEsJg5G32J1IWVfeH3wl5z
         XhiISUtbPA762ilkLOy6D/d6ECpapzets3qO7cEhT2U9xR5FCHqrA1Jm6l/Y3h1bL6pi
         YJRTLGrFOZ23wZjpYhgBQuHtT+MMeteK4v4MXz4B5aMFrIHT4O1riYv13zMCZEG85/IZ
         jwyAqf9AgdSC6qIsneVbd8APjbkILjQLVBEt+/1MenbhxSmE7hHbNQE5iD7UZJgvFiNh
         4xKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=y/ceorpu3MgGm4csWaDcZvrXjVMGthEIF935vam0Vz8=;
        b=CSpt/XpT5cb0cUZ62kgdqm4CvNdFkPTKcWzp/lj8dL1cFJql9+tx8VtafxA5xLE2jF
         rAnypi//hhAr/WNp5vUBJQoqk5WruPYBIAHL7+Afwu8GqT0kWm02Ze0zU0eLyNy127Wl
         wsY/C4itBZbXIjoqjhN011aB9pCWrZKHoxZnsqSzjAQELp7fRr4FD2RA9yB8S3UgqXhN
         v6Q3xtchwSLaatrkv6vBtDEx78P++WnA6g9hvsMff9g/VGs1KKQwnbWb9Zn6+og0uZxl
         cvLcZtY6d/rR544G8CYRKNt61NVyR1gmxMR7IRJy+JW2g2pautn/x6cjdSbxbqs/yNin
         tcpw==
X-Gm-Message-State: AOAM532dSEn1fKxo8AMhFuQz0+Bkn4L1/W/AvV5AciMDsMkz1AuUy8X8
	cKISdPU29auZvcDVS9Bptag=
X-Google-Smtp-Source: ABdhPJyGZCu+SmkYEpX0JuMLACjjGN33BALofxFMKaRoblWR7Hn/WdIBk3Q1DQEXpE1Zd9yoPHQsIQ==
X-Received: by 2002:a05:6102:74a:: with SMTP id v10mr2149304vsg.20.1614857501004;
        Thu, 04 Mar 2021 03:31:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:df87:: with SMTP id x7ls683996vsk.8.gmail; Thu, 04 Mar
 2021 03:31:40 -0800 (PST)
X-Received: by 2002:a05:6102:a0c:: with SMTP id t12mr2057154vsa.33.1614857500548;
        Thu, 04 Mar 2021 03:31:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614857500; cv=none;
        d=google.com; s=arc-20160816;
        b=C6ZUYBc+3G9aoSCNkZy4dvnrQcwS+wwnPT47POxIeRwodxP352vNYm99IeJzahARUC
         7Plkyg1PKcoMbXX8Vj6BUKUra4t8/xkJOfHSAjBk4mnIaojn2oFLte7w1ysD2JblWt0S
         EcFmYOg1BYrxYbpJgIWc8ewR0TTQubibkmeKLPbQjJNCFZArWJoeeDxJ2fGvMpFIJxW8
         KfWzPx4gjlgqK91Edy3hrN0rMK18pDOBA/SS3yI2KZcgort4RySG0EU3z1cyJbtcRyef
         xXZAxKq0hX9NhrmMoyq4oGlQgxyYSNXiDPI3DUTCX6rMqg13ypB0tY1pTP/XWZ5HZrPu
         TWMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=j0Anx46LrA/DH7upo2qHDfKBBW2EhpUPPJfiwAkE4e4=;
        b=ttnYZNCTywZcBa9j3b7liAHp9D8KSW9n0Kg3ubqwUJa8lVCqx0H/PzkunUZX/rsaYx
         TP2dZN3du75rdDCDJr05G0OAlyZIwk0exiczPNPVZ/oUceWwrq+TYkl0tZbwAQ2FvIFC
         qMF4X+c91jX65X8AfAUV74P5Cu7u8yRxUyXFTvQ1V8Fd0IpUmY7ES4ULHA1KjXDDbBXn
         Yi5Q506b9Za3qYaXCUNeqFG9W4H20PK3BcSvTnvcLBJUKqDe7e9U3o1wjMxjj4xoxwHA
         vgN8OKrN+bSh0YDAAFQvbI4Um4rpbT7HRwdOBSGyybD1R6H7vSMtAWGY4M9arUdiz93U
         lHxQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FvLMEup3;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::230 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x230.google.com (mail-oi1-x230.google.com. [2607:f8b0:4864:20::230])
        by gmr-mx.google.com with ESMTPS id a136si1491112vki.0.2021.03.04.03.31.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Mar 2021 03:31:40 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::230 as permitted sender) client-ip=2607:f8b0:4864:20::230;
Received: by mail-oi1-x230.google.com with SMTP id w65so6151113oie.7
        for <kasan-dev@googlegroups.com>; Thu, 04 Mar 2021 03:31:40 -0800 (PST)
X-Received: by 2002:a05:6808:10d3:: with SMTP id s19mr2682857ois.70.1614857499889;
 Thu, 04 Mar 2021 03:31:39 -0800 (PST)
MIME-Version: 1.0
References: <51c397a23631d8bb2e2a6515c63440d88bf74afd.1614674144.git.christophe.leroy@csgroup.eu>
 <CANpmjNPOJfL_qsSZYRbwMUrxnXxtF5L3k9hursZZ7k9H1jLEuA@mail.gmail.com>
 <b9dc8d35-a3b0-261a-b1a4-5f4d33406095@csgroup.eu> <CAG_fn=WFffkVzqC9b6pyNuweFhFswZfa8RRio2nL9-Wq10nBbw@mail.gmail.com>
 <f806de26-daf9-9317-fdaa-a0f7a32d8fe0@csgroup.eu> <CANpmjNPGj4C2rr2FbSD+FC-GnWUvJrtdLyX5TYpJE_Um8CGu1Q@mail.gmail.com>
 <08a96c5d-4ae7-03b4-208f-956226dee6bb@csgroup.eu> <CANpmjNPYEmLtQEu5G=zJLUzOBaGoqNKwLyipDCxvytdKDKb7mg@mail.gmail.com>
 <ad61cb3a-2b4a-3754-5761-832a1dd0c34e@csgroup.eu> <CANpmjNOnVzei7frKcMzMHxaDXh5NvTA-Wpa29C2YC1GUxyKfhQ@mail.gmail.com>
 <f036c53d-7e81-763c-47f4-6024c6c5f058@csgroup.eu>
In-Reply-To: <f036c53d-7e81-763c-47f4-6024c6c5f058@csgroup.eu>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 4 Mar 2021 12:31:27 +0100
Message-ID: <CANpmjNMn_CUrgeSqBgiKx4+J8a+XcxkaLPWoDMUvUEXk8+-jxg@mail.gmail.com>
Subject: Re: [RFC PATCH v1] powerpc: Enable KFENCE for PPC32
To: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: Alexander Potapenko <glider@google.com>, Benjamin Herrenschmidt <benh@kernel.crashing.org>, 
	Paul Mackerras <paulus@samba.org>, Michael Ellerman <mpe@ellerman.id.au>, 
	Dmitry Vyukov <dvyukov@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	linuxppc-dev@lists.ozlabs.org, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=FvLMEup3;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::230 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, 4 Mar 2021 at 12:23, Christophe Leroy
<christophe.leroy@csgroup.eu> wrote:
> Le 03/03/2021 =C3=A0 11:56, Marco Elver a =C3=A9crit :
> >
> > Somewhat tangentially, I also note that e.g. show_regs(regs) (which
> > was printed along the KFENCE report above) didn't include the top
> > frame in the "Call Trace", so this assumption is definitely not
> > isolated to KFENCE.
> >
>
> Now, I have tested PPC64 (with the patch I sent yesterday to modify save_=
stack_trace_regs()
> applied), and I get many failures. Any idea ?
>
> [   17.653751][   T58] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> [   17.654379][   T58] BUG: KFENCE: invalid free in .kfence_guarded_free+=
0x2e4/0x530
> [   17.654379][   T58]
> [   17.654831][   T58] Invalid free of 0xc00000003c9c0000 (in kfence-#77)=
:
> [   17.655358][   T58]  .kfence_guarded_free+0x2e4/0x530
> [   17.655775][   T58]  .__slab_free+0x320/0x5a0
> [   17.656039][   T58]  .test_double_free+0xe0/0x198
> [   17.656308][   T58]  .kunit_try_run_case+0x80/0x110
> [   17.656523][   T58]  .kunit_generic_run_threadfn_adapter+0x38/0x50
> [   17.657161][   T58]  .kthread+0x18c/0x1a0
> [   17.659148][   T58]  .ret_from_kernel_thread+0x58/0x70
> [   17.659869][   T58]
> [   17.663954][   T58] kfence-#77 [0xc00000003c9c0000-0xc00000003c9c001f,=
 size=3D32, cache=3Dkmalloc-32]
> allocated by task 58:
> [   17.666113][   T58]  .__kfence_alloc+0x1bc/0x510
> [   17.667069][   T58]  .__kmalloc+0x280/0x4f0
> [   17.667452][   T58]  .test_alloc+0x19c/0x430
> [   17.667732][   T58]  .test_double_free+0x88/0x198
> [   17.667971][   T58]  .kunit_try_run_case+0x80/0x110
> [   17.668283][   T58]  .kunit_generic_run_threadfn_adapter+0x38/0x50
> [   17.668553][   T58]  .kthread+0x18c/0x1a0
> [   17.669315][   T58]  .ret_from_kernel_thread+0x58/0x70
> [   17.669711][   T58]
> [   17.669711][   T58] freed by task 58:
> [   17.670116][   T58]  .kfence_guarded_free+0x3d0/0x530
> [   17.670421][   T58]  .__slab_free+0x320/0x5a0
> [   17.670603][   T58]  .test_double_free+0xb4/0x198
> [   17.670827][   T58]  .kunit_try_run_case+0x80/0x110
> [   17.671073][   T58]  .kunit_generic_run_threadfn_adapter+0x38/0x50
> [   17.671410][   T58]  .kthread+0x18c/0x1a0
> [   17.671618][   T58]  .ret_from_kernel_thread+0x58/0x70
> [   17.671972][   T58]
> [   17.672638][   T58] CPU: 0 PID: 58 Comm: kunit_try_catch Tainted: G   =
 B
> 5.12.0-rc1-01540-g0783285cc1b8-dirty #4685
> [   17.673768][   T58] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> [   17.677031][   T58]     # test_double_free: EXPECTATION FAILED at mm/k=
fence/kfence_test.c:380
> [   17.677031][   T58]     Expected report_matches(&expect) to be true, b=
ut is false
> [   17.684397][    T1]     not ok 7 - test_double_free
> [   17.686463][   T59]     # test_double_free-memcache: setup_test_cache:=
 size=3D32, ctor=3D0x0
> [   17.688403][   T59]     # test_double_free-memcache: test_alloc: size=
=3D32, gfp=3Dcc0, policy=3Dany,
> cache=3D1

Looks like something is prepending '.' to function names. We expect
the function name to appear as-is, e.g. "kfence_guarded_free",
"test_double_free", etc.

Is there something special on ppc64, where the '.' is some convention?

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNMn_CUrgeSqBgiKx4%2BJ8a%2BXcxkaLPWoDMUvUEXk8%2B-jxg%40mail.=
gmail.com.
