Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5UYQOBAMGQE3IQGKHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id A86F332D232
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Mar 2021 13:03:03 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id s4sf20300394ilv.23
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Mar 2021 04:03:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614859382; cv=pass;
        d=google.com; s=arc-20160816;
        b=KCn78v9KSMBhYKyE9kE/XylmpYNs1Y45TH3eBtgMupUtHtFSvxofjO4Y0SXhelyfne
         o+YxVEMl68z7g2cRWJOmvoFRMw6+St1Q1eICz5ACdoNzAzqilsktwvpxw2VH+h6jMGEo
         IwjhGJ5fY2uyAB0pUuHnPgAEIAotgG76JF7RsvR42ji804YZpIkbQc5nMZGbIyigYmr3
         wM4FHsOiLBjJ+k5JYJJD5rJB47tZTqpn7Wkw1OC8xO4dNo73LsIkDjMNyfcG1Fpg13BJ
         AllCIfW4PzItg3HHcQKl3iUsaZqNTVUAY86InR5dOCzDIW+vBCADN1Ij91QKGMnRZQwx
         zg6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=lEktTLlFtgWi35B1SehBMifS22cxldYHnAGmpa2TZzc=;
        b=SAZtwYddqgdmlJclD3LQ059MNyGxXcH/fXQ9idjIkyYn7GvVkeHMFkS2bZb8T4LoYF
         g5uId5oRNpVAPptRB36CWGM4Fa4CGeolFpOANI+a3ulnO9L+DBd2zQBEI4h0mx4/8Y/c
         U0VlqPxSGCOoxGy7fCR1ZvNKBPlpZTWcpRLzPQRBrGVOKcH8obhd3XzBnzNx6wQuN91m
         AYwcHsVPC7KgUSLelyshu75q5Hl7+7PAEJkdRzK0MUQWTKePGPpRbWTNITgs9CilSlg8
         S9oE+O4O2HXU+b7munUCMoaerIu4hkk/X0sxCOvdns+mqOOIaXFms+tbG9vOp0zBM1Qx
         DsDg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RJPO8rPq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::233 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=lEktTLlFtgWi35B1SehBMifS22cxldYHnAGmpa2TZzc=;
        b=NxZ0nzrfCwoCMme3TZbzHhbDYoAG3dkphXA3GPq2fIX1JSeLtVHyg7+EMrqYFVIIxy
         OkybJeVIHpfsF2ideFBqvAk80ptNa6njWWsji2u2wuThETWQLremOHaya3mw0xjlV+oU
         O+iy7PMuf86QK2THbe+xT85zI3REvQql1V+NDeiR+WrngpoMmbCf9NWy0QP4sSr4Hicb
         /kVBTRuFILfHF0biqeqcELvERL1bgVVYdEIZyyNJTsI6VO9ISnJgoJRm6xWcU7d6XSS9
         VSBxr+/PGUP6/qPXJzwSNyjRljV5ob35Nv8MfK4xULYcOBtIfzJnNc3il8Qwm4762oYj
         D7Gg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lEktTLlFtgWi35B1SehBMifS22cxldYHnAGmpa2TZzc=;
        b=cndsSWsf6qrI+tRf+LgxdIr54Ws6U3rgl8qUwjq7tSOX0Qlerm80K++hWPDctvpf6G
         vUzafTtISl8mI/uq8Mv2Gh1taRr5upSD2jNEF1m453VGUNmjoiWHLGSHgepBnY3ejnw7
         q91+cK/R3f2cWzX3VJhWWG3WuroijOyMSEIT6k9B9O48IUUmqZ/ekjsHGy2Z1HfSPBSn
         QQIKDNEkX6ClSIoVsGwUQdnjRwNzE0tihelnQ73L0TZLWAKBb3rvIGDrIpH18HwTVHqS
         YzOGEqXIFKnrygWkbvRVhFy/dNmRqXZNlAwYy1gjIbM80YHsQ4MptSh+6xpcUKYhu1Xu
         D5nA==
X-Gm-Message-State: AOAM532oejXGsZrYeOWK81/mDOEsTzbzbqhnoQNSNgsNlACRf5rGX9To
	I6A3MpE6q8a+2PWRmKUJmKA=
X-Google-Smtp-Source: ABdhPJwsqH2bIURQhFe7Z5AkM6ifJvJVyjwgohSfbOlpbdIKSKGcYYL1siyen6onbcAWmtiU04VYdg==
X-Received: by 2002:a5d:9d01:: with SMTP id j1mr3230501ioj.195.1614859382157;
        Thu, 04 Mar 2021 04:03:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:8348:: with SMTP id q8ls895878ior.8.gmail; Thu, 04 Mar
 2021 04:03:01 -0800 (PST)
X-Received: by 2002:a5e:840a:: with SMTP id h10mr3264188ioj.206.1614859381818;
        Thu, 04 Mar 2021 04:03:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614859381; cv=none;
        d=google.com; s=arc-20160816;
        b=reXIM0aM3AHSs34y6Mv9SiswVHrq4WKOCosbOmlFWto3AnAA+qrRW3+GBb+0+IOY7R
         CDqWlb7tUsPhQz76Hfp/dz4aQvc/uv6z2bIuM/xIcI4RWt597GwEbUicfNvNnK1zLtR1
         ymEEEywXX5gUPYqv/b+TeikTE7fFbUGlUoFI+xE35Mv0qVZlvUj5L3yGlIQeUa1JLP9X
         DSaVwnx6v+SsGmoepNHLTSYS2jS51PJPH9dgbhfuUmWhoqeuZAbbuo2gn6jTmQeYid/e
         PF4XAB9v2268hxUbW27iYTn6Yzwj4aKyiTj15M7L/LaOgQ4kDInPB1bFVoBBPwQ7jlXU
         jo3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=FH7ph6cwSCi93IJHohvQ0RuLXYukCCGdk/pW1zQYl0k=;
        b=VKh8jHlA66Gjg0k9f43aaGikUkV59DCv7sr2S5onm+GkqSB8PrbZ6mW0Anr9T05reN
         KAR+MUZjetJi2kxvx4ICW4byfpYJkkFkj6tci7MIK2vI5b+ONmfYNz6YkiMGLWs4iAgO
         blERDB7mBpB/pnxHsXwkgsnruS7SKyKzWtiLun+6N+1jCyKmKniczi98g2/U5FDTJ8zv
         XmT33/ej2mnAzE1VUserH7AydInMv7iaF8GteqmXl7HQ7EXWz7OWIEOqHivnWdl0kMOc
         mtOY02OurcFdDdSAjhfR9DjZEOsQAGyhT5P7EMGV4IeAsU4T0OWaJcJUOfc5SSm0XcH8
         dYZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RJPO8rPq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::233 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x233.google.com (mail-oi1-x233.google.com. [2607:f8b0:4864:20::233])
        by gmr-mx.google.com with ESMTPS id r19si1425343iov.3.2021.03.04.04.03.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Mar 2021 04:03:01 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::233 as permitted sender) client-ip=2607:f8b0:4864:20::233;
Received: by mail-oi1-x233.google.com with SMTP id x20so29766248oie.11
        for <kasan-dev@googlegroups.com>; Thu, 04 Mar 2021 04:03:01 -0800 (PST)
X-Received: by 2002:a05:6808:10d3:: with SMTP id s19mr2772884ois.70.1614859381258;
 Thu, 04 Mar 2021 04:03:01 -0800 (PST)
MIME-Version: 1.0
References: <51c397a23631d8bb2e2a6515c63440d88bf74afd.1614674144.git.christophe.leroy@csgroup.eu>
 <CANpmjNPOJfL_qsSZYRbwMUrxnXxtF5L3k9hursZZ7k9H1jLEuA@mail.gmail.com>
 <b9dc8d35-a3b0-261a-b1a4-5f4d33406095@csgroup.eu> <CAG_fn=WFffkVzqC9b6pyNuweFhFswZfa8RRio2nL9-Wq10nBbw@mail.gmail.com>
 <f806de26-daf9-9317-fdaa-a0f7a32d8fe0@csgroup.eu> <CANpmjNPGj4C2rr2FbSD+FC-GnWUvJrtdLyX5TYpJE_Um8CGu1Q@mail.gmail.com>
 <08a96c5d-4ae7-03b4-208f-956226dee6bb@csgroup.eu> <CANpmjNPYEmLtQEu5G=zJLUzOBaGoqNKwLyipDCxvytdKDKb7mg@mail.gmail.com>
 <ad61cb3a-2b4a-3754-5761-832a1dd0c34e@csgroup.eu> <CANpmjNOnVzei7frKcMzMHxaDXh5NvTA-Wpa29C2YC1GUxyKfhQ@mail.gmail.com>
 <f036c53d-7e81-763c-47f4-6024c6c5f058@csgroup.eu> <CANpmjNMn_CUrgeSqBgiKx4+J8a+XcxkaLPWoDMUvUEXk8+-jxg@mail.gmail.com>
 <7270e1cc-bb6b-99ee-0043-08a027b8d83a@csgroup.eu> <72e31c34-e947-1084-2bd2-f5b80786f827@csgroup.eu>
In-Reply-To: <72e31c34-e947-1084-2bd2-f5b80786f827@csgroup.eu>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 4 Mar 2021 13:02:49 +0100
Message-ID: <CANpmjNNzTGN1xa5Egf2e+twd9n0LgEVUS_sG9nOCzb50NPTKpg@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=RJPO8rPq;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::233 as
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

On Thu, 4 Mar 2021 at 13:00, Christophe Leroy
<christophe.leroy@csgroup.eu> wrote:
>
>
>
> Le 04/03/2021 =C3=A0 12:48, Christophe Leroy a =C3=A9crit :
> >
> >
> > Le 04/03/2021 =C3=A0 12:31, Marco Elver a =C3=A9crit :
> >> On Thu, 4 Mar 2021 at 12:23, Christophe Leroy
> >> <christophe.leroy@csgroup.eu> wrote:
> >>> Le 03/03/2021 =C3=A0 11:56, Marco Elver a =C3=A9crit :
> >>>>
> >>>> Somewhat tangentially, I also note that e.g. show_regs(regs) (which
> >>>> was printed along the KFENCE report above) didn't include the top
> >>>> frame in the "Call Trace", so this assumption is definitely not
> >>>> isolated to KFENCE.
> >>>>
> >>>
> >>> Now, I have tested PPC64 (with the patch I sent yesterday to modify s=
ave_stack_trace_regs()
> >>> applied), and I get many failures. Any idea ?
> >>>
> >>> [   17.653751][   T58] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D
> >>> [   17.654379][   T58] BUG: KFENCE: invalid free in .kfence_guarded_f=
ree+0x2e4/0x530
> >>> [   17.654379][   T58]
> >>> [   17.654831][   T58] Invalid free of 0xc00000003c9c0000 (in kfence-=
#77):
> >>> [   17.655358][   T58]  .kfence_guarded_free+0x2e4/0x530
> >>> [   17.655775][   T58]  .__slab_free+0x320/0x5a0
> >>> [   17.656039][   T58]  .test_double_free+0xe0/0x198
> >>> [   17.656308][   T58]  .kunit_try_run_case+0x80/0x110
> >>> [   17.656523][   T58]  .kunit_generic_run_threadfn_adapter+0x38/0x50
> >>> [   17.657161][   T58]  .kthread+0x18c/0x1a0
> >>> [   17.659148][   T58]  .ret_from_kernel_thread+0x58/0x70
> >>> [   17.659869][   T58]
> >>> [   17.663954][   T58] kfence-#77 [0xc00000003c9c0000-0xc00000003c9c0=
01f, size=3D32, cache=3Dkmalloc-32]
> >>> allocated by task 58:
> >>> [   17.666113][   T58]  .__kfence_alloc+0x1bc/0x510
> >>> [   17.667069][   T58]  .__kmalloc+0x280/0x4f0
> >>> [   17.667452][   T58]  .test_alloc+0x19c/0x430
> >>> [   17.667732][   T58]  .test_double_free+0x88/0x198
> >>> [   17.667971][   T58]  .kunit_try_run_case+0x80/0x110
> >>> [   17.668283][   T58]  .kunit_generic_run_threadfn_adapter+0x38/0x50
> >>> [   17.668553][   T58]  .kthread+0x18c/0x1a0
> >>> [   17.669315][   T58]  .ret_from_kernel_thread+0x58/0x70
> >>> [   17.669711][   T58]
> >>> [   17.669711][   T58] freed by task 58:
> >>> [   17.670116][   T58]  .kfence_guarded_free+0x3d0/0x530
> >>> [   17.670421][   T58]  .__slab_free+0x320/0x5a0
> >>> [   17.670603][   T58]  .test_double_free+0xb4/0x198
> >>> [   17.670827][   T58]  .kunit_try_run_case+0x80/0x110
> >>> [   17.671073][   T58]  .kunit_generic_run_threadfn_adapter+0x38/0x50
> >>> [   17.671410][   T58]  .kthread+0x18c/0x1a0
> >>> [   17.671618][   T58]  .ret_from_kernel_thread+0x58/0x70
> >>> [   17.671972][   T58]
> >>> [   17.672638][   T58] CPU: 0 PID: 58 Comm: kunit_try_catch Tainted: =
G    B
> >>> 5.12.0-rc1-01540-g0783285cc1b8-dirty #4685
> >>> [   17.673768][   T58] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D
> >>> [   17.677031][   T58]     # test_double_free: EXPECTATION FAILED at =
mm/kfence/kfence_test.c:380
> >>> [   17.677031][   T58]     Expected report_matches(&expect) to be tru=
e, but is false
> >>> [   17.684397][    T1]     not ok 7 - test_double_free
> >>> [   17.686463][   T59]     # test_double_free-memcache: setup_test_ca=
che: size=3D32, ctor=3D0x0
> >>> [   17.688403][   T59]     # test_double_free-memcache: test_alloc: s=
ize=3D32, gfp=3Dcc0, policy=3Dany,
> >>> cache=3D1
> >>
> >> Looks like something is prepending '.' to function names. We expect
> >> the function name to appear as-is, e.g. "kfence_guarded_free",
> >> "test_double_free", etc.
> >>
> >> Is there something special on ppc64, where the '.' is some convention?
> >>
> >
> > I think so, see https://refspecs.linuxfoundation.org/ELF/ppc64/PPC-elf6=
4abi.html#FUNC-DES
> >
> > Also see commit https://github.com/linuxppc/linux/commit/02424d896
> >
>
> But I'm wondering, if the dot is the problem, how so is the following one=
 ok ?
>
> [   79.574457][   T75]     # test_krealloc: test_alloc: size=3D32, gfp=3D=
cc0, policy=3Dany, cache=3D0
> [   79.682728][   T75] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> [   79.684017][   T75] BUG: KFENCE: use-after-free read in .test_krealloc=
+0x4fc/0x5b8
> [   79.684017][   T75]
> [   79.684955][   T75] Use-after-free read at 0xc00000003d060000 (in kfen=
ce-#130):
> [   79.687581][   T75]  .test_krealloc+0x4fc/0x5b8
> [   79.688216][   T75]  .test_krealloc+0x4e4/0x5b8
> [   79.688824][   T75]  .kunit_try_run_case+0x80/0x110
> [   79.689737][   T75]  .kunit_generic_run_threadfn_adapter+0x38/0x50
> [   79.690335][   T75]  .kthread+0x18c/0x1a0
> [   79.691092][   T75]  .ret_from_kernel_thread+0x58/0x70
> [   79.692081][   T75]
> [   79.692671][   T75] kfence-#130 [0xc00000003d060000-0xc00000003d06001f=
, size=3D32,
> cache=3Dkmalloc-32] allocated by task 75:
> [   79.700977][   T75]  .__kfence_alloc+0x1bc/0x510
> [   79.701812][   T75]  .__kmalloc+0x280/0x4f0
> [   79.702695][   T75]  .test_alloc+0x19c/0x430
> [   79.703051][   T75]  .test_krealloc+0xa8/0x5b8
> [   79.703276][   T75]  .kunit_try_run_case+0x80/0x110
> [   79.703693][   T75]  .kunit_generic_run_threadfn_adapter+0x38/0x50
> [   79.704223][   T75]  .kthread+0x18c/0x1a0
> [   79.704586][   T75]  .ret_from_kernel_thread+0x58/0x70
> [   79.704968][   T75]
> [   79.704968][   T75] freed by task 75:
> [   79.705756][   T75]  .kfence_guarded_free+0x3d0/0x530
> [   79.706754][   T75]  .__slab_free+0x320/0x5a0
> [   79.708575][   T75]  .krealloc+0xe8/0x180
> [   79.708970][   T75]  .test_krealloc+0x1c8/0x5b8
> [   79.709606][   T75]  .kunit_try_run_case+0x80/0x110
> [   79.710204][   T75]  .kunit_generic_run_threadfn_adapter+0x38/0x50
> [   79.710639][   T75]  .kthread+0x18c/0x1a0
> [   79.710996][   T75]  .ret_from_kernel_thread+0x58/0x70
> [   79.711349][   T75]
> [   79.717435][   T75] CPU: 0 PID: 75 Comm: kunit_try_catch Tainted: G   =
 B
> 5.12.0-rc1-01540-g0783285cc1b8-dirty #4685
> [   79.718124][   T75] NIP:  c000000000468a40 LR: c000000000468a28 CTR: 0=
000000000000000
> [   79.727741][   T75] REGS: c000000007dd3830 TRAP: 0300   Tainted: G    =
B
> (5.12.0-rc1-01540-g0783285cc1b8-dirty)
> [   79.733377][   T75] MSR:  8000000002009032 <SF,VEC,EE,ME,IR,DR,RI>  CR=
: 28000440  XER: 00000000
> [   79.738770][   T75] CFAR: c000000000888c7c DAR: c00000003d060000 DSISR=
: 40000000 IRQMASK: 0
> [   79.738770][   T75] GPR00: c000000000468a28 c000000007dd3ad0 c00000000=
1eaad00 c0000000073c3988
> [   79.738770][   T75] GPR04: c000000007dd3b60 0000000000000001 000000000=
0000000 c00000003d060000
> [   79.738770][   T75] GPR08: 00000000000002c8 0000000000000001 c00000000=
11bb410 c00000003fe903d8
> [   79.738770][   T75] GPR12: 0000000028000440 c0000000020f0000 c00000000=
01a6460 c00000000724bb80
> [   79.738770][   T75] GPR16: 0000000000000000 c00000000731749f c00000000=
11bb278 c00000000731749f
> [   79.738770][   T75] GPR20: 00000001000002c1 0000000000000000 c00000000=
11bb278 c0000000011bb3b8
> [   79.738770][   T75] GPR24: c0000000073174a0 c0000000011aa7b8 c00000000=
1e35328 c00000000208ad00
> [   79.738770][   T75] GPR28: 0000000000000000 c0000000011bb0b8 c00000000=
73c3988 c000000007dd3ad0
> [   79.751744][   T75] NIP [c000000000468a40] .test_krealloc+0x4fc/0x5b8
> [   79.752243][   T75] LR [c000000000468a28] .test_krealloc+0x4e4/0x5b8
> [   79.752699][   T75] Call Trace:
> [   79.753027][   T75] [c000000007dd3ad0] [c000000000468a28] .test_kreall=
oc+0x4e4/0x5b8 (unreliable)
> [   79.753878][   T75] [c000000007dd3c40] [c0000000008886d0] .kunit_try_r=
un_case+0x80/0x110
> [   79.754641][   T75] [c000000007dd3cd0] [c00000000088a808]
> .kunit_generic_run_threadfn_adapter+0x38/0x50
> [   79.755494][   T75] [c000000007dd3d50] [c0000000001a65ec] .kthread+0x1=
8c/0x1a0
> [   79.757254][   T75] [c000000007dd3e10] [c00000000000dd68] .ret_from_ke=
rnel_thread+0x58/0x70
> [   79.775521][   T75] Instruction dump:
> [   79.776890][   T75] 68a50001 9b9f00c8 fbdf0090 fbbf00a0 fb5f00b8 48420=
1cd 60000000 e8ff0080
> [   79.783146][   T75] 3d42ff31 390002c8 394a0710 39200001 <88e70000> 38a=
00000 fb9f00a8 e8fbe80e
> [   79.787563][   T75] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> [   79.804667][    T1]     ok 24 - test_krealloc

This one is using pt_regs, and therefore isn't trying to determine how
many entries we can skip in the stack trace to avoid showing
internals. I'll reply with a potential solution you can test shortly.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNNzTGN1xa5Egf2e%2Btwd9n0LgEVUS_sG9nOCzb50NPTKpg%40mail.gmai=
l.com.
