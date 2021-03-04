Return-Path: <kasan-dev+bncBDLKPY4HVQKBBO4GQOBAMGQEZFZODLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id A5CE732D1AB
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Mar 2021 12:23:40 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id a9sf5831944lfb.19
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Mar 2021 03:23:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614857020; cv=pass;
        d=google.com; s=arc-20160816;
        b=n1RYZNxkOdzisEv3ze5COMiplj/XbUnhgMp+B2GUAvQeWtJNk1r5I6tORcfMHSxiV1
         biU3tI/km7DqDp2HQ4MS3kuHQnmIlgKSDI1j+h3km2R/Dxn5oLqfKD03P6U5qYACOrrQ
         YvxTh+pp17xQTe/sSaVQZiNyldDzSZ1HeDrrFjt1YL3ECu3/OyVaJVbmqfPorQZHHsiY
         UHY13+HAjUw1Yf9uz8YUIZcLAE/xWqujnP4WaEcQ50ExhMxLWtBy6AigoIKaRPvwRC06
         VztD9g7Rr2WbSxibzY4EdnTxIONAWQO3zrM4GgMXBgFeGl9lComU1fSeId+qdE/OQKLI
         ma/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=jktFHKhOP3jT/OKc87K70yJ4DyVhvem0LrPCvWgTF5M=;
        b=vuTCKmULEBungCrYxrYhcYrVXKN/fzyd629DdrfE70/R1/3Dog/HhUtecy+b9cpz4N
         xz/IwPipGg8NHHmi0c5ggeSGLS1wp61kJL2uLWvVA9qfq/nSArnYW8EYEcqjvTrUtZH0
         XxxQnBWSM3YCPherjyKjXXzY0lQeVf3mOY2PYHLk3/2e4s4OwQqkc9uXXdGmKHKNFD/P
         QSO+6PuE69lDW8XzE9VraPyROIgZyw9I8FsqwCPnAKXNsVvTHy+9TpnrhpOwcA1Kdi38
         /dlh+TUdp2TnMoYpk7DhH0TbfxBLM5pLg1sme8LGnnyEkABemtJ/yWFoJJbdCIhTDjbr
         /TQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jktFHKhOP3jT/OKc87K70yJ4DyVhvem0LrPCvWgTF5M=;
        b=Tvc2U0A3YfGMOJho738+zHkAEDvSavLXEK659S3Ba87KgMpsddXyuGYLPi1e24MU4B
         KHNxS/HWFBMIePsg9i7RMu8nkMi5HPzHm4Nzn9dwEa4li03U4berMIFKn5r8o/KGaNwY
         pU3gwN6i8zZzWTr6oBgccufXc5wYvxlRVIrfJnUXTBm1SlzYIcSQCauXwukqLH+qPc/p
         HCkUFbNdrnkmPAgf288/Qqv8IHKqopriGqFpkOAqhY7G6AOwYCV6MWe9SY/6IYvNiw53
         5ZhWPaSWuWWdIwMMaybnVhZCHjDkKwDJ2eukwHU5t+/PJ7UbQyjpCPjN4z9rQrQ8QzmW
         uouQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jktFHKhOP3jT/OKc87K70yJ4DyVhvem0LrPCvWgTF5M=;
        b=lRCo1pngCbEe5wYRsbmbyR5zz1vygwFhvogkABCp/6p0Pdtf9a7zDR1jv5r2wP2BLH
         G17QglINU5ihg85BEXlN+EfgwH/37LIJA03BKBaOP0JtiYOL4vbSwMmCilE1lkbiDKHw
         VxqhyoCe2t2HB7cKpNGKirQHw7zl8ydgdQSSRdqD1cvgkq0US+pGes+qTzRCpKOfLbAk
         RK+9Kwhl18SNT7E9hWTHTRhmSHO0FFQdjQekHLH885DihJgI7AostZxa/EbFcOgPK+hX
         gVaO+SwOScI+3/5Wz1lMZVva1yNHmd670gfb2UWdPA4IszL6oGu9u9BwdQUoDp1mFNai
         qBNg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532ltN9cGCpshrJrJV410wDV4OqX95NZ5wzL+6pFOaSJCDmQgr/p
	cGPGR4ZHaHQkpZbyASLRo5c=
X-Google-Smtp-Source: ABdhPJxBHG1SdxBbV68BBd09bEM2Tbl3y8IGWemJ6zxrjjL2BbUy19T6rIZiM5XAYLkY1xTDceEuJw==
X-Received: by 2002:a2e:9c41:: with SMTP id t1mr2042041ljj.345.1614857020211;
        Thu, 04 Mar 2021 03:23:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3993:: with SMTP id j19ls803402lfu.3.gmail; Thu, 04
 Mar 2021 03:23:39 -0800 (PST)
X-Received: by 2002:a05:6512:3047:: with SMTP id b7mr2102699lfb.279.1614857019173;
        Thu, 04 Mar 2021 03:23:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614857019; cv=none;
        d=google.com; s=arc-20160816;
        b=tYdahA34P6dpmfpJjxxYZEUkGgSqJSXZULYDQ4GWQTLF9SWG8Wc6JfTTCbzTxbG9PF
         4Mfa+ijULXJIZyH7CGDZTZB2PTPw+JWclxkRATtz2OinGoPQPZ+sDTxA3l8g7Ksuf5LZ
         hZJC3aH1ia2P/IAjLdTKjVUjqXlxdXoszz2y/Yi6OQ5p/4+DzEM94i4mP6NGl/LrVPkI
         gEp9mPk3oPs4DWFX3MuRItLGnIFlSwNZfRK0cbcT+yne1aF68MKNfzlGsc/8A5eY19Wp
         gqDEPF/QKiAc4EiVwdaF/7owELzge9ywNSgIEWqfpA4nl/XML35XDy/3Wp06Xmbwz9Tl
         wUOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=Ht1wZjNEeQsx16HQbnugO/xR/sl88+Gnj9CPHP5F3FY=;
        b=XhP8OO1Sy5PomxeFver2GcNtoFgGVKMcTS8OHzV4dD5IbOwVvaWut/WHsRuIseeFFS
         B1eCulX6WtKY6j1kfvFzRBz/qq0ZF2onMOU+oElSNMI4Z4tWrhNLoSg7AwKrLhZC71ow
         xNxf3H4XKM7KeMG+dGdRA5ACMgF9OcqerNkDXrq9ZIDAKMtd+8HZYpN5y7FKrqs7Lllz
         peNw7bFDDTRfoI5DvE5Tq2AWtvGVLYnPkdNldF3pXwHz1+2Al1N6z4I86cMyso1l/bs3
         6Yvpv6PtjZj5kBL2wMCsmbyMqlalIf8gtAGT7nrYYBNRvAzyUQSrnsLPQjOFvL4rZrB1
         a9PA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id q26si1341948ljj.4.2021.03.04.03.23.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 04 Mar 2021 03:23:39 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 4DrpQc33TNz9v1s1;
	Thu,  4 Mar 2021 12:23:36 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id cSK_19P4qbTv; Thu,  4 Mar 2021 12:23:36 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4DrpQc23Wrz9v1ry;
	Thu,  4 Mar 2021 12:23:36 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id D2B8D8B7FF;
	Thu,  4 Mar 2021 12:23:37 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id a51erVwSvf4n; Thu,  4 Mar 2021 12:23:37 +0100 (CET)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 0B3B88B773;
	Thu,  4 Mar 2021 12:23:36 +0100 (CET)
Subject: Re: [RFC PATCH v1] powerpc: Enable KFENCE for PPC32
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>,
 Benjamin Herrenschmidt <benh@kernel.crashing.org>,
 Paul Mackerras <paulus@samba.org>, Michael Ellerman <mpe@ellerman.id.au>,
 Dmitry Vyukov <dvyukov@google.com>, LKML <linux-kernel@vger.kernel.org>,
 linuxppc-dev@lists.ozlabs.org, kasan-dev <kasan-dev@googlegroups.com>
References: <51c397a23631d8bb2e2a6515c63440d88bf74afd.1614674144.git.christophe.leroy@csgroup.eu>
 <CANpmjNPOJfL_qsSZYRbwMUrxnXxtF5L3k9hursZZ7k9H1jLEuA@mail.gmail.com>
 <b9dc8d35-a3b0-261a-b1a4-5f4d33406095@csgroup.eu>
 <CAG_fn=WFffkVzqC9b6pyNuweFhFswZfa8RRio2nL9-Wq10nBbw@mail.gmail.com>
 <f806de26-daf9-9317-fdaa-a0f7a32d8fe0@csgroup.eu>
 <CANpmjNPGj4C2rr2FbSD+FC-GnWUvJrtdLyX5TYpJE_Um8CGu1Q@mail.gmail.com>
 <08a96c5d-4ae7-03b4-208f-956226dee6bb@csgroup.eu>
 <CANpmjNPYEmLtQEu5G=zJLUzOBaGoqNKwLyipDCxvytdKDKb7mg@mail.gmail.com>
 <ad61cb3a-2b4a-3754-5761-832a1dd0c34e@csgroup.eu>
 <CANpmjNOnVzei7frKcMzMHxaDXh5NvTA-Wpa29C2YC1GUxyKfhQ@mail.gmail.com>
From: Christophe Leroy <christophe.leroy@csgroup.eu>
Message-ID: <f036c53d-7e81-763c-47f4-6024c6c5f058@csgroup.eu>
Date: Thu, 4 Mar 2021 12:23:36 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.1
MIME-Version: 1.0
In-Reply-To: <CANpmjNOnVzei7frKcMzMHxaDXh5NvTA-Wpa29C2YC1GUxyKfhQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as
 permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
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



Le 03/03/2021 =C3=A0 11:56, Marco Elver a =C3=A9crit=C2=A0:
>=20
> Somewhat tangentially, I also note that e.g. show_regs(regs) (which
> was printed along the KFENCE report above) didn't include the top
> frame in the "Call Trace", so this assumption is definitely not
> isolated to KFENCE.
>=20

Now, I have tested PPC64 (with the patch I sent yesterday to modify save_st=
ack_trace_regs()=20
applied), and I get many failures. Any idea ?

[   17.653751][   T58] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[   17.654379][   T58] BUG: KFENCE: invalid free in .kfence_guarded_free+0x=
2e4/0x530
[   17.654379][   T58]
[   17.654831][   T58] Invalid free of 0xc00000003c9c0000 (in kfence-#77):
[   17.655358][   T58]  .kfence_guarded_free+0x2e4/0x530
[   17.655775][   T58]  .__slab_free+0x320/0x5a0
[   17.656039][   T58]  .test_double_free+0xe0/0x198
[   17.656308][   T58]  .kunit_try_run_case+0x80/0x110
[   17.656523][   T58]  .kunit_generic_run_threadfn_adapter+0x38/0x50
[   17.657161][   T58]  .kthread+0x18c/0x1a0
[   17.659148][   T58]  .ret_from_kernel_thread+0x58/0x70
[   17.659869][   T58]
[   17.663954][   T58] kfence-#77 [0xc00000003c9c0000-0xc00000003c9c001f, s=
ize=3D32, cache=3Dkmalloc-32]=20
allocated by task 58:
[   17.666113][   T58]  .__kfence_alloc+0x1bc/0x510
[   17.667069][   T58]  .__kmalloc+0x280/0x4f0
[   17.667452][   T58]  .test_alloc+0x19c/0x430
[   17.667732][   T58]  .test_double_free+0x88/0x198
[   17.667971][   T58]  .kunit_try_run_case+0x80/0x110
[   17.668283][   T58]  .kunit_generic_run_threadfn_adapter+0x38/0x50
[   17.668553][   T58]  .kthread+0x18c/0x1a0
[   17.669315][   T58]  .ret_from_kernel_thread+0x58/0x70
[   17.669711][   T58]
[   17.669711][   T58] freed by task 58:
[   17.670116][   T58]  .kfence_guarded_free+0x3d0/0x530
[   17.670421][   T58]  .__slab_free+0x320/0x5a0
[   17.670603][   T58]  .test_double_free+0xb4/0x198
[   17.670827][   T58]  .kunit_try_run_case+0x80/0x110
[   17.671073][   T58]  .kunit_generic_run_threadfn_adapter+0x38/0x50
[   17.671410][   T58]  .kthread+0x18c/0x1a0
[   17.671618][   T58]  .ret_from_kernel_thread+0x58/0x70
[   17.671972][   T58]
[   17.672638][   T58] CPU: 0 PID: 58 Comm: kunit_try_catch Tainted: G    B=
=20
5.12.0-rc1-01540-g0783285cc1b8-dirty #4685
[   17.673768][   T58] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[   17.677031][   T58]     # test_double_free: EXPECTATION FAILED at mm/kfe=
nce/kfence_test.c:380
[   17.677031][   T58]     Expected report_matches(&expect) to be true, but=
 is false
[   17.684397][    T1]     not ok 7 - test_double_free
[   17.686463][   T59]     # test_double_free-memcache: setup_test_cache: s=
ize=3D32, ctor=3D0x0
[   17.688403][   T59]     # test_double_free-memcache: test_alloc: size=3D=
32, gfp=3Dcc0, policy=3Dany,=20
cache=3D1
[   17.797584][   T59] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[   17.801260][   T59] BUG: KFENCE: invalid free in .kfence_guarded_free+0x=
2e4/0x530
[   17.801260][   T59]
[   17.801512][   T59] Invalid free of 0xc00000003c9effe0 (in kfence-#78):
[   17.801668][   T59]  .kfence_guarded_free+0x2e4/0x530
[   17.801849][   T59]  .__slab_free+0x320/0x5a0
[   17.801983][   T59]  .kmem_cache_free+0x31c/0x5c0
[   17.802109][   T59]  .test_double_free+0xd0/0x198
[   17.802227][   T59]  .kunit_try_run_case+0x80/0x110
[   17.802494][   T59]  .kunit_generic_run_threadfn_adapter+0x38/0x50
[   17.802641][   T59]  .kthread+0x18c/0x1a0
[   17.802821][   T59]  .ret_from_kernel_thread+0x58/0x70
[   17.802989][   T59]
[   17.803303][   T59] kfence-#78 [0xc00000003c9effe0-0xc00000003c9effff, s=
ize=3D32, cache=3Dtest]=20
allocated by task 59:
[   17.803666][   T59]  .__kfence_alloc+0x1bc/0x510
[   17.803898][   T59]  .kmem_cache_alloc+0x290/0x440
[   17.804036][   T59]  .test_alloc+0x188/0x430
[   17.804151][   T59]  .test_double_free+0x88/0x198
[   17.804363][   T59]  .kunit_try_run_case+0x80/0x110
[   17.804637][   T59]  .kunit_generic_run_threadfn_adapter+0x38/0x50
[   17.805099][   T59]  .kthread+0x18c/0x1a0
[   17.805313][   T59]  .ret_from_kernel_thread+0x58/0x70
[   17.806035][   T59]
[   17.806035][   T59] freed by task 59:
[   17.806495][   T59]  .kfence_guarded_free+0x3d0/0x530
[   17.806689][   T59]  .__slab_free+0x320/0x5a0
[   17.806941][   T59]  .kmem_cache_free+0x31c/0x5c0
[   17.807122][   T59]  .test_double_free+0xa8/0x198
[   17.807360][   T59]  .kunit_try_run_case+0x80/0x110
[   17.807538][   T59]  .kunit_generic_run_threadfn_adapter+0x38/0x50
[   17.807703][   T59]  .kthread+0x18c/0x1a0
[   17.808015][   T59]  .ret_from_kernel_thread+0x58/0x70
[   17.808220][   T59]
[   17.808406][   T59] CPU: 0 PID: 59 Comm: kunit_try_catch Tainted: G    B=
=20
5.12.0-rc1-01540-g0783285cc1b8-dirty #4685
[   17.808670][   T59] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[   17.809882][   T59]     # test_double_free-memcache: EXPECTATION FAILED =
at=20
mm/kfence/kfence_test.c:380
[   17.809882][   T59]     Expected report_matches(&expect) to be true, but=
 is false
[   17.812462][    T1]     not ok 8 - test_double_free-memcache
[   17.813872][   T60]     # test_invalid_addr_free: test_alloc: size=3D32,=
 gfp=3Dcc0, policy=3Dany, cache=3D0
[   17.920432][   T60] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[   17.920747][   T60] BUG: KFENCE: invalid free in .kfence_guarded_free+0x=
2e4/0x530
[   17.920747][   T60]
[   17.921003][   T60] Invalid free of 0xc00000003ca0ffe1 (in kfence-#79):
[   17.921137][   T60]  .kfence_guarded_free+0x2e4/0x530
[   17.921268][   T60]  .__slab_free+0x320/0x5a0
[   17.921461][   T60]  .test_invalid_addr_free+0xc0/0x1a8
[   17.921607][   T60]  .kunit_try_run_case+0x80/0x110
[   17.921739][   T60]  .kunit_generic_run_threadfn_adapter+0x38/0x50
[   17.921946][   T60]  .kthread+0x18c/0x1a0
[   17.922065][   T60]  .ret_from_kernel_thread+0x58/0x70
[   17.922215][   T60]
[   17.922327][   T60] kfence-#79 [0xc00000003ca0ffe0-0xc00000003ca0ffff, s=
ize=3D32, cache=3Dkmalloc-32]=20
allocated by task 60:
[   17.922585][   T60]  .__kfence_alloc+0x1bc/0x510
[   17.922730][   T60]  .__kmalloc+0x280/0x4f0
[   17.922903][   T60]  .test_alloc+0x19c/0x430
[   17.923032][   T60]  .test_invalid_addr_free+0x8c/0x1a8
[   17.923164][   T60]  .kunit_try_run_case+0x80/0x110
[   17.923333][   T60]  .kunit_generic_run_threadfn_adapter+0x38/0x50
[   17.923489][   T60]  .kthread+0x18c/0x1a0
[   17.923608][   T60]  .ret_from_kernel_thread+0x58/0x70
[   17.923773][   T60]
[   17.923913][   T60] CPU: 0 PID: 60 Comm: kunit_try_catch Tainted: G    B=
=20
5.12.0-rc1-01540-g0783285cc1b8-dirty #4685
[   17.924128][   T60] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[   17.925133][   T60]     # test_invalid_addr_free: EXPECTATION FAILED at =
mm/kfence/kfence_test.c:397
[   17.925133][   T60]     Expected report_matches(&expect) to be true, but=
 is false
[   17.927243][    T1]     not ok 9 - test_invalid_addr_free
[   17.931185][   T61]     # test_invalid_addr_free-memcache: setup_test_ca=
che: size=3D32, ctor=3D0x0
[   17.932183][   T61]     # test_invalid_addr_free-memcache: test_alloc: s=
ize=3D32, gfp=3Dcc0,=20
policy=3Dany, cache=3D1
[   18.149594][   T61] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[   18.149909][   T61] BUG: KFENCE: invalid free in .kfence_guarded_free+0x=
2e4/0x530
[   18.149909][   T61]
[   18.150129][   T61] Invalid free of 0xc00000003ca20001 (in kfence-#80):
[   18.150267][   T61]  .kfence_guarded_free+0x2e4/0x530
[   18.150465][   T61]  .__slab_free+0x320/0x5a0
[   18.150643][   T61]  .kmem_cache_free+0x31c/0x5c0
[   18.150873][   T61]  .test_invalid_addr_free+0xb0/0x1a8
[   18.151097][   T61]  .kunit_try_run_case+0x80/0x110
[   18.151286][   T61]  .kunit_generic_run_threadfn_adapter+0x38/0x50
[   18.151578][   T61]  .kthread+0x18c/0x1a0
[   18.151762][   T61]  .ret_from_kernel_thread+0x58/0x70
[   18.152085][   T61]
[   18.152260][   T61] kfence-#80 [0xc00000003ca20000-0xc00000003ca2001f, s=
ize=3D32, cache=3Dtest]=20
allocated by task 61:
[   18.152660][   T61]  .__kfence_alloc+0x1bc/0x510
[   18.152883][   T61]  .kmem_cache_alloc+0x290/0x440
[   18.153128][   T61]  .test_alloc+0x188/0x430
[   18.153325][   T61]  .test_invalid_addr_free+0x8c/0x1a8
[   18.153584][   T61]  .kunit_try_run_case+0x80/0x110
[   18.153796][   T61]  .kunit_generic_run_threadfn_adapter+0x38/0x50
[   18.154094][   T61]  .kthread+0x18c/0x1a0
[   18.154279][   T61]  .ret_from_kernel_thread+0x58/0x70
[   18.154555][   T61]
[   18.154762][   T61] CPU: 0 PID: 61 Comm: kunit_try_catch Tainted: G    B=
=20
5.12.0-rc1-01540-g0783285cc1b8-dirty #4685
[   18.155179][   T61] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[   18.157795][   T61]     # test_invalid_addr_free-memcache: EXPECTATION F=
AILED at=20
mm/kfence/kfence_test.c:397
[   18.157795][   T61]     Expected report_matches(&expect) to be true, but=
 is false
[   18.165055][    T1]     not ok 10 - test_invalid_addr_free-memcache
[   18.166459][   T62]     # test_corruption: test_alloc: size=3D32, gfp=3D=
cc0, policy=3Dleft, cache=3D0
[   18.514038][   T62] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[   18.514772][   T62] BUG: KFENCE: memory corruption in .kfence_guarded_fr=
ee+0x23c/0x530
[   18.514772][   T62]
[   18.515235][   T62] Corrupted memory at 0xc00000003ca60020 [ 0x2a . . . =
. . . . . . . . . . . . ]=20
(in kfence-#82):
[   18.516308][   T62]  .kfence_guarded_free+0x23c/0x530
[   18.516550][   T62]  .__slab_free+0x320/0x5a0
[   18.516814][   T62]  .test_corruption+0xcc/0x248
[   18.517053][   T62]  .kunit_try_run_case+0x80/0x110
[   18.517347][   T62]  .kunit_generic_run_threadfn_adapter+0x38/0x50
[   18.517609][   T62]  .kthread+0x18c/0x1a0
[   18.517841][   T62]  .ret_from_kernel_thread+0x58/0x70
[   18.518271][   T62]
[   18.518405][   T62] kfence-#82 [0xc00000003ca60000-0xc00000003ca6001f, s=
ize=3D32, cache=3Dkmalloc-32]=20
allocated by task 62:
[   18.518858][   T62]  .__kfence_alloc+0x1bc/0x510
[   18.519180][   T62]  .__kmalloc+0x280/0x4f0
[   18.519370][   T62]  .test_alloc+0x19c/0x430
[   18.519583][   T62]  .test_corruption+0x94/0x248
[   18.519864][   T62]  .kunit_try_run_case+0x80/0x110
[   18.520135][   T62]  .kunit_generic_run_threadfn_adapter+0x38/0x50
[   18.520368][   T62]  .kthread+0x18c/0x1a0
[   18.520569][   T62]  .ret_from_kernel_thread+0x58/0x70
[   18.520825][   T62]
[   18.520990][   T62] CPU: 0 PID: 62 Comm: kunit_try_catch Tainted: G    B=
=20
5.12.0-rc1-01540-g0783285cc1b8-dirty #4685
[   18.521803][   T62] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[   18.523184][   T62]     # test_corruption: EXPECTATION FAILED at mm/kfen=
ce/kfence_test.c:417
[   18.523184][   T62]     Expected report_matches(&expect) to be true, but=
 is false
[   18.524015][   T62]     # test_corruption: test_alloc: size=3D32, gfp=3D=
cc0, policy=3Dright, cache=3D0
[   18.741141][   T62] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[   18.741476][   T62] BUG: KFENCE: memory corruption in .kfence_guarded_fr=
ee+0x160/0x530
[   18.741476][   T62]
[   18.741746][   T62] Corrupted memory at 0xc00000003ca8ffdf [ 0x2a ] (in =
kfence-#83):
[   18.741995][   T62]  .kfence_guarded_free+0x160/0x530
[   18.742140][   T62]  .__slab_free+0x320/0x5a0
[   18.742402][   T62]  .test_corruption+0x19c/0x248
[   18.742586][   T62]  .kunit_try_run_case+0x80/0x110
[   18.742809][   T62]  .kunit_generic_run_threadfn_adapter+0x38/0x50
[   18.743027][   T62]  .kthread+0x18c/0x1a0
[   18.743488][   T62]  .ret_from_kernel_thread+0x58/0x70
[   18.743970][   T62]
[   18.744156][   T62] kfence-#83 [0xc00000003ca8ffe0-0xc00000003ca8ffff, s=
ize=3D32, cache=3Dkmalloc-32]=20
allocated by task 62:
[   18.745071][   T62]  .__kfence_alloc+0x1bc/0x510
[   18.746079][   T62]  .__kmalloc+0x280/0x4f0
[   18.746595][   T62]  .test_alloc+0x19c/0x430
[   18.746879][   T62]  .test_corruption+0x164/0x248
[   18.748178][   T62]  .kunit_try_run_case+0x80/0x110
[   18.749636][   T62]  .kunit_generic_run_threadfn_adapter+0x38/0x50
[   18.749949][   T62]  .kthread+0x18c/0x1a0
[   18.750201][   T62]  .ret_from_kernel_thread+0x58/0x70
[   18.750369][   T62]
[   18.750485][   T62] CPU: 0 PID: 62 Comm: kunit_try_catch Tainted: G    B=
=20
5.12.0-rc1-01540-g0783285cc1b8-dirty #4685
[   18.750762][   T62] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[   18.751578][   T62]     # test_corruption: EXPECTATION FAILED at mm/kfen=
ce/kfence_test.c:423
[   18.751578][   T62]     Expected report_matches(&expect) to be true, but=
 is false
[   18.753340][    T1]     not ok 11 - test_corruption
[   18.754944][   T63]     # test_corruption-memcache: setup_test_cache: si=
ze=3D32, ctor=3D0x0
[   18.756995][   T63]     # test_corruption-memcache: test_alloc: size=3D3=
2, gfp=3Dcc0, policy=3Dleft,=20
cache=3D1
[   19.109763][   T63] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[   19.110515][   T63] BUG: KFENCE: memory corruption in .kfence_guarded_fr=
ee+0x23c/0x530
[   19.110515][   T63]
[   19.110978][   T63] Corrupted memory at 0xc00000003cac0020 [ 0x2a . . . =
. . . . . . . . . . . . ]=20
(in kfence-#85):
[   19.111848][   T63]  .kfence_guarded_free+0x23c/0x530
[   19.112763][   T63]  .__slab_free+0x320/0x5a0
[   19.113121][   T63]  .kmem_cache_free+0x31c/0x5c0
[   19.113351][   T63]  .test_corruption+0xc0/0x248
[   19.113806][   T63]  .kunit_try_run_case+0x80/0x110
[   19.114019][   T63]  .kunit_generic_run_threadfn_adapter+0x38/0x50
[   19.114173][   T63]  .kthread+0x18c/0x1a0
[   19.114292][   T63]  .ret_from_kernel_thread+0x58/0x70
[   19.114535][   T63]
[   19.114681][   T63] kfence-#85 [0xc00000003cac0000-0xc00000003cac001f, s=
ize=3D32, cache=3Dtest]=20
allocated by task 63:
[   19.115287][   T63]  .__kfence_alloc+0x1bc/0x510
[   19.115597][   T63]  .kmem_cache_alloc+0x290/0x440
[   19.115875][   T63]  .test_alloc+0x188/0x430
[   19.116456][   T63]  .test_corruption+0x94/0x248
[   19.116689][   T63]  .kunit_try_run_case+0x80/0x110
[   19.117021][   T63]  .kunit_generic_run_threadfn_adapter+0x38/0x50
[   19.117383][   T63]  .kthread+0x18c/0x1a0
[   19.117572][   T63]  .ret_from_kernel_thread+0x58/0x70
[   19.117713][   T63]
[   19.117816][   T63] CPU: 0 PID: 63 Comm: kunit_try_catch Tainted: G    B=
=20
5.12.0-rc1-01540-g0783285cc1b8-dirty #4685
[   19.118706][   T63] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[   19.119719][   T63]     # test_corruption-memcache: EXPECTATION FAILED a=
t mm/kfence/kfence_test.c:417
[   19.119719][   T63]     Expected report_matches(&expect) to be true, but=
 is false
[   19.120669][   T63]     # test_corruption-memcache: test_alloc: size=3D3=
2, gfp=3Dcc0, policy=3Dright,=20
cache=3D1
[   19.339842][   T63] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[   19.340238][   T63] BUG: KFENCE: memory corruption in .kfence_guarded_fr=
ee+0x160/0x530
[   19.340238][   T63]
[   19.340487][   T63] Corrupted memory at 0xc00000003caeffdf [ 0x2a ] (in =
kfence-#86):
[   19.340748][   T63]  .kfence_guarded_free+0x160/0x530
[   19.340885][   T63]  .__slab_free+0x320/0x5a0
[   19.341095][   T63]  .kmem_cache_free+0x31c/0x5c0
[   19.341285][   T63]  .test_corruption+0x190/0x248
[   19.341480][   T63]  .kunit_try_run_case+0x80/0x110
[   19.341921][   T63]  .kunit_generic_run_threadfn_adapter+0x38/0x50
[   19.342298][   T63]  .kthread+0x18c/0x1a0
[   19.342816][   T63]  .ret_from_kernel_thread+0x58/0x70
[   19.343799][   T63]
[   19.345941][   T63] kfence-#86 [0xc00000003caeffe0-0xc00000003caeffff, s=
ize=3D32, cache=3Dtest]=20
allocated by task 63:
[   19.347301][   T63]  .__kfence_alloc+0x1bc/0x510
[   19.347620][   T63]  .kmem_cache_alloc+0x290/0x440
[   19.347820][   T63]  .test_alloc+0x188/0x430
[   19.348202][   T63]  .test_corruption+0x164/0x248
[   19.348400][   T63]  .kunit_try_run_case+0x80/0x110
[   19.348609][   T63]  .kunit_generic_run_threadfn_adapter+0x38/0x50
[   19.348810][   T63]  .kthread+0x18c/0x1a0
[   19.349131][   T63]  .ret_from_kernel_thread+0x58/0x70
[   19.349429][   T63]
[   19.349612][   T63] CPU: 0 PID: 63 Comm: kunit_try_catch Tainted: G    B=
=20
5.12.0-rc1-01540-g0783285cc1b8-dirty #4685
[   19.349985][   T63] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[   19.351145][   T63]     # test_corruption-memcache: EXPECTATION FAILED a=
t mm/kfence/kfence_test.c:423
[   19.351145][   T63]     Expected report_matches(&expect) to be true, but=
 is false
[   19.353730][    T1]     not ok 12 - test_corruption-memcache
[   26.350432][   T69] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[   26.350757][   T69] BUG: KFENCE: memory corruption in .kfence_guarded_fr=
ee+0x23c/0x530
[   26.350757][   T69]
[   26.350961][   T69] Corrupted memory at 0xc00000003cfcfff9 [ 0xac . . . =
. . . ] (in kfence-#125):
[   26.351333][   T69]  .kfence_guarded_free+0x23c/0x530
[   26.351517][   T69]  .__slab_free+0x320/0x5a0
[   26.351645][   T69]  .test_kmalloc_aligned_oob_write+0x12c/0x1e4
[   26.351774][   T69]  .kunit_try_run_case+0x80/0x110
[   26.351902][   T69]  .kunit_generic_run_threadfn_adapter+0x38/0x50
[   26.352066][   T69]  .kthread+0x18c/0x1a0
[   26.352180][   T69]  .ret_from_kernel_thread+0x58/0x70
[   26.352294][   T69]
[   26.352367][   T69] kfence-#125 [0xc00000003cfcffb0-0xc00000003cfcfff8, =
size=3D73,=20
cache=3Dkmalloc-96] allocated by task 69:
[   26.352668][   T69]  .__kfence_alloc+0x1bc/0x510
[   26.352804][   T69]  .__kmalloc+0x280/0x4f0
[   26.352913][   T69]  .test_alloc+0x19c/0x430
[   26.353092][   T69]  .test_kmalloc_aligned_oob_write+0x80/0x1e4
[   26.353290][   T69]  .kunit_try_run_case+0x80/0x110
[   26.353505][   T69]  .kunit_generic_run_threadfn_adapter+0x38/0x50
[   26.353724][   T69]  .kthread+0x18c/0x1a0
[   26.353896][   T69]  .ret_from_kernel_thread+0x58/0x70
[   26.354153][   T69]
[   26.354309][   T69] CPU: 0 PID: 69 Comm: kunit_try_catch Tainted: G    B=
=20
5.12.0-rc1-01540-g0783285cc1b8-dirty #4685
[   26.354714][   T69] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[   26.355421][   T69]     # test_kmalloc_aligned_oob_write: EXPECTATION FA=
ILED at=20
mm/kfence/kfence_test.c:489
[   26.355421][   T69]     Expected report_matches(&expect) to be true, but=
 is false
[   26.357224][    T1]     not ok 18 - test_kmalloc_aligned_oob_write



Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/f036c53d-7e81-763c-47f4-6024c6c5f058%40csgroup.eu.
