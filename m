Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBEWSX32AKGQEZORLGSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 7333C1A3CA5
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Apr 2020 01:00:36 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id 78sf128274pfy.22
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Apr 2020 16:00:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586473235; cv=pass;
        d=google.com; s=arc-20160816;
        b=sp4lyukpfKmmxJB0BMh3W4rjNGIZTmLqQYC8TQbb4YQJccNfEgoHLoLQqrAdGcfQSD
         2zoTHWpRqivSAuqJWvcpbF2cNy31wA718Sww5dmV7iSxZQnsUQaZcJVPjxoAkePR/NKo
         PnNwB2+FvzEMHlE8//nssr2ksoTP0OLG7WxOYK87EAcRCNDtKu1mLjMLJw1YLRW2yL/5
         4NY26PewOdu5h8EuoQ0cwUXzAiYuNhOKWAmBpaooW0RcuH4XlRJTxsndKivUBBDFyTys
         L+fER6Kr5f0Bii7bjlDZHenHh0DHGXiXyrdLYGqTHMAoO4dS7Sm4GwLZgzIhTDG2KukG
         G1Cw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:references:message-id
         :content-transfer-encoding:cc:date:in-reply-to:from:subject
         :mime-version:sender:dkim-signature;
        bh=bxumW5YtVfMQQj3/4I5UpH6DU3RQ6DmEj3vKiwwQTns=;
        b=pm0Wi+l/PK3WwSTYq9YWDMLI2YMFByCfapjeRC06FK1TjzfL7f3++yYA4gzgoHkzOQ
         tWAI36o/AmrouMB39cNv3JTDkVGn1s3YQwsrQOeSvLWySDRHBWZVXjL6wsU2WYOin6WW
         9aKg+EKaultR6BFfmDgcfc94+y77l+JUcI3Xc7ouanQDqKF3p9xHH606TK4Ks9DAKCmr
         z3anAPir8Zsjz8oCm5olRYIJwD1b17OKod5Si9gLP6bMzZZBCAR1LOftznSH5pBtEzDh
         vLeXXCx87YGUM00Snlwo7SHJC491qTZhTdzv81dyZtg6LRyfHwqGo8j1xaN6YcjVsVI+
         9zlA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=E55hQkfn;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:subject:from:in-reply-to:date:cc
         :content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bxumW5YtVfMQQj3/4I5UpH6DU3RQ6DmEj3vKiwwQTns=;
        b=rfFyj0Kk6P6mC7RjqxJjydaejclaTwhHSl9ehzA5kTBNJajvoSv4ZxIGkPgQDlanUj
         Pfif2CwVYQbDzdTzr85lJ+bSSFmpyHmf0BbYZetXUcI/u//797G/1IwzagA9Xxt/7zK9
         kFRAV0+tLRvpwR6hCzKmeyK1IfKKEdxsgtSukmOIEQDJUqDDIGcyMGEFR54IuTzfhcx5
         iRcZIWL4EyvZGz7qzWVisBxeGigX4FRpkQU/C+24gh0KJA2xKl5MXmeQWDRyeZ+LEj3M
         cSwXFgogv6Jhecd/pvittr2+5nZdCtK92BZPRfEOX01OSuicPNY4XYMMKdr4y9f6hk3Q
         Nwjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:subject:from:in-reply-to
         :date:cc:content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=bxumW5YtVfMQQj3/4I5UpH6DU3RQ6DmEj3vKiwwQTns=;
        b=djm4b60/0w8l+WBA6qbDKcIFeg3g4HmFEsL91GRiQ7MJw/48tWTQqAWEPp05ts2jkL
         ugCLbHCX9ygib3vN65W+e8GKIbsKfbURnngtylzOFjZlNhG2fjuQDwYP2HxI3Ur/8aa1
         nqM1du8jsNSuBH3xYBzvPfwVEBxl2PURkDGpkf1G/kQewSMXFcywhtZbfd/CRLqH8ir6
         3Q9rgGwUyOHb1kPFo2aHu66DY+DyTNHMqKtMDUbRD32H56ZkQ6b1WGa1CtDQ/N4Q6rhQ
         GhQ9uLprkazNndv3I88Iipu6br4ahrX19tE8Ddyf50dBo5ZsxgS+jYf75/3GKvD+cLXJ
         lm8g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYhV4TOTb75R/5K//IlSMrIbuNazzoEg1QNAsgHeaRApwpbwelD
	dvYORKSxT21mgWD4eTJSaRw=
X-Google-Smtp-Source: APiQypJjv5Q+Szw2sWRj81cNQCpbLBAGNU+wvhQxHnFMsl8T2/aMW9Jly64vXY5qzHV0QcKWGMRPRQ==
X-Received: by 2002:a17:902:a58b:: with SMTP id az11mr1867945plb.137.1586473234979;
        Thu, 09 Apr 2020 16:00:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:bb93:: with SMTP id m19ls8037734pls.6.gmail; Thu, 09
 Apr 2020 16:00:34 -0700 (PDT)
X-Received: by 2002:a17:902:d217:: with SMTP id t23mr1859860ply.290.1586473234386;
        Thu, 09 Apr 2020 16:00:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586473234; cv=none;
        d=google.com; s=arc-20160816;
        b=Zxr9WP3nARMB3xwV57qq425cgFcsS0GVgGZF2wth6kLIF4GNTdP9+LKc2UZsCt94dg
         dly/ySL/7kDVV02ZHuqhgPjvdV8oe27rj1D46j24MNO8uWIweAoOEsmRRruDVPuTBrJe
         FQkI0RqbsMM1x+Nrgm8UawIwsc6nBGsNqlz+6mGzNn4P6xxJ9nKs4IknCXSuxsBDp9sX
         iSxSCubZpho7SaYzRr8szpLUvB7mcIPnzyOYzXNgcNLT/oqhfU/ZySD+wt7PR7ONx4ov
         T7LtSLLS2V1g0IXJfAQqQrdDaz9RTZzYibfhP+aXDWwf0Ph+G2t1XuiwAzymHvWtRnqk
         SDqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:references:message-id:content-transfer-encoding:cc:date
         :in-reply-to:from:subject:mime-version:dkim-signature;
        bh=9za1cgL5saDGUL4ncdk/vOmVKH89NTfUqWctXJV+wKg=;
        b=hVFSMgF2t6Jpf+FB+qkJZD3jwms48ztyzjeBeJx3FLt8AGCsNi24D9LBSWZL1v0OnL
         wyJvSDZGZDxUFMfI3ArsRccoTBDQVfvZfjSo/oTc45SrJiXLSy7oq8tqckua51H7BOCV
         LblosBv1ePC+g37aizWmdPiNF8j59812LL//UWjUoVM5lLwh3gjjN2WjjD4E5Mn7Vkis
         FPxMLFGInT/uaeXOWYGLiEjTDvv6qqRF+wlaTWYasnKbwV3+E1tfAl4QvxbBWPcWh0Ve
         itqSSaU28GadV5TqabLfoo5iUcshKISA5woLM82FPsUkArwl3HUyWbpE8NsyOVCJj8DG
         fcXA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=E55hQkfn;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qt1-x842.google.com (mail-qt1-x842.google.com. [2607:f8b0:4864:20::842])
        by gmr-mx.google.com with ESMTPS id 138si24327pfa.6.2020.04.09.16.00.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Apr 2020 16:00:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::842 as permitted sender) client-ip=2607:f8b0:4864:20::842;
Received: by mail-qt1-x842.google.com with SMTP id 14so257095qtp.1
        for <kasan-dev@googlegroups.com>; Thu, 09 Apr 2020 16:00:34 -0700 (PDT)
X-Received: by 2002:ac8:7286:: with SMTP id v6mr1775597qto.299.1586473233327;
        Thu, 09 Apr 2020 16:00:33 -0700 (PDT)
Received: from [192.168.1.153] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id 69sm226385qki.131.2020.04.09.16.00.32
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Apr 2020 16:00:32 -0700 (PDT)
Content-Type: text/plain; charset="UTF-8"
Mime-Version: 1.0 (Mac OS X Mail 13.4 \(3608.80.23.2.2\))
Subject: Re: KCSAN + KVM = host reset
From: Qian Cai <cai@lca.pw>
In-Reply-To: <B5F0F530-911E-4B75-886A-9D8C54FF49C8@lca.pw>
Date: Thu, 9 Apr 2020 19:00:31 -0400
Cc: Paolo Bonzini <pbonzini@redhat.com>,
 "paul E. McKenney" <paulmck@kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>,
 LKML <linux-kernel@vger.kernel.org>,
 kvm@vger.kernel.org
Content-Transfer-Encoding: quoted-printable
Message-Id: <DF45D739-59F3-407C-BE8C-2B1E164B493B@lca.pw>
References: <E180B225-BF1E-4153-B399-1DBF8C577A82@lca.pw>
 <fb39d3d2-063e-b828-af1c-01f91d9be31c@redhat.com>
 <017E692B-4791-46AD-B9ED-25B887ECB56B@lca.pw>
 <CANpmjNMiHNVh3BVxZUqNo4jW3DPjoQPrn-KEmAJRtSYORuryEA@mail.gmail.com>
 <B7F7F73E-EE27-48F4-A5D0-EBB29292913E@lca.pw>
 <CANpmjNMEgc=+bLU472jy37hYPYo5_c+Kbyti8-mubPsEGBrm3A@mail.gmail.com>
 <2730C0CC-B8B5-4A65-A4ED-9DFAAE158AA6@lca.pw>
 <CANpmjNNUn9_Q30CSeqbU_TNvaYrMqwXkKCA23xO4ZLr2zO0w9Q@mail.gmail.com>
 <B5F0F530-911E-4B75-886A-9D8C54FF49C8@lca.pw>
To: Marco Elver <elver@google.com>
X-Mailer: Apple Mail (2.3608.80.23.2.2)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=E55hQkfn;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::842 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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



> On Apr 9, 2020, at 5:28 PM, Qian Cai <cai@lca.pw> wrote:
>=20
>=20
>=20
>> On Apr 9, 2020, at 12:03 PM, Marco Elver <elver@google.com> wrote:
>>=20
>> On Thu, 9 Apr 2020 at 17:30, Qian Cai <cai@lca.pw> wrote:
>>>=20
>>>=20
>>>=20
>>>> On Apr 9, 2020, at 11:22 AM, Marco Elver <elver@google.com> wrote:
>>>>=20
>>>> On Thu, 9 Apr 2020 at 17:10, Qian Cai <cai@lca.pw> wrote:
>>>>>=20
>>>>>=20
>>>>>=20
>>>>>> On Apr 9, 2020, at 3:03 AM, Marco Elver <elver@google.com> wrote:
>>>>>>=20
>>>>>> On Wed, 8 Apr 2020 at 23:29, Qian Cai <cai@lca.pw> wrote:
>>>>>>>=20
>>>>>>>=20
>>>>>>>=20
>>>>>>>> On Apr 8, 2020, at 5:25 PM, Paolo Bonzini <pbonzini@redhat.com> wr=
ote:
>>>>>>>>=20
>>>>>>>> On 08/04/20 22:59, Qian Cai wrote:
>>>>>>>>> Running a simple thing on this AMD host would trigger a reset rig=
ht away.
>>>>>>>>> Unselect KCSAN kconfig makes everything work fine (the host would=
 also
>>>>>>>>> reset If only "echo off > /sys/kernel/debug/kcsan=E2=80=9D before=
 running qemu-kvm).
>>>>>>>>=20
>>>>>>>> Is this a regression or something you've just started to play with=
?  (If
>>>>>>>> anything, the assembly language conversion of the AMD world switch=
 that
>>>>>>>> is in linux-next could have reduced the likelihood of such a failu=
re,
>>>>>>>> not increased it).
>>>>>>>=20
>>>>>>> I don=E2=80=99t remember I had tried this combination before, so do=
n=E2=80=99t know if it is a
>>>>>>> regression or not.
>>>>>>=20
>>>>>> What happens with KASAN? My guess is that, since it also happens wit=
h
>>>>>> "off", something that should not be instrumented is being
>>>>>> instrumented.
>>>>>=20
>>>>> No, KASAN + KVM works fine.
>>>>>=20
>>>>>>=20
>>>>>> What happens if you put a 'KCSAN_SANITIZE :=3D n' into
>>>>>> arch/x86/kvm/Makefile? Since it's hard for me to reproduce on this
>>>>>=20
>>>>> Yes, that works, but this below alone does not work,
>>>>>=20
>>>>> KCSAN_SANITIZE_kvm-amd.o :=3D n
>>>>=20
>>>> There are some other files as well, that you could try until you hit
>>>> the right one.
>>>>=20
>>>> But since this is in arch, 'KCSAN_SANITIZE :=3D n' wouldn't be too bad
>>>> for now. If you can't narrow it down further, do you want to send a
>>>> patch?
>>>=20
>>> No, that would be pretty bad because it will disable KCSAN for Intel
>>> KVM as well which is working perfectly fine right now. It is only AMD
>>> is broken.
>>=20
>> Interesting. Unfortunately I don't have access to an AMD machine right n=
ow.
>>=20
>> Actually I think it should be:
>>=20
>> KCSAN_SANITIZE_svm.o :=3D n
>> KCSAN_SANITIZE_pmu_amd.o :=3D n
>>=20
>> If you want to disable KCSAN for kvm-amd.
>=20
> KCSAN_SANITIZE_svm.o :=3D n
>=20
> That alone works fine. I am wondering which functions there could trigger
> perhaps some kind of recursing with KCSAN?

Another data point is set CONFIG_KCSAN_INTERRUPT_WATCHER=3Dn alone
also fixed the issue. I saw quite a few interrupt related function in svm.c=
, so
some interrupt-related recursion going on?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/DF45D739-59F3-407C-BE8C-2B1E164B493B%40lca.pw.
