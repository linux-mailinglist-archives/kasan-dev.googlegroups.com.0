Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVXG536QKGQEC22HAIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 9921B2C0806
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 14:04:23 +0100 (CET)
Received: by mail-yb1-xb40.google.com with SMTP id a13sf22844068ybj.3
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 05:04:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606136662; cv=pass;
        d=google.com; s=arc-20160816;
        b=X9jaTvhpr3OEQjGL5qhqEHhAEwlOu+Hw5/TdX6xsHl5PIp9a8veOCG7G4zq/1jMFqJ
         dBCWXFYrTaHH4BBemzdFLV8UG2Xys+EhBnTqMYbU2A7E/ExL8UNmBWz+pVZiarm6/bxe
         zoyYrfDVl3i3ILMxfA4L1br9/t59NonG4T8aDziCK4oh0oDU3MbhuZ3HlX0EYknbZqI8
         8c9OEo1OovNlIsNJ1CS4aFBsqAe4rP0KXd/q3ulU7XyuRZTyG6Esm20NwnOlZkSYzTuS
         yB6223ZlImjfC39Wn2k+R4hlxwsNC5Ix7eJ4BxftKv6qMQXawHmBeRQzspslgWASQe1b
         kA/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pE7GN3WhDcPkCkv/741dVTmVzZn1T2IfjaP8pa6yano=;
        b=s+9QaDKsyhuOArKrp550+lh142PQbHD8M5vDQrTZkJLoCfu0MMaUtDoLG+QTIfoA1c
         oEQ6VTrIirXspK6oKay+hqM3BWMp7xhw8RFliDyElfYvtcFOxmQGDHMwRgmK9h0mDCr8
         ZzjMeyKBEau9WZowtyONdoxXorseW8MAuVH6vthc+ARntOb+NOnkjURBnkZkXvtWbUeU
         QI4gsBNd8zukh+tjFuF/5vaWDEJsHkIFlIRkH8VGBHoYdAkJkfzQfTyekS8FOkdEVjlT
         v7hOznMwT7pgHolkiFfHRcfcWC9Bz75NNMmMfWf6nFja9PVfipt7i7XB34gpTUnhReHc
         nE+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ajuB1xWN;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=pE7GN3WhDcPkCkv/741dVTmVzZn1T2IfjaP8pa6yano=;
        b=F+YL8QoxNiIVH8Ko+wEibiS74pRep6suGPe7wxOGX39eXzjLPWFF03wbG3WTFzeO+c
         PRGs1HMMW2Ht9aVBfzW7mQuqPzCzWu32SohUT7jecHPF+IpgNf1+AvXLnCu8fUqnt+vV
         vDNTI7U8g6CIuyXNKKpcxbw7uMEpsgrwHyVmc2zQQLoId1ZhQPIOTlJ6YRtJZeilJ9em
         EWC56lUK5ZgmFjHIj3qB9EcaNMxCsVntgK+AYCoQvMqLHTwMwJdORaTsvm/TTvtOhOTo
         7R3Hss8iMPLcwRSseqTYrSga0RktsX/ivGmNE3KDOruqGQVqoBLBakDXqj2AJRPQJAVL
         PIWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pE7GN3WhDcPkCkv/741dVTmVzZn1T2IfjaP8pa6yano=;
        b=Kdr16UQjsr5YSUhuMZBMWsFtG6uQ8F5SWAItTnB0CeihjIcpSowSF5MXaZQwNQx5Rz
         RuzQzF0Gi6krcAGbhMpfiJQkJnMAaTw3iYtKYX5tHNYge7Z2T8ikHHMipG6hBsVXjnOv
         sMvo1Nt4eGDmI0QeJ3NNyb8phbhpJnUAMywxxnmL4F22BxvSLRXC/ZU6BFZgTnh4CKve
         CJLkDCVLtOcsZ1tQEXwaaNX+XUx2caXWi6E9QGxeA4EuqEw1e9S8vjoFaZjfse2KN5YC
         700WhHXUTTTMgVxSKVN1kfVBBiTwuq3j1dOrZoRiEkB510ub9AJKBPUmD7QSX9shQ6w2
         t8qw==
X-Gm-Message-State: AOAM533eFL9uFWv288iQB8GyKbWehORProSZgKDGHQpHUG/tXieeGuAl
	H4pISnMr8p+xRxaG93Vh/wA=
X-Google-Smtp-Source: ABdhPJwezNIq7P8vccrtFpGdCP/vrfvU+FZTvMEu3P940kqMG5LxWIVqXY+ouvscU6dLAGd285Vy3Q==
X-Received: by 2002:a25:748a:: with SMTP id p132mr36573545ybc.430.1606136662412;
        Mon, 23 Nov 2020 05:04:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:5f42:: with SMTP id h2ls6956994ybm.11.gmail; Mon, 23 Nov
 2020 05:04:21 -0800 (PST)
X-Received: by 2002:a25:cc51:: with SMTP id l78mr45206341ybf.496.1606136661844;
        Mon, 23 Nov 2020 05:04:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606136661; cv=none;
        d=google.com; s=arc-20160816;
        b=SNOOI+nj+d9IbKHzlBk/czJhoabTQhezvMdE4slprwn2BSQoJnFNYnupfMIeT8UNHJ
         T5ZA3r3R2P1B0OOGWkvDeovbXVJF4ZJyLhWbZm6Uhc18fhamIbpoujnZOodKhQCuxj/x
         j12TqEZiEH4RXF5+l6WmN7Ud+eausNzV9pFa5B7L//q+TWOUWFNm8faAOodoJIfIY2mF
         Vm+hSE/Xi+7VQX0oJP3IZMpSWx60PVC1kDBoZl5iyo2EC0l92jfBfIb3QfCI9vB01HxG
         flOqnryDLgtgDHJAF3lEP1L3hLj1mBgH7LBocsPTY9O1Ot4Rb/S/Jr/VvR65sWmtjKOB
         P/ng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=0nlgszyfF+EKplTPoMhsVS8TBi6zOUScjVPLNs+3MvU=;
        b=oMYvJPGGK1qSfhlbx5dgbQzyHU243pDj5yH3bp8ygoZz5ntOT5YbJrtZrwI57bne6/
         IEqd10TcNQ0RBp52S+yUSj3LOEL0PAFLgf7se5xxjJcahPVOWYgOubQ3DpfU19eulBhu
         GAWEejg95PGefDYEk5AuikiN5IT4FCVZkXwhksN5eHKTIRmPid42vANSk9C7mW6FhSzw
         AG2XJeTuzAH7lIW446/Dmj7eRUGBnVkQKwx2N6wmFp+NjrWSmsfM7MKkKaN4t+hW4AuU
         M72JUStgjh0ypPTHHudLk9X7TFNQINDs2FZXUNUXGeKpfqnfQ0xxO4hXiMMyz6Y/V5Fh
         b4EA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ajuB1xWN;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x341.google.com (mail-ot1-x341.google.com. [2607:f8b0:4864:20::341])
        by gmr-mx.google.com with ESMTPS id n185si675939yba.3.2020.11.23.05.04.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 05:04:21 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) client-ip=2607:f8b0:4864:20::341;
Received: by mail-ot1-x341.google.com with SMTP id l36so15809242ota.4
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 05:04:21 -0800 (PST)
X-Received: by 2002:a9d:f44:: with SMTP id 62mr24138426ott.17.1606136661191;
 Mon, 23 Nov 2020 05:04:21 -0800 (PST)
MIME-Version: 1.0
References: <f4a62280-43f5-468b-94c4-fdda826d28d0n@googlegroups.com>
 <CANpmjNPsjXqDQLkeBb2Ap7j8rbrDwRHeuGPyzXXQ++Qxe4A=7A@mail.gmail.com>
 <8b89f21f-e3e9-4344-92d3-580d2f0f2860n@googlegroups.com> <CANpmjNPm3U=aeuhv4CpqsxbkQj8SnKbauLmXyAu2b=8bCEg6pQ@mail.gmail.com>
 <83c70bdd-4f74-421a-85bc-fd518f303ce1n@googlegroups.com>
In-Reply-To: <83c70bdd-4f74-421a-85bc-fd518f303ce1n@googlegroups.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 23 Nov 2020 14:04:09 +0100
Message-ID: <CANpmjNOWVO1XnPvB9M1HS1Pm_DKOU-yVxANHE0r7JSOX5Xbw7A@mail.gmail.com>
Subject: Re: Any guidance to port KCSAN to previous Linux Kernel versions?
To: "mudongl...@gmail.com" <mudongliangabcd@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ajuB1xWN;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as
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

[Resend with reply-all]

On Mon, 23 Nov 2020 at 13:44, mudongl...@gmail.com
<mudongliangabcd@gmail.com> wrote:
[...]
>> > Let's imagine a scenario: KASAN detects a UAF crash in an old Linux ke=
rnel(e.g., 5.4, 4.19), but the underlying reason for this crash behavior is=
 data racing from two different threads with plain accesses(without READ_ON=
CE/WRITE_ONCE).
>> > What I want is to backport KCSAN and test whether it could catch the u=
nderlying data race before triggering the further UAF crash. This would hel=
p us identify the underlying issue(two concurrent threads and the object fo=
r data race) and fix the bug completely.
>>
>> For debugging such issues, I'd run with a more aggressive KCSAN config
>> (regardless of kernel version):
>>
>> CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY=3Dn
>> CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC=3Dn
>>
>> and lower 'kcsan.skip_watch=3D' boot parameter from default of 4000 down
>> to ~500 in decrements of 500 and stop when the system becomes too
>> slow.
>>
>
> That's a good idea. I will try this config when testing my problem.
>
>>
>> > Therefore, if I try to backport KCSAN and test whether KCSAN catches t=
his special data race, is it still too complicated or need non-trivial effo=
rts?
>>
>> See if 'git cherry-pick v5.7-rc7..50a19ad4b1ec' works.
>
>
> Quick question about the above command: cherry-pick requires the first co=
mmit(v5.7-rc7) is older than the second commit(50a19ad4b1ec). However,

This is incorrect. See "git help log" or [1] -- age is irrelevant.
Git's range operators are effectively set operations, and ordering is
irrelevant.
[1] https://git-scm.com/book/en/v2/Git-Tools-Revision-Selection

> commit 9cb1fd0efd195590b828b9b865421ad345a4a145 (tag: v5.7-rc7)
> Author: Linus Torvalds <torvalds@linux-foundation.org>
> Date:   Sun May 24 15:32:54 2020 -0700
>
>     Linux 5.7-rc7
>
> commit 50a19ad4b1ec531eb550183cb5d4ab9f25a56bf8
> Author: Marco Elver <elver@google.com>
> Date:   Fri Apr 24 17:47:30 2020 +0200
>
>     objtool, kcsan: Add kcsan_disable_current() and kcsan_enable_current_=
nowarn()
>
>     Both are safe to be called from uaccess contexts.
>
>     Signed-off-by: Marco Elver <elver@google.com>
>     Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
>
> However, in fact it does not hold.
>
> After a search, I found the first commit to add the infrastructure is dfd=
402a4c4baae42398ce9180ff424d589b8bffc kcsan: Add Kernel Concurrency Sanitiz=
er infrastructure, right after 5.4-rc7.
> Do you mean "git cherry-pick v5.4-rc7..50a19ad4b1ec"

No.

See "git help log". Specifically "a..b" means "list all the commits
which are reachable from b, but not from a". Because we only want
KCSAN related commits, the above is correct. Try it! You can also
check what commits you'll get by sanity-checking with 'git log'.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNOWVO1XnPvB9M1HS1Pm_DKOU-yVxANHE0r7JSOX5Xbw7A%40mail.gmail.=
com.
