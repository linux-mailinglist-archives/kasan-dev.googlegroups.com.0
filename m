Return-Path: <kasan-dev+bncBDKYJ4OFZQIRBAH4ZSAAMGQEDARWOZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E627308132
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Jan 2021 23:43:13 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id b14sf3922450wrw.12
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Jan 2021 14:43:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611873792; cv=pass;
        d=google.com; s=arc-20160816;
        b=UGwR4ObMcP0NfbSjE7+wLxzcwZIsBs8gunO5fdjQsUZFA1vlqdPW/HfU9Cxaw7fmm0
         jZMa8MCcfHfm0aqKSDF3qQadE+yCF1PfuDX4gJL19Gsd0iKoHZO65C840+AkwvUHAboh
         iUG+pt9VJz00J+HmkQTMQCQYuie4U71Jm7w9W+oxy8vPkL2TPfmL/HrZ9Kb2d6azJuxv
         nBRBUEPs1eH4UnBDxFNoN0Yc61pGpU61qLBCmvDdJTK6sTkhM9i1/ljsg3I2MVj3IWQz
         6Eqn9WVrRsZU+bAclgYcAt+gHzVb/OM2N5PEp45VYV/v30QTS56CNJmDxRrpgQd4FXpc
         p1Gw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=xgXHOFf28oGfF7W9NuMs567lvFnMtCJ3YvhcMSRo088=;
        b=yzQZUYw0/HgU0D5xSbXF4ZyPTEYC63dhrHC0jQJPnWN4ccHfhYAb8Jy7yN00awDHY7
         0lrZAioEQK/PrXLYMDHUHVW+gV38H+r0Z0Fw+hpfwli21ZEX5goYq9Z/fKo+a69ndSUW
         EezVJvOfvwsPhW0jr6J9U6nQ86aFL/8ULRS7PSifA8CRepmGD1mz/OsK4SCvAbpaPBD6
         vCOlMADfsLdV2wfEphCtvh95m6Ega2sUGe4gnYgzPWvYQPnB/TFlTEi/lJDmA2LTpinA
         qV2M9EGfE551LZA4lbd5HL8RbiUkjyV7BGWxvvj+OAALFX7HFhsWmvE2U5ZtP1Y92YfI
         +uUw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=PUaq5PwN;
       spf=pass (google.com: domain of andy.jinhuang@gmail.com designates 2a00:1450:4864:20::62d as permitted sender) smtp.mailfrom=andy.jinhuang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xgXHOFf28oGfF7W9NuMs567lvFnMtCJ3YvhcMSRo088=;
        b=fDQmz8L0oPB+/B7CSA6E0/mSzOUpRNtEBS2a4zYGNNQZcGrTRSReugz2xNo92+Fz3G
         j169ZIYGrelNFA1XxQWMKSmraXum3tBtr9TXQL9/xs45gPYJYuXD5XXyXW51nfOUbwX6
         ZS1yhp3S2bNZVEwGuy7bY0frMc4ex27p+jTMH/EOHDEiGI3mytjhgGXmNFaigHTO14kV
         qfNYinhKDCvPGSF28J7Pkkpf0boiC079tVAgazDIaYdre1P3+UshOf7WojRzKJsBKpzX
         iz1MJy9ZcKWtQmalhGhnWALWYeZSUgM76WD/gzo/oFV+EVybBtjF6cf2rePm/leqLHXD
         NeFg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xgXHOFf28oGfF7W9NuMs567lvFnMtCJ3YvhcMSRo088=;
        b=UxLwWVthLNL/qmiReMphFnTuTWA6Uo3iiDH4jbGMX34Asn/jYo1ln6D9WYwFKQDjPe
         B9OXHYCZGZdmW8o/2gW+/XJwumiZjmKqk6i2QPaU+JaGDUbaGgq22I1rVrk7QT81prk/
         4fnWeq4eYV97/3KDiDX0QJkXmdrl7LuC5iGr5HYwFYhzvVehokKkklJCp4OQyAiu/6uq
         lZzB3OtI4EtD28Bj1ZFGyn+mJ3YV19ukpFvWAejjY+2EkT9t1zVEPybTU/8eHxIKuFRj
         yBQCAc1L8EKCwTBOJqnoousO5OWnHUkB1CMvFosvxLGI1iRoXp+EngsP2wG3gyqia9Bs
         +fNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xgXHOFf28oGfF7W9NuMs567lvFnMtCJ3YvhcMSRo088=;
        b=ANt1HkTn/+B0UwGBhzqLVw0PvT40OWCAqLhfJ+HEw2ecD8fvOoAzYa40ROisL+rhLv
         zR7i6hVYBN4L9oWxfm7TBBX6LV0lfEmSFLApHp6KoG9Y1fh2PV4LqnJzLHjNHLTcuwzH
         rp0vx03ByLbUBRgetvMb46gl6cRzZkU3i+RSlCDVUAHo9/j6N+TIncsnYnH2CHUpcUms
         /ZEB39Ri5p8LHWE5s5PJDtvOupTSi3euw0FXlqrIDa9fgFV70OECSrcsuzXkzBSe/hjc
         aQXatwPx0r3Zqq3vnZw686blitJqCJg+zF6ksA9Ahgk1LEa5+t00FGXlgG7SndGIT8re
         L+1g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533FNpUbAhNgp58SoEE+bdh5ZDXOgd5ah0puNGK/Sp5l8rKhR/B4
	HhFpM19bp9tC2U/6Z9RgPqY=
X-Google-Smtp-Source: ABdhPJxEJY9ZD/4nQE25Gvk2c/yCrzkZLFRC+JmDJZO/EGDkq3Jcm2lrV6VyKQcUwajq8t8zVh1gbQ==
X-Received: by 2002:a5d:6912:: with SMTP id t18mr1349148wru.268.1611873792871;
        Thu, 28 Jan 2021 14:43:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f852:: with SMTP id d18ls4929994wrq.2.gmail; Thu, 28 Jan
 2021 14:43:12 -0800 (PST)
X-Received: by 2002:adf:bbc1:: with SMTP id z1mr1279435wrg.95.1611873792012;
        Thu, 28 Jan 2021 14:43:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611873792; cv=none;
        d=google.com; s=arc-20160816;
        b=q+i7WCiEV4XFuo0S4189NyNoJ9bSYMyGPsTDGq64f2mx6X5+LYGUXfsov0rkaH1B+D
         ZaBSSDlAbCevV2ENWBA1Zk1oI5xnDGHjXPzz6MtQgF7UErlHuFbgLP4StvdOMFED6qAA
         QoL7KZWTcq3GjNhQo0REqdYeeVN8D0ZUK87KVOws47rgkvs71fEXaKl/kRzZuFv/ThEH
         CX/v6LBwrCjWquWBuXgt7YSpgHMC++pta6mP1kYUIl/6bYPnIMXmyxUJY9kZ4bHhPxlq
         ENHwQ+t5jkEsChG5xEyEdkvibloWhPTdtpkuewQGu65y3qQnPQmafkbFGqpNM0b7xaDp
         RUSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9kaDYTKlZ4wNIngjgc1IkyjQfe7sCdicF5kaL/bCBvs=;
        b=qiLZipcKLf1QWrjymwNx554HRzE8PIPEUXy9iGh4xV652P7igow1KAWXykX8tzZ0h9
         xMLI91Tg6iBniu8J6N0uBtk5DskmjLbFmGewRQfo0iLzSfdF+RslkXMiv+GgHcGYpfMy
         MnQlFGL9raih/NUgfmNkjoQz6h9AZHInIrFIf2MQ1pJ7ajlZ1gh51ChR+4X2HepcS+H9
         GUg/+3t6xRXWTHanjkba0pJ14C8aK069xvxehfAoCWVapSVX0+y8Gx0phikcSdknsLpu
         1K8Ij+ruXcWkl6MpToXTJQCwBEkuheN+cGC9ji2cvUqmNEk8uHXhDwjGKr3pUxKIK3F1
         bYAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=PUaq5PwN;
       spf=pass (google.com: domain of andy.jinhuang@gmail.com designates 2a00:1450:4864:20::62d as permitted sender) smtp.mailfrom=andy.jinhuang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x62d.google.com (mail-ej1-x62d.google.com. [2a00:1450:4864:20::62d])
        by gmr-mx.google.com with ESMTPS id 7si279198wrp.3.2021.01.28.14.43.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 28 Jan 2021 14:43:12 -0800 (PST)
Received-SPF: pass (google.com: domain of andy.jinhuang@gmail.com designates 2a00:1450:4864:20::62d as permitted sender) client-ip=2a00:1450:4864:20::62d;
Received: by mail-ej1-x62d.google.com with SMTP id gx5so10171066ejb.7
        for <kasan-dev@googlegroups.com>; Thu, 28 Jan 2021 14:43:11 -0800 (PST)
X-Received: by 2002:a17:906:494c:: with SMTP id f12mr1731451ejt.56.1611873791690;
 Thu, 28 Jan 2021 14:43:11 -0800 (PST)
MIME-Version: 1.0
References: <CACV+narOjL5_o_in_WtOo9kjhcKFD4S4ozctPtdj6JR0+b8adg@mail.gmail.com>
 <CACT4Y+aAarvX0aoesAZjfTnHijwcg68G7o-mtV2CED5PgwygZQ@mail.gmail.com>
 <CACV+napfUFrnr6WxcidQG+di5YTC8KKd=pcWxAp28FJmivTgpQ@mail.gmail.com>
 <CANpmjNM_zO_u=r732JLzE5=+Timjgky+7P8So_k9_cukO876CQ@mail.gmail.com>
 <CACV+narfJs5WSpdbG8=Ui0mCda4+ibToEMPxu4GHhGu0RbhD_w@mail.gmail.com> <CACT4Y+aMjm9tER-tsHeUY6xjOq7pDWJxVa1_AJ-XVO8nVoAEjQ@mail.gmail.com>
In-Reply-To: <CACT4Y+aMjm9tER-tsHeUY6xjOq7pDWJxVa1_AJ-XVO8nVoAEjQ@mail.gmail.com>
From: Jin Huang <andy.jinhuang@gmail.com>
Date: Thu, 28 Jan 2021 17:43:00 -0500
Message-ID: <CACV+naoGypEtGan65+PQR0Z8pWgF=uejYTT_+bAO-Lo3O4v+CA@mail.gmail.com>
Subject: Re: KCSAN how to use
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>
Content-Type: multipart/alternative; boundary="000000000000c6cc4c05b9fd9c12"
X-Original-Sender: andy.jinhuang@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=PUaq5PwN;       spf=pass
 (google.com: domain of andy.jinhuang@gmail.com designates 2a00:1450:4864:20::62d
 as permitted sender) smtp.mailfrom=andy.jinhuang@gmail.com;       dmarc=pass
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

--000000000000c6cc4c05b9fd9c12
Content-Type: text/plain; charset="UTF-8"

Hi, Dmitry
Thank you for your help.

I also want to ask an interesting question about the call stack
information, how did you get the inline function call information in the
call stack like this:

vfs_unlink+0x269/0x3b0 fs/namei.c:3837

 do_unlinkat+0x28a/0x4d0 fs/namei.c:3899

 __do_sys_unlink fs/namei.c:3945 [inline]

 __se_sys_unlink fs/namei.c:3943 [inline]

 __x64_sys_unlink+0x2c/0x30 fs/namei.c:3943

 do_syscall_64+0x39/0x80 arch/x86/entry/common.c:46

 entry_SYSCALL_64_after_hwframe+0x44/0xa9

I use dump_stack(), but can only get this kind of info:

vfs_unlink+0x269/0x3b0

do_unlinkat+0x28a/0x4d0

__x64_sys_unlink+0x2c/0x30

do_syscall_64+0x39/0x80

entry_SYSCALL_64_after_hwframe+0x44/0xa9

Obviously, inline function info misses. When I look at the Linux Kernel
source code, the implementation of dump_stack(), seems because the inline
function is not within the range of kernel_text_address().
Do you have any idea?



Thank You
Best
Jin Huang


On Wed, Jan 27, 2021 at 4:27 AM Dmitry Vyukov <dvyukov@google.com> wrote:

> On Wed, Jan 27, 2021 at 5:57 AM Jin Huang <andy.jinhuang@gmail.com> wrote:
> >
> > Hi, Macro
> > Could you provide some instructions about how to use syz-symbolize to
> locate the kernel source code?
> > I did not find any document about it.
>
> Hi Jin,
>
> If you build kernel in-tree, then you can just run:
> $ syz-symbolize file-with-kernel-crash
> from the kernel dir.
>
> Otherwise add -kernel_src flag and/or -kernel_obj flag:
>
> https://github.com/google/syzkaller/blob/master/tools/syz-symbolize/symbolize.go#L24
>
>
>
> > Thank You
> > Best
> > Jin Huang
> >
> >
> > On Mon, Jan 11, 2021 at 2:09 AM Marco Elver <elver@google.com> wrote:
> >>
> >> On Mon, 11 Jan 2021 at 07:54, Jin Huang <andy.jinhuang@gmail.com>
> wrote:
> >>>
> >>> Really thank you for your help, Dmitry.
> >>> I tried and saw the KCSAN info.
> >>>
> >>> But now it seems weird, the KCSAN reports differently every time I run
> the kernel, and the /sys/kernel/debug/kcsan seems does not match with the
> KCSAN report. What is wrong?
> >>
> >>
> >> /sys/kernel/debug/kcsan shows the total data races found, but that may
> differ from those reported to console, because there is an extra filtering
> step (e.g. KCSAN won't report the same data race more than once 3 sec).
> >>
> >>>
> >>> And I also want to ask, besides gdb, how to use other ways to locate
> the kernel source code, like decode_stacktrace.sh and syz-symbolize, talked
> about here https://lwn.net/Articles/816850/. Is gdb the best way?
> >>
> >>
> >> I use syz-symbolize 99% of the time.
> >>
> >>>
> >>> Also, does KCSAN recognizes all the synchronizations in the Linux
> Kernel? Is there false positives or false negatives?
> >>
> >>
> >> Data races in the Linux kernel is an ongoing story, however, there are
> no false positives (but KCSAN can miss data races).
> >>
> >> Regarding the data races you're observing: there are numerous known
> data races in the kernel that are expected when you currently run KCSAN. To
> understand the severity of different reports, let's define the following 3
> concurrency bug classes:
> >>
> >> A. Data race, where failure due to current compilers is unlikely
> (supposedly "benign"); merely marking the accesses appropriately is
> sufficient. Finding a crash for these will require a miscompilation, but
> otherwise look "benign" at the C-language level.
> >>
> >> B. Race-condition bugs where the bug manifests as a data race, too --
> simply marking things doesn't fix the problem. These are the types of bugs
> where a data race would point out a more severe issue.
> >>
> >> C. Race-condition bugs where the bug never manifests as a data race. An
> example of these might be 2 threads that acquire the necessary locks, yet
> some interleaving of them still results in a bug (e.g. because the logic
> inside the critical sections is buggy). These are harder to detect with
> KCSAN as-is, and require using ASSERT_EXCLUSIVE_ACCESS() or
> ASSERT_EXCLUSIVE_WRITER() in the right place. See
> https://lwn.net/Articles/816854/.
> >>
> >> One problem currently is that the kernel has quite a lot type-(A)
> reports if we run KCSAN, which makes it harder to identify bugs of type (B)
> and (C). My wish for the future is that we can get to a place, where the
> kernel has almost no unintentional (A) issues, so that we primarily find
> (B) and (C) bugs.
> >>
> >> Hope this helps.
> >>
> >> Thanks,
> >> -- Marco
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACV%2BnaoGypEtGan65%2BPQR0Z8pWgF%3DuejYTT_%2BbAO-Lo3O4v%2BCA%40mail.gmail.com.

--000000000000c6cc4c05b9fd9c12
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div>Hi, Dmitry</div>Thank you for=C2=A0your help.<div><br=
></div><div>I also want to ask an interesting question about the call stack=
 information, how did you get the inline function call information in the c=
all stack like this:</div><div><span id=3D"m_-8542952683865599682gmail-docs=
-internal-guid-2b5f7e77-7fff-5700-ed6f-99c9b58d2c6e"><p dir=3D"ltr" style=
=3D"line-height:1.38;margin-top:0pt;margin-bottom:0pt"><span style=3D"font-=
size:11pt;font-family:Arial;color:rgb(0,0,0);background-color:transparent;f=
ont-variant-numeric:normal;font-variant-east-asian:normal;vertical-align:ba=
seline;white-space:pre-wrap">vfs_unlink+0x269/0x3b0 fs/namei.c:3837</span><=
/p><p dir=3D"ltr" style=3D"line-height:1.38;margin-top:0pt;margin-bottom:0p=
t"><span style=3D"font-size:11pt;font-family:Arial;color:rgb(0,0,0);backgro=
und-color:transparent;font-variant-numeric:normal;font-variant-east-asian:n=
ormal;vertical-align:baseline;white-space:pre-wrap">=C2=A0do_unlinkat+0x28a=
/0x4d0 fs/namei.c:3899</span></p><p dir=3D"ltr" style=3D"line-height:1.38;m=
argin-top:0pt;margin-bottom:0pt"><span style=3D"font-size:11pt;font-family:=
Arial;color:rgb(0,0,0);background-color:transparent;font-variant-numeric:no=
rmal;font-variant-east-asian:normal;vertical-align:baseline;white-space:pre=
-wrap">=C2=A0__do_sys_unlink fs/namei.c:3945 [inline]</span></p><p dir=3D"l=
tr" style=3D"line-height:1.38;margin-top:0pt;margin-bottom:0pt"><span style=
=3D"font-size:11pt;font-family:Arial;color:rgb(0,0,0);background-color:tran=
sparent;font-variant-numeric:normal;font-variant-east-asian:normal;vertical=
-align:baseline;white-space:pre-wrap">=C2=A0__se_sys_unlink fs/namei.c:3943=
 [inline]</span></p><p dir=3D"ltr" style=3D"line-height:1.38;margin-top:0pt=
;margin-bottom:0pt"><span style=3D"font-size:11pt;font-family:Arial;color:r=
gb(0,0,0);background-color:transparent;font-variant-numeric:normal;font-var=
iant-east-asian:normal;vertical-align:baseline;white-space:pre-wrap">=C2=A0=
__x64_sys_unlink+0x2c/0x30 fs/namei.c:3943</span></p><p dir=3D"ltr" style=
=3D"line-height:1.38;margin-top:0pt;margin-bottom:0pt"><span style=3D"font-=
size:11pt;font-family:Arial;color:rgb(0,0,0);background-color:transparent;f=
ont-variant-numeric:normal;font-variant-east-asian:normal;vertical-align:ba=
seline;white-space:pre-wrap">=C2=A0do_syscall_64+0x39/0x80 arch/x86/entry/c=
ommon.c:46</span></p><p dir=3D"ltr" style=3D"line-height:1.38;margin-top:0p=
t;margin-bottom:0pt"><span style=3D"font-size:11pt;font-family:Arial;color:=
rgb(0,0,0);background-color:transparent;font-variant-numeric:normal;font-va=
riant-east-asian:normal;vertical-align:baseline;white-space:pre-wrap">=C2=
=A0entry_SYSCALL_64_after_hwframe+0x44/0xa9</span></p></span><br></div><div=
>I use dump_stack(), but can only get this kind of info:</div><div><span id=
=3D"m_-8542952683865599682gmail-docs-internal-guid-c80502d7-7fff-7c41-8d14-=
47379c3eb404"><p dir=3D"ltr" style=3D"line-height:1.38;margin-top:0pt;margi=
n-bottom:0pt"><span style=3D"font-size:11pt;font-family:Arial;color:rgb(0,0=
,0);background-color:transparent;font-variant-numeric:normal;font-variant-e=
ast-asian:normal;vertical-align:baseline;white-space:pre-wrap">vfs_unlink+0=
x269/0x3b0</span></p><p dir=3D"ltr" style=3D"line-height:1.38;margin-top:0p=
t;margin-bottom:0pt"><span style=3D"font-size:11pt;font-family:Arial;color:=
rgb(0,0,0);background-color:transparent;font-variant-numeric:normal;font-va=
riant-east-asian:normal;vertical-align:baseline;white-space:pre-wrap">do_un=
linkat+0x28a/0x4d0</span></p><p dir=3D"ltr" style=3D"line-height:1.38;margi=
n-top:0pt;margin-bottom:0pt"><span style=3D"font-size:11pt;font-family:Aria=
l;color:rgb(0,0,0);background-color:transparent;font-variant-numeric:normal=
;font-variant-east-asian:normal;vertical-align:baseline;white-space:pre-wra=
p">__x64_sys_unlink+0x2c/0x30</span></p><p dir=3D"ltr" style=3D"line-height=
:1.38;margin-top:0pt;margin-bottom:0pt"><span style=3D"font-size:11pt;font-=
family:Arial;color:rgb(0,0,0);background-color:transparent;font-variant-num=
eric:normal;font-variant-east-asian:normal;vertical-align:baseline;white-sp=
ace:pre-wrap">do_syscall_64+0x39/0x80</span></p><p dir=3D"ltr" style=3D"lin=
e-height:1.38;margin-top:0pt;margin-bottom:0pt"><span style=3D"font-size:11=
pt;font-family:Arial;color:rgb(0,0,0);background-color:transparent;font-var=
iant-numeric:normal;font-variant-east-asian:normal;vertical-align:baseline;=
white-space:pre-wrap">entry_SYSCALL_64_after_hwframe+0x44/0xa9</span></p></=
span><br></div><div>Obviously, inline function info misses. When I look at =
the Linux Kernel source code, the implementation of dump_stack(), seems bec=
ause the inline function is not within the range of kernel_text_address().<=
/div><div>Do you have any idea?</div><div><br></div><div><br clear=3D"all">=
<div><div dir=3D"ltr" data-smartmail=3D"gmail_signature"><div dir=3D"ltr"><=
div><br></div><div>Thank You</div>Best<div>Jin Huang</div></div></div></div=
><br></div></div><br><div class=3D"gmail_quote"><div dir=3D"ltr" class=3D"g=
mail_attr">On Wed, Jan 27, 2021 at 4:27 AM Dmitry Vyukov &lt;<a href=3D"mai=
lto:dvyukov@google.com" target=3D"_blank">dvyukov@google.com</a>&gt; wrote:=
<br></div><blockquote class=3D"gmail_quote" style=3D"margin:0px 0px 0px 0.8=
ex;border-left:1px solid rgb(204,204,204);padding-left:1ex">On Wed, Jan 27,=
 2021 at 5:57 AM Jin Huang &lt;<a href=3D"mailto:andy.jinhuang@gmail.com" t=
arget=3D"_blank">andy.jinhuang@gmail.com</a>&gt; wrote:<br>
&gt;<br>
&gt; Hi, Macro<br>
&gt; Could you provide some instructions about how to use syz-symbolize to =
locate the kernel source code?<br>
&gt; I did not find any document about it.<br>
<br>
Hi Jin,<br>
<br>
If you build kernel in-tree, then you can just run:<br>
$ syz-symbolize file-with-kernel-crash<br>
from the kernel dir.<br>
<br>
Otherwise add -kernel_src flag and/or -kernel_obj flag:<br>
<a href=3D"https://github.com/google/syzkaller/blob/master/tools/syz-symbol=
ize/symbolize.go#L24" rel=3D"noreferrer" target=3D"_blank">https://github.c=
om/google/syzkaller/blob/master/tools/syz-symbolize/symbolize.go#L24</a><br=
>
<br>
<br>
<br>
&gt; Thank You<br>
&gt; Best<br>
&gt; Jin Huang<br>
&gt;<br>
&gt;<br>
&gt; On Mon, Jan 11, 2021 at 2:09 AM Marco Elver &lt;<a href=3D"mailto:elve=
r@google.com" target=3D"_blank">elver@google.com</a>&gt; wrote:<br>
&gt;&gt;<br>
&gt;&gt; On Mon, 11 Jan 2021 at 07:54, Jin Huang &lt;<a href=3D"mailto:andy=
.jinhuang@gmail.com" target=3D"_blank">andy.jinhuang@gmail.com</a>&gt; wrot=
e:<br>
&gt;&gt;&gt;<br>
&gt;&gt;&gt; Really thank you for your help, Dmitry.<br>
&gt;&gt;&gt; I tried and saw the KCSAN info.<br>
&gt;&gt;&gt;<br>
&gt;&gt;&gt; But now it seems weird, the KCSAN reports differently every ti=
me I run the kernel, and the /sys/kernel/debug/kcsan seems does not match w=
ith the KCSAN report. What is wrong?<br>
&gt;&gt;<br>
&gt;&gt;<br>
&gt;&gt; /sys/kernel/debug/kcsan shows the total data races found, but that=
 may differ from those reported to console, because there is an extra filte=
ring step (e.g. KCSAN won&#39;t report the same data race more than once 3 =
sec).<br>
&gt;&gt;<br>
&gt;&gt;&gt;<br>
&gt;&gt;&gt; And I also want to ask, besides gdb, how to use other ways to =
locate the kernel source code, like decode_stacktrace.sh and syz-symbolize,=
 talked about here <a href=3D"https://lwn.net/Articles/816850/" rel=3D"nore=
ferrer" target=3D"_blank">https://lwn.net/Articles/816850/</a>. Is gdb the =
best way?<br>
&gt;&gt;<br>
&gt;&gt;<br>
&gt;&gt; I use syz-symbolize 99% of the time.<br>
&gt;&gt;<br>
&gt;&gt;&gt;<br>
&gt;&gt;&gt; Also, does KCSAN recognizes all the synchronizations in the Li=
nux Kernel? Is there false positives or false negatives?<br>
&gt;&gt;<br>
&gt;&gt;<br>
&gt;&gt; Data races in the Linux kernel is an ongoing story, however, there=
 are no false positives (but KCSAN can miss data races).<br>
&gt;&gt;<br>
&gt;&gt; Regarding the data races you&#39;re observing: there are numerous =
known data races in the kernel that are expected when you currently run KCS=
AN. To understand the severity of different reports, let&#39;s define the f=
ollowing 3 concurrency bug classes:<br>
&gt;&gt;<br>
&gt;&gt; A. Data race, where failure due to current compilers is unlikely (=
supposedly &quot;benign&quot;); merely marking the accesses appropriately i=
s sufficient. Finding a crash for these will require a miscompilation, but =
otherwise look &quot;benign&quot; at the C-language level.<br>
&gt;&gt;<br>
&gt;&gt; B. Race-condition bugs where the bug manifests as a data race, too=
 -- simply marking things doesn&#39;t fix the problem. These are the types =
of bugs where a data race would point out a more severe issue.<br>
&gt;&gt;<br>
&gt;&gt; C. Race-condition bugs where the bug never manifests as a data rac=
e. An example of these might be 2 threads that acquire the necessary locks,=
 yet some interleaving of them still results in a bug (e.g. because the log=
ic inside the critical sections is buggy). These are harder to detect with =
KCSAN as-is, and require using ASSERT_EXCLUSIVE_ACCESS() or ASSERT_EXCLUSIV=
E_WRITER() in the right place. See <a href=3D"https://lwn.net/Articles/8168=
54/" rel=3D"noreferrer" target=3D"_blank">https://lwn.net/Articles/816854/<=
/a>.<br>
&gt;&gt;<br>
&gt;&gt; One problem currently is that the kernel has quite a lot type-(A) =
reports if we run KCSAN, which makes it harder to identify bugs of type (B)=
 and (C). My wish for the future is that we can get to a place, where the k=
ernel has almost no unintentional (A) issues, so that we primarily find (B)=
 and (C) bugs.<br>
&gt;&gt;<br>
&gt;&gt; Hope this helps.<br>
&gt;&gt;<br>
&gt;&gt; Thanks,<br>
&gt;&gt; -- Marco<br>
</blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CACV%2BnaoGypEtGan65%2BPQR0Z8pWgF%3DuejYTT_%2BbAO-Lo3O=
4v%2BCA%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://gr=
oups.google.com/d/msgid/kasan-dev/CACV%2BnaoGypEtGan65%2BPQR0Z8pWgF%3DuejYT=
T_%2BbAO-Lo3O4v%2BCA%40mail.gmail.com</a>.<br />

--000000000000c6cc4c05b9fd9c12--
