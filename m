Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBGU7YP2AKGQE6GVO7WY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id E47741A4ADD
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Apr 2020 21:57:15 +0200 (CEST)
Received: by mail-oi1-x23d.google.com with SMTP id 8sf2638959oiq.2
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Apr 2020 12:57:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586548635; cv=pass;
        d=google.com; s=arc-20160816;
        b=WLzMVdOsMxt6ljakPSn3+qy8y+A+LmJWs+b5YKzC7kbrUwiWCbhpoeW3aMRJ8EGcfR
         q2olmeCZCaqP369Y/v93G4UhG4KgNfpMfn2lMR4VtLWKwukJPGD839ZJTDlW56XOY8/U
         Yk/JmumeDfj6s8dbXVEOL44VuZ6LUuZHj46UiOIND+e2FoJx1lWfx0qYhKN/SoIKgmLK
         s8xR2/xdxtTqCtnK8msgfRQVnySWE0+hUHu7UdO8waYim0W+rANJ7Kez/ZXEnr2fgrp0
         iAeCLkc+bsh5rBhjUYkPwy40F4aqE32FRyoCL4dLE9RS0rl2UWDsx8bSb1CG+hQR7wjv
         /7Qg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:references:message-id
         :content-transfer-encoding:cc:date:in-reply-to:from:subject
         :mime-version:sender:dkim-signature;
        bh=dgbwoJEC1WtTNamRPotbOoS5wphce6FaL82nouitBaw=;
        b=0ii5d1B3KMK0CGAefRdyMRYwv2AIQXTC5DYT8CPnkQgQc0rgqQVJ0XtTq5L8Kp6ICR
         pFKoL2jhkgH1PpiDJGOxPzk474TlEg3e4LYc7+4Aqoi+RXCFBCe9Dp4RP0zSnX9xibkN
         BTgQW3uCLz56nxLGYro6MPb6xcNgpcZvqHy2iMY6Xe570Z9EZVLrnlA9GKpZ0RUTk1w6
         GX9Lqb7jiHYqw8BoEoztVx1mAypFio+kHKnZ7W1rzDVcWB1S8d2c8dI6tucGWRYZAox0
         m4ObikNClBKLTHGQiRgVml0PNvXBVor6d/NIP8cIqUl66WGC6IxLKYfvsCzVehuJ/KYJ
         fimQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=nq1ZWmiu;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f41 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:subject:from:in-reply-to:date:cc
         :content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dgbwoJEC1WtTNamRPotbOoS5wphce6FaL82nouitBaw=;
        b=WBU4bHJHJD3i2tdi8geelYLvLBk0daSx2tml8AhyeBqMx/z2rP6nYPUldkiSqDVntb
         XShKqW/yuKosBWGGmsUvvygPiDgZUK36jVhqgWvIgqhAvleLnOyg7OR7zIO6WZSO3Yng
         zKKI4XWEeUz002J8c2TGMRAU3U9k28TnwgRTBXfJK+XSCTg3YOg6TOGaQ2KEUH0VOxFM
         UTet8/cTuW5e4x4Dr8KH0HCp2VL+V9g1NIP6HNdbyBRdAU8DD7Ia+Sec6ZoK2+zRUhLM
         OTZXXqvMScYSTFlHvlirpME0CpoIfNTojHMupavK3eu5gTF6ct2XeuTDBUA9/u/Q5lA8
         qSTQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:subject:from:in-reply-to
         :date:cc:content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=dgbwoJEC1WtTNamRPotbOoS5wphce6FaL82nouitBaw=;
        b=nNYWsTN3iCABwmnW4MyCVKfxMBvkRplpodmrkwOGvvETxf5Y9BVzvZmE44PkAhpA0A
         qf4ZZGFO722b//UH1bv1Aby8nN+wYRxUeqJexPBxXPwJIcfFJ3vlooO80cVRsCCzWiGo
         ZWnC5s/Bo0+QWRRkE3P4ZxLNQQgfAtM9bBow4ITr9By/R0JS52PDEgy02WfeAe9RNMuP
         WV5RNF3x5wNgw9RNRyUXcitKYqMrXKkbDf27gY2yOqYpiw+nWosH9HrjTiSNYLVoEONY
         XydRjEBprL41U0JXr3tkD50ZG9kuc9vz48sGX2zIhY36Be+jMJ3Wua0IXc74mSncsTyh
         R36w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0Publc61vxAqfSTlbkHjcz0j1IOU7P1YcRc93zpCUWobvSOepSWCP
	3oATxRFRxXJ1cyXc8f227yc=
X-Google-Smtp-Source: APiQypKjXhnNVqp1rCogVaigx3jcJgw5kdNUFHmZ3aXVqjLxzVLigzF8VT7rtoBR16V4N6buFgH5gQ==
X-Received: by 2002:a9d:12d:: with SMTP id 42mr5230110otu.2.1586548634856;
        Fri, 10 Apr 2020 12:57:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:d485:: with SMTP id l127ls970755oig.9.gmail; Fri, 10 Apr
 2020 12:57:14 -0700 (PDT)
X-Received: by 2002:aca:aa81:: with SMTP id t123mr4550648oie.117.1586548634577;
        Fri, 10 Apr 2020 12:57:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586548634; cv=none;
        d=google.com; s=arc-20160816;
        b=UuW2Fa+pmfZ6NYwP7A5MnYIxy5kfOpIn2yUQIPOmnFyXHtyEmMQHu13UNXwCLU5IYg
         Iz13hxrHBqukvZuVSkmbDvq6jOd9mONTA0Xv4E6PIdd5vaic7myaypSpSXLrVTYq2UKM
         QrKkgIjULfIfuwb1uT2MUrYQtlms7wO0FOxaDPwfRbWIlJIA/sU5xPBdsMS91iNxXdAy
         zXp/UQDP3uCx6fS+qaV+leBn3jJ/x9cDw3Q5085JMI8Y8T+SjJ11zXT2GfAMyW9PPBZT
         eps1y28+1SqlvmuTZ0+qJ/MxC5oPLYXg8vlaSG0mUeNQqg5wS8SDmqPQdnScCRh7D24b
         mB0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:references:message-id:content-transfer-encoding:cc:date
         :in-reply-to:from:subject:mime-version:dkim-signature;
        bh=pS46DIfpY3lCgLGWiwz/LrxVk7ZBGeU+Fv83QXgtneM=;
        b=ErJsh1hd3PhH3mLiZQzu47PVEECl5VKedKOy798LLaQV0QOcDOU/Vv/YyrgTpPcc88
         ONNCRQd1PCqWEdgP7mG91gI4qRt1DDpuWNNE/mCkwHBFjCDUdgfPd7as7CF1SCiGTMlK
         W/ooY1H/Z2tHL1Qnjj+aRmU8Mk4N31tqgfKOD701ID+CyuWKxG5wOwNNiyjnxfkxSIBq
         2v/sdbKRNmba/rRoTzF/lsa7My4NOZlI9BbLDmwjOAh1vLTsSQhb3epMCV0lO8919N9/
         U1VAq2fxBxCV4z3vDT1PhUlN/xDJsqxkrQTYv8d8uooWcpsONaGzvFRTOgwnU3ss2jhD
         r4DQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=nq1ZWmiu;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f41 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qv1-xf41.google.com (mail-qv1-xf41.google.com. [2607:f8b0:4864:20::f41])
        by gmr-mx.google.com with ESMTPS id t81si191233oie.5.2020.04.10.12.57.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Apr 2020 12:57:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f41 as permitted sender) client-ip=2607:f8b0:4864:20::f41;
Received: by mail-qv1-xf41.google.com with SMTP id w26so1465354qvd.10
        for <kasan-dev@googlegroups.com>; Fri, 10 Apr 2020 12:57:14 -0700 (PDT)
X-Received: by 2002:a0c:9068:: with SMTP id o95mr6816196qvo.101.1586548634028;
        Fri, 10 Apr 2020 12:57:14 -0700 (PDT)
Received: from [192.168.1.153] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id m1sm2439743qtm.22.2020.04.10.12.57.12
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 10 Apr 2020 12:57:13 -0700 (PDT)
Content-Type: text/plain; charset="UTF-8"
Mime-Version: 1.0 (Mac OS X Mail 13.4 \(3608.80.23.2.2\))
Subject: Re: KCSAN + KVM = host reset
From: Qian Cai <cai@lca.pw>
In-Reply-To: <CANpmjNPqQHKUjqAzcFym5G8kHX0mjProOpGu8e4rBmuGRykAUg@mail.gmail.com>
Date: Fri, 10 Apr 2020 15:57:12 -0400
Cc: Paolo Bonzini <pbonzini@redhat.com>,
 "paul E. McKenney" <paulmck@kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>,
 LKML <linux-kernel@vger.kernel.org>,
 kvm@vger.kernel.org
Content-Transfer-Encoding: quoted-printable
Message-Id: <C4FED226-E3DE-44AE-BBED-2B56B9F5B12F@lca.pw>
References: <CANpmjNMR4BgfCxL9qXn0sQrJtQJbEPKxJ5_HEa2VXWi6UY4wig@mail.gmail.com>
 <AC8A5393-B817-4868-AA85-B3019A1086F9@lca.pw>
 <CANpmjNPqQHKUjqAzcFym5G8kHX0mjProOpGu8e4rBmuGRykAUg@mail.gmail.com>
To: Marco Elver <elver@google.com>
X-Mailer: Apple Mail (2.3608.80.23.2.2)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=nq1ZWmiu;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f41 as
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



> On Apr 10, 2020, at 7:35 AM, Marco Elver <elver@google.com> wrote:
>=20
> On Fri, 10 Apr 2020 at 13:25, Qian Cai <cai@lca.pw> wrote:
>>=20
>>=20
>>=20
>>> On Apr 10, 2020, at 5:47 AM, Marco Elver <elver@google.com> wrote:
>>>=20
>>> That would contradict what you said about it working if KCSAN is
>>> "off". What kernel are you attempting to use in the VM?
>=20
> Ah, sorry this was a typo,
>  s/working if KCSAN/not working if KCSAN/
>=20
>> Well, I said set KCSAN debugfs to =E2=80=9Coff=E2=80=9D did not help, i.=
e., it will reset the host running kvm.sh. It is the vanilla ubuntu 18.04 k=
ernel in VM.
>>=20
>> github.com/cailca/linux-mm/blob/master/kvm.sh
>=20
> So, if you say that CONFIG_KCSAN_INTERRUPT_WATCHER=3Dn works, that
> contradicts it not working when KCSAN is "off". Because if KCSAN is
> off, it never sets up any watchpoints, and whether or not
> KCSAN_INTERRUPT_WATCHER is selected or not shouldn't matter. Does that
> make more sense?

Yes, you are right. CONFIG_KCSAN_INTERRUPT_WATCHER=3Dn does not
make it work. It was a mistake when I tested it because there was a stale s=
vm.o
leftover from the previous run, and then it will not trigger a rebuild (a b=
ug?) when
only modify the Makefile to remove KCSAN_SANITIZE :=3D n. Sorry for the mis=
leading
information. I should be checking if svm.o was really recompiled in the fir=
st place.

Anyway, I=E2=80=99ll send a patch to add __no_kcsan for svm_vcpu_run() beca=
use I tried
to narrow down more with a kcsan_[disable|enable]_current() pair, but it do=
es NOT
work even by enclosing the almost whole function below until Marcro has mor=
e ideas?

diff --git a/arch/x86/kvm/svm/svm.c b/arch/x86/kvm/svm/svm.c
index 2be5bbae3a40..e58b2d5a575c 100644
--- a/arch/x86/kvm/svm/svm.c
+++ b/arch/x86/kvm/svm/svm.c
@@ -3286,6 +3286,7 @@ static void svm_vcpu_run(struct kvm_vcpu *vcpu)
        svm->vmcb->save.rsp =3D vcpu->arch.regs[VCPU_REGS_RSP];
        svm->vmcb->save.rip =3D vcpu->arch.regs[VCPU_REGS_RIP];
=20
+       kcsan_disable_current();
        /*
         * A vmexit emulation is required before the vcpu can be executed
         * again.
@@ -3410,6 +3411,7 @@ static void svm_vcpu_run(struct kvm_vcpu *vcpu)
                svm_handle_mce(svm);
=20
        mark_all_clean(svm->vmcb);
+       kcsan_enable_current();
 }
 STACK_FRAME_NON_STANDARD(svm_vcpu_run);
=20

=20



--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/C4FED226-E3DE-44AE-BBED-2B56B9F5B12F%40lca.pw.
