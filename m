Return-Path: <kasan-dev+bncBCMIZB7QWENRBH7JZWAQMGQER36EVRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 09A433212B7
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Feb 2021 10:08:49 +0100 (CET)
Received: by mail-qv1-xf39.google.com with SMTP id ba14sf1236090qvb.3
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Feb 2021 01:08:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613984928; cv=pass;
        d=google.com; s=arc-20160816;
        b=DMC2//WvGX3vQVNG8Qu+xZsXhH0/mfZtdnI2NVApOLEYDafVkZtJZ1DQOtEdmkPa+j
         Lda8SF7FdvX7KxVaZNVpAO2ilalv+tM3TQ47vLfl+STuXXVJdpV6HKpqo9TZyW2qrKJV
         JLlqwwGAfvrWiDvf8XUR1weWdndU5LD71ZLrdkkX9HpxOiDKM8ymVV+4661Q8aTkH6Te
         e0AvP3vSzpFl1+ANnMirjMzJcOH4eIywMyMdNtd1g5eRqa6XoP1yMGVycQPfvjGcqc36
         KFzkCeMmFuCJqptvQ9QHlZi1xMxwILlKZtdScd3TXlRm9szJARhti+tkzZsbEhabnWor
         O90g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/hGQ/Gac6NEfmpnhrvEtBPSuC0AYXyw0h064fpXlzcg=;
        b=OGUBPoPwvDgVxPxUVmGbzhU5il/fgWuYh0m/8v8NqEV75QXfixFVMOAyw2Pr8g5MS+
         IjJpjksrPNAbtRfe1fBvURFmFzBz/kDM9ALJYdQNiBHzOPCLNIe/cC3MMbvC8CEyvZnH
         DMvWsbS3G91eraMd6TLuCJPH+F0URr43+XZ28yUAwkmTgaALKK/XFWp4mR7IBXJMpWbw
         2MGWQ6Uo3HK+bUGKQ43TyuRxlT6tSAD+lpgCadSryS2Qnw9G9twPMXRa/JJaBHG9UNge
         Z5t8KQcRUaSbbXg+Xp02XNeB7+vgn2r5y0E++6L2C5s3gFaKOaHnamXSWx1DmkPB0Y/7
         nkDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GtPuXVxm;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::731 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=/hGQ/Gac6NEfmpnhrvEtBPSuC0AYXyw0h064fpXlzcg=;
        b=rwOf/Ipgrt7qW2ZUWEAsMQNkGDyVygKCAAcK2lmUxRGnTrC7RpaZ0GSURjgvEjfg9l
         GMO7gEPR3dx/IkoOa44gSb5Oe4I5xShOYoO/6fhOohUR067LMF2FV7saGE8DJke3BiGh
         n+F7pG0UTnjyzgcFtKtZqpHDgZzU/aTiowLV8sbRH+Uw5IZcDEO/3D5JDuHpm0DVSdud
         sMJTcFh1i93ZOwbocgZk4vlTiRWceIBmAxWV8k8yZVbX3vPoAu27/k3Iy45A89F9Q0N0
         wdTsHOu1OzsHOdHNTXXiNCaVN8GAZDo/cRXse1efFJIIZdA09ftAO5+rVOoeMW/6dleE
         unJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/hGQ/Gac6NEfmpnhrvEtBPSuC0AYXyw0h064fpXlzcg=;
        b=X1QVikZ1355Y2MPEnDtnMaWkd6BrBWCS42uxTLwsIfxY5fzgke1dDMwh4zpQ4kvyUJ
         fLXeA18r4e17Q2+2xNRsPVNXp1dvykiG1hwhfqCMqVLMtB8Y4GlTCexArjnyO42XyWs9
         Sarxv1yQUpS/8hetff0AqbdPFAmSQgdOKUHa0GVIps39rEQk1/8Syw+pvgfMKTOFluHO
         8foVhWLkf7xMqQgbmDsiV7jrtdrbo8KAzI5LHjU2CjL+tgEnyLDidw/wditTyZch7m9Y
         a3dY15UM6/ln94x5NiYs+73iKu2yXAGOOuA44yRbTVdFoBb0Ti7uBV0/OLg3DSvwdJkN
         BfHA==
X-Gm-Message-State: AOAM5325g7uCGnXUhIXWKLfNFjsKn7AsVblLIdxGbNvwv1S/F/ytUTbj
	ti3Khrg1CcGsVLu7chVYnhE=
X-Google-Smtp-Source: ABdhPJz7KRqIB7uL4Ogb340pshWK5agIsd2DbHfpXY6fAaadaMCP8nSHf6v7GC8GIIpOBN1x9rjVug==
X-Received: by 2002:a37:48c2:: with SMTP id v185mr20147721qka.329.1613984927844;
        Mon, 22 Feb 2021 01:08:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5a04:: with SMTP id n4ls6147207qta.5.gmail; Mon, 22 Feb
 2021 01:08:47 -0800 (PST)
X-Received: by 2002:ac8:5c92:: with SMTP id r18mr18403295qta.27.1613984927514;
        Mon, 22 Feb 2021 01:08:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613984927; cv=none;
        d=google.com; s=arc-20160816;
        b=cYy6e+5IvruU9jFBC6xTA++BwaAujwqxI8G42unTB8FjM1DhEUVXi0x2xwuJ5edIIQ
         lDu4NTmjh5Z1go7CxJENO94jpgBMOTFsM5eUxl6Z4VarKFOOMxNRsrkB6xffVIMjIkEB
         VUB2Rn2Pdr+oSZN8XZ/W/bcGGwc3nwqanMX1hGM51f1vfYwQjTMvyzDVfiGpnO3Geqgi
         5Vq5hr5UtfL3Ni29XmbAfOm0Dsy2ZTA7pgl9m7Hs3y5y4rFgHVy4l5TQ2hZZWa12s7A7
         vFAUOkpLSi9e20ftz4CmtQ9ngfkOlGTxKF070x0RdqmTq3BjJpR5G7q6bFfhOu2poKyd
         2VrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Is44dzJkRsyuyuf+aXLarR61jPyjb3ZSR5ZVi6prDhs=;
        b=ala8L50GOiXeYtrjwlE8BncdahNG3IcTm0mWSEukK5G1R4BUpNG8BeKW/H1LwIDzeG
         fbibHZjh33FrrKlT+qPmeIdaffsPR6xR2yNTgdDJnt1tgcHkCeUZKOMSuqBidMITykLo
         2Wn70lXyDy9c2g+XrTnHF3bykMsCgskqVbIeYWEFwJmU7Rg6D0jlKjE45d6YpMCxyyMW
         Nvtb+MNieKr9llgk27koi24MyGQu0cJYzt8PRfBLA5oju3JUMnKpL1pIVwARijcHRFlK
         AjIypnzCrPWBSaDy8NXUhezDM14Htb7GS7zg3d0Ay12R+wQh3EhF+mzGt/iyhVdnKy9R
         nbJw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GtPuXVxm;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::731 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x731.google.com (mail-qk1-x731.google.com. [2607:f8b0:4864:20::731])
        by gmr-mx.google.com with ESMTPS id f94si494582qtd.2.2021.02.22.01.08.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 22 Feb 2021 01:08:47 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::731 as permitted sender) client-ip=2607:f8b0:4864:20::731;
Received: by mail-qk1-x731.google.com with SMTP id m144so11846102qke.10
        for <kasan-dev@googlegroups.com>; Mon, 22 Feb 2021 01:08:47 -0800 (PST)
X-Received: by 2002:a37:96c4:: with SMTP id y187mr7610636qkd.231.1613984926948;
 Mon, 22 Feb 2021 01:08:46 -0800 (PST)
MIME-Version: 1.0
References: <dce73168-1cff-413d-a3e5-f88365eb73a3n@googlegroups.com> <92bec3ec-ff7e-4aa3-b344-7b9e0daf4ae9n@googlegroups.com>
In-Reply-To: <92bec3ec-ff7e-4aa3-b344-7b9e0daf4ae9n@googlegroups.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 22 Feb 2021 10:08:35 +0100
Message-ID: <CACT4Y+bWytKc_3Qz1hAYvZQiFbGvn+ruAbgGm9wO9EtmUxxA1w@mail.gmail.com>
Subject: Re: KCSAN for Android
To: Hunter J <andy.jinhuang@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=GtPuXVxm;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::731
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Sat, Feb 20, 2021 at 11:49 PM Hunter J <andy.jinhuang@gmail.com> wrote:
>
> I solved the skzkaller compilation problem by defining the undeclared var=
iables myself.
>
> syzkaller is running on my machine now,
> I think KCSAN is not available for Android now, right?

+kasan-dev for KCSAN question, syzkaller to bcc

I see that KCSAN was added in v5.8:
https://www.kernel.org/doc/html/v5.8/dev-tools/kcsan.html
https://www.kernel.org/doc/html/v5.7/dev-tools/kcsan.html

To use KCSAN you either need to switch to kernel v5.8+, e.g. GKI 5.10:
https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10
or backport KCSAN to your kernel.



> On Saturday, February 20, 2021 at 5:45:59 AM UTC-5 Hunter J wrote:
>>
>> Hi, I want to ask whether KCSAN is available for Android now?
>> If not, how about KTSAN for datarace detection purpose?
>>
>> As I read the document, for Android fuzzing purpose, we can just configu=
re and run LinuxKernel with ARM64, or Android Kernel ARM64, on QEMU right?
>>
>> But when I tried to build syzkaller with the gcc you provided on documen=
t, errors come out. Do you have some ideas about this? I think it is gcc is=
sues, right? Mayne I need to use some other version of aarch64-linux-gnu-gc=
c?
>>
>>
>> make TARGETARCH=3Darm64 CC=3Daarch64-linux-gnu-g++ -j64
>> ------------------------------------------------------------------------=
----------------------------
>>
>> go list -f '{{.Stale}}' ./sys/syz-sysgen | grep -q false || go install .=
/sys/syz-sysgen
>> make .descriptions
>> make[1]: '.descriptions' is up to date.
>> GOOS=3Dlinux GOARCH=3Damd64 go build "-ldflags=3D-s -w -X github.com/goo=
gle/syzkaller/prog.GitRevision=3D3e5ed8b45e7a561d6344a4d3d7bf3bfb8f24a7b3 -=
X 'github.com/google/syzkaller/prog.gitRevisionDate=3D20210220-100218'" -o =
./bin/syz-manager github.com/google/syzkaller/syz-manager
>> GOOS=3Dlinux GOARCH=3Damd64 go build "-ldflags=3D-s -w -X github.com/goo=
gle/syzkaller/prog.GitRevision=3D3e5ed8b45e7a561d6344a4d3d7bf3bfb8f24a7b3 -=
X 'github.com/google/syzkaller/prog.gitRevisionDate=3D20210220-100218'" -o =
./bin/syz-runtest github.com/google/syzkaller/tools/syz-runtest
>> GOOS=3Dlinux GOARCH=3Damd64 go build "-ldflags=3D-s -w -X github.com/goo=
gle/syzkaller/prog.GitRevision=3D3e5ed8b45e7a561d6344a4d3d7bf3bfb8f24a7b3 -=
X 'github.com/google/syzkaller/prog.gitRevisionDate=3D20210220-100218'" -o =
./bin/syz-repro github.com/google/syzkaller/tools/syz-repro
>> GOOS=3Dlinux GOARCH=3Damd64 go build "-ldflags=3D-s -w -X github.com/goo=
gle/syzkaller/prog.GitRevision=3D3e5ed8b45e7a561d6344a4d3d7bf3bfb8f24a7b3 -=
X 'github.com/google/syzkaller/prog.gitRevisionDate=3D20210220-100218'" -o =
./bin/syz-mutate github.com/google/syzkaller/tools/syz-mutate
>> GOOS=3Dlinux GOARCH=3Damd64 go build "-ldflags=3D-s -w -X github.com/goo=
gle/syzkaller/prog.GitRevision=3D3e5ed8b45e7a561d6344a4d3d7bf3bfb8f24a7b3 -=
X 'github.com/google/syzkaller/prog.gitRevisionDate=3D20210220-100218'" -o =
./bin/syz-prog2c github.com/google/syzkaller/tools/syz-prog2c
>> GOOS=3Dlinux GOARCH=3Damd64 go build "-ldflags=3D-s -w -X github.com/goo=
gle/syzkaller/prog.GitRevision=3D3e5ed8b45e7a561d6344a4d3d7bf3bfb8f24a7b3 -=
X 'github.com/google/syzkaller/prog.gitRevisionDate=3D20210220-100218'" -o =
./bin/syz-db github.com/google/syzkaller/tools/syz-db
>> GOOS=3Dlinux GOARCH=3Damd64 go build "-ldflags=3D-s -w -X github.com/goo=
gle/syzkaller/prog.GitRevision=3D3e5ed8b45e7a561d6344a4d3d7bf3bfb8f24a7b3 -=
X 'github.com/google/syzkaller/prog.gitRevisionDate=3D20210220-100218'" -o =
./bin/syz-upgrade github.com/google/syzkaller/tools/syz-upgrade
>> GOOS=3Dlinux GOARCH=3Darm64 go build "-ldflags=3D-s -w -X github.com/goo=
gle/syzkaller/prog.GitRevision=3D3e5ed8b45e7a561d6344a4d3d7bf3bfb8f24a7b3 -=
X 'github.com/google/syzkaller/prog.gitRevisionDate=3D20210220-100218'" "-t=
ags=3Dsyz_target syz_os_linux syz_arch_arm64 " -o ./bin/linux_arm64/syz-fuz=
zer github.com/google/syzkaller/syz-fuzzer
>> GOOS=3Dlinux GOARCH=3Darm64 go build "-ldflags=3D-s -w -X github.com/goo=
gle/syzkaller/prog.GitRevision=3D3e5ed8b45e7a561d6344a4d3d7bf3bfb8f24a7b3 -=
X 'github.com/google/syzkaller/prog.gitRevisionDate=3D20210220-100218'" "-t=
ags=3Dsyz_target syz_os_linux syz_arch_arm64 " -o ./bin/linux_arm64/syz-exe=
cprog github.com/google/syzkaller/tools/syz-execprog
>> GOOS=3Dlinux GOARCH=3Darm64 go build "-ldflags=3D-s -w -X github.com/goo=
gle/syzkaller/prog.GitRevision=3D3e5ed8b45e7a561d6344a4d3d7bf3bfb8f24a7b3 -=
X 'github.com/google/syzkaller/prog.gitRevisionDate=3D20210220-100218'" "-t=
ags=3Dsyz_target syz_os_linux syz_arch_arm64 " -o ./bin/linux_arm64/syz-str=
ess github.com/google/syzkaller/tools/syz-stress
>> mkdir -p ./bin/linux_arm64
>> /home/jin/syzkaller_arm/gcc-linaro/bin/aarch64-linux-gnu-g++ -o ./bin/li=
nux_arm64/syz-executor executor/executor.cc \
>> -O2 -pthread -Wall -Werror -Wparentheses -Wframe-larger-than=3D16384 -st=
atic  -DGOOS_linux=3D1 -DGOARCH_arm64=3D1 \
>> -DHOSTGOOS_linux=3D1 -DGIT_REVISION=3D\"3e5ed8b45e7a561d6344a4d3d7bf3bfb=
8f24a7b3\"
>> In file included from executor/common.h:436:0,
>>                  from executor/executor.cc:160:
>> executor/common_linux.h: In function =E2=80=98void netlink_add_geneve(nl=
msg*, int, const char*, uint32, in_addr*, in6_addr*)=E2=80=99:
>> executor/common_linux.h:392:22: error: =E2=80=98IFLA_GENEVE_ID=E2=80=99 =
was not declared in this scope
>>   netlink_attr(nlmsg, IFLA_GENEVE_ID, &vni, sizeof(vni));
>>                       ^
>> executor/common_linux.h:394:23: error: =E2=80=98IFLA_GENEVE_REMOTE=E2=80=
=99 was not declared in this scope
>>    netlink_attr(nlmsg, IFLA_GENEVE_REMOTE, addr4, sizeof(*addr4));
>>                        ^
>> executor/common_linux.h:396:23: error: =E2=80=98IFLA_GENEVE_REMOTE6=E2=
=80=99 was not declared in this scope
>>    netlink_attr(nlmsg, IFLA_GENEVE_REMOTE6, addr6, sizeof(*addr6));
>>                        ^
>> make: *** [Makefile:128: executor] Error 1
>> make: *** Waiting for unfinished jobs....
>>
>> Thank you
>> Best
>> Jin Huang
>
> --
> You received this message because you are subscribed to the Google Groups=
 "syzkaller" group.
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to syzkaller+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgi=
d/syzkaller/92bec3ec-ff7e-4aa3-b344-7b9e0daf4ae9n%40googlegroups.com.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BbWytKc_3Qz1hAYvZQiFbGvn%2BruAbgGm9wO9EtmUxxA1w%40mail.gm=
ail.com.
