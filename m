Return-Path: <kasan-dev+bncBCCMH5WKTMGRBV7X3DUAKGQEGVVVNIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 939655A06E
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2019 18:10:01 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id a21sf3396012pgh.11
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2019 09:10:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561738200; cv=pass;
        d=google.com; s=arc-20160816;
        b=s/OBZ+CdYwDxMVOyJ9EgF4sZLtG8Adv/IsaEg4Vgm7V0ujbkSKKP39QACHckcP8fAM
         Vueoc9fFcZ5LsJ2GFbmhpVpbM+qs8HBY0KosYCPct3cRFnotHAwQAtAJLWiaKp93XAGg
         ell/wUJBnHhUao4SImK3EbMIRYoEAzPDHJ60dmP0xcIIDMWo55536Rbl85hj74fjdYmi
         bo6/CA4oBD4wYybUkDp+qfIP2z4mYxkvbp2Y+ezYNcri26Ue+pkeWzQCpv8iYUKHn++6
         w3XFFKeMucc2/ThM6FbYJdEs7oHqKonh6OfvTQrxKrbyhuPvtmaTIGauGerXYxWiKCfL
         aYpw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=LbfXhPp5zHQY1bqVGbPd3bODGllPQQQDaPnmZRyjjuk=;
        b=vM943hawM2ic7zfJpOjldGIWQ2/kIxjtIpFITy3bP7hGeuokt9LdUzWjmDgvKfBrC9
         trKgctl51gz1lLIr0cBLvYfEcxF9m9G03w+pKxvynckfCKFo7sBXOgQ4uBDsm+I7zneU
         jeFaiyim6XeWqDnVEB5NneNIPcADCy2PR10ydx9cCwMmQ8x+qgijW6CLY9uzeuO2fU7S
         CBEf6KMlHcIniK/CsI7X4taxYOR3uAScPfp+BjE+st1/qZ/yzhVD97YCT1c+fJlmTJ3C
         MeobhCafYtbSOHcMh5ltXpUO0kFRSvALaT+A6giM6e9ksV4pHz56SdiEVhhXiVdsO9d/
         JM3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kOaD2Qm5;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::a34 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LbfXhPp5zHQY1bqVGbPd3bODGllPQQQDaPnmZRyjjuk=;
        b=KkjE2qR/rgjRA1jdfwMXNaBJz0mAwV0d6mMs1J8UwBvodUp/3pJpS3KzTuYDL7JMV4
         0fzMCMr8ceNjts5JXjLqwcscYLhHtrubd09jBXeWjrfyZrsYGRiZfCTqg/0YEWy4Nipd
         Gb5bW657KaiCpr9o55Ibd84UDFAmvLv2FViUAIuS2Sl9OjPFgK8y9bBlu44GYBrK9h9i
         O1uR0buYytUuPftrjiakl553hQh8PFKw3NoZwC06JR57hUEy8rzMCuqS6/+HmcpsoLM1
         y74CDikOvFOZlPFkPrET1YCAY5zfl297OR1u5VMf5IVMVahYtoi7ajiptIPPU2xhBywS
         TWVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LbfXhPp5zHQY1bqVGbPd3bODGllPQQQDaPnmZRyjjuk=;
        b=aaf4LL9CnOZqs365KQJKb6wsfTDevXoybvDGCrnnvGQ5cOvBhS4INklwylYQlOT6U6
         ftw+BLt8eksdkNOKMzsk2kw5g3DD6oZuNkjD8t7iwhL5xGSopPntxLeop92hdKS7GKby
         oz9vWCo+tHekLM1VKzXF9HSOzmLVLoI39EIR39rdIea+RZfC7TTbgd20/+Ra9KW9r5GH
         JebHjO09WelsWicuZtOhku8gSKlFcIV5SlMxnlloul9PCDXPjoGtv/znEIBlGCYgiNUS
         JCnY+o3kBVpuxcUWlw7Tkd8XACgPIs6nyKp7JHkDoe7dL+ZtNlF6KQHwF2TdunK7Fces
         jddg==
X-Gm-Message-State: APjAAAX9E8T+XxTu8O/UFfXQCsaEziC6MSsyF3DnFcoBUyXnowNZzJMn
	/bjT2xBvJ1b4Hh9Ag8TcUm4=
X-Google-Smtp-Source: APXvYqzNPsrTUs7YtbssVV7lKImbdEJyqaGs4t4+bBdbS9m4WQhSucnvKr6EDScDRMOIYF2CX+VNOg==
X-Received: by 2002:a63:2a83:: with SMTP id q125mr9865502pgq.102.1561738200080;
        Fri, 28 Jun 2019 09:10:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:2866:: with SMTP id e93ls1068225plb.10.gmail; Fri,
 28 Jun 2019 09:09:59 -0700 (PDT)
X-Received: by 2002:a17:902:3103:: with SMTP id w3mr12773945plb.84.1561738199575;
        Fri, 28 Jun 2019 09:09:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561738199; cv=none;
        d=google.com; s=arc-20160816;
        b=e4m0GzKMFMX41MT3t/V/mRL3OpuJMXFrnkTS2hMRtK6lFf0svtKquBFq3dKOZosEDa
         bUCB6txaqO+78X1hVeHMSUQBIXfwIf7dNkhmlumUHlWKCRrromn+qZx8u2hmsw9KvQWq
         9G7iGRVthqvdewcP8T0GRE/WuULDDFBl3fCFcyWX+DkloCiEgG9yCTvujwFK+uMmZ2+p
         HJiYH3qXcGha41n/MaDfhvtzEQrv/ljWbhvt0DvP3wvkVa337/dosdn2XJT2MpFTjUOC
         cDRTSXSdPRstoCZjoFF9DGhpouacaQqO0AArCv2+SOL14eXJypUEQ03Fdo4wMGRAXjW1
         Eplw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=VzwxPoo6R+h2aU4i3f+rMqPGWCZ+S79Xy+CKxNOyAZk=;
        b=jrBKJem95mnF4p45gsWxi2f49hdJiuE9S5PLjnX4fkguSpNZ6T76LxxDvQ3o4xO0jZ
         SZrR0VAe8obRgskxjsRNF507nG+mpB6je4R97QSPeQ3XfGaZ2FB9a+X08K0ZgmhIhHKC
         xSt0cFB+zSVYgAOXKfi86+2QdcCaTmNR8CBJ84dIKR3E5ZkwhJ5ps5z3trULOmC0aAVM
         J9D0DTk1zw/6wql5LLqTy/7SAsFDsPj90gvYr/qfxC1wUQYqTaldW4qQ3qPfxH+hKoEJ
         JrRZb5YA5nSj1NuXcYP9I0AJFp4XiezGRVH0C9q3qP8/2H1OzcatAzo2v5p6zhuIEbvZ
         RtZw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kOaD2Qm5;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::a34 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa34.google.com (mail-vk1-xa34.google.com. [2607:f8b0:4864:20::a34])
        by gmr-mx.google.com with ESMTPS id y13si105096pfl.3.2019.06.28.09.09.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Fri, 28 Jun 2019 09:09:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::a34 as permitted sender) client-ip=2607:f8b0:4864:20::a34;
Received: by mail-vk1-xa34.google.com with SMTP id b64so1329086vke.13
        for <kasan-dev@googlegroups.com>; Fri, 28 Jun 2019 09:09:59 -0700 (PDT)
X-Received: by 2002:a1f:5144:: with SMTP id f65mr4067769vkb.22.1561738198363;
 Fri, 28 Jun 2019 09:09:58 -0700 (PDT)
MIME-Version: 1.0
References: <CADvbK_fCWry5LRV-6yzkgLQXFj0_Qxi46gRrrO-ikOh8SbxQuA@mail.gmail.com>
 <CAG_fn=UoK7qE-x7NHN17GXGNctKoEKZe9rZ7QqP1otnSCfcJDw@mail.gmail.com>
 <CADvbK_fTGwW=HHhXFgatN7QzhNHoFTjmNH7orEdb3N1Gt+1fgg@mail.gmail.com>
 <CAG_fn=U-OBaRhPN7ab9dFcpchC1AftBN+wJMF+13FOBZORieUg@mail.gmail.com>
 <CAG_fn=W7Z31JjMio++4pWa67BNfZRzwtjnRC-_DQXQch1X=F5w@mail.gmail.com>
 <CADvbK_eeDPm2K3w2Y37fWeW=W=X3Kw6Lz9c10JyZC1vV0pYSEw@mail.gmail.com>
 <CAG_fn=VoQuryp2sGS6mVrQD3HnMFSC1MboCy0xSWA9mRCDS2NA@mail.gmail.com>
 <CADvbK_f06sZj3T5JK_X5pjjoA7FKDKQ51DO8ayF2yeFhh1NkJQ@mail.gmail.com>
 <CAG_fn=VS2R3apgDPOvu8+MGgifvD50qVEaj3kDwZsZ-BK33Ncg@mail.gmail.com>
 <CADvbK_d6vOZJK7KEu8pXi0WzaqJ4uDUz5TLYAd2GS=8hiD-VLg@mail.gmail.com>
 <CAG_fn=XYNq=o9nB42L=azEynMVSyNNKHPCJwePNNObk2z8Ahfw@mail.gmail.com> <CADvbK_eLaRPSgSANMXBRGLfCPx=D9r9nrr=vsb0tfo0f4rEVXg@mail.gmail.com>
In-Reply-To: <CADvbK_eLaRPSgSANMXBRGLfCPx=D9r9nrr=vsb0tfo0f4rEVXg@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 28 Jun 2019 18:09:44 +0200
Message-ID: <CAG_fn=VgE7b4V4fCFApxUKFeV46pSmXuNucAUqqMWUdMV+CrvA@mail.gmail.com>
Subject: Re: how to start kmsan kernel with qemu
To: lucien xin <lucien.xin@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Dmitriy Vyukov <dvyukov@google.com>
Content-Type: multipart/alternative; boundary="0000000000008c03d1058c6482fc"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=kOaD2Qm5;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::a34 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

--0000000000008c03d1058c6482fc
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Hm, now that's your Clang binary versus mine :)
Can you please ensure your git repo doesn't contain local changes and share
the commands you're using to build Clang?
(Both cmake and make or ninja)
Is the bug still reproducible in a clean CMake directory?

On Fri, 28 Jun 2019, 16:20 Xin Long, <lucien.xin@gmail.com> wrote:

> yes
>
> https://paste.fedoraproject.org/paste/DU2nnxpZWpWMri9Up7hypA
>
> On Fri, Jun 28, 2019 at 9:48 PM Alexander Potapenko <glider@google.com>
> wrote:
> >
> > Hm, strange, but I still can compile this file.
> > Does the following command line crash your compiler?
> > https://paste.fedoraproject.org/paste/oJwOVm5cHWyd7hxIZ4uGeA (note it
> > should be run from the same directory where process_64.i resides; also
> > make sure to invoke the right Clang)
> >
> > On Fri, Jun 28, 2019 at 3:35 PM Xin Long <lucien.xin@gmail.com> wrote:
> > >
> > > As attached, thanks.
> > >
> > > On Fri, Jun 28, 2019 at 9:24 PM Alexander Potapenko <glider@google.co=
m>
> wrote:
> > > >
> > > > On Fri, Jun 28, 2019 at 3:10 PM Xin Long <lucien.xin@gmail.com>
> wrote:
> > > > >
> > > > > This is what I did:
> > > > > https://paste.fedoraproject.org/paste/q4~GWx9Sx~QUbJQfNDoJIw
> > > > >
> > > > > There's no process_64.i file generated.
> > > > >
> > > > > Btw, I couldn't find "-c" in the command line, so there was no
> "-E" added.
> > > > Ah, right, Clang is invoked with -S. Could you replace that one wit=
h
> -E?
> > > > > On Fri, Jun 28, 2019 at 8:40 PM Alexander Potapenko <
> glider@google.com> wrote:
> > > > > >
> > > > > > It's interesting that you're seeing the same error as reported
> here:
> > > > > > https://github.com/google/kmsan/issues/53
> > > > > > I've updated my Clang to
> a4771e9dfdb0485c2edb416bfdc479d49de0aa14, but
> > > > > > the kernel compiles just fine.
> > > > > > May I ask you to do the following:
> > > > > >
> > > > > >  - run `make V=3D1` to capture the command line used to build
> > > > > > arch/x86/kernel/process_64.o
> > > > > >  - copy and paste the command line into a shell, remove '-o
> > > > > > /tmp/somefile' and run again to make sure the compiler still
> crashes
> > > > > >  - replace '-c' with '-E' in the command line and add '-o
> > > > > > process_64.i' to the end
> > > > > >  - send me the resulting preprocessed file (process_64.i)
> > > > > >
> > > > > > Thanks!
> > > > > >
> > > > > >
> > > > > >
> > > > > > On Thu, Jun 27, 2019 at 4:45 PM Xin Long <lucien.xin@gmail.com>
> wrote:
> > > > > > >
> > > > > > > Now I'm using:
> > > > > > > # Compiler: clang version 9.0.0
> > > > > > > (https://github.com/llvm/llvm-project.git
> > > > > > > a056684c335995214f6d3467c699d32f8e73b763)
> > > > > > >
> > > > > > > Errors shows up when building the kernel:
> > > > > > >
> > > > > > >   CC      arch/x86/kernel/process_64.o
> > > > > > > clang-9:
> /home/tools/llvm-project/llvm/lib/Transforms/Instrumentation/MemorySaniti=
zer.cpp:3236:
> > > > > > > void
> {anonymous}::MemorySanitizerVisitor::visitCallSite(llvm::CallSite):
> > > > > > > Assertion `(CS.isCall() || CS.isInvoke()) && "Unknown type of
> > > > > > > CallSite"' failed.
> > > > > > > Stack dump:
> > > > > > > 0.      Program arguments:
> /home/tools/llvm-project/build/bin/clang-9
> > > > > > > -cc1 -triple x86_64-unknown-linux-gnu -S -disable-free
> -main-file-name
> > > > > > > process_64.c -mrelocation-model static -mthread-model posix
> > > > > > > -fno-delete-null-pointer-checks -mllvm -warn-stack-size=3D204=
8
> > > > > > > -mdisable-fp-elim -relaxed-aliasing -mdisable-tail-calls
> -fmath-errno
> > > > > > > -masm-verbose -no-integrated-as -mconstructor-aliases
> -fuse-init-array
> > > > > > > -mcode-model kernel -target-cpu core2 -target-feature
> > > > > > > +retpoline-indirect-calls -target-feature
> +retpoline-indirect-branches
> > > > > > > -target-feature -sse -target-feature -mmx -target-feature -ss=
e2
> > > > > > > -target-feature -3dnow -target-feature -avx -target-feature
> -x87
> > > > > > > -target-feature +retpoline-external-thunk -disable-red-zone
> > > > > > > -dwarf-column-info -debug-info-kind=3Dlimited -dwarf-version=
=3D4
> > > > > > > -debugger-tuning=3Dgdb -momit-leaf-frame-pointer
> -coverage-notes-file
> > > > > > > /home/kmsan/arch/x86/kernel/process_64.gcno -nostdsysteminc
> > > > > > > -nobuiltininc -resource-dir
> > > > > > > /home/tools/llvm-project/build/lib/clang/9.0.0 -dependency-fi=
le
> > > > > > > arch/x86/kernel/.process_64.o.d -MT
> arch/x86/kernel/process_64.o
> > > > > > > -sys-header-deps -isystem
> > > > > > > /home/tools/llvm-project/build/lib/clang/9.0.0/include -inclu=
de
> > > > > > > ./include/linux/kconfig.h -include
> ./include/linux/compiler_types.h -I
> > > > > > > ./arch/x86/include -I ./arch/x86/include/generated -I
> ./include -I
> > > > > > > ./arch/x86/include/uapi -I ./arch/x86/include/generated/uapi =
-I
> > > > > > > ./include/uapi -I ./include/generated/uapi -D __KERNEL__ -D
> > > > > > > CONFIG_X86_X32_ABI -D CONFIG_AS_CFI=3D1 -D
> CONFIG_AS_CFI_SIGNAL_FRAME=3D1
> > > > > > > -D CONFIG_AS_CFI_SECTIONS=3D1 -D CONFIG_AS_SSSE3=3D1 -D
> CONFIG_AS_AVX=3D1 -D
> > > > > > > CONFIG_AS_AVX2=3D1 -D CONFIG_AS_AVX512=3D1 -D CONFIG_AS_SHA1_=
NI=3D1
> -D
> > > > > > > CONFIG_AS_SHA256_NI=3D1 -D KBUILD_BASENAME=3D"process_64" -D
> > > > > > > KBUILD_MODNAME=3D"process_64" -O2 -Wall -Wundef
> > > > > > > -Werror=3Dstrict-prototypes -Wno-trigraphs
> > > > > > > -Werror=3Dimplicit-function-declaration -Werror=3Dimplicit-in=
t
> > > > > > > -Wno-format-security -Wno-sign-compare
> -Wno-address-of-packed-member
> > > > > > > -Wno-format-invalid-specifier -Wno-gnu
> -Wno-tautological-compare
> > > > > > > -Wno-unused-const-variable -Wdeclaration-after-statement -Wvl=
a
> > > > > > > -Wno-pointer-sign -Werror=3Ddate-time
> -Werror=3Dincompatible-pointer-types
> > > > > > > -Wno-initializer-overrides -Wno-unused-value -Wno-format
> > > > > > > -Wno-sign-compare -Wno-format-zero-length -Wno-uninitialized
> > > > > > > -std=3Dgnu89 -fno-dwarf-directory-asm -fdebug-compilation-dir
> > > > > > > /home/kmsan -ferror-limit 19 -fmessage-length 0
> > > > > > > -fsanitize=3Dkernel-memory -fwrapv -stack-protector 2
> > > > > > > -mstack-alignment=3D8 -fwchar-type=3Dshort -fno-signed-wchar
> > > > > > > -fobjc-runtime=3Dgcc -fno-common -fdiagnostics-show-option
> > > > > > > -fcolor-diagnostics -vectorize-loops -vectorize-slp -o
> > > > > > > /tmp/process_64-e20ead.s -x c arch/x86/kernel/process_64.c
> > > > > > > 1.      <eof> parser at end of file
> > > > > > > 2.      Per-module optimization passes
> > > > > > > 3.      Running pass 'Function Pass Manager' on module
> > > > > > > 'arch/x86/kernel/process_64.c'.
> > > > > > > 4.      Running pass 'MemorySanitizerLegacyPass' on function
> '@start_thread'
> > > > > > >  #0 0x00000000024f03ba
> llvm::sys::PrintStackTrace(llvm::raw_ostream&)
> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x24f03ba)
> > > > > > >  #1 0x00000000024ee214 llvm::sys::RunSignalHandlers()
> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x24ee214)
> > > > > > >  #2 0x00000000024ee375 SignalHandler(int)
> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x24ee375)
> > > > > > >  #3 0x00007f85ed99bd80 __restore_rt
> (/lib64/libpthread.so.0+0x12d80)
> > > > > > >  #4 0x00007f85ec47c93f raise (/lib64/libc.so.6+0x3793f)
> > > > > > >  #5 0x00007f85ec466c95 abort (/lib64/libc.so.6+0x21c95)
> > > > > > >  #6 0x00007f85ec466b69 _nl_load_domain.cold.0
> (/lib64/libc.so.6+0x21b69)
> > > > > > >  #7 0x00007f85ec474df6 (/lib64/libc.so.6+0x2fdf6)
> > > > > > >  #8 0x000000000327b864 (anonymous
> > > > > > >
> namespace)::MemorySanitizerVisitor::visitCallSite(llvm::CallSite)
> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x327b864)
> > > > > > >  #9 0x0000000003283036 (anonymous
> > > > > > > namespace)::MemorySanitizerVisitor::runOnFunction()
> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x3283036)
> > > > > > > #10 0x000000000328605f (anonymous
> > > > > > > namespace)::MemorySanitizer::sanitizeFunction(llvm::Function&=
,
> > > > > > > llvm::TargetLibraryInfo&)
> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x328605f)
> > > > > > > #11 0x0000000001f42ac8
> > > > > > > llvm::FPPassManager::runOnFunction(llvm::Function&)
> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x1f42ac8)
> > > > > > > #12 0x0000000001f42be9
> llvm::FPPassManager::runOnModule(llvm::Module&)
> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x1f42be9)
> > > > > > > #13 0x0000000001f41ed8
> > > > > > > llvm::legacy::PassManagerImpl::run(llvm::Module&)
> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x1f41ed8)
> > > > > > > #14 0x00000000026fa4f8 (anonymous
> > > > > > >
> namespace)::EmitAssemblyHelper::EmitAssembly(clang::BackendAction,
> > > > > > > std::unique_ptr<llvm::raw_pwrite_stream,
> > > > > > > std::default_delete<llvm::raw_pwrite_stream> >)
> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x26fa4f8)
> > > > > > > #15 0x00000000026fbbf8
> > > > > > > clang::EmitBackendOutput(clang::DiagnosticsEngine&,
> > > > > > > clang::HeaderSearchOptions const&, clang::CodeGenOptions
> const&,
> > > > > > > clang::TargetOptions const&, clang::LangOptions const&,
> > > > > > > llvm::DataLayout const&, llvm::Module*, clang::BackendAction,
> > > > > > > std::unique_ptr<llvm::raw_pwrite_stream,
> > > > > > > std::default_delete<llvm::raw_pwrite_stream> >)
> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x26fbbf8)
> > > > > > > #16 0x000000000310234d
> > > > > > >
> clang::BackendConsumer::HandleTranslationUnit(clang::ASTContext&)
> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x310234d)
> > > > > > > #17 0x0000000003aaddf9 clang::ParseAST(clang::Sema&, bool,
> bool)
> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x3aaddf9)
> > > > > > > #18 0x00000000030fe5e0 clang::CodeGenAction::ExecuteAction()
> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x30fe5e0)
> > > > > > > #19 0x0000000002ba1929 clang::FrontendAction::Execute()
> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x2ba1929)
> > > > > > > #20 0x0000000002b68e62
> > > > > > > clang::CompilerInstance::ExecuteAction(clang::FrontendAction&=
)
> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x2b68e62)
> > > > > > > #21 0x0000000002c5738a
> > > > > > > clang::ExecuteCompilerInvocation(clang::CompilerInstance*)
> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x2c5738a)
> > > > > > > #22 0x00000000009cd1a6 cc1_main(llvm::ArrayRef<char const*>,
> char
> > > > > > > const*, void*)
> (/home/tools/llvm-project/build/bin/clang-9+0x9cd1a6)
> > > > > > > #23 0x000000000094cac1 main
> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x94cac1)
> > > > > > > #24 0x00007f85ec468813 __libc_start_main
> (/lib64/libc.so.6+0x23813)
> > > > > > > #25 0x00000000009c96ee _start
> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x9c96ee)
> > > > > > > clang-9: error: unable to execute command: Aborted (core
> dumped)
> > > > > > > clang-9: error: clang frontend command failed due to signal
> (use -v to
> > > > > > > see invocation)
> > > > > > > clang version 9.0.0 (https://github.com/llvm/llvm-project.git
> > > > > > > a056684c335995214f6d3467c699d32f8e73b763)
> > > > > > > Target: x86_64-unknown-linux-gnu
> > > > > > > Thread model: posix
> > > > > > > InstalledDir: /home/tools/llvm-project/build/bin
> > > > > > > clang-9: note: diagnostic msg: PLEASE submit a bug report to
> > > > > > > https://bugs.llvm.org/ and include the crash backtrace,
> preprocessed
> > > > > > > source, and associated run script.
> > > > > > > clang-9: note: diagnostic msg:
> > > > > > > ********************
> > > > > > >
> > > > > > > PLEASE ATTACH THE FOLLOWING FILES TO THE BUG REPORT:
> > > > > > > Preprocessed source(s) and associated run script(s) are
> located at:
> > > > > > > clang-9: note: diagnostic msg: /tmp/process_64-5fbbdc.c
> > > > > > > clang-9: note: diagnostic msg: /tmp/process_64-5fbbdc.sh
> > > > > > > clang-9: note: diagnostic msg:
> > > > > > >
> > > > > > > ********************
> > > > > > > make[2]: *** [scripts/Makefile.build:276:
> > > > > > > arch/x86/kernel/process_64.o] Error 254
> > > > > > >
> > > > > > >
> > > > > > > any idea why?
> > > > > > >
> > > > > > > On Thu, Jun 27, 2019 at 5:23 PM Alexander Potapenko <
> glider@google.com> wrote:
> > > > > > > >
> > > > > > > > Actually, your config says:
> > > > > > > >   "Compiler: clang version 8.0.0 (trunk 343298)"
> > > > > > > > I think you'll need at least Clang r362410 (mine is r362913=
)
> > > > > > > >
> > > > > > > > On Thu, Jun 27, 2019 at 11:20 AM Alexander Potapenko <
> glider@google.com> wrote:
> > > > > > > > >
> > > > > > > > > Hi Xin,
> > > > > > > > >
> > > > > > > > > Sorry for the late reply.
> > > > > > > > > I've built the ToT KMSAN tree using your config and my
> almost-ToT
> > > > > > > > > Clang and couldn't reproduce the problem.
> > > > > > > > > I believe something is wrong with your Clang version, as
> > > > > > > > > CONFIG_CLANG_VERSION should really be 90000.
> > > > > > > > > You can run `make V=3D1` to see which Clang version is be=
ing
> invoked -
> > > > > > > > > make sure it's a fresh one.
> > > > > > > > >
> > > > > > > > > HTH,
> > > > > > > > > Alex
> > > > > > > > >
> > > > > > > > > On Fri, Jun 21, 2019 at 10:09 PM Xin Long <
> lucien.xin@gmail.com> wrote:
> > > > > > > > > >
> > > > > > > > > > as attached,
> > > > > > > > > >
> > > > > > > > > > It actually came from
> https://syzkaller.appspot.com/x/.config?x=3D602468164ccdc30a
> > > > > > > > > > after I built, clang version changed to:
> > > > > > > > > >
> > > > > > > > > > CONFIG_CLANG_VERSION=3D80000
> > > > > > > > > >
> > > > > > > > > > On Sat, Jun 22, 2019 at 2:06 AM Alexander Potapenko <
> glider@google.com> wrote:
> > > > > > > > > > >
> > > > > > > > > > > Hi Xin,
> > > > > > > > > > >
> > > > > > > > > > > Could you please share the config you're using to
> build the kernel?
> > > > > > > > > > > I'll take a closer look on Monday when I am back to
> the office.
> > > > > > > > > > >
> > > > > > > > > > > On Fri, 21 Jun 2019, 18:15 Xin Long, <
> lucien.xin@gmail.com> wrote:
> > > > > > > > > > >>
> > > > > > > > > > >> this is my command:
> > > > > > > > > > >>
> > > > > > > > > > >> /usr/libexec/qemu-kvm -smp 2 -m 4G -enable-kvm -cpu
> host \
> > > > > > > > > > >>     -net nic -net user,hostfwd=3Dtcp::10022-:22 \
> > > > > > > > > > >>     -kernel /home/kmsan/arch/x86/boot/bzImage
> -nographic \
> > > > > > > > > > >>     -device virtio-scsi-pci,id=3Dscsi \
> > > > > > > > > > >>     -device scsi-hd,bus=3Dscsi.0,drive=3Dd0 \
> > > > > > > > > > >>     -drive
> file=3D/root/test/wheezy.img,format=3Draw,if=3Dnone,id=3Dd0 \
> > > > > > > > > > >>     -append "root=3D/dev/sda console=3DttyS0
> earlyprintk=3Dserial rodata=3Dn \
> > > > > > > > > > >>       oops=3Dpanic panic_on_warn=3D1 panic=3D86400
> kvm-intel.nested=3D1 \
> > > > > > > > > > >>       security=3Dapparmor ima_policy=3Dtcb
> workqueue.watchdog_thresh=3D140 \
> > > > > > > > > > >>       nf-conntrack-ftp.ports=3D20000
> nf-conntrack-tftp.ports=3D20000 \
> > > > > > > > > > >>       nf-conntrack-sip.ports=3D20000
> nf-conntrack-irc.ports=3D20000 \
> > > > > > > > > > >>       nf-conntrack-sane.ports=3D20000 vivid.n_devs=
=3D16 \
> > > > > > > > > > >>
>  vivid.multiplanar=3D1,2,1,2,1,2,1,2,1,2,1,2,1,2,1,2 \
> > > > > > > > > > >>       spec_store_bypass_disable=3Dprctl nopcid"
> > > > > > > > > > >>
> > > > > > > > > > >> the commit is on:
> > > > > > > > > > >> commit f75e4cfea97f67b7530b8b991b3005f991f04778 (HEA=
D)
> > > > > > > > > > >> Author: Alexander Potapenko <glider@google.com>
> > > > > > > > > > >> Date:   Wed May 22 12:30:13 2019 +0200
> > > > > > > > > > >>
> > > > > > > > > > >>     kmsan: use kmsan_handle_urb() in urb.c
> > > > > > > > > > >>
> > > > > > > > > > >> and when starting, it shows:
> > > > > > > > > > >> [    0.561925][    T0] Kernel command line:
> root=3D/dev/sda
> > > > > > > > > > >> console=3DttyS0 earlyprintk=3Dserial rodata=3Dn
>  oops=3Dpanic
> > > > > > > > > > >> panic_on_warn=3D1 panic=3D86400 kvm-intel.nested=3D1
>  security=3Dad
> > > > > > > > > > >> [    0.707792][    T0] Memory: 3087328K/4193776K
> available (219164K
> > > > > > > > > > >> kernel code, 7059K rwdata, 11712K rodata, 5064K init=
,
> 11904K bss,
> > > > > > > > > > >> 1106448K reserved, 0K cma-reserved)
> > > > > > > > > > >> [    0.710935][    T0] SLUB: HWalign=3D64, Order=3D0=
-3,
> MinObjects=3D0,
> > > > > > > > > > >> CPUs=3D2, Nodes=3D1
> > > > > > > > > > >> [    0.711953][    T0] Starting KernelMemorySanitize=
r
> > > > > > > > > > >> [    0.712563][    T0]
> > > > > > > > > > >>
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > > > > > > > > > >> [    0.713657][    T0] BUG: KMSAN: uninit-value in
> mutex_lock+0xd1/0xe0
> > > > > > > > > > >> [    0.714570][    T0] CPU: 0 PID: 0 Comm: swapper
> Not tainted 5.1.0 #5
> > > > > > > > > > >> [    0.715417][    T0] Hardware name: Red Hat KVM,
> BIOS
> > > > > > > > > > >> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01/2014
> > > > > > > > > > >> [    0.716659][    T0] Call Trace:
> > > > > > > > > > >> [    0.717127][    T0]  dump_stack+0x134/0x190
> > > > > > > > > > >> [    0.717727][    T0]  kmsan_report+0x131/0x2a0
> > > > > > > > > > >> [    0.718347][    T0]  __msan_warning+0x7a/0xf0
> > > > > > > > > > >> [    0.718952][    T0]  mutex_lock+0xd1/0xe0
> > > > > > > > > > >> [    0.719478][    T0]
> __cpuhp_setup_state_cpuslocked+0x149/0xd20
> > > > > > > > > > >> [    0.720260][    T0]  ? vprintk_func+0x6b5/0x8a0
> > > > > > > > > > >> [    0.720926][    T0]  ?
> rb_get_reader_page+0x1140/0x1140
> > > > > > > > > > >> [    0.721632][    T0]
> __cpuhp_setup_state+0x181/0x2e0
> > > > > > > > > > >> [    0.722374][    T0]  ?
> rb_get_reader_page+0x1140/0x1140
> > > > > > > > > > >> [    0.723115][    T0]
> tracer_alloc_buffers+0x16b/0xb96
> > > > > > > > > > >> [    0.723846][    T0]  early_trace_init+0x193/0x28f
> > > > > > > > > > >> [    0.724501][    T0]  start_kernel+0x497/0xb38
> > > > > > > > > > >> [    0.725134][    T0]
> x86_64_start_reservations+0x19/0x2f
> > > > > > > > > > >> [    0.725871][    T0]  x86_64_start_kernel+0x84/0x8=
7
> > > > > > > > > > >> [    0.726538][    T0]  secondary_startup_64+0xa4/0x=
b0
> > > > > > > > > > >> [    0.727173][    T0]
> > > > > > > > > > >> [    0.727454][    T0] Local variable description:
> > > > > > > > > > >> ----success.i.i.i.i@mutex_lock
> > > > > > > > > > >> [    0.728379][    T0] Variable was created at:
> > > > > > > > > > >> [    0.728977][    T0]  mutex_lock+0x48/0xe0
> > > > > > > > > > >> [    0.729536][    T0]
> __cpuhp_setup_state_cpuslocked+0x149/0xd20
> > > > > > > > > > >> [    0.730323][    T0]
> > > > > > > > > > >>
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > > > > > > > > > >> [    0.731364][    T0] Disabling lock debugging due
> to kernel taint
> > > > > > > > > > >> [    0.732169][    T0] Kernel panic - not syncing:
> panic_on_warn set ...
> > > > > > > > > > >> [    0.733047][    T0] CPU: 0 PID: 0 Comm: swapper
> Tainted: G    B
> > > > > > > > > > >>         5.1.0 #5
> > > > > > > > > > >> [    0.734080][    T0] Hardware name: Red Hat KVM,
> BIOS
> > > > > > > > > > >> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01/2014
> > > > > > > > > > >> [    0.735319][    T0] Call Trace:
> > > > > > > > > > >> [    0.735735][    T0]  dump_stack+0x134/0x190
> > > > > > > > > > >> [    0.736308][    T0]  panic+0x3ec/0xb3b
> > > > > > > > > > >> [    0.736826][    T0]  kmsan_report+0x29a/0x2a0
> > > > > > > > > > >> [    0.737417][    T0]  __msan_warning+0x7a/0xf0
> > > > > > > > > > >> [    0.737973][    T0]  mutex_lock+0xd1/0xe0
> > > > > > > > > > >> [    0.738527][    T0]
> __cpuhp_setup_state_cpuslocked+0x149/0xd20
> > > > > > > > > > >> [    0.739342][    T0]  ? vprintk_func+0x6b5/0x8a0
> > > > > > > > > > >> [    0.739972][    T0]  ?
> rb_get_reader_page+0x1140/0x1140
> > > > > > > > > > >> [    0.740695][    T0]
> __cpuhp_setup_state+0x181/0x2e0
> > > > > > > > > > >> [    0.741412][    T0]  ?
> rb_get_reader_page+0x1140/0x1140
> > > > > > > > > > >> [    0.742160][    T0]
> tracer_alloc_buffers+0x16b/0xb96
> > > > > > > > > > >> [    0.742866][    T0]  early_trace_init+0x193/0x28f
> > > > > > > > > > >> [    0.743512][    T0]  start_kernel+0x497/0xb38
> > > > > > > > > > >> [    0.744128][    T0]
> x86_64_start_reservations+0x19/0x2f
> > > > > > > > > > >> [    0.744863][    T0]  x86_64_start_kernel+0x84/0x8=
7
> > > > > > > > > > >> [    0.745534][    T0]  secondary_startup_64+0xa4/0x=
b0
> > > > > > > > > > >> [    0.746290][    T0] Rebooting in 86400 seconds..
> > > > > > > > > > >>
> > > > > > > > > > >> when I set "panic_on_warn=3D0", it foods the console
> with:
> > > > > > > > > > >> ...
> > > > > > > > > > >> [   25.206759][    C0] Variable was created at:
> > > > > > > > > > >> [   25.207302][    C0]  vprintk_emit+0xf4/0x800
> > > > > > > > > > >> [   25.207844][    C0]  vprintk_deferred+0x90/0xed
> > > > > > > > > > >> [   25.208404][    C0]
> > > > > > > > > > >>
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > > > > > > > > > >> [   25.209763][    C0]
> x86_64_start_reservations+0x19/0x2f
> > > > > > > > > > >> [   25.209769][    C0]
> > > > > > > > > > >>
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > > > > > > > > > >> [   25.211408][    C0] BUG: KMSAN: uninit-value in
> vprintk_emit+0x443/0x800
> > > > > > > > > > >> [   25.212237][    C0] CPU: 0 PID: 0 Comm: swapper/0
> Tainted: G    B
> > > > > > > > > > >>           5.1.0 #5
> > > > > > > > > > >> [   25.213206][    C0] Hardware name: Red Hat KVM,
> BIOS
> > > > > > > > > > >> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01/2014
> > > > > > > > > > >> [   25.214326][    C0] Call Trace:
> > > > > > > > > > >> [   25.214725][    C0]  <IRQ>
> > > > > > > > > > >> [   25.215080][    C0]  dump_stack+0x134/0x190
> > > > > > > > > > >> [   25.215624][    C0]  kmsan_report+0x131/0x2a0
> > > > > > > > > > >> [   25.216204][    C0]  __msan_warning+0x7a/0xf0
> > > > > > > > > > >> [   25.216771][    C0]  vprintk_emit+0x443/0x800
> > > > > > > > > > >> [   25.217334][    C0]  ?
> __msan_metadata_ptr_for_store_1+0x13/0x20
> > > > > > > > > > >> [   25.218127][    C0]  vprintk_deferred+0x90/0xed
> > > > > > > > > > >> [   25.218714][    C0]  printk_deferred+0x186/0x1d3
> > > > > > > > > > >> [   25.219353][    C0]
> __printk_safe_flush+0x72e/0xc00
> > > > > > > > > > >> [   25.220006][    C0]  ?
> printk_safe_flush+0x1e0/0x1e0
> > > > > > > > > > >> [   25.220635][    C0]  irq_work_run+0x1ad/0x5c0
> > > > > > > > > > >> [   25.221210][    C0]  ?
> flat_init_apic_ldr+0x170/0x170
> > > > > > > > > > >> [   25.221851][    C0]
> smp_irq_work_interrupt+0x237/0x3e0
> > > > > > > > > > >> [   25.222520][    C0]  irq_work_interrupt+0x2e/0x40
> > > > > > > > > > >> [   25.223110][    C0]  </IRQ>
> > > > > > > > > > >> [   25.223475][    C0] RIP:
> 0010:kmem_cache_init_late+0x0/0xb
> > > > > > > > > > >> [   25.224164][    C0] Code: d4 e8 5d dd 2e f2 e9 74
> fe ff ff 48 89 d3
> > > > > > > > > > >> 8b 7d d4 e8 cd d7 2e f2 89 c0 48 89 c1 48 c1 e1 20 4=
8
> 09 c1 48 89 0b
> > > > > > > > > > >> e9 81 fe ff ff <55> 48 89 e5 e8 20 de 2e1
> > > > > > > > > > >> [   25.226526][    C0] RSP: 0000:ffffffff8f40feb8
> EFLAGS: 00000246
> > > > > > > > > > >> ORIG_RAX: ffffffffffffff09
> > > > > > > > > > >> [   25.227548][    C0] RAX: ffff88813f995785 RBX:
> 0000000000000000
> > > > > > > > > > >> RCX: 0000000000000000
> > > > > > > > > > >> [   25.228511][    C0] RDX: ffff88813f2b0784 RSI:
> 0000160000000000
> > > > > > > > > > >> RDI: 0000000000000785
> > > > > > > > > > >> [   25.229473][    C0] RBP: ffffffff8f40ff20 R08:
> 000000000fac3785
> > > > > > > > > > >> R09: 0000778000000001
> > > > > > > > > > >> [   25.230440][    C0] R10: ffffd0ffffffffff R11:
> 0000100000000000
> > > > > > > > > > >> R12: 0000000000000000
> > > > > > > > > > >> [   25.231403][    C0] R13: 0000000000000000 R14:
> ffffffff8fb8cfd0
> > > > > > > > > > >> R15: 0000000000000000
> > > > > > > > > > >> [   25.232407][    C0]  ? start_kernel+0x5d8/0xb38
> > > > > > > > > > >> [   25.233003][    C0]
> x86_64_start_reservations+0x19/0x2f
> > > > > > > > > > >> [   25.233670][    C0]  x86_64_start_kernel+0x84/0x8=
7
> > > > > > > > > > >> [   25.234314][    C0]  secondary_startup_64+0xa4/0x=
b0
> > > > > > > > > > >> [   25.234949][    C0]
> > > > > > > > > > >> [   25.235231][    C0] Local variable description:
> ----flags.i.i.i@vprintk_emit
> > > > > > > > > > >> [   25.236101][    C0] Variable was created at:
> > > > > > > > > > >> [   25.236643][    C0]  vprintk_emit+0xf4/0x800
> > > > > > > > > > >> [   25.237188][    C0]  vprintk_deferred+0x90/0xed
> > > > > > > > > > >> [   25.237752][    C0]
> > > > > > > > > > >>
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > > > > > > > > > >> [   25.239117][    C0]  x86_64_start_kernel+0x84/0x8=
7
> > > > > > > > > > >> [   25.239123][    C0]
> > > > > > > > > > >>
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > > > > > > > > > >> [   25.240704][    C0] BUG: KMSAN: uninit-value in
> vprintk_emit+0x443/0x800
> > > > > > > > > > >> [   25.241540][    C0] CPU: 0 PID: 0 Comm: swapper/0
> Tainted: G    B
> > > > > > > > > > >>           5.1.0 #5
> > > > > > > > > > >> [   25.242512][    C0] Hardware name: Red Hat KVM,
> BIOS
> > > > > > > > > > >> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01/2014
> > > > > > > > > > >> [   25.243635][    C0] Call Trace:
> > > > > > > > > > >> [   25.244038][    C0]  <IRQ>
> > > > > > > > > > >> [   25.244390][    C0]  dump_stack+0x134/0x190
> > > > > > > > > > >> [   25.244940][    C0]  kmsan_report+0x131/0x2a0
> > > > > > > > > > >> [   25.245515][    C0]  __msan_warning+0x7a/0xf0
> > > > > > > > > > >> [   25.246082][    C0]  vprintk_emit+0x443/0x800
> > > > > > > > > > >> [   25.246638][    C0]  ?
> __msan_metadata_ptr_for_store_1+0x13/0x20
> > > > > > > > > > >> [   25.247430][    C0]  vprintk_deferred+0x90/0xed
> > > > > > > > > > >> [   25.248018][    C0]  printk_deferred+0x186/0x1d3
> > > > > > > > > > >> [   25.248650][    C0]
> __printk_safe_flush+0x72e/0xc00
> > > > > > > > > > >> [   25.249320][    C0]  ?
> printk_safe_flush+0x1e0/0x1e0
> > > > > > > > > > >> [   25.249949][    C0]  irq_work_run+0x1ad/0x5c0
> > > > > > > > > > >> [   25.250524][    C0]  ?
> flat_init_apic_ldr+0x170/0x170
> > > > > > > > > > >> [   25.251167][    C0]
> smp_irq_work_interrupt+0x237/0x3e0
> > > > > > > > > > >> [   25.251837][    C0]  irq_work_interrupt+0x2e/0x40
> > > > > > > > > > >> [   25.252424][    C0]  </IRQ>
> > > > > > > > > > >> ....
> > > > > > > > > > >>
> > > > > > > > > > >>
> > > > > > > > > > >> I couldn't even log in.
> > > > > > > > > > >>
> > > > > > > > > > >> how should I use qemu with wheezy.img to start a
> kmsan kernel?
> > > > > > > > > > >>
> > > > > > > > > > >> Thanks.
> > > > > > > > >
> > > > > > > > >
> > > > > > > > >
> > > > > > > > > --
> > > > > > > > > Alexander Potapenko
> > > > > > > > > Software Engineer
> > > > > > > > >
> > > > > > > > > Google Germany GmbH
> > > > > > > > > Erika-Mann-Stra=C3=9Fe, 33
> > > > > > > > > 80636 M=C3=BCnchen
> > > > > > > > >
> > > > > > > > > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine =
Prado
> > > > > > > > > Registergericht und -nummer: Hamburg, HRB 86891
> > > > > > > > > Sitz der Gesellschaft: Hamburg
> > > > > > > >
> > > > > > > >
> > > > > > > >
> > > > > > > > --
> > > > > > > > Alexander Potapenko
> > > > > > > > Software Engineer
> > > > > > > >
> > > > > > > > Google Germany GmbH
> > > > > > > > Erika-Mann-Stra=C3=9Fe, 33
> > > > > > > > 80636 M=C3=BCnchen
> > > > > > > >
> > > > > > > > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Pr=
ado
> > > > > > > > Registergericht und -nummer: Hamburg, HRB 86891
> > > > > > > > Sitz der Gesellschaft: Hamburg
> > > > > >
> > > > > >
> > > > > >
> > > > > > --
> > > > > > Alexander Potapenko
> > > > > > Software Engineer
> > > > > >
> > > > > > Google Germany GmbH
> > > > > > Erika-Mann-Stra=C3=9Fe, 33
> > > > > > 80636 M=C3=BCnchen
> > > > > >
> > > > > > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
> > > > > > Registergericht und -nummer: Hamburg, HRB 86891
> > > > > > Sitz der Gesellschaft: Hamburg
> > > >
> > > >
> > > >
> > > > --
> > > > Alexander Potapenko
> > > > Software Engineer
> > > >
> > > > Google Germany GmbH
> > > > Erika-Mann-Stra=C3=9Fe, 33
> > > > 80636 M=C3=BCnchen
> > > >
> > > > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
> > > > Registergericht und -nummer: Hamburg, HRB 86891
> > > > Sitz der Gesellschaft: Hamburg
> >
> >
> >
> > --
> > Alexander Potapenko
> > Software Engineer
> >
> > Google Germany GmbH
> > Erika-Mann-Stra=C3=9Fe, 33
> > 80636 M=C3=BCnchen
> >
> > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
> > Registergericht und -nummer: Hamburg, HRB 86891
> > Sitz der Gesellschaft: Hamburg
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVgE7b4V4fCFApxUKFeV46pSmXuNucAUqqMWUdMV%2BCrvA%40mail.gm=
ail.com.
For more options, visit https://groups.google.com/d/optout.

--0000000000008c03d1058c6482fc
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"auto">Hm, now that&#39;s your Clang binary versus mine :)<div d=
ir=3D"auto">Can you please ensure your git repo doesn&#39;t contain local c=
hanges and share the commands you&#39;re using to build Clang?</div><div di=
r=3D"auto">(Both cmake and make or ninja)</div><div dir=3D"auto">Is the bug=
 still reproducible in a clean CMake directory?</div></div><br><div class=
=3D"gmail_quote"><div dir=3D"ltr" class=3D"gmail_attr">On Fri, 28 Jun 2019,=
 16:20 Xin Long, &lt;<a href=3D"mailto:lucien.xin@gmail.com">lucien.xin@gma=
il.com</a>&gt; wrote:<br></div><blockquote class=3D"gmail_quote" style=3D"m=
argin:0 0 0 .8ex;border-left:1px #ccc solid;padding-left:1ex">yes<br>
<br>
<a href=3D"https://paste.fedoraproject.org/paste/DU2nnxpZWpWMri9Up7hypA" re=
l=3D"noreferrer noreferrer" target=3D"_blank">https://paste.fedoraproject.o=
rg/paste/DU2nnxpZWpWMri9Up7hypA</a><br>
<br>
On Fri, Jun 28, 2019 at 9:48 PM Alexander Potapenko &lt;<a href=3D"mailto:g=
lider@google.com" target=3D"_blank" rel=3D"noreferrer">glider@google.com</a=
>&gt; wrote:<br>
&gt;<br>
&gt; Hm, strange, but I still can compile this file.<br>
&gt; Does the following command line crash your compiler?<br>
&gt; <a href=3D"https://paste.fedoraproject.org/paste/oJwOVm5cHWyd7hxIZ4uGe=
A" rel=3D"noreferrer noreferrer" target=3D"_blank">https://paste.fedoraproj=
ect.org/paste/oJwOVm5cHWyd7hxIZ4uGeA</a> (note it<br>
&gt; should be run from the same directory where process_64.i resides; also=
<br>
&gt; make sure to invoke the right Clang)<br>
&gt;<br>
&gt; On Fri, Jun 28, 2019 at 3:35 PM Xin Long &lt;<a href=3D"mailto:lucien.=
xin@gmail.com" target=3D"_blank" rel=3D"noreferrer">lucien.xin@gmail.com</a=
>&gt; wrote:<br>
&gt; &gt;<br>
&gt; &gt; As attached, thanks.<br>
&gt; &gt;<br>
&gt; &gt; On Fri, Jun 28, 2019 at 9:24 PM Alexander Potapenko &lt;<a href=
=3D"mailto:glider@google.com" target=3D"_blank" rel=3D"noreferrer">glider@g=
oogle.com</a>&gt; wrote:<br>
&gt; &gt; &gt;<br>
&gt; &gt; &gt; On Fri, Jun 28, 2019 at 3:10 PM Xin Long &lt;<a href=3D"mail=
to:lucien.xin@gmail.com" target=3D"_blank" rel=3D"noreferrer">lucien.xin@gm=
ail.com</a>&gt; wrote:<br>
&gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; This is what I did:<br>
&gt; &gt; &gt; &gt; <a href=3D"https://paste.fedoraproject.org/paste/q4~GWx=
9Sx~QUbJQfNDoJIw" rel=3D"noreferrer noreferrer" target=3D"_blank">https://p=
aste.fedoraproject.org/paste/q4~GWx9Sx~QUbJQfNDoJIw</a><br>
&gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; There&#39;s no process_64.i file generated.<br>
&gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; Btw, I couldn&#39;t find &quot;-c&quot; in the command =
line, so there was no &quot;-E&quot; added.<br>
&gt; &gt; &gt; Ah, right, Clang is invoked with -S. Could you replace that =
one with -E?<br>
&gt; &gt; &gt; &gt; On Fri, Jun 28, 2019 at 8:40 PM Alexander Potapenko &lt=
;<a href=3D"mailto:glider@google.com" target=3D"_blank" rel=3D"noreferrer">=
glider@google.com</a>&gt; wrote:<br>
&gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt; It&#39;s interesting that you&#39;re seeing the sa=
me error as reported here:<br>
&gt; &gt; &gt; &gt; &gt; <a href=3D"https://github.com/google/kmsan/issues/=
53" rel=3D"noreferrer noreferrer" target=3D"_blank">https://github.com/goog=
le/kmsan/issues/53</a><br>
&gt; &gt; &gt; &gt; &gt; I&#39;ve updated my Clang to a4771e9dfdb0485c2edb4=
16bfdc479d49de0aa14, but<br>
&gt; &gt; &gt; &gt; &gt; the kernel compiles just fine.<br>
&gt; &gt; &gt; &gt; &gt; May I ask you to do the following:<br>
&gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt;=C2=A0 - run `make V=3D1` to capture the command li=
ne used to build<br>
&gt; &gt; &gt; &gt; &gt; arch/x86/kernel/process_64.o<br>
&gt; &gt; &gt; &gt; &gt;=C2=A0 - copy and paste the command line into a she=
ll, remove &#39;-o<br>
&gt; &gt; &gt; &gt; &gt; /tmp/somefile&#39; and run again to make sure the =
compiler still crashes<br>
&gt; &gt; &gt; &gt; &gt;=C2=A0 - replace &#39;-c&#39; with &#39;-E&#39; in =
the command line and add &#39;-o<br>
&gt; &gt; &gt; &gt; &gt; process_64.i&#39; to the end<br>
&gt; &gt; &gt; &gt; &gt;=C2=A0 - send me the resulting preprocessed file (p=
rocess_64.i)<br>
&gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt; Thanks!<br>
&gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt; On Thu, Jun 27, 2019 at 4:45 PM Xin Long &lt;<a hr=
ef=3D"mailto:lucien.xin@gmail.com" target=3D"_blank" rel=3D"noreferrer">luc=
ien.xin@gmail.com</a>&gt; wrote:<br>
&gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; Now I&#39;m using:<br>
&gt; &gt; &gt; &gt; &gt; &gt; # Compiler: clang version 9.0.0<br>
&gt; &gt; &gt; &gt; &gt; &gt; (<a href=3D"https://github.com/llvm/llvm-proj=
ect.git" rel=3D"noreferrer noreferrer" target=3D"_blank">https://github.com=
/llvm/llvm-project.git</a><br>
&gt; &gt; &gt; &gt; &gt; &gt; a056684c335995214f6d3467c699d32f8e73b763)<br>
&gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; Errors shows up when building the kernel:<br>
&gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt;=C2=A0 =C2=A0CC=C2=A0 =C2=A0 =C2=A0 arch/x86/k=
ernel/process_64.o<br>
&gt; &gt; &gt; &gt; &gt; &gt; clang-9: /home/tools/llvm-project/llvm/lib/Tr=
ansforms/Instrumentation/MemorySanitizer.cpp:3236:<br>
&gt; &gt; &gt; &gt; &gt; &gt; void {anonymous}::MemorySanitizerVisitor::vis=
itCallSite(llvm::CallSite):<br>
&gt; &gt; &gt; &gt; &gt; &gt; Assertion `(CS.isCall() || CS.isInvoke()) &am=
p;&amp; &quot;Unknown type of<br>
&gt; &gt; &gt; &gt; &gt; &gt; CallSite&quot;&#39; failed.<br>
&gt; &gt; &gt; &gt; &gt; &gt; Stack dump:<br>
&gt; &gt; &gt; &gt; &gt; &gt; 0.=C2=A0 =C2=A0 =C2=A0 Program arguments: /ho=
me/tools/llvm-project/build/bin/clang-9<br>
&gt; &gt; &gt; &gt; &gt; &gt; -cc1 -triple x86_64-unknown-linux-gnu -S -dis=
able-free -main-file-name<br>
&gt; &gt; &gt; &gt; &gt; &gt; process_64.c -mrelocation-model static -mthre=
ad-model posix<br>
&gt; &gt; &gt; &gt; &gt; &gt; -fno-delete-null-pointer-checks -mllvm -warn-=
stack-size=3D2048<br>
&gt; &gt; &gt; &gt; &gt; &gt; -mdisable-fp-elim -relaxed-aliasing -mdisable=
-tail-calls -fmath-errno<br>
&gt; &gt; &gt; &gt; &gt; &gt; -masm-verbose -no-integrated-as -mconstructor=
-aliases -fuse-init-array<br>
&gt; &gt; &gt; &gt; &gt; &gt; -mcode-model kernel -target-cpu core2 -target=
-feature<br>
&gt; &gt; &gt; &gt; &gt; &gt; +retpoline-indirect-calls -target-feature +re=
tpoline-indirect-branches<br>
&gt; &gt; &gt; &gt; &gt; &gt; -target-feature -sse -target-feature -mmx -ta=
rget-feature -sse2<br>
&gt; &gt; &gt; &gt; &gt; &gt; -target-feature -3dnow -target-feature -avx -=
target-feature -x87<br>
&gt; &gt; &gt; &gt; &gt; &gt; -target-feature +retpoline-external-thunk -di=
sable-red-zone<br>
&gt; &gt; &gt; &gt; &gt; &gt; -dwarf-column-info -debug-info-kind=3Dlimited=
 -dwarf-version=3D4<br>
&gt; &gt; &gt; &gt; &gt; &gt; -debugger-tuning=3Dgdb -momit-leaf-frame-poin=
ter -coverage-notes-file<br>
&gt; &gt; &gt; &gt; &gt; &gt; /home/kmsan/arch/x86/kernel/process_64.gcno -=
nostdsysteminc<br>
&gt; &gt; &gt; &gt; &gt; &gt; -nobuiltininc -resource-dir<br>
&gt; &gt; &gt; &gt; &gt; &gt; /home/tools/llvm-project/build/lib/clang/9.0.=
0 -dependency-file<br>
&gt; &gt; &gt; &gt; &gt; &gt; arch/x86/kernel/.process_64.o.d -MT arch/x86/=
kernel/process_64.o<br>
&gt; &gt; &gt; &gt; &gt; &gt; -sys-header-deps -isystem<br>
&gt; &gt; &gt; &gt; &gt; &gt; /home/tools/llvm-project/build/lib/clang/9.0.=
0/include -include<br>
&gt; &gt; &gt; &gt; &gt; &gt; ./include/linux/kconfig.h -include ./include/=
linux/compiler_types.h -I<br>
&gt; &gt; &gt; &gt; &gt; &gt; ./arch/x86/include -I ./arch/x86/include/gene=
rated -I ./include -I<br>
&gt; &gt; &gt; &gt; &gt; &gt; ./arch/x86/include/uapi -I ./arch/x86/include=
/generated/uapi -I<br>
&gt; &gt; &gt; &gt; &gt; &gt; ./include/uapi -I ./include/generated/uapi -D=
 __KERNEL__ -D<br>
&gt; &gt; &gt; &gt; &gt; &gt; CONFIG_X86_X32_ABI -D CONFIG_AS_CFI=3D1 -D CO=
NFIG_AS_CFI_SIGNAL_FRAME=3D1<br>
&gt; &gt; &gt; &gt; &gt; &gt; -D CONFIG_AS_CFI_SECTIONS=3D1 -D CONFIG_AS_SS=
SE3=3D1 -D CONFIG_AS_AVX=3D1 -D<br>
&gt; &gt; &gt; &gt; &gt; &gt; CONFIG_AS_AVX2=3D1 -D CONFIG_AS_AVX512=3D1 -D=
 CONFIG_AS_SHA1_NI=3D1 -D<br>
&gt; &gt; &gt; &gt; &gt; &gt; CONFIG_AS_SHA256_NI=3D1 -D KBUILD_BASENAME=3D=
&quot;process_64&quot; -D<br>
&gt; &gt; &gt; &gt; &gt; &gt; KBUILD_MODNAME=3D&quot;process_64&quot; -O2 -=
Wall -Wundef<br>
&gt; &gt; &gt; &gt; &gt; &gt; -Werror=3Dstrict-prototypes -Wno-trigraphs<br=
>
&gt; &gt; &gt; &gt; &gt; &gt; -Werror=3Dimplicit-function-declaration -Werr=
or=3Dimplicit-int<br>
&gt; &gt; &gt; &gt; &gt; &gt; -Wno-format-security -Wno-sign-compare -Wno-a=
ddress-of-packed-member<br>
&gt; &gt; &gt; &gt; &gt; &gt; -Wno-format-invalid-specifier -Wno-gnu -Wno-t=
autological-compare<br>
&gt; &gt; &gt; &gt; &gt; &gt; -Wno-unused-const-variable -Wdeclaration-afte=
r-statement -Wvla<br>
&gt; &gt; &gt; &gt; &gt; &gt; -Wno-pointer-sign -Werror=3Ddate-time -Werror=
=3Dincompatible-pointer-types<br>
&gt; &gt; &gt; &gt; &gt; &gt; -Wno-initializer-overrides -Wno-unused-value =
-Wno-format<br>
&gt; &gt; &gt; &gt; &gt; &gt; -Wno-sign-compare -Wno-format-zero-length -Wn=
o-uninitialized<br>
&gt; &gt; &gt; &gt; &gt; &gt; -std=3Dgnu89 -fno-dwarf-directory-asm -fdebug=
-compilation-dir<br>
&gt; &gt; &gt; &gt; &gt; &gt; /home/kmsan -ferror-limit 19 -fmessage-length=
 0<br>
&gt; &gt; &gt; &gt; &gt; &gt; -fsanitize=3Dkernel-memory -fwrapv -stack-pro=
tector 2<br>
&gt; &gt; &gt; &gt; &gt; &gt; -mstack-alignment=3D8 -fwchar-type=3Dshort -f=
no-signed-wchar<br>
&gt; &gt; &gt; &gt; &gt; &gt; -fobjc-runtime=3Dgcc -fno-common -fdiagnostic=
s-show-option<br>
&gt; &gt; &gt; &gt; &gt; &gt; -fcolor-diagnostics -vectorize-loops -vectori=
ze-slp -o<br>
&gt; &gt; &gt; &gt; &gt; &gt; /tmp/process_64-e20ead.s -x c arch/x86/kernel=
/process_64.c<br>
&gt; &gt; &gt; &gt; &gt; &gt; 1.=C2=A0 =C2=A0 =C2=A0 &lt;eof&gt; parser at =
end of file<br>
&gt; &gt; &gt; &gt; &gt; &gt; 2.=C2=A0 =C2=A0 =C2=A0 Per-module optimizatio=
n passes<br>
&gt; &gt; &gt; &gt; &gt; &gt; 3.=C2=A0 =C2=A0 =C2=A0 Running pass &#39;Func=
tion Pass Manager&#39; on module<br>
&gt; &gt; &gt; &gt; &gt; &gt; &#39;arch/x86/kernel/process_64.c&#39;.<br>
&gt; &gt; &gt; &gt; &gt; &gt; 4.=C2=A0 =C2=A0 =C2=A0 Running pass &#39;Memo=
rySanitizerLegacyPass&#39; on function &#39;@start_thread&#39;<br>
&gt; &gt; &gt; &gt; &gt; &gt;=C2=A0 #0 0x00000000024f03ba llvm::sys::PrintS=
tackTrace(llvm::raw_ostream&amp;)<br>
&gt; &gt; &gt; &gt; &gt; &gt; (/home/tools/llvm-project/build/bin/clang-9+0=
x24f03ba)<br>
&gt; &gt; &gt; &gt; &gt; &gt;=C2=A0 #1 0x00000000024ee214 llvm::sys::RunSig=
nalHandlers()<br>
&gt; &gt; &gt; &gt; &gt; &gt; (/home/tools/llvm-project/build/bin/clang-9+0=
x24ee214)<br>
&gt; &gt; &gt; &gt; &gt; &gt;=C2=A0 #2 0x00000000024ee375 SignalHandler(int=
)<br>
&gt; &gt; &gt; &gt; &gt; &gt; (/home/tools/llvm-project/build/bin/clang-9+0=
x24ee375)<br>
&gt; &gt; &gt; &gt; &gt; &gt;=C2=A0 #3 0x00007f85ed99bd80 __restore_rt (/li=
b64/libpthread.so.0+0x12d80)<br>
&gt; &gt; &gt; &gt; &gt; &gt;=C2=A0 #4 0x00007f85ec47c93f raise (/lib64/lib=
c.so.6+0x3793f)<br>
&gt; &gt; &gt; &gt; &gt; &gt;=C2=A0 #5 0x00007f85ec466c95 abort (/lib64/lib=
c.so.6+0x21c95)<br>
&gt; &gt; &gt; &gt; &gt; &gt;=C2=A0 #6 0x00007f85ec466b69 _nl_load_domain.c=
old.0 (/lib64/libc.so.6+0x21b69)<br>
&gt; &gt; &gt; &gt; &gt; &gt;=C2=A0 #7 0x00007f85ec474df6 (/lib64/libc.so.6=
+0x2fdf6)<br>
&gt; &gt; &gt; &gt; &gt; &gt;=C2=A0 #8 0x000000000327b864 (anonymous<br>
&gt; &gt; &gt; &gt; &gt; &gt; namespace)::MemorySanitizerVisitor::visitCall=
Site(llvm::CallSite)<br>
&gt; &gt; &gt; &gt; &gt; &gt; (/home/tools/llvm-project/build/bin/clang-9+0=
x327b864)<br>
&gt; &gt; &gt; &gt; &gt; &gt;=C2=A0 #9 0x0000000003283036 (anonymous<br>
&gt; &gt; &gt; &gt; &gt; &gt; namespace)::MemorySanitizerVisitor::runOnFunc=
tion()<br>
&gt; &gt; &gt; &gt; &gt; &gt; (/home/tools/llvm-project/build/bin/clang-9+0=
x3283036)<br>
&gt; &gt; &gt; &gt; &gt; &gt; #10 0x000000000328605f (anonymous<br>
&gt; &gt; &gt; &gt; &gt; &gt; namespace)::MemorySanitizer::sanitizeFunction=
(llvm::Function&amp;,<br>
&gt; &gt; &gt; &gt; &gt; &gt; llvm::TargetLibraryInfo&amp;)<br>
&gt; &gt; &gt; &gt; &gt; &gt; (/home/tools/llvm-project/build/bin/clang-9+0=
x328605f)<br>
&gt; &gt; &gt; &gt; &gt; &gt; #11 0x0000000001f42ac8<br>
&gt; &gt; &gt; &gt; &gt; &gt; llvm::FPPassManager::runOnFunction(llvm::Func=
tion&amp;)<br>
&gt; &gt; &gt; &gt; &gt; &gt; (/home/tools/llvm-project/build/bin/clang-9+0=
x1f42ac8)<br>
&gt; &gt; &gt; &gt; &gt; &gt; #12 0x0000000001f42be9 llvm::FPPassManager::r=
unOnModule(llvm::Module&amp;)<br>
&gt; &gt; &gt; &gt; &gt; &gt; (/home/tools/llvm-project/build/bin/clang-9+0=
x1f42be9)<br>
&gt; &gt; &gt; &gt; &gt; &gt; #13 0x0000000001f41ed8<br>
&gt; &gt; &gt; &gt; &gt; &gt; llvm::legacy::PassManagerImpl::run(llvm::Modu=
le&amp;)<br>
&gt; &gt; &gt; &gt; &gt; &gt; (/home/tools/llvm-project/build/bin/clang-9+0=
x1f41ed8)<br>
&gt; &gt; &gt; &gt; &gt; &gt; #14 0x00000000026fa4f8 (anonymous<br>
&gt; &gt; &gt; &gt; &gt; &gt; namespace)::EmitAssemblyHelper::EmitAssembly(=
clang::BackendAction,<br>
&gt; &gt; &gt; &gt; &gt; &gt; std::unique_ptr&lt;llvm::raw_pwrite_stream,<b=
r>
&gt; &gt; &gt; &gt; &gt; &gt; std::default_delete&lt;llvm::raw_pwrite_strea=
m&gt; &gt;)<br>
&gt; &gt; &gt; &gt; &gt; &gt; (/home/tools/llvm-project/build/bin/clang-9+0=
x26fa4f8)<br>
&gt; &gt; &gt; &gt; &gt; &gt; #15 0x00000000026fbbf8<br>
&gt; &gt; &gt; &gt; &gt; &gt; clang::EmitBackendOutput(clang::DiagnosticsEn=
gine&amp;,<br>
&gt; &gt; &gt; &gt; &gt; &gt; clang::HeaderSearchOptions const&amp;, clang:=
:CodeGenOptions const&amp;,<br>
&gt; &gt; &gt; &gt; &gt; &gt; clang::TargetOptions const&amp;, clang::LangO=
ptions const&amp;,<br>
&gt; &gt; &gt; &gt; &gt; &gt; llvm::DataLayout const&amp;, llvm::Module*, c=
lang::BackendAction,<br>
&gt; &gt; &gt; &gt; &gt; &gt; std::unique_ptr&lt;llvm::raw_pwrite_stream,<b=
r>
&gt; &gt; &gt; &gt; &gt; &gt; std::default_delete&lt;llvm::raw_pwrite_strea=
m&gt; &gt;)<br>
&gt; &gt; &gt; &gt; &gt; &gt; (/home/tools/llvm-project/build/bin/clang-9+0=
x26fbbf8)<br>
&gt; &gt; &gt; &gt; &gt; &gt; #16 0x000000000310234d<br>
&gt; &gt; &gt; &gt; &gt; &gt; clang::BackendConsumer::HandleTranslationUnit=
(clang::ASTContext&amp;)<br>
&gt; &gt; &gt; &gt; &gt; &gt; (/home/tools/llvm-project/build/bin/clang-9+0=
x310234d)<br>
&gt; &gt; &gt; &gt; &gt; &gt; #17 0x0000000003aaddf9 clang::ParseAST(clang:=
:Sema&amp;, bool, bool)<br>
&gt; &gt; &gt; &gt; &gt; &gt; (/home/tools/llvm-project/build/bin/clang-9+0=
x3aaddf9)<br>
&gt; &gt; &gt; &gt; &gt; &gt; #18 0x00000000030fe5e0 clang::CodeGenAction::=
ExecuteAction()<br>
&gt; &gt; &gt; &gt; &gt; &gt; (/home/tools/llvm-project/build/bin/clang-9+0=
x30fe5e0)<br>
&gt; &gt; &gt; &gt; &gt; &gt; #19 0x0000000002ba1929 clang::FrontendAction:=
:Execute()<br>
&gt; &gt; &gt; &gt; &gt; &gt; (/home/tools/llvm-project/build/bin/clang-9+0=
x2ba1929)<br>
&gt; &gt; &gt; &gt; &gt; &gt; #20 0x0000000002b68e62<br>
&gt; &gt; &gt; &gt; &gt; &gt; clang::CompilerInstance::ExecuteAction(clang:=
:FrontendAction&amp;)<br>
&gt; &gt; &gt; &gt; &gt; &gt; (/home/tools/llvm-project/build/bin/clang-9+0=
x2b68e62)<br>
&gt; &gt; &gt; &gt; &gt; &gt; #21 0x0000000002c5738a<br>
&gt; &gt; &gt; &gt; &gt; &gt; clang::ExecuteCompilerInvocation(clang::Compi=
lerInstance*)<br>
&gt; &gt; &gt; &gt; &gt; &gt; (/home/tools/llvm-project/build/bin/clang-9+0=
x2c5738a)<br>
&gt; &gt; &gt; &gt; &gt; &gt; #22 0x00000000009cd1a6 cc1_main(llvm::ArrayRe=
f&lt;char const*&gt;, char<br>
&gt; &gt; &gt; &gt; &gt; &gt; const*, void*) (/home/tools/llvm-project/buil=
d/bin/clang-9+0x9cd1a6)<br>
&gt; &gt; &gt; &gt; &gt; &gt; #23 0x000000000094cac1 main<br>
&gt; &gt; &gt; &gt; &gt; &gt; (/home/tools/llvm-project/build/bin/clang-9+0=
x94cac1)<br>
&gt; &gt; &gt; &gt; &gt; &gt; #24 0x00007f85ec468813 __libc_start_main (/li=
b64/libc.so.6+0x23813)<br>
&gt; &gt; &gt; &gt; &gt; &gt; #25 0x00000000009c96ee _start<br>
&gt; &gt; &gt; &gt; &gt; &gt; (/home/tools/llvm-project/build/bin/clang-9+0=
x9c96ee)<br>
&gt; &gt; &gt; &gt; &gt; &gt; clang-9: error: unable to execute command: Ab=
orted (core dumped)<br>
&gt; &gt; &gt; &gt; &gt; &gt; clang-9: error: clang frontend command failed=
 due to signal (use -v to<br>
&gt; &gt; &gt; &gt; &gt; &gt; see invocation)<br>
&gt; &gt; &gt; &gt; &gt; &gt; clang version 9.0.0 (<a href=3D"https://githu=
b.com/llvm/llvm-project.git" rel=3D"noreferrer noreferrer" target=3D"_blank=
">https://github.com/llvm/llvm-project.git</a><br>
&gt; &gt; &gt; &gt; &gt; &gt; a056684c335995214f6d3467c699d32f8e73b763)<br>
&gt; &gt; &gt; &gt; &gt; &gt; Target: x86_64-unknown-linux-gnu<br>
&gt; &gt; &gt; &gt; &gt; &gt; Thread model: posix<br>
&gt; &gt; &gt; &gt; &gt; &gt; InstalledDir: /home/tools/llvm-project/build/=
bin<br>
&gt; &gt; &gt; &gt; &gt; &gt; clang-9: note: diagnostic msg: PLEASE submit =
a bug report to<br>
&gt; &gt; &gt; &gt; &gt; &gt; <a href=3D"https://bugs.llvm.org/" rel=3D"nor=
eferrer noreferrer" target=3D"_blank">https://bugs.llvm.org/</a> and includ=
e the crash backtrace, preprocessed<br>
&gt; &gt; &gt; &gt; &gt; &gt; source, and associated run script.<br>
&gt; &gt; &gt; &gt; &gt; &gt; clang-9: note: diagnostic msg:<br>
&gt; &gt; &gt; &gt; &gt; &gt; ********************<br>
&gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; PLEASE ATTACH THE FOLLOWING FILES TO THE BUG =
REPORT:<br>
&gt; &gt; &gt; &gt; &gt; &gt; Preprocessed source(s) and associated run scr=
ipt(s) are located at:<br>
&gt; &gt; &gt; &gt; &gt; &gt; clang-9: note: diagnostic msg: /tmp/process_6=
4-5fbbdc.c<br>
&gt; &gt; &gt; &gt; &gt; &gt; clang-9: note: diagnostic msg: /tmp/process_6=
4-5fbbdc.sh<br>
&gt; &gt; &gt; &gt; &gt; &gt; clang-9: note: diagnostic msg:<br>
&gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; ********************<br>
&gt; &gt; &gt; &gt; &gt; &gt; make[2]: *** [scripts/Makefile.build:276:<br>
&gt; &gt; &gt; &gt; &gt; &gt; arch/x86/kernel/process_64.o] Error 254<br>
&gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; any idea why?<br>
&gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; On Thu, Jun 27, 2019 at 5:23 PM Alexander Pot=
apenko &lt;<a href=3D"mailto:glider@google.com" target=3D"_blank" rel=3D"no=
referrer">glider@google.com</a>&gt; wrote:<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; Actually, your config says:<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt;=C2=A0 =C2=A0&quot;Compiler: clang versio=
n 8.0.0 (trunk 343298)&quot;<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; I think you&#39;ll need at least Clang r=
362410 (mine is r362913)<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; On Thu, Jun 27, 2019 at 11:20 AM Alexand=
er Potapenko &lt;<a href=3D"mailto:glider@google.com" target=3D"_blank" rel=
=3D"noreferrer">glider@google.com</a>&gt; wrote:<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; Hi Xin,<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; Sorry for the late reply.<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; I&#39;ve built the ToT KMSAN tree u=
sing your config and my almost-ToT<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; Clang and couldn&#39;t reproduce th=
e problem.<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; I believe something is wrong with y=
our Clang version, as<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; CONFIG_CLANG_VERSION should really =
be 90000.<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; You can run `make V=3D1` to see whi=
ch Clang version is being invoked -<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; make sure it&#39;s a fresh one.<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; HTH,<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; Alex<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; On Fri, Jun 21, 2019 at 10:09 PM Xi=
n Long &lt;<a href=3D"mailto:lucien.xin@gmail.com" target=3D"_blank" rel=3D=
"noreferrer">lucien.xin@gmail.com</a>&gt; wrote:<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; as attached,<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; It actually came from <a href=
=3D"https://syzkaller.appspot.com/x/.config?x=3D602468164ccdc30a" rel=3D"no=
referrer noreferrer" target=3D"_blank">https://syzkaller.appspot.com/x/.con=
fig?x=3D602468164ccdc30a</a><br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; after I built, clang version c=
hanged to:<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; CONFIG_CLANG_VERSION=3D80000<b=
r>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; On Sat, Jun 22, 2019 at 2:06 A=
M Alexander Potapenko &lt;<a href=3D"mailto:glider@google.com" target=3D"_b=
lank" rel=3D"noreferrer">glider@google.com</a>&gt; wrote:<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; Hi Xin,<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; Could you please share th=
e config you&#39;re using to build the kernel?<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; I&#39;ll take a closer lo=
ok on Monday when I am back to the office.<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; On Fri, 21 Jun 2019, 18:1=
5 Xin Long, &lt;<a href=3D"mailto:lucien.xin@gmail.com" target=3D"_blank" r=
el=3D"noreferrer">lucien.xin@gmail.com</a>&gt; wrote:<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; this is my command:<b=
r>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; /usr/libexec/qemu-kvm=
 -smp 2 -m 4G -enable-kvm -cpu host \<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;=C2=A0 =C2=A0 =C2=A0-n=
et nic -net user,hostfwd=3Dtcp::10022-:22 \<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;=C2=A0 =C2=A0 =C2=A0-k=
ernel /home/kmsan/arch/x86/boot/bzImage -nographic \<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;=C2=A0 =C2=A0 =C2=A0-d=
evice virtio-scsi-pci,id=3Dscsi \<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;=C2=A0 =C2=A0 =C2=A0-d=
evice scsi-hd,bus=3Dscsi.0,drive=3Dd0 \<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;=C2=A0 =C2=A0 =C2=A0-d=
rive file=3D/root/test/wheezy.img,format=3Draw,if=3Dnone,id=3Dd0 \<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;=C2=A0 =C2=A0 =C2=A0-a=
ppend &quot;root=3D/dev/sda console=3DttyS0 earlyprintk=3Dserial rodata=3Dn=
 \<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;=C2=A0 =C2=A0 =C2=A0 =
=C2=A0oops=3Dpanic panic_on_warn=3D1 panic=3D86400 kvm-intel.nested=3D1 \<b=
r>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;=C2=A0 =C2=A0 =C2=A0 =
=C2=A0security=3Dapparmor ima_policy=3Dtcb workqueue.watchdog_thresh=3D140 =
\<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;=C2=A0 =C2=A0 =C2=A0 =
=C2=A0nf-conntrack-ftp.ports=3D20000 nf-conntrack-tftp.ports=3D20000 \<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;=C2=A0 =C2=A0 =C2=A0 =
=C2=A0nf-conntrack-sip.ports=3D20000 nf-conntrack-irc.ports=3D20000 \<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;=C2=A0 =C2=A0 =C2=A0 =
=C2=A0nf-conntrack-sane.ports=3D20000 vivid.n_devs=3D16 \<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;=C2=A0 =C2=A0 =C2=A0 =
=C2=A0vivid.multiplanar=3D1,2,1,2,1,2,1,2,1,2,1,2,1,2,1,2 \<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;=C2=A0 =C2=A0 =C2=A0 =
=C2=A0spec_store_bypass_disable=3Dprctl nopcid&quot;<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; the commit is on:<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; commit f75e4cfea97f67=
b7530b8b991b3005f991f04778 (HEAD)<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; Author: Alexander Pot=
apenko &lt;<a href=3D"mailto:glider@google.com" target=3D"_blank" rel=3D"no=
referrer">glider@google.com</a>&gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; Date:=C2=A0 =C2=A0Wed=
 May 22 12:30:13 2019 +0200<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;=C2=A0 =C2=A0 =C2=A0km=
san: use kmsan_handle_urb() in urb.c<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; and when starting, it=
 shows:<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.5619=
25][=C2=A0 =C2=A0 T0] Kernel command line: root=3D/dev/sda<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; console=3DttyS0 early=
printk=3Dserial rodata=3Dn=C2=A0 =C2=A0 =C2=A0 =C2=A0oops=3Dpanic<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; panic_on_warn=3D1 pan=
ic=3D86400 kvm-intel.nested=3D1=C2=A0 =C2=A0 =C2=A0 =C2=A0security=3Dad<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7077=
92][=C2=A0 =C2=A0 T0] Memory: 3087328K/4193776K available (219164K<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; kernel code, 7059K rw=
data, 11712K rodata, 5064K init, 11904K bss,<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; 1106448K reserved, 0K=
 cma-reserved)<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7109=
35][=C2=A0 =C2=A0 T0] SLUB: HWalign=3D64, Order=3D0-3, MinObjects=3D0,<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; CPUs=3D2, Nodes=3D1<b=
r>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7119=
53][=C2=A0 =C2=A0 T0] Starting KernelMemorySanitizer<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7125=
63][=C2=A0 =C2=A0 T0]<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; =3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7136=
57][=C2=A0 =C2=A0 T0] BUG: KMSAN: uninit-value in mutex_lock+0xd1/0xe0<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7145=
70][=C2=A0 =C2=A0 T0] CPU: 0 PID: 0 Comm: swapper Not tainted 5.1.0 #5<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7154=
17][=C2=A0 =C2=A0 T0] Hardware name: Red Hat KVM, BIOS<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; 1.11.1-3.module+el8.1=
.0+2983+b2ae9c0a 04/01/2014<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7166=
59][=C2=A0 =C2=A0 T0] Call Trace:<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7171=
27][=C2=A0 =C2=A0 T0]=C2=A0 dump_stack+0x134/0x190<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7177=
27][=C2=A0 =C2=A0 T0]=C2=A0 kmsan_report+0x131/0x2a0<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7183=
47][=C2=A0 =C2=A0 T0]=C2=A0 __msan_warning+0x7a/0xf0<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7189=
52][=C2=A0 =C2=A0 T0]=C2=A0 mutex_lock+0xd1/0xe0<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7194=
78][=C2=A0 =C2=A0 T0]=C2=A0 __cpuhp_setup_state_cpuslocked+0x149/0xd20<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7202=
60][=C2=A0 =C2=A0 T0]=C2=A0 ? vprintk_func+0x6b5/0x8a0<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7209=
26][=C2=A0 =C2=A0 T0]=C2=A0 ? rb_get_reader_page+0x1140/0x1140<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7216=
32][=C2=A0 =C2=A0 T0]=C2=A0 __cpuhp_setup_state+0x181/0x2e0<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7223=
74][=C2=A0 =C2=A0 T0]=C2=A0 ? rb_get_reader_page+0x1140/0x1140<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7231=
15][=C2=A0 =C2=A0 T0]=C2=A0 tracer_alloc_buffers+0x16b/0xb96<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7238=
46][=C2=A0 =C2=A0 T0]=C2=A0 early_trace_init+0x193/0x28f<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7245=
01][=C2=A0 =C2=A0 T0]=C2=A0 start_kernel+0x497/0xb38<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7251=
34][=C2=A0 =C2=A0 T0]=C2=A0 x86_64_start_reservations+0x19/0x2f<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7258=
71][=C2=A0 =C2=A0 T0]=C2=A0 x86_64_start_kernel+0x84/0x87<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7265=
38][=C2=A0 =C2=A0 T0]=C2=A0 secondary_startup_64+0xa4/0xb0<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7271=
73][=C2=A0 =C2=A0 T0]<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7274=
54][=C2=A0 =C2=A0 T0] Local variable description:<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; ----success.i.i.i.i@m=
utex_lock<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7283=
79][=C2=A0 =C2=A0 T0] Variable was created at:<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7289=
77][=C2=A0 =C2=A0 T0]=C2=A0 mutex_lock+0x48/0xe0<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7295=
36][=C2=A0 =C2=A0 T0]=C2=A0 __cpuhp_setup_state_cpuslocked+0x149/0xd20<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7303=
23][=C2=A0 =C2=A0 T0]<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; =3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7313=
64][=C2=A0 =C2=A0 T0] Disabling lock debugging due to kernel taint<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7321=
69][=C2=A0 =C2=A0 T0] Kernel panic - not syncing: panic_on_warn set ...<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7330=
47][=C2=A0 =C2=A0 T0] CPU: 0 PID: 0 Comm: swapper Tainted: G=C2=A0 =C2=A0 B=
<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;=C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A05.1.0 #5<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7340=
80][=C2=A0 =C2=A0 T0] Hardware name: Red Hat KVM, BIOS<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; 1.11.1-3.module+el8.1=
.0+2983+b2ae9c0a 04/01/2014<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7353=
19][=C2=A0 =C2=A0 T0] Call Trace:<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7357=
35][=C2=A0 =C2=A0 T0]=C2=A0 dump_stack+0x134/0x190<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7363=
08][=C2=A0 =C2=A0 T0]=C2=A0 panic+0x3ec/0xb3b<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7368=
26][=C2=A0 =C2=A0 T0]=C2=A0 kmsan_report+0x29a/0x2a0<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7374=
17][=C2=A0 =C2=A0 T0]=C2=A0 __msan_warning+0x7a/0xf0<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7379=
73][=C2=A0 =C2=A0 T0]=C2=A0 mutex_lock+0xd1/0xe0<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7385=
27][=C2=A0 =C2=A0 T0]=C2=A0 __cpuhp_setup_state_cpuslocked+0x149/0xd20<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7393=
42][=C2=A0 =C2=A0 T0]=C2=A0 ? vprintk_func+0x6b5/0x8a0<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7399=
72][=C2=A0 =C2=A0 T0]=C2=A0 ? rb_get_reader_page+0x1140/0x1140<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7406=
95][=C2=A0 =C2=A0 T0]=C2=A0 __cpuhp_setup_state+0x181/0x2e0<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7414=
12][=C2=A0 =C2=A0 T0]=C2=A0 ? rb_get_reader_page+0x1140/0x1140<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7421=
60][=C2=A0 =C2=A0 T0]=C2=A0 tracer_alloc_buffers+0x16b/0xb96<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7428=
66][=C2=A0 =C2=A0 T0]=C2=A0 early_trace_init+0x193/0x28f<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7435=
12][=C2=A0 =C2=A0 T0]=C2=A0 start_kernel+0x497/0xb38<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7441=
28][=C2=A0 =C2=A0 T0]=C2=A0 x86_64_start_reservations+0x19/0x2f<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7448=
63][=C2=A0 =C2=A0 T0]=C2=A0 x86_64_start_kernel+0x84/0x87<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7455=
34][=C2=A0 =C2=A0 T0]=C2=A0 secondary_startup_64+0xa4/0xb0<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A0 0.7462=
90][=C2=A0 =C2=A0 T0] Rebooting in 86400 seconds..<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; when I set &quot;pani=
c_on_warn=3D0&quot;, it foods the console with:<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; ...<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2067=
59][=C2=A0 =C2=A0 C0] Variable was created at:<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2073=
02][=C2=A0 =C2=A0 C0]=C2=A0 vprintk_emit+0xf4/0x800<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2078=
44][=C2=A0 =C2=A0 C0]=C2=A0 vprintk_deferred+0x90/0xed<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2084=
04][=C2=A0 =C2=A0 C0]<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; =3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2097=
63][=C2=A0 =C2=A0 C0]=C2=A0 x86_64_start_reservations+0x19/0x2f<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2097=
69][=C2=A0 =C2=A0 C0]<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; =3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2114=
08][=C2=A0 =C2=A0 C0] BUG: KMSAN: uninit-value in vprintk_emit+0x443/0x800<=
br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2122=
37][=C2=A0 =C2=A0 C0] CPU: 0 PID: 0 Comm: swapper/0 Tainted: G=C2=A0 =C2=A0=
 B<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;=C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A05.1.0 #5<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2132=
06][=C2=A0 =C2=A0 C0] Hardware name: Red Hat KVM, BIOS<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; 1.11.1-3.module+el8.1=
.0+2983+b2ae9c0a 04/01/2014<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2143=
26][=C2=A0 =C2=A0 C0] Call Trace:<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2147=
25][=C2=A0 =C2=A0 C0]=C2=A0 &lt;IRQ&gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2150=
80][=C2=A0 =C2=A0 C0]=C2=A0 dump_stack+0x134/0x190<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2156=
24][=C2=A0 =C2=A0 C0]=C2=A0 kmsan_report+0x131/0x2a0<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2162=
04][=C2=A0 =C2=A0 C0]=C2=A0 __msan_warning+0x7a/0xf0<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2167=
71][=C2=A0 =C2=A0 C0]=C2=A0 vprintk_emit+0x443/0x800<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2173=
34][=C2=A0 =C2=A0 C0]=C2=A0 ? __msan_metadata_ptr_for_store_1+0x13/0x20<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2181=
27][=C2=A0 =C2=A0 C0]=C2=A0 vprintk_deferred+0x90/0xed<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2187=
14][=C2=A0 =C2=A0 C0]=C2=A0 printk_deferred+0x186/0x1d3<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2193=
53][=C2=A0 =C2=A0 C0]=C2=A0 __printk_safe_flush+0x72e/0xc00<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2200=
06][=C2=A0 =C2=A0 C0]=C2=A0 ? printk_safe_flush+0x1e0/0x1e0<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2206=
35][=C2=A0 =C2=A0 C0]=C2=A0 irq_work_run+0x1ad/0x5c0<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2212=
10][=C2=A0 =C2=A0 C0]=C2=A0 ? flat_init_apic_ldr+0x170/0x170<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2218=
51][=C2=A0 =C2=A0 C0]=C2=A0 smp_irq_work_interrupt+0x237/0x3e0<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2225=
20][=C2=A0 =C2=A0 C0]=C2=A0 irq_work_interrupt+0x2e/0x40<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2231=
10][=C2=A0 =C2=A0 C0]=C2=A0 &lt;/IRQ&gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2234=
75][=C2=A0 =C2=A0 C0] RIP: 0010:kmem_cache_init_late+0x0/0xb<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2241=
64][=C2=A0 =C2=A0 C0] Code: d4 e8 5d dd 2e f2 e9 74 fe ff ff 48 89 d3<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; 8b 7d d4 e8 cd d7 2e =
f2 89 c0 48 89 c1 48 c1 e1 20 48 09 c1 48 89 0b<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; e9 81 fe ff ff &lt;55=
&gt; 48 89 e5 e8 20 de 2e1<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2265=
26][=C2=A0 =C2=A0 C0] RSP: 0000:ffffffff8f40feb8 EFLAGS: 00000246<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; ORIG_RAX: fffffffffff=
fff09<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2275=
48][=C2=A0 =C2=A0 C0] RAX: ffff88813f995785 RBX: 0000000000000000<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; RCX: 0000000000000000=
<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2285=
11][=C2=A0 =C2=A0 C0] RDX: ffff88813f2b0784 RSI: 0000160000000000<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; RDI: 0000000000000785=
<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2294=
73][=C2=A0 =C2=A0 C0] RBP: ffffffff8f40ff20 R08: 000000000fac3785<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; R09: 0000778000000001=
<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2304=
40][=C2=A0 =C2=A0 C0] R10: ffffd0ffffffffff R11: 0000100000000000<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; R12: 0000000000000000=
<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2314=
03][=C2=A0 =C2=A0 C0] R13: 0000000000000000 R14: ffffffff8fb8cfd0<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; R15: 0000000000000000=
<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2324=
07][=C2=A0 =C2=A0 C0]=C2=A0 ? start_kernel+0x5d8/0xb38<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2330=
03][=C2=A0 =C2=A0 C0]=C2=A0 x86_64_start_reservations+0x19/0x2f<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2336=
70][=C2=A0 =C2=A0 C0]=C2=A0 x86_64_start_kernel+0x84/0x87<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2343=
14][=C2=A0 =C2=A0 C0]=C2=A0 secondary_startup_64+0xa4/0xb0<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2349=
49][=C2=A0 =C2=A0 C0]<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2352=
31][=C2=A0 =C2=A0 C0] Local variable description: ----flags.i.i.i@vprintk_e=
mit<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2361=
01][=C2=A0 =C2=A0 C0] Variable was created at:<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2366=
43][=C2=A0 =C2=A0 C0]=C2=A0 vprintk_emit+0xf4/0x800<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2371=
88][=C2=A0 =C2=A0 C0]=C2=A0 vprintk_deferred+0x90/0xed<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2377=
52][=C2=A0 =C2=A0 C0]<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; =3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2391=
17][=C2=A0 =C2=A0 C0]=C2=A0 x86_64_start_kernel+0x84/0x87<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2391=
23][=C2=A0 =C2=A0 C0]<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; =3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2407=
04][=C2=A0 =C2=A0 C0] BUG: KMSAN: uninit-value in vprintk_emit+0x443/0x800<=
br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2415=
40][=C2=A0 =C2=A0 C0] CPU: 0 PID: 0 Comm: swapper/0 Tainted: G=C2=A0 =C2=A0=
 B<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;=C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A05.1.0 #5<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2425=
12][=C2=A0 =C2=A0 C0] Hardware name: Red Hat KVM, BIOS<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; 1.11.1-3.module+el8.1=
.0+2983+b2ae9c0a 04/01/2014<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2436=
35][=C2=A0 =C2=A0 C0] Call Trace:<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2440=
38][=C2=A0 =C2=A0 C0]=C2=A0 &lt;IRQ&gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2443=
90][=C2=A0 =C2=A0 C0]=C2=A0 dump_stack+0x134/0x190<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2449=
40][=C2=A0 =C2=A0 C0]=C2=A0 kmsan_report+0x131/0x2a0<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2455=
15][=C2=A0 =C2=A0 C0]=C2=A0 __msan_warning+0x7a/0xf0<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2460=
82][=C2=A0 =C2=A0 C0]=C2=A0 vprintk_emit+0x443/0x800<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2466=
38][=C2=A0 =C2=A0 C0]=C2=A0 ? __msan_metadata_ptr_for_store_1+0x13/0x20<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2474=
30][=C2=A0 =C2=A0 C0]=C2=A0 vprintk_deferred+0x90/0xed<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2480=
18][=C2=A0 =C2=A0 C0]=C2=A0 printk_deferred+0x186/0x1d3<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2486=
50][=C2=A0 =C2=A0 C0]=C2=A0 __printk_safe_flush+0x72e/0xc00<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2493=
20][=C2=A0 =C2=A0 C0]=C2=A0 ? printk_safe_flush+0x1e0/0x1e0<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2499=
49][=C2=A0 =C2=A0 C0]=C2=A0 irq_work_run+0x1ad/0x5c0<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2505=
24][=C2=A0 =C2=A0 C0]=C2=A0 ? flat_init_apic_ldr+0x170/0x170<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2511=
67][=C2=A0 =C2=A0 C0]=C2=A0 smp_irq_work_interrupt+0x237/0x3e0<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2518=
37][=C2=A0 =C2=A0 C0]=C2=A0 irq_work_interrupt+0x2e/0x40<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=A025.2524=
24][=C2=A0 =C2=A0 C0]=C2=A0 &lt;/IRQ&gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; ....<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; I couldn&#39;t even l=
og in.<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; how should I use qemu=
 with wheezy.img to start a kmsan kernel?<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; Thanks.<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; --<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; Alexander Potapenko<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; Software Engineer<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; Google Germany GmbH<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; Erika-Mann-Stra=C3=9Fe, 33<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; 80636 M=C3=BCnchen<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; Gesch=C3=A4ftsf=C3=BChrer: Paul Man=
icle, Halimah DeLaine Prado<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; Registergericht und -nummer: Hambur=
g, HRB 86891<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; Sitz der Gesellschaft: Hamburg<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; --<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; Alexander Potapenko<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; Software Engineer<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; Google Germany GmbH<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; Erika-Mann-Stra=C3=9Fe, 33<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; 80636 M=C3=BCnchen<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle,=
 Halimah DeLaine Prado<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; Registergericht und -nummer: Hamburg, HR=
B 86891<br>
&gt; &gt; &gt; &gt; &gt; &gt; &gt; Sitz der Gesellschaft: Hamburg<br>
&gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt; --<br>
&gt; &gt; &gt; &gt; &gt; Alexander Potapenko<br>
&gt; &gt; &gt; &gt; &gt; Software Engineer<br>
&gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt; Google Germany GmbH<br>
&gt; &gt; &gt; &gt; &gt; Erika-Mann-Stra=C3=9Fe, 33<br>
&gt; &gt; &gt; &gt; &gt; 80636 M=C3=BCnchen<br>
&gt; &gt; &gt; &gt; &gt;<br>
&gt; &gt; &gt; &gt; &gt; Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah D=
eLaine Prado<br>
&gt; &gt; &gt; &gt; &gt; Registergericht und -nummer: Hamburg, HRB 86891<br=
>
&gt; &gt; &gt; &gt; &gt; Sitz der Gesellschaft: Hamburg<br>
&gt; &gt; &gt;<br>
&gt; &gt; &gt;<br>
&gt; &gt; &gt;<br>
&gt; &gt; &gt; --<br>
&gt; &gt; &gt; Alexander Potapenko<br>
&gt; &gt; &gt; Software Engineer<br>
&gt; &gt; &gt;<br>
&gt; &gt; &gt; Google Germany GmbH<br>
&gt; &gt; &gt; Erika-Mann-Stra=C3=9Fe, 33<br>
&gt; &gt; &gt; 80636 M=C3=BCnchen<br>
&gt; &gt; &gt;<br>
&gt; &gt; &gt; Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Pra=
do<br>
&gt; &gt; &gt; Registergericht und -nummer: Hamburg, HRB 86891<br>
&gt; &gt; &gt; Sitz der Gesellschaft: Hamburg<br>
&gt;<br>
&gt;<br>
&gt;<br>
&gt; --<br>
&gt; Alexander Potapenko<br>
&gt; Software Engineer<br>
&gt;<br>
&gt; Google Germany GmbH<br>
&gt; Erika-Mann-Stra=C3=9Fe, 33<br>
&gt; 80636 M=C3=BCnchen<br>
&gt;<br>
&gt; Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado<br>
&gt; Registergericht und -nummer: Hamburg, HRB 86891<br>
&gt; Sitz der Gesellschaft: Hamburg<br>
</blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To post to this group, send email to <a href=3D"mailto:kasan-dev@googlegrou=
ps.com">kasan-dev@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAG_fn%3DVgE7b4V4fCFApxUKFeV46pSmXuNucAUqqMWUdMV%2BCrv=
A%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.g=
oogle.com/d/msgid/kasan-dev/CAG_fn%3DVgE7b4V4fCFApxUKFeV46pSmXuNucAUqqMWUdM=
V%2BCrvA%40mail.gmail.com</a>.<br />
For more options, visit <a href=3D"https://groups.google.com/d/optout">http=
s://groups.google.com/d/optout</a>.<br />

--0000000000008c03d1058c6482fc--
