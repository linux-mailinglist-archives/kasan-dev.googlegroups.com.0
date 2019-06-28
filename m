Return-Path: <kasan-dev+bncBCCMH5WKTMGRB4MZ3HUAKGQEY6ANJYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3c.google.com (mail-yw1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 339DE5A22E
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2019 19:22:59 +0200 (CEST)
Received: by mail-yw1-xc3c.google.com with SMTP id i136sf9700932ywe.23
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2019 10:22:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561742578; cv=pass;
        d=google.com; s=arc-20160816;
        b=vsXex/0wYgMO9nqiEeLS8Bzoxm1ZqZiCo8XyXefB41ppTMYiUDgLYdQy2/wD7fC5bt
         uNrAbnsffAHyTVj7l5I205kUUze5sp+sm1G0kajpu88UYsPJlQJTh9f3DXNzDkYClM0m
         rM2vWk532YJfhBsr5Fqx8ou4HsmVU9sKEOWW9/MGzH3FlPo2J/MAKTMVJKSwoCQvDVnl
         O1qlOv9YsD+ELGznljiKTVeb+G6d5rP8pexpbwwvbUB1sEPPVLH08mJa5VuDp92FWnK6
         TBzjM5aAUymVjp4AUQAmnWVclny9TL8yL0YEj1Wv7vxDb2WIR2MjmBLhs3ep3DRJ9eWL
         LWZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=I5O1BHIOBXssXAG4qB+ceVkx2DDNFEEisv/v9KTDu6A=;
        b=s0RPf1PnUGPoxTessdmZSA3pRMINVAKq2WFFm6hkBJGXC6u7JJ3S+6SG90HdNG4caS
         +NMlltUmQ4kfp+uXN0zsSBr9+ulf1y0i+XsNdTVP7DT5AZsFwy+A0C0Qdw7smkjrYqBq
         LLz/b6Omip1PuWwsI2relFLVM25Ry4qq1W0bd/G4bVxHb883wzz30ZL/j3gRYgFJa6Uu
         /ZBuFZQM3D8ZfMKMEKzNJqe9ssycVAKh/sZmpkM9xvFgxrs02PkJNB+5HTAauMj2Xu+r
         gFKsWM6PS1cIkN5fVG57XuL0lnjEfdlWR8H4rabCvqWjRX00K3Q089Grr+OI45KRIH/3
         +uUw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fqv5pOI+;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::a32 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=I5O1BHIOBXssXAG4qB+ceVkx2DDNFEEisv/v9KTDu6A=;
        b=Rf2bGVpFQh13dWtXJApDTXnGjRdqCIPYAsPHYmaO/2dhTgjGqL13BqUiOTTteLiR+n
         XJcFKMjhaqQIDUYb2Z3tMIm0YIoLrz5L2kWdbTlpWcB/9apD7F3ykBc4fKWUFxOJvMFI
         MnOh3EUR3fsGvKmz1gGZl4Mv2ig6UOH0HSCjujlSy1Ko0vkxDTB7Qr+HA3+QVbZ0D5K5
         DeJHgKTCx4QvUPRCTnfa4KBeQU3JTaS2xD3jaK4U0iYKKG+tV9fgJE5wtuxpTiMf1hF8
         /pPFEJiyY87ws/rN8CR/VSq15FRyEflIpLJ+21oIykoI1ElsjzQAodOIt7Xdajl6gErp
         l1Yw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=I5O1BHIOBXssXAG4qB+ceVkx2DDNFEEisv/v9KTDu6A=;
        b=pVjravqE7m26oswoyZ0UPeKSgAAXEnorc6qyCbzt5XB6hH4GoQ1cE9wNWgEWLE3Tmu
         wo2QHcB9ltMvVlXcQn0EhXFlmnXxjd90/9gg6ORRbuKFZWppxK5va0kV/5VSe2oQRYje
         299jY9TkmWnnVMGpa2BHZ36abmzn0+5QqtE1yQQZO+xWN+XWZ9LgeIHrel50DNvfkEjX
         z9LFAURjZvw/aRPdyMpikwrEr+WGkam0ZneaYS3tQzKD0K/Z0tt4KDC1KqseZE0ld/Xg
         2Qp+0ULuVH5SmdLMPAgUnmNcNyOQxH8lgD5YQ5P/ceWOZaXqPx7XOIMtavySvCleYJJd
         edZg==
X-Gm-Message-State: APjAAAUXSqjvw//em+3daUlHQjhfs1Yh4QlqHTJxNEX/aTWS6LfH/Mir
	skx76gvsS7NzEAZfe2T8byA=
X-Google-Smtp-Source: APXvYqwGl/ojDbO7JMymSiWuIBhJKufO3PklppC9LDTJsKBsdTDfxEepH25sW2KMZmCJM0dGAqRTZQ==
X-Received: by 2002:a81:4a05:: with SMTP id x5mr6913509ywa.247.1561742577828;
        Fri, 28 Jun 2019 10:22:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:5f10:: with SMTP id t16ls461230ybb.8.gmail; Fri, 28 Jun
 2019 10:22:57 -0700 (PDT)
X-Received: by 2002:a25:5d0b:: with SMTP id r11mr7438683ybb.359.1561742577169;
        Fri, 28 Jun 2019 10:22:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561742577; cv=none;
        d=google.com; s=arc-20160816;
        b=rqEnsYab+NfksGLvtnY/1F/4pWBORmoRKJtwxQmhvHG42Dg+4P6/ZFzbMUMQ5zurSp
         Lg5CMtEu3Zbcny3tEipGd48Ne3WDR2tfa8AX1dOWrbLonB04PJcQQVmLPpse9C0d+PMj
         LFgoZpxgMlJQ/7Ljz8I+jpJ7gubqnLVuE9vX3R6mJ2gCpvxZGPOVv6Zcz4A2GYJmLIrW
         zFHv9fP+DyaHNG01H8GizmmfWKch1D9uWTyfAC5zmpgAlOE9sij2Zpbx0scdb8pvCKAv
         Z/jl0FPezOs02k/yNfQAIv7y5kzsF77MXps4+SvQmyDzn0jcJZAgnwc6NTuj3f2Uqzpc
         T1uQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=XWu1MJG8HaBtoUugL3E7oQGT6KPWraqN7PTUKCtC4bs=;
        b=zRjIyvJdG1mkgEoyfH2M18YBTXxId2KKX8N66XDTMC+ImCTDibsFeB2iaw/Y76JUxu
         9PbZIxjnht+S/4jWUKNw7n853/+n09EfGxflKRwDOuBDQGTE5fzqbbREp4o6DP+Xoqh7
         FVvhhVXkDgFJC1dr/GtvXle3vw4DbrLnji7ZGw02lbuhyqL7S2BspmVKOPKJGQJUVQw9
         C5rfvq9BX1IlUphCPK3sxmE+nNRXNPIN3Q3Se6Zy1W5KVW0fiM24+CJzJqlk0sgST+cm
         WHMmyRWWmE58quZbjxomAj2oMG+jkfnY5cB1OIaVnBlL89K4oU6DpYY/M+ZLmNJWWmwd
         ARcw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fqv5pOI+;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::a32 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa32.google.com (mail-vk1-xa32.google.com. [2607:f8b0:4864:20::a32])
        by gmr-mx.google.com with ESMTPS id v16si203714ywv.1.2019.06.28.10.22.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Fri, 28 Jun 2019 10:22:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::a32 as permitted sender) client-ip=2607:f8b0:4864:20::a32;
Received: by mail-vk1-xa32.google.com with SMTP id b64so1374689vke.13
        for <kasan-dev@googlegroups.com>; Fri, 28 Jun 2019 10:22:57 -0700 (PDT)
X-Received: by 2002:a1f:200b:: with SMTP id g11mr4197803vkg.26.1561742576211;
 Fri, 28 Jun 2019 10:22:56 -0700 (PDT)
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
 <CAG_fn=XYNq=o9nB42L=azEynMVSyNNKHPCJwePNNObk2z8Ahfw@mail.gmail.com>
 <CADvbK_eLaRPSgSANMXBRGLfCPx=D9r9nrr=vsb0tfo0f4rEVXg@mail.gmail.com>
 <CAG_fn=VgE7b4V4fCFApxUKFeV46pSmXuNucAUqqMWUdMV+CrvA@mail.gmail.com> <CADvbK_fPKE6zq91yGp-J0XuZF+0XUayJgJUMSBGNkRaFbi7dtg@mail.gmail.com>
In-Reply-To: <CADvbK_fPKE6zq91yGp-J0XuZF+0XUayJgJUMSBGNkRaFbi7dtg@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 28 Jun 2019 19:22:42 +0200
Message-ID: <CAG_fn=WKLynY8fWdrsSxYcQXHMPC+Vnjg-C322cfwR=Sb3wuZA@mail.gmail.com>
Subject: Re: how to start kmsan kernel with qemu
To: lucien xin <lucien.xin@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Dmitriy Vyukov <dvyukov@google.com>
Content-Type: multipart/alternative; boundary="0000000000007ccb39058c65873f"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=fqv5pOI+;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::a32 as
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

--0000000000007ccb39058c65873f
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Thanks! I'll try this out next week. My tree might also have local changes,
if so, I'd better figure it out sooner rather than later :)

On Fri, 28 Jun 2019, 19:18 Xin Long, <lucien.xin@gmail.com> wrote:

> # cd /home/tools/
> # git clone https://github.com/llvm/llvm-project.git
> # cd llvm-project/
> # mkdir build
> # cd build/
> # cmake -DLLVM_ENABLE_PROJECTS=3Dclang -DCMAKE_BUILD_TYPE=3DRelease
> -DLLVM_ENABLE_ASSERTIONS=3DON -G "Unix Makefiles" ../llvm
> # make
> # cd /home/kmsan
> # git checkout f75e4cfea97f
> (use the .config I sent you last time)
> # make CC=3D/home/tools/llvm-project/build/bin/clang -j64 -k LOCALVERSION=
=3D
> 2>&1
>
> These are the whole thing I did to build it.
>
> On Sat, Jun 29, 2019 at 12:09 AM Alexander Potapenko <glider@google.com>
> wrote:
> >
> > Hm, now that's your Clang binary versus mine :)
> > Can you please ensure your git repo doesn't contain local changes and
> share the commands you're using to build Clang?
> > (Both cmake and make or ninja)
> No any local changes on both llvm-project and kmsan
>
> > Is the bug still reproducible in a clean CMake directory?
> A clean CMake directory? how to clean it? something like: # cmake clean
>
> Thank you for being so patient. :-)
>
> >
> > On Fri, 28 Jun 2019, 16:20 Xin Long, <lucien.xin@gmail.com> wrote:
> >>
> >> yes
> >>
> >> https://paste.fedoraproject.org/paste/DU2nnxpZWpWMri9Up7hypA
> >>
> >> On Fri, Jun 28, 2019 at 9:48 PM Alexander Potapenko <glider@google.com=
>
> wrote:
> >> >
> >> > Hm, strange, but I still can compile this file.
> >> > Does the following command line crash your compiler?
> >> > https://paste.fedoraproject.org/paste/oJwOVm5cHWyd7hxIZ4uGeA (note i=
t
> >> > should be run from the same directory where process_64.i resides; al=
so
> >> > make sure to invoke the right Clang)
> >> >
> >> > On Fri, Jun 28, 2019 at 3:35 PM Xin Long <lucien.xin@gmail.com>
> wrote:
> >> > >
> >> > > As attached, thanks.
> >> > >
> >> > > On Fri, Jun 28, 2019 at 9:24 PM Alexander Potapenko <
> glider@google.com> wrote:
> >> > > >
> >> > > > On Fri, Jun 28, 2019 at 3:10 PM Xin Long <lucien.xin@gmail.com>
> wrote:
> >> > > > >
> >> > > > > This is what I did:
> >> > > > > https://paste.fedoraproject.org/paste/q4~GWx9Sx~QUbJQfNDoJIw
> >> > > > >
> >> > > > > There's no process_64.i file generated.
> >> > > > >
> >> > > > > Btw, I couldn't find "-c" in the command line, so there was no
> "-E" added.
> >> > > > Ah, right, Clang is invoked with -S. Could you replace that one
> with -E?
> >> > > > > On Fri, Jun 28, 2019 at 8:40 PM Alexander Potapenko <
> glider@google.com> wrote:
> >> > > > > >
> >> > > > > > It's interesting that you're seeing the same error as
> reported here:
> >> > > > > > https://github.com/google/kmsan/issues/53
> >> > > > > > I've updated my Clang to
> a4771e9dfdb0485c2edb416bfdc479d49de0aa14, but
> >> > > > > > the kernel compiles just fine.
> >> > > > > > May I ask you to do the following:
> >> > > > > >
> >> > > > > >  - run `make V=3D1` to capture the command line used to buil=
d
> >> > > > > > arch/x86/kernel/process_64.o
> >> > > > > >  - copy and paste the command line into a shell, remove '-o
> >> > > > > > /tmp/somefile' and run again to make sure the compiler still
> crashes
> >> > > > > >  - replace '-c' with '-E' in the command line and add '-o
> >> > > > > > process_64.i' to the end
> >> > > > > >  - send me the resulting preprocessed file (process_64.i)
> >> > > > > >
> >> > > > > > Thanks!
> >> > > > > >
> >> > > > > >
> >> > > > > >
> >> > > > > > On Thu, Jun 27, 2019 at 4:45 PM Xin Long <
> lucien.xin@gmail.com> wrote:
> >> > > > > > >
> >> > > > > > > Now I'm using:
> >> > > > > > > # Compiler: clang version 9.0.0
> >> > > > > > > (https://github.com/llvm/llvm-project.git
> >> > > > > > > a056684c335995214f6d3467c699d32f8e73b763)
> >> > > > > > >
> >> > > > > > > Errors shows up when building the kernel:
> >> > > > > > >
> >> > > > > > >   CC      arch/x86/kernel/process_64.o
> >> > > > > > > clang-9:
> /home/tools/llvm-project/llvm/lib/Transforms/Instrumentation/MemorySaniti=
zer.cpp:3236:
> >> > > > > > > void
> {anonymous}::MemorySanitizerVisitor::visitCallSite(llvm::CallSite):
> >> > > > > > > Assertion `(CS.isCall() || CS.isInvoke()) && "Unknown type
> of
> >> > > > > > > CallSite"' failed.
> >> > > > > > > Stack dump:
> >> > > > > > > 0.      Program arguments:
> /home/tools/llvm-project/build/bin/clang-9
> >> > > > > > > -cc1 -triple x86_64-unknown-linux-gnu -S -disable-free
> -main-file-name
> >> > > > > > > process_64.c -mrelocation-model static -mthread-model posi=
x
> >> > > > > > > -fno-delete-null-pointer-checks -mllvm -warn-stack-size=3D=
2048
> >> > > > > > > -mdisable-fp-elim -relaxed-aliasing -mdisable-tail-calls
> -fmath-errno
> >> > > > > > > -masm-verbose -no-integrated-as -mconstructor-aliases
> -fuse-init-array
> >> > > > > > > -mcode-model kernel -target-cpu core2 -target-feature
> >> > > > > > > +retpoline-indirect-calls -target-feature
> +retpoline-indirect-branches
> >> > > > > > > -target-feature -sse -target-feature -mmx -target-feature
> -sse2
> >> > > > > > > -target-feature -3dnow -target-feature -avx -target-featur=
e
> -x87
> >> > > > > > > -target-feature +retpoline-external-thunk -disable-red-zon=
e
> >> > > > > > > -dwarf-column-info -debug-info-kind=3Dlimited -dwarf-versi=
on=3D4
> >> > > > > > > -debugger-tuning=3Dgdb -momit-leaf-frame-pointer
> -coverage-notes-file
> >> > > > > > > /home/kmsan/arch/x86/kernel/process_64.gcno -nostdsystemin=
c
> >> > > > > > > -nobuiltininc -resource-dir
> >> > > > > > > /home/tools/llvm-project/build/lib/clang/9.0.0
> -dependency-file
> >> > > > > > > arch/x86/kernel/.process_64.o.d -MT
> arch/x86/kernel/process_64.o
> >> > > > > > > -sys-header-deps -isystem
> >> > > > > > > /home/tools/llvm-project/build/lib/clang/9.0.0/include
> -include
> >> > > > > > > ./include/linux/kconfig.h -include
> ./include/linux/compiler_types.h -I
> >> > > > > > > ./arch/x86/include -I ./arch/x86/include/generated -I
> ./include -I
> >> > > > > > > ./arch/x86/include/uapi -I
> ./arch/x86/include/generated/uapi -I
> >> > > > > > > ./include/uapi -I ./include/generated/uapi -D __KERNEL__ -=
D
> >> > > > > > > CONFIG_X86_X32_ABI -D CONFIG_AS_CFI=3D1 -D
> CONFIG_AS_CFI_SIGNAL_FRAME=3D1
> >> > > > > > > -D CONFIG_AS_CFI_SECTIONS=3D1 -D CONFIG_AS_SSSE3=3D1 -D
> CONFIG_AS_AVX=3D1 -D
> >> > > > > > > CONFIG_AS_AVX2=3D1 -D CONFIG_AS_AVX512=3D1 -D
> CONFIG_AS_SHA1_NI=3D1 -D
> >> > > > > > > CONFIG_AS_SHA256_NI=3D1 -D KBUILD_BASENAME=3D"process_64" =
-D
> >> > > > > > > KBUILD_MODNAME=3D"process_64" -O2 -Wall -Wundef
> >> > > > > > > -Werror=3Dstrict-prototypes -Wno-trigraphs
> >> > > > > > > -Werror=3Dimplicit-function-declaration -Werror=3Dimplicit=
-int
> >> > > > > > > -Wno-format-security -Wno-sign-compare
> -Wno-address-of-packed-member
> >> > > > > > > -Wno-format-invalid-specifier -Wno-gnu
> -Wno-tautological-compare
> >> > > > > > > -Wno-unused-const-variable -Wdeclaration-after-statement
> -Wvla
> >> > > > > > > -Wno-pointer-sign -Werror=3Ddate-time
> -Werror=3Dincompatible-pointer-types
> >> > > > > > > -Wno-initializer-overrides -Wno-unused-value -Wno-format
> >> > > > > > > -Wno-sign-compare -Wno-format-zero-length -Wno-uninitializ=
ed
> >> > > > > > > -std=3Dgnu89 -fno-dwarf-directory-asm -fdebug-compilation-=
dir
> >> > > > > > > /home/kmsan -ferror-limit 19 -fmessage-length 0
> >> > > > > > > -fsanitize=3Dkernel-memory -fwrapv -stack-protector 2
> >> > > > > > > -mstack-alignment=3D8 -fwchar-type=3Dshort -fno-signed-wch=
ar
> >> > > > > > > -fobjc-runtime=3Dgcc -fno-common -fdiagnostics-show-option
> >> > > > > > > -fcolor-diagnostics -vectorize-loops -vectorize-slp -o
> >> > > > > > > /tmp/process_64-e20ead.s -x c arch/x86/kernel/process_64.c
> >> > > > > > > 1.      <eof> parser at end of file
> >> > > > > > > 2.      Per-module optimization passes
> >> > > > > > > 3.      Running pass 'Function Pass Manager' on module
> >> > > > > > > 'arch/x86/kernel/process_64.c'.
> >> > > > > > > 4.      Running pass 'MemorySanitizerLegacyPass' on
> function '@start_thread'
> >> > > > > > >  #0 0x00000000024f03ba
> llvm::sys::PrintStackTrace(llvm::raw_ostream&)
> >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x24f03ba)
> >> > > > > > >  #1 0x00000000024ee214 llvm::sys::RunSignalHandlers()
> >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x24ee214)
> >> > > > > > >  #2 0x00000000024ee375 SignalHandler(int)
> >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x24ee375)
> >> > > > > > >  #3 0x00007f85ed99bd80 __restore_rt
> (/lib64/libpthread.so.0+0x12d80)
> >> > > > > > >  #4 0x00007f85ec47c93f raise (/lib64/libc.so.6+0x3793f)
> >> > > > > > >  #5 0x00007f85ec466c95 abort (/lib64/libc.so.6+0x21c95)
> >> > > > > > >  #6 0x00007f85ec466b69 _nl_load_domain.cold.0
> (/lib64/libc.so.6+0x21b69)
> >> > > > > > >  #7 0x00007f85ec474df6 (/lib64/libc.so.6+0x2fdf6)
> >> > > > > > >  #8 0x000000000327b864 (anonymous
> >> > > > > > >
> namespace)::MemorySanitizerVisitor::visitCallSite(llvm::CallSite)
> >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x327b864)
> >> > > > > > >  #9 0x0000000003283036 (anonymous
> >> > > > > > > namespace)::MemorySanitizerVisitor::runOnFunction()
> >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x3283036)
> >> > > > > > > #10 0x000000000328605f (anonymous
> >> > > > > > >
> namespace)::MemorySanitizer::sanitizeFunction(llvm::Function&,
> >> > > > > > > llvm::TargetLibraryInfo&)
> >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x328605f)
> >> > > > > > > #11 0x0000000001f42ac8
> >> > > > > > > llvm::FPPassManager::runOnFunction(llvm::Function&)
> >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x1f42ac8)
> >> > > > > > > #12 0x0000000001f42be9
> llvm::FPPassManager::runOnModule(llvm::Module&)
> >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x1f42be9)
> >> > > > > > > #13 0x0000000001f41ed8
> >> > > > > > > llvm::legacy::PassManagerImpl::run(llvm::Module&)
> >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x1f41ed8)
> >> > > > > > > #14 0x00000000026fa4f8 (anonymous
> >> > > > > > >
> namespace)::EmitAssemblyHelper::EmitAssembly(clang::BackendAction,
> >> > > > > > > std::unique_ptr<llvm::raw_pwrite_stream,
> >> > > > > > > std::default_delete<llvm::raw_pwrite_stream> >)
> >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x26fa4f8)
> >> > > > > > > #15 0x00000000026fbbf8
> >> > > > > > > clang::EmitBackendOutput(clang::DiagnosticsEngine&,
> >> > > > > > > clang::HeaderSearchOptions const&, clang::CodeGenOptions
> const&,
> >> > > > > > > clang::TargetOptions const&, clang::LangOptions const&,
> >> > > > > > > llvm::DataLayout const&, llvm::Module*,
> clang::BackendAction,
> >> > > > > > > std::unique_ptr<llvm::raw_pwrite_stream,
> >> > > > > > > std::default_delete<llvm::raw_pwrite_stream> >)
> >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x26fbbf8)
> >> > > > > > > #16 0x000000000310234d
> >> > > > > > >
> clang::BackendConsumer::HandleTranslationUnit(clang::ASTContext&)
> >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x310234d)
> >> > > > > > > #17 0x0000000003aaddf9 clang::ParseAST(clang::Sema&, bool,
> bool)
> >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x3aaddf9)
> >> > > > > > > #18 0x00000000030fe5e0 clang::CodeGenAction::ExecuteAction=
()
> >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x30fe5e0)
> >> > > > > > > #19 0x0000000002ba1929 clang::FrontendAction::Execute()
> >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x2ba1929)
> >> > > > > > > #20 0x0000000002b68e62
> >> > > > > > >
> clang::CompilerInstance::ExecuteAction(clang::FrontendAction&)
> >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x2b68e62)
> >> > > > > > > #21 0x0000000002c5738a
> >> > > > > > > clang::ExecuteCompilerInvocation(clang::CompilerInstance*)
> >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x2c5738a)
> >> > > > > > > #22 0x00000000009cd1a6 cc1_main(llvm::ArrayRef<char
> const*>, char
> >> > > > > > > const*, void*)
> (/home/tools/llvm-project/build/bin/clang-9+0x9cd1a6)
> >> > > > > > > #23 0x000000000094cac1 main
> >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x94cac1)
> >> > > > > > > #24 0x00007f85ec468813 __libc_start_main
> (/lib64/libc.so.6+0x23813)
> >> > > > > > > #25 0x00000000009c96ee _start
> >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x9c96ee)
> >> > > > > > > clang-9: error: unable to execute command: Aborted (core
> dumped)
> >> > > > > > > clang-9: error: clang frontend command failed due to signa=
l
> (use -v to
> >> > > > > > > see invocation)
> >> > > > > > > clang version 9.0.0 (
> https://github.com/llvm/llvm-project.git
> >> > > > > > > a056684c335995214f6d3467c699d32f8e73b763)
> >> > > > > > > Target: x86_64-unknown-linux-gnu
> >> > > > > > > Thread model: posix
> >> > > > > > > InstalledDir: /home/tools/llvm-project/build/bin
> >> > > > > > > clang-9: note: diagnostic msg: PLEASE submit a bug report =
to
> >> > > > > > > https://bugs.llvm.org/ and include the crash backtrace,
> preprocessed
> >> > > > > > > source, and associated run script.
> >> > > > > > > clang-9: note: diagnostic msg:
> >> > > > > > > ********************
> >> > > > > > >
> >> > > > > > > PLEASE ATTACH THE FOLLOWING FILES TO THE BUG REPORT:
> >> > > > > > > Preprocessed source(s) and associated run script(s) are
> located at:
> >> > > > > > > clang-9: note: diagnostic msg: /tmp/process_64-5fbbdc.c
> >> > > > > > > clang-9: note: diagnostic msg: /tmp/process_64-5fbbdc.sh
> >> > > > > > > clang-9: note: diagnostic msg:
> >> > > > > > >
> >> > > > > > > ********************
> >> > > > > > > make[2]: *** [scripts/Makefile.build:276:
> >> > > > > > > arch/x86/kernel/process_64.o] Error 254
> >> > > > > > >
> >> > > > > > >
> >> > > > > > > any idea why?
> >> > > > > > >
> >> > > > > > > On Thu, Jun 27, 2019 at 5:23 PM Alexander Potapenko <
> glider@google.com> wrote:
> >> > > > > > > >
> >> > > > > > > > Actually, your config says:
> >> > > > > > > >   "Compiler: clang version 8.0.0 (trunk 343298)"
> >> > > > > > > > I think you'll need at least Clang r362410 (mine is
> r362913)
> >> > > > > > > >
> >> > > > > > > > On Thu, Jun 27, 2019 at 11:20 AM Alexander Potapenko <
> glider@google.com> wrote:
> >> > > > > > > > >
> >> > > > > > > > > Hi Xin,
> >> > > > > > > > >
> >> > > > > > > > > Sorry for the late reply.
> >> > > > > > > > > I've built the ToT KMSAN tree using your config and my
> almost-ToT
> >> > > > > > > > > Clang and couldn't reproduce the problem.
> >> > > > > > > > > I believe something is wrong with your Clang version, =
as
> >> > > > > > > > > CONFIG_CLANG_VERSION should really be 90000.
> >> > > > > > > > > You can run `make V=3D1` to see which Clang version is
> being invoked -
> >> > > > > > > > > make sure it's a fresh one.
> >> > > > > > > > >
> >> > > > > > > > > HTH,
> >> > > > > > > > > Alex
> >> > > > > > > > >
> >> > > > > > > > > On Fri, Jun 21, 2019 at 10:09 PM Xin Long <
> lucien.xin@gmail.com> wrote:
> >> > > > > > > > > >
> >> > > > > > > > > > as attached,
> >> > > > > > > > > >
> >> > > > > > > > > > It actually came from
> https://syzkaller.appspot.com/x/.config?x=3D602468164ccdc30a
> >> > > > > > > > > > after I built, clang version changed to:
> >> > > > > > > > > >
> >> > > > > > > > > > CONFIG_CLANG_VERSION=3D80000
> >> > > > > > > > > >
> >> > > > > > > > > > On Sat, Jun 22, 2019 at 2:06 AM Alexander Potapenko =
<
> glider@google.com> wrote:
> >> > > > > > > > > > >
> >> > > > > > > > > > > Hi Xin,
> >> > > > > > > > > > >
> >> > > > > > > > > > > Could you please share the config you're using to
> build the kernel?
> >> > > > > > > > > > > I'll take a closer look on Monday when I am back t=
o
> the office.
> >> > > > > > > > > > >
> >> > > > > > > > > > > On Fri, 21 Jun 2019, 18:15 Xin Long, <
> lucien.xin@gmail.com> wrote:
> >> > > > > > > > > > >>
> >> > > > > > > > > > >> this is my command:
> >> > > > > > > > > > >>
> >> > > > > > > > > > >> /usr/libexec/qemu-kvm -smp 2 -m 4G -enable-kvm
> -cpu host \
> >> > > > > > > > > > >>     -net nic -net user,hostfwd=3Dtcp::10022-:22 \
> >> > > > > > > > > > >>     -kernel /home/kmsan/arch/x86/boot/bzImage
> -nographic \
> >> > > > > > > > > > >>     -device virtio-scsi-pci,id=3Dscsi \
> >> > > > > > > > > > >>     -device scsi-hd,bus=3Dscsi.0,drive=3Dd0 \
> >> > > > > > > > > > >>     -drive
> file=3D/root/test/wheezy.img,format=3Draw,if=3Dnone,id=3Dd0 \
> >> > > > > > > > > > >>     -append "root=3D/dev/sda console=3DttyS0
> earlyprintk=3Dserial rodata=3Dn \
> >> > > > > > > > > > >>       oops=3Dpanic panic_on_warn=3D1 panic=3D8640=
0
> kvm-intel.nested=3D1 \
> >> > > > > > > > > > >>       security=3Dapparmor ima_policy=3Dtcb
> workqueue.watchdog_thresh=3D140 \
> >> > > > > > > > > > >>       nf-conntrack-ftp.ports=3D20000
> nf-conntrack-tftp.ports=3D20000 \
> >> > > > > > > > > > >>       nf-conntrack-sip.ports=3D20000
> nf-conntrack-irc.ports=3D20000 \
> >> > > > > > > > > > >>       nf-conntrack-sane.ports=3D20000
> vivid.n_devs=3D16 \
> >> > > > > > > > > > >>
>  vivid.multiplanar=3D1,2,1,2,1,2,1,2,1,2,1,2,1,2,1,2 \
> >> > > > > > > > > > >>       spec_store_bypass_disable=3Dprctl nopcid"
> >> > > > > > > > > > >>
> >> > > > > > > > > > >> the commit is on:
> >> > > > > > > > > > >> commit f75e4cfea97f67b7530b8b991b3005f991f04778
> (HEAD)
> >> > > > > > > > > > >> Author: Alexander Potapenko <glider@google.com>
> >> > > > > > > > > > >> Date:   Wed May 22 12:30:13 2019 +0200
> >> > > > > > > > > > >>
> >> > > > > > > > > > >>     kmsan: use kmsan_handle_urb() in urb.c
> >> > > > > > > > > > >>
> >> > > > > > > > > > >> and when starting, it shows:
> >> > > > > > > > > > >> [    0.561925][    T0] Kernel command line:
> root=3D/dev/sda
> >> > > > > > > > > > >> console=3DttyS0 earlyprintk=3Dserial rodata=3Dn
>  oops=3Dpanic
> >> > > > > > > > > > >> panic_on_warn=3D1 panic=3D86400 kvm-intel.nested=
=3D1
>    security=3Dad
> >> > > > > > > > > > >> [    0.707792][    T0] Memory: 3087328K/4193776K
> available (219164K
> >> > > > > > > > > > >> kernel code, 7059K rwdata, 11712K rodata, 5064K
> init, 11904K bss,
> >> > > > > > > > > > >> 1106448K reserved, 0K cma-reserved)
> >> > > > > > > > > > >> [    0.710935][    T0] SLUB: HWalign=3D64,
> Order=3D0-3, MinObjects=3D0,
> >> > > > > > > > > > >> CPUs=3D2, Nodes=3D1
> >> > > > > > > > > > >> [    0.711953][    T0] Starting
> KernelMemorySanitizer
> >> > > > > > > > > > >> [    0.712563][    T0]
> >> > > > > > > > > > >>
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> >> > > > > > > > > > >> [    0.713657][    T0] BUG: KMSAN: uninit-value i=
n
> mutex_lock+0xd1/0xe0
> >> > > > > > > > > > >> [    0.714570][    T0] CPU: 0 PID: 0 Comm: swappe=
r
> Not tainted 5.1.0 #5
> >> > > > > > > > > > >> [    0.715417][    T0] Hardware name: Red Hat KVM=
,
> BIOS
> >> > > > > > > > > > >> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01/2014
> >> > > > > > > > > > >> [    0.716659][    T0] Call Trace:
> >> > > > > > > > > > >> [    0.717127][    T0]  dump_stack+0x134/0x190
> >> > > > > > > > > > >> [    0.717727][    T0]  kmsan_report+0x131/0x2a0
> >> > > > > > > > > > >> [    0.718347][    T0]  __msan_warning+0x7a/0xf0
> >> > > > > > > > > > >> [    0.718952][    T0]  mutex_lock+0xd1/0xe0
> >> > > > > > > > > > >> [    0.719478][    T0]
> __cpuhp_setup_state_cpuslocked+0x149/0xd20
> >> > > > > > > > > > >> [    0.720260][    T0]  ? vprintk_func+0x6b5/0x8a=
0
> >> > > > > > > > > > >> [    0.720926][    T0]  ?
> rb_get_reader_page+0x1140/0x1140
> >> > > > > > > > > > >> [    0.721632][    T0]
> __cpuhp_setup_state+0x181/0x2e0
> >> > > > > > > > > > >> [    0.722374][    T0]  ?
> rb_get_reader_page+0x1140/0x1140
> >> > > > > > > > > > >> [    0.723115][    T0]
> tracer_alloc_buffers+0x16b/0xb96
> >> > > > > > > > > > >> [    0.723846][    T0]
> early_trace_init+0x193/0x28f
> >> > > > > > > > > > >> [    0.724501][    T0]  start_kernel+0x497/0xb38
> >> > > > > > > > > > >> [    0.725134][    T0]
> x86_64_start_reservations+0x19/0x2f
> >> > > > > > > > > > >> [    0.725871][    T0]
> x86_64_start_kernel+0x84/0x87
> >> > > > > > > > > > >> [    0.726538][    T0]
> secondary_startup_64+0xa4/0xb0
> >> > > > > > > > > > >> [    0.727173][    T0]
> >> > > > > > > > > > >> [    0.727454][    T0] Local variable description=
:
> >> > > > > > > > > > >> ----success.i.i.i.i@mutex_lock
> >> > > > > > > > > > >> [    0.728379][    T0] Variable was created at:
> >> > > > > > > > > > >> [    0.728977][    T0]  mutex_lock+0x48/0xe0
> >> > > > > > > > > > >> [    0.729536][    T0]
> __cpuhp_setup_state_cpuslocked+0x149/0xd20
> >> > > > > > > > > > >> [    0.730323][    T0]
> >> > > > > > > > > > >>
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> >> > > > > > > > > > >> [    0.731364][    T0] Disabling lock debugging
> due to kernel taint
> >> > > > > > > > > > >> [    0.732169][    T0] Kernel panic - not syncing=
:
> panic_on_warn set ...
> >> > > > > > > > > > >> [    0.733047][    T0] CPU: 0 PID: 0 Comm: swappe=
r
> Tainted: G    B
> >> > > > > > > > > > >>         5.1.0 #5
> >> > > > > > > > > > >> [    0.734080][    T0] Hardware name: Red Hat KVM=
,
> BIOS
> >> > > > > > > > > > >> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01/2014
> >> > > > > > > > > > >> [    0.735319][    T0] Call Trace:
> >> > > > > > > > > > >> [    0.735735][    T0]  dump_stack+0x134/0x190
> >> > > > > > > > > > >> [    0.736308][    T0]  panic+0x3ec/0xb3b
> >> > > > > > > > > > >> [    0.736826][    T0]  kmsan_report+0x29a/0x2a0
> >> > > > > > > > > > >> [    0.737417][    T0]  __msan_warning+0x7a/0xf0
> >> > > > > > > > > > >> [    0.737973][    T0]  mutex_lock+0xd1/0xe0
> >> > > > > > > > > > >> [    0.738527][    T0]
> __cpuhp_setup_state_cpuslocked+0x149/0xd20
> >> > > > > > > > > > >> [    0.739342][    T0]  ? vprintk_func+0x6b5/0x8a=
0
> >> > > > > > > > > > >> [    0.739972][    T0]  ?
> rb_get_reader_page+0x1140/0x1140
> >> > > > > > > > > > >> [    0.740695][    T0]
> __cpuhp_setup_state+0x181/0x2e0
> >> > > > > > > > > > >> [    0.741412][    T0]  ?
> rb_get_reader_page+0x1140/0x1140
> >> > > > > > > > > > >> [    0.742160][    T0]
> tracer_alloc_buffers+0x16b/0xb96
> >> > > > > > > > > > >> [    0.742866][    T0]
> early_trace_init+0x193/0x28f
> >> > > > > > > > > > >> [    0.743512][    T0]  start_kernel+0x497/0xb38
> >> > > > > > > > > > >> [    0.744128][    T0]
> x86_64_start_reservations+0x19/0x2f
> >> > > > > > > > > > >> [    0.744863][    T0]
> x86_64_start_kernel+0x84/0x87
> >> > > > > > > > > > >> [    0.745534][    T0]
> secondary_startup_64+0xa4/0xb0
> >> > > > > > > > > > >> [    0.746290][    T0] Rebooting in 86400 seconds=
..
> >> > > > > > > > > > >>
> >> > > > > > > > > > >> when I set "panic_on_warn=3D0", it foods the cons=
ole
> with:
> >> > > > > > > > > > >> ...
> >> > > > > > > > > > >> [   25.206759][    C0] Variable was created at:
> >> > > > > > > > > > >> [   25.207302][    C0]  vprintk_emit+0xf4/0x800
> >> > > > > > > > > > >> [   25.207844][    C0]  vprintk_deferred+0x90/0xe=
d
> >> > > > > > > > > > >> [   25.208404][    C0]
> >> > > > > > > > > > >>
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> >> > > > > > > > > > >> [   25.209763][    C0]
> x86_64_start_reservations+0x19/0x2f
> >> > > > > > > > > > >> [   25.209769][    C0]
> >> > > > > > > > > > >>
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> >> > > > > > > > > > >> [   25.211408][    C0] BUG: KMSAN: uninit-value i=
n
> vprintk_emit+0x443/0x800
> >> > > > > > > > > > >> [   25.212237][    C0] CPU: 0 PID: 0 Comm:
> swapper/0 Tainted: G    B
> >> > > > > > > > > > >>           5.1.0 #5
> >> > > > > > > > > > >> [   25.213206][    C0] Hardware name: Red Hat KVM=
,
> BIOS
> >> > > > > > > > > > >> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01/2014
> >> > > > > > > > > > >> [   25.214326][    C0] Call Trace:
> >> > > > > > > > > > >> [   25.214725][    C0]  <IRQ>
> >> > > > > > > > > > >> [   25.215080][    C0]  dump_stack+0x134/0x190
> >> > > > > > > > > > >> [   25.215624][    C0]  kmsan_report+0x131/0x2a0
> >> > > > > > > > > > >> [   25.216204][    C0]  __msan_warning+0x7a/0xf0
> >> > > > > > > > > > >> [   25.216771][    C0]  vprintk_emit+0x443/0x800
> >> > > > > > > > > > >> [   25.217334][    C0]  ?
> __msan_metadata_ptr_for_store_1+0x13/0x20
> >> > > > > > > > > > >> [   25.218127][    C0]  vprintk_deferred+0x90/0xe=
d
> >> > > > > > > > > > >> [   25.218714][    C0]  printk_deferred+0x186/0x1=
d3
> >> > > > > > > > > > >> [   25.219353][    C0]
> __printk_safe_flush+0x72e/0xc00
> >> > > > > > > > > > >> [   25.220006][    C0]  ?
> printk_safe_flush+0x1e0/0x1e0
> >> > > > > > > > > > >> [   25.220635][    C0]  irq_work_run+0x1ad/0x5c0
> >> > > > > > > > > > >> [   25.221210][    C0]  ?
> flat_init_apic_ldr+0x170/0x170
> >> > > > > > > > > > >> [   25.221851][    C0]
> smp_irq_work_interrupt+0x237/0x3e0
> >> > > > > > > > > > >> [   25.222520][    C0]
> irq_work_interrupt+0x2e/0x40
> >> > > > > > > > > > >> [   25.223110][    C0]  </IRQ>
> >> > > > > > > > > > >> [   25.223475][    C0] RIP:
> 0010:kmem_cache_init_late+0x0/0xb
> >> > > > > > > > > > >> [   25.224164][    C0] Code: d4 e8 5d dd 2e f2 e9
> 74 fe ff ff 48 89 d3
> >> > > > > > > > > > >> 8b 7d d4 e8 cd d7 2e f2 89 c0 48 89 c1 48 c1 e1 2=
0
> 48 09 c1 48 89 0b
> >> > > > > > > > > > >> e9 81 fe ff ff <55> 48 89 e5 e8 20 de 2e1
> >> > > > > > > > > > >> [   25.226526][    C0] RSP: 0000:ffffffff8f40feb8
> EFLAGS: 00000246
> >> > > > > > > > > > >> ORIG_RAX: ffffffffffffff09
> >> > > > > > > > > > >> [   25.227548][    C0] RAX: ffff88813f995785 RBX:
> 0000000000000000
> >> > > > > > > > > > >> RCX: 0000000000000000
> >> > > > > > > > > > >> [   25.228511][    C0] RDX: ffff88813f2b0784 RSI:
> 0000160000000000
> >> > > > > > > > > > >> RDI: 0000000000000785
> >> > > > > > > > > > >> [   25.229473][    C0] RBP: ffffffff8f40ff20 R08:
> 000000000fac3785
> >> > > > > > > > > > >> R09: 0000778000000001
> >> > > > > > > > > > >> [   25.230440][    C0] R10: ffffd0ffffffffff R11:
> 0000100000000000
> >> > > > > > > > > > >> R12: 0000000000000000
> >> > > > > > > > > > >> [   25.231403][    C0] R13: 0000000000000000 R14:
> ffffffff8fb8cfd0
> >> > > > > > > > > > >> R15: 0000000000000000
> >> > > > > > > > > > >> [   25.232407][    C0]  ? start_kernel+0x5d8/0xb3=
8
> >> > > > > > > > > > >> [   25.233003][    C0]
> x86_64_start_reservations+0x19/0x2f
> >> > > > > > > > > > >> [   25.233670][    C0]
> x86_64_start_kernel+0x84/0x87
> >> > > > > > > > > > >> [   25.234314][    C0]
> secondary_startup_64+0xa4/0xb0
> >> > > > > > > > > > >> [   25.234949][    C0]
> >> > > > > > > > > > >> [   25.235231][    C0] Local variable description=
:
> ----flags.i.i.i@vprintk_emit
> >> > > > > > > > > > >> [   25.236101][    C0] Variable was created at:
> >> > > > > > > > > > >> [   25.236643][    C0]  vprintk_emit+0xf4/0x800
> >> > > > > > > > > > >> [   25.237188][    C0]  vprintk_deferred+0x90/0xe=
d
> >> > > > > > > > > > >> [   25.237752][    C0]
> >> > > > > > > > > > >>
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> >> > > > > > > > > > >> [   25.239117][    C0]
> x86_64_start_kernel+0x84/0x87
> >> > > > > > > > > > >> [   25.239123][    C0]
> >> > > > > > > > > > >>
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> >> > > > > > > > > > >> [   25.240704][    C0] BUG: KMSAN: uninit-value i=
n
> vprintk_emit+0x443/0x800
> >> > > > > > > > > > >> [   25.241540][    C0] CPU: 0 PID: 0 Comm:
> swapper/0 Tainted: G    B
> >> > > > > > > > > > >>           5.1.0 #5
> >> > > > > > > > > > >> [   25.242512][    C0] Hardware name: Red Hat KVM=
,
> BIOS
> >> > > > > > > > > > >> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01/2014
> >> > > > > > > > > > >> [   25.243635][    C0] Call Trace:
> >> > > > > > > > > > >> [   25.244038][    C0]  <IRQ>
> >> > > > > > > > > > >> [   25.244390][    C0]  dump_stack+0x134/0x190
> >> > > > > > > > > > >> [   25.244940][    C0]  kmsan_report+0x131/0x2a0
> >> > > > > > > > > > >> [   25.245515][    C0]  __msan_warning+0x7a/0xf0
> >> > > > > > > > > > >> [   25.246082][    C0]  vprintk_emit+0x443/0x800
> >> > > > > > > > > > >> [   25.246638][    C0]  ?
> __msan_metadata_ptr_for_store_1+0x13/0x20
> >> > > > > > > > > > >> [   25.247430][    C0]  vprintk_deferred+0x90/0xe=
d
> >> > > > > > > > > > >> [   25.248018][    C0]  printk_deferred+0x186/0x1=
d3
> >> > > > > > > > > > >> [   25.248650][    C0]
> __printk_safe_flush+0x72e/0xc00
> >> > > > > > > > > > >> [   25.249320][    C0]  ?
> printk_safe_flush+0x1e0/0x1e0
> >> > > > > > > > > > >> [   25.249949][    C0]  irq_work_run+0x1ad/0x5c0
> >> > > > > > > > > > >> [   25.250524][    C0]  ?
> flat_init_apic_ldr+0x170/0x170
> >> > > > > > > > > > >> [   25.251167][    C0]
> smp_irq_work_interrupt+0x237/0x3e0
> >> > > > > > > > > > >> [   25.251837][    C0]
> irq_work_interrupt+0x2e/0x40
> >> > > > > > > > > > >> [   25.252424][    C0]  </IRQ>
> >> > > > > > > > > > >> ....
> >> > > > > > > > > > >>
> >> > > > > > > > > > >>
> >> > > > > > > > > > >> I couldn't even log in.
> >> > > > > > > > > > >>
> >> > > > > > > > > > >> how should I use qemu with wheezy.img to start a
> kmsan kernel?
> >> > > > > > > > > > >>
> >> > > > > > > > > > >> Thanks.
> >> > > > > > > > >
> >> > > > > > > > >
> >> > > > > > > > >
> >> > > > > > > > > --
> >> > > > > > > > > Alexander Potapenko
> >> > > > > > > > > Software Engineer
> >> > > > > > > > >
> >> > > > > > > > > Google Germany GmbH
> >> > > > > > > > > Erika-Mann-Stra=C3=9Fe, 33
> >> > > > > > > > > 80636 M=C3=BCnchen
> >> > > > > > > > >
> >> > > > > > > > > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLai=
ne Prado
> >> > > > > > > > > Registergericht und -nummer: Hamburg, HRB 86891
> >> > > > > > > > > Sitz der Gesellschaft: Hamburg
> >> > > > > > > >
> >> > > > > > > >
> >> > > > > > > >
> >> > > > > > > > --
> >> > > > > > > > Alexander Potapenko
> >> > > > > > > > Software Engineer
> >> > > > > > > >
> >> > > > > > > > Google Germany GmbH
> >> > > > > > > > Erika-Mann-Stra=C3=9Fe, 33
> >> > > > > > > > 80636 M=C3=BCnchen
> >> > > > > > > >
> >> > > > > > > > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine=
 Prado
> >> > > > > > > > Registergericht und -nummer: Hamburg, HRB 86891
> >> > > > > > > > Sitz der Gesellschaft: Hamburg
> >> > > > > >
> >> > > > > >
> >> > > > > >
> >> > > > > > --
> >> > > > > > Alexander Potapenko
> >> > > > > > Software Engineer
> >> > > > > >
> >> > > > > > Google Germany GmbH
> >> > > > > > Erika-Mann-Stra=C3=9Fe, 33
> >> > > > > > 80636 M=C3=BCnchen
> >> > > > > >
> >> > > > > > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Pra=
do
> >> > > > > > Registergericht und -nummer: Hamburg, HRB 86891
> >> > > > > > Sitz der Gesellschaft: Hamburg
> >> > > >
> >> > > >
> >> > > >
> >> > > > --
> >> > > > Alexander Potapenko
> >> > > > Software Engineer
> >> > > >
> >> > > > Google Germany GmbH
> >> > > > Erika-Mann-Stra=C3=9Fe, 33
> >> > > > 80636 M=C3=BCnchen
> >> > > >
> >> > > > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
> >> > > > Registergericht und -nummer: Hamburg, HRB 86891
> >> > > > Sitz der Gesellschaft: Hamburg
> >> >
> >> >
> >> >
> >> > --
> >> > Alexander Potapenko
> >> > Software Engineer
> >> >
> >> > Google Germany GmbH
> >> > Erika-Mann-Stra=C3=9Fe, 33
> >> > 80636 M=C3=BCnchen
> >> >
> >> > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
> >> > Registergericht und -nummer: Hamburg, HRB 86891
> >> > Sitz der Gesellschaft: Hamburg
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DWKLynY8fWdrsSxYcQXHMPC%2BVnjg-C322cfwR%3DSb3wuZA%40mail.=
gmail.com.
For more options, visit https://groups.google.com/d/optout.

--0000000000007ccb39058c65873f
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"auto">Thanks! I&#39;ll try this out next week. My tree might al=
so have local changes, if so, I&#39;d better figure it out sooner rather th=
an later :)</div><br><div class=3D"gmail_quote"><div dir=3D"ltr" class=3D"g=
mail_attr">On Fri, 28 Jun 2019, 19:18 Xin Long, &lt;<a href=3D"mailto:lucie=
n.xin@gmail.com">lucien.xin@gmail.com</a>&gt; wrote:<br></div><blockquote c=
lass=3D"gmail_quote" style=3D"margin:0 0 0 .8ex;border-left:1px #ccc solid;=
padding-left:1ex"># cd /home/tools/<br>
# git clone <a href=3D"https://github.com/llvm/llvm-project.git" rel=3D"nor=
eferrer noreferrer" target=3D"_blank">https://github.com/llvm/llvm-project.=
git</a><br>
# cd llvm-project/<br>
# mkdir build<br>
# cd build/<br>
# cmake -DLLVM_ENABLE_PROJECTS=3Dclang -DCMAKE_BUILD_TYPE=3DRelease<br>
-DLLVM_ENABLE_ASSERTIONS=3DON -G &quot;Unix Makefiles&quot; ../llvm<br>
# make<br>
# cd /home/kmsan<br>
# git checkout f75e4cfea97f<br>
(use the .config I sent you last time)<br>
# make CC=3D/home/tools/llvm-project/build/bin/clang -j64 -k LOCALVERSION=
=3D 2&gt;&amp;1<br>
<br>
These are the whole thing I did to build it.<br>
<br>
On Sat, Jun 29, 2019 at 12:09 AM Alexander Potapenko &lt;<a href=3D"mailto:=
glider@google.com" target=3D"_blank" rel=3D"noreferrer">glider@google.com</=
a>&gt; wrote:<br>
&gt;<br>
&gt; Hm, now that&#39;s your Clang binary versus mine :)<br>
&gt; Can you please ensure your git repo doesn&#39;t contain local changes =
and share the commands you&#39;re using to build Clang?<br>
&gt; (Both cmake and make or ninja)<br>
No any local changes on both llvm-project and kmsan<br>
<br>
&gt; Is the bug still reproducible in a clean CMake directory?<br>
A clean CMake directory? how to clean it? something like: # cmake clean<br>
<br>
Thank you for being so patient. :-)<br>
<br>
&gt;<br>
&gt; On Fri, 28 Jun 2019, 16:20 Xin Long, &lt;<a href=3D"mailto:lucien.xin@=
gmail.com" target=3D"_blank" rel=3D"noreferrer">lucien.xin@gmail.com</a>&gt=
; wrote:<br>
&gt;&gt;<br>
&gt;&gt; yes<br>
&gt;&gt;<br>
&gt;&gt; <a href=3D"https://paste.fedoraproject.org/paste/DU2nnxpZWpWMri9Up=
7hypA" rel=3D"noreferrer noreferrer" target=3D"_blank">https://paste.fedora=
project.org/paste/DU2nnxpZWpWMri9Up7hypA</a><br>
&gt;&gt;<br>
&gt;&gt; On Fri, Jun 28, 2019 at 9:48 PM Alexander Potapenko &lt;<a href=3D=
"mailto:glider@google.com" target=3D"_blank" rel=3D"noreferrer">glider@goog=
le.com</a>&gt; wrote:<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; Hm, strange, but I still can compile this file.<br>
&gt;&gt; &gt; Does the following command line crash your compiler?<br>
&gt;&gt; &gt; <a href=3D"https://paste.fedoraproject.org/paste/oJwOVm5cHWyd=
7hxIZ4uGeA" rel=3D"noreferrer noreferrer" target=3D"_blank">https://paste.f=
edoraproject.org/paste/oJwOVm5cHWyd7hxIZ4uGeA</a> (note it<br>
&gt;&gt; &gt; should be run from the same directory where process_64.i resi=
des; also<br>
&gt;&gt; &gt; make sure to invoke the right Clang)<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; On Fri, Jun 28, 2019 at 3:35 PM Xin Long &lt;<a href=3D"mailt=
o:lucien.xin@gmail.com" target=3D"_blank" rel=3D"noreferrer">lucien.xin@gma=
il.com</a>&gt; wrote:<br>
&gt;&gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; As attached, thanks.<br>
&gt;&gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; On Fri, Jun 28, 2019 at 9:24 PM Alexander Potapenko &lt;=
<a href=3D"mailto:glider@google.com" target=3D"_blank" rel=3D"noreferrer">g=
lider@google.com</a>&gt; wrote:<br>
&gt;&gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; On Fri, Jun 28, 2019 at 3:10 PM Xin Long &lt;<a hre=
f=3D"mailto:lucien.xin@gmail.com" target=3D"_blank" rel=3D"noreferrer">luci=
en.xin@gmail.com</a>&gt; wrote:<br>
&gt;&gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; This is what I did:<br>
&gt;&gt; &gt; &gt; &gt; &gt; <a href=3D"https://paste.fedoraproject.org/pas=
te/q4~GWx9Sx~QUbJQfNDoJIw" rel=3D"noreferrer noreferrer" target=3D"_blank">=
https://paste.fedoraproject.org/paste/q4~GWx9Sx~QUbJQfNDoJIw</a><br>
&gt;&gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; There&#39;s no process_64.i file generated.<br=
>
&gt;&gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; Btw, I couldn&#39;t find &quot;-c&quot; in the=
 command line, so there was no &quot;-E&quot; added.<br>
&gt;&gt; &gt; &gt; &gt; Ah, right, Clang is invoked with -S. Could you repl=
ace that one with -E?<br>
&gt;&gt; &gt; &gt; &gt; &gt; On Fri, Jun 28, 2019 at 8:40 PM Alexander Pota=
penko &lt;<a href=3D"mailto:glider@google.com" target=3D"_blank" rel=3D"nor=
eferrer">glider@google.com</a>&gt; wrote:<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; It&#39;s interesting that you&#39;re seei=
ng the same error as reported here:<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; <a href=3D"https://github.com/google/kmsa=
n/issues/53" rel=3D"noreferrer noreferrer" target=3D"_blank">https://github=
.com/google/kmsan/issues/53</a><br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; I&#39;ve updated my Clang to a4771e9dfdb0=
485c2edb416bfdc479d49de0aa14, but<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; the kernel compiles just fine.<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; May I ask you to do the following:<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt;=C2=A0 - run `make V=3D1` to capture the c=
ommand line used to build<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; arch/x86/kernel/process_64.o<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt;=C2=A0 - copy and paste the command line i=
nto a shell, remove &#39;-o<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; /tmp/somefile&#39; and run again to make =
sure the compiler still crashes<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt;=C2=A0 - replace &#39;-c&#39; with &#39;-E=
&#39; in the command line and add &#39;-o<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; process_64.i&#39; to the end<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt;=C2=A0 - send me the resulting preprocesse=
d file (process_64.i)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; Thanks!<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; On Thu, Jun 27, 2019 at 4:45 PM Xin Long =
&lt;<a href=3D"mailto:lucien.xin@gmail.com" target=3D"_blank" rel=3D"norefe=
rrer">lucien.xin@gmail.com</a>&gt; wrote:<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; Now I&#39;m using:<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; # Compiler: clang version 9.0.0<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; (<a href=3D"https://github.com/llvm/=
llvm-project.git" rel=3D"noreferrer noreferrer" target=3D"_blank">https://g=
ithub.com/llvm/llvm-project.git</a><br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; a056684c335995214f6d3467c699d32f8e73=
b763)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; Errors shows up when building the ke=
rnel:<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt;=C2=A0 =C2=A0CC=C2=A0 =C2=A0 =C2=A0 a=
rch/x86/kernel/process_64.o<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; clang-9: /home/tools/llvm-project/ll=
vm/lib/Transforms/Instrumentation/MemorySanitizer.cpp:3236:<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; void {anonymous}::MemorySanitizerVis=
itor::visitCallSite(llvm::CallSite):<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; Assertion `(CS.isCall() || CS.isInvo=
ke()) &amp;&amp; &quot;Unknown type of<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; CallSite&quot;&#39; failed.<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; Stack dump:<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; 0.=C2=A0 =C2=A0 =C2=A0 Program argum=
ents: /home/tools/llvm-project/build/bin/clang-9<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; -cc1 -triple x86_64-unknown-linux-gn=
u -S -disable-free -main-file-name<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; process_64.c -mrelocation-model stat=
ic -mthread-model posix<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; -fno-delete-null-pointer-checks -mll=
vm -warn-stack-size=3D2048<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; -mdisable-fp-elim -relaxed-aliasing =
-mdisable-tail-calls -fmath-errno<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; -masm-verbose -no-integrated-as -mco=
nstructor-aliases -fuse-init-array<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; -mcode-model kernel -target-cpu core=
2 -target-feature<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; +retpoline-indirect-calls -target-fe=
ature +retpoline-indirect-branches<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; -target-feature -sse -target-feature=
 -mmx -target-feature -sse2<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; -target-feature -3dnow -target-featu=
re -avx -target-feature -x87<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; -target-feature +retpoline-external-=
thunk -disable-red-zone<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; -dwarf-column-info -debug-info-kind=
=3Dlimited -dwarf-version=3D4<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; -debugger-tuning=3Dgdb -momit-leaf-f=
rame-pointer -coverage-notes-file<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; /home/kmsan/arch/x86/kernel/process_=
64.gcno -nostdsysteminc<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; -nobuiltininc -resource-dir<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; /home/tools/llvm-project/build/lib/c=
lang/9.0.0 -dependency-file<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; arch/x86/kernel/.process_64.o.d -MT =
arch/x86/kernel/process_64.o<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; -sys-header-deps -isystem<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; /home/tools/llvm-project/build/lib/c=
lang/9.0.0/include -include<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; ./include/linux/kconfig.h -include .=
/include/linux/compiler_types.h -I<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; ./arch/x86/include -I ./arch/x86/inc=
lude/generated -I ./include -I<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; ./arch/x86/include/uapi -I ./arch/x8=
6/include/generated/uapi -I<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; ./include/uapi -I ./include/generate=
d/uapi -D __KERNEL__ -D<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; CONFIG_X86_X32_ABI -D CONFIG_AS_CFI=
=3D1 -D CONFIG_AS_CFI_SIGNAL_FRAME=3D1<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; -D CONFIG_AS_CFI_SECTIONS=3D1 -D CON=
FIG_AS_SSSE3=3D1 -D CONFIG_AS_AVX=3D1 -D<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; CONFIG_AS_AVX2=3D1 -D CONFIG_AS_AVX5=
12=3D1 -D CONFIG_AS_SHA1_NI=3D1 -D<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; CONFIG_AS_SHA256_NI=3D1 -D KBUILD_BA=
SENAME=3D&quot;process_64&quot; -D<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; KBUILD_MODNAME=3D&quot;process_64&qu=
ot; -O2 -Wall -Wundef<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; -Werror=3Dstrict-prototypes -Wno-tri=
graphs<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; -Werror=3Dimplicit-function-declarat=
ion -Werror=3Dimplicit-int<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; -Wno-format-security -Wno-sign-compa=
re -Wno-address-of-packed-member<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; -Wno-format-invalid-specifier -Wno-g=
nu -Wno-tautological-compare<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; -Wno-unused-const-variable -Wdeclara=
tion-after-statement -Wvla<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; -Wno-pointer-sign -Werror=3Ddate-tim=
e -Werror=3Dincompatible-pointer-types<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; -Wno-initializer-overrides -Wno-unus=
ed-value -Wno-format<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; -Wno-sign-compare -Wno-format-zero-l=
ength -Wno-uninitialized<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; -std=3Dgnu89 -fno-dwarf-directory-as=
m -fdebug-compilation-dir<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; /home/kmsan -ferror-limit 19 -fmessa=
ge-length 0<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; -fsanitize=3Dkernel-memory -fwrapv -=
stack-protector 2<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; -mstack-alignment=3D8 -fwchar-type=
=3Dshort -fno-signed-wchar<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; -fobjc-runtime=3Dgcc -fno-common -fd=
iagnostics-show-option<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; -fcolor-diagnostics -vectorize-loops=
 -vectorize-slp -o<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; /tmp/process_64-e20ead.s -x c arch/x=
86/kernel/process_64.c<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; 1.=C2=A0 =C2=A0 =C2=A0 &lt;eof&gt; p=
arser at end of file<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; 2.=C2=A0 =C2=A0 =C2=A0 Per-module op=
timization passes<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; 3.=C2=A0 =C2=A0 =C2=A0 Running pass =
&#39;Function Pass Manager&#39; on module<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &#39;arch/x86/kernel/process_64.c&#3=
9;.<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; 4.=C2=A0 =C2=A0 =C2=A0 Running pass =
&#39;MemorySanitizerLegacyPass&#39; on function &#39;@start_thread&#39;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt;=C2=A0 #0 0x00000000024f03ba llvm::sy=
s::PrintStackTrace(llvm::raw_ostream&amp;)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; (/home/tools/llvm-project/build/bin/=
clang-9+0x24f03ba)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt;=C2=A0 #1 0x00000000024ee214 llvm::sy=
s::RunSignalHandlers()<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; (/home/tools/llvm-project/build/bin/=
clang-9+0x24ee214)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt;=C2=A0 #2 0x00000000024ee375 SignalHa=
ndler(int)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; (/home/tools/llvm-project/build/bin/=
clang-9+0x24ee375)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt;=C2=A0 #3 0x00007f85ed99bd80 __restor=
e_rt (/lib64/libpthread.so.0+0x12d80)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt;=C2=A0 #4 0x00007f85ec47c93f raise (/=
lib64/libc.so.6+0x3793f)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt;=C2=A0 #5 0x00007f85ec466c95 abort (/=
lib64/libc.so.6+0x21c95)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt;=C2=A0 #6 0x00007f85ec466b69 _nl_load=
_domain.cold.0 (/lib64/libc.so.6+0x21b69)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt;=C2=A0 #7 0x00007f85ec474df6 (/lib64/=
libc.so.6+0x2fdf6)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt;=C2=A0 #8 0x000000000327b864 (anonymo=
us<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; namespace)::MemorySanitizerVisitor::=
visitCallSite(llvm::CallSite)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; (/home/tools/llvm-project/build/bin/=
clang-9+0x327b864)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt;=C2=A0 #9 0x0000000003283036 (anonymo=
us<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; namespace)::MemorySanitizerVisitor::=
runOnFunction()<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; (/home/tools/llvm-project/build/bin/=
clang-9+0x3283036)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; #10 0x000000000328605f (anonymous<br=
>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; namespace)::MemorySanitizer::sanitiz=
eFunction(llvm::Function&amp;,<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; llvm::TargetLibraryInfo&amp;)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; (/home/tools/llvm-project/build/bin/=
clang-9+0x328605f)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; #11 0x0000000001f42ac8<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; llvm::FPPassManager::runOnFunction(l=
lvm::Function&amp;)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; (/home/tools/llvm-project/build/bin/=
clang-9+0x1f42ac8)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; #12 0x0000000001f42be9 llvm::FPPassM=
anager::runOnModule(llvm::Module&amp;)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; (/home/tools/llvm-project/build/bin/=
clang-9+0x1f42be9)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; #13 0x0000000001f41ed8<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; llvm::legacy::PassManagerImpl::run(l=
lvm::Module&amp;)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; (/home/tools/llvm-project/build/bin/=
clang-9+0x1f41ed8)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; #14 0x00000000026fa4f8 (anonymous<br=
>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; namespace)::EmitAssemblyHelper::Emit=
Assembly(clang::BackendAction,<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; std::unique_ptr&lt;llvm::raw_pwrite_=
stream,<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; std::default_delete&lt;llvm::raw_pwr=
ite_stream&gt; &gt;)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; (/home/tools/llvm-project/build/bin/=
clang-9+0x26fa4f8)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; #15 0x00000000026fbbf8<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; clang::EmitBackendOutput(clang::Diag=
nosticsEngine&amp;,<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; clang::HeaderSearchOptions const&amp=
;, clang::CodeGenOptions const&amp;,<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; clang::TargetOptions const&amp;, cla=
ng::LangOptions const&amp;,<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; llvm::DataLayout const&amp;, llvm::M=
odule*, clang::BackendAction,<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; std::unique_ptr&lt;llvm::raw_pwrite_=
stream,<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; std::default_delete&lt;llvm::raw_pwr=
ite_stream&gt; &gt;)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; (/home/tools/llvm-project/build/bin/=
clang-9+0x26fbbf8)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; #16 0x000000000310234d<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; clang::BackendConsumer::HandleTransl=
ationUnit(clang::ASTContext&amp;)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; (/home/tools/llvm-project/build/bin/=
clang-9+0x310234d)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; #17 0x0000000003aaddf9 clang::ParseA=
ST(clang::Sema&amp;, bool, bool)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; (/home/tools/llvm-project/build/bin/=
clang-9+0x3aaddf9)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; #18 0x00000000030fe5e0 clang::CodeGe=
nAction::ExecuteAction()<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; (/home/tools/llvm-project/build/bin/=
clang-9+0x30fe5e0)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; #19 0x0000000002ba1929 clang::Fronte=
ndAction::Execute()<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; (/home/tools/llvm-project/build/bin/=
clang-9+0x2ba1929)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; #20 0x0000000002b68e62<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; clang::CompilerInstance::ExecuteActi=
on(clang::FrontendAction&amp;)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; (/home/tools/llvm-project/build/bin/=
clang-9+0x2b68e62)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; #21 0x0000000002c5738a<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; clang::ExecuteCompilerInvocation(cla=
ng::CompilerInstance*)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; (/home/tools/llvm-project/build/bin/=
clang-9+0x2c5738a)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; #22 0x00000000009cd1a6 cc1_main(llvm=
::ArrayRef&lt;char const*&gt;, char<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; const*, void*) (/home/tools/llvm-pro=
ject/build/bin/clang-9+0x9cd1a6)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; #23 0x000000000094cac1 main<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; (/home/tools/llvm-project/build/bin/=
clang-9+0x94cac1)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; #24 0x00007f85ec468813 __libc_start_=
main (/lib64/libc.so.6+0x23813)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; #25 0x00000000009c96ee _start<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; (/home/tools/llvm-project/build/bin/=
clang-9+0x9c96ee)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; clang-9: error: unable to execute co=
mmand: Aborted (core dumped)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; clang-9: error: clang frontend comma=
nd failed due to signal (use -v to<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; see invocation)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; clang version 9.0.0 (<a href=3D"http=
s://github.com/llvm/llvm-project.git" rel=3D"noreferrer noreferrer" target=
=3D"_blank">https://github.com/llvm/llvm-project.git</a><br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; a056684c335995214f6d3467c699d32f8e73=
b763)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; Target: x86_64-unknown-linux-gnu<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; Thread model: posix<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; InstalledDir: /home/tools/llvm-proje=
ct/build/bin<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; clang-9: note: diagnostic msg: PLEAS=
E submit a bug report to<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; <a href=3D"https://bugs.llvm.org/" r=
el=3D"noreferrer noreferrer" target=3D"_blank">https://bugs.llvm.org/</a> a=
nd include the crash backtrace, preprocessed<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; source, and associated run script.<b=
r>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; clang-9: note: diagnostic msg:<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; ********************<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; PLEASE ATTACH THE FOLLOWING FILES TO=
 THE BUG REPORT:<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; Preprocessed source(s) and associate=
d run script(s) are located at:<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; clang-9: note: diagnostic msg: /tmp/=
process_64-5fbbdc.c<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; clang-9: note: diagnostic msg: /tmp/=
process_64-5fbbdc.sh<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; clang-9: note: diagnostic msg:<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; ********************<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; make[2]: *** [scripts/Makefile.build=
:276:<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; arch/x86/kernel/process_64.o] Error =
254<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; any idea why?<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; On Thu, Jun 27, 2019 at 5:23 PM Alex=
ander Potapenko &lt;<a href=3D"mailto:glider@google.com" target=3D"_blank" =
rel=3D"noreferrer">glider@google.com</a>&gt; wrote:<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; Actually, your config says:<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;=C2=A0 =C2=A0&quot;Compiler: cla=
ng version 8.0.0 (trunk 343298)&quot;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; I think you&#39;ll need at leas=
t Clang r362410 (mine is r362913)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; On Thu, Jun 27, 2019 at 11:20 A=
M Alexander Potapenko &lt;<a href=3D"mailto:glider@google.com" target=3D"_b=
lank" rel=3D"noreferrer">glider@google.com</a>&gt; wrote:<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; Hi Xin,<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; Sorry for the late reply.<=
br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; I&#39;ve built the ToT KMS=
AN tree using your config and my almost-ToT<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; Clang and couldn&#39;t rep=
roduce the problem.<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; I believe something is wro=
ng with your Clang version, as<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; CONFIG_CLANG_VERSION shoul=
d really be 90000.<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; You can run `make V=3D1` t=
o see which Clang version is being invoked -<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; make sure it&#39;s a fresh=
 one.<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; HTH,<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; Alex<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; On Fri, Jun 21, 2019 at 10=
:09 PM Xin Long &lt;<a href=3D"mailto:lucien.xin@gmail.com" target=3D"_blan=
k" rel=3D"noreferrer">lucien.xin@gmail.com</a>&gt; wrote:<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; as attached,<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; It actually came from=
 <a href=3D"https://syzkaller.appspot.com/x/.config?x=3D602468164ccdc30a" r=
el=3D"noreferrer noreferrer" target=3D"_blank">https://syzkaller.appspot.co=
m/x/.config?x=3D602468164ccdc30a</a><br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; after I built, clang =
version changed to:<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; CONFIG_CLANG_VERSION=
=3D80000<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; On Sat, Jun 22, 2019 =
at 2:06 AM Alexander Potapenko &lt;<a href=3D"mailto:glider@google.com" tar=
get=3D"_blank" rel=3D"noreferrer">glider@google.com</a>&gt; wrote:<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; Hi Xin,<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; Could you please=
 share the config you&#39;re using to build the kernel?<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; I&#39;ll take a =
closer look on Monday when I am back to the office.<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; On Fri, 21 Jun 2=
019, 18:15 Xin Long, &lt;<a href=3D"mailto:lucien.xin@gmail.com" target=3D"=
_blank" rel=3D"noreferrer">lucien.xin@gmail.com</a>&gt; wrote:<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; this is my c=
ommand:<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; /usr/libexec=
/qemu-kvm -smp 2 -m 4G -enable-kvm -cpu host \<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;=C2=A0 =C2=A0=
 =C2=A0-net nic -net user,hostfwd=3Dtcp::10022-:22 \<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;=C2=A0 =C2=A0=
 =C2=A0-kernel /home/kmsan/arch/x86/boot/bzImage -nographic \<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;=C2=A0 =C2=A0=
 =C2=A0-device virtio-scsi-pci,id=3Dscsi \<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;=C2=A0 =C2=A0=
 =C2=A0-device scsi-hd,bus=3Dscsi.0,drive=3Dd0 \<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;=C2=A0 =C2=A0=
 =C2=A0-drive file=3D/root/test/wheezy.img,format=3Draw,if=3Dnone,id=3Dd0 \=
<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;=C2=A0 =C2=A0=
 =C2=A0-append &quot;root=3D/dev/sda console=3DttyS0 earlyprintk=3Dserial r=
odata=3Dn \<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;=C2=A0 =C2=A0=
 =C2=A0 =C2=A0oops=3Dpanic panic_on_warn=3D1 panic=3D86400 kvm-intel.nested=
=3D1 \<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;=C2=A0 =C2=A0=
 =C2=A0 =C2=A0security=3Dapparmor ima_policy=3Dtcb workqueue.watchdog_thres=
h=3D140 \<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;=C2=A0 =C2=A0=
 =C2=A0 =C2=A0nf-conntrack-ftp.ports=3D20000 nf-conntrack-tftp.ports=3D2000=
0 \<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;=C2=A0 =C2=A0=
 =C2=A0 =C2=A0nf-conntrack-sip.ports=3D20000 nf-conntrack-irc.ports=3D20000=
 \<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;=C2=A0 =C2=A0=
 =C2=A0 =C2=A0nf-conntrack-sane.ports=3D20000 vivid.n_devs=3D16 \<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;=C2=A0 =C2=A0=
 =C2=A0 =C2=A0vivid.multiplanar=3D1,2,1,2,1,2,1,2,1,2,1,2,1,2,1,2 \<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;=C2=A0 =C2=A0=
 =C2=A0 =C2=A0spec_store_bypass_disable=3Dprctl nopcid&quot;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; the commit i=
s on:<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; commit f75e4=
cfea97f67b7530b8b991b3005f991f04778 (HEAD)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; Author: Alex=
ander Potapenko &lt;<a href=3D"mailto:glider@google.com" target=3D"_blank" =
rel=3D"noreferrer">glider@google.com</a>&gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; Date:=C2=A0 =
=C2=A0Wed May 22 12:30:13 2019 +0200<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;=C2=A0 =C2=A0=
 =C2=A0kmsan: use kmsan_handle_urb() in urb.c<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; and when sta=
rting, it shows:<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.561925][=C2=A0 =C2=A0 T0] Kernel command line: root=3D/dev/sda<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; console=3Dtt=
yS0 earlyprintk=3Dserial rodata=3Dn=C2=A0 =C2=A0 =C2=A0 =C2=A0oops=3Dpanic<=
br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; panic_on_war=
n=3D1 panic=3D86400 kvm-intel.nested=3D1=C2=A0 =C2=A0 =C2=A0 =C2=A0security=
=3Dad<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.707792][=C2=A0 =C2=A0 T0] Memory: 3087328K/4193776K available (219164=
K<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; kernel code,=
 7059K rwdata, 11712K rodata, 5064K init, 11904K bss,<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; 1106448K res=
erved, 0K cma-reserved)<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.710935][=C2=A0 =C2=A0 T0] SLUB: HWalign=3D64, Order=3D0-3, MinObjects=
=3D0,<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; CPUs=3D2, No=
des=3D1<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.711953][=C2=A0 =C2=A0 T0] Starting KernelMemorySanitizer<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.712563][=C2=A0 =C2=A0 T0]<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; =3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.713657][=C2=A0 =C2=A0 T0] BUG: KMSAN: uninit-value in mutex_lock+0xd1=
/0xe0<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.714570][=C2=A0 =C2=A0 T0] CPU: 0 PID: 0 Comm: swapper Not tainted 5.1=
.0 #5<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.715417][=C2=A0 =C2=A0 T0] Hardware name: Red Hat KVM, BIOS<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; 1.11.1-3.mod=
ule+el8.1.0+2983+b2ae9c0a 04/01/2014<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.716659][=C2=A0 =C2=A0 T0] Call Trace:<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.717127][=C2=A0 =C2=A0 T0]=C2=A0 dump_stack+0x134/0x190<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.717727][=C2=A0 =C2=A0 T0]=C2=A0 kmsan_report+0x131/0x2a0<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.718347][=C2=A0 =C2=A0 T0]=C2=A0 __msan_warning+0x7a/0xf0<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.718952][=C2=A0 =C2=A0 T0]=C2=A0 mutex_lock+0xd1/0xe0<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.719478][=C2=A0 =C2=A0 T0]=C2=A0 __cpuhp_setup_state_cpuslocked+0x149/=
0xd20<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.720260][=C2=A0 =C2=A0 T0]=C2=A0 ? vprintk_func+0x6b5/0x8a0<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.720926][=C2=A0 =C2=A0 T0]=C2=A0 ? rb_get_reader_page+0x1140/0x1140<br=
>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.721632][=C2=A0 =C2=A0 T0]=C2=A0 __cpuhp_setup_state+0x181/0x2e0<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.722374][=C2=A0 =C2=A0 T0]=C2=A0 ? rb_get_reader_page+0x1140/0x1140<br=
>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.723115][=C2=A0 =C2=A0 T0]=C2=A0 tracer_alloc_buffers+0x16b/0xb96<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.723846][=C2=A0 =C2=A0 T0]=C2=A0 early_trace_init+0x193/0x28f<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.724501][=C2=A0 =C2=A0 T0]=C2=A0 start_kernel+0x497/0xb38<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.725134][=C2=A0 =C2=A0 T0]=C2=A0 x86_64_start_reservations+0x19/0x2f<b=
r>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.725871][=C2=A0 =C2=A0 T0]=C2=A0 x86_64_start_kernel+0x84/0x87<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.726538][=C2=A0 =C2=A0 T0]=C2=A0 secondary_startup_64+0xa4/0xb0<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.727173][=C2=A0 =C2=A0 T0]<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.727454][=C2=A0 =C2=A0 T0] Local variable description:<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; ----success.=
i.i.i.i@mutex_lock<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.728379][=C2=A0 =C2=A0 T0] Variable was created at:<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.728977][=C2=A0 =C2=A0 T0]=C2=A0 mutex_lock+0x48/0xe0<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.729536][=C2=A0 =C2=A0 T0]=C2=A0 __cpuhp_setup_state_cpuslocked+0x149/=
0xd20<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.730323][=C2=A0 =C2=A0 T0]<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; =3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.731364][=C2=A0 =C2=A0 T0] Disabling lock debugging due to kernel tain=
t<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.732169][=C2=A0 =C2=A0 T0] Kernel panic - not syncing: panic_on_warn s=
et ...<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.733047][=C2=A0 =C2=A0 T0] CPU: 0 PID: 0 Comm: swapper Tainted: G=C2=
=A0 =C2=A0 B<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;=C2=A0 =C2=A0=
 =C2=A0 =C2=A0 =C2=A05.1.0 #5<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.734080][=C2=A0 =C2=A0 T0] Hardware name: Red Hat KVM, BIOS<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; 1.11.1-3.mod=
ule+el8.1.0+2983+b2ae9c0a 04/01/2014<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.735319][=C2=A0 =C2=A0 T0] Call Trace:<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.735735][=C2=A0 =C2=A0 T0]=C2=A0 dump_stack+0x134/0x190<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.736308][=C2=A0 =C2=A0 T0]=C2=A0 panic+0x3ec/0xb3b<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.736826][=C2=A0 =C2=A0 T0]=C2=A0 kmsan_report+0x29a/0x2a0<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.737417][=C2=A0 =C2=A0 T0]=C2=A0 __msan_warning+0x7a/0xf0<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.737973][=C2=A0 =C2=A0 T0]=C2=A0 mutex_lock+0xd1/0xe0<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.738527][=C2=A0 =C2=A0 T0]=C2=A0 __cpuhp_setup_state_cpuslocked+0x149/=
0xd20<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.739342][=C2=A0 =C2=A0 T0]=C2=A0 ? vprintk_func+0x6b5/0x8a0<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.739972][=C2=A0 =C2=A0 T0]=C2=A0 ? rb_get_reader_page+0x1140/0x1140<br=
>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.740695][=C2=A0 =C2=A0 T0]=C2=A0 __cpuhp_setup_state+0x181/0x2e0<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.741412][=C2=A0 =C2=A0 T0]=C2=A0 ? rb_get_reader_page+0x1140/0x1140<br=
>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.742160][=C2=A0 =C2=A0 T0]=C2=A0 tracer_alloc_buffers+0x16b/0xb96<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.742866][=C2=A0 =C2=A0 T0]=C2=A0 early_trace_init+0x193/0x28f<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.743512][=C2=A0 =C2=A0 T0]=C2=A0 start_kernel+0x497/0xb38<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.744128][=C2=A0 =C2=A0 T0]=C2=A0 x86_64_start_reservations+0x19/0x2f<b=
r>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.744863][=C2=A0 =C2=A0 T0]=C2=A0 x86_64_start_kernel+0x84/0x87<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.745534][=C2=A0 =C2=A0 T0]=C2=A0 secondary_startup_64+0xa4/0xb0<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A0 0.746290][=C2=A0 =C2=A0 T0] Rebooting in 86400 seconds..<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; when I set &=
quot;panic_on_warn=3D0&quot;, it foods the console with:<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; ...<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.206759][=C2=A0 =C2=A0 C0] Variable was created at:<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.207302][=C2=A0 =C2=A0 C0]=C2=A0 vprintk_emit+0xf4/0x800<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.207844][=C2=A0 =C2=A0 C0]=C2=A0 vprintk_deferred+0x90/0xed<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.208404][=C2=A0 =C2=A0 C0]<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; =3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.209763][=C2=A0 =C2=A0 C0]=C2=A0 x86_64_start_reservations+0x19/0x2f<b=
r>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.209769][=C2=A0 =C2=A0 C0]<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; =3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.211408][=C2=A0 =C2=A0 C0] BUG: KMSAN: uninit-value in vprintk_emit+0x=
443/0x800<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.212237][=C2=A0 =C2=A0 C0] CPU: 0 PID: 0 Comm: swapper/0 Tainted: G=C2=
=A0 =C2=A0 B<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;=C2=A0 =C2=A0=
 =C2=A0 =C2=A0 =C2=A0 =C2=A05.1.0 #5<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.213206][=C2=A0 =C2=A0 C0] Hardware name: Red Hat KVM, BIOS<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; 1.11.1-3.mod=
ule+el8.1.0+2983+b2ae9c0a 04/01/2014<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.214326][=C2=A0 =C2=A0 C0] Call Trace:<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.214725][=C2=A0 =C2=A0 C0]=C2=A0 &lt;IRQ&gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.215080][=C2=A0 =C2=A0 C0]=C2=A0 dump_stack+0x134/0x190<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.215624][=C2=A0 =C2=A0 C0]=C2=A0 kmsan_report+0x131/0x2a0<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.216204][=C2=A0 =C2=A0 C0]=C2=A0 __msan_warning+0x7a/0xf0<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.216771][=C2=A0 =C2=A0 C0]=C2=A0 vprintk_emit+0x443/0x800<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.217334][=C2=A0 =C2=A0 C0]=C2=A0 ? __msan_metadata_ptr_for_store_1+0x1=
3/0x20<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.218127][=C2=A0 =C2=A0 C0]=C2=A0 vprintk_deferred+0x90/0xed<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.218714][=C2=A0 =C2=A0 C0]=C2=A0 printk_deferred+0x186/0x1d3<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.219353][=C2=A0 =C2=A0 C0]=C2=A0 __printk_safe_flush+0x72e/0xc00<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.220006][=C2=A0 =C2=A0 C0]=C2=A0 ? printk_safe_flush+0x1e0/0x1e0<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.220635][=C2=A0 =C2=A0 C0]=C2=A0 irq_work_run+0x1ad/0x5c0<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.221210][=C2=A0 =C2=A0 C0]=C2=A0 ? flat_init_apic_ldr+0x170/0x170<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.221851][=C2=A0 =C2=A0 C0]=C2=A0 smp_irq_work_interrupt+0x237/0x3e0<br=
>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.222520][=C2=A0 =C2=A0 C0]=C2=A0 irq_work_interrupt+0x2e/0x40<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.223110][=C2=A0 =C2=A0 C0]=C2=A0 &lt;/IRQ&gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.223475][=C2=A0 =C2=A0 C0] RIP: 0010:kmem_cache_init_late+0x0/0xb<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.224164][=C2=A0 =C2=A0 C0] Code: d4 e8 5d dd 2e f2 e9 74 fe ff ff 48 8=
9 d3<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; 8b 7d d4 e8 =
cd d7 2e f2 89 c0 48 89 c1 48 c1 e1 20 48 09 c1 48 89 0b<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; e9 81 fe ff =
ff &lt;55&gt; 48 89 e5 e8 20 de 2e1<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.226526][=C2=A0 =C2=A0 C0] RSP: 0000:ffffffff8f40feb8 EFLAGS: 00000246=
<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; ORIG_RAX: ff=
ffffffffffff09<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.227548][=C2=A0 =C2=A0 C0] RAX: ffff88813f995785 RBX: 0000000000000000=
<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; RCX: 0000000=
000000000<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.228511][=C2=A0 =C2=A0 C0] RDX: ffff88813f2b0784 RSI: 0000160000000000=
<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; RDI: 0000000=
000000785<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.229473][=C2=A0 =C2=A0 C0] RBP: ffffffff8f40ff20 R08: 000000000fac3785=
<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; R09: 0000778=
000000001<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.230440][=C2=A0 =C2=A0 C0] R10: ffffd0ffffffffff R11: 0000100000000000=
<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; R12: 0000000=
000000000<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.231403][=C2=A0 =C2=A0 C0] R13: 0000000000000000 R14: ffffffff8fb8cfd0=
<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; R15: 0000000=
000000000<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.232407][=C2=A0 =C2=A0 C0]=C2=A0 ? start_kernel+0x5d8/0xb38<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.233003][=C2=A0 =C2=A0 C0]=C2=A0 x86_64_start_reservations+0x19/0x2f<b=
r>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.233670][=C2=A0 =C2=A0 C0]=C2=A0 x86_64_start_kernel+0x84/0x87<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.234314][=C2=A0 =C2=A0 C0]=C2=A0 secondary_startup_64+0xa4/0xb0<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.234949][=C2=A0 =C2=A0 C0]<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.235231][=C2=A0 =C2=A0 C0] Local variable description: ----flags.i.i.i=
@vprintk_emit<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.236101][=C2=A0 =C2=A0 C0] Variable was created at:<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.236643][=C2=A0 =C2=A0 C0]=C2=A0 vprintk_emit+0xf4/0x800<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.237188][=C2=A0 =C2=A0 C0]=C2=A0 vprintk_deferred+0x90/0xed<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.237752][=C2=A0 =C2=A0 C0]<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; =3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.239117][=C2=A0 =C2=A0 C0]=C2=A0 x86_64_start_kernel+0x84/0x87<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.239123][=C2=A0 =C2=A0 C0]<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; =3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.240704][=C2=A0 =C2=A0 C0] BUG: KMSAN: uninit-value in vprintk_emit+0x=
443/0x800<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.241540][=C2=A0 =C2=A0 C0] CPU: 0 PID: 0 Comm: swapper/0 Tainted: G=C2=
=A0 =C2=A0 B<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;=C2=A0 =C2=A0=
 =C2=A0 =C2=A0 =C2=A0 =C2=A05.1.0 #5<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.242512][=C2=A0 =C2=A0 C0] Hardware name: Red Hat KVM, BIOS<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; 1.11.1-3.mod=
ule+el8.1.0+2983+b2ae9c0a 04/01/2014<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.243635][=C2=A0 =C2=A0 C0] Call Trace:<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.244038][=C2=A0 =C2=A0 C0]=C2=A0 &lt;IRQ&gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.244390][=C2=A0 =C2=A0 C0]=C2=A0 dump_stack+0x134/0x190<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.244940][=C2=A0 =C2=A0 C0]=C2=A0 kmsan_report+0x131/0x2a0<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.245515][=C2=A0 =C2=A0 C0]=C2=A0 __msan_warning+0x7a/0xf0<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.246082][=C2=A0 =C2=A0 C0]=C2=A0 vprintk_emit+0x443/0x800<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.246638][=C2=A0 =C2=A0 C0]=C2=A0 ? __msan_metadata_ptr_for_store_1+0x1=
3/0x20<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.247430][=C2=A0 =C2=A0 C0]=C2=A0 vprintk_deferred+0x90/0xed<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.248018][=C2=A0 =C2=A0 C0]=C2=A0 printk_deferred+0x186/0x1d3<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.248650][=C2=A0 =C2=A0 C0]=C2=A0 __printk_safe_flush+0x72e/0xc00<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.249320][=C2=A0 =C2=A0 C0]=C2=A0 ? printk_safe_flush+0x1e0/0x1e0<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.249949][=C2=A0 =C2=A0 C0]=C2=A0 irq_work_run+0x1ad/0x5c0<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.250524][=C2=A0 =C2=A0 C0]=C2=A0 ? flat_init_apic_ldr+0x170/0x170<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.251167][=C2=A0 =C2=A0 C0]=C2=A0 smp_irq_work_interrupt+0x237/0x3e0<br=
>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.251837][=C2=A0 =C2=A0 C0]=C2=A0 irq_work_interrupt+0x2e/0x40<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; [=C2=A0 =C2=
=A025.252424][=C2=A0 =C2=A0 C0]=C2=A0 &lt;/IRQ&gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; ....<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; I couldn&#39=
;t even log in.<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; how should I=
 use qemu with wheezy.img to start a kmsan kernel?<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;&gt; Thanks.<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; --<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; Alexander Potapenko<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; Software Engineer<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; Google Germany GmbH<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; Erika-Mann-Stra=C3=9Fe, 33=
<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; 80636 M=C3=BCnchen<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; Gesch=C3=A4ftsf=C3=BChrer:=
 Paul Manicle, Halimah DeLaine Prado<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; Registergericht und -numme=
r: Hamburg, HRB 86891<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; Sitz der Gesellschaft: Ham=
burg<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; --<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; Alexander Potapenko<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; Software Engineer<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; Google Germany GmbH<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; Erika-Mann-Stra=C3=9Fe, 33<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; 80636 M=C3=BCnchen<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; Gesch=C3=A4ftsf=C3=BChrer: Paul=
 Manicle, Halimah DeLaine Prado<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; Registergericht und -nummer: Ha=
mburg, HRB 86891<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; &gt; &gt; Sitz der Gesellschaft: Hamburg<=
br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; --<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; Alexander Potapenko<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; Software Engineer<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; Google Germany GmbH<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; Erika-Mann-Stra=C3=9Fe, 33<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; 80636 M=C3=BCnchen<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, =
Halimah DeLaine Prado<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; Registergericht und -nummer: Hamburg, HRB=
 86891<br>
&gt;&gt; &gt; &gt; &gt; &gt; &gt; Sitz der Gesellschaft: Hamburg<br>
&gt;&gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; --<br>
&gt;&gt; &gt; &gt; &gt; Alexander Potapenko<br>
&gt;&gt; &gt; &gt; &gt; Software Engineer<br>
&gt;&gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; Google Germany GmbH<br>
&gt;&gt; &gt; &gt; &gt; Erika-Mann-Stra=C3=9Fe, 33<br>
&gt;&gt; &gt; &gt; &gt; 80636 M=C3=BCnchen<br>
&gt;&gt; &gt; &gt; &gt;<br>
&gt;&gt; &gt; &gt; &gt; Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah De=
Laine Prado<br>
&gt;&gt; &gt; &gt; &gt; Registergericht und -nummer: Hamburg, HRB 86891<br>
&gt;&gt; &gt; &gt; &gt; Sitz der Gesellschaft: Hamburg<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; --<br>
&gt;&gt; &gt; Alexander Potapenko<br>
&gt;&gt; &gt; Software Engineer<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; Google Germany GmbH<br>
&gt;&gt; &gt; Erika-Mann-Stra=C3=9Fe, 33<br>
&gt;&gt; &gt; 80636 M=C3=BCnchen<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prad=
o<br>
&gt;&gt; &gt; Registergericht und -nummer: Hamburg, HRB 86891<br>
&gt;&gt; &gt; Sitz der Gesellschaft: Hamburg<br>
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
om/d/msgid/kasan-dev/CAG_fn%3DWKLynY8fWdrsSxYcQXHMPC%2BVnjg-C322cfwR%3DSb3w=
uZA%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups=
.google.com/d/msgid/kasan-dev/CAG_fn%3DWKLynY8fWdrsSxYcQXHMPC%2BVnjg-C322cf=
wR%3DSb3wuZA%40mail.gmail.com</a>.<br />
For more options, visit <a href=3D"https://groups.google.com/d/optout">http=
s://groups.google.com/d/optout</a>.<br />

--0000000000007ccb39058c65873f--
