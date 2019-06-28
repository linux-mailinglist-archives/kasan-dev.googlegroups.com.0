Return-Path: <kasan-dev+bncBCWPNP5RT4JRBNFD3DUAKGQEZB6LQ5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C28159C9D
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2019 15:10:13 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id q2sf2499327wrr.18
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2019 06:10:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561727412; cv=pass;
        d=google.com; s=arc-20160816;
        b=jf5niuiZGe/lqDVQYW+nwthdxcjyK1sfm+tDNj4cpMdRea7teaBHSdpJVM7US2+k6n
         hZ49X8kOSEZbuHw9K+zIxIbXcsHujlwSU4CrMQchVpLWW5nJqyQ6l5faSWkfFLurunqm
         Qx1C/d87vxC4QZb4DBMc/1+8edyJ1aD+3dHn4kLs2Ilpr/D56/oEvbURcU5nr/1KV8Ze
         VCyBz4QWimYQZXTEF5ONNcaFQkS4F/esQaAJE6DD+XkvzXD9ooXd7kmMPz4Baz1daC8y
         LIvEc0hGwKrv54f6TuNzhlZu9EeI7kvco3AlWpCUOB0O0ivrZ1qkD/tJDY+ItO0Am6Wk
         mmfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=wyoSwIinlRP0VzP7/UY5D62M0R7CehLrUfoOGavpV9U=;
        b=kPuFlDkAkHh7RuqGEpA5i4d/Mb76a1EuNHv8Y/NPeaJpo6e5Sm45MGh9Tzut0xTZiP
         aGwseRbGZMWHtiMnsLhUbE9KkJY0TwT7MMtUIyM4OJZ6I67JSnkCq/hNavOmbMozFpWd
         lRnJDmjl+GaWDhq7if45bz347yCMAQcy/4pv6BegU55WVzEgqyfpab+EGkhjSi7/wHRB
         2Vsr9Nz4K3QFXR0LpqgkOIvrdYPcM3qLq+PrInuEl/G6UYSEu3nBNHOlqsdefsYJghsi
         HakmDCzQzq3Ypn0qLX2zhRIZPnPRHqvaXCk0rhSYfZyT1l5rOJMhhW+QFw1waFf5wAK/
         bbGw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=Ss8bmAEt;
       spf=pass (google.com: domain of lucien.xin@gmail.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=lucien.xin@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wyoSwIinlRP0VzP7/UY5D62M0R7CehLrUfoOGavpV9U=;
        b=r8Z511VVUJdkjgoxT+dsYSoR2T5hHcqHs50uWuxqBUOJryS+BXqrOEPFE3s0irgF5l
         Y/FsZDUb3rP4rF8x5vTua/HBK6+9dRx1Uit0SB6jor2syCPxNsIlfQ+7vGl2ayx5q2o0
         8lBcsWy7iNZfk2FIE3xz6PlxyMBzXID6oN0pY/orx0dLPhkogYbXOpT1xTHy+sgZXKEC
         5LVLl0SVPuJyGM/jjyY4bHAAUoXKBnjTuGLzcWiWpnVDrMzhw6kd7g0gK/rzmg42attL
         W4sRUllnuejuISWvQ+rPWzhVZBzMsvoR6/60R3zTUKzqn6iq6bVvEAcAljh5IJGCnD8P
         UTlw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wyoSwIinlRP0VzP7/UY5D62M0R7CehLrUfoOGavpV9U=;
        b=vgns2Xc0B+C4SDQVtk0LZcTtLP1sH/3Pn1HftZ0HrKhtxt5FUv8BPYbERgnc+vKp90
         fhSFjFOAOteMgGkX2ZPZaXD3C2O4fchEnkEOl9r/ZqMP/OYDjsWjAw/q3x5LXff9Y+Z/
         jyRfCpVzJoDjGv8GC9P2wDlyWuBO8JcXgwLBXSlX+PPbRQMvSdd3iKOde/mpl1cVB4x9
         ebZkAraKHsofinvTVBPDXcIj8eWOzszj+sFjk9KQPvrMSeAcUmOCld0DUqy21EwK/SsC
         GdS6PGuULCHqZcdGwnI6MQseTaOtAOLZDvKyeVqNbyd3T1TLmJznpYVckNAkWT6BgT1Q
         cU/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=wyoSwIinlRP0VzP7/UY5D62M0R7CehLrUfoOGavpV9U=;
        b=KE2SHlrKczbfsBErZ7cTSCv+KVLIL7kFzMOSwcM7pF/yKDs9Epbaw7YMJiIZv4KWWy
         5YSB/8QW4UQFQQ2uFZ8qo2UWK+w8IEhG0y1V3W+Bp8DAo4B34GlbrISvXvliDslX9da8
         bWyKQdkPXveClh1Gizxc2S05IxUx2yNMb8g4sn7dB+DIIPdaZUEcxoMtTM8W0oN0vuF6
         Ye2B1+X4FpXX0LOEL5G9uQstWSv7VVBWaS6fIDGGepoNcUA2qDLonfLChUVHRBfCFJJw
         //odnlXSdUcKDMK7bKyhjGHDmyCgjJiOPabhDhRAx4svOpMY/DOLIGrivqpmG8Am9kLt
         +WaA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVNbWw9+2sLSFohedMl0nDUQ++RpHwe9WGvtK/ypY5zAGJxKR3S
	TUnL6wsR5pphBe+o79CHR9Q=
X-Google-Smtp-Source: APXvYqzPtcQHbCmlwaYLIr6i+e4M6PB2TZ24jAugy8osrOt/bb26ps3430zRAruS4Lup5zjcOb965w==
X-Received: by 2002:a05:6000:1c9:: with SMTP id t9mr8353785wrx.187.1561727412723;
        Fri, 28 Jun 2019 06:10:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2d02:: with SMTP id t2ls799217wmt.0.canary-gmail; Fri,
 28 Jun 2019 06:10:12 -0700 (PDT)
X-Received: by 2002:a1c:9ac9:: with SMTP id c192mr7755382wme.0.1561727412118;
        Fri, 28 Jun 2019 06:10:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561727412; cv=none;
        d=google.com; s=arc-20160816;
        b=WxKArRFEobWcehqGg6wU/ZoLx5P3u5MODMm4ZPp30DbvwIqsmK8wRzSeP/hlWnIb9l
         LrezAzessWucawmV3fTLcmBfGA2UFxrzz4iocikDH8eqqTHNl0xWTrhoz9kbS+x0ROap
         CF2v+vqtCtL0k764enlZGlIabZvySPH5h/RRn2/vfACejW+HNjc3l8lp5NjJIyi4Y6Md
         SWQN/bgU1FcT0Uq+icd0bv0a9X408FFI7/8rCydTilh78oV3yhe2O5LSSZ+MWk5y8qeY
         QXpRX7DQvCX3nXn/kEZvuafuZvzyOKlieknxla4Oq86LIXOzHEJ2S2Jti306CGyZgC0p
         jtEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=2U1qC/2jMoT4+d84WrYrlIc0b4o0MSDYtfbb2aP/Aro=;
        b=jbuNq1WGNQoAOiO5yJfIgl0uyjSSAf3o4tf+EHZ5mDwGDjEyzrQwq19CLfZmS446rD
         F+RsaN+t3TkfcuowPUP5UgvudjoHSfEd7zh8if+XWf934gqGdx11cyd+P4gqsdtCjF1A
         MLBFLxRLOISp5Cy/jydkxGffpY+b4Ifi2iemw8GPoj4m4pqcczk/FMjOsHXplor7kIEq
         NLP4hDfh8h/kTHb7AZD2sAKtJKqfGhMM3urmDJi/1leD1nA5gRuwzIFE5BttF7YQtT0O
         V3b7vCNGC9YA66DMLyJwTd161ClLh90wCYFmMPzUf6bimqIGBQxy1q5oCpZkwkg5OCTW
         AKPQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=Ss8bmAEt;
       spf=pass (google.com: domain of lucien.xin@gmail.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=lucien.xin@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id j4si429361wme.3.2019.06.28.06.10.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Fri, 28 Jun 2019 06:10:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of lucien.xin@gmail.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id c66so9077824wmf.0
        for <kasan-dev@googlegroups.com>; Fri, 28 Jun 2019 06:10:12 -0700 (PDT)
X-Received: by 2002:a1c:228b:: with SMTP id i133mr7386096wmi.140.1561727411563;
 Fri, 28 Jun 2019 06:10:11 -0700 (PDT)
MIME-Version: 1.0
References: <CADvbK_fCWry5LRV-6yzkgLQXFj0_Qxi46gRrrO-ikOh8SbxQuA@mail.gmail.com>
 <CAG_fn=UoK7qE-x7NHN17GXGNctKoEKZe9rZ7QqP1otnSCfcJDw@mail.gmail.com>
 <CADvbK_fTGwW=HHhXFgatN7QzhNHoFTjmNH7orEdb3N1Gt+1fgg@mail.gmail.com>
 <CAG_fn=U-OBaRhPN7ab9dFcpchC1AftBN+wJMF+13FOBZORieUg@mail.gmail.com>
 <CAG_fn=W7Z31JjMio++4pWa67BNfZRzwtjnRC-_DQXQch1X=F5w@mail.gmail.com>
 <CADvbK_eeDPm2K3w2Y37fWeW=W=X3Kw6Lz9c10JyZC1vV0pYSEw@mail.gmail.com> <CAG_fn=VoQuryp2sGS6mVrQD3HnMFSC1MboCy0xSWA9mRCDS2NA@mail.gmail.com>
In-Reply-To: <CAG_fn=VoQuryp2sGS6mVrQD3HnMFSC1MboCy0xSWA9mRCDS2NA@mail.gmail.com>
From: Xin Long <lucien.xin@gmail.com>
Date: Fri, 28 Jun 2019 21:09:59 +0800
Message-ID: <CADvbK_f06sZj3T5JK_X5pjjoA7FKDKQ51DO8ayF2yeFhh1NkJQ@mail.gmail.com>
Subject: Re: how to start kmsan kernel with qemu
To: Alexander Potapenko <glider@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Dmitriy Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: lucien.xin@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=Ss8bmAEt;       spf=pass
 (google.com: domain of lucien.xin@gmail.com designates 2a00:1450:4864:20::32e
 as permitted sender) smtp.mailfrom=lucien.xin@gmail.com;       dmarc=pass
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

This is what I did:
https://paste.fedoraproject.org/paste/q4~GWx9Sx~QUbJQfNDoJIw

There's no process_64.i file generated.

Btw, I couldn't find "-c" in the command line, so there was no "-E" added.

On Fri, Jun 28, 2019 at 8:40 PM Alexander Potapenko <glider@google.com> wro=
te:
>
> It's interesting that you're seeing the same error as reported here:
> https://github.com/google/kmsan/issues/53
> I've updated my Clang to a4771e9dfdb0485c2edb416bfdc479d49de0aa14, but
> the kernel compiles just fine.
> May I ask you to do the following:
>
>  - run `make V=3D1` to capture the command line used to build
> arch/x86/kernel/process_64.o
>  - copy and paste the command line into a shell, remove '-o
> /tmp/somefile' and run again to make sure the compiler still crashes
>  - replace '-c' with '-E' in the command line and add '-o
> process_64.i' to the end
>  - send me the resulting preprocessed file (process_64.i)
>
> Thanks!
>
>
>
> On Thu, Jun 27, 2019 at 4:45 PM Xin Long <lucien.xin@gmail.com> wrote:
> >
> > Now I'm using:
> > # Compiler: clang version 9.0.0
> > (https://github.com/llvm/llvm-project.git
> > a056684c335995214f6d3467c699d32f8e73b763)
> >
> > Errors shows up when building the kernel:
> >
> >   CC      arch/x86/kernel/process_64.o
> > clang-9: /home/tools/llvm-project/llvm/lib/Transforms/Instrumentation/M=
emorySanitizer.cpp:3236:
> > void {anonymous}::MemorySanitizerVisitor::visitCallSite(llvm::CallSite)=
:
> > Assertion `(CS.isCall() || CS.isInvoke()) && "Unknown type of
> > CallSite"' failed.
> > Stack dump:
> > 0.      Program arguments: /home/tools/llvm-project/build/bin/clang-9
> > -cc1 -triple x86_64-unknown-linux-gnu -S -disable-free -main-file-name
> > process_64.c -mrelocation-model static -mthread-model posix
> > -fno-delete-null-pointer-checks -mllvm -warn-stack-size=3D2048
> > -mdisable-fp-elim -relaxed-aliasing -mdisable-tail-calls -fmath-errno
> > -masm-verbose -no-integrated-as -mconstructor-aliases -fuse-init-array
> > -mcode-model kernel -target-cpu core2 -target-feature
> > +retpoline-indirect-calls -target-feature +retpoline-indirect-branches
> > -target-feature -sse -target-feature -mmx -target-feature -sse2
> > -target-feature -3dnow -target-feature -avx -target-feature -x87
> > -target-feature +retpoline-external-thunk -disable-red-zone
> > -dwarf-column-info -debug-info-kind=3Dlimited -dwarf-version=3D4
> > -debugger-tuning=3Dgdb -momit-leaf-frame-pointer -coverage-notes-file
> > /home/kmsan/arch/x86/kernel/process_64.gcno -nostdsysteminc
> > -nobuiltininc -resource-dir
> > /home/tools/llvm-project/build/lib/clang/9.0.0 -dependency-file
> > arch/x86/kernel/.process_64.o.d -MT arch/x86/kernel/process_64.o
> > -sys-header-deps -isystem
> > /home/tools/llvm-project/build/lib/clang/9.0.0/include -include
> > ./include/linux/kconfig.h -include ./include/linux/compiler_types.h -I
> > ./arch/x86/include -I ./arch/x86/include/generated -I ./include -I
> > ./arch/x86/include/uapi -I ./arch/x86/include/generated/uapi -I
> > ./include/uapi -I ./include/generated/uapi -D __KERNEL__ -D
> > CONFIG_X86_X32_ABI -D CONFIG_AS_CFI=3D1 -D CONFIG_AS_CFI_SIGNAL_FRAME=
=3D1
> > -D CONFIG_AS_CFI_SECTIONS=3D1 -D CONFIG_AS_SSSE3=3D1 -D CONFIG_AS_AVX=
=3D1 -D
> > CONFIG_AS_AVX2=3D1 -D CONFIG_AS_AVX512=3D1 -D CONFIG_AS_SHA1_NI=3D1 -D
> > CONFIG_AS_SHA256_NI=3D1 -D KBUILD_BASENAME=3D"process_64" -D
> > KBUILD_MODNAME=3D"process_64" -O2 -Wall -Wundef
> > -Werror=3Dstrict-prototypes -Wno-trigraphs
> > -Werror=3Dimplicit-function-declaration -Werror=3Dimplicit-int
> > -Wno-format-security -Wno-sign-compare -Wno-address-of-packed-member
> > -Wno-format-invalid-specifier -Wno-gnu -Wno-tautological-compare
> > -Wno-unused-const-variable -Wdeclaration-after-statement -Wvla
> > -Wno-pointer-sign -Werror=3Ddate-time -Werror=3Dincompatible-pointer-ty=
pes
> > -Wno-initializer-overrides -Wno-unused-value -Wno-format
> > -Wno-sign-compare -Wno-format-zero-length -Wno-uninitialized
> > -std=3Dgnu89 -fno-dwarf-directory-asm -fdebug-compilation-dir
> > /home/kmsan -ferror-limit 19 -fmessage-length 0
> > -fsanitize=3Dkernel-memory -fwrapv -stack-protector 2
> > -mstack-alignment=3D8 -fwchar-type=3Dshort -fno-signed-wchar
> > -fobjc-runtime=3Dgcc -fno-common -fdiagnostics-show-option
> > -fcolor-diagnostics -vectorize-loops -vectorize-slp -o
> > /tmp/process_64-e20ead.s -x c arch/x86/kernel/process_64.c
> > 1.      <eof> parser at end of file
> > 2.      Per-module optimization passes
> > 3.      Running pass 'Function Pass Manager' on module
> > 'arch/x86/kernel/process_64.c'.
> > 4.      Running pass 'MemorySanitizerLegacyPass' on function '@start_th=
read'
> >  #0 0x00000000024f03ba llvm::sys::PrintStackTrace(llvm::raw_ostream&)
> > (/home/tools/llvm-project/build/bin/clang-9+0x24f03ba)
> >  #1 0x00000000024ee214 llvm::sys::RunSignalHandlers()
> > (/home/tools/llvm-project/build/bin/clang-9+0x24ee214)
> >  #2 0x00000000024ee375 SignalHandler(int)
> > (/home/tools/llvm-project/build/bin/clang-9+0x24ee375)
> >  #3 0x00007f85ed99bd80 __restore_rt (/lib64/libpthread.so.0+0x12d80)
> >  #4 0x00007f85ec47c93f raise (/lib64/libc.so.6+0x3793f)
> >  #5 0x00007f85ec466c95 abort (/lib64/libc.so.6+0x21c95)
> >  #6 0x00007f85ec466b69 _nl_load_domain.cold.0 (/lib64/libc.so.6+0x21b69=
)
> >  #7 0x00007f85ec474df6 (/lib64/libc.so.6+0x2fdf6)
> >  #8 0x000000000327b864 (anonymous
> > namespace)::MemorySanitizerVisitor::visitCallSite(llvm::CallSite)
> > (/home/tools/llvm-project/build/bin/clang-9+0x327b864)
> >  #9 0x0000000003283036 (anonymous
> > namespace)::MemorySanitizerVisitor::runOnFunction()
> > (/home/tools/llvm-project/build/bin/clang-9+0x3283036)
> > #10 0x000000000328605f (anonymous
> > namespace)::MemorySanitizer::sanitizeFunction(llvm::Function&,
> > llvm::TargetLibraryInfo&)
> > (/home/tools/llvm-project/build/bin/clang-9+0x328605f)
> > #11 0x0000000001f42ac8
> > llvm::FPPassManager::runOnFunction(llvm::Function&)
> > (/home/tools/llvm-project/build/bin/clang-9+0x1f42ac8)
> > #12 0x0000000001f42be9 llvm::FPPassManager::runOnModule(llvm::Module&)
> > (/home/tools/llvm-project/build/bin/clang-9+0x1f42be9)
> > #13 0x0000000001f41ed8
> > llvm::legacy::PassManagerImpl::run(llvm::Module&)
> > (/home/tools/llvm-project/build/bin/clang-9+0x1f41ed8)
> > #14 0x00000000026fa4f8 (anonymous
> > namespace)::EmitAssemblyHelper::EmitAssembly(clang::BackendAction,
> > std::unique_ptr<llvm::raw_pwrite_stream,
> > std::default_delete<llvm::raw_pwrite_stream> >)
> > (/home/tools/llvm-project/build/bin/clang-9+0x26fa4f8)
> > #15 0x00000000026fbbf8
> > clang::EmitBackendOutput(clang::DiagnosticsEngine&,
> > clang::HeaderSearchOptions const&, clang::CodeGenOptions const&,
> > clang::TargetOptions const&, clang::LangOptions const&,
> > llvm::DataLayout const&, llvm::Module*, clang::BackendAction,
> > std::unique_ptr<llvm::raw_pwrite_stream,
> > std::default_delete<llvm::raw_pwrite_stream> >)
> > (/home/tools/llvm-project/build/bin/clang-9+0x26fbbf8)
> > #16 0x000000000310234d
> > clang::BackendConsumer::HandleTranslationUnit(clang::ASTContext&)
> > (/home/tools/llvm-project/build/bin/clang-9+0x310234d)
> > #17 0x0000000003aaddf9 clang::ParseAST(clang::Sema&, bool, bool)
> > (/home/tools/llvm-project/build/bin/clang-9+0x3aaddf9)
> > #18 0x00000000030fe5e0 clang::CodeGenAction::ExecuteAction()
> > (/home/tools/llvm-project/build/bin/clang-9+0x30fe5e0)
> > #19 0x0000000002ba1929 clang::FrontendAction::Execute()
> > (/home/tools/llvm-project/build/bin/clang-9+0x2ba1929)
> > #20 0x0000000002b68e62
> > clang::CompilerInstance::ExecuteAction(clang::FrontendAction&)
> > (/home/tools/llvm-project/build/bin/clang-9+0x2b68e62)
> > #21 0x0000000002c5738a
> > clang::ExecuteCompilerInvocation(clang::CompilerInstance*)
> > (/home/tools/llvm-project/build/bin/clang-9+0x2c5738a)
> > #22 0x00000000009cd1a6 cc1_main(llvm::ArrayRef<char const*>, char
> > const*, void*) (/home/tools/llvm-project/build/bin/clang-9+0x9cd1a6)
> > #23 0x000000000094cac1 main
> > (/home/tools/llvm-project/build/bin/clang-9+0x94cac1)
> > #24 0x00007f85ec468813 __libc_start_main (/lib64/libc.so.6+0x23813)
> > #25 0x00000000009c96ee _start
> > (/home/tools/llvm-project/build/bin/clang-9+0x9c96ee)
> > clang-9: error: unable to execute command: Aborted (core dumped)
> > clang-9: error: clang frontend command failed due to signal (use -v to
> > see invocation)
> > clang version 9.0.0 (https://github.com/llvm/llvm-project.git
> > a056684c335995214f6d3467c699d32f8e73b763)
> > Target: x86_64-unknown-linux-gnu
> > Thread model: posix
> > InstalledDir: /home/tools/llvm-project/build/bin
> > clang-9: note: diagnostic msg: PLEASE submit a bug report to
> > https://bugs.llvm.org/ and include the crash backtrace, preprocessed
> > source, and associated run script.
> > clang-9: note: diagnostic msg:
> > ********************
> >
> > PLEASE ATTACH THE FOLLOWING FILES TO THE BUG REPORT:
> > Preprocessed source(s) and associated run script(s) are located at:
> > clang-9: note: diagnostic msg: /tmp/process_64-5fbbdc.c
> > clang-9: note: diagnostic msg: /tmp/process_64-5fbbdc.sh
> > clang-9: note: diagnostic msg:
> >
> > ********************
> > make[2]: *** [scripts/Makefile.build:276:
> > arch/x86/kernel/process_64.o] Error 254
> >
> >
> > any idea why?
> >
> > On Thu, Jun 27, 2019 at 5:23 PM Alexander Potapenko <glider@google.com>=
 wrote:
> > >
> > > Actually, your config says:
> > >   "Compiler: clang version 8.0.0 (trunk 343298)"
> > > I think you'll need at least Clang r362410 (mine is r362913)
> > >
> > > On Thu, Jun 27, 2019 at 11:20 AM Alexander Potapenko <glider@google.c=
om> wrote:
> > > >
> > > > Hi Xin,
> > > >
> > > > Sorry for the late reply.
> > > > I've built the ToT KMSAN tree using your config and my almost-ToT
> > > > Clang and couldn't reproduce the problem.
> > > > I believe something is wrong with your Clang version, as
> > > > CONFIG_CLANG_VERSION should really be 90000.
> > > > You can run `make V=3D1` to see which Clang version is being invoke=
d -
> > > > make sure it's a fresh one.
> > > >
> > > > HTH,
> > > > Alex
> > > >
> > > > On Fri, Jun 21, 2019 at 10:09 PM Xin Long <lucien.xin@gmail.com> wr=
ote:
> > > > >
> > > > > as attached,
> > > > >
> > > > > It actually came from https://syzkaller.appspot.com/x/.config?x=
=3D602468164ccdc30a
> > > > > after I built, clang version changed to:
> > > > >
> > > > > CONFIG_CLANG_VERSION=3D80000
> > > > >
> > > > > On Sat, Jun 22, 2019 at 2:06 AM Alexander Potapenko <glider@googl=
e.com> wrote:
> > > > > >
> > > > > > Hi Xin,
> > > > > >
> > > > > > Could you please share the config you're using to build the ker=
nel?
> > > > > > I'll take a closer look on Monday when I am back to the office.
> > > > > >
> > > > > > On Fri, 21 Jun 2019, 18:15 Xin Long, <lucien.xin@gmail.com> wro=
te:
> > > > > >>
> > > > > >> this is my command:
> > > > > >>
> > > > > >> /usr/libexec/qemu-kvm -smp 2 -m 4G -enable-kvm -cpu host \
> > > > > >>     -net nic -net user,hostfwd=3Dtcp::10022-:22 \
> > > > > >>     -kernel /home/kmsan/arch/x86/boot/bzImage -nographic \
> > > > > >>     -device virtio-scsi-pci,id=3Dscsi \
> > > > > >>     -device scsi-hd,bus=3Dscsi.0,drive=3Dd0 \
> > > > > >>     -drive file=3D/root/test/wheezy.img,format=3Draw,if=3Dnone=
,id=3Dd0 \
> > > > > >>     -append "root=3D/dev/sda console=3DttyS0 earlyprintk=3Dser=
ial rodata=3Dn \
> > > > > >>       oops=3Dpanic panic_on_warn=3D1 panic=3D86400 kvm-intel.n=
ested=3D1 \
> > > > > >>       security=3Dapparmor ima_policy=3Dtcb workqueue.watchdog_=
thresh=3D140 \
> > > > > >>       nf-conntrack-ftp.ports=3D20000 nf-conntrack-tftp.ports=
=3D20000 \
> > > > > >>       nf-conntrack-sip.ports=3D20000 nf-conntrack-irc.ports=3D=
20000 \
> > > > > >>       nf-conntrack-sane.ports=3D20000 vivid.n_devs=3D16 \
> > > > > >>       vivid.multiplanar=3D1,2,1,2,1,2,1,2,1,2,1,2,1,2,1,2 \
> > > > > >>       spec_store_bypass_disable=3Dprctl nopcid"
> > > > > >>
> > > > > >> the commit is on:
> > > > > >> commit f75e4cfea97f67b7530b8b991b3005f991f04778 (HEAD)
> > > > > >> Author: Alexander Potapenko <glider@google.com>
> > > > > >> Date:   Wed May 22 12:30:13 2019 +0200
> > > > > >>
> > > > > >>     kmsan: use kmsan_handle_urb() in urb.c
> > > > > >>
> > > > > >> and when starting, it shows:
> > > > > >> [    0.561925][    T0] Kernel command line: root=3D/dev/sda
> > > > > >> console=3DttyS0 earlyprintk=3Dserial rodata=3Dn       oops=3Dp=
anic
> > > > > >> panic_on_warn=3D1 panic=3D86400 kvm-intel.nested=3D1       sec=
urity=3Dad
> > > > > >> [    0.707792][    T0] Memory: 3087328K/4193776K available (21=
9164K
> > > > > >> kernel code, 7059K rwdata, 11712K rodata, 5064K init, 11904K b=
ss,
> > > > > >> 1106448K reserved, 0K cma-reserved)
> > > > > >> [    0.710935][    T0] SLUB: HWalign=3D64, Order=3D0-3, MinObj=
ects=3D0,
> > > > > >> CPUs=3D2, Nodes=3D1
> > > > > >> [    0.711953][    T0] Starting KernelMemorySanitizer
> > > > > >> [    0.712563][    T0]
> > > > > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > > > > >> [    0.713657][    T0] BUG: KMSAN: uninit-value in mutex_lock+=
0xd1/0xe0
> > > > > >> [    0.714570][    T0] CPU: 0 PID: 0 Comm: swapper Not tainted=
 5.1.0 #5
> > > > > >> [    0.715417][    T0] Hardware name: Red Hat KVM, BIOS
> > > > > >> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01/2014
> > > > > >> [    0.716659][    T0] Call Trace:
> > > > > >> [    0.717127][    T0]  dump_stack+0x134/0x190
> > > > > >> [    0.717727][    T0]  kmsan_report+0x131/0x2a0
> > > > > >> [    0.718347][    T0]  __msan_warning+0x7a/0xf0
> > > > > >> [    0.718952][    T0]  mutex_lock+0xd1/0xe0
> > > > > >> [    0.719478][    T0]  __cpuhp_setup_state_cpuslocked+0x149/0=
xd20
> > > > > >> [    0.720260][    T0]  ? vprintk_func+0x6b5/0x8a0
> > > > > >> [    0.720926][    T0]  ? rb_get_reader_page+0x1140/0x1140
> > > > > >> [    0.721632][    T0]  __cpuhp_setup_state+0x181/0x2e0
> > > > > >> [    0.722374][    T0]  ? rb_get_reader_page+0x1140/0x1140
> > > > > >> [    0.723115][    T0]  tracer_alloc_buffers+0x16b/0xb96
> > > > > >> [    0.723846][    T0]  early_trace_init+0x193/0x28f
> > > > > >> [    0.724501][    T0]  start_kernel+0x497/0xb38
> > > > > >> [    0.725134][    T0]  x86_64_start_reservations+0x19/0x2f
> > > > > >> [    0.725871][    T0]  x86_64_start_kernel+0x84/0x87
> > > > > >> [    0.726538][    T0]  secondary_startup_64+0xa4/0xb0
> > > > > >> [    0.727173][    T0]
> > > > > >> [    0.727454][    T0] Local variable description:
> > > > > >> ----success.i.i.i.i@mutex_lock
> > > > > >> [    0.728379][    T0] Variable was created at:
> > > > > >> [    0.728977][    T0]  mutex_lock+0x48/0xe0
> > > > > >> [    0.729536][    T0]  __cpuhp_setup_state_cpuslocked+0x149/0=
xd20
> > > > > >> [    0.730323][    T0]
> > > > > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > > > > >> [    0.731364][    T0] Disabling lock debugging due to kernel =
taint
> > > > > >> [    0.732169][    T0] Kernel panic - not syncing: panic_on_wa=
rn set ...
> > > > > >> [    0.733047][    T0] CPU: 0 PID: 0 Comm: swapper Tainted: G =
   B
> > > > > >>         5.1.0 #5
> > > > > >> [    0.734080][    T0] Hardware name: Red Hat KVM, BIOS
> > > > > >> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01/2014
> > > > > >> [    0.735319][    T0] Call Trace:
> > > > > >> [    0.735735][    T0]  dump_stack+0x134/0x190
> > > > > >> [    0.736308][    T0]  panic+0x3ec/0xb3b
> > > > > >> [    0.736826][    T0]  kmsan_report+0x29a/0x2a0
> > > > > >> [    0.737417][    T0]  __msan_warning+0x7a/0xf0
> > > > > >> [    0.737973][    T0]  mutex_lock+0xd1/0xe0
> > > > > >> [    0.738527][    T0]  __cpuhp_setup_state_cpuslocked+0x149/0=
xd20
> > > > > >> [    0.739342][    T0]  ? vprintk_func+0x6b5/0x8a0
> > > > > >> [    0.739972][    T0]  ? rb_get_reader_page+0x1140/0x1140
> > > > > >> [    0.740695][    T0]  __cpuhp_setup_state+0x181/0x2e0
> > > > > >> [    0.741412][    T0]  ? rb_get_reader_page+0x1140/0x1140
> > > > > >> [    0.742160][    T0]  tracer_alloc_buffers+0x16b/0xb96
> > > > > >> [    0.742866][    T0]  early_trace_init+0x193/0x28f
> > > > > >> [    0.743512][    T0]  start_kernel+0x497/0xb38
> > > > > >> [    0.744128][    T0]  x86_64_start_reservations+0x19/0x2f
> > > > > >> [    0.744863][    T0]  x86_64_start_kernel+0x84/0x87
> > > > > >> [    0.745534][    T0]  secondary_startup_64+0xa4/0xb0
> > > > > >> [    0.746290][    T0] Rebooting in 86400 seconds..
> > > > > >>
> > > > > >> when I set "panic_on_warn=3D0", it foods the console with:
> > > > > >> ...
> > > > > >> [   25.206759][    C0] Variable was created at:
> > > > > >> [   25.207302][    C0]  vprintk_emit+0xf4/0x800
> > > > > >> [   25.207844][    C0]  vprintk_deferred+0x90/0xed
> > > > > >> [   25.208404][    C0]
> > > > > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > > > > >> [   25.209763][    C0]  x86_64_start_reservations+0x19/0x2f
> > > > > >> [   25.209769][    C0]
> > > > > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > > > > >> [   25.211408][    C0] BUG: KMSAN: uninit-value in vprintk_emi=
t+0x443/0x800
> > > > > >> [   25.212237][    C0] CPU: 0 PID: 0 Comm: swapper/0 Tainted: =
G    B
> > > > > >>           5.1.0 #5
> > > > > >> [   25.213206][    C0] Hardware name: Red Hat KVM, BIOS
> > > > > >> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01/2014
> > > > > >> [   25.214326][    C0] Call Trace:
> > > > > >> [   25.214725][    C0]  <IRQ>
> > > > > >> [   25.215080][    C0]  dump_stack+0x134/0x190
> > > > > >> [   25.215624][    C0]  kmsan_report+0x131/0x2a0
> > > > > >> [   25.216204][    C0]  __msan_warning+0x7a/0xf0
> > > > > >> [   25.216771][    C0]  vprintk_emit+0x443/0x800
> > > > > >> [   25.217334][    C0]  ? __msan_metadata_ptr_for_store_1+0x13=
/0x20
> > > > > >> [   25.218127][    C0]  vprintk_deferred+0x90/0xed
> > > > > >> [   25.218714][    C0]  printk_deferred+0x186/0x1d3
> > > > > >> [   25.219353][    C0]  __printk_safe_flush+0x72e/0xc00
> > > > > >> [   25.220006][    C0]  ? printk_safe_flush+0x1e0/0x1e0
> > > > > >> [   25.220635][    C0]  irq_work_run+0x1ad/0x5c0
> > > > > >> [   25.221210][    C0]  ? flat_init_apic_ldr+0x170/0x170
> > > > > >> [   25.221851][    C0]  smp_irq_work_interrupt+0x237/0x3e0
> > > > > >> [   25.222520][    C0]  irq_work_interrupt+0x2e/0x40
> > > > > >> [   25.223110][    C0]  </IRQ>
> > > > > >> [   25.223475][    C0] RIP: 0010:kmem_cache_init_late+0x0/0xb
> > > > > >> [   25.224164][    C0] Code: d4 e8 5d dd 2e f2 e9 74 fe ff ff =
48 89 d3
> > > > > >> 8b 7d d4 e8 cd d7 2e f2 89 c0 48 89 c1 48 c1 e1 20 48 09 c1 48=
 89 0b
> > > > > >> e9 81 fe ff ff <55> 48 89 e5 e8 20 de 2e1
> > > > > >> [   25.226526][    C0] RSP: 0000:ffffffff8f40feb8 EFLAGS: 0000=
0246
> > > > > >> ORIG_RAX: ffffffffffffff09
> > > > > >> [   25.227548][    C0] RAX: ffff88813f995785 RBX: 000000000000=
0000
> > > > > >> RCX: 0000000000000000
> > > > > >> [   25.228511][    C0] RDX: ffff88813f2b0784 RSI: 000016000000=
0000
> > > > > >> RDI: 0000000000000785
> > > > > >> [   25.229473][    C0] RBP: ffffffff8f40ff20 R08: 000000000fac=
3785
> > > > > >> R09: 0000778000000001
> > > > > >> [   25.230440][    C0] R10: ffffd0ffffffffff R11: 000010000000=
0000
> > > > > >> R12: 0000000000000000
> > > > > >> [   25.231403][    C0] R13: 0000000000000000 R14: ffffffff8fb8=
cfd0
> > > > > >> R15: 0000000000000000
> > > > > >> [   25.232407][    C0]  ? start_kernel+0x5d8/0xb38
> > > > > >> [   25.233003][    C0]  x86_64_start_reservations+0x19/0x2f
> > > > > >> [   25.233670][    C0]  x86_64_start_kernel+0x84/0x87
> > > > > >> [   25.234314][    C0]  secondary_startup_64+0xa4/0xb0
> > > > > >> [   25.234949][    C0]
> > > > > >> [   25.235231][    C0] Local variable description: ----flags.i=
.i.i@vprintk_emit
> > > > > >> [   25.236101][    C0] Variable was created at:
> > > > > >> [   25.236643][    C0]  vprintk_emit+0xf4/0x800
> > > > > >> [   25.237188][    C0]  vprintk_deferred+0x90/0xed
> > > > > >> [   25.237752][    C0]
> > > > > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > > > > >> [   25.239117][    C0]  x86_64_start_kernel+0x84/0x87
> > > > > >> [   25.239123][    C0]
> > > > > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > > > > >> [   25.240704][    C0] BUG: KMSAN: uninit-value in vprintk_emi=
t+0x443/0x800
> > > > > >> [   25.241540][    C0] CPU: 0 PID: 0 Comm: swapper/0 Tainted: =
G    B
> > > > > >>           5.1.0 #5
> > > > > >> [   25.242512][    C0] Hardware name: Red Hat KVM, BIOS
> > > > > >> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01/2014
> > > > > >> [   25.243635][    C0] Call Trace:
> > > > > >> [   25.244038][    C0]  <IRQ>
> > > > > >> [   25.244390][    C0]  dump_stack+0x134/0x190
> > > > > >> [   25.244940][    C0]  kmsan_report+0x131/0x2a0
> > > > > >> [   25.245515][    C0]  __msan_warning+0x7a/0xf0
> > > > > >> [   25.246082][    C0]  vprintk_emit+0x443/0x800
> > > > > >> [   25.246638][    C0]  ? __msan_metadata_ptr_for_store_1+0x13=
/0x20
> > > > > >> [   25.247430][    C0]  vprintk_deferred+0x90/0xed
> > > > > >> [   25.248018][    C0]  printk_deferred+0x186/0x1d3
> > > > > >> [   25.248650][    C0]  __printk_safe_flush+0x72e/0xc00
> > > > > >> [   25.249320][    C0]  ? printk_safe_flush+0x1e0/0x1e0
> > > > > >> [   25.249949][    C0]  irq_work_run+0x1ad/0x5c0
> > > > > >> [   25.250524][    C0]  ? flat_init_apic_ldr+0x170/0x170
> > > > > >> [   25.251167][    C0]  smp_irq_work_interrupt+0x237/0x3e0
> > > > > >> [   25.251837][    C0]  irq_work_interrupt+0x2e/0x40
> > > > > >> [   25.252424][    C0]  </IRQ>
> > > > > >> ....
> > > > > >>
> > > > > >>
> > > > > >> I couldn't even log in.
> > > > > >>
> > > > > >> how should I use qemu with wheezy.img to start a kmsan kernel?
> > > > > >>
> > > > > >> Thanks.
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
> > >
> > >
> > >
> > > --
> > > Alexander Potapenko
> > > Software Engineer
> > >
> > > Google Germany GmbH
> > > Erika-Mann-Stra=C3=9Fe, 33
> > > 80636 M=C3=BCnchen
> > >
> > > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
> > > Registergericht und -nummer: Hamburg, HRB 86891
> > > Sitz der Gesellschaft: Hamburg
>
>
>
> --
> Alexander Potapenko
> Software Engineer
>
> Google Germany GmbH
> Erika-Mann-Stra=C3=9Fe, 33
> 80636 M=C3=BCnchen
>
> Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
> Registergericht und -nummer: Hamburg, HRB 86891
> Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CADvbK_f06sZj3T5JK_X5pjjoA7FKDKQ51DO8ayF2yeFhh1NkJQ%40mail.gmail.=
com.
For more options, visit https://groups.google.com/d/optout.
