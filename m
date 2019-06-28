Return-Path: <kasan-dev+bncBCCMH5WKTMGRBTEV3DUAKGQELTTHNGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3d.google.com (mail-vs1-xe3d.google.com [IPv6:2607:f8b0:4864:20::e3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E13359BC7
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2019 14:40:45 +0200 (CEST)
Received: by mail-vs1-xe3d.google.com with SMTP id a11sf1819119vso.9
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2019 05:40:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561725644; cv=pass;
        d=google.com; s=arc-20160816;
        b=XWUbzXESO8YVBLIF3lzEcwlh69JEwZHDKeV4xS10FClvZx2ADLmNyQzhUpmXJUpwWT
         xn+0IZO/G6nLsn1F2zHniMd3tI2b1a7IcnMoi9k0B77x7MbvqJKrnTC3hv4J8w1C5AHy
         mXVwxCIa2GEIXVvb0eSu/FrUdXErw+YCTHTptxnq17i/b+NqVhushV8y1+A6yXupH4jw
         x82vHnorJy8u60CxD6uVpVZE2ha7hYYItJP2/kbsdBXnEyJQNu5aeaCy1zpWbzrItgXC
         tw1wfkGsCQIj9qOXJmsOnpwsJvxV/7lWj+c21+xiKiaXj9udzAmpt7xNpkdzu9tUmKPM
         S0Mg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wvR12O/svMw1xMzS41WMP0Cmta1gvVRiz+eKvGHnczc=;
        b=ofygDFo1OhAa5z4UchJMIdq9zyguIrOZknmu6bYy1pluMZjDa/WUFu6JYJI6n2VXUu
         7JlgoLuuNxtrIvo4cdgB7q2V1kUd2USuRpX6+vIRSexHiPYu+rPWVbScCII24BGQi/5+
         81lEYclN3eO01admo/S1C8HC207+AN1y7nNoyxgxxH6S3Uv/YyGcfCzoTBYGFObleveU
         cBWFs07+25luinyu2F+fhRMEgNQJbxhp3xKwFmTT4P878RiMKi+zYCcbuENXXzJlE2N4
         +ElSda+gpfcMgiCXI8TNe+DjpWoQhCIdC3sXS/BXQv7rEapn1L4ghU8TIUH0RxhPvipO
         aQDg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YmSKfcAY;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e44 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=wvR12O/svMw1xMzS41WMP0Cmta1gvVRiz+eKvGHnczc=;
        b=Au9CC46b7fjfiKRymM+phgcMiz79yWXbr1+8JIN3NADuyYEjTYiCF2WlIbQPHAIRbC
         seS/twOfKQ3QAJSRFZ5ofavOJVqD+QdC5IZ2ZzQcUD0L/9lMH19XnO9sQaT9MpeoUR+i
         vHJ7eth6mL77tcNAwCNkAGf3dLuJtSicSDO4+eAz1kJZJOZRmQwF18rF/fatH9CdDcXp
         6DluJoMxzH/+umRW7/w8HTLSZv8Q/RvQ8OE7nyLnXnee+/zwBGsyv+5J239IR3H1dSjy
         0Y/V0SU/DrlmLzy8pLHwGMMM8Jeh3iZdiLyqT3/bh9hWiWpmhg8brylhH0LgvqZ4MWyK
         S/Cw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wvR12O/svMw1xMzS41WMP0Cmta1gvVRiz+eKvGHnczc=;
        b=bNmyzmmZbH0OqY56F1hUR9LRMt6fEJlkwq6FJGe1PtrBJatpgBbBcAta7kHIw1BY1k
         CXrGWu4AnTjkVE0zql5bX6nUToZM2ueqRi77jqc1TdkIDnutgB7uYaRWHwuvcYLOqwSY
         ME8We1VOsTx4TktkBVyNgRp3Q7MozKAa3EbfOWBsW/NFyvyCJXkkhTvtBHpo1ziq1c8M
         zSFI2B+XJ/uhENLvcxlNPYpwq4OZjxF6dq2ujxR0TfMIsG37cv+TPxGsVjMzsFJ6wQRq
         VVpZCr2iNiBxKlIKAccQpBIeQ4LhVeUJ0D6BmjTXK1MnGeLzadQ/IsFaMqky9sBjWrHy
         Rk0A==
X-Gm-Message-State: APjAAAX2Uqq87lRgR9anuB6opzxKggdtZo7a8Zf/tNkel+60Li8sy8Dp
	dJAgAA3nJHi3jKPnfcLS0FA=
X-Google-Smtp-Source: APXvYqx+qWrgwShdMIYzJEOPZyH316/Ij5UqRgygYD7ChGAFKJf7JSHk11ZHQN6RQTmB+jg1RKcQYA==
X-Received: by 2002:a67:d403:: with SMTP id c3mr6295397vsj.168.1561725644516;
        Fri, 28 Jun 2019 05:40:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:3229:: with SMTP id x38ls154095uad.4.gmail; Fri, 28 Jun
 2019 05:40:44 -0700 (PDT)
X-Received: by 2002:ab0:2556:: with SMTP id l22mr503495uan.46.1561725644159;
        Fri, 28 Jun 2019 05:40:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561725644; cv=none;
        d=google.com; s=arc-20160816;
        b=eJCIWryJzJxmqIaWYU1JS+VIXVAYZST/VuodwwIiQ2JUEKbuk7vWLbBGXWVH/9xb08
         DSEWEfxn2BBRyKm9M6leNqrwS3UWFtYz3OAi0I0Gv+qVgsZRxAT/EfbvHhlprA7Hw335
         CCEyyOkAhq8ZhS917a/cAtQNhbY/I/0DlITkNCsKjwuyXTidTJ7IcAioXFjU3XJ064AQ
         hel8bcflMR8iUE+KncHKu/Pw/hsdQaGxZZan/AnaFIYhPOEoZP04fKRfbDkOsD2xzD00
         rdK6cmlr9eX6kv9/Kz1qXPxU//LrWt60QEOoipsmfR+DpcZNshiG3c+tJEeZoOCLouMC
         WN8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=4r5lnU+Fb20qIJcPxgVPlPe0n66217ogjppTK0HI2rc=;
        b=yFp30wp+FM/FdY67DpeWBwseHf6xXKabQkqbv67N3wjdPC4lBSwNPhi6/0QDSCEit6
         ia8griB5ws7Bkf/Er6egGHkEj+CKdzitKEzStgSgM2QfvB3TQ0+y/6nRh/9lI9iqSpH5
         l/Lo0abtZvazACen8K8d+PxVpclVwdeKhSxvYeRpWN8V8GFgesIXJ15ecPM24XqdsGLB
         +CwWvEgbHfVGU7Pu4ZSpXntYKC9M3LU29tT6XNfuNipeBddqRsSe2VXgmp+l4SgzBdqF
         Zdkz0Z+Vzmgl0njb6fG9Qs9kmxvetS1lpD+4OVS+blvXpE/lt0Dfgb4YoNJ1hF+wtIR5
         3UHA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YmSKfcAY;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e44 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe44.google.com (mail-vs1-xe44.google.com. [2607:f8b0:4864:20::e44])
        by gmr-mx.google.com with ESMTPS id h141si135036vkh.4.2019.06.28.05.40.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Fri, 28 Jun 2019 05:40:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e44 as permitted sender) client-ip=2607:f8b0:4864:20::e44;
Received: by mail-vs1-xe44.google.com with SMTP id q64so3944267vsd.1
        for <kasan-dev@googlegroups.com>; Fri, 28 Jun 2019 05:40:44 -0700 (PDT)
X-Received: by 2002:a67:8d8a:: with SMTP id p132mr5852269vsd.103.1561725643278;
 Fri, 28 Jun 2019 05:40:43 -0700 (PDT)
MIME-Version: 1.0
References: <CADvbK_fCWry5LRV-6yzkgLQXFj0_Qxi46gRrrO-ikOh8SbxQuA@mail.gmail.com>
 <CAG_fn=UoK7qE-x7NHN17GXGNctKoEKZe9rZ7QqP1otnSCfcJDw@mail.gmail.com>
 <CADvbK_fTGwW=HHhXFgatN7QzhNHoFTjmNH7orEdb3N1Gt+1fgg@mail.gmail.com>
 <CAG_fn=U-OBaRhPN7ab9dFcpchC1AftBN+wJMF+13FOBZORieUg@mail.gmail.com>
 <CAG_fn=W7Z31JjMio++4pWa67BNfZRzwtjnRC-_DQXQch1X=F5w@mail.gmail.com> <CADvbK_eeDPm2K3w2Y37fWeW=W=X3Kw6Lz9c10JyZC1vV0pYSEw@mail.gmail.com>
In-Reply-To: <CADvbK_eeDPm2K3w2Y37fWeW=W=X3Kw6Lz9c10JyZC1vV0pYSEw@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 28 Jun 2019 14:40:30 +0200
Message-ID: <CAG_fn=VoQuryp2sGS6mVrQD3HnMFSC1MboCy0xSWA9mRCDS2NA@mail.gmail.com>
Subject: Re: how to start kmsan kernel with qemu
To: Xin Long <lucien.xin@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Dmitriy Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YmSKfcAY;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e44 as
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

It's interesting that you're seeing the same error as reported here:
https://github.com/google/kmsan/issues/53
I've updated my Clang to a4771e9dfdb0485c2edb416bfdc479d49de0aa14, but
the kernel compiles just fine.
May I ask you to do the following:

 - run `make V=3D1` to capture the command line used to build
arch/x86/kernel/process_64.o
 - copy and paste the command line into a shell, remove '-o
/tmp/somefile' and run again to make sure the compiler still crashes
 - replace '-c' with '-E' in the command line and add '-o
process_64.i' to the end
 - send me the resulting preprocessed file (process_64.i)

Thanks!



On Thu, Jun 27, 2019 at 4:45 PM Xin Long <lucien.xin@gmail.com> wrote:
>
> Now I'm using:
> # Compiler: clang version 9.0.0
> (https://github.com/llvm/llvm-project.git
> a056684c335995214f6d3467c699d32f8e73b763)
>
> Errors shows up when building the kernel:
>
>   CC      arch/x86/kernel/process_64.o
> clang-9: /home/tools/llvm-project/llvm/lib/Transforms/Instrumentation/Mem=
orySanitizer.cpp:3236:
> void {anonymous}::MemorySanitizerVisitor::visitCallSite(llvm::CallSite):
> Assertion `(CS.isCall() || CS.isInvoke()) && "Unknown type of
> CallSite"' failed.
> Stack dump:
> 0.      Program arguments: /home/tools/llvm-project/build/bin/clang-9
> -cc1 -triple x86_64-unknown-linux-gnu -S -disable-free -main-file-name
> process_64.c -mrelocation-model static -mthread-model posix
> -fno-delete-null-pointer-checks -mllvm -warn-stack-size=3D2048
> -mdisable-fp-elim -relaxed-aliasing -mdisable-tail-calls -fmath-errno
> -masm-verbose -no-integrated-as -mconstructor-aliases -fuse-init-array
> -mcode-model kernel -target-cpu core2 -target-feature
> +retpoline-indirect-calls -target-feature +retpoline-indirect-branches
> -target-feature -sse -target-feature -mmx -target-feature -sse2
> -target-feature -3dnow -target-feature -avx -target-feature -x87
> -target-feature +retpoline-external-thunk -disable-red-zone
> -dwarf-column-info -debug-info-kind=3Dlimited -dwarf-version=3D4
> -debugger-tuning=3Dgdb -momit-leaf-frame-pointer -coverage-notes-file
> /home/kmsan/arch/x86/kernel/process_64.gcno -nostdsysteminc
> -nobuiltininc -resource-dir
> /home/tools/llvm-project/build/lib/clang/9.0.0 -dependency-file
> arch/x86/kernel/.process_64.o.d -MT arch/x86/kernel/process_64.o
> -sys-header-deps -isystem
> /home/tools/llvm-project/build/lib/clang/9.0.0/include -include
> ./include/linux/kconfig.h -include ./include/linux/compiler_types.h -I
> ./arch/x86/include -I ./arch/x86/include/generated -I ./include -I
> ./arch/x86/include/uapi -I ./arch/x86/include/generated/uapi -I
> ./include/uapi -I ./include/generated/uapi -D __KERNEL__ -D
> CONFIG_X86_X32_ABI -D CONFIG_AS_CFI=3D1 -D CONFIG_AS_CFI_SIGNAL_FRAME=3D1
> -D CONFIG_AS_CFI_SECTIONS=3D1 -D CONFIG_AS_SSSE3=3D1 -D CONFIG_AS_AVX=3D1=
 -D
> CONFIG_AS_AVX2=3D1 -D CONFIG_AS_AVX512=3D1 -D CONFIG_AS_SHA1_NI=3D1 -D
> CONFIG_AS_SHA256_NI=3D1 -D KBUILD_BASENAME=3D"process_64" -D
> KBUILD_MODNAME=3D"process_64" -O2 -Wall -Wundef
> -Werror=3Dstrict-prototypes -Wno-trigraphs
> -Werror=3Dimplicit-function-declaration -Werror=3Dimplicit-int
> -Wno-format-security -Wno-sign-compare -Wno-address-of-packed-member
> -Wno-format-invalid-specifier -Wno-gnu -Wno-tautological-compare
> -Wno-unused-const-variable -Wdeclaration-after-statement -Wvla
> -Wno-pointer-sign -Werror=3Ddate-time -Werror=3Dincompatible-pointer-type=
s
> -Wno-initializer-overrides -Wno-unused-value -Wno-format
> -Wno-sign-compare -Wno-format-zero-length -Wno-uninitialized
> -std=3Dgnu89 -fno-dwarf-directory-asm -fdebug-compilation-dir
> /home/kmsan -ferror-limit 19 -fmessage-length 0
> -fsanitize=3Dkernel-memory -fwrapv -stack-protector 2
> -mstack-alignment=3D8 -fwchar-type=3Dshort -fno-signed-wchar
> -fobjc-runtime=3Dgcc -fno-common -fdiagnostics-show-option
> -fcolor-diagnostics -vectorize-loops -vectorize-slp -o
> /tmp/process_64-e20ead.s -x c arch/x86/kernel/process_64.c
> 1.      <eof> parser at end of file
> 2.      Per-module optimization passes
> 3.      Running pass 'Function Pass Manager' on module
> 'arch/x86/kernel/process_64.c'.
> 4.      Running pass 'MemorySanitizerLegacyPass' on function '@start_thre=
ad'
>  #0 0x00000000024f03ba llvm::sys::PrintStackTrace(llvm::raw_ostream&)
> (/home/tools/llvm-project/build/bin/clang-9+0x24f03ba)
>  #1 0x00000000024ee214 llvm::sys::RunSignalHandlers()
> (/home/tools/llvm-project/build/bin/clang-9+0x24ee214)
>  #2 0x00000000024ee375 SignalHandler(int)
> (/home/tools/llvm-project/build/bin/clang-9+0x24ee375)
>  #3 0x00007f85ed99bd80 __restore_rt (/lib64/libpthread.so.0+0x12d80)
>  #4 0x00007f85ec47c93f raise (/lib64/libc.so.6+0x3793f)
>  #5 0x00007f85ec466c95 abort (/lib64/libc.so.6+0x21c95)
>  #6 0x00007f85ec466b69 _nl_load_domain.cold.0 (/lib64/libc.so.6+0x21b69)
>  #7 0x00007f85ec474df6 (/lib64/libc.so.6+0x2fdf6)
>  #8 0x000000000327b864 (anonymous
> namespace)::MemorySanitizerVisitor::visitCallSite(llvm::CallSite)
> (/home/tools/llvm-project/build/bin/clang-9+0x327b864)
>  #9 0x0000000003283036 (anonymous
> namespace)::MemorySanitizerVisitor::runOnFunction()
> (/home/tools/llvm-project/build/bin/clang-9+0x3283036)
> #10 0x000000000328605f (anonymous
> namespace)::MemorySanitizer::sanitizeFunction(llvm::Function&,
> llvm::TargetLibraryInfo&)
> (/home/tools/llvm-project/build/bin/clang-9+0x328605f)
> #11 0x0000000001f42ac8
> llvm::FPPassManager::runOnFunction(llvm::Function&)
> (/home/tools/llvm-project/build/bin/clang-9+0x1f42ac8)
> #12 0x0000000001f42be9 llvm::FPPassManager::runOnModule(llvm::Module&)
> (/home/tools/llvm-project/build/bin/clang-9+0x1f42be9)
> #13 0x0000000001f41ed8
> llvm::legacy::PassManagerImpl::run(llvm::Module&)
> (/home/tools/llvm-project/build/bin/clang-9+0x1f41ed8)
> #14 0x00000000026fa4f8 (anonymous
> namespace)::EmitAssemblyHelper::EmitAssembly(clang::BackendAction,
> std::unique_ptr<llvm::raw_pwrite_stream,
> std::default_delete<llvm::raw_pwrite_stream> >)
> (/home/tools/llvm-project/build/bin/clang-9+0x26fa4f8)
> #15 0x00000000026fbbf8
> clang::EmitBackendOutput(clang::DiagnosticsEngine&,
> clang::HeaderSearchOptions const&, clang::CodeGenOptions const&,
> clang::TargetOptions const&, clang::LangOptions const&,
> llvm::DataLayout const&, llvm::Module*, clang::BackendAction,
> std::unique_ptr<llvm::raw_pwrite_stream,
> std::default_delete<llvm::raw_pwrite_stream> >)
> (/home/tools/llvm-project/build/bin/clang-9+0x26fbbf8)
> #16 0x000000000310234d
> clang::BackendConsumer::HandleTranslationUnit(clang::ASTContext&)
> (/home/tools/llvm-project/build/bin/clang-9+0x310234d)
> #17 0x0000000003aaddf9 clang::ParseAST(clang::Sema&, bool, bool)
> (/home/tools/llvm-project/build/bin/clang-9+0x3aaddf9)
> #18 0x00000000030fe5e0 clang::CodeGenAction::ExecuteAction()
> (/home/tools/llvm-project/build/bin/clang-9+0x30fe5e0)
> #19 0x0000000002ba1929 clang::FrontendAction::Execute()
> (/home/tools/llvm-project/build/bin/clang-9+0x2ba1929)
> #20 0x0000000002b68e62
> clang::CompilerInstance::ExecuteAction(clang::FrontendAction&)
> (/home/tools/llvm-project/build/bin/clang-9+0x2b68e62)
> #21 0x0000000002c5738a
> clang::ExecuteCompilerInvocation(clang::CompilerInstance*)
> (/home/tools/llvm-project/build/bin/clang-9+0x2c5738a)
> #22 0x00000000009cd1a6 cc1_main(llvm::ArrayRef<char const*>, char
> const*, void*) (/home/tools/llvm-project/build/bin/clang-9+0x9cd1a6)
> #23 0x000000000094cac1 main
> (/home/tools/llvm-project/build/bin/clang-9+0x94cac1)
> #24 0x00007f85ec468813 __libc_start_main (/lib64/libc.so.6+0x23813)
> #25 0x00000000009c96ee _start
> (/home/tools/llvm-project/build/bin/clang-9+0x9c96ee)
> clang-9: error: unable to execute command: Aborted (core dumped)
> clang-9: error: clang frontend command failed due to signal (use -v to
> see invocation)
> clang version 9.0.0 (https://github.com/llvm/llvm-project.git
> a056684c335995214f6d3467c699d32f8e73b763)
> Target: x86_64-unknown-linux-gnu
> Thread model: posix
> InstalledDir: /home/tools/llvm-project/build/bin
> clang-9: note: diagnostic msg: PLEASE submit a bug report to
> https://bugs.llvm.org/ and include the crash backtrace, preprocessed
> source, and associated run script.
> clang-9: note: diagnostic msg:
> ********************
>
> PLEASE ATTACH THE FOLLOWING FILES TO THE BUG REPORT:
> Preprocessed source(s) and associated run script(s) are located at:
> clang-9: note: diagnostic msg: /tmp/process_64-5fbbdc.c
> clang-9: note: diagnostic msg: /tmp/process_64-5fbbdc.sh
> clang-9: note: diagnostic msg:
>
> ********************
> make[2]: *** [scripts/Makefile.build:276:
> arch/x86/kernel/process_64.o] Error 254
>
>
> any idea why?
>
> On Thu, Jun 27, 2019 at 5:23 PM Alexander Potapenko <glider@google.com> w=
rote:
> >
> > Actually, your config says:
> >   "Compiler: clang version 8.0.0 (trunk 343298)"
> > I think you'll need at least Clang r362410 (mine is r362913)
> >
> > On Thu, Jun 27, 2019 at 11:20 AM Alexander Potapenko <glider@google.com=
> wrote:
> > >
> > > Hi Xin,
> > >
> > > Sorry for the late reply.
> > > I've built the ToT KMSAN tree using your config and my almost-ToT
> > > Clang and couldn't reproduce the problem.
> > > I believe something is wrong with your Clang version, as
> > > CONFIG_CLANG_VERSION should really be 90000.
> > > You can run `make V=3D1` to see which Clang version is being invoked =
-
> > > make sure it's a fresh one.
> > >
> > > HTH,
> > > Alex
> > >
> > > On Fri, Jun 21, 2019 at 10:09 PM Xin Long <lucien.xin@gmail.com> wrot=
e:
> > > >
> > > > as attached,
> > > >
> > > > It actually came from https://syzkaller.appspot.com/x/.config?x=3D6=
02468164ccdc30a
> > > > after I built, clang version changed to:
> > > >
> > > > CONFIG_CLANG_VERSION=3D80000
> > > >
> > > > On Sat, Jun 22, 2019 at 2:06 AM Alexander Potapenko <glider@google.=
com> wrote:
> > > > >
> > > > > Hi Xin,
> > > > >
> > > > > Could you please share the config you're using to build the kerne=
l?
> > > > > I'll take a closer look on Monday when I am back to the office.
> > > > >
> > > > > On Fri, 21 Jun 2019, 18:15 Xin Long, <lucien.xin@gmail.com> wrote=
:
> > > > >>
> > > > >> this is my command:
> > > > >>
> > > > >> /usr/libexec/qemu-kvm -smp 2 -m 4G -enable-kvm -cpu host \
> > > > >>     -net nic -net user,hostfwd=3Dtcp::10022-:22 \
> > > > >>     -kernel /home/kmsan/arch/x86/boot/bzImage -nographic \
> > > > >>     -device virtio-scsi-pci,id=3Dscsi \
> > > > >>     -device scsi-hd,bus=3Dscsi.0,drive=3Dd0 \
> > > > >>     -drive file=3D/root/test/wheezy.img,format=3Draw,if=3Dnone,i=
d=3Dd0 \
> > > > >>     -append "root=3D/dev/sda console=3DttyS0 earlyprintk=3Dseria=
l rodata=3Dn \
> > > > >>       oops=3Dpanic panic_on_warn=3D1 panic=3D86400 kvm-intel.nes=
ted=3D1 \
> > > > >>       security=3Dapparmor ima_policy=3Dtcb workqueue.watchdog_th=
resh=3D140 \
> > > > >>       nf-conntrack-ftp.ports=3D20000 nf-conntrack-tftp.ports=3D2=
0000 \
> > > > >>       nf-conntrack-sip.ports=3D20000 nf-conntrack-irc.ports=3D20=
000 \
> > > > >>       nf-conntrack-sane.ports=3D20000 vivid.n_devs=3D16 \
> > > > >>       vivid.multiplanar=3D1,2,1,2,1,2,1,2,1,2,1,2,1,2,1,2 \
> > > > >>       spec_store_bypass_disable=3Dprctl nopcid"
> > > > >>
> > > > >> the commit is on:
> > > > >> commit f75e4cfea97f67b7530b8b991b3005f991f04778 (HEAD)
> > > > >> Author: Alexander Potapenko <glider@google.com>
> > > > >> Date:   Wed May 22 12:30:13 2019 +0200
> > > > >>
> > > > >>     kmsan: use kmsan_handle_urb() in urb.c
> > > > >>
> > > > >> and when starting, it shows:
> > > > >> [    0.561925][    T0] Kernel command line: root=3D/dev/sda
> > > > >> console=3DttyS0 earlyprintk=3Dserial rodata=3Dn       oops=3Dpan=
ic
> > > > >> panic_on_warn=3D1 panic=3D86400 kvm-intel.nested=3D1       secur=
ity=3Dad
> > > > >> [    0.707792][    T0] Memory: 3087328K/4193776K available (2191=
64K
> > > > >> kernel code, 7059K rwdata, 11712K rodata, 5064K init, 11904K bss=
,
> > > > >> 1106448K reserved, 0K cma-reserved)
> > > > >> [    0.710935][    T0] SLUB: HWalign=3D64, Order=3D0-3, MinObjec=
ts=3D0,
> > > > >> CPUs=3D2, Nodes=3D1
> > > > >> [    0.711953][    T0] Starting KernelMemorySanitizer
> > > > >> [    0.712563][    T0]
> > > > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > > > >> [    0.713657][    T0] BUG: KMSAN: uninit-value in mutex_lock+0x=
d1/0xe0
> > > > >> [    0.714570][    T0] CPU: 0 PID: 0 Comm: swapper Not tainted 5=
.1.0 #5
> > > > >> [    0.715417][    T0] Hardware name: Red Hat KVM, BIOS
> > > > >> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01/2014
> > > > >> [    0.716659][    T0] Call Trace:
> > > > >> [    0.717127][    T0]  dump_stack+0x134/0x190
> > > > >> [    0.717727][    T0]  kmsan_report+0x131/0x2a0
> > > > >> [    0.718347][    T0]  __msan_warning+0x7a/0xf0
> > > > >> [    0.718952][    T0]  mutex_lock+0xd1/0xe0
> > > > >> [    0.719478][    T0]  __cpuhp_setup_state_cpuslocked+0x149/0xd=
20
> > > > >> [    0.720260][    T0]  ? vprintk_func+0x6b5/0x8a0
> > > > >> [    0.720926][    T0]  ? rb_get_reader_page+0x1140/0x1140
> > > > >> [    0.721632][    T0]  __cpuhp_setup_state+0x181/0x2e0
> > > > >> [    0.722374][    T0]  ? rb_get_reader_page+0x1140/0x1140
> > > > >> [    0.723115][    T0]  tracer_alloc_buffers+0x16b/0xb96
> > > > >> [    0.723846][    T0]  early_trace_init+0x193/0x28f
> > > > >> [    0.724501][    T0]  start_kernel+0x497/0xb38
> > > > >> [    0.725134][    T0]  x86_64_start_reservations+0x19/0x2f
> > > > >> [    0.725871][    T0]  x86_64_start_kernel+0x84/0x87
> > > > >> [    0.726538][    T0]  secondary_startup_64+0xa4/0xb0
> > > > >> [    0.727173][    T0]
> > > > >> [    0.727454][    T0] Local variable description:
> > > > >> ----success.i.i.i.i@mutex_lock
> > > > >> [    0.728379][    T0] Variable was created at:
> > > > >> [    0.728977][    T0]  mutex_lock+0x48/0xe0
> > > > >> [    0.729536][    T0]  __cpuhp_setup_state_cpuslocked+0x149/0xd=
20
> > > > >> [    0.730323][    T0]
> > > > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > > > >> [    0.731364][    T0] Disabling lock debugging due to kernel ta=
int
> > > > >> [    0.732169][    T0] Kernel panic - not syncing: panic_on_warn=
 set ...
> > > > >> [    0.733047][    T0] CPU: 0 PID: 0 Comm: swapper Tainted: G   =
 B
> > > > >>         5.1.0 #5
> > > > >> [    0.734080][    T0] Hardware name: Red Hat KVM, BIOS
> > > > >> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01/2014
> > > > >> [    0.735319][    T0] Call Trace:
> > > > >> [    0.735735][    T0]  dump_stack+0x134/0x190
> > > > >> [    0.736308][    T0]  panic+0x3ec/0xb3b
> > > > >> [    0.736826][    T0]  kmsan_report+0x29a/0x2a0
> > > > >> [    0.737417][    T0]  __msan_warning+0x7a/0xf0
> > > > >> [    0.737973][    T0]  mutex_lock+0xd1/0xe0
> > > > >> [    0.738527][    T0]  __cpuhp_setup_state_cpuslocked+0x149/0xd=
20
> > > > >> [    0.739342][    T0]  ? vprintk_func+0x6b5/0x8a0
> > > > >> [    0.739972][    T0]  ? rb_get_reader_page+0x1140/0x1140
> > > > >> [    0.740695][    T0]  __cpuhp_setup_state+0x181/0x2e0
> > > > >> [    0.741412][    T0]  ? rb_get_reader_page+0x1140/0x1140
> > > > >> [    0.742160][    T0]  tracer_alloc_buffers+0x16b/0xb96
> > > > >> [    0.742866][    T0]  early_trace_init+0x193/0x28f
> > > > >> [    0.743512][    T0]  start_kernel+0x497/0xb38
> > > > >> [    0.744128][    T0]  x86_64_start_reservations+0x19/0x2f
> > > > >> [    0.744863][    T0]  x86_64_start_kernel+0x84/0x87
> > > > >> [    0.745534][    T0]  secondary_startup_64+0xa4/0xb0
> > > > >> [    0.746290][    T0] Rebooting in 86400 seconds..
> > > > >>
> > > > >> when I set "panic_on_warn=3D0", it foods the console with:
> > > > >> ...
> > > > >> [   25.206759][    C0] Variable was created at:
> > > > >> [   25.207302][    C0]  vprintk_emit+0xf4/0x800
> > > > >> [   25.207844][    C0]  vprintk_deferred+0x90/0xed
> > > > >> [   25.208404][    C0]
> > > > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > > > >> [   25.209763][    C0]  x86_64_start_reservations+0x19/0x2f
> > > > >> [   25.209769][    C0]
> > > > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > > > >> [   25.211408][    C0] BUG: KMSAN: uninit-value in vprintk_emit+=
0x443/0x800
> > > > >> [   25.212237][    C0] CPU: 0 PID: 0 Comm: swapper/0 Tainted: G =
   B
> > > > >>           5.1.0 #5
> > > > >> [   25.213206][    C0] Hardware name: Red Hat KVM, BIOS
> > > > >> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01/2014
> > > > >> [   25.214326][    C0] Call Trace:
> > > > >> [   25.214725][    C0]  <IRQ>
> > > > >> [   25.215080][    C0]  dump_stack+0x134/0x190
> > > > >> [   25.215624][    C0]  kmsan_report+0x131/0x2a0
> > > > >> [   25.216204][    C0]  __msan_warning+0x7a/0xf0
> > > > >> [   25.216771][    C0]  vprintk_emit+0x443/0x800
> > > > >> [   25.217334][    C0]  ? __msan_metadata_ptr_for_store_1+0x13/0=
x20
> > > > >> [   25.218127][    C0]  vprintk_deferred+0x90/0xed
> > > > >> [   25.218714][    C0]  printk_deferred+0x186/0x1d3
> > > > >> [   25.219353][    C0]  __printk_safe_flush+0x72e/0xc00
> > > > >> [   25.220006][    C0]  ? printk_safe_flush+0x1e0/0x1e0
> > > > >> [   25.220635][    C0]  irq_work_run+0x1ad/0x5c0
> > > > >> [   25.221210][    C0]  ? flat_init_apic_ldr+0x170/0x170
> > > > >> [   25.221851][    C0]  smp_irq_work_interrupt+0x237/0x3e0
> > > > >> [   25.222520][    C0]  irq_work_interrupt+0x2e/0x40
> > > > >> [   25.223110][    C0]  </IRQ>
> > > > >> [   25.223475][    C0] RIP: 0010:kmem_cache_init_late+0x0/0xb
> > > > >> [   25.224164][    C0] Code: d4 e8 5d dd 2e f2 e9 74 fe ff ff 48=
 89 d3
> > > > >> 8b 7d d4 e8 cd d7 2e f2 89 c0 48 89 c1 48 c1 e1 20 48 09 c1 48 8=
9 0b
> > > > >> e9 81 fe ff ff <55> 48 89 e5 e8 20 de 2e1
> > > > >> [   25.226526][    C0] RSP: 0000:ffffffff8f40feb8 EFLAGS: 000002=
46
> > > > >> ORIG_RAX: ffffffffffffff09
> > > > >> [   25.227548][    C0] RAX: ffff88813f995785 RBX: 00000000000000=
00
> > > > >> RCX: 0000000000000000
> > > > >> [   25.228511][    C0] RDX: ffff88813f2b0784 RSI: 00001600000000=
00
> > > > >> RDI: 0000000000000785
> > > > >> [   25.229473][    C0] RBP: ffffffff8f40ff20 R08: 000000000fac37=
85
> > > > >> R09: 0000778000000001
> > > > >> [   25.230440][    C0] R10: ffffd0ffffffffff R11: 00001000000000=
00
> > > > >> R12: 0000000000000000
> > > > >> [   25.231403][    C0] R13: 0000000000000000 R14: ffffffff8fb8cf=
d0
> > > > >> R15: 0000000000000000
> > > > >> [   25.232407][    C0]  ? start_kernel+0x5d8/0xb38
> > > > >> [   25.233003][    C0]  x86_64_start_reservations+0x19/0x2f
> > > > >> [   25.233670][    C0]  x86_64_start_kernel+0x84/0x87
> > > > >> [   25.234314][    C0]  secondary_startup_64+0xa4/0xb0
> > > > >> [   25.234949][    C0]
> > > > >> [   25.235231][    C0] Local variable description: ----flags.i.i=
.i@vprintk_emit
> > > > >> [   25.236101][    C0] Variable was created at:
> > > > >> [   25.236643][    C0]  vprintk_emit+0xf4/0x800
> > > > >> [   25.237188][    C0]  vprintk_deferred+0x90/0xed
> > > > >> [   25.237752][    C0]
> > > > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > > > >> [   25.239117][    C0]  x86_64_start_kernel+0x84/0x87
> > > > >> [   25.239123][    C0]
> > > > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > > > >> [   25.240704][    C0] BUG: KMSAN: uninit-value in vprintk_emit+=
0x443/0x800
> > > > >> [   25.241540][    C0] CPU: 0 PID: 0 Comm: swapper/0 Tainted: G =
   B
> > > > >>           5.1.0 #5
> > > > >> [   25.242512][    C0] Hardware name: Red Hat KVM, BIOS
> > > > >> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01/2014
> > > > >> [   25.243635][    C0] Call Trace:
> > > > >> [   25.244038][    C0]  <IRQ>
> > > > >> [   25.244390][    C0]  dump_stack+0x134/0x190
> > > > >> [   25.244940][    C0]  kmsan_report+0x131/0x2a0
> > > > >> [   25.245515][    C0]  __msan_warning+0x7a/0xf0
> > > > >> [   25.246082][    C0]  vprintk_emit+0x443/0x800
> > > > >> [   25.246638][    C0]  ? __msan_metadata_ptr_for_store_1+0x13/0=
x20
> > > > >> [   25.247430][    C0]  vprintk_deferred+0x90/0xed
> > > > >> [   25.248018][    C0]  printk_deferred+0x186/0x1d3
> > > > >> [   25.248650][    C0]  __printk_safe_flush+0x72e/0xc00
> > > > >> [   25.249320][    C0]  ? printk_safe_flush+0x1e0/0x1e0
> > > > >> [   25.249949][    C0]  irq_work_run+0x1ad/0x5c0
> > > > >> [   25.250524][    C0]  ? flat_init_apic_ldr+0x170/0x170
> > > > >> [   25.251167][    C0]  smp_irq_work_interrupt+0x237/0x3e0
> > > > >> [   25.251837][    C0]  irq_work_interrupt+0x2e/0x40
> > > > >> [   25.252424][    C0]  </IRQ>
> > > > >> ....
> > > > >>
> > > > >>
> > > > >> I couldn't even log in.
> > > > >>
> > > > >> how should I use qemu with wheezy.img to start a kmsan kernel?
> > > > >>
> > > > >> Thanks.
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



--
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVoQuryp2sGS6mVrQD3HnMFSC1MboCy0xSWA9mRCDS2NA%40mail.gmai=
l.com.
For more options, visit https://groups.google.com/d/optout.
