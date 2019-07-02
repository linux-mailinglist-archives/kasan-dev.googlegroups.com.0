Return-Path: <kasan-dev+bncBCWPNP5RT4JRB26M5TUAKGQEUTNTVQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2FC475CCBE
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jul 2019 11:39:56 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id 9sf3338510ljp.7
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jul 2019 02:39:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1562060395; cv=pass;
        d=google.com; s=arc-20160816;
        b=Qzl3l8JYpikEEO+bMetwWv1JzidL8eQWf2VL3pgdaGSoqw54FTX49VVs2JuH3ojNcL
         qKtRLwTLaRqcSRxfqPxSHLNggIgQ5B1r2CBm63ZqMoig8BSxuMklqjXMgtWA/Nz1mWSe
         DoDC+37QVIragHKY6B3nbhcfwyBINnwDzM0xoecB/AwX2F+nz27rORYAXkFAf9onIZOq
         i4jh6sQInMeg1KyC8sR35bkmrv3vu337vH26BrBWV/IuC6h8VLolKDqqcJrEqqvVoZSD
         6OcaUewgworgCCIjGtnzAcFRp1A8/mVhbi0TRn08HN2zzkU0DvMektR78V8SHhyAXEUO
         mW6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=pnK115YzVAofvB4HT0Kl9KzHy5Iif+B0KA5yoeD/EY8=;
        b=i77CHZ/94bx5+yqU/DUBMLMFckxGLdzI6bI7cAfH5VyBUnashCFybDMxNT8YJzCEsd
         MPnwmCFnzZt8Rm3RkzqZyFABM8haWPsTXVMyIfC37EtTtDj/I9a1hk92nkSZISWsRaOk
         vaw8qCS/Frsqt77bH/MkFwJ7UX+knZq/GBUlNOdR8pqfQJB0B8yMfGax5Z0fMeKdyo4N
         Z4zbYRZLt2xV0exzIg1bgxSJByi1CVwkkBNmMzlx6tRL/4NhhMQOEjaIhSb1W3Py25F9
         ECbqPcPnvlTPfH5Xv2MI0/sf4gMmzBRVWryLEHtYKCyOqjmfMBNc50ytrWe63JgC4qUt
         waOQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=o7S+qxK4;
       spf=pass (google.com: domain of lucien.xin@gmail.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=lucien.xin@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pnK115YzVAofvB4HT0Kl9KzHy5Iif+B0KA5yoeD/EY8=;
        b=hNdH6W9Zb0JSuAeGsXLGlkb/ZTWe6ZAKo18QMWt1hfc9A9DqV82k6iC23Q4VssbF52
         JonVn3AbIjPiPuLvm/YFryZ20pjCbDViA0qkLeCQ2HxlARqA/8Kcep81CkHSlYgNy94b
         vaApOZd4RN61l427spJbPLIrkQ0Dts0C3aQ3eh6KMCKRX0R0s9i4LtTQcwa13QQYXIzM
         USsFP/L6sp+D7Wv9D/b42aQho5Y5GMTQFXJKweRKCAEYmR2GpF9dB2El5qSG6LppHkSV
         /S3WryyDRHBZOaREOLCBne5tcHWgTK2Tq4Mkqw2foVAmqPqK0NK5J81CwRpMWHjTFZOM
         KpYg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pnK115YzVAofvB4HT0Kl9KzHy5Iif+B0KA5yoeD/EY8=;
        b=hRyZPkEeDts2d9NCOAOCDdJf13CjC92AKwKsnoz1D9lC0o4jXDYshKly9t+kCtqePD
         oCHjiRbdxtIcTSTppCACRPrdTV9a3kcKDEVK3I4XGGuY8EH6IhlqUNfgUdkOkY///Ryz
         lK85kMnNXl+5HUWTHrxdm6Niawhw8TGdknOs3YX1xV8YqI+k7axZQ86LkwuaZu7ZZW4p
         eCsmFqBqaq3m+40Dj1qAGH+fUlEovNqd5pGfCrLXu4S45MDK5WH1lbaBaR1IWMMwJ9as
         gd6FANTjq6CfEAhetbrq8fuviBB13Tdj9NvRHvwDEslPLkXexyGZejBQuUSS4TfixWgJ
         E78g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=pnK115YzVAofvB4HT0Kl9KzHy5Iif+B0KA5yoeD/EY8=;
        b=KW5iXztZISR6SrGXgS0HksAs0ec5ZWtVQ+DltVJrgda0V2wGohv5FG3qTV5Zkh9hSh
         rPgHxBvz6xKKcWzhRh6i7bAhdAfXTbJR8Dgg5mNiXO2ocQpMIn/DILqMaUGt8JN+QnvJ
         gZExWjaAAdHzN1CzeRJLlLBtkf//a1tFPeIPEIyVD9quYWhiVX42nHM1+vBVayNXjBVE
         OAtVewf8uwW8LW429n73WGljO2MfkybjGMRw8zMqT5td6t/KzAu3tEbQdUJj4UycaLOJ
         yTIxJIkGE6WCUUhB2LpmqfO2oL6A32UeCpNfCxVvLgH+wel5+nPGDtiqwDN1PE+/+CKq
         eXuw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUsbJF2krISWKMOS38c9Vi9LTk8tJpU8GtqQ2HRmP2JNH77gRfW
	L7cTbkBsJptkOb9zt/uct50=
X-Google-Smtp-Source: APXvYqzbWAHjJU5KTX5e8ATl3L/Wm62S0KG3vAsyDM/dIny3WS80XfY4KyxSKV5FPbGb9Xm/Nkj0fA==
X-Received: by 2002:a2e:988b:: with SMTP id b11mr5499873ljj.110.1562060395642;
        Tue, 02 Jul 2019 02:39:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:640f:: with SMTP id y15ls964972lfb.14.gmail; Tue, 02 Jul
 2019 02:39:54 -0700 (PDT)
X-Received: by 2002:ac2:5a01:: with SMTP id q1mr14395603lfn.46.1562060394926;
        Tue, 02 Jul 2019 02:39:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1562060394; cv=none;
        d=google.com; s=arc-20160816;
        b=uz/hp3RwZVRLvPHmtILf2gMHfljfPXnKoOtVhcI0b6HJk5C5VveTXYjQQ4cwQO4Eua
         oo68D+MIAQQ3x1pS2h/2s38Q3c3/Bxd9vsbbJNRP96zS7eF+J9rr0gMVCS2b2Ict3nO4
         THtAhSx6PhQZU5kMD3wRWc85lwB3HnT7Q0v8vMYfld53rTvjeMtuonxBjZam3cbC7dnG
         t5mTAfeesqu1bmmK3rTB5GaFBSppZSxpJJt7DpLqrSipufaF6L7O1419e6D+CTcIrMqw
         avniPTkR6iiFkWZtP5Pin+sIZLF/oV2Ed8KYpEQJbuP4MQGgPAGp4XER8pkouoNdUcBT
         4Epg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=UC+2b80SWmdIohu2zhMCA9jpfXXVEfB2dCwF/0BYqfw=;
        b=kORDyz5z0cPYEVrmEOWvXRrg7j38UVVjQuo1fdpwr04ebDtz2S9hFjocL8X1accCtM
         aPEL8tElKhpIw1j3zUNt7l8uaJZ3DD0jMwAP7utkFfT8S0e9C5tDP0ae83Cc9aO2LxWe
         KAasKlgrMjhzRt7Z+XkjLNMcZ3jUz9Qf7SyirUaamR1Xn9HCy9CYllxDyIIvgLZgHBba
         Q7vsTfDUAEGogoZGRrQOggrNukple2wkJTZpnJ7+8f3iSC1fheGwqd0PW0N1FCQSQLyl
         QQmzHpWCP7gnqvahDoFnkLZF9a9ATktPRMoIUbnHgO/6rvmvsYWDthihiLENQgRPNjJp
         OeBg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=o7S+qxK4;
       spf=pass (google.com: domain of lucien.xin@gmail.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=lucien.xin@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x444.google.com (mail-wr1-x444.google.com. [2a00:1450:4864:20::444])
        by gmr-mx.google.com with ESMTPS id z18si661770lfh.1.2019.07.02.02.39.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Tue, 02 Jul 2019 02:39:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of lucien.xin@gmail.com designates 2a00:1450:4864:20::444 as permitted sender) client-ip=2a00:1450:4864:20::444;
Received: by mail-wr1-x444.google.com with SMTP id n4so16943249wrw.13
        for <kasan-dev@googlegroups.com>; Tue, 02 Jul 2019 02:39:54 -0700 (PDT)
X-Received: by 2002:a5d:5386:: with SMTP id d6mr14998792wrv.207.1562060394275;
 Tue, 02 Jul 2019 02:39:54 -0700 (PDT)
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
 <CAG_fn=VgE7b4V4fCFApxUKFeV46pSmXuNucAUqqMWUdMV+CrvA@mail.gmail.com>
 <CADvbK_fPKE6zq91yGp-J0XuZF+0XUayJgJUMSBGNkRaFbi7dtg@mail.gmail.com>
 <CADvbK_d03Fhowi7DR3+PvbafhW=6BV430Gt3K8gCyF_EAxsOGg@mail.gmail.com> <CAG_fn=XAytdKY+QbcNY6ZiNrnKAu==OSz8SBz2f=W=K8HqAyug@mail.gmail.com>
In-Reply-To: <CAG_fn=XAytdKY+QbcNY6ZiNrnKAu==OSz8SBz2f=W=K8HqAyug@mail.gmail.com>
From: Xin Long <lucien.xin@gmail.com>
Date: Tue, 2 Jul 2019 17:39:42 +0800
Message-ID: <CADvbK_d8HnKu+oSGha4w2wWRmQW8w+mqxJDnqDqezZEvVd-_7A@mail.gmail.com>
Subject: Re: how to start kmsan kernel with qemu
To: Alexander Potapenko <glider@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Dmitriy Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: lucien.xin@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=o7S+qxK4;       spf=pass
 (google.com: domain of lucien.xin@gmail.com designates 2a00:1450:4864:20::444
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

On Tue, Jul 2, 2019 at 5:32 PM Alexander Potapenko <glider@google.com> wrot=
e:
>
> Ah, I see.
> You build with assertions enabled, I for some reason did not.
> There's really a bug in KMSAN instrumentation, I'll fix it.
Thanks, great that you figured it out so quickly.
I'm waiting. :-)

>
> On Fri, Jun 28, 2019 at 7:24 PM Xin Long <lucien.xin@gmail.com> wrote:
> >
> > On Sat, Jun 29, 2019 at 1:18 AM Xin Long <lucien.xin@gmail.com> wrote:
> > >
> > > # cd /home/tools/
> > > # git clone https://github.com/llvm/llvm-project.git
> > > # cd llvm-project/
> > > # mkdir build
> > > # cd build/
> > > # cmake -DLLVM_ENABLE_PROJECTS=3Dclang -DCMAKE_BUILD_TYPE=3DRelease
> > > -DLLVM_ENABLE_ASSERTIONS=3DON -G "Unix Makefiles" ../llvm
> > the output is:
> > https://paste.fedoraproject.org/paste/D9-QpmZnDcXkr4AykumRnw
> > myabe you can have a vimdiff for the outputs of yours and mine.
> >
> > > # make
> > sorry, it was # make -j64
> >
> > > # cd /home/kmsan
> > > # git checkout f75e4cfea97f
> > > (use the .config I sent you last time)
> > > # make CC=3D/home/tools/llvm-project/build/bin/clang -j64 -k LOCALVER=
SION=3D 2>&1
> > >
> > > These are the whole thing I did to build it.
> > >
> > > On Sat, Jun 29, 2019 at 12:09 AM Alexander Potapenko <glider@google.c=
om> wrote:
> > > >
> > > > Hm, now that's your Clang binary versus mine :)
> > > > Can you please ensure your git repo doesn't contain local changes a=
nd share the commands you're using to build Clang?
> > > > (Both cmake and make or ninja)
> > > No any local changes on both llvm-project and kmsan
> > >
> > > > Is the bug still reproducible in a clean CMake directory?
> > > A clean CMake directory? how to clean it? something like: # cmake cle=
an
> > >
> > > Thank you for being so patient. :-)
> > >
> > > >
> > > > On Fri, 28 Jun 2019, 16:20 Xin Long, <lucien.xin@gmail.com> wrote:
> > > >>
> > > >> yes
> > > >>
> > > >> https://paste.fedoraproject.org/paste/DU2nnxpZWpWMri9Up7hypA
> > > >>
> > > >> On Fri, Jun 28, 2019 at 9:48 PM Alexander Potapenko <glider@google=
.com> wrote:
> > > >> >
> > > >> > Hm, strange, but I still can compile this file.
> > > >> > Does the following command line crash your compiler?
> > > >> > https://paste.fedoraproject.org/paste/oJwOVm5cHWyd7hxIZ4uGeA (no=
te it
> > > >> > should be run from the same directory where process_64.i resides=
; also
> > > >> > make sure to invoke the right Clang)
> > > >> >
> > > >> > On Fri, Jun 28, 2019 at 3:35 PM Xin Long <lucien.xin@gmail.com> =
wrote:
> > > >> > >
> > > >> > > As attached, thanks.
> > > >> > >
> > > >> > > On Fri, Jun 28, 2019 at 9:24 PM Alexander Potapenko <glider@go=
ogle.com> wrote:
> > > >> > > >
> > > >> > > > On Fri, Jun 28, 2019 at 3:10 PM Xin Long <lucien.xin@gmail.c=
om> wrote:
> > > >> > > > >
> > > >> > > > > This is what I did:
> > > >> > > > > https://paste.fedoraproject.org/paste/q4~GWx9Sx~QUbJQfNDoJ=
Iw
> > > >> > > > >
> > > >> > > > > There's no process_64.i file generated.
> > > >> > > > >
> > > >> > > > > Btw, I couldn't find "-c" in the command line, so there wa=
s no "-E" added.
> > > >> > > > Ah, right, Clang is invoked with -S. Could you replace that =
one with -E?
> > > >> > > > > On Fri, Jun 28, 2019 at 8:40 PM Alexander Potapenko <glide=
r@google.com> wrote:
> > > >> > > > > >
> > > >> > > > > > It's interesting that you're seeing the same error as re=
ported here:
> > > >> > > > > > https://github.com/google/kmsan/issues/53
> > > >> > > > > > I've updated my Clang to a4771e9dfdb0485c2edb416bfdc479d=
49de0aa14, but
> > > >> > > > > > the kernel compiles just fine.
> > > >> > > > > > May I ask you to do the following:
> > > >> > > > > >
> > > >> > > > > >  - run `make V=3D1` to capture the command line used to =
build
> > > >> > > > > > arch/x86/kernel/process_64.o
> > > >> > > > > >  - copy and paste the command line into a shell, remove =
'-o
> > > >> > > > > > /tmp/somefile' and run again to make sure the compiler s=
till crashes
> > > >> > > > > >  - replace '-c' with '-E' in the command line and add '-=
o
> > > >> > > > > > process_64.i' to the end
> > > >> > > > > >  - send me the resulting preprocessed file (process_64.i=
)
> > > >> > > > > >
> > > >> > > > > > Thanks!
> > > >> > > > > >
> > > >> > > > > >
> > > >> > > > > >
> > > >> > > > > > On Thu, Jun 27, 2019 at 4:45 PM Xin Long <lucien.xin@gma=
il.com> wrote:
> > > >> > > > > > >
> > > >> > > > > > > Now I'm using:
> > > >> > > > > > > # Compiler: clang version 9.0.0
> > > >> > > > > > > (https://github.com/llvm/llvm-project.git
> > > >> > > > > > > a056684c335995214f6d3467c699d32f8e73b763)
> > > >> > > > > > >
> > > >> > > > > > > Errors shows up when building the kernel:
> > > >> > > > > > >
> > > >> > > > > > >   CC      arch/x86/kernel/process_64.o
> > > >> > > > > > > clang-9: /home/tools/llvm-project/llvm/lib/Transforms/=
Instrumentation/MemorySanitizer.cpp:3236:
> > > >> > > > > > > void {anonymous}::MemorySanitizerVisitor::visitCallSit=
e(llvm::CallSite):
> > > >> > > > > > > Assertion `(CS.isCall() || CS.isInvoke()) && "Unknown =
type of
> > > >> > > > > > > CallSite"' failed.
> > > >> > > > > > > Stack dump:
> > > >> > > > > > > 0.      Program arguments: /home/tools/llvm-project/bu=
ild/bin/clang-9
> > > >> > > > > > > -cc1 -triple x86_64-unknown-linux-gnu -S -disable-free=
 -main-file-name
> > > >> > > > > > > process_64.c -mrelocation-model static -mthread-model =
posix
> > > >> > > > > > > -fno-delete-null-pointer-checks -mllvm -warn-stack-siz=
e=3D2048
> > > >> > > > > > > -mdisable-fp-elim -relaxed-aliasing -mdisable-tail-cal=
ls -fmath-errno
> > > >> > > > > > > -masm-verbose -no-integrated-as -mconstructor-aliases =
-fuse-init-array
> > > >> > > > > > > -mcode-model kernel -target-cpu core2 -target-feature
> > > >> > > > > > > +retpoline-indirect-calls -target-feature +retpoline-i=
ndirect-branches
> > > >> > > > > > > -target-feature -sse -target-feature -mmx -target-feat=
ure -sse2
> > > >> > > > > > > -target-feature -3dnow -target-feature -avx -target-fe=
ature -x87
> > > >> > > > > > > -target-feature +retpoline-external-thunk -disable-red=
-zone
> > > >> > > > > > > -dwarf-column-info -debug-info-kind=3Dlimited -dwarf-v=
ersion=3D4
> > > >> > > > > > > -debugger-tuning=3Dgdb -momit-leaf-frame-pointer -cove=
rage-notes-file
> > > >> > > > > > > /home/kmsan/arch/x86/kernel/process_64.gcno -nostdsyst=
eminc
> > > >> > > > > > > -nobuiltininc -resource-dir
> > > >> > > > > > > /home/tools/llvm-project/build/lib/clang/9.0.0 -depend=
ency-file
> > > >> > > > > > > arch/x86/kernel/.process_64.o.d -MT arch/x86/kernel/pr=
ocess_64.o
> > > >> > > > > > > -sys-header-deps -isystem
> > > >> > > > > > > /home/tools/llvm-project/build/lib/clang/9.0.0/include=
 -include
> > > >> > > > > > > ./include/linux/kconfig.h -include ./include/linux/com=
piler_types.h -I
> > > >> > > > > > > ./arch/x86/include -I ./arch/x86/include/generated -I =
./include -I
> > > >> > > > > > > ./arch/x86/include/uapi -I ./arch/x86/include/generate=
d/uapi -I
> > > >> > > > > > > ./include/uapi -I ./include/generated/uapi -D __KERNEL=
__ -D
> > > >> > > > > > > CONFIG_X86_X32_ABI -D CONFIG_AS_CFI=3D1 -D CONFIG_AS_C=
FI_SIGNAL_FRAME=3D1
> > > >> > > > > > > -D CONFIG_AS_CFI_SECTIONS=3D1 -D CONFIG_AS_SSSE3=3D1 -=
D CONFIG_AS_AVX=3D1 -D
> > > >> > > > > > > CONFIG_AS_AVX2=3D1 -D CONFIG_AS_AVX512=3D1 -D CONFIG_A=
S_SHA1_NI=3D1 -D
> > > >> > > > > > > CONFIG_AS_SHA256_NI=3D1 -D KBUILD_BASENAME=3D"process_=
64" -D
> > > >> > > > > > > KBUILD_MODNAME=3D"process_64" -O2 -Wall -Wundef
> > > >> > > > > > > -Werror=3Dstrict-prototypes -Wno-trigraphs
> > > >> > > > > > > -Werror=3Dimplicit-function-declaration -Werror=3Dimpl=
icit-int
> > > >> > > > > > > -Wno-format-security -Wno-sign-compare -Wno-address-of=
-packed-member
> > > >> > > > > > > -Wno-format-invalid-specifier -Wno-gnu -Wno-tautologic=
al-compare
> > > >> > > > > > > -Wno-unused-const-variable -Wdeclaration-after-stateme=
nt -Wvla
> > > >> > > > > > > -Wno-pointer-sign -Werror=3Ddate-time -Werror=3Dincomp=
atible-pointer-types
> > > >> > > > > > > -Wno-initializer-overrides -Wno-unused-value -Wno-form=
at
> > > >> > > > > > > -Wno-sign-compare -Wno-format-zero-length -Wno-uniniti=
alized
> > > >> > > > > > > -std=3Dgnu89 -fno-dwarf-directory-asm -fdebug-compilat=
ion-dir
> > > >> > > > > > > /home/kmsan -ferror-limit 19 -fmessage-length 0
> > > >> > > > > > > -fsanitize=3Dkernel-memory -fwrapv -stack-protector 2
> > > >> > > > > > > -mstack-alignment=3D8 -fwchar-type=3Dshort -fno-signed=
-wchar
> > > >> > > > > > > -fobjc-runtime=3Dgcc -fno-common -fdiagnostics-show-op=
tion
> > > >> > > > > > > -fcolor-diagnostics -vectorize-loops -vectorize-slp -o
> > > >> > > > > > > /tmp/process_64-e20ead.s -x c arch/x86/kernel/process_=
64.c
> > > >> > > > > > > 1.      <eof> parser at end of file
> > > >> > > > > > > 2.      Per-module optimization passes
> > > >> > > > > > > 3.      Running pass 'Function Pass Manager' on module
> > > >> > > > > > > 'arch/x86/kernel/process_64.c'.
> > > >> > > > > > > 4.      Running pass 'MemorySanitizerLegacyPass' on fu=
nction '@start_thread'
> > > >> > > > > > >  #0 0x00000000024f03ba llvm::sys::PrintStackTrace(llvm=
::raw_ostream&)
> > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x24f03ba)
> > > >> > > > > > >  #1 0x00000000024ee214 llvm::sys::RunSignalHandlers()
> > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x24ee214)
> > > >> > > > > > >  #2 0x00000000024ee375 SignalHandler(int)
> > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x24ee375)
> > > >> > > > > > >  #3 0x00007f85ed99bd80 __restore_rt (/lib64/libpthread=
.so.0+0x12d80)
> > > >> > > > > > >  #4 0x00007f85ec47c93f raise (/lib64/libc.so.6+0x3793f=
)
> > > >> > > > > > >  #5 0x00007f85ec466c95 abort (/lib64/libc.so.6+0x21c95=
)
> > > >> > > > > > >  #6 0x00007f85ec466b69 _nl_load_domain.cold.0 (/lib64/=
libc.so.6+0x21b69)
> > > >> > > > > > >  #7 0x00007f85ec474df6 (/lib64/libc.so.6+0x2fdf6)
> > > >> > > > > > >  #8 0x000000000327b864 (anonymous
> > > >> > > > > > > namespace)::MemorySanitizerVisitor::visitCallSite(llvm=
::CallSite)
> > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x327b864)
> > > >> > > > > > >  #9 0x0000000003283036 (anonymous
> > > >> > > > > > > namespace)::MemorySanitizerVisitor::runOnFunction()
> > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x3283036)
> > > >> > > > > > > #10 0x000000000328605f (anonymous
> > > >> > > > > > > namespace)::MemorySanitizer::sanitizeFunction(llvm::Fu=
nction&,
> > > >> > > > > > > llvm::TargetLibraryInfo&)
> > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x328605f)
> > > >> > > > > > > #11 0x0000000001f42ac8
> > > >> > > > > > > llvm::FPPassManager::runOnFunction(llvm::Function&)
> > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x1f42ac8)
> > > >> > > > > > > #12 0x0000000001f42be9 llvm::FPPassManager::runOnModul=
e(llvm::Module&)
> > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x1f42be9)
> > > >> > > > > > > #13 0x0000000001f41ed8
> > > >> > > > > > > llvm::legacy::PassManagerImpl::run(llvm::Module&)
> > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x1f41ed8)
> > > >> > > > > > > #14 0x00000000026fa4f8 (anonymous
> > > >> > > > > > > namespace)::EmitAssemblyHelper::EmitAssembly(clang::Ba=
ckendAction,
> > > >> > > > > > > std::unique_ptr<llvm::raw_pwrite_stream,
> > > >> > > > > > > std::default_delete<llvm::raw_pwrite_stream> >)
> > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x26fa4f8)
> > > >> > > > > > > #15 0x00000000026fbbf8
> > > >> > > > > > > clang::EmitBackendOutput(clang::DiagnosticsEngine&,
> > > >> > > > > > > clang::HeaderSearchOptions const&, clang::CodeGenOptio=
ns const&,
> > > >> > > > > > > clang::TargetOptions const&, clang::LangOptions const&=
,
> > > >> > > > > > > llvm::DataLayout const&, llvm::Module*, clang::Backend=
Action,
> > > >> > > > > > > std::unique_ptr<llvm::raw_pwrite_stream,
> > > >> > > > > > > std::default_delete<llvm::raw_pwrite_stream> >)
> > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x26fbbf8)
> > > >> > > > > > > #16 0x000000000310234d
> > > >> > > > > > > clang::BackendConsumer::HandleTranslationUnit(clang::A=
STContext&)
> > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x310234d)
> > > >> > > > > > > #17 0x0000000003aaddf9 clang::ParseAST(clang::Sema&, b=
ool, bool)
> > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x3aaddf9)
> > > >> > > > > > > #18 0x00000000030fe5e0 clang::CodeGenAction::ExecuteAc=
tion()
> > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x30fe5e0)
> > > >> > > > > > > #19 0x0000000002ba1929 clang::FrontendAction::Execute(=
)
> > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x2ba1929)
> > > >> > > > > > > #20 0x0000000002b68e62
> > > >> > > > > > > clang::CompilerInstance::ExecuteAction(clang::Frontend=
Action&)
> > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x2b68e62)
> > > >> > > > > > > #21 0x0000000002c5738a
> > > >> > > > > > > clang::ExecuteCompilerInvocation(clang::CompilerInstan=
ce*)
> > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x2c5738a)
> > > >> > > > > > > #22 0x00000000009cd1a6 cc1_main(llvm::ArrayRef<char co=
nst*>, char
> > > >> > > > > > > const*, void*) (/home/tools/llvm-project/build/bin/cla=
ng-9+0x9cd1a6)
> > > >> > > > > > > #23 0x000000000094cac1 main
> > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x94cac1)
> > > >> > > > > > > #24 0x00007f85ec468813 __libc_start_main (/lib64/libc.=
so.6+0x23813)
> > > >> > > > > > > #25 0x00000000009c96ee _start
> > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x9c96ee)
> > > >> > > > > > > clang-9: error: unable to execute command: Aborted (co=
re dumped)
> > > >> > > > > > > clang-9: error: clang frontend command failed due to s=
ignal (use -v to
> > > >> > > > > > > see invocation)
> > > >> > > > > > > clang version 9.0.0 (https://github.com/llvm/llvm-proj=
ect.git
> > > >> > > > > > > a056684c335995214f6d3467c699d32f8e73b763)
> > > >> > > > > > > Target: x86_64-unknown-linux-gnu
> > > >> > > > > > > Thread model: posix
> > > >> > > > > > > InstalledDir: /home/tools/llvm-project/build/bin
> > > >> > > > > > > clang-9: note: diagnostic msg: PLEASE submit a bug rep=
ort to
> > > >> > > > > > > https://bugs.llvm.org/ and include the crash backtrace=
, preprocessed
> > > >> > > > > > > source, and associated run script.
> > > >> > > > > > > clang-9: note: diagnostic msg:
> > > >> > > > > > > ********************
> > > >> > > > > > >
> > > >> > > > > > > PLEASE ATTACH THE FOLLOWING FILES TO THE BUG REPORT:
> > > >> > > > > > > Preprocessed source(s) and associated run script(s) ar=
e located at:
> > > >> > > > > > > clang-9: note: diagnostic msg: /tmp/process_64-5fbbdc.=
c
> > > >> > > > > > > clang-9: note: diagnostic msg: /tmp/process_64-5fbbdc.=
sh
> > > >> > > > > > > clang-9: note: diagnostic msg:
> > > >> > > > > > >
> > > >> > > > > > > ********************
> > > >> > > > > > > make[2]: *** [scripts/Makefile.build:276:
> > > >> > > > > > > arch/x86/kernel/process_64.o] Error 254
> > > >> > > > > > >
> > > >> > > > > > >
> > > >> > > > > > > any idea why?
> > > >> > > > > > >
> > > >> > > > > > > On Thu, Jun 27, 2019 at 5:23 PM Alexander Potapenko <g=
lider@google.com> wrote:
> > > >> > > > > > > >
> > > >> > > > > > > > Actually, your config says:
> > > >> > > > > > > >   "Compiler: clang version 8.0.0 (trunk 343298)"
> > > >> > > > > > > > I think you'll need at least Clang r362410 (mine is =
r362913)
> > > >> > > > > > > >
> > > >> > > > > > > > On Thu, Jun 27, 2019 at 11:20 AM Alexander Potapenko=
 <glider@google.com> wrote:
> > > >> > > > > > > > >
> > > >> > > > > > > > > Hi Xin,
> > > >> > > > > > > > >
> > > >> > > > > > > > > Sorry for the late reply.
> > > >> > > > > > > > > I've built the ToT KMSAN tree using your config an=
d my almost-ToT
> > > >> > > > > > > > > Clang and couldn't reproduce the problem.
> > > >> > > > > > > > > I believe something is wrong with your Clang versi=
on, as
> > > >> > > > > > > > > CONFIG_CLANG_VERSION should really be 90000.
> > > >> > > > > > > > > You can run `make V=3D1` to see which Clang versio=
n is being invoked -
> > > >> > > > > > > > > make sure it's a fresh one.
> > > >> > > > > > > > >
> > > >> > > > > > > > > HTH,
> > > >> > > > > > > > > Alex
> > > >> > > > > > > > >
> > > >> > > > > > > > > On Fri, Jun 21, 2019 at 10:09 PM Xin Long <lucien.=
xin@gmail.com> wrote:
> > > >> > > > > > > > > >
> > > >> > > > > > > > > > as attached,
> > > >> > > > > > > > > >
> > > >> > > > > > > > > > It actually came from https://syzkaller.appspot.=
com/x/.config?x=3D602468164ccdc30a
> > > >> > > > > > > > > > after I built, clang version changed to:
> > > >> > > > > > > > > >
> > > >> > > > > > > > > > CONFIG_CLANG_VERSION=3D80000
> > > >> > > > > > > > > >
> > > >> > > > > > > > > > On Sat, Jun 22, 2019 at 2:06 AM Alexander Potape=
nko <glider@google.com> wrote:
> > > >> > > > > > > > > > >
> > > >> > > > > > > > > > > Hi Xin,
> > > >> > > > > > > > > > >
> > > >> > > > > > > > > > > Could you please share the config you're using=
 to build the kernel?
> > > >> > > > > > > > > > > I'll take a closer look on Monday when I am ba=
ck to the office.
> > > >> > > > > > > > > > >
> > > >> > > > > > > > > > > On Fri, 21 Jun 2019, 18:15 Xin Long, <lucien.x=
in@gmail.com> wrote:
> > > >> > > > > > > > > > >>
> > > >> > > > > > > > > > >> this is my command:
> > > >> > > > > > > > > > >>
> > > >> > > > > > > > > > >> /usr/libexec/qemu-kvm -smp 2 -m 4G -enable-kv=
m -cpu host \
> > > >> > > > > > > > > > >>     -net nic -net user,hostfwd=3Dtcp::10022-:=
22 \
> > > >> > > > > > > > > > >>     -kernel /home/kmsan/arch/x86/boot/bzImage=
 -nographic \
> > > >> > > > > > > > > > >>     -device virtio-scsi-pci,id=3Dscsi \
> > > >> > > > > > > > > > >>     -device scsi-hd,bus=3Dscsi.0,drive=3Dd0 \
> > > >> > > > > > > > > > >>     -drive file=3D/root/test/wheezy.img,forma=
t=3Draw,if=3Dnone,id=3Dd0 \
> > > >> > > > > > > > > > >>     -append "root=3D/dev/sda console=3DttyS0 =
earlyprintk=3Dserial rodata=3Dn \
> > > >> > > > > > > > > > >>       oops=3Dpanic panic_on_warn=3D1 panic=3D=
86400 kvm-intel.nested=3D1 \
> > > >> > > > > > > > > > >>       security=3Dapparmor ima_policy=3Dtcb wo=
rkqueue.watchdog_thresh=3D140 \
> > > >> > > > > > > > > > >>       nf-conntrack-ftp.ports=3D20000 nf-connt=
rack-tftp.ports=3D20000 \
> > > >> > > > > > > > > > >>       nf-conntrack-sip.ports=3D20000 nf-connt=
rack-irc.ports=3D20000 \
> > > >> > > > > > > > > > >>       nf-conntrack-sane.ports=3D20000 vivid.n=
_devs=3D16 \
> > > >> > > > > > > > > > >>       vivid.multiplanar=3D1,2,1,2,1,2,1,2,1,2=
,1,2,1,2,1,2 \
> > > >> > > > > > > > > > >>       spec_store_bypass_disable=3Dprctl nopci=
d"
> > > >> > > > > > > > > > >>
> > > >> > > > > > > > > > >> the commit is on:
> > > >> > > > > > > > > > >> commit f75e4cfea97f67b7530b8b991b3005f991f047=
78 (HEAD)
> > > >> > > > > > > > > > >> Author: Alexander Potapenko <glider@google.co=
m>
> > > >> > > > > > > > > > >> Date:   Wed May 22 12:30:13 2019 +0200
> > > >> > > > > > > > > > >>
> > > >> > > > > > > > > > >>     kmsan: use kmsan_handle_urb() in urb.c
> > > >> > > > > > > > > > >>
> > > >> > > > > > > > > > >> and when starting, it shows:
> > > >> > > > > > > > > > >> [    0.561925][    T0] Kernel command line: r=
oot=3D/dev/sda
> > > >> > > > > > > > > > >> console=3DttyS0 earlyprintk=3Dserial rodata=
=3Dn       oops=3Dpanic
> > > >> > > > > > > > > > >> panic_on_warn=3D1 panic=3D86400 kvm-intel.nes=
ted=3D1       security=3Dad
> > > >> > > > > > > > > > >> [    0.707792][    T0] Memory: 3087328K/41937=
76K available (219164K
> > > >> > > > > > > > > > >> kernel code, 7059K rwdata, 11712K rodata, 506=
4K init, 11904K bss,
> > > >> > > > > > > > > > >> 1106448K reserved, 0K cma-reserved)
> > > >> > > > > > > > > > >> [    0.710935][    T0] SLUB: HWalign=3D64, Or=
der=3D0-3, MinObjects=3D0,
> > > >> > > > > > > > > > >> CPUs=3D2, Nodes=3D1
> > > >> > > > > > > > > > >> [    0.711953][    T0] Starting KernelMemoryS=
anitizer
> > > >> > > > > > > > > > >> [    0.712563][    T0]
> > > >> > > > > > > > > > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D
> > > >> > > > > > > > > > >> [    0.713657][    T0] BUG: KMSAN: uninit-val=
ue in mutex_lock+0xd1/0xe0
> > > >> > > > > > > > > > >> [    0.714570][    T0] CPU: 0 PID: 0 Comm: sw=
apper Not tainted 5.1.0 #5
> > > >> > > > > > > > > > >> [    0.715417][    T0] Hardware name: Red Hat=
 KVM, BIOS
> > > >> > > > > > > > > > >> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01/2=
014
> > > >> > > > > > > > > > >> [    0.716659][    T0] Call Trace:
> > > >> > > > > > > > > > >> [    0.717127][    T0]  dump_stack+0x134/0x19=
0
> > > >> > > > > > > > > > >> [    0.717727][    T0]  kmsan_report+0x131/0x=
2a0
> > > >> > > > > > > > > > >> [    0.718347][    T0]  __msan_warning+0x7a/0=
xf0
> > > >> > > > > > > > > > >> [    0.718952][    T0]  mutex_lock+0xd1/0xe0
> > > >> > > > > > > > > > >> [    0.719478][    T0]  __cpuhp_setup_state_c=
puslocked+0x149/0xd20
> > > >> > > > > > > > > > >> [    0.720260][    T0]  ? vprintk_func+0x6b5/=
0x8a0
> > > >> > > > > > > > > > >> [    0.720926][    T0]  ? rb_get_reader_page+=
0x1140/0x1140
> > > >> > > > > > > > > > >> [    0.721632][    T0]  __cpuhp_setup_state+0=
x181/0x2e0
> > > >> > > > > > > > > > >> [    0.722374][    T0]  ? rb_get_reader_page+=
0x1140/0x1140
> > > >> > > > > > > > > > >> [    0.723115][    T0]  tracer_alloc_buffers+=
0x16b/0xb96
> > > >> > > > > > > > > > >> [    0.723846][    T0]  early_trace_init+0x19=
3/0x28f
> > > >> > > > > > > > > > >> [    0.724501][    T0]  start_kernel+0x497/0x=
b38
> > > >> > > > > > > > > > >> [    0.725134][    T0]  x86_64_start_reservat=
ions+0x19/0x2f
> > > >> > > > > > > > > > >> [    0.725871][    T0]  x86_64_start_kernel+0=
x84/0x87
> > > >> > > > > > > > > > >> [    0.726538][    T0]  secondary_startup_64+=
0xa4/0xb0
> > > >> > > > > > > > > > >> [    0.727173][    T0]
> > > >> > > > > > > > > > >> [    0.727454][    T0] Local variable descrip=
tion:
> > > >> > > > > > > > > > >> ----success.i.i.i.i@mutex_lock
> > > >> > > > > > > > > > >> [    0.728379][    T0] Variable was created a=
t:
> > > >> > > > > > > > > > >> [    0.728977][    T0]  mutex_lock+0x48/0xe0
> > > >> > > > > > > > > > >> [    0.729536][    T0]  __cpuhp_setup_state_c=
puslocked+0x149/0xd20
> > > >> > > > > > > > > > >> [    0.730323][    T0]
> > > >> > > > > > > > > > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D
> > > >> > > > > > > > > > >> [    0.731364][    T0] Disabling lock debuggi=
ng due to kernel taint
> > > >> > > > > > > > > > >> [    0.732169][    T0] Kernel panic - not syn=
cing: panic_on_warn set ...
> > > >> > > > > > > > > > >> [    0.733047][    T0] CPU: 0 PID: 0 Comm: sw=
apper Tainted: G    B
> > > >> > > > > > > > > > >>         5.1.0 #5
> > > >> > > > > > > > > > >> [    0.734080][    T0] Hardware name: Red Hat=
 KVM, BIOS
> > > >> > > > > > > > > > >> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01/2=
014
> > > >> > > > > > > > > > >> [    0.735319][    T0] Call Trace:
> > > >> > > > > > > > > > >> [    0.735735][    T0]  dump_stack+0x134/0x19=
0
> > > >> > > > > > > > > > >> [    0.736308][    T0]  panic+0x3ec/0xb3b
> > > >> > > > > > > > > > >> [    0.736826][    T0]  kmsan_report+0x29a/0x=
2a0
> > > >> > > > > > > > > > >> [    0.737417][    T0]  __msan_warning+0x7a/0=
xf0
> > > >> > > > > > > > > > >> [    0.737973][    T0]  mutex_lock+0xd1/0xe0
> > > >> > > > > > > > > > >> [    0.738527][    T0]  __cpuhp_setup_state_c=
puslocked+0x149/0xd20
> > > >> > > > > > > > > > >> [    0.739342][    T0]  ? vprintk_func+0x6b5/=
0x8a0
> > > >> > > > > > > > > > >> [    0.739972][    T0]  ? rb_get_reader_page+=
0x1140/0x1140
> > > >> > > > > > > > > > >> [    0.740695][    T0]  __cpuhp_setup_state+0=
x181/0x2e0
> > > >> > > > > > > > > > >> [    0.741412][    T0]  ? rb_get_reader_page+=
0x1140/0x1140
> > > >> > > > > > > > > > >> [    0.742160][    T0]  tracer_alloc_buffers+=
0x16b/0xb96
> > > >> > > > > > > > > > >> [    0.742866][    T0]  early_trace_init+0x19=
3/0x28f
> > > >> > > > > > > > > > >> [    0.743512][    T0]  start_kernel+0x497/0x=
b38
> > > >> > > > > > > > > > >> [    0.744128][    T0]  x86_64_start_reservat=
ions+0x19/0x2f
> > > >> > > > > > > > > > >> [    0.744863][    T0]  x86_64_start_kernel+0=
x84/0x87
> > > >> > > > > > > > > > >> [    0.745534][    T0]  secondary_startup_64+=
0xa4/0xb0
> > > >> > > > > > > > > > >> [    0.746290][    T0] Rebooting in 86400 sec=
onds..
> > > >> > > > > > > > > > >>
> > > >> > > > > > > > > > >> when I set "panic_on_warn=3D0", it foods the =
console with:
> > > >> > > > > > > > > > >> ...
> > > >> > > > > > > > > > >> [   25.206759][    C0] Variable was created a=
t:
> > > >> > > > > > > > > > >> [   25.207302][    C0]  vprintk_emit+0xf4/0x8=
00
> > > >> > > > > > > > > > >> [   25.207844][    C0]  vprintk_deferred+0x90=
/0xed
> > > >> > > > > > > > > > >> [   25.208404][    C0]
> > > >> > > > > > > > > > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D
> > > >> > > > > > > > > > >> [   25.209763][    C0]  x86_64_start_reservat=
ions+0x19/0x2f
> > > >> > > > > > > > > > >> [   25.209769][    C0]
> > > >> > > > > > > > > > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D
> > > >> > > > > > > > > > >> [   25.211408][    C0] BUG: KMSAN: uninit-val=
ue in vprintk_emit+0x443/0x800
> > > >> > > > > > > > > > >> [   25.212237][    C0] CPU: 0 PID: 0 Comm: sw=
apper/0 Tainted: G    B
> > > >> > > > > > > > > > >>           5.1.0 #5
> > > >> > > > > > > > > > >> [   25.213206][    C0] Hardware name: Red Hat=
 KVM, BIOS
> > > >> > > > > > > > > > >> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01/2=
014
> > > >> > > > > > > > > > >> [   25.214326][    C0] Call Trace:
> > > >> > > > > > > > > > >> [   25.214725][    C0]  <IRQ>
> > > >> > > > > > > > > > >> [   25.215080][    C0]  dump_stack+0x134/0x19=
0
> > > >> > > > > > > > > > >> [   25.215624][    C0]  kmsan_report+0x131/0x=
2a0
> > > >> > > > > > > > > > >> [   25.216204][    C0]  __msan_warning+0x7a/0=
xf0
> > > >> > > > > > > > > > >> [   25.216771][    C0]  vprintk_emit+0x443/0x=
800
> > > >> > > > > > > > > > >> [   25.217334][    C0]  ? __msan_metadata_ptr=
_for_store_1+0x13/0x20
> > > >> > > > > > > > > > >> [   25.218127][    C0]  vprintk_deferred+0x90=
/0xed
> > > >> > > > > > > > > > >> [   25.218714][    C0]  printk_deferred+0x186=
/0x1d3
> > > >> > > > > > > > > > >> [   25.219353][    C0]  __printk_safe_flush+0=
x72e/0xc00
> > > >> > > > > > > > > > >> [   25.220006][    C0]  ? printk_safe_flush+0=
x1e0/0x1e0
> > > >> > > > > > > > > > >> [   25.220635][    C0]  irq_work_run+0x1ad/0x=
5c0
> > > >> > > > > > > > > > >> [   25.221210][    C0]  ? flat_init_apic_ldr+=
0x170/0x170
> > > >> > > > > > > > > > >> [   25.221851][    C0]  smp_irq_work_interrup=
t+0x237/0x3e0
> > > >> > > > > > > > > > >> [   25.222520][    C0]  irq_work_interrupt+0x=
2e/0x40
> > > >> > > > > > > > > > >> [   25.223110][    C0]  </IRQ>
> > > >> > > > > > > > > > >> [   25.223475][    C0] RIP: 0010:kmem_cache_i=
nit_late+0x0/0xb
> > > >> > > > > > > > > > >> [   25.224164][    C0] Code: d4 e8 5d dd 2e f=
2 e9 74 fe ff ff 48 89 d3
> > > >> > > > > > > > > > >> 8b 7d d4 e8 cd d7 2e f2 89 c0 48 89 c1 48 c1 =
e1 20 48 09 c1 48 89 0b
> > > >> > > > > > > > > > >> e9 81 fe ff ff <55> 48 89 e5 e8 20 de 2e1
> > > >> > > > > > > > > > >> [   25.226526][    C0] RSP: 0000:ffffffff8f40=
feb8 EFLAGS: 00000246
> > > >> > > > > > > > > > >> ORIG_RAX: ffffffffffffff09
> > > >> > > > > > > > > > >> [   25.227548][    C0] RAX: ffff88813f995785 =
RBX: 0000000000000000
> > > >> > > > > > > > > > >> RCX: 0000000000000000
> > > >> > > > > > > > > > >> [   25.228511][    C0] RDX: ffff88813f2b0784 =
RSI: 0000160000000000
> > > >> > > > > > > > > > >> RDI: 0000000000000785
> > > >> > > > > > > > > > >> [   25.229473][    C0] RBP: ffffffff8f40ff20 =
R08: 000000000fac3785
> > > >> > > > > > > > > > >> R09: 0000778000000001
> > > >> > > > > > > > > > >> [   25.230440][    C0] R10: ffffd0ffffffffff =
R11: 0000100000000000
> > > >> > > > > > > > > > >> R12: 0000000000000000
> > > >> > > > > > > > > > >> [   25.231403][    C0] R13: 0000000000000000 =
R14: ffffffff8fb8cfd0
> > > >> > > > > > > > > > >> R15: 0000000000000000
> > > >> > > > > > > > > > >> [   25.232407][    C0]  ? start_kernel+0x5d8/=
0xb38
> > > >> > > > > > > > > > >> [   25.233003][    C0]  x86_64_start_reservat=
ions+0x19/0x2f
> > > >> > > > > > > > > > >> [   25.233670][    C0]  x86_64_start_kernel+0=
x84/0x87
> > > >> > > > > > > > > > >> [   25.234314][    C0]  secondary_startup_64+=
0xa4/0xb0
> > > >> > > > > > > > > > >> [   25.234949][    C0]
> > > >> > > > > > > > > > >> [   25.235231][    C0] Local variable descrip=
tion: ----flags.i.i.i@vprintk_emit
> > > >> > > > > > > > > > >> [   25.236101][    C0] Variable was created a=
t:
> > > >> > > > > > > > > > >> [   25.236643][    C0]  vprintk_emit+0xf4/0x8=
00
> > > >> > > > > > > > > > >> [   25.237188][    C0]  vprintk_deferred+0x90=
/0xed
> > > >> > > > > > > > > > >> [   25.237752][    C0]
> > > >> > > > > > > > > > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D
> > > >> > > > > > > > > > >> [   25.239117][    C0]  x86_64_start_kernel+0=
x84/0x87
> > > >> > > > > > > > > > >> [   25.239123][    C0]
> > > >> > > > > > > > > > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D
> > > >> > > > > > > > > > >> [   25.240704][    C0] BUG: KMSAN: uninit-val=
ue in vprintk_emit+0x443/0x800
> > > >> > > > > > > > > > >> [   25.241540][    C0] CPU: 0 PID: 0 Comm: sw=
apper/0 Tainted: G    B
> > > >> > > > > > > > > > >>           5.1.0 #5
> > > >> > > > > > > > > > >> [   25.242512][    C0] Hardware name: Red Hat=
 KVM, BIOS
> > > >> > > > > > > > > > >> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01/2=
014
> > > >> > > > > > > > > > >> [   25.243635][    C0] Call Trace:
> > > >> > > > > > > > > > >> [   25.244038][    C0]  <IRQ>
> > > >> > > > > > > > > > >> [   25.244390][    C0]  dump_stack+0x134/0x19=
0
> > > >> > > > > > > > > > >> [   25.244940][    C0]  kmsan_report+0x131/0x=
2a0
> > > >> > > > > > > > > > >> [   25.245515][    C0]  __msan_warning+0x7a/0=
xf0
> > > >> > > > > > > > > > >> [   25.246082][    C0]  vprintk_emit+0x443/0x=
800
> > > >> > > > > > > > > > >> [   25.246638][    C0]  ? __msan_metadata_ptr=
_for_store_1+0x13/0x20
> > > >> > > > > > > > > > >> [   25.247430][    C0]  vprintk_deferred+0x90=
/0xed
> > > >> > > > > > > > > > >> [   25.248018][    C0]  printk_deferred+0x186=
/0x1d3
> > > >> > > > > > > > > > >> [   25.248650][    C0]  __printk_safe_flush+0=
x72e/0xc00
> > > >> > > > > > > > > > >> [   25.249320][    C0]  ? printk_safe_flush+0=
x1e0/0x1e0
> > > >> > > > > > > > > > >> [   25.249949][    C0]  irq_work_run+0x1ad/0x=
5c0
> > > >> > > > > > > > > > >> [   25.250524][    C0]  ? flat_init_apic_ldr+=
0x170/0x170
> > > >> > > > > > > > > > >> [   25.251167][    C0]  smp_irq_work_interrup=
t+0x237/0x3e0
> > > >> > > > > > > > > > >> [   25.251837][    C0]  irq_work_interrupt+0x=
2e/0x40
> > > >> > > > > > > > > > >> [   25.252424][    C0]  </IRQ>
> > > >> > > > > > > > > > >> ....
> > > >> > > > > > > > > > >>
> > > >> > > > > > > > > > >>
> > > >> > > > > > > > > > >> I couldn't even log in.
> > > >> > > > > > > > > > >>
> > > >> > > > > > > > > > >> how should I use qemu with wheezy.img to star=
t a kmsan kernel?
> > > >> > > > > > > > > > >>
> > > >> > > > > > > > > > >> Thanks.
> > > >> > > > > > > > >
> > > >> > > > > > > > >
> > > >> > > > > > > > >
> > > >> > > > > > > > > --
> > > >> > > > > > > > > Alexander Potapenko
> > > >> > > > > > > > > Software Engineer
> > > >> > > > > > > > >
> > > >> > > > > > > > > Google Germany GmbH
> > > >> > > > > > > > > Erika-Mann-Stra=C3=9Fe, 33
> > > >> > > > > > > > > 80636 M=C3=BCnchen
> > > >> > > > > > > > >
> > > >> > > > > > > > > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah D=
eLaine Prado
> > > >> > > > > > > > > Registergericht und -nummer: Hamburg, HRB 86891
> > > >> > > > > > > > > Sitz der Gesellschaft: Hamburg
> > > >> > > > > > > >
> > > >> > > > > > > >
> > > >> > > > > > > >
> > > >> > > > > > > > --
> > > >> > > > > > > > Alexander Potapenko
> > > >> > > > > > > > Software Engineer
> > > >> > > > > > > >
> > > >> > > > > > > > Google Germany GmbH
> > > >> > > > > > > > Erika-Mann-Stra=C3=9Fe, 33
> > > >> > > > > > > > 80636 M=C3=BCnchen
> > > >> > > > > > > >
> > > >> > > > > > > > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeL=
aine Prado
> > > >> > > > > > > > Registergericht und -nummer: Hamburg, HRB 86891
> > > >> > > > > > > > Sitz der Gesellschaft: Hamburg
> > > >> > > > > >
> > > >> > > > > >
> > > >> > > > > >
> > > >> > > > > > --
> > > >> > > > > > Alexander Potapenko
> > > >> > > > > > Software Engineer
> > > >> > > > > >
> > > >> > > > > > Google Germany GmbH
> > > >> > > > > > Erika-Mann-Stra=C3=9Fe, 33
> > > >> > > > > > 80636 M=C3=BCnchen
> > > >> > > > > >
> > > >> > > > > > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine=
 Prado
> > > >> > > > > > Registergericht und -nummer: Hamburg, HRB 86891
> > > >> > > > > > Sitz der Gesellschaft: Hamburg
> > > >> > > >
> > > >> > > >
> > > >> > > >
> > > >> > > > --
> > > >> > > > Alexander Potapenko
> > > >> > > > Software Engineer
> > > >> > > >
> > > >> > > > Google Germany GmbH
> > > >> > > > Erika-Mann-Stra=C3=9Fe, 33
> > > >> > > > 80636 M=C3=BCnchen
> > > >> > > >
> > > >> > > > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Pra=
do
> > > >> > > > Registergericht und -nummer: Hamburg, HRB 86891
> > > >> > > > Sitz der Gesellschaft: Hamburg
> > > >> >
> > > >> >
> > > >> >
> > > >> > --
> > > >> > Alexander Potapenko
> > > >> > Software Engineer
> > > >> >
> > > >> > Google Germany GmbH
> > > >> > Erika-Mann-Stra=C3=9Fe, 33
> > > >> > 80636 M=C3=BCnchen
> > > >> >
> > > >> > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
> > > >> > Registergericht und -nummer: Hamburg, HRB 86891
> > > >> > Sitz der Gesellschaft: Hamburg
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
kasan-dev/CADvbK_d8HnKu%2BoSGha4w2wWRmQW8w%2BmqxJDnqDqezZEvVd-_7A%40mail.gm=
ail.com.
For more options, visit https://groups.google.com/d/optout.
