Return-Path: <kasan-dev+bncBCCMH5WKTMGRB65Z5XUAKGQE44UOL3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id D39585D0B5
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jul 2019 15:32:43 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id v125sf228533wmf.4
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jul 2019 06:32:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1562074363; cv=pass;
        d=google.com; s=arc-20160816;
        b=1B7YyNa8LfP7V8f6yczhwy40WJQnMFZQjwqnf7jGSN2KfWcakr/wLrCgEmkrOoBwGv
         hQ9IOuhlLEWFVQufCOg2OwOayISOoYqiNPa6E1mR6cRXwqUTdnjVvsFmgvrkf/rY+3BV
         vWKAWYjmzDoPEZ0LOMUL4UO2uL3mWmSvTVuBKy9mmUvlbydUOYW5IpRLqoacE6EYslTa
         CA50EAiGYWmKcToHKqoG4OImJu3QS5nA5V4Y/k6/q2oIdrRN3585miKA8TvpSf26ywgn
         2Yp5x/Gx17Uy30DMt83D4rEU6bROqKJjoFemAHEA4ToJBF3YOcYELGOnFZgt40cZT31T
         vucQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IWKCbPCZsRDz33P2PsfcFx9LAnXC45nkLSpPBiATVzQ=;
        b=mUAv84gcM9lEB1qRkO9+qIwaUzf7yyzJfVF5Zhmm42xLSycxBP+sej74tzQ3iypSd2
         ZApQatctFX1aFjFeujNQL0hpbA8wCzyRg3iLwvZrlnuja9inIE6DOv5L1QvTuID2n2Ig
         IK87OsSOjuqgHXiIBhZIxJJOZbII6Jfl4XUEMuG8IN1EQ+y1Ksw/9+GDOD94MUFHr67g
         Au+m7ECyWLEDuq13PHweWyuFwKTa5RGlVC+HVeAM5PsOEtJhWOQVCJzFcC46y8LxLn1m
         tUkKTlu4A8jM9kZoYP+uToPNPy6RsISwBnz9m4/XYPGpAajkzlwUOqfESWzVJQxUgedD
         W4gw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IhVtfT2V;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=IWKCbPCZsRDz33P2PsfcFx9LAnXC45nkLSpPBiATVzQ=;
        b=pYSobw+/2GmiASU+y+YjT5Q4178Qo/aAl6u6d2QicbXzNO2PgCVebRDBl+R4qOIHIR
         6mG8F+/VpRl6JGAhwHwU4kqsqwRiEj7hqnbS26LllEoqGL+/ufUTzWNrgq80oky+IFRF
         o8IOxq0UN1Dl4lCVqF8wI0oPgkbjTcnQro68+IBHGZO6FxwB53268Qwqy19Nu95XZaNh
         MaNTAzNRZb9XJw9OetQreJKb1zP4cq3Ww3yvD+VSE4kyXNa1rtgtqgesdxTUW0498BPi
         aRncv6bT2iNt+6tJMrAj+RroNcYWupWK/zBrMo4c+dFFZ9VDyxvZaX4Vz82GTuMD8EY2
         PTeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=IWKCbPCZsRDz33P2PsfcFx9LAnXC45nkLSpPBiATVzQ=;
        b=fRKswcACr77/ynIHJ9vyXgzeWL07jIbFXePB3ZHoUGNeIL90XpLWZjLxPgBHviMTex
         AvPFqtJQ+fu7XJujt2Ze8UwEycP1u2TofhVSQvQylZNoLWyHiCTXHQv/IK3eCb0rT4sX
         k7cn+QxRY27W6uWUgCUH2KfHB+78QEoI9O4uaSaYsHrrYGO6ye7paU1SFA3HIFZJX+Kf
         er6CuYT9ig2GqbBAc/GqHpmEcINjhQP6xiqNRGZmafMAdpbhEYfEhpVekgtc63eTrMmW
         XrDe7JFvLz8WB+wAIdZH+0no/3t3IX/RLvEp/nqRhwmd3A1dfvMDUaWDPJeqi0SGt+2E
         +tYQ==
X-Gm-Message-State: APjAAAXfGZ4WVUWnEU65RSbA++Yf5mIZ7OwAJKja8VWP3571AVMTLMYw
	sBC3zt291goaHZu4TI6+bkw=
X-Google-Smtp-Source: APXvYqzR+XqXWApQZXrCdrhyYGFLhjJ62nA+usfr/jC1ANApf05S42W9Y+9dm78rLu022Y0coxGDfQ==
X-Received: by 2002:a1c:968c:: with SMTP id y134mr3467189wmd.75.1562074363434;
        Tue, 02 Jul 2019 06:32:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:ee92:: with SMTP id b18ls2036918wro.13.gmail; Tue, 02
 Jul 2019 06:32:42 -0700 (PDT)
X-Received: by 2002:adf:a19e:: with SMTP id u30mr18373194wru.33.1562074362935;
        Tue, 02 Jul 2019 06:32:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1562074362; cv=none;
        d=google.com; s=arc-20160816;
        b=Mahf6wkGcrs4MfMUzvLUVA/4x8F4Crs7WG1Zx0y4EfechByj6FSz8/ar4s04txrgYR
         NNVgAYVnrhJp/5Mdc/lH48KivTau+i8WDnDl0DKfS4yyAnSV1SMw35R27pHyW/X9bU3P
         VLTc1WWa3DO6mI2aoZ2mUY3GP8GHSpBAe66jKUvifXaJiA7QSv9rPzJ0AuTNXgtTIJJk
         jrprIoMR6cwBqLPiKl/isOgwXMJ/9cX8yNV1pKjGFkusdWUOZvsKkJkFdnqqZsxchuGT
         V4BsUhJBCj4WlwFs923yo0tUKN6oa47XhmAsdL8i78FAObvDYxiahNA3cCDMCrYpdKmQ
         ziOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=jb46eIIX+oUNwU4oEIxc36/eqWKUWBJHPSUb45dYZ+A=;
        b=BwtCB0UFE/zNA2+ZKVFqMBCu2wd5vlg/K6LdZsKQlaQf0JRXWrrOXx/gE7GnKBET04
         QhMganuIfww+zUWh2euOcSlErO/GIJRnQzdhGvs5kyr/lYLG64AgKyaOO6mvAdYUKqtK
         Yksnv8cmoL6a5MK77wUfcF5e11tQZLVoB/qZkMtbQObK6OG4ilPQ/somnj7hcSReBOYS
         vkmoluUYQCU9fcqriC5I7tRuWYXYV3H2yk3M0z6lwVYDhYCyEd007SQPR/xNs0jTmb+o
         KpUhKlm623l7feFH9CME+0YcJz5PFv1B18gPRK3QwZdHCiNZWTQ/JuDDQROVN+udgO5x
         SpTA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IhVtfT2V;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x342.google.com (mail-wm1-x342.google.com. [2a00:1450:4864:20::342])
        by gmr-mx.google.com with ESMTPS id z24si203153wml.0.2019.07.02.06.32.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Tue, 02 Jul 2019 06:32:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::342 as permitted sender) client-ip=2a00:1450:4864:20::342;
Received: by mail-wm1-x342.google.com with SMTP id u8so1061340wmm.1
        for <kasan-dev@googlegroups.com>; Tue, 02 Jul 2019 06:32:42 -0700 (PDT)
X-Received: by 2002:a1c:770d:: with SMTP id t13mr3429393wmi.79.1562074361959;
 Tue, 02 Jul 2019 06:32:41 -0700 (PDT)
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
 <CADvbK_d03Fhowi7DR3+PvbafhW=6BV430Gt3K8gCyF_EAxsOGg@mail.gmail.com>
 <CAG_fn=XAytdKY+QbcNY6ZiNrnKAu==OSz8SBz2f=W=K8HqAyug@mail.gmail.com> <CADvbK_d8HnKu+oSGha4w2wWRmQW8w+mqxJDnqDqezZEvVd-_7A@mail.gmail.com>
In-Reply-To: <CADvbK_d8HnKu+oSGha4w2wWRmQW8w+mqxJDnqDqezZEvVd-_7A@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Jul 2019 15:32:30 +0200
Message-ID: <CAG_fn=WS1NBRiaH_s_W9fa_qMTV3yKkmseiH6ZUK3iL7Mu3EAA@mail.gmail.com>
Subject: Re: how to start kmsan kernel with qemu
To: Xin Long <lucien.xin@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Dmitriy Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=IhVtfT2V;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::342 as
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

https://reviews.llvm.org/D64072 seems to fix the problem. I hope to
land this patch soon, in the meantime you can apply it to your Clang.
Thanks for your help tracking the bug down!

On Tue, Jul 2, 2019 at 11:39 AM Xin Long <lucien.xin@gmail.com> wrote:
>
> On Tue, Jul 2, 2019 at 5:32 PM Alexander Potapenko <glider@google.com> wr=
ote:
> >
> > Ah, I see.
> > You build with assertions enabled, I for some reason did not.
> > There's really a bug in KMSAN instrumentation, I'll fix it.
> Thanks, great that you figured it out so quickly.
> I'm waiting. :-)
>
> >
> > On Fri, Jun 28, 2019 at 7:24 PM Xin Long <lucien.xin@gmail.com> wrote:
> > >
> > > On Sat, Jun 29, 2019 at 1:18 AM Xin Long <lucien.xin@gmail.com> wrote=
:
> > > >
> > > > # cd /home/tools/
> > > > # git clone https://github.com/llvm/llvm-project.git
> > > > # cd llvm-project/
> > > > # mkdir build
> > > > # cd build/
> > > > # cmake -DLLVM_ENABLE_PROJECTS=3Dclang -DCMAKE_BUILD_TYPE=3DRelease
> > > > -DLLVM_ENABLE_ASSERTIONS=3DON -G "Unix Makefiles" ../llvm
> > > the output is:
> > > https://paste.fedoraproject.org/paste/D9-QpmZnDcXkr4AykumRnw
> > > myabe you can have a vimdiff for the outputs of yours and mine.
> > >
> > > > # make
> > > sorry, it was # make -j64
> > >
> > > > # cd /home/kmsan
> > > > # git checkout f75e4cfea97f
> > > > (use the .config I sent you last time)
> > > > # make CC=3D/home/tools/llvm-project/build/bin/clang -j64 -k LOCALV=
ERSION=3D 2>&1
> > > >
> > > > These are the whole thing I did to build it.
> > > >
> > > > On Sat, Jun 29, 2019 at 12:09 AM Alexander Potapenko <glider@google=
.com> wrote:
> > > > >
> > > > > Hm, now that's your Clang binary versus mine :)
> > > > > Can you please ensure your git repo doesn't contain local changes=
 and share the commands you're using to build Clang?
> > > > > (Both cmake and make or ninja)
> > > > No any local changes on both llvm-project and kmsan
> > > >
> > > > > Is the bug still reproducible in a clean CMake directory?
> > > > A clean CMake directory? how to clean it? something like: # cmake c=
lean
> > > >
> > > > Thank you for being so patient. :-)
> > > >
> > > > >
> > > > > On Fri, 28 Jun 2019, 16:20 Xin Long, <lucien.xin@gmail.com> wrote=
:
> > > > >>
> > > > >> yes
> > > > >>
> > > > >> https://paste.fedoraproject.org/paste/DU2nnxpZWpWMri9Up7hypA
> > > > >>
> > > > >> On Fri, Jun 28, 2019 at 9:48 PM Alexander Potapenko <glider@goog=
le.com> wrote:
> > > > >> >
> > > > >> > Hm, strange, but I still can compile this file.
> > > > >> > Does the following command line crash your compiler?
> > > > >> > https://paste.fedoraproject.org/paste/oJwOVm5cHWyd7hxIZ4uGeA (=
note it
> > > > >> > should be run from the same directory where process_64.i resid=
es; also
> > > > >> > make sure to invoke the right Clang)
> > > > >> >
> > > > >> > On Fri, Jun 28, 2019 at 3:35 PM Xin Long <lucien.xin@gmail.com=
> wrote:
> > > > >> > >
> > > > >> > > As attached, thanks.
> > > > >> > >
> > > > >> > > On Fri, Jun 28, 2019 at 9:24 PM Alexander Potapenko <glider@=
google.com> wrote:
> > > > >> > > >
> > > > >> > > > On Fri, Jun 28, 2019 at 3:10 PM Xin Long <lucien.xin@gmail=
.com> wrote:
> > > > >> > > > >
> > > > >> > > > > This is what I did:
> > > > >> > > > > https://paste.fedoraproject.org/paste/q4~GWx9Sx~QUbJQfND=
oJIw
> > > > >> > > > >
> > > > >> > > > > There's no process_64.i file generated.
> > > > >> > > > >
> > > > >> > > > > Btw, I couldn't find "-c" in the command line, so there =
was no "-E" added.
> > > > >> > > > Ah, right, Clang is invoked with -S. Could you replace tha=
t one with -E?
> > > > >> > > > > On Fri, Jun 28, 2019 at 8:40 PM Alexander Potapenko <gli=
der@google.com> wrote:
> > > > >> > > > > >
> > > > >> > > > > > It's interesting that you're seeing the same error as =
reported here:
> > > > >> > > > > > https://github.com/google/kmsan/issues/53
> > > > >> > > > > > I've updated my Clang to a4771e9dfdb0485c2edb416bfdc47=
9d49de0aa14, but
> > > > >> > > > > > the kernel compiles just fine.
> > > > >> > > > > > May I ask you to do the following:
> > > > >> > > > > >
> > > > >> > > > > >  - run `make V=3D1` to capture the command line used t=
o build
> > > > >> > > > > > arch/x86/kernel/process_64.o
> > > > >> > > > > >  - copy and paste the command line into a shell, remov=
e '-o
> > > > >> > > > > > /tmp/somefile' and run again to make sure the compiler=
 still crashes
> > > > >> > > > > >  - replace '-c' with '-E' in the command line and add =
'-o
> > > > >> > > > > > process_64.i' to the end
> > > > >> > > > > >  - send me the resulting preprocessed file (process_64=
.i)
> > > > >> > > > > >
> > > > >> > > > > > Thanks!
> > > > >> > > > > >
> > > > >> > > > > >
> > > > >> > > > > >
> > > > >> > > > > > On Thu, Jun 27, 2019 at 4:45 PM Xin Long <lucien.xin@g=
mail.com> wrote:
> > > > >> > > > > > >
> > > > >> > > > > > > Now I'm using:
> > > > >> > > > > > > # Compiler: clang version 9.0.0
> > > > >> > > > > > > (https://github.com/llvm/llvm-project.git
> > > > >> > > > > > > a056684c335995214f6d3467c699d32f8e73b763)
> > > > >> > > > > > >
> > > > >> > > > > > > Errors shows up when building the kernel:
> > > > >> > > > > > >
> > > > >> > > > > > >   CC      arch/x86/kernel/process_64.o
> > > > >> > > > > > > clang-9: /home/tools/llvm-project/llvm/lib/Transform=
s/Instrumentation/MemorySanitizer.cpp:3236:
> > > > >> > > > > > > void {anonymous}::MemorySanitizerVisitor::visitCallS=
ite(llvm::CallSite):
> > > > >> > > > > > > Assertion `(CS.isCall() || CS.isInvoke()) && "Unknow=
n type of
> > > > >> > > > > > > CallSite"' failed.
> > > > >> > > > > > > Stack dump:
> > > > >> > > > > > > 0.      Program arguments: /home/tools/llvm-project/=
build/bin/clang-9
> > > > >> > > > > > > -cc1 -triple x86_64-unknown-linux-gnu -S -disable-fr=
ee -main-file-name
> > > > >> > > > > > > process_64.c -mrelocation-model static -mthread-mode=
l posix
> > > > >> > > > > > > -fno-delete-null-pointer-checks -mllvm -warn-stack-s=
ize=3D2048
> > > > >> > > > > > > -mdisable-fp-elim -relaxed-aliasing -mdisable-tail-c=
alls -fmath-errno
> > > > >> > > > > > > -masm-verbose -no-integrated-as -mconstructor-aliase=
s -fuse-init-array
> > > > >> > > > > > > -mcode-model kernel -target-cpu core2 -target-featur=
e
> > > > >> > > > > > > +retpoline-indirect-calls -target-feature +retpoline=
-indirect-branches
> > > > >> > > > > > > -target-feature -sse -target-feature -mmx -target-fe=
ature -sse2
> > > > >> > > > > > > -target-feature -3dnow -target-feature -avx -target-=
feature -x87
> > > > >> > > > > > > -target-feature +retpoline-external-thunk -disable-r=
ed-zone
> > > > >> > > > > > > -dwarf-column-info -debug-info-kind=3Dlimited -dwarf=
-version=3D4
> > > > >> > > > > > > -debugger-tuning=3Dgdb -momit-leaf-frame-pointer -co=
verage-notes-file
> > > > >> > > > > > > /home/kmsan/arch/x86/kernel/process_64.gcno -nostdsy=
steminc
> > > > >> > > > > > > -nobuiltininc -resource-dir
> > > > >> > > > > > > /home/tools/llvm-project/build/lib/clang/9.0.0 -depe=
ndency-file
> > > > >> > > > > > > arch/x86/kernel/.process_64.o.d -MT arch/x86/kernel/=
process_64.o
> > > > >> > > > > > > -sys-header-deps -isystem
> > > > >> > > > > > > /home/tools/llvm-project/build/lib/clang/9.0.0/inclu=
de -include
> > > > >> > > > > > > ./include/linux/kconfig.h -include ./include/linux/c=
ompiler_types.h -I
> > > > >> > > > > > > ./arch/x86/include -I ./arch/x86/include/generated -=
I ./include -I
> > > > >> > > > > > > ./arch/x86/include/uapi -I ./arch/x86/include/genera=
ted/uapi -I
> > > > >> > > > > > > ./include/uapi -I ./include/generated/uapi -D __KERN=
EL__ -D
> > > > >> > > > > > > CONFIG_X86_X32_ABI -D CONFIG_AS_CFI=3D1 -D CONFIG_AS=
_CFI_SIGNAL_FRAME=3D1
> > > > >> > > > > > > -D CONFIG_AS_CFI_SECTIONS=3D1 -D CONFIG_AS_SSSE3=3D1=
 -D CONFIG_AS_AVX=3D1 -D
> > > > >> > > > > > > CONFIG_AS_AVX2=3D1 -D CONFIG_AS_AVX512=3D1 -D CONFIG=
_AS_SHA1_NI=3D1 -D
> > > > >> > > > > > > CONFIG_AS_SHA256_NI=3D1 -D KBUILD_BASENAME=3D"proces=
s_64" -D
> > > > >> > > > > > > KBUILD_MODNAME=3D"process_64" -O2 -Wall -Wundef
> > > > >> > > > > > > -Werror=3Dstrict-prototypes -Wno-trigraphs
> > > > >> > > > > > > -Werror=3Dimplicit-function-declaration -Werror=3Dim=
plicit-int
> > > > >> > > > > > > -Wno-format-security -Wno-sign-compare -Wno-address-=
of-packed-member
> > > > >> > > > > > > -Wno-format-invalid-specifier -Wno-gnu -Wno-tautolog=
ical-compare
> > > > >> > > > > > > -Wno-unused-const-variable -Wdeclaration-after-state=
ment -Wvla
> > > > >> > > > > > > -Wno-pointer-sign -Werror=3Ddate-time -Werror=3Dinco=
mpatible-pointer-types
> > > > >> > > > > > > -Wno-initializer-overrides -Wno-unused-value -Wno-fo=
rmat
> > > > >> > > > > > > -Wno-sign-compare -Wno-format-zero-length -Wno-unini=
tialized
> > > > >> > > > > > > -std=3Dgnu89 -fno-dwarf-directory-asm -fdebug-compil=
ation-dir
> > > > >> > > > > > > /home/kmsan -ferror-limit 19 -fmessage-length 0
> > > > >> > > > > > > -fsanitize=3Dkernel-memory -fwrapv -stack-protector =
2
> > > > >> > > > > > > -mstack-alignment=3D8 -fwchar-type=3Dshort -fno-sign=
ed-wchar
> > > > >> > > > > > > -fobjc-runtime=3Dgcc -fno-common -fdiagnostics-show-=
option
> > > > >> > > > > > > -fcolor-diagnostics -vectorize-loops -vectorize-slp =
-o
> > > > >> > > > > > > /tmp/process_64-e20ead.s -x c arch/x86/kernel/proces=
s_64.c
> > > > >> > > > > > > 1.      <eof> parser at end of file
> > > > >> > > > > > > 2.      Per-module optimization passes
> > > > >> > > > > > > 3.      Running pass 'Function Pass Manager' on modu=
le
> > > > >> > > > > > > 'arch/x86/kernel/process_64.c'.
> > > > >> > > > > > > 4.      Running pass 'MemorySanitizerLegacyPass' on =
function '@start_thread'
> > > > >> > > > > > >  #0 0x00000000024f03ba llvm::sys::PrintStackTrace(ll=
vm::raw_ostream&)
> > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x24f03b=
a)
> > > > >> > > > > > >  #1 0x00000000024ee214 llvm::sys::RunSignalHandlers(=
)
> > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x24ee21=
4)
> > > > >> > > > > > >  #2 0x00000000024ee375 SignalHandler(int)
> > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x24ee37=
5)
> > > > >> > > > > > >  #3 0x00007f85ed99bd80 __restore_rt (/lib64/libpthre=
ad.so.0+0x12d80)
> > > > >> > > > > > >  #4 0x00007f85ec47c93f raise (/lib64/libc.so.6+0x379=
3f)
> > > > >> > > > > > >  #5 0x00007f85ec466c95 abort (/lib64/libc.so.6+0x21c=
95)
> > > > >> > > > > > >  #6 0x00007f85ec466b69 _nl_load_domain.cold.0 (/lib6=
4/libc.so.6+0x21b69)
> > > > >> > > > > > >  #7 0x00007f85ec474df6 (/lib64/libc.so.6+0x2fdf6)
> > > > >> > > > > > >  #8 0x000000000327b864 (anonymous
> > > > >> > > > > > > namespace)::MemorySanitizerVisitor::visitCallSite(ll=
vm::CallSite)
> > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x327b86=
4)
> > > > >> > > > > > >  #9 0x0000000003283036 (anonymous
> > > > >> > > > > > > namespace)::MemorySanitizerVisitor::runOnFunction()
> > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x328303=
6)
> > > > >> > > > > > > #10 0x000000000328605f (anonymous
> > > > >> > > > > > > namespace)::MemorySanitizer::sanitizeFunction(llvm::=
Function&,
> > > > >> > > > > > > llvm::TargetLibraryInfo&)
> > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x328605=
f)
> > > > >> > > > > > > #11 0x0000000001f42ac8
> > > > >> > > > > > > llvm::FPPassManager::runOnFunction(llvm::Function&)
> > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x1f42ac=
8)
> > > > >> > > > > > > #12 0x0000000001f42be9 llvm::FPPassManager::runOnMod=
ule(llvm::Module&)
> > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x1f42be=
9)
> > > > >> > > > > > > #13 0x0000000001f41ed8
> > > > >> > > > > > > llvm::legacy::PassManagerImpl::run(llvm::Module&)
> > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x1f41ed=
8)
> > > > >> > > > > > > #14 0x00000000026fa4f8 (anonymous
> > > > >> > > > > > > namespace)::EmitAssemblyHelper::EmitAssembly(clang::=
BackendAction,
> > > > >> > > > > > > std::unique_ptr<llvm::raw_pwrite_stream,
> > > > >> > > > > > > std::default_delete<llvm::raw_pwrite_stream> >)
> > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x26fa4f=
8)
> > > > >> > > > > > > #15 0x00000000026fbbf8
> > > > >> > > > > > > clang::EmitBackendOutput(clang::DiagnosticsEngine&,
> > > > >> > > > > > > clang::HeaderSearchOptions const&, clang::CodeGenOpt=
ions const&,
> > > > >> > > > > > > clang::TargetOptions const&, clang::LangOptions cons=
t&,
> > > > >> > > > > > > llvm::DataLayout const&, llvm::Module*, clang::Backe=
ndAction,
> > > > >> > > > > > > std::unique_ptr<llvm::raw_pwrite_stream,
> > > > >> > > > > > > std::default_delete<llvm::raw_pwrite_stream> >)
> > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x26fbbf=
8)
> > > > >> > > > > > > #16 0x000000000310234d
> > > > >> > > > > > > clang::BackendConsumer::HandleTranslationUnit(clang:=
:ASTContext&)
> > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x310234=
d)
> > > > >> > > > > > > #17 0x0000000003aaddf9 clang::ParseAST(clang::Sema&,=
 bool, bool)
> > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x3aaddf=
9)
> > > > >> > > > > > > #18 0x00000000030fe5e0 clang::CodeGenAction::Execute=
Action()
> > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x30fe5e=
0)
> > > > >> > > > > > > #19 0x0000000002ba1929 clang::FrontendAction::Execut=
e()
> > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x2ba192=
9)
> > > > >> > > > > > > #20 0x0000000002b68e62
> > > > >> > > > > > > clang::CompilerInstance::ExecuteAction(clang::Fronte=
ndAction&)
> > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x2b68e6=
2)
> > > > >> > > > > > > #21 0x0000000002c5738a
> > > > >> > > > > > > clang::ExecuteCompilerInvocation(clang::CompilerInst=
ance*)
> > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x2c5738=
a)
> > > > >> > > > > > > #22 0x00000000009cd1a6 cc1_main(llvm::ArrayRef<char =
const*>, char
> > > > >> > > > > > > const*, void*) (/home/tools/llvm-project/build/bin/c=
lang-9+0x9cd1a6)
> > > > >> > > > > > > #23 0x000000000094cac1 main
> > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x94cac1=
)
> > > > >> > > > > > > #24 0x00007f85ec468813 __libc_start_main (/lib64/lib=
c.so.6+0x23813)
> > > > >> > > > > > > #25 0x00000000009c96ee _start
> > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x9c96ee=
)
> > > > >> > > > > > > clang-9: error: unable to execute command: Aborted (=
core dumped)
> > > > >> > > > > > > clang-9: error: clang frontend command failed due to=
 signal (use -v to
> > > > >> > > > > > > see invocation)
> > > > >> > > > > > > clang version 9.0.0 (https://github.com/llvm/llvm-pr=
oject.git
> > > > >> > > > > > > a056684c335995214f6d3467c699d32f8e73b763)
> > > > >> > > > > > > Target: x86_64-unknown-linux-gnu
> > > > >> > > > > > > Thread model: posix
> > > > >> > > > > > > InstalledDir: /home/tools/llvm-project/build/bin
> > > > >> > > > > > > clang-9: note: diagnostic msg: PLEASE submit a bug r=
eport to
> > > > >> > > > > > > https://bugs.llvm.org/ and include the crash backtra=
ce, preprocessed
> > > > >> > > > > > > source, and associated run script.
> > > > >> > > > > > > clang-9: note: diagnostic msg:
> > > > >> > > > > > > ********************
> > > > >> > > > > > >
> > > > >> > > > > > > PLEASE ATTACH THE FOLLOWING FILES TO THE BUG REPORT:
> > > > >> > > > > > > Preprocessed source(s) and associated run script(s) =
are located at:
> > > > >> > > > > > > clang-9: note: diagnostic msg: /tmp/process_64-5fbbd=
c.c
> > > > >> > > > > > > clang-9: note: diagnostic msg: /tmp/process_64-5fbbd=
c.sh
> > > > >> > > > > > > clang-9: note: diagnostic msg:
> > > > >> > > > > > >
> > > > >> > > > > > > ********************
> > > > >> > > > > > > make[2]: *** [scripts/Makefile.build:276:
> > > > >> > > > > > > arch/x86/kernel/process_64.o] Error 254
> > > > >> > > > > > >
> > > > >> > > > > > >
> > > > >> > > > > > > any idea why?
> > > > >> > > > > > >
> > > > >> > > > > > > On Thu, Jun 27, 2019 at 5:23 PM Alexander Potapenko =
<glider@google.com> wrote:
> > > > >> > > > > > > >
> > > > >> > > > > > > > Actually, your config says:
> > > > >> > > > > > > >   "Compiler: clang version 8.0.0 (trunk 343298)"
> > > > >> > > > > > > > I think you'll need at least Clang r362410 (mine i=
s r362913)
> > > > >> > > > > > > >
> > > > >> > > > > > > > On Thu, Jun 27, 2019 at 11:20 AM Alexander Potapen=
ko <glider@google.com> wrote:
> > > > >> > > > > > > > >
> > > > >> > > > > > > > > Hi Xin,
> > > > >> > > > > > > > >
> > > > >> > > > > > > > > Sorry for the late reply.
> > > > >> > > > > > > > > I've built the ToT KMSAN tree using your config =
and my almost-ToT
> > > > >> > > > > > > > > Clang and couldn't reproduce the problem.
> > > > >> > > > > > > > > I believe something is wrong with your Clang ver=
sion, as
> > > > >> > > > > > > > > CONFIG_CLANG_VERSION should really be 90000.
> > > > >> > > > > > > > > You can run `make V=3D1` to see which Clang vers=
ion is being invoked -
> > > > >> > > > > > > > > make sure it's a fresh one.
> > > > >> > > > > > > > >
> > > > >> > > > > > > > > HTH,
> > > > >> > > > > > > > > Alex
> > > > >> > > > > > > > >
> > > > >> > > > > > > > > On Fri, Jun 21, 2019 at 10:09 PM Xin Long <lucie=
n.xin@gmail.com> wrote:
> > > > >> > > > > > > > > >
> > > > >> > > > > > > > > > as attached,
> > > > >> > > > > > > > > >
> > > > >> > > > > > > > > > It actually came from https://syzkaller.appspo=
t.com/x/.config?x=3D602468164ccdc30a
> > > > >> > > > > > > > > > after I built, clang version changed to:
> > > > >> > > > > > > > > >
> > > > >> > > > > > > > > > CONFIG_CLANG_VERSION=3D80000
> > > > >> > > > > > > > > >
> > > > >> > > > > > > > > > On Sat, Jun 22, 2019 at 2:06 AM Alexander Pota=
penko <glider@google.com> wrote:
> > > > >> > > > > > > > > > >
> > > > >> > > > > > > > > > > Hi Xin,
> > > > >> > > > > > > > > > >
> > > > >> > > > > > > > > > > Could you please share the config you're usi=
ng to build the kernel?
> > > > >> > > > > > > > > > > I'll take a closer look on Monday when I am =
back to the office.
> > > > >> > > > > > > > > > >
> > > > >> > > > > > > > > > > On Fri, 21 Jun 2019, 18:15 Xin Long, <lucien=
.xin@gmail.com> wrote:
> > > > >> > > > > > > > > > >>
> > > > >> > > > > > > > > > >> this is my command:
> > > > >> > > > > > > > > > >>
> > > > >> > > > > > > > > > >> /usr/libexec/qemu-kvm -smp 2 -m 4G -enable-=
kvm -cpu host \
> > > > >> > > > > > > > > > >>     -net nic -net user,hostfwd=3Dtcp::10022=
-:22 \
> > > > >> > > > > > > > > > >>     -kernel /home/kmsan/arch/x86/boot/bzIma=
ge -nographic \
> > > > >> > > > > > > > > > >>     -device virtio-scsi-pci,id=3Dscsi \
> > > > >> > > > > > > > > > >>     -device scsi-hd,bus=3Dscsi.0,drive=3Dd0=
 \
> > > > >> > > > > > > > > > >>     -drive file=3D/root/test/wheezy.img,for=
mat=3Draw,if=3Dnone,id=3Dd0 \
> > > > >> > > > > > > > > > >>     -append "root=3D/dev/sda console=3DttyS=
0 earlyprintk=3Dserial rodata=3Dn \
> > > > >> > > > > > > > > > >>       oops=3Dpanic panic_on_warn=3D1 panic=
=3D86400 kvm-intel.nested=3D1 \
> > > > >> > > > > > > > > > >>       security=3Dapparmor ima_policy=3Dtcb =
workqueue.watchdog_thresh=3D140 \
> > > > >> > > > > > > > > > >>       nf-conntrack-ftp.ports=3D20000 nf-con=
ntrack-tftp.ports=3D20000 \
> > > > >> > > > > > > > > > >>       nf-conntrack-sip.ports=3D20000 nf-con=
ntrack-irc.ports=3D20000 \
> > > > >> > > > > > > > > > >>       nf-conntrack-sane.ports=3D20000 vivid=
.n_devs=3D16 \
> > > > >> > > > > > > > > > >>       vivid.multiplanar=3D1,2,1,2,1,2,1,2,1=
,2,1,2,1,2,1,2 \
> > > > >> > > > > > > > > > >>       spec_store_bypass_disable=3Dprctl nop=
cid"
> > > > >> > > > > > > > > > >>
> > > > >> > > > > > > > > > >> the commit is on:
> > > > >> > > > > > > > > > >> commit f75e4cfea97f67b7530b8b991b3005f991f0=
4778 (HEAD)
> > > > >> > > > > > > > > > >> Author: Alexander Potapenko <glider@google.=
com>
> > > > >> > > > > > > > > > >> Date:   Wed May 22 12:30:13 2019 +0200
> > > > >> > > > > > > > > > >>
> > > > >> > > > > > > > > > >>     kmsan: use kmsan_handle_urb() in urb.c
> > > > >> > > > > > > > > > >>
> > > > >> > > > > > > > > > >> and when starting, it shows:
> > > > >> > > > > > > > > > >> [    0.561925][    T0] Kernel command line:=
 root=3D/dev/sda
> > > > >> > > > > > > > > > >> console=3DttyS0 earlyprintk=3Dserial rodata=
=3Dn       oops=3Dpanic
> > > > >> > > > > > > > > > >> panic_on_warn=3D1 panic=3D86400 kvm-intel.n=
ested=3D1       security=3Dad
> > > > >> > > > > > > > > > >> [    0.707792][    T0] Memory: 3087328K/419=
3776K available (219164K
> > > > >> > > > > > > > > > >> kernel code, 7059K rwdata, 11712K rodata, 5=
064K init, 11904K bss,
> > > > >> > > > > > > > > > >> 1106448K reserved, 0K cma-reserved)
> > > > >> > > > > > > > > > >> [    0.710935][    T0] SLUB: HWalign=3D64, =
Order=3D0-3, MinObjects=3D0,
> > > > >> > > > > > > > > > >> CPUs=3D2, Nodes=3D1
> > > > >> > > > > > > > > > >> [    0.711953][    T0] Starting KernelMemor=
ySanitizer
> > > > >> > > > > > > > > > >> [    0.712563][    T0]
> > > > >> > > > > > > > > > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D
> > > > >> > > > > > > > > > >> [    0.713657][    T0] BUG: KMSAN: uninit-v=
alue in mutex_lock+0xd1/0xe0
> > > > >> > > > > > > > > > >> [    0.714570][    T0] CPU: 0 PID: 0 Comm: =
swapper Not tainted 5.1.0 #5
> > > > >> > > > > > > > > > >> [    0.715417][    T0] Hardware name: Red H=
at KVM, BIOS
> > > > >> > > > > > > > > > >> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01=
/2014
> > > > >> > > > > > > > > > >> [    0.716659][    T0] Call Trace:
> > > > >> > > > > > > > > > >> [    0.717127][    T0]  dump_stack+0x134/0x=
190
> > > > >> > > > > > > > > > >> [    0.717727][    T0]  kmsan_report+0x131/=
0x2a0
> > > > >> > > > > > > > > > >> [    0.718347][    T0]  __msan_warning+0x7a=
/0xf0
> > > > >> > > > > > > > > > >> [    0.718952][    T0]  mutex_lock+0xd1/0xe=
0
> > > > >> > > > > > > > > > >> [    0.719478][    T0]  __cpuhp_setup_state=
_cpuslocked+0x149/0xd20
> > > > >> > > > > > > > > > >> [    0.720260][    T0]  ? vprintk_func+0x6b=
5/0x8a0
> > > > >> > > > > > > > > > >> [    0.720926][    T0]  ? rb_get_reader_pag=
e+0x1140/0x1140
> > > > >> > > > > > > > > > >> [    0.721632][    T0]  __cpuhp_setup_state=
+0x181/0x2e0
> > > > >> > > > > > > > > > >> [    0.722374][    T0]  ? rb_get_reader_pag=
e+0x1140/0x1140
> > > > >> > > > > > > > > > >> [    0.723115][    T0]  tracer_alloc_buffer=
s+0x16b/0xb96
> > > > >> > > > > > > > > > >> [    0.723846][    T0]  early_trace_init+0x=
193/0x28f
> > > > >> > > > > > > > > > >> [    0.724501][    T0]  start_kernel+0x497/=
0xb38
> > > > >> > > > > > > > > > >> [    0.725134][    T0]  x86_64_start_reserv=
ations+0x19/0x2f
> > > > >> > > > > > > > > > >> [    0.725871][    T0]  x86_64_start_kernel=
+0x84/0x87
> > > > >> > > > > > > > > > >> [    0.726538][    T0]  secondary_startup_6=
4+0xa4/0xb0
> > > > >> > > > > > > > > > >> [    0.727173][    T0]
> > > > >> > > > > > > > > > >> [    0.727454][    T0] Local variable descr=
iption:
> > > > >> > > > > > > > > > >> ----success.i.i.i.i@mutex_lock
> > > > >> > > > > > > > > > >> [    0.728379][    T0] Variable was created=
 at:
> > > > >> > > > > > > > > > >> [    0.728977][    T0]  mutex_lock+0x48/0xe=
0
> > > > >> > > > > > > > > > >> [    0.729536][    T0]  __cpuhp_setup_state=
_cpuslocked+0x149/0xd20
> > > > >> > > > > > > > > > >> [    0.730323][    T0]
> > > > >> > > > > > > > > > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D
> > > > >> > > > > > > > > > >> [    0.731364][    T0] Disabling lock debug=
ging due to kernel taint
> > > > >> > > > > > > > > > >> [    0.732169][    T0] Kernel panic - not s=
yncing: panic_on_warn set ...
> > > > >> > > > > > > > > > >> [    0.733047][    T0] CPU: 0 PID: 0 Comm: =
swapper Tainted: G    B
> > > > >> > > > > > > > > > >>         5.1.0 #5
> > > > >> > > > > > > > > > >> [    0.734080][    T0] Hardware name: Red H=
at KVM, BIOS
> > > > >> > > > > > > > > > >> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01=
/2014
> > > > >> > > > > > > > > > >> [    0.735319][    T0] Call Trace:
> > > > >> > > > > > > > > > >> [    0.735735][    T0]  dump_stack+0x134/0x=
190
> > > > >> > > > > > > > > > >> [    0.736308][    T0]  panic+0x3ec/0xb3b
> > > > >> > > > > > > > > > >> [    0.736826][    T0]  kmsan_report+0x29a/=
0x2a0
> > > > >> > > > > > > > > > >> [    0.737417][    T0]  __msan_warning+0x7a=
/0xf0
> > > > >> > > > > > > > > > >> [    0.737973][    T0]  mutex_lock+0xd1/0xe=
0
> > > > >> > > > > > > > > > >> [    0.738527][    T0]  __cpuhp_setup_state=
_cpuslocked+0x149/0xd20
> > > > >> > > > > > > > > > >> [    0.739342][    T0]  ? vprintk_func+0x6b=
5/0x8a0
> > > > >> > > > > > > > > > >> [    0.739972][    T0]  ? rb_get_reader_pag=
e+0x1140/0x1140
> > > > >> > > > > > > > > > >> [    0.740695][    T0]  __cpuhp_setup_state=
+0x181/0x2e0
> > > > >> > > > > > > > > > >> [    0.741412][    T0]  ? rb_get_reader_pag=
e+0x1140/0x1140
> > > > >> > > > > > > > > > >> [    0.742160][    T0]  tracer_alloc_buffer=
s+0x16b/0xb96
> > > > >> > > > > > > > > > >> [    0.742866][    T0]  early_trace_init+0x=
193/0x28f
> > > > >> > > > > > > > > > >> [    0.743512][    T0]  start_kernel+0x497/=
0xb38
> > > > >> > > > > > > > > > >> [    0.744128][    T0]  x86_64_start_reserv=
ations+0x19/0x2f
> > > > >> > > > > > > > > > >> [    0.744863][    T0]  x86_64_start_kernel=
+0x84/0x87
> > > > >> > > > > > > > > > >> [    0.745534][    T0]  secondary_startup_6=
4+0xa4/0xb0
> > > > >> > > > > > > > > > >> [    0.746290][    T0] Rebooting in 86400 s=
econds..
> > > > >> > > > > > > > > > >>
> > > > >> > > > > > > > > > >> when I set "panic_on_warn=3D0", it foods th=
e console with:
> > > > >> > > > > > > > > > >> ...
> > > > >> > > > > > > > > > >> [   25.206759][    C0] Variable was created=
 at:
> > > > >> > > > > > > > > > >> [   25.207302][    C0]  vprintk_emit+0xf4/0=
x800
> > > > >> > > > > > > > > > >> [   25.207844][    C0]  vprintk_deferred+0x=
90/0xed
> > > > >> > > > > > > > > > >> [   25.208404][    C0]
> > > > >> > > > > > > > > > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D
> > > > >> > > > > > > > > > >> [   25.209763][    C0]  x86_64_start_reserv=
ations+0x19/0x2f
> > > > >> > > > > > > > > > >> [   25.209769][    C0]
> > > > >> > > > > > > > > > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D
> > > > >> > > > > > > > > > >> [   25.211408][    C0] BUG: KMSAN: uninit-v=
alue in vprintk_emit+0x443/0x800
> > > > >> > > > > > > > > > >> [   25.212237][    C0] CPU: 0 PID: 0 Comm: =
swapper/0 Tainted: G    B
> > > > >> > > > > > > > > > >>           5.1.0 #5
> > > > >> > > > > > > > > > >> [   25.213206][    C0] Hardware name: Red H=
at KVM, BIOS
> > > > >> > > > > > > > > > >> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01=
/2014
> > > > >> > > > > > > > > > >> [   25.214326][    C0] Call Trace:
> > > > >> > > > > > > > > > >> [   25.214725][    C0]  <IRQ>
> > > > >> > > > > > > > > > >> [   25.215080][    C0]  dump_stack+0x134/0x=
190
> > > > >> > > > > > > > > > >> [   25.215624][    C0]  kmsan_report+0x131/=
0x2a0
> > > > >> > > > > > > > > > >> [   25.216204][    C0]  __msan_warning+0x7a=
/0xf0
> > > > >> > > > > > > > > > >> [   25.216771][    C0]  vprintk_emit+0x443/=
0x800
> > > > >> > > > > > > > > > >> [   25.217334][    C0]  ? __msan_metadata_p=
tr_for_store_1+0x13/0x20
> > > > >> > > > > > > > > > >> [   25.218127][    C0]  vprintk_deferred+0x=
90/0xed
> > > > >> > > > > > > > > > >> [   25.218714][    C0]  printk_deferred+0x1=
86/0x1d3
> > > > >> > > > > > > > > > >> [   25.219353][    C0]  __printk_safe_flush=
+0x72e/0xc00
> > > > >> > > > > > > > > > >> [   25.220006][    C0]  ? printk_safe_flush=
+0x1e0/0x1e0
> > > > >> > > > > > > > > > >> [   25.220635][    C0]  irq_work_run+0x1ad/=
0x5c0
> > > > >> > > > > > > > > > >> [   25.221210][    C0]  ? flat_init_apic_ld=
r+0x170/0x170
> > > > >> > > > > > > > > > >> [   25.221851][    C0]  smp_irq_work_interr=
upt+0x237/0x3e0
> > > > >> > > > > > > > > > >> [   25.222520][    C0]  irq_work_interrupt+=
0x2e/0x40
> > > > >> > > > > > > > > > >> [   25.223110][    C0]  </IRQ>
> > > > >> > > > > > > > > > >> [   25.223475][    C0] RIP: 0010:kmem_cache=
_init_late+0x0/0xb
> > > > >> > > > > > > > > > >> [   25.224164][    C0] Code: d4 e8 5d dd 2e=
 f2 e9 74 fe ff ff 48 89 d3
> > > > >> > > > > > > > > > >> 8b 7d d4 e8 cd d7 2e f2 89 c0 48 89 c1 48 c=
1 e1 20 48 09 c1 48 89 0b
> > > > >> > > > > > > > > > >> e9 81 fe ff ff <55> 48 89 e5 e8 20 de 2e1
> > > > >> > > > > > > > > > >> [   25.226526][    C0] RSP: 0000:ffffffff8f=
40feb8 EFLAGS: 00000246
> > > > >> > > > > > > > > > >> ORIG_RAX: ffffffffffffff09
> > > > >> > > > > > > > > > >> [   25.227548][    C0] RAX: ffff88813f99578=
5 RBX: 0000000000000000
> > > > >> > > > > > > > > > >> RCX: 0000000000000000
> > > > >> > > > > > > > > > >> [   25.228511][    C0] RDX: ffff88813f2b078=
4 RSI: 0000160000000000
> > > > >> > > > > > > > > > >> RDI: 0000000000000785
> > > > >> > > > > > > > > > >> [   25.229473][    C0] RBP: ffffffff8f40ff2=
0 R08: 000000000fac3785
> > > > >> > > > > > > > > > >> R09: 0000778000000001
> > > > >> > > > > > > > > > >> [   25.230440][    C0] R10: ffffd0fffffffff=
f R11: 0000100000000000
> > > > >> > > > > > > > > > >> R12: 0000000000000000
> > > > >> > > > > > > > > > >> [   25.231403][    C0] R13: 000000000000000=
0 R14: ffffffff8fb8cfd0
> > > > >> > > > > > > > > > >> R15: 0000000000000000
> > > > >> > > > > > > > > > >> [   25.232407][    C0]  ? start_kernel+0x5d=
8/0xb38
> > > > >> > > > > > > > > > >> [   25.233003][    C0]  x86_64_start_reserv=
ations+0x19/0x2f
> > > > >> > > > > > > > > > >> [   25.233670][    C0]  x86_64_start_kernel=
+0x84/0x87
> > > > >> > > > > > > > > > >> [   25.234314][    C0]  secondary_startup_6=
4+0xa4/0xb0
> > > > >> > > > > > > > > > >> [   25.234949][    C0]
> > > > >> > > > > > > > > > >> [   25.235231][    C0] Local variable descr=
iption: ----flags.i.i.i@vprintk_emit
> > > > >> > > > > > > > > > >> [   25.236101][    C0] Variable was created=
 at:
> > > > >> > > > > > > > > > >> [   25.236643][    C0]  vprintk_emit+0xf4/0=
x800
> > > > >> > > > > > > > > > >> [   25.237188][    C0]  vprintk_deferred+0x=
90/0xed
> > > > >> > > > > > > > > > >> [   25.237752][    C0]
> > > > >> > > > > > > > > > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D
> > > > >> > > > > > > > > > >> [   25.239117][    C0]  x86_64_start_kernel=
+0x84/0x87
> > > > >> > > > > > > > > > >> [   25.239123][    C0]
> > > > >> > > > > > > > > > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D
> > > > >> > > > > > > > > > >> [   25.240704][    C0] BUG: KMSAN: uninit-v=
alue in vprintk_emit+0x443/0x800
> > > > >> > > > > > > > > > >> [   25.241540][    C0] CPU: 0 PID: 0 Comm: =
swapper/0 Tainted: G    B
> > > > >> > > > > > > > > > >>           5.1.0 #5
> > > > >> > > > > > > > > > >> [   25.242512][    C0] Hardware name: Red H=
at KVM, BIOS
> > > > >> > > > > > > > > > >> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01=
/2014
> > > > >> > > > > > > > > > >> [   25.243635][    C0] Call Trace:
> > > > >> > > > > > > > > > >> [   25.244038][    C0]  <IRQ>
> > > > >> > > > > > > > > > >> [   25.244390][    C0]  dump_stack+0x134/0x=
190
> > > > >> > > > > > > > > > >> [   25.244940][    C0]  kmsan_report+0x131/=
0x2a0
> > > > >> > > > > > > > > > >> [   25.245515][    C0]  __msan_warning+0x7a=
/0xf0
> > > > >> > > > > > > > > > >> [   25.246082][    C0]  vprintk_emit+0x443/=
0x800
> > > > >> > > > > > > > > > >> [   25.246638][    C0]  ? __msan_metadata_p=
tr_for_store_1+0x13/0x20
> > > > >> > > > > > > > > > >> [   25.247430][    C0]  vprintk_deferred+0x=
90/0xed
> > > > >> > > > > > > > > > >> [   25.248018][    C0]  printk_deferred+0x1=
86/0x1d3
> > > > >> > > > > > > > > > >> [   25.248650][    C0]  __printk_safe_flush=
+0x72e/0xc00
> > > > >> > > > > > > > > > >> [   25.249320][    C0]  ? printk_safe_flush=
+0x1e0/0x1e0
> > > > >> > > > > > > > > > >> [   25.249949][    C0]  irq_work_run+0x1ad/=
0x5c0
> > > > >> > > > > > > > > > >> [   25.250524][    C0]  ? flat_init_apic_ld=
r+0x170/0x170
> > > > >> > > > > > > > > > >> [   25.251167][    C0]  smp_irq_work_interr=
upt+0x237/0x3e0
> > > > >> > > > > > > > > > >> [   25.251837][    C0]  irq_work_interrupt+=
0x2e/0x40
> > > > >> > > > > > > > > > >> [   25.252424][    C0]  </IRQ>
> > > > >> > > > > > > > > > >> ....
> > > > >> > > > > > > > > > >>
> > > > >> > > > > > > > > > >>
> > > > >> > > > > > > > > > >> I couldn't even log in.
> > > > >> > > > > > > > > > >>
> > > > >> > > > > > > > > > >> how should I use qemu with wheezy.img to st=
art a kmsan kernel?
> > > > >> > > > > > > > > > >>
> > > > >> > > > > > > > > > >> Thanks.
> > > > >> > > > > > > > >
> > > > >> > > > > > > > >
> > > > >> > > > > > > > >
> > > > >> > > > > > > > > --
> > > > >> > > > > > > > > Alexander Potapenko
> > > > >> > > > > > > > > Software Engineer
> > > > >> > > > > > > > >
> > > > >> > > > > > > > > Google Germany GmbH
> > > > >> > > > > > > > > Erika-Mann-Stra=C3=9Fe, 33
> > > > >> > > > > > > > > 80636 M=C3=BCnchen
> > > > >> > > > > > > > >
> > > > >> > > > > > > > > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah=
 DeLaine Prado
> > > > >> > > > > > > > > Registergericht und -nummer: Hamburg, HRB 86891
> > > > >> > > > > > > > > Sitz der Gesellschaft: Hamburg
> > > > >> > > > > > > >
> > > > >> > > > > > > >
> > > > >> > > > > > > >
> > > > >> > > > > > > > --
> > > > >> > > > > > > > Alexander Potapenko
> > > > >> > > > > > > > Software Engineer
> > > > >> > > > > > > >
> > > > >> > > > > > > > Google Germany GmbH
> > > > >> > > > > > > > Erika-Mann-Stra=C3=9Fe, 33
> > > > >> > > > > > > > 80636 M=C3=BCnchen
> > > > >> > > > > > > >
> > > > >> > > > > > > > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah D=
eLaine Prado
> > > > >> > > > > > > > Registergericht und -nummer: Hamburg, HRB 86891
> > > > >> > > > > > > > Sitz der Gesellschaft: Hamburg
> > > > >> > > > > >
> > > > >> > > > > >
> > > > >> > > > > >
> > > > >> > > > > > --
> > > > >> > > > > > Alexander Potapenko
> > > > >> > > > > > Software Engineer
> > > > >> > > > > >
> > > > >> > > > > > Google Germany GmbH
> > > > >> > > > > > Erika-Mann-Stra=C3=9Fe, 33
> > > > >> > > > > > 80636 M=C3=BCnchen
> > > > >> > > > > >
> > > > >> > > > > > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLai=
ne Prado
> > > > >> > > > > > Registergericht und -nummer: Hamburg, HRB 86891
> > > > >> > > > > > Sitz der Gesellschaft: Hamburg
> > > > >> > > >
> > > > >> > > >
> > > > >> > > >
> > > > >> > > > --
> > > > >> > > > Alexander Potapenko
> > > > >> > > > Software Engineer
> > > > >> > > >
> > > > >> > > > Google Germany GmbH
> > > > >> > > > Erika-Mann-Stra=C3=9Fe, 33
> > > > >> > > > 80636 M=C3=BCnchen
> > > > >> > > >
> > > > >> > > > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine P=
rado
> > > > >> > > > Registergericht und -nummer: Hamburg, HRB 86891
> > > > >> > > > Sitz der Gesellschaft: Hamburg
> > > > >> >
> > > > >> >
> > > > >> >
> > > > >> > --
> > > > >> > Alexander Potapenko
> > > > >> > Software Engineer
> > > > >> >
> > > > >> > Google Germany GmbH
> > > > >> > Erika-Mann-Stra=C3=9Fe, 33
> > > > >> > 80636 M=C3=BCnchen
> > > > >> >
> > > > >> > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
> > > > >> > Registergericht und -nummer: Hamburg, HRB 86891
> > > > >> > Sitz der Gesellschaft: Hamburg
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
> --
> You received this message because you are subscribed to the Google Groups=
 "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kasan-dev+unsubscribe@googlegroups.com.
> To post to this group, send email to kasan-dev@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgi=
d/kasan-dev/CADvbK_d8HnKu%2BoSGha4w2wWRmQW8w%2BmqxJDnqDqezZEvVd-_7A%40mail.=
gmail.com.
> For more options, visit https://groups.google.com/d/optout.



--=20
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
kasan-dev/CAG_fn%3DWS1NBRiaH_s_W9fa_qMTV3yKkmseiH6ZUK3iL7Mu3EAA%40mail.gmai=
l.com.
For more options, visit https://groups.google.com/d/optout.
