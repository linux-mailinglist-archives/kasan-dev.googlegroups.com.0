Return-Path: <kasan-dev+bncBCCMH5WKTMGRBUEU6PUAKGQE2YLNJOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 227FB5E7DE
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jul 2019 17:31:29 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id m2sf217183lfj.1
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jul 2019 08:31:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1562167888; cv=pass;
        d=google.com; s=arc-20160816;
        b=tDQuLvoMmStkI54fWk7J6asLxt7h3wztwGSiaEGarGpCZk9mnF9UxUsNTV80r9ROdN
         Kj1GdY6iJ+knq6I3raThSZsjf80kMB8f1i2Jhr42SRUam0udCGvWKG/ibtIbeEu2U8EB
         8o73yISGxgC/ABD5hGUBhUXm+whk5z+XJCb83JcI3Hj8RPedJU8IordIxB+G+x4AzN+E
         hxYGZg4erx1ZTxhSTPx/NZqfmA3iICB1vmc4K8SouqNXYFLDZFANW5olkpBiQCV26487
         o/h/XaKM+YhJfHOwptC0pZk1kVCcZCbFOyjEoOb67Bzg8w69M4xY4nNn5DiXpdAccNlc
         1S0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Lrlu6ltuiBBWvgxMEaR+czdZZhnjR54nAHjdqJXTkYQ=;
        b=RPtczLNVLt4f8zpRIRts7NT9hmFWObTE2X1PXnP1RNzE4gNaOruNj//bDBL7cVqMGX
         CaX4jpEdMPa4C0jRx8RhqAbgsutseTcZ/3GZlgazGxGU3PkpI4TDlk3xbb8cLy0YGpjY
         8rvZF9JGf/YkCgAYJTnodzHqMFROff/8o2+GMwxL9z/SFoFEo0CmsgyWLtBrirxhwgU9
         AlMGmgZMwRlLNTVCdEKJArQw4zgR7teP1L+9wYy2/jGsg5SK7MoyQTeN9JcrQ9LKMAhg
         uQnXa61d06OkiP0o6PHJGknRLwBB87CqbsZbvZVHstM8mTGkD7LsGwClrHiZ41z4tsB8
         5WAg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Bi/XXvXv";
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Lrlu6ltuiBBWvgxMEaR+czdZZhnjR54nAHjdqJXTkYQ=;
        b=l6MKyTMhmn2f08e8Qmh520M8+77geVdqMuQZIweJZPpm9VJTYY9S+EGOZ2nUCmsOk6
         S+9HoFILPY+73v5E9dp5y8667PAOg+YOVyUMu7s6ZVF1eDzKgODGVwkmyw/jKb2HoqIb
         G53eTNDasOu41q17SycaDafQawgrh/6hgmvfBEdrps0qU/aW5sknS6JxQ0Nn11zQKEbE
         qTXL6ogdAbNGFy2drgmfibFKlHYJUJcg30bzyckOw+gTL0QswDbTFdnkWve9Ujvc3so2
         9lQCn436ikgh3/0G8pNQr78gsX4mvVtAcO+CFoAI1XEu1cxOlMLjssz95Le+2vbidGNx
         lpkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Lrlu6ltuiBBWvgxMEaR+czdZZhnjR54nAHjdqJXTkYQ=;
        b=ZUxp/yQa9ze4XCv/wTBDB1JmiJIosp16R82sAWSlsXV3jsPOJfD2596ZuYdga2KuSp
         LHMv4FkhovocttwvOtgvOooKcKz6+PARmwenDU54DIgVaWypv9gccnwcViokfTirZHWA
         BHoJmBqc5k7o7HVKdKKo8BfA9sTlnhn++gR2i1Q9LxtQoLlXNiVwQwey/qFUfqzuKel4
         GGgXFiSw8QR8oa6BMv2e2GQuSUfQT+ZKtAo8TrVeMJkTRhcFCcybhTxluLuUdp5g2KrY
         K5VyWSnc+nwtcjemYCT1/Mk8Vo4L5MvoAz2GQsrRn8KDPMHIJqon5681lQLjDlkrgA81
         YCug==
X-Gm-Message-State: APjAAAVW/gDpFa+hrPp3Nb7Tm9BJw/3dbz8a6W6zV9rQYOt+PcsFpNpv
	26nWQdttxs9syxvv+w264+M=
X-Google-Smtp-Source: APXvYqyDZws3nL7J9409KRKRGmeSNhufW2eWx4JxJ+4DtjODnxj+sh39OT6+iE+f7s/0gWzKlHWl7A==
X-Received: by 2002:a2e:b047:: with SMTP id d7mr21936905ljl.8.1562167888500;
        Wed, 03 Jul 2019 08:31:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:96d5:: with SMTP id d21ls359160ljj.16.gmail; Wed, 03 Jul
 2019 08:31:28 -0700 (PDT)
X-Received: by 2002:a2e:9ac4:: with SMTP id p4mr21517514ljj.185.1562167887982;
        Wed, 03 Jul 2019 08:31:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1562167887; cv=none;
        d=google.com; s=arc-20160816;
        b=z5A3DBPTUdzLRraDjVi/phR1tRVX4hmxsPSMXTXjnQwe2ptEjDnbMOAoIEDZUqK7Gb
         2KbRWPjPdNXSCM0zQ5yS+Z31jimcdrsB3iQYNk47ACzR7fhVnH4TY9H+fbD6qHyXwvLk
         1Guu0tlUoPqDkFGr+MBDSyKiIQ5+VUzop3PHKlrU5nqBE2e5NoAXA+eoASNggEw05RpU
         kJ9qIfEAIrYZ8WpvY2PPLHeWrDNQfAd14Rl4v3t8kFNgEE/avdvJV30o55fcjuJVv9dE
         HGVpdhkxcJdi0I5JfGHo0BQFKfFP52a1YHH+fIijeTtfgi1sgvCmcP+2yQie6b9s7Nrc
         nKyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=mlwBdmupxJlyGX+8uPaQ1u3n55b5oJuJfW+7jzNWBuo=;
        b=ytHPvq5wJySul0PUUNjvHn/wZyBAHE/XbvJUo7NdLujSUT8tnasgCMVxUAcKc1s3NF
         xRUuQfaig+QSZ7+TyFEfNwcnc3qYb+vorUQypHuf6eAFhSKyAPKo6aPbxRdJTQE7fg/5
         1SAx0mF2Cmm2dcSeIlO85DRa2Zmk8ziOMjZ3iWDGj+ArswgN4uWMZcuTpgRDnEo4f4dU
         /6vWxoxI8EuahO4opwM3iKr3Y142ZkhbOw+7fCYzQSz3eVl02f86baKI1Ti/cJyo3utl
         z2x5Y3SX5oEjwUQB1/JKN3Wc3Cua/B20xG5QFdbAB02IAuqfQhIxQucgqAcBT3jy4Ub+
         fjlA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Bi/XXvXv";
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x344.google.com (mail-wm1-x344.google.com. [2a00:1450:4864:20::344])
        by gmr-mx.google.com with ESMTPS id q7si155553lji.5.2019.07.03.08.31.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Wed, 03 Jul 2019 08:31:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::344 as permitted sender) client-ip=2a00:1450:4864:20::344;
Received: by mail-wm1-x344.google.com with SMTP id f17so2882086wme.2
        for <kasan-dev@googlegroups.com>; Wed, 03 Jul 2019 08:31:27 -0700 (PDT)
X-Received: by 2002:a1c:6a0e:: with SMTP id f14mr9144596wmc.154.1562167886804;
 Wed, 03 Jul 2019 08:31:26 -0700 (PDT)
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
 <CAG_fn=XAytdKY+QbcNY6ZiNrnKAu==OSz8SBz2f=W=K8HqAyug@mail.gmail.com>
 <CADvbK_d8HnKu+oSGha4w2wWRmQW8w+mqxJDnqDqezZEvVd-_7A@mail.gmail.com>
 <CAG_fn=WS1NBRiaH_s_W9fa_qMTV3yKkmseiH6ZUK3iL7Mu3EAA@mail.gmail.com> <CADvbK_dGFV5XTVebK6YJNnBQJGPF=mi03wkyVM=mmt_uqFgzag@mail.gmail.com>
In-Reply-To: <CADvbK_dGFV5XTVebK6YJNnBQJGPF=mi03wkyVM=mmt_uqFgzag@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 Jul 2019 17:31:14 +0200
Message-ID: <CAG_fn=VwPNAn0t7XYQH+4HgaSrFWFm_1cY9aguvS=i+Gq4EUDQ@mail.gmail.com>
Subject: Re: how to start kmsan kernel with qemu
To: Xin Long <lucien.xin@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Dmitriy Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="Bi/XXvXv";       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::344 as
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

Glad to hear!
I've submitted the patch to LLVM.

On Wed, Jul 3, 2019 at 10:36 AM Xin Long <lucien.xin@gmail.com> wrote:
>
> On Tue, Jul 2, 2019 at 9:32 PM Alexander Potapenko <glider@google.com> wr=
ote:
> >
> > https://reviews.llvm.org/D64072 seems to fix the problem. I hope to
> > land this patch soon, in the meantime you can apply it to your Clang.
> It worked perfectly, thanks!
>
> > Thanks for your help tracking the bug down!
> >
> > On Tue, Jul 2, 2019 at 11:39 AM Xin Long <lucien.xin@gmail.com> wrote:
> > >
> > > On Tue, Jul 2, 2019 at 5:32 PM Alexander Potapenko <glider@google.com=
> wrote:
> > > >
> > > > Ah, I see.
> > > > You build with assertions enabled, I for some reason did not.
> > > > There's really a bug in KMSAN instrumentation, I'll fix it.
> > > Thanks, great that you figured it out so quickly.
> > > I'm waiting. :-)
> > >
> > > >
> > > > On Fri, Jun 28, 2019 at 7:24 PM Xin Long <lucien.xin@gmail.com> wro=
te:
> > > > >
> > > > > On Sat, Jun 29, 2019 at 1:18 AM Xin Long <lucien.xin@gmail.com> w=
rote:
> > > > > >
> > > > > > # cd /home/tools/
> > > > > > # git clone https://github.com/llvm/llvm-project.git
> > > > > > # cd llvm-project/
> > > > > > # mkdir build
> > > > > > # cd build/
> > > > > > # cmake -DLLVM_ENABLE_PROJECTS=3Dclang -DCMAKE_BUILD_TYPE=3DRel=
ease
> > > > > > -DLLVM_ENABLE_ASSERTIONS=3DON -G "Unix Makefiles" ../llvm
> > > > > the output is:
> > > > > https://paste.fedoraproject.org/paste/D9-QpmZnDcXkr4AykumRnw
> > > > > myabe you can have a vimdiff for the outputs of yours and mine.
> > > > >
> > > > > > # make
> > > > > sorry, it was # make -j64
> > > > >
> > > > > > # cd /home/kmsan
> > > > > > # git checkout f75e4cfea97f
> > > > > > (use the .config I sent you last time)
> > > > > > # make CC=3D/home/tools/llvm-project/build/bin/clang -j64 -k LO=
CALVERSION=3D 2>&1
> > > > > >
> > > > > > These are the whole thing I did to build it.
> > > > > >
> > > > > > On Sat, Jun 29, 2019 at 12:09 AM Alexander Potapenko <glider@go=
ogle.com> wrote:
> > > > > > >
> > > > > > > Hm, now that's your Clang binary versus mine :)
> > > > > > > Can you please ensure your git repo doesn't contain local cha=
nges and share the commands you're using to build Clang?
> > > > > > > (Both cmake and make or ninja)
> > > > > > No any local changes on both llvm-project and kmsan
> > > > > >
> > > > > > > Is the bug still reproducible in a clean CMake directory?
> > > > > > A clean CMake directory? how to clean it? something like: # cma=
ke clean
> > > > > >
> > > > > > Thank you for being so patient. :-)
> > > > > >
> > > > > > >
> > > > > > > On Fri, 28 Jun 2019, 16:20 Xin Long, <lucien.xin@gmail.com> w=
rote:
> > > > > > >>
> > > > > > >> yes
> > > > > > >>
> > > > > > >> https://paste.fedoraproject.org/paste/DU2nnxpZWpWMri9Up7hypA
> > > > > > >>
> > > > > > >> On Fri, Jun 28, 2019 at 9:48 PM Alexander Potapenko <glider@=
google.com> wrote:
> > > > > > >> >
> > > > > > >> > Hm, strange, but I still can compile this file.
> > > > > > >> > Does the following command line crash your compiler?
> > > > > > >> > https://paste.fedoraproject.org/paste/oJwOVm5cHWyd7hxIZ4uG=
eA (note it
> > > > > > >> > should be run from the same directory where process_64.i r=
esides; also
> > > > > > >> > make sure to invoke the right Clang)
> > > > > > >> >
> > > > > > >> > On Fri, Jun 28, 2019 at 3:35 PM Xin Long <lucien.xin@gmail=
.com> wrote:
> > > > > > >> > >
> > > > > > >> > > As attached, thanks.
> > > > > > >> > >
> > > > > > >> > > On Fri, Jun 28, 2019 at 9:24 PM Alexander Potapenko <gli=
der@google.com> wrote:
> > > > > > >> > > >
> > > > > > >> > > > On Fri, Jun 28, 2019 at 3:10 PM Xin Long <lucien.xin@g=
mail.com> wrote:
> > > > > > >> > > > >
> > > > > > >> > > > > This is what I did:
> > > > > > >> > > > > https://paste.fedoraproject.org/paste/q4~GWx9Sx~QUbJ=
QfNDoJIw
> > > > > > >> > > > >
> > > > > > >> > > > > There's no process_64.i file generated.
> > > > > > >> > > > >
> > > > > > >> > > > > Btw, I couldn't find "-c" in the command line, so th=
ere was no "-E" added.
> > > > > > >> > > > Ah, right, Clang is invoked with -S. Could you replace=
 that one with -E?
> > > > > > >> > > > > On Fri, Jun 28, 2019 at 8:40 PM Alexander Potapenko =
<glider@google.com> wrote:
> > > > > > >> > > > > >
> > > > > > >> > > > > > It's interesting that you're seeing the same error=
 as reported here:
> > > > > > >> > > > > > https://github.com/google/kmsan/issues/53
> > > > > > >> > > > > > I've updated my Clang to a4771e9dfdb0485c2edb416bf=
dc479d49de0aa14, but
> > > > > > >> > > > > > the kernel compiles just fine.
> > > > > > >> > > > > > May I ask you to do the following:
> > > > > > >> > > > > >
> > > > > > >> > > > > >  - run `make V=3D1` to capture the command line us=
ed to build
> > > > > > >> > > > > > arch/x86/kernel/process_64.o
> > > > > > >> > > > > >  - copy and paste the command line into a shell, r=
emove '-o
> > > > > > >> > > > > > /tmp/somefile' and run again to make sure the comp=
iler still crashes
> > > > > > >> > > > > >  - replace '-c' with '-E' in the command line and =
add '-o
> > > > > > >> > > > > > process_64.i' to the end
> > > > > > >> > > > > >  - send me the resulting preprocessed file (proces=
s_64.i)
> > > > > > >> > > > > >
> > > > > > >> > > > > > Thanks!
> > > > > > >> > > > > >
> > > > > > >> > > > > >
> > > > > > >> > > > > >
> > > > > > >> > > > > > On Thu, Jun 27, 2019 at 4:45 PM Xin Long <lucien.x=
in@gmail.com> wrote:
> > > > > > >> > > > > > >
> > > > > > >> > > > > > > Now I'm using:
> > > > > > >> > > > > > > # Compiler: clang version 9.0.0
> > > > > > >> > > > > > > (https://github.com/llvm/llvm-project.git
> > > > > > >> > > > > > > a056684c335995214f6d3467c699d32f8e73b763)
> > > > > > >> > > > > > >
> > > > > > >> > > > > > > Errors shows up when building the kernel:
> > > > > > >> > > > > > >
> > > > > > >> > > > > > >   CC      arch/x86/kernel/process_64.o
> > > > > > >> > > > > > > clang-9: /home/tools/llvm-project/llvm/lib/Trans=
forms/Instrumentation/MemorySanitizer.cpp:3236:
> > > > > > >> > > > > > > void {anonymous}::MemorySanitizerVisitor::visitC=
allSite(llvm::CallSite):
> > > > > > >> > > > > > > Assertion `(CS.isCall() || CS.isInvoke()) && "Un=
known type of
> > > > > > >> > > > > > > CallSite"' failed.
> > > > > > >> > > > > > > Stack dump:
> > > > > > >> > > > > > > 0.      Program arguments: /home/tools/llvm-proj=
ect/build/bin/clang-9
> > > > > > >> > > > > > > -cc1 -triple x86_64-unknown-linux-gnu -S -disabl=
e-free -main-file-name
> > > > > > >> > > > > > > process_64.c -mrelocation-model static -mthread-=
model posix
> > > > > > >> > > > > > > -fno-delete-null-pointer-checks -mllvm -warn-sta=
ck-size=3D2048
> > > > > > >> > > > > > > -mdisable-fp-elim -relaxed-aliasing -mdisable-ta=
il-calls -fmath-errno
> > > > > > >> > > > > > > -masm-verbose -no-integrated-as -mconstructor-al=
iases -fuse-init-array
> > > > > > >> > > > > > > -mcode-model kernel -target-cpu core2 -target-fe=
ature
> > > > > > >> > > > > > > +retpoline-indirect-calls -target-feature +retpo=
line-indirect-branches
> > > > > > >> > > > > > > -target-feature -sse -target-feature -mmx -targe=
t-feature -sse2
> > > > > > >> > > > > > > -target-feature -3dnow -target-feature -avx -tar=
get-feature -x87
> > > > > > >> > > > > > > -target-feature +retpoline-external-thunk -disab=
le-red-zone
> > > > > > >> > > > > > > -dwarf-column-info -debug-info-kind=3Dlimited -d=
warf-version=3D4
> > > > > > >> > > > > > > -debugger-tuning=3Dgdb -momit-leaf-frame-pointer=
 -coverage-notes-file
> > > > > > >> > > > > > > /home/kmsan/arch/x86/kernel/process_64.gcno -nos=
tdsysteminc
> > > > > > >> > > > > > > -nobuiltininc -resource-dir
> > > > > > >> > > > > > > /home/tools/llvm-project/build/lib/clang/9.0.0 -=
dependency-file
> > > > > > >> > > > > > > arch/x86/kernel/.process_64.o.d -MT arch/x86/ker=
nel/process_64.o
> > > > > > >> > > > > > > -sys-header-deps -isystem
> > > > > > >> > > > > > > /home/tools/llvm-project/build/lib/clang/9.0.0/i=
nclude -include
> > > > > > >> > > > > > > ./include/linux/kconfig.h -include ./include/lin=
ux/compiler_types.h -I
> > > > > > >> > > > > > > ./arch/x86/include -I ./arch/x86/include/generat=
ed -I ./include -I
> > > > > > >> > > > > > > ./arch/x86/include/uapi -I ./arch/x86/include/ge=
nerated/uapi -I
> > > > > > >> > > > > > > ./include/uapi -I ./include/generated/uapi -D __=
KERNEL__ -D
> > > > > > >> > > > > > > CONFIG_X86_X32_ABI -D CONFIG_AS_CFI=3D1 -D CONFI=
G_AS_CFI_SIGNAL_FRAME=3D1
> > > > > > >> > > > > > > -D CONFIG_AS_CFI_SECTIONS=3D1 -D CONFIG_AS_SSSE3=
=3D1 -D CONFIG_AS_AVX=3D1 -D
> > > > > > >> > > > > > > CONFIG_AS_AVX2=3D1 -D CONFIG_AS_AVX512=3D1 -D CO=
NFIG_AS_SHA1_NI=3D1 -D
> > > > > > >> > > > > > > CONFIG_AS_SHA256_NI=3D1 -D KBUILD_BASENAME=3D"pr=
ocess_64" -D
> > > > > > >> > > > > > > KBUILD_MODNAME=3D"process_64" -O2 -Wall -Wundef
> > > > > > >> > > > > > > -Werror=3Dstrict-prototypes -Wno-trigraphs
> > > > > > >> > > > > > > -Werror=3Dimplicit-function-declaration -Werror=
=3Dimplicit-int
> > > > > > >> > > > > > > -Wno-format-security -Wno-sign-compare -Wno-addr=
ess-of-packed-member
> > > > > > >> > > > > > > -Wno-format-invalid-specifier -Wno-gnu -Wno-taut=
ological-compare
> > > > > > >> > > > > > > -Wno-unused-const-variable -Wdeclaration-after-s=
tatement -Wvla
> > > > > > >> > > > > > > -Wno-pointer-sign -Werror=3Ddate-time -Werror=3D=
incompatible-pointer-types
> > > > > > >> > > > > > > -Wno-initializer-overrides -Wno-unused-value -Wn=
o-format
> > > > > > >> > > > > > > -Wno-sign-compare -Wno-format-zero-length -Wno-u=
ninitialized
> > > > > > >> > > > > > > -std=3Dgnu89 -fno-dwarf-directory-asm -fdebug-co=
mpilation-dir
> > > > > > >> > > > > > > /home/kmsan -ferror-limit 19 -fmessage-length 0
> > > > > > >> > > > > > > -fsanitize=3Dkernel-memory -fwrapv -stack-protec=
tor 2
> > > > > > >> > > > > > > -mstack-alignment=3D8 -fwchar-type=3Dshort -fno-=
signed-wchar
> > > > > > >> > > > > > > -fobjc-runtime=3Dgcc -fno-common -fdiagnostics-s=
how-option
> > > > > > >> > > > > > > -fcolor-diagnostics -vectorize-loops -vectorize-=
slp -o
> > > > > > >> > > > > > > /tmp/process_64-e20ead.s -x c arch/x86/kernel/pr=
ocess_64.c
> > > > > > >> > > > > > > 1.      <eof> parser at end of file
> > > > > > >> > > > > > > 2.      Per-module optimization passes
> > > > > > >> > > > > > > 3.      Running pass 'Function Pass Manager' on =
module
> > > > > > >> > > > > > > 'arch/x86/kernel/process_64.c'.
> > > > > > >> > > > > > > 4.      Running pass 'MemorySanitizerLegacyPass'=
 on function '@start_thread'
> > > > > > >> > > > > > >  #0 0x00000000024f03ba llvm::sys::PrintStackTrac=
e(llvm::raw_ostream&)
> > > > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x24=
f03ba)
> > > > > > >> > > > > > >  #1 0x00000000024ee214 llvm::sys::RunSignalHandl=
ers()
> > > > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x24=
ee214)
> > > > > > >> > > > > > >  #2 0x00000000024ee375 SignalHandler(int)
> > > > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x24=
ee375)
> > > > > > >> > > > > > >  #3 0x00007f85ed99bd80 __restore_rt (/lib64/libp=
thread.so.0+0x12d80)
> > > > > > >> > > > > > >  #4 0x00007f85ec47c93f raise (/lib64/libc.so.6+0=
x3793f)
> > > > > > >> > > > > > >  #5 0x00007f85ec466c95 abort (/lib64/libc.so.6+0=
x21c95)
> > > > > > >> > > > > > >  #6 0x00007f85ec466b69 _nl_load_domain.cold.0 (/=
lib64/libc.so.6+0x21b69)
> > > > > > >> > > > > > >  #7 0x00007f85ec474df6 (/lib64/libc.so.6+0x2fdf6=
)
> > > > > > >> > > > > > >  #8 0x000000000327b864 (anonymous
> > > > > > >> > > > > > > namespace)::MemorySanitizerVisitor::visitCallSit=
e(llvm::CallSite)
> > > > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x32=
7b864)
> > > > > > >> > > > > > >  #9 0x0000000003283036 (anonymous
> > > > > > >> > > > > > > namespace)::MemorySanitizerVisitor::runOnFunctio=
n()
> > > > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x32=
83036)
> > > > > > >> > > > > > > #10 0x000000000328605f (anonymous
> > > > > > >> > > > > > > namespace)::MemorySanitizer::sanitizeFunction(ll=
vm::Function&,
> > > > > > >> > > > > > > llvm::TargetLibraryInfo&)
> > > > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x32=
8605f)
> > > > > > >> > > > > > > #11 0x0000000001f42ac8
> > > > > > >> > > > > > > llvm::FPPassManager::runOnFunction(llvm::Functio=
n&)
> > > > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x1f=
42ac8)
> > > > > > >> > > > > > > #12 0x0000000001f42be9 llvm::FPPassManager::runO=
nModule(llvm::Module&)
> > > > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x1f=
42be9)
> > > > > > >> > > > > > > #13 0x0000000001f41ed8
> > > > > > >> > > > > > > llvm::legacy::PassManagerImpl::run(llvm::Module&=
)
> > > > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x1f=
41ed8)
> > > > > > >> > > > > > > #14 0x00000000026fa4f8 (anonymous
> > > > > > >> > > > > > > namespace)::EmitAssemblyHelper::EmitAssembly(cla=
ng::BackendAction,
> > > > > > >> > > > > > > std::unique_ptr<llvm::raw_pwrite_stream,
> > > > > > >> > > > > > > std::default_delete<llvm::raw_pwrite_stream> >)
> > > > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x26=
fa4f8)
> > > > > > >> > > > > > > #15 0x00000000026fbbf8
> > > > > > >> > > > > > > clang::EmitBackendOutput(clang::DiagnosticsEngin=
e&,
> > > > > > >> > > > > > > clang::HeaderSearchOptions const&, clang::CodeGe=
nOptions const&,
> > > > > > >> > > > > > > clang::TargetOptions const&, clang::LangOptions =
const&,
> > > > > > >> > > > > > > llvm::DataLayout const&, llvm::Module*, clang::B=
ackendAction,
> > > > > > >> > > > > > > std::unique_ptr<llvm::raw_pwrite_stream,
> > > > > > >> > > > > > > std::default_delete<llvm::raw_pwrite_stream> >)
> > > > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x26=
fbbf8)
> > > > > > >> > > > > > > #16 0x000000000310234d
> > > > > > >> > > > > > > clang::BackendConsumer::HandleTranslationUnit(cl=
ang::ASTContext&)
> > > > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x31=
0234d)
> > > > > > >> > > > > > > #17 0x0000000003aaddf9 clang::ParseAST(clang::Se=
ma&, bool, bool)
> > > > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x3a=
addf9)
> > > > > > >> > > > > > > #18 0x00000000030fe5e0 clang::CodeGenAction::Exe=
cuteAction()
> > > > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x30=
fe5e0)
> > > > > > >> > > > > > > #19 0x0000000002ba1929 clang::FrontendAction::Ex=
ecute()
> > > > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x2b=
a1929)
> > > > > > >> > > > > > > #20 0x0000000002b68e62
> > > > > > >> > > > > > > clang::CompilerInstance::ExecuteAction(clang::Fr=
ontendAction&)
> > > > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x2b=
68e62)
> > > > > > >> > > > > > > #21 0x0000000002c5738a
> > > > > > >> > > > > > > clang::ExecuteCompilerInvocation(clang::Compiler=
Instance*)
> > > > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x2c=
5738a)
> > > > > > >> > > > > > > #22 0x00000000009cd1a6 cc1_main(llvm::ArrayRef<c=
har const*>, char
> > > > > > >> > > > > > > const*, void*) (/home/tools/llvm-project/build/b=
in/clang-9+0x9cd1a6)
> > > > > > >> > > > > > > #23 0x000000000094cac1 main
> > > > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x94=
cac1)
> > > > > > >> > > > > > > #24 0x00007f85ec468813 __libc_start_main (/lib64=
/libc.so.6+0x23813)
> > > > > > >> > > > > > > #25 0x00000000009c96ee _start
> > > > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x9c=
96ee)
> > > > > > >> > > > > > > clang-9: error: unable to execute command: Abort=
ed (core dumped)
> > > > > > >> > > > > > > clang-9: error: clang frontend command failed du=
e to signal (use -v to
> > > > > > >> > > > > > > see invocation)
> > > > > > >> > > > > > > clang version 9.0.0 (https://github.com/llvm/llv=
m-project.git
> > > > > > >> > > > > > > a056684c335995214f6d3467c699d32f8e73b763)
> > > > > > >> > > > > > > Target: x86_64-unknown-linux-gnu
> > > > > > >> > > > > > > Thread model: posix
> > > > > > >> > > > > > > InstalledDir: /home/tools/llvm-project/build/bin
> > > > > > >> > > > > > > clang-9: note: diagnostic msg: PLEASE submit a b=
ug report to
> > > > > > >> > > > > > > https://bugs.llvm.org/ and include the crash bac=
ktrace, preprocessed
> > > > > > >> > > > > > > source, and associated run script.
> > > > > > >> > > > > > > clang-9: note: diagnostic msg:
> > > > > > >> > > > > > > ********************
> > > > > > >> > > > > > >
> > > > > > >> > > > > > > PLEASE ATTACH THE FOLLOWING FILES TO THE BUG REP=
ORT:
> > > > > > >> > > > > > > Preprocessed source(s) and associated run script=
(s) are located at:
> > > > > > >> > > > > > > clang-9: note: diagnostic msg: /tmp/process_64-5=
fbbdc.c
> > > > > > >> > > > > > > clang-9: note: diagnostic msg: /tmp/process_64-5=
fbbdc.sh
> > > > > > >> > > > > > > clang-9: note: diagnostic msg:
> > > > > > >> > > > > > >
> > > > > > >> > > > > > > ********************
> > > > > > >> > > > > > > make[2]: *** [scripts/Makefile.build:276:
> > > > > > >> > > > > > > arch/x86/kernel/process_64.o] Error 254
> > > > > > >> > > > > > >
> > > > > > >> > > > > > >
> > > > > > >> > > > > > > any idea why?
> > > > > > >> > > > > > >
> > > > > > >> > > > > > > On Thu, Jun 27, 2019 at 5:23 PM Alexander Potape=
nko <glider@google.com> wrote:
> > > > > > >> > > > > > > >
> > > > > > >> > > > > > > > Actually, your config says:
> > > > > > >> > > > > > > >   "Compiler: clang version 8.0.0 (trunk 343298=
)"
> > > > > > >> > > > > > > > I think you'll need at least Clang r362410 (mi=
ne is r362913)
> > > > > > >> > > > > > > >
> > > > > > >> > > > > > > > On Thu, Jun 27, 2019 at 11:20 AM Alexander Pot=
apenko <glider@google.com> wrote:
> > > > > > >> > > > > > > > >
> > > > > > >> > > > > > > > > Hi Xin,
> > > > > > >> > > > > > > > >
> > > > > > >> > > > > > > > > Sorry for the late reply.
> > > > > > >> > > > > > > > > I've built the ToT KMSAN tree using your con=
fig and my almost-ToT
> > > > > > >> > > > > > > > > Clang and couldn't reproduce the problem.
> > > > > > >> > > > > > > > > I believe something is wrong with your Clang=
 version, as
> > > > > > >> > > > > > > > > CONFIG_CLANG_VERSION should really be 90000.
> > > > > > >> > > > > > > > > You can run `make V=3D1` to see which Clang =
version is being invoked -
> > > > > > >> > > > > > > > > make sure it's a fresh one.
> > > > > > >> > > > > > > > >
> > > > > > >> > > > > > > > > HTH,
> > > > > > >> > > > > > > > > Alex
> > > > > > >> > > > > > > > >
> > > > > > >> > > > > > > > > On Fri, Jun 21, 2019 at 10:09 PM Xin Long <l=
ucien.xin@gmail.com> wrote:
> > > > > > >> > > > > > > > > >
> > > > > > >> > > > > > > > > > as attached,
> > > > > > >> > > > > > > > > >
> > > > > > >> > > > > > > > > > It actually came from https://syzkaller.ap=
pspot.com/x/.config?x=3D602468164ccdc30a
> > > > > > >> > > > > > > > > > after I built, clang version changed to:
> > > > > > >> > > > > > > > > >
> > > > > > >> > > > > > > > > > CONFIG_CLANG_VERSION=3D80000
> > > > > > >> > > > > > > > > >
> > > > > > >> > > > > > > > > > On Sat, Jun 22, 2019 at 2:06 AM Alexander =
Potapenko <glider@google.com> wrote:
> > > > > > >> > > > > > > > > > >
> > > > > > >> > > > > > > > > > > Hi Xin,
> > > > > > >> > > > > > > > > > >
> > > > > > >> > > > > > > > > > > Could you please share the config you're=
 using to build the kernel?
> > > > > > >> > > > > > > > > > > I'll take a closer look on Monday when I=
 am back to the office.
> > > > > > >> > > > > > > > > > >
> > > > > > >> > > > > > > > > > > On Fri, 21 Jun 2019, 18:15 Xin Long, <lu=
cien.xin@gmail.com> wrote:
> > > > > > >> > > > > > > > > > >>
> > > > > > >> > > > > > > > > > >> this is my command:
> > > > > > >> > > > > > > > > > >>
> > > > > > >> > > > > > > > > > >> /usr/libexec/qemu-kvm -smp 2 -m 4G -ena=
ble-kvm -cpu host \
> > > > > > >> > > > > > > > > > >>     -net nic -net user,hostfwd=3Dtcp::1=
0022-:22 \
> > > > > > >> > > > > > > > > > >>     -kernel /home/kmsan/arch/x86/boot/b=
zImage -nographic \
> > > > > > >> > > > > > > > > > >>     -device virtio-scsi-pci,id=3Dscsi \
> > > > > > >> > > > > > > > > > >>     -device scsi-hd,bus=3Dscsi.0,drive=
=3Dd0 \
> > > > > > >> > > > > > > > > > >>     -drive file=3D/root/test/wheezy.img=
,format=3Draw,if=3Dnone,id=3Dd0 \
> > > > > > >> > > > > > > > > > >>     -append "root=3D/dev/sda console=3D=
ttyS0 earlyprintk=3Dserial rodata=3Dn \
> > > > > > >> > > > > > > > > > >>       oops=3Dpanic panic_on_warn=3D1 pa=
nic=3D86400 kvm-intel.nested=3D1 \
> > > > > > >> > > > > > > > > > >>       security=3Dapparmor ima_policy=3D=
tcb workqueue.watchdog_thresh=3D140 \
> > > > > > >> > > > > > > > > > >>       nf-conntrack-ftp.ports=3D20000 nf=
-conntrack-tftp.ports=3D20000 \
> > > > > > >> > > > > > > > > > >>       nf-conntrack-sip.ports=3D20000 nf=
-conntrack-irc.ports=3D20000 \
> > > > > > >> > > > > > > > > > >>       nf-conntrack-sane.ports=3D20000 v=
ivid.n_devs=3D16 \
> > > > > > >> > > > > > > > > > >>       vivid.multiplanar=3D1,2,1,2,1,2,1=
,2,1,2,1,2,1,2,1,2 \
> > > > > > >> > > > > > > > > > >>       spec_store_bypass_disable=3Dprctl=
 nopcid"
> > > > > > >> > > > > > > > > > >>
> > > > > > >> > > > > > > > > > >> the commit is on:
> > > > > > >> > > > > > > > > > >> commit f75e4cfea97f67b7530b8b991b3005f9=
91f04778 (HEAD)
> > > > > > >> > > > > > > > > > >> Author: Alexander Potapenko <glider@goo=
gle.com>
> > > > > > >> > > > > > > > > > >> Date:   Wed May 22 12:30:13 2019 +0200
> > > > > > >> > > > > > > > > > >>
> > > > > > >> > > > > > > > > > >>     kmsan: use kmsan_handle_urb() in ur=
b.c
> > > > > > >> > > > > > > > > > >>
> > > > > > >> > > > > > > > > > >> and when starting, it shows:
> > > > > > >> > > > > > > > > > >> [    0.561925][    T0] Kernel command l=
ine: root=3D/dev/sda
> > > > > > >> > > > > > > > > > >> console=3DttyS0 earlyprintk=3Dserial ro=
data=3Dn       oops=3Dpanic
> > > > > > >> > > > > > > > > > >> panic_on_warn=3D1 panic=3D86400 kvm-int=
el.nested=3D1       security=3Dad
> > > > > > >> > > > > > > > > > >> [    0.707792][    T0] Memory: 3087328K=
/4193776K available (219164K
> > > > > > >> > > > > > > > > > >> kernel code, 7059K rwdata, 11712K rodat=
a, 5064K init, 11904K bss,
> > > > > > >> > > > > > > > > > >> 1106448K reserved, 0K cma-reserved)
> > > > > > >> > > > > > > > > > >> [    0.710935][    T0] SLUB: HWalign=3D=
64, Order=3D0-3, MinObjects=3D0,
> > > > > > >> > > > > > > > > > >> CPUs=3D2, Nodes=3D1
> > > > > > >> > > > > > > > > > >> [    0.711953][    T0] Starting KernelM=
emorySanitizer
> > > > > > >> > > > > > > > > > >> [    0.712563][    T0]
> > > > > > >> > > > > > > > > > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D
> > > > > > >> > > > > > > > > > >> [    0.713657][    T0] BUG: KMSAN: unin=
it-value in mutex_lock+0xd1/0xe0
> > > > > > >> > > > > > > > > > >> [    0.714570][    T0] CPU: 0 PID: 0 Co=
mm: swapper Not tainted 5.1.0 #5
> > > > > > >> > > > > > > > > > >> [    0.715417][    T0] Hardware name: R=
ed Hat KVM, BIOS
> > > > > > >> > > > > > > > > > >> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 0=
4/01/2014
> > > > > > >> > > > > > > > > > >> [    0.716659][    T0] Call Trace:
> > > > > > >> > > > > > > > > > >> [    0.717127][    T0]  dump_stack+0x13=
4/0x190
> > > > > > >> > > > > > > > > > >> [    0.717727][    T0]  kmsan_report+0x=
131/0x2a0
> > > > > > >> > > > > > > > > > >> [    0.718347][    T0]  __msan_warning+=
0x7a/0xf0
> > > > > > >> > > > > > > > > > >> [    0.718952][    T0]  mutex_lock+0xd1=
/0xe0
> > > > > > >> > > > > > > > > > >> [    0.719478][    T0]  __cpuhp_setup_s=
tate_cpuslocked+0x149/0xd20
> > > > > > >> > > > > > > > > > >> [    0.720260][    T0]  ? vprintk_func+=
0x6b5/0x8a0
> > > > > > >> > > > > > > > > > >> [    0.720926][    T0]  ? rb_get_reader=
_page+0x1140/0x1140
> > > > > > >> > > > > > > > > > >> [    0.721632][    T0]  __cpuhp_setup_s=
tate+0x181/0x2e0
> > > > > > >> > > > > > > > > > >> [    0.722374][    T0]  ? rb_get_reader=
_page+0x1140/0x1140
> > > > > > >> > > > > > > > > > >> [    0.723115][    T0]  tracer_alloc_bu=
ffers+0x16b/0xb96
> > > > > > >> > > > > > > > > > >> [    0.723846][    T0]  early_trace_ini=
t+0x193/0x28f
> > > > > > >> > > > > > > > > > >> [    0.724501][    T0]  start_kernel+0x=
497/0xb38
> > > > > > >> > > > > > > > > > >> [    0.725134][    T0]  x86_64_start_re=
servations+0x19/0x2f
> > > > > > >> > > > > > > > > > >> [    0.725871][    T0]  x86_64_start_ke=
rnel+0x84/0x87
> > > > > > >> > > > > > > > > > >> [    0.726538][    T0]  secondary_start=
up_64+0xa4/0xb0
> > > > > > >> > > > > > > > > > >> [    0.727173][    T0]
> > > > > > >> > > > > > > > > > >> [    0.727454][    T0] Local variable d=
escription:
> > > > > > >> > > > > > > > > > >> ----success.i.i.i.i@mutex_lock
> > > > > > >> > > > > > > > > > >> [    0.728379][    T0] Variable was cre=
ated at:
> > > > > > >> > > > > > > > > > >> [    0.728977][    T0]  mutex_lock+0x48=
/0xe0
> > > > > > >> > > > > > > > > > >> [    0.729536][    T0]  __cpuhp_setup_s=
tate_cpuslocked+0x149/0xd20
> > > > > > >> > > > > > > > > > >> [    0.730323][    T0]
> > > > > > >> > > > > > > > > > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D
> > > > > > >> > > > > > > > > > >> [    0.731364][    T0] Disabling lock d=
ebugging due to kernel taint
> > > > > > >> > > > > > > > > > >> [    0.732169][    T0] Kernel panic - n=
ot syncing: panic_on_warn set ...
> > > > > > >> > > > > > > > > > >> [    0.733047][    T0] CPU: 0 PID: 0 Co=
mm: swapper Tainted: G    B
> > > > > > >> > > > > > > > > > >>         5.1.0 #5
> > > > > > >> > > > > > > > > > >> [    0.734080][    T0] Hardware name: R=
ed Hat KVM, BIOS
> > > > > > >> > > > > > > > > > >> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 0=
4/01/2014
> > > > > > >> > > > > > > > > > >> [    0.735319][    T0] Call Trace:
> > > > > > >> > > > > > > > > > >> [    0.735735][    T0]  dump_stack+0x13=
4/0x190
> > > > > > >> > > > > > > > > > >> [    0.736308][    T0]  panic+0x3ec/0xb=
3b
> > > > > > >> > > > > > > > > > >> [    0.736826][    T0]  kmsan_report+0x=
29a/0x2a0
> > > > > > >> > > > > > > > > > >> [    0.737417][    T0]  __msan_warning+=
0x7a/0xf0
> > > > > > >> > > > > > > > > > >> [    0.737973][    T0]  mutex_lock+0xd1=
/0xe0
> > > > > > >> > > > > > > > > > >> [    0.738527][    T0]  __cpuhp_setup_s=
tate_cpuslocked+0x149/0xd20
> > > > > > >> > > > > > > > > > >> [    0.739342][    T0]  ? vprintk_func+=
0x6b5/0x8a0
> > > > > > >> > > > > > > > > > >> [    0.739972][    T0]  ? rb_get_reader=
_page+0x1140/0x1140
> > > > > > >> > > > > > > > > > >> [    0.740695][    T0]  __cpuhp_setup_s=
tate+0x181/0x2e0
> > > > > > >> > > > > > > > > > >> [    0.741412][    T0]  ? rb_get_reader=
_page+0x1140/0x1140
> > > > > > >> > > > > > > > > > >> [    0.742160][    T0]  tracer_alloc_bu=
ffers+0x16b/0xb96
> > > > > > >> > > > > > > > > > >> [    0.742866][    T0]  early_trace_ini=
t+0x193/0x28f
> > > > > > >> > > > > > > > > > >> [    0.743512][    T0]  start_kernel+0x=
497/0xb38
> > > > > > >> > > > > > > > > > >> [    0.744128][    T0]  x86_64_start_re=
servations+0x19/0x2f
> > > > > > >> > > > > > > > > > >> [    0.744863][    T0]  x86_64_start_ke=
rnel+0x84/0x87
> > > > > > >> > > > > > > > > > >> [    0.745534][    T0]  secondary_start=
up_64+0xa4/0xb0
> > > > > > >> > > > > > > > > > >> [    0.746290][    T0] Rebooting in 864=
00 seconds..
> > > > > > >> > > > > > > > > > >>
> > > > > > >> > > > > > > > > > >> when I set "panic_on_warn=3D0", it food=
s the console with:
> > > > > > >> > > > > > > > > > >> ...
> > > > > > >> > > > > > > > > > >> [   25.206759][    C0] Variable was cre=
ated at:
> > > > > > >> > > > > > > > > > >> [   25.207302][    C0]  vprintk_emit+0x=
f4/0x800
> > > > > > >> > > > > > > > > > >> [   25.207844][    C0]  vprintk_deferre=
d+0x90/0xed
> > > > > > >> > > > > > > > > > >> [   25.208404][    C0]
> > > > > > >> > > > > > > > > > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D
> > > > > > >> > > > > > > > > > >> [   25.209763][    C0]  x86_64_start_re=
servations+0x19/0x2f
> > > > > > >> > > > > > > > > > >> [   25.209769][    C0]
> > > > > > >> > > > > > > > > > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D
> > > > > > >> > > > > > > > > > >> [   25.211408][    C0] BUG: KMSAN: unin=
it-value in vprintk_emit+0x443/0x800
> > > > > > >> > > > > > > > > > >> [   25.212237][    C0] CPU: 0 PID: 0 Co=
mm: swapper/0 Tainted: G    B
> > > > > > >> > > > > > > > > > >>           5.1.0 #5
> > > > > > >> > > > > > > > > > >> [   25.213206][    C0] Hardware name: R=
ed Hat KVM, BIOS
> > > > > > >> > > > > > > > > > >> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 0=
4/01/2014
> > > > > > >> > > > > > > > > > >> [   25.214326][    C0] Call Trace:
> > > > > > >> > > > > > > > > > >> [   25.214725][    C0]  <IRQ>
> > > > > > >> > > > > > > > > > >> [   25.215080][    C0]  dump_stack+0x13=
4/0x190
> > > > > > >> > > > > > > > > > >> [   25.215624][    C0]  kmsan_report+0x=
131/0x2a0
> > > > > > >> > > > > > > > > > >> [   25.216204][    C0]  __msan_warning+=
0x7a/0xf0
> > > > > > >> > > > > > > > > > >> [   25.216771][    C0]  vprintk_emit+0x=
443/0x800
> > > > > > >> > > > > > > > > > >> [   25.217334][    C0]  ? __msan_metada=
ta_ptr_for_store_1+0x13/0x20
> > > > > > >> > > > > > > > > > >> [   25.218127][    C0]  vprintk_deferre=
d+0x90/0xed
> > > > > > >> > > > > > > > > > >> [   25.218714][    C0]  printk_deferred=
+0x186/0x1d3
> > > > > > >> > > > > > > > > > >> [   25.219353][    C0]  __printk_safe_f=
lush+0x72e/0xc00
> > > > > > >> > > > > > > > > > >> [   25.220006][    C0]  ? printk_safe_f=
lush+0x1e0/0x1e0
> > > > > > >> > > > > > > > > > >> [   25.220635][    C0]  irq_work_run+0x=
1ad/0x5c0
> > > > > > >> > > > > > > > > > >> [   25.221210][    C0]  ? flat_init_api=
c_ldr+0x170/0x170
> > > > > > >> > > > > > > > > > >> [   25.221851][    C0]  smp_irq_work_in=
terrupt+0x237/0x3e0
> > > > > > >> > > > > > > > > > >> [   25.222520][    C0]  irq_work_interr=
upt+0x2e/0x40
> > > > > > >> > > > > > > > > > >> [   25.223110][    C0]  </IRQ>
> > > > > > >> > > > > > > > > > >> [   25.223475][    C0] RIP: 0010:kmem_c=
ache_init_late+0x0/0xb
> > > > > > >> > > > > > > > > > >> [   25.224164][    C0] Code: d4 e8 5d d=
d 2e f2 e9 74 fe ff ff 48 89 d3
> > > > > > >> > > > > > > > > > >> 8b 7d d4 e8 cd d7 2e f2 89 c0 48 89 c1 =
48 c1 e1 20 48 09 c1 48 89 0b
> > > > > > >> > > > > > > > > > >> e9 81 fe ff ff <55> 48 89 e5 e8 20 de 2=
e1
> > > > > > >> > > > > > > > > > >> [   25.226526][    C0] RSP: 0000:ffffff=
ff8f40feb8 EFLAGS: 00000246
> > > > > > >> > > > > > > > > > >> ORIG_RAX: ffffffffffffff09
> > > > > > >> > > > > > > > > > >> [   25.227548][    C0] RAX: ffff88813f9=
95785 RBX: 0000000000000000
> > > > > > >> > > > > > > > > > >> RCX: 0000000000000000
> > > > > > >> > > > > > > > > > >> [   25.228511][    C0] RDX: ffff88813f2=
b0784 RSI: 0000160000000000
> > > > > > >> > > > > > > > > > >> RDI: 0000000000000785
> > > > > > >> > > > > > > > > > >> [   25.229473][    C0] RBP: ffffffff8f4=
0ff20 R08: 000000000fac3785
> > > > > > >> > > > > > > > > > >> R09: 0000778000000001
> > > > > > >> > > > > > > > > > >> [   25.230440][    C0] R10: ffffd0fffff=
fffff R11: 0000100000000000
> > > > > > >> > > > > > > > > > >> R12: 0000000000000000
> > > > > > >> > > > > > > > > > >> [   25.231403][    C0] R13: 00000000000=
00000 R14: ffffffff8fb8cfd0
> > > > > > >> > > > > > > > > > >> R15: 0000000000000000
> > > > > > >> > > > > > > > > > >> [   25.232407][    C0]  ? start_kernel+=
0x5d8/0xb38
> > > > > > >> > > > > > > > > > >> [   25.233003][    C0]  x86_64_start_re=
servations+0x19/0x2f
> > > > > > >> > > > > > > > > > >> [   25.233670][    C0]  x86_64_start_ke=
rnel+0x84/0x87
> > > > > > >> > > > > > > > > > >> [   25.234314][    C0]  secondary_start=
up_64+0xa4/0xb0
> > > > > > >> > > > > > > > > > >> [   25.234949][    C0]
> > > > > > >> > > > > > > > > > >> [   25.235231][    C0] Local variable d=
escription: ----flags.i.i.i@vprintk_emit
> > > > > > >> > > > > > > > > > >> [   25.236101][    C0] Variable was cre=
ated at:
> > > > > > >> > > > > > > > > > >> [   25.236643][    C0]  vprintk_emit+0x=
f4/0x800
> > > > > > >> > > > > > > > > > >> [   25.237188][    C0]  vprintk_deferre=
d+0x90/0xed
> > > > > > >> > > > > > > > > > >> [   25.237752][    C0]
> > > > > > >> > > > > > > > > > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D
> > > > > > >> > > > > > > > > > >> [   25.239117][    C0]  x86_64_start_ke=
rnel+0x84/0x87
> > > > > > >> > > > > > > > > > >> [   25.239123][    C0]
> > > > > > >> > > > > > > > > > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D
> > > > > > >> > > > > > > > > > >> [   25.240704][    C0] BUG: KMSAN: unin=
it-value in vprintk_emit+0x443/0x800
> > > > > > >> > > > > > > > > > >> [   25.241540][    C0] CPU: 0 PID: 0 Co=
mm: swapper/0 Tainted: G    B
> > > > > > >> > > > > > > > > > >>           5.1.0 #5
> > > > > > >> > > > > > > > > > >> [   25.242512][    C0] Hardware name: R=
ed Hat KVM, BIOS
> > > > > > >> > > > > > > > > > >> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 0=
4/01/2014
> > > > > > >> > > > > > > > > > >> [   25.243635][    C0] Call Trace:
> > > > > > >> > > > > > > > > > >> [   25.244038][    C0]  <IRQ>
> > > > > > >> > > > > > > > > > >> [   25.244390][    C0]  dump_stack+0x13=
4/0x190
> > > > > > >> > > > > > > > > > >> [   25.244940][    C0]  kmsan_report+0x=
131/0x2a0
> > > > > > >> > > > > > > > > > >> [   25.245515][    C0]  __msan_warning+=
0x7a/0xf0
> > > > > > >> > > > > > > > > > >> [   25.246082][    C0]  vprintk_emit+0x=
443/0x800
> > > > > > >> > > > > > > > > > >> [   25.246638][    C0]  ? __msan_metada=
ta_ptr_for_store_1+0x13/0x20
> > > > > > >> > > > > > > > > > >> [   25.247430][    C0]  vprintk_deferre=
d+0x90/0xed
> > > > > > >> > > > > > > > > > >> [   25.248018][    C0]  printk_deferred=
+0x186/0x1d3
> > > > > > >> > > > > > > > > > >> [   25.248650][    C0]  __printk_safe_f=
lush+0x72e/0xc00
> > > > > > >> > > > > > > > > > >> [   25.249320][    C0]  ? printk_safe_f=
lush+0x1e0/0x1e0
> > > > > > >> > > > > > > > > > >> [   25.249949][    C0]  irq_work_run+0x=
1ad/0x5c0
> > > > > > >> > > > > > > > > > >> [   25.250524][    C0]  ? flat_init_api=
c_ldr+0x170/0x170
> > > > > > >> > > > > > > > > > >> [   25.251167][    C0]  smp_irq_work_in=
terrupt+0x237/0x3e0
> > > > > > >> > > > > > > > > > >> [   25.251837][    C0]  irq_work_interr=
upt+0x2e/0x40
> > > > > > >> > > > > > > > > > >> [   25.252424][    C0]  </IRQ>
> > > > > > >> > > > > > > > > > >> ....
> > > > > > >> > > > > > > > > > >>
> > > > > > >> > > > > > > > > > >>
> > > > > > >> > > > > > > > > > >> I couldn't even log in.
> > > > > > >> > > > > > > > > > >>
> > > > > > >> > > > > > > > > > >> how should I use qemu with wheezy.img t=
o start a kmsan kernel?
> > > > > > >> > > > > > > > > > >>
> > > > > > >> > > > > > > > > > >> Thanks.
> > > > > > >> > > > > > > > >
> > > > > > >> > > > > > > > >
> > > > > > >> > > > > > > > >
> > > > > > >> > > > > > > > > --
> > > > > > >> > > > > > > > > Alexander Potapenko
> > > > > > >> > > > > > > > > Software Engineer
> > > > > > >> > > > > > > > >
> > > > > > >> > > > > > > > > Google Germany GmbH
> > > > > > >> > > > > > > > > Erika-Mann-Stra=C3=9Fe, 33
> > > > > > >> > > > > > > > > 80636 M=C3=BCnchen
> > > > > > >> > > > > > > > >
> > > > > > >> > > > > > > > > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Hal=
imah DeLaine Prado
> > > > > > >> > > > > > > > > Registergericht und -nummer: Hamburg, HRB 86=
891
> > > > > > >> > > > > > > > > Sitz der Gesellschaft: Hamburg
> > > > > > >> > > > > > > >
> > > > > > >> > > > > > > >
> > > > > > >> > > > > > > >
> > > > > > >> > > > > > > > --
> > > > > > >> > > > > > > > Alexander Potapenko
> > > > > > >> > > > > > > > Software Engineer
> > > > > > >> > > > > > > >
> > > > > > >> > > > > > > > Google Germany GmbH
> > > > > > >> > > > > > > > Erika-Mann-Stra=C3=9Fe, 33
> > > > > > >> > > > > > > > 80636 M=C3=BCnchen
> > > > > > >> > > > > > > >
> > > > > > >> > > > > > > > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halim=
ah DeLaine Prado
> > > > > > >> > > > > > > > Registergericht und -nummer: Hamburg, HRB 8689=
1
> > > > > > >> > > > > > > > Sitz der Gesellschaft: Hamburg
> > > > > > >> > > > > >
> > > > > > >> > > > > >
> > > > > > >> > > > > >
> > > > > > >> > > > > > --
> > > > > > >> > > > > > Alexander Potapenko
> > > > > > >> > > > > > Software Engineer
> > > > > > >> > > > > >
> > > > > > >> > > > > > Google Germany GmbH
> > > > > > >> > > > > > Erika-Mann-Stra=C3=9Fe, 33
> > > > > > >> > > > > > 80636 M=C3=BCnchen
> > > > > > >> > > > > >
> > > > > > >> > > > > > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah D=
eLaine Prado
> > > > > > >> > > > > > Registergericht und -nummer: Hamburg, HRB 86891
> > > > > > >> > > > > > Sitz der Gesellschaft: Hamburg
> > > > > > >> > > >
> > > > > > >> > > >
> > > > > > >> > > >
> > > > > > >> > > > --
> > > > > > >> > > > Alexander Potapenko
> > > > > > >> > > > Software Engineer
> > > > > > >> > > >
> > > > > > >> > > > Google Germany GmbH
> > > > > > >> > > > Erika-Mann-Stra=C3=9Fe, 33
> > > > > > >> > > > 80636 M=C3=BCnchen
> > > > > > >> > > >
> > > > > > >> > > > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLai=
ne Prado
> > > > > > >> > > > Registergericht und -nummer: Hamburg, HRB 86891
> > > > > > >> > > > Sitz der Gesellschaft: Hamburg
> > > > > > >> >
> > > > > > >> >
> > > > > > >> >
> > > > > > >> > --
> > > > > > >> > Alexander Potapenko
> > > > > > >> > Software Engineer
> > > > > > >> >
> > > > > > >> > Google Germany GmbH
> > > > > > >> > Erika-Mann-Stra=C3=9Fe, 33
> > > > > > >> > 80636 M=C3=BCnchen
> > > > > > >> >
> > > > > > >> > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine P=
rado
> > > > > > >> > Registergericht und -nummer: Hamburg, HRB 86891
> > > > > > >> > Sitz der Gesellschaft: Hamburg
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
> > > --
> > > You received this message because you are subscribed to the Google Gr=
oups "kasan-dev" group.
> > > To unsubscribe from this group and stop receiving emails from it, sen=
d an email to kasan-dev+unsubscribe@googlegroups.com.
> > > To post to this group, send email to kasan-dev@googlegroups.com.
> > > To view this discussion on the web visit https://groups.google.com/d/=
msgid/kasan-dev/CADvbK_d8HnKu%2BoSGha4w2wWRmQW8w%2BmqxJDnqDqezZEvVd-_7A%40m=
ail.gmail.com.
> > > For more options, visit https://groups.google.com/d/optout.
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
kasan-dev/CAG_fn%3DVwPNAn0t7XYQH%2B4HgaSrFWFm_1cY9aguvS%3Di%2BGq4EUDQ%40mai=
l.gmail.com.
For more options, visit https://groups.google.com/d/optout.
