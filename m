Return-Path: <kasan-dev+bncBCWPNP5RT4JRB4WR6HUAKGQEBFV2VRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id D8C575DFF3
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jul 2019 10:36:02 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id z202sf276978wmc.9
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jul 2019 01:36:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1562142962; cv=pass;
        d=google.com; s=arc-20160816;
        b=p74/+9uDJcFBcqXLA43apZHZUu7QQ8kk5y9TRPkeqdKA/BiqlSF94I5yWW8SUTBQjW
         4tNs7CBVVvaDU46jKrK+VVZP16gf2BO+BCfnShdBrfL7+/YZoQRq6gZayH2qu4Tk1rmd
         3wP4glUxFQn07zqdCZaw4k2c3nzBjLvzOqK2B6IhV6zqrUQddtmP/Hj3xS3KgNQHlxpF
         iX3rvKWT6NhVToohQQ7bRP0nIm0+XsXURl86Ku1koWRt3azgqIl9sF+OcfN7Y+CgczOh
         v47BwBU0pLx1cYvAqLiAMmpUHnDk3kblgL8JraTpE5x2kyhM0NoenfQspogsvzxzAcUk
         Reeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=KqsrAkF/l6z4V3OiHV0SCrJG4hHxBH94pHUUldXoKE0=;
        b=T/0rweq+GXLNlWphcgwRxvgw4B9iYr9vNxg1BLqMQ6TxJfiw2ekBZN/idyhGPGZ8zu
         h5Kl6qNOYtpBx2fiHnnYXau6q4E6AdKz6XjaW3YZjE0DpBRX1bsoclUeXMyhMAWhtrOh
         LXvFloCMHpfthZbipV5IVo7JvHn1Egg2arMwB6oAwclwioEyIlY2e+BiRy+aS+rdiGMQ
         tL3ASDRNbxB0A2u4Fcn3eI5I874QijWSP3JVS9TdUsO+ycX4FCbd8Dez4Hqh9GDfFhz9
         McIPrMD0fI973t26FOt7Yz/AuFfUN5X4wojCZ58O23Os4y13AXlOVIbr17gTcpluaf51
         thWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=aWJB9QKh;
       spf=pass (google.com: domain of lucien.xin@gmail.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=lucien.xin@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KqsrAkF/l6z4V3OiHV0SCrJG4hHxBH94pHUUldXoKE0=;
        b=nTl3K89Eq4d9ZH7MPOsxL8YlKwm+w0GgNuwHT0pyxiivG1s/8+uOvApCSslZf75740
         JBSU+hsssAQ+FIMm1dIvShHNNZpHbXzfyyu3AsAYV/pIb4wHQ0Z3bek3a1GSF4I/KrLP
         LjT6Jzj+bZMPGemPDe7nX1OSmu7frcxlmwUFm1mTGxuwrslicmr2BzDReGv8ujwyibID
         i5gSDTLtipZYC63TTWl36Iq/oFB+n/AJrMiIvDfuQtBGfEapqkFU+LMJfyXIlEep2Gcp
         xDwl2dnucqVWfJ8yFOsFBdxG98H6DK024WxloD+BLne1OY74gy/rwS9UlNRMXegN3QrI
         uSEQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KqsrAkF/l6z4V3OiHV0SCrJG4hHxBH94pHUUldXoKE0=;
        b=VZ5bc7BuTddo4wB6vNH/CmT1Gt9o4umU1EGLqZZ+OkwOajrkYeoY2A6R0XIrKm17jm
         5amYXa4K8RnD2i7hRn+NgXA0GssAJ1Wrmy1sgql43Z1cee46sVBaL0VaX1bgrNbN5IOi
         0hspvc3fnJRkyIh/Qpf26w80neXoRhkXNWiA955l5XLI8IqNW33i8IFO5qI0FIe2HvCg
         1xr2mejiTrQTGgJhoIY3Pjw2y5u4KrFiF+hc68axb0Eqbq4niLsCDL+2wcSDHZQcptWn
         UzDSNW8yrGAl67ni0zILSD8nL69MxpdljbCC6PexGhqpVPRxbmGYbDzTAPzq5Eb8YIwq
         0Zbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=KqsrAkF/l6z4V3OiHV0SCrJG4hHxBH94pHUUldXoKE0=;
        b=NZivYckt4C7eY3jOig+QNrYLl/snggcnzzJL5IW4Ll5mwwIXAhziXMDKRGjDqy/jIc
         H7DRJ6XMKy+k9ZB7EK18tiAsmA3gdD1d0V19N35wsDldl0fpiOILxc18tWKldKCAoVjc
         Eey+WgxeptynPwlVTDOREFWKgq1Nb2LSmVZYA4w2SBiESi5p7Xro6zrG09yuVSXn8Ifs
         Xpx0P0RaQQ1syhgGrREILgFMOw3Vzl8D52KfpVGvjAyvhd/D6RhB/jG8DuC3BaXOQAr0
         7oWvcKXAVBEnhDfY7h6vn6RfWHoO8DW5XodF2gF8NONJMAqk1GEyfWiK6ALmoGgAVcIz
         qUfQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXv2WugRL/+uYniM7X8DVLRsHH9oelUZeurswfYyBNnZmi/CM9J
	ft/8uwODKCdKqtPYDdQX1ao=
X-Google-Smtp-Source: APXvYqwaRYqre8d66Q3RuN7CzaLmIJ7eyT8tgeS7pmIiP7EQk71DSRi4pfd8Ik/F5V0rU31kOBn89Q==
X-Received: by 2002:a5d:5189:: with SMTP id k9mr7972546wrv.45.1562142962511;
        Wed, 03 Jul 2019 01:36:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:a557:: with SMTP id o84ls431369wme.3.gmail; Wed, 03 Jul
 2019 01:36:01 -0700 (PDT)
X-Received: by 2002:a1c:9d48:: with SMTP id g69mr7359861wme.31.1562142961938;
        Wed, 03 Jul 2019 01:36:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1562142961; cv=none;
        d=google.com; s=arc-20160816;
        b=qC/gpyo2v4537TQK61QSjGswuY5jXFRJVsKZPShGbreGGLLTLQJUuUC0vaDboFyaN2
         N8/hWKEgPEdf8wN2wOCVEvJJ6drWQyamgjKCqdVd5z6mOXrCyK32lrBjksjLttelhqrM
         seT/ZkbJYCqIxBw+qjyyjTLdIbLSBAFP38RP4tlX5FEG5rhSPhDA0whk7ESH2JSuh80f
         TlTdWdvME8MsQQRPjJ7PrqcTBJY4IEMdFYmio82nUzWTaOIZqChJkknUtxBc4CNu74ro
         wf2iRYgFfOzbGnDtnzJ3/mfBGyvq3ihhec9iyFi9tZJbQB+P2OlGO4dXySAqmAJrpRPT
         +e8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=FDGK779JsBE5S3VoMi3AJtHGbuHf3kkpVKADbdqYbpo=;
        b=Ga7JkvVDWmmODC2qigzONqqys7uIfrdojMqzIygAJSEj3UmwNCYkRXlC13nh0eVWoa
         QFesNT4G8NTntCV1LZ/qkiuQPu36m3fAHIM52dd2+wKCPC4HVQZPdDHJ5HXdTBangR/d
         mUH2T5PGCk4q1Eir5Pbccu2RvlXNb6aE3C9vO7Bwy/a4pXbEkg9szosLjMXs9rhDIS/I
         umTgKTvoVzjS70gZzuGwlclS0bFOOC8r1zVnZbt09h883gQALbCh6rCSrMlgwehRLNEK
         0ds+g9YEesPNjFHnGnVC6kvVm88ey4GwaT2sx4VRDQru/hNKeWsqfPmQ6TOAjnQo/iIf
         ztQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=aWJB9QKh;
       spf=pass (google.com: domain of lucien.xin@gmail.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=lucien.xin@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x442.google.com (mail-wr1-x442.google.com. [2a00:1450:4864:20::442])
        by gmr-mx.google.com with ESMTPS id v21si82083wmc.2.2019.07.03.01.36.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Wed, 03 Jul 2019 01:36:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of lucien.xin@gmail.com designates 2a00:1450:4864:20::442 as permitted sender) client-ip=2a00:1450:4864:20::442;
Received: by mail-wr1-x442.google.com with SMTP id a10so638658wrp.9
        for <kasan-dev@googlegroups.com>; Wed, 03 Jul 2019 01:36:01 -0700 (PDT)
X-Received: by 2002:a5d:5386:: with SMTP id d6mr20181069wrv.207.1562142961385;
 Wed, 03 Jul 2019 01:36:01 -0700 (PDT)
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
 <CADvbK_d8HnKu+oSGha4w2wWRmQW8w+mqxJDnqDqezZEvVd-_7A@mail.gmail.com> <CAG_fn=WS1NBRiaH_s_W9fa_qMTV3yKkmseiH6ZUK3iL7Mu3EAA@mail.gmail.com>
In-Reply-To: <CAG_fn=WS1NBRiaH_s_W9fa_qMTV3yKkmseiH6ZUK3iL7Mu3EAA@mail.gmail.com>
From: Xin Long <lucien.xin@gmail.com>
Date: Wed, 3 Jul 2019 16:35:44 +0800
Message-ID: <CADvbK_dGFV5XTVebK6YJNnBQJGPF=mi03wkyVM=mmt_uqFgzag@mail.gmail.com>
Subject: Re: how to start kmsan kernel with qemu
To: Alexander Potapenko <glider@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Dmitriy Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: lucien.xin@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=aWJB9QKh;       spf=pass
 (google.com: domain of lucien.xin@gmail.com designates 2a00:1450:4864:20::442
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

On Tue, Jul 2, 2019 at 9:32 PM Alexander Potapenko <glider@google.com> wrot=
e:
>
> https://reviews.llvm.org/D64072 seems to fix the problem. I hope to
> land this patch soon, in the meantime you can apply it to your Clang.
It worked perfectly, thanks!

> Thanks for your help tracking the bug down!
>
> On Tue, Jul 2, 2019 at 11:39 AM Xin Long <lucien.xin@gmail.com> wrote:
> >
> > On Tue, Jul 2, 2019 at 5:32 PM Alexander Potapenko <glider@google.com> =
wrote:
> > >
> > > Ah, I see.
> > > You build with assertions enabled, I for some reason did not.
> > > There's really a bug in KMSAN instrumentation, I'll fix it.
> > Thanks, great that you figured it out so quickly.
> > I'm waiting. :-)
> >
> > >
> > > On Fri, Jun 28, 2019 at 7:24 PM Xin Long <lucien.xin@gmail.com> wrote=
:
> > > >
> > > > On Sat, Jun 29, 2019 at 1:18 AM Xin Long <lucien.xin@gmail.com> wro=
te:
> > > > >
> > > > > # cd /home/tools/
> > > > > # git clone https://github.com/llvm/llvm-project.git
> > > > > # cd llvm-project/
> > > > > # mkdir build
> > > > > # cd build/
> > > > > # cmake -DLLVM_ENABLE_PROJECTS=3Dclang -DCMAKE_BUILD_TYPE=3DRelea=
se
> > > > > -DLLVM_ENABLE_ASSERTIONS=3DON -G "Unix Makefiles" ../llvm
> > > > the output is:
> > > > https://paste.fedoraproject.org/paste/D9-QpmZnDcXkr4AykumRnw
> > > > myabe you can have a vimdiff for the outputs of yours and mine.
> > > >
> > > > > # make
> > > > sorry, it was # make -j64
> > > >
> > > > > # cd /home/kmsan
> > > > > # git checkout f75e4cfea97f
> > > > > (use the .config I sent you last time)
> > > > > # make CC=3D/home/tools/llvm-project/build/bin/clang -j64 -k LOCA=
LVERSION=3D 2>&1
> > > > >
> > > > > These are the whole thing I did to build it.
> > > > >
> > > > > On Sat, Jun 29, 2019 at 12:09 AM Alexander Potapenko <glider@goog=
le.com> wrote:
> > > > > >
> > > > > > Hm, now that's your Clang binary versus mine :)
> > > > > > Can you please ensure your git repo doesn't contain local chang=
es and share the commands you're using to build Clang?
> > > > > > (Both cmake and make or ninja)
> > > > > No any local changes on both llvm-project and kmsan
> > > > >
> > > > > > Is the bug still reproducible in a clean CMake directory?
> > > > > A clean CMake directory? how to clean it? something like: # cmake=
 clean
> > > > >
> > > > > Thank you for being so patient. :-)
> > > > >
> > > > > >
> > > > > > On Fri, 28 Jun 2019, 16:20 Xin Long, <lucien.xin@gmail.com> wro=
te:
> > > > > >>
> > > > > >> yes
> > > > > >>
> > > > > >> https://paste.fedoraproject.org/paste/DU2nnxpZWpWMri9Up7hypA
> > > > > >>
> > > > > >> On Fri, Jun 28, 2019 at 9:48 PM Alexander Potapenko <glider@go=
ogle.com> wrote:
> > > > > >> >
> > > > > >> > Hm, strange, but I still can compile this file.
> > > > > >> > Does the following command line crash your compiler?
> > > > > >> > https://paste.fedoraproject.org/paste/oJwOVm5cHWyd7hxIZ4uGeA=
 (note it
> > > > > >> > should be run from the same directory where process_64.i res=
ides; also
> > > > > >> > make sure to invoke the right Clang)
> > > > > >> >
> > > > > >> > On Fri, Jun 28, 2019 at 3:35 PM Xin Long <lucien.xin@gmail.c=
om> wrote:
> > > > > >> > >
> > > > > >> > > As attached, thanks.
> > > > > >> > >
> > > > > >> > > On Fri, Jun 28, 2019 at 9:24 PM Alexander Potapenko <glide=
r@google.com> wrote:
> > > > > >> > > >
> > > > > >> > > > On Fri, Jun 28, 2019 at 3:10 PM Xin Long <lucien.xin@gma=
il.com> wrote:
> > > > > >> > > > >
> > > > > >> > > > > This is what I did:
> > > > > >> > > > > https://paste.fedoraproject.org/paste/q4~GWx9Sx~QUbJQf=
NDoJIw
> > > > > >> > > > >
> > > > > >> > > > > There's no process_64.i file generated.
> > > > > >> > > > >
> > > > > >> > > > > Btw, I couldn't find "-c" in the command line, so ther=
e was no "-E" added.
> > > > > >> > > > Ah, right, Clang is invoked with -S. Could you replace t=
hat one with -E?
> > > > > >> > > > > On Fri, Jun 28, 2019 at 8:40 PM Alexander Potapenko <g=
lider@google.com> wrote:
> > > > > >> > > > > >
> > > > > >> > > > > > It's interesting that you're seeing the same error a=
s reported here:
> > > > > >> > > > > > https://github.com/google/kmsan/issues/53
> > > > > >> > > > > > I've updated my Clang to a4771e9dfdb0485c2edb416bfdc=
479d49de0aa14, but
> > > > > >> > > > > > the kernel compiles just fine.
> > > > > >> > > > > > May I ask you to do the following:
> > > > > >> > > > > >
> > > > > >> > > > > >  - run `make V=3D1` to capture the command line used=
 to build
> > > > > >> > > > > > arch/x86/kernel/process_64.o
> > > > > >> > > > > >  - copy and paste the command line into a shell, rem=
ove '-o
> > > > > >> > > > > > /tmp/somefile' and run again to make sure the compil=
er still crashes
> > > > > >> > > > > >  - replace '-c' with '-E' in the command line and ad=
d '-o
> > > > > >> > > > > > process_64.i' to the end
> > > > > >> > > > > >  - send me the resulting preprocessed file (process_=
64.i)
> > > > > >> > > > > >
> > > > > >> > > > > > Thanks!
> > > > > >> > > > > >
> > > > > >> > > > > >
> > > > > >> > > > > >
> > > > > >> > > > > > On Thu, Jun 27, 2019 at 4:45 PM Xin Long <lucien.xin=
@gmail.com> wrote:
> > > > > >> > > > > > >
> > > > > >> > > > > > > Now I'm using:
> > > > > >> > > > > > > # Compiler: clang version 9.0.0
> > > > > >> > > > > > > (https://github.com/llvm/llvm-project.git
> > > > > >> > > > > > > a056684c335995214f6d3467c699d32f8e73b763)
> > > > > >> > > > > > >
> > > > > >> > > > > > > Errors shows up when building the kernel:
> > > > > >> > > > > > >
> > > > > >> > > > > > >   CC      arch/x86/kernel/process_64.o
> > > > > >> > > > > > > clang-9: /home/tools/llvm-project/llvm/lib/Transfo=
rms/Instrumentation/MemorySanitizer.cpp:3236:
> > > > > >> > > > > > > void {anonymous}::MemorySanitizerVisitor::visitCal=
lSite(llvm::CallSite):
> > > > > >> > > > > > > Assertion `(CS.isCall() || CS.isInvoke()) && "Unkn=
own type of
> > > > > >> > > > > > > CallSite"' failed.
> > > > > >> > > > > > > Stack dump:
> > > > > >> > > > > > > 0.      Program arguments: /home/tools/llvm-projec=
t/build/bin/clang-9
> > > > > >> > > > > > > -cc1 -triple x86_64-unknown-linux-gnu -S -disable-=
free -main-file-name
> > > > > >> > > > > > > process_64.c -mrelocation-model static -mthread-mo=
del posix
> > > > > >> > > > > > > -fno-delete-null-pointer-checks -mllvm -warn-stack=
-size=3D2048
> > > > > >> > > > > > > -mdisable-fp-elim -relaxed-aliasing -mdisable-tail=
-calls -fmath-errno
> > > > > >> > > > > > > -masm-verbose -no-integrated-as -mconstructor-alia=
ses -fuse-init-array
> > > > > >> > > > > > > -mcode-model kernel -target-cpu core2 -target-feat=
ure
> > > > > >> > > > > > > +retpoline-indirect-calls -target-feature +retpoli=
ne-indirect-branches
> > > > > >> > > > > > > -target-feature -sse -target-feature -mmx -target-=
feature -sse2
> > > > > >> > > > > > > -target-feature -3dnow -target-feature -avx -targe=
t-feature -x87
> > > > > >> > > > > > > -target-feature +retpoline-external-thunk -disable=
-red-zone
> > > > > >> > > > > > > -dwarf-column-info -debug-info-kind=3Dlimited -dwa=
rf-version=3D4
> > > > > >> > > > > > > -debugger-tuning=3Dgdb -momit-leaf-frame-pointer -=
coverage-notes-file
> > > > > >> > > > > > > /home/kmsan/arch/x86/kernel/process_64.gcno -nostd=
systeminc
> > > > > >> > > > > > > -nobuiltininc -resource-dir
> > > > > >> > > > > > > /home/tools/llvm-project/build/lib/clang/9.0.0 -de=
pendency-file
> > > > > >> > > > > > > arch/x86/kernel/.process_64.o.d -MT arch/x86/kerne=
l/process_64.o
> > > > > >> > > > > > > -sys-header-deps -isystem
> > > > > >> > > > > > > /home/tools/llvm-project/build/lib/clang/9.0.0/inc=
lude -include
> > > > > >> > > > > > > ./include/linux/kconfig.h -include ./include/linux=
/compiler_types.h -I
> > > > > >> > > > > > > ./arch/x86/include -I ./arch/x86/include/generated=
 -I ./include -I
> > > > > >> > > > > > > ./arch/x86/include/uapi -I ./arch/x86/include/gene=
rated/uapi -I
> > > > > >> > > > > > > ./include/uapi -I ./include/generated/uapi -D __KE=
RNEL__ -D
> > > > > >> > > > > > > CONFIG_X86_X32_ABI -D CONFIG_AS_CFI=3D1 -D CONFIG_=
AS_CFI_SIGNAL_FRAME=3D1
> > > > > >> > > > > > > -D CONFIG_AS_CFI_SECTIONS=3D1 -D CONFIG_AS_SSSE3=
=3D1 -D CONFIG_AS_AVX=3D1 -D
> > > > > >> > > > > > > CONFIG_AS_AVX2=3D1 -D CONFIG_AS_AVX512=3D1 -D CONF=
IG_AS_SHA1_NI=3D1 -D
> > > > > >> > > > > > > CONFIG_AS_SHA256_NI=3D1 -D KBUILD_BASENAME=3D"proc=
ess_64" -D
> > > > > >> > > > > > > KBUILD_MODNAME=3D"process_64" -O2 -Wall -Wundef
> > > > > >> > > > > > > -Werror=3Dstrict-prototypes -Wno-trigraphs
> > > > > >> > > > > > > -Werror=3Dimplicit-function-declaration -Werror=3D=
implicit-int
> > > > > >> > > > > > > -Wno-format-security -Wno-sign-compare -Wno-addres=
s-of-packed-member
> > > > > >> > > > > > > -Wno-format-invalid-specifier -Wno-gnu -Wno-tautol=
ogical-compare
> > > > > >> > > > > > > -Wno-unused-const-variable -Wdeclaration-after-sta=
tement -Wvla
> > > > > >> > > > > > > -Wno-pointer-sign -Werror=3Ddate-time -Werror=3Din=
compatible-pointer-types
> > > > > >> > > > > > > -Wno-initializer-overrides -Wno-unused-value -Wno-=
format
> > > > > >> > > > > > > -Wno-sign-compare -Wno-format-zero-length -Wno-uni=
nitialized
> > > > > >> > > > > > > -std=3Dgnu89 -fno-dwarf-directory-asm -fdebug-comp=
ilation-dir
> > > > > >> > > > > > > /home/kmsan -ferror-limit 19 -fmessage-length 0
> > > > > >> > > > > > > -fsanitize=3Dkernel-memory -fwrapv -stack-protecto=
r 2
> > > > > >> > > > > > > -mstack-alignment=3D8 -fwchar-type=3Dshort -fno-si=
gned-wchar
> > > > > >> > > > > > > -fobjc-runtime=3Dgcc -fno-common -fdiagnostics-sho=
w-option
> > > > > >> > > > > > > -fcolor-diagnostics -vectorize-loops -vectorize-sl=
p -o
> > > > > >> > > > > > > /tmp/process_64-e20ead.s -x c arch/x86/kernel/proc=
ess_64.c
> > > > > >> > > > > > > 1.      <eof> parser at end of file
> > > > > >> > > > > > > 2.      Per-module optimization passes
> > > > > >> > > > > > > 3.      Running pass 'Function Pass Manager' on mo=
dule
> > > > > >> > > > > > > 'arch/x86/kernel/process_64.c'.
> > > > > >> > > > > > > 4.      Running pass 'MemorySanitizerLegacyPass' o=
n function '@start_thread'
> > > > > >> > > > > > >  #0 0x00000000024f03ba llvm::sys::PrintStackTrace(=
llvm::raw_ostream&)
> > > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x24f0=
3ba)
> > > > > >> > > > > > >  #1 0x00000000024ee214 llvm::sys::RunSignalHandler=
s()
> > > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x24ee=
214)
> > > > > >> > > > > > >  #2 0x00000000024ee375 SignalHandler(int)
> > > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x24ee=
375)
> > > > > >> > > > > > >  #3 0x00007f85ed99bd80 __restore_rt (/lib64/libpth=
read.so.0+0x12d80)
> > > > > >> > > > > > >  #4 0x00007f85ec47c93f raise (/lib64/libc.so.6+0x3=
793f)
> > > > > >> > > > > > >  #5 0x00007f85ec466c95 abort (/lib64/libc.so.6+0x2=
1c95)
> > > > > >> > > > > > >  #6 0x00007f85ec466b69 _nl_load_domain.cold.0 (/li=
b64/libc.so.6+0x21b69)
> > > > > >> > > > > > >  #7 0x00007f85ec474df6 (/lib64/libc.so.6+0x2fdf6)
> > > > > >> > > > > > >  #8 0x000000000327b864 (anonymous
> > > > > >> > > > > > > namespace)::MemorySanitizerVisitor::visitCallSite(=
llvm::CallSite)
> > > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x327b=
864)
> > > > > >> > > > > > >  #9 0x0000000003283036 (anonymous
> > > > > >> > > > > > > namespace)::MemorySanitizerVisitor::runOnFunction(=
)
> > > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x3283=
036)
> > > > > >> > > > > > > #10 0x000000000328605f (anonymous
> > > > > >> > > > > > > namespace)::MemorySanitizer::sanitizeFunction(llvm=
::Function&,
> > > > > >> > > > > > > llvm::TargetLibraryInfo&)
> > > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x3286=
05f)
> > > > > >> > > > > > > #11 0x0000000001f42ac8
> > > > > >> > > > > > > llvm::FPPassManager::runOnFunction(llvm::Function&=
)
> > > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x1f42=
ac8)
> > > > > >> > > > > > > #12 0x0000000001f42be9 llvm::FPPassManager::runOnM=
odule(llvm::Module&)
> > > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x1f42=
be9)
> > > > > >> > > > > > > #13 0x0000000001f41ed8
> > > > > >> > > > > > > llvm::legacy::PassManagerImpl::run(llvm::Module&)
> > > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x1f41=
ed8)
> > > > > >> > > > > > > #14 0x00000000026fa4f8 (anonymous
> > > > > >> > > > > > > namespace)::EmitAssemblyHelper::EmitAssembly(clang=
::BackendAction,
> > > > > >> > > > > > > std::unique_ptr<llvm::raw_pwrite_stream,
> > > > > >> > > > > > > std::default_delete<llvm::raw_pwrite_stream> >)
> > > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x26fa=
4f8)
> > > > > >> > > > > > > #15 0x00000000026fbbf8
> > > > > >> > > > > > > clang::EmitBackendOutput(clang::DiagnosticsEngine&=
,
> > > > > >> > > > > > > clang::HeaderSearchOptions const&, clang::CodeGenO=
ptions const&,
> > > > > >> > > > > > > clang::TargetOptions const&, clang::LangOptions co=
nst&,
> > > > > >> > > > > > > llvm::DataLayout const&, llvm::Module*, clang::Bac=
kendAction,
> > > > > >> > > > > > > std::unique_ptr<llvm::raw_pwrite_stream,
> > > > > >> > > > > > > std::default_delete<llvm::raw_pwrite_stream> >)
> > > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x26fb=
bf8)
> > > > > >> > > > > > > #16 0x000000000310234d
> > > > > >> > > > > > > clang::BackendConsumer::HandleTranslationUnit(clan=
g::ASTContext&)
> > > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x3102=
34d)
> > > > > >> > > > > > > #17 0x0000000003aaddf9 clang::ParseAST(clang::Sema=
&, bool, bool)
> > > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x3aad=
df9)
> > > > > >> > > > > > > #18 0x00000000030fe5e0 clang::CodeGenAction::Execu=
teAction()
> > > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x30fe=
5e0)
> > > > > >> > > > > > > #19 0x0000000002ba1929 clang::FrontendAction::Exec=
ute()
> > > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x2ba1=
929)
> > > > > >> > > > > > > #20 0x0000000002b68e62
> > > > > >> > > > > > > clang::CompilerInstance::ExecuteAction(clang::Fron=
tendAction&)
> > > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x2b68=
e62)
> > > > > >> > > > > > > #21 0x0000000002c5738a
> > > > > >> > > > > > > clang::ExecuteCompilerInvocation(clang::CompilerIn=
stance*)
> > > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x2c57=
38a)
> > > > > >> > > > > > > #22 0x00000000009cd1a6 cc1_main(llvm::ArrayRef<cha=
r const*>, char
> > > > > >> > > > > > > const*, void*) (/home/tools/llvm-project/build/bin=
/clang-9+0x9cd1a6)
> > > > > >> > > > > > > #23 0x000000000094cac1 main
> > > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x94ca=
c1)
> > > > > >> > > > > > > #24 0x00007f85ec468813 __libc_start_main (/lib64/l=
ibc.so.6+0x23813)
> > > > > >> > > > > > > #25 0x00000000009c96ee _start
> > > > > >> > > > > > > (/home/tools/llvm-project/build/bin/clang-9+0x9c96=
ee)
> > > > > >> > > > > > > clang-9: error: unable to execute command: Aborted=
 (core dumped)
> > > > > >> > > > > > > clang-9: error: clang frontend command failed due =
to signal (use -v to
> > > > > >> > > > > > > see invocation)
> > > > > >> > > > > > > clang version 9.0.0 (https://github.com/llvm/llvm-=
project.git
> > > > > >> > > > > > > a056684c335995214f6d3467c699d32f8e73b763)
> > > > > >> > > > > > > Target: x86_64-unknown-linux-gnu
> > > > > >> > > > > > > Thread model: posix
> > > > > >> > > > > > > InstalledDir: /home/tools/llvm-project/build/bin
> > > > > >> > > > > > > clang-9: note: diagnostic msg: PLEASE submit a bug=
 report to
> > > > > >> > > > > > > https://bugs.llvm.org/ and include the crash backt=
race, preprocessed
> > > > > >> > > > > > > source, and associated run script.
> > > > > >> > > > > > > clang-9: note: diagnostic msg:
> > > > > >> > > > > > > ********************
> > > > > >> > > > > > >
> > > > > >> > > > > > > PLEASE ATTACH THE FOLLOWING FILES TO THE BUG REPOR=
T:
> > > > > >> > > > > > > Preprocessed source(s) and associated run script(s=
) are located at:
> > > > > >> > > > > > > clang-9: note: diagnostic msg: /tmp/process_64-5fb=
bdc.c
> > > > > >> > > > > > > clang-9: note: diagnostic msg: /tmp/process_64-5fb=
bdc.sh
> > > > > >> > > > > > > clang-9: note: diagnostic msg:
> > > > > >> > > > > > >
> > > > > >> > > > > > > ********************
> > > > > >> > > > > > > make[2]: *** [scripts/Makefile.build:276:
> > > > > >> > > > > > > arch/x86/kernel/process_64.o] Error 254
> > > > > >> > > > > > >
> > > > > >> > > > > > >
> > > > > >> > > > > > > any idea why?
> > > > > >> > > > > > >
> > > > > >> > > > > > > On Thu, Jun 27, 2019 at 5:23 PM Alexander Potapenk=
o <glider@google.com> wrote:
> > > > > >> > > > > > > >
> > > > > >> > > > > > > > Actually, your config says:
> > > > > >> > > > > > > >   "Compiler: clang version 8.0.0 (trunk 343298)"
> > > > > >> > > > > > > > I think you'll need at least Clang r362410 (mine=
 is r362913)
> > > > > >> > > > > > > >
> > > > > >> > > > > > > > On Thu, Jun 27, 2019 at 11:20 AM Alexander Potap=
enko <glider@google.com> wrote:
> > > > > >> > > > > > > > >
> > > > > >> > > > > > > > > Hi Xin,
> > > > > >> > > > > > > > >
> > > > > >> > > > > > > > > Sorry for the late reply.
> > > > > >> > > > > > > > > I've built the ToT KMSAN tree using your confi=
g and my almost-ToT
> > > > > >> > > > > > > > > Clang and couldn't reproduce the problem.
> > > > > >> > > > > > > > > I believe something is wrong with your Clang v=
ersion, as
> > > > > >> > > > > > > > > CONFIG_CLANG_VERSION should really be 90000.
> > > > > >> > > > > > > > > You can run `make V=3D1` to see which Clang ve=
rsion is being invoked -
> > > > > >> > > > > > > > > make sure it's a fresh one.
> > > > > >> > > > > > > > >
> > > > > >> > > > > > > > > HTH,
> > > > > >> > > > > > > > > Alex
> > > > > >> > > > > > > > >
> > > > > >> > > > > > > > > On Fri, Jun 21, 2019 at 10:09 PM Xin Long <luc=
ien.xin@gmail.com> wrote:
> > > > > >> > > > > > > > > >
> > > > > >> > > > > > > > > > as attached,
> > > > > >> > > > > > > > > >
> > > > > >> > > > > > > > > > It actually came from https://syzkaller.apps=
pot.com/x/.config?x=3D602468164ccdc30a
> > > > > >> > > > > > > > > > after I built, clang version changed to:
> > > > > >> > > > > > > > > >
> > > > > >> > > > > > > > > > CONFIG_CLANG_VERSION=3D80000
> > > > > >> > > > > > > > > >
> > > > > >> > > > > > > > > > On Sat, Jun 22, 2019 at 2:06 AM Alexander Po=
tapenko <glider@google.com> wrote:
> > > > > >> > > > > > > > > > >
> > > > > >> > > > > > > > > > > Hi Xin,
> > > > > >> > > > > > > > > > >
> > > > > >> > > > > > > > > > > Could you please share the config you're u=
sing to build the kernel?
> > > > > >> > > > > > > > > > > I'll take a closer look on Monday when I a=
m back to the office.
> > > > > >> > > > > > > > > > >
> > > > > >> > > > > > > > > > > On Fri, 21 Jun 2019, 18:15 Xin Long, <luci=
en.xin@gmail.com> wrote:
> > > > > >> > > > > > > > > > >>
> > > > > >> > > > > > > > > > >> this is my command:
> > > > > >> > > > > > > > > > >>
> > > > > >> > > > > > > > > > >> /usr/libexec/qemu-kvm -smp 2 -m 4G -enabl=
e-kvm -cpu host \
> > > > > >> > > > > > > > > > >>     -net nic -net user,hostfwd=3Dtcp::100=
22-:22 \
> > > > > >> > > > > > > > > > >>     -kernel /home/kmsan/arch/x86/boot/bzI=
mage -nographic \
> > > > > >> > > > > > > > > > >>     -device virtio-scsi-pci,id=3Dscsi \
> > > > > >> > > > > > > > > > >>     -device scsi-hd,bus=3Dscsi.0,drive=3D=
d0 \
> > > > > >> > > > > > > > > > >>     -drive file=3D/root/test/wheezy.img,f=
ormat=3Draw,if=3Dnone,id=3Dd0 \
> > > > > >> > > > > > > > > > >>     -append "root=3D/dev/sda console=3Dtt=
yS0 earlyprintk=3Dserial rodata=3Dn \
> > > > > >> > > > > > > > > > >>       oops=3Dpanic panic_on_warn=3D1 pani=
c=3D86400 kvm-intel.nested=3D1 \
> > > > > >> > > > > > > > > > >>       security=3Dapparmor ima_policy=3Dtc=
b workqueue.watchdog_thresh=3D140 \
> > > > > >> > > > > > > > > > >>       nf-conntrack-ftp.ports=3D20000 nf-c=
onntrack-tftp.ports=3D20000 \
> > > > > >> > > > > > > > > > >>       nf-conntrack-sip.ports=3D20000 nf-c=
onntrack-irc.ports=3D20000 \
> > > > > >> > > > > > > > > > >>       nf-conntrack-sane.ports=3D20000 viv=
id.n_devs=3D16 \
> > > > > >> > > > > > > > > > >>       vivid.multiplanar=3D1,2,1,2,1,2,1,2=
,1,2,1,2,1,2,1,2 \
> > > > > >> > > > > > > > > > >>       spec_store_bypass_disable=3Dprctl n=
opcid"
> > > > > >> > > > > > > > > > >>
> > > > > >> > > > > > > > > > >> the commit is on:
> > > > > >> > > > > > > > > > >> commit f75e4cfea97f67b7530b8b991b3005f991=
f04778 (HEAD)
> > > > > >> > > > > > > > > > >> Author: Alexander Potapenko <glider@googl=
e.com>
> > > > > >> > > > > > > > > > >> Date:   Wed May 22 12:30:13 2019 +0200
> > > > > >> > > > > > > > > > >>
> > > > > >> > > > > > > > > > >>     kmsan: use kmsan_handle_urb() in urb.=
c
> > > > > >> > > > > > > > > > >>
> > > > > >> > > > > > > > > > >> and when starting, it shows:
> > > > > >> > > > > > > > > > >> [    0.561925][    T0] Kernel command lin=
e: root=3D/dev/sda
> > > > > >> > > > > > > > > > >> console=3DttyS0 earlyprintk=3Dserial roda=
ta=3Dn       oops=3Dpanic
> > > > > >> > > > > > > > > > >> panic_on_warn=3D1 panic=3D86400 kvm-intel=
.nested=3D1       security=3Dad
> > > > > >> > > > > > > > > > >> [    0.707792][    T0] Memory: 3087328K/4=
193776K available (219164K
> > > > > >> > > > > > > > > > >> kernel code, 7059K rwdata, 11712K rodata,=
 5064K init, 11904K bss,
> > > > > >> > > > > > > > > > >> 1106448K reserved, 0K cma-reserved)
> > > > > >> > > > > > > > > > >> [    0.710935][    T0] SLUB: HWalign=3D64=
, Order=3D0-3, MinObjects=3D0,
> > > > > >> > > > > > > > > > >> CPUs=3D2, Nodes=3D1
> > > > > >> > > > > > > > > > >> [    0.711953][    T0] Starting KernelMem=
orySanitizer
> > > > > >> > > > > > > > > > >> [    0.712563][    T0]
> > > > > >> > > > > > > > > > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D
> > > > > >> > > > > > > > > > >> [    0.713657][    T0] BUG: KMSAN: uninit=
-value in mutex_lock+0xd1/0xe0
> > > > > >> > > > > > > > > > >> [    0.714570][    T0] CPU: 0 PID: 0 Comm=
: swapper Not tainted 5.1.0 #5
> > > > > >> > > > > > > > > > >> [    0.715417][    T0] Hardware name: Red=
 Hat KVM, BIOS
> > > > > >> > > > > > > > > > >> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/=
01/2014
> > > > > >> > > > > > > > > > >> [    0.716659][    T0] Call Trace:
> > > > > >> > > > > > > > > > >> [    0.717127][    T0]  dump_stack+0x134/=
0x190
> > > > > >> > > > > > > > > > >> [    0.717727][    T0]  kmsan_report+0x13=
1/0x2a0
> > > > > >> > > > > > > > > > >> [    0.718347][    T0]  __msan_warning+0x=
7a/0xf0
> > > > > >> > > > > > > > > > >> [    0.718952][    T0]  mutex_lock+0xd1/0=
xe0
> > > > > >> > > > > > > > > > >> [    0.719478][    T0]  __cpuhp_setup_sta=
te_cpuslocked+0x149/0xd20
> > > > > >> > > > > > > > > > >> [    0.720260][    T0]  ? vprintk_func+0x=
6b5/0x8a0
> > > > > >> > > > > > > > > > >> [    0.720926][    T0]  ? rb_get_reader_p=
age+0x1140/0x1140
> > > > > >> > > > > > > > > > >> [    0.721632][    T0]  __cpuhp_setup_sta=
te+0x181/0x2e0
> > > > > >> > > > > > > > > > >> [    0.722374][    T0]  ? rb_get_reader_p=
age+0x1140/0x1140
> > > > > >> > > > > > > > > > >> [    0.723115][    T0]  tracer_alloc_buff=
ers+0x16b/0xb96
> > > > > >> > > > > > > > > > >> [    0.723846][    T0]  early_trace_init+=
0x193/0x28f
> > > > > >> > > > > > > > > > >> [    0.724501][    T0]  start_kernel+0x49=
7/0xb38
> > > > > >> > > > > > > > > > >> [    0.725134][    T0]  x86_64_start_rese=
rvations+0x19/0x2f
> > > > > >> > > > > > > > > > >> [    0.725871][    T0]  x86_64_start_kern=
el+0x84/0x87
> > > > > >> > > > > > > > > > >> [    0.726538][    T0]  secondary_startup=
_64+0xa4/0xb0
> > > > > >> > > > > > > > > > >> [    0.727173][    T0]
> > > > > >> > > > > > > > > > >> [    0.727454][    T0] Local variable des=
cription:
> > > > > >> > > > > > > > > > >> ----success.i.i.i.i@mutex_lock
> > > > > >> > > > > > > > > > >> [    0.728379][    T0] Variable was creat=
ed at:
> > > > > >> > > > > > > > > > >> [    0.728977][    T0]  mutex_lock+0x48/0=
xe0
> > > > > >> > > > > > > > > > >> [    0.729536][    T0]  __cpuhp_setup_sta=
te_cpuslocked+0x149/0xd20
> > > > > >> > > > > > > > > > >> [    0.730323][    T0]
> > > > > >> > > > > > > > > > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D
> > > > > >> > > > > > > > > > >> [    0.731364][    T0] Disabling lock deb=
ugging due to kernel taint
> > > > > >> > > > > > > > > > >> [    0.732169][    T0] Kernel panic - not=
 syncing: panic_on_warn set ...
> > > > > >> > > > > > > > > > >> [    0.733047][    T0] CPU: 0 PID: 0 Comm=
: swapper Tainted: G    B
> > > > > >> > > > > > > > > > >>         5.1.0 #5
> > > > > >> > > > > > > > > > >> [    0.734080][    T0] Hardware name: Red=
 Hat KVM, BIOS
> > > > > >> > > > > > > > > > >> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/=
01/2014
> > > > > >> > > > > > > > > > >> [    0.735319][    T0] Call Trace:
> > > > > >> > > > > > > > > > >> [    0.735735][    T0]  dump_stack+0x134/=
0x190
> > > > > >> > > > > > > > > > >> [    0.736308][    T0]  panic+0x3ec/0xb3b
> > > > > >> > > > > > > > > > >> [    0.736826][    T0]  kmsan_report+0x29=
a/0x2a0
> > > > > >> > > > > > > > > > >> [    0.737417][    T0]  __msan_warning+0x=
7a/0xf0
> > > > > >> > > > > > > > > > >> [    0.737973][    T0]  mutex_lock+0xd1/0=
xe0
> > > > > >> > > > > > > > > > >> [    0.738527][    T0]  __cpuhp_setup_sta=
te_cpuslocked+0x149/0xd20
> > > > > >> > > > > > > > > > >> [    0.739342][    T0]  ? vprintk_func+0x=
6b5/0x8a0
> > > > > >> > > > > > > > > > >> [    0.739972][    T0]  ? rb_get_reader_p=
age+0x1140/0x1140
> > > > > >> > > > > > > > > > >> [    0.740695][    T0]  __cpuhp_setup_sta=
te+0x181/0x2e0
> > > > > >> > > > > > > > > > >> [    0.741412][    T0]  ? rb_get_reader_p=
age+0x1140/0x1140
> > > > > >> > > > > > > > > > >> [    0.742160][    T0]  tracer_alloc_buff=
ers+0x16b/0xb96
> > > > > >> > > > > > > > > > >> [    0.742866][    T0]  early_trace_init+=
0x193/0x28f
> > > > > >> > > > > > > > > > >> [    0.743512][    T0]  start_kernel+0x49=
7/0xb38
> > > > > >> > > > > > > > > > >> [    0.744128][    T0]  x86_64_start_rese=
rvations+0x19/0x2f
> > > > > >> > > > > > > > > > >> [    0.744863][    T0]  x86_64_start_kern=
el+0x84/0x87
> > > > > >> > > > > > > > > > >> [    0.745534][    T0]  secondary_startup=
_64+0xa4/0xb0
> > > > > >> > > > > > > > > > >> [    0.746290][    T0] Rebooting in 86400=
 seconds..
> > > > > >> > > > > > > > > > >>
> > > > > >> > > > > > > > > > >> when I set "panic_on_warn=3D0", it foods =
the console with:
> > > > > >> > > > > > > > > > >> ...
> > > > > >> > > > > > > > > > >> [   25.206759][    C0] Variable was creat=
ed at:
> > > > > >> > > > > > > > > > >> [   25.207302][    C0]  vprintk_emit+0xf4=
/0x800
> > > > > >> > > > > > > > > > >> [   25.207844][    C0]  vprintk_deferred+=
0x90/0xed
> > > > > >> > > > > > > > > > >> [   25.208404][    C0]
> > > > > >> > > > > > > > > > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D
> > > > > >> > > > > > > > > > >> [   25.209763][    C0]  x86_64_start_rese=
rvations+0x19/0x2f
> > > > > >> > > > > > > > > > >> [   25.209769][    C0]
> > > > > >> > > > > > > > > > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D
> > > > > >> > > > > > > > > > >> [   25.211408][    C0] BUG: KMSAN: uninit=
-value in vprintk_emit+0x443/0x800
> > > > > >> > > > > > > > > > >> [   25.212237][    C0] CPU: 0 PID: 0 Comm=
: swapper/0 Tainted: G    B
> > > > > >> > > > > > > > > > >>           5.1.0 #5
> > > > > >> > > > > > > > > > >> [   25.213206][    C0] Hardware name: Red=
 Hat KVM, BIOS
> > > > > >> > > > > > > > > > >> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/=
01/2014
> > > > > >> > > > > > > > > > >> [   25.214326][    C0] Call Trace:
> > > > > >> > > > > > > > > > >> [   25.214725][    C0]  <IRQ>
> > > > > >> > > > > > > > > > >> [   25.215080][    C0]  dump_stack+0x134/=
0x190
> > > > > >> > > > > > > > > > >> [   25.215624][    C0]  kmsan_report+0x13=
1/0x2a0
> > > > > >> > > > > > > > > > >> [   25.216204][    C0]  __msan_warning+0x=
7a/0xf0
> > > > > >> > > > > > > > > > >> [   25.216771][    C0]  vprintk_emit+0x44=
3/0x800
> > > > > >> > > > > > > > > > >> [   25.217334][    C0]  ? __msan_metadata=
_ptr_for_store_1+0x13/0x20
> > > > > >> > > > > > > > > > >> [   25.218127][    C0]  vprintk_deferred+=
0x90/0xed
> > > > > >> > > > > > > > > > >> [   25.218714][    C0]  printk_deferred+0=
x186/0x1d3
> > > > > >> > > > > > > > > > >> [   25.219353][    C0]  __printk_safe_flu=
sh+0x72e/0xc00
> > > > > >> > > > > > > > > > >> [   25.220006][    C0]  ? printk_safe_flu=
sh+0x1e0/0x1e0
> > > > > >> > > > > > > > > > >> [   25.220635][    C0]  irq_work_run+0x1a=
d/0x5c0
> > > > > >> > > > > > > > > > >> [   25.221210][    C0]  ? flat_init_apic_=
ldr+0x170/0x170
> > > > > >> > > > > > > > > > >> [   25.221851][    C0]  smp_irq_work_inte=
rrupt+0x237/0x3e0
> > > > > >> > > > > > > > > > >> [   25.222520][    C0]  irq_work_interrup=
t+0x2e/0x40
> > > > > >> > > > > > > > > > >> [   25.223110][    C0]  </IRQ>
> > > > > >> > > > > > > > > > >> [   25.223475][    C0] RIP: 0010:kmem_cac=
he_init_late+0x0/0xb
> > > > > >> > > > > > > > > > >> [   25.224164][    C0] Code: d4 e8 5d dd =
2e f2 e9 74 fe ff ff 48 89 d3
> > > > > >> > > > > > > > > > >> 8b 7d d4 e8 cd d7 2e f2 89 c0 48 89 c1 48=
 c1 e1 20 48 09 c1 48 89 0b
> > > > > >> > > > > > > > > > >> e9 81 fe ff ff <55> 48 89 e5 e8 20 de 2e1
> > > > > >> > > > > > > > > > >> [   25.226526][    C0] RSP: 0000:ffffffff=
8f40feb8 EFLAGS: 00000246
> > > > > >> > > > > > > > > > >> ORIG_RAX: ffffffffffffff09
> > > > > >> > > > > > > > > > >> [   25.227548][    C0] RAX: ffff88813f995=
785 RBX: 0000000000000000
> > > > > >> > > > > > > > > > >> RCX: 0000000000000000
> > > > > >> > > > > > > > > > >> [   25.228511][    C0] RDX: ffff88813f2b0=
784 RSI: 0000160000000000
> > > > > >> > > > > > > > > > >> RDI: 0000000000000785
> > > > > >> > > > > > > > > > >> [   25.229473][    C0] RBP: ffffffff8f40f=
f20 R08: 000000000fac3785
> > > > > >> > > > > > > > > > >> R09: 0000778000000001
> > > > > >> > > > > > > > > > >> [   25.230440][    C0] R10: ffffd0fffffff=
fff R11: 0000100000000000
> > > > > >> > > > > > > > > > >> R12: 0000000000000000
> > > > > >> > > > > > > > > > >> [   25.231403][    C0] R13: 0000000000000=
000 R14: ffffffff8fb8cfd0
> > > > > >> > > > > > > > > > >> R15: 0000000000000000
> > > > > >> > > > > > > > > > >> [   25.232407][    C0]  ? start_kernel+0x=
5d8/0xb38
> > > > > >> > > > > > > > > > >> [   25.233003][    C0]  x86_64_start_rese=
rvations+0x19/0x2f
> > > > > >> > > > > > > > > > >> [   25.233670][    C0]  x86_64_start_kern=
el+0x84/0x87
> > > > > >> > > > > > > > > > >> [   25.234314][    C0]  secondary_startup=
_64+0xa4/0xb0
> > > > > >> > > > > > > > > > >> [   25.234949][    C0]
> > > > > >> > > > > > > > > > >> [   25.235231][    C0] Local variable des=
cription: ----flags.i.i.i@vprintk_emit
> > > > > >> > > > > > > > > > >> [   25.236101][    C0] Variable was creat=
ed at:
> > > > > >> > > > > > > > > > >> [   25.236643][    C0]  vprintk_emit+0xf4=
/0x800
> > > > > >> > > > > > > > > > >> [   25.237188][    C0]  vprintk_deferred+=
0x90/0xed
> > > > > >> > > > > > > > > > >> [   25.237752][    C0]
> > > > > >> > > > > > > > > > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D
> > > > > >> > > > > > > > > > >> [   25.239117][    C0]  x86_64_start_kern=
el+0x84/0x87
> > > > > >> > > > > > > > > > >> [   25.239123][    C0]
> > > > > >> > > > > > > > > > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D
> > > > > >> > > > > > > > > > >> [   25.240704][    C0] BUG: KMSAN: uninit=
-value in vprintk_emit+0x443/0x800
> > > > > >> > > > > > > > > > >> [   25.241540][    C0] CPU: 0 PID: 0 Comm=
: swapper/0 Tainted: G    B
> > > > > >> > > > > > > > > > >>           5.1.0 #5
> > > > > >> > > > > > > > > > >> [   25.242512][    C0] Hardware name: Red=
 Hat KVM, BIOS
> > > > > >> > > > > > > > > > >> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/=
01/2014
> > > > > >> > > > > > > > > > >> [   25.243635][    C0] Call Trace:
> > > > > >> > > > > > > > > > >> [   25.244038][    C0]  <IRQ>
> > > > > >> > > > > > > > > > >> [   25.244390][    C0]  dump_stack+0x134/=
0x190
> > > > > >> > > > > > > > > > >> [   25.244940][    C0]  kmsan_report+0x13=
1/0x2a0
> > > > > >> > > > > > > > > > >> [   25.245515][    C0]  __msan_warning+0x=
7a/0xf0
> > > > > >> > > > > > > > > > >> [   25.246082][    C0]  vprintk_emit+0x44=
3/0x800
> > > > > >> > > > > > > > > > >> [   25.246638][    C0]  ? __msan_metadata=
_ptr_for_store_1+0x13/0x20
> > > > > >> > > > > > > > > > >> [   25.247430][    C0]  vprintk_deferred+=
0x90/0xed
> > > > > >> > > > > > > > > > >> [   25.248018][    C0]  printk_deferred+0=
x186/0x1d3
> > > > > >> > > > > > > > > > >> [   25.248650][    C0]  __printk_safe_flu=
sh+0x72e/0xc00
> > > > > >> > > > > > > > > > >> [   25.249320][    C0]  ? printk_safe_flu=
sh+0x1e0/0x1e0
> > > > > >> > > > > > > > > > >> [   25.249949][    C0]  irq_work_run+0x1a=
d/0x5c0
> > > > > >> > > > > > > > > > >> [   25.250524][    C0]  ? flat_init_apic_=
ldr+0x170/0x170
> > > > > >> > > > > > > > > > >> [   25.251167][    C0]  smp_irq_work_inte=
rrupt+0x237/0x3e0
> > > > > >> > > > > > > > > > >> [   25.251837][    C0]  irq_work_interrup=
t+0x2e/0x40
> > > > > >> > > > > > > > > > >> [   25.252424][    C0]  </IRQ>
> > > > > >> > > > > > > > > > >> ....
> > > > > >> > > > > > > > > > >>
> > > > > >> > > > > > > > > > >>
> > > > > >> > > > > > > > > > >> I couldn't even log in.
> > > > > >> > > > > > > > > > >>
> > > > > >> > > > > > > > > > >> how should I use qemu with wheezy.img to =
start a kmsan kernel?
> > > > > >> > > > > > > > > > >>
> > > > > >> > > > > > > > > > >> Thanks.
> > > > > >> > > > > > > > >
> > > > > >> > > > > > > > >
> > > > > >> > > > > > > > >
> > > > > >> > > > > > > > > --
> > > > > >> > > > > > > > > Alexander Potapenko
> > > > > >> > > > > > > > > Software Engineer
> > > > > >> > > > > > > > >
> > > > > >> > > > > > > > > Google Germany GmbH
> > > > > >> > > > > > > > > Erika-Mann-Stra=C3=9Fe, 33
> > > > > >> > > > > > > > > 80636 M=C3=BCnchen
> > > > > >> > > > > > > > >
> > > > > >> > > > > > > > > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halim=
ah DeLaine Prado
> > > > > >> > > > > > > > > Registergericht und -nummer: Hamburg, HRB 8689=
1
> > > > > >> > > > > > > > > Sitz der Gesellschaft: Hamburg
> > > > > >> > > > > > > >
> > > > > >> > > > > > > >
> > > > > >> > > > > > > >
> > > > > >> > > > > > > > --
> > > > > >> > > > > > > > Alexander Potapenko
> > > > > >> > > > > > > > Software Engineer
> > > > > >> > > > > > > >
> > > > > >> > > > > > > > Google Germany GmbH
> > > > > >> > > > > > > > Erika-Mann-Stra=C3=9Fe, 33
> > > > > >> > > > > > > > 80636 M=C3=BCnchen
> > > > > >> > > > > > > >
> > > > > >> > > > > > > > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah=
 DeLaine Prado
> > > > > >> > > > > > > > Registergericht und -nummer: Hamburg, HRB 86891
> > > > > >> > > > > > > > Sitz der Gesellschaft: Hamburg
> > > > > >> > > > > >
> > > > > >> > > > > >
> > > > > >> > > > > >
> > > > > >> > > > > > --
> > > > > >> > > > > > Alexander Potapenko
> > > > > >> > > > > > Software Engineer
> > > > > >> > > > > >
> > > > > >> > > > > > Google Germany GmbH
> > > > > >> > > > > > Erika-Mann-Stra=C3=9Fe, 33
> > > > > >> > > > > > 80636 M=C3=BCnchen
> > > > > >> > > > > >
> > > > > >> > > > > > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeL=
aine Prado
> > > > > >> > > > > > Registergericht und -nummer: Hamburg, HRB 86891
> > > > > >> > > > > > Sitz der Gesellschaft: Hamburg
> > > > > >> > > >
> > > > > >> > > >
> > > > > >> > > >
> > > > > >> > > > --
> > > > > >> > > > Alexander Potapenko
> > > > > >> > > > Software Engineer
> > > > > >> > > >
> > > > > >> > > > Google Germany GmbH
> > > > > >> > > > Erika-Mann-Stra=C3=9Fe, 33
> > > > > >> > > > 80636 M=C3=BCnchen
> > > > > >> > > >
> > > > > >> > > > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine=
 Prado
> > > > > >> > > > Registergericht und -nummer: Hamburg, HRB 86891
> > > > > >> > > > Sitz der Gesellschaft: Hamburg
> > > > > >> >
> > > > > >> >
> > > > > >> >
> > > > > >> > --
> > > > > >> > Alexander Potapenko
> > > > > >> > Software Engineer
> > > > > >> >
> > > > > >> > Google Germany GmbH
> > > > > >> > Erika-Mann-Stra=C3=9Fe, 33
> > > > > >> > 80636 M=C3=BCnchen
> > > > > >> >
> > > > > >> > Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Pra=
do
> > > > > >> > Registergericht und -nummer: Hamburg, HRB 86891
> > > > > >> > Sitz der Gesellschaft: Hamburg
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
> > --
> > You received this message because you are subscribed to the Google Grou=
ps "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send =
an email to kasan-dev+unsubscribe@googlegroups.com.
> > To post to this group, send email to kasan-dev@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/ms=
gid/kasan-dev/CADvbK_d8HnKu%2BoSGha4w2wWRmQW8w%2BmqxJDnqDqezZEvVd-_7A%40mai=
l.gmail.com.
> > For more options, visit https://groups.google.com/d/optout.
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
kasan-dev/CADvbK_dGFV5XTVebK6YJNnBQJGPF%3Dmi03wkyVM%3Dmmt_uqFgzag%40mail.gm=
ail.com.
For more options, visit https://groups.google.com/d/optout.
