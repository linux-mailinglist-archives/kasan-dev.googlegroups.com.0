Return-Path: <kasan-dev+bncBDEKVJM7XAHRB3XEXD3AKGQEKNSQ4OY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id B9A651E3D89
	for <lists+kasan-dev@lfdr.de>; Wed, 27 May 2020 11:27:10 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id u11sf662953wmc.7
        for <lists+kasan-dev@lfdr.de>; Wed, 27 May 2020 02:27:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590571630; cv=pass;
        d=google.com; s=arc-20160816;
        b=Wh1KpMDSG7i/W4s+6FT4Ub+ur+ZEYchexzE0aTQyYXeTYPnKv74BHutzMKcTrqZO6f
         7U+myUm+o7eZuEADmkiGuyTEWVKr2a0m59LHslOylBFQ8AiB3c1jRrXjJcp0D2kJT5JW
         9wMmRCgFzPMVXNc0yoXInieyh0yNm5JbJJd6jD75kLbdBjRpu02piMYqAKh/S4wbISIY
         /1M4vfTwXngCDwjVKi4QfBGT41lfjlQvn1/IpaB81X22BxUwJz41y/cKZJVu13g/p7BM
         jA79W5NU5lArjtqPSUoM8DcLGoQry/ELkimX+J78QQ6bxOy38K5QbQNuMSL7RU5e0krT
         qIPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=rTT8TNfrp+xmBUgagOiCrLbj/ygRnyRCjtTA7aNI8I0=;
        b=F2m/Nz2JYx1CznpWGp9kPtN5P/VztaKuWbZq8pngrpbIAvByG5fqAqVbzdK/AgFJTu
         zswm8TrdA5Fa4yb6cMxXvOqryNJLRSD555Xf9nlNFtfTABCjakwyrOAvJmCbOQjk5qCl
         cvhe2E+XM/s60saUGWY0c3b8VR6SADk7SxLG5YkdwtX593/anzOj/22f0naFDlJVUOIA
         0jeweWk0x3Aopv1jOW76MGe65PTBdxyZRUJ6bUwsMScdQODIYYXcs3JS5lLn6+p9YLsd
         pS2BOXHWI62poPwUNM1fKKaHK162DDm0sn88qGNqVPaXkNBwyKsbyFPErC3iwMfh3MLB
         qnpw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.126.131 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rTT8TNfrp+xmBUgagOiCrLbj/ygRnyRCjtTA7aNI8I0=;
        b=CF2SqWz0q18VZvPQdeOKMX6va81Q6Qv1fKHbE4gLB31Y1Gc1uGyS2i/1jXAlGv8mvy
         Nw9wQAHhMMJFn4hmUhErA4PnpMPchOivTROTi2j3ASEYDT9akCvx3OaT2buhQHFDguSO
         pbAeUFNfMvAFXPmSW3zcLax3IsQMIdIubSxqNinqteTSyLoDd8ruwkxawFE25BUwRdcu
         B8dt69KWrZ6tgA2psR1JUi/tDTtjwFXbRrMo06vXDyKzbI0xJKd79AZl0P8HAfinf8x6
         POBLLebmM7thiC04p3VcDV5QQeZZzbocU427dcMpLvkh2d2f2axnbhz+FIcrNWzMNL9e
         ZLwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rTT8TNfrp+xmBUgagOiCrLbj/ygRnyRCjtTA7aNI8I0=;
        b=NAa7syRSrxCHOBx85ZMdarwY5BrJlsO+ZH9GVgR0zDftMp7oIncWCwGxf0qwa4k3Oi
         TIY7fbaLUf8zaT2PRa79ORPbqdRZbvr3keOsRapeZXu4698UPDgfh+m/g9GRwQLGiS7D
         cUz9FsbP4DDoLU1NUZL2cC34l/HkgtD+QGe5URxBcSTifAChz2vXdTq+YNoN6/eKI/Qj
         lPyTlm/Y8XYvdhBXjlszFtGO8xEcKhVUQnVZV4xeQsBLyjDGgo5GTGclsdU1BHmZ2rlm
         ueNOIyZw7c/i8BfeyzIf2BS4ri5ukAclXL9eK8Q5RdpPO1oQect3YwNGBepBbFx7/a1Z
         7C2Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532eB1cOllxqG6vfFUB/yoUeWyPcYoVyJg4lYzfw7uL6MNGXoaSP
	YPATejIrXTqBmGFbRtVuKTY=
X-Google-Smtp-Source: ABdhPJzrC+JubtNTQcW83OsbFClhUAytLVcwpjshbSSJaBS/KR5RQw1/hoPJIPvfoGwPbM6Gn5ClKg==
X-Received: by 2002:a5d:5389:: with SMTP id d9mr25645997wrv.77.1590571630453;
        Wed, 27 May 2020 02:27:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fac9:: with SMTP id a9ls2644445wrs.2.gmail; Wed, 27 May
 2020 02:27:10 -0700 (PDT)
X-Received: by 2002:a5d:4b4d:: with SMTP id w13mr25545445wrs.178.1590571629985;
        Wed, 27 May 2020 02:27:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590571629; cv=none;
        d=google.com; s=arc-20160816;
        b=quoVvaLr+YHDYmRHD1tLg3VOOfIce4qzACmn7SutCLD/gM8Dr+IQUAzagBZmfH72dJ
         aMHU77/Ll7hmyhyfqqogzh/u925HyrBxQWNMyy6m+1hgzQSZwyxfHVPSZYhJiD6OUjtZ
         NaEQX+Yrd5AOB05CVKhE/KKPoBdApAvF/MaZpjpNP5daaZgQ0qx8DSRbn/UfzQJ8t7is
         ltuwMMVBM+DCtZCeDRvfb7enE7uZgXwKTSBWJm4borxzEpaZiWhCst0w64AqVcof5E/s
         Kb7BFnN9JdWxDcNMLHNIHfhXZQy8zAUWbSBWMDWOIbsb8rZj10ytiSR8teyCf1qyc2n5
         rofA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version;
        bh=S25vVde9yiEiJGC4pstAOIXqe7k8wnOQKj8y0xY81d8=;
        b=Hk4Nv/FzCr+sWnfto5v9eHq2wPSurllpcNpMoOj6mGhj5mNHV0w+mkVLbRrj62zgWv
         9QzIsaD4nCQmnP5jWSVBD8uJKboYUVduERV0OBRZdiOOpRzlRwfxujwWNN5pEBnkgZV7
         jae8oBPKUMZ+q1Dp1FD9Rl00U5n7Co48T5No7tuD+FHdksHo3UFfq9XaaayJDVczU5uG
         RzArpXSD9ykc5Yz+Ry1XAo4yr57aJWVYiak59bo/ZImMVT1uMik2SrvZnhUBlZJoYLk0
         HEWXoXVt/YD9kiYoyW7pizajRd6E3xUaO2rnYnvl46FWqeoSnCh0v9zIBOzV2gAgSD3F
         M23g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.126.131 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
Received: from mout.kundenserver.de (mout.kundenserver.de. [212.227.126.131])
        by gmr-mx.google.com with ESMTPS id y71si151014wmd.3.2020.05.27.02.27.09
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 May 2020 02:27:09 -0700 (PDT)
Received-SPF: neutral (google.com: 212.227.126.131 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) client-ip=212.227.126.131;
Received: from mail-qk1-f171.google.com ([209.85.222.171]) by
 mrelayeu.kundenserver.de (mreue009 [212.227.15.129]) with ESMTPSA (Nemesis)
 id 1M2wCi-1jaaY51dhE-003QxJ; Wed, 27 May 2020 11:27:09 +0200
Received: by mail-qk1-f171.google.com with SMTP id b27so13661989qka.4;
        Wed, 27 May 2020 02:27:09 -0700 (PDT)
X-Received: by 2002:ae9:c10d:: with SMTP id z13mr2828308qki.3.1590571628188;
 Wed, 27 May 2020 02:27:08 -0700 (PDT)
MIME-Version: 1.0
References: <20200521142047.169334-1-elver@google.com> <20200521142047.169334-10-elver@google.com>
 <CAKwvOdnR7BXw_jYS5PFTuUamcwprEnZ358qhOxSu6wSSSJhxOA@mail.gmail.com>
 <CAK8P3a0RJtbVi1JMsfik=jkHCNFv+DJn_FeDg-YLW+ueQW3tNg@mail.gmail.com>
 <20200526120245.GB27166@willie-the-truck> <CAK8P3a29BNwvdN1YNzoN966BF4z1QiSxdRXTP+BzhM9H07LoYQ@mail.gmail.com>
 <CANpmjNOUdr2UG3F45=JaDa0zLwJ5ukPc1MMKujQtmYSmQnjcXg@mail.gmail.com>
 <20200526173312.GA30240@google.com> <CAK8P3a3ZawPnzmzx4q58--M1h=v4X-1GtQLiwL1=G6rDK8=Wpg@mail.gmail.com>
 <CAK8P3a3UYQeXhiufUevz=rwe09WM_vSTCd9W+KvJHJcOeQyWVA@mail.gmail.com>
 <20200527072248.GA9887@willie-the-truck> <CANpmjNO2A39XRQ9OstwKGKpZ6wQ4ebVcBNfH_ZhCTi8RG6WqYw@mail.gmail.com>
In-Reply-To: <CANpmjNO2A39XRQ9OstwKGKpZ6wQ4ebVcBNfH_ZhCTi8RG6WqYw@mail.gmail.com>
From: Arnd Bergmann <arnd@arndb.de>
Date: Wed, 27 May 2020 11:26:51 +0200
X-Gmail-Original-Message-ID: <CAK8P3a1BH5nXDK2VS7jWc_u2B1kztr4u9JMXhWF9-iZdrsb-7Q@mail.gmail.com>
Message-ID: <CAK8P3a1BH5nXDK2VS7jWc_u2B1kztr4u9JMXhWF9-iZdrsb-7Q@mail.gmail.com>
Subject: Re: [PATCH -tip v3 09/11] data_race: Avoid nested statement expression
To: Marco Elver <elver@google.com>
Cc: Will Deacon <will@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, Borislav Petkov <bp@alien8.de>, 
	Stephen Rothwell <sfr@canb.auug.org.au>
Content-Type: text/plain; charset="UTF-8"
X-Provags-ID: V03:K1:OKhXd5sauaVhy9yPy9q+1hLD9XO7k/02k5bDh0/XnEr+XkJ1o+e
 u2SP+OCnnreggI1HSoiXYjwNEZw2U69UWa2QqpORVoUbfCEQmiL0y7ROsUJXp/HHu5wcHBB
 6g74U5hPOj9N9f/+KIQRing2mL2B8lmrUJnDQm+vTMiUxaF5m0y2GC01a/aZA0B/FKePblN
 EzzKgovOSK3DuLeRI5dIw==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:GSc5di7Wdg0=:QJGaIvhp132N8AvTVnfDcD
 Za3G8pfgssZdEtO8XHz3AAxIGupexbIEE+Em+O7HdjjvoqW1XVAZRyoPlRlYcFKoYc+gBjGkY
 MsNceLOKddJJLdTVEqmvXt35QuT+Bla5lzVsctRuqMLQhtEo2CmCId6Ad4rF++cFAIK/bvJz5
 r65rk8KtjrinWgrYitXzooC83B2uSStuTZiYLXFv82gqfUH6HSrzUlMc9zDXneMgc/srZ3PEh
 kqYcgfppA4s3Zk5K49hs+JDjURXg7CxwBd6qYViUqs8x/R2W21pOAHC7DAUk5P9swek2TE2kD
 HVPuhGXarh5kxV2qZLr5ZkwJH+VRkBGXXB1ODLFQr96TuoSsxKsyLiP7czNgPczjWVG7oQL4I
 YqGul1qM4GogTS9kwo4cZu2egrbbo4o1v9jAU50NHpngaXm/eEfZ0CZFfmofb3MsWqfikd41t
 pvp798OuL/1hmKYsmerWA7qQuebNNCdi2r2Ibozy1g0yLIfMLe3PbfrQFLe+ldYlcvM3P1+el
 7XvgzewmZA49Mpeo5NsWb9XbpkauayH1+mTjDN8IGGiogrYsd95q7ycWS/ZGRvbWVVAvJljee
 At2kFTU2yef+GqvDWySMKYHoqkEEQP7kzWMAstk19DWdfCBzfzk41+lApNqURvWE+mQPDznRR
 hphT7AkePjacQ5jih4u5FzWJ9XtdfuJioIwp2EIC2Qww2rydcAkTpLMesNZM1INQjOF77My6y
 00gMI+nXdXzBmemrsRhPbJNwmdvVVNqVN0VJhd5ptynTJGv6hByMEzWJJk52vLxezXzpkpbKk
 UppxwD+ed9RmUIeSAAohur/IrUdEIpSDZDPBnQwel3Loj54sMM=
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 212.227.126.131 is neither permitted nor denied by best guess
 record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
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

On Wed, May 27, 2020 at 9:44 AM 'Marco Elver' via Clang Built Linux
<clang-built-linux@googlegroups.com> wrote:
> On Wed, 27 May 2020 at 09:22, Will Deacon <will@kernel.org> wrote:
> >
> > Nice! FWIW, I'm planning to have Alpha override __READ_ONCE_SCALAR()
> > eventually, so that smp_read_barrier_depends() can disappear forever. I
> > just bit off more than I can chew for 5.8 :(
> >
> > However, '__unqual_scalar_typeof()' is still useful for
> > load-acquire/store-release on arm64, so we still need a better solution to
> > the build-time regression imo. I'm not fond of picking random C11 features
> > to accomplish that, but I also don't have any better ideas...
>
> We already use _Static_assert in the kernel, so it's not the first use
> of a C11 feature.
>
> > Is there any mileage in the clever trick from Rasmus?
> >
> > https://lore.kernel.org/r/6cbc8ae1-8eb1-a5a0-a584-2081fca1c4aa@rasmusvillemoes.dk
>
> Apparently that one only works with GCC 7 or newer, and is only
> properly defined behaviour since C11. It also relies on multiple
> _Pragma. I'd probably take the arguably much cleaner _Generic solution
> over that. ;-)

I'd have to try, but I suspect we could force gcc-4.9 or higher to
accept it by always passing --std=gnu11 instead of --std=gnu89,
but that still wouldn't help us with gcc-4.8, and it's definitely not
something we could consider changing for v5.8.

However, if we find a solution that is nicer and faster but does
requires C11 or some other features from a newer compiler,
I think making it version dependent is a good idea and lets us
drop the worse code eventually.

> I think given that Peter and Arnd already did some testing, and it
> works as intended, if you don't mind, I'll send a patch for the
> _Generic version. At least that'll give us a more optimized
> __unqual_scalar_typeof(). Any further optimizations to READ_ONCE()
> like you mentioned then become a little less urgent.

Right. I think there is still room for optimization around here, but
for v5.8 I'm happy enough with Marco's__unqual_scalar_typeof()
change. Stephen Rothwell is probably the one who's most affected
by compile speed, so it would be good to get an Ack/Nak from him
on whether this brings speed and memory usage back to normal
for him as well.

      Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAK8P3a1BH5nXDK2VS7jWc_u2B1kztr4u9JMXhWF9-iZdrsb-7Q%40mail.gmail.com.
