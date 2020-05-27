Return-Path: <kasan-dev+bncBDEKVJM7XAHRBH6EXH3AKGQEEOX2QCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7534E1E42AC
	for <lists+kasan-dev@lfdr.de>; Wed, 27 May 2020 14:50:39 +0200 (CEST)
Received: by mail-ed1-x53e.google.com with SMTP id f10sf10035887edn.10
        for <lists+kasan-dev@lfdr.de>; Wed, 27 May 2020 05:50:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590583839; cv=pass;
        d=google.com; s=arc-20160816;
        b=kGfDL/Yhb3IuV9A43Ab98ieGba6kQV15AD+gtrtFqQ1aIzFJDo6axdDOClt9QIXCTJ
         6i6vJz0UWnxHHvAVuIUVchQc9zdw2H44hBGEB2pqyZOnISNms3vwk5CuPo44Axh4U3zr
         XN8vW/fPRBkrB6wB9qWoQqFBs1JWSx2mDg2G7I/qtOewu3mUS2XVunFDcznb0BpG0UkS
         b4XOwkHi6oB2ArAlDXBiF1aqfix3K1hAyBaNfW0KA99pWVlqTJCDNOLWnmVRlGD0VgrF
         afJL4DSwqc79CJxWx3Sq31ndGu1I8KneLSO2AeKWcbgIO/9i0UuIiMPgTFQ3BP9guZqe
         qoeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=IifBGXsat1bk8klgvkcK0/IFib1Uw9dV55Ji+Uq098A=;
        b=y9MYcLS8PO8FPUMv/AVT1ULjFquoopdgMXch1iFr93h5B6JG4BwLoohP5AYgrWYRXG
         2JybxlQ+SXqhX8iIf5Qf49s0v9csJ/gVhST/+52uwIqSn19gbFAKZfPzJlaVh9mQnrCM
         Yys6/t9Yoe9vUiWOtuibN2Hdp4c7ug3V30d03Ram/YZo/sdalti1XW61qGShgY+HLsSg
         rZNkyn4BT2HFh/LxEzVHhpSkSbUHW6wqiT0MRj7R+AAZ8UMZls7DbUjr9YQqss9aUz6v
         4tduesOyXzP2lRLSl3PE/6dv7o55navTdgk58sGG8Jq3g0Ebh/Qy0SzIM/64UqPJY6Cv
         pTZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.17.10 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IifBGXsat1bk8klgvkcK0/IFib1Uw9dV55Ji+Uq098A=;
        b=AXJU+rnS9HymzGUbAyRVf6bI+fBV+n6/Z33sAqV96d159Xn68BaAyQrPg5UBx6Nafy
         DBzb2fJN/Y1iiT57q0dUyBf/FYNuwHC0gXi/bwar0JHYOYHo2VJ/dSKZWfh8sEQ6Qs8J
         PjD9tXo3OaPvSfAbi/n86WwkEA4u0r7qfvoSIUDPM5nuRPQja12AMaYcs2SR9KBBj2NF
         sGgBta37BMDM7w2Aka//5iCNLAseITMFlGj09wOXY2LgSysj7fL/NqUohuIsktFf+BVH
         J3OpVsrEX4mvcFydfoTZlZ2T00S/VcmMA2Da3+4ZYlZX6nOXMpZCQZ/8S/ECCUP7bVsi
         6d2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IifBGXsat1bk8klgvkcK0/IFib1Uw9dV55Ji+Uq098A=;
        b=FGNA05vRtvYcwDe3sZ2Z/ACLP0fhiPGx6+rgFsRpFBVdgzwkRtt0iiXntH2Wp2pc/0
         8GrhCSx198yAE+TWZHYSgI5hvEW+0J39Gn1yWpCH4GxEsXxmps6EYRqkQnwUSVMVZCIi
         jRpGeRizf5iP5d7GOZnzPcybPCKB2LzowCcD9tz805xc0M9WE5B2mmWuRQLyKRxxhWFg
         BBByiXQl/Y74b5hNvpvREUUL5AxopZ4bLi1BxlgW4myn8vJO4Tvn6ha6Iv6OrxsGjZNK
         Ka01lIC0zMbDG73skGD6xB4RaUDjW+UpNhvHAjIOBG9gHTEbrHkuF8c9+G0lGo5Csw04
         fA/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531mIxKzaQkqKRz4t4xwCTXVzEW6eSjZ/gCHISKbSD64O5yJ+Y4W
	H2lggGddAOVFhbi3UBCG6Fs=
X-Google-Smtp-Source: ABdhPJylW/c+rdAZkFhOr84LT8/wth0LVHf7w8To0tQwCW9iY2Rg2khIBUMwKa+9kizCsPE+2x7idQ==
X-Received: by 2002:a17:907:11cb:: with SMTP id va11mr6254435ejb.515.1590583839206;
        Wed, 27 May 2020 05:50:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:d4dd:: with SMTP id e29ls14957450edj.2.gmail; Wed, 27
 May 2020 05:50:38 -0700 (PDT)
X-Received: by 2002:a05:6402:5:: with SMTP id d5mr24296464edu.247.1590583838689;
        Wed, 27 May 2020 05:50:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590583838; cv=none;
        d=google.com; s=arc-20160816;
        b=FOVLRMJ3iuUwH8WJzHIgqWAV7OjrK/rAAjMJT+VzQJmCS6MVbuWkYzb9olb0OYuDMU
         jGmRndsTkXKr3BQrcoTb1Oy4971X46PQ0Y8TqHF4vJxZwTbGu92NOjgEEc7OP3wDSvK8
         1F/daHqYk97li7x8Q6Vl7uMVXO8ai50AZFRzqHabsO/pFInABIF+Tn2PGFgoLkaoXypj
         2u4wU8AN52684tk7pblvezfubqCdwjeLqZ3+kDYZOPNl1MdLkOBRjg9jsaZ3zFiFCwPi
         A52XTgm8oQlOMhtbCu09yuj+ZVyVgwxwxjjCjkbnEwUXzgmw5E4W8CVgUmavP5jFQurr
         YhOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version;
        bh=SjlUDgGaLjzHIwqSWSWLPaSWF5QMnSb3qK3mK7SdDCk=;
        b=E/RqGezqm7FTUJGeQi2qSS7ko6Pi37NgzZGQTt2+6C6aptLB+8n0ZOyFQRHEHPbv67
         OLD//Tad+RaLnuV9zTRnel8arZp6FFeLezj01ru4bFOqcm5HjgQUBwOZJDw2iWozawzo
         rD5zTQOlzVJX281ivL0LAB875NeL6B63JPzLVtrWoTSDejBP35GtJbM9J43mPw03CVYf
         aHEiK8+YzOo6ZwLdOc0ic+0JVrH914/vHp3i646pW5mc23FuCKaSlBsKVLImi3lsN5RS
         KkmklWNhBYp6vsJZQ2APiqXRNwsOuNMDFTJoxms/MXkTuzz6CXoV5pfqjX5xIeXwLWXt
         gqEQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.17.10 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
Received: from mout.kundenserver.de (mout.kundenserver.de. [212.227.17.10])
        by gmr-mx.google.com with ESMTPS id o23si137898edz.4.2020.05.27.05.50.38
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 May 2020 05:50:38 -0700 (PDT)
Received-SPF: neutral (google.com: 212.227.17.10 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) client-ip=212.227.17.10;
Received: from mail-qt1-f173.google.com ([209.85.160.173]) by
 mrelayeu.kundenserver.de (mreue107 [212.227.15.145]) with ESMTPSA (Nemesis)
 id 1M1IRY-1jbBQK0D7a-002lLd; Wed, 27 May 2020 14:50:38 +0200
Received: by mail-qt1-f173.google.com with SMTP id j32so4059536qte.10;
        Wed, 27 May 2020 05:50:37 -0700 (PDT)
X-Received: by 2002:ac8:1844:: with SMTP id n4mr3896231qtk.142.1590583836877;
 Wed, 27 May 2020 05:50:36 -0700 (PDT)
MIME-Version: 1.0
References: <20200527103236.148700-1-elver@google.com> <CAK8P3a1MFgRxm6=+9WZKNzN+Nc5fhrDso6orSNQaaa-0yqygYA@mail.gmail.com>
 <CA+icZUWtzu0ONUSy0E27Mq1BrdO79qNaY3Si-PDhHZyF8M4S5g@mail.gmail.com>
 <CAK8P3a04=mVQgSrvDhpVxQj50JEFDn_xMhYrvjmUnLYTWH3QXQ@mail.gmail.com> <CA+icZUXVSTxDYJwXLyAwZd91cjMPcPRpeAR72JKqkqa-wRNnWg@mail.gmail.com>
In-Reply-To: <CA+icZUXVSTxDYJwXLyAwZd91cjMPcPRpeAR72JKqkqa-wRNnWg@mail.gmail.com>
From: Arnd Bergmann <arnd@arndb.de>
Date: Wed, 27 May 2020 14:50:20 +0200
X-Gmail-Original-Message-ID: <CAK8P3a3i0kPf8dRg7Ko-33hsb+LkP=P05uz2tGvg5B43O-hFvg@mail.gmail.com>
Message-ID: <CAK8P3a3i0kPf8dRg7Ko-33hsb+LkP=P05uz2tGvg5B43O-hFvg@mail.gmail.com>
Subject: Re: [PATCH -tip] compiler_types.h: Optimize __unqual_scalar_typeof
 compilation time
To: Sedat Dilek <sedat.dilek@gmail.com>
Cc: Marco Elver <elver@google.com>, Will Deacon <will@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Borislav Petkov <bp@alien8.de>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>
Content-Type: text/plain; charset="UTF-8"
X-Provags-ID: V03:K1:Gd7aGXUyty0UAbLIe5ipkPsFNX4oQZqBROlo3KrEdFqu167d2Am
 b5+eiRFIO4KbIiRVfruuAzeQ9H32JYesB55IbiiBr7FUxZnDqwEyPAkaSIXQAZOFr4e3brN
 VzhKzGHACtRt4zaMdQcFol5V3tTxGXAb0huKIMjXjMF8mBAuKu5VTtaMVHKJf4CW6DE2yLl
 eV4Z/t7moqAFGWB+rDj/A==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:pnZykpW+VLk=:yZ+cob4Fjn9wcuRbtUWmFm
 49eSE1ulxXa+D43doQgnd2vdR53UWWrozgu/JPH5lD7IbfwuS2pniZm0rLTnPvlRZ9E901euh
 YFNitCIWiVOzZMAECAx1KyF8kBbSCnWX+RM6h502FpW6X5DrmNOJZE5G1Qb4Shp/2iTC+2w0B
 k7usy69Cul1Ct6EWANpqxU/ygmQ2TAvUCxHUSi+UucVFKzfHxIg7QPHDWJWdFyiJpsnq3suqd
 fhTrWOLtRHtVJ+1mkGE2Y1G+uFyWPx2fsJ82BWoCpayro08ih1Hx8b89bj3aXXLEvMOzPBZe+
 vr6IrPjhhFE8ERLEVJDTyUZNo6ojhu7KOdrAfcsYjYGOFQ6x/etbhxeTZ3Kg4f8XIh9D1Swks
 D5sr+wZ2CZ1ZhMwHpAHqvi8VREIzXjdZ45lzJxaUzQzY8X7nod3Kk6pRnTbeSy5GmDPMh8nwG
 qOce4bqE/slekra/dDBZTWVylY02gkoE9OwfCZEf+UpRwdlEE46pjJK1MnNS42Qy+Ivp8Xhr2
 w9IP8FTf+yZ9u7vaWt/LVFIjtkRTipJbMH49clwZYqQC6vMkgZzzNROl1s6sVGnAjpNV540qv
 Z3eOeRUmgCpVbKkKEbCl5feuqaa2s3mML4amReLpc0hq4dlb0U2RZeagsnTKN0ZtsVtUvZ/ho
 NG28+WhhT6RZS73vAwbGcRUWRHKa4y6UxeQUhEMsd39bmJiDA7KNM6Gmi5r/TsYHxLWP0ehBn
 HMUSyq4ypn7waioiVS90yjU7Z5SHYBEDpY6rdnJkTzuhYcpre4Y0laUTaGIvNPAyEPq7U3J0C
 4gCJQRbOi2npeF/PiFvOdPBuyX/X78XOTYCEUCsxdjQO+46PJo=
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 212.227.17.10 is neither permitted nor denied by best guess
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

On Wed, May 27, 2020 at 2:35 PM Sedat Dilek <sedat.dilek@gmail.com> wrote:
> On Wed, May 27, 2020 at 2:31 PM Arnd Bergmann <arnd@arndb.de> wrote:
> > On Wed, May 27, 2020 at 1:36 PM Sedat Dilek <sedat.dilek@gmail.com> wrote:
> > > On Wed, May 27, 2020 at 1:27 PM Arnd Bergmann <arnd@arndb.de> wrote:
> > > > On Wed, May 27, 2020 at 12:33 PM Marco Elver <elver@google.com> wrote:
> > > >
> > > > This gives us back 80% of the performance drop on clang, and 50%
> > > > of the drop I saw with gcc, compared to current mainline.
> > > >
> > > > Tested-by: Arnd Bergmann <arnd@arndb.de>
> > > >
> > >
> > > Hi Arnd,
> > >
> > > with "mainline" you mean Linux-next aka Linux v5.8 - not v5.7?
> >
> > I meant v5.7.
> >
> > > I have not seen __unqual_scalar_typeof(x) in compiler_types.h in Linux v5.7.
> > >
> > > Is there a speedup benefit also for Linux v5.7?
> > > Which patches do I need?
> >
> > v5.7-rc is the baseline and is the fastest I currently see. On certain files,
> > I saw an intermittent 10x slowdown that was already fixed earlier, now
> > linux-next
> > is more like 2x slowdown for me and 1.2x with this patch on top, so we're
> > almost back to the speed of linux-5.7.
> >
>
> Which clang version did you use - and have you set KCSAN kconfigs -
> AFAICS this needs clang-11?

I'm currently using clang-11, but I see the same problem with older
versions, and both with and without KCSAN enabled. I think the issue
is mostly the deep nesting of macros that leads to code bloat.

        Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAK8P3a3i0kPf8dRg7Ko-33hsb%2BLkP%3DP05uz2tGvg5B43O-hFvg%40mail.gmail.com.
