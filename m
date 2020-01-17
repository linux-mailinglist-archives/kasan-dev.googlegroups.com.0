Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVPGQ3YQKGQESD37AAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id 60F33140A7E
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 14:15:02 +0100 (CET)
Received: by mail-io1-xd38.google.com with SMTP id w22sf10231994ior.6
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 05:15:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579266901; cv=pass;
        d=google.com; s=arc-20160816;
        b=L2BsukHK5g2Bj9ayfhtwbpLroQLJzWBdLlRtlIhfcAMVIy17Or1d6bFrRoW9zv+mVA
         dt3IFHfyRBuNn/ci7wZ4BYtaOtdSkfJIhRVlbNFZjCq035G028MMOkJxsqWwALyQbwAZ
         1vYb+0Z/Bx4DN+gjec/NDY4BKn8MzDDrz2oyvkJqwfhZJrAcpLvnPI/DBi8CYz0sX1zl
         d6fnXufsfegapkKqDlXxdeoEf9joXWEHskE2tOt0Zsqj5tIXXfggxNyrAmz8tyxzRlqh
         7bKqg+XNFcIytjkKy09zWFYsyVj9Vvitc73ZOHsJtqrx4xOUO9D7hmfMR9Xa+IqH6Sq5
         vl/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=s19g+Eu2U1F8HiL7DFNnh5j4n1aLNk55thDyZJ/ergM=;
        b=i25K7SbfWPHT+NjfXh3fgFlA7wMVnt0DL34O1JEVnYYSEzv61gc14t32auZ9/kvqk3
         hPx5daRqjdoenCKX0JN3H9lzwEVFDlcwjCl01+ji5dcnx0mWqYorg7oQPOQaSuepGT7u
         k5aVlN1yABLLa41g7/Xn8KlBPnirsK1qupJ9nC0H0ZFhaRSabG/ICadkICgnXvmVbYly
         qX1FH2n748UhjEQU80OX0rLpQJ0aacTDG16I9K4qWOqZHv9FQ1qOc/cjjAdtH/cokEUb
         juZeOGIqwtcnxsfmUxajzBky1PNA5OYuyABdFLxRCmIMqqbzYkxzy2Odi04HDvSSPXkW
         aGQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=phe1Ud2o;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=s19g+Eu2U1F8HiL7DFNnh5j4n1aLNk55thDyZJ/ergM=;
        b=rdSCR9mnBe6UrM1342n2ZwqpJOtzYFYx4yGmuRYMmejT2tl4nsey8s0V0jB6QtHGFS
         tyq6PZMaFsrxw5+cJEDIZODRcw5osIjeov90Egksvqqpt7WHB2m5XPFQa5UNnY41TUWr
         liNFMes0g4PJ6hUujod80E4eurmka0SZ4sGihepHqjSOr6WFLACo35EtAb6ZsT3+MEIZ
         MqFGvO2gOu+125ZyjCnBZ2Q+jVo6rcjdmn6ifPBdSkSpi4exbqaphFnauUSyHDaz9EMW
         NbdCLr5Ha/PR8RR3b5OPaO7Crp3m0YMpSWZRcT+HfaObO0sPYSAUg7I+L5Iocx5tr6hv
         VsYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=s19g+Eu2U1F8HiL7DFNnh5j4n1aLNk55thDyZJ/ergM=;
        b=i0DUzlKF162XUWywcMeNJAwBbT9zb1J/g+tv7ZtxsxIDPcYAA9EXyumFeW+4LSd90m
         leniTdyJg9eCKKR+0MbZ0z1b2pigW9dBvu1hF1VLRRrgaUVxsJckdl2h+RLGLgTI8Jh/
         +NGotY/2IkV2bFpYFmb7i0chd9fzuMcrPsOtCv+dpxBZ9XvmMiY9rkbtExs4hnxCn8Ct
         gi6FOaXZf8NgoIODvg0m93S9SF9BVOwF/hxZaglBDbo/MZdLtirm/wLm/bDTYv7AbbZJ
         Md2iLaAvvzcxVMQBS3P6FDMF7H4ZvExyVunHPGL7/LWYHb/zyfKMOjvTpRyA6XGh5Ig4
         /Q3w==
X-Gm-Message-State: APjAAAVLUr0y4WGlblnaN3mri2JL8207/q+wYuf5/zl4/2NVilea1V+N
	z7B4UD0JVCUnXl56uS0zCE4=
X-Google-Smtp-Source: APXvYqyPGkT2QNSleUDj0hShcTNoDsBPq8Xv5+p6oo7q+/mL6swTmIrqQwDdj+ZGY0Wb6RlJvFDErw==
X-Received: by 2002:a02:7fd0:: with SMTP id r199mr3188454jac.126.1579266901245;
        Fri, 17 Jan 2020 05:15:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5e:9807:: with SMTP id s7ls4063341ioj.13.gmail; Fri, 17 Jan
 2020 05:15:00 -0800 (PST)
X-Received: by 2002:a6b:5904:: with SMTP id n4mr32330436iob.9.1579266900824;
        Fri, 17 Jan 2020 05:15:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579266900; cv=none;
        d=google.com; s=arc-20160816;
        b=w/spFTxE5kNpqf2lAqRVNGnC+FhiY94VL13sjUsHLN8DIFbUNVxrEmmf7QdcB6/H5y
         xbtcWGhNmDmZriodHe1L4CHEo5aTTR4CR+x0qDp0qIse0LbjBy4TVCTes2Vr1mUFXacS
         mYYwBHPhs2D+NV+RoGQvKyX2TDukeSQSAWe2rRW0qVOCT7JCyLI4kharkkMeGnN9DmtQ
         8cz6RrOO7jCzT8hD5GtjLYQcQxXxSTN6yoBuyP/j5MWrKztxLx3oyGryy56qebtVbCaK
         7ZOH3YlXy+YPd8mE7oBP7Ax2lfUjmWgp8jwO/5hL3o0r6msORyRpGlbhuEOtJsJA5pnd
         t9VQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=B8YqwuFYQqcgYYrogodMJhZN7j+MHKf9rIlBL0O/Le8=;
        b=jNWgHBABsN4a47758afhCeSA+H+c4+aIFVxsE3MPTQH+aE7C4TFSGdSE3R/lZgC2zC
         Vd17N3GiEu3hCWHK1222/7WMt3TV5I309JRmQT2H6EGIzGW0j53oHOeOsKxutI2XUWnv
         7PzldDb/x51TE4oZvWkjx7HoMdFSySxX6ezjCUMmG6JSwrA3tFA2DB4ZIBzPe/jQz65I
         x4aFkdu2isJLfsrSDvFrEp2B8cNBGEmBBYo9yFhvYT6lSkiRWZAyMyo2E2ez03cwFXoS
         ACqON+dLWFPFCxVeYUmBrBvsh6Jln3xb0pshXZ6MvtVtqZCPnsMZPEfimQ8OReCKy0gU
         /OFw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=phe1Ud2o;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32b.google.com (mail-ot1-x32b.google.com. [2607:f8b0:4864:20::32b])
        by gmr-mx.google.com with ESMTPS id h4si1356991ilf.3.2020.01.17.05.15.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Jan 2020 05:15:00 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32b as permitted sender) client-ip=2607:f8b0:4864:20::32b;
Received: by mail-ot1-x32b.google.com with SMTP id i15so22495840oto.2
        for <kasan-dev@googlegroups.com>; Fri, 17 Jan 2020 05:15:00 -0800 (PST)
X-Received: by 2002:a9d:588c:: with SMTP id x12mr5863094otg.2.1579266899985;
 Fri, 17 Jan 2020 05:14:59 -0800 (PST)
MIME-Version: 1.0
References: <20200115165749.145649-1-elver@google.com> <CAK8P3a3b=SviUkQw7ZXZF85gS1JO8kzh2HOns5zXoEJGz-+JiQ@mail.gmail.com>
 <CANpmjNOpTYnF3ssqrE_s+=UA-2MpfzzdrXoyaifb3A55_mc0uA@mail.gmail.com>
 <CAK8P3a3WywSsahH2vtZ_EOYTWE44YdN+Pj6G8nt_zrL3sckdwQ@mail.gmail.com>
 <CANpmjNMk2HbuvmN1RaZ=8OV+tx9qZwKyRySONDRQar6RCGM1SA@mail.gmail.com> <CAK8P3a066Knr-KC2v4M8Dr1phr0Gbb2KeZZLQ7Ana0fkrgPDPg@mail.gmail.com>
In-Reply-To: <CAK8P3a066Knr-KC2v4M8Dr1phr0Gbb2KeZZLQ7Ana0fkrgPDPg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 17 Jan 2020 14:14:48 +0100
Message-ID: <CANpmjNO395-atZXu_yEArZqAQ+ib3Ack-miEhA9msJ6_eJsh4g@mail.gmail.com>
Subject: Re: [PATCH -rcu] asm-generic, kcsan: Add KCSAN instrumentation for bitops
To: Arnd Bergmann <arnd@arndb.de>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, Michael Ellerman <mpe@ellerman.id.au>, 
	christophe leroy <christophe.leroy@c-s.fr>, Daniel Axtens <dja@axtens.net>, 
	linux-arch <linux-arch@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=phe1Ud2o;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32b as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Fri, 17 Jan 2020 at 13:25, Arnd Bergmann <arnd@arndb.de> wrote:
>
> On Wed, Jan 15, 2020 at 9:50 PM Marco Elver <elver@google.com> wrote:
> > On Wed, 15 Jan 2020 at 20:55, Arnd Bergmann <arnd@arndb.de> wrote:
> > > On Wed, Jan 15, 2020 at 8:51 PM Marco Elver <elver@google.com> wrote:
> > > > On Wed, 15 Jan 2020 at 20:27, Arnd Bergmann <arnd@arndb.de> wrote:
> > > Are there any that really just want kasan_check_write() but not one
> > > of the kcsan checks?
> >
> > If I understood correctly, this suggestion would amount to introducing
> > a new header, e.g. 'ksan-checks.h', that provides unified generic
> > checks. For completeness, we will also need to consider reads. Since
> > KCSAN provides 4 check variants ({read,write} x {plain,atomic}), we
> > will need 4 generic check variants.
>
> Yes, that was the idea.
>
> > I certainly do not feel comfortable blindly introducing kcsan_checks
> > in all places where we have kasan_checks, but it may be worthwhile
> > adding this infrastructure and starting with atomic-instrumented and
> > bitops-instrumented wrappers. The other locations you list above would
> > need to be evaluated on a case-by-case basis to check if we want to
> > report data races for those accesses.
>
> I think the main question to answer is whether it is more likely to go
> wrong because we are missing checks when one caller accidentally
> only has one but not the other, or whether they go wrong because
> we accidentally check both when we should only be checking one.
>
> My guess would be that the first one is more likely to happen, but
> the second one is more likely to cause problems when it happens.

Right, I guess both have trade-offs.

> > As a minor data point, {READ,WRITE}_ONCE in compiler.h currently only
> > has kcsan_checks and not kasan_checks.
>
> Right. This is because we want an explicit "atomic" check for kcsan
> but we want to have the function inlined for kasan, right?

Yes, correct.

> > My personal preference would be to keep the various checks explicit,
> > clearly opting into either KCSAN and/or KASAN. Since I do not think
> > it's obvious if we want both for the existing and potentially new
> > locations (in future), the potential for error by blindly using a
> > generic 'ksan_check' appears worse than potentially adding a dozen
> > lines or so.
> >
> > Let me know if you'd like to proceed with 'ksan-checks.h'.
>
> Could you have a look at the files I listed and see if there are any
> other examples that probably a different set of checks between the
> two, besides the READ_ONCE() example?

All the user-copy related code should probably have kcsan_checks as well.

> If you can't find any, I would prefer having the simpler interface
> with just one set of annotations.

That's fair enough. I'll prepare a v2 series that first introduces the
new header, and then applies it to the locations that seem obvious
candidates for having both checks.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO395-atZXu_yEArZqAQ%2Bib3Ack-miEhA9msJ6_eJsh4g%40mail.gmail.com.
