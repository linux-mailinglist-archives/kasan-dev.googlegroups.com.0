Return-Path: <kasan-dev+bncBDHYDDNWVUNRBWPWXL3AKGQETZK55FA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1DB201E4DE6
	for <lists+kasan-dev@lfdr.de>; Wed, 27 May 2020 21:11:23 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id q7sf18844139plr.4
        for <lists+kasan-dev@lfdr.de>; Wed, 27 May 2020 12:11:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590606681; cv=pass;
        d=google.com; s=arc-20160816;
        b=rUgZ/n0K2I4W/TmDUyuHomB0E2MfmtTQRelRgY0L3BqEh+755WZnxWPNAKXwqLxWvt
         4OMgvK2YyZmqCuomog7QjScVumosbWofJoPVMBx1WZI4sHyJ29RPFENkbQmG6Vy1ayr+
         knG65rNMzgLASEFyCKxKhSJ3AW5QRF5cBb2p3Oy/qtjDrWvXKVDcaqXqF/dyDaWUldHH
         YozeZ2biM/HQzSUoLzZDbF8/CLvIb7DrvqLashuZkboW7PAN9x4drV9FHIcoXygof3le
         nTEijANtfu2YwwGhWWlDmQ0q6bOgUOgYIcjKeJJFoS4ZLpWe5sKFp9xKUcS9D2l8BDRr
         nxcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :reply-to:in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=tsXFBW2RFAh2hh6ldjz5gymJyNZSSzqgh2sf7Vuzpgo=;
        b=GOkiCIwPw5qyjVT96QyLA0Ri+YIrZTbl03kuq+a0AobxrhHtCAgL1+xnq4A7FeQV55
         aYKkyOVAJlLqrNJO+QcnENqWGiXA2w5cQTmhQnvUrNnrDZvWAipsvzQLrv1r6KF36Ciq
         LI+miVKBIUL1Bs6u6xgGEke6vZbkt116xIPSd7TU35Wy+MxhUzYuq7QWfkFGmEnVv7e/
         gfb2QOEO/cqomd/Q2ySHEpj2iQRFeUvsdfxwA6nqKERtKKtY3SXmJqVBbitoba3N+frL
         5z1kOdd5jQPGeAX/SAkHEAXgCifJ7asP14TiBn/OBYHNw7NqWS927Vxh//Ib+BTEvVGt
         Gd/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=n6zV0SYa;
       spf=pass (google.com: domain of sedat.dilek@gmail.com designates 2607:f8b0:4864:20::d42 as permitted sender) smtp.mailfrom=sedat.dilek@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tsXFBW2RFAh2hh6ldjz5gymJyNZSSzqgh2sf7Vuzpgo=;
        b=jk6FTdCVsxW2cKitVEOpUn359+FVoQPKLeS04d0r8K4cnBs0UgYE8RvZpx8RPIZ5Nj
         K2P672pTt/RqHYpImeBztKkK3K8j68BmclGWt5eBb+yc0++kq+KVaIKQqHHunZBSAN8a
         0DYkjnqPJ99vwg24Dm70gCMhi5fyPMOwGy8CPr9rHBIwlTSopTi2AQqAiW3Jjup3RqLn
         ewiB9O1pVec1e4ZYg/lQP2xnDvPEK09MsppXPB1pDBJvUIify8gsES/3YTn3K11Z7PoW
         Ec+EzMPtszpHAqw9HT5qAV8qOreFwtF9RZi2R43lcYkl4ybGZdPr9J+PJLkFXa7MkYmC
         J/Ag==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tsXFBW2RFAh2hh6ldjz5gymJyNZSSzqgh2sf7Vuzpgo=;
        b=i1O+AsS0ksO87J8Hyan7Rh8kJXxi7tuYBPkYXT8DFU5v5L2kGoWuN3kRv4vYVayHTE
         JCBTTnCikmRo1i3/xx6E2v2CnN/bfDt3pd0dfgKloBNABjnqDtd/4At4MXDRUUBrs2yv
         6anjLEp+qaBMmRR8eqGMeyqlnNjJ90ghuHn6K2yCfeLb9E29CrYojKnXB3OP7iNnunp9
         uQnQLsD/JYm/mAP1y5ONWi8R6qx3KpX+fQIlG/unsqR/mCtQckJv2OX9C22gBO+kZdj/
         hgYtPO2DsXbJX8ieKf7Y80pP8F/5dUJQ9QL5C1862jkQkUywVu2Veutu2/xgmQCEYqzs
         2tnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to
         :reply-to:from:date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tsXFBW2RFAh2hh6ldjz5gymJyNZSSzqgh2sf7Vuzpgo=;
        b=M76y0yXEFodQFDsLkA2kCghDcwvEpxQY07tVhL1iDkvTYLQvULnak2SRwJ47Dj2Zjv
         mf0WmXiPIG4EAH1EsWAN5+DxhdLnVqGuLVeWZG/Fw7Sv88y+8LmW2vY40VEZunYQdca+
         efZTGZtz+6ddhPcSXsTIBDcFfdCDaCeaEKF3O1O5YvzPVrT+1nr5PNBKAhaz3du1puD8
         khUloQlIVN0Jq4cUjM/+APjMeTEMJzPZMza7jtvvHogV+cMeZ8E/yrzkFs1BCYkapuyM
         RbwHNKtf+hPFFn5qdigwQzcebwiCIIn3ybrjNeX6aQiN3fBmQLxy3wFVUdYFOhmVAwQv
         TQ8Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530QMSH5rkYt098GpsC0DGWFJ/5rJ8f+xV0paaeqqTBJipY9Ui4G
	EmCe6nYsCVFHrrUi76U1pu4=
X-Google-Smtp-Source: ABdhPJztHr22XS6U1FVjUgySfwV13lxfszg/k6wLfyK9JTV7n/YKtt0PXHXMzzsliKclNI22Z5J1Ag==
X-Received: by 2002:a17:902:fe84:: with SMTP id x4mr7437327plm.1.1590606681367;
        Wed, 27 May 2020 12:11:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:4f04:: with SMTP id p4ls1845869pjh.3.canary-gmail;
 Wed, 27 May 2020 12:11:20 -0700 (PDT)
X-Received: by 2002:a17:90a:7385:: with SMTP id j5mr6376856pjg.204.1590606680856;
        Wed, 27 May 2020 12:11:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590606680; cv=none;
        d=google.com; s=arc-20160816;
        b=BWJuVjVGmFRl6HdDkeSMxFeHR7SMC+i5xoq/HwQfAi/6zG4g+xJMm4rhuda46Nkosf
         YmMz8V6h6F0+5NO8G6zdg9o8UpOCRxC8teaqLogLXRDk84/nRGfS2k1wap8ZLVfuUh9r
         6AkUbn9q2wEXuYFvur3uQ6rmZd35aNHmhK3M2E/ysODV1Bv2t7Gxudy0rjXYkb8cdrrH
         7pyv3zzogBC3rmgjwWM4ALgWIK9PLhpYabgujKTJ7fJeau8Llw+4dY/aXrdXGwGukGJg
         IdH+efR4IHH8+q13yHR1al/uiVxra9CeL3FIqsm6boDnjyFU12XRO1D8vT8NNyTNVnW6
         ZfJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:reply-to:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2Bcnmg1EgnfjTcnvj1Aw3QKP56IMZAnvcGT8sqHeRnk=;
        b=ETXw+mez7OBoWF4qsEVJkaRz1RHi3+stcSKGd30bNDG2PncflM/YwD3erHsNmHWWya
         SkWwXjyroBtDN8GY2aPGdnQRUmY0LDttDmqKhuBFe71aUZ1NexRhFpWerB7V/EKVZ1jn
         JJhVs/6ar9OEuC/Ivq582JaKinKcMoPHHahA+1nzzgd21cbwaLkXY6KanPA7bvXKEHxc
         aAfQOCNk8gtFcydHueSimN+Kk0SpIOBzvEPmspnF8JgVVWhoB+LQHxbbB31IP5glqOS0
         hdY7Zm9a9Cmfe4MIRjIlu2PtlxHwlCgIpNhvzh1CbZOdCkOw4nHLvRAy6QdKaCQbhMqf
         aN5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=n6zV0SYa;
       spf=pass (google.com: domain of sedat.dilek@gmail.com designates 2607:f8b0:4864:20::d42 as permitted sender) smtp.mailfrom=sedat.dilek@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd42.google.com (mail-io1-xd42.google.com. [2607:f8b0:4864:20::d42])
        by gmr-mx.google.com with ESMTPS id j204si384270pfd.1.2020.05.27.12.11.20
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 May 2020 12:11:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of sedat.dilek@gmail.com designates 2607:f8b0:4864:20::d42 as permitted sender) client-ip=2607:f8b0:4864:20::d42;
Received: by mail-io1-xd42.google.com with SMTP id d7so27370910ioq.5;
        Wed, 27 May 2020 12:11:20 -0700 (PDT)
X-Received: by 2002:a02:5249:: with SMTP id d70mr7200470jab.121.1590606680180;
 Wed, 27 May 2020 12:11:20 -0700 (PDT)
MIME-Version: 1.0
References: <20200527103236.148700-1-elver@google.com> <CAK8P3a1MFgRxm6=+9WZKNzN+Nc5fhrDso6orSNQaaa-0yqygYA@mail.gmail.com>
 <CA+icZUWtzu0ONUSy0E27Mq1BrdO79qNaY3Si-PDhHZyF8M4S5g@mail.gmail.com>
 <CAK8P3a04=mVQgSrvDhpVxQj50JEFDn_xMhYrvjmUnLYTWH3QXQ@mail.gmail.com>
 <CA+icZUXVSTxDYJwXLyAwZd91cjMPcPRpeAR72JKqkqa-wRNnWg@mail.gmail.com>
 <CAK8P3a3i0kPf8dRg7Ko-33hsb+LkP=P05uz2tGvg5B43O-hFvg@mail.gmail.com>
 <CA+icZUWr5xDz5ujBfsXjnDdiBuopaGE6xO5LJQP9_y=YoROb+Q@mail.gmail.com>
 <CANpmjNOtKQAB_3t1G5Da-J1k-9Dk6eQKP+xNozRbmHJXZqXGFw@mail.gmail.com>
 <CA+icZUWzPMOj+qsDz-5Z3tD-hX5gcowjBkwYyiy8SL36Jg+2Nw@mail.gmail.com> <CANpmjNOPcFSr2n_ro8TqhOBXOBfUY0vZtj_VT7hh3HOhJN4BqQ@mail.gmail.com>
In-Reply-To: <CANpmjNOPcFSr2n_ro8TqhOBXOBfUY0vZtj_VT7hh3HOhJN4BqQ@mail.gmail.com>
Reply-To: sedat.dilek@gmail.com
From: Sedat Dilek <sedat.dilek@gmail.com>
Date: Wed, 27 May 2020 21:11:13 +0200
Message-ID: <CA+icZUVK=5agY_FPdPeRbZyn3EoUgnmPToR3iGWuCzY+KHtoAA@mail.gmail.com>
Subject: Re: [PATCH -tip] compiler_types.h: Optimize __unqual_scalar_typeof
 compilation time
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>, Will Deacon <will@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Borislav Petkov <bp@alien8.de>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: sedat.dilek@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=n6zV0SYa;       spf=pass
 (google.com: domain of sedat.dilek@gmail.com designates 2607:f8b0:4864:20::d42
 as permitted sender) smtp.mailfrom=sedat.dilek@gmail.com;       dmarc=pass
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

On Wed, May 27, 2020 at 3:57 PM Marco Elver <elver@google.com> wrote:
>
> On Wed, 27 May 2020 at 15:37, Sedat Dilek <sedat.dilek@gmail.com> wrote:
> >
> > On Wed, May 27, 2020 at 3:30 PM Marco Elver <elver@google.com> wrote:
> > >
> > > On Wed, 27 May 2020 at 15:11, Sedat Dilek <sedat.dilek@gmail.com> wrote:
> > > >
> > > > On Wed, May 27, 2020 at 2:50 PM Arnd Bergmann <arnd@arndb.de> wrote:
> > > > >
> > > > > On Wed, May 27, 2020 at 2:35 PM Sedat Dilek <sedat.dilek@gmail.com> wrote:
> > > > > > On Wed, May 27, 2020 at 2:31 PM Arnd Bergmann <arnd@arndb.de> wrote:
> > > > > > > On Wed, May 27, 2020 at 1:36 PM Sedat Dilek <sedat.dilek@gmail.com> wrote:
> > > > > > > > On Wed, May 27, 2020 at 1:27 PM Arnd Bergmann <arnd@arndb.de> wrote:
> > > > > > > > > On Wed, May 27, 2020 at 12:33 PM Marco Elver <elver@google.com> wrote:
> > > > > > > > >
> > > > > > > > > This gives us back 80% of the performance drop on clang, and 50%
> > > > > > > > > of the drop I saw with gcc, compared to current mainline.
> > > > > > > > >
> > > > > > > > > Tested-by: Arnd Bergmann <arnd@arndb.de>
> > > > > > > > >
> > > > > > > >
> > > > > > > > Hi Arnd,
> > > > > > > >
> > > > > > > > with "mainline" you mean Linux-next aka Linux v5.8 - not v5.7?
> > > > > > >
> > > > > > > I meant v5.7.
> > > > > > >
> > > > > > > > I have not seen __unqual_scalar_typeof(x) in compiler_types.h in Linux v5.7.
> > > > > > > >
> > > > > > > > Is there a speedup benefit also for Linux v5.7?
> > > > > > > > Which patches do I need?
> > > > > > >
> > > > > > > v5.7-rc is the baseline and is the fastest I currently see. On certain files,
> > > > > > > I saw an intermittent 10x slowdown that was already fixed earlier, now
> > > > > > > linux-next
> > > > > > > is more like 2x slowdown for me and 1.2x with this patch on top, so we're
> > > > > > > almost back to the speed of linux-5.7.
> > > > > > >
> > > > > >
> > > > > > Which clang version did you use - and have you set KCSAN kconfigs -
> > > > > > AFAICS this needs clang-11?
> > > > >
> > > > > I'm currently using clang-11, but I see the same problem with older
> > > > > versions, and both with and without KCSAN enabled. I think the issue
> > > > > is mostly the deep nesting of macros that leads to code bloat.
> > > > >
> > > >
> > > > Thanks.
> > > >
> > > > With clang-10:
> > > >
> > > > $ scripts/diffconfig /boot/config-5.7.0-rc7-2-amd64-clang .config
> > > >  BUILD_SALT "5.7.0-rc7-2-amd64-clang" -> "5.7.0-rc7-3-amd64-clang"
> > > > +HAVE_ARCH_KCSAN y
> > >
> > > Clang 10 doesn't support KCSAN (HAVE_KCSAN_COMPILER unset).
> > >
> > > > With clang-11:
> > > >
> > > > $ scripts/diffconfig /boot/config-5.7.0-rc7-2-amd64-clang .config
> > > >  BUILD_SALT "5.7.0-rc7-2-amd64-clang" -> "5.7.0-rc7-3-amd64-clang"
> > > >  CLANG_VERSION 100001 -> 110000
> > > > +CC_HAS_ASM_INLINE y
> > > > +HAVE_ARCH_KCSAN y
> > > > +HAVE_KCSAN_COMPILER y
> > > > +KCSAN n
> > > >
> > > > Which KCSAN kconfigs did you enable?
> > >
> > > To clarify: as said in [1], KCSAN (or any other instrumentation) is no
> > > longer relevant to the issue here, and the compile-time regression is
> > > observable with most configs. The problem is due to pre-processing and
> > > parsing, which came about due to new READ_ONCE() and the
> > > __unqual_scalar_typeof() macro (which this patch optimizes).
> > >
> > > KCSAN and new ONCEs got tangled up because we first attempted to
> > > annotate {READ,WRITE}_ONCE() with data_race(), but that turned out to
> > > have all kinds of other issues (explanation in [2]). So we decided to
> > > drop all the KCSAN-specific bits from ONCE, and require KCSAN to be
> > > Clang 11. Those fixes were applied to the first version of new
> > > {READ,WRITE}_ONCE() in -tip, which actually restored the new ONCEs to
> > > the pre-KCSAN version (now that KCSAN can deal with them without
> > > annotations).
> > >
> > > Hope this makes more sense now.
> > >
> > > [1] https://lore.kernel.org/lkml/CANpmjNOUdr2UG3F45=JaDa0zLwJ5ukPc1MMKujQtmYSmQnjcXg@mail.gmail.com/
> > > [2] https://lore.kernel.org/lkml/20200521142047.169334-1-elver@google.com/
> > >
> >
> > Thanks, Marco.
> >
> > I pulled tip.git#locking/kcsan on top of Linux v5.7-rc7 and applied this patch.
> > Just wanted to try KCSAN for the first time and it will also be my
> > first building with clang-11.
> > That's why I asked.
>
> In general, CONFIG_KCSAN=y and the defaults for the other KCSAN
> options should be good. Depending on the size of your system, you
> could also tweak KCSAN runtime performance:
> https://lwn.net/Articles/816850/#Interacting%20with%20KCSAN%20at%20Runtime
> -- the defaults should be good for most systems though.
> Hope this helps. Any more questions, do let me know.
>

Which "projects" and packages do I need?

I have installed:

# LC_ALL=C apt-get install llvm-11 clang-11 lld-11
--no-install-recommends -t llvm-toolchain -y

# dpkg -l | grep
1:11~++20200527111130+65030821d4a-1~exp1~20200527091804.3261 | awk
'/^ii/ {print $1 " " $2 " " $3}' | column -t
ii  clang-11
1:11~++20200527111130+65030821d4a-1~exp1~20200527091804.3261
ii  libclang-common-11-dev
1:11~++20200527111130+65030821d4a-1~exp1~20200527091804.3261
ii  libclang-cpp11
1:11~++20200527111130+65030821d4a-1~exp1~20200527091804.3261
ii  libclang1-11
1:11~++20200527111130+65030821d4a-1~exp1~20200527091804.3261
ii  libllvm11:amd64
1:11~++20200527111130+65030821d4a-1~exp1~20200527091804.3261
ii  lld-11
1:11~++20200527111130+65030821d4a-1~exp1~20200527091804.3261
ii  llvm-11
1:11~++20200527111130+65030821d4a-1~exp1~20200527091804.3261
ii  llvm-11-runtime
1:11~++20200527111130+65030821d4a-1~exp1~20200527091804.3261

Is that enough?

- Sedat -

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BicZUVK%3D5agY_FPdPeRbZyn3EoUgnmPToR3iGWuCzY%2BKHtoAA%40mail.gmail.com.
