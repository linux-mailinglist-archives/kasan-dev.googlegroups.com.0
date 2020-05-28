Return-Path: <kasan-dev+bncBDHYDDNWVUNRBT6SX73AKGQEWUAJDGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 963D11E6798
	for <lists+kasan-dev@lfdr.de>; Thu, 28 May 2020 18:39:44 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id v194sf758016ybv.5
        for <lists+kasan-dev@lfdr.de>; Thu, 28 May 2020 09:39:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590683983; cv=pass;
        d=google.com; s=arc-20160816;
        b=otgkWlayO31Lj6X+nWjMVjMN48QXyE2h+mAHiqMXBTAWj2yISVssjYekEPOiWgZh16
         YVoe4wbzLClNe6j3cj0Yq/QMiskTsqY74DdufPwkxQZRCu/EgsM3pFRxoZh/3W8KmfZ+
         rPl5r3jD+eC1X/gNmSS6WfYzg714+LokhBoxiLuBu325NJjhB9NgqCeYagSiPea8Juj0
         X0NeHdEA5G8I2NXuPQ7HOFO3BJUOqc0yTwBfojEzJPjSB0/hWCeXnx+hEi/UH6c89PNG
         HK9Ys6Zrxr64NYkwtlO64Bgo7U2W/af6FTlbff44E+oCsGtOJygvEB3j0fKHMz8XbH0E
         gZIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :reply-to:in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=QCTjgk7d8+P1iqi9RyUcqvyuP+vBvRFmUTqgTtCSukg=;
        b=ZB3JQB9pGJty9IwptYayap+WGWXra1IoFtY46Z87fGxPhmBXy0Y73EtPfFfNtHNvA/
         TU/jlBFkSSHgsJLdbz5P4A6JtplkgI7WyrEXtO6ck4sGCPqo+z3ElLXIw98+w5OeOo+i
         NXFmQEiEdhO/tme/B1q28c+R/jU2OihBeLicoHpev3uN6/Zu0i8Mp//e0HD171I54QDq
         BjL3qM8jSaAzYL4uvck5k2AeaxY9ycRR4L8GmFyZxpA1ukvbMX1ufFdmFrRVO5yKuW5a
         hOzSmpdT7yIvaIRBEnGC9LNbiiCqP1Lbneqozju94+TKpYFJ/JNUX5UTVMrvMdJoutQD
         q+SQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="TQkg3Z/E";
       spf=pass (google.com: domain of sedat.dilek@gmail.com designates 2607:f8b0:4864:20::d41 as permitted sender) smtp.mailfrom=sedat.dilek@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QCTjgk7d8+P1iqi9RyUcqvyuP+vBvRFmUTqgTtCSukg=;
        b=iCjy+u5hEXsHUXAoVy31nPciKU3afLRiOk4MnooitPVukfT+tlAzoec1oV8EhrmjCU
         FWdYJRUKGGI5YyyDjNSfmsPkohtrI0TXTgekxiNbKT/OSti73zSXqoCWps/HM7xuUd5q
         pbpoYJWfXhwBefDSWAKlyBnv7DZNFtJ/s6r1W52gzhxuEpvDP7CHcfZuSFcoyRZIxtge
         F3C7RSOLXwQ42fyFMQEE8m0wXrfcBb5b9jgia9gyuIySHRjkFUWuj1rnkxPWmDKSdnD6
         0PsN1dsYl6t/jmHWmA2NK/dsZHm2NonXQt02memONeFbnkg+cEVEz4pCc4y5aoxT2WJL
         PUMw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QCTjgk7d8+P1iqi9RyUcqvyuP+vBvRFmUTqgTtCSukg=;
        b=pNMaVHImmeP4RSV3FWn+0ZjHqctjTQ5zfr6ayutLQuvzFo5kLnQ7Baergb2k1RXBrL
         UJ4Wmj5lC2xt+cFQYr3Nxb2J4nrOL2fU+Zvp39DxXTTlKsGY0rE9s/+RiZ+PZdQMFPgq
         t5U9Iqbyn0e8OW/hFU67K8CwI5zmMj4GttdhC8oI+u2PMi9ppJqeq+yu1V4onLP5dCVk
         +mKyqey2XGy8T1ksUK0dErPfp5H6lSVwOQeu4UVxtJr4L/GcRD/xIvrYZmVVhKUFzZ95
         kQfMAc266imYYr3dFfOvrueHqgEeGjV2cmK6Qj1F8zVa5b6Z4xrrCPhz0P2LFpAAcQWN
         fQ/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to
         :reply-to:from:date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QCTjgk7d8+P1iqi9RyUcqvyuP+vBvRFmUTqgTtCSukg=;
        b=ML3EyIM3unK5XdK1FHxgOjKyQ7Nbc1dn4UhLcfdwnrVKGMl25HCYiWX+1yvbBu3g7W
         75bqOhsMEdAPGih9uCT/OHV62EvjW+jryfP4+I4rnE9vI/IWwNsQQlBV6IzISClchI+/
         blmrIZPPDutviXzB2Xin+xerXB9tDtPR8Omda8vdtbTbujL4EHF1Zwh4v6zIgiw7Jxqn
         zgjFxMxJE84XrQ422IZ5aCMZ5pFeX7s37X3u4MixaqanRvXeXuksi+3kZefj82N6Ve5N
         DS+z5B/PmQz2fKruEYkAmvqO7GsTJCx+E2O+zY9dYiaQUH37K92HRTBe2mMz1lQ991ab
         rrPQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533dZEKDO9+cg0pMYPEaV6OAc2rB/uOnf7fnqf5uIZ7MX0oj2i1X
	S/pCRSGhEX2sG2bglWR2mQc=
X-Google-Smtp-Source: ABdhPJxpvZ35NIhs3IvPClVoNho3HVMuEnkfwDxDUqLmUeV5flavXXXeOW031KPEGhdvZGF1J7sZAw==
X-Received: by 2002:a5b:3c9:: with SMTP id t9mr7132604ybp.40.1590683983487;
        Thu, 28 May 2020 09:39:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:cd43:: with SMTP id d64ls1111778ybf.6.gmail; Thu, 28 May
 2020 09:39:41 -0700 (PDT)
X-Received: by 2002:a25:aaec:: with SMTP id t99mr6791382ybi.262.1590683981525;
        Thu, 28 May 2020 09:39:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590683981; cv=none;
        d=google.com; s=arc-20160816;
        b=0F3Eh+G9mv9wqvET769jsNtr97ZLppI2SbaKK3gWnJEWmOi5aOl9H/+77iPm1QCxxE
         tvGk28Msfmu8kcJNZGdsgvf7FZfdmoIF5+hbadFQSMP7nWAj4OGYX0t3rS+e35EqIexs
         1tN77wnA5jwMdAsfPjxsv8WYDn/4W3cLXVym+Urgf5QVf0ohTRtOHW5m0eq1JhySzLol
         oKPCtJISMMv/WzFjp3tB1vX74MYmhBA1j6Zt5f6+TUazKGNqBMMEmuo67/ig2WyZAw7i
         086pQv7AHMIuwusePyhhSSWILMWodPtCViIHVyEbrboHNdx7CtwttYrWWe3+5MyqJLv6
         PI+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:reply-to:in-reply-to:references
         :mime-version:dkim-signature;
        bh=b49uRRn6kGfrBFDUIRU2bZkw+wlzpFf1iaU7drJseCA=;
        b=KSd9pICPOhC5yUEeyfd5KKq+ZXAgercxSCIheyvHwd4Q8Cwqe/vliSFqewIiEhMYHi
         zRyUe6h1Bzr/CV2UMS78VPPMbqJ6pGafOGw02mKT7fuHcPai8WM8S+rFTd0cukmV2JHE
         PU7hu6orM22y/aVuFmAt/TR7C3i68bU21Z96Mil77qMsFOfANZ0uABRt8EBVKJiBLEmX
         7ESEMh98fV4597FA9OT/gYidJ5ItYyQuQ+mOoW1SsiWr8PdaezuJMNx5RASbjykCK4N4
         58ywoTLMHV7Bui/voadDoIo4hv/RUivimPnAsa445JGCP9Qo61g6bcy5DetUX7wtY+lf
         7L8w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="TQkg3Z/E";
       spf=pass (google.com: domain of sedat.dilek@gmail.com designates 2607:f8b0:4864:20::d41 as permitted sender) smtp.mailfrom=sedat.dilek@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd41.google.com (mail-io1-xd41.google.com. [2607:f8b0:4864:20::d41])
        by gmr-mx.google.com with ESMTPS id s35si427610ybi.5.2020.05.28.09.39.41
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 28 May 2020 09:39:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of sedat.dilek@gmail.com designates 2607:f8b0:4864:20::d41 as permitted sender) client-ip=2607:f8b0:4864:20::d41;
Received: by mail-io1-xd41.google.com with SMTP id y5so7886174iob.12;
        Thu, 28 May 2020 09:39:41 -0700 (PDT)
X-Received: by 2002:a02:ca18:: with SMTP id i24mr3395552jak.70.1590683981110;
 Thu, 28 May 2020 09:39:41 -0700 (PDT)
MIME-Version: 1.0
References: <20200527103236.148700-1-elver@google.com> <CAK8P3a1MFgRxm6=+9WZKNzN+Nc5fhrDso6orSNQaaa-0yqygYA@mail.gmail.com>
 <CA+icZUWtzu0ONUSy0E27Mq1BrdO79qNaY3Si-PDhHZyF8M4S5g@mail.gmail.com>
 <CAK8P3a04=mVQgSrvDhpVxQj50JEFDn_xMhYrvjmUnLYTWH3QXQ@mail.gmail.com>
 <CA+icZUXVSTxDYJwXLyAwZd91cjMPcPRpeAR72JKqkqa-wRNnWg@mail.gmail.com>
 <CAK8P3a3i0kPf8dRg7Ko-33hsb+LkP=P05uz2tGvg5B43O-hFvg@mail.gmail.com>
 <CA+icZUWr5xDz5ujBfsXjnDdiBuopaGE6xO5LJQP9_y=YoROb+Q@mail.gmail.com>
 <CANpmjNOtKQAB_3t1G5Da-J1k-9Dk6eQKP+xNozRbmHJXZqXGFw@mail.gmail.com>
 <CA+icZUWzPMOj+qsDz-5Z3tD-hX5gcowjBkwYyiy8SL36Jg+2Nw@mail.gmail.com>
 <CANpmjNOPcFSr2n_ro8TqhOBXOBfUY0vZtj_VT7hh3HOhJN4BqQ@mail.gmail.com>
 <CA+icZUVK=5agY_FPdPeRbZyn3EoUgnmPToR3iGWuCzY+KHtoAA@mail.gmail.com>
 <CANpmjNOA2Oa=AJkKYadbvEVOaqzgD840aC5wfGGrFvDqUmjhpg@mail.gmail.com>
 <CA+icZUXu15=NK8wQgy=eeu=JcOGfB4Qr6UnwzTVvcH4T1L4pUQ@mail.gmail.com> <CANpmjNNFxvL2Mrq1eJeRsyU19wgSdZrtLaTo2ksOfTzPTGKOzQ@mail.gmail.com>
In-Reply-To: <CANpmjNNFxvL2Mrq1eJeRsyU19wgSdZrtLaTo2ksOfTzPTGKOzQ@mail.gmail.com>
Reply-To: sedat.dilek@gmail.com
From: Sedat Dilek <sedat.dilek@gmail.com>
Date: Thu, 28 May 2020 18:39:42 +0200
Message-ID: <CA+icZUU7Jg0gJgWOwUD0a8ei2wKGFN2FeJZzm=_jG4-Nntck2Q@mail.gmail.com>
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
 header.i=@gmail.com header.s=20161025 header.b="TQkg3Z/E";       spf=pass
 (google.com: domain of sedat.dilek@gmail.com designates 2607:f8b0:4864:20::d41
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

On Thu, May 28, 2020 at 5:16 PM Marco Elver <elver@google.com> wrote:
>
> On Thu, 28 May 2020 at 04:12, Sedat Dilek <sedat.dilek@gmail.com> wrote:
> >
> [...]
>
> > > > >
> > > > > In general, CONFIG_KCSAN=y and the defaults for the other KCSAN
> > > > > options should be good. Depending on the size of your system, you
> > > > > could also tweak KCSAN runtime performance:
> > > > > https://lwn.net/Articles/816850/#Interacting%20with%20KCSAN%20at%20Runtime
> > > > > -- the defaults should be good for most systems though.
> > > > > Hope this helps. Any more questions, do let me know.
> > > > >
> > > >
> > > > Which "projects" and packages do I need?
> > > >
> > > > I have installed:
> > > >
> > > > # LC_ALL=C apt-get install llvm-11 clang-11 lld-11
> > > > --no-install-recommends -t llvm-toolchain -y
> > > >
> > > > # dpkg -l | grep
> > > > 1:11~++20200527111130+65030821d4a-1~exp1~20200527091804.3261 | awk
> > > > '/^ii/ {print $1 " " $2 " " $3}' | column -t
> > > > ii  clang-11
> > > > 1:11~++20200527111130+65030821d4a-1~exp1~20200527091804.3261
> > > > ii  libclang-common-11-dev
> > > > 1:11~++20200527111130+65030821d4a-1~exp1~20200527091804.3261
> > > > ii  libclang-cpp11
> > > > 1:11~++20200527111130+65030821d4a-1~exp1~20200527091804.3261
> > > > ii  libclang1-11
> > > > 1:11~++20200527111130+65030821d4a-1~exp1~20200527091804.3261
> > > > ii  libllvm11:amd64
> > > > 1:11~++20200527111130+65030821d4a-1~exp1~20200527091804.3261
> > > > ii  lld-11
> > > > 1:11~++20200527111130+65030821d4a-1~exp1~20200527091804.3261
> > > > ii  llvm-11
> > > > 1:11~++20200527111130+65030821d4a-1~exp1~20200527091804.3261
> > > > ii  llvm-11-runtime
> > > > 1:11~++20200527111130+65030821d4a-1~exp1~20200527091804.3261
> > > >
> > > > Is that enough?
> > >
> > > Just clang-11 (and its transitive dependencies) is enough. Unsure what
> > > your installed binary is, likely "clang-11", so if you can do "make
> > > CC=clang-11 defconfig" (and check for CONFIG_HAVE_KCSAN_COMPILER)
> > > you're good to go.
> > >
> >
> > I was able to build with clang-11 from apt.llvm.org.
> >
> > [ build-time ]
> >
> > Normally, it takes me approx. 05:00 to build with clang-10
> > (10.0.1-rc1) and Linux v5.7-rc7.
> >
> > This time start: 21:18 and stop: 03:45 means 06:27 - took 01:27 longer.
> >
> > Samsung Ultrabook 2nd generation aka Intel Sandybridge CPU with 'make -j3'.
> >
> > [ diffconfig ]
> >
> >  BUILD_SALT "5.7.0-rc7-2-amd64-clang" -> "5.7.0-rc7-3-amd64-clang"
> >  CLANG_VERSION 100001 -> 110000
> > +CC_HAS_ASM_INLINE y
> > +HAVE_ARCH_KCSAN y
> > +HAVE_KCSAN_COMPILER y
> > +KCSAN y
> > +KCSAN_ASSUME_PLAIN_WRITES_ATOMIC y
> > +KCSAN_DEBUG n
> > +KCSAN_DELAY_RANDOMIZE y
> > +KCSAN_EARLY_ENABLE y
> > +KCSAN_IGNORE_ATOMICS n
> > +KCSAN_INTERRUPT_WATCHER n
> > +KCSAN_NUM_WATCHPOINTS 64
> > +KCSAN_REPORT_ONCE_IN_MS 3000
> > +KCSAN_REPORT_RACE_UNKNOWN_ORIGIN y
> > +KCSAN_REPORT_VALUE_CHANGE_ONLY y
> > +KCSAN_SELFTEST y
> > +KCSAN_SKIP_WATCH 4000
> > +KCSAN_SKIP_WATCH_RANDOMIZE y
> > +KCSAN_UDELAY_INTERRUPT 20
> > +KCSAN_UDELAY_TASK 80
> >
> > I am seeing this data-races:
> >
> > root@iniza:~# LC_ALL=C dmesg -T | grep 'BUG: KCSAN: data-race'
> > [Thu May 28 03:51:53 2020] BUG: KCSAN: data-race in
> > mutex_spin_on_owner+0xe0/0x1b0
> > [Thu May 28 03:52:00 2020] BUG: KCSAN: data-race in mark_page_accessed
> > / workingset_activation
> > [Thu May 28 03:52:02 2020] BUG: KCSAN: data-race in
> > mutex_spin_on_owner+0xe0/0x1b0
> > [Thu May 28 03:52:08 2020] BUG: KCSAN: data-race in
> > blk_mq_sched_dispatch_requests / blk_mq_sched_dispatch_requests
> > [Thu May 28 03:52:10 2020] BUG: KCSAN: data-race in dd_has_work /
> > dd_insert_requests
> > [Thu May 28 03:52:11 2020] BUG: KCSAN: data-race in
> > mutex_spin_on_owner+0xe0/0x1b0
> > [Thu May 28 03:52:13 2020] BUG: KCSAN: data-race in
> > page_counter_try_charge / page_counter_try_charge
> > [Thu May 28 03:52:15 2020] BUG: KCSAN: data-race in ep_poll_callback /
> > ep_send_events_proc
> > [Thu May 28 03:52:21 2020] BUG: KCSAN: data-race in
> > mutex_spin_on_owner+0xe0/0x1b0
> > [Thu May 28 03:52:25 2020] BUG: KCSAN: data-race in
> > mutex_spin_on_owner+0xe0/0x1b0
> > [Thu May 28 03:52:26 2020] BUG: KCSAN: data-race in dd_has_work /
> > deadline_remove_request
> > [Thu May 28 03:52:31 2020] BUG: KCSAN: data-race in dd_has_work /
> > deadline_remove_request
> > [Thu May 28 03:52:38 2020] BUG: KCSAN: data-race in dd_has_work /
> > deadline_remove_request
> > [Thu May 28 03:52:53 2020] BUG: KCSAN: data-race in dd_has_work /
> > dd_insert_requests
> > [Thu May 28 03:52:56 2020] BUG: KCSAN: data-race in dd_has_work /
> > deadline_remove_request
> > [Thu May 28 03:52:59 2020] BUG: KCSAN: data-race in
> > blk_mq_sched_dispatch_requests / blk_mq_sched_dispatch_requests
> > [Thu May 28 03:53:25 2020] BUG: KCSAN: data-race in
> > rwsem_spin_on_owner+0x102/0x1a0
> > [Thu May 28 03:53:25 2020] BUG: KCSAN: data-race in
> > page_counter_try_charge / page_counter_try_charge
> > [Thu May 28 03:53:39 2020] BUG: KCSAN: data-race in do_epoll_wait /
> > ep_poll_callback
> > [Thu May 28 03:53:39 2020] BUG: KCSAN: data-race in find_next_and_bit+0x30/0xd0
> > [Thu May 28 03:53:41 2020] BUG: KCSAN: data-race in dd_has_work /
> > dd_insert_requests
> > [Thu May 28 03:53:43 2020] BUG: KCSAN: data-race in do_epoll_wait /
> > ep_poll_callback
> > [Thu May 28 03:53:45 2020] BUG: KCSAN: data-race in dd_has_work /
> > dd_insert_requests
> > [Thu May 28 03:53:46 2020] BUG: KCSAN: data-race in
> > blk_mq_sched_dispatch_requests / blk_mq_sched_dispatch_requests
> > [Thu May 28 03:53:47 2020] BUG: KCSAN: data-race in
> > rwsem_spin_on_owner+0x102/0x1a0
> > [Thu May 28 03:54:02 2020] BUG: KCSAN: data-race in dd_has_work /
> > deadline_remove_request
> > [Thu May 28 03:54:11 2020] BUG: KCSAN: data-race in find_next_and_bit+0x30/0xd0
> > [Thu May 28 03:54:19 2020] BUG: KCSAN: data-race in
> > rwsem_spin_on_owner+0x102/0x1a0
> > [Thu May 28 03:55:00 2020] BUG: KCSAN: data-race in
> > mutex_spin_on_owner+0xe0/0x1b0
> > [Thu May 28 03:56:14 2020] BUG: KCSAN: data-race in dd_has_work /
> > deadline_remove_request
> > [Thu May 28 03:56:50 2020] BUG: KCSAN: data-race in dd_has_work /
> > deadline_remove_request
> > [Thu May 28 03:56:50 2020] BUG: KCSAN: data-race in dd_has_work /
> > deadline_remove_request
> > [Thu May 28 03:56:52 2020] BUG: KCSAN: data-race in
> > tick_nohz_next_event / tick_nohz_stop_tick
> > [Thu May 28 03:56:58 2020] BUG: KCSAN: data-race in
> > blk_mq_sched_dispatch_requests / blk_mq_sched_dispatch_requests
> > [Thu May 28 03:57:58 2020] BUG: KCSAN: data-race in
> > blk_mq_sched_dispatch_requests / blk_mq_sched_dispatch_requests
> > [Thu May 28 03:58:00 2020] BUG: KCSAN: data-race in dd_has_work /
> > deadline_remove_request
> > [Thu May 28 03:58:07 2020] BUG: KCSAN: data-race in
> > tick_nohz_next_event / tick_nohz_stop_tick
> > [Thu May 28 03:58:44 2020] BUG: KCSAN: data-race in
> > mutex_spin_on_owner+0xe0/0x1b0
> > [Thu May 28 03:58:49 2020] BUG: KCSAN: data-race in __bitmap_subset+0x38/0xd0
> > [Thu May 28 03:59:46 2020] BUG: KCSAN: data-race in
> > tick_nohz_next_event / tick_nohz_stop_tick
> > [Thu May 28 04:00:25 2020] BUG: KCSAN: data-race in dd_has_work /
> > deadline_remove_request
> > [Thu May 28 04:00:26 2020] BUG: KCSAN: data-race in
> > tick_nohz_next_event / tick_nohz_stop_tick
> >
> > Full dmesg output and linux-config attached.
>
> Thank you for the report. There are a number of known data races. Note
> that, we do not think it's wise to rush fixes for data races,
> especially because each one requires careful analysis of what the
> appropriate response is. In the meantime, also have a look at these 2
> articles (if you haven't already), which describes the current state
> of things:
>
> 1. https://lwn.net/Articles/816850/
> 2. https://lwn.net/Articles/816854/
>

Hi Marco,

thanks for your feedback.

The first article I have read already.
That does not mean I am a KCSAN expert now.

As you say each data-race needs an individual analysis.

Just one last number:
Building again a Linux v5.7-rc7 on a clang-11-compiled and
kcsan-enabled linux-kernel took me...
one hour longer (6 instead of 5 hours, start: 12:14 and stop: 18:15)

Regards,
- Sedat -

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BicZUU7Jg0gJgWOwUD0a8ei2wKGFN2FeJZzm%3D_jG4-Nntck2Q%40mail.gmail.com.
