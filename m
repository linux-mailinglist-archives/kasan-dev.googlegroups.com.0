Return-Path: <kasan-dev+bncBC3ZPIWN3EFBBNNSZD6AKGQEXIVLVLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E2B02967B4
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Oct 2020 01:43:50 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id c204sf1178697wmd.5
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 16:43:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603410230; cv=pass;
        d=google.com; s=arc-20160816;
        b=iDIBkFpSA8JeM5KSCHlfm5kt2VNL1TOhu8HAJMaK0w/TCkammXacQjS5x8T7wvoxVM
         vhiT/NP4NQYtA8xf8rdd+2eS7ktjcWf9IQUUsHV21fWlJt8CBRNoJibjJsk/hJkry92g
         CavK2JW/vjwXXL96w1MfuvlOMaWH1CuCzjTb6YI8Vo39v6kKgjdd/IidUeVrjbRJvLmz
         eoaIoY7p76FpQMhBnoJsuG4JPyie81WN0w9UcKgCuNgJiu+y2Bt9TxNqmZamz0Sde/59
         CPfrV80NJsk/WP5A/T9Vjzoh6wrm8OA+BVknjStViK4NpFBzrCubcXSwpfWQj4Xbw4tY
         SzuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=t4ywYZIgYyYS0h+DARmiZWRWXzpWLYx6hrUy0RyjsJM=;
        b=zbu41FhsTsNJQRAADDQaBQfFN7PTlbd4Lifh16mcs/h/GnbNZ/q2nGi3Nj11I6rbSg
         yBLUUciTzq0g8iE+mNKBqKJcX9wZ5dnPVok2BeY2JZroCvdwT8CaJ0dVy0C53mc0t3Py
         9M/4wrzskXB7lnFG/WJHOIRmoQdeIGtG6uySRh04bhGs8aKXKqn+1zJabgTMpDJ9Mh8J
         lYLYo/F8dM7gCdPT4GkWlITo7JHS2mRgSQ9/3cW2JCjJzGVN1GEga7XyNzmikTUz3MFx
         ZavpvVSRm4YSNGIsASia4TYiSb1t8pOmEethUvt4qmReU3y3IV8VLN2ngHNzb64sHMEA
         J2cA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=cUh4yK+P;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::141 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=t4ywYZIgYyYS0h+DARmiZWRWXzpWLYx6hrUy0RyjsJM=;
        b=pWiZcRWFo4c0Ltba7lkf6k/LqUoPgxDs9TRi2K+i82uK/wmOwf4D5IgiNeW/jfJJsR
         sAOEwZkkwNhKNQgUDorYzC7jQu0mzXY38XsHSgN6P7E5WhBg5wtNJVjlYY4tLGRSplVE
         xi1r3zgNzHGNRQ90XIWJ7urbPwPPA70xlyBVv/BJyBxwHewGiQzMIeEZvOrkQfTbZUWH
         2iXUKkGRZCJSi2s1v62JWPs1jt6R/djCYKBbiASrlsbC1Wocf+QseQ34ZvsjYpSwPePd
         K/Bc7x549DGeWIm1mmgPD+y3qBZT85tQ2kPTAn1NswoH8QwvFSLgkEheadP5mmmCK7Yo
         vPLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=t4ywYZIgYyYS0h+DARmiZWRWXzpWLYx6hrUy0RyjsJM=;
        b=byOS82HJndEtnXLe+x97o9zzseOVmxf1INQYOqnIAtBbNVt8QqwEHbj0C1xyaZhx7A
         7qlx/GMpi4JCvg7RCIG/DJf8CJ/ko+ab6r4XODiGtBZIuM5iGqzR99P+JtHs8id951y7
         gUiDx5bixbXusCJCdr4b+nIAKOToYYo7lU5dsZS2itBEvqaHMBM0HaS5OZvCfaGudmng
         /8gTKFOB+gdrYmMudzCFgH5Zdt75QiyULtm+DN7LbRjHuDzVDaGrH6dBOJMIbrarkm6o
         IQ7csFyhcgmUUec2xrN9MUy+pDVbyQywCyHm/0cpm9XoSYbFKkMI2Aucy6JvH74vvirT
         kPIg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530pHLBzTl5ZxGd3ZkyKnRp+Uq9SOQkp3DDTr6yAmSHav0dW2W+C
	PB3B0tb+k1Tsi0h7JMIILOw=
X-Google-Smtp-Source: ABdhPJyWEEu+eJDKk5GXXfetGN4M07lZtkouAOAhDC7FYkxj+snceYh1MOsNQZ/Nqxt5fWLhU19R5g==
X-Received: by 2002:adf:f903:: with SMTP id b3mr5189766wrr.142.1603410230154;
        Thu, 22 Oct 2020 16:43:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:cd8c:: with SMTP id q12ls1344389wrj.0.gmail; Thu, 22 Oct
 2020 16:43:49 -0700 (PDT)
X-Received: by 2002:adf:eccb:: with SMTP id s11mr5119624wro.135.1603410229124;
        Thu, 22 Oct 2020 16:43:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603410229; cv=none;
        d=google.com; s=arc-20160816;
        b=wHkrtO4EDQGMVsRvhGSxBUZ4bWeqZ01gRyNTg6M6LneH0AFG2j+7IHw3xU2EqIbRKq
         uAKZfmPBsaoF/zaGogqgsD/s4QRLla0rqnqCs8BayHNgRkd6PMOgzHQ9R0w9EcgE/EjR
         I3dRlP7oNmaVu8Sdah2PJiNS4kghsYMTFlx92j8peGj1wHhU75zt8CCDsW4YnPwaZzzG
         cH8Y2y2XZnVb+tY5Ite3cZzoZDR+Bai7+oxqJB/ZjP7gc6DtDGiLCsHQj1YoO4JonGjm
         zhEKUpVEiT+v7watRs1I6JM36Rt4ymBzwV/B2Z2jPW2LdALwpKbhJGG6dO2LYGDIbQtl
         VO6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=lZlkuWdQsWCC+a50v77gxrEMTeODSOjQWFOP4UJJDnk=;
        b=ntw3Gw1JXf3XEWgpthLEOehLT6l5o6+aILPtwj5ONBJHtbLIjCw93877h0PZNdBmrb
         doho82RJYjhBnAXc5D9dyz9DSrTtDeYpAE/n3d+Q0LfdtTUpmblch2aFsorrCPpwqPyM
         MpipDpOhUb/e9bTIB6573E5jDRLdsmpMxQ8srzTrZHtHQuzDyofY76D1Z+tn9V+sN6z+
         GkSmOt54yE4Bn4gI7wyFllBYvV84oA3Syi2yS9ON3Y76BcWkz3vQIPExuC5zmjOb3TSO
         D5eguJ5PQLJOB6+I+68W+nrumzGAwG221RVQwzjEYRkrWSGOOZ+Xaymm+My9r3LA1K+V
         Q6hw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=cUh4yK+P;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::141 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
Received: from mail-lf1-x141.google.com (mail-lf1-x141.google.com. [2a00:1450:4864:20::141])
        by gmr-mx.google.com with ESMTPS id v12si96380wmh.0.2020.10.22.16.43.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 16:43:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::141 as permitted sender) client-ip=2a00:1450:4864:20::141;
Received: by mail-lf1-x141.google.com with SMTP id a7so4362781lfk.9
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 16:43:49 -0700 (PDT)
X-Received: by 2002:a19:8885:: with SMTP id k127mr1518043lfd.594.1603410228300;
        Thu, 22 Oct 2020 16:43:48 -0700 (PDT)
Received: from mail-lj1-f170.google.com (mail-lj1-f170.google.com. [209.85.208.170])
        by smtp.gmail.com with ESMTPSA id m10sm405809lfo.237.2020.10.22.16.43.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 16:43:46 -0700 (PDT)
Received: by mail-lj1-f170.google.com with SMTP id c21so3792870ljn.13
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 16:43:45 -0700 (PDT)
X-Received: by 2002:a2e:8815:: with SMTP id x21mr2045832ljh.312.1603410225256;
 Thu, 22 Oct 2020 16:43:45 -0700 (PDT)
MIME-Version: 1.0
References: <CA+G9fYvHze+hKROmiB0uL90S8h9ppO9S9Xe7RWwv808QwOd_Yw@mail.gmail.com>
 <CAHk-=wg5-P79Hr4iaC_disKR2P+7cRVqBA9Dsria9jdVwHo0+A@mail.gmail.com>
 <CA+G9fYv=DUanNfL2yza=y9kM7Y9bFpVv22Wd4L9NP28i0y7OzA@mail.gmail.com> <CA+G9fYudry0cXOuSfRTqHKkFKW-sMrA6Z9BdQFmtXsnzqaOgPg@mail.gmail.com>
In-Reply-To: <CA+G9fYudry0cXOuSfRTqHKkFKW-sMrA6Z9BdQFmtXsnzqaOgPg@mail.gmail.com>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Thu, 22 Oct 2020 16:43:29 -0700
X-Gmail-Original-Message-ID: <CAHk-=who8WmkWuuOJeGKa-7QCtZHqp3PsOSJY0hadyywucPMcQ@mail.gmail.com>
Message-ID: <CAHk-=who8WmkWuuOJeGKa-7QCtZHqp3PsOSJY0hadyywucPMcQ@mail.gmail.com>
Subject: Re: mmstress[1309]: segfault at 7f3d71a36ee8 ip 00007f3d77132bdf sp
 00007f3d71a36ee8 error 4 in libc-2.27.so[7f3d77058000+1aa000]
To: Naresh Kamboju <naresh.kamboju@linaro.org>
Cc: open list <linux-kernel@vger.kernel.org>, 
	linux-m68k <linux-m68k@lists.linux-m68k.org>, X86 ML <x86@kernel.org>, 
	LTP List <ltp@lists.linux.it>, lkft-triage@lists.linaro.org, 
	Linux-Next Mailing List <linux-next@vger.kernel.org>, linux-mm <linux-mm@kvack.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Christian Brauner <christian.brauner@ubuntu.com>, Ingo Molnar <mingo@redhat.com>, 
	Thomas Gleixner <tglx@linutronix.de>, "Matthew Wilcox (Oracle)" <willy@infradead.org>, 
	"Peter Zijlstra (Intel)" <peterz@infradead.org>, Al Viro <viro@zeniv.linux.org.uk>, 
	Geert Uytterhoeven <geert@linux-m68k.org>, Viresh Kumar <viresh.kumar@linaro.org>, zenglg.jy@cn.fujitsu.com, 
	Stephen Rothwell <sfr@canb.auug.org.au>, "Eric W. Biederman" <ebiederm@xmission.com>, 
	Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b=cUh4yK+P;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::141 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
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

On Thu, Oct 22, 2020 at 1:55 PM Naresh Kamboju
<naresh.kamboju@linaro.org> wrote:
>
> The bad commit points to,
>
> commit d55564cfc222326e944893eff0c4118353e349ec
> x86: Make __put_user() generate an out-of-line call
>
> I have reverted this single patch and confirmed the reported
> problem is not seen anymore.

Thanks. Very funky, but thanks. I've been running that commit on my
machine for over half a year, and it still looks "trivially correct"
to me, but let me go look at it one more time. Can't argue with a
reliable bisect and revert..

            Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3Dwho8WmkWuuOJeGKa-7QCtZHqp3PsOSJY0hadyywucPMcQ%40mail.gmail.com.
