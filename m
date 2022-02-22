Return-Path: <kasan-dev+bncBDW2JDUY5AORBJ6N2SIAMGQEMZTQBCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id B07F04C00F7
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Feb 2022 19:08:40 +0100 (CET)
Received: by mail-pf1-x440.google.com with SMTP id k130-20020a628488000000b004f362b45f28sf1065828pfd.9
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Feb 2022 10:08:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645553319; cv=pass;
        d=google.com; s=arc-20160816;
        b=DrAZMzyggqIEpfHNG5mr84eoU6yZ1FQuDPwNzDVNoaOrsHLY0h0r+G56EBS7ouGNON
         FiTIM1ynetW2zq6aBKlVsgv1Mh38fy69xJ/0cyJOIo7ZGyv5GE5PIy7MHZq87e1nKocy
         9hNCM1kly1OXwFopInRV0nMJrBjclFUkhi5JOH8fDTOASpHwNrVCfo1YOox4heTyY3Ss
         KNbUgmpF0F5XJ6bI81rZBcuPCww4tP924rGpIkLQTRUemrYWs25U5AbjacnykwYMZOJn
         2xJl44djT1kH5GLBXhIcU+xcDRFUoQGqi/hKgKPWwuz5YMixXlyBXs7i4XxIRf4i5LdR
         RwLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=U7Sf9IIz6SHdFTaOsJqirWV/l/dRZoELl/WOC0LXSRM=;
        b=J+Pa59S5EOXSq9erpBMTuyeoVmhqcSqZk0BJMstkRXhuD/yY6Yk1CIkPp+6rr/tGqA
         ulnHW4indXDlLxIhwPCwDZKB1ds/5oCKl52b2hA3F4UQ7n0rJSJUdRbBHqAJI8iTV/Ul
         F5Z5NcqS7pRvh4Y5pWw7G04NAdsCSKlxvtQSGtPecDbDeZzEgHbOTgeS0Y2LQ4ywgk1A
         ShyleJ6q6EaP1LKTvw6x9zIB/KLfh0N6mB7JPCh+KNxhTYQN1k7odhWVP2klCxKhB6Gx
         OE2rQ+23sM56/yvPsm8VRFDIBgZhtTYZTNmgZWQSB9OuTzIr/xU/syOxQ6tH6J//yggs
         pYbg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=E5GkLf4q;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::134 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=U7Sf9IIz6SHdFTaOsJqirWV/l/dRZoELl/WOC0LXSRM=;
        b=Mtm4EYqnURdCcHwWIYpFTr7KFi4LrM2QAl23mkXMe7LkahzmN4+skLhksTPNXPXteM
         gqnLdt/1+SOxIRpl23FDFRlXMyemqopTVUoMFTTYk6R7PQ+iw/iYvbx03eXh1RSuLoy0
         bIlDZ4qnnEcngxXeYwO8cvmfH3aeNNXDbTDyWu2qlTFaAf+lJFzAnOcVZBP7HjOUqhlX
         JoO8UVsLSzsCLwGiaJ0dyGHE2rCS+HaoHQIGxwfLWOMlAcmViJ+KVKg7q+RE1zW3Jwym
         vm7ufRZ3Y4T2vIEwOvZIbja/q/s19Pz9BlikODTKu+SVevaBvHvNyrqqHLF41shu6A6A
         iVYQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=U7Sf9IIz6SHdFTaOsJqirWV/l/dRZoELl/WOC0LXSRM=;
        b=pm74w9xOIfAFJOOaPA55tAWGYQJIv/ArerTc22+Blce++5Pscq7rh7hg1czXFO7HNd
         DgVkDEHP3c5bXdDDv4T/Uxn/FgoMAK7uR72+0BYipM9hN6zzGjnB7BObOWDiIq8nzZXP
         icvyJtpuEnVqaHKG0+6ze9ewqs/E7oDSWfgZq0kL3fiVGY7BwgzhvNfjB58MNGLVXz4l
         EVy07Rsfz5Jve8oTNvekbRJPICW7ZT7kn9KxTOtc04JGPF5lFqProXjdiNLsQBIMQBNW
         0qr1xoAGzVaqsDORIVAgDUFUUOKjNsvl/8IfXyPn/7smvJ6M9FReB8HxfYadkhflHbhr
         SCXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=U7Sf9IIz6SHdFTaOsJqirWV/l/dRZoELl/WOC0LXSRM=;
        b=XYBQL4oGtEs3jgpmWiJRWAC/1KwtCJNp2qFCgxqklpgx5kRRCQmfF4cCap5+4wlbpl
         QdSqWkyi5Yu/9XOa/g4+kUQSbA4QoeZrTt88qpma/J6P7mt43E4guXWyDGnmZVEahBSu
         0ExT3mcZQgB5A5p/PE6+Gww//AgEyvboiuEDfPFFbpwCCs8FPL+/xHxpHcia94JFRArF
         SC9HLRfkBMqpcPeDTBYvC9M2bbBvP9hraIF5BQv6/vsBbFlg6Xt9DfFSS0nuTuxEFqvh
         UhpijgT3a8zqWxNj4Lj81p6ukifqmtu4VqsLzp3mmzNKUBCW9e9OZ4E3jwMwTtpKvhCH
         m5Fg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533PQL7yrimhZIueJ4gKdhMP8ZEnZERSN48R6cEUmu9xVMr2I5BW
	JJhFhL/MkZprAJNVpDTe6Kw=
X-Google-Smtp-Source: ABdhPJwXCPXImvOcoIcWzZIV2d/MHMIihqMw/K97bL6VM5hbUOpIBo/wyz1reVYOpr2p7pbENAXgJA==
X-Received: by 2002:a63:ce51:0:b0:362:c4fd:273b with SMTP id r17-20020a63ce51000000b00362c4fd273bmr20478733pgi.540.1645553319420;
        Tue, 22 Feb 2022 10:08:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:644f:0:b0:374:5e1a:d7cb with SMTP id s15-20020a65644f000000b003745e1ad7cbls1868026pgv.8.gmail;
 Tue, 22 Feb 2022 10:08:38 -0800 (PST)
X-Received: by 2002:a65:5888:0:b0:374:5575:ba08 with SMTP id d8-20020a655888000000b003745575ba08mr7496349pgu.375.1645553318822;
        Tue, 22 Feb 2022 10:08:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645553318; cv=none;
        d=google.com; s=arc-20160816;
        b=YPBHG1VCBszLMKyHnP3oUGkINt9R2U8kPocyHO49c7raWGsh8bw212Rw0bHuticuvw
         Et9mPneFsxD4J/gUCfjDn10xJK5O9tLysKXFQ92yP4jvJ1cW+Hi2hmDILXE+kHYI5Sw1
         YB56xygVVvJwRlZDQtgG0HLxiiYUovPK2TTjxRbTlYdRdBXYoBSdxUQItPXT3Zg2i5B9
         ftsQ1JbGj5SKyGOgiNENytbqVGKWXYgEN1XTsd7Ri1DRp8Lq6PzKmvS1nIdcX1G9Vhxk
         wBJxnc1rilPIMb+BjleWiJ/CPT+Kxnv4Oay3/ZAOS+5SvjEqXl2iz4pP+s9TxHA39NFa
         32FQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3MFpylEeTI6XidlITe8mkhmRrO1Ymt6z5H1OOXcy0qU=;
        b=hkelKRDAfvBO1xz5dV/ano/2eFSRsCNe5AAWrn35I/XlNIoahcHeOT84Nwqonx8V0/
         O2/cWE0veA7Zmtck1UuyH9H4x1OZb0pLRclOqjPlML0vvxmVWPRSzGMTW7RgXoyJ9GBC
         IRMs7V3pSwS85MMpH+l7+2CBQ1T899YQ8qCe1M96gOIM/vvTx6Gx32A7/KO3pXidZohZ
         dk550PucHQ+lHehQCUsIiuz70JNBkG+G4VGap09TBlRaBITIboAagaAE23JB0gf4CDLX
         tP0n+KDTLtn4hu3J4bGWS4NxhiK+srU/Cyqt4PlcbIWpTOCwEz0+88lyBb8oGA+/ss9V
         J/fw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=E5GkLf4q;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::134 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x134.google.com (mail-il1-x134.google.com. [2607:f8b0:4864:20::134])
        by gmr-mx.google.com with ESMTPS id p6si990143pgj.1.2022.02.22.10.08.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 22 Feb 2022 10:08:38 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::134 as permitted sender) client-ip=2607:f8b0:4864:20::134;
Received: by mail-il1-x134.google.com with SMTP id c14so13269721ilm.4
        for <kasan-dev@googlegroups.com>; Tue, 22 Feb 2022 10:08:38 -0800 (PST)
X-Received: by 2002:a05:6e02:190c:b0:2c2:6851:bce3 with SMTP id
 w12-20020a056e02190c00b002c26851bce3mr2988283ilu.28.1645553318268; Tue, 22
 Feb 2022 10:08:38 -0800 (PST)
MIME-Version: 1.0
References: <2d44632c4067be35491b58b147a4d1329fdfcf16.1645549750.git.andreyknvl@google.com>
 <CANpmjNOnr=B_o83BJ6b1S6FKWe+p2vR58H8CHtGPNPnu6-cQZg@mail.gmail.com>
In-Reply-To: <CANpmjNOnr=B_o83BJ6b1S6FKWe+p2vR58H8CHtGPNPnu6-cQZg@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 22 Feb 2022 19:08:27 +0100
Message-ID: <CA+fCnZf2jE1N8j9iQRtOnQsTP=2CQOGYqREbzypPQa-=UXjhDA@mail.gmail.com>
Subject: Re: [PATCH mm] another fix for "kasan: improve vmalloc tests"
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, kernel test robot <lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=E5GkLf4q;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::134
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Tue, Feb 22, 2022 at 6:50 PM Marco Elver <elver@google.com> wrote:
>
> On Tue, 22 Feb 2022 at 18:10, <andrey.konovalov@linux.dev> wrote:
> >
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > set_memory_rw/ro() are not exported to be used in modules and thus
> > cannot be used in KUnit-compatible KASAN tests.
> >
> > Drop the checks that rely on these functions.
> >
> > Reported-by: kernel test robot <lkp@intel.com>
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > ---
> >  lib/test_kasan.c | 6 ------
> >  1 file changed, 6 deletions(-)
> >
> > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > index ef99d81fe8b3..448194bbc41d 100644
> > --- a/lib/test_kasan.c
> > +++ b/lib/test_kasan.c
> > @@ -1083,12 +1083,6 @@ static void vmalloc_helpers_tags(struct kunit *test)
> >         KUNIT_ASSERT_TRUE(test, is_vmalloc_addr(ptr));
> >         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, vmalloc_to_page(ptr));
> >
> > -       /* Make sure vmalloc'ed memory permissions can be changed. */
> > -       rv = set_memory_ro((unsigned long)ptr, 1);
> > -       KUNIT_ASSERT_GE(test, rv, 0);
> > -       rv = set_memory_rw((unsigned long)ptr, 1);
> > -       KUNIT_ASSERT_GE(test, rv, 0);
>
> You can still test it by checking 'ifdef MODULE'. You could add a
> separate test which is skipped if MODULE is defined. Does that work?

Yes, putting it under ifdef will work. I thought that having a
discrepancy between built-in and module tests is weird, but I see the
kprobes tests doing this, so maybe it's not such a bad idea. Will do
in v2.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZf2jE1N8j9iQRtOnQsTP%3D2CQOGYqREbzypPQa-%3DUXjhDA%40mail.gmail.com.
