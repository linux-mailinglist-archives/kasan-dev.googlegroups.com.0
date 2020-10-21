Return-Path: <kasan-dev+bncBCT6537ZTEKRB7G4YH6AKGQEJFZ7ZOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id D1027295171
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Oct 2020 19:23:09 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id 41sf1611935pjz.4
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Oct 2020 10:23:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603300988; cv=pass;
        d=google.com; s=arc-20160816;
        b=SV77rsObBovZaq2rQzqzPbtb7LtRwQb4ngMdMzm9IRvvwj+y+lgZrBOoI/lbkp19zM
         XQI93g66u/GffrTjfb2KUeiYE9ebnpI4G8BDBswOhYur9fVTxM2OuTBykOIJJg5kpi0B
         C0VuVNZH8b+SQJg0CzCIeN1U+KtIR60IYhvQ/LdccoyZYefGG+lEDHyTiGDXotVBRX+4
         y92D2rzu3ElYpkpIi04XpdjuCmgzO9ml9cFnMfsY7/zhelwuCCuRwiWDUqgVnJ7VUc2e
         7Uo/Nw/Oh8l2y5ccT4PFlzCsjay4odOprdW0PNvMyaqf5gOYIvc/oInKOTopT7uEOmFD
         GHtA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=IuMgK+2oofUwdCbKJyx6Bz1cgaGeU8O/obkpkE7T7es=;
        b=evW1rIzxwz+2BDb3+V1rxmL8A78YkQEU5tJHVpcg63Y9/9CU2deBhaZtRVcGAjNWfd
         SQ0qWTnS4jw2WmdKxDBdVrBoEETwf9WPrIhRmeqbyoHNXika2HF30+XQVc+QUEXJv7pC
         3VurA9KCwrQsEYHLKWuAUPVmM6NWdrGtjV/rGinrNPEBkiCvbR9VAH8IrFcUpo4q7hm4
         bbIC0a3COgNgrmNxT31rquGgOK2syGt+rXAPj8EoZTww5Uke4ARkPnkMlMu08FvV4w3k
         LXH5+H6BfUECVFTUpvbue/K+bs1NzcFslmNdfdJn6Mnvh/n8sBWIROq7vakELFpE92rR
         Yzcg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=ub1i2qnq;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::d41 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IuMgK+2oofUwdCbKJyx6Bz1cgaGeU8O/obkpkE7T7es=;
        b=bhIZ1wk+2N8665wArFNAAw/3CYIVD9XByJWAMuS5DLvIKLWobuoisi9ZfA3Mz+lNhs
         30JctyPbmDlte+BI59nOM+h0Y9i+Hc9D3HwLpl7BLQdTJ9Y4y67g63K5J/qMi8cbvml3
         tHTr+lWWgZpcIn7LSZ3PgsqOzJajHDE5E1NndiP5fKBpQT28K9yWNtNNwiLx1o9tSHca
         OoMdYOCY54ie5XAbUK4MEKBTGrN1B7v98y9r085N2y8ekQVtapXfMUFvBjdr/HaD5b6k
         Y3kFmxNxluCrnMFCfWKd+HoSVBeh9x/y3p5qOqRKMh3Xbh0vVrm+vRM9rY9YE26/YZCr
         yhsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IuMgK+2oofUwdCbKJyx6Bz1cgaGeU8O/obkpkE7T7es=;
        b=DXiGjQ7y59boMGODhAD1wb7eWnTQmLi1vrEBbdkRBedxuBoWBSsYIO5tYiu1ivK4L1
         1qCwRyk0KXtsK58XI+y/FYqYpbgtqF8tJN6iSuau7roy02s3J5EpM/cDjcvclokXWERy
         H40lkyqoKHTqqt5UqrluP5fXbsTmcVH6v6MyM0BQzAS4tmKIm6S84kwzPNrzujHeHWcG
         Buv9qyz1nJbjFFXDrI+lPplGBE/7oBK5frJl8rZ/oMWO9Hs7NhegapQUkZMRh1rkMYdJ
         SsWBL4sQx/qMqcgY/eKu65d+hdXEM+Zvbp309DcgppuyXpFgLXXcuCx1qB9M8aDn2wjD
         jSWg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533MCGo3N5uaCd16S46fpq6IFJDR+QbaeAf2eVxo4YD+LPRwH3Gb
	XMUuVfQbsht5UQx54Ow51Vc=
X-Google-Smtp-Source: ABdhPJztZ4jh1rodPviWgb4waXEo5cqmVdRpmTBJasbw2jlg6JuxLw9nLu7QV//jcKUsx9Gf3L1WUA==
X-Received: by 2002:a17:902:864b:b029:d3:ce46:2829 with SMTP id y11-20020a170902864bb02900d3ce462829mr4622375plt.16.1603300988410;
        Wed, 21 Oct 2020 10:23:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:ae08:: with SMTP id q8ls220592pff.0.gmail; Wed, 21 Oct
 2020 10:23:07 -0700 (PDT)
X-Received: by 2002:aa7:8492:0:b029:155:79b1:437a with SMTP id u18-20020aa784920000b029015579b1437amr4617240pfn.26.1603300987869;
        Wed, 21 Oct 2020 10:23:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603300987; cv=none;
        d=google.com; s=arc-20160816;
        b=vdaQWqjxtTx4yfbtOGyjdCHKv4y+PxMVSBXwlUrLiPMDpV0l6QrJ0y17yJRgxWLEq0
         qARdlQENoVQ/8n92xhgxgJxBjGz4FibArpVSQUiCkOICaIPbMvU91c+6t1OmDP9hqNLx
         zyHw8FKO5j25WeEKY4z7I86H3dFd+9ub45zFtwc12kJ+eKBkZkCnRFN60yQ0R96FIPIc
         WY2N3eq2QR9MDwCsnbz0+1Nilm8muCOxpzWXGgya1eYQIJup8cAeNnHCsgGZ8jt4sGm0
         lPZaRQ/hsFt/FCnsrRpR3hj5ijvyzPeHEIsV00JWtow27PGQi953OP3uG9/gqkf1mUBN
         U+vA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7535FUlfM8DZDchGw8aykWjhU0FVacKPwMt6VunyyW4=;
        b=Czy42voofSbXRTflpBffWt2BRgzCzLpwr0l0UZlZYVTxWt6jvjSe3wmO5MgNBff/Il
         q4mGR0eVJho0GLrsYaO+PRM9Fk1oIOnG30X8RI35f+6X6iHptgjbK2iuYFvkAuwNgy1O
         DR3y24djHtrjP7xx0GzY8V1M/42+xbwS0lN5nF+KMaaR6CqtKrLcPyElhQK8dplDQHnX
         QsBJtEXkadjqEPLxATXuWO2Wm9LEPP8m9j6QTxVVwCT8fQwNo9Ylvvq9+w0yCAgYxJp2
         1Pv0rkFJjX57nDbHP9afqTgxcGu1tsOEPmKg5ezEzc4PJK4pfrSo5xn+s6KiSh/tWhNn
         GfBg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=ub1i2qnq;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::d41 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-io1-xd41.google.com (mail-io1-xd41.google.com. [2607:f8b0:4864:20::d41])
        by gmr-mx.google.com with ESMTPS id v8si215141pgj.1.2020.10.21.10.23.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Oct 2020 10:23:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::d41 as permitted sender) client-ip=2607:f8b0:4864:20::d41;
Received: by mail-io1-xd41.google.com with SMTP id b8so3960976ioh.11
        for <kasan-dev@googlegroups.com>; Wed, 21 Oct 2020 10:23:07 -0700 (PDT)
X-Received: by 2002:a6b:5c06:: with SMTP id z6mr3661750ioh.49.1603300986883;
 Wed, 21 Oct 2020 10:23:06 -0700 (PDT)
MIME-Version: 1.0
References: <CA+G9fYvHze+hKROmiB0uL90S8h9ppO9S9Xe7RWwv808QwOd_Yw@mail.gmail.com>
 <CAHk-=wg5-P79Hr4iaC_disKR2P+7cRVqBA9Dsria9jdVwHo0+A@mail.gmail.com>
In-Reply-To: <CAHk-=wg5-P79Hr4iaC_disKR2P+7cRVqBA9Dsria9jdVwHo0+A@mail.gmail.com>
From: Naresh Kamboju <naresh.kamboju@linaro.org>
Date: Wed, 21 Oct 2020 22:52:55 +0530
Message-ID: <CA+G9fYv=DUanNfL2yza=y9kM7Y9bFpVv22Wd4L9NP28i0y7OzA@mail.gmail.com>
Subject: Re: mmstress[1309]: segfault at 7f3d71a36ee8 ip 00007f3d77132bdf sp
 00007f3d71a36ee8 error 4 in libc-2.27.so[7f3d77058000+1aa000]
To: Linus Torvalds <torvalds@linux-foundation.org>
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
X-Original-Sender: naresh.kamboju@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=ub1i2qnq;       spf=pass
 (google.com: domain of naresh.kamboju@linaro.org designates
 2607:f8b0:4864:20::d41 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On Wed, 21 Oct 2020 at 22:35, Linus Torvalds
<torvalds@linux-foundation.org> wrote:
>
> On Wed, Oct 21, 2020 at 9:58 AM Naresh Kamboju
> <naresh.kamboju@linaro.org> wrote:
> >
> > LTP mm mtest05 (mmstress), mtest06_3 and mallocstress01 (mallocstress) tested on
> > x86 KASAN enabled build. But tests are getting PASS on Non KASAN builds.
> > This regression started happening from next-20201015 nowards
>
> Is it repeatable enough to be bisectable?

Yes. This is easily reproducible.
I will bisect and report here.

>
>              Linus

- Naresh

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BG9fYv%3DDUanNfL2yza%3Dy9kM7Y9bFpVv22Wd4L9NP28i0y7OzA%40mail.gmail.com.
