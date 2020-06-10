Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBZFDQP3QKGQEIBGVYEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id B147A1F54CC
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Jun 2020 14:28:21 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id o140sf1991595yba.16
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Jun 2020 05:28:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591792100; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZBHKXshLenMzKc8Rxx++V93FbgSFbdvFRv7XJ4Gnrs8j78PYwOw6+oB+YffiQF49GS
         APolluzzetFyM6YDmO0UwxxpZO7eFC5EzuZZn8LKiArfiU/miOWTWBXIVmHcDPq2/0Hr
         oc5FySiilLfe08OuREkhFqIjR4v8KQOTV1r1y1l+x9htJokn/1r9u3hKsX7mF4wHJIMS
         XfTtqYeSOhud2BYpYzqZuPMmTIjk8f42EnXWURvKUbrQ0jwJViWzM13rWlJVrgxkJDI9
         MwOhJgp3Cb6dyvrLLUG8xpDVnfJe3Tmbm/4inCWU81kH2RKfZYrueT/+O+ZL8RSA1LBJ
         HQCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=nTN7mOKW4KjTx3YGHyuxZq24js7Ye/iA9fZ7KleM7o4=;
        b=tMHJaI4rbvSvJQuKMXpAvhgL0+saFL4ymvZSBsWDxs1lRveAMnfOxDCQEMDQTwlozk
         cPkJb3C1EPpW0R0AnXswcb5eGj0HOfL9m3ZKVROkEJwc7U5WoKDNWPIbiHg+WSeNNWVu
         7rIvrJdiNNtihdAkGnwsx8Hb9QV2+p8PVREo8IpP80n0T2vSvoHjglH+EibJ33gfX0a4
         G1etnhUW+xkc3Pw923HLsqBzci/GyUZjDRxRkscqO9s2TRX+HszYcYn8uKLHTP2pvM7g
         R3K4ycJ8aVsu79LtKPjVu6psTvzbRjbYByqkHqCptUSqasOI2z9yAOiZBixfMpikoLKL
         TEZw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=rhC0j4t2;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=nTN7mOKW4KjTx3YGHyuxZq24js7Ye/iA9fZ7KleM7o4=;
        b=ULS2pUQkMpJmiSmI0fiPI0CqSNE3Hi2Ogx8Jyp2xOgWRk3NWEVyhsY17EcPKYPDNSF
         tj1KR602sHQZVLkSgOCc3+aMRS+fbZ7PUnx3fBZOMByjpzo1Qw6xBVpmKvF1LiKVBOeR
         +0LsdkE2M3IP9rkVHVrXMtTg/o/MNQ7ecQR3nfZJI5uXvgaoJ7UmtkIzFA7U78alsWbf
         rk2UrawCVI9TA8pxQZO6IYVev1cyIYHKabjoP5keKzkvh9CsJpjqaGwVk6KqEdXV+J9m
         KWkkTCdiZHLetvxRYsmvQtOfuS4aNv+VAIk/GF7cUjTxPBJrN6W92hpivQMUulW7WeY1
         UqMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=nTN7mOKW4KjTx3YGHyuxZq24js7Ye/iA9fZ7KleM7o4=;
        b=oq7/uXBiTvuvPjFcbsQUBmR97KYzrfm7uovdi5tYwgkYZXxcCdO3AI9YPrjUdyQWDC
         DDfBbKCJiARuQUvfuWL/cru2Ykft3fStN71kGsT1puMDK701HRXzGfcmosbLQEdOLd/u
         I03s+col1X2aPddjdfqZtYGSdQ0wi79jagrLINDQiUvK7UZ8aCI1kdkDxdgY+kW+NAry
         fprZ+3uBxJxm5hzn4oNbau3LqSbPQNoLKqhGQ2Sr/yQ3W/KSKmG/4UOr244QMlYCDl0Q
         ddtqepWNI3lDfn3uUtiqRCjtpDJmIDtVqRHxssksslHiWPX44wiPFXxxgAO/KfzGJ1oc
         Df+Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533a/ESpxyvVcN1exYSpOIbMNzRPG+9HGQcslP/qm3H+KZikMpEi
	o63rq4/7frsCpNZHW5TIvbs=
X-Google-Smtp-Source: ABdhPJyGFVLYmpOkG1udP9HwZIpKQ63uqc6CC4AfR1VLZdbZmNAOBuRGtHlbCEWdxn3a1Mumya4HVQ==
X-Received: by 2002:a25:b909:: with SMTP id x9mr4931277ybj.163.1591792100731;
        Wed, 10 Jun 2020 05:28:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:b18b:: with SMTP id h11ls5057647ybj.4.gmail; Wed, 10 Jun
 2020 05:28:20 -0700 (PDT)
X-Received: by 2002:a25:9a04:: with SMTP id x4mr5285531ybn.137.1591792100467;
        Wed, 10 Jun 2020 05:28:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591792100; cv=none;
        d=google.com; s=arc-20160816;
        b=NBGHWkPSzch1OpN0ahj762aGwd2I63ELYZFm6olpCbkH6ofr9oMNLozTF3JKiVktsW
         mU3PkxJw9+2gWdVs+R+bKngyVSc88+hqCGhIeEl2hCLqvFspoa8YZco3vwZCzfKho/nn
         rRsJkHt+rT7zXEbxQsBy/nRg0s6c5bGW0NLfQLHJazCTryUZyPutCv+Aa7ipG0Hu5UOE
         aQPrixMNuSYeIlEzfuJ6/hDWh2JTsN/mkhWeHE+SqLM/KpduJ8QJIAHg9UHi+UyEXdbf
         oiX0Q7eLvubeWuEBNaHSHqtM7O1qUVV3kVdXP/U32C3wD5EstEj9P4hJy0E5e26/0XeR
         8gBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=+g/QNFEcpPiOwSyTtWV6UhK4FMdUVFtGGz85G+f+/28=;
        b=KHWxBIwJ25ftZu3AsdQ7Ev/s/76fkajo5lM3Z66T2Kp+tFT5L0S6cn/jeORwIkOiBP
         0BlE/L8PtjeC5mliHOUute1SMfEt3UaioXPheWn+grr8qC/yYexVFzXqWBgWixrdpiJd
         4A3WRpeNpwAYGRPjAmD13EsnEMfrUXel2AOq7O1PBlUoyhT7n57JPGl3rWS3VKlcRm7f
         4Vs2xQlTdM/3fvGoACIPH8Wf1n16aukDf8L2KDCuC0DJkT6fesT3PbZvAupMKdhmQgU6
         4OJg4De9aewE6Gtshluu0buPkAq7SilHlNncASuzWILLg6Fga26xD7ngNR3oe54foSKJ
         PeIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=rhC0j4t2;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id n82si226786ybc.3.2020.06.10.05.28.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 10 Jun 2020 05:28:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id j32so1500258qte.10
        for <kasan-dev@googlegroups.com>; Wed, 10 Jun 2020 05:28:20 -0700 (PDT)
X-Received: by 2002:ac8:fa7:: with SMTP id b36mr2997242qtk.100.1591792100186;
        Wed, 10 Jun 2020 05:28:20 -0700 (PDT)
Received: from lca.pw (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id h64sm11681352qkf.46.2020.06.10.05.28.19
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 10 Jun 2020 05:28:19 -0700 (PDT)
Date: Wed, 10 Jun 2020 08:28:17 -0400
From: Qian Cai <cai@lca.pw>
To: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christian Borntraeger <borntraeger@de.ibm.com>,
	Kees Cook <keescook@chromium.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux-MM <linux-mm@kvack.org>,
	linux-s390 <linux-s390@vger.kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	Heiko Carstens <heiko.carstens@de.ibm.com>,
	Vasily Gorbik <gor@linux.ibm.com>
Subject: Re: [PATCH] mm/page_alloc: silence a KASAN false positive
Message-ID: <20200610122817.GC954@lca.pw>
References: <20200610052154.5180-1-cai@lca.pw>
 <CACT4Y+Ze=cddKcU_bYf4L=GaHuJRUjY=AdFFpM7aKy2+aZrmyQ@mail.gmail.com>
 <CAG_fn=X-da3V0OC-Bzd2rmkNuZ_bVpH_n7Sp5P_hSGXD4ryyBA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAG_fn=X-da3V0OC-Bzd2rmkNuZ_bVpH_n7Sp5P_hSGXD4ryyBA@mail.gmail.com>
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=rhC0j4t2;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::844 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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

On Wed, Jun 10, 2020 at 01:02:04PM +0200, Alexander Potapenko wrote:
> On Wed, Jun 10, 2020 at 7:55 AM Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Wed, Jun 10, 2020 at 7:22 AM Qian Cai <cai@lca.pw> wrote:
> > >
> > > kernel_init_free_pages() will use memset() on s390 to clear all pages
> > > from kmalloc_order() which will override KASAN redzones because a
> > > redzone was setup from the end of the allocation size to the end of the
> > > last page. Silence it by not reporting it there. An example of the
> > > report is,
> >
> > Interesting. The reason why we did not hit it on x86_64 is because
> > clear_page is implemented in asm (arch/x86/lib/clear_page_64.S) and
> > thus is not instrumented. Arm64 probably does the same. However, on
> > s390 clear_page is defined to memset.
> 
> Can we define it to __memset() instead?
> __memset() is supposed to be ignored by KASAN, e.g. KASAN runtime uses
> it in the places where we don't care about bugs.

I suppose that could work if s390 maintains perfer this way.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200610122817.GC954%40lca.pw.
