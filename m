Return-Path: <kasan-dev+bncBDV37XP3XYDRBY5L7T4AKGQEWSEDGDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id EF69622F732
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Jul 2020 19:59:00 +0200 (CEST)
Received: by mail-qk1-x738.google.com with SMTP id v16sf12160407qka.18
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Jul 2020 10:59:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595872739; cv=pass;
        d=google.com; s=arc-20160816;
        b=KBLxD2v1Uqo6fzJlzF+laawnpeCAt5GQANjDZsxg+3brwlG4rVFTrLQw0v2Kz38htC
         siVAMFp/EnIIjnsmn70Wur2/GHeRvNmov4LQp+e8qTf2T6LRIAxOLNcAogYxUftMnIcg
         6bFMg6hym7JY8+NEuaTA0JJIlaneiK1sL5q36frgJmtTavWKx58lht3NYsICM43RaBk+
         GpL1d+D6Jb3ilJTiKm+mL6kIfTuU6Y/X22OPfP0E8LI4KBnHQQENEZeuRpygZ+ee0f6z
         Clgx7VVJIruMFyHZOxKcOU3osCuA+FLXp240VisMg9ZJ3mhHHC12sbh+z4/I/SCNmvLH
         RAqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=RFAnqcnTeKeG+WT97VhKeRrt8gacsez9NYdVXulAkuc=;
        b=c7/TYhwZs/qTr+SxRu28ZPOhdN0nuvGwsXB4Tqk+Hq1YLfcc/iME8J5MNvWVFJRKWO
         4Cy0gwOOFkQxDf5nCHm84TPjTlxuZx+UTMrRYWBwVdPLRzYTEOkqspToto33IHzAeAcT
         roibAaVN+CZU8tujAxhuHInuh990Gd2ngdHqbBdqwaNibgT8xY/j9NYyxaxKSGwgIohD
         sZC49G7INEx3mSmcEg5Ym0GmshJWyrrdTU9ENwQxv+F7FIZVIyLp9Fti69+mgOs9P5r2
         nvuXGT8lS66mCS/DpzI1g4mKqAIp1eAabolXWwiYWCdfPeC3GjwwRSpuJk2T76iXjlwu
         Svjg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=RFAnqcnTeKeG+WT97VhKeRrt8gacsez9NYdVXulAkuc=;
        b=KfE2UOd6yxZCKF7pEe9HZRm47MegATewXwX9ZgzqGiXV2+Qijjr8MDpJxmuKZ5uNyn
         mybcKUz0Hznou7a2YjTBkAp69wOAbbDUm+aKUXlQIaYN070pT+Q9fc33VcxAXYXLYLnJ
         4GlYJUKZpY76m8qOSwFhUpAj1hV8PRsuwcnmXGsd52zVvy93mmzkMmnovbGTKsU1JZWz
         uFai8GgG19qWs+Pl0FzRz3Mf7+PzLr9z/HiUlRT/1xKGysGK9zjrDtHq0P5eOAPNxp6R
         fP8rZL41HEJMaDif38txut1/7JdkwlGXmt3aGsMED/YPwGB8Rp735S1dxoEo8FJfQys5
         w3vQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=RFAnqcnTeKeG+WT97VhKeRrt8gacsez9NYdVXulAkuc=;
        b=dV4HfJmxC3vBOr2BiJ3oBZfqG3mllc5OtZ3WosZfycMM89DwKevLzp41uqWyUiYbVA
         KeEf8xsdA3xAmmemsUjxUFUr6SDYFlb5BpG4sii/xbM2KZ02+dvpn+iAq5+u5dzOfxYQ
         KhPYlcdoSqaQxB4e7O3Wa5fPsyi9qpx4GwRRY6Ip3Ep2JrGRAbeXp9QEO8b8t2EH/8tD
         J17IoFlDzyMGCMseah+cyUDBTAbCUPjGtw6qDkiA98eh7sbeUfZtO/yKY9sULrV+vF7u
         T94uSB8mOH8GTmFNkc50ujAcUkr/OC5XXhAAfbwDhwJi27XMNu10Z85sfi+IzqqAHn1m
         Anrw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530JzlAM11pTP4PTvpL4QGIxi12zDfh3kOrICp6xyCWTSKuTO13C
	RWSwdSwRg+2AsDkspO0J+14=
X-Google-Smtp-Source: ABdhPJxzW2jmrTASUKUrEo2lBjHReyNb5j+1n0Tn59nJCrkoCwlYLDU7/HBIPAM870tD/o4U34c7wg==
X-Received: by 2002:a0c:82a2:: with SMTP id i31mr23980985qva.106.1595872739696;
        Mon, 27 Jul 2020 10:58:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:16ca:: with SMTP id d10ls4084680qvz.7.gmail; Mon,
 27 Jul 2020 10:58:59 -0700 (PDT)
X-Received: by 2002:ad4:4812:: with SMTP id g18mr23340220qvy.56.1595872739246;
        Mon, 27 Jul 2020 10:58:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595872739; cv=none;
        d=google.com; s=arc-20160816;
        b=haAkRHusBCiXUBu25stZQlt3FFCvhRdDeCBjz+rQPzADA+6ujJi7beKK1ER9RPlpQ0
         eTCN2L6uv6yuzo8OoKDy20+7TBbp+4P9UPxD31R65MOYONsLFlr+agD95poBBESsWoPv
         U4UEddl6UEBK1ZaBmhMrABB3J+3uZE5jC7qDhZyy670qmWODgVFdsXcUybwTpM8xoHcR
         3xkydt+Qs9r48GRBVuY3m534E3AIEAC/+KnL1Ixp9q26Cc+DV0RFCvFUoVSEBw9UrYs5
         edXtKUuosWUBv4RAGaEM6zqCZEaKSNeoSZv9/JdXtbBQ+EOvtu4geDm1jWS8hA/toFBC
         elKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=0kzeYj6X11Ofoi7iLAfTdcQKVOHgyy3O+WaZyrdpx9k=;
        b=vBKZbjYgU6m09Yqs2/2KGbNDgVPT18o65UeiSS6Y8Dy4c723aPuhQNGKeeRLgXz7rD
         1sC+ZeDUTFRL7R7bgAarnXLz2r5P5DZD+M6dfupsUC/TOC54gQH+HZaYoqMDzP3WSp91
         selgZgnl1WzbPDb+0cu7GP962sFruBXfaPVhfAGHpQ7Ax5FyhnBIWc0Gq8Krl32KkfFj
         B3e6TnFosb8mMhEzWACZ2CMxgaupEFZnoIpZZYKrjqRNxe8PEHvruKMJZ6SCllO0ttxP
         HTuPA/udowGAd9OEP5/lELQFA6kyUmo2FhKsJXXW+apY/ORXYnybzTn+XedkGQsT4xds
         dKUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id f38si410094qte.4.2020.07.27.10.58.58
        for <kasan-dev@googlegroups.com>;
        Mon, 27 Jul 2020 10:58:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 6891230E;
	Mon, 27 Jul 2020 10:58:58 -0700 (PDT)
Received: from C02TD0UTHF1T.local (unknown [10.57.28.121])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id EF5283F718;
	Mon, 27 Jul 2020 10:58:56 -0700 (PDT)
Date: Mon, 27 Jul 2020 18:58:54 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: sgrover@codeaurora.org, Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: KCSAN Support on ARM64 Kernel
Message-ID: <20200727175854.GC68855@C02TD0UTHF1T.local>
References: <CACT4Y+aAicvQ1FYyOVbhJy62F4U6R_PXr+myNghFh8PZixfYLQ@mail.gmail.com>
 <CANpmjNOx7fuLLBasdEgnOCJepeufY4zo_FijsoSg0hfVgN7Ong@mail.gmail.com>
 <002801d58271$f5d01db0$e1705910$@codeaurora.org>
 <CANpmjNPVK00wsrpcVPFjudpqE-4-AVnZY0Pk-WMXTtqZTMXoOw@mail.gmail.com>
 <CANpmjNM9RhZ_V7vPBLp146m_JRqajeHgRT3h3gSBz3OH4Ya_Yg@mail.gmail.com>
 <000801d656bb$64aada40$2e008ec0$@codeaurora.org>
 <CANpmjNMEtocM7f1UG6OFTmAudcFJaa22WTc7aM=YGYn6SMY6HQ@mail.gmail.com>
 <20200710135747.GA29727@C02TD0UTHF1T.local>
 <CANpmjNNPL65y23Qz3pHHqqdQrkK6CqTDSsD+zO_3C0P0xjYXYw@mail.gmail.com>
 <20200710175300.GA31697@C02TD0UTHF1T.local>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200710175300.GA31697@C02TD0UTHF1T.local>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

On Fri, Jul 10, 2020 at 06:53:09PM +0100, Mark Rutland wrote:
> On Fri, Jul 10, 2020 at 05:12:02PM +0200, Marco Elver wrote:
> > On Fri, 10 Jul 2020 at 15:57, Mark Rutland <mark.rutland@arm.com> wrote:
> > > As a heads-up, since KCSAN now requires clang 11, I was waiting for the
> > > release before sending the arm64 patch. I'd wanted to stress the result
> > > locally with my arm64 Syzkaller instsance etc before sending it out, and
> > > didn't fancy doing that from a locally-built clang on an arbitrary
> > > commit.
> > >
> > > If you think there'sa a sufficiently stable clang commit to test from,
> > > I'm happy to give that a go.
> > 
> > Thanks, Mark. LLVM/Clang is usually quite stable even the pre-release
> > (famous last words ;-)). We've been using LLVM commit
> > ca2dcbd030eadbf0aa9b660efe864ff08af6e18b
> > (https://github.com/llvm/llvm-project/commit/ca2dcbd030eadbf0aa9b660efe864ff08af6e18b).

> Regardless of whether the kernel has BTI and BTI_KERNEL selected it
> doesn't produce any console output, but that may be something I need to
> fix up and I haven't tried to debug it yet.

I had the chance to dig into this, and the issue was that some
instrumented code runs before we set up the per-cpu offset for the boot
CPU, and this ended up causing a recursive fault.

I have a preparatory patch to address that by changing the way we set up
the offset.

> For now I've pushed out my rebased (and currently broken) patch to my
> arm64/kcsan-new branch:
> 
> git://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git arm64/kcsan-new

I've pushed out an updated branch with the preparatory patch, rebased
atop today's arm64 for-next/core branch. Note that due to the BTI issue
with generated functions this is still broken, and I won't be sending
this for review until that's fixed in clang.

Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200727175854.GC68855%40C02TD0UTHF1T.local.
