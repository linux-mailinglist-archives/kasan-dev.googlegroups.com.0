Return-Path: <kasan-dev+bncBDV37XP3XYDRBQ4J3L4QKGQE5KWEQLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id D05662449CB
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 14:34:12 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id s22sf4377402oot.1
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 05:34:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597408451; cv=pass;
        d=google.com; s=arc-20160816;
        b=sLDyjHPI4/30NnXQi3y34BCgYSovPiN3at7v+ZNRU1qbCPWgOLH9m/ydTRuMvDnKpV
         ZsAQo9p4/ZxEozd/UAM145T6sNFstvFh/sFSxJsJGDb3MwW9HT7XXvLP0rMFvIAtkzGv
         wea2ZUjbiL0QNipntwA06TDiodFL9qe6H5nfjhOpDyzZKCqxTmNaFgAuEo3UODinXOTj
         VgGyseRYPUJkMyYodVTOUdD/hXSDLrC5Vel9Bwc59l120QRFZvcYEKw2hi8qsksxxt2I
         mbxAEuxK06dMYUdi6NyVTHdP/X300wFZdPE2w13FOCpQnBQndx0I8BCNq0zx9ZfchjmX
         riJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=YTvSgeVNDHT2v1NI0Z4UcWXeweoccCvmPkcI6/F+BtI=;
        b=FSwlosS3kxa/CUXjI2ZJSkpLq7HU1LdklMZwc9aXTcGGf8vbPqzDlRQhZ1AZ47gnom
         1cONmCGwQOO55jWXwBwzw5JJc69dCzSUEdpmMAdhJoC/SgCa+z4I8Ousc3Nk/K5aRnJZ
         x77XBtbKrZjxYSut9lcoKEb0/SL23vRFmFiLjaTHMPuG0sYRWu5Vgpgu8apyOG5Ug22U
         DJZDPJrnmS7tIWjXmCAVx72kt6sGuxxzp7EiwaBsfH3aA8k0PvCmF9M9/ExlsdtMNOji
         S9682uSgiQrJB/fryb4mpEWSasE/oUf75HOqOTBQdL+7q80CLcp3PByC0NJv77DssN8n
         45QQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YTvSgeVNDHT2v1NI0Z4UcWXeweoccCvmPkcI6/F+BtI=;
        b=DZQbeoKDvIdlDR664bgDFwwsDq50efpGAIVaxFV4VcZyW6h3mx5m7NkUO8iAswrz8T
         RTLay/tVRqlWmAVKzviMRIgBWS/egiCUtMt97/ZVQY42MN47ke8GEHs3RyvoTwfPTqIE
         N8Qz6xCdmLJHIaEAGwDBvcC67yw/Sfj9pO+EyKetCMLeZB/o13dLW319H9wsFT6lyOXU
         1li1EU4Rco4/DbA7E+RlnmegzRI9j3QDlsjX7D0CNI5dQO2aCB5Ka4AvgzjOqNOE1Oq8
         cxp7AGmdz3IVJVtn0izsr0cQnfxzNQpeaVL4dACrjt+XFVTC0Jhn2jbs+4ytAkbdetiS
         HFuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=YTvSgeVNDHT2v1NI0Z4UcWXeweoccCvmPkcI6/F+BtI=;
        b=TX4a6WgNSv0MmNWafm24lJJzf0ux3An9+3K+TiYjONnC+TKC1JJqZ0OOHMfitGChM1
         xPiQsI3ZxMagQqNK464uqhpyvaEd1F4jYDKifeUh621S3R5MlL77zPb4UYqvXeO1sx76
         sxiSs7RaOSBVxtBtEQbYQq0v4/3ydovYfcPFKgQKxJ65zho8zMZSrFQAAuUSQEkt4yap
         JVzfz1mCjO7XzY0Zplcc+DoTWh5dxacGqwGKfYlgFlfkBIMhOByEPRY1enmjoiliob+q
         ovRhZPT442JmCniGl98Lh2HOwVbBpSkPLFe0zaBEEvE4pG55GvHrW5ILBjxdOIkKeTtP
         fbVQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532uhrS17BuLG6/DLY2ThRjfNXiWhYK11ju6giaYnldvujPJ7cAT
	zsvHH7mq8sAf0MpG6irM3ms=
X-Google-Smtp-Source: ABdhPJyrP5GLoeD8gyF/UYMI2S6VLPHzFiXY7IUAMUSoa+HGZOkqtRAOxGDv8mWBbm/MAnyQSxq0cQ==
X-Received: by 2002:aca:4cce:: with SMTP id z197mr1262325oia.118.1597408451361;
        Fri, 14 Aug 2020 05:34:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:d555:: with SMTP id q21ls45074oos.11.gmail; Fri, 14 Aug
 2020 05:34:11 -0700 (PDT)
X-Received: by 2002:a4a:9298:: with SMTP id i24mr1515934ooh.5.1597408450933;
        Fri, 14 Aug 2020 05:34:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597408450; cv=none;
        d=google.com; s=arc-20160816;
        b=fyrNGWQ7Ronp3j55A2v9LNwbD9H/V/1yUfqc9wdrNJje0aRkGEJjqYgNy4B4Z9gA+0
         D8YSGvi3g3pWtEeqX06d1VRFur6V7PJyhsoxmm5q78s8ILfz1v9dbFINgBeenB6TbSUS
         v6C8IuUHp62JQQOpr5j4+5Ho+mjDrDP2L86B7x+wxicr2gyoYUCuIJZFodx22w9+IOHX
         GyZdB+QexOz03pAd1xz05voXa7cRZ84nmdBBkQ9J44cu++Lmh3GMEDhNE3QPjjwQfbpr
         EamT/hGT4rsnTu2khjdGIGXxmBxHSz1mP85zd9D1KAQqm0iDOrZOjnEn8Qwdon7gXQA4
         WW5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=Ukhz8djqX1OiGAc3hdvf/8g0VwarRLmUdLD4Jq1qXII=;
        b=R0Z7m7SqWguk3vpfzQH8xwTA0vE+2FcDC38oWYmc9SScypupfwSoEQJaR7fSCoQb96
         CgzxjCn6RJPKBgL5GPcGcP54cd9B6gQrd6pg4Vd4A9rXezHuoblgC5UvnHvWPYskfwV7
         HpKma+EvkkGSoGsL5Zh71d6Iv1f64gLuhmEVggRAiJMmdD3scQbIzg+b8w/4OeiodSM4
         a6fyrCNSuzHCbH4UJiIONpAPvY1gCALvH+tRXi9WhhjlDs6fpiGMp1TDjxa7QdxCycqR
         N1WbMTMhP+Uz8HhAi9/XlqOGGoIxwoIHkWd8NvWtaVxbBDiwyjGr4xPz2zhmJuEQErH8
         r+RA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id p10si616853ota.3.2020.08.14.05.34.10
        for <kasan-dev@googlegroups.com>;
        Fri, 14 Aug 2020 05:34:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 9C6EB31B;
	Fri, 14 Aug 2020 05:34:10 -0700 (PDT)
Received: from C02TD0UTHF1T.local (unknown [10.57.33.165])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 40F0E3F6CF;
	Fri, 14 Aug 2020 05:34:08 -0700 (PDT)
Date: Fri, 14 Aug 2020 13:34:05 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Will Deacon <will@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	linux-arch <linux-arch@vger.kernel.org>
Subject: Re: [PATCH 8/8] locking/atomics: Use read-write instrumentation for
 atomic RMWs
Message-ID: <20200814123405.GD68877@C02TD0UTHF1T.local>
References: <20200721103016.3287832-1-elver@google.com>
 <20200721103016.3287832-9-elver@google.com>
 <20200721141859.GC10769@hirez.programming.kicks-ass.net>
 <CANpmjNM6C6QtrtLhRkbmfc3jLqYaQOvvM_vKA6UyrkWadkdzNQ@mail.gmail.com>
 <20200814112826.GB68877@C02TD0UTHF1T.local>
 <20200814113149.GC68877@C02TD0UTHF1T.local>
 <CANpmjNNXXMXMBOqJqQTkDDoavggDVktNL6AZn-hLMbEPYzZ_0w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNXXMXMBOqJqQTkDDoavggDVktNL6AZn-hLMbEPYzZ_0w@mail.gmail.com>
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

On Fri, Aug 14, 2020 at 01:59:08PM +0200, Marco Elver wrote:
> On Fri, 14 Aug 2020 at 13:31, Mark Rutland <mark.rutland@arm.com> wrote:
> > On Fri, Aug 14, 2020 at 12:28:26PM +0100, Mark Rutland wrote:
> > > Hi,
> > >
> > > Sorry to come to this rather late -- this comment equally applies to v2
> > > so I'm replying here to have context.
> >
> > ... and now I see that was already applied, so please ignore this!
> 
> Thank you for the comment anyway. If this is something urgent, we
> could send a separate patch to change.

I'm not particularly concerned; it would've been nice for legibility but
I don't think it's very important. I'm happy with leaving it as-is or
with a cleanup at some point -- I'll defer to Peter to decide either
way.

> My argument in favour of keeping it as-is was that the alternative
> would throw away the "type" and we no longer recognize a difference
> between arguments (in fairness, currently not important though). If,
> say, we get an RMW that has a constant argument though, the current
> version would do the "right thing" as far as I can tell. Maybe I'm
> overly conservative here, but it saves us worrying about some future
> use-case breaking this more than before.

I'd argue that clarity is preferable, since we'd have to change this to
deal with other variations in future (e.g. mixes of RW and W). I have
difficulty imagining an atomic op that'd work on multiple atomic
variables with different access types, so I suspect it's unlikely to
happen.

As above, not a big deal regardless.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200814123405.GD68877%40C02TD0UTHF1T.local.
