Return-Path: <kasan-dev+bncBCT4XGV33UIBB7USYGPAMGQEMZGPQSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 29FD467A49D
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Jan 2023 22:11:27 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id h2-20020a1ccc02000000b003db1ded176dsf4426188wmb.5
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Jan 2023 13:11:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674594686; cv=pass;
        d=google.com; s=arc-20160816;
        b=bIJj6ZNNu48eEnJfe/iQyB6RzfpCoV43Sy+kbDK/m+fpCWD5bbCIM+lVyE9GHaCySl
         Uy78kSIanyJikGjLP7KpmAphdQp0Ylz5KCZGrdVvN4Qz2D9jOCFhsVtPb6S4K38LME2s
         LfvGbJO8zeCtaLUKQrncjwRD4fCSVag3eWNAMHLFJ6WLnFuqLaTrzNidJ++uGbHXKiyL
         V6d6gWd/qEjhnc/FOQNFFobiQ5xc4lRsgWhI6pozvEuXeNIq8687Xffo322SAJhda8gf
         2TeyW/IyyGuXpSk+2ilkmB+tcVpvRBIRvVK9EI6tj4xsZUJAocxlXvGfUBoXvartQf8y
         2BuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=Rz1zdemo/Fa2QsxUL5E/onYKQtwRvT7ZNx3iJMfMKqs=;
        b=v83ubvmI5DDO2ul7ES3gW2CycscglkgnMyKggzBjp4hJ74dBFo3vEugesyLm67hIoF
         PLfNEILt3N5XkIfnIbxGkb3E8dKCfxwbyjtOYsmWz7RVDcK1t1O/ULqm3CyIOQvVm/Tk
         nKyxjRYEuFf1nOX3peW9xRuPx1d+wNa1CkIBnTKmmYo4Z5pSvKaGAs3k9xFv53hw/4my
         8rg7HlwLexkdGMAxxZE0EMpCq8B8BXfCSIoKXqyB85iLKSeb27MQYCQ8cR10sS+ivwVU
         2CGaMx5tOai1JYjYy1Q0aCACKUTQr8iert3ec3oWLQVXHQcMOqtUCvbd1roPVDpvxeYH
         TioA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=CKExzjS4;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Rz1zdemo/Fa2QsxUL5E/onYKQtwRvT7ZNx3iJMfMKqs=;
        b=DAa1qa3+G4IGcy9NB44NCRjTTlp292A+WfnDzeq35mIDk0Up4sSrGc4+wSgHqGzeKo
         PaXApWi4wYEy9uujhKbvG3Q97b/aBtmWQ5WWscLgbgYzY8lUFEaB0LPfOtcLHiwqqP1t
         DdVoDiG4geHG4b2VMsdS0+c0BY/toHz/unBMVt8lc9t0jP6wmGZIhjtL9hdNbab2/bCM
         xBO7d4IPQ3YbjzJ5CJ6bOnX7MTqOAkwKSJeEHmt6qZgcMvt1PH3JeYIhiDcV95BBncPN
         x+BF9EIVI9Oz5/810ieW6JQTUghkDNhKDMNvu9ZwT32a4cqgZwaVGwQwFxFslcCS3YSC
         dqlA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Rz1zdemo/Fa2QsxUL5E/onYKQtwRvT7ZNx3iJMfMKqs=;
        b=0ox1I9C2v+1IcoOh+ZSbwDxS+X+YtWQ8H9eJZRrzQGIp8VIr2kywLxTiBCX6EIhstX
         CEDMeKVW1nKxeWeC++YpeT3zkCHz3b9R0s/ILi+6y5pKE2Yq9IAp+d9ivUgWkDVlZblu
         bmz+7AW9+BKKgRnHYN3OF8du3x2VQIkBaC0yPHkrgpvZiAeauc2MS7uslGOqTmUH21fm
         Z7SguH/HrWM6L5gfpxzy1WnUdcehWyUjhztCoc7xsAJD03fgnYmD7UdHj2gf55HLKV3n
         xr1GrkliDZMLvZHXP5Z7s6QSnnHP6zLqPotwe2Z4NvnEcTbUq+0vx2fHTHIy506quRjS
         bwHA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUTlzao+hQIZi3dfN3k0HijUzjGcJIi4sCQB2SHMaNkUVnj00op
	zi2JS+oDda8HB1n0RJJFSfM=
X-Google-Smtp-Source: AK7set+At37zmJ3DW9nXJ3m0fTes+BZMtnvOi1h/rreXwtug4tSwR6vh4ziRk7Gf/dg7G8P8kCyaTw==
X-Received: by 2002:adf:e90f:0:b0:2bf:b414:7f44 with SMTP id f15-20020adfe90f000000b002bfb4147f44mr150852wrm.12.1674594686819;
        Tue, 24 Jan 2023 13:11:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e48f:0:b0:2bf:ae0c:669b with SMTP id i15-20020adfe48f000000b002bfae0c669bls3357691wrm.2.-pod-prod-gmail;
 Tue, 24 Jan 2023 13:11:25 -0800 (PST)
X-Received: by 2002:a5d:5244:0:b0:2bf:b77d:c5b9 with SMTP id k4-20020a5d5244000000b002bfb77dc5b9mr391346wrc.14.1674594685512;
        Tue, 24 Jan 2023 13:11:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674594685; cv=none;
        d=google.com; s=arc-20160816;
        b=vzx+MTmuDELZK+o+ohcb0ONY36aLZtMthEQ8XoO2tJt+54LZ0eNVkktevYDtj70bnR
         8XDNl0CqqH9nG8dIg9oKhNMwh61twp/Mo65DuYrHIivciyHHM3fIg+ZaZYoFV/Xeq4am
         9nKpzpTRsIf75Ze3KRaiiLGQTnaW3XealRxJb2cLywZ+QiyYc/Votxmtw0pMtNnSz3B8
         6GHXtXeWReDnbhWlda9uUvGn8kw7cFhubngD1s30Y80v4x332drRTJVeqcUGVAigFb4n
         QY3Kbo0pJ1FcaqDBsqokk4M0t2YCGEG6n1QnXx47/1qamQGEM1c5Slhztigk3BYBO5gX
         OCqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=GhdlvJXtQ848aeaEeE9k6y/WzXUlf4pRiY81iob67bI=;
        b=HKU9W7ZIKjybYVXn7SI9MJ5vTk5NUjWK3ok8rnO24zLfhp03A3UhuHH+ZEiidmHQON
         JHyQ+MiPssuAQrdol9t3cRf5LSfZckxRPniGr/6n64BT+4bU/4yZEofGC2CJd7XT/PSU
         OYCNM7Hr3KsfWeLrj8KhgjnMgE/ZQByR5WoEeJFsWUyci6Tr2XKX6sgg3pC9b7KozPr4
         xH31lpNi/KXoYCW69AV6u0vk43o/cwSWaWQcVjBOLqsVNNFWzbcKd3xHVDWtngwRLC3y
         ktLgz+M4Loncyshl++I9qC803dSH/PEza+MvD3DkrDxj9Cz2Rr8TtMjqNAvkVrEVISNp
         Nggg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=CKExzjS4;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id ba25-20020a0560001c1900b002be1052742esi152285wrb.4.2023.01.24.13.11.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 24 Jan 2023 13:11:25 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 2FB27B816D9;
	Tue, 24 Jan 2023 21:11:25 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 89A16C433EF;
	Tue, 24 Jan 2023 21:11:23 +0000 (UTC)
Date: Tue, 24 Jan 2023 13:11:22 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, Alexander
 Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrey
 Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, linux-kernel@vger.kernel.org, Andrey Konovalov
 <andreyknvl@google.com>, Peter Collingbourne <pcc@google.com>
Subject: Re: [PATCH mm] kasan: reset page tags properly with sampling
Message-Id: <20230124131122.fdbf6ae3069e6b0d05d14361@linux-foundation.org>
In-Reply-To: <CA+fCnZeDWxFB0BgUy_tEybtagth=bcGcqqu9LPSOEjKr5j-o8A@mail.gmail.com>
References: <24ea20c1b19c2b4b56cf9f5b354915f8dbccfc77.1674592496.git.andreyknvl@google.com>
	<20230124124504.2b21f0fde58af208a4f4e290@linux-foundation.org>
	<CA+fCnZeDWxFB0BgUy_tEybtagth=bcGcqqu9LPSOEjKr5j-o8A@mail.gmail.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=CKExzjS4;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 145.40.68.75 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Tue, 24 Jan 2023 21:46:51 +0100 Andrey Konovalov <andreyknvl@gmail.com> wrote:

> On Tue, Jan 24, 2023 at 9:45 PM Andrew Morton <akpm@linux-foundation.org> wrote:
> >
> > On Tue, 24 Jan 2023 21:35:26 +0100 andrey.konovalov@linux.dev wrote:
> >
> > > The implementation of page_alloc poisoning sampling assumed that
> > > tag_clear_highpage resets page tags for __GFP_ZEROTAGS allocations.
> > > However, this is no longer the case since commit 70c248aca9e7
> > > ("mm: kasan: Skip unpoisoning of user pages").
> > >
> > > This leads to kernel crashes when MTE-enabled userspace mappings are
> > > used with Hardware Tag-Based KASAN enabled.
> > >
> > > Reset page tags for __GFP_ZEROTAGS allocations in post_alloc_hook().
> > >
> > > Also clarify and fix related comments.
> >
> > I assume this is a fix against 44383cef54c0 ("kasan: allow sampling
> > page_alloc allocations for HW_TAGS") which is presently in mm-stable,
> > yes?
> 
> Correct. I assumed I shouldn't include a Fixes tag, as the patch is
> not in the mainline.

I think it's best to add the Fixes: if it's known.  If the patch was in
mm-unstable then I'd just fold the fix into the base patch, but a
Fixes: is still helpful because it tells people (especially me) which
patch needs the fix.

If the patch is in mm-stable then the SHA is stable and the Fixes: is
desirable for people who are backporting the base patch into earlier
kernels - hopefully when doing this they know to search the tree for
other patches which fix the patch which they are backporting.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230124131122.fdbf6ae3069e6b0d05d14361%40linux-foundation.org.
