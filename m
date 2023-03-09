Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3MKU6QAMGQEMC37CPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id BAB886B2334
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Mar 2023 12:39:26 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id u14-20020a170902e5ce00b0019e3ce940b7sf964727plf.12
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Mar 2023 03:39:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678361965; cv=pass;
        d=google.com; s=arc-20160816;
        b=iT0HkDP2a4OBAcW6m6kM7acSerkUfPr+DWZ2QH80WGWG1i4ZXWgeSQyYtNKeIQ4dgI
         obKj8SV8D2zUQtdBAknj5UG4fM9XJnuofWnKeYNvloMakuOVh659DoTxIiK/fG4jOL0R
         5rwwgAcfbDZlMTn0kLned2T33HVxrrfBMZFWBHuVfulPxVgDzUAmZJ+gWV/7SrkOTTQR
         w2vUsBhuqxZyOWuSG2T03mVwPr3aex3j0YaVz2Ts6D5IL5Sf1MMRtokeVfQuRoboiR+j
         eThJpRrflB2RteA0sJsIdvH+m1ad1hRf+GQfP5YvFOWAF82+HDFABtRCdyJfOhTST6gE
         uaBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=s6sXeoemdzigb4TWnPRYcOQZ+0vFvJ6jShOms/N25WU=;
        b=ykPtAicVZZaTsb56c+Hl7Qhg3nPg+kXq37O7T6tTN7bEEnCTEbUQiyLHRvtVZDnxnL
         b+gPBMPyppNvm+T1LpVwFTXTOlEXZzYO7BBGWDhr+VZpxpD4aiFvwuh2k4VXayzcrqCf
         /xPrpnH6SI4EQFDRGbSpB8XQPcYfx22bo/jwIaZje5zgEiSEPBzmGiP+yU0Ueiq7EH36
         PWhOCEZY3B6U112wyDxs6/RqhTJDgSYSsV1WfN7rB4PQMplV6yKtszyx0Uqan++WTCJg
         dMmDmKtSeotde6MeCkc9YHXR74/mt/6GLUaAs7CS9HjbdYvx3jXnifyufaTlQt/NB9l8
         KiGg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VzEe7sRh;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::935 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678361965;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=s6sXeoemdzigb4TWnPRYcOQZ+0vFvJ6jShOms/N25WU=;
        b=VseuUQe1VidRkfMitmWXPy48EpcpC6xq75dzKmG0dNjgP0193u0kzPRVOcma5nXKsJ
         KlEwAD/zeR+ZBl2SoJQLpOQdioRyL4WOcl8EtBQUuSs7Fz5c0EmDl7Z/etoBUDxADJb6
         UlejXgY1DeAj1D5sv0jMnsT5OiD/j79N9adTpXYzNbAcMcPoM3pDgmpsxzhwvdiluHOy
         TmX6I5TQusUlniOLCYupgoD1ErhvQLE/aEpAI28niMji5Z8jLCnIQ2OkOYTMYvRBKF/a
         rEr3t9gjqWvp0R0ym3OQkX4gWm96XfzJaVe9pQyHRITkOMGFE5H0xm9Y2R/8pmrdaGmZ
         UHMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678361965;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=s6sXeoemdzigb4TWnPRYcOQZ+0vFvJ6jShOms/N25WU=;
        b=yvpC2t0qw5LoGgFZFnfjpmA7g7QOxo/qxeW/j91OEjb9fffU64gx3KJWQLKL3UULPW
         GtFPyVU2CzytkL3ACGx0duPLfqb3/I/1yGhi5Sbtv82LPFu1mt4FBQzzVropbFs8BClQ
         Ok/UfjprGyxTTwRmyG2n6YVUmAlEEsQgKTPOshx6mp0FoI6EAml9GdMpJm1AB2oPZT/r
         HyVRpz1etPqs5TSzCgAnpe8vJkbmTtpTFuRMK9a3jLRw1xqru/ZvNDouh7LZnokmwScP
         Z6khJB6oB9YQFAj/Uc1N4YRxCxe2U+s2j3ws5YlhK6hIY67Z6tGXFGEu0n/qKrHE7Dve
         Ch1g==
X-Gm-Message-State: AO0yUKXC/RfynRHtQCmufMbjtPpoNl5w2VgUizua4mTJ0cN/ZhxrHH7v
	cIztKQu4F2t2wsqiTi5jDXw=
X-Google-Smtp-Source: AK7set/1C1Y6neaPX3Qtr4DGDZY0vHL2caGMmzDl5pSe/X8vF78PgSjpbIPRp+cpQR4i53cr3JUc+Q==
X-Received: by 2002:a17:902:ab05:b0:198:ec76:e249 with SMTP id ik5-20020a170902ab0500b00198ec76e249mr8663967plb.13.1678361965302;
        Thu, 09 Mar 2023 03:39:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b60e:b0:19c:a86d:b340 with SMTP id
 b14-20020a170902b60e00b0019ca86db340ls1974441pls.9.-pod-prod-gmail; Thu, 09
 Mar 2023 03:39:24 -0800 (PST)
X-Received: by 2002:a05:6a21:99a9:b0:d0:52b9:5f76 with SMTP id ve41-20020a056a2199a900b000d052b95f76mr9062758pzb.3.1678361964468;
        Thu, 09 Mar 2023 03:39:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678361964; cv=none;
        d=google.com; s=arc-20160816;
        b=wA/GpfIjm3pGSBamYf/DHimvA24fojbGOBTat5n3qmZ7KduZtEWRYZqoaWyDpS90Yg
         cBOhNA91//eZm20LEgImjlXwtaS6YrpZs9A3gSo1BsDlipBwToH/aV7Cum1jdvmyG/NX
         b5z6Tjha6sQAV/HgxcOqfs97cm0wZV/H5ue7cPt1kBpVySh2KkZctHd0Bno8dZM9QYvq
         DFF/G1CBM0b+pCg5CoO6k7UK4NMXVWe70QjgLgppHzpk5yfFqqCPWXfRNk36aqZ5Gtgs
         i/j+nf9fnbLcc8mJrfO1xVsoL9OpDq8eWF2CH38s0LM4xPfMhRACEFP5BKhX5SVtvQrM
         +EfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=G+8z2L1kFSNkS27suUQ09cJ0m82R8UDZ0dpQDPDz3WU=;
        b=tu/TC9iLsc3xfiJqUXgnDlgqGL8PgI1YVeW+N/x1rWqYXskAYj0LVMI+l+I6+eMhcN
         f3lX4nH8CPmQXEcRdDRX1lZuoTw3cFQ14mHhhhMz6s/1idRNQUn0F10CScyEzHpAzbqQ
         LQKoIQa4bMG7f/vPHEPEgFO9VL9wRGTya5uz+KCRH5rpmbmeerVDv5uaNmtVMMCtYbcO
         CujUu0VegtiXV4Pe02EJ4LmjJXMzrD5Gz5e7hJy3zKjy/HRP7GQ0sGJz4e9bdUFB9CQM
         GPlRBijrtqCmHhBMwBJh4XHlieP0Oup8QRMiUFntchb1x3mCcsAU8KvdPz7lUdpIYVSd
         yRlA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VzEe7sRh;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::935 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x935.google.com (mail-ua1-x935.google.com. [2607:f8b0:4864:20::935])
        by gmr-mx.google.com with ESMTPS id f22-20020a056a00229600b005a9c5460f25si751600pfe.4.2023.03.09.03.39.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Mar 2023 03:39:24 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::935 as permitted sender) client-ip=2607:f8b0:4864:20::935;
Received: by mail-ua1-x935.google.com with SMTP id f17so895841uax.7
        for <kasan-dev@googlegroups.com>; Thu, 09 Mar 2023 03:39:24 -0800 (PST)
X-Received: by 2002:a1f:4384:0:b0:41d:fe99:4633 with SMTP id
 q126-20020a1f4384000000b0041dfe994633mr13340530vka.2.1678361963509; Thu, 09
 Mar 2023 03:39:23 -0800 (PST)
MIME-Version: 1.0
References: <1678349122-19279-1-git-send-email-quic_zhenhuah@quicinc.com>
 <CANpmjNOah6gSB_mRvhsK_9DpBtiYinRd5z34PU+tOFgSqXB8Sw@mail.gmail.com>
 <706340ef-1745-c1e4-be4d-358d5db4c05e@quicinc.com> <CANpmjNP64OSJgnYyfrijJMdkBNhsvVM9hmwLXOkKJAxoZJV=tg@mail.gmail.com>
 <3e8606e4-0585-70fa-433d-75bf115aa191@quicinc.com>
In-Reply-To: <3e8606e4-0585-70fa-433d-75bf115aa191@quicinc.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Mar 2023 12:38:43 +0100
Message-ID: <CANpmjNOT9kk00nps2vcZ8_Zuh+m1zVpReT+k28U4iD7iOC5cQw@mail.gmail.com>
Subject: Re: [PATCH] mm,kfence: decouple kfence from page granularity mapping judgement
To: Zhenhua Huang <quic_zhenhuah@quicinc.com>
Cc: catalin.marinas@arm.com, will@kernel.org, glider@google.com, 
	dvyukov@google.com, akpm@linux-foundation.org, robin.murphy@arm.com, 
	mark.rutland@arm.com, jianyong.wu@arm.com, james.morse@arm.com, 
	linux-arm-kernel@lists.infradead.org, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, quic_pkondeti@quicinc.com, quic_guptap@quicinc.com, 
	quic_tingweiz@quicinc.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=VzEe7sRh;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::935 as
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

On Thu, 9 Mar 2023 at 12:26, Zhenhua Huang <quic_zhenhuah@quicinc.com> wrote:
[...]
> > Ah right - well, you can initialize __kfence_pool however you like
> > within arm64 init code. Just teaching kfence_alloc_pool() to do
> > nothing if it's already initialized should be enough. Within
> > arch/arm64/mm/mmu.c it might be nice to factor out some bits into a
> > helper like arm64_kfence_alloc_pool(), but would just stick to
> > whatever is simplest.
>
> Many thanks Marco. Let me conclude as following:
> 1. put arm64_kfence_alloc_pool() within arch/arm64/mm/mmu.c as it's
> arch_ specific codes.
> 2. leave kfence_set_pool() to set _kfence_pool within kfence driver, as
> it may become common part.
>
> The reason we still need #2 is because _kfence_pool only can be used
> after mapping set up, it must be late than pool allocation. Do you have
> any further suggestion?

I don't mind kfence_set_pool() if it helps avoid some #ifdef CONFIG_KFENCE.

However, do note that __kfence_pool is exported from
include/linux/kfence.h. Since you guard all the new arm64 code by
#ifdef CONFIG_KFENCE, kfence_set_pool() doesn't look necessary.
However, if you do something like:

#ifdef CONFIG_KFENCE
... define arm64_kfence_alloc_pool ...
#else
... define empty arm64_kfence_alloc_pool that returns NULL ...
#endif

and make that the only #ifdef CONFIG_KFENCE in the new arm64 code,
then you need kfence_set_pool(). I think that'd be preferable, so that
most code is always compile-tested, even if the compiler ends up
optimizing it out if it's dead code if !CONFIG_KFENCE.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOT9kk00nps2vcZ8_Zuh%2Bm1zVpReT%2Bk28U4iD7iOC5cQw%40mail.gmail.com.
