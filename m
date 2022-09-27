Return-Path: <kasan-dev+bncBDW2JDUY5AORB5HZZSMQMGQEHJ2CPZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0508D5ECBEE
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 20:12:08 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id f16-20020a05680814d000b003506268b99fsf3509700oiw.2
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 11:12:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664302324; cv=pass;
        d=google.com; s=arc-20160816;
        b=qk/6hXdron/mA0z4l56DXhiIhTIhNSVgF+xpXki3cxy3fxBATjA//keg8m1FK/OFNj
         zUf7VWCWqGMwBFyvUBNQYclrpZZB36Mpcn6NNUD7NkPkcpyREH/6xbq4kKV1SPApqpcD
         kNdzvBBKvvf1n3gAiMxGxC99QNo25kAs8ak5420/51UZ6+Zguor7vb1OMZbIdhcxJAg4
         PtbEAyTLGbjnCWf8QLcoDlgptlQR2otJV8js31nKdr9Yc2lk/OlG7TQHelBI8/DUnuQw
         ddK1SjexxfVqTMfPb3LRpeIS32ZgWdVby4bdAoZCr0uYJkjbf0tlslnfOfI4ciF7u2kG
         oNpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=Pf4yaxk6PBbIzppK5zHPnD71SkaHUzGWbxAkCEwmB6U=;
        b=c2Lff9VU8HlAySI8aT2+dO1w+cargjTpk3sJTrkqMWgPuCRK+3h8NTMIlQMc17Qrji
         420npk7bHfXeRk63ydB7hdGdFkv0M1ltSFet3w3FrrgtrX8zCl0acVhbp5ZpSENWx7MZ
         fysTVOXr49+LhV7ZTfWZ1w/tDJK1jKPXAqCgcniWEIytkWpEfJ1Cj/RQG52GxVB16cnI
         wRssLphB46gUYVHB/d0YFWcy/afVu1wJrs1D6pWd7NxMNUsFJGGyeICOVkT77Ue/qrXz
         pNnYM5jmhYPogurmPJ4Q4+6cvDdKclwexwYb4vwmmwwX+iJzQe5ZNEcin0zCwdmtR9xM
         ZmEQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=K12nEPM8;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::82e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date;
        bh=Pf4yaxk6PBbIzppK5zHPnD71SkaHUzGWbxAkCEwmB6U=;
        b=QtUbrgVlSvuupnScz3HbsjSEMas3atplm3fG+ySakzKjg1fiwmXP9p7MTKyN+x9DrP
         aYFtswHY0CddXDARQ/GdRNi0CgcejjKbLJR8JixfDFcoxXUJwuNNASrSK9cMx0tLpeQI
         NecjSPjPv3DE6WTS3NXJh2HNg6mjU60GyJZPYNsmJYzwN6fvnwptByq3G3SLSkAjOfRh
         rebKYYlOjP9UMGHtr2Jmd/+ke9FyM4ZmoiystYCdAQPgomhtM/Z/Btt+14Xb5SWEODHs
         5wFTqnQBXe7Yp+So34gV/fvcEttb8r/Aiv7N38GtoJVFcio02gLrEfznDB5ybbK8AK4w
         osBA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date;
        bh=Pf4yaxk6PBbIzppK5zHPnD71SkaHUzGWbxAkCEwmB6U=;
        b=JI/0hrHYYlqghuoolHBz1NVQRqkVHLHW6jIS6n/M9PawxZAjk5xoepoDly1/rtR6xT
         i/5PhPLl+zrfhYgzV0u3P1hNAhiNmKRm+F/NXTcfspDH++RWsUexAGsagOhdLCep92yg
         yzQK2O+tXWC0GeViMN1EVvUkKt2dD6WtOFlxWb4UwG71sfHTTui7Z9YNycOzxVs1XUh2
         tNCqfoWDgvAsVZV07qVmMwAv0G/a075LFmWYr1F0fDKl58Oe8+M6xTkpZUWvF2BSqBO4
         nVhJg6rOout2SsXbFc3ltixgVRbRmo6LyyGbByj6X8Oyf1honll34azIpQZUDR94POSz
         e6nw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=Pf4yaxk6PBbIzppK5zHPnD71SkaHUzGWbxAkCEwmB6U=;
        b=IGStRvi7NVUddagaKvd1aFrkVeFdAqEcqWM3iBLCvnprEZFSlKnV2tDrHsONXcH8mc
         K9H9YuishKEPL6B6DRkk8zvaUepC8jrWYdbSAKJlQy5bQ8jJBSmSIAgx+x41o3czDGGQ
         UbEUMQerb8PfIeMWkRUZ6XxybEUmGzHtZqjSmNLmVr8OhqF6yz1a20HUduiN4u2jjl+W
         WJzgGWnZ+pF6bmubSppH21bejc7G+L1bd2VTQe722nG/MFb9zAzbkIaQqzRg3k66kDTf
         MeqPogANxKVVsJll3wPz0FWnbIg3J9zTjHpXoE2X7EGCNb7MHBeC+Ylsvt5umZN7UXBL
         85HA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3BUBupF6jxQbAx0yMXxrWqz3woq3xYreMAK49xwzc5vnchvrdf
	iSvg3V50RSInzIh8e+gv/cs=
X-Google-Smtp-Source: AMsMyM5M2c7dZ/ROcCT2uhYQFOvvA3XhmhmkWLbwG9oJrsZCOpoadLcL1Bd1sEoOPQTS2aDFhJddjw==
X-Received: by 2002:a05:6870:d6a9:b0:127:fb20:c5c0 with SMTP id z41-20020a056870d6a900b00127fb20c5c0mr3033451oap.175.1664302324554;
        Tue, 27 Sep 2022 11:12:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:602:0:b0:344:8f41:1800 with SMTP id 2-20020aca0602000000b003448f411800ls881963oig.10.-pod-prod-gmail;
 Tue, 27 Sep 2022 11:12:04 -0700 (PDT)
X-Received: by 2002:a05:6808:210f:b0:350:185d:2f31 with SMTP id r15-20020a056808210f00b00350185d2f31mr2352811oiw.224.1664302324146;
        Tue, 27 Sep 2022 11:12:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664302324; cv=none;
        d=google.com; s=arc-20160816;
        b=Pa5TXmgdt170pw/8dmYgiu+BFYIRAiFd4iD/vAHEfh0d3N1u8RkqW0sbd1sFTWThOR
         8q3NfmcRYLI9CCSxR3KNifYX8SXhft+Eluau05jQbZ4J8tlyR/bB3+AGZMg5IsE9sXSn
         krX5i9RWeb2F1Rlv2u79TeDIHFVt9bH244YGHLBvt2QhRlqG12bs/xv13K40WmHIFESn
         bJe+Fmkhc5XMUTOSxjUHDT+SekiPfZ3szkQKHim2KxghHBcxNUpNgJove3Y2lusdZBf4
         VHyOX+E6VPL+xOA7SO/GVS3MOElJSpAsEXOmNYAZLWuMVD6fGhfff2pAlaFZNMyU6EKe
         tGtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=UA0/tgSQ2gUroOfJyqI9Qe+9Q/6Wy5CUcMkTK6avI5s=;
        b=NS5hudZYvw+2dxqrIzqirpcNk3SGsSkxHFEfyrvPP2kpSNrP2bERKVRtc1/VzoeReH
         Tzbg3iJ1TQ4DQ2vd2D76pBlsinpFqNeCMTxa4njRmg8Q83CVwtKHECyxCXzH5wSChVIb
         9KRExABwl8A7qtOwHEMKf9vhBHHQ0M91WU8J9R+4njJu7jzdkHgXUe+RMgfMBmrCIzmI
         pD1ANuEuZddZTJWTNEbJJRvUwUHQTmCj1Dx+GNuk0kO2WAwJHrIqZRe7iPuZP3Z6/Lsl
         TlU7YFGzqeJ9e+QZ//BRYs5GJSRqjekiypGjC8smEhnKV1N8b+VfZNRQBmlKnH8zUCl9
         xpsw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=K12nEPM8;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::82e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qt1-x82e.google.com (mail-qt1-x82e.google.com. [2607:f8b0:4864:20::82e])
        by gmr-mx.google.com with ESMTPS id u12-20020a4ad0cc000000b00476778e657asi58107oor.1.2022.09.27.11.12.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 27 Sep 2022 11:12:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::82e as permitted sender) client-ip=2607:f8b0:4864:20::82e;
Received: by mail-qt1-x82e.google.com with SMTP id j10so6558398qtv.4
        for <kasan-dev@googlegroups.com>; Tue, 27 Sep 2022 11:12:04 -0700 (PDT)
X-Received: by 2002:a05:622a:11cf:b0:35b:a369:cc3 with SMTP id
 n15-20020a05622a11cf00b0035ba3690cc3mr23563179qtk.11.1664302323892; Tue, 27
 Sep 2022 11:12:03 -0700 (PDT)
MIME-Version: 1.0
References: <9345acdd11e953b207b0ed4724ff780e63afeb36.1664298455.git.andreyknvl@google.com>
 <CANpmjNM3EYpq_qaN8yzt6eVzK59YCPeBdoFMjLRBqoTy2p=HuQ@mail.gmail.com>
In-Reply-To: <CANpmjNM3EYpq_qaN8yzt6eVzK59YCPeBdoFMjLRBqoTy2p=HuQ@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 27 Sep 2022 20:11:53 +0200
Message-ID: <CA+fCnZeoaVHudERNTKFK1kNcOp9TY40kPxbCMM5zO75CDfHfuw@mail.gmail.com>
Subject: Re: [PATCH mm v2 1/3] kasan: switch kunit tests to console tracepoints
To: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=K12nEPM8;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::82e
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

On Tue, Sep 27, 2022 at 7:12 PM Marco Elver <elver@google.com> wrote:
>
> On Tue, 27 Sept 2022 at 19:09, <andrey.konovalov@linux.dev> wrote:
> >
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Switch KUnit-compatible KASAN tests from using per-task KUnit resources
> > to console tracepoints.
> >
> > This allows for two things:
> >
> > 1. Migrating tests that trigger a KASAN report in the context of a task
> >    other than current to KUnit framework.
> >    This is implemented in the patches that follow.
> >
> > 2. Parsing and matching the contents of KASAN reports.
> >    This is not yet implemented.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
> Reviewed-by: Marco Elver <elver@google.com>

Thanks, Marco!

Andrew, could you consider picking up this series into mm? Thank you!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZeoaVHudERNTKFK1kNcOp9TY40kPxbCMM5zO75CDfHfuw%40mail.gmail.com.
