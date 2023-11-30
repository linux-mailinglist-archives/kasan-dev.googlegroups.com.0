Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAO3UGVQMGQETKLSC6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id CE0777FED88
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Nov 2023 12:09:55 +0100 (CET)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-1f9e2d92cd7sf1151369fac.0
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Nov 2023 03:09:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701342594; cv=pass;
        d=google.com; s=arc-20160816;
        b=xx6XIhsCTW5YRvafxEe2lddJRaCm+YzNAXm+o6gmvEduAKJecEHJDUxCeNxVjmKanj
         4ZVrFQ/zzWh8F5jGbvAmRnT5Dq2kFKYYDhfzaIvN1iAQUJGZyab6YIg+bDldyne4Gjrp
         9Q/x9fm9nnVgDTCh586gDLL2CgJWaw7ouEEGJl4iL1U2oa4OciqKgY4InLB38vt3RGTu
         4+adgW609FH6ARkJcigJbSL2FUiDE25+L2YuVZ5I6JqLBZ8ZyXqvosURyLwH05mICFAO
         E+UskeSZUcMV1q8rG6aPaeNMeLM2DwpAv8jbxdZU+t4lk87tqqMPZNkfqyYIaXIHJ1DP
         RzSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=HA1zB0tkujOyBlOGBpvg+Sp2KC1DxIdxuZW0m5m4UYI=;
        fh=fwWJ42K6w6cdbJRbPUk/A0m9E3CoA/JFe3Wn1sPWXJk=;
        b=LbCEAbv2ZpFHmyG+nwTEdQGK3Nbm3DS7SCweI3Q/x26AxQSDRfuW3xDEROEsJjY3HK
         qYArWNUM24AyH5RvC83r3xbMvOILWkKFIdSRH3lJXHEf9wsd5+G+fjRtNoJB1p4JPk/p
         S8+EzxM3W3dLfFCvYw8raGmDlG1M1vJzeV6VT4PRFmS5CbAt32kHqxYG733OsIdrRozc
         CU3s9ZbNtYG5c8Ceqat4ZIU7LUehxAJC5cu3sW2TJbAoMt2vS9ARSYmIXm5CqfnM9UEu
         h1Sr7mguDY35hS2c5ugyrdd+16R4NYMZ5jHu/rcqhj000nq/i+cg12Ss0uPwZDwMKi20
         sjHQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="mH90Ezy/";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::931 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701342594; x=1701947394; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=HA1zB0tkujOyBlOGBpvg+Sp2KC1DxIdxuZW0m5m4UYI=;
        b=Trj6j7y+C9z4n7EhnlAiYXGVyAClPoKWutnickG2ad9mJh7Ykacor5rX0OwttPC7pW
         GuN4BqQQXcawqORR1o2wTj0dR/0Lr3F3oOBE1jssnowCFQmyTdWQVDhQJRWtK7ujpPhC
         1UQ6ZQRPcyctQpvTZpnWDIWpc8XnFObOkitzCgDYPVtMoSJ9alfruXpPOQ6pmXZ8SNbJ
         tyGE01wdyvSvCZvCoLbmUzPeUigFPzNXhbNSj+b6IX8TSc3WnCvBIsKaQGoyZxMEQeWA
         OckXswKTSGpkT5KXy9CudqjfLTjw6Yh+T0DeSTCeqmVPpEWFGlqR0tynRxNdOSWfihSw
         +rlA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701342594; x=1701947394;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=HA1zB0tkujOyBlOGBpvg+Sp2KC1DxIdxuZW0m5m4UYI=;
        b=SsH1Xs8Dqc/qOQhHT/fBOdCSpZOaes7gDlujMEfXRe9LYf5dT6qLboiP8+kVKVfppP
         GEGlj4Ib+iQM8flV/rhFPUwYJsQDVhRMvS/GA4YRYJWxQ5JCgI6IMonW+ygiAqAi423e
         XbQ2E/ywxYaJ6H9MtWPnvMZeMGQ28zgWBDZqti26CpvvEu8oyF4UeekV8kFzntIWc1Jx
         YwUxOFUNEqn5jVLdz43trl7IywGjMrUXEB72wmDPST12hLoaqlCoDGv3K0AqwxWsp2tZ
         /mnMLk63Ag8xqDyvK2MnPzUvgSVPgRzYXEIgwg44CVklMLS0qFmxBHPNJvZ/XrRe+Gys
         1gMQ==
X-Gm-Message-State: AOJu0YzqPHV9aIH3AUVB9wjAlWCAaBul7rDw64qWt5o+L6wUw/9+gHqX
	QLp9Cc76oExRODN6K5Bc8l0=
X-Google-Smtp-Source: AGHT+IFvRcTPUYjEiL4SM0BkuB9vwKiRcD3vW1o82jirKpI4LMuHYTmygnHcg1VFKOAwaDQHPhXQUg==
X-Received: by 2002:a05:6870:213:b0:1f4:b1d6:573f with SMTP id j19-20020a056870021300b001f4b1d6573fmr25582501oad.13.1701342594053;
        Thu, 30 Nov 2023 03:09:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:890b:b0:1f9:e591:9c62 with SMTP id
 ti11-20020a056871890b00b001f9e5919c62ls3754oab.2.-pod-prod-03-us; Thu, 30 Nov
 2023 03:09:53 -0800 (PST)
X-Received: by 2002:a05:6870:c44:b0:1fa:1ca4:b917 with SMTP id lf4-20020a0568700c4400b001fa1ca4b917mr25695109oab.41.1701342593280;
        Thu, 30 Nov 2023 03:09:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701342593; cv=none;
        d=google.com; s=arc-20160816;
        b=Pmezi76sp0T1xSeexJzhn11Jnod1j3qT/AonmjjzrFNXcA86QAJAPp2toqO49SeyTi
         oeTOLlrq7KjRM3w/v+Z+5OKg1aDL6IojjmzYGaX7vHhZqtwwIYVmi9IpTT3ghNbSfBfv
         MuE3y4GoHgfKfKJN+mS7fXIykiIVASv5H0tiMw4OoQkuqNjqi/LkjgRW631adNdFzFKC
         S9rwXuKAr1pXeivJ3OZkW02Q6trjOaL5ByDR7Z5e6+pBSsgeRKf1IUAgOT4ebWY3vQgS
         aUx+7JEn4pikiK2LS+xyr5ATIbGRzXkctjt4t4oJhRgsBTp+RFYN+adyFot4WCJNJ9Ux
         RcqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=2WunqtOIKV/FoN9YcD9MHGxp9/5dKzq2zQLQrxQi39c=;
        fh=fwWJ42K6w6cdbJRbPUk/A0m9E3CoA/JFe3Wn1sPWXJk=;
        b=rvIUlpD30RoFsB54gUL3DeKtpGDjaPUyIfjPKB/uCd40C/iMBVG5jThoZXs94gll5W
         olFtHxnzvIFH2NF5clpwHgRvJnMQS9h9wIMPuqQJSdJ8+Wm26wZ3cz1EvMjRp66LDvC2
         1LBmLxdazJ072++I+eSUIalwmw8jvIm2nmAExrbDq/rt1rZoI4gb2+kAtOk9+3CARnpO
         a/9Q9ubRjT3m+cy4Of524O9xqC0Pyq6fHtVKLVXmMZyqhfchpCgVI7kGNtqJdgfvkP1E
         lsplL+odME5Gvbm58FsjODhFhitrcDWoEphChIjbOPDGxvZgYZhnMUpisugD+pvHY/gU
         d31w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="mH90Ezy/";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::931 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x931.google.com (mail-ua1-x931.google.com. [2607:f8b0:4864:20::931])
        by gmr-mx.google.com with ESMTPS id i16-20020a056871029000b001f9ea588ca0si223322oae.3.2023.11.30.03.09.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 30 Nov 2023 03:09:53 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::931 as permitted sender) client-ip=2607:f8b0:4864:20::931;
Received: by mail-ua1-x931.google.com with SMTP id a1e0cc1a2514c-7c461a8cb0dso260673241.0
        for <kasan-dev@googlegroups.com>; Thu, 30 Nov 2023 03:09:53 -0800 (PST)
X-Received: by 2002:a05:6102:1794:b0:464:4b26:5111 with SMTP id
 je20-20020a056102179400b004644b265111mr4097465vsb.8.1701342592610; Thu, 30
 Nov 2023 03:09:52 -0800 (PST)
MIME-Version: 1.0
References: <ZWgml3PCpk1kWcEg@cork>
In-Reply-To: <ZWgml3PCpk1kWcEg@cork>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 30 Nov 2023 12:09:14 +0100
Message-ID: <CANpmjNMpty5+g76RLy5uZARZAfx+Uzr+z5uAKMp-om9__2O77Q@mail.gmail.com>
Subject: Re: dynamic kfence scaling
To: =?UTF-8?Q?J=C3=B6rn_Engel?= <joern@purestorage.com>
Cc: dvyukov@google.com, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="mH90Ezy/";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::931 as
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

Hi J=C3=B6rn,

On Thu, 30 Nov 2023 at 07:07, J=C3=B6rn Engel <joern@purestorage.com> wrote=
:
>
> Hello Marco!
>
> One thing that came up for us is that we want a more aggressive kfence
> during in-house testing.  But we don't want a debug build, those tend to
> cause more trouble than they are worth.  So the goal is to dynamically
> scale kfence via sysfs-knobs.

Glad to hear KFENCE is working out for you.

> That works for the instrumentation frequency.  But it doesn't work for
> the amount of memory reserved for kfence.  We should be able to scale
> that dynamically as well.

Yeah, that's been requested before. The main problem is that it'd add
a few more instructions to the allocator fast path (in the simplest
version). Discussed previously here:

https://lore.kernel.org/lkml/Ye5hKItk3j7arjaI@elver.google.com/

Maybe it's possible to add a config option and if you can live with a
few more instructions in the allocator fast path, then maybe that
could work.

Also, we found that in most scenarios, preventing the pool from
exhausting works well with tweaking kfence.skip_covered_thresh [1].

[1] https://docs.kernel.org/dev-tools/kfence.html#implementation-details

> I don't think we have time to implement this anytime soon.  You are
> probably in no better position, but at least you should be aware that
> this would be useful.
>
> If I had a magical wand and six months of spare time, I would reserve a
> fairly large portion of virtual memory and add/remove physical pages to
> that range as desired.  That approach seems the cleanest and can easily
> scale from tiny to huge amounts of memory, on 64bit systems at least.
> Drawback is that we likely need some new infrastructure, hence the six
> months.

From this I infer you mean an effectively unbounded pool, or just
having a soft upper limit, right? That looks rather tricky.

I think an intermediate solution is the ability to resize the static pool.

FYI, we recently published a paper on the general sampling
memory-safety error detection idea and our results (that also
discusses KFENCE): https://arxiv.org/pdf/2311.09394.pdf

Looking at the problem space from a higher level, we're hoping that
Arm MTE and whatever the equivalent will be on x86 systems will be the
long-term solution to this. KASAN already has the required support
with CONFIG_KASAN_HW_TAGS (i.e. MTE-enabled KASAN). If you're running
arm64 servers, you may be in luck sooner than later.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNMpty5%2Bg76RLy5uZARZAfx%2BUzr%2Bz5uAKMp-om9__2O77Q%40mail.=
gmail.com.
