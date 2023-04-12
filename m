Return-Path: <kasan-dev+bncBCCMH5WKTMGRBMEF3OQQMGQECB4BGHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E33E6DF8C3
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Apr 2023 16:39:46 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id w184-20020a6382c1000000b0050bed8b0b61sf5007318pgd.11
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Apr 2023 07:39:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681310384; cv=pass;
        d=google.com; s=arc-20160816;
        b=vUQJIK1H6xIk1uBqKul/ElYN1eDRqQxjnjz9pLVq11IyI4H8vpMtr+/rPxtNR02mPz
         K1582i+o3jn5sJRqwb50LTauR2qaXRRkFP5k/lfW3OrDgXE14LBs9oxIsDbKe9P+gBdl
         KSmD4Gg0HaLOtddhyxNaogzNUFRF+KeiCzvB6RwIsRaAZVLr/68/5Jhi8ioNSNgVbq1U
         xF7v6JoanQhnud6gcsnMXAGRSjbz/ucnsK5QqD4ZdYAAL1Qbop6PE+sIRgxzN0ZLYl3f
         6TApP5rLqSULJUcOxSFms/U5d+kMDAzkE0q/y2WVbdcSVrfB0k5IEiPxs6Roz/RJV/DZ
         bSAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WqjMFKjoq03dvtcYqIZ46RTOdZHcbwrds/iYo54dSCU=;
        b=l24MRe81qQi/XFwxLE+kIgtTRATSTlmIK9shO6C+vebwk0VRGao1aDe1N+lrs7rZ91
         ZW7YTu3jgXx7v+uIf4xxWmj7CE7ttdiMTsyiPCv2G84Li6paMGf/Ddk3jW67Iag91xYH
         a9stZdp01hMKvwM/Q2oDB3YUubRWlymjNmBOqFp1YL3mSXD0z+yUQU85c2Y6H7EODyRU
         vvKu3rB0Equ0cy7L3bv3Og7XjQ+IV15A8xCVK2UXJuQgmMMMNBmwWxj1Y2S1+pqJ4wow
         N0iteWdZHEJui7/xYyyyTv/2sHkU7zuxn+h57MxLCqatllt4lBZ8v8w0ucPPnuW5pVog
         ikHQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=tz7PxQgn;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681310384; x=1683902384;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WqjMFKjoq03dvtcYqIZ46RTOdZHcbwrds/iYo54dSCU=;
        b=axXKWDDP0SicDrdPGucx2BU0sifJLkyqBZSib/rgFf4zPsSF5FvF0HoE77cqvAtUCs
         kF5zg/ARltsWN9hfHCpSQ1f2nQmTyGksWtFMRQzzglKGs5xeEWBMdTn3ExBxNTxYYP70
         Age153dcXLN+adRn/focdVMbksnREme2bQNxuJGqvm1M6/kolAc4F62Cpelx5ttueFz1
         7XBcgZuF28bzPoQrSb53vrUq6JBgsOxH25E65rWHMvm8X3s06ws7d3wFKCWQYMy2MSRy
         o87AYEeml172tMcRpTJ/vEtx5Rotfw9ofmXZHO4GrSN1weTVADilVLFCjYxKc1clA8Q9
         8ljw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1681310384; x=1683902384;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=WqjMFKjoq03dvtcYqIZ46RTOdZHcbwrds/iYo54dSCU=;
        b=dJEyuEdsV79oBSqGfI1m9nTHEiJsTDoxTMtva6lws645ElKomyZOZksxJEI+/VHqri
         OPcpBmrWreYLWhtgl1Pi2LgEZ3EBvWOiYW29odbpFnp4pLbNHN9m93WCigxJR8iUmwre
         r7Cz3Ja6S0HF9kcjRM6e/u5CsqNV1VSpvFEdIVx9B1ifcpF6c36ae9/fdCBlgwh2IRQt
         I9J6F2Z6cw2ZFz2E2FvseDJdICXIvSzrmLTZPQ4oZCQZwFvkWZfCQEjEhIysYoU8o9ks
         qJUZQFzM4v2N9iVo5k+VMMq9iu7bGCfS7u03BT5IU/M47/9AjOWFIQDMSnecansVroV0
         Sluw==
X-Gm-Message-State: AAQBX9ebaxq9HvHFIRx+22m5y6RV6gQDZD6TUat/jMwv5LiUIcP/ToNg
	O5ebxmgsss51SI+ca/ZmYRk=
X-Google-Smtp-Source: AKy350a84WJ5cTjWRfNQ6MAZnTB0w5rU4wZOUy+fI6y+xEyrzt2RrALE2nTsT3uGteLap63v44e3lg==
X-Received: by 2002:a63:5d49:0:b0:513:c7d:6ed3 with SMTP id o9-20020a635d49000000b005130c7d6ed3mr4472023pgm.4.1681310384221;
        Wed, 12 Apr 2023 07:39:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:f64b:0:b0:502:f46f:c79a with SMTP id u11-20020a63f64b000000b00502f46fc79als6891517pgj.3.-pod-prod-gmail;
 Wed, 12 Apr 2023 07:39:43 -0700 (PDT)
X-Received: by 2002:aa7:9f9b:0:b0:626:dc8:b004 with SMTP id z27-20020aa79f9b000000b006260dc8b004mr19235300pfr.26.1681310383456;
        Wed, 12 Apr 2023 07:39:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681310383; cv=none;
        d=google.com; s=arc-20160816;
        b=p8UAtrWm8W1PojZd9w0RDpTTkFjpanV4GQYazzniVhmV7bAtGj3MJWTopCgM3M1BEJ
         sdi14jtjRRaPq2fbpzG/FzdlY4UkMD9OrHM85Ib6eKW7FEfyzk9r8L+Gv3frF7BTAboo
         YyPss5RmMkvyKCWW2rjgrB9152xyoxaR/IO6MF+xTthMWjmljOHS8SHJw/TlvCSYGv37
         ++DUK9xe9qTN0oHQr0NMQL1AO+xGs0T0JTU6DaQHrBe8cZHJwoZDOH0MXq+MOPiuQG4K
         4n70evZT6/3bnWGgyACyEIVj/DUpVIW/qdCrTL1VRaYtpwjsMN+2cC/G8Fsf4tEFqmEZ
         KkSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=1pKFL1ied8XK1n0xf5sr2x4G8CCMOMqbda58ygnphsg=;
        b=HYApLvADgIH/jX0tvgMxNMbjI/MJQQsWxEHnLyxQyyOvglz6td0YdwhZM55Nnhir2H
         mCxMpkJSPpacIZMyZkY2QL3gnHUNSoPP7mrIce+H+kI8kfEr6PdmIqZj/CHkAApRDpZL
         +or82EkQ9MfI/dcbODSDsDnQWZkIYUf1KFkWkT8Ywgm/CmKcwiX8awRfTS7dm/WN99Gf
         LsgwgvjsvVf1d1P2BdNebFzeYMsevFTALp7HjZK6rwQwGMCwiN9WisWJZQUKOfp5QCyW
         TW9p3wlUuNYMAy6nQO8V+ME7fSir8HkeWiB/u2fhoiPbpTilQp90EBwj/JWNnqGq0c+V
         Ooww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=tz7PxQgn;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb31.google.com (mail-yb1-xb31.google.com. [2607:f8b0:4864:20::b31])
        by gmr-mx.google.com with ESMTPS id h2-20020a656382000000b00502ff5fbceasi1013585pgv.3.2023.04.12.07.39.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Apr 2023 07:39:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) client-ip=2607:f8b0:4864:20::b31;
Received: by mail-yb1-xb31.google.com with SMTP id q5so14776844ybk.7
        for <kasan-dev@googlegroups.com>; Wed, 12 Apr 2023 07:39:43 -0700 (PDT)
X-Received: by 2002:a25:ada1:0:b0:b67:412e:a81e with SMTP id
 z33-20020a25ada1000000b00b67412ea81emr16250857ybi.17.1681310382532; Wed, 12
 Apr 2023 07:39:42 -0700 (PDT)
MIME-Version: 1.0
References: <CANX2M5ZRrRA64k0hOif02TjmY9kbbO2aCBPyq79es34RXZ=cAw@mail.gmail.com>
In-Reply-To: <CANX2M5ZRrRA64k0hOif02TjmY9kbbO2aCBPyq79es34RXZ=cAw@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 12 Apr 2023 16:39:05 +0200
Message-ID: <CAG_fn=V57m0om5HUHHFOQr9R9TWHtfm4+jO96Smf+Q+XjRkxtQ@mail.gmail.com>
Subject: Re: Possible incorrect handling of fault injection inside KMSAN instrumentation
To: Dipanjan Das <mail.dipanjan.das@gmail.com>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, syzkaller <syzkaller@googlegroups.com>, 
	Marius Fleischer <fleischermarius@googlemail.com>, 
	Priyanka Bose <its.priyanka.bose@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=tz7PxQgn;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b31 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Sat, Apr 8, 2023 at 5:51=E2=80=AFPM Dipanjan Das <mail.dipanjan.das@gmai=
l.com> wrote:
>
> Hi,

Hi Dipanjan, thanks a lot for the elaborate analysis!


> kmsan's allocation of shadow or origin memory in
> kmsan_vmap_pages_range_noflush() fails silently due to fault injection
> (FI). KMSAN sort of =E2=80=9Cswallows=E2=80=9D the allocation failure, an=
d moves on.
> When either of them is later accessed while updating the metadata,
> there are no checks to test the validity of the respective pointers,
> which results in a page fault.

You are absolutely right.

> Our conclusions/Questions:
>
> - Should KMSAN fail silently? Probably not. Otherwise, the
> instrumentation always needs to check whether shadow/origin memory
> exists.

KMSAN shouldn't fail silently in any case.
kmsan_vmap_pages_range_noflush() used to have KMSAN_WARN_ON() to catch
such cases, but unfortunately I've failed to check the return values
of the kcalloc() calls.

> - Should KMSAN even be tested using fault injection? We are not sure.

At least our deployment of KMSAN on syzbot uses fault injection, so
having the two play well together is important.

> On one hand, the primary purpose of FI should be testing the
> application code. But also, inducing faults inside instrumentation
> clearly helps to find mistakes in that, too.

At first I had an idea of having a special GFP flag that prohibits
fault injections for the tool's allocations.
But this would just shift the allocations failures right, making them
harder to detect, because they will occur less often.
We'd better handle the failures properly instead.

> - What is a fix for this? Should a failure in the KMSAN
> instrumentation be propagated up so that the kernel allocator
> (vzalloc() in this case) can =E2=80=9Cpretend=E2=80=9D to fail, too?

Yes, I think so.
Here are two patches that fix the problem:
 - https://github.com/google/kmsan/commit/b793a6d5a1c1258326b0f53d6e3ac8aa3=
eeb3499
- for kmsan_vmap_pages_range_noflush();
 - https://github.com/google/kmsan/commit/cb9e33e0cd7ff735bc302ff69c02274f2=
4060cff
- for kmsan_ioremap_page_range()

Can you please try them out?

Alex

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DV57m0om5HUHHFOQr9R9TWHtfm4%2BjO96Smf%2BQ%2BXjRkxtQ%40mai=
l.gmail.com.
