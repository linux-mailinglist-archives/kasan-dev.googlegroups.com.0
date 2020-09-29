Return-Path: <kasan-dev+bncBC7OBJGL2MHBBP66ZX5QKGQE7C5YD6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 43F2327D481
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 19:30:41 +0200 (CEST)
Received: by mail-io1-xd3d.google.com with SMTP id f8sf3428313iow.7
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 10:30:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601400640; cv=pass;
        d=google.com; s=arc-20160816;
        b=cKxLqpmFXa3D/Ff7HIUUZ3BMJWwAhdHu0XSe5kg1OSv17Ii5PqI0trGTBZLdiL/3PA
         PV5/W/KferTMO066WTxgT1ZlQrdSuv5o3tLrNyu5uCtRdSeUMjSOMSb0Nyu/3eP93qx2
         YmWG3SQMRAreh66ZPPxLKt8mETVDuyjcwjixrtzncjYL7zI677fNbAH4qE+A5Arlx7Qg
         AYwWHPkMpkRALD42b1J3nDn29zrFzPrHtAxkhBdexfEGUlQD2wkgt4Gz/I48Ujs2T0DB
         AeRBlV0u+5kGKy7NPrIZq1Kis5PiofsAGC40+aPu5rAmy2T6iFjcrLM0sSgWsrhvafPU
         KqXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=YC73WHhcSFbO+j4ydXq8CgVqpzNzVMBujRbF9ib03J8=;
        b=rkhLaKoon4H+PpLxuJNiAYGzpccOCtfMqjBJRFo5HbOmCEWVQjyc9iSlRjU1npeqoC
         VVGJ8/iX/Li/jle92TDleRxE0VaoE1V/Jq6LF7tagOqy8K99zo859p+xYm8VgsJdO2Ri
         sUG3cAYc2j/bDxzqqmIaLOXuddpev+0JnKCzc06rjUTi/BGuDoRzSfHPJzwWqzUVOqrv
         4vLfKRWRYY8WNG0rOwbgFTZ8YXf7b0utCAQoCxTHiWwjCfl3JfL246Fpx5hVqoF0Yvw2
         Gud+cvF6UejQzHC+qdsT1D06ncbtunllVRHdYdJ9OVNzi7mgFYeFB4gJPpZ1/hsWz8L6
         HR1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZCQin60X;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YC73WHhcSFbO+j4ydXq8CgVqpzNzVMBujRbF9ib03J8=;
        b=qtT3j+pqKRLK6Qo5vLFt5mjpGGZf8japYpYfc9183y+lnu7chjTitgghXp5dmZpZM9
         ERAHZjtG+fl4JP6Y4F9Zm/qE7N7fgsp6n0zWjUQi9NtQ/6Uxk0CP8irbS8al9DQ61NXi
         8kAPhnqCATIn/4E9nXRSP/JF1o82iDS60aDgn7KSRCvbFoFx4GUmAUe7Dtm48Gq3cxmX
         jXRXHp5FTPIxczfL+q5MYF1ldVzMNH2QfpiGJycm9DkppH1uC5auJ5jFcLaA5oyr5Vau
         Cg7FGhl6t/JlRPl0/OpS5YwM0QS7QJCMSTxjhhLeJKRE3G9cau5sRUdhbOEHXJJ4M0Z5
         3TDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YC73WHhcSFbO+j4ydXq8CgVqpzNzVMBujRbF9ib03J8=;
        b=TtPShtTeGN5gkmuorGhhVeYtWjH9eJQJE1rohL3y9AQWRM5BarjwDJfb5gRLN7LHnB
         ljq7RJghfkOiQTTiMeGW6AaWflSRWJYbVtj7QwlJw5dLJh4vK81mtOus+5VTtLutt+Rx
         XV0nX8zs8ksWdgYtGdlj+1s2NMtQ0S/hk/lR8B1aYbaKJgc0LXy2/BEHUkeIxW0vc//f
         NXCu4pOLugqxCAD2u8xgS18qMEc0OtU7K/Dou98Lp0IJXqp2wSL21k0uL1jJjT7+EzNq
         F/Kz5aNTccDQzfcskbxSRDP881boqi70UU1/EFAJJxXCyeKtdufYrg1+8yqC9Evn+uQZ
         i4dQ==
X-Gm-Message-State: AOAM531ULUoyniIwMwq0LZ82Eoeb8+Cdc19o7eFjOy45Fm2OQbAyB1bW
	5sEoMDPEr16fk1rUcQDHCCk=
X-Google-Smtp-Source: ABdhPJxwHBcF4AXJbSynYBynmVrtGIhXPjp3YuF2LzcpdOs67ebfW7Xngrp3VypVFzEyr0IPGs2vSQ==
X-Received: by 2002:a92:2904:: with SMTP id l4mr4231157ilg.197.1601400640039;
        Tue, 29 Sep 2020 10:30:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c805:: with SMTP id v5ls1506204iln.1.gmail; Tue, 29 Sep
 2020 10:30:39 -0700 (PDT)
X-Received: by 2002:a05:6e02:13a2:: with SMTP id h2mr2792880ilo.271.1601400639580;
        Tue, 29 Sep 2020 10:30:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601400639; cv=none;
        d=google.com; s=arc-20160816;
        b=s6Bm15fKoSHvZHghh6U+qzioeoXJANKLPkp9DNh9pOiGz+8MpwTyBlpg2fctMDiTAX
         NPM7fRqKG58tUDbEJrNjPJfCPVNcucGjKXdzVjd9qV1FTlzWdbw1sNHwPTJywXd4SZDA
         mYuG0Rjlqqp+lLFQn8HkTPIfCQaqf9LdMUVMfX8O5NI5MX/TRD4A0euozpW3/aj2velY
         lFEJtcVlizZZvahj27HwQi0QT2pOOEHa8B05EVfHKsNxJZ01szFnmAIU5rxKACi+fRrj
         qMDilmrVysg+Uw07PfcIdVdDjqjRkQNxWuaMUrTK/7yT3b8xKMlNJPhRj9Pl3TzdrBO0
         wkiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fuZO8tp7RlJzrPhnTOl1nFXMWo7xTR576Xmf51kX0Yc=;
        b=s7YhXIUpoXWn6864WGLWZ50KBhVSftr7IPdFTo2FmKWICfm1xysPQinUAqb7D78pmq
         uf0PvFdxq4Pm7ZS/H0DNZY7QzWLIehITi8mRGLC342WQyLtjmXwB4tl5BnGp2niYt1wt
         Rp0WROYC/nJg2tR656bGWbo58BiZF/1bZAYTq8fNcbs6lK5MsCQXFrULYiiq9v+d8BO2
         oFIwl+8GnOWBfbWsUBSduggd2NgK0KXzKXqEY/UzXFcee5cVbeBdLxVoj5TGjcdtFYoe
         QOi8wl0EavKfe+dKx4KeIvGVaTdFNcYBCdlwiy9iMpNmaw1ZI04XaH++gX76eQFSVPvU
         49LQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZCQin60X;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x341.google.com (mail-ot1-x341.google.com. [2607:f8b0:4864:20::341])
        by gmr-mx.google.com with ESMTPS id e1si464193ilm.0.2020.09.29.10.30.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Sep 2020 10:30:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) client-ip=2607:f8b0:4864:20::341;
Received: by mail-ot1-x341.google.com with SMTP id 95so5194491ota.13
        for <kasan-dev@googlegroups.com>; Tue, 29 Sep 2020 10:30:39 -0700 (PDT)
X-Received: by 2002:a9d:66a:: with SMTP id 97mr3663143otn.233.1601400638921;
 Tue, 29 Sep 2020 10:30:38 -0700 (PDT)
MIME-Version: 1.0
References: <644ba54f-20b5-5864-9c1b-e273c637834c@gmail.com>
In-Reply-To: <644ba54f-20b5-5864-9c1b-e273c637834c@gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 29 Sep 2020 19:30:27 +0200
Message-ID: <CANpmjNNBGjjJyv+6QZm9hm=vQ3vHuAOTRYDs-T25X91AQxxyyw@mail.gmail.com>
Subject: Re: [v4,01/11] mm: add Kernel Electric-Fence infrastructure
To: Andy Lavr <andy.lavr@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ZCQin60X;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as
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

[+Cc kasan-dev, Alexander]

On Tue, 29 Sep 2020 at 19:22, Andy Lavr <andy.lavr@gmail.com> wrote:
>
> Hey,
>
>
> https://lore.kernel.org/patchwork/patch/1314588/
>
> https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=6ba0efa46047936afa81460489cfd24bc95dd863
>
>
> And how will this work together?

KFENCE is for heap memory only. We do not touch the stack or rely on
any of the features mentioned in that commit.

Or was it something else?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNBGjjJyv%2B6QZm9hm%3DvQ3vHuAOTRYDs-T25X91AQxxyyw%40mail.gmail.com.
