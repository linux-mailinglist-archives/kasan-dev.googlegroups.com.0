Return-Path: <kasan-dev+bncBC7OBJGL2MHBBA553L3AKGQE4AQ77JY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A2481EC210
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jun 2020 20:46:28 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id l26sf9947525qtr.14
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jun 2020 11:46:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591123587; cv=pass;
        d=google.com; s=arc-20160816;
        b=VTN4XydunBOZi6fLcFOqSI18LXFXZrcaYE7BZEZxhAycc/eLZyCuwHVu6bouRIqHcj
         07RBDqQTg1h1A/FvdebZG+bWR1F7vbRgT2AMaZiYwOTYsBZEOB9sLbUQ67IjPNgsjUbA
         pr4NH0biGP8gfYnLeKpRKaEpoi9yjKsEIOUXvDJoudWmLCd5Q3NuZ+OQJqZXMftgnADo
         xvh0+OKsvT+EXMA1BD1htVvy6Va4s2GYbGQr9FnqORU5rrn3mgH5yOK/mxbyB8M1VOXF
         BqSk4myflkEn0wyhEayo7veCIxnRwDLzp2UFobv/6F8BimHioFpywt1uFPhcP/4zcOXV
         bexg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=N5y7UpWM2tQEF65vGT7DTEISDVVuViAX88DPGzShI/k=;
        b=o8txoy+9/NSUdNfRNn2pNm/7oXZ6UL1h6HjmvK34/fCmWbZqu92wPzxfnGg0bQAkJJ
         qDeLtsFJBZs8uEfgcHvZWEKKTAjefhZPivbtkXENrqa1upMqTdHuomlH8Wl8Qy4K3DJd
         BaFg1MrZCfQDZLu0Z8HjspBnt5IAHz3diSv0r+0o73qqBuJFUsoFDKX/2118cccg0hPZ
         WZDXVdvulpb3OHwgqPsWAxLmdKcT5uF482ZJ9XKA82rg5t3968EFp1zxOjdbIxVYl/n/
         2F4f6kIrulp2kqy8u1IC7jhFQlk8ULfSZcGS4Qt9A02O3KmrQRv2T4S+SoyXe5cRVbnK
         jnmQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=C77CODst;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=N5y7UpWM2tQEF65vGT7DTEISDVVuViAX88DPGzShI/k=;
        b=NQ2QahGNNYZ4DWCem4H62nUQlkX4ZKWoVbCA3XKe4cDDf+K/C9q584MwXmnyOHaJH5
         ccM0TkIOPj9QNjC80WwK7gu1E6QWwm4uGdtTbAru+rdzii3eoKBWTZoAAo3fW5ZNsIxr
         rDD8IK8oC6MdC1Iw0+vpNSpa3o3bOxuKgcBTs1oCQ1VKZEd6/BuiVj/RzmjEJXcj0O0w
         N+R63to/JOxHSutadRKJmOd7OCbaXEDZBWDXcU7WFSSvTFcaKvgJeC5JgyrplBGmOWVB
         kfgUH/v+IOBfyQ3ZFS+qGfArCdUiGP3QTscJaTYXtjMMTe+wM40B3E4RCKqYWgm2dwTh
         Nd/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=N5y7UpWM2tQEF65vGT7DTEISDVVuViAX88DPGzShI/k=;
        b=M288HJ8E7NjlUxVVPT/ekv75J1ybpBk+ryYQ8LKwWtMSBR/rXQek7mya85CXnERjYW
         BX9Iqfo2HEanDF/FIgg7tr7KRMjixncqVq4B7tpzhLGdqs10Pu4D1F3aSTHBnOry1eU7
         xmX/NzH54vMQPpxKEUGsBs7H4mdEj3boXPYZheevgi1CLfXms+SkV95MzOtr0BbQAlwZ
         G/0VS/1PZP+Sj0J8whuznxEV7zSMU077N68+bgcKkfvLGK3LCSkRluGNVvnptBSAWY+f
         xiPLCYxJ6dFdZtFw8esYy8pqT1DoCXM5owgxFh4QrOKMIXq2z7KPusfXWzIBeC1yDCEr
         M6pg==
X-Gm-Message-State: AOAM533Yld6dZlerTZtb43A890e/2ip69y4rupOI6iu0n8u9XFjQ+ca3
	RJbvCWNR//AGDTMj7POGvsc=
X-Google-Smtp-Source: ABdhPJw8mrNIJA6coV3/pWYupe8k7CMIbDJP/3+dzCxr+yWsg9eD+6PEPFbzOScgBaj1Xng85MsD7A==
X-Received: by 2002:a37:4f97:: with SMTP id d145mr26851016qkb.191.1591123587535;
        Tue, 02 Jun 2020 11:46:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:6654:: with SMTP id a81ls9067070qkc.7.gmail; Tue, 02 Jun
 2020 11:46:27 -0700 (PDT)
X-Received: by 2002:ae9:eb44:: with SMTP id b65mr24734596qkg.403.1591123587138;
        Tue, 02 Jun 2020 11:46:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591123587; cv=none;
        d=google.com; s=arc-20160816;
        b=u8rK0vnMCQBvkTSIiVcMEHGCpf+BehWwUgfthz58M9hiLuuB2vEYfl+ARhf1JUl8t7
         KY/LK4ekPiBDXjg/u2vJYgBDmcqU7ZsLCsXjw3WLUVW5iJsS491xh3vP+Unpfz1DlUBq
         RsG7SDdtpJ8hlhWxw1pMDQRbJQhN7i83hqcgwDTwX/nH1+gfP7h6lDyPrqPIXDwekxaf
         bmumjts+8UUaWOc/KJP2oX/WI7Ffbgdabkopg40amvnWdfteYAozFmyJ5aintWroDUHp
         UzRVBcsLzVEELYeHvtLw606DjW8/84a5bl7bTFXa/ezIL+Twfo5li3MDQzaB1E31QrXB
         FtmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4hl9GTMfiZFweYcD3SG7WaF/Uh/wZehheCxG9u8jMv4=;
        b=d9vH2TkPLggFD37XGk7F2HA/W7SnXvUrIiMmoCjbESl39nlfLi+Rp86uv0cl6Z2QRk
         oQGyXcN/gdg4fkusSXl7YGLIjyYm7Fg68rFnW/uFWHKqL+AOt7afJvwEjQuJ4U3KV8jG
         QOFLXZ6KZfy1Aq1SlTE21ArjdtilQlRaXL+RcSkLfCwu67SwxjorGoaQgJtsIpKMGYRq
         6PS1hVPSpvCcyHymtM5RQa4W+fKzE+r0Bp3mJ2NvX3uGagZxcOa4D/9MkH6qDHhkUOM8
         Nqwe51CNtv2igOqItJ0QXhLuo9rYEResFQQP3uxL3sBaZcgnPq27GvtMCDG6lZ89RpF7
         teAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=C77CODst;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id x74si133288qka.4.2020.06.02.11.46.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Jun 2020 11:46:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id b3so12908425oib.13
        for <kasan-dev@googlegroups.com>; Tue, 02 Jun 2020 11:46:27 -0700 (PDT)
X-Received: by 2002:a05:6808:3ac:: with SMTP id n12mr2284273oie.172.1591123586643;
 Tue, 02 Jun 2020 11:46:26 -0700 (PDT)
MIME-Version: 1.0
References: <20200602173103.931412766@infradead.org>
In-Reply-To: <20200602173103.931412766@infradead.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Jun 2020 20:46:15 +0200
Message-ID: <CANpmjNP20SZH+ORhmSGdv=96FaJPOYfH1pEYRtgBGs2U=cOcsQ@mail.gmail.com>
Subject: Re: [PATCH 0/3] KCSAN cleanups and noinstr
To: Peter Zijlstra <peterz@infradead.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"Paul E. McKenney" <paulmck@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=C77CODst;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as
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

On Tue, 2 Jun 2020 at 19:34, Peter Zijlstra <peterz@infradead.org> wrote:
>
> Hi all,
>
> Here's two KCSAN cleanups and the required noinstr change for x86.

Thank you!

Reviewed-by: Marco Elver <elver@google.com>

As promised, here are the patches that would take care of KASAN and
UBSAN, rebased on the patches here:
https://lkml.kernel.org/r/20200602184409.22142-1-elver@google.com

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP20SZH%2BORhmSGdv%3D96FaJPOYfH1pEYRtgBGs2U%3DcOcsQ%40mail.gmail.com.
