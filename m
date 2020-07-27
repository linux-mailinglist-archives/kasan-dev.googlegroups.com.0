Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEVV7T4AKGQEQAPR6MY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D4C722F796
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Jul 2020 20:18:59 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id w81sf11976219ilk.23
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Jul 2020 11:18:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595873938; cv=pass;
        d=google.com; s=arc-20160816;
        b=txkdvEQf6qSO6ML1jEo40G0fO172HYKpX0rWWBjyv4cPCOJ+nlgNllCH90o9I6A3kZ
         drRrUM8C64Q2DWTsZT2MbtFy9ZcDrD0AVWmE+NGCUPqeJjd5AFxUZFOoDWbj54BBsa9D
         nxIFSH0xJlHpEoVkSMCw8k6DgDLqMOfk5gfIv+4Jfn0JmDRKRUrkrN2xiLriMN2oFKw6
         f280ZTPrv283SvBWhPhS/TVYwlKproRTxOb3HR/DoGvHxA/2sH9WpsWKSEokA7UYtNhc
         j8X06fJQePKtt1cL//Kv9jvUT9McTcbQ4vv5PtCYEMQmA7j/4uJJCY3h7kMSKcEEKVZi
         77rw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ccmNjoauNF6iycCKfgR+XY1LuOTf/v4qejKMzv48Qk8=;
        b=DwylB+MKDe5cby/wvv9ACXlzHJpaSPFw57xoBgqiAUOVkY78+2efXVT8YocZedfNe6
         T/B1Hg0Y7HJw0RpQc4tZaS2LzRLFrRIcnLJxjbMRzDWrYDZOa/vf8EMDQt3ZQq5CQJZp
         qbIgWGThEyuy0FHxTX3HtB4I5LsWHBo5OLnHKuRnLIEnLpznuhEjb36dYIO4ZT5pxFPX
         C33zYLv1nO61GQP+9zt3mtF3h+sompdZZcwUck1Z1HLUFpY5TMVcSQ9isY+ssF366Rrd
         kK2jjCXKVMoOTZ4cxXYVnpFXzxRDONsCQ7n9mC+Gn4RpdiCqTd88a2HNYagNOOWigyBz
         XPFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=v9jrZ9t6;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ccmNjoauNF6iycCKfgR+XY1LuOTf/v4qejKMzv48Qk8=;
        b=YB7cpe+kBqw86pE7TXaYi26M9u729lP/j03AsNocQdoJ60iVAOHC4nMcM5P2/Dn/wE
         nfDrBrJQq48gqzgtufmgtMMvQtSaMzywdW6Rga/NwUImysNPDFZOpFH2D13ZNKGCagHY
         fu6q9uSbLfO+HQgue2sxG7G9xgVtKM12drlmsfTfuQgQFtSK0KS29wc1/DcAWhMg04Wu
         q1L3H9h1UBopo+zimVk7PZ7DxG70lp+rnN6/MHUWYexJnl1zhuyhf4Vj0fUYfmd2p4aH
         fSbsuFAHtJdZWzW1JzQvaFB3tz1iO7tc3taZBZUKhWGWz0CMqvFDFb2zqCvwAPB97Shn
         L/bg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ccmNjoauNF6iycCKfgR+XY1LuOTf/v4qejKMzv48Qk8=;
        b=R2JxYZcCA2RVBQvLnmVBwMd8hTtRO49LELhtIxPKj/x7aWP+99MWNq6YbJjvT8a4Y/
         T5jxjt2nE0Y9zL0kMFFz73eNjdVIJz+yh4y/yaTJRJ8UT5741TQw3A0sSX/N/XqRlsrN
         6kwl9KJlRVQZhy9bU6Ro/6XWF/pUjd5N8HLU15UE3RVX/MfwRmUGk9SQcDaYaMOMUZvp
         bobK6Venk5Q51sz7KsdbVWdmr87Ph3GxJU7eABYlcpo/CyDRgJMP9rUk5P9jWKnlTpId
         boYaORLkDk8WFK6gUD8psbP9Af2TaCcJGXKRKZj9Rx3k96rDXDfUhZhNHX5Bt3iYyUZC
         8p4w==
X-Gm-Message-State: AOAM532dexWsCVulx3byB+AHOYGxywuqGpYxMkMfdXdsN1Yg1nyQogwq
	3kMmGwI+vejxCaHC8k96Fqw=
X-Google-Smtp-Source: ABdhPJwMyn72/NA1yrLnzlNTml7NOpuqb88i/ZiTVWBZ28wvgoTLVFzlpy6SoiRgBaVGaBoSFBNQgg==
X-Received: by 2002:a92:d812:: with SMTP id y18mr26270952ilm.286.1595873938265;
        Mon, 27 Jul 2020 11:18:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d651:: with SMTP id x17ls1080971ilp.4.gmail; Mon, 27 Jul
 2020 11:18:57 -0700 (PDT)
X-Received: by 2002:a92:41c9:: with SMTP id o192mr23429453ila.21.1595873937862;
        Mon, 27 Jul 2020 11:18:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595873937; cv=none;
        d=google.com; s=arc-20160816;
        b=ZWLN6mEM9QFXqKrhEN5eavaclvCyrLh2Dd5mCq+NwImhRHb3lUXaFyX/BMfvnezGFH
         F4DV16YTSUjsK3PP9FOzEZq8aOIOEKi9yivJi5tiE9+xXezMCb7fye2WQ2gu69+q7N/k
         y5w1tcw/LfgoLUFt92jjhWh5tFRGuxE94QRpN/TxJrds6i/CjAzFbTKyZBtskWE5Vk/n
         u6jp7nnRdmi7AcVr/l0xsa5L9R7kLAzcym0wv3rRI/yLYfHIjbd1rMse1ouhDfVUmVAL
         tXw+CtXpEdTEqZNnIZbMGUiHcj9uEkJFjp2RdIKJPqtevq8gFzHuVabOUKwaINp+uKbk
         ZEeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Doc7m3/cVBtXUCHj5Q9YGt6gCLdJXZGDI49O+QxUe3Y=;
        b=eH/Z31vcy+Jrdbgbd/sWqR+Hj8Y40QCkDlbdgWQKQk9PEep3ZqTWB5xALUAKWg28t+
         4PJBaecAr+TZl+KB4A4fCaQIcmZSBpWlDHW+5dspjkEhfEHwO3c9rDWAvdCEeGcyWXKX
         3juqryq6/WG0ZvLwp03gypDIEF1pnvCM+aShsxif/NWisKggJttb29R6kjBVwIXdhMNd
         AdYYshBWZ1F4Pe8EQYhNx+KUZq8yu84H8beU8c+/dvOQzpjibf2Auabus8Nny4lxxf6O
         XlySHA4xPKlXy9cCY5wmH61qV9kgIOC96b4GQZVuOPom8iYQv1xSBXqhZgXBW8kwEN1W
         XqvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=v9jrZ9t6;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id t7si763120ilh.2.2020.07.27.11.18.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 27 Jul 2020 11:18:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id s144so5209197oie.3
        for <kasan-dev@googlegroups.com>; Mon, 27 Jul 2020 11:18:57 -0700 (PDT)
X-Received: by 2002:aca:d4d5:: with SMTP id l204mr511005oig.70.1595873937242;
 Mon, 27 Jul 2020 11:18:57 -0700 (PDT)
MIME-Version: 1.0
References: <CACT4Y+aAicvQ1FYyOVbhJy62F4U6R_PXr+myNghFh8PZixfYLQ@mail.gmail.com>
 <CANpmjNOx7fuLLBasdEgnOCJepeufY4zo_FijsoSg0hfVgN7Ong@mail.gmail.com>
 <002801d58271$f5d01db0$e1705910$@codeaurora.org> <CANpmjNPVK00wsrpcVPFjudpqE-4-AVnZY0Pk-WMXTtqZTMXoOw@mail.gmail.com>
 <CANpmjNM9RhZ_V7vPBLp146m_JRqajeHgRT3h3gSBz3OH4Ya_Yg@mail.gmail.com>
 <000801d656bb$64aada40$2e008ec0$@codeaurora.org> <CANpmjNMEtocM7f1UG6OFTmAudcFJaa22WTc7aM=YGYn6SMY6HQ@mail.gmail.com>
 <20200710135747.GA29727@C02TD0UTHF1T.local> <CANpmjNNPL65y23Qz3pHHqqdQrkK6CqTDSsD+zO_3C0P0xjYXYw@mail.gmail.com>
 <20200710175300.GA31697@C02TD0UTHF1T.local> <20200727175854.GC68855@C02TD0UTHF1T.local>
In-Reply-To: <20200727175854.GC68855@C02TD0UTHF1T.local>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 27 Jul 2020 20:18:45 +0200
Message-ID: <CANpmjNOtVskyAh2Bi=iCBXJW6GOQWxXpGmMj9T8Q7qGB7Fm_Ag@mail.gmail.com>
Subject: Re: KCSAN Support on ARM64 Kernel
To: Mark Rutland <mark.rutland@arm.com>
Cc: sgrover@codeaurora.org, Will Deacon <will@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=v9jrZ9t6;       spf=pass
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

On Mon, 27 Jul 2020 at 19:58, Mark Rutland <mark.rutland@arm.com> wrote:
>
> On Fri, Jul 10, 2020 at 06:53:09PM +0100, Mark Rutland wrote:
> > On Fri, Jul 10, 2020 at 05:12:02PM +0200, Marco Elver wrote:
> > > On Fri, 10 Jul 2020 at 15:57, Mark Rutland <mark.rutland@arm.com> wrote:
> > > > As a heads-up, since KCSAN now requires clang 11, I was waiting for the
> > > > release before sending the arm64 patch. I'd wanted to stress the result
> > > > locally with my arm64 Syzkaller instsance etc before sending it out, and
> > > > didn't fancy doing that from a locally-built clang on an arbitrary
> > > > commit.
> > > >
> > > > If you think there'sa a sufficiently stable clang commit to test from,
> > > > I'm happy to give that a go.
> > >
> > > Thanks, Mark. LLVM/Clang is usually quite stable even the pre-release
> > > (famous last words ;-)). We've been using LLVM commit
> > > ca2dcbd030eadbf0aa9b660efe864ff08af6e18b
> > > (https://github.com/llvm/llvm-project/commit/ca2dcbd030eadbf0aa9b660efe864ff08af6e18b).
>
> > Regardless of whether the kernel has BTI and BTI_KERNEL selected it
> > doesn't produce any console output, but that may be something I need to
> > fix up and I haven't tried to debug it yet.
>
> I had the chance to dig into this, and the issue was that some
> instrumented code runs before we set up the per-cpu offset for the boot
> CPU, and this ended up causing a recursive fault.
>
> I have a preparatory patch to address that by changing the way we set up
> the offset.
>
> > For now I've pushed out my rebased (and currently broken) patch to my
> > arm64/kcsan-new branch:
> >
> > git://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git arm64/kcsan-new
>
> I've pushed out an updated branch with the preparatory patch, rebased
> atop today's arm64 for-next/core branch. Note that due to the BTI issue
> with generated functions this is still broken, and I won't be sending
> this for review until that's fixed in clang.

Great, thank you! Let's see which one comes first: BTI getting fixed
with Clang; or mainlining GCC support [1] and having GCC 11 released.
:-)

[1] https://lore.kernel.org/lkml/20200714173252.GA32057@paulmck-ThinkPad-P72/

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOtVskyAh2Bi%3DiCBXJW6GOQWxXpGmMj9T8Q7qGB7Fm_Ag%40mail.gmail.com.
