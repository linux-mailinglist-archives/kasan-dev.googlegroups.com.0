Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEXQ5X6QKGQEHSQSPTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id 438F52C01AF
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 09:51:32 +0100 (CET)
Received: by mail-qk1-x73d.google.com with SMTP id v134sf14103619qka.19
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 00:51:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606121491; cv=pass;
        d=google.com; s=arc-20160816;
        b=huWc7eN0ss6Lvo6WbAGYJyYJQwyYOoutdvmXJW9LAgdDl9uefpSvnVuSeGOAYJ6Ywl
         TVDZTPFzGt2TshUt45CWiTw7seiZUf2y9iYwqHYfi8t7MqPfiUyEeRCeor/Wze+OWMFA
         agjiRcG3uGwxoS5Vi0yoEIZ6LNBilDHBD70W4gCkxUwtmeglJgSwZ++7CmSQIsxO3Hcg
         nWPceVgdgO+lBtqK4QxVnqMF/BNWfMUpSpBv8KvqC28uLsUyVmErPAc8w2sATYNoD5a3
         zPuvMdX5ykkKu4BwHIXkWhQsVVhtkJ19Mxb+aASsGxj1hwd+y7aUngx6kEb+unmPs3H5
         ZGbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yun0lV5NEq2DfleFEIogc7TBMJY3j8Pvmqit9gdNya4=;
        b=Li9fQprWqleUVKX4qKgS26kf2fvan9clhLCQDsU8z/O6k50PLn+oOxY8sxbH8GrvKX
         GSU6rGPHmBMaUWw2PohzEz71IXJnHhe2CfuVKbRJIv4z3ptFj9URZD6f7CxB7/lNPluc
         XgPlyeoRp/rMgSNEPRAxuDNNRqZVj6MAGwxbkE1ETBT2djvvk2YhMCFD9WRALEKNH8dG
         r9K7jQaU2GiI20J8yrzSeKoeROv+TToRhytFIUH88tWdYgQSmDHfw6YCMcq0jAeuSNnm
         4W3Y47tyruEMyTGPhWwWg16sdmFl9fq1YR+GdT/fenagR/XL0sNouCJ84f5HHWzwXGrd
         sALQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dKKPSkGT;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=yun0lV5NEq2DfleFEIogc7TBMJY3j8Pvmqit9gdNya4=;
        b=cyZdhC2VJ+ynGn9QYLP2X4cRidAn5g3xuAAqqckcY4R5gWKoRrnImQhkjNXDleKgzh
         cPIztJjfnUam0EigvV6TWgTZor/m1p0mDupFckh3/wRvMztW19Ze5d/RSIE7In0XPmoK
         kEG1MQwhLBmHeAhlhnkDrKE8IChaAluWbjdAUC6BNGr3/ZVfexzV0q9LEXwZtPXvwDP0
         4zdd7YX62boS279rBzD9IK2OcpRQlaMAae9F1K55BJsk1QEaJsHnRzHWh6nMoizPDQR5
         bc0pr3CNQm5PypLQmfEvcf+fBF8TA2DJ4uMPP8sjIpsrgi7WyVeT0UXVaNdbRcLEte4O
         UrXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yun0lV5NEq2DfleFEIogc7TBMJY3j8Pvmqit9gdNya4=;
        b=M69g9EFuuA3P9mXsUqjz/9xUtFZgrjBOe7mTWhmHBveI4BdGWuxbZm3uludPJjdDeN
         +pHFS/lXh/GZOilswZWA9hmZNpYzTMYurqyJs7webdBwhWrPZsWDzz2RCn/KMVcdhHYM
         1bNL7tdKRDgHtFOEgpoxGGeSCrbXMwFryPbNfw08arsBlPVKyy8IaFu6ZB18jUWm17s2
         6PIj5q+47A/NqaHesKzMst7lWmJCaQ4u32sCEsmOliKVD5MAIxDCtRyqEl6zJ29tUPVz
         Ah4RqDEW814X6aQMa/418DSuB21XwHeKC0hCo/fWfqSMkdU+t8AGaktgEs+tcl04XAPN
         frJw==
X-Gm-Message-State: AOAM531yRtFQjejQbTWTUT2jxIZHzxYqdmOJB2qBuHt0nwDd3SGEjKwM
	zmybQUqgeDBzPyCl8ulwplw=
X-Google-Smtp-Source: ABdhPJxBTGVu2A5N4wTlsD11mS0L1Qcd41map2ILJSLu5obbEZnTp/u0RCz1zgbtPjUnUfUSoPdHPw==
X-Received: by 2002:a0c:a8c4:: with SMTP id h4mr27987292qvc.58.1606121490924;
        Mon, 23 Nov 2020 00:51:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:6717:: with SMTP id e23ls2055785qtp.7.gmail; Mon, 23 Nov
 2020 00:51:30 -0800 (PST)
X-Received: by 2002:ac8:543:: with SMTP id c3mr1456882qth.9.1606121490438;
        Mon, 23 Nov 2020 00:51:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606121490; cv=none;
        d=google.com; s=arc-20160816;
        b=TBq2hfLOEIM89GgT2c47LqWai0CLYOES3ADK3M2JarXiMxPunJxGEfN/4GZSUMgU4d
         j/71BzeAyGtVOzFf0J9qnT+8h87IEI7gAlZRtgOBl3BmwR030M9Qtwi5oSW7D+ek584P
         YJqsooVv3iBVpefGAq6KcdoMCr7naLHwCHWfhQeHIh3738D2IyIxcxK83DldZm7dNid0
         llt3YTuBlGsMGI+yZAwHxaS2ldvT/GbGW6H512fCI4OLw6+1Nz9iSUuXnE3llijcCZjI
         BgcMig6vSkkha//uM1a7AQxUG4dzJHb1d/mAwJ0U6ZHRmavYK/k61s+s10AFPXc85qWj
         OKAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=vxWUjkIjY0SGGG2ytBKC057yoee9Wp9HxgbBFW6Dh4A=;
        b=jp12aYIThn5gU4EUdYQLcN6iMS8n+y+2hPXjXenWufBHN2+kusX7CVFWO/6T6cmP56
         KAvlBDR/FrkWpN9YFRH/e1aBiW+STVeN95e+2ScB1jqjZfHrSwdjkxvxwPGDK1mO7Sbh
         xpoDSJkqijUp3/gYn9T/9U40mO2pfsQXt6MtzeAoskp/gU1GZ1ngT4L8P9rdFSCHhOPb
         ekhS/gOTvGuuV4y8EMhScfg2ln6O1Tcr8MP8HxDNmTNEl11Xx+2zQNSeeKe/V2vIFRjz
         PmSXRmG703HAQfOD4q6eVnkl7Ka66cWiguXEcegGPlC9+lQvxyVFE86nOtuLysRptkaD
         t1CQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dKKPSkGT;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x243.google.com (mail-oi1-x243.google.com. [2607:f8b0:4864:20::243])
        by gmr-mx.google.com with ESMTPS id c19si300025qkl.3.2020.11.23.00.51.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 00:51:30 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) client-ip=2607:f8b0:4864:20::243;
Received: by mail-oi1-x243.google.com with SMTP id a130so10778112oif.7
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 00:51:30 -0800 (PST)
X-Received: by 2002:aca:a988:: with SMTP id s130mr14473777oie.172.1606121489748;
 Mon, 23 Nov 2020 00:51:29 -0800 (PST)
MIME-Version: 1.0
References: <f4a62280-43f5-468b-94c4-fdda826d28d0n@googlegroups.com>
 <CANpmjNPsjXqDQLkeBb2Ap7j8rbrDwRHeuGPyzXXQ++Qxe4A=7A@mail.gmail.com> <8b89f21f-e3e9-4344-92d3-580d2f0f2860n@googlegroups.com>
In-Reply-To: <8b89f21f-e3e9-4344-92d3-580d2f0f2860n@googlegroups.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 23 Nov 2020 09:51:18 +0100
Message-ID: <CANpmjNPm3U=aeuhv4CpqsxbkQj8SnKbauLmXyAu2b=8bCEg6pQ@mail.gmail.com>
Subject: Re: Any guidance to port KCSAN to previous Linux Kernel versions?
To: "mudongl...@gmail.com" <mudongliangabcd@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=dKKPSkGT;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as
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

On Mon, 23 Nov 2020 at 04:18, mudongl...@gmail.com
<mudongliangabcd@gmail.com> wrote:
>
>
>
> On Wednesday, November 18, 2020 at 6:05:45 PM UTC+8 el...@google.com wrot=
e:
>>
>> On Wed, 18 Nov 2020 at 08:09, mudongl...@gmail.com
>> <mudongl...@gmail.com> wrote:
>> >
>> > Hello all,
>> >
>> > I am writing to ask for some guidance to port KCSAN to some LTS kernel=
 versions. As KCSAN is already merged into upstream and works well to catch=
 some bugs in some kernel trees, it is good idea to port KCSAN to some prev=
ious Linux Kernel version. On one hand, it is good for bug detection in LTS=
 kernel; On the other hand, it is good to diagnose some kernel crashes caus=
ed by data race.
>> >
>> > Thanks in advance.
>> >
>> > Dongliang Mu
>>
>> There have been major changes to READ_ONCE()/WRITE_ONCE() in Linux 5.8
>> which make backporting non-trivial since those changes would have to
>> be backported, too. Your best bet might be looking at the version of
>> KCSAN at 50a19ad4b1ec: git log v5.7-rc7..50a19ad4b1ec -- but that is
>> missing some important changes, and I question the value in
>> backporting.
>
>
> Thanks for your explanation. That's helpful.
>
> Let's imagine a scenario: KASAN detects a UAF crash in an old Linux kerne=
l(e.g., 5.4, 4.19), but the underlying reason for this crash behavior is da=
ta racing from two different threads with plain accesses(without READ_ONCE/=
WRITE_ONCE).
> What I want is to backport KCSAN and test whether it could catch the unde=
rlying data race before triggering the further UAF crash. This would help u=
s identify the underlying issue(two concurrent threads and the object for d=
ata race) and fix the bug completely.

For debugging such issues, I'd run with a more aggressive KCSAN config
(regardless of kernel version):

CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY=3Dn
CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC=3Dn

and lower 'kcsan.skip_watch=3D' boot parameter from default of 4000 down
to ~500 in decrements of 500 and stop when the system becomes too
slow.

> Therefore, if I try to backport KCSAN and test whether KCSAN catches this=
 special data race, is it still too complicated or need non-trivial efforts=
?

See if 'git cherry-pick v5.7-rc7..50a19ad4b1ec' works.

>> In particular, we have the following problem: The kernel still has
>> (and before 5.5 it was worse) numerous very frequent data races that
>> are -- with current compilers and architectures -- seemingly benign,
>> or failure due to them is unlikely. The emphasis here should be on
>> _very frequent data races_, because we know there are infrequent data
>> races that are potentially harmful. But, unfortunately we're still
>> suffering from a "find the needle in the haystack problem" here. Which
>> means a backport isn't going to be too helpful right now because we'd
>> only like to tackle this problem for mainline right now. A better
>> approach is to backport fixes as required.
>>
>> We are slowly working on addressing these problems, the most
>> straightforward approach would be to mark intentional data races and
>> fix other issues, but that isn't trivial because there are so many and
>> each needs to be carefully analyzed.
>>
>> I recommend reading https://lwn.net/Articles/816854/ .
>>
>> Thanks,
>> -- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNPm3U%3Daeuhv4CpqsxbkQj8SnKbauLmXyAu2b%3D8bCEg6pQ%40mail.gm=
ail.com.
