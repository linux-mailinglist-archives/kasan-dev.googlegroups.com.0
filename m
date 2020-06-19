Return-Path: <kasan-dev+bncBD66N3MZ6ALRBNHCWL3QKGQEYWQD2FQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id E09F72008C7
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Jun 2020 14:36:05 +0200 (CEST)
Received: by mail-io1-xd40.google.com with SMTP id x2sf6634904iof.0
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Jun 2020 05:36:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592570164; cv=pass;
        d=google.com; s=arc-20160816;
        b=pSaXDrSVtxQeKAmMgI5pn+3RQhxjTYQFoBx/YO3EPiH9sxGOjg6PwMfYwm0LnByJgC
         hkIDpNzWMyvhs3fwAfTuaR/H+Yo+T4K4I0cnSRKa5TSDuqO2n0dBnC3AWYI5jCh7t0Os
         xJGXhuB5pAUc4wGR0kFEOczNMcGKTZLseRQpe8S2a/TdUvzpaDA7IYPX3DmFue7Ji8KR
         ULc67xJXBuCAWgvPdSHp7mj6EINMXWFKQvepoFwLUJ0XuY9Hf5fUatlknEu1Z/oI8M4m
         jnc3v/C4erwVRLODM3ZggQZna03UAXRwsMV/EBkz075war80drHJ0fBlsxL27LJDRqRG
         bW2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=Gjbz3uqcTTXmEYw3KVvfLSn5bXuKz+Pe/nobih919uQ=;
        b=vsBuZoaXTgOtGh9ZkZCLHqhrmoi0snvBjv5aRTtGbzZ9OpxkesBoNrJ0yDE2cW6nPS
         s4lBryhYOHZFo/jlQtJyYapl3+7thgrNaVGAzF5GcGAzQ7ItuIfQqFWYe6NX/ZUmMSUG
         +8x5DMKdHkO+fEYstYFWTkGs6Ksrozxzhs7mYf2/RlsBijx9Gw20tA/PYa7ncI5C8SLu
         olGOtsgoW5VtS9wtTK51Dxw/Daxg/hNiywNtLAwru5iwsWYLEHsCEEZ3KhVJU7PoajWa
         Xjl7asmrpoZejdZC9F9/BkVEPkiOxHGwHmsg1u4oPdkDDMNdBrnsW7cIBpK6NbMm00ko
         sA9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="gFVzP4z/";
       spf=pass (google.com: domain of oleg@redhat.com designates 207.211.31.81 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Gjbz3uqcTTXmEYw3KVvfLSn5bXuKz+Pe/nobih919uQ=;
        b=Tobj2VOcePD1OmFLK7RMJyGj0uAZ4GTwzCB62xkdQa7w29tfHJWxaqbod7bSNKSBq0
         sByD6kyri3t1LYqt4ti5UJeBuXghTN2r1i44qmnJ8GVQp5sXnzFjXAVx7EHbuFuoKb+c
         mwzYb+UMq1XArUSLecMKd4WOYXWSbpYIVRz3e5W3bnTaUWc95nP7ah0LxvzTVzFjmp8D
         EfvIB3g/lYuKqWchIHMr1jc6F6ux5xF5MnK0Jx3lX2b/4IerQEfEA0ilcLrzeBmsyEoj
         GlCdW/r5cL2O0nP+O2TEcucSqi/YFUnAdxTOcRtOBbKUUsD89nblSkre17ohyzOk2vu/
         iTMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Gjbz3uqcTTXmEYw3KVvfLSn5bXuKz+Pe/nobih919uQ=;
        b=FDocmO3aQ6NSksvdJ203TA6TpdDMI3iFQnDqIPTCEvAqZ/S5bdJ1AFCn9TQp+Jk/h+
         DbIhYyYGp2zV5Nc1Uk816uGO7tqa1FEAtVruZJlvfcn/ml8oFBqzHJ1g5uhjn4pFcT9V
         VrfTFLpy8/GOZ8XaxEzJ1yD0GpqURUMk7rJICu4CcvN8Nbxo9yljS4tCWN/Vy5Vynqjc
         Kj9Jp74AIoXRw23M84ZHt3OHEqGf/7pPXqbGzcnnF7BtcLxBv1wi1CzrdMgGprVU/ppc
         vJVTR9i3PUWuBNTq/aIHw30MOvIiL5KMJzByA8n9hrAyJWEeoEAfFro2yZ4l9pDFDfg0
         HOoA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5336i8AZQKOHf9BcnG+G168rmsdrhfwz0dlQ4FLOgfKR1DUdtN36
	IeJmDQCrPst2KJOCb4DOvvI=
X-Google-Smtp-Source: ABdhPJyuGFH92bNHkw29XUnZwMJbfdOeURbQRe+wqEXu1HFzWPt77tFdzNnEJtNQ9i1owg/s4ua3YQ==
X-Received: by 2002:a92:db49:: with SMTP id w9mr3147006ilq.188.1592570164490;
        Fri, 19 Jun 2020 05:36:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c002:: with SMTP id q2ls2514535ild.4.gmail; Fri, 19 Jun
 2020 05:36:04 -0700 (PDT)
X-Received: by 2002:a05:6e02:10c:: with SMTP id t12mr3320997ilm.187.1592570163962;
        Fri, 19 Jun 2020 05:36:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592570163; cv=none;
        d=google.com; s=arc-20160816;
        b=xH5GPj/gqzKeQhIUkhUZ12ELOvgqXbeHaHxklPnUrp53jt96VszdvklCNtGg0c0JKm
         8J1Zoq8WSBmmeF5Qw46fQgv9mPfLm+rZBYItSiaJ/0+YCinO/ozve3QZOerrRj+IfLiw
         ePioNJOai1pbOsPnBZvdYbbDB7EfNwVKAQ6HwE+hvgZQWpvO+bKNokvL/Exi1eDX5Qbm
         ZDGOMXh3G4sp2Q79Cse1W9optSEbGOXfOaG09q33ijS1CdDgArMPEyN1ZILAKxEZSvjY
         vdpAMHMJ57lPy7SoIz3cF80cEPM066JuKVyntd69qvJPT6keP5KBXFtVOmPi6IyDcsKR
         1gXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=e8VjI/lCu6Vrf+Vb47+xXdK4EsvC1iOMrR4e/LBvef8=;
        b=Wwz4z26qDd9ojvfy6l8mC7SLlwfhprCet4Y6omfGmUbwyXOiC8qlbfxhy3H2TSwUF0
         KbzngHc2YV653OBH0pJ6mYOhqwKwIL5fFaHNTK5mWIavj8ymEdP0Ymr23t6QVoFq3jGU
         HWt5wKRZCaEaSlZXMx7pks8gOA74fQzEfjD+WK0D7bfX6PV0f+WEVbwLvXLjQ31D4kI4
         CcM8i8zZCl5R0TOod5t3SymghHbp7DbawVleK0v6wgs3TtGH3b0VnkkIjEDKRmXDESW2
         H472ET0r0qKzEIinsMmWqaST6stf5lKrk2kZG8SBG03BNjUsAIdx/nkHIu5KbhEYHip1
         6QUA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="gFVzP4z/";
       spf=pass (google.com: domain of oleg@redhat.com designates 207.211.31.81 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-1.mimecast.com (us-smtp-1.mimecast.com. [207.211.31.81])
        by gmr-mx.google.com with ESMTPS id g12si235195iow.3.2020.06.19.05.36.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 19 Jun 2020 05:36:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of oleg@redhat.com designates 207.211.31.81 as permitted sender) client-ip=207.211.31.81;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-397-c4bJcoD5OLSBN6xfAp0LNw-1; Fri, 19 Jun 2020 08:36:01 -0400
X-MC-Unique: c4bJcoD5OLSBN6xfAp0LNw-1
Received: from smtp.corp.redhat.com (int-mx07.intmail.prod.int.phx2.redhat.com [10.5.11.22])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 683151883632;
	Fri, 19 Jun 2020 12:35:57 +0000 (UTC)
Received: from dhcp-27-174.brq.redhat.com (unknown [10.40.192.193])
	by smtp.corp.redhat.com (Postfix) with SMTP id 511C41002394;
	Fri, 19 Jun 2020 12:35:54 +0000 (UTC)
Received: by dhcp-27-174.brq.redhat.com (nbSMTP-1.00) for uid 1000
	oleg@redhat.com; Fri, 19 Jun 2020 14:35:57 +0200 (CEST)
Date: Fri, 19 Jun 2020 14:35:53 +0200
From: Oleg Nesterov <oleg@redhat.com>
To: Marco Elver <elver@google.com>
Cc: Christian Brauner <christian.brauner@ubuntu.com>,
	Weilong Chen <chenweilong@huawei.com>, akpm@linux-foundation.org,
	mm-commits@vger.kernel.org, tglx@linutronix.de, paulmck@kernel.org,
	lizefan@huawei.com, cai@lca.pw, will@kernel.org, dvyukov@google.com,
	kasan-dev@googlegroups.com
Subject: Re: + kernel-forkc-annotate-data-races-for-copy_process.patch added
 to -mm tree
Message-ID: <20200619123552.GA29636@redhat.com>
References: <20200618011657.hCkkO%akpm@linux-foundation.org>
 <20200618081736.4uvvc3lrvaoigt3w@wittgenstein>
 <20200618082632.c2diaradzdo2val2@wittgenstein>
 <263d23f1-fe38-8cb4-71ee-62a6a189b095@huawei.com>
 <9BFEC318-05AE-40E1-8A1F-215A9F78EDC2@ubuntu.com>
 <20200618121545.GA61498@elver.google.com>
 <20200618165035.wpu7n7bud7rwczyt@wittgenstein>
 <20200619112006.GB222848@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200619112006.GB222848@elver.google.com>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-Scanned-By: MIMEDefang 2.84 on 10.5.11.22
X-Original-Sender: oleg@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="gFVzP4z/";
       spf=pass (google.com: domain of oleg@redhat.com designates
 207.211.31.81 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On 06/19, Marco Elver wrote:
>
> For the change here, I would almost say 'data_race(nr_threads)' is
> adequate, because it seems to be a best-effort check as suggested by the
> comment above it. All other accesses are under the lock, and if they
> weren't KCSAN would tell you.

	if (data_race(nr_threads) >= max_threads)

or
	if (data_race(nr_threads) >= data_race(max_threads))

or
	if (data_race(nr_threads >= max_threads))

?

> In an ideal world we end up eliminating all unintentional data races by
> marking (whether it be *ONCE, data_race, atomic, etc.) because it makes
> the code more readable and the tools then know what the intent is.

Well, to me READ_ONCE/etc quite often looks confusing. because sometimes
it is not clear if it is actually needed for correctness, or it was added
"just in case", or it should make some tool happy.

And I can't resist... copy_process() checks "processes < RLIMIT_NPROC" few
lines above and this check is equally racy, but since it uses atomic_read()
everything looks fine.

Just in case, I am not trying to blame KCSAN, not at all. And yes,
atomic_read() at least makes it clear that a concurrent update is possible.

Oleg.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200619123552.GA29636%40redhat.com.
