Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBR6SZCRAMGQEFMHB7TI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B9146F54AE
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 11:28:40 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-3f170a1fbe7sf29714455e9.2
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 02:28:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683106120; cv=pass;
        d=google.com; s=arc-20160816;
        b=X7ZF/oVSC8T69t53Y/tgjSSeelfL+Tz0pTURCM1eM9LbfMuC8wkxFA6ktkjjLyAof9
         kQfuadiBatUdGzS1sp7GpiZUP7T2PEr0nFNFaUN2vRRtDSF4BWAfG+eRkfbUcSO0oS4X
         sor/unSAdQXhhCcLzVMql+SgxT7EP8qaae7D899P5uZ5kPSHB5znzXo8y6Vbz2LmgmiO
         7E4uZkbAtpIFA96aKBRErWZlReCXL+JHhdT+vmRyiUUQQilZiiuoYE0eKrQAoPGj6S6C
         77b8LWAHAH/UGLK4JQUjlRDdmdSRen8+R16OhLu3rc6GxWNcNhGXQ6ZJtMsQFPT6KxSR
         HxJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=QHoi60sod8TtaQgo1pI0Cyz71Twd6Tgu6kHej/8QRCg=;
        b=L6muj5iXc8BAzMJUvG0hg5LVON/xI98ItypykwGIrYHIs5+HMuatgrifN5JOC3nrSj
         J/HcJ8N/0YQroJlNx7J8J21IRxNdTJ9yLQnyUkBCDTRCjcPRlfzLmhr+fjkCYPAcleQm
         GDScC7s9BXiBmsIccmUh6x5QsRG4+4RHLvJVbTS002i5ocMPD8weIQgg0NNzoTTABGeQ
         rZkA4skRpUdoC1S6j/FUkmeg1msQ2amd0/C0FaeZ5TE4KqmiXWtE5N4QeOxdKpCaQyFm
         7Wln+rNYsvitKzDtYgsrTo2d5172Xk0sR0urH3LeGPZLtkNP2N/SyxfELK6pFxafONqf
         D4Ug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=KNBGK8zj;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=8s+fY93F;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683106120; x=1685698120;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=QHoi60sod8TtaQgo1pI0Cyz71Twd6Tgu6kHej/8QRCg=;
        b=poOoxxajVt4jDYdZygkcG7N7PpknbK6SC+hWm8dsL21vbk416OnPjvaEAGzOOnHh6h
         9t6iATdTpP9OFhviIteeLZlhEEhcY8N+mqqRPepZSajR55Iba4H1ExXwZv8qqlxg9iJx
         Ush8v+Gl5NcrzURmLj3lCX0hH2jr48zoZkTQ4+gD0hwdfpdsWxfNLMXQoQqyt1lNlbi0
         WQabgn47gAtaAKbl19TqwnoFCP5fV1FA2AAq/ZYH6ULYNYuYAU+JvEYU6i+irThsaSUm
         ayuoSWsOUapD+iCyY2wVOEkmlOL8StiAZsNFblJChb7LY2B2msXZaTY8a4rKF90A9YhT
         Et3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683106120; x=1685698120;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QHoi60sod8TtaQgo1pI0Cyz71Twd6Tgu6kHej/8QRCg=;
        b=Qfg0x4R1pqDQEJm+uhVMuDbn+qkn+Rh6cs3Tz9nuQI9JFHjZkEhypp6ypGbWyKphvL
         otcOQJQ1M0TzU/TeKGn9vbGtt7KzsXBH+Pjbo9WXrKKqGXucW0PR1knrKVeTtlzKQI+h
         Vv+ZprbtzMPSl/i7OKA4aUhK6DEK/2PqZOUu1K1Nx9qjV+hmr8z2i2Xm7Igq8ELt5Orb
         FdLvPct7wWAg8jro1GFToMI86ySJ4a6dDaZimSzyylmsluA94ta269jmffitTdhaHb51
         mFf7PT2lhuTnO/E2CNC/gg5OoBMLp+8yIpmGM6oDje0V8mWNyEhg8xxu1CSZcLaX5Vu0
         id8Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDxQIVGKDnc/bDsXhaseSiR+clRmlgwtFRNLN1aQ3KY6VlmlSqPO
	76tiJmcEjEULff6djNuas2g=
X-Google-Smtp-Source: ACHHUZ7X8QiKHMceTQD3TMoODXI70k7AvQWH3Q0ki0ouM7CnMJimUooFSJwl9aDyy3vfbX6q7G1C4Q==
X-Received: by 2002:a7b:cc1a:0:b0:3f1:830a:a34d with SMTP id f26-20020a7bcc1a000000b003f1830aa34dmr3566884wmh.1.1683106119902;
        Wed, 03 May 2023 02:28:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4445:b0:3f1:68f0:7451 with SMTP id
 v5-20020a05600c444500b003f168f07451ls9677188wmn.3.-pod-canary-gmail; Wed, 03
 May 2023 02:28:38 -0700 (PDT)
X-Received: by 2002:a1c:e90a:0:b0:3f1:65cb:8156 with SMTP id q10-20020a1ce90a000000b003f165cb8156mr1013526wmc.0.1683106118467;
        Wed, 03 May 2023 02:28:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683106118; cv=none;
        d=google.com; s=arc-20160816;
        b=f1ZXLy3FV1ejRSIXYkB7Wry+tSJoB2Id3g7A5CoNTyYjrF1ttas2pktqF5PGqk9259
         VvUOibyIXsUjdsAvbZobf/RrCx0mqvWU/TlPBCayz0I81J4X87/fTcDJ0yfQLwstvHwa
         wHOBiIQrtSMKLcfbxqk/ZCR/Az8SMbdpzeuM91pgdGzhUaPHC+CubRxlNguKInUrUOAD
         ZoOadxchc5lPYaJXOci7Qs2UkY5t4FRpul2NLd5BhxTAlEU4nqJNMQA14jpkOEf/XUHH
         YC2MFUqTKwCXMduOOYBjPo0eEZ7870mNqJbpGPVFU/NeRsQ21RuizKwpyxHy3WnMZE5j
         7svA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=WT8hRoGrD7YYsyuNzU3m9hUOCfJOj+hVhsiy6Y68fVU=;
        b=wX31vf9fqPhhWnGYdxquRSntQnFlwqqdTcxmbU3cZuwQB2W1bDBD1/SXadSBdc0dHi
         Q+LvcHN1178+M+Z8YbTRv1N/xI9E06ht5O9bTZJJABEr0J4ikjW3zWcpUDZsBJbEZXE6
         hDM5fcqyh5ZmkGodyCi4oIn5XQ4IoYLpJlyqt1791vhh33LVIIFu4V3xBilRZBd3mTRQ
         QEk66WJ4OH0ZHG7wHWotdQWI3MHFA/QWSt05TKSAK5T8q4QHIMQL43ab1cLRAnAVPYsi
         kDmR+QYDDlUYJ/19GlueZCeKsWjqZ1ASPX1BRto65jNKUuR4AwhoYolwuerQRsa6Y+3y
         F4ew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=KNBGK8zj;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=8s+fY93F;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id ba12-20020a0560001c0c00b002f419cfd872si1824623wrb.3.2023.05.03.02.28.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 May 2023 02:28:38 -0700 (PDT)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 140E3201AC;
	Wed,  3 May 2023 09:28:38 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 05E311331F;
	Wed,  3 May 2023 09:28:37 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id lnnVAEUpUmT8FAAAMHmgww
	(envelope-from <vbabka@suse.cz>); Wed, 03 May 2023 09:28:37 +0000
Message-ID: <b6857aad-4cfc-4961-df54-6e658fca7f75@suse.cz>
Date: Wed, 3 May 2023 11:28:36 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.10.1
Subject: Re: [PATCH 01/40] lib/string_helpers: Drop space in string_get_size's
 output
To: Dave Chinner <david@fromorbit.com>,
 James Bottomley <James.Bottomley@hansenpartnership.com>
Cc: Kent Overstreet <kent.overstreet@linux.dev>,
 Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
 mhocko@suse.com, hannes@cmpxchg.org, roman.gushchin@linux.dev,
 mgorman@suse.de, willy@infradead.org, liam.howlett@oracle.com,
 corbet@lwn.net, void@manifault.com, peterz@infradead.org,
 juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com,
 will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev,
 rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
 yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
 hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
 ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com,
 ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
 rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
 vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
 iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
 elver@google.com, dvyukov@google.com, shakeelb@google.com,
 songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
 minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 iommu@lists.linux.dev, linux-arch@vger.kernel.org,
 linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
 linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
 cgroups@vger.kernel.org, Andy Shevchenko <andy@kernel.org>,
 Michael Ellerman <mpe@ellerman.id.au>,
 Benjamin Herrenschmidt <benh@kernel.crashing.org>,
 Paul Mackerras <paulus@samba.org>, "Michael S. Tsirkin" <mst@redhat.com>,
 Jason Wang <jasowang@redhat.com>, =?UTF-8?B?Tm9yYWxmIFRyw6/Cv8K9bm5lcw==?=
 <noralf@tronnes.org>, Andy Shevchenko <andy.shevchenko@gmail.com>
References: <20230501165450.15352-1-surenb@google.com>
 <20230501165450.15352-2-surenb@google.com>
 <ouuidemyregstrijempvhv357ggp4tgnv6cijhasnungsovokm@jkgvyuyw2fti>
 <ZFAUj+Q+hP7cWs4w@moria.home.lan>
 <b6b472b65b76e95bb4c7fc7eac1ee296fdbb64fd.camel@HansenPartnership.com>
 <ZFCA2FF+9MI8LI5i@moria.home.lan>
 <2f5ebe8a9ce8471906a85ef092c1e50cfd7ddecd.camel@HansenPartnership.com>
 <20230502225016.GJ2155823@dread.disaster.area>
Content-Language: en-US
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20230502225016.GJ2155823@dread.disaster.area>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=KNBGK8zj;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=8s+fY93F;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does
 not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 5/3/23 00:50, Dave Chinner wrote:
> On Tue, May 02, 2023 at 07:42:59AM -0400, James Bottomley wrote:
>> On Mon, 2023-05-01 at 23:17 -0400, Kent Overstreet wrote:
>> > On Mon, May 01, 2023 at 10:22:18PM -0400, James Bottomley wrote:
>> > > It is not used just for debug.=C2=A0 It's used all over the kernel f=
or
>> > > printing out device sizes.=C2=A0 The output mostly goes to the kerne=
l
>> > > print buffer, so it's anyone's guess as to what, if any, tools are
>> > > parsing it, but the concern about breaking log parsers seems to be
>> > > a valid one.
>> >=20
>> > Ok, there is sd_print_capacity() - but who in their right mind would
>> > be trying to scrape device sizes, in human readable units,
>>=20
>> If you bother to google "kernel log parser", you'll discover it's quite
>> an active area which supports a load of company business models.
>=20
> That doesn't mean log messages are unchangable ABI. Indeed, we had
> the whole "printk_index_emit()" addition recently to create
> an external index of printk message formats for such applications to
> use. [*]
>=20
>> >  from log messages when it's available in sysfs/procfs (actually, is
>> > it in sysfs? if not, that's an oversight) in more reasonable units?
>>=20
>> It's not in sysfs, no.  As aren't a lot of things, which is why log
>> parsing for system monitoring is big business.
>=20
> And that big business is why printk_index_emit() exists to allow
> them to easily determine how log messages change format and come and
> go across different kernel versions.
>=20
>> > Correct me if I'm wrong, but I've yet to hear about kernel log
>> > messages being consider a stable interface, and this seems a bit out
>> > there.
>>=20
>> It might not be listed as stable, but when it's known there's a large
>> ecosystem out there consuming it we shouldn't break it just because you
>> feel like it.
>=20
> But we've solved this problem already, yes?
>=20
> If the userspace applications are not using the kernel printk format
> index to detect such changes between kernel version, then they
> should be. This makes trivial issues like whether we have a space or
> not between units is completely irrelevant because the entry in the
> printk format index for the log output we emit will match whatever
> is output by the kernel....

If I understand that correctly from the commit changelog, this would have
indeed helped, but if the change was reflected in format string. But with
string_get_size() it's always an %s and the change of the helper's or a
switch to another variant of the helper that would omit the space, wouldn't
be reflected in the format string at all? I guess that would be an argument
for Andy's suggestion for adding a new %pt / %pT which would then be
reflected in the format string. And also more concise to use than using the
helper, fwiw.

> Cheers,
>=20
> Dave.
>=20
> [*]
> commit 337015573718b161891a3473d25f59273f2e626b
> Author: Chris Down <chris@chrisdown.name>
> Date:   Tue Jun 15 17:52:53 2021 +0100
>=20
>     printk: Userspace format indexing support
>    =20
>     We have a number of systems industry-wide that have a subset of their
>     functionality that works as follows:
>    =20
>     1. Receive a message from local kmsg, serial console, or netconsole;
>     2. Apply a set of rules to classify the message;
>     3. Do something based on this classification (like scheduling a
>        remediation for the machine), rinse, and repeat.
>    =20
>     As a couple of examples of places we have this implemented just insid=
e
>     Facebook, although this isn't a Facebook-specific problem, we have th=
is
>     inside our netconsole processing (for alarm classification), and as p=
art
>     of our machine health checking. We use these messages to determine
>     fairly important metrics around production health, and it's important
>     that we get them right.
>    =20
>     While for some kinds of issues we have counters, tracepoints, or metr=
ics
>     with a stable interface which can reliably indicate the issue, in ord=
er
>     to react to production issues quickly we need to work with the interf=
ace
>     which most kernel developers naturally use when developing: printk.
>    =20
>     Most production issues come from unexpected phenomena, and as such
>     usually the code in question doesn't have easily usable tracepoints o=
r
>     other counters available for the specific problem being mitigated. We
>     have a number of lines of monitoring defence against problems in
>     production (host metrics, process metrics, service metrics, etc), and
>     where it's not feasible to reliably monitor at another level, this ki=
nd
>     of pragmatic netconsole monitoring is essential.
>    =20
>     As one would expect, monitoring using printk is rather brittle for a
>     number of reasons -- most notably that the message might disappear
>     entirely in a new version of the kernel, or that the message may chan=
ge
>     in some way that the regex or other classification methods start to
>     silently fail.
>    =20
>     One factor that makes this even harder is that, under normal operatio=
n,
>     many of these messages are never expected to be hit. For example, the=
re
>     may be a rare hardware bug which one wants to detect if it was to eve=
r
>     happen again, but its recurrence is not likely or anticipated. This
>     precludes using something like checking whether the printk in questio=
n
>     was printed somewhere fleetwide recently to determine whether the
>     message in question is still present or not, since we don't anticipat=
e
>     that it should be printed anywhere, but still need to monitor for its
>     future presence in the long-term.
>    =20
>     This class of issue has happened on a number of occasions, causing
>     unhealthy machines with hardware issues to remain in production for
>     longer than ideal. As a recent example, some monitoring around
>     blk_update_request fell out of date and caused semi-broken machines t=
o
>     remain in production for longer than would be desirable.
>    =20
>     Searching through the codebase to find the message is also extremely
>     fragile, because many of the messages are further constructed beyond
>     their callsite (eg. btrfs_printk and other module-specific wrappers,
>     each with their own functionality). Even if they aren't, guessing the
>     format and formulation of the underlying message based on the aesthet=
ics
>     of the message emitted is not a recipe for success at scale, and our
>     previous issues with fleetwide machine health checking demonstrate as
>     much.
>    =20
>     This provides a solution to the issue of silently changed or deleted
>     printks: we record pointers to all printk format strings known at
>     compile time into a new .printk_index section, both in vmlinux and
>     modules. At runtime, this can then be iterated by looking at
>     <debugfs>/printk/index/<module>, which emits the following format, bo=
th
>     readable by humans and able to be parsed by machines:
>    =20
>         $ head -1 vmlinux; shuf -n 5 vmlinux
>         # <level[,flags]> filename:line function "format"
>         <5> block/blk-settings.c:661 disk_stack_limits "%s: Warning: Devi=
ce %s is misaligned\n"
>         <4> kernel/trace/trace.c:8296 trace_create_file "Could not create=
 tracefs '%s' entry\n"
>         <6> arch/x86/kernel/hpet.c:144 _hpet_print_config "hpet: %s(%d):\=
n"
>         <6> init/do_mounts.c:605 prepare_namespace "Waiting for root devi=
ce %s...\n"
>         <6> drivers/acpi/osl.c:1410 acpi_no_auto_serialize_setup "ACPI: a=
uto-serialization disabled\n"
>    =20
>     This mitigates the majority of cases where we have a highly-specific
>     printk which we want to match on, as we can now enumerate and check
>     whether the format changed or the printk callsite disappeared entirel=
y
>     in userspace. This allows us to catch changes to printks we monitor
>     earlier and decide what to do about it before it becomes problematic.
>    =20
>     There is no additional runtime cost for printk callers or printk itse=
lf,
>     and the assembly generated is exactly the same.
>    =20
>     Signed-off-by: Chris Down <chris@chrisdown.name>
>     Cc: Petr Mladek <pmladek@suse.com>
>     Cc: Jessica Yu <jeyu@kernel.org>
>     Cc: Sergey Senozhatsky <sergey.senozhatsky@gmail.com>
>     Cc: John Ogness <john.ogness@linutronix.de>
>     Cc: Steven Rostedt <rostedt@goodmis.org>
>     Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
>     Cc: Johannes Weiner <hannes@cmpxchg.org>
>     Cc: Kees Cook <keescook@chromium.org>
>     Reviewed-by: Petr Mladek <pmladek@suse.com>
>     Tested-by: Petr Mladek <pmladek@suse.com>
>     Reported-by: kernel test robot <lkp@intel.com>
>     Acked-by: Andy Shevchenko <andy.shevchenko@gmail.com>
>     Acked-by: Jessica Yu <jeyu@kernel.org> # for module.{c,h}
>     Signed-off-by: Petr Mladek <pmladek@suse.com>
>     Link: https://lore.kernel.org/r/e42070983637ac5e384f17fbdbe86d19c7b21=
2a5.1623775748.git.chris@chrisdown.name
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/b6857aad-4cfc-4961-df54-6e658fca7f75%40suse.cz.
