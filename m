Return-Path: <kasan-dev+bncBCQJ32NM6AJBBLNHY2RAMGQE26N6TJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id D9AC86F4D22
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 00:50:22 +0200 (CEST)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-18b018b1036sf1187561fac.1
        for <lists+kasan-dev@lfdr.de>; Tue, 02 May 2023 15:50:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683067821; cv=pass;
        d=google.com; s=arc-20160816;
        b=Uj+Um8uPt/u4mnDqj3WkizQNuxp+bLQxDFDiOQ+4w6XppWxjUVA574GOAzzmtRBigF
         iRXoXRK8exVFgT2bwB3B6O5uQnpYI5lt4XllUK5QGRYAyCQGaxMNYMMBsMt1bDu+Qklv
         o12HTtcmJCH5rJ5HzHr6k6KVrVUTm48t4u2elm2cdXVYG2UleoKF3CZA+C3JT9YRCqC2
         0N0Dsm3LFVNSx7dFkbWUfwnIAbtsiI3rQGOo2WtAU3MD/fQfHLVrsixUIcNvW/pDI61l
         4pdQ48IngbRzkfRV2BEgpJG/9IqBMDogyEzQYw9GrgIKp8hoxn11yxy+6g4mBozEwBN3
         XUQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=JSmYIemBNFkT+66eira48CKL49UkDtLyVdj+VcW8NPc=;
        b=he+m42qVw5a4d5xK56t4ELYy36PDoxoP1oSmeXEbv9zfsnUBbDh0DaQQmHDDZoe8aK
         7WP3ZTnEtHIGwNjil/cycDIsWTWerWfYPecm5eDNhJBB1lNLtGJVbme3TOwkyiHbHfti
         FSx4+UH8LEkSrRUQ4EXZd2vwS1SCn8VuoziSlXdJCp9b4R2ouX4jQ6t7W9Sbh88Qd1S7
         2H0yDnXjj5UVcNjF6i2lbYTVhZKIt/AUBGPlhFDXGCK8BpbWhyoBFDfTLlUkn+eKc1mf
         Y9fr/Pv6d4V2jK35xjXa5TkG6mdAhd+tPoEUE3zry/8n6aTFxjuYbnObcyHwdPZffQnK
         AW+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@fromorbit-com.20221208.gappssmtp.com header.s=20221208 header.b=xLl94DvD;
       spf=pass (google.com: domain of david@fromorbit.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=david@fromorbit.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=fromorbit.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683067821; x=1685659821;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=JSmYIemBNFkT+66eira48CKL49UkDtLyVdj+VcW8NPc=;
        b=L6fz2keLgiUH2Nhstnx/N9mzP7LWQe9YyGN5DX21QxIxjJP/aCWOMjw6ZARPWELrDL
         Z78rCAmp971nEg2xHInvULNbxtcIpgs5W5S5MRPbTidzQEn6njJPzmwkq14LW71yJQoI
         3mXHdtqTZky2VHGJZIN6tTjtAw2eKQHUgZISay5pkAE9L677JCPCcTjCyyTOW5V+T9i1
         iUhmiU8ZYzBwIvlSFpUUXHfDmi+veiYsJ8/OrXcyGBIlgSn+j3Jb/sCPil0tYVpcZd4R
         KisDZKsDEOflEHIJ/yc6xAEFP/w5KO4emOX6PtdYxmxP2iEQbQdpFPRcwYIHplV5vGAC
         asuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683067821; x=1685659821;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=JSmYIemBNFkT+66eira48CKL49UkDtLyVdj+VcW8NPc=;
        b=JLshKaCk8iJY7x+oYgfAxGAsjEp36/8ti47wF8XLAZasqDowzwz4PzZBnTIm4ro6tv
         8aUgta91is1XTvrOgsVBqw94IcTEZB6rJnbpwPvmzgLGGIea8H3Vlt/Bh06jcLCYjnhx
         x7nDDy+oPhe3RQ5wLQvqXbcp51k8osncPRB3W7QcSv2MXiaov0bjz4oCVqHpdyGwaJB3
         PEv+BmdtuEuSKmavR4sEp/+ztfUxacqXoDFYqQuTs1xRmNom8KsdKFt0wRbnPdzcNn4W
         rcKyAZhHD8MXzFXMX03zurcKSOkX2o6NTjYBTjSIutiZmL88T0i0ggCdt0o8tW4wbFQv
         sFew==
X-Gm-Message-State: AC+VfDzEhq6rOwrks/II4/p+A+n0wKs/edIPulbJNttJ2qhpBaPf209u
	jVY09sjr0WObXetP1+GO/WU=
X-Google-Smtp-Source: ACHHUZ4aiI0ZqodeiuNVJ9UgfGu3qrYCL/1n9tPcWcLKYgMrbQnqnZSJ4J8d47bVV6LkRaV/kTYDUw==
X-Received: by 2002:a05:6870:9d9c:b0:187:8a98:1082 with SMTP id pv28-20020a0568709d9c00b001878a981082mr7133475oab.11.1683067821596;
        Tue, 02 May 2023 15:50:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:319b:b0:38e:2d4c:6cfd with SMTP id
 cd27-20020a056808319b00b0038e2d4c6cfdls3608157oib.6.-pod-prod-gmail; Tue, 02
 May 2023 15:50:21 -0700 (PDT)
X-Received: by 2002:aca:2118:0:b0:389:4f7b:949d with SMTP id 24-20020aca2118000000b003894f7b949dmr8441381oiz.22.1683067820930;
        Tue, 02 May 2023 15:50:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683067820; cv=none;
        d=google.com; s=arc-20160816;
        b=0MG1hXjPv6kAFH05zILOXjNmaldav2JhDnjbcfea4yC+UcvQkO058m1UO8LSH9pIZy
         D2CmXXUXU5J5pOl86getuiyFbe29IGDlwWfERbsI+V9fklx4uubaWel2j5vXeuMqJUr/
         GrVwUWHySZ/Vfz9Bl5YOlsRLL3ThQfkfOL5splUZ51Oap+KzsXtlk4UvUsxjEAOb9EUU
         RboaqlLKIPATi4e8E75/ddrkPxS6beHY13/Xd7WFkubsweS6/EuXEVmah4bsYuYRYY3N
         5AOsAMbS7GuP17whg2h3HsMqO4mfQ81wjgMhwSmc/M2FbXwrQvMSvSsWNhUht++caAAu
         DDSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=g8QAkHheKqFpH2L93tPDJOTqznflZZjkS+pV5SBVWTE=;
        b=uRURX+iVwSfdFDxhZl7KRgZPsw8UP2HWeGs/DqmQUuT0YMg/iJ1tVKwh+DwpJzA1o4
         RnRyH/d3J894Kw2JPgYd2rP99x0xFDAF0LvWopQNFpVvcdgRxzrNxr+dRRsAFh69UCno
         X1VCsmUDnUOux72UJnoBSlcwyGaV2jccInmEx5qL3ULZpVqk9BuwjIAcxHCnmfO3wV4u
         NQag1TiTqmAGXfFTMYp++KNWGeFECp2mvI7TnB/bCh4pZSFBmpDJUBjj2mGaygC0uY+j
         fNekZr1Bb+Hds/L7bdzD9aygqZEOYXR90Rciu7oXM6/RGBwPlrNk8Sl8y9p8wHmsn7iR
         sVcg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@fromorbit-com.20221208.gappssmtp.com header.s=20221208 header.b=xLl94DvD;
       spf=pass (google.com: domain of david@fromorbit.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=david@fromorbit.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=fromorbit.com
Received: from mail-pl1-x636.google.com (mail-pl1-x636.google.com. [2607:f8b0:4864:20::636])
        by gmr-mx.google.com with ESMTPS id y127-20020aca3285000000b0038c2f0e920bsi7774oiy.4.2023.05.02.15.50.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 May 2023 15:50:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@fromorbit.com designates 2607:f8b0:4864:20::636 as permitted sender) client-ip=2607:f8b0:4864:20::636;
Received: by mail-pl1-x636.google.com with SMTP id d9443c01a7336-1aae46e62e9so26080885ad.2
        for <kasan-dev@googlegroups.com>; Tue, 02 May 2023 15:50:20 -0700 (PDT)
X-Received: by 2002:a17:902:db03:b0:1a9:7707:80b1 with SMTP id m3-20020a170902db0300b001a9770780b1mr23452836plx.67.1683067820093;
        Tue, 02 May 2023 15:50:20 -0700 (PDT)
Received: from dread.disaster.area (pa49-181-88-204.pa.nsw.optusnet.com.au. [49.181.88.204])
        by smtp.gmail.com with ESMTPSA id r12-20020a170902be0c00b00194d14d8e54sm20215564pls.96.2023.05.02.15.50.19
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 May 2023 15:50:19 -0700 (PDT)
Received: from dave by dread.disaster.area with local (Exim 4.92.3)
	(envelope-from <david@fromorbit.com>)
	id 1ptyp6-00AcrA-Ao; Wed, 03 May 2023 08:50:16 +1000
Date: Wed, 3 May 2023 08:50:16 +1000
From: "'Dave Chinner' via kasan-dev" <kasan-dev@googlegroups.com>
To: James Bottomley <James.Bottomley@hansenpartnership.com>
Cc: Kent Overstreet <kent.overstreet@linux.dev>,
	Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
	roman.gushchin@linux.dev, mgorman@suse.de, willy@infradead.org,
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
	peterz@infradead.org, juri.lelli@redhat.com, ldufour@linux.ibm.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
	keescook@chromium.org, ndesaulniers@google.com,
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
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
	Paul Mackerras <paulus@samba.org>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Jason Wang <jasowang@redhat.com>,
	Noralf =?iso-8859-1?B?VHLvv71ubmVz?= <noralf@tronnes.org>
Subject: Re: [PATCH 01/40] lib/string_helpers: Drop space in
 string_get_size's output
Message-ID: <20230502225016.GJ2155823@dread.disaster.area>
References: <20230501165450.15352-1-surenb@google.com>
 <20230501165450.15352-2-surenb@google.com>
 <ouuidemyregstrijempvhv357ggp4tgnv6cijhasnungsovokm@jkgvyuyw2fti>
 <ZFAUj+Q+hP7cWs4w@moria.home.lan>
 <b6b472b65b76e95bb4c7fc7eac1ee296fdbb64fd.camel@HansenPartnership.com>
 <ZFCA2FF+9MI8LI5i@moria.home.lan>
 <2f5ebe8a9ce8471906a85ef092c1e50cfd7ddecd.camel@HansenPartnership.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <2f5ebe8a9ce8471906a85ef092c1e50cfd7ddecd.camel@HansenPartnership.com>
X-Original-Sender: david@fromorbit.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@fromorbit-com.20221208.gappssmtp.com header.s=20221208
 header.b=xLl94DvD;       spf=pass (google.com: domain of david@fromorbit.com
 designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=david@fromorbit.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=fromorbit.com
X-Original-From: Dave Chinner <david@fromorbit.com>
Reply-To: Dave Chinner <david@fromorbit.com>
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

On Tue, May 02, 2023 at 07:42:59AM -0400, James Bottomley wrote:
> On Mon, 2023-05-01 at 23:17 -0400, Kent Overstreet wrote:
> > On Mon, May 01, 2023 at 10:22:18PM -0400, James Bottomley wrote:
> > > It is not used just for debug.=C2=A0 It's used all over the kernel fo=
r
> > > printing out device sizes.=C2=A0 The output mostly goes to the kernel
> > > print buffer, so it's anyone's guess as to what, if any, tools are
> > > parsing it, but the concern about breaking log parsers seems to be
> > > a valid one.
> >=20
> > Ok, there is sd_print_capacity() - but who in their right mind would
> > be trying to scrape device sizes, in human readable units,
>=20
> If you bother to google "kernel log parser", you'll discover it's quite
> an active area which supports a load of company business models.

That doesn't mean log messages are unchangable ABI. Indeed, we had
the whole "printk_index_emit()" addition recently to create
an external index of printk message formats for such applications to
use. [*]

> >  from log messages when it's available in sysfs/procfs (actually, is
> > it in sysfs? if not, that's an oversight) in more reasonable units?
>=20
> It's not in sysfs, no.  As aren't a lot of things, which is why log
> parsing for system monitoring is big business.

And that big business is why printk_index_emit() exists to allow
them to easily determine how log messages change format and come and
go across different kernel versions.

> > Correct me if I'm wrong, but I've yet to hear about kernel log
> > messages being consider a stable interface, and this seems a bit out
> > there.
>=20
> It might not be listed as stable, but when it's known there's a large
> ecosystem out there consuming it we shouldn't break it just because you
> feel like it.

But we've solved this problem already, yes?

If the userspace applications are not using the kernel printk format
index to detect such changes between kernel version, then they
should be. This makes trivial issues like whether we have a space or
not between units is completely irrelevant because the entry in the
printk format index for the log output we emit will match whatever
is output by the kernel....

Cheers,

Dave.

[*]
commit 337015573718b161891a3473d25f59273f2e626b
Author: Chris Down <chris@chrisdown.name>
Date:   Tue Jun 15 17:52:53 2021 +0100

    printk: Userspace format indexing support
   =20
    We have a number of systems industry-wide that have a subset of their
    functionality that works as follows:
   =20
    1. Receive a message from local kmsg, serial console, or netconsole;
    2. Apply a set of rules to classify the message;
    3. Do something based on this classification (like scheduling a
       remediation for the machine), rinse, and repeat.
   =20
    As a couple of examples of places we have this implemented just inside
    Facebook, although this isn't a Facebook-specific problem, we have this
    inside our netconsole processing (for alarm classification), and as par=
t
    of our machine health checking. We use these messages to determine
    fairly important metrics around production health, and it's important
    that we get them right.
   =20
    While for some kinds of issues we have counters, tracepoints, or metric=
s
    with a stable interface which can reliably indicate the issue, in order
    to react to production issues quickly we need to work with the interfac=
e
    which most kernel developers naturally use when developing: printk.
   =20
    Most production issues come from unexpected phenomena, and as such
    usually the code in question doesn't have easily usable tracepoints or
    other counters available for the specific problem being mitigated. We
    have a number of lines of monitoring defence against problems in
    production (host metrics, process metrics, service metrics, etc), and
    where it's not feasible to reliably monitor at another level, this kind
    of pragmatic netconsole monitoring is essential.
   =20
    As one would expect, monitoring using printk is rather brittle for a
    number of reasons -- most notably that the message might disappear
    entirely in a new version of the kernel, or that the message may change
    in some way that the regex or other classification methods start to
    silently fail.
   =20
    One factor that makes this even harder is that, under normal operation,
    many of these messages are never expected to be hit. For example, there
    may be a rare hardware bug which one wants to detect if it was to ever
    happen again, but its recurrence is not likely or anticipated. This
    precludes using something like checking whether the printk in question
    was printed somewhere fleetwide recently to determine whether the
    message in question is still present or not, since we don't anticipate
    that it should be printed anywhere, but still need to monitor for its
    future presence in the long-term.
   =20
    This class of issue has happened on a number of occasions, causing
    unhealthy machines with hardware issues to remain in production for
    longer than ideal. As a recent example, some monitoring around
    blk_update_request fell out of date and caused semi-broken machines to
    remain in production for longer than would be desirable.
   =20
    Searching through the codebase to find the message is also extremely
    fragile, because many of the messages are further constructed beyond
    their callsite (eg. btrfs_printk and other module-specific wrappers,
    each with their own functionality). Even if they aren't, guessing the
    format and formulation of the underlying message based on the aesthetic=
s
    of the message emitted is not a recipe for success at scale, and our
    previous issues with fleetwide machine health checking demonstrate as
    much.
   =20
    This provides a solution to the issue of silently changed or deleted
    printks: we record pointers to all printk format strings known at
    compile time into a new .printk_index section, both in vmlinux and
    modules. At runtime, this can then be iterated by looking at
    <debugfs>/printk/index/<module>, which emits the following format, both
    readable by humans and able to be parsed by machines:
   =20
        $ head -1 vmlinux; shuf -n 5 vmlinux
        # <level[,flags]> filename:line function "format"
        <5> block/blk-settings.c:661 disk_stack_limits "%s: Warning: Device=
 %s is misaligned\n"
        <4> kernel/trace/trace.c:8296 trace_create_file "Could not create t=
racefs '%s' entry\n"
        <6> arch/x86/kernel/hpet.c:144 _hpet_print_config "hpet: %s(%d):\n"
        <6> init/do_mounts.c:605 prepare_namespace "Waiting for root device=
 %s...\n"
        <6> drivers/acpi/osl.c:1410 acpi_no_auto_serialize_setup "ACPI: aut=
o-serialization disabled\n"
   =20
    This mitigates the majority of cases where we have a highly-specific
    printk which we want to match on, as we can now enumerate and check
    whether the format changed or the printk callsite disappeared entirely
    in userspace. This allows us to catch changes to printks we monitor
    earlier and decide what to do about it before it becomes problematic.
   =20
    There is no additional runtime cost for printk callers or printk itself=
,
    and the assembly generated is exactly the same.
   =20
    Signed-off-by: Chris Down <chris@chrisdown.name>
    Cc: Petr Mladek <pmladek@suse.com>
    Cc: Jessica Yu <jeyu@kernel.org>
    Cc: Sergey Senozhatsky <sergey.senozhatsky@gmail.com>
    Cc: John Ogness <john.ogness@linutronix.de>
    Cc: Steven Rostedt <rostedt@goodmis.org>
    Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
    Cc: Johannes Weiner <hannes@cmpxchg.org>
    Cc: Kees Cook <keescook@chromium.org>
    Reviewed-by: Petr Mladek <pmladek@suse.com>
    Tested-by: Petr Mladek <pmladek@suse.com>
    Reported-by: kernel test robot <lkp@intel.com>
    Acked-by: Andy Shevchenko <andy.shevchenko@gmail.com>
    Acked-by: Jessica Yu <jeyu@kernel.org> # for module.{c,h}
    Signed-off-by: Petr Mladek <pmladek@suse.com>
    Link: https://lore.kernel.org/r/e42070983637ac5e384f17fbdbe86d19c7b212a=
5.1623775748.git.chris@chrisdown.name

--=20
Dave Chinner
david@fromorbit.com

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20230502225016.GJ2155823%40dread.disaster.area.
