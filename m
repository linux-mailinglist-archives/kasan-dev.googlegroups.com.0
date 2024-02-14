Return-Path: <kasan-dev+bncBDV6LP4FXIHRBLFXWGXAMGQEVKVXK4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id 43F2D8542B8
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 07:20:30 +0100 (CET)
Received: by mail-io1-xd38.google.com with SMTP id ca18e2360f4ac-7c477fbce84sf127079939f.0
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 22:20:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707891629; cv=pass;
        d=google.com; s=arc-20160816;
        b=bK1gkB4C/PlerGo39jo5EvVye+Y1NtE23EjT3JJ72J/VcVg/zrHjzIBat2mn+vLdYi
         quhr0fxqOCbYln/DVMBzq619F89Vg6J0R7QX10U+WI/HfYeZTiv1JP+nI8WbRl6GgW8Y
         D8KuahFO1C+7r8wO189Bhlnuvq8dus8cNta8vnQRl0HF/M6g+4WjiOGw6fpV4c/hJGFV
         0bWbvl7p9dTg7EVeE8BJTRm2JggBc9lS3dXhC0pDcp5TZBZCvPd2nNtOR230D6TPt4Ie
         MYctdUd8efSQ2efAz/aBxT/fDfjbayPSBO5KbH00s74miEpkiQXvS0t7flT1lxn/eve7
         N1Vw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=u/GtnqmYxn8f7Jn1yXrzSXwvBzXgTpejjw3Xjtk0VXk=;
        fh=udvROuXPL1qEXfcneA6CFSnVyb0QA/+JNrMyWTWlV1Y=;
        b=MPWG/RHLobTfuv/uazLd+oCIZy2Rabb+fBJbqx2TVGsEnwEUhlNLfsMvNDL1VNlfe4
         PZBkQZVYwe1PDpfRmdXeHW7BAE5jlSNyEnlfX85a7Rw6IVf6NB/fJEgjT8eDUc10kaCH
         wT654Y6Omk66cLd4gwT1j5iX+CT9Sbk6ZR7aWcGJ51BF6cLb1jMtLRBrSrjV7zN/OPic
         u8winYojmvgKaf9XJ4dMwDOZR6KdlDs+x/z+Efq/zjSj0tL8Ak7X/yhr+KOC5JEIlw9s
         U2Q1JZzDCeSRimX6Nwdo+QpXdXR9BD6LDEyEOZ1qYfLSq/OXtTqhBdfuAP7m1EIPiZDm
         e/Sw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@cmpxchg-org.20230601.gappssmtp.com header.s=20230601 header.b="sH/hgDHN";
       spf=pass (google.com: domain of hannes@cmpxchg.org designates 2607:f8b0:4864:20::82c as permitted sender) smtp.mailfrom=hannes@cmpxchg.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=cmpxchg.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707891629; x=1708496429; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=u/GtnqmYxn8f7Jn1yXrzSXwvBzXgTpejjw3Xjtk0VXk=;
        b=PCmVG2nlyVWQGNbK7mjOWL3+qopjjBRW9NJSsJOVInNkAqUC6BV5036pQ36xa2fUlK
         SH7mcfs+0eu3oBvfkaZM7JpnJ50QLKC8/G/RY59z+QPXiBzuathVn7uNoOnrHC0OOFYK
         1iCgAypP34sMORu73o/DthMlXm3vp0p7q3TVjFKvKOaxfGG6CNkeEXTaxxjfG5tXF2Md
         R9Xo0Z6bz2yQJ5c2GAyV+pygU3xycAV6qiI/g0fxx3sCQ5HkP2inRCu4RD6QEZLojmiH
         6cjl7cgoG1LYDltq4gVfLns+OCrfRV2kak/jXQOxh3NmwhZeReh2EUX2nZ/eGPVj7zZ4
         kBaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707891629; x=1708496429;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=u/GtnqmYxn8f7Jn1yXrzSXwvBzXgTpejjw3Xjtk0VXk=;
        b=lEh1cNWCgK+x6j+KL9uNqoHwNL7+q5pKyDZ9qn1r5dR2IrSwXzJ1sUb8Cj+tavgahr
         EqaWs7EB6ZFpQsJWqRrM4QP5EKQhoI0O0nv56/d8wPmKsVM6NNo4cuvRJjC7Qvj8gTM8
         AkDa33aQ0yKLyltSPDkGRNdjToAkDeyHuVr70pQMOKc+M51dPvgzxQ+UCyyWeXYK+Hg/
         6KqkR6vS3DrsEqFwNIsZmaE161c69CgZN8DhLJTW9UZ7UOe4wyc+e7Ou7SMBue88T/dC
         N1Jgx+SXkBCvkIqwgZbzcgcst6YKfP7DrysGkLJqkl7xk0gV+MKW8RbVRfmt7HLjPVEy
         RhJw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUOYd2rNGHz0g01N5TOByPcZLes5OJAIEgf6XirIFlH3A8/6s8+BZikHnjOSgnwwBJfStLHvzL929NtFuHiTBnNzNvoiR/bxw==
X-Gm-Message-State: AOJu0YwxPdLQff+RNctrbusHafCD2bvHeKcsQlaEa0Pcf/5mIBfMdsEC
	pOBiZQ+/ItA6j5EvLxA6k4hoK4uwyO+KYPm+4IvP+IkiE3pN2WUm
X-Google-Smtp-Source: AGHT+IEB0SxvD/Xy1XiFsrlCZdx57ZCxvvCKfzYZMvabRCIf5LhQt8zEAmoFBeIthn4ORsRjEF67PA==
X-Received: by 2002:a05:6e02:f12:b0:363:c33d:82de with SMTP id x18-20020a056e020f1200b00363c33d82demr2022371ilj.23.1707891628606;
        Tue, 13 Feb 2024 22:20:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:2608:b0:363:d634:8952 with SMTP id
 by8-20020a056e02260800b00363d6348952ls2802620ilb.0.-pod-prod-08-us; Tue, 13
 Feb 2024 22:20:27 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWIwUuKIbed6ZbMTF0tRlfkhEG0+UGvxHW5Qp8OnxdQCl0aiXu8IrTEyLlMdAjyNJo93hws8GN7NcG9fKbgHqSUANn0/jvjXUtEmQ==
X-Received: by 2002:a92:dcd2:0:b0:363:c1bc:356f with SMTP id b18-20020a92dcd2000000b00363c1bc356fmr1842203ilr.21.1707891627615;
        Tue, 13 Feb 2024 22:20:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707891627; cv=none;
        d=google.com; s=arc-20160816;
        b=xw45+yXAqUtOnSNNUsCysYmjBKjdgzC1sVhXlMXPvaSO4u3dLGUz61/YzKlJPQpnkd
         8M4p0ADIaYmUxG5CGfd5zZOFsOgTs5gj1gBqAUTkOGbDzL9EXAoyPcV0yC6WO96aJHsd
         0wTB6IJhg8IDUmDsoiM40hsKQrvxhVrYPoepoD/xj7ZF/fh4mt7dypaBK7OVPfIvMWLu
         hJRSNdDvP0DpAxwxqRHGOeNkVhzUhhVHW92kXSLtRuAScS+UjGbP6lZPL3jiN9a3B7IH
         DOq4Se82QfVtlMIzjPZS2HLHXgVlYoW//1f4MNJbLD2f9h3+0Z5t5otDzotRLqUQgMfk
         hApg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=mPZvfWNgR9UvijIIJJg1XLOXvrF3xKs/y4S11I2T7Mc=;
        fh=QqQhLr51UjbRYwp9iyvLPsLsrWWzAgh/2B3LML/Flpo=;
        b=JOtGX2kxdWEGEn2VMMeJuV0/AeCuXtMbgNU+Zd+nPLKLRxS5SQku2XIVfhB7MykbkL
         o5sIHYRKy+tYZCtZP1mMq3FHVWOfZ9I6HPEg4DvugQozvqGVCJBXRG5YxGdBlr09snFS
         3H6v6ABaFm7W0kCV/HJ9LpUsOktxmbakTaaQvWCdsk7NOG5Sk74GFwQ2/YSEFszBE5xe
         XL/Ydma4EW2kFi0hu2AUBHsBQ5TcjzFlGbqUPH5hm6gJTQsIk4fQfRsB8f+WyeIITClY
         ZyEPbWqCDlP1IhCI7Mkxfz66FwYeEsv57qaYR5WWjwAPygs5rSBJNwARa+0zWeXBP4l5
         fjBw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@cmpxchg-org.20230601.gappssmtp.com header.s=20230601 header.b="sH/hgDHN";
       spf=pass (google.com: domain of hannes@cmpxchg.org designates 2607:f8b0:4864:20::82c as permitted sender) smtp.mailfrom=hannes@cmpxchg.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=cmpxchg.org
X-Forwarded-Encrypted: i=1; AJvYcCXUZJStNL2UWj2FbsOmPwXy8QCIFLVtRL5qW5nKv/uhMKSTVJfoWGY8D7B+dE6tV/IHte0zk+HZPe8XaW/DFbFa9agpzeGzCW8UgA==
Received: from mail-qt1-x82c.google.com (mail-qt1-x82c.google.com. [2607:f8b0:4864:20::82c])
        by gmr-mx.google.com with ESMTPS id z10-20020a92bf0a000000b0036458258671si9103ilh.3.2024.02.13.22.20.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Feb 2024 22:20:27 -0800 (PST)
Received-SPF: pass (google.com: domain of hannes@cmpxchg.org designates 2607:f8b0:4864:20::82c as permitted sender) client-ip=2607:f8b0:4864:20::82c;
Received: by mail-qt1-x82c.google.com with SMTP id d75a77b69052e-42a8a3973c5so26129191cf.2
        for <kasan-dev@googlegroups.com>; Tue, 13 Feb 2024 22:20:27 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUIm6J/OGTpeZ2hUWB0iViaQqO6SwaQWS2XZ6IuLI9D6Q94s4XVjXbmA4CoXI6KaXnTaTXUJ1B1Hr58KxrhbNMtUSfVgRVhfLETEg==
X-Received: by 2002:a05:622a:1045:b0:42c:70a8:1b3f with SMTP id f5-20020a05622a104500b0042c70a81b3fmr1875328qte.7.1707891626471;
        Tue, 13 Feb 2024 22:20:26 -0800 (PST)
X-Forwarded-Encrypted: i=1; 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
Received: from localhost ([2620:10d:c091:400::5:6326])
        by smtp.gmail.com with ESMTPSA id l13-20020ac8078d000000b0042c613a5cf3sm1755053qth.33.2024.02.13.22.20.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Feb 2024 22:20:25 -0800 (PST)
Date: Wed, 14 Feb 2024 01:20:20 -0500
From: Johannes Weiner <hannes@cmpxchg.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
	vbabka@suse.cz, roman.gushchin@linux.dev, mgorman@suse.de,
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
	corbet@lwn.net, void@manifault.com, peterz@infradead.org,
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org,
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
	masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org,
	tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org,
	paulmck@kernel.org, pasha.tatashin@soleen.com,
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
	ndesaulniers@google.com, vvvvvv@google.com,
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
	cgroups@vger.kernel.org
Subject: Re: [PATCH v3 00/35] Memory allocation profiling
Message-ID: <20240214062020.GA989328@cmpxchg.org>
References: <20240212213922.783301-1-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240212213922.783301-1-surenb@google.com>
X-Original-Sender: hannes@cmpxchg.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@cmpxchg-org.20230601.gappssmtp.com header.s=20230601
 header.b="sH/hgDHN";       spf=pass (google.com: domain of hannes@cmpxchg.org
 designates 2607:f8b0:4864:20::82c as permitted sender) smtp.mailfrom=hannes@cmpxchg.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=cmpxchg.org
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

I'll do a more throrough code review, but before the discussion gets
too sidetracked, I wanted to add my POV on the overall merit of the
direction that is being proposed here.

I have backported and used this code for debugging production issues
before. Logging into a random host with an unfamiliar workload and
being able to get a reliable, comprehensive list of kernel memory
consumers is one of the coolest things I have seen in a long
time. This is a huge improvement to sysadmin quality of life.

It's also a huge improvement for MM developers. We're the first points
of contact for memory regressions that can be caused by pretty much
any driver or subsystem in the kernel.

I encourage anybody who is undecided on whether this is worth doing to
build a kernel with these patches applied and run it on their own
machine. I think you'll be surprised what you'll find - and how myopic
and uninformative /proc/meminfo feels in comparison to this. Did you
know there is a lot more to modern filesystems than the VFS objects we
are currently tracking? :)

Then imagine what this looks like on a production host running a
complex mix of filesystems, enterprise networking, bpf programs, gpus
and accelerators etc.

Backporting the code to a slightly older production kernel wasn't too
difficult. The instrumentation layering is explicit, clean, and fairly
centralized, so resolving minor conflicts around the _noprof renames
and the wrappers was pretty straight-forward.

When we talk about maintenance cost, a fair shake would be to weigh it
against the cost and reliability of our current method: evaluating
consumers in the kernel on a case-by-case basis and annotating the
alloc/free sites by hand; then quibbling with the MM community about
whether that consumer is indeed significant enough to warrant an entry
in /proc/meminfo, and what the catchiest name for the stat would be.

I think we can agree that this is vastly less scalable and more
burdensome than central annotations around a handful of mostly static
allocator entry points. Especially considering the rate of change in
the kernel as a whole, and that not everybody will think of the
comprehensive MM picture when writing a random driver. And I think
that's generous - we don't even have the network stack in meminfo.

So I think what we do now isn't working. In the Meta fleet, at any
given time the p50 for unaccounted kernel memory is several gigabytes
per host. The p99 is between 15% and 30% of total memory. That's a
looot of opaque resource usage we have to accept on faith.

For hunting down regressions, all it takes is one untracked consumer
in the kernel to really throw a wrench into things. It's difficult to
find in the noise with tracing, and if it's not growing after an
initial allocation spike, you're pretty much out of luck finding it at
all. Raise your hand if you've written a drgn script to walk pfns and
try to guess consumers from the state of struct page :)

I agree we should discuss how the annotations are implemented on a
technical basis, but my take is that we need something like this.

In a codebase of our size, I don't think the allocator should be
handing out memory without some basic implied tracking of where it's
going. It's a liability for production environments, and it can hide
bad memory management decisions in drivers and other subsystems for a
very long time.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240214062020.GA989328%40cmpxchg.org.
