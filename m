Return-Path: <kasan-dev+bncBCU73AEHRQBBBTOA4KMAMGQEYBQV76A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 07D565B058A
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Sep 2022 15:44:47 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id d6-20020a170902cec600b00174be1616c4sf9955523plg.22
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Sep 2022 06:44:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662558285; cv=pass;
        d=google.com; s=arc-20160816;
        b=09BcEjqO9DUcqKYCuNzgVjmAyKOgdRQWGKTQHK6O8kLMmRSTbfRQ0hiCZ6yOE1l7W5
         OvE27RLiqO8+LEja+fxoU/pk597c5otq01meV5iM8JwY/fcQlz9UEUldv7hlFYLr+fFR
         3hda1qALHcHezvcFsdJu0KVd18rJRNwMAwqBPqCIxPfOQYXSAFRc9zhjvZX4Isbo+ros
         GfWL+Tin+AUZSSwkv7MXKvhQnH2bka2eHOwhWFqGQOKzA3wFEuVhNiL0IsE8w6wXKDht
         okrmh/YBeLUDvC/wrTG3i+HqD9UxH1GzXc/aDornCM9nLhpFy8CxW9ACp6UXlQqK61at
         fGhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=1BIVToI8iSDwez0CPZ2rLLwe7oWLSwYMHQWcQK+7PUk=;
        b=C75pH1r+Dk/ONvnN6VesWPzaveVeELbR8rtD30gKYSu3pdjHPK6UlJ4yPYQnl/voy6
         PVDbAxN9aEcN6ku9cKSIJ6xQdeOFO8m1UC3A21DazsUq7YySSWiO9vIAKrC+past5IbT
         vydUwUlCwHkS27JbRfvrRDexD1gai1owRCoNt1k4fOBxtwdl1AmATxNIL0V+CYuJ/X5G
         ZpH649pfF5YDmAgOs00LQ2etVf/7OWpTWx6dcfcn1kcSWPEOjauTW/RBq/0YvOhjlkil
         8TMDbIrMirP5cDVzXpoVNHUwbDWCYjnsX+i6hVLjT7Z3Fv/d9ZNSBOpEeEGkGpwaCj4v
         Xlww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=5krg=zk=goodmis.org=rostedt@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=5krg=ZK=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date;
        bh=1BIVToI8iSDwez0CPZ2rLLwe7oWLSwYMHQWcQK+7PUk=;
        b=CiM2jognd2SINP6jZiH61+H9EYVAcmwpwZvkh1useqxA1hD5WQnsvHAJXefSsXG6hn
         hfKsVoI2piTvcKaCK1NR9ylodz0EHBnwlGJrOUfo0lqC/nkGEqakrF/jJzlIoQQjFjBk
         UWxyLKxCU6aQOGE+j2GoQeslOF5ghOVc/8GSdCdYmgoQFAN2b21aJrN/7BwyhsWaZRpS
         2p3DGyiiKpeJqVE4N2vEqJlCw79QfiWOTJgRRTxT9MHE74fc8xyAlMWIz+yk5zteb9lk
         9VGhChyI+0rIQ9/CK339OEFg6Tn1jV9r5W2o9Dgi/p6+R81Pj1h1WtbRxusNsFIBrV+4
         l/Ug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=1BIVToI8iSDwez0CPZ2rLLwe7oWLSwYMHQWcQK+7PUk=;
        b=yZVzpqL1vr++4eL9+nAs73Rp0lF5wQUdQksh/quVCLTe8G4XrGBWN82izaUS5cXOCs
         HxJ+v1TgvDMgHoQ9es2bIQbHIsDqnE73jX//bBK27ReC2oJJdmlWZQ/c3mE3mxEI9BDA
         Yndja/BWl1QWY+J5rCpqmeoykCG5ZdVIQXy4kcrFTb87qmzLBmgGd2WlaWGYKBYaJtpM
         FVnPCsrqNSQVe2o6Hh8U9kfgmVrT68Bhtjy2ymXzvZ9gBognW9beQIvTmGsdjPDuWDtp
         /wiXJYLbr4G6Tn0ruqZm9kJbCSTR1sMsMF+cB7AhH8EZiDyW8tXImDecMQQyvfV98q4j
         GLZA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2bE7H06MmmT5U1opVtXiq5g2uO3aGnvRkNrYgfuX6R/gvscIkC
	9i/m1dM1HhjBKbEwZ6467rE=
X-Google-Smtp-Source: AA6agR6Vuo2fYPQhhQkfzXQG0PvFfHyJUUHAv9gPzmV5d1VttbW4u/8lAPFxuAMVKgLDhSx2WgkwOQ==
X-Received: by 2002:a17:902:ea02:b0:176:afd7:3d1d with SMTP id s2-20020a170902ea0200b00176afd73d1dmr3897138plg.120.1662558285364;
        Wed, 07 Sep 2022 06:44:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:5845:0:b0:536:5777:1f90 with SMTP id m66-20020a625845000000b0053657771f90ls9477378pfb.2.-pod-prod-gmail;
 Wed, 07 Sep 2022 06:44:44 -0700 (PDT)
X-Received: by 2002:a05:6a00:1a49:b0:52d:4ad7:3bea with SMTP id h9-20020a056a001a4900b0052d4ad73beamr4031791pfv.66.1662558284582;
        Wed, 07 Sep 2022 06:44:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662558284; cv=none;
        d=google.com; s=arc-20160816;
        b=ctktODPq1LAF/lFbwVHTemoDuIV6nPaPw2+5HvypZuvrGEJzo+05shg5SFdPcYs4dI
         XHUzu4i4gzxExX12SejAIvsyn92kM4jcI2uD8bWQfYqHlMybK9c6lGT9y1dgZZCC/Vnq
         oeHtdz+QfieoGP4qNJAW1OijYXEbuKZ2PIf0x1iJeXXkKxF8fY6XFzjuWTq4ilinMUMP
         1dP8rB4/cbBAgR34BGHRhJnQ50nsb0kqP6GddGhsruCpgCBSl6BfgidtrLDylmwaDxg9
         Ni30WUbUJgxiX2kZTp8xIe7KOqCKJQS5ogKcLZqYBAB8mmdGZrNf/OVC7jvqC2N5Vavw
         /MeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=WUoA1jKleDNFlK22FgBPSfNN6dcxZ8lc0wOpbdzGBxc=;
        b=z65kbdf4hMLJ6UvOpZ9T4FKbVDgtMjMxMnCAcPEmP0FDVeuo4Cd8roRE/tpn3pOIdw
         jaziDH1l/mLAxfTUI5/yV7NZz+KZHUA+w05zff21yc3jRwKgDAI7ISov9eh3rrQQUNUO
         Ht+0Uve2UNA2XMFzr+6LaRkaK9ygJM9SFeA/ggUSQRWiGjuJEyr0lVWuykyUubt5Utxr
         SQLQnK3Spbls3uus0pM1JxdthIJpC+8r9JU3tbWSu6D6x3c1nmK3gQ8ZwhOgkSs8gPmf
         ifBe/+rGOrbh7hKl6s9OHwUc2Y1/0TclbrkY391tRzwnywn8M/0gPVHlYdjY1ebZb7OG
         4qXQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=5krg=zk=goodmis.org=rostedt@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=5krg=ZK=goodmis.org=rostedt@kernel.org"
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id b12-20020a17090a9bcc00b002002f6fd0d3si79442pjw.1.2022.09.07.06.44.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 07 Sep 2022 06:44:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=5krg=zk=goodmis.org=rostedt@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id E4F50618F6;
	Wed,  7 Sep 2022 13:44:43 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3E8F1C433C1;
	Wed,  7 Sep 2022 13:44:38 +0000 (UTC)
Date: Wed, 7 Sep 2022 09:45:18 -0400
From: Steven Rostedt <rostedt@goodmis.org>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Michal Hocko <mhocko@suse.com>, Suren Baghdasaryan <surenb@google.com>,
 Mel Gorman <mgorman@suse.de>, Peter Zijlstra <peterz@infradead.org>, Andrew
 Morton <akpm@linux-foundation.org>, Vlastimil Babka <vbabka@suse.cz>,
 Johannes Weiner <hannes@cmpxchg.org>, Roman Gushchin
 <roman.gushchin@linux.dev>, Davidlohr Bueso <dave@stgolabs.net>, Matthew
 Wilcox <willy@infradead.org>, "Liam R. Howlett" <liam.howlett@oracle.com>,
 David Vernet <void@manifault.com>, Juri Lelli <juri.lelli@redhat.com>,
 Laurent Dufour <ldufour@linux.ibm.com>, Peter Xu <peterx@redhat.com>, David
 Hildenbrand <david@redhat.com>, Jens Axboe <axboe@kernel.dk>,
 mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org,
 changbin.du@intel.com, ytcoode@gmail.com, Vincent Guittot
 <vincent.guittot@linaro.org>, Dietmar Eggemann <dietmar.eggemann@arm.com>,
 Benjamin Segall <bsegall@google.com>, Daniel Bristot de Oliveira
 <bristot@redhat.com>, Valentin Schneider <vschneid@redhat.com>, Christopher
 Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, Joonsoo Kim
 <iamjoonsoo.kim@lge.com>, 42.hyeyoo@gmail.com, Alexander Potapenko
 <glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, Shakeel Butt <shakeelb@google.com>, Muchun Song
 <songmuchun@bytedance.com>, arnd@arndb.de, jbaron@akamai.com, David
 Rientjes <rientjes@google.com>, Minchan Kim <minchan@google.com>, Kalesh
 Singh <kaleshsingh@google.com>, kernel-team <kernel-team@android.com>,
 linux-mm <linux-mm@kvack.org>, iommu@lists.linux.dev,
 kasan-dev@googlegroups.com, io-uring@vger.kernel.org,
 linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org,
 linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org, LKML
 <linux-kernel@vger.kernel.org>
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
Message-ID: <20220907094306.3383dac2@gandalf.local.home>
In-Reply-To: <20220907130323.rwycrntnckc6h43n@kmo-framework>
References: <YxBc1xuGbB36f8zC@dhcp22.suse.cz>
	<CAJuCfpGhwPFYdkOLjwwD4ra9JxPqq1T5d1jd41Jy3LJnVnhNdg@mail.gmail.com>
	<YxEE1vOwRPdzKxoq@dhcp22.suse.cz>
	<CAJuCfpHuzJGTA_-m0Jfawc7LgJLt4GztUUY4K9N9-7bFqJuXnw@mail.gmail.com>
	<20220901201502.sn6223bayzwferxv@moria.home.lan>
	<YxW4Ig338d2vQAz3@dhcp22.suse.cz>
	<20220905234649.525vorzx27ybypsn@kmo-framework>
	<Yxb1cxDSyte1Ut/F@dhcp22.suse.cz>
	<20220906182058.iijmpzu4rtxowy37@kmo-framework>
	<Yxh5ueDTAOcwEmCQ@dhcp22.suse.cz>
	<20220907130323.rwycrntnckc6h43n@kmo-framework>
X-Mailer: Claws Mail 3.17.8 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=5krg=zk=goodmis.org=rostedt@kernel.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=5krg=ZK=goodmis.org=rostedt@kernel.org"
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

On Wed, 7 Sep 2022 09:04:28 -0400
Kent Overstreet <kent.overstreet@linux.dev> wrote:

> On Wed, Sep 07, 2022 at 01:00:09PM +0200, Michal Hocko wrote:
> > Hmm, it seems that further discussion doesn't really make much sense
> > here. I know how to use my time better.  
> 
> Just a thought, but I generally find it more productive to propose ideas than to
> just be disparaging.
> 

But it's not Michal's job to do so. He's just telling you that the given
feature is not worth the burden. He's telling you the issues that he has
with the patch set. It's the submitter's job to address those concerns and
not the maintainer's to tell you how to make it better.

When Linus tells us that a submission is crap, we don't ask him how to make
it less crap, we listen to why he called it crap, and then rewrite to be
not so crappy. If we cannot figure it out, it doesn't get in.

-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220907094306.3383dac2%40gandalf.local.home.
