Return-Path: <kasan-dev+bncBC7OD3FKWUERBJUJX2MAMGQEJUDO2MQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id CC7F15A8275
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 17:56:23 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id k126-20020a253d84000000b0068bb342010dsf2431517yba.1
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 08:56:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661961382; cv=pass;
        d=google.com; s=arc-20160816;
        b=PTWmRO1gb3I+DlpD9N53B1SF5QwKE+R8/DOQojxNEOf3KuhJTb7+T2oAkRSlTCkQF0
         EbxbFCDONkLOu1JezTa59XjzZ8nyVXfXV0uhVXGyTr1pbNjI1Mw9duayPrFDkbD69SQi
         Z2/JyyhBiD2D94mksFCNqJ9O2kK46046znGzuRZ4IS+FLmmrG+v1HjOVE7Grk68loB5V
         IMQT41IFK5q/zk3Csj2WdsnBYqmxEor6rnx4UEBS8+VBs6d+toJ4r+ITwWGWW4bOyEzv
         t8aZJJPiP81d6454h+f8KTFjmqo5vNLXSYcWYRJCnu4O7JsLRbm5XNtZ1hA84XWmdiDj
         Bv5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=mdHjH8lqq6S6egdxpPWMDc2r3VYQuIGhlPMPg1AYvSQ=;
        b=ec9+cfFOFn/XDha+ukL7wYvNxO8MYmFcKY/sqcLw0qnr7tvRqBXveBdGcNlbps0ec4
         pWbRFylYhMdyN9K89i3+QkbGR6uXiScV3HHtUO+Lz4bfcbpaPvcqw+JA1GfcR0DAanpd
         gZAWowIqiGWwawa7o18VeLZS27M16EIGqGgMjf8/hyewdiP67tMs1Bg+umJDdmiwUeJV
         qq1OPIlhQxyqJK/locRzuYMXZpce8CBd76qjTbYKfRLHB74sxRH6KcN0YrvEcZXOGGi4
         +yK7BKHL3kGNO+MpBDKnDyWHmzc340FOHjnO4bGtmerCbMQPt/eV/yYdWMSjN0ExA8ez
         VcVQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="dp7ag/s/";
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc;
        bh=mdHjH8lqq6S6egdxpPWMDc2r3VYQuIGhlPMPg1AYvSQ=;
        b=CjW6490zf/bDwzLC06/y+bP3anyocSmvzPpxmRaNOUzNMx1ap8OthJ+I7w/0i/goD1
         sdG++A00+0xNIWY7fnX7Ik6P0/uNOvsEld1bjoqkMngi5bw0mK3ZbcN08KCjm2DhV18B
         Lbl5/hP9yRVyoMs6sT4yZMx/LVIMWXgpsL5edl8KQS2W1bFjk1Rx2GPoSJbBck+rn1lk
         Qdg1Bg6RLGTNDZjy8wgXeBNRHGWUe8OnPJHE9dAr5NzV4flfXIrpbeJbD6N4OleqPwP8
         qAgLhNPdwjxwJq4iwFSe8pri5lEPJPbVhVkq7f9x73E1dkvWrMOGx03o1g5k7ITvL7fT
         bQgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc;
        bh=mdHjH8lqq6S6egdxpPWMDc2r3VYQuIGhlPMPg1AYvSQ=;
        b=7T4uRMEG3I7OZHA8eba+u3eixIQuBs2B3NeotOU634zr05JQONIC/r5g57XRweBS9u
         J9aaifWDqVr+nriLi6KI3ZXP6Dk/KEQWoqRFiEIQetO/UohQ2fn5sTkE8LRbRKgdQIXG
         gaKCIz3ftxSYaoYFe3lBdTi5aLu3C1CEu9ZKX8mqKT/SfhsaMwW95PjMA1ibHtM0kz66
         fEJe9n0NJ3EDZq0NLJJIK8+O+ipCJQgh4Tyg76Rlw3OycNr6H9W9EoOdxFYX5q7+JBYX
         OH732nQ+wrrz/cPiV/aiD7cSJEA/71a7/ug03ewjhM7FAIi/UOzevZ420M29xkTeppsD
         VEvA==
X-Gm-Message-State: ACgBeo1b+2gpZnyuRFOeiZr9/+vaaeixvmZ0KFe4PadO3RluKVYifg7E
	nViMtHjaaT6B/ubFxIy3Mzg=
X-Google-Smtp-Source: AA6agR7KDnoSBI+rqZ64jE+OHtkaYBmBrnGiD8TrFHls0idN8m8gNgJDyI2uM6TPIjCHovYjbIJg0A==
X-Received: by 2002:a0d:c244:0:b0:33b:9697:36be with SMTP id e65-20020a0dc244000000b0033b969736bemr19303514ywd.373.1661961382434;
        Wed, 31 Aug 2022 08:56:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:a56a:0:b0:66e:7859:9c23 with SMTP id h97-20020a25a56a000000b0066e78599c23ls5980102ybi.1.-pod-prod-gmail;
 Wed, 31 Aug 2022 08:56:21 -0700 (PDT)
X-Received: by 2002:a25:bc05:0:b0:699:fc86:da41 with SMTP id i5-20020a25bc05000000b00699fc86da41mr12955333ybh.569.1661961381906;
        Wed, 31 Aug 2022 08:56:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661961381; cv=none;
        d=google.com; s=arc-20160816;
        b=Ip0Ej9n81qMHtcGvrNaA9JODetO8kfWqd6sJaEc9lOVHdTEuSloIBtbC8z8NCKHTft
         s1aT7aqlGT4TrZwYFaP9uFAFcXuuWqoP6Ll4/Yq+S2cLBl5gmlLDVIFIKfHAovlbxi4Y
         xN6eQFD3up3/nLdfX26v8PDkE3SVMBnd9qHlUiN21K27YFp1NF+p7/VmXhUoalyO01mg
         l73pJvaDR97alTFr/dO3T0SL/zYaER9D9DVW0e349Tj1HYXIltG3F0c5HenqgKi0No+X
         FSMFSD6olXjwbC/M1Vxf1hUiRaLCr0ZpFq6hyfPEBAI8gxOgiPUvY2e0p9XiSvugQXJV
         fz1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=cCRpuq5ugrZCMPNASqLzmnmQqSHwIbDaqesnsW6hpVY=;
        b=j9sc5RD63YB7YpooH1wd+0HYgtifDZCCyGK1/gba22ZYPPjjQdFo+tMfD1Hc98l9A/
         V6fAgNLqbGTP5la1wcsKg/PnFoQV4ShVo1pIsniTDypjEq+5kQ6f7QOdxBjMrnFtFY1K
         vrXRA0AmBZm+cFhJR7X/Rh/iMx8eCbG77m//Fvt8WT189UnJMKH9iX2ypElyEqV0EhF2
         v2589JL7tb15Ai9g1OreT7nv+eeWVyA2OejdDm43roDRbSTbFb4sXMyByqx0ncMngiKA
         Mh+Op8uaFHOhEKMijHbZnq+BKW0RPxFgJYwLGZO/gyz6ed8+u2PZxYjv3fjBFI4tzGXk
         OdzQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="dp7ag/s/";
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1132.google.com (mail-yw1-x1132.google.com. [2607:f8b0:4864:20::1132])
        by gmr-mx.google.com with ESMTPS id cm21-20020a05690c0c9500b003306f06af42si650509ywb.3.2022.08.31.08.56.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 31 Aug 2022 08:56:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) client-ip=2607:f8b0:4864:20::1132;
Received: by mail-yw1-x1132.google.com with SMTP id 00721157ae682-32a09b909f6so312203887b3.0
        for <kasan-dev@googlegroups.com>; Wed, 31 Aug 2022 08:56:21 -0700 (PDT)
X-Received: by 2002:a81:85c3:0:b0:33d:a4d9:4599 with SMTP id
 v186-20020a8185c3000000b0033da4d94599mr18562781ywf.237.1661961381492; Wed, 31
 Aug 2022 08:56:21 -0700 (PDT)
MIME-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com> <20220830214919.53220-23-surenb@google.com>
 <b252a4e0-57a1-0f27-f4b0-598e851b47ea@infradead.org>
In-Reply-To: <b252a4e0-57a1-0f27-f4b0-598e851b47ea@infradead.org>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 31 Aug 2022 08:56:10 -0700
Message-ID: <CAJuCfpFff1iVx50QeJWE7=sJUZ2enig34VTAOCz75u_SY2EXKw@mail.gmail.com>
Subject: Re: [RFC PATCH 22/30] Code tagging based fault injection
To: Randy Dunlap <rdunlap@infradead.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, Kent Overstreet <kent.overstreet@linux.dev>, 
	Michal Hocko <mhocko@suse.com>, Vlastimil Babka <vbabka@suse.cz>, Johannes Weiner <hannes@cmpxchg.org>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Mel Gorman <mgorman@suse.de>, 
	Davidlohr Bueso <dave@stgolabs.net>, Matthew Wilcox <willy@infradead.org>, 
	"Liam R. Howlett" <liam.howlett@oracle.com>, David Vernet <void@manifault.com>, 
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, 
	Laurent Dufour <ldufour@linux.ibm.com>, Peter Xu <peterx@redhat.com>, 
	David Hildenbrand <david@redhat.com>, Jens Axboe <axboe@kernel.dk>, mcgrof@kernel.org, 
	masahiroy@kernel.org, nathan@kernel.org, changbin.du@intel.com, 
	ytcoode@gmail.com, Vincent Guittot <vincent.guittot@linaro.org>, 
	Dietmar Eggemann <dietmar.eggemann@arm.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Benjamin Segall <bsegall@google.com>, Daniel Bristot de Oliveira <bristot@redhat.com>, 
	Valentin Schneider <vschneid@redhat.com>, Christopher Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, 42.hyeyoo@gmail.com, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, dvyukov@google.com, 
	Shakeel Butt <shakeelb@google.com>, Muchun Song <songmuchun@bytedance.com>, arnd@arndb.de, 
	jbaron@akamai.com, David Rientjes <rientjes@google.com>, Minchan Kim <minchan@google.com>, 
	Kalesh Singh <kaleshsingh@google.com>, kernel-team <kernel-team@android.com>, 
	linux-mm <linux-mm@kvack.org>, iommu@lists.linux.dev, kasan-dev@googlegroups.com, 
	io-uring@vger.kernel.org, linux-arch@vger.kernel.org, 
	xen-devel@lists.xenproject.org, linux-bcache@vger.kernel.org, 
	linux-modules@vger.kernel.org, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="dp7ag/s/";       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1132
 as permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

On Tue, Aug 30, 2022 at 6:52 PM Randy Dunlap <rdunlap@infradead.org> wrote:
>
>
>
> On 8/30/22 14:49, Suren Baghdasaryan wrote:
> > From: Kent Overstreet <kent.overstreet@linux.dev>
> >
> > This adds a new fault injection capability, based on code tagging.
> >
> > To use, simply insert somewhere in your code
> >
> >   dynamic_fault("fault_class_name")
> >
> > and check whether it returns true - if so, inject the error.
> > For example
> >
> >   if (dynamic_fault("init"))
> >       return -EINVAL;
> >
> > There's no need to define faults elsewhere, as with
> > include/linux/fault-injection.h. Faults show up in debugfs, under
> > /sys/kernel/debug/dynamic_faults, and can be selected based on
> > file/module/function/line number/class, and enabled permanently, or in
> > oneshot mode, or with a specified frequency.
> >
> > Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
>
> Missing Signed-off-by: from Suren.
> See Documentation/process/submitting-patches.rst:
>
> When to use Acked-by:, Cc:, and Co-developed-by:
> ------------------------------------------------
>
> The Signed-off-by: tag indicates that the signer was involved in the
> development of the patch, or that he/she was in the patch's delivery path.

Thanks for the note! Will fix in the next respin.

>
>
> --
> ~Randy

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJuCfpFff1iVx50QeJWE7%3DsJUZ2enig34VTAOCz75u_SY2EXKw%40mail.gmail.com.
