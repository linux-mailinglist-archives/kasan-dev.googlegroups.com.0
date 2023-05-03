Return-Path: <kasan-dev+bncBCB5ZLWIQIBRB2U2ZKRAMGQEJZCTGUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 64F8B6F5C22
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 18:35:55 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-3f362f3d22fsf8562101cf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 09:35:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683131754; cv=pass;
        d=google.com; s=arc-20160816;
        b=j9NnvgVwc9yHCnM0U7nNEUWUwU5SSq9kiWR/F7Rwj62nHgXnxMC/QLKdCRVhmnNH/k
         BgMAgaW8WQtiOny7KVO3G1GljTiThA3A368eOpFQex3u6sOox6OSluvYiFJdeuPRXZTQ
         PSBbQlQVuyk7MY7h/QuHKh0FWAwCVn6ORh+wfwiZ1nFxVT01BSjS0iqLfVpMisUe04mD
         FKYB+oQS9vWUBWMhrC5N5UZMhAJzpXSK2D2a9XCxUY02z/4FGEplMQUclFQ0yk26ZT9n
         LSRee8e7EtwgfSRzQoqW+OD714Ums8b4hG3KJ8rhYNrI3EX4XFpF2vnpS+AN0rGUJoVd
         zH3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=g8psrDH/MDl7jKLRyQtqJaNlpP3lrWYepciZK+2mdlY=;
        b=VH8plf3azRWIaCyebj3yFij2ueixQj13K6yjn5OpoG+4WsCoMjAGzf3hT9HQK7zpA1
         oy9pyRmuKGsiN1EEoikQqYhhuDv0ZiCqnAKUAepWqGQBNxBKBq0dpNi7uhYATTjg7vWU
         wqC9U2X+r12v5URdPu3BYsVP2RabwrKfi8c9qxE3wFcB6t0vocGR+FXCpxLGM/edwYO1
         erWBPCHBiyOVXVQw4hScA4sIJMSIrHo3STa4L9aZiU5m1BCqsCut27kKq6mKBDw5rJ4l
         a8OCcH7Z8yYa8wywZZZcqYVPxVbf9C9pKW1q70WX7caOLgMLVvQdkMH+mB6amHTN/nAP
         k9FA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b="Z4Cs5R4/";
       spf=pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=htejun@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1683131754; x=1685723754;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=g8psrDH/MDl7jKLRyQtqJaNlpP3lrWYepciZK+2mdlY=;
        b=FrLDSktv/h05XVzoU8s1LkD06AD1JXFazul1rEWLKR3citEYV2SapE8t76GTYVPaOc
         XuxQbJm98YdHOblkr57SF+VR6WUWP8uYi5JWeA9Yv4qQ332HQD5jKjU/9Z8Ozg4SS20+
         73KJ0UNgngjX5HDf2XKl8lQj09JrC7qglatjEACLE44u7zQyWE1rheq46fC2CMdbpcri
         aEy8g4ot2MjJsDYpcPwrSBa7AhsNJS5AQ8Ypb1k8JtF38bKOILUYRHOvYjJunnpSbwxT
         JgUXdz331YhfnuZVq+FC6fcVV70pA0kTdJ5Z6SyOm3/vdu2yTXpdaGzOce3eFdRfq6cc
         ce/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683131754; x=1685723754;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=g8psrDH/MDl7jKLRyQtqJaNlpP3lrWYepciZK+2mdlY=;
        b=kM7AtxTARxfe4bl1pQ9v4DjDvJd8yepxIihokZW/JHqf7opaf2HHePTWwLv1KTLp93
         9ZBiH6NSd4vRxvVqNVU+AXgCl3UIvIPSQEP6rrMNle2hAl4Jo78PHjoFaKxKHl9iY3yb
         jd2y1ikMrhHms+6pi06cod17SEnVGTg8jsBiZRc3Hng4IYNHKnUWWL6i007NmkY8xEpa
         mdsS2EZrHYv+exsB3CqKSxKMQIDNeNKyfyDtoT6MNymnG+9HAsmxj+qV3fbO74pR3SAL
         D/EzVEjgCAszcwM9QL3WPHKRQe2xxkZDD2Oj1lgF6HCpDQFpCpUauq5qhdJSanpOZc+T
         vjNQ==
X-Gm-Message-State: AC+VfDwAwyaGDRMDJypzcYhWKAR7ZI2W2f96wYUNUtPIwEOcHtiTP6ge
	Kayfnad4RYtKByydbHrXEeg=
X-Google-Smtp-Source: ACHHUZ6g1mCyOq51IadY5NFcIYnxdPM867fPLXylKcho1hgYhPkbHftlQjcCvZZ8v7v4zHyjlAmuqQ==
X-Received: by 2002:a05:622a:1356:b0:3ef:6370:3d62 with SMTP id w22-20020a05622a135600b003ef63703d62mr181080qtk.11.1683131754207;
        Wed, 03 May 2023 09:35:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:5786:b0:5a2:29c1:b542 with SMTP id
 lv6-20020a056214578600b005a229c1b542ls10726417qvb.10.-pod-prod-gmail; Wed, 03
 May 2023 09:35:53 -0700 (PDT)
X-Received: by 2002:a05:6214:400c:b0:5ef:8c79:fe8b with SMTP id kd12-20020a056214400c00b005ef8c79fe8bmr10224011qvb.2.1683131753204;
        Wed, 03 May 2023 09:35:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683131753; cv=none;
        d=google.com; s=arc-20160816;
        b=P5TJE5YE5KWGW8aUWOhYZpsV34b5OW5IdhWkEtU+mIDw5M36GcCwbUGoFElt82jnFN
         BHRnl2Nrs5N26lJ6Vz+J+ppxncgrVxqT6P22c9KVb15f+KP8NA0LGopKmB1bYLa8Z04p
         iAgYCmJvjj5cs6xTLfQl5bBclr8QzKBlR1a9wqjwJfAoB+tnQTOb7OHl14bHFgvYUirI
         FAjW+YlM/PlqMizjCtgGzmjZCgbfBLYQ1d221fTXJkvrOJfZMtOcJHXKdRLVRaXSeLEo
         pleVzTgcJcqH5l/7CG6zqmcPOFuOhuOHAUP/Yj/b1p7/bif0l+4wPx5zvo0QAVQmCXyL
         7Eng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=W/389qplif+CNkXxtQ/HgIFDi4dycC02/rtil8xXRXc=;
        b=mXaLcAnWSQ4M9EW2rnM9MzbhVgpsSGaFdRX/8ZqbltVUPP52aimeNOglxymeJAfMuV
         hus/oheqUNSz15FbbnbgwVlzvcMJNQW67/xBz1DqRGeo1Q/2gwAcP8X9dMYUICCmVsfI
         ao1G/5NuCznoNVa6Go368wmS8erGmv8vZXkTAKr2eUFsjdQW2wa3bAIu/sI/6pKwkKHX
         9J0mB25SbVj7kb6SW5ew3Z8X5o1cWWeKhWY+4tLxDINFTbmppcTKXST2jMzHBf3H842r
         rt7VmMAKsSb7gCKSM7GRleXklNg+gvzjwLwfFIkQa47eTTzYub29sh92zyzk3aSlW2Sc
         b3yw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b="Z4Cs5R4/";
       spf=pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=htejun@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-pl1-x633.google.com (mail-pl1-x633.google.com. [2607:f8b0:4864:20::633])
        by gmr-mx.google.com with ESMTPS id i3-20020ad44ba3000000b0061b5c30b3a3si541957qvw.8.2023.05.03.09.35.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 May 2023 09:35:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) client-ip=2607:f8b0:4864:20::633;
Received: by mail-pl1-x633.google.com with SMTP id d9443c01a7336-1ab05018381so29493465ad.2
        for <kasan-dev@googlegroups.com>; Wed, 03 May 2023 09:35:53 -0700 (PDT)
X-Received: by 2002:a17:902:82c3:b0:1a9:1b4:9fd5 with SMTP id u3-20020a17090282c300b001a901b49fd5mr589673plz.68.1683131751882;
        Wed, 03 May 2023 09:35:51 -0700 (PDT)
Received: from localhost ([2620:10d:c090:400::5:6454])
        by smtp.gmail.com with ESMTPSA id b5-20020a170902a9c500b001a4fa2f7a23sm21823336plr.274.2023.05.03.09.35.50
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 May 2023 09:35:51 -0700 (PDT)
Sender: Tejun Heo <htejun@gmail.com>
Date: Wed, 3 May 2023 06:35:49 -1000
From: Tejun Heo <tj@kernel.org>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Michal Hocko <mhocko@suse.com>, Suren Baghdasaryan <surenb@google.com>,
	akpm@linux-foundation.org, vbabka@suse.cz, hannes@cmpxchg.org,
	roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
	willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net,
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com,
	ldufour@linux.ibm.com, catalin.marinas@arm.com, will@kernel.org,
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
	masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org,
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
	cgroups@vger.kernel.org
Subject: Re: [PATCH 00/40] Memory allocation profiling
Message-ID: <ZFKNZZwC8EUbOLMv@slm.duckdns.org>
References: <20230501165450.15352-1-surenb@google.com>
 <ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
 <ZFIOfb6/jHwLqg6M@moria.home.lan>
 <ZFISlX+mSx4QJDK6@dhcp22.suse.cz>
 <ZFIVtB8JyKk0ddA5@moria.home.lan>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZFIVtB8JyKk0ddA5@moria.home.lan>
X-Original-Sender: tj@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b="Z4Cs5R4/";       spf=pass
 (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::633 as
 permitted sender) smtp.mailfrom=htejun@gmail.com;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

Hello, Kent.

On Wed, May 03, 2023 at 04:05:08AM -0400, Kent Overstreet wrote:
> No, we're still waiting on the tracing people to _demonstrate_, not
> claim, that this is at all possible in a comparable way with tracing. 

So, we (meta) happen to do stuff like this all the time in the fleet to hunt
down tricky persistent problems like memory leaks, ref leaks, what-have-you.
In recent kernels, with kprobe and BPF, our ability to debug these sorts of
problems has improved a great deal. Below, I'm attaching a bcc script I used
to hunt down, IIRC, a double vfree. It's not exactly for a leak but leaks
can follow the same pattern.

There are of course some pros and cons to this approach:

Pros:

* The framework doesn't really have any runtime overhead, so we can have it
  deployed in the entire fleet and debug wherever problem is.

* It's fully flexible and programmable which enables non-trivial filtering
  and summarizing to be done inside kernel w/ BPF as necessary, which is
  pretty handy for tracking high frequency events.

* BPF is pretty performant. Dedicated built-in kernel code can do better of
  course but BPF's jit compiled code & its data structures are fast enough.
  I don't remember any time this was a problem.

Cons:

* BPF has some learning curve. Also the fact that what it provides is a wide
  open field rather than something scoped out for a specific problem can
  make it seem a bit daunting at the beginning.

* Because tracking starts when the script starts running, it doesn't know
  anything which has happened upto that point, so you gotta pay attention to
  handling e.g. handling frees which don't match allocs. It's kinda annoying
  but not a huge problem usually. There are ways to build in BPF progs into
  the kernel and load it early but I haven't experiemnted with it yet
  personally.

I'm not necessarily against adding dedicated memory debugging mechanism but
do wonder whether the extra benefits would be enough to justify the code and
maintenance overhead.

Oh, a bit of delta but for anyone who's more interested in debugging
problems like this, while I tend to go for bcc
(https://github.com/iovisor/bcc) for this sort of problems. Others prefer to
write against libbpf directly or use bpftrace
(https://github.com/iovisor/bpftrace).

Thanks.

#!/usr/bin/env bcc-py

import bcc
import time
import datetime
import argparse
import os
import sys
import errno

description = """
Record vmalloc/vfrees and trigger on unmatched vfree
"""

bpf_source = """
#include <uapi/linux/ptrace.h>
#include <linux/vmalloc.h>

struct vmalloc_rec {
	unsigned long		ptr;
	int			last_alloc_stkid;
	int			last_free_stkid;
	int			this_stkid;
	bool			allocated;
};

BPF_STACK_TRACE(stacks, 8192);
BPF_HASH(vmallocs, unsigned long, struct vmalloc_rec, 131072);
BPF_ARRAY(dup_free, struct vmalloc_rec, 1);

int kpret_vmalloc_node_range(struct pt_regs *ctx)
{
        unsigned long ptr = PT_REGS_RC(ctx);
	uint32_t zkey = 0;
	struct vmalloc_rec rec_init = { };
	struct vmalloc_rec *rec;
	int stkid;

	if (!ptr)
		return 0;

	stkid = stacks.get_stackid(ctx, 0);

        rec_init.ptr = ptr;
        rec_init.last_alloc_stkid = -1;
        rec_init.last_free_stkid = -1;
        rec_init.this_stkid = -1;

	rec = vmallocs.lookup_or_init(&ptr, &rec_init);
	rec->allocated = true;
	rec->last_alloc_stkid = stkid;
	return 0;
}

int kp_vfree(struct pt_regs *ctx, const void *addr)
{
	unsigned long ptr = (unsigned long)addr;
	uint32_t zkey = 0;
	struct vmalloc_rec rec_init = { };
	struct vmalloc_rec *rec;
	int stkid;

	stkid = stacks.get_stackid(ctx, 0);

        rec_init.ptr = ptr;
        rec_init.last_alloc_stkid = -1;
        rec_init.last_free_stkid = -1;
        rec_init.this_stkid = -1;

	rec = vmallocs.lookup_or_init(&ptr, &rec_init);
	if (!rec->allocated && rec->last_alloc_stkid >= 0) {
		rec->this_stkid = stkid;
		dup_free.update(&zkey, rec);
	}

	rec->allocated = false;
	rec->last_free_stkid = stkid;
        return 0;
}
"""

bpf = bcc.BPF(text=bpf_source)
bpf.attach_kretprobe(event="__vmalloc_node_range", fn_name="kpret_vmalloc_node_range");
bpf.attach_kprobe(event="vfree", fn_name="kp_vfree");
bpf.attach_kprobe(event="vfree_atomic", fn_name="kp_vfree");

stacks = bpf["stacks"]
vmallocs = bpf["vmallocs"]
dup_free = bpf["dup_free"]
last_dup_free_ptr = dup_free[0].ptr

def print_stack(stkid):
    for addr in stacks.walk(stkid):
        sym = bpf.ksym(addr)
        print('  {}'.format(sym))

def print_dup(dup):
    print('allocated={} ptr={}'.format(dup.allocated, hex(dup.ptr)))
    if (dup.last_alloc_stkid >= 0):
        print('last_alloc_stack: ')
        print_stack(dup.last_alloc_stkid)
    if (dup.last_free_stkid >= 0):
        print('last_free_stack: ')
        print_stack(dup.last_free_stkid)
    if (dup.this_stkid >= 0):
        print('this_stack: ')
        print_stack(dup.this_stkid)

while True:
    time.sleep(1)
    
    if dup_free[0].ptr != last_dup_free_ptr:
        print('\nDUP_FREE:')
        print_dup(dup_free[0])
        last_dup_free_ptr = dup_free[0].ptr

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZFKNZZwC8EUbOLMv%40slm.duckdns.org.
