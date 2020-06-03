Return-Path: <kasan-dev+bncBCV5TUXXRUIBBNNF333AKGQEDSQJ7MQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D9F91ECF6F
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jun 2020 14:08:22 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id u4sf1286516ilq.17
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jun 2020 05:08:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591186101; cv=pass;
        d=google.com; s=arc-20160816;
        b=tgL2LyIaFx60R9UCa3+1KG4IYonXsEHfTp2knSwp0TDeL2WHvDDK73O8HtzSDElRni
         M1F/2aadHOBX3Ker3a2+rFldqmAhH6qChg6xqMCZQJxb+U2SNDzzpBb1IjEeYCUGQ+uG
         25b8BKQHBl5SIpdRmItGe8kK8XAkzhGbZdFYqkS2sr0BdWvmTRr7QCLFN9ECdAWBBb1/
         zLYuyEhzTuDtAuj5M45+d4tAEaauh01Ihtxqe61tHP63bZWJn6QTZU+h6TRHXiSthP9O
         whKFA1+oqvXjxl2tb3NuneQgS1Js61XRnNNPrqtyfdnYHUI6+csNurp7ZofXyay0mm4S
         6z4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=5+v/VWlxPLYoRPOmLjVhgAVmr/hvpXuO8/tweXYOL7E=;
        b=vLVFSrhnOG5SZUiK2yHZoIemxwoZJLQTdb2UFP2/MkqxeRe/9Sfw3R1gSIgH+JOsif
         AXz4KHxyHKnJh8d9yEvr6pYEobUstAHBHZ/FSAMRozoYFJ6/QKkqc9Ys3nlwaQZdqctV
         tmA9ahe0FBUrBKjCDSB3JIt+pDAcHiYuabpY9Fu7Ty0aLpm/KOP71zSofxDfLBhjHD+1
         yDclWUK7ZLpmpQBqD8e9ilLZXiM4d2UeD+g7JcgnEWF3WeXWOpSCudnNvSRiWiqnG0De
         lsRAAGXbsSNinZ3YbZwwV2xyLeDZbQVdoKfFHQFLp0uXPvxnmqUvyqB/XNUxex2OaQHh
         b/vA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=qdI7n8GI;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=5+v/VWlxPLYoRPOmLjVhgAVmr/hvpXuO8/tweXYOL7E=;
        b=FKKe9KryKxToV0FTcYhB8md3Z8aKGWdeyOwT+DfphlLJMSw0ClktGguEBpRyszRkMp
         wgA0F4dlL3irIulo0wI4nQSSG7pCrZg1zQQFJOAXLwASgPM7uWcYf/H5nirNosUZXj/i
         751dUE49L+tXMzsh/nOOni6kn40xrBrVI2vq8G3iwlKBZYX7OisPRs59rCPvpQJQ36me
         7QaWy78iaQfo3Tp8YVX/g6kXhLUQJ+5TLbdKbKMZoKK5S6R2iQ2zNj+sfLwkNlSnTCxS
         inLd9sniHXQHBjlOV8mCDV8AgjA2/n7qUcAhZOFW3I0IfRa5WsX+rqw9fQ5dLj1Hnge1
         ekww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=5+v/VWlxPLYoRPOmLjVhgAVmr/hvpXuO8/tweXYOL7E=;
        b=MUMYfFuWfuiTtsa+KTEdsmc/izhsEU77reoWvK9q+jp2OJqO50CpcED3EPYe5ZLgwq
         QK8tCe5/KY43LI0/eSDGpt3euIh0E80F1FmE7W5E8h9V+n0menvOIwn9Nz2vk3xgQOQ2
         iHCQv9huaHR9ttnv/RK9E21/l3vQIm6y3pQ65dKJ/qoCRDzPg4BSkZeuK51R+vgn48rf
         YSlo9FsUOaZBv+p4Yl7hu9SoPTiUAu3G1zZsiHlYBcymYZgwQgh7mZ+l4YxmBA82zEzO
         BWqR92MhABe3lSybuE9Dioik33kW1+ErWTiHhAa1I862gX3wdzMzoz891lCheuRaTtAV
         0Rew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530/zu9jmyd2QZwfL/gf2RtfqExcchPaSmZg6KfWPDE0541brEhb
	VBzTUNHcjSkAIhM2iRzA5bc=
X-Google-Smtp-Source: ABdhPJzw1y6yrTywF6tbTN0IbnOogYxj/pzDWZst7H3r9Ei+ysTpLIrhD5oQV1k3UVMu1i6K3yqetw==
X-Received: by 2002:a92:c04d:: with SMTP id o13mr3449740ilf.201.1591186101573;
        Wed, 03 Jun 2020 05:08:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:2e8f:: with SMTP id m15ls290351iow.9.gmail; Wed, 03
 Jun 2020 05:08:21 -0700 (PDT)
X-Received: by 2002:a05:6602:2c8f:: with SMTP id i15mr3263084iow.45.1591186101225;
        Wed, 03 Jun 2020 05:08:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591186101; cv=none;
        d=google.com; s=arc-20160816;
        b=y4RO7fbriq4M0meU/Vd+20K/WhZotDYZHVKvCKjh9Ukgio0TI/fdbKMj4idTv3Mmg8
         zB++Fkh0vcWHGkADOSEey+KkSQL3zQ2Wb9MTIriAQ4FAKctuCeke1MBtwAn3XnEmt/gW
         6KZOY02f68OLfaMzJOJDNTLW+IDsyXXzh8VfEp8Cd728AUhQsrvAScBtaSZa8EqWV1Bi
         hfPCcGxszzUV7h8mpb8sB5r3tNGv+eE2t4UL3TRSMyhTCvaGGFXFyc13ZxHK8Y2nvyUy
         9TjU3lzR/kEibb9KQ7mRQGVbY7HHpkYqOx5E0uqBwjkpg1HkCKBS01YS6bwJCTLGTr7A
         deEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=/Nf3Sa5CJ3lKHf/KlMc8A7/yA30Oo820YTwvr4Pe3Zw=;
        b=XkYSig5c5DQUg7oc5+vDmb9/lIU15lJQZfKFSmdCdKB5VhsMYZ2KA5yoKbGbOxaGOH
         F5WXFrmEDcq9pO8u+ObhtHiKW1WCu4xVxzv2emtm+EGXOzP9Cc9RQD1vPRjmq5AJyu36
         Fk8opINONPMLmOiSLe9ldglxPXIVA+g5bCOs1mWenFEw82+5EcADrsgq7LBqXj4QYAUx
         JqteNndcqKzB7cLYbVUsOUlLrGAK7My8yNFA3zaraSk3Jnsl40e0HhzsGmMUDCSkV/i9
         nLVe3mdY6BsUUxhOAYL2OKi59dZA2V7DvDfFT5ZnFzNKGhVolNOjC4GefvBWRb63LF4/
         Zo8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=qdI7n8GI;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id g12si82750iow.3.2020.06.03.05.08.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Jun 2020 05:08:21 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jgSBw-00069r-Bj; Wed, 03 Jun 2020 12:08:20 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id CBB16300261;
	Wed,  3 Jun 2020 14:08:18 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id B8BAF20707D3B; Wed,  3 Jun 2020 14:08:18 +0200 (CEST)
Date: Wed, 3 Jun 2020 14:08:18 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: tglx@linutronix.de
Cc: x86@kernel.org, elver@google.com, paulmck@kernel.org,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	will@kernel.org, dvyukov@google.com, glider@google.com,
	andreyknvl@google.com
Subject: Re: [PATCH 0/9] x86/entry fixes
Message-ID: <20200603120818.GC2627@hirez.programming.kicks-ass.net>
References: <20200603114014.152292216@infradead.org>
 <20200603120037.GA2570@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200603120037.GA2570@hirez.programming.kicks-ass.net>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=qdI7n8GI;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Wed, Jun 03, 2020 at 02:00:37PM +0200, Peter Zijlstra wrote:
> On Wed, Jun 03, 2020 at 01:40:14PM +0200, Peter Zijlstra wrote:
> > The first patch is a fix for x86/entry, I'm quicky runing out of brown paper bags again :/
> > 
> > The rest goes on top of these:
> > 
> >   https://lkml.kernel.org/r/20200602173103.931412766@infradead.org
> >   https://lkml.kernel.org/r/20200602184409.22142-1-elver@google.com
> > 
> > patches from myself and Marco that enable *SAN builds. So far GCC-KASAN seen to
> > behave quite well, I've yet to try UBSAN.
> 
> GCC10 + UBSAN:
> 
> vmlinux.o: warning: objtool: match_held_lock()+0x1b2: call to __ubsan_handle_type_mismatch_v1() leaves .noinstr.text section
> vmlinux.o: warning: objtool: rcu_nmi_enter()+0x234: call to __ubsan_handle_out_of_bounds() leaves .noinstr.text section
> vmlinux.o: warning: objtool: __rcu_is_watching()+0x59: call to __ubsan_handle_out_of_bounds() leaves .noinstr.text section
> 
> All of them are marked noinstr. So I suppose UBSAN is just buggered in
> GCC :-/

CLANG11 + UBSAN:

vmlinux.o: warning: objtool: exc_nmi()+0x1c3: call to __ubsan_handle_load_invalid_value() leaves .noinstr.text section
vmlinux.o: warning: objtool: poke_int3_handler()+0x72: call to __ubsan_handle_load_invalid_value() leaves .noinstr.text section
vmlinux.o: warning: objtool: mce_check_crashing_cpu()+0x71: call to __ubsan_handle_load_invalid_value() leaves .noinstr.text section
vmlinux.o: warning: objtool: lock_is_held_type()+0x95: call to __ubsan_handle_out_of_bounds() leaves .noinstr.text section
vmlinux.o: warning: objtool: rcu_nmi_enter()+0xba: call to __ubsan_handle_out_of_bounds() leaves .noinstr.text section
vmlinux.o: warning: objtool: __rcu_is_watching()+0x2c: call to __ubsan_handle_out_of_bounds() leaves .noinstr.text section

IOW, UBSAN appears to be completely hosed.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200603120818.GC2627%40hirez.programming.kicks-ass.net.
