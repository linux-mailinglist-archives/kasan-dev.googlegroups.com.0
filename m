Return-Path: <kasan-dev+bncBCV5TUXXRUIBB2NB333AKGQEN5XZVQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id A7D5E1ECF2C
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jun 2020 14:00:44 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id c17sf3454815ybf.7
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jun 2020 05:00:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591185643; cv=pass;
        d=google.com; s=arc-20160816;
        b=kXtuHPYIf2qshRE0+aYb1fIz+jdci3gTpzDLHAp3vhQr0KbV/wgIdViwEDb7qlONWM
         NpRXLv+ep7ZxF5oZjr9tT+CiBNIX/9aP2w5xo6NL6sK/rbqKPAFZtmpk44YGfxttF+YY
         f5XJnzgNhOJjVnmcisbuzlBxJkVjZwCkl6C58/3erwfFsQv1uV5Ylt+NnUG01ff6B3lG
         1SP9RnhO8O5XQHbjQHWs52my7Y3+tBIJYN5cTXVWcMsDfoSbRYQkiHI1yrVcHGFgEr7h
         RxX55O4fvJVIEmR+nOP6BRjt2M2YWe9KAZFOSU3qkvq1bf8NcxGZADwy5vWB6cBqewcf
         kVpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=UupTi9xRbZRvk4xmaXEPR8lE/Ny0b1gC/+F7J6PKqT8=;
        b=XwC0wVRcFxXTx6LaaBOtJjsUmmA/uMT27OC1H+JW3qJPj1eDVG/L9NZ+nhDsOwSwBF
         fDjI32P6meK0wxjhfg8u8tq3bz6N39PiuMryCf/sT8VnHI53KhbGDyBCl73VurGBJ4XU
         RUoMErpuX+idia82tv8lkdJu6Xp9fYKFt+kZwZBNIhmrGnqTYtAsNj+IDJsTMFM6wYmQ
         cru4MdzkHTTywi+rigB8J8o9/omKY9m8FoStuAPyUWPpAa+KDq+uLhJFeqBxC3IgTfKl
         Vj2v8hwXAbPh/yUQgnNBg6VirAfD0leRJ5a5WOpE1Nwb7d1O4fNmu5KdL+zrd5/jVvSI
         vIPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=lIA5MI4J;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UupTi9xRbZRvk4xmaXEPR8lE/Ny0b1gC/+F7J6PKqT8=;
        b=CRiNClIb0rpOZWedlEEqJgmmS3EW8IC6SJz5KL/lpKtCE8hlygSaCe53/ahNfXij7c
         axMV2PSilud3VxXSyc1PubAYg2JCo16GdVFiEdX7PrVcpyG8jqkP/lo7dQyZleCENu+h
         SeuHOJA2AJkvXrcEo2WIkgbKwN95FOeBttkb9UerE57uAIowQgjpz2EVHLEqv+YqKSsy
         TeTppzq3BJ1sJGMgPHzCZKLTm9ZkMcuGatLiuWw/mZLkQ0RgwkzroE72JWGZ7Y3fyzWP
         wz0zY5kdjEKEY9nBT9OUL4oMRVfQouJD4jJqApO0NRzVy8NGcKDhh0r0aIhUOyMpYDUO
         vdyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=UupTi9xRbZRvk4xmaXEPR8lE/Ny0b1gC/+F7J6PKqT8=;
        b=ETUbLPl/Kle+8XoQtQodMaHwPdR2KCpc+uVKki6+xRDSUyEEMDSXNQJiyQWq+tUU+P
         YI/izxd+7p9l2uYnNiF3Lx1LlATvBGJnetJsh3+LkKAzsW6haGz/9Hz72LB5AvV8QS73
         lwqnFkq0k+62FaWxZPH762FgXoo+oyRvOgC1rUhNI3wluaPYXX6rLWpJb3AT8dryvgNK
         N9HSdnBhI8CwfEz6GIQg7b2U9NDLrok4KGs44TP9Wh/1cReWOtpLUsXjhBHCK42rKv2d
         5Mvu7Gtv5aBIZqGaWqtdi/8fjNvu3smd5UKII1wEM3lyLIvvxZQESfClMp6ZytZbcIiz
         /p3w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530cqStFupDPkRK9EhDPPpgvSvzCvNr+yIwIYySGXuj0hLoiio/K
	RZNrltogjE5CzEd4pQgCpcU=
X-Google-Smtp-Source: ABdhPJzw1qLHEN19iWSpigHuIXU65giKLJIfmJaL5z2q6aMkF5CsoC1kn1RhsqI9MZ3iQ+5cu1jVMw==
X-Received: by 2002:a25:1645:: with SMTP id 66mr50942811ybw.332.1591185642213;
        Wed, 03 Jun 2020 05:00:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:8684:: with SMTP id z4ls749806ybk.4.gmail; Wed, 03 Jun
 2020 05:00:40 -0700 (PDT)
X-Received: by 2002:a25:c683:: with SMTP id k125mr25733091ybf.305.1591185640153;
        Wed, 03 Jun 2020 05:00:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591185640; cv=none;
        d=google.com; s=arc-20160816;
        b=X9gsEbUs4EsGVxr69BnuRLR93hrnk1XbZw7h3MIMvwkws92SUCiI/JQN6jwfczG3vw
         zdPgTxiq0hh15Jn9pIuKzD8gmEQRFMtrtmGYGAltt2QcwigyFP+EEfOn2G1Xf7GDRXFq
         pgQ6L8UQOKp3PbHgBBo2kvnP7/ul2PngnBjfWqXIfTlvoWrc4WypgUlgJLBoQs71Xuwo
         5NNwrBhOnNsFouhLtgsI7BnJDjSVchU97Mk/AQkQ4hABtPyL99m0sFiemzSsW/u3WPl0
         cuUBKyjLckxSp/csjREqo3B/U73EDKK9l4eWSaRw+MxviMkMdDO1vbnuOELH3ZbFzTnR
         bU6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=HUsvsrTi4Pk2unP72gitF1ESvPnnwLM16HEeHV57pjY=;
        b=w/30A+ye6VWlbeRkKST04nf/rf98I3OL1BFKfk9Deyc+9XJkHc/2lom4t0V5LOL3sn
         7AVPbvdhkuLQJXhXs8gCc2YBOLRMt+cQU0SpfFM/Z/QwQtmaHyNVBb+UnZB/232mmcwn
         SolFLd5+d5MYYC0X/+N8HRrBONgAsimGWwGtyTqlD04oUsaAH5b5ZmhPIO7eLe18YRu0
         14LnjKm556EKcRc0mTPEytniSVuxWLnetkkgPzp48OS7o9grSQWAnBHpSYESU/uz8ZJF
         XY0apgzevw/3HuXEAPcYhY0LnYmtP591Qr/TJMPA39skuHtoHjSdYjUPxq8rZWvXNYMO
         3fEg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=lIA5MI4J;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id r143si59657ybc.5.2020.06.03.05.00.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Jun 2020 05:00:40 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jgS4V-0002iW-8O; Wed, 03 Jun 2020 12:00:39 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id B261430008D;
	Wed,  3 Jun 2020 14:00:37 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 9D5EC209C23B0; Wed,  3 Jun 2020 14:00:37 +0200 (CEST)
Date: Wed, 3 Jun 2020 14:00:37 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: tglx@linutronix.de
Cc: x86@kernel.org, elver@google.com, paulmck@kernel.org,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	will@kernel.org, dvyukov@google.com, glider@google.com,
	andreyknvl@google.com
Subject: Re: [PATCH 0/9] x86/entry fixes
Message-ID: <20200603120037.GA2570@hirez.programming.kicks-ass.net>
References: <20200603114014.152292216@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200603114014.152292216@infradead.org>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=lIA5MI4J;
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

On Wed, Jun 03, 2020 at 01:40:14PM +0200, Peter Zijlstra wrote:
> The first patch is a fix for x86/entry, I'm quicky runing out of brown paper bags again :/
> 
> The rest goes on top of these:
> 
>   https://lkml.kernel.org/r/20200602173103.931412766@infradead.org
>   https://lkml.kernel.org/r/20200602184409.22142-1-elver@google.com
> 
> patches from myself and Marco that enable *SAN builds. So far GCC-KASAN seen to
> behave quite well, I've yet to try UBSAN.

GCC10 + UBSAN:

vmlinux.o: warning: objtool: match_held_lock()+0x1b2: call to __ubsan_handle_type_mismatch_v1() leaves .noinstr.text section
vmlinux.o: warning: objtool: rcu_nmi_enter()+0x234: call to __ubsan_handle_out_of_bounds() leaves .noinstr.text section
vmlinux.o: warning: objtool: __rcu_is_watching()+0x59: call to __ubsan_handle_out_of_bounds() leaves .noinstr.text section

All of them are marked noinstr. So I suppose UBSAN is just buggered in
GCC :-/

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200603120037.GA2570%40hirez.programming.kicks-ass.net.
