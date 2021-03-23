Return-Path: <kasan-dev+bncBCV5TUXXRUIBBKUH46BAMGQEB26WSMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 422C9345BEA
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 11:32:11 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id h21sf893093wrc.19
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 03:32:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616495531; cv=pass;
        d=google.com; s=arc-20160816;
        b=bKk9b0qHklcKZ4O81r+cRApHTUtTl7MKD5mfTZDd7ccS6Jq620gThwHFQHhfxoV7gd
         ARNIXH6Xu0Vxhzig/UnpC1nAS1foD7Mh+pJy0oHLsEFmukxozIou9IEtARzXrF+sltYN
         vOhwpTGMhP5ROcLBobsjyBFxni3ont3vEf3cvhZOOzCRDdszbxZRX9ByR13yCjyMVY2j
         g6EWfQQq/zCL5SGigg4Cdqp2fz2omY1vnytWe6BTH1x95P9jLV+5K/jvsOk4z1fF+/yJ
         uZu4l4loLpMLuphE/CS198AajBGBam+TuzViN45vP1TtotxczerrNj9ajVV6LBs2ZPp/
         3oBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ZXuvY6pH5fTQSByW9B9zSu44B81XuC9rmEGWtiW95eI=;
        b=Sp631ykK8rSvT01s/2GVeHWox8mLp6s2sQrmHlKpR4pmqrQGz1C0E7EvqogOzm5Nze
         qTt/bjDvgo91lHuQ+row/FdmvqRCqn/97wvKkA9J9EMh3sn6PQ75vSIEx9TfJCpY0ua/
         nq2PnCIugwGYeSE96KMGjAh+wYMlVQer+j6/Fm1yMb38vosKTtDZ4pfwoRYLB2CvteM5
         eiMHrND0wJaFFoEV8qOSd6D0FoNy2wtLlQSSLXMKiJRIfizuWDTtWHBEjcJvNRDdLf3S
         yLTuDOKc6OnbgaKRkRZDpdVB9n+I3ST8bjd74cMnDXE2P+UiyQkPTTS8Y8YEG8wGKhoB
         b9Pg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b="j/5Ci76G";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZXuvY6pH5fTQSByW9B9zSu44B81XuC9rmEGWtiW95eI=;
        b=YTRHX+mdbV/CCqKWBHq2r3fCMIqubHEsmBnSfQ+zcfOUc3sYhbI+984XPCE7TqQEeq
         XEKD72jRozWCZc/knhm0JvtGJoc7B0G0d76Pg+caAihtDRLYsoMfIWYSkmfw7pLa3bZ+
         UJd3QaUkMWbSiAuISi9rnWTDo16iCXDgGhDZPY6RMYxDjZytv0eAzzTLWZMq8sEEc6f9
         evyZERCczKbFzJ3CfTDT1Kvf8eH1P2y0noLhib4jOJbmfCbvdgDivOayBdfpYZUvVrD1
         Rw0Llgpek0gmxpxohoi24FO2092zOny0VDge/3Db/XU2c4IEl5IZMFyqbr5xVszPd4td
         qZcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ZXuvY6pH5fTQSByW9B9zSu44B81XuC9rmEGWtiW95eI=;
        b=IKiqVMHklkHvIUL9q6uO/Z6tWpoXpuhgf6c3dG+gp9bQ2/gGtUrGBNy0fUtYDHm2ns
         +lZ67MfZ0+EwSVO4jcJIexS1xxtXnAWOaZVxgEsEBaUYsAIMbaQSRbRKaYGtnoQQN5uG
         0Z6GsNaWNmkwqYM0dV8SO46VoMDfa3FR5cZxC+hVLa/nIgXy3804Dz0usox8aZbDsPzt
         lMi2B2d0RmhJsUjkDPNGV/NJdwK+5oGEnVE/sV5MyNeBF0YuSAmgnvJOctNl8PWp86+H
         qfW6e/B/4dezwapbhtoZHTxYLKnYEALAIUmhot94J7XM4afLmnObz+vskmlxNWOEqs1M
         lcgw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531P96hi+z86KF/5emweS3mIEscq1HVJYS+QEVPXkqrP8HfAApqP
	Ee7SVAqcNqRxWE2tAJ8Yqjw=
X-Google-Smtp-Source: ABdhPJyNO9ehROUALG7YxUYv3ivAmCHzvZZLOmqYQKV0lQkKDlUEF9Zhp6iz0Btwc2rxeWfHosblOw==
X-Received: by 2002:a7b:c3cd:: with SMTP id t13mr2596492wmj.109.1616495531050;
        Tue, 23 Mar 2021 03:32:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:bd84:: with SMTP id n126ls1035694wmf.2.canary-gmail;
 Tue, 23 Mar 2021 03:32:10 -0700 (PDT)
X-Received: by 2002:a1c:541a:: with SMTP id i26mr2575313wmb.75.1616495530242;
        Tue, 23 Mar 2021 03:32:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616495530; cv=none;
        d=google.com; s=arc-20160816;
        b=ipz+mvPV2Btgc0KcJ9oLrGD5DZyyfo6sIzQ4sRtLacYg5r9GDx767OlWaBgro7vXXY
         MtF2uVBV3jbstd7E23yXML+9cjjK5L5ZvSkFoUe6fcTPY6Jv7CvBhOvSyJKSCCPGvym+
         o81NiPSHl7YdYHx5wLtxFpfPKn8sHDQyQ6BtGm/AQv2oXYgklJa7NWs7KuSqdEVuQMsK
         s024OtI1nDktVYJ9cRXhQ6jVIt78NOjTEbBmJz5wy5iE/BmloH8mzWSwT7IOMXFPqhlY
         lF9lGKWzolaFVjOZLzviq3XbR8P1iAK3ughsMfJSZQpTu27fFhERIswR+/StdbXfGwlR
         h1vw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=hZmnbYtc3QdpsYLPmr+JQv0YQpsjHqDjO5iTGYtgkq8=;
        b=QHsUFWv5Jd0FU/OjdZbUv/N6e9dw1iBKhZaDJJ16wdvxpYfAFR0vM7jDfCIT60DkIX
         ovhScFqzPTKL6pApH9YrmrRge5fhUYm3Uns1jL01fizAUbFXpHOI02azhPMLSeap7dj0
         jKjKyHnAQLL4MsqaVF/9Vm4SiW6yl/suc5f6LqqJ5KUNknCJ9d3lFzaos49qkio1AlhA
         VB3qagzS7BZFz32KaPB7E7RVuY5DmcwxOelOFnJkHHos/vNUydxV1kosjaHUXkgOvUzH
         mePxbkop0Q/wBQmBjurCq5vnazNLSvk9uKO3KtreeBFzUcLNQuPszDlayOJmep94zkyo
         b/Yg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b="j/5Ci76G";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id b5si109507wmc.2.2021.03.23.03.32.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 23 Mar 2021 03:32:10 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94 #2 (Red Hat Linux))
	id 1lOeKS-00EcdZ-Od; Tue, 23 Mar 2021 10:32:05 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 2D0FE30257C;
	Tue, 23 Mar 2021 11:32:03 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 1189723601885; Tue, 23 Mar 2021 11:32:03 +0100 (CET)
Date: Tue, 23 Mar 2021 11:32:03 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: alexander.shishkin@linux.intel.com, acme@kernel.org, mingo@redhat.com,
	jolsa@redhat.com, mark.rutland@arm.com, namhyung@kernel.org,
	tglx@linutronix.de, glider@google.com, viro@zeniv.linux.org.uk,
	arnd@arndb.de, christian@brauner.io, dvyukov@google.com,
	jannh@google.com, axboe@kernel.dk, mascasa@google.com,
	pcc@google.com, irogers@google.com, kasan-dev@googlegroups.com,
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	linux-kernel@vger.kernel.org, x86@kernel.org,
	linux-kselftest@vger.kernel.org
Subject: Re: [PATCH RFC v2 8/8] selftests/perf: Add kselftest for
 remove_on_exec
Message-ID: <YFnDo7dczjDzLP68@hirez.programming.kicks-ass.net>
References: <20210310104139.679618-1-elver@google.com>
 <20210310104139.679618-9-elver@google.com>
 <YFiamKX+xYH2HJ4E@elver.google.com>
 <YFjI5qU0z3Q7J/jF@hirez.programming.kicks-ass.net>
 <YFm6aakSRlF2nWtu@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YFm6aakSRlF2nWtu@elver.google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b="j/5Ci76G";
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as
 permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Tue, Mar 23, 2021 at 10:52:41AM +0100, Marco Elver wrote:

> with efs->func==__perf_event_enable. I believe it's sufficient to add
> 
> 	mutex_lock(&parent_event->child_mutex);
> 	list_del_init(&event->child_list);
> 	mutex_unlock(&parent_event->child_mutex);
> 
> right before removing from context. With the version I have now (below
> for completeness), extended torture with the above test results in no
> more warnings and the test also passes.
> 

> +	list_for_each_entry_safe(event, next, &ctx->event_list, event_entry) {
> +		struct perf_event *parent_event = event->parent;
> +
> +		if (!event->attr.remove_on_exec)
>  			continue;
>  
> +		if (!is_kernel_event(event))
> +			perf_remove_from_owner(event);
>  
> +		modified = true;
> +
> +		if (parent_event) {
>  			/*
> +			 * Remove event from parent, to avoid race where the
> +			 * parent concurrently iterates through its children to
> +			 * enable, disable, or otherwise modify an event.
>  			 */
> +			mutex_lock(&parent_event->child_mutex);
> +			list_del_init(&event->child_list);
> +			mutex_unlock(&parent_event->child_mutex);
>  		}

		^^^ this, right?

But that's something perf_event_exit_event() alread does. So then you're
worried about the order of things.

> +
> +		perf_remove_from_context(event, !!event->parent * DETACH_GROUP);
> +		perf_event_exit_event(event, ctx, current, true);
>  	}

perf_event_release_kernel() first does perf_remove_from_context() and
then clears the child_list, and that makes sense because if we're there,
there's no external access anymore, the filedesc is gone and nobody will
be iterating child_list anymore.

perf_event_exit_task_context() and perf_event_exit_event() OTOH seem to
rely on ctx->task == TOMBSTONE to sabotage event_function_call() such
that if anybody is iterating the child_list, it'll NOP out.

But here we don't have neither, and thus need to worry about the order
vs child_list iteration.

I suppose we should stick sync_child_event() in there as well.

And at that point there's very little value in still using
perf_event_exit_event()... let me see if there's something to be done
about that.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YFnDo7dczjDzLP68%40hirez.programming.kicks-ass.net.
