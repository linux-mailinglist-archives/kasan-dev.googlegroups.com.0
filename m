Return-Path: <kasan-dev+bncBC7OBJGL2MHBBREDT2CQMGQESBOZ6UY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id C7B9238C3C0
	for <lists+kasan-dev@lfdr.de>; Fri, 21 May 2021 11:47:48 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id z1-20020a1c7e010000b0290179806d11d4sf2420418wmc.3
        for <lists+kasan-dev@lfdr.de>; Fri, 21 May 2021 02:47:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621590468; cv=pass;
        d=google.com; s=arc-20160816;
        b=WKBLRGbgkUsH024LYuJfidNX+bTniby3Wpkw+UOx8lhcQydxzqusFo8kGuodAZZ8+i
         kNMWqRly5qyuBYIXVlmcfqJp4BCUA0d8wHlhQatajrrOqgVLbHHDFJI/V5K8PRsnuL1A
         AXjqtfz60ALfTLMr9hXZLBsT3eZ0tcvFwiLza6E0Gz3Xi9SIb47KLj925FlSLWXBBulX
         Hntq2MH74oQR/L8Ji5mcYnKid5EeBwJ4fof+H8iE1AaWLQpa5WHsevUbJiHv5U0XVhII
         lU7+dVgjms/1HhH1cQwkvZ4mhDiLhAzmvGxU3ahSMNXiR0WHlakv0gSj6y++GO/VDp4v
         TNqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=CYrC9Mz4+xaxoqbXyBlWY7NGldTdA/f0ZDG7dma+hSo=;
        b=SQtOXh7qGXOTHRS+HD+IXaa1IejPHYmYfYI7HyUORZEDPrJWv7ApS00pXqX//Yvd6D
         q1pdaELVpWrevZ/2NOvV7XgYyCDTroHby7lOvKob9I50ndpazf8kfD6y9lsiT2MmUkH1
         CR/inRX9Xr9AQEodYSvRGvMuKV7iH6JGiGwS7kXwvoq/J0eYD3AxHv+0xNkggdtP/6Ws
         mVKuBIBskzNRB2ULiE/vTO0I2RLGG7LpCHQR+JDS8LEBhGQCwMcTdEXgPyoUZi+XN63q
         isqs4QXnbGFTlY0soaXPu1enIfPV9GhhwoJYIGfvUO7UNtjjtq3pERxDaz9n47PzD/A0
         hRhg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BZ4SRa8E;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=CYrC9Mz4+xaxoqbXyBlWY7NGldTdA/f0ZDG7dma+hSo=;
        b=aiCCvjleIMHg9P0xpz51jb0oT8G/Sa23xJ480a7Z60zj6NvqjFbg2mv6iy1OINw/Ng
         Qj8OG/c7r4af58ommN3pMW6bpSYHsnTVF9BDJ1RbqPH5oGawqMlH2UM6mDYJXDM4EMX4
         lMz51ZCNtw/NUckg5EoIYiYJ0HlSJj4G4WtzAGCan/wBsBcM7waxLf/BfKhAtA2BLWCc
         omWp/uBy/KAiE7DxRM4D+YktvCOZ1ahdypLimAskKGjwYE6pBoT4y2fiwfNOSpq4hwBl
         xUxCavmOfZmDXHsnRFwalhgk7t2W0D49hQGqLcrbNv5m+2GqmOkJUtfVWPyx+aDRsMRG
         SamQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CYrC9Mz4+xaxoqbXyBlWY7NGldTdA/f0ZDG7dma+hSo=;
        b=cQzr9YB0SJSdr3pHmeJcoW/lFPYrnu1kEVCycuc+GQJ0jMvulZXSSlTups9hfIxk7f
         3dELoqcw4G5AJpgdG9iOh3gTUHnsudysyBv8r5gRpoRPNPeJPAQAFlSm8hgixf6DIlmW
         Xw/4PBiVupaY48hgeicp3Y11oso3Y314oq3DlxOcyzvZ+0E3LoQI+lYJyvbwNh8B7IZQ
         C32nLrnSwgrkY/R0aPiUsnPeu6NoC5geSplWAY/O3h0LO3q60b0T3A6QzF3IJHnpav/B
         5I7yLXbsre1iQT6XqEVtg/TRXdWbg65jcQm0NoGPjZdZzi23K5HhZNZ6bFmWE8KnWHH8
         9DBw==
X-Gm-Message-State: AOAM530Kx+wYJXWBM/SYOd71S200lSvRPQcRnmEBRlkOP5P9748dmmvQ
	rYKUT2m+E6yz96Jez1jW9mc=
X-Google-Smtp-Source: ABdhPJzQH8NT6fnc+7yfj/ovR6OgEYjtYcCXTXVB4HvTRHLUW9aNUKoQ3rFIDnM3bGU40n9os7cxwQ==
X-Received: by 2002:a1c:5544:: with SMTP id j65mr8072661wmb.174.1621590468542;
        Fri, 21 May 2021 02:47:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4e87:: with SMTP id f7ls6058496wmq.1.canary-gmail;
 Fri, 21 May 2021 02:47:47 -0700 (PDT)
X-Received: by 2002:a7b:c30f:: with SMTP id k15mr8393401wmj.128.1621590467603;
        Fri, 21 May 2021 02:47:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621590467; cv=none;
        d=google.com; s=arc-20160816;
        b=b0vmDUi5+tzhjDFz99MLORUuZELBfFV3xPnhJ51Qmxk5MeSDC5F8kvMt0I0cDcvatM
         TSZ+Be8nzknWk1A0DMdEgVUJhzyA6rps8WnunLNEad5PgxsvpClJ0VDLeFvjWiXW+zi8
         pfzgMWlvABjThbCOcnhAlIye0blClOIlqXIH57hS4PEExDums2YN/Yn3V8gMwmkqA38/
         ioO0sZxYThllvdtTqFEeGAytLDaMGHO3pgbOGvH/PQDt5MiHcTHePohHMceoB1m6jKEi
         UjOXsL/ofY0FzXkyUiI5xg0O7gOpPbVRjy1z8nv1OLSPhe2AvIW5d+RjmoAvh0V9QzMo
         pJgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=U9YtYqD1zOgwTQj4rwYUvRL9M+o9cBUdkDhNiVVCqT4=;
        b=xfjJeiLlPuTaKnopC2OFMQTOkgDemQ4PWFD5+2h/pWxxpOv6LZ4NojC3FS1lw1a/Na
         vqAwiMWLlJ8tNqLbhMwjdmNuccDj8FPCd1rZoqQMMAeSh+os/6RyuYE3pN6HcoW7uHoy
         KpoIJ2fCcBySTZibOb9gl36XtFNEE0Mpek3vvLB8be2FLCG5AMuVi46+qUEYAEV4ONoP
         ZMkH7S6kRAN5qumpDFVRe/j4YYgycjmOvIiuAl+GC1O5NJIM48ZlX24PAY4i1n2HUBwS
         sNySzY6qfd1Wf/8Af1Fr99x5Mu84+Q2AoqpLb1zQ60smoYvsZNH9KqKuLS8CHeP1KHB4
         H8Cg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BZ4SRa8E;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42c.google.com (mail-wr1-x42c.google.com. [2a00:1450:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id o11si262996wmc.0.2021.05.21.02.47.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 21 May 2021 02:47:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as permitted sender) client-ip=2a00:1450:4864:20::42c;
Received: by mail-wr1-x42c.google.com with SMTP id d11so20391318wrw.8
        for <kasan-dev@googlegroups.com>; Fri, 21 May 2021 02:47:47 -0700 (PDT)
X-Received: by 2002:adf:aad8:: with SMTP id i24mr8716047wrc.0.1621590467086;
        Fri, 21 May 2021 02:47:47 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:a932:cdd6:7230:17ba])
        by smtp.gmail.com with ESMTPSA id t7sm1429438wrs.87.2021.05.21.02.47.46
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 21 May 2021 02:47:46 -0700 (PDT)
Date: Fri, 21 May 2021 11:47:41 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Laight <David.Laight@aculab.com>
Cc: "akpm@linux-foundation.org" <akpm@linux-foundation.org>,
	"glider@google.com" <glider@google.com>,
	"dvyukov@google.com" <dvyukov@google.com>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	Mel Gorman <mgorman@suse.de>,
	"stable@vger.kernel.org" <stable@vger.kernel.org>
Subject: Re: [PATCH] kfence: use TASK_IDLE when awaiting allocation
Message-ID: <YKeBvR0sZGTqX4fG@elver.google.com>
References: <20210521083209.3740269-1-elver@google.com>
 <bc14f4f1a3874e55bef033246768a775@AcuMS.aculab.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <bc14f4f1a3874e55bef033246768a775@AcuMS.aculab.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=BZ4SRa8E;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42c as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Fri, May 21, 2021 at 09:39AM +0000, David Laight wrote:
> From: Marco Elver
> > Sent: 21 May 2021 09:32
> > 
> > Since wait_event() uses TASK_UNINTERRUPTIBLE by default, waiting for an
> > allocation counts towards load. However, for KFENCE, this does not make
> > any sense, since there is no busy work we're awaiting.
> > 
> > Instead, use TASK_IDLE via wait_event_idle() to not count towards load.
> 
> Doesn't that let the process be interruptible by a signal.
> Which is probably not desirable.
> 
> There really ought to be a way of sleeping with TASK_UNINTERRUPTIBLE
> without changing the load-average.

That's what TASK_IDLE is:

	include/linux/sched.h:#define TASK_IDLE                 (TASK_UNINTERRUPTIBLE | TASK_NOLOAD)

See https://lore.kernel.org/lkml/alpine.LFD.2.11.1505112154420.1749@ja.home.ssi.bg/T/

Thanks,
-- Marco

> IIRC the load-average is really intended to include processes
> that are waiting for disk - especially for swap.
> 
> 	David
> 
> -
> Registered Address Lakeside, Bramley Road, Mount Farm, Milton Keynes, MK1 1PT, UK
> Registration No: 1397386 (Wales)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YKeBvR0sZGTqX4fG%40elver.google.com.
