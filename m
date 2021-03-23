Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNNA5CBAMGQELGENFNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 970F8346407
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 16:58:45 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id b6sf1287499wrq.22
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 08:58:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616515125; cv=pass;
        d=google.com; s=arc-20160816;
        b=SWfE5M3jILSbMRm5IIG1YuEngz7LLkmCe6evHtyPAH/Dv04BLnQHH/upRS1RNzFfya
         g5zzpXfyHKwLRlKRzWqiFc0sy+iWHx5u1ZhUgGTLvt6Grgp6Y64YauNWAayRY1ydFUGB
         kWaXVbL84PQp8fvEkH9M8ksQrS8REO2fzlZ8/LuD/UWoeHRTEXyMdIf5VMfxUzpxPx1Z
         z2fkMhXr2o2rcSu8FEFXqvM5rYxngURM7/IAwNjz+Mpq7ko3D/B5N3aNu3Zy66u88fvs
         zqEJ18eY+8qgpTzhGRaZf8tGtShekOnvDZeHjZBctJSFLFiIoVo5F7H4bk9Hc/uf5L9W
         zzqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=znZLdZkDmwhN3Dmd22W97aEO8MNUcdHRPUaSAGJqElQ=;
        b=jARHh5dJfo0jid51fWeKCZJffs2nziI7UH/3PP+hnTakQNIO958k+Sc3nq7zdG7c3t
         vuvg4V9nflggkArs46b4lccL7rIhN4oiAIZ0L/XUPCWCCapQeciTKSfnF12QZvvmjeKk
         0C0dQwc1KOLWtUcDt/3aTtmWBjA0ZDn71hc6hKm3+oavi4nEgw/BE7nrFF+QISTeWsel
         zeCk/KIlvVebQrRnUDPmNzNMRYOz3s4rF2f9FF9owulzb5mC+3zd/kz22dUNr1/LEkz0
         Zy/nKVabSel+cMHsTnCGJ2amK2VZqedYVhFx6edIf8jB2dZ4n1Scr3BuLSQ1GkTf2a9Z
         I5tQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QvHJQk94;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=znZLdZkDmwhN3Dmd22W97aEO8MNUcdHRPUaSAGJqElQ=;
        b=ea4GSQ3c7kBhCZ548bwLMq5IvVUEZF0JzyYMc2hRwU6wHBOkbcjkjQgIWD5BsiwZpb
         +MGZsQxtYz2mlDOMnDOa0/3Vxzpr7Udpjd/AV5PV0wyNopv2+uS2vrsfItLdpn+aDajX
         l/isyOOD84HCpj/ls74JDsOSX2nCsooh2Z6ZoyCuNiLgGSQrzcjvq1bAdTMA01SjcfrL
         iCa6WuqxQe1rkFsYi60bEs6QyAtpnCQNRZNPDGl+x9/uLtFAlgR4I8OvnZYj4zhW0w/s
         EbaPvQS4VdJhvhVjqsJ0fVmWYsJ7mVcAzuPWgsdM6ElZP1LtWM7OT8TVi8V9X4K0IUWr
         q1Fw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=znZLdZkDmwhN3Dmd22W97aEO8MNUcdHRPUaSAGJqElQ=;
        b=XYEDd4eLOYCJC2ozuocUbjpUxcfi5L4la+fJCDt6y86rMl89BSG823t4Vv3O1cf4JU
         7L1umVlKgGic+vyB7rNeozoV8ND7VO3956H+Hc4beeCWeimlN5us6UyH7dPHA7Ant035
         9ofyhfW/9qbg1yKjWIeIn4tl1ppvDSPWGBTXXhJ2BLHWKthIFBohI7g7p7JNCtwjfXPH
         +3vm3S8xfduOcvWmhb31c4g6I6PhqiPC+7wv/H+X9GcXhaMpGkdnAruoKAhwp3o+Mk0x
         6QSD6h+texPhbfSwgWPUpueUXiAKus+vWunyPr465vMLV1tXH4L6/sUY9rrHA/5QpoIl
         NOqQ==
X-Gm-Message-State: AOAM5330XFxSsQp4zW/X9wKWkOjqyrheM0olDyIVXxaem/bwBOE/dIfI
	GoczuAUn0IR5ZA84phbYc3s=
X-Google-Smtp-Source: ABdhPJxDKetya8SLNf2hpuccCdylrvb8J5omc3GobEFYJdTJmC05Oxr/2IuZpmmhsswYbqFzt29duA==
X-Received: by 2002:adf:f60b:: with SMTP id t11mr4753977wrp.269.1616515125368;
        Tue, 23 Mar 2021 08:58:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6a89:: with SMTP id s9ls3550782wru.2.gmail; Tue, 23 Mar
 2021 08:58:44 -0700 (PDT)
X-Received: by 2002:a5d:6d48:: with SMTP id k8mr4706689wri.93.1616515124417;
        Tue, 23 Mar 2021 08:58:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616515124; cv=none;
        d=google.com; s=arc-20160816;
        b=IMf+VR/XskJSHPZCaucdogIPqoxyN06541a7oBLzbsK877z+mOPmAYcINVrBuqsV1u
         rkQPl2mBnQyfwl5l8cbjpOkdiZziblvWaYKBKl+F0PSXP45k5S+nwcMokWsdesmxmPVa
         Z9KP4jWnlsZKSsh4QfGsZmCpsgw1cRY0fzxzY1jAfspH7u1IK9JVwEo+E4aZeMWHPieH
         1pGamKR2aknSnY+CvlL3zfZEFIS6YTwsWusCl16YTpl1aZMelHhRqOxvEUT5OZs6Ants
         A983tiWU+yhrswhiLeTvVqGuGdFaNOISTqv27QypF45zw0y3mo/TiATD1ZxfOjHN+HVg
         RwiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=cyK9GwZbrXgU/Gi6qb7KmMrpgs6Gz19VbNc5ko69Bxg=;
        b=ac4NxXRHWXCqd5dHH+/YPbUW9aKeWkHkFH1y64MkpXX07fddf7kTYO5fuJYPlv/HpL
         VRlkQ+EW7i78AvHKDoQv9YyyAV9S7wCf0B5nF34ElUhMf1JJQ3F01oVlBYqci4jKQgKO
         mVU+5omtqfkTSMuP3rkD+HB4fMkA54tCrLGvpEXCHDoeG8ddXpQ2wP0wJYxFkuu2PwBm
         XWpsFDnSpNnCijgnUFaiT428btY/tiHsa9mxviBTg+scNht1BKdCxK767U6NLcOIeZ8w
         dVQ38cDsRRD6yLmD4C+9SCcHKu4I9mpVORkOJ03xaUgpib7I33tix5H4i91Mg2k3tkHE
         jzvg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QvHJQk94;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42a.google.com (mail-wr1-x42a.google.com. [2a00:1450:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id b6si180324wmc.2.2021.03.23.08.58.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Mar 2021 08:58:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42a as permitted sender) client-ip=2a00:1450:4864:20::42a;
Received: by mail-wr1-x42a.google.com with SMTP id z2so21323739wrl.5
        for <kasan-dev@googlegroups.com>; Tue, 23 Mar 2021 08:58:44 -0700 (PDT)
X-Received: by 2002:adf:dc91:: with SMTP id r17mr4692370wrj.293.1616515124001;
        Tue, 23 Mar 2021 08:58:44 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:4cfd:1405:ab5d:85f8])
        by smtp.gmail.com with ESMTPSA id t20sm3076962wmi.15.2021.03.23.08.58.42
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 23 Mar 2021 08:58:43 -0700 (PDT)
Date: Tue, 23 Mar 2021 16:58:37 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Peter Zijlstra <peterz@infradead.org>
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
Message-ID: <YFoQLfsZXPn9zuT4@elver.google.com>
References: <20210310104139.679618-1-elver@google.com>
 <20210310104139.679618-9-elver@google.com>
 <YFiamKX+xYH2HJ4E@elver.google.com>
 <YFjI5qU0z3Q7J/jF@hirez.programming.kicks-ass.net>
 <YFm6aakSRlF2nWtu@elver.google.com>
 <YFnDo7dczjDzLP68@hirez.programming.kicks-ass.net>
 <YFn/I3aKF+TOjGcl@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YFn/I3aKF+TOjGcl@hirez.programming.kicks-ass.net>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=QvHJQk94;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42a as
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

On Tue, Mar 23, 2021 at 03:45PM +0100, Peter Zijlstra wrote:
> On Tue, Mar 23, 2021 at 11:32:03AM +0100, Peter Zijlstra wrote:
> > And at that point there's very little value in still using
> > perf_event_exit_event()... let me see if there's something to be done
> > about that.
> 
> I ended up with something like the below. Which then simplifies
> remove_on_exec() to:
> 
[...]
> 
> Very lightly tested with that {1..1000} thing.
> 
> ---
> 
> Subject: perf: Rework perf_event_exit_event()
> From: Peter Zijlstra <peterz@infradead.org>
> Date: Tue Mar 23 15:16:06 CET 2021
> 
> Make perf_event_exit_event() more robust, such that we can use it from
> other contexts. Specifically the up and coming remove_on_exec.
> 
> For this to work we need to address a few issues. Remove_on_exec will
> not destroy the entire context, so we cannot rely on TASK_TOMBSTONE to
> disable event_function_call() and we thus have to use
> perf_remove_from_context().
> 
> When using perf_remove_from_context(), there's two races to consider.
> The first is against close(), where we can have concurrent tear-down
> of the event. The second is against child_list iteration, which should
> not find a half baked event.
> 
> To address this, teach perf_remove_from_context() to special case
> !ctx->is_active and about DETACH_CHILD.
> 
> Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>

Very nice, thanks! It seems to all hold up to testing as well.

Unless you already have this on some branch somewhere, I'll prepend it
to the series for now. I'll test some more and try to get v3 out
tomorrow.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YFoQLfsZXPn9zuT4%40elver.google.com.
