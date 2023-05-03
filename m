Return-Path: <kasan-dev+bncBCS2NBWRUIFBBKN6ZKRAMGQEWR4F7MY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id DE7476F5D48
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 19:51:37 +0200 (CEST)
Received: by mail-ed1-x53a.google.com with SMTP id 4fb4d7f45d1cf-50bcaec14c2sf1056027a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 10:51:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683136297; cv=pass;
        d=google.com; s=arc-20160816;
        b=M4z2swe+CHO1bxeqdSHkmbh2QAxCTHHAxo2nfGaMZtZFSWbbJA86aHvuWRvY+4KfrC
         ErNQs3LJod1mvsxPjSRXbC4ZEnLSWkoKJtc+XxqYt//LWqmuft2fYvYcQqSq0homOeT+
         R+/hubbtwr/QGLUlNCW3a+pg7vAmbAFQD9ZHIROMuBau0xTI5jOvVVBtO4pR+oEAOZam
         TQt0OL8ghy687xpknp+NaD+MENgGhXwjnOjTQEYYsMlxqEWvcbOC0CZxDf1/yFpUD9Od
         dJbOj6jS3EwaOGEnLB3ykNsNAc1KblWEct9UY3WJ0Edmu5TJh2nfze/9pnHANje/ABbf
         ivHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=2LrmW2V9wbFaXweyHyyv2ZcKWBbbJL+S+l+dvm1CEBc=;
        b=kuVdyMaKt1Yhz6DKz/Rt45hF1TiDrRrjQjD2PIiSiS/x6HJmT8nqqv9zPcWv65O3Ay
         s5YlHFE+sbM07De6SEab/PN1BEWih4lnD5Zt/zINMEzsVIX19xQjQx7V1Mqy2QVo3Q3n
         ZmV+rKTDA9ELfhAA5A6qFsJ95BC6Fa2MNemOnoV2e05hM6g1c/be1yvaeLkC3XLOUOhA
         wQVhe/EojzdR+RJ6HIL374aADJizqKtZcb0uc1Q+crPnGGiv60zdokNfF9Plk8a7WBf0
         pmUeTBno9QHJVHqjxG0kX9/OSmf5L0dovcUnlR2ln1fYg1rZkEDYspm/+p2nSzLcFRJq
         yZhg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Jly2gSOT;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.40 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683136297; x=1685728297;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2LrmW2V9wbFaXweyHyyv2ZcKWBbbJL+S+l+dvm1CEBc=;
        b=YYWeqUab/gdNORmRs90sCDImDJ0DkI5xYvL/NIVr8Hbn1QADGwy0R505KzeKgsyBev
         uwxmDiZxQgqvMGYbHwz8JNtFIw7390ACNN+FFMYu0CpIAJKn8h51WPmy2W4eCmpRVMZC
         t4vOm9FO2f7S+tXYE+1tJqOfzzXZ38avMZgTQn4u3Na+b7xDOxivMKKv20fmh0SzlCns
         Ae+iMVp6SOKqRyjf7gQQjGYYSqUp0iwZWKsdKreyCuxCtd6c38bE3qhWjnhWqemmsfY8
         GqFQz6BfVHYuKxSrBRhySjB4j6n0uWv1+G6R3njAvkgZ8StV7pFK0NXLmi8kFLOgsV/Q
         IC+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683136297; x=1685728297;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2LrmW2V9wbFaXweyHyyv2ZcKWBbbJL+S+l+dvm1CEBc=;
        b=UC1Ch6DPPK5e4S7gFUyzNogCvgquijqxfd/whz64vUvhQHW/I1HGbB3YMtqLTQIkGf
         SBfFsIX9foWmsY7/mo22nuL2eQlJUZlvx0l6mvMoyz/Zx38D8iviXQ03sCyTVfc5sXi/
         96NNLMB4QqCL6Tj3Tn6YQZP36t2jYgCmwoeVonZLz68ac4xJMvDQWDHZpYJlrHzKo2az
         KYjunfRdsRkEwc0uqrkIDOZ5xSnwp0WWuMpI8shEmlHHu64SFWEIVVNFeQr6C59Olj/g
         gx+JbgV02I0yYhgTLmEpZrqK44saP+i0cXGRT54JM/AvTvr+0MIyvBo1O8Dz4gi1s20T
         rEIg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDw79Z5Pg7Q5WS8rvtqEikKJs9LFZnKtnjhbUdcUKxJBlhzuVDan
	UccPG0HlCXDxfEdsjhuMNpA=
X-Google-Smtp-Source: ACHHUZ6XsirGRRbUAzW4kTt2N4RS5djycawH172oRkE4UTUg7rUkk7RK0bPHC5tDsoNAivth/EES3Q==
X-Received: by 2002:a05:6402:4496:b0:506:6a99:ef53 with SMTP id er22-20020a056402449600b005066a99ef53mr1273924edb.2.1683136297244;
        Wed, 03 May 2023 10:51:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:35c7:b0:50b:c404:41f5 with SMTP id
 z7-20020a05640235c700b0050bc40441f5ls8701924edc.0.-pod-prod-gmail; Wed, 03
 May 2023 10:51:35 -0700 (PDT)
X-Received: by 2002:aa7:c2c7:0:b0:50b:c69a:da36 with SMTP id m7-20020aa7c2c7000000b0050bc69ada36mr8977959edp.12.1683136295907;
        Wed, 03 May 2023 10:51:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683136295; cv=none;
        d=google.com; s=arc-20160816;
        b=RzR1FPMVWCtZqm8fmNfjkFQJV1vrg9plRV6NZfAbvt4jur2A5c9TprouekO7mvCEd9
         GpYVJQkTh6t/tZfVMluweorcO/Qr7Z9Zt9rnen9kVYnKR7zGTT80AD9NTicQo2+kehUL
         OOPQ4vhJpZRY0fZsVdADRbSfa4O0y2RHWQ/n9EX4Pb7YljM/Y2z/6Ao2+fdKn7yns/vC
         OMdatkpbRpi6cjZJQ+npdP4MOjj8M+vV97MZf/IDrzzHEbAZV2lIpARaJQmBr21bOYOH
         2hNrpGcWLwPTsRdpGsipdB1DDtE5rGm1cQykgoqhEF7j3lcFFhZW83VH0QDbegthWpEO
         4crQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=/8YhiaEwKxHE5nN6YeY/72JOBihWRYRCXK0QvEQ+Qv4=;
        b=mkV9rzHCgcu0qzUgLc2VRJYQ4HAHZiNJjCA73mpYRHu3lRRN+x2kBzadr4YgFJm0cn
         ojJfUztWW6MBaINKchPuQg4apkXudeWeQBHoNJ6M4t3zW0pIZgfjpimPba9tB0UHJYg6
         ccv6QXUNOdnh+x2bDfYJl9icYb5nAgY2H1KcfcezHSXqlYNW1VGKSj5ulZZzLnlqwTWP
         h9iL08z4WOoAOr2XizG8ABaBe5s0HFnK1QlP/uP7qXLHqifDeYC5OrXE/LmdgS1MGzsx
         uhIQ7um3fScR/nOexPjr+uHUz1Lk3cEHcwbKNhQWoA8ISW8MUqtk0/C/rCFfCHi+RA57
         d30w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Jly2gSOT;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.40 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-40.mta0.migadu.com (out-40.mta0.migadu.com. [91.218.175.40])
        by gmr-mx.google.com with ESMTPS id d12-20020a056402400c00b00506bc68cafasi127951eda.4.2023.05.03.10.51.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 May 2023 10:51:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.40 as permitted sender) client-ip=91.218.175.40;
Date: Wed, 3 May 2023 13:51:23 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Tejun Heo <tj@kernel.org>
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
Message-ID: <ZFKfG7bVuOAk27yP@moria.home.lan>
References: <20230501165450.15352-1-surenb@google.com>
 <ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
 <ZFIOfb6/jHwLqg6M@moria.home.lan>
 <ZFISlX+mSx4QJDK6@dhcp22.suse.cz>
 <ZFIVtB8JyKk0ddA5@moria.home.lan>
 <ZFKNZZwC8EUbOLMv@slm.duckdns.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZFKNZZwC8EUbOLMv@slm.duckdns.org>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Jly2gSOT;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.40 as
 permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Wed, May 03, 2023 at 06:35:49AM -1000, Tejun Heo wrote:
> Hello, Kent.
> 
> On Wed, May 03, 2023 at 04:05:08AM -0400, Kent Overstreet wrote:
> > No, we're still waiting on the tracing people to _demonstrate_, not
> > claim, that this is at all possible in a comparable way with tracing. 
> 
> So, we (meta) happen to do stuff like this all the time in the fleet to hunt
> down tricky persistent problems like memory leaks, ref leaks, what-have-you.
> In recent kernels, with kprobe and BPF, our ability to debug these sorts of
> problems has improved a great deal. Below, I'm attaching a bcc script I used
> to hunt down, IIRC, a double vfree. It's not exactly for a leak but leaks
> can follow the same pattern.
> 
> There are of course some pros and cons to this approach:
> 
> Pros:
> 
> * The framework doesn't really have any runtime overhead, so we can have it
>   deployed in the entire fleet and debug wherever problem is.
> 
> * It's fully flexible and programmable which enables non-trivial filtering
>   and summarizing to be done inside kernel w/ BPF as necessary, which is
>   pretty handy for tracking high frequency events.
> 
> * BPF is pretty performant. Dedicated built-in kernel code can do better of
>   course but BPF's jit compiled code & its data structures are fast enough.
>   I don't remember any time this was a problem.
> 
> Cons:
> 
> * BPF has some learning curve. Also the fact that what it provides is a wide
>   open field rather than something scoped out for a specific problem can
>   make it seem a bit daunting at the beginning.
> 
> * Because tracking starts when the script starts running, it doesn't know
>   anything which has happened upto that point, so you gotta pay attention to
>   handling e.g. handling frees which don't match allocs. It's kinda annoying
>   but not a huge problem usually. There are ways to build in BPF progs into
>   the kernel and load it early but I haven't experiemnted with it yet
>   personally.
> 
> I'm not necessarily against adding dedicated memory debugging mechanism but
> do wonder whether the extra benefits would be enough to justify the code and
> maintenance overhead.
> 
> Oh, a bit of delta but for anyone who's more interested in debugging
> problems like this, while I tend to go for bcc
> (https://github.com/iovisor/bcc) for this sort of problems. Others prefer to
> write against libbpf directly or use bpftrace
> (https://github.com/iovisor/bpftrace).

Do you have example output?

TBH I'm skeptical that it's even possible to do full memory allocation
profiling with tracing/bpf, due to recursive memory allocations and
needing an index of outstanding allcations.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZFKfG7bVuOAk27yP%40moria.home.lan.
