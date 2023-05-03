Return-Path: <kasan-dev+bncBCB5ZLWIQIBRBMGLZKRAMGQE3A4YM3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D39E6F5DC0
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 20:19:29 +0200 (CEST)
Received: by mail-qk1-x73d.google.com with SMTP id af79cd13be357-74e26504096sf316980285a.3
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 11:19:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683137968; cv=pass;
        d=google.com; s=arc-20160816;
        b=L3Z+Mk/3h+SDiUoWkSUbDMS8cN2MJFaWYKc7jjnN7eCRfrR5Q+ZssxbrSk3q6v3W2d
         YCF9nHQ++dbyPgCGEkQu0n/mcuscjGhl0QZmKtT8OccvyHInygBPJt031apdiMKEkCpM
         k+SaafRqLk8TGH3A+B9AN7bkk35L0Sw0QqRHmuIv9qET9j1DTn21FbW9XIcWYq6gkyEY
         nZvJu9ETRVeoTy9M1CHvaCwGPJdyJ0o1b4g9nJUEcqyOi9OG+AcrllUcDTtdEZ/Qop5b
         gOoXgWewevdyIohI+Alu8cebKAsa8BakodUI/n6VBhpA4DF04Oftxtke/NzDJ62jiPBa
         CnDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Au4JAiTWYVKAUWVJGnGzuBp+hDigf7DqMpC65u5mbGc=;
        b=H5g2r+CSgXnftfNkCsHT6JyuxAAbwgPbw2GblkFZaPJqqA7Lf5NaSmL3neh0yTWtNj
         SjwjFOwZxivfG6BvO/1gfPdaCso2ipQa+vqBpSDubbZ5jkiYku9h/7DcNHs64Q8/4M6n
         soG8mvrg4703ERIthQe34uIjRa2Zxtw6lmbLWYvmNMa4XJ/yWrgYc7ShB3fmKKAD2rV0
         8YYw3JswrizNpF6WY6+C2iUKoT+nrLFvfvji8MkrewvtCKWVFYi1P2JfTNbEgTBLYApN
         3od86yI7NwnMDEkfpOTh2aBoK6yiSuZVbebHVGZ3l+gN9Qh04UiU82JRaw3h6jup0BuD
         8lEw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=aZNjJ0sK;
       spf=pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=htejun@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1683137968; x=1685729968;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Au4JAiTWYVKAUWVJGnGzuBp+hDigf7DqMpC65u5mbGc=;
        b=M5WaO5YEk8EMsGCsgEXCJVWgonQSRwjYnISOskaofDzIIZteQOHOlWFwLOcj+0wcz4
         HfH4mvO/9NpOxcEPJ0gtndhzGVcjaF7H29eYXiKk6pnq6iGateDQQxWnYMNx/W9VBU8/
         tEdtpZBFdOxN1F6IwsglUXoS1cow+y50VgpCyife7/9vPLj5keKkCdDSOHce/TwD2tZb
         9n8WhJpbC4uPqA9nyjqGPpY/jfZzLl9KQfqXXVd+jzR7XNxihHEzuyd4fHLKYFTnFLZl
         KTqzPQOhxxnkUosfHa8JstLRQzncXs9hKdWXXYUe41umuHmpLrXIcqLDgxlItMylPxDA
         KIlA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683137968; x=1685729968;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Au4JAiTWYVKAUWVJGnGzuBp+hDigf7DqMpC65u5mbGc=;
        b=DUaAcFwVwHQGsqyK3bhwD68btOkBreKHg4EeJrap4Y+4Ir9dP0iy6wa9FXHdgj0dBV
         QDNSd9VBVrEQcsWUsTCSifo2oseFk3UcJNGr+9WlGiDx6gGV74p6eaKbYTCRZ26UQxWC
         2PZgdpWaRGHB9UZupMS9oIuCplL53+iVcEfM8pp2J9dWpbf/gAXXRDCzuCg9OC8Ed5wR
         T8r6UJtbZiHG4Eqk4IwS68L65vr20B2cY0lG5s3Hx765Ai6bGFEaAEsbkIbN+XvEsNmc
         kuu28wTtTm8/4F/oxTMxBW63J7E7posQuk+u4xDV3DNDCq1gSHIc+dXsykrW8veT+TaH
         b40A==
X-Gm-Message-State: AC+VfDySWP+xOsP68IfAy3E4zDYENbLn5Yw1h0eH3T+osk1ZYBCb+Zv4
	H2bJESewaTewqEbqk86QwxFZpQ==
X-Google-Smtp-Source: ACHHUZ4XKl3Bl3AxArvzdet1dA+05iMPhiyLlruGzsB28YkMDqKwO6BeEtmFC22Gtu6lUx6z7hF1dw==
X-Received: by 2002:a05:620a:15e7:b0:74d:1be5:f1a3 with SMTP id p7-20020a05620a15e700b0074d1be5f1a3mr3785798qkm.15.1683137968282;
        Wed, 03 May 2023 11:19:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:53a2:0:b0:5ee:87d9:b564 with SMTP id j2-20020ad453a2000000b005ee87d9b564ls10902463qvv.4.-pod-prod-gmail;
 Wed, 03 May 2023 11:19:27 -0700 (PDT)
X-Received: by 2002:a05:6214:248b:b0:5ef:4bdd:42e0 with SMTP id gi11-20020a056214248b00b005ef4bdd42e0mr11993861qvb.51.1683137967678;
        Wed, 03 May 2023 11:19:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683137967; cv=none;
        d=google.com; s=arc-20160816;
        b=L/aDjzd0jbK3X6ki4vnnCJZ0I9HfmCru1pSbnvQhRhm3hhKSpqzzynnDcOIPWlOvG+
         iWNjjNcgN/zJq+a/+lpa+T1lOXQ5w+DwKWO9zZijjWvbanS3QuJwZeLPKbZbx7Y5OsVD
         mQdYRhFKsAesIRVI5AlFOOtgiEoNa9NXLJkTNlld5RCT5jFM/eWjT4C2Ryp9jhnAAS3n
         /oC+/VQzpQwQcbbqg8TGDOdNzgS7uSuruq7oKZI39pNA3azhzrlNpNkSLMkrrclAiZR0
         QS23OGnRNge3PhZxq1ZUK+2yf067MsLqqh4f+DcoS3Sl8t0KQu1xY8m944p9ZJ0S/ZH6
         Z9cw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=b8EyOQL7PrYcjENM7voIrei4tZKK2YZzqm7TQH+pwlU=;
        b=Hk0n1KuQrbeoZ+AU+V8Nk9tJ9/SdxTqKbSjDBup2Oc8PrFT97aavS5Xafsqv7DlpP7
         43QKRsgE7W/yrZ4xPS0q5HFbj/0Cbtree+H2fi1SvN7aB0Q/EwK9sCRKAihjgGzqYowb
         UVhH2eTUEZYXnfqEedvoFz3ApKo18jGKRzhEgzhSy0Frj/pfDJSapaSaBivSGQbpHr79
         m/JT5fu6Il89L4DcuH1HimuiXQoQpRy/vX4eFzTjCaXD1/7FSBXe/xiMfVcxObezd0IU
         CRNM/jDJG3KwfD6xS/++mVf0OgxAiOsw4IN/GPXOHNrCm7dHUnXlHN320pU0Ouquft0o
         Nwag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=aZNjJ0sK;
       spf=pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=htejun@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-pl1-x62c.google.com (mail-pl1-x62c.google.com. [2607:f8b0:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id t13-20020a056214154d00b0061b64963d98si426629qvw.6.2023.05.03.11.19.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 May 2023 11:19:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::62c as permitted sender) client-ip=2607:f8b0:4864:20::62c;
Received: by mail-pl1-x62c.google.com with SMTP id d9443c01a7336-1aaec6f189cso31880345ad.3
        for <kasan-dev@googlegroups.com>; Wed, 03 May 2023 11:19:27 -0700 (PDT)
X-Received: by 2002:a17:903:11c9:b0:1ab:16e0:ef49 with SMTP id q9-20020a17090311c900b001ab16e0ef49mr1056514plh.24.1683137966573;
        Wed, 03 May 2023 11:19:26 -0700 (PDT)
Received: from localhost ([2620:10d:c090:400::5:6454])
        by smtp.gmail.com with ESMTPSA id s2-20020a170902988200b0019a7d58e595sm21845154plp.143.2023.05.03.11.19.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 May 2023 11:19:26 -0700 (PDT)
Sender: Tejun Heo <htejun@gmail.com>
Date: Wed, 3 May 2023 08:19:24 -1000
From: Tejun Heo <tj@kernel.org>
To: Johannes Weiner <hannes@cmpxchg.org>
Cc: Kent Overstreet <kent.overstreet@linux.dev>,
	Michal Hocko <mhocko@suse.com>,
	Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	vbabka@suse.cz, roman.gushchin@linux.dev, mgorman@suse.de,
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
	corbet@lwn.net, void@manifault.com, peterz@infradead.org,
	juri.lelli@redhat.com, ldufour@linux.ibm.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, muchun.song@linux.dev,
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
	ndesaulniers@google.com, gregkh@linuxfoundation.org,
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org,
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
	glider@google.com, elver@google.com, dvyukov@google.com,
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com,
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
	kernel-team@android.com, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	linux-mm@kvack.org, linux-modules@vger.kernel.org,
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org,
	Alexei Starovoitov <ast@kernel.org>,
	Andrii Nakryiko <andrii@kernel.org>
Subject: Re: [PATCH 00/40] Memory allocation profiling
Message-ID: <ZFKlrP7nLn93iIRf@slm.duckdns.org>
References: <20230501165450.15352-1-surenb@google.com>
 <ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
 <ZFIOfb6/jHwLqg6M@moria.home.lan>
 <ZFISlX+mSx4QJDK6@dhcp22.suse.cz>
 <ZFIVtB8JyKk0ddA5@moria.home.lan>
 <ZFKNZZwC8EUbOLMv@slm.duckdns.org>
 <20230503180726.GA196054@cmpxchg.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230503180726.GA196054@cmpxchg.org>
X-Original-Sender: tj@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=aZNjJ0sK;       spf=pass
 (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::62c as
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

Hello,

On Wed, May 03, 2023 at 02:07:26PM -0400, Johannes Weiner wrote:
...
> > * Because tracking starts when the script starts running, it doesn't know
> >   anything which has happened upto that point, so you gotta pay attention to
> >   handling e.g. handling frees which don't match allocs. It's kinda annoying
> >   but not a huge problem usually. There are ways to build in BPF progs into
> >   the kernel and load it early but I haven't experiemnted with it yet
> >   personally.
> 
> Yeah, early loading is definitely important, especially before module
> loading etc.
> 
> One common usecase is that we see a machine in the wild with a high
> amount of kernel memory disappearing somewhere that isn't voluntarily
> reported in vmstat/meminfo. Reproducing it isn't always
> practical. Something that records early and always (with acceptable
> runtime overhead) would be the holy grail.
> 
> Matching allocs to frees is doable using the pfn as the key for pages,
> and virtual addresses for slab objects.
> 
> The biggest issue I had when I tried with bpf was losing updates to
> the map. IIRC there is some trylocking going on to avoid deadlocks
> from nested contexts (alloc interrupted, interrupt frees). It doesn't
> sound like an unsolvable problem, though.

(cc'ing Alexei and Andrii)

This is the same thing that I hit with sched_ext. BPF plugged it for
struct_ops but I wonder whether it can be done for specific maps / progs -
ie. just declare that a given map or prog is not to be accessed from NMI and
bypass the trylock deadlock avoidance mechanism. But, yeah, this should be
addressed from BPF side.

> Another minor thing was the stack trace map exploding on a basically
> infinite number of unique interrupt stacks. This could probably also
> be solved by extending the trace extraction API to cut the frames off
> at the context switch boundary.
> 
> Taking a step back though, given the multitude of allocation sites in
> the kernel, it's a bit odd that the only accounting we do is the tiny
> fraction of voluntary vmstat/meminfo reporting. We try to cover the
> biggest consumers with this of course, but it's always going to be
> incomplete and is maintenance overhead too. There are on average
> several gigabytes in unknown memory (total - known vmstats) on our
> machines. It's difficult to detect regressions easily. And it's per
> definition the unexpected cornercases that are the trickiest to track
> down. So it might be doable with BPF, but it does feel like the kernel
> should do a better job of tracking out of the box and without
> requiring too much plumbing and somewhat fragile kernel allocation API
> tracking and probing from userspace.

Yeah, easy / default visibility argument does make sense to me.

Thanks.

-- 
tejun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZFKlrP7nLn93iIRf%40slm.duckdns.org.
