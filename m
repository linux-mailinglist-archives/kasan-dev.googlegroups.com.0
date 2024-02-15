Return-Path: <kasan-dev+bncBCS2NBWRUIFBBNGJXKXAMGQEWSUYQ4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7484D857221
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 00:56:37 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id ffacd0b85a97d-337a9795c5csf884643f8f.2
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 15:56:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708041397; cv=pass;
        d=google.com; s=arc-20160816;
        b=qpC12FMdsHuIKId+HKYh4pruECbbynbmDmCNHJbHOJ7Nx68nuDKQ5gRiutOkhdi0PH
         t6u9wA5oOczfz5nw0eg5ViBwGQEEkIeGsvq+I0OLufTRXVEUAmdLx2+fs2fz2ymnFOVE
         eVSTcd8QG/9zNpyjW+3+XPxy1RImkKgbIOjFu6Q6BjA9moIzVYYS1S65sBxRetsgmXu/
         47K7L5GpPbIXAAbmihgEivnmC6e+axqZKC4qdT8+EEgallHce0SHSGeafqhkr/QXypYo
         WL6KSk54meh09wa1yEQhLzVK4mQAJSZ01RmgvV6WsGiP7Fl2ykKzEEO4zTBjMrbW3ewQ
         ahBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=5vDZSG5M62qSLOJ6oa3vGSWLYimWX7dfAHYv3ej4HUc=;
        fh=VpMvIWix9h/Vuk576V0U1WyLOEuRqihF//WSiZk+7rY=;
        b=xuLIul7x97KklqvsQeBMlZH5cKaF6GGnfgPfQ6kQb5goi+mvm8ODA33J4jCYW1io7E
         7BHKU9z0qzL64y+yekeAmrA4i+51zjflz6m+oFr+Grqd6OHVjCZy/qFbjdk26uOJxFv+
         MnTnU+4rNpChgiUuvjGtzNunNIMQAEvP5zU1VjYy+o/iTFdRu2bTtzjaXrczt2DcVCcm
         20MVXciwBHUBCNIQn4waUJv068NQE8yfN4r08uLW6Gr2rB40m9fv9PiGoerqqjCZlQm9
         +0Pr0NYJ+E0qBlNivx8CKBl3C5Su2HiJ1EQvRijhwwzhqk8AMXHwGzrZGWEDgRA2BjOu
         FqWA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=W8aCebO2;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::ac as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708041397; x=1708646197; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5vDZSG5M62qSLOJ6oa3vGSWLYimWX7dfAHYv3ej4HUc=;
        b=iSWhJ1PLofcc9npCqFHNAr9kpLHw89BvmuctXHfGSgTh3HlQpDix5F1ffa+XlvBHWE
         gyjk0z7dDuss/jYS+SX3Mp19svtF3rr1O0iLrDjGgncGDlrxLuGM76bXEkJseCterjed
         yGRYul6Dg/aBS6NGFDHaNF8EfRoRde5UAGFTjHo2ANCrkS5LZAgHVQ2bh/A2roZPqvqM
         aBNLWpQbgEFNO4oM62XIFWoB1J9+UaEwAUZCRhB6v6Xp1GAHCQ1rZNwvLQkNTvcU1sgd
         KL8P3xoo2vRlOR7tGFsy/NBj7vi4F8qRTl2zViXWZbdCKciRJ3yo9GTbkMvuhtN0NBc0
         haxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708041397; x=1708646197;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5vDZSG5M62qSLOJ6oa3vGSWLYimWX7dfAHYv3ej4HUc=;
        b=kn3hE6UWNEsgD5YkG7t93BEsDLlHO5TO4HSZVFLw1yVzr4+vSXeLf3aLb9/Rnz/d1r
         wdLXyCwuOimEMXr9Mw65kzaxIPITnxJFBDeahojAfM2aki5YgSn8eBeNw2znxr0SPMTD
         o+prbS6bgsRvGP3OSCYow0Ve2hG/p0+PtpEjjPNWW6chB8s8SgdnJWNeruu/tQ9PuF5K
         KsHo6e+9e9Ln8QaYE1sYt036w8uwHbkO8n1mr62KpQhlTvpJhQBwXKPJdAwB6OllQzIl
         gFFHY3GTiEJWr0aQwAUlTU64AYbBo2sYcvQAO9P33kxKeo25sQqUwXGPqO6Ttvfgm9qt
         ZY1Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXhVcYCKdjTAIRs1pgHpmALfKW9sD7xV4cB5c/GZcW0TkQaAPybZo070xvsvmr2qqmqAF0yRZX7IzqKgBeD7tVYsqhUVULYSw==
X-Gm-Message-State: AOJu0YxqAHu8GRWtUAEDhO6hoOUpLGflnAPxyKlYJ465FkZ0+9m32bn8
	va1EJvIbik9YhB7CU0BdyQiOlQRWDQww1j0O9UBktHV+bUV/gn/F
X-Google-Smtp-Source: AGHT+IHgqPThTS5nNiGEwXnub5E61WNnQVntYE1Nv2dAXG9wNMJo3gaDNEw1sujq/KvIYXfcd7Tpqg==
X-Received: by 2002:a5d:64a7:0:b0:33d:ed4:5c86 with SMTP id m7-20020a5d64a7000000b0033d0ed45c86mr2612141wrp.63.1708041396512;
        Thu, 15 Feb 2024 15:56:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d8f:b0:412:430a:b25a with SMTP id
 p15-20020a05600c1d8f00b00412430ab25als28323wms.0.-pod-prod-02-eu; Thu, 15 Feb
 2024 15:56:35 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWfkCL+0qKsRmODlA4VrOX5bAvKB2adwZ3hoPAzWIeS8Hlm7EfxmFYXnf2UX+ubNp+VcJYfFz+K9OBV6b2X3tNDenOazB7DZecqDA==
X-Received: by 2002:a05:600c:4f82:b0:412:11ad:b891 with SMTP id n2-20020a05600c4f8200b0041211adb891mr2247949wmq.6.1708041394956;
        Thu, 15 Feb 2024 15:56:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708041394; cv=none;
        d=google.com; s=arc-20160816;
        b=BqL3xMfIVfzWu+XusJm+2/Gq0KnPewG71uwt9Tl7iB/vtKfVWzPaDSTNmO9KWZ8Hpq
         4YdKHzwTOeoP1gQA8e8FEjTU5ynD1JdnQ2Ww2PFABfslCm/sV5j/bDHlYqrRhMUQfWqU
         0QNwGTru+wkkzXmeogWrJeFmvtVAg73NRBoAgRJ0xhRVfRTBzH3usPs3JcILDBwTj1+e
         9Qy7rAbxIVYN4ZczoebpJgbCAzi+D6GH/GgLeHcysbQqYAXo7uGRiDWl2LBB+8yLXFAE
         Yv5oTk4uGOYc/c/7xRDArCyjIaMf5eki+QzPaUzWaoEjK3REOglLFA3T7enWy2YBeE1K
         0QEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=52irb0w7kCnlBvMxLW0+SFuqopgYfciVJASMwoihRhE=;
        fh=OiwBIvYIPHGDMdlNleqgT10F8L7VFJzUbQ6V59nSWw8=;
        b=CxMbRFCyzSiy02Nu/i8GMVMbD8og4wfH3HNNbee5qHiXyuIXu48yb0STrzS3xUAwOf
         MiBUjYRj5wHHUq797xtmC2m7AIe9gUWNDdFpL0vRXeweREx9GJDLvSGBhNUaXGU1EqIB
         cEb1WzMAksTYjlkPM3clo72gftPPMJRMVnXtNh2REDQ7riTaCIdIHgG3mTqq0iOUtpvk
         uODdadaQZfUVKRz0F6DvyvsjUMqH0AHWgryCipLdHUdwMRWIVlkT4QX/qajfvNiOLCKa
         EBJ22DTQxvoNn56k2qX5NC1IamZFZOXGQpq9BpaWEANbFd1eyRXgoDUzOyU/yavd8PBs
         E8XQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=W8aCebO2;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::ac as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-172.mta1.migadu.com (out-172.mta1.migadu.com. [2001:41d0:203:375::ac])
        by gmr-mx.google.com with ESMTPS id t15-20020a1c770f000000b00411e6247f00si8506wmi.1.2024.02.15.15.56.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Feb 2024 15:56:34 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::ac as permitted sender) client-ip=2001:41d0:203:375::ac;
Date: Thu, 15 Feb 2024 18:56:23 -0500
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Steven Rostedt <rostedt@goodmis.org>
Cc: Vlastimil Babka <vbabka@suse.cz>, 
	Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>, akpm@linux-foundation.org, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net, 
	willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, david@redhat.com, 
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, 
	dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org, 
	paulmck@kernel.org, pasha.tatashin@soleen.com, yosryahmed@google.com, 
	yuzhao@google.com, dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v3 31/35] lib: add memory allocations report in show_mem()
Message-ID: <mi5zw42r6c2yfg7fr2pfhfff6hudwizybwydosmdiwsml7vqna@a5iu6ksb2ltk>
References: <Zc3X8XlnrZmh2mgN@tiehlicka>
 <CAJuCfpHc2ee_V6SGAc_31O_ikjGGNivhdSG+2XNcc9vVmzO-9g@mail.gmail.com>
 <Zc4_i_ED6qjGDmhR@tiehlicka>
 <CAJuCfpHq3N0h6dGieHxD6Au+qs=iKAifFrHAMxTsHTcDrOwSQA@mail.gmail.com>
 <ruxvgrm3scv7zfjzbq22on7tj2fjouydzk33k7m2kukm2n6uuw@meusbsciwuut>
 <320cd134-b767-4f29-869b-d219793ba8a1@suse.cz>
 <efxe67vo32epvmyzplmpd344nw2wf37azicpfhvkt3zz4aujm3@n27pl5j5zahj>
 <20240215180742.34470209@gandalf.local.home>
 <20240215181648.67170ed5@gandalf.local.home>
 <20240215182729.659f3f1c@gandalf.local.home>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240215182729.659f3f1c@gandalf.local.home>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=W8aCebO2;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:203:375::ac as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Thu, Feb 15, 2024 at 06:27:29PM -0500, Steven Rostedt wrote:
> All this, and we are still worried about 4k for useful debugging :-/

Every additional 4k still needs justification. And whether we burn a
reserve on this will have no observable effect on user output in
remotely normal situations; if this allocation ever fails, we've already
been in an OOM situation for awhile and we've already printed out this
report many times, with less memory pressure where the allocation would
have succeeded.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/mi5zw42r6c2yfg7fr2pfhfff6hudwizybwydosmdiwsml7vqna%40a5iu6ksb2ltk.
