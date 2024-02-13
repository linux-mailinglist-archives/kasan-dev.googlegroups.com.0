Return-Path: <kasan-dev+bncBCS2NBWRUIFBBOPCVOXAMGQEXL72TMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 210BC8527F7
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 05:34:03 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-5612eb8848asf5793a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 20:34:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707798842; cv=pass;
        d=google.com; s=arc-20160816;
        b=X5qVP++B9fasVP4Ir2FZx23T+K7b3RvsFa7wKI9rJbCu85d/Ftr5rXGtg85gHMSL3z
         zumj1WshuvkaVY4zDobvr76xb/sVke4gQDhTA3K+jHIsXbR4SO1Ia4u7r4/B7KMWW+Vd
         h6oQa79GEO1M4OiIowFFa7zp9K9ztdRalstMPwCfF0EIgUI/TDtvDr+2az9fsD8w4Bho
         TYErLRsuu0PIKVW7fz+bJzyZwpzmqiJEWvRk0q463a75YtVr60B0ihFXv58pewy+ihck
         AlB22dAnrpm8UKADwWLRnvZUADGr22plr7xca+wxskK03kB+tJzI/0DNcaR9PYLmx+N1
         EMHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=g37sMGktKOUKioEVRaZ3z4XdaIrjzLP4GrV+qFDFlSo=;
        fh=JZ5LSSeyrdx4ryjNPm40dzzoR3gOnGjFGIN256z9nGc=;
        b=qnxnJTmp7yqiHrAlLqACjZLul5+oNtyLP5p4oKQAKz5CkuZ5++kPcu1pZvLOsds3Lv
         sGFmV97Fuf2GwVhCVTrWdgl9yzjzt5Xee0JYimeYfH18ZCLZyQ/12MwicAhXQ2VDUbCI
         wCCK6SN3EcsavlWZFx/CUAjXMsXaziddctsg3q17D/0NbF0UAn9ik48uKqnTa9sKsTcX
         x0h2+ybdLSD66CzHuOVvHUvkefQ+vHIt0Fdvr/00o3Nl0NK4Uyndgzqf8hCouLgMlH9v
         ibPo7Ldw2GNvUkp2vMGXOxdWP8CdpDPmbS6+cYiQ7wLXSL75/xRKTFPFmvYv19mX1Zos
         //gA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=QwlyriZv;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::b3 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707798842; x=1708403642; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=g37sMGktKOUKioEVRaZ3z4XdaIrjzLP4GrV+qFDFlSo=;
        b=RUR9jD/xj5iwYhl740yr13z5ZZvczxDyNCXSMwOoGKJT8VvyqMClH55nzwzUretc4O
         kuoXLxI11y/6QXZcmaKWqqKEWIUtz9xO4lteFRWa/arNxZIww+srD5hqObXxtBEXvl2U
         mfe611bHP49s8z1zX+EtB7QORBQkpegcyovmL1SCVxyBWWYJV4Eu+5IJthn3o4kYkas8
         ZrGobtAC9FbzMTKhS9sjMGTR5jKNs5GSyLkpqFAVgxTh2Bi/kRiM7tqzSazLWXdMtMVx
         iy/cf/9XAXqo0ph6aD6VGgcbc8ashYyXGcIc8QruBxt/7rRFhQ2P+uddgXMkmDzLULzb
         XmoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707798842; x=1708403642;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=g37sMGktKOUKioEVRaZ3z4XdaIrjzLP4GrV+qFDFlSo=;
        b=uI/WhgAvSP0NhvcIlk2BECotWdFj3gdpny4JBoG2XhSnta4cUVFMUafX9BhVUCfeHp
         AfaUob/Ss+Uv29oTkqx8Gd/RZs2JpUjNlV1F0vfzVfHPIxbyzloE3SQh2585BakNZOxL
         4utAg/K4FEcBGR2Dtb/mHeIFSVZCgLUjrALIkk13cGV2FCofgjk+aLwrbfhyUonM/hyW
         PkKX9n+q4avuRu7eic2HKS4ypKnvCZM5oJY+k3rTwNp1egR2RKEdab5vf1o5/11UC3Vf
         SZRJcfIOxS1GGAdaxyyOnTt8S6WPqkWR504gjzvCfI7/4uW8ykrZ8OVt6goODmAJpr9/
         F8bg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yxlj8Lt/gY2xogcOP+7TTzMc/ow7eeuO7chCDACQmCreTdw0Dl0
	evWjEQAWboNynVSQZyXgax4RQfthuGNu3zn9TUXi6aIoNjgl/Hb3
X-Google-Smtp-Source: AGHT+IGrTbqCzVZLeeWvqhIyFlVJhPv8AM1uTIBflK9BXQ4V3/azXtZx4AZf5rofcW/T92hLec78kA==
X-Received: by 2002:a50:d6dd:0:b0:560:1a1:eb8d with SMTP id l29-20020a50d6dd000000b0056001a1eb8dmr34207edj.7.1707798841819;
        Mon, 12 Feb 2024 20:34:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a4cf:0:b0:2d0:f95b:25e0 with SMTP id p15-20020a2ea4cf000000b002d0f95b25e0ls773262ljm.0.-pod-prod-06-eu;
 Mon, 12 Feb 2024 20:34:00 -0800 (PST)
X-Received: by 2002:a2e:9f42:0:b0:2d0:ccc4:4f91 with SMTP id v2-20020a2e9f42000000b002d0ccc44f91mr5308887ljk.44.1707798839895;
        Mon, 12 Feb 2024 20:33:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707798839; cv=none;
        d=google.com; s=arc-20160816;
        b=rLSigJFLorbUFfn7S2xs89bn6AI0ZyKyJY0x1EbKJVNb1gk4WLYXuGB1+Hjq5/OZlJ
         y1OjNe6fcEIq0cYKzSoDXGHaFMiiYAOYseRPbECHCxtsc9XU7JSq1LckIozVye0CK5YZ
         Qed0LZz3+5Y1dDPysCVFnpgXrx9f2gVmP5jTtp9RCcO/BurUWqRJmG085Z4RkyfFPmGc
         S5fSgJy+cjo2awVXzziojaE+59FcHOpTGb4gU7MdNkwRUcsDyGolI2rqq79pYG5jvmRq
         Z9XD4nRo+vTfWhttotPstvKgvBlbp2TZpzGGHcVbw/C/ZCRugmg9xK3f5pWfte3lyXDd
         8zUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=DvjY8M+9GsBv1uGSt+JuoCXswHcqrEcE4jibODW0tFs=;
        fh=JZ5LSSeyrdx4ryjNPm40dzzoR3gOnGjFGIN256z9nGc=;
        b=sb3/vVl/CH79kkHWTvLA+poTHYnDJScHsUOHNf88OLHq9jjFKZTC6kj8MlyG2LZEvB
         J5QRwAr/5+rUmI17AaeILwZ2G/TUJzOU1SXMeYh0Zhk0Mf3rac0ukoBrRTGG+hqjmWnx
         23F8vlBS395TnMmf4qIY6rdKPfjeNlCbm1u6AOSGLJpVBb5vZxkLBFjI55CDvWQwcSqw
         d+U88DsM4u24xhKPeewWVpIIBB5fOcqwXjkT4Y4DCJcOq49NNfHo+nRSNi8vFp5nDGGo
         7VTqfx/4OPWa2Qqz8vl8Hde6RYbN+HzvCG5FLgzJrhzC+xUrj0X2FpWXc5y1peiCNmji
         vP3A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=QwlyriZv;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::b3 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
X-Forwarded-Encrypted: i=1; AJvYcCWLD0vroUHno4HJe/BXqXX4R5cx1Gcq3kb1EN6+JqdSrhofGo563EI4Y6VmsLmr/gWrXXsB+qMGLa3Km0bzca4dGIj9GA8N5P3OwQ==
Received: from out-179.mta0.migadu.com (out-179.mta0.migadu.com. [2001:41d0:1004:224b::b3])
        by gmr-mx.google.com with ESMTPS id i13-20020a2e864d000000b002d0a7814671si163431ljj.7.2024.02.12.20.33.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Feb 2024 20:33:59 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::b3 as permitted sender) client-ip=2001:41d0:1004:224b::b3;
Date: Mon, 12 Feb 2024 23:33:30 -0500
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Steven Rostedt <rostedt@goodmis.org>
Cc: Kees Cook <keescook@chromium.org>, 
	Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net, 
	willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, david@redhat.com, 
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, 
	dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org, 
	paulmck@kernel.org, pasha.tatashin@soleen.com, yosryahmed@google.com, 
	yuzhao@google.com, dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, 
	cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, minchan@google.com, 
	kaleshsingh@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, linux-modules@vger.kernel.org, 
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v3 31/35] lib: add memory allocations report in show_mem()
Message-ID: <wvn5hh63omtqvs4e3jy7vfu7fvkikkzkhqbmcd7vdtmm7jta7s@qjagmjwle2z3>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-32-surenb@google.com>
 <202402121606.687E798B@keescook>
 <20240212192242.44493392@gandalf.local.home>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240212192242.44493392@gandalf.local.home>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=QwlyriZv;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:1004:224b::b3 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
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

On Mon, Feb 12, 2024 at 07:22:42PM -0500, Steven Rostedt wrote:
> On Mon, 12 Feb 2024 16:10:02 -0800
> Kees Cook <keescook@chromium.org> wrote:
> 
> > >  #endif
> > > +#ifdef CONFIG_MEM_ALLOC_PROFILING
> > > +	{
> > > +		struct seq_buf s;
> > > +		char *buf = kmalloc(4096, GFP_ATOMIC);  
> > 
> > Why 4096? Maybe use PAGE_SIZE instead?
> 
> Will it make a difference for architectures that don't have 4096 PAGE_SIZE?
> Like PowerPC which has PAGE_SIZE of anywhere between 4K to 256K!

it's just a string buffer

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/wvn5hh63omtqvs4e3jy7vfu7fvkikkzkhqbmcd7vdtmm7jta7s%40qjagmjwle2z3.
