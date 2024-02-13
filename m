Return-Path: <kasan-dev+bncBCU73AEHRQBBBMHMVKXAMGQEIGL5NZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93e.google.com (mail-ua1-x93e.google.com [IPv6:2607:f8b0:4864:20::93e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5281D852342
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 01:22:09 +0100 (CET)
Received: by mail-ua1-x93e.google.com with SMTP id a1e0cc1a2514c-7d2df856a0bsf2340662241.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 16:22:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707783728; cv=pass;
        d=google.com; s=arc-20160816;
        b=CFhPopH4lepgOfxs4uW8ty72SclmFoDe7VbOqiZxiETsDOFRIhlC7e9jMf580H8kFf
         EZHkybce/Qm4d8J8icowzlkztutEarU4Zq92Uj3eVMBRWpErbCLHzxbsREo3V74lL/2j
         xUleTLIi2A1ZdXxExalUxFUJVCiK4qfclRhfC9wN4m48n9Yipl8wvEp3YdWHnnfUXw6m
         LYr9OtG7ubGGDHT1ThYDiiGh3IeIBfj7SRses6hdm8J6mcIT46/P0AU4+HtIcnAz95dS
         rTKC6BvJh5T4u1i5h6dWNw8FrcgDOx/9PNvb+d632vFKfgmFbpG0P89ugYkEVPQdBQI1
         GiYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=a8pRculkH5SqP4CB7T4ftu0me3mofBodVvnSY1CH1R4=;
        fh=QDBnOEu3HG60UjkQQfXif1ZM2pSW5K8DfoelCEduI88=;
        b=kDFyC0yMzpVzeJHiLZYgRCeKi0LJTzSL63JWpPS/WSHby/mZ0ngBC1e8zdyYll70Gz
         KzDD1J9BGo2gv5kvBlVd1XLEa7LEctTEzkJ1j1VDafqS0oAAFHADCi21tgEWWeoc1lNR
         1rKdomYR7Y2L3IE7emYYOs0KoLWVcruN6Au5yj3tiRZmran3Hve5X9zjBJtZnYRuMntq
         yHeGAeOWBDg5ASXTpdzcWBDCJhBvX028CiNX+iRZa6fAE4FBvKnDF6yumP8FTOxuPtds
         tLjmLlMQaTNyMWatUKJvV9yA44ayKRw1gOM6Q8tKap1+jJ2UVFl5YZdrEBXHUoA2s7ea
         4tjQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=4rjb=jw=goodmis.org=rostedt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=4RJB=JW=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707783728; x=1708388528; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=a8pRculkH5SqP4CB7T4ftu0me3mofBodVvnSY1CH1R4=;
        b=opy88bB59yrH/YWtwgCzeOuMnzIyo2i4cGxZzNLKizuLhNpjDu6k/HSE+Q0GAHs5nx
         aKGWCN2ajFPfZWnd3Mggpey1W8ylZxrRA5WHNBYYuUpl30+95lEtPTXg0mva42ixH523
         yx8KKan2B5nlE7v9dH1QqPe0cC0YHLAQOZwrjahQ6tSHP40jKgNDQvtWTesvRJA2JsyB
         15BcS6tzTSCgLe00dE2c1P0OMeFTHo81jF3U2xEQbqXiRdLDhL56rPzUgF3Vq7RdPJB+
         iANQvZQaEU8MOy3MIb/rYBYXUuf2EItQg8fQ+VfuCLW1eXg1vgGqX21Cdhk/Wpy82Mp0
         dn/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707783728; x=1708388528;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=a8pRculkH5SqP4CB7T4ftu0me3mofBodVvnSY1CH1R4=;
        b=P+jZLusxM/hohT+LeSYfPdpyx0Gf1e/0PpwzN4JaADoxvuz332KgZHxa0YoRV2r91L
         gb3vBGnfoP34icFAjvadISS7niYcpRS9mLmqxgdndKZ1EdYeSPyxjjEpqDZtBTHuSc+u
         IBXSKwQjXBLUtOjZZwahSkmEOHXPa/9krOnT8fkvn4ujAgOypip8bF/219IkwOvplWiB
         lnK/lP/ruJAgDBqyJyAs20LSNEx/m+rM66KAUAUtSP3cNeYtg8rOrmV2VTlye2runKzU
         f2dMrYHi78hIWDjaToEMrD1NMSfwCj1JtREQUwxG1K5DI/xN/FsOnEk/l460P8cfPiaj
         xfsw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yz+IzXhG12DQ8EErRBdva7ZnzPWDJthIGpoqSrZHDiAfVwWUHhG
	n+HPYHqDh5pyv+dFTfHScyyCZNT7k8ehB18HvkSs7HyRCZS7DrcN
X-Google-Smtp-Source: AGHT+IGbXkOBxO1Cm2foaSyWBn70uh08NBh5Q21uRpVcKXMkmCDZTyYZdm4XJaJ4VBU+WViHlY3B7g==
X-Received: by 2002:a67:b447:0:b0:46d:28b4:95a2 with SMTP id c7-20020a67b447000000b0046d28b495a2mr6329452vsm.32.1707783728218;
        Mon, 12 Feb 2024 16:22:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:262f:b0:68c:c08c:bfe2 with SMTP id
 gv15-20020a056214262f00b0068cc08cbfe2ls6422076qvb.0.-pod-prod-05-us; Mon, 12
 Feb 2024 16:22:07 -0800 (PST)
X-Received: by 2002:a0c:9d4a:0:b0:686:9de1:7015 with SMTP id n10-20020a0c9d4a000000b006869de17015mr7207367qvf.61.1707783727586;
        Mon, 12 Feb 2024 16:22:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707783727; cv=none;
        d=google.com; s=arc-20160816;
        b=Kfqlp0PZpARzpZ7OghcBsXbfoKDEjYH+tG5OZXLsp96LP3WYVdT9ZgdgKhketFLDiN
         57Ku8/D+FO88iD++t/CKPMy1T6fwP3+Y7EhPRzCGg1Hn6nwb/Y1v/0jyS4flNkC54OFN
         5kPz5ICozgCTl4kjgiP+hLs/v+vew8hmtITMcT+6cubNVYM24lP71mXiLujxqnzDRCyM
         6QW/pLuiuf9CE95iqZ/z338MAn7YcNtGCiBc+Nx7jvq6NnY7NcoohP7k/KfFGS80UwPp
         IcErawORl1QOB+eQpUt6m/Lh+TgugjRBlFQG5IOhO3cPmLdeMbQnypbFNE8lO4wFmWUO
         Ix1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=CaCpyDeHXDa+8CkGkZ4BeT+7NNJLDIM9RFOacxKeyRQ=;
        fh=QDBnOEu3HG60UjkQQfXif1ZM2pSW5K8DfoelCEduI88=;
        b=KhPpOkjeOLlsQNB6edcmpMmikbNp8Hk9PeAIJB0rc4+cwhOfx7PnYkABW+xy8uvSDJ
         a+kn1PIq+O9IqdJD02ABdciFl+t2Nrs2o1oAyOUcAD13NBC77CzeDy9Dvew41crZWqfL
         pDWV5/jO9UnwEvQq7Ta+xV5p9OITIfWfqcgUZF1wqFimXjS3a6LjDNhVayp0ltj9NlYR
         RGhse/MPOa0Tr+aEIoWuImL/k1rl0+jPLswHff3vsgVvELZ7Y5yTFeX+uKqYbk7BFBYT
         fJ7SfeV/xniaw8zqcQfOYkM1dRTHfpmZt3qz14iaT4VKzBinyDZWq3FyrS0DiNSO84sy
         bU1w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=4rjb=jw=goodmis.org=rostedt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=4RJB=JW=goodmis.org=rostedt@kernel.org"
X-Forwarded-Encrypted: i=1; AJvYcCVoWrQHQ/ROy2J/qYAY1Wh5uCokJbnsQGlqiCbBf7kbdZG8P8mK53ruDMYKBvXQGN0gbXLmqn5FyI7CJNqnu3Z97GB95mLjx1JM4g==
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id o11-20020a0562140e4b00b0068d1142cc4bsi161432qvc.2.2024.02.12.16.22.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Feb 2024 16:22:07 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=4rjb=jw=goodmis.org=rostedt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id DCD7D60ED0;
	Tue, 13 Feb 2024 00:22:06 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3ED59C4166A;
	Tue, 13 Feb 2024 00:21:59 +0000 (UTC)
Date: Mon, 12 Feb 2024 19:22:42 -0500
From: Steven Rostedt <rostedt@goodmis.org>
To: Kees Cook <keescook@chromium.org>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
 kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz,
 hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
 dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
 corbet@lwn.net, void@manifault.com, peterz@infradead.org,
 juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org,
 arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev,
 rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
 yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
 hughd@google.com, andreyknvl@gmail.com, ndesaulniers@google.com,
 vvvvvv@google.com, gregkh@linuxfoundation.org, ebiggers@google.com,
 ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
 bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
 penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
 glider@google.com, elver@google.com, dvyukov@google.com,
 shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com,
 rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
 kernel-team@android.com, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
 linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
 linux-mm@kvack.org, linux-modules@vger.kernel.org,
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v3 31/35] lib: add memory allocations report in
 show_mem()
Message-ID: <20240212192242.44493392@gandalf.local.home>
In-Reply-To: <202402121606.687E798B@keescook>
References: <20240212213922.783301-1-surenb@google.com>
	<20240212213922.783301-32-surenb@google.com>
	<202402121606.687E798B@keescook>
X-Mailer: Claws Mail 3.19.1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=4rjb=jw=goodmis.org=rostedt@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=4RJB=JW=goodmis.org=rostedt@kernel.org"
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

On Mon, 12 Feb 2024 16:10:02 -0800
Kees Cook <keescook@chromium.org> wrote:

> >  #endif
> > +#ifdef CONFIG_MEM_ALLOC_PROFILING
> > +	{
> > +		struct seq_buf s;
> > +		char *buf = kmalloc(4096, GFP_ATOMIC);  
> 
> Why 4096? Maybe use PAGE_SIZE instead?

Will it make a difference for architectures that don't have 4096 PAGE_SIZE?
Like PowerPC which has PAGE_SIZE of anywhere between 4K to 256K!

-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240212192242.44493392%40gandalf.local.home.
