Return-Path: <kasan-dev+bncBCT4XGV33UIBBOFS6KXQMGQETTIWGDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id D73C28861B8
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 21:31:53 +0100 (CET)
Received: by mail-io1-xd3b.google.com with SMTP id ca18e2360f4ac-7cc61b1d690sf105848539f.3
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 13:31:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711053112; cv=pass;
        d=google.com; s=arc-20160816;
        b=wUBUDWhO08jBoqxjhHk191l1cW6llBqG95h4mGoA43n+DwgFS/UmNm9wqVUaS4JN+V
         euFc6hvZnR1kP0rbtBRBkIsn9dCAgeRghIXfuu3O5XNEbhcVnkmPo6b5Uo8GPFahEZzG
         0BaBm5qmeYM2X8oiT7WZMZ7Z8mgnhVmyrM9pwPWxn00JCAyLEEjqaMeFnhaOHwT3KD+O
         OFfvqTCKOq1u6q2LY4Zs+/AUe5jYe1ohqaHHHVdSNuTqgnKMr66irRWoHSVXNztlD14Y
         fKWj92Yz/TZDRTEy2xYtIUi3Ta/c6dJSr1mPy0W55imdz6DahtWuQ5X/mGeiNLDYFPHs
         l6bg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=TpmTYvvHOyCk17QU13jTVBAPfl3Ch9efOwp3IaPo24E=;
        fh=bd4Yn3mGsON5wu+wBP58aleZrO+VXQiUaNBOo1FgbHA=;
        b=iCq7iMW+GlMQVSGy2EvJDTFKNUaDLAyDnRAGbFgcit+kaepad+MsPjv/gWmH0SlQlZ
         wqjo+wYo/UPuoM79H+tDlHaPqqfcKgD7SiFPfoK6NKw6UYOUWN6QN073yF4Jng+he3Ik
         Uug0TJt7butE40KcyR6hRSzI6yQVJ6YSAIEZ1s/tkfSevdV5L24dfV0X7sLM6PqJd4bx
         z1VOsOZ9HgP2uWS7+P5bYGY7IpcEdxN2hCKAbahZms0I43cuT6VfQa+dt4QDQYear8Uo
         dMkQw5X0XtgwNq2Z7ozCNlT/WFVCnHv3pWE/Nk78uXZKA1KTmzMB40gIAOcIor1Dw3re
         gnhw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=myqqqaYb;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711053112; x=1711657912; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TpmTYvvHOyCk17QU13jTVBAPfl3Ch9efOwp3IaPo24E=;
        b=jnxPCXpm5cGujQazzqaNBTSvwc0BCbuLuRVQju5XLX2pPmlVt/7reuRzlN/iM21GXa
         s5kE5WWLe63dn73HVJ8IERImCUkCf3CKGLpfgoSZTTJzxDTUlO9BvGBjUNQ80dB4Rzv4
         FqRQ2HG9LgHrKOXUoDCVJtxSNJL3yw1TaCsmNCfxYaPLzYNf4R1P1pSybTvQbG+bJxDq
         Jjpb1O1LoUMeF41Fmy0RUCsrGP5EJ+upFuPA6LgopdDYzwtSloS3sqkCs7bXq3Q7ncQZ
         DAadsOZ9L+pa8HmTovRpgIcDfiQLKS7VDdIhrbTu53j81w0SK0pI1zNzjW8JiawaUDq0
         pxBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711053112; x=1711657912;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=TpmTYvvHOyCk17QU13jTVBAPfl3Ch9efOwp3IaPo24E=;
        b=YLqNJWPRj7S2nPezotDIO7HEBwfG0PZ3ZHw1CnYxVGC/u8Wwk/OE+b9ediB95ue8xy
         Xl7lYTDyKnwbE8w6Ui7ApT5IzFwe+xIM17iKZiUtMyti0WMUOtYfxerSU6+IJlwcsDpR
         pA0C9wIr5ChOfazpMpfsRRZdT3WZZkpSyf6NgMvGMzda8WgbQibS4qgcTs50lr8dIvsw
         U4dEfELWfXeYt31GtG4MYDq/ZwIdIBVgyQCenSTGNm8m03bILPPzFHCEx6fmslxVT5gX
         FSYbEivNpDbyBFvwIcgYpHDHoFYX9MNu7hz3Imzfn+UpnG75eEAOQKN04D37AxLvFoxx
         PRFw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUsaLx+dPNPWuZ1Are+eCcrFQZqBiB9/kn6LfeHCoP/Np7+EIBDKoA0NY9DPO6gMUorGbyWUx+1Lxx5/KiaL2OKiPE9sTK9kg==
X-Gm-Message-State: AOJu0YzN6BVF0rnM8EEsubJe8uU0EP1ZNfZOi0vzSmDpgd9mhVl6iUB+
	c3KkXHVMiuZiihxxr9n5kniLOFwIbCI/r5SruY4HdYIgERvzhXwc
X-Google-Smtp-Source: AGHT+IHI2mYS3xiMw+fVIO7TcOOTQEamUuGw3H6JxFdmnD1OVQuF4J5pxwUJZ1TpUcXbvj+BLDLQww==
X-Received: by 2002:a92:c213:0:b0:368:4f33:a034 with SMTP id j19-20020a92c213000000b003684f33a034mr658403ilo.19.1711053112450;
        Thu, 21 Mar 2024 13:31:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c54e:0:b0:368:59f4:6433 with SMTP id a14-20020a92c54e000000b0036859f46433ls273448ilj.2.-pod-prod-06-us;
 Thu, 21 Mar 2024 13:31:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWm+tWXsAksyzLy4m7KtzSSdBqqaxmwpWL0MtQUKdZd9z7NKG9r5c7Qy/SY6iIyy2KDibaJCfV2Vc8sssCdtNCtqwkD6E6YsW6b0Q==
X-Received: by 2002:a5e:cb06:0:b0:7cc:b10:b09e with SMTP id p6-20020a5ecb06000000b007cc0b10b09emr663750iom.0.1711053111126;
        Thu, 21 Mar 2024 13:31:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711053111; cv=none;
        d=google.com; s=arc-20160816;
        b=RjJi8N6ap7bHG97sZmiXz6N+FtZ3EA0f92N4ryenUFYzpO5/hxLEJ4+aP885BgClBN
         z+hFtho6sDZ49AohkazXxB6p2lcX8xne7xZrwgCjxNEWzf9DEUQBOdzEbPbks1t+Fr6T
         zndauarJdtwn8LqD0Qo2YNm2RBOk/GMr1jP6P1knuUXiP2zL0nyVkhDWir1mgHvevsw+
         GtMYj7BEuqEi1G3bb+NzICQVcD3rEXDu3q5ly3hsGRUfgc+UePcaVrgCjL93+KC5c2NU
         2PmAXMApNGoVTUPJUUB3SC/uC3xQTBaqBaS1FQW+xcyrn9l6KgDkFz3IEN5PQD236mOX
         mgnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=5bivwr0w6V4Aq5kxqPnIVYurFU/PCEOCVDjr9lQ9raQ=;
        fh=k43ZFzTGpw3h4AfHH7vRtExqnNiSeKNDN9LVZdLMZ6U=;
        b=bdQR+nzxxxMT1ii489rvYQmAGJrZN4TVi0LQrvaBdibIL0OCdUFf9L4t9qLHze0JLb
         W6tXrvklpwXFsXkKEiEz66euiw6t62u6ARcKBFGMEYgkrmSJ0Ijl0nGfdh4WEo4DLix7
         7RJVkBmGcbYmDZx0iRvdaUPkHAtkfS9r+gsIZ/MeV+cGhVjg49yqfZyR0koYEwVI/DBI
         wL3LS3sC1PKtO9d8ZXprRq0LXNuI08O1pCo3+F/Ll5/9+KO6IAhuZv84wn9DvNEKWAR+
         9QfRPihvRHf5XK+AJEWx/ZNg4Oat+G6iELq2qQYXhPil7ItBAWvfNKujbf8qqlrh3bfW
         67zA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=myqqqaYb;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id v18-20020a05663812d200b004791bba666esi20276jas.6.2024.03.21.13.31.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Mar 2024 13:31:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 6DE5C6122A;
	Thu, 21 Mar 2024 20:31:50 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C826DC433C7;
	Thu, 21 Mar 2024 20:31:47 +0000 (UTC)
Date: Thu, 21 Mar 2024 13:31:47 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz,
 hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
 dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
 penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com,
 peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com,
 will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org,
 muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
 pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
 dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
 keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com,
 gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
 vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org,
 bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
 penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
 glider@google.com, elver@google.com, dvyukov@google.com,
 songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com,
 rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
 kernel-team@android.com, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
 linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
 linux-mm@kvack.org, linux-modules@vger.kernel.org,
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org, Alexander Viro
 <viro@zeniv.linux.org.uk>
Subject: Re: [PATCH v6 05/37] fs: Convert alloc_inode_sb() to a macro
Message-Id: <20240321133147.6d05af5744f9d4da88234fb4@linux-foundation.org>
In-Reply-To: <20240321163705.3067592-6-surenb@google.com>
References: <20240321163705.3067592-1-surenb@google.com>
	<20240321163705.3067592-6-surenb@google.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=myqqqaYb;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Thu, 21 Mar 2024 09:36:27 -0700 Suren Baghdasaryan <surenb@google.com> wrote:

> From: Kent Overstreet <kent.overstreet@linux.dev>
> 
> We're introducing alloc tagging, which tracks memory allocations by
> callsite. Converting alloc_inode_sb() to a macro means allocations will
> be tracked by its caller, which is a bit more useful.

I'd have thought that there would be many similar
inlines-which-allocate-memory.  Such as, I dunno, jbd2_alloc_inode(). 
Do we have to go converting things to macros as people report
misleading or less useful results, or is there some more general
solution to this?

> --- a/include/linux/fs.h
> +++ b/include/linux/fs.h
> @@ -3083,11 +3083,7 @@ int setattr_should_drop_sgid(struct mnt_idmap *idmap,
>   * This must be used for allocating filesystems specific inodes to set
>   * up the inode reclaim context correctly.
>   */
> -static inline void *
> -alloc_inode_sb(struct super_block *sb, struct kmem_cache *cache, gfp_t gfp)
> -{
> -	return kmem_cache_alloc_lru(cache, &sb->s_inode_lru, gfp);
> -}
> +#define alloc_inode_sb(_sb, _cache, _gfp) kmem_cache_alloc_lru(_cache, &_sb->s_inode_lru, _gfp)

Parenthesizing __sb seems sensible here?  

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240321133147.6d05af5744f9d4da88234fb4%40linux-foundation.org.
