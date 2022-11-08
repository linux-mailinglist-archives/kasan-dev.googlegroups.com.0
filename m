Return-Path: <kasan-dev+bncBCAIHYNQQ4IRBHPMVKNQMGQEYIIUGFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 3640E621D5F
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Nov 2022 21:03:43 +0100 (CET)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-13af11be44dsf7657244fac.21
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Nov 2022 12:03:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1667937821; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ts1h3S+67/HV9Oh6At+h0u9BVxzKnmwwF7Dv4cQ4y7PzV2u5N7xoARSDpOqTBz/o0G
         euzbgY5fabu1qi0InBunfM7HViYanfkynpAjqDGI4Xo1kDwF30qsbUUWxo9qreVZnzWP
         xizEgtvqXlw4fS4pQBWtr4GiMbQCHavAGd+erHqZUUFr3CIYZrctYyf1ffXOLoxAa0MY
         wdxzYIDxwCgmDregDl7PXTlrT9rGodqwhYI65dJMU9lDbT/Ti8tfrj/80rJcHb56lMQO
         fzZ5BBRlpATbPULEGeZVfgCP5NlbqZLMn4lxYjp7fKTt71R8fPhTq8VAjJn70Nyl7ZOh
         x7yw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=Hw7Fcv1NdqBMiSH4M8Hodbr0Ve0BQQxqDbK/CETiY6Q=;
        b=wRlqp9MOoWYUsLD7K00wGmAhiVtP+4tHjnM70/pSGsr1cdK8bFxY4j7ysC81ZdPQUu
         /vdOUbtvXwpbDe9gtZAwf1vJbkvYfWE1izYqfYJG4G++gg8zB99yGql7uM3QnaAz5g3f
         INEQ9hWDubp/R/qllvIgGuTgizJ40SzmqLRsnFSOQ7sU26F+74LG1ZGEr1PJUKLMpTa1
         84TBKLgn0O5ZKDBa56QnLZ1ffly/RCfA2RPpjUZo70uica7qz/CPxJKeLW8Zoa/CN9+g
         MDC5eZahoswsb6KfoEyHmiTpf8sKSi9T8cIOxRl5wDIXnGW2KN6q5wgX1r5WzDnOfolO
         Dy8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=WfTYpQNy;
       spf=pass (google.com: domain of seanjc@google.com designates 2607:f8b0:4864:20::42a as permitted sender) smtp.mailfrom=seanjc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=Hw7Fcv1NdqBMiSH4M8Hodbr0Ve0BQQxqDbK/CETiY6Q=;
        b=VKBmCgZrUNeYmcmGCFz8OvDUQFK7zXxwkO/p5YKpVpcDMoOnCvHPM1pqaYDHqDxFYA
         +s0wSQBrt7uQPcEs6lBIU+raa3WpUAoUXZHUa/LbiO8nLwkRvhcFllXHsnukS67lqfL8
         efGodWFHhDdqH464k7gcGPzwOpF4Osg1MxnAPE2ny5NaYmZNNLFo1JXcL6olB7Jdrri6
         6inMpDiDO6xwtJMHwdWJi4O3EVMiPbbW2pbFPCHMpAxrGIje7IW+9pyUSPZi9vhJr5cK
         zF4CVz/H1wD9eT3D4EtzDmjTrVBB4mh+isw4+cAEZnFuEWkdwvlEtWQG3RW6xugv7o64
         Br0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Hw7Fcv1NdqBMiSH4M8Hodbr0Ve0BQQxqDbK/CETiY6Q=;
        b=WzcORQN7T44/YpY5ru6ur5cFPBYxK6aYe7xjAzJI3s8L2LiG82ns3+AngWC2obnFMp
         U0GdHLDsavI1TPS45vyKPv/F03nt+tvaUtk50VoycnJSU0xBc3lvrFbgwEDjlzJu7X3c
         CA0WUqs3bj81zA/2Nw1E7M//yRHybdpDdCy+8voPRqQIc8XQItr5K+v3yCWxV3N1zYyj
         AqGu95O1MuWhmkc8vmCcll1O1/L7C2tFViCLBkuz6AQdio6m12v2wDsX1QrENEKROJ2X
         tJ0G2o1hrmA20nNVGLIA9JqdIkvizY6Iluf7TdTs94BqLi6MQRg9jufHvFGoLb7nH3+F
         965A==
X-Gm-Message-State: ANoB5pmhc1cWVxXWxkc7gBKe43k+/Qb3q+FwhXg0dPMhME8aAW917BZX
	sepF17icZMVzIa4DUfAXMLE=
X-Google-Smtp-Source: AA0mqf40Hs872DZiTg8aynFdq5HGpx1NOhvhO997ZTc49I6v7P8gByoC1mYv5CqjF8BQFQmJjHRbWw==
X-Received: by 2002:a9d:744f:0:b0:66d:3221:78e6 with SMTP id p15-20020a9d744f000000b0066d322178e6mr1081372otk.176.1667937821547;
        Tue, 08 Nov 2022 12:03:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:120e:b0:661:f369:1f4b with SMTP id
 r14-20020a056830120e00b00661f3691f4bls2670643otp.4.-pod-prod-gmail; Tue, 08
 Nov 2022 12:03:41 -0800 (PST)
X-Received: by 2002:a05:6830:368c:b0:660:ece0:ce33 with SMTP id bk12-20020a056830368c00b00660ece0ce33mr28121844otb.146.1667937821146;
        Tue, 08 Nov 2022 12:03:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1667937821; cv=none;
        d=google.com; s=arc-20160816;
        b=GEqj6svgeAGvEN++rdmRHRAEWcI9LpcLCJkGTHMAa32sztUrIKBQh+ZVlHb25R6WN+
         7Ooet6OLek35VIihxzScVeE4cSgwK4Z9hcLHQmfj+cO8VmZ7ACA+atG8HJdMBfYzoiOy
         BiKfmnyFVIeZx4wfxG2Ki2U1yfdNfO+Qw2JutvXqshJyPCOYTXSQ08lfsrJ4BRPcaowx
         S5Y8uLWmlP3EJ2WYlk+x9Cy3Zg5sEUfnNCBTTEQxjFJXcNU37XBWD7845G/aBmLbg7Zh
         l779MbKx/nwAGQFhKeamWfw6hq82dG01NvGQJ0tg/FqjA7nS1soZb3yfD/8oJBgqfV+Z
         AjcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=UabFGB3dgHdDGh8rYKaeDmUDo6Yz1+GrAprP6mnLPVs=;
        b=Gy+FMu1/dk53fDZZ3qWAJo29g7NvyK1Es2nKRF1XBvIuwyQRBbEbOmRB5QBEUS7J9C
         7bfmYEqz8JXKPFXcF18GfbW0CQrqBucpeWM4yexQfpcW8A63Ye3l62HRjLJ4zjX/LQ9l
         H4cZnWVjHFmNhp6LXw7qzypGMrCIWKbjpw8X01v6Ot0jMPBXRVl2kqeyunQpKHSmJoCV
         VjR8nhm9fux6KFlvuvJT5s+9eOFSB9I5OYOskYyaWkPGH0nN21h+T9LdPnRSlvwkBNpB
         dl6ud4i/N3rH6saxdXHjmphrPDCTpwEEaRKH4g8HcPSlZyOnTKuZ7wFsg6+slTXfZxJt
         nS3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=WfTYpQNy;
       spf=pass (google.com: domain of seanjc@google.com designates 2607:f8b0:4864:20::42a as permitted sender) smtp.mailfrom=seanjc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x42a.google.com (mail-pf1-x42a.google.com. [2607:f8b0:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id d128-20020acab486000000b00353e4e7f335si620576oif.4.2022.11.08.12.03.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Nov 2022 12:03:41 -0800 (PST)
Received-SPF: pass (google.com: domain of seanjc@google.com designates 2607:f8b0:4864:20::42a as permitted sender) client-ip=2607:f8b0:4864:20::42a;
Received: by mail-pf1-x42a.google.com with SMTP id i3so14728412pfc.11
        for <kasan-dev@googlegroups.com>; Tue, 08 Nov 2022 12:03:41 -0800 (PST)
X-Received: by 2002:a05:6a00:b82:b0:56c:d5bf:1019 with SMTP id g2-20020a056a000b8200b0056cd5bf1019mr57436217pfj.72.1667937820352;
        Tue, 08 Nov 2022 12:03:40 -0800 (PST)
Received: from google.com (7.104.168.34.bc.googleusercontent.com. [34.168.104.7])
        by smtp.gmail.com with ESMTPSA id e13-20020a17090301cd00b001782398648dsm7424642plh.8.2022.11.08.12.03.39
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 08 Nov 2022 12:03:39 -0800 (PST)
Date: Tue, 8 Nov 2022 20:03:36 +0000
From: "'Sean Christopherson' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Dave Hansen <dave.hansen@linux.intel.com>,
	Andy Lutomirski <luto@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	x86@kernel.org, Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	"H. Peter Anvin" <hpa@zytor.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	syzbot+8cdd16fd5a6c0565e227@syzkaller.appspotmail.com
Subject: Re: [PATCH 3/3] x86/kasan: Populate shadow for shared chunk of the
 CPU entry area
Message-ID: <Y2q2GFWjLKMp5eUr@google.com>
References: <20221104183247.834988-1-seanjc@google.com>
 <20221104183247.834988-4-seanjc@google.com>
 <06debc96-ea5d-df61-3d2e-0d1d723e55b7@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <06debc96-ea5d-df61-3d2e-0d1d723e55b7@gmail.com>
X-Original-Sender: seanjc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=WfTYpQNy;       spf=pass
 (google.com: domain of seanjc@google.com designates 2607:f8b0:4864:20::42a as
 permitted sender) smtp.mailfrom=seanjc@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Sean Christopherson <seanjc@google.com>
Reply-To: Sean Christopherson <seanjc@google.com>
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

On Tue, Nov 08, 2022, Andrey Ryabinin wrote:
> 
> On 11/4/22 21:32, Sean Christopherson wrote:
> > @@ -409,6 +410,15 @@ void __init kasan_init(void)
> >  		kasan_mem_to_shadow((void *)VMALLOC_END + 1),
> >  		(void *)shadow_cea_begin);
> >  
> > +	/*
> > +	 * Populate the shadow for the shared portion of the CPU entry area.
> > +	 * Shadows for the per-CPU areas are mapped on-demand, as each CPU's
> > +	 * area is randomly placed somewhere in the 512GiB range and mapping
> > +	 * the entire 512GiB range is prohibitively expensive.
> > +	 */
> > +	kasan_populate_shadow(shadow_cea_begin,
> > +			      shadow_cea_per_cpu_begin, 0);
> > +
> 
> I think we can extend the kasan_populate_early_shadow() call above up to
> shadow_cea_per_cpu_begin point, instead of this.
> populate_early_shadow() maps single RO zeroed page. No one should write to the shadow for IDT.
> KASAN only needs writable shadow for linear mapping/stacks/vmalloc/global variables.

Is that the only difference between the "early" and "normal" variants?  If so,
renaming them to kasan_populate_ro_shadow() vs. kasan_populate_rw_shadow() would
make this code much more intuitive for non-KASAN folks.

> 
> >  	kasan_populate_early_shadow((void *)shadow_cea_end,
> >  			kasan_mem_to_shadow((void *)__START_KERNEL_map));
> >  

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y2q2GFWjLKMp5eUr%40google.com.
