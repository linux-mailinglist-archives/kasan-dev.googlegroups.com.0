Return-Path: <kasan-dev+bncBC6LHPWNU4DBBU6JQPZAKGQEY56DGGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 2163F156E90
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 06:06:29 +0100 (CET)
Received: by mail-oi1-x239.google.com with SMTP id m7sf3764982oim.14
        for <lists+kasan-dev@lfdr.de>; Sun, 09 Feb 2020 21:06:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581311188; cv=pass;
        d=google.com; s=arc-20160816;
        b=tBGl1Dz6H/jlZwuqvKHucoQiqaZttgJcNthv8JIJm+VhceSvg10egkLlscosih0Abn
         pYBI+CLN6ivJNpvtYpekP0FAE2TsV194KZjF+Ah0l8ZMazAmt8tG6Dj+JXB90cqLXn9H
         MFF6pO7MnM7nE32ni6tMB5Xuv0AAMIwaLTKYoZ6vUQbu4cTWWSYOy0ZrrqoeX+MrEwFT
         nWm0gh+G9pRTj5y8mH4XarSs00sSSUQsUDmLzRcGxHT9KNMajh+FeDP0WVhUGMtC5C4J
         uE45hmMyee4a/DGFXbFD3eMY99xZmjHtUo1Oo7byTfkmIhsTblxaZkdfW9tHF9wsdDsO
         fevA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=x589868xRbQjAQZLcR1ACPZkSrtPebkfn9IiXsPbeI4=;
        b=fzvFWS11Utr3H8JLNDkfDmNOvLhiEShS9vZizZ9BDC7dYD072fRcH5P7LDlJ7zNXk3
         H++g6VaMPjHYX34fIKRS58C7tNAp6rcKXUM6ScT8zVywlhHEkGM5qp6zuDg1/kZrunhv
         BpwsV2SWqy3R1UvzbxeWeoICV2fYvsR2snu/3Ttyo/EoZ+hhhQSOXARMnsoffMIQR4CI
         R2l5HYS4lRK7GSvl+eB7z5ywCRtbMYlF8CAF0MyZR5jE8iHEqMm4kgAtcm60UxQS4mK6
         rmutTaiUQ7RfnOQIIjNRCO4WMjQi51o3HDvDcpw5XzWCM0st7K3QJXceGsjFtcEto9lw
         lJqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=qMDqBORm;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=x589868xRbQjAQZLcR1ACPZkSrtPebkfn9IiXsPbeI4=;
        b=nLaPC+9nxRZ2ugyaIX2C4gaIhKu1MngUdnN3T6KMf5ne9GVKcivPRy68eAIxWADZu/
         hmlgTd7oqMWMHNYenPKUnHMSVQFOzAKy9AbobELl+eUXvjc39JINvGjzVGWfEcJ52xHV
         JgyEAr/BtjOg0Mr84U8oi9kiv3ZRcmo0Aeb7O+0VmiPTK8I6sHLepFK5VZgmo85cLhug
         tp0H1kWGr6JCGTFEgy4wDT9D0B9xxMvYxH99TZBCW2/ovZmsfnPIq3VS74CEjBdxQoXs
         4pCmJddfRnqNEVBblDqgyKRuGS6VnwWct4TLrHQoafU9oGHNgDimoSKf8SQSHTZeQzfm
         u/dg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=x589868xRbQjAQZLcR1ACPZkSrtPebkfn9IiXsPbeI4=;
        b=A5JLHUXZw3th4+BBdXv48HCpU4lD35mCFjC/HqkDk4WpkYALJj6rx5EQnfgF9Pl3TD
         dVBo2rS2h44eKhbhAQ6giCqxVzskTzegYk+XkHnLxr5FdvO6OrOifmDXcEILLX84u2wP
         VNoI8j77pwfsJnRvoWUJYdmdCmMye68CaDP8nJvZdtsiRB6gln6v93Xsd9B+awRzme/X
         xwd0XJgJpS8p+rqiyAk4k21jcSypYWZ+DLOdpDHU6JETEAEBEygnPbepCL3Ou/E54GOl
         dzCnCJbsYyy/l8TN1LTPvLTUhpJ4QnWyzFJErVzwg/mfA453b3NKgvvxI/+moS43KfSZ
         7e2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=x589868xRbQjAQZLcR1ACPZkSrtPebkfn9IiXsPbeI4=;
        b=G+fqx+clzRd2zA8FV0qaU8kAJEhaxKhN9BwZrlBDRZxYXN/KZAoWwZabvufzMalZi/
         51kvueZTL37yQ/hRMVtOAzEkxM7hbyY/R212cOU83Qf3VY23A/4jfFX4S1Y+bWQ349dt
         QIj0fzamMqMRaaYGxmFe3QxmG6F/42/kVk9uu215PGxVjtcYCRjp+uWR1QD+hWtfFEMx
         9733AhXLTrWPBaHUcYkYEq2S54T6DnVfWGfqilVrHB3WgjgbPJCIkcYmK80tJ+AimZVY
         fD7lVqG/vPdbh1JJrv+c9K8TkndYEHA+jk0h4dOEXnxJmDVw31KOu2ALuXm8oBpY5pem
         0vaw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVXnaFMAlXQGYW4VUKOcOTVvUdjesJ6I8EroKctO2LaalL6K/pC
	Y68Ps45mCgcrvFkk3AE7Gcs=
X-Google-Smtp-Source: APXvYqzx/OD4z/mVubgYBD6agvH4TQyDZevJHi9F3CCdFuJdFHweOcZE2FwT4rz+9hv3FOVTPEYA3g==
X-Received: by 2002:aca:f44a:: with SMTP id s71mr8095593oih.7.1581311187769;
        Sun, 09 Feb 2020 21:06:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:d615:: with SMTP id n21ls4367009oig.5.gmail; Sun, 09 Feb
 2020 21:06:27 -0800 (PST)
X-Received: by 2002:aca:b284:: with SMTP id b126mr9588664oif.79.1581311187317;
        Sun, 09 Feb 2020 21:06:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581311187; cv=none;
        d=google.com; s=arc-20160816;
        b=SRW7b5JxDx/RHdOsZzLddPnTLFPGQp22228C2Edlhkx/oKmfl6b5mWcqK1Klfo5Ipa
         LIQrCmPC39X1WzR3UCzjIsAj4kWvzsquqie2qGQVq9wTBCBNcbZnRPOWEv+CD0vaK0IM
         QxzUkoGcLDErpOWaPokg/R/HYrz+dzQKmyfem5s3hfhwJmenGyMzI/7YeYIRP8zBxq3u
         L/PlbtQcz+0ks57P/GWhuaNJxRT0AOo8LLJjHmIF/JWQcqzBzuhoCkHuYSEARNeBpMEl
         bAgVB1MocwS0MyS0102HUVhAMLDWBowKMUZ4j+Doc1+vLXhaf5lN+pHhikTOiLqZJqsx
         7EZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Gkrur8ZH9ga6UJf6rP/okXyfpeLE1Q7jCwwBrZ0bZFM=;
        b=A7pmH3aUEKFq9nwvBE1OnwKGbzWOdj0fM2WAhsOg4Hujq9TAPp2yriixddlUhduDgF
         /SVxjTzqCLYeHfermNE02aD+NUVL0j50YzSPqP+M5JiGS5rUoI4ULLC+NyT+2AHGElCj
         pMTtnWwzLzy5Z3TO+dowEViEg9Yd6KqZqtsJ8lllNBxGOYgW+JUhlIfA5IsrnUc1WkeI
         8WpUR+i18so6aD5jRNrGURkp0/VzZbkEVcSvVNExyxXCtRJaZFE8Baal09gKkC424bNN
         4kh1Na5J4H7wOOctvLTukrh93d9pgu+xsOsqZR14CgcLAC3bL7GRBIRkZ4d60HJEuyWO
         3ntg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=qMDqBORm;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id b2si244221oib.5.2020.02.09.21.06.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 09 Feb 2020 21:06:27 -0800 (PST)
Received-SPF: pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id w25so5368342qki.3
        for <kasan-dev@googlegroups.com>; Sun, 09 Feb 2020 21:06:27 -0800 (PST)
X-Received: by 2002:a37:693:: with SMTP id 141mr9034197qkg.134.1581311186806;
        Sun, 09 Feb 2020 21:06:26 -0800 (PST)
Received: from auth1-smtp.messagingengine.com (auth1-smtp.messagingengine.com. [66.111.4.227])
        by smtp.gmail.com with ESMTPSA id q130sm5238519qka.114.2020.02.09.21.06.25
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 09 Feb 2020 21:06:26 -0800 (PST)
Received: from compute6.internal (compute6.nyi.internal [10.202.2.46])
	by mailauth.nyi.internal (Postfix) with ESMTP id 61B2A21ADD;
	Mon, 10 Feb 2020 00:06:25 -0500 (EST)
Received: from mailfrontend1 ([10.202.2.162])
  by compute6.internal (MEProxy); Mon, 10 Feb 2020 00:06:25 -0500
X-ME-Sender: <xms:0ORAXj082ZX2f0mvLw_lTVNcfgVqHnk2OdcBfKX5CZidSeTVg2qUJg>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgedugedriedtgdegjecutefuodetggdotefrodftvf
    curfhrohhfihhlvgemucfhrghsthforghilhdpqfgfvfdpuffrtefokffrpgfnqfghnecu
    uegrihhlohhuthemuceftddtnecunecujfgurhepfffhvffukfhfgggtuggjsehttdertd
    dttddvnecuhfhrohhmpeeuohhquhhnucfhvghnghcuoegsohhquhhnrdhfvghnghesghhm
    rghilhdrtghomheqnecuffhomhgrihhnpehkvghrnhgvlhdrohhrghenucfkphephedvrd
    duheehrdduuddurdejudenucevlhhushhtvghrufhiiigvpedtnecurfgrrhgrmhepmhgr
    ihhlfhhrohhmpegsohhquhhnodhmvghsmhhtphgruhhthhhpvghrshhonhgrlhhithihqd
    eiledvgeehtdeigedqudejjeekheehhedvqdgsohhquhhnrdhfvghngheppehgmhgrihhl
    rdgtohhmsehfihigmhgvrdhnrghmvg
X-ME-Proxy: <xmx:0ORAXkeaS0vsh9hphVg5ara8sSALAIK9pPbyS1APcE4TUJHV3t9Mww>
    <xmx:0ORAXtJ708DhpCxWnYjsps7jOER7L-PblLN0wXJs425T806EKprg0Q>
    <xmx:0ORAXr8Po-h87hb_pymMVqxE1OoNJSAo7VJHS3imKW6KlrAALEECSA>
    <xmx:0eRAXuiXgJYAxbQsh6dLAynE3_8s0-CHQ-bPiUfqAbrstoJQ9SCh29AiXao>
Received: from localhost (unknown [52.155.111.71])
	by mail.messagingengine.com (Postfix) with ESMTPA id 94EBE328005E;
	Mon, 10 Feb 2020 00:06:23 -0500 (EST)
Date: Mon, 10 Feb 2020 13:06:22 +0800
From: Boqun Feng <boqun.feng@gmail.com>
To: Jules Irenge <jbi.octave@gmail.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	kasan-dev@googlegroups.com, akpm@linux-foundation.org,
	dvyukov@google.com, glider@google.com, aryabinin@virtuozzo.com,
	bsegall@google.com, rostedt@goodmis.org, dietmar.eggemann@arm.com,
	vincent.guittot@linaro.org, juri.lelli@redhat.com,
	peterz@infradead.org, mingo@redhat.com, mgorman@suse.de,
	dvhart@infradead.org, tglx@linutronix.de, namhyung@kernel.org,
	jolsa@redhat.com, alexander.shishkin@linux.intel.com,
	mark.rutland@arm.com, acme@kernel.org, viro@zeniv.linux.org.uk,
	linux-fsdevel@vger.kernel.org
Subject: Re: [PATCH 00/11] Lock warning cleanup
Message-ID: <20200210050622.GC69108@debian-boqun.qqnc3lrjykvubdpftowmye0fmh.lx.internal.cloudapp.net>
References: <0/11>
 <cover.1581282103.git.jbi.octave@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1581282103.git.jbi.octave@gmail.com>
X-Original-Sender: boqun.feng@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=qMDqBORm;       spf=pass
 (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::743
 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Hi Jules,

On Sun, Feb 09, 2020 at 10:24:42PM +0000, Jules Irenge wrote:
> This patch series adds missing annotations to functions that register warnings of context imbalance when built with Sparse tool.
> The adds fix the warnings and give insight on what the functions are actually doing.
> 
> 1. Within the futex subsystem, a __releases(&pi_state->.pi_mutex.wait_lock) is added because wake_futex_pi() only releases the lock at exit,
> must_hold(q->lock_ptr) have been added to fixup_pi_state_owner() because the lock is held at entry and exit;
> a __releases(&hb->lock) added to futex_wait_queue_me() as it only releases the lock.
> 
> 2. Within fs_pin, a __releases(RCU) is added because the function exit RCU critical section at exit.
> 
> 3. In kasan, an __acquires(&report_lock) has been added to start_report() and   __releases(&report_lock) to end_report() 
> 
> 4. Within ring_buffer subsystem, a __releases(RCU) has been added perf_output_end() 
> 
> 5. schedule subsystem recorded an addition of the __releases(rq->lock) annotation and a __must_hold(this_rq->lock)
> 
> 6. At hrtimer subsystem, __acquires(timer) is added  to lock_hrtimer_base() as the function acquire the lock but never releases it.
> Jules Irenge (11):
>   hrtimer: Add missing annotation to lock_hrtimer_base()
>   futex: Add missing annotation for wake_futex_pi()
>   futex: Add missing annotation for fixup_pi_state_owner()

Given that those three patches have been sent and reviewed, please do
increase the version number (this time, for example, using v2) when
sending the updated ones. Also please add a few sentences after the
commit log describing what you have changed between versions.

Here is an example:

	https://lore.kernel.org/lkml/20200124231834.63628-4-pmalani@chromium.org/

Regards,
Boqun

>   perf/ring_buffer: Add missing annotation to perf_output_end()
>   sched/fair: Add missing annotation for nohz_newidle_balance()
>   sched/deadline: Add missing annotation for dl_task_offline_migration()
>   fs_pin: Add missing annotation for pin_kill() declaration
>   fs_pin: Add missing annotation for pin_kill() definition
>   kasan: add missing annotation for start_report()
>   kasan: add missing annotation for end_report()
>   futex: Add missing annotation for futex_wait_queue_me()
> 
>  fs/fs_pin.c                 | 2 +-
>  include/linux/fs_pin.h      | 2 +-
>  kernel/events/ring_buffer.c | 2 +-
>  kernel/futex.c              | 3 +++
>  kernel/sched/deadline.c     | 1 +
>  kernel/sched/fair.c         | 2 +-
>  kernel/time/hrtimer.c       | 1 +
>  mm/kasan/report.c           | 4 ++--
>  8 files changed, 11 insertions(+), 6 deletions(-)
> 
> -- 
> 2.24.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200210050622.GC69108%40debian-boqun.qqnc3lrjykvubdpftowmye0fmh.lx.internal.cloudapp.net.
