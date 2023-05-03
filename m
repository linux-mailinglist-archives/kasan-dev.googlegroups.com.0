Return-Path: <kasan-dev+bncBCS2NBWRUIFBBMOIZKRAMGQEON6HBZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 81C986F5D9A
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 20:13:06 +0200 (CEST)
Received: by mail-ed1-x53a.google.com with SMTP id 4fb4d7f45d1cf-50bc55eaaccsf5005411a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 11:13:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683137586; cv=pass;
        d=google.com; s=arc-20160816;
        b=dNCtdutAYzTrAdiMeW+8JXDfYezuorPY8Q6Cy57In14gNCreFmL84cphoh2IqIeAuR
         aRmfg5tDu0t9vba0PAbn1NBJtyfiIAKFlylxuJRIywa1X9/+LWd4/RAR+t6pVqD+08+F
         rsALiV+9+gzH7s9mNbVkHhdAp4GpSliPWk0E3ecojn2Q292fefMZmKuKg/r4mmJPIv2P
         AwQP0ybNLn6HZe29FeKghYnA42tsmTsgFuW7N3QntqRerdeZ8u5Ysff5EvpAeUmjIqJv
         TFhWNfmtODnZFoAS6srF+SxSWmtDrw2cq6wKGwoq4uUtLybQBTZRh4vqJQeuqSn3Ulv9
         bp+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=gnMNtZ6Cc+JG14+8g++DCuUdgpJyrU77iPpckBUi/T4=;
        b=TwmOkGM6YzRcDoYZOjaqLCzfu4xHEFb4HnCdpmr2FskgSJEBQVXBvPr1vxPPKXoa/t
         bF0kCDD4sgek6FsPEVlEzyLR6uUqUcq4F0VuxinGRt4BNTQCmzUY+vC4B3Y/v3lxvqei
         x48phKSe7OblMaTWPyIg3PA97QwfQNprrszazEs40hhXmLUy4//VkMpsg7ppbxy4h7hy
         JlEQSEb/XvXzgFl0wDJSH77b2xUz8HZK5ee5QZFSNBMD+HNQMjmSHckXesxoHJ5vPcGu
         c5gvTDcyIiURHp05iUxgIRVuLvH33wTkOkN+iCvt3bZmJNUFoa5wE/JcDDzQyNTeh4Nw
         tIPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=siD6Jyei;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::2a as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683137586; x=1685729586;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gnMNtZ6Cc+JG14+8g++DCuUdgpJyrU77iPpckBUi/T4=;
        b=ZCw/+Jt9wQ9uUhzbCMFDWq8DgNNyR1mfFKczwgbB+MqchwiLIH3+2Bb4jzeCfIDMWI
         cnHUvviAvzSmdNJhJlgR9WROpZrvggzsPE9jwQPPOHmm+AfB5JTpEzI0Wd+gBVGkh6Al
         EByRW164DHQUajkJhsN2V/1xjjzHAjENFX5A6QeQhQzOnWPriS0caVMr2NN98aJfoJbW
         dmABZQJd2oyb4aXy6lB/A5nSBlu5vcA1sw3+saRJ7iRn5g98hFXzR5aBe+mCsQSA5xG3
         kX6lVvR68G8LK4BKGsbfCU9Nor/JfqGnpk3GEAEqSRj+Sr9Uech5kWQ8AVwTRL5CbDfc
         tscw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683137586; x=1685729586;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gnMNtZ6Cc+JG14+8g++DCuUdgpJyrU77iPpckBUi/T4=;
        b=VdBOAq68P7LGnbZvXxIVAh+7rb3dR1iRJviGodwpju+8BtPcnAGz2ZFcdltqFc8z5j
         GLO0uhR4kqdc3cSahqoMbDAWAr2chlF3/bSWrO2gFkhEroIi+muRYuP0njgbz2hRE90C
         f6UcmmYoQzr+ypc1JR/R5vVoxmybt39RmO454Z54doNfl+DMtMrGapdi80xSzS3EmlLE
         62v85FaFzHcLUxCyvKVJjrtDTfrrYZAfM5abVgS+I7UsfykzQRxsXRKg4tLD5TAsaCvr
         gjpeAtPqe2jl8lxP8SOMQQCZvbfjMNWbsxDQTBfwkH59mDCSy+vqM3PmFlwAcbazN9Ux
         J2hw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDwfxNZkpZA3Ea5bupE0r2PSujR9cZ3z+xiTm/si0QCa6Ykfrqkk
	VE2cT+x04EYOHmwtB3jTgPu69g==
X-Google-Smtp-Source: ACHHUZ5DnXu5Dw/YYKj0DiyGKjwKYfnJ0+JaOyiqOA00IXKVbw5GVbJfLgdTp4BsCLjhroH8j1+how==
X-Received: by 2002:a50:cc9c:0:b0:50b:c3f9:1615 with SMTP id q28-20020a50cc9c000000b0050bc3f91615mr4826666edi.3.1683137586042;
        Wed, 03 May 2023 11:13:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:6a0b:b0:961:8fcc:81ca with SMTP id
 qw11-20020a1709066a0b00b009618fcc81cals6533165ejc.9.-pod-prod-gmail; Wed, 03
 May 2023 11:13:04 -0700 (PDT)
X-Received: by 2002:a17:907:7ea2:b0:94f:7c4e:24ea with SMTP id qb34-20020a1709077ea200b0094f7c4e24eamr4487187ejc.38.1683137584776;
        Wed, 03 May 2023 11:13:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683137584; cv=none;
        d=google.com; s=arc-20160816;
        b=yNnZqLQO+TIc+QJ0xX0VIK4O1eTPIbPaG6F4VqeHn+W/kHk8fhU4yRIwSojzBTKhNT
         2r9uSO0/EOR2rLLkCEfMC5sACNLXu9twq+ujNP9V4fOk0hB/KLXY7maRmQxsq9gxDQgs
         8DA4sSIlpcWs3TcbSI8aCLVxJpc1UVlWOcVVyP49MWP7WMSOo33mD5e8uBsdKTtGpJ+7
         9aEu2mWOpnXTO+Bx6lG+tPR6bvNRFkiBhCRzI8wHc21g6lfpayo4UYeNa5Wx4pv94lU5
         wXbGNhmi3L1ra1QNfZnUflyCdIC56njpivTb+6Fz8uEiz5o9m0i8ZmDA6Dv34JYTM3pX
         oqaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=bFNCoxPB6ZGjmPXwS7aActt9s9ZGw8uNq57D7UKDjKM=;
        b=hlcPpvdoQglqWPAbWeBdTh182sI6brwXPLqp+aBkt9Ozt9oG64Ng9JxN0jxEj1RWwh
         uzMkKVUNsTBqmSluDIKXySErq7gWJ0100rth01wMfDSttFdKya+QT78dbOwCLv8/VT7J
         GjpwKWRSVPDEmT2Uk2+v28KV78i14Cmj4s/zJ9P/9HGaXIpt9TGCYT/xIZyZPgd7Ft2N
         mJgavXXxhslBro/fi+CGlFoxGJoOZFjWkhdbWyJZ9WD/KowDGBG1QcvtLZTY2L3b37yc
         vS6ocCs2aIyCKps3dIjvEn3Ahaopu+JPD58q5g+2siiJu1iB1Z95c7vMs9jNPGbz2orK
         Y7mw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=siD6Jyei;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::2a as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-42.mta1.migadu.com (out-42.mta1.migadu.com. [2001:41d0:203:375::2a])
        by gmr-mx.google.com with ESMTPS id d12-20020a056402400c00b00506bc68cafasi130484eda.4.2023.05.03.11.13.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 May 2023 11:13:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::2a as permitted sender) client-ip=2001:41d0:203:375::2a;
Date: Wed, 3 May 2023 14:12:52 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Steven Rostedt <rostedt@goodmis.org>
Cc: Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>,
	akpm@linux-foundation.org, vbabka@suse.cz, hannes@cmpxchg.org,
	roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
	willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net,
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com,
	ldufour@linux.ibm.com, catalin.marinas@arm.com, will@kernel.org,
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
	masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org,
	tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org,
	paulmck@kernel.org, pasha.tatashin@soleen.com,
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
	ndesaulniers@google.com, gregkh@linuxfoundation.org,
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org,
	dietmar.eggemann@arm.com, bsegall@google.com, bristot@redhat.com,
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
Message-ID: <ZFKkJJ8+/uD0tPMM@moria.home.lan>
References: <20230501165450.15352-1-surenb@google.com>
 <ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
 <CAJuCfpHxbYFxDENYFfnggh1D8ot4s493PQX0C7kD-JLvixC-Vg@mail.gmail.com>
 <20230503122839.0d9934c5@gandalf.local.home>
 <CAJuCfpFYq7CZS4y2ZiF+AJHRKwnyhmZCk_uuTwFse26DxGh-qQ@mail.gmail.com>
 <20230503140337.0f7127b2@gandalf.local.home>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230503140337.0f7127b2@gandalf.local.home>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=siD6Jyei;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:203:375::2a as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
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

On Wed, May 03, 2023 at 02:03:37PM -0400, Steven Rostedt wrote:
> On Wed, 3 May 2023 10:40:42 -0700
> Suren Baghdasaryan <surenb@google.com> wrote:
> 
> > > This approach is actually quite common, especially since tagging every
> > > instance is usually overkill, as if you trace function calls in a running
> > > kernel, you will find that only a small percentage of the kernel ever
> > > executes. It's possible that you will be allocating a lot of tags that will
> > > never be used. If run time allocation is possible, that is usually the
> > > better approach.  
> > 
> > True but the memory overhead should not be prohibitive here. As a
> > ballpark number, on my machine I see there are 4838 individual
> > allocation locations and each codetag structure is 32 bytes, so that's
> > 152KB.
> 
> If it's not that big, then allocating at runtime should not be an issue
> either. If runtime allocation can make it less intrusive to the code, that
> would be more rationale to do so.

We're more optimizing for runtime overhead - a major goal of this
patchset was to be cheap enough to be always on, we've got too many
debugging features that are really useful, but too expensive to have on
all the time.

Doing more runtime allocation would add another pointer fetch to the
fast paths - and I don't see how it would even be possible to runtime
allocate the codetag struct itself.

We already do runtime allocation of percpu counters; see the lazy percpu
counter patch.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZFKkJJ8%2B/uD0tPMM%40moria.home.lan.
