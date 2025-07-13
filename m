Return-Path: <kasan-dev+bncBAABB5EB2HBQMGQEPMNZJ3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id C6C8AB0336F
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Jul 2025 01:27:50 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-313fb0ec33bsf3560553a91.2
        for <lists+kasan-dev@lfdr.de>; Sun, 13 Jul 2025 16:27:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752449269; cv=pass;
        d=google.com; s=arc-20240605;
        b=b2riACkIZnmvmVn9g2fqcAwW0w/IAuQsg9DDYcHK4M9XuxRpu8gAKkG2aSQJLRKRgl
         LcvdThIHGBjUbFVOQsvOoDpPX/7kW5eIZqHjGXKRIM2hZdIok5oQdfBI68oWpltXjaGC
         HV613aBrYUQ9ZTruxQlHXJrkJUPCJf5NGwjcYYrTPaLsulkaClfxqjKAfdHxH8y00DhE
         4OqWSLhGnTCdfy7QlkvBzCWosnAUidp68jy7DEZeDnHTmB24slBfDfOpNMFRfbWp9dMI
         pe70n98V998s4Uj/So0w43EWVvopmVA3nQbjmwFWQynk63CXcRe2xhHM2q1w6TPsXLhG
         FUbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=kHI9uZO7q4jIfQ4+20BZYPuhWjDVwkF/ESUEEAfGih8=;
        fh=AqMwGktZzwsr+/ISh7ndYJ6VOhoaA50n2Rw9loGvJRc=;
        b=Cisu2E4iOrj3+PT8Y9rowVxkKWQcvsz3gdLmaAJoo9hU+sd08wN2wKCfd249tfDhAo
         4wVfNkG8ZmpsbjlTInrhIJxsXGhc6umsewgtfDkFjOwXzzJE18Wwkg9jAfNs1629PRfU
         7rPUFAtwgKt5T3hBmmOhekBVedyI/77ezK1FQt/bH7+jbFiEOm6m+CvNeojO7YHv0wot
         b6sebV22TXAhv5LJFzfMchbgFu6o/hFmhdxj6lDWnMPeZPfFsqhbnBMLwhxKDzWEP1tE
         8Cn0hxSlYegirqp94N3wHWC9O4j5SMZ0n2zuLV2K682gmFKeslZZkKEcLfwEP4OmCv41
         U9og==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of byungchul@sk.com designates 166.125.252.92 as permitted sender) smtp.mailfrom=byungchul@sk.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752449269; x=1753054069; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=kHI9uZO7q4jIfQ4+20BZYPuhWjDVwkF/ESUEEAfGih8=;
        b=EaQ2tiMVBvu6oQI54MxY9WcnN0PaD1+8AyEDpV00Ay/LoaEta5FyO1WQU4D/z1BOIK
         eqgzkVb6CZ7cCaJULz8E/GGY+lmkMY9Oy96zGPIG5IE+9MGBzlJT2i5xNti8azZXcnHd
         38VVlTKT0ExcK2XTHLGsMEPywU6I+pBOGZVaGmhIqkG22VIF6M+7g9awSbw1yZJNKASp
         QgtcwFONl6uLPcb3Iebn1YJIY82GsQIkt8FebuZg6EnGV3OJnzqYEGbWNU0lbnmuYTSP
         8NtlgQsGfLFheHUPIOP95othlxgwgdO33I7bniBQtIZ4GpDN6bC1Xw/uifUb41lKa2+K
         7RGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752449269; x=1753054069;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=kHI9uZO7q4jIfQ4+20BZYPuhWjDVwkF/ESUEEAfGih8=;
        b=LLvDUoXKNqDl/a4M+QNiGlIBETp6yAD72ngsoCnI2zx6+akEagtUiPbBlobtsHpiSC
         iRkSrVD/N7F3KuAKU5sef2aHN4tOopSDkfTftueMpyaZcPlaeb1PfjBdky6Of7yzF0yS
         t0GDal21z///AScxld4qXLzF+kSCH6tO/BvzQ2cv7PeAF7Z95wd4yM4ivf68hPsY/z0l
         Nm3Jqeh4cfK9v6IZTGZdkacPQNqLFOpr23IqIArcQdy5CfRQXSOJGfTkotPRRI4K5NUv
         aY7CY5DuiJ06w4ZJQf51XkpwXNViNi5FwrTuArDO5BQyIDd1ywRwWQRQAdG/ICfiu49r
         QKpA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWfZyvlNf5hKxLNO0IcbbJ676vVaIgYAdJVjb42jnST/ys30JdROQPKsEjdDaKhrN4boXw33A==@lfdr.de
X-Gm-Message-State: AOJu0YyJSJCTQDgpZy3I6OULhlCBF67CRU6TJMU0PCp2RxVbxE5HIY9B
	aj5NTddN3oe8UsnncpDINJHNRA9a3n57DlZMSk7+7Aw3NLLpKv9x71kO
X-Google-Smtp-Source: AGHT+IFkHTUVjkStiTdMJW0Y7azhRy0o/BtHy8Uwu6x20Y6dNdyCegX2y+1eb6iZCbcB0wDhSENGfw==
X-Received: by 2002:a17:90b:184d:b0:312:e49b:c972 with SMTP id 98e67ed59e1d1-31c4ccdaa7dmr15661991a91.15.1752449268968;
        Sun, 13 Jul 2025 16:27:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcJ52LlFgrsevhnbpLH5wEfABLbI3q/2k206L0B0NwLmA==
Received: by 2002:a17:90b:3609:b0:30e:8102:9f57 with SMTP id
 98e67ed59e1d1-31c3c8b6489ls3152447a91.2.-pod-prod-04-us; Sun, 13 Jul 2025
 16:27:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXdzJhwLeGFNIDbv0R6iM2SqKuIcZadaHJgC7GVV+o42/WGsZNLJPO+h1OYfGhD9EO0Jm5hDwzD6wc=@googlegroups.com
X-Received: by 2002:a17:90b:17d1:b0:311:b5ac:6f6b with SMTP id 98e67ed59e1d1-31c4ccbbec2mr18196921a91.9.1752449267842;
        Sun, 13 Jul 2025 16:27:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752449267; cv=none;
        d=google.com; s=arc-20240605;
        b=cWcaWIkjlf0vvWcv22OOpRTWpDFgVxTtF2rs53t6tPjYPbMGoR/uiEsyJ7AEpQ0xWr
         UuADGzITz11oezshTGaIX0o2EhWRiKsPISqlbeYjuxcnALYg/f6EIJCTIcXsh+CLWkTz
         HRD+xVdZiUDkydr/yFmqhoUkyu6q5jySJo3otGgd0bkrRoGAi4HLSDq5yY2nY3q0phud
         QJPpTbsEn9BIKT2Btp7rGFF0qKddZQbxxJuj6crjfW7NTd4KfmIzBY9WR9RZ4PQR5j0p
         A/p7PZhVFSTIzVuhgAXHNu3CX+E5A2a8i+2j27D6HwfhidwBa9TVMUMWkpMVXaR9oSGe
         3hzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=1xw1ouskdusNRcbgp4uxp4FwvsFlVFNyTSL6KjlcnAI=;
        fh=/51sRVcLsGnJKIpmrffFstLs3g1tKJDJr/8/6qVYv/E=;
        b=Co9f/Krz0uru5VpiwXBavCk8av/OaPussfo8gpHbkTE60oFiiWEnkZ+pkie92RzdOP
         nTU7zMurNzlaUKcTNoe79pksO7R0K1vyfF3o3EeAVufAzpQn0vxyati0BOQN/EitoQ4Z
         bRbEQIaiwSrDEphBOpOm9UrJ07IQ63MMh87Z20WR3Q7kjseVt7nWSNHWtzUCL4qtC9Fw
         WMhY4EnR/LqO2mGEU2RNryeFEaCN/1FkGs4C3eRODPpxLjiHtV3B1T3PqHm8H11/zWt9
         TKkvzn729/AGjE/5X0LDF+Bc//ilBcd5Ro00FX2n1IndPWTD7jswrWBp5rOWsOzgWgGI
         /1jw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of byungchul@sk.com designates 166.125.252.92 as permitted sender) smtp.mailfrom=byungchul@sk.com
Received: from invmail4.hynix.com (exvmail4.skhynix.com. [166.125.252.92])
        by gmr-mx.google.com with ESMTP id 98e67ed59e1d1-31c22ff31a0si429881a91.1.2025.07.13.16.27.47
        for <kasan-dev@googlegroups.com>;
        Sun, 13 Jul 2025 16:27:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of byungchul@sk.com designates 166.125.252.92 as permitted sender) client-ip=166.125.252.92;
X-AuditID: a67dfc5b-669ff7000002311f-54-687440f1ab53
Date: Mon, 14 Jul 2025 08:27:40 +0900
From: Byungchul Park <byungchul@sk.com>
To: Yeo Reum Yun <YeoReum.Yun@arm.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	"akpm@linux-foundation.org" <akpm@linux-foundation.org>,
	"glider@google.com" <glider@google.com>,
	"dvyukov@google.com" <dvyukov@google.com>,
	Vincenzo Frascino <Vincenzo.Frascino@arm.com>,
	"bigeasy@linutronix.de" <bigeasy@linutronix.de>,
	"clrkwllms@kernel.org" <clrkwllms@kernel.org>,
	"rostedt@goodmis.org" <rostedt@goodmis.org>,
	"max.byungchul.park@gmail.com" <max.byungchul.park@gmail.com>,
	"ysk@kzalloc.com" <ysk@kzalloc.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"linux-rt-devel@lists.linux.dev" <linux-rt-devel@lists.linux.dev>,
	"kernel_team@skhynix.com" <kernel_team@skhynix.com>,
	"urezki@gmail.com" <urezki@gmail.com>
Subject: Re: [PATCH v2] kasan: remove kasan_find_vm_area() to prevent
 possible deadlock
Message-ID: <20250713232740.GA18327@system.software.com>
References: <20250703181018.580833-1-yeoreum.yun@arm.com>
 <CA+fCnZcMpi6sUW2ksd_r1D78D8qnKag41HNYCHz=HM1-DL71jg@mail.gmail.com>
 <20250711020858.GA78977@system.software.com>
 <20250711021100.GA4320@system.software.com>
 <GV1PR08MB1052126BB553BD36DA768C998FB4AA@GV1PR08MB10521.eurprd08.prod.outlook.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <GV1PR08MB1052126BB553BD36DA768C998FB4AA@GV1PR08MB10521.eurprd08.prod.outlook.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Brightmail-Tracker: H4sIAAAAAAAAA+NgFlrEIsWRmVeSWpSXmKPExsXC9ZZnoe5Hh5IMg3f7NCzmrF/DZvF94nR2
	i2kXJzFbLHvyj8liwsM2dov2j3uZLVY8u89kcXnXHDaLe2v+s1pcWn2BxeLCxF5Wi30dD5gs
	Vl9ksdj77yeLxdwvhhZfVq9icxDwWDNvDaPHzll32T1a9t1i91iwqdRjz8STbB6bVnUCiU+T
	2D0W/n7B7PHu3Dl2jxMzfrN4vNg8k9Hj8ya5AJ4oLpuU1JzMstQifbsEroz7d/vZC65wVOze
	85e5gfEFWxcjJ4eEgInE1h9NzDD23XknmUBsFgFVia2/GsDibALqEjdu/ASzRQTUJH6uOgZW
	wyywi03iwvtEEFtYIFKieds1sDivgIVE883ZrF2MHBxCApuYJN7aQ4QFJU7OfMIC0aolcePf
	SyaQEmYBaYnl/zhAwpwC8RKPzk8FmyIqoCxxYNtxIJsL6LLp7BJLl25jhThTUuLgihssExgF
	ZiEZOwvJ2FkIYxcwMq9iFMrMK8tNzMwx0cuozMus0EvOz93ECIy5ZbV/oncwfroQfIhRgINR
	iYf3xpbiDCHWxLLiytxDjBIczEoivK/uFmUI8aYkVlalFuXHF5XmpBYfYpTmYFES5zX6Vp4i
	JJCeWJKanZpakFoEk2Xi4JRqYIytEl/4xfodQ6X/3dmSFUerlnmd4zbh8BTNNvmZ43z613zH
	ma2B84qXndr89JyVw0TulbseR8zglov7W9Fc8l/ha1ZLce6zdXITGYXeVK/7zKNSHH/XULpp
	l338Wz5vZr8Tn4RrFQWSdkjPaSiPYFE10BI7mr3uRZpWV92m7y3Sv/e+Dvv5WomlOCPRUIu5
	qDgRAOKU1i+1AgAA
X-Brightmail-Tracker: H4sIAAAAAAAAA+NgFupkkeLIzCtJLcpLzFFi42Lh8rNu1v3oUJJhcPW2uMWc9WvYLL5PnM5u
	Me3iJGaLZU/+MVlMeNjGbtH+cS+zxYpn95ksDs89yWpxedccNot7a/6zWlxafYHF4sLEXlaL
	fR0PmCxWX2Sx2PvvJ4vF3C+GFl9Wr2JzEPRYM28No8fOWXfZPVr23WL3WLCp1GPPxJNsHptW
	dQKJT5PYPRb+fsHs8e7cOXaPEzN+s3i82DyT0WPxiw9MHp83yQXwRnHZpKTmZJalFunbJXBl
	3L/bz15whaNi956/zA2ML9i6GDk5JARMJO7OO8kEYrMIqEps/dXADGKzCahL3LjxE8wWEVCT
	+LnqGFgNs8AuNokL7xNBbGGBSInmbdfA4rwCFhLNN2ezdjFycAgJbGKSeGsPERaUODnzCQtE
	q5bEjX8vmUBKmAWkJZb/4wAJcwrESzw6PxVsiqiAssSBbceZJjDyzkLSPQtJ9yyE7gWMzKsY
	RTLzynITM3NM9YqzMyrzMiv0kvNzNzECI2hZ7Z+JOxi/XHY/xCjAwajEw3tjS3GGEGtiWXFl
	7iFGCQ5mJRHeV3eLMoR4UxIrq1KL8uOLSnNSiw8xSnOwKInzeoWnJggJpCeWpGanphakFsFk
	mTg4pRoYVfkyX039eKwuy+l9Xuz821OtZzLIne2+pJz56Pvk+XI7YkWaJA83Jwox7svqqRXI
	Ez+wLUt/7smqQL0Slv9z53l7hU2yPdGfodMlwHUh9ujxZ4Izua5l2n/5dfLx7D0NfxMeT1zF
	oj3J37L+yAU+NpbcgOZJeta/5zdLvI7gEu7xCf7FF7NAiaU4I9FQi7moOBEAkEiYeZwCAAA=
X-CFilter-Loop: Reflected
X-Original-Sender: byungchul@sk.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of byungchul@sk.com designates 166.125.252.92 as
 permitted sender) smtp.mailfrom=byungchul@sk.com
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

On Sat, Jul 12, 2025 at 03:46:10PM +0000, Yeo Reum Yun wrote:
> Hi ByungChul,
> 
> [...]
> > I checked the critical section by &vn->busy.lock in find_vm_area().  The
> > time complextity looks O(log N).  I don't think an irq disabled section
> > of O(log N) is harmful.  I still think using
> > spin_lock_irqsave(&vn->busy.lock) can resolve this issue with no worry
> > of significant irq delay.  Am I missing something?
> 
> I don't agree for this.
> since in PREEMPT_RT case, it has the same problem.
> 
> In case of PREEMPT_RT, spin_lock_irqsave() becomes rt_spin_lock() which is sleepable.
> But, KASAN calls "rt_spin_lock()" holding raw_spin_lock_irqsave() which is definitely wrong.

It's another issue than irq handling latency, but it's about lock usage
correctness.  You are right.

	Byungchul

> But as Uladzislau said, without reference count manage, UAF can always happen.
> IOW, If KASAN to dump vm information, I think we need:
>     1. manage reference for vmap_area.
>     2. find_vm_area() with rcu version.
> 
> 
> Thanks.
> 
> --
> Sincerely,
> Yeoreum Yun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250713232740.GA18327%40system.software.com.
