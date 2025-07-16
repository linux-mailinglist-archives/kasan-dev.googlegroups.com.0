Return-Path: <kasan-dev+bncBDK7LR5URMGRBR6Y3XBQMGQERMY43HQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A7C2B07135
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Jul 2025 11:09:30 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-32b3700af0fsf29593661fa.2
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Jul 2025 02:09:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752656970; cv=pass;
        d=google.com; s=arc-20240605;
        b=Su8G2YSHGQ/ZNGWy+hyybl/pKRN5O3yo5a1ut2oebWYD99qJjU7slp78Vf9Xin9K7Q
         ZiyFblEzGHhqHXvvT+LgSbCrqQKvWpjONoC4XZS3yD4KWVM4zVObJzgQvE/1IutQ/uVg
         tqjT3pvhKmn3sKUSpnBCImGwPFaLVEFjwoSzienfWcqy9chj7xddfmW6QXZ8na7y7bPc
         0n3kKpNyCHYkKfFuQbsuR2Jm8DSngawYUqNdX0/j1RGr5aIYkeD3EKI6nPL9FhvUGgOE
         pR13yyvhC+CbbKyIlBcn3K1UZdMVrhCKep1ycKT7tCw7PlmWGY6jRwo2DE3Ydx4H9JVM
         TL7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:date:from:sender
         :dkim-signature:dkim-signature;
        bh=kbz0MDx/1dB5y+pArpE7HF3XSJFL0IXjYUA26XGUVMw=;
        fh=GEFatA45ii/TizYWTxGbsTvc3ey1CJDlC2pZrqW4XFk=;
        b=gtvdAGE4V+2eQKD6EnI2bLTH7AjHeGw0LKJvRJGkg0KwqRXWfRbVCHIWk+SFhRxe6s
         CjdVpo0+URfFBy3RekvCyj+NXzVpC1FL0FxO3IGcFdUgsCzN5w/ylwWN7MAKstCj9XK9
         jj7E5H4KPLMcWAC5B3Aq9CRZYJlMC8xBnjjzTVVsm/t8G0G874GBhf8ePzeT4xdsMmo6
         tZO1Tqb+RZusMXWzm61aGEJdcXXGg6/tkK8yHdSTxQpG5iWftrI6c4vROLWgcPHvU0F7
         BEXoxUc2YlFTwEhi62EN9tnB78k7roVPlUjN2BGjc3NQnVKvcZd0s7FqNaVv0SmSZG6T
         wf1w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=NBxXKW80;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752656970; x=1753261770; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=kbz0MDx/1dB5y+pArpE7HF3XSJFL0IXjYUA26XGUVMw=;
        b=Cbb2RKeCcLVqcudcAwNwM+L6GM8ykFEvMNC7F+SXh23Im4Skrbwk7cK1w3j2nL7i2w
         4lAkLHYU6ATVXt1usIduK7tTP23u1H4LMnMDaC2K0MerVMhcRAYVv37znEtOIY/hgnS5
         4l0xIJcIyq0V18edrHGlkkA8duPffu0lYt1GfYAY9Qih3Bq6cPz/aj4rq8Npo7JB9j+X
         ZQxjxaN5U5IQ25qJZ6OlJmq4CRr5fr2t3qoyfkFdLAxkke5SgF3QRlxbVMRH1dtj8ODE
         yQ8tMsLR2BlZz5+tGoHSTwZ35Teo61dGhUtp2YEKBDqRHH6GgJP9ANPa9J1jk+7C0+ta
         rOgA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1752656970; x=1753261770; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=kbz0MDx/1dB5y+pArpE7HF3XSJFL0IXjYUA26XGUVMw=;
        b=VUcComdpQiZ907o+mBMXyi3Iv44HPwdwk1bc5fpJP8WGBR5W8iM/ViV/YTO02Bbp2D
         RvrMDaKAKtwSPMOjwU+vxFpWXFvEP2eS5ZsFgZouB8bMGK764EZuZ8v2QifmgoGvQ7/m
         Ee3xU7+XD6g9PcbmZL04akcaTJS2rsM+lxsTpH4GsrSATJzXKAbg5lWhD4X4mKlRi/a5
         3KoJmIwZhI7ORQj8FbdbGPszYWB9BpJOzrqTmC5dWD+SbCSDXrqKlvLBTZK8+BHVShH9
         JifJojmQRrZdF195bSBn4WIOksZul2juWazVqJFKd7brTjCFThI7XzXTTTZlWTDTzQQS
         Hchg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752656970; x=1753261770;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=kbz0MDx/1dB5y+pArpE7HF3XSJFL0IXjYUA26XGUVMw=;
        b=ayKHip+P+PheobJTgrJRLUGavqLH23HdrXutP5mV1vlVRmbD8gK/D2Dp+jRghopMx9
         vKQRRDR5eNdQtJ6hCfSMEySlXr8WmPSCxCOhElJOUQQ+V59jlCxSAXsgg6WGeQ7pTxb6
         KUMkdUugWdndq4gqN/O2rirhPU0uN39YWLTmBDzN4g9PGD2btRB4ULf+i+WpTfcHyaVr
         anCyewjPvJh54f6zFTWPeNRCwX7rqQbtVdcGO0FCTPRcMGQcVA/yvZ9Kj1ldlU7M6aVX
         Hv+zbpCIHkNCcgMzoToQLOHFZl/LX+7tBzMHR7N8FerwhxTQM4J2j+CXJ39tFNkyYgww
         UZeA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWjfKzUjZWx6/WVTTkTAUG7ODiE9cOYSYBL/JdF+xYgf7yfuRpJyqkMn/sHqDngFFZV4iuYUw==@lfdr.de
X-Gm-Message-State: AOJu0YztIrNf/F3ok63PSGmiB30nL13SML1GTMvkSoiACHx19FrmPZRD
	KgpcmDnUHU+ol77q4HRw/HffdnvCelGjaHqsGDxWQ3kvgE+BAbngss78
X-Google-Smtp-Source: AGHT+IHp3NbcCqDKWtWwB626K/M0dbvQOCt1uYV8MDqrNHEpKheYUsPLO39ZM9bhMUqaJFDvxsP1Kw==
X-Received: by 2002:a2e:bc1b:0:b0:32a:6b23:d3cc with SMTP id 38308e7fff4ca-3308f5b6844mr6491391fa.25.1752656969218;
        Wed, 16 Jul 2025 02:09:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeYBgKay6HF4H8cxPyuedrjMPqCndS6bznAognUQoNMbg==
Received: by 2002:a05:651c:2cf:b0:32a:6004:f724 with SMTP id
 38308e7fff4ca-32f4fcab2f8ls15746281fa.0.-pod-prod-08-eu; Wed, 16 Jul 2025
 02:09:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU2+bi16W7UZhB32zbkWs/BEuUdnMr8WCDCCV7zUZUi9NPb3BtFToCOaznNBCDAjOyW+iHkTRlO2T8=@googlegroups.com
X-Received: by 2002:a2e:a588:0:b0:32b:4905:e08 with SMTP id 38308e7fff4ca-3308f63750bmr5573081fa.37.1752656965409;
        Wed, 16 Jul 2025 02:09:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752656965; cv=none;
        d=google.com; s=arc-20240605;
        b=MPDTYtlmV7BInK1wWqVuDEC0OI6rdkeYt+10rREr2SKcp57hUtFY5vshqyS5sbWOrJ
         p0dkx8CujT0+7Uvwso02AkL0zpKNBoH7aNkVEXx1aBNmZtxJ2lIKvQ241EbmBge89LDw
         pXZCa7kJNj9g+yklKstxIjlTo0WwOfL0ug2D+Rrvg2Jh6wAfjIfV8ip6SlmZIe3xpfqX
         72mF0G6e3zcHfBRGRiTScjZmrow5cGbxPFDQIOWAGTbK597UkUM8XEiTfLx/whSQ6Iol
         6gL0taEjZgMM+NEkkOeTlkxNVgMkVUZ9EG5XpHzM5CJKS3YJcDCwtqZ497Ak933fZGcl
         oIPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:date:from:dkim-signature;
        bh=2eOTiw68BIyhYHvtk2S5wRVGB/8ahHu3vX68UO+Adzs=;
        fh=pkW+NlX7mglogQVrdbHB3cVb+byjHEtt45dlEIbBZn8=;
        b=gT/E4HmOUXqSaBA3KU+5j5Ngayrk8EJw0VFmTiGp7zswpvt/0L4F0sPxrn0qZLrZYh
         htBoq8kZqlO5HLUqVuomS9ABZ+2lN3BkHPAFHXkgFcywZ6jYO0j2bUzgjYzBNPSxTGj+
         7ugO6FsjQipMpqjY2PJY4Lxm/u0IdUS3U70+pCDgxXFYP0u6hYzdzpOBYyGAh2qmNIKM
         pHWSejWGJLH9CVUc7a4qt+hEZskGXlfWNIWoubcl9YnvxsqKZC7CY+vDjjR9yu3oalTJ
         U/JtxW5q//8vkpbxAxFK0j8m1XMGB4NPdisQtrJ6aFtIZFUinjtqKnst7M9oS4quaJCy
         lS4g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=NBxXKW80;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x133.google.com (mail-lf1-x133.google.com. [2a00:1450:4864:20::133])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-32fab84ef66si3886271fa.8.2025.07.16.02.09.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Jul 2025 02:09:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) client-ip=2a00:1450:4864:20::133;
Received: by mail-lf1-x133.google.com with SMTP id 2adb3069b0e04-54b10594812so6209241e87.1
        for <kasan-dev@googlegroups.com>; Wed, 16 Jul 2025 02:09:25 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVIQQGWoTzowiVWINH/sV3sfpCTOFe75l6bo5hNJPDZSgLA26O6TQ0bOphSDZqlmWOoW0b1y7KlhCQ=@googlegroups.com
X-Gm-Gg: ASbGncsqyeh40n5yZDJfbjl6eTgK8x9yzcXm7TUlsESMET8IiX2LNqnOhTSDGKF9ba0
	nGvly74IUj1SWUidFFzYl79P/VhCXwV7pKFDP88tBJELxnT/H7LEB931JiZkyzRVhf3AFlv9ay7
	MQ4BaYs5tvDUV0d9B9qq4vfERHAFKKPcUmO2flcj4ztp9/SflfRLGNKhwDa7jPELQzzMlt/jt3h
	f9/tiLl1GXY2oY7kKm1M3n4/bN7aq4KLyPO0SYeDqPwUnhwY/kISM7Bp1gbXb+YUxkrCX9deJq7
	cR0qq4YGlWGf/Su8hGmbNRZ64Mfb2TKRi1kD33kbYTNuEv+flEOSBP3nliJ/V8+c+pj7XVW0FMg
	rk6K1DEacdO87B4xJnL8KxOlv72T0Wuyp4e8vNwhlBy6M0Mo=
X-Received: by 2002:a05:6512:1313:b0:553:1f90:cca4 with SMTP id 2adb3069b0e04-55a23eef245mr521782e87.13.1752656964569;
        Wed, 16 Jul 2025 02:09:24 -0700 (PDT)
Received: from pc636 (host-95-203-27-91.mobileonline.telia.com. [95.203.27.91])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-5593c9d0f1fsm2561084e87.107.2025.07.16.02.09.22
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Jul 2025 02:09:23 -0700 (PDT)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Wed, 16 Jul 2025 11:09:21 +0200
To: Byungchul Park <byungchul@sk.com>, Yeo Reum Yun <YeoReum.Yun@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>
Cc: Yeo Reum Yun <YeoReum.Yun@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
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
Message-ID: <aHdsQYvKN-dLQG2O@pc636>
References: <20250703181018.580833-1-yeoreum.yun@arm.com>
 <CA+fCnZcMpi6sUW2ksd_r1D78D8qnKag41HNYCHz=HM1-DL71jg@mail.gmail.com>
 <20250711020858.GA78977@system.software.com>
 <20250711021100.GA4320@system.software.com>
 <GV1PR08MB1052126BB553BD36DA768C998FB4AA@GV1PR08MB10521.eurprd08.prod.outlook.com>
 <20250713232740.GA18327@system.software.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250713232740.GA18327@system.software.com>
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=NBxXKW80;       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::133 as
 permitted sender) smtp.mailfrom=urezki@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Mon, Jul 14, 2025 at 08:27:40AM +0900, Byungchul Park wrote:
> On Sat, Jul 12, 2025 at 03:46:10PM +0000, Yeo Reum Yun wrote:
> > Hi ByungChul,
> > 
> > [...]
> > > I checked the critical section by &vn->busy.lock in find_vm_area().  The
> > > time complextity looks O(log N).  I don't think an irq disabled section
> > > of O(log N) is harmful.  I still think using
> > > spin_lock_irqsave(&vn->busy.lock) can resolve this issue with no worry
> > > of significant irq delay.  Am I missing something?
> > 
> > I don't agree for this.
> > since in PREEMPT_RT case, it has the same problem.
> > 
> > In case of PREEMPT_RT, spin_lock_irqsave() becomes rt_spin_lock() which is sleepable.
> > But, KASAN calls "rt_spin_lock()" holding raw_spin_lock_irqsave() which is definitely wrong.
> 
> It's another issue than irq handling latency, but it's about lock usage
> correctness.  You are right.
> 
There is vmalloc_dump_obj() function which should be used IMO:

<snip>
pr_err("The buggy address %px belongs to a vmalloc virtual mapping, dump it...\n", addr);
vmalloc_dump_obj(addr);
<snip>

we use trylock there to eliminate an issue if invoked from the IRQ
context.

--
Uladzislau Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aHdsQYvKN-dLQG2O%40pc636.
