Return-Path: <kasan-dev+bncBCUJ7YGL3QFBB3MVSLCAMGQEIW6ZDVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 80447B129AE
	for <lists+kasan-dev@lfdr.de>; Sat, 26 Jul 2025 09:59:43 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-74ea5d9982csf2461499b3a.2
        for <lists+kasan-dev@lfdr.de>; Sat, 26 Jul 2025 00:59:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753516782; cv=pass;
        d=google.com; s=arc-20240605;
        b=TB40/9CrTRQ9n1xkpiI8fFLZCip37ZhmYSW3TCrbW2dpmAZI9v4FtrVbfrDQFruldd
         b5w9TT49WbSqD04DO22fO6Vjkyt2gbzUr5j2wnqe0nW09ZATEIVAK/tgz749pp0UFh2T
         3hLukfNKmBSTTGtr3oeHoIGJlKzbVpXcNbuuih8JHqrK8noO//SHkh6uhnb1WUzlcBkK
         gzsFjhMyemd79ttbO1/S7JKIIzAc0rwYdHptRTdkchSDjD4+N+u2OtC0E57ybK8C9J1g
         xatGpE5auWpUQ8RWWWtx/dXeU3OaIxokl9+w0UmdpXEViNGoaM1IVK43KmHM8URM3jTv
         YRxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Sn0esjSJYFwjl96kmxqKXgW1ot17UKWYxzoR+pfPSTE=;
        fh=xES9ilg3ble16HmVq69Je6wCe+IKzVLeXn2Kc49pMDs=;
        b=jFdJ9oAuY+Kms3NP0WlXhxvuGbDHd8V3Mcv390YVhH/ZE6TSfngk6804DM7o7lugCH
         Xbgtvn5xvIlJ64+rHbVHrH8rGjejBWGLkKURY1gt04GbSI7JkTMwwrWYSe66zO24VpQ3
         aoztVUFDGD+kVO5t6KhacfEhoYTTVju6ifqB8ocJSHCn9n+Qfi8+Xq3oFpM43agDD3h2
         CwAD7FoG1M28fMR7NFCHKmHT1ASvE2MOy/Q0OFDYosxBtEvY21ZjSwRdFtkMCI3sbOXd
         j2YK8nDQV0lAHor8zJ4ovEw4Uffp4L1bvhTwhfrhQCTp5oJQmdYveWg138c80DeE+OH+
         WjiQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=fVrDNwtE;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753516782; x=1754121582; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Sn0esjSJYFwjl96kmxqKXgW1ot17UKWYxzoR+pfPSTE=;
        b=OC1kR6ntwD/Ov+XgWreu2Ai2/gLJ2OsqZCJMZ+qk2IWiJ2k12o6ZTIXdIMbJIc8ekF
         +F1ZfUX4tvYE0r9PgVclrTUAkBSeYk+49iHl6zodOl8lOXQjoIOLCp79DJ5VTR2cc/d7
         /AI86js/e2lgINC5aNmqVHMUdnPrFIIfB8zMELAw/k5y1Uuz47XRgDEQY1e4cbiuahdl
         YQazroeOupy5N9yMiQjW3FLgICB+t3MohOp8p9BWkCVy1Qfg0EshwnAiL9Hz/Qd2ABfR
         v58MZwiTAGkEaoConlvaT939+xn0KvDXBkvGYlO/9p4WhUUy5F94pGU6BDxkvvbtuv31
         PmdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753516782; x=1754121582;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Sn0esjSJYFwjl96kmxqKXgW1ot17UKWYxzoR+pfPSTE=;
        b=aFMWVNncSYUXzQBySTWT0EIRASQJkoUqbzZ6z8iqfXlZotirrn9fzNoqoIMOgTdbly
         yrzyKz9++TJOYVFIs02DvUxlUTILINRVa+MvedDJhN/rKKn4AWjOyaRZfET4VdG3VMBE
         AfCZsqwDOwPJH8u5EiAl3kSv4Q3IBzVipYE0F44sVwyadjVz0nSqvk5ws9NNuyMMA1SO
         YIuAsuorQws71+Ed9J58hPVcgs0/zBROaxvH40Klz6EIEPXdNGumoUzDdeT+ILNOzrEl
         mpvUdnCJUFRZuDrZ44gbb/cjVzr674cu7lkL7HDLnUN0kf7/F+0P9JB35a3RnOz0+mbq
         2ztw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWjcDn2wjh7zwskFqTFkSYvN+neC9MaeOxztCUAOn1h+pw2CMLUDREZJ7mGQ/vKNpKi7Ougwg==@lfdr.de
X-Gm-Message-State: AOJu0YwN+GGpp8X4G6PfpUeDn6chIijKlBheGLoJT/PLFi7eTElwbn1U
	oGFHQLg2wxeE5gRNDMq8hIYy/b6teOmznWJXQrreQvniZLcClzHdRrTD
X-Google-Smtp-Source: AGHT+IEPP19QstTMNs522E3lRr+ISn8tYbCuSFKbgU1br/is+7GoQue+fmUP+sl9MT71IVNB6krOiQ==
X-Received: by 2002:a05:6a00:3d07:b0:748:33f3:8da3 with SMTP id d2e1a72fcca58-763389acd06mr7776483b3a.19.1753516781595;
        Sat, 26 Jul 2025 00:59:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf8q/6OdZ8BDQw4I5BmbMCNVb6cXuzskJqhFljnh5J0hA==
Received: by 2002:a05:6a00:4603:b0:732:d98:9b2e with SMTP id
 d2e1a72fcca58-7615fe9804fls2882702b3a.0.-pod-prod-04-us; Sat, 26 Jul 2025
 00:59:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXZzNNGFxP+ZgtdBOxyWzEqTMMPIJj0/Sl1zBynAYtbDKUMGQmiaMmB48VuRS+pNn74z7Omqubbqlg=@googlegroups.com
X-Received: by 2002:a05:6a21:33a9:b0:22b:c70:398a with SMTP id adf61e73a8af0-23d70150d36mr8103570637.25.1753516780131;
        Sat, 26 Jul 2025 00:59:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753516780; cv=none;
        d=google.com; s=arc-20240605;
        b=OfdXinvTO69ZciHlCcKjBsWWB5aH/JCKfO1MziUxizbjahqOaR/8Tsj4vzOY3IaOkJ
         6AzuNIFzgr9nRjZSOr07NNobAGw4EuWuucrzFGy46TQ7RTIRP11joApkjMbHMmWRdrYe
         5rLeRUDW39lpi4hsrCNAiBy4H7IeSgTv3D4QKylCe8pThk6y2ApbR8rqZHshAUtSJFoG
         +8llVlcX1HB9Yerh7++E5IVA8MZ+uF8I7BZX1gbAUDzUK3AgywbO4/CS6ajgkysvNY1c
         ypJcTe8cvQ54CVO4zk10nnnFdw9f+GCkL4IXjq/1xDD4UGNO752PhFJ6/DCc1k7tHk7P
         Ozyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=tp3zoLi+1taRlaLqKtga/Kw94vL/c5reN+4UwIZcpP8=;
        fh=RQgD7bi18w8eidXxn1RhqWwK8/2vZLd62hD0GPZ9aG8=;
        b=DPgBHuXv5AHxF3GyhLV2h+BU/lYH9g3OG4vxW+Zgyc42dJ/T0GlqZ1OOfHdVe61JOn
         A1EkEMbQmmh4V/uAlG7GXH/+fQd50TVp6ihgXKJG/Clq/DENBK5FgxuJCOMQME69sMNa
         5L4cnFK3Oq5epjRM9BU8f2eqAEqiKWZ4fgEZSRvO2KWwGj0tHO9tUbOK0D0/Va2oBqxQ
         iZi0ITQB1Q66QmujG+SGrNVvwecZlGsJayiYDwylLKrv4P0Zwt2yrE2y0Nl7LIiZ1j0z
         mtigiMcQ8DXF0L/lXqPmUmDRsR21x75EUt683JfNnx4IdiYOoWUoAsH6a37Ln/QKQ1bk
         1fhA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=fVrDNwtE;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b40bd2900d8si39011a12.4.2025.07.26.00.59.39
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 26 Jul 2025 00:59:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id E1041601D3;
	Sat, 26 Jul 2025 07:59:38 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 950F5C4CEED;
	Sat, 26 Jul 2025 07:59:37 +0000 (UTC)
Date: Sat, 26 Jul 2025 09:59:35 +0200
From: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
To: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Cc: Yunseong Kim <ysk@kzalloc.com>, Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Byungchul Park <byungchul@sk.com>, max.byungchul.park@gmail.com,
	Yeoreum Yun <yeoreum.yun@arm.com>,
	Michelle Jin <shjy180909@gmail.com>, linux-kernel@vger.kernel.org,
	Alan Stern <stern@rowland.harvard.edu>,
	Thomas Gleixner <tglx@linutronix.de>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	stable@vger.kernel.org, kasan-dev@googlegroups.com,
	syzkaller@googlegroups.com, linux-usb@vger.kernel.org,
	linux-rt-devel@lists.linux.dev
Subject: Re: [PATCH] kcov, usb: Fix invalid context sleep in softirq path on
 PREEMPT_RT
Message-ID: <2025072614-molehill-sequel-3aff@gregkh>
References: <20250725201400.1078395-2-ysk@kzalloc.com>
 <2025072615-espresso-grandson-d510@gregkh>
 <77c582ad-471e-49b1-98f8-0addf2ca2bbb@I-love.SAKURA.ne.jp>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <77c582ad-471e-49b1-98f8-0addf2ca2bbb@I-love.SAKURA.ne.jp>
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=fVrDNwtE;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates 172.105.4.254 as
 permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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

On Sat, Jul 26, 2025 at 04:44:42PM +0900, Tetsuo Handa wrote:
> On 2025/07/26 15:36, Greg Kroah-Hartman wrote:
> > Why is this only a USB thing?  What is unique about it to trigger this
> > issue?
> 
> I couldn't catch your question. But the answer could be that
> 
>   __usb_hcd_giveback_urb() is a function which is a USB thing
> 
> and
> 
>   kcov_remote_start_usb_softirq() is calling local_irq_save() despite CONFIG_PREEMPT_RT=y
> 
> as shown below.
> 
> 
> 
> static void __usb_hcd_giveback_urb(struct urb *urb)
> {
>   (...snipped...)
>   kcov_remote_start_usb_softirq((u64)urb->dev->bus->busnum) {
>     if (in_serving_softirq()) {
>       local_irq_save(flags); // calling local_irq_save() is wrong if CONFIG_PREEMPT_RT=y
>       kcov_remote_start_usb(id) {
>         kcov_remote_start(id) {
>           kcov_remote_start(kcov_remote_handle(KCOV_SUBSYSTEM_USB, id)) {
>             (...snipped...)
>             local_lock_irqsave(&kcov_percpu_data.lock, flags) {
>               __local_lock_irqsave(lock, flags) {
>                 #ifndef CONFIG_PREEMPT_RT
>                   https://elixir.bootlin.com/linux/v6.16-rc7/source/include/linux/local_lock_internal.h#L125
>                 #else
>                   https://elixir.bootlin.com/linux/v6.16-rc7/source/include/linux/local_lock_internal.h#L235 // not calling local_irq_save(flags)
>                 #endif
>               }
>             }
>             (...snipped...)
>             spin_lock(&kcov_remote_lock) {
>               #ifndef CONFIG_PREEMPT_RT
>                 https://elixir.bootlin.com/linux/v6.16-rc7/source/include/linux/spinlock.h#L351
>               #else
>                 https://elixir.bootlin.com/linux/v6.16-rc7/source/include/linux/spinlock_rt.h#L42 // mapped to rt_mutex which might sleep
>               #endif
>             }
>             (...snipped...)
>           }
>         }
>       }
>     }
>   }
>   (...snipped...)
> }
> 

Ok, but then how does the big comment section for
kcov_remote_start_usb_softirq() work, where it explicitly states:

 * 2. Disables interrupts for the duration of the coverage collection section.
 *    This allows avoiding nested remote coverage collection sections in the
 *    softirq context (a softirq might occur during the execution of a work in
 *    the BH workqueue, which runs with in_serving_softirq() > 0).
 *    For example, usb_giveback_urb_bh() runs in the BH workqueue with
 *    interrupts enabled, so __usb_hcd_giveback_urb() might be interrupted in
 *    the middle of its remote coverage collection section, and the interrupt
 *    handler might invoke __usb_hcd_giveback_urb() again.


You are removing half of this function entirely, which feels very wrong
to me as any sort of solution, as you have just said that all of that
documentation entry is now not needed.

Are you sure this is ok?

thanks,

greg k-h

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2025072614-molehill-sequel-3aff%40gregkh.
