Return-Path: <kasan-dev+bncBCUJ7YGL3QFBB6XOSHCAMGQETSLEHZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B9CAB12939
	for <lists+kasan-dev@lfdr.de>; Sat, 26 Jul 2025 08:36:44 +0200 (CEST)
Received: by mail-qk1-x738.google.com with SMTP id af79cd13be357-7e623cb763bsf507223385a.3
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Jul 2025 23:36:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753511802; cv=pass;
        d=google.com; s=arc-20240605;
        b=TJ+/RBAOf2It9Fn1h54638fwitVxnvss1tXUnrej77uhSlXZmbHTOMcf1hKOPJ1S4K
         1icwHRJtezSjY0kcHkyT2eW/sWVTqxCwxMZszvXgldzaY1pmNnukhHF081abYYcS0W0X
         XFo6jerkNM/+PtssJmPIgm8heKOWSZXobzL/HlxcWAs8yRn3n0fcubNWD74q4Q/uzwZR
         RnoC515/Fysnazc7IVrGysbzkVCHYSXKcfm2ZpZoe3mOPEKk1tyny4QS5VucrYy6zqdt
         v9R13e8mG1Sm6cX0z6hg0pmAcIGVY9+PtiODvlh/fjHg5bPq410KNb3aAghgH5rMUiZe
         RGUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=nr/zYy/xlprYVTVTK7vteVhO3NELpKbp3th6m1p3D4Y=;
        fh=1K8MSNV4yFG6vVbqSPKeB2mHXnwHc5aF3AYezPdGqro=;
        b=Nm9W9hZG6rfyiqNuAv8Z6kCv/2pKXSckThDYYkMtEu5NTPFpRT20TsloUX3P7dwx6/
         F/qThQzdLJJWcEBosvuEh6bSxQBtotkC/dOFdSdpo2XIQQbkAGmiLT365/uMciyGNP0U
         sCyMRNMB1+c+KfcvzZYGlMWY5d+k1ZyN8Kphh/+YDe6i7CRSkfkSVSvns69pKtxJ0b1A
         Y83DVqbHdD39ZW3mMgCm/dDpH5OehHcfurFPfc93O88SQTnMR7w1s9j0aCdWb7r+cGRs
         jKHXLuJW/gofydE9QbxprBEF77/YqtT8Vpzp3oyIi9c/CFQHk25jQ+q2xkj/MuFShI0w
         yhFg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=Z4FAtJ2R;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753511802; x=1754116602; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=nr/zYy/xlprYVTVTK7vteVhO3NELpKbp3th6m1p3D4Y=;
        b=hBJBpyOmKu7fl7o+5YlnD3jukJf3DAYOIxbze5nRKZmaAD8SkGgAX45JxDNVdAcJaF
         VyivJn24CdcaD4HMCvw0Z0n8mk9GXFHzFrvXGhIo9T+/855gH0RPI50aOYMDcfFdSg54
         gHbAUOHtmfilooyOcDlG336tqd7iYh/803l7UHRNNN6CNLeHxu3OzXvMN57eT7O5cTyP
         Wwf1ZQ4VufYr2PKeiScP3sMKpkxYYmQt0JW858Yes2GqzWzILbGbR3p7SGYAHCFyQA2d
         jjNT7dM3erYyAHWLaFe1TcdxWlGECNcbZibh9YhqPoqXwELk/G4wGPOkh6XmZXPPa4AP
         2u+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753511802; x=1754116602;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=nr/zYy/xlprYVTVTK7vteVhO3NELpKbp3th6m1p3D4Y=;
        b=uBaTxpgKKtOOUXR7j/jN7t4bRMPZYwe0tBUWm8sksaRo1LqlZb4Xzg+vnCuH/VtRKY
         FjLcYCqFyKEXtthy8Ou0KUYNTAFucWEFESlwq7Wp+699kIEsRrWxXcmAXBl4KxqPvb7R
         6p6zVkpNfYInvjA2+XX+3oFZ+ka7SbT9yINhebayTMDGy1LV6XgIjJPip1rw54OIsnVx
         DIsNT+HIS3OZKcUZN3dmMfY3E/P7Jcbh+zr9aogLecLSMyWfq9u6QWmxi4G3ixopnzil
         fEsAMxCj02AW3uR7Fh3mES6+kT/Cf4o+ck/eiNmluqp3KxqlqvVg9RNVN/q2Rss6UZuo
         g6Ow==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWhF5JXTsLMKSb9YTn+wT+EZNCKTLBTnKKhtTwElKb2MGJq9/r3z404qcTxLOEmhye0kqHaQg==@lfdr.de
X-Gm-Message-State: AOJu0YzdO31Xopzzj0uCvwRWooJBcSk+g2encmSSXl1plyIVwtzp8m2E
	ncJf2wp825FdZNDP7qyaqJ3pVTD0a1Qb8+uF13TjkOltfxn2mVkqpwWQ
X-Google-Smtp-Source: AGHT+IGGwwWR4psT5jqGNlErshn6H8PSfbk5Sxnu0qHgls+udsvCwLNoMxkViBy+cbjrUR40wWekQA==
X-Received: by 2002:a05:6214:1c8a:b0:6fb:43d:65b7 with SMTP id 6a1803df08f44-707205c1e15mr72085756d6.36.1753511802567;
        Fri, 25 Jul 2025 23:36:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfiH51UYGXLbiULT11CmaE4TzJxOzquYAu60iClkNVq3Q==
Received: by 2002:a05:6214:4285:b0:6fa:c598:5a6e with SMTP id
 6a1803df08f44-7070d2a0aabls35638216d6.1.-pod-prod-09-us; Fri, 25 Jul 2025
 23:36:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUzXCtsbLFV9VdLHQqqlJqNRbFld9UC5sKHWM0pP0/1h0vqJyOmJhlXeUPA5/lNbu4syI5+HzZZTVo=@googlegroups.com
X-Received: by 2002:a05:6122:2228:b0:535:e714:70af with SMTP id 71dfb90a1353d-538dc84a416mr1529801e0c.7.1753511801590;
        Fri, 25 Jul 2025 23:36:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753511801; cv=none;
        d=google.com; s=arc-20240605;
        b=NEsKeTmLbrU3czrTMMZv2a+XUwCO8S918cEkVVkYps+eaUXNraElEHt4cbdQ3D7PAW
         KmQQy/vOoWtDwu0zu4tUR/Sws1f3yiMBLCJvQqZK5YoMRgOvTipJo1/rKWaO78OhEJBT
         ltlQsHfUGNTDH68m6WM0jUV25c2jfIvZ4SxtTWUYsN5IJOP/9WjbJjDmFD+27cM0yL2E
         gsHUNJBOuHvBS/trkQwYyM0Vb840v4NfJhcSPJYliGE0vfspBfPXetV6Td8gZ0PoxyFS
         UsqqpBf/jH6te0qR7qjuTSf4YjxxGZ5DuurM+eG2YVxQUgCszNyxpTmxrw7n87l2LBVo
         UFbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=pW0pooXYQvLDCs8wfthBx1Dgd/2g/FlgH6hfWAXIty8=;
        fh=Ig7NkDQesZPQ1rmh9vkc/24pl4lU7JxF4zv6ukEgJ9w=;
        b=eRvuZy9A0CXA1Pjc/BRwdtCkyN1i3ngwxT3jzB4k7LDW37DKm+FdOgGZnugLWSuKXI
         nWrdmLNWDUM2CW89T8qa5J0tjoPcN1bsbnOub0j8HmOk0jXOBXdWXDJFimn8Rcmr9nJI
         ML9QYFfNJXVQQ9i+WXlS1/eQsvSjtueeYFNLSb9lx+CgnEHKGe2EczFNU2E00x3vPqVO
         TzhSWXLxmsEgopD61wzncMYqxvUWA8GeBidN3S23DdansarpgFvCS250uc2gbuT6Nb2s
         8G60Qditi6l+M952YbpFs97lykKnDSMdsIv6fR08ZH3SQAVFrp0fQqi0iX6Mwky39ZjG
         gLGA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=Z4FAtJ2R;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-538e25dfa6asi101578e0c.1.2025.07.25.23.36.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 25 Jul 2025 23:36:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id EA27FA50061;
	Sat, 26 Jul 2025 06:36:40 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A7B37C4CEEF;
	Sat, 26 Jul 2025 06:36:39 +0000 (UTC)
Date: Sat, 26 Jul 2025 08:36:37 +0200
From: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
To: Yunseong Kim <ysk@kzalloc.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Byungchul Park <byungchul@sk.com>, max.byungchul.park@gmail.com,
	Yeoreum Yun <yeoreum.yun@arm.com>,
	Michelle Jin <shjy180909@gmail.com>, linux-kernel@vger.kernel.org,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	Alan Stern <stern@rowland.harvard.edu>,
	Thomas Gleixner <tglx@linutronix.de>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	stable@vger.kernel.org, kasan-dev@googlegroups.com,
	syzkaller@googlegroups.com, linux-usb@vger.kernel.org,
	linux-rt-devel@lists.linux.dev
Subject: Re: [PATCH] kcov, usb: Fix invalid context sleep in softirq path on
 PREEMPT_RT
Message-ID: <2025072615-espresso-grandson-d510@gregkh>
References: <20250725201400.1078395-2-ysk@kzalloc.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250725201400.1078395-2-ysk@kzalloc.com>
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=Z4FAtJ2R;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates
 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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

On Fri, Jul 25, 2025 at 08:14:01PM +0000, Yunseong Kim wrote:
> When fuzzing USB with syzkaller on a PREEMPT_RT enabled kernel, following
> bug is triggered in the ksoftirqd context.
> 
> | BUG: sleeping function called from invalid context at kernel/locking/spinlock_rt.c:48
> | in_atomic(): 0, irqs_disabled(): 1, non_block: 0, pid: 30, name: ksoftirqd/1
> | preempt_count: 0, expected: 0
> | RCU nest depth: 2, expected: 2
> | CPU: 1 UID: 0 PID: 30 Comm: ksoftirqd/1 Tainted: G        W           6.16.0-rc1-rt1 #11 PREEMPT_RT
> | Tainted: [W]=WARN
> | Hardware name: QEMU KVM Virtual Machine, BIOS 2025.02-8 05/13/2025
> | Call trace:
> |  show_stack+0x2c/0x3c (C)
> |  __dump_stack+0x30/0x40
> |  dump_stack_lvl+0x148/0x1d8
> |  dump_stack+0x1c/0x3c
> |  __might_resched+0x2e4/0x52c
> |  rt_spin_lock+0xa8/0x1bc
> |  kcov_remote_start+0xb0/0x490
> |  __usb_hcd_giveback_urb+0x2d0/0x5e8
> |  usb_giveback_urb_bh+0x234/0x3c4
> |  process_scheduled_works+0x678/0xd18
> |  bh_worker+0x2f0/0x59c
> |  workqueue_softirq_action+0x104/0x14c
> |  tasklet_action+0x18/0x8c
> |  handle_softirqs+0x208/0x63c
> |  run_ksoftirqd+0x64/0x264
> |  smpboot_thread_fn+0x4ac/0x908
> |  kthread+0x5e8/0x734
> |  ret_from_fork+0x10/0x20

Why is this only a USB thing?  What is unique about it to trigger this
issue?

thanks,

greg k-h

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2025072615-espresso-grandson-d510%40gregkh.
