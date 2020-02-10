Return-Path: <kasan-dev+bncBDCO5FWBMEINFRMH6ICRUBEIFMOF4@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D6671585F7
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2020 00:10:10 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id j21sf3153416lji.12
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 15:10:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581376210; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z/N06TWPJWhNKaYsZl0RfECs5ATVfHaL8idZzg7+kwxU1Hdo4y19qTqpYq9x4t8l5K
         J035NFQhhBseCh9FZiNOtWgnSPfgaxn5WaO95zONofV+xyZ2c48R2KAecpFmoDsCPv0I
         CntORyntJhi7qwMnTDhJry7Vt9wK0KfdU81JglYE3Kc5qNyN2vTa4UA6HtSMT03/dKpE
         vxKzcAs8pfJZTrI8niR+usxkT48q9CIz51XFzbsqt6PpsSmEc70yM3rZu+P6lbb5xfBt
         IXYxqN9wA5ZVf27cF14YNpxW9dvCCejGo0ZucbogatqfWoqsv5sKjvD2+Twi+NG5XaV3
         9dkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:message-id
         :in-reply-to:subject:cc:to:date:from:sender:dkim-signature
         :dkim-signature;
        bh=Z+UosE4ZflvC0pt99qB8AbxUSoCxMD3q61VjtYkUqbo=;
        b=VEagNlbBiILhEBEU7tfr8diIfu+kkMgHICbbeJhl9DmgRwXRBL+ZbJGi2RVkAFLVjI
         glURRnQLtcP1zGI/HQXLUSEy+AIcnGEbq+xLiBM04hC1n0ttsT6txc+YoB67r3gDq94I
         zkp6NhdP98R96IuTW9cDfjOpA/uYIKwOH/EzCpe6tKgxkXptAOyKEPfhTrItsnrrB67G
         0ZU4X4H1UO5fGIeMyycSYunXyQAE3ytXsWF21SsrqwSkPBJ6vKr4usd8gvKCL0Ko7tNs
         Pe8XxtFcSELS8z6JDH1h162WflhGSbsISjqoUG4eorpgpZc9Rto+WRQS9RVaiL3NoSim
         +bkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=hUMe+OTA;
       spf=pass (google.com: domain of jbi.octave@gmail.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=jbi.octave@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:date:to:cc:subject:in-reply-to:message-id:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z+UosE4ZflvC0pt99qB8AbxUSoCxMD3q61VjtYkUqbo=;
        b=Or6KyFsfpwE3GZO3GloLvkpnKdQtXOqynf+kFvcrU0ZchFmmkFaYGg94NjSUilSTIO
         QnZ6S2M77qv6FaRUUv8l7tfwcYkbYSG4vVXsVd3UQhN+qPyuxIGrOAvzw0cD5TRM983p
         ju4eK5ALNNQQaYHoRrsuj8t1tN+dq36/gncbhWeAt9dpxcUFUUjSl4j2XHE00N5cE4yz
         VzmL07+S6nvZ5XmI0XuRmp0qUTapgO6fJDVLDv/yoTJSjwo1+9UkGEoqWekK2+KPYk+q
         frLtnSdp0bARMvQwmoLyyZpjteWfFu/fldQsMGu+/t1WMdlQPVd32V6XR4OTOxRvQcx4
         sgyg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:date:to:cc:subject:in-reply-to:message-id:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z+UosE4ZflvC0pt99qB8AbxUSoCxMD3q61VjtYkUqbo=;
        b=ZV+8tw/vzNkUwY0iD5Yg5tgnxi+u6s9TPeB5iLP3nfXJly7oMW92njsQc00l5yzQAi
         jsw9xhXQbVZRHc7ABcRTfMgWKpWWyXC9A7XMQUH+z86XUQ+QTRWAwtDAwacPac+i+YCr
         8hLF12J/AD3du3IB0Oe4mT3VzgTkV9nknqE1LdrTAa3+AIaJE9Y72HwIWhp5BXPVp5gL
         XwaBQsK0Q+5YhVucmDQ7gVK71R38XuA7bptcTnp3CXAeN2+7Wy5+uxoxJAN75zeJGRK7
         iw7LUOcU0ttwdqJNz/kESWfMUPV2sKXDKUZnNeT2Ynzv5mgc1eumhCwGK3tKtTfwthD0
         mXPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:date:to:cc:subject:in-reply-to
         :message-id:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z+UosE4ZflvC0pt99qB8AbxUSoCxMD3q61VjtYkUqbo=;
        b=KWCe2To5qTzV3Zhc4naA5cnkrP91Rh7N/tnIuuiW1Hcz9wXDgab2MmkAy0D3OOyMus
         7ArvRl0QR5bP+OVAm6s0pDZfnDqCRp6749uc2Au9xvNNh3Iu8YA+5qPn9l1i/x12jN+N
         isoqGZmDTFdqI7ZQ1KGz6jJBtgtnPmcpCMeQGprYuHXbGBG5gMn+PWT8WQxIaCOioex6
         Vbvz3tbomlqAdaxentpphMcoVgqqyj07FYPT2cG5TE0OwrX/kM/cY4CnpbF6MfBENCBb
         npwG3/ssFLTC7Fov8qE/r6uRHlyOJJQc1IAM/e47XY3TsRAXWAH/mjunS0FEZaAjDQgx
         TFrQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX5RlFl31YVIs4uNZZ9c1NcVL8yi3gpBrU0KFkWScSyYbgW9scq
	Z5eOIRjf9HRqBSeEWR0qBoA=
X-Google-Smtp-Source: APXvYqxL0HPT88CUzv96eSDxtIWc+xtSGdKojV2WNXPK9tjTgp3ezcQzVJR1b13nh4qYVIimJYFdrg==
X-Received: by 2002:a2e:8105:: with SMTP id d5mr2297344ljg.25.1581376210171;
        Mon, 10 Feb 2020 15:10:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9516:: with SMTP id f22ls1759344ljh.2.gmail; Mon, 10 Feb
 2020 15:10:09 -0800 (PST)
X-Received: by 2002:a2e:9110:: with SMTP id m16mr2271307ljg.140.1581376209320;
        Mon, 10 Feb 2020 15:10:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581376209; cv=none;
        d=google.com; s=arc-20160816;
        b=F3SBDFJ1uzkv7T+3mh/913YsHBxmZk/UPKj6cfbzLNAND3979rhtYw5tleE0WLjRUc
         M36oojJTdAhKf7wz2oTcioEyDEhDIuRQsAlxVSTNblkpoefWVB+CkRaqHOFwyqU+Z+9U
         mg9imgVpA2YwDFyXJ1meUP9rCmbUFDe4vL6a0M7oqQnyc/wW52WC0GNQaPWpxu38Yz25
         tzrekxlm2fTfDtk8N+sKcqC/0liSoYEG1fbYma2eC2YPpUzs6ZcnjunkBmbEMwlpfWei
         7KtZq1KneGCme9GQyT1h05rBkaUYpeF2FsFe8vmLjZFn9QSliv46NbuLP4BmuiY4n0BW
         7FYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:message-id:in-reply-to:subject:cc:to:date
         :from:dkim-signature;
        bh=HlH978RiT/OKtcm1ieT3FHA3Af2vEFe/d++NhRbZZHo=;
        b=T6AskPMLcz+YnSwzKvD8/R5H2qiqkRxuSrcpLitChTv+jZJRoBLJafwlb8xgK3ABB/
         XaLUWlNgN32PS5nYyTzCsz8fuzAYMzhw0lX1DMhRL/dy3DQXI0Fncv5NtUSZ1/3uqQ3G
         NCZ8ky6FS++42Rw+SFFT/CQqRKhcWgHFH48Uqhyz52F3a++F+5XzkdNdP/Tq9Ep7dIQY
         5lNxwMbVqe7gfalF8rYCHH2JjkIePHUhOuWjrlRv1Ym9erdiNWCjpKYIdYJexwBQteSm
         LEV3SlZgUAKQsB20DRwUwa2i4UBjymoEgPiiU6TJgGe6PNifrrkh388ktFfNDQhK5KaC
         mJLw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=hUMe+OTA;
       spf=pass (google.com: domain of jbi.octave@gmail.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=jbi.octave@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wm1-x342.google.com (mail-wm1-x342.google.com. [2a00:1450:4864:20::342])
        by gmr-mx.google.com with ESMTPS id h8si96702ljj.3.2020.02.10.15.10.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Feb 2020 15:10:09 -0800 (PST)
Received-SPF: pass (google.com: domain of jbi.octave@gmail.com designates 2a00:1450:4864:20::342 as permitted sender) client-ip=2a00:1450:4864:20::342;
Received: by mail-wm1-x342.google.com with SMTP id p9so1165604wmc.2
        for <kasan-dev@googlegroups.com>; Mon, 10 Feb 2020 15:10:09 -0800 (PST)
X-Received: by 2002:a1c:740b:: with SMTP id p11mr1428624wmc.78.1581376208631;
        Mon, 10 Feb 2020 15:10:08 -0800 (PST)
Received: from ninjahub.lan (host-2-102-13-223.as13285.net. [2.102.13.223])
        by smtp.gmail.com with ESMTPSA id 18sm1122951wmf.1.2020.02.10.15.10.06
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Feb 2020 15:10:08 -0800 (PST)
From: Jules Irenge <jbi.octave@gmail.com>
Date: Mon, 10 Feb 2020 23:09:59 +0000 (GMT)
To: Boqun Feng <boqun.feng@gmail.com>
cc: Jules Irenge <jbi.octave@gmail.com>, linux-kernel@vger.kernel.org, 
    linux-mm@kvack.org, kasan-dev@googlegroups.com, akpm@linux-foundation.org, 
    dvyukov@google.com, glider@google.com, aryabinin@virtuozzo.com, 
    bsegall@google.com, rostedt@goodmis.org, dietmar.eggemann@arm.com, 
    vincent.guittot@linaro.org, juri.lelli@redhat.com, peterz@infradead.org, 
    mingo@redhat.com, mgorman@suse.de, dvhart@infradead.org, 
    tglx@linutronix.de, namhyung@kernel.org, jolsa@redhat.com, 
    alexander.shishkin@linux.intel.com, mark.rutland@arm.com, acme@kernel.org, 
    viro@zeniv.linux.org.uk, linux-fsdevel@vger.kernel.org
Subject: Re: [PATCH 00/11] Lock warning cleanup
In-Reply-To: <20200210050622.GC69108@debian-boqun.qqnc3lrjykvubdpftowmye0fmh.lx.internal.cloudapp.net>
Message-ID: <alpine.LFD.2.21.2002102306000.191510@ninjahub.org>
References: <0/11> <cover.1581282103.git.jbi.octave@gmail.com> <20200210050622.GC69108@debian-boqun.qqnc3lrjykvubdpftowmye0fmh.lx.internal.cloudapp.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jbi.octave@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=hUMe+OTA;       spf=pass
 (google.com: domain of jbi.octave@gmail.com designates 2a00:1450:4864:20::342
 as permitted sender) smtp.mailfrom=jbi.octave@gmail.com;       dmarc=pass
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



On Mon, 10 Feb 2020, Boqun Feng wrote:

> Hi Jules,
> 
> On Sun, Feb 09, 2020 at 10:24:42PM +0000, Jules Irenge wrote:
> > This patch series adds missing annotations to functions that register warnings of context imbalance when built with Sparse tool.
> > The adds fix the warnings and give insight on what the functions are actually doing.
> > 
> > 1. Within the futex subsystem, a __releases(&pi_state->.pi_mutex.wait_lock) is added because wake_futex_pi() only releases the lock at exit,
> > must_hold(q->lock_ptr) have been added to fixup_pi_state_owner() because the lock is held at entry and exit;
> > a __releases(&hb->lock) added to futex_wait_queue_me() as it only releases the lock.
> > 
> > 2. Within fs_pin, a __releases(RCU) is added because the function exit RCU critical section at exit.
> > 
> > 3. In kasan, an __acquires(&report_lock) has been added to start_report() and   __releases(&report_lock) to end_report() 
> > 
> > 4. Within ring_buffer subsystem, a __releases(RCU) has been added perf_output_end() 
> > 
> > 5. schedule subsystem recorded an addition of the __releases(rq->lock) annotation and a __must_hold(this_rq->lock)
> > 
> > 6. At hrtimer subsystem, __acquires(timer) is added  to lock_hrtimer_base() as the function acquire the lock but never releases it.
> > Jules Irenge (11):
> >   hrtimer: Add missing annotation to lock_hrtimer_base()
> >   futex: Add missing annotation for wake_futex_pi()
> >   futex: Add missing annotation for fixup_pi_state_owner()
> 
> Given that those three patches have been sent and reviewed, please do
> increase the version number (this time, for example, using v2) when
> sending the updated ones. Also please add a few sentences after the
> commit log describing what you have changed between versions.
> 
> Here is an example:
> 
> 	https://lore.kernel.org/lkml/20200124231834.63628-4-pmalani@chromium.org/
> 
> Regards,
> Boqun
> 
> >   perf/ring_buffer: Add missing annotation to perf_output_end()
> >   sched/fair: Add missing annotation for nohz_newidle_balance()
> >   sched/deadline: Add missing annotation for dl_task_offline_migration()
> >   fs_pin: Add missing annotation for pin_kill() declaration
> >   fs_pin: Add missing annotation for pin_kill() definition
> >   kasan: add missing annotation for start_report()
> >   kasan: add missing annotation for end_report()
> >   futex: Add missing annotation for futex_wait_queue_me()
> > 
> >  fs/fs_pin.c                 | 2 +-
> >  include/linux/fs_pin.h      | 2 +-
> >  kernel/events/ring_buffer.c | 2 +-
> >  kernel/futex.c              | 3 +++
> >  kernel/sched/deadline.c     | 1 +
> >  kernel/sched/fair.c         | 2 +-
> >  kernel/time/hrtimer.c       | 1 +
> >  mm/kasan/report.c           | 4 ++--
> >  8 files changed, 11 insertions(+), 6 deletions(-)
> > 
> > -- 
> > 2.24.1
> > 
> 

Thanks for the feedback, I take good notes. I am working on the 
second version.

Kind regards,
Jules

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/alpine.LFD.2.21.2002102306000.191510%40ninjahub.org.
