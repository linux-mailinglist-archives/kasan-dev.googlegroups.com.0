Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBUN7Z3YQKGQE24F3VOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id E1B7614E798
	for <lists+kasan-dev@lfdr.de>; Fri, 31 Jan 2020 04:32:34 +0100 (CET)
Received: by mail-pl1-x63f.google.com with SMTP id 91sf2966565plf.23
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Jan 2020 19:32:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580441553; cv=pass;
        d=google.com; s=arc-20160816;
        b=g2Fu/zVUXVM88f6HOSJgosrQMfia9gsC8rZ5JU4kiOz8eFpJEHzf3xjgRDEpp5MO+L
         /ygC/1sRSd1mK8jUSTwLLpnwIdhAGMcLVuf8FhYy3sCvGZsKvvZEVFy8HudlULAcLI/e
         eJ7unc64zzOfc0RDPm6z6V9c3Dbar0UKbqqMK01T7jxva+h6yG+sSu6/+bp+1RuWEjXk
         PzQPver7zCS+djODYD/gV4wDenugjihl4u6xWuiuxRYFsrof/xTZxEIIGmYEsVIX9cqL
         goEaeKkrsobWHeAMNFrByhn2VJta8XjmpeWD+eGKGySIB1vu5UkzPDnFcmUicuzLf+p3
         BZHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:references:message-id
         :content-transfer-encoding:cc:date:in-reply-to:from:subject
         :mime-version:sender:dkim-signature;
        bh=UfsbONaSJOR1tZx60/zlUosPZ8UC8NrKYLuUoX9W1nw=;
        b=duANirKKCrWPrH1sLtq3OuAEvnm9dcq0FfQ2a/qFjSi5qMAjMXoZN8Oj8tufVnwPtJ
         EcUGl0JOueLtsg5q2UyhTYFXbLDf9Ar/a8Sx3tbaLuttZmg/wim5XCB5Am4CAVKmUklV
         uV+Xk+W5wNkFmsPupMabuAzRNG3czDw43CWA1C1YKZe2OHXocOoddE8qkHnk4NFfaFr8
         ACK/0VmhSu5QZMZjLBobueui98PTZEAFshB/WgOFW90GOny4JchvftKxaXQYLAryR+wY
         pLMuNcfhb1OZ8wyLQTZ0hZPR2PM9znXkBKUuJVWi/jVsZk2POVekfzkHsiqwezh1/Wik
         6l+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=c5zX5LAM;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:subject:from:in-reply-to:date:cc
         :content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UfsbONaSJOR1tZx60/zlUosPZ8UC8NrKYLuUoX9W1nw=;
        b=fcQH4bspLe6N8y6G4zmsw/DvQ26uDvmyGseWy3xtwSHVS7hCKVrft0u5MhV0PHRDhe
         syOby5iMMdBRIvDPD/OXDB7ExBKxzyUGPlvgEp0RpeO5P1VtQuuiOvn7akjUARFu180s
         E3O1s+NTOIvxkpnCOthK9dfgKxCq5IgA3T7Dpm8KBXTgwwd0cPaPk6aOLpY4Nj085RKM
         DMh9REFDipKa5S/wmXpnOK6J1MuQS5vRnzma/SxGIRn3wlBLHCHcUHuZ87PMgOg+1Vj5
         rPNoY+o0PlLy9o5uJS0hkaD/7v7y0uA7oMGqMufG0r4+WJUwSa0jM1JjwUBMjdS/13GL
         Cn9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:subject:from:in-reply-to
         :date:cc:content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=UfsbONaSJOR1tZx60/zlUosPZ8UC8NrKYLuUoX9W1nw=;
        b=FGVqfWuFPmG5AlVBiHxW1tFMCxM4LiN4M9aG8n19oscUm/TJ6Lx1PqnddZ9YV7xYhz
         oqKTPARasBdILNs33xx4lxJREcNyPKS5VXFQNygUcz4SwJ9mB3kZ9xSi4mMEdHGap0SA
         etim34R/QHy0ZxzOO8pgmVJr76wIdvrDmO1eVvRCMmrfauAS6LQcdbKlicCS5P65t2rd
         L1LRAnxVSUPzBlKL9cBwC0Ubx/zgogOlyzGWNtxzdtnUNOnvO5RTmnBjC2OqLktcWeiI
         2MdjYIKpMw7K2GWc7F7OoWSRFWmBGXc6K5bItoie2KSwob+Kq5eEGKTDAt8BhLXtWkbT
         lCZw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVsYeuqcnblr0FU7OS7n4luu/G/iwOUiDwArweAnOnxiX+Qeld4
	ij70BcajwBxafJyyz78eqGo=
X-Google-Smtp-Source: APXvYqwPRHi6XDGxs7g2cq3AAz86mJicsmaGN2DucFbPhrCYKidRuabTt9pxn9LwA3w6mpbPLOjtrw==
X-Received: by 2002:a62:4e42:: with SMTP id c63mr8399136pfb.86.1580441553057;
        Thu, 30 Jan 2020 19:32:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:6644:: with SMTP id f4ls3137561pjm.2.gmail; Thu, 30
 Jan 2020 19:32:32 -0800 (PST)
X-Received: by 2002:a17:902:74c3:: with SMTP id f3mr6249862plt.0.1580441552607;
        Thu, 30 Jan 2020 19:32:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580441552; cv=none;
        d=google.com; s=arc-20160816;
        b=bNXVsoXUnna82ZRDUpIKC9yEqhHwC8glGvr95TBJ4ZSwj2eSVRMBTAA1TSsGw1b0E0
         NyGwnFxxXGscAfboA5UrYeE09LiqxS72/fWDXq9mlZ2wb0pQlm+/r1dxYoBgUYMC7fsT
         /E0+dXekDhgdYzNAtUM6p3rxLVP8pha75KZdkekn+no76xck7ePw78a80P7Q6uG5n8XK
         QbZ/gmFVhMVvA93+YAEcptE6d7Ilv6dK5QK4pM33Td0kc8W98g5EF2hId3Qqgr+ZZ3bL
         i5eyBff7zx6a4JdqOaroEUnirsJnXIoasbjTb3HJCEzsjQ9eVRgdzxau93aNN1qqC9Sd
         lTdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:references:message-id:content-transfer-encoding:cc:date
         :in-reply-to:from:subject:mime-version:dkim-signature;
        bh=0gSHAzHwvtexhAGJkoXJN1aU/Deb8qQRpOrPk8l4RYM=;
        b=vihKduIvoNwiMQeA55Bzypt8kodT6WDQOxbIzyjagT7YYEPrJRFF+tL+ET39Mdw/xr
         qlK5vX55sWDaXXI1EFQF8z0nCQUgF06n0y5M55wUEHJnBZMAqWAqv8XKQpleb5uXP/Vi
         nKChuqCvX/KV0Q5ZdXbAn085NWHvNALJGRVvH7RJEFopw/sMVSGjHvxV3/GFKBNdSJg1
         lnrEk8nu5nwB7k4I2M2q8LM5bPZYJmD8X59XbYVZhKF9j0vDLaePyAGSQ5+/VY/49eF/
         CMJ7UjvnOAzmNHWHb+boIuoKbR+TD5HVbjJ+J9T0jFmDWc2oHIqrDfTPtLFwWlNtK5mx
         2GWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=c5zX5LAM;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id d12si621023pjv.0.2020.01.30.19.32.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 30 Jan 2020 19:32:32 -0800 (PST)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id x1so5213994qkl.12
        for <kasan-dev@googlegroups.com>; Thu, 30 Jan 2020 19:32:32 -0800 (PST)
X-Received: by 2002:a37:89c7:: with SMTP id l190mr8869880qkd.498.1580441551472;
        Thu, 30 Jan 2020 19:32:31 -0800 (PST)
Received: from [192.168.1.153] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id e13sm4223434qtq.26.2020.01.30.19.32.30
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 30 Jan 2020 19:32:30 -0800 (PST)
Content-Type: text/plain; charset="UTF-8"
Mime-Version: 1.0 (Mac OS X Mail 13.0 \(3608.40.2.2.4\))
Subject: Re: [PATCH] locking/osq_lock: fix a data race in osq_wait_next
From: Qian Cai <cai@lca.pw>
In-Reply-To: <20200130134851.GY14914@hirez.programming.kicks-ass.net>
Date: Thu, 30 Jan 2020 22:32:29 -0500
Cc: Marco Elver <elver@google.com>,
 "Paul E. McKenney" <paulmck@kernel.org>,
 Will Deacon <will@kernel.org>,
 Ingo Molnar <mingo@redhat.com>,
 Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>
Content-Transfer-Encoding: quoted-printable
Message-Id: <4A97061E-2152-4734-92C6-F5431C27360B@lca.pw>
References: <20200122223851.GA45602@google.com>
 <A90E2B85-77CB-4743-AEC3-90D7836C4D47@lca.pw>
 <20200123093905.GU14914@hirez.programming.kicks-ass.net>
 <E722E6E0-26CB-440F-98D7-D182B57D1F43@lca.pw>
 <CANpmjNNo6yW-y-Af7JgvWi3t==+=02hE4-pFU4OiH8yvbT3Byg@mail.gmail.com>
 <20200128165655.GM14914@hirez.programming.kicks-ass.net>
 <20200129002253.GT2935@paulmck-ThinkPad-P72>
 <CANpmjNN8J1oWtLPHTgCwbbtTuU_Js-8HD=cozW5cYkm8h-GTBg@mail.gmail.com>
 <20200129184024.GT14879@hirez.programming.kicks-ass.net>
 <CANpmjNNZQsatHexXHm4dXvA0na6r9xMgVD5R+-8d7VXEBRi32w@mail.gmail.com>
 <20200130134851.GY14914@hirez.programming.kicks-ass.net>
To: Peter Zijlstra <peterz@infradead.org>
X-Mailer: Apple Mail (2.3608.40.2.2.4)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=c5zX5LAM;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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



> On Jan 30, 2020, at 8:48 AM, Peter Zijlstra <peterz@infradead.org> wrote:
>=20
> On Thu, Jan 30, 2020 at 02:39:38PM +0100, Marco Elver wrote:
>> On Wed, 29 Jan 2020 at 19:40, Peter Zijlstra <peterz@infradead.org> wrot=
e:
>=20
>>> It's probably not terrible to put a READ_ONCE() there; we just need to
>>> make sure the compiler doesn't do something stupid (it is known to do
>>> stupid when 'volatile' is present).
>>=20
>> Maybe we need to optimize READ_ONCE().
>=20
> I think recent compilers have gotten better at volatile. In part because
> of our complaints.
>=20
>> 'if (data_race(..))' would also work here and has no cost.
>=20
> Right, that might be the best option.
>=20

OK, I=E2=80=99ll send a patch for that.

BTW, I have another one to report. Can=E2=80=99t see how the load tearing w=
ould
cause any real issue.

[  519.240629] BUG: KCSAN: data-race in osq_lock / osq_unlock

[  519.249088] write (marked) to 0xffff8bb2f133be40 of 8 bytes by task 421 =
on cpu 38:
[  519.257427]  osq_unlock+0xa8/0x170 kernel/locking/osq_lock.c:219
[  519.261571]  __mutex_lock+0x4b3/0xd20
[  519.265972]  mutex_lock_nested+0x31/0x40
[  519.270639]  memcg_create_kmem_cache+0x2e/0x190
[  519.275922]  memcg_kmem_cache_create_func+0x40/0x80
[  519.281553]  process_one_work+0x54c/0xbe0
[  519.286308]  worker_thread+0x80/0x650
[  519.290715]  kthread+0x1e0/0x200
[  519.294690]  ret_from_fork+0x27/0x50


void osq_unlock(struct optimistic_spin_queue *lock)
{
        struct optimistic_spin_node *node, *next;
        int curr =3D encode_cpu(smp_processor_id());

        /*
         * Fast path for the uncontended case.
         */
        if (likely(atomic_cmpxchg_release(&lock->tail, curr,
                                          OSQ_UNLOCKED_VAL) =3D=3D curr))
                return;

        /*
         * Second most likely case.
         */
        node =3D this_cpu_ptr(&osq_node);
        next =3D xchg(&node->next, NULL);    <--------------------------
        if (next) {
                WRITE_ONCE(next->locked, 1);
                return;
        }

        next =3D osq_wait_next(lock, node, NULL);
        if (next)
                WRITE_ONCE(next->locked, 1);
}


[  519.301232] read to 0xffff8bb2f133be40 of 8 bytes by task 196 on cpu 12:
[  519.308705]  osq_lock+0x1e2/0x340 kernel/locking/osq_lock.c:157
[  519.312762]  __mutex_lock+0x277/0xd20
[  519.317167]  mutex_lock_nested+0x31/0x40
[  519.321838]  memcg_create_kmem_cache+0x2e/0x190
[  519.327120]  memcg_kmem_cache_create_func+0x40/0x80
[  519.332751]  process_one_work+0x54c/0xbe0
[  519.337508]  worker_thread+0x80/0x650
[  519.341922]  kthread+0x1e0/0x200
[  519.345889]  ret_from_fork+0x27/0x50


        for (;;) {
                if (prev->next =3D=3D node &&         <--------------------=
----
                    cmpxchg(&prev->next, node, NULL) =3D=3D node)
                        break;

                /*
                 * We can only fail the cmpxchg() racing against an unlock(=
),
                 * in which case we should observe @node->locked becomming
                 * true.
                 */
                if (smp_load_acquire(&node->locked))
                        return true;

                cpu_relax();

                /*
                 * Or we race against a concurrent unqueue()'s step-B, in w=
hich
                 * case its step-C will write us a new @node->prev pointer.
                 */
                prev =3D READ_ONCE(node->prev);
        }


[  519.352420] Reported by Kernel Concurrency Sanitizer on:
[  519.358492] CPU: 12 PID: 196 Comm: kworker/12:1 Tainted: G        W    L=
    5.5.0-next-20200130+ #3
[  519.368317] Hardware name: HPE ProLiant DL385 Gen10/ProLiant DL385 Gen10=
, BIOS A40 07/10/2019
[  519.377627] Workqueue: memcg_kmem_cache memcg_kmem_cache_create_func

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/4A97061E-2152-4734-92C6-F5431C27360B%40lca.pw.
