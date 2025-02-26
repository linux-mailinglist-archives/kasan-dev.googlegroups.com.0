Return-Path: <kasan-dev+bncBDK7LR5URMGRBLGL7S6QMGQESXWLBAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id A2FFFA462D3
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2025 15:31:10 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-4399304b329sf32647535e9.3
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2025 06:31:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740580269; cv=pass;
        d=google.com; s=arc-20240605;
        b=h/cz0I+5PU2n/UhpAcbkTFmcVDOR56c7yjKhGNsR6Fr4SvOSLT5tcbQaaiYZthmWtb
         Mja5Mg5kbvsrzRBYUQz1v+INVhxNwMNIumeiwsEF5165ErRFkCLdJffV2g6t0X5lyTX1
         tcqbF/8Z5Z/+EUz/xgywYZHW9pVyAV7zVuNmcOqs5TwcIjW2piJ8RVYKS+mNxzR99IdP
         YjQeVEyBaKaEGo1r7AEsPH9w4fbIqiJnvKgBraKbVVmcjkzJW7KVBMa8xqPoTS3Du09/
         H7lj8+qWxvbz6mj5NjyUsjWRSK+4P3sKINpMSgA9z/A0Shsll17o59mkkCg7rn3DY7l+
         YJ5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:date:from:sender
         :dkim-signature:dkim-signature;
        bh=FjqqD92QSR1mLEacUs8/Kbn4eChmhda4M4742Tne2z0=;
        fh=m3Uhwu56ea1+rs7eS0BO3C7Xq0BWg6lZiEpQ81OqlU4=;
        b=k2+s6N3XdQVhg5LNn/ExxlyX/zDP3zf3CdGpRXQQHhcYf6qdM/dsfzOcy9TJry5GJD
         JJdgljKXDaeEQk6+sh95h/hMcHaN4mNY92672qHnSgC3/FCTzrNaFYo6rBQdOY+T6iGL
         F7AsICbhBaUoXNYQoUXfuGpsi5aDs6/iB84T7bSDM6Oy2dVQL7OcX5HiD9YocCg+xC4a
         dF1dwhmS44ahEO3XQgdVDlpGvCzFLav33s7bYblC6JqsMPpzOmU7u1G8VfTYmPLYnFiI
         g8CKa482bSKpPHz3fLRXCMKTm0FIbs/ykM2lDNHpfEl3SjYQ/GA1JMuM/AjXGdsklGYe
         kAxA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Oji4RWUB;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::22d as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740580269; x=1741185069; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=FjqqD92QSR1mLEacUs8/Kbn4eChmhda4M4742Tne2z0=;
        b=BFP71EOQvJgPuj/0v8KXN6LmMMNbFP4sQ8kOk/Y96xjIaj04KJBsOcSgHjmf59/sfB
         rgid1/mlnozTS4pwNh+01MmtRNinMYJlouwLaNIYW79/Cg3s1BCX8SkWHgmzYARt6TQJ
         qFCn8kC36kb+nD4Ccn86vpy2Ja8m6sR+vidZKyMf+jKudLapjY82bLA8tQPinKK7pg6i
         1uHGN41Ov+FRv76AmW6Zb6YgLciPh+W2NZavrPuOKcPyw/LmeHORTA1uqNBPjHD4OHIP
         Y219e22QzdV1DqBIXDpzJ8rd0wAeZ22LHImpe6kYKOdtbQ/28sb0me742VoH2GbiYxoU
         ccDA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1740580269; x=1741185069; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=FjqqD92QSR1mLEacUs8/Kbn4eChmhda4M4742Tne2z0=;
        b=ekLqsaLeYQLzNIOdhU2L9L67VYVCtCyDSyAWl7SMBRB/SCjk8myaGWblvuO43P4HXj
         h/vNGWvN1F6iS1yo9tV50aLuz3Gq7ya6p8AGI2PQH4nVZijWF7HlViuWygccj14U6/k8
         6pE1rqsdWxQMGV6b4JqVRP6VUPl+JT2qWQ/M0PNvFhzpvQ1KoUI3I5+j4J21gq09UGDN
         WX4xOwZZnioX75EcOsFxajlfekAjSH/Bd11z51OMnN5Rb2Pnfw1RuRJ5657ocNcjNQ3r
         tT2Wckd/6jmcaaU4kqK1uIXvqJy/xO2rzrPBW0rs3x8GJwXjjkBsh3t8nVdL6BDZBoJJ
         GpQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740580269; x=1741185069;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=FjqqD92QSR1mLEacUs8/Kbn4eChmhda4M4742Tne2z0=;
        b=hIFspKHApc+1CiMM5oJgDLcfgvObkW2XGsNFI5GfHs5nQL0QbMjd5+Vu2e1omCIRnF
         B3fUd5hzltE4/3e158OorZLQFFj8FMPExPRKqn+LDk/kKBZf5q/SBNcl7K3HynCFkQx0
         lVfJdMMdFpJ9G6OpWQjjsTn4ppyOQglaRAT53cr46dBWCQuGHu62wMbujDgGsN8MFtVR
         /NX+ZyDph8TZUN4w9o9Kl79/ek/crQV67+4gcaTBibj5AfWW+PPxZ6BOOG5rrjE9KKv2
         LsiadslqPc9WUHNdw2Mq1J9gpVcaun8waRlPX6VtJ81PrHfJOuQrZDljUsKEZbDvOA6C
         mg9w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUyulGYt3GI9T8s5Z38YR7ySzOYtWgGq8l1kOsosolUNn59tlZ+6k4du5dzslEHF8zpEeMsyA==@lfdr.de
X-Gm-Message-State: AOJu0YyQpLLVKcQGeHks0nyJ3cGM+O1Fvi8aI2oPACUA+E+7ifhvgTAW
	khcudlG112U227bN/apCmfkCSTv7UM8uXYS81d1Z1HSIcj8gyV4g
X-Google-Smtp-Source: AGHT+IEMbd2BpY4nHzzkFzdEl3MQJqd5Vev3B1jS7onCRKm/Ztd3BoNM+/oZBGGuNMwDG/mlUI+XJg==
X-Received: by 2002:a05:600c:5250:b0:439:69e0:fa23 with SMTP id 5b1f17b1804b1-43ab8fd1d79mr31014225e9.2.1740580268539;
        Wed, 26 Feb 2025 06:31:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHHYjFRwrf3okbnjWIPdoTBfeVZcLNq9+tMjkPIf2L8Pw==
Received: by 2002:a05:600c:45cb:b0:439:a0c8:41aa with SMTP id
 5b1f17b1804b1-43ab9456da9ls4218185e9.1.-pod-prod-08-eu; Wed, 26 Feb 2025
 06:31:06 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXy+gIuAfdq2PUC2VT7LZCIIDUMlwMKsFKbsgXkWd4zTafBB8HSF8xmp4odeeJV7Kdcunu92Z3s22k=@googlegroups.com
X-Received: by 2002:a05:600c:1d03:b0:439:6ab6:5d46 with SMTP id 5b1f17b1804b1-43ab9029c8emr28015825e9.27.1740580266404;
        Wed, 26 Feb 2025 06:31:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740580266; cv=none;
        d=google.com; s=arc-20240605;
        b=earJTbZuS2AeHWzVkkZTfLLslrQLifEXh+FsJF9WFGyd8P12cCIVN6CnPS9GzQsR6v
         mLehOVhJ2ys/ZANWWJxCHjh/9txaqbsnz9tdg36xdf0QvmHANwDem9i95LeRw4lgGDxL
         Rqz0zT2WqtxZFnlZLCDCpWO9Hq8oVRALUet8b/Gv9Rk5mRKP1xGJaymIl/Usy6Q81iSH
         L0ZMtqH15die0Nyhc7aqdGmZB/bdMCPAEIhhozdiEp3wPuGDo1RSwzmyL8oU3+BtY4pe
         PsvB59PxoaLKxJc9FqCWbq6wCacS2z+Xq8RNa9X3UZt0bKktdo1S7ECA42oNrjYZe20s
         jWLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:date:from:dkim-signature;
        bh=eswWLfkEnQpdtu+isG+K14u+ZfJSvAbvqWCgztSMnzs=;
        fh=H3PmQKhN5PxVcCVvroxDeSkeaMN5543pbTpH0BoBkq4=;
        b=j1Qc9y2PXQf9MDoI3j8TZxCkRuDNSE2GTQKVnyKEVTTuFJrOQ01n4dl6fBpRGAqNPL
         mxDYtAv49n5I0cz3xpMZOcGcf8lKO6SicuA/s1kvSfKzprRTdE02jaIyjoKPYWtkq1Da
         2EKLlRGhwZwn2oRdhnt1hdkpoTuD38vL9EfL63Fh+WICYaa0BKu5haTzXJ0EOIbWyR6h
         C+A5CqXhc8+gAArWy0oN9GJOF2yySU99NmUvY8o6HRiCELE3FhJWFc5EKNvn38Z63STb
         mCEkJbjrVnGKu8TdmnMYhm+es82jMWORggWUv5R/D2QZlo64hm2OAwPdU4Tw/R6kp4Qe
         ni3w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Oji4RWUB;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::22d as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x22d.google.com (mail-lj1-x22d.google.com. [2a00:1450:4864:20::22d])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43ab374a2adsi2548445e9.1.2025.02.26.06.31.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 26 Feb 2025 06:31:06 -0800 (PST)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::22d as permitted sender) client-ip=2a00:1450:4864:20::22d;
Received: by mail-lj1-x22d.google.com with SMTP id 38308e7fff4ca-30613802a59so71515381fa.0
        for <kasan-dev@googlegroups.com>; Wed, 26 Feb 2025 06:31:06 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXckBTxF1Dccam7Qp6KsJh5H6r8m94FZwkY1PlmCsxCh2s+zqbhJnsE9UOSHqP1Ofcnx8G/51T2tOc=@googlegroups.com
X-Gm-Gg: ASbGncu4xCXdczT1hQ/CmIFYShIzKh1vKwajG84TiClPM8qErNqxyk0mJz3QMR4m4+G
	4Xm74oUaeP1uaSYgQCFLB2Aef+48YDBPRClg8lumndad/xbQbL3QV6cmf4f+GhPYOyayfET+Kdg
	N64NFFd0T8PKDYZ2a7wPLr1cMVB+haAK9OD6N4P5mrctOquboC8Jzy+iTDE+Wsc0z8AS6T9dZTH
	hJk4T3S+gcbk46j3gLUyoLZ2lfr4kPM/NKN8x8kHLi3MvtFAucqJIFbFFNph6NWL6yUISDPCtMs
	O5jl+D7pzqKnySgZiUSjGsNuTenl0Y+DDF6tyFTbgf+KZ9xR
X-Received: by 2002:a2e:9a98:0:b0:307:5879:e7d8 with SMTP id 38308e7fff4ca-30b792cb29cmr26025521fa.30.1740580265244;
        Wed, 26 Feb 2025 06:31:05 -0800 (PST)
Received: from pc636 (host-95-203-6-24.mobileonline.telia.com. [95.203.6.24])
        by smtp.gmail.com with ESMTPSA id 38308e7fff4ca-30a819f5e4asm5422341fa.63.2025.02.26.06.31.02
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 26 Feb 2025 06:31:04 -0800 (PST)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Wed, 26 Feb 2025 15:31:01 +0100
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Uladzislau Rezki <urezki@gmail.com>,
	Keith Busch <keith.busch@gmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Joel Fernandes <joel@joelfernandes.org>,
	Josh Triplett <josh@joshtriplett.org>,
	Boqun Feng <boqun.feng@gmail.com>, Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Lai Jiangshan <jiangshanlai@gmail.com>,
	Zqiang <qiang.zhang1211@gmail.com>,
	Julia Lawall <Julia.Lawall@inria.fr>,
	Jakub Kicinski <kuba@kernel.org>,
	"Jason A. Donenfeld" <Jason@zx2c4.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, rcu@vger.kernel.org,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com, Jann Horn <jannh@google.com>,
	Mateusz Guzik <mjguzik@gmail.com>, linux-nvme@lists.infradead.org,
	leitao@debian.org
Subject: Re: [PATCH v2 6/7] mm, slab: call kvfree_rcu_barrier() from
 kmem_cache_destroy()
Message-ID: <Z78lpfLFvNxjoTNf@pc636>
References: <20240807-b4-slab-kfree_rcu-destroy-v2-6-ea79102f428c@suse.cz>
 <Z7iqJtCjHKfo8Kho@kbusch-mbp>
 <2811463a-751f-4443-9125-02628dc315d9@suse.cz>
 <Z7xbrnP8kTQKYO6T@pc636>
 <ef97428b-f6e7-481e-b47e-375cc76653ad@suse.cz>
 <Z73p2lRwKagaoUnP@kbusch-mbp>
 <CAOSXXT6-oWjKPV1hzXa5Ra4SPQg0L_FvxCPM0Sh0Yk6X90h0Sw@mail.gmail.com>
 <Z74Av6tlSOqcfb-q@pc636>
 <Z74KHyGGMzkhx5f-@pc636>
 <8d7aabb2-2836-4c09-9fc7-8bde271e7f23@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <8d7aabb2-2836-4c09-9fc7-8bde271e7f23@suse.cz>
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Oji4RWUB;       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::22d as
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

On Wed, Feb 26, 2025 at 11:59:53AM +0100, Vlastimil Babka wrote:
> On 2/25/25 7:21 PM, Uladzislau Rezki wrote:
> >>
> > WQ_MEM_RECLAIM-patch fixes this for me:
> 
> Sounds good, can you send a formal patch then?
>
Do you mean both? Test case and fix? I can :)

> Some nits below:
> 
> > <snip>
> > diff --git a/mm/slab_common.c b/mm/slab_common.c
> > index 4030907b6b7d..1b5ed5512782 100644
> > --- a/mm/slab_common.c
> > +++ b/mm/slab_common.c
> > @@ -1304,6 +1304,8 @@ module_param(rcu_min_cached_objs, int, 0444);
> >  static int rcu_delay_page_cache_fill_msec = 5000;
> >  module_param(rcu_delay_page_cache_fill_msec, int, 0444);
> > 
> > +static struct workqueue_struct *rcu_reclaim_wq;
> > +
> >  /* Maximum number of jiffies to wait before draining a batch. */
> >  #define KFREE_DRAIN_JIFFIES (5 * HZ)
> >  #define KFREE_N_BATCHES 2
> > @@ -1632,10 +1634,10 @@ __schedule_delayed_monitor_work(struct kfree_rcu_cpu *krcp)
> >         if (delayed_work_pending(&krcp->monitor_work)) {
> >                 delay_left = krcp->monitor_work.timer.expires - jiffies;
> >                 if (delay < delay_left)
> > -                       mod_delayed_work(system_unbound_wq, &krcp->monitor_work, delay);
> > +                       mod_delayed_work(rcu_reclaim_wq, &krcp->monitor_work, delay);
> >                 return;
> >         }
> > -       queue_delayed_work(system_unbound_wq, &krcp->monitor_work, delay);
> > +       queue_delayed_work(rcu_reclaim_wq, &krcp->monitor_work, delay);
> >  }
> > 
> >  static void
> > @@ -1733,7 +1735,7 @@ kvfree_rcu_queue_batch(struct kfree_rcu_cpu *krcp)
> >                         // "free channels", the batch can handle. Break
> >                         // the loop since it is done with this CPU thus
> >                         // queuing an RCU work is _always_ success here.
> > -                       queued = queue_rcu_work(system_unbound_wq, &krwp->rcu_work);
> > +                       queued = queue_rcu_work(rcu_reclaim_wq, &krwp->rcu_work);
> >                         WARN_ON_ONCE(!queued);
> >                         break;
> >                 }
> > @@ -1883,7 +1885,7 @@ run_page_cache_worker(struct kfree_rcu_cpu *krcp)
> >         if (rcu_scheduler_active == RCU_SCHEDULER_RUNNING &&
> >                         !atomic_xchg(&krcp->work_in_progress, 1)) {
> >                 if (atomic_read(&krcp->backoff_page_cache_fill)) {
> > -                       queue_delayed_work(system_unbound_wq,
> > +                       queue_delayed_work(rcu_reclaim_wq,
> >                                 &krcp->page_cache_work,
> >                                         msecs_to_jiffies(rcu_delay_page_cache_fill_msec));
> >                 } else {
> > @@ -2120,6 +2122,10 @@ void __init kvfree_rcu_init(void)
> >         int i, j;
> >         struct shrinker *kfree_rcu_shrinker;
> > 
> > +       rcu_reclaim_wq = alloc_workqueue("rcu_reclaim",
> 
> Should we name it "kvfree_rcu_reclaim"? rcu_reclaim sounds too generic
> as if it's part of rcu itself?
> 
> > +               WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
> 
> Do we want WQ_SYSFS? Or maybe only when someone asks, with a use case?
> 
If someone asks, IMO.

--
Uladzislau Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z78lpfLFvNxjoTNf%40pc636.
