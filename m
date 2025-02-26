Return-Path: <kasan-dev+bncBDXYDPH3S4OBBRPH7O6QMGQEBGOTZ2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id B37C2A45C65
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2025 11:58:15 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-438e4e9a53fsf51146425e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2025 02:58:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740567495; cv=pass;
        d=google.com; s=arc-20240605;
        b=bF1egPohuvd7Ikxb27JxGFA5PRqe6/4jVSBNp2OWKRhlZ3ZeFQ5d4+FO8WLr9Sd65k
         Bth15xmpQVFPnIkZPAw/BVxERq7Z6NwIVwW1esmHJ+dbY0zS6hA6E22Y5KV2FnFbihiV
         B5KKhYcp3S+5p5JGbJG6gg9RlZI1Nc3CwuyHe/QnSaWzDpZNvBnB3e7MEszgkr+K9xow
         kXZ14AVvFSni9yChLBiQfZKKD5Nu+iPp/ZWHJ56Lx+YeCJv6nCCS84FNGl/yqBCYzBU5
         KtfT6xh5e1UwRDQ/MjgiZ/xTiWBE3g0KrgdBwjYPOdYwKhDW+ZWpposixaii87LzU3sQ
         0jPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=1Vm381uEKOlf9g96QzbyJHypZECmWuvWCm7A/JRPNqk=;
        fh=3EGtad5S/87RNdj1FIGDNF2Q8ekLJjSIx+LMaSAodWA=;
        b=dDH9PdcaQRk0D7Ib+BR1pu4xDUCvkPwkA/xbgJyGZXcJ6VXo4GwPduWPLsu/tXK5vA
         bfK23OV0OSoVI/QGcrbhgW/ma3rYVgdDf5msN1HD62eeIwJPAg6qXwQjrfyILyuhCqel
         R06ZzKD27ZJjmWU4wewgmc7kfccu3CymLev8SJoEgORg/tvd0UOVJKqedTvO1oywAVR0
         eKI4Qd0l74Ctapk5efHzPVS9OFcD2MMFuXO1PrwPswZjoom0qEEf2TXBKowBLu3ypN4C
         jU0Z36Y0MJ4X3ynQFEps/Eg3EDLwZhHaVK2xnN5YC9gfYkYW7GB9N7xP9mbQoCegEHHe
         43LQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=zqQI5+yM;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=zqQI5+yM;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740567495; x=1741172295; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-language:from:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=1Vm381uEKOlf9g96QzbyJHypZECmWuvWCm7A/JRPNqk=;
        b=r0covM6NI1nIrrZ4pyhbs0dEnfQ6I4nNen++QWpi8ITkHTYBicqvHWcLvKP4s08lPp
         8KeCrbo58P5786OkITn961VCusC/ShBPuQj4MH1g2xFx6nV4Em7MIWH6CF7K4EnZF/a/
         wYRNYx+eJ8vwYNpYDp/PRdjTGarqkTu0oIRjJLrG5eVrXsFwnCwdz7oki1/R5d4/Smdn
         OqzOPSnm7RsfvbwuYA1FhXCxlWEtrzL+a31TXpiVfQDMvprVtLcbpU96FxfKj1bfwF9J
         oCj+1lDPFroJeuZ76qe3hMLWRLG4RyHWGeD3l8CtcewuhWfTWWT9ZISbunZ476a3cm0R
         ep3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740567495; x=1741172295;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=1Vm381uEKOlf9g96QzbyJHypZECmWuvWCm7A/JRPNqk=;
        b=fKXYqfC4PwKdlXoACG9WkNIntiu7ugvO10gz2ph4zTkoBJzVFd1kwETOJ9GwAb+n7u
         /CgsaAT6/ttXDRmblGURQHt7o3UIr/CwY6x8xrBpjd1/rFaCkDFOTwee2kVSDk1gfL1z
         zi73WmTtNVAX80izg7RtLe7e2aA381Lw8KqLkTN7FWFHHC7p2rON20PmDF3JWKa5zPZK
         R5Ni6hGLN/sA1SOSveJybCrNSU7r3L1Yx/61p4wtaYo4qGqoIUxk3idDYCE/SMQZ7nzd
         vzzFrhZmvyaWWewUZsqXztGP1/JNDlLs2dB5sz7I3OsppHYL+VutRDEi1are6xtYv38O
         deEw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXbpUfnb7oOyZ9nFtbd2V+SiMATO7/1HuYGKCnVsGA1JhPJh9FhzLaoYRe6IvUVTDt/QsHgyA==@lfdr.de
X-Gm-Message-State: AOJu0YznGUP03m+/CaMEEU6Jw7cL9dmCzvC2QIrrXj8z+Swu7zO+oAwY
	f7P9zODhq7+65GNDP7UyjvjFshK/KGIDK44uQJxlmXSM7c+SSQS3
X-Google-Smtp-Source: AGHT+IEudyD/hMkIejfvrQYghTEC1gaPSBxAQKydpSEfzweyM77b6K7NlUvVlM/mSN5COy7hQzM5Og==
X-Received: by 2002:a05:600c:19ce:b0:439:92ca:f01b with SMTP id 5b1f17b1804b1-439aeb34975mr163458785e9.13.1740567494260;
        Wed, 26 Feb 2025 02:58:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVEhlKFhmBoABOirBpmTqz/QC1sU1hPuAOjnV5GgQce8Rw==
Received: by 2002:a05:600c:4f13:b0:439:8b18:3dcd with SMTP id
 5b1f17b1804b1-439ae3138cfls16296715e9.2.-pod-prod-02-eu; Wed, 26 Feb 2025
 02:58:11 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUF0MylGXJ5FqesLZ0hcSk2IxnxnKV4NHSm8OuvDZnPn39jwIHpW+6PIQrK/b3aVMVjVuN7qMMI7Lk=@googlegroups.com
X-Received: by 2002:a05:600c:458d:b0:439:99e6:2ab with SMTP id 5b1f17b1804b1-439aebcfd58mr162966975e9.28.1740567491180;
        Wed, 26 Feb 2025 02:58:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740567491; cv=none;
        d=google.com; s=arc-20240605;
        b=DMVvy62w6m4zdb0dmadnEtyn4H36hgw7c3Kig/GmTj1oGGqCbc1PH2Ve+SJeZmYzF/
         lAy25Br/JzXRiBSoetTJ2121wlqlc9cPXfyd2fiTY2HQBWgfWxZeL7B5jQKqvRXNxMdD
         X84Ha4RcXiP8gNDfj4y+p+y70txrAJBHsbeO1N2Uw2EJkL8/VJo2ho89VXc9+eQOMnH0
         L2fPaufz0Rwl/HnfPCoBdjUasyArWv2ZROD92HbwyMaFpr/VirbFJexZGWQATxoQ26Sj
         iF46ZWuYhgmTYj05LXMI8syuaixt37tzpJb/Q6ptDoqxw443HJ385QEhMOt8mg8X9KKy
         /xVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=WvQMaogfR4p5vXml1R1gl73Lc4GXJegwVY6rJmvbNrQ=;
        fh=sGQxV+Ls1Ivp3fL0+oIOF/WUu9JfdgutgYrv3phwnY8=;
        b=c94hY5NaArtZOfOTN1vxTyngIPswkNB1AxHTGSgnjxZACIPh6prOJb2my86R84MDWQ
         TldIvfbrJnt5XoFiFPoT7pqajPPoRE52EG7rph6G4txmIxfKSutpS75aCZW1l6ePIEop
         rXIU8E77+yaYnGEMRA47KGp4I+p2PA+cpxNb1uGWzSGTOZCpMaH+nWIM3nqdU1TIQa+a
         a12aXB0+Sq55s94gsJm3cNDBHXakLU9hOth1p9bV9y0sslikoT02DjEgOFUiJcRvVakx
         OKnK4tAhIClD3IdrtpE5Yc7/1VmfMa1Dey7OoXJ3pVK4EiL3mFxbwBtAsMQjCs86dP2L
         y7aA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=zqQI5+yM;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=zqQI5+yM;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43aba0d3e09si1045925e9.0.2025.02.26.02.58.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 26 Feb 2025 02:58:11 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 68A6221184;
	Wed, 26 Feb 2025 10:58:10 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 3DA491377F;
	Wed, 26 Feb 2025 10:58:10 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id HQrvDcLzvmdaeQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 26 Feb 2025 10:58:10 +0000
Message-ID: <8d7aabb2-2836-4c09-9fc7-8bde271e7f23@suse.cz>
Date: Wed, 26 Feb 2025 11:59:53 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 6/7] mm, slab: call kvfree_rcu_barrier() from
 kmem_cache_destroy()
To: Uladzislau Rezki <urezki@gmail.com>, Keith Busch <keith.busch@gmail.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
 Joel Fernandes <joel@joelfernandes.org>,
 Josh Triplett <josh@joshtriplett.org>, Boqun Feng <boqun.feng@gmail.com>,
 Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
 Steven Rostedt <rostedt@goodmis.org>,
 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 Lai Jiangshan <jiangshanlai@gmail.com>, Zqiang <qiang.zhang1211@gmail.com>,
 Julia Lawall <Julia.Lawall@inria.fr>, Jakub Kicinski <kuba@kernel.org>,
 "Jason A. Donenfeld" <Jason@zx2c4.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, rcu@vger.kernel.org,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
 Jann Horn <jannh@google.com>, Mateusz Guzik <mjguzik@gmail.com>,
 linux-nvme@lists.infradead.org, leitao@debian.org
References: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz>
 <20240807-b4-slab-kfree_rcu-destroy-v2-6-ea79102f428c@suse.cz>
 <Z7iqJtCjHKfo8Kho@kbusch-mbp> <2811463a-751f-4443-9125-02628dc315d9@suse.cz>
 <Z7xbrnP8kTQKYO6T@pc636> <ef97428b-f6e7-481e-b47e-375cc76653ad@suse.cz>
 <Z73p2lRwKagaoUnP@kbusch-mbp>
 <CAOSXXT6-oWjKPV1hzXa5Ra4SPQg0L_FvxCPM0Sh0Yk6X90h0Sw@mail.gmail.com>
 <Z74Av6tlSOqcfb-q@pc636> <Z74KHyGGMzkhx5f-@pc636>
From: Vlastimil Babka <vbabka@suse.cz>
Content-Language: en-US
In-Reply-To: <Z74KHyGGMzkhx5f-@pc636>
Content-Type: text/plain; charset="UTF-8"
X-Rspamd-Queue-Id: 68A6221184
X-Spam-Score: -3.01
X-Rspamd-Action: no action
X-Spamd-Result: default: False [-3.01 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	ARC_NA(0.00)[];
	FREEMAIL_TO(0.00)[gmail.com];
	RCPT_COUNT_TWELVE(0.00)[29];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	FREEMAIL_CC(0.00)[kernel.org,joelfernandes.org,joshtriplett.org,gmail.com,linux.com,google.com,goodmis.org,efficios.com,inria.fr,zx2c4.com,linux-foundation.org,linux.dev,kvack.org,vger.kernel.org,googlegroups.com,lists.infradead.org,debian.org];
	RCVD_TLS_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[];
	DKIM_TRACE(0.00)[suse.cz:+];
	R_RATELIMIT(0.00)[to_ip_from(RLctujmen6hjyrx8fu4drawbuj)];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:rdns,imap1.dmz-prg2.suse.org:helo,suse.cz:mid,suse.cz:dkim]
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Flag: NO
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=zqQI5+yM;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=zqQI5+yM;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 2/25/25 7:21 PM, Uladzislau Rezki wrote:
>>
> WQ_MEM_RECLAIM-patch fixes this for me:

Sounds good, can you send a formal patch then?
Some nits below:

> <snip>
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 4030907b6b7d..1b5ed5512782 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -1304,6 +1304,8 @@ module_param(rcu_min_cached_objs, int, 0444);
>  static int rcu_delay_page_cache_fill_msec = 5000;
>  module_param(rcu_delay_page_cache_fill_msec, int, 0444);
> 
> +static struct workqueue_struct *rcu_reclaim_wq;
> +
>  /* Maximum number of jiffies to wait before draining a batch. */
>  #define KFREE_DRAIN_JIFFIES (5 * HZ)
>  #define KFREE_N_BATCHES 2
> @@ -1632,10 +1634,10 @@ __schedule_delayed_monitor_work(struct kfree_rcu_cpu *krcp)
>         if (delayed_work_pending(&krcp->monitor_work)) {
>                 delay_left = krcp->monitor_work.timer.expires - jiffies;
>                 if (delay < delay_left)
> -                       mod_delayed_work(system_unbound_wq, &krcp->monitor_work, delay);
> +                       mod_delayed_work(rcu_reclaim_wq, &krcp->monitor_work, delay);
>                 return;
>         }
> -       queue_delayed_work(system_unbound_wq, &krcp->monitor_work, delay);
> +       queue_delayed_work(rcu_reclaim_wq, &krcp->monitor_work, delay);
>  }
> 
>  static void
> @@ -1733,7 +1735,7 @@ kvfree_rcu_queue_batch(struct kfree_rcu_cpu *krcp)
>                         // "free channels", the batch can handle. Break
>                         // the loop since it is done with this CPU thus
>                         // queuing an RCU work is _always_ success here.
> -                       queued = queue_rcu_work(system_unbound_wq, &krwp->rcu_work);
> +                       queued = queue_rcu_work(rcu_reclaim_wq, &krwp->rcu_work);
>                         WARN_ON_ONCE(!queued);
>                         break;
>                 }
> @@ -1883,7 +1885,7 @@ run_page_cache_worker(struct kfree_rcu_cpu *krcp)
>         if (rcu_scheduler_active == RCU_SCHEDULER_RUNNING &&
>                         !atomic_xchg(&krcp->work_in_progress, 1)) {
>                 if (atomic_read(&krcp->backoff_page_cache_fill)) {
> -                       queue_delayed_work(system_unbound_wq,
> +                       queue_delayed_work(rcu_reclaim_wq,
>                                 &krcp->page_cache_work,
>                                         msecs_to_jiffies(rcu_delay_page_cache_fill_msec));
>                 } else {
> @@ -2120,6 +2122,10 @@ void __init kvfree_rcu_init(void)
>         int i, j;
>         struct shrinker *kfree_rcu_shrinker;
> 
> +       rcu_reclaim_wq = alloc_workqueue("rcu_reclaim",

Should we name it "kvfree_rcu_reclaim"? rcu_reclaim sounds too generic
as if it's part of rcu itself?

> +               WQ_UNBOUND | WQ_MEM_RECLAIM, 0);

Do we want WQ_SYSFS? Or maybe only when someone asks, with a use case?

Thanks,
Vlastimil

> +       WARN_ON(!rcu_reclaim_wq);
> +
>         /* Clamp it to [0:100] seconds interval. */
>         if (rcu_delay_page_cache_fill_msec < 0 ||
>                 rcu_delay_page_cache_fill_msec > 100 * MSEC_PER_SEC) {
> <snip>
> 
> it passes:
> 
> <snip>
> [   15.972416] KTAP version 1
> [   15.972421] 1..1
> [   15.973467]     KTAP version 1
> [   15.973470]     # Subtest: slub_test
> [   15.973472]     # module: slub_kunit
> [   15.973474]     1..10
> [   15.974483]     ok 1 test_clobber_zone
> [   15.974927]     ok 2 test_next_pointer
> [   15.975308]     ok 3 test_first_word
> [   15.975672]     ok 4 test_clobber_50th_byte
> [   15.976035]     ok 5 test_clobber_redzone_free
> [   15.976128] stackdepot: allocating hash table of 1048576 entries via kvcalloc
> [   15.979505]     ok 6 test_kmalloc_redzone_access
> [   16.014408]     ok 7 test_kfree_rcu
> [   17.726602]     ok 8 test_kfree_rcu_wq_destroy
> [   17.750323]     ok 9 test_leak_destroy
> [   17.750883]     ok 10 test_krealloc_redzone_zeroing
> [   17.750887] # slub_test: pass:10 fail:0 skip:0 total:10
> [   17.750890] # Totals: pass:10 fail:0 skip:0 total:10
> [   17.750891] ok 1 slub_test
> <snip>
> 
> --
> Uladzislau Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/8d7aabb2-2836-4c09-9fc7-8bde271e7f23%40suse.cz.
